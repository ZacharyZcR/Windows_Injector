# Process Doppelgänging (进程变脸) - 技术文档

## 技术概述

Process Doppelgänging（进程变脸）是 2017 年 Black Hat Europe 大会上由 enSilo 研究团队披露的高级代码注入技术，被认为是最隐蔽的进程注入技术之一。

**核心特性**：
- **完全无文件关联** - 进程不关联任何磁盘文件
- **NTFS 事务回滚** - 利用事务机制，文件写入后立即删除
- **从内存节创建进程** - 使用 `NtCreateProcessEx` 直接从内存节创建进程
- **绕过检测** - `GetProcessImageFileName` 返回空字符串
- **原生 PE 加载** - Windows 自动处理 PE 格式

## 技术原理

### 与前两种技术的对比

| 特性 | Process Hollowing | Transacted Hollowing | Process Doppelgänging |
|------|-------------------|---------------------|----------------------|
| **创建方式** | CreateProcess + 手动替换内存 | CreateProcess + 映射事务节 | NtCreateProcessEx 从节创建 |
| **需要目标进程** | ✅ 是 | ✅ 是 | ❌ 否 |
| **内存操作** | 手动写入各节 | 映射内存节 | 系统自动加载 |
| **文件落地** | 载荷持续存在 | 临时文件立即删除 | 临时文件立即删除 |
| **隐蔽性** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **实现复杂度** | 高 | 中 | 高 |

### 核心创新：NtCreateProcessEx

Process Doppelgänging 的关键在于使用 `NtCreateProcessEx` API，这是一个未公开的 NT 系统调用：

```c
NTSTATUS NtCreateProcessEx(
    PHANDLE ProcessHandle,              // 输出：新进程句柄
    ACCESS_MASK DesiredAccess,          // 访问权限
    POBJECT_ATTRIBUTES ObjectAttributes,// NULL
    HANDLE ParentProcess,               // 父进程句柄
    ULONG Flags,                        // PS_INHERIT_HANDLES
    HANDLE SectionHandle,               // 内存节句柄（关键！）
    HANDLE DebugPort,                   // NULL
    HANDLE ExceptionPort,               // NULL
    BOOLEAN InJob                       // FALSE
);
```

**与 CreateProcess 的本质区别**：
- `CreateProcess`：从文件路径创建进程，系统记录文件路径
- `NtCreateProcessEx`：从内存节创建进程，**不关联任何文件**

### 执行流程

**10 个关键步骤**：

```
1. 创建 NTFS 事务
   └─> CreateTransaction()

2. 创建事务性文件（写入模式）
   └─> CreateFileTransactedW(GENERIC_WRITE)

3. 写入载荷到事务性文件
   └─> WriteFile(payloadData)

4. 重新打开文件（读取模式）
   └─> CreateFileTransactedW(GENERIC_READ)

5. 创建内存节对象（SEC_IMAGE）
   └─> NtCreateSection(SEC_IMAGE, hTransactedFile)

6. 回滚事务（删除文件）
   └─> RollbackTransaction()
   └─> 文件消失，但内存节依然有效！

7. 从内存节创建进程（核心步骤！）
   └─> NtCreateProcessEx(hSection)
   └─> 进程从内存节加载，不关联文件

8. 查询进程信息
   └─> NtQueryInformationProcess(ProcessBasicInformation)
   └─> 获取 PEB 地址

9. 设置进程参数
   └─> RtlCreateProcessParametersEx()
   └─> WriteProcessMemory(进程参数到远程 PEB)

10. 创建线程执行入口点
    └─> NtCreateThreadEx(entryPoint)
```

### 技术优势

**1. 最高隐蔽性**：
- 进程不关联任何磁盘文件
- `GetProcessImageFileName` 返回空字符串
- 无法通过文件路径追踪进程来源

**2. 无内存操作痕迹**：
- 不需要 `WriteProcessMemory` 写入代码
- 不需要 `VirtualAllocEx` 分配可执行内存
- Windows 自动加载 PE，使用原生权限

**3. 稳定性**：
- Windows 自动处理 PE 加载
- 自动处理重定位、导入表、TLS
- 支持所有标准 PE 特性

## 测试方法

### 环境要求
- **操作系统**: Windows Vista 及以上（需要 NTFS 事务）
- **文件系统**: NTFS
- **编译器**: MinGW-w64 或 MSVC
- **权限**: 管理员权限（NtCreateThreadEx 需要）
- **架构**: x64（当前实现）

### 编译步骤

**使用批处理脚本（推荐）**：
```bash
cd techniques/03-process-doppelganging
./build.bat
```

输出文件位于 `build/x64/` 目录：
- `process_doppelganging.exe` - 主程序
- `test_payload.exe` - 测试载荷

**手动编译**：
```bash
cd techniques/03-process-doppelganging/src

# 编译主程序
gcc -o ../build/x64/process_doppelganging.exe \
    process_doppelganging.c pe_utils.c \
    -lntdll -lktmw32 -luserenv \
    -O2 -municode -DUNICODE

# 编译测试载荷
gcc -o ../build/x64/test_payload.exe test_payload.c -mwindows
```

### 执行测试

**基本用法**：
```bash
# 使用默认目标路径（calc.exe）
./build/x64/process_doppelganging.exe build/x64/test_payload.exe

# 指定目标路径（仅用于进程参数）
./build/x64/process_doppelganging.exe build/x64/test_payload.exe C:\Windows\System32\notepad.exe
```

**注意**：目标路径仅用于设置进程参数，进程实际不关联该文件。

### 观察要点

**1. 控制台输出**
成功的执行会显示以下步骤：
```
[0] 读取载荷文件
    载荷架构：64 位

[1] 创建 NTFS 事务
    事务句柄：0x...

[2] 创建事务性文件（写入）
    文件路径：C:\Users\...\Temp\PDxxxx.tmp

[3] 写入载荷到事务性文件
    载荷大小：xxxxx 字节

[4] 重新打开事务性文件（读取）

[5] 创建内存节对象（SEC_IMAGE）
    节句柄：0x...

[6] 回滚事务（删除文件）
    事务已回滚，文件已删除
    内存节创建成功！

[7] 从内存节创建进程（NtCreateProcessEx）
    进程 ID：xxxxx

[8] 查询进程基本信息
    PEB 地址：0x...
    镜像基址：0x...

[9] 设置进程参数
    进程参数已设置

[10] 创建线程执行入口点
    线程 ID：xxxxx
```

**2. 验证进程特性**

使用 Process Explorer 或 Process Hacker：
- **Image Path**: 空或 `<unknown>`
- **Command Line**: 显示指定的目标路径
- **Verified Signer**: 无
- **Parent Process**: 当前进程

使用 PowerShell 验证：
```powershell
# 获取进程信息
Get-Process -Id <PID> | Select-Object Path

# 结果应该为空或不可用
```

**3. 文件系统验证**
```bash
# 临时文件应该已被删除
dir C:\Users\%USERNAME%\AppData\Local\Temp\PD*.tmp
# 应该找不到文件
```

## 预期效果

### 成功场景

**正常执行**：
1. 创建事务性文件（短暂存在）
2. 写入 PE 数据
3. 创建 SEC_IMAGE 内存节
4. 回滚事务，文件消失
5. 从内存节创建进程（进程无文件关联）
6. 设置进程参数
7. 创建并启动线程

**视觉表现**：
- MessageBox 弹出（test_payload.exe 行为）
- 任务管理器显示进程，但无明确的映像路径
- 进程可以正常执行

### 已知问题与限制

**1. Windows 版本兼容性**

在某些 Windows 版本（特别是 Windows 10 新版本）上，可能遇到以下问题：

**问题 A：ImageBaseAddress 为 NULL**
```
[8] 查询进程基本信息
    PEB 地址：0x...
    镜像基址：0x0000000000000000  <- 问题！
```

**原因**：
- Windows 10 1709+ 对 `NtCreateProcessEx` 的行为进行了更改
- 进程创建后，PEB 的 ImageBaseAddress 可能未立即初始化
- 需要等待或使用其他方法获取真实的镜像基址

**问题 B：NtCreateThreadEx 失败（0xC0000022）**
```
错误：NtCreateThreadEx 失败，状态码：0xC0000022
```

**原因**：
- `STATUS_ACCESS_DENIED`
- Windows 10 增强了对进程创建的保护
- 即使有管理员权限，某些操作仍可能被拒绝

**2. 架构限制**
- 载荷和主程序必须同架构（都是 x64）
- 当前实现不支持 x86

**3. 权限要求**
- 需要管理员权限
- 某些防护软件可能阻止执行

**4. NTFS 事务要求**
- 必须在 NTFS 分区上运行
- FAT32 不支持事务

### 常见错误

**1. STATUS_IMAGE_MACHINE_TYPE_MISMATCH (0xC000012F)**
- **原因**：载荷架构与主程序不匹配
- **解决**：确保都是 x64 或都是 x86

**2. 创建事务失败（Error 87）**
- **原因**：文件系统不支持事务（FAT32）
- **解决**：在 NTFS 分区上运行

**3. NtCreateSection 失败（STATUS_INVALID_IMAGE_FORMAT）**
- **原因**：载荷不是有效的 PE 文件
- **解决**：检查 PE 格式

**4. 环境变量分配失败**
- **原因**：地址冲突或权限不足
- **影响**：可能导致进程无法正常初始化
- **解决**：这是警告，可以继续，但可能影响进程行为

## 技术深度分析

### 为什么 Process Doppelgänging 最隐蔽？

**1. 完全匿名的进程**：
- 传统方法：进程的 `ImageFileName` 指向磁盘文件
- Doppelgänging：进程从内存节创建，`ImageFileName` 为空

**2. 无可疑的内存操作**：
- 传统方法：需要 `WriteProcessMemory`、`VirtualAllocEx(PAGE_EXECUTE_READWRITE)`
- Doppelgänging：Windows 自动加载 PE，使用原生权限（如 `.text` 为 `PAGE_EXECUTE_READ`）

**3. 事务回滚清除痕迹**：
- 文件仅存在毫秒级别
- 即使捕获到文件创建事件，文件已被删除
- 内存取证无法关联到原始文件

### 内存节（Section Object）机制

Windows 内核使用内存节对象管理内存映射：

```
磁盘文件 → CreateFileTransacted
          ↓
     事务性文件
          ↓
     NtCreateSection(SEC_IMAGE) → 内存节对象
          ↓                            ↓
     RollbackTransaction          NtCreateProcessEx
          ↓                            ↓
     文件删除                      进程创建（从节）
          ✓                            ✓
     磁盘无痕迹                    进程正常运行
```

**关键点**：
- 内存节对象是内核对象，独立于文件句柄
- 即使文件被删除，内存节依然有效
- `SEC_IMAGE` 标志告诉系统这是 PE 镜像，自动解析

## 防御检测

### 检测特征

**1. API 调用序列**：
```
CreateTransaction
→ CreateFileTransacted (write)
→ WriteFile
→ CreateFileTransacted (read)
→ NtCreateSection (SEC_IMAGE)
→ RollbackTransaction
→ NtCreateProcessEx (with section handle)
→ NtCreateThreadEx
```

**2. 行为特征**：
- 创建事务后立即回滚
- 从匿名内存节创建进程
- 进程无文件路径关联

**3. 内存特征**：
- 存在 SEC_IMAGE 类型的匿名内存节
- 进程的 PEB.ImageBaseAddress 指向匿名节

### EDR 检测建议

**1. 监控事务 API**：
```c
// 检测短时间内创建并回滚的事务
if (CreateTransaction && RollbackTransaction) {
    DWORD elapsed = time_between_calls();
    if (elapsed < 1000) {  // 1秒内
        ALERT("Suspicious transacted operation");
    }
}
```

**2. 监控 NtCreateProcessEx**：
```c
// 检测从内存节创建进程
if (NtCreateProcessEx && SectionHandle != NULL) {
    if (GetFileNameFromSection(SectionHandle) == NULL) {
        ALERT("Process created from anonymous section");
    }
}
```

**3. 进程属性检查**：
```c
// 检测无文件关联的进程
if (GetProcessImageFileName(hProcess) == NULL) {
    ALERT("Process with no image file name");
}
```

### 缓解措施

**1. 系统级防护**：
- 启用 Kernel Control Flow Guard (KCFG)
- 启用 Hypervisor-protected Code Integrity (HVCI)
- 使用 Windows Defender Application Control (WDAC)

**2. EDR 防护**：
- 监控所有 NTFS 事务操作
- Hook `NtCreateProcessEx` 调用
- 扫描匿名内存节

**3. 企业策略**：
- 限制普通用户使用 NTFS 事务
- 审计所有进程创建事件
- 要求所有可执行文件签名

## 参考资料

### 原始披露
- **Black Hat Europe 2017**: [Process Doppelgänging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf)
- **enSilo 博客**: [Lost in Transaction: Process Doppelgänging](https://www.ensilo.com/blog/process-doppelganging-new-method-code-injection)

### 参考实现
- [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) - 原始 C++ 实现
- [m417z/proc_doppel](https://github.com/m417z/proc_doppel) - 简化实现

### 相关技术
- [Process Hollowing](./01-process-hollowing.md)
- [Transacted Hollowing](./02-transacted-hollowing.md)

### 技术文章
- [Windows Internals: NTFS Transactions](https://docs.microsoft.com/en-us/windows/win32/fileio/transactional-ntfs-portal)
- [Undocumented NT APIs](http://undocumented.ntinternals.net/)

## 总结

Process Doppelgänging 代表了进程注入技术的巅峰，通过结合 NTFS 事务和未公开的 `NtCreateProcessEx` API，实现了完全无文件关联的进程创建。

**优势**：
- 最高隐蔽性（完全匿名进程）
- 无可疑内存操作
- 稳定性高（Windows 自动加载 PE）

**挑战**：
- 实现复杂度高
- Windows 版本兼容性问题
- 需要管理员权限
- 现代 EDR 可以检测

**研究价值**：
- 深入理解 Windows 内核进程创建机制
- 了解 NTFS 事务的安全隐患
- 研究防御和检测方法

这项技术揭示了 Windows 系统的深层机制，对于安全研究人员和防御者都具有重要的学习价值。
