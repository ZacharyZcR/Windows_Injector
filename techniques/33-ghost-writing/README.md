# GhostWriting - 幽灵写入注入

## 概述

GhostWriting 是一种不使用 `OpenProcess` 或 `WriteProcessMemory` 的进程注入技术。它通过线程上下文操作和 gadget 搜索，利用目标线程自己的执行流来实现内存写入。

**原作者**: c0de90e7 (Spring 2007)

## 核心思想

> "A paradox: Writing to another process without opening it nor actually writing to it"

传统注入技术依赖：
- `OpenProcess` - 打开目标进程
- `VirtualAllocEx` - 在目标进程分配内存
- `WriteProcessMemory` - 写入 payload
- `CreateRemoteThread` - 执行 payload

GhostWriting 完全避开这些 API，转而使用：
- `OpenThread` - 打开目标线程（不是进程）
- `GetThreadContext/SetThreadContext` - 操作寄存器
- 利用目标进程自身的指令来写入内存

## 技术原理

### 1. Gadget 搜索

在 ntdll.dll 的代码段中搜索两种 gadget：

**JMP $ Gadget (0xEB 0xFE)**
```assembly
jmp $  ; 无限循环，用于线程自锁
```

**MOV+RET Gadget**
```assembly
mov [reg1], reg2  ; 或 mov [reg1+offset], reg2
pop regX          ; 可选的栈平衡指令
add esp, yy       ; 可选的栈平衡指令
...
ret               ; 返回指令
```

### 2. 内存写入机制

核心技巧：通过修改线程上下文来控制 MOV 指令的执行

```
初始状态：
ESP -> [返回地址]  ; 栈顶是某个返回地址
       [其他数据]

设置寄存器：
REG1 = 目标地址 - offset   ; 要写入的内存地址
REG2 = 要写入的值           ; DWORD 数据
EIP  = MOV gadget 地址      ; 跳转到 MOV 指令
ESP  = 栈顶                 ; 保持栈平衡

ResumeThread() ->
    执行：mov [REG1+offset], REG2   ; 写入一个 DWORD！
    执行：pop/add (栈平衡)
    执行：ret -> 跳到栈顶的返回地址

如果返回地址是 JMP $ gadget：
    线程进入自锁状态 (EIP == JMPTOSELFAddress)
```

### 3. 注入流程

**阶段 1: 初始化返回地址**
```
写入第一个 DWORD（返回地址 = JMP $ gadget）
之后每次 MOV 执行完都会跳到 JMP $ 自锁
```

**阶段 2: 写入 NtProtectVirtualMemory 调用帧**
```
写入 9 个 DWORD：
[0] = JMP $ 地址                        ; 返回地址
[1] = 0xFFFFFFFF                        ; ProcessHandle (当前进程)
[2] = &BaseAddress                      ; 指向 [6]
[3] = &NumberOfBytesToProtect           ; 指向 [7]
[4] = PAGE_EXECUTE_READWRITE            ; 新保护标志
[5] = &OldAccessProtection              ; 指向 [8]
[6] = 注入代码的基地址                   ; BaseAddress
[7] = 注入代码大小                       ; NumberOfBytesToProtect
[8] = 0                                 ; OldAccessProtection (输出)
```

**阶段 3: 写入 Shellcode**
```
逐 DWORD 写入注入代码（MessageBox shellcode）
```

**阶段 4: 执行 NtProtectVirtualMemory**
```
设置：
ESP = NtProtectVirtualMemory 调用帧地址
EIP = NtProtectVirtualMemory 函数地址

ResumeThread() ->
    执行 NtProtectVirtualMemory，标记栈为可执行
    返回到 JMP $ 自锁
```

**阶段 5: 执行注入代码**
```
设置：
ESP = 安全位置
ESI = JMP $ 地址 (shellcode 会将其作为返回地址)
EBX = 注入代码基地址 (delta handle)
EIP = 注入代码入口点

ResumeThread() ->
    执行 shellcode (MessageBoxA)
    返回到 JMP $ 自锁
```

**阶段 6: 恢复线程**
```
SetThreadContext(SavedContext)
ResumeThread()

线程恢复正常执行，就像什么都没发生过
```

## 栈布局示意图

```
Higher Address
+---------------------------+
|  Stack Bottom             |
+---------------------------+
|  ...                      |
+---------------------------+
|  BASEOfWrittenBytes       |<--- 写入区域开始
|  [dummy bytes]            |     栈平衡用
|  [JMP $ address]          |<--- 初始返回地址
|  [NtProtectVM callframe]  |     9 DWORDs
|  [Injection code]         |     Shellcode
+---------------------------+
|  Original ESP             |<--- 原始栈顶
|  Used stack space         |
+---------------------------+
Lower Address
```

## 关键数据结构

### DisassembleAndValidateMOV

验证 MOV 指令的有效性：
- 只接受 `mov [reg1], reg2` 或 `mov [reg1+offset], reg2`
- reg1 和 reg2 必须是非易失性寄存器（EBX, EBP, ESI, EDI）
- reg1 ≠ reg2

### WaitForThreadAutoLock

等待线程执行到自锁点：
```c
do {
    ResumeThread(Thread);
    Sleep(30);
    SuspendThread(Thread);
    GetThreadContext(Thread, &Context);
} while (Context.Eip != JMPTOSELFAddress);
```

## 技术特点

### 优势
- ✅ 完全不使用 `OpenProcess`
- ✅ 完全不使用 `WriteProcessMemory`
- ✅ 完全不使用 `VirtualAllocEx`
- ✅ 完全不使用 `CreateRemoteThread`
- ✅ 可以绕过监控这些 API 的安全软件
- ✅ 注入过程精准可控

### 局限性
- ❌ 需要目标线程有窗口句柄（用于 PostMessage 唤醒）
- ❌ 依赖 ntdll.dll 中存在特定 gadget
- ❌ 写入速度较慢（每个 DWORD 需要多次 Resume/Suspend）
- ❌ 32 位技术，需要在 32 位环境下编译
- ❌ 需要目标线程处于可挂起状态

## 与其他技术对比

| 技术 | OpenProcess | WriteProcessMemory | 写入方式 |
|-----|------------|-------------------|---------|
| 经典注入 | ✅ | ✅ | WriteProcessMemory |
| Stack Bombing | ✅ | ❌ | NtQueueApcThread + memset |
| GhostInjector | ✅ | ❌ | 目标进程的 fread + malloc |
| **GhostWriting** | ❌ | ❌ | **MOV gadget + SetThreadContext** |

## 代码结构

```
33-ghost-writing/
├── src/
│   └── ghost_writing.c         # 完整实现（单文件）
├── build.sh                     # 编译脚本（需要 32 位编译器）
└── README.md                    # 本文档
```

## 编译要求

这是一个 **32 位技术**，需要：
- i686-w64-mingw32-gcc (推荐)
- 或者支持 -m32 的 MinGW-w64

```bash
chmod +x build.sh
./build.sh
```

如果编译失败，请参考 build.sh 中的说明安装 32 位编译器。

## 使用方法

```bash
./ghost_writing.exe
```

程序会：
1. 获取 Explorer.exe 的 Shell Window 线程
2. 在 ntdll.dll 中搜索 gadget
3. 将 MessageBox shellcode 注入到线程栈
4. 执行 shellcode
5. 恢复线程原始状态

成功后，会弹出一个来自 Explorer.exe 的 MessageBox。

## 安全考虑

⚠️ **仅供学习和防御性研究使用**

此技术展示了：
- 传统 API 监控的盲点
- 线程上下文操作的威力
- ROP 技术在注入中的应用

防御建议：
1. 监控 `GetThreadContext/SetThreadContext` 的异常调用
2. 检测线程在异常地址（如 ntdll gadget）的执行
3. 监控栈内存的权限变化（PAGE_EXECUTE_READWRITE）
4. 检测线程频繁的 Suspend/Resume 操作

## 技术演化

GhostWriting (2007) 开创了"无 OpenProcess/WriteProcessMemory"注入的先河。后续演化：
- **GhostHook**: 使用类似技术进行 Hook
- **Process Doppelgänging**: 利用 NTFS 事务实现无 WriteProcessMemory 注入
- **Process Herpaderping**: 利用文件映射实现无 WriteProcessMemory 注入

## 参考资料

- 原始论文: GhostWriting - c0de90e7 (2007)
- Intel x86 指令集手册: MOV 指令编码
- Windows Internals: Thread Context 结构
- ROP 技术: Return-Oriented Programming

## 实现细节

### Shellcode 结构
```assembly
push 0                    ; uType
call next
db "GhostWriting", 0      ; lpCaption
next:
call next2
db "Running into EXPLORER.EXE...", 0  ; lpText
next2:
push 0                    ; hWnd
push esi                  ; 返回地址 (JMP $ gadget)
push <MessageBoxA>        ; 运行时填充
ret                       ; 调用 MessageBoxA
```

### 寄存器使用约定
- **EBX**: 注入代码基地址（delta handle）
- **ESI**: 退出地址（JMP $ gadget）
- **EBP/EDI**: 用于 MOV gadget 的寄存器
- **ESP**: 栈指针，精心计算的偏移
- **EIP**: 指令指针，控制执行流

## 历史意义

GhostWriting 发布于 2007 年，当时：
- Windows Vista 引入了更多安全机制
- AV 软件开始大量监控 WriteProcessMemory
- 研究者需要新的方法绕过检测

这项技术证明了：
- 即使不"写入"进程，也能修改其内存
- 线程上下文是强大的攻击面
- Gadget 技术不仅限于栈溢出利用

---

**实现状态**: ✅ 完整实现原始版本
**编译状态**: ⚠️ 需要 32 位编译环境
**测试状态**: 源码已验证，需要 32 位 Windows 环境运行
