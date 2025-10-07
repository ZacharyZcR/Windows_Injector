# Stack Bombing（栈轰炸注入）

## 技术概述

Stack Bombing 是一种极其高级和隐蔽的代码注入技术，通过滥用 `NtQueueApcThread` API 直接修改目标线程的栈内存，植入 ROP chain，实现无需分配新内存、无需 WriteProcessMemory 的代码执行。

该技术由 maziland 开发，能够绕过几乎所有的安全机制（Windows 10 Build 1909 之前）。

## 核心原理

### 传统注入的局限

传统注入技术的共同特征：
- ✅ VirtualAllocEx - 分配可疑的新内存
- ✅ WriteProcessMemory - 直接写入进程内存（易被 Hook）
- ✅ CreateRemoteThread - 创建远程线程（触发内核回调）

### Stack Bombing 的突破

**核心思路**：滥用 APC 机制，利用 `NtQueueApcThread` 间接修改线程栈。

```
传统思维：分配内存 → 写入 shellcode → 创建线程

Stack Bombing：
1. 不分配新内存（使用目标线程的栈）
2. 不使用 WriteProcessMemory（使用 NtQueueApcThread + memset）
3. 不创建新线程（劫持现有线程）
```

### 技术细节

#### 1. NtQueueApcThread 滥用

`NtQueueApcThread` 的正常用途：向线程的 APC 队列添加回调函数。

**Stack Bombing 的滥用方式**：
```c
// 正常用途：
NtQueueApcThread(hThread, MyCallback, arg1, arg2, arg3);

// Stack Bombing 滥用：
NtQueueApcThread(hThread, ntdll!memset, stackAddress, byteValue, 1);
//                        ↑ ApcRoutine   ↑ arg1        ↑ arg2      ↑ arg3
//                        使用 memset    目标地址      写入的字节   写入 1 个字节
```

**逐字节写入栈**：
```c
// 写入 ROP chain 到栈
for (int i = 0; i < ropChainSize; i++) {
    NtQueueApcThread(hThread, ntdll!memset, newStackAddress + i, ropChain[i], 1);
}
```

#### 2. Stack Pivoting（栈切换）

**目标**：让线程从当前栈切换到我们构造的恶意栈。

**步骤**：
1. 保存线程当前栈指针（RSP）
2. 在栈的低地址构造 ROP chain
3. 覆盖当前栈的返回地址为 "pop rsp; ret" gadget
4. 覆盖 RSP+8 为新栈地址
5. 当线程从当前函数返回时：
   ```asm
   ret                  ; 跳转到 pivot gadget
   → pop rsp            ; 从 [RSP+8] 弹出新栈地址到 RSP
   → ret                ; 使用新栈，开始执行 ROP chain
   ```

#### 3. ROP Chain 构建

**Gadgets 来源**：ntdll.dll, kernel32.dll 等系统 DLL 的 .text 节。

**常用 Gadgets**：
| Gadget | 字节码 | 用途 |
|--------|-------|------|
| `pop rsp; ret` | `5C C3` | Stack pivoting |
| `pop rcx; ret` | `59 C3` | 设置 RCX 参数 |
| `pop rdx; ret` | `5A C3` | 设置 RDX 参数 |
| `pop r8; ret` | `41 58 C3` | 设置 R8 参数 |
| `add rsp, 0x28; ret` | `48 83 C4 28 C3` | 跳过 shadow space |
| `ret` | `C3` | 对齐栈 |

**调用 MessageBoxA 的 ROP chain 示例**：
```c
ROP[0] = pop_rcx_gadget    ; RCX = 0 (hWnd)
ROP[1] = 0
ROP[2] = pop_rdx_gadget    ; RDX = textAddress
ROP[3] = textAddress
ROP[4] = pop_r8_gadget     ; R8 = titleAddress
ROP[5] = titleAddress
ROP[6] = movsxd_r9_gadget  ; R9 = 0 (uType)
ROP[7] = 0
ROP[8] = ... (shadow space)
ROP[12] = MessageBoxA_address
ROP[13] = add_rsp_0x28_gadget  ; 清理栈
```

## 执行流程图

```
[主程序]
    ↓
1. OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT)
    ↓
2. SuspendThread(hThread)
    ↓
3. GetThreadContext(hThread, &context)
   获取当前 RSP = 0x00000000001FF000
    ↓
4. 计算新栈地址 = RSP - 0x2000 = 0x00000000001FD000
    ↓
5. 搜索 ROP Gadgets（在 ntdll.dll .text 节）
   ├─ pop rsp; ret (Stack pivot)
   ├─ pop rcx; ret
   ├─ pop rdx; ret
   └─ ... (其他 gadgets)
    ↓
6. 构建 ROP chain（调用 MessageBoxA）
    ↓
7. 使用 NtQueueApcThread 逐字节写入栈
   for (i = 0; i < ropChainSize; i++) {
       NtQueueApcThread(hThread, ntdll!memset,
                        newStackAddr + i,
                        ropChain[i],
                        1);
   }
    ↓
8. 保存原始返回地址到新栈
   NtQueueApcThread(hThread, ntdll!memmove,
                    newStack[savedRetAddr],
                    originalRSP,
                    8);
    ↓
9. 覆盖原始返回地址为 pivot gadget
   for (i = 0; i < 8; i++) {
       NtQueueApcThread(hThread, ntdll!memset,
                        originalRSP + i,
                        pivotGadget[i],
                        1);
   }
    ↓
10. 覆盖 RSP+8 为新栈地址
    for (i = 0; i < 8; i++) {
        NtQueueApcThread(hThread, ntdll!memset,
                         originalRSP + 8 + i,
                         newStackAddr[i],
                         1);
    }
    ↓
11. ResumeThread(hThread)
    ↓
[目标线程恢复执行]
    ↓
12. 线程从当前函数返回
    ret  ; 跳转到 pivot gadget (pop rsp; ret)
    ↓
13. Stack Pivot
    pop rsp  ; RSP = newStackAddr (0x00000000001FD000)
    ret      ; 开始执行 ROP chain
    ↓
14. ROP Chain 执行
    ├─ pop rcx; 0
    ├─ pop rdx; textAddress
    ├─ pop r8; titleAddress
    ├─ MessageBoxA(...)
    └─ Stack cleanup & restore
    ↓
15. 恢复原始栈，线程继续正常执行 ✨
```

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ 无内存分配 | 不使用 VirtualAllocEx |
| ✅ 无直接写入 | 不使用 WriteProcessMemory |
| ✅ 无新线程 | 不使用 CreateRemoteThread |
| ✅ 绕过 Hook | NtQueueApcThread 很少被 Hook |
| ✅ 极高隐蔽性 | 仅修改栈内存，无可疑内存特征 |
| ✅ ROP 风格 | 利用现有系统 DLL 的 gadgets |
| ⚠️ 复杂度高 | 需要 Gadget 搜索、ROP chain 构建 |
| ⚠️ 稳定性 | 依赖目标线程处于合适状态 |
| ⚠️ x64 Only | 原始实现仅支持 x64 |

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **Payload 改进**
   - ❌ 当前仅 MessageBoxA POC
   - ✅ 构建完整的 C2 Beacon ROP chain
   - ✅ 使用 Shellcode-to-ROP 转换器

2. **Gadget 多样性**
   - ❌ 固定从 ntdll.dll 搜索
   - ✅ 随机选择多个系统 DLL
   - ✅ Gadget 地址随机化

3. **线程选择**
   - ❌ 随意选择线程
   - ✅ 选择处于 Alertable 状态的线程
   - ✅ 避免关键线程（防止崩溃）

4. **栈对齐**
   - ✅ 原始实现已处理栈对齐（16 字节边界）
   - ✅ 确保 ROP chain 不破坏栈结构

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **API 监控** | Hook NtQueueApcThread 检测异常调用模式（大量 memset APC） |
| **内存监控** | 监控线程栈内存被频繁修改 |
| **行为分析** | 检测线程从非正常地址返回 |
| **栈完整性** | 验证栈返回地址是否指向合法模块 |
| **APC 队列** | 监控 APC 队列中的 memset/memmove 调用 |

## 技术来源

- **原作者**: maziland
- **原仓库**: [maziland/StackBombing](https://github.com/maziland/StackBombing)
- **首次公开**: ~2020 年
- **命名来源**: "Bombing" 指通过大量 APC 调用"轰炸"目标线程的栈

## 致谢

- [maziland](https://github.com/maziland) - 技术发现和实现
- ROP 技术研究社区

## 参考链接

- [maziland Repository](https://github.com/maziland/StackBombing)
- [NtQueueApcThread Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kequeueuserapc)
- [ROP Chaining Techniques](https://en.wikipedia.org/wiki/Return-oriented_programming)

## 重要提示

1. **仅限研究和防御用途**
   - 此技术仅用于安全研究和防御目的
   - 不得用于恶意攻击

2. **技术复杂性**
   - 需要深入理解 x64 调用约定
   - 需要掌握 ROP chain 构建
   - Gadget 搜索需要 PE 解析知识

3. **稳定性考虑**
   - 选择正确的目标线程很重要
   - 确保线程不在关键代码段
   - ROP chain 必须正确清理栈

4. **兼容性**
   - 原始实现仅支持 x64
   - Gadgets 地址在不同 Windows 版本可能不同
   - 需要动态搜索 Gadgets

## 实现限制

本 POC 实现了核心概念，但为简化起见做了以下限制：

- ✅ 实现了 Gadget 搜索
- ✅ 实现了 ROP chain 构建（MessageBoxA）
- ✅ 实现了 NtQueueApcThread 栈写入
- ✅ 实现了 Stack pivoting
- ⚠️ Payload 仅为 MessageBoxA POC
- ⚠️ 未实现完整的栈恢复清理
- ⚠️ 未实现线程状态检测

完整的生产环境实现需要更复杂的工程化处理。
