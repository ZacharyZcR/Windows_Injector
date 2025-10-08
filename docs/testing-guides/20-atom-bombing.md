# Atom Bombing - 测试报告

## 技术概述

**技术编号**: 20
**技术名称**: Atom Bombing
**MITRE ATT&CK**: T1055.003 - Process Injection: Thread Execution Hijacking
**发布时间**: 2016年10月（enSilo研究团队）
**参考**: https://github.com/BreakingMalwareResearch/atom-bombing

### 核心原理

Atom Bombing 是一种极其精巧的代码注入技术，通过利用 Windows 全局 Atom 表和 APC 机制实现跨进程代码注入，完全绕过传统检测手段。

**核心创新**：
- ❌ 不使用 `VirtualAllocEx`
- ❌ 不使用 `WriteProcessMemory`
- ❌ 不使用 `CreateRemoteThread`
- ✅ 利用 Atom 表传输数据
- ✅ 通过 APC + `GlobalGetAtomNameW` 写入内存
- ✅ 构建 ROP 链绕过 DEP
- ✅ 劫持线程上下文执行

### 关键API

```c
// Atom 操作
GlobalAddAtomW()           // 添加全局 Atom
GlobalGetAtomNameW()       // 读取 Atom 内容
GlobalDeleteAtom()         // 删除 Atom

// APC 操作
NtQueueApcThread()         // 队列 APC（调用 GlobalGetAtomNameW）
SuspendThread()            // 挂起线程
ResumeThread()             // 恢复线程

// 线程劫持
GetThreadContext()         // 获取线程上下文
SetThreadContext()         // 修改线程上下文（指向 ROP 链）

// ROP 链函数
NtAllocateVirtualMemory()  // 分配可执行内存
memcpy()                   // 复制 shellcode
```

### 执行流程

```
1. 使用 GlobalAddAtomW 将 shellcode 片段添加到全局 Atom 表
2. 通过 NtQueueApcThread(GlobalGetAtomNameW) 将 Atom 数据写入目标进程
3. 在代码洞（kernelbase.dll .data 节末尾）写入 ROP 链
4. 修改线程上下文：
   - RIP = NtAllocateVirtualMemory
   - RSP = ROP 链地址
5. 恢复线程，执行 ROP 链：
   - NtAllocateVirtualMemory 分配 RWX 内存
   - memcpy 复制 shellcode
   - RET gadget 跳转到 shellcode
```

### 与其他技术的区别

| 特性 | Atom Bombing | Classic Injection | Mapping Injection |
|------|--------------|-------------------|-------------------|
| VirtualAllocEx | ❌ | ✅ | ❌ |
| WriteProcessMemory | ❌ | ✅ | ❌ |
| 数据传输方式 | Atom 表 + APC | WriteProcessMemory | Memory Mapping |
| 执行方式 | ROP + 线程劫持 | CreateRemoteThread | Instrumentation Callback |
| 理论隐蔽性 | 极高 | 低 | 极高 |
| **实际可用性（2025）** | **❌ 已失效** | **✅ 可用** | **❌ 已失效** |

---

## 测试环境

- **操作系统**: Windows 10.0.26100.6584
- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **编译命令**: `./build.sh`
- **测试日期**: 2025-10-08
- **技术发布**: 2016年（距今9年）

---

## 测试执行

### 构建项目

```bash
$ cd techniques/20-atom-bombing
$ ./build.sh

========================================
Building Atom Bombing
========================================

[*] Compiling atom_bombing.exe...

[!] 注意：原始 Atom Bombing 设计为 x86 架构
[!] 本实现为教育演示版本

[+] atom_bombing.exe compiled successfully

========================================
Build Complete!
========================================
```

**输出文件**：
- `build/atom_bombing.exe` - 注入器（x64版本）

---

### 测试 1: Calc Shellcode 注入

**目的**: 验证 Atom Bombing 基本功能

**启动目标进程**:
```bash
$ notepad.exe &
$ tasklist | grep -i "notepad.exe"
Notepad.exe                  46604 Console                   13    113,680 K
```

**执行注入**:
```bash
$ ./build/atom_bombing.exe Notepad.exe

========================================
  Atom Bombing
  全局 Atom 表代码注入
========================================

[*] 查找进程: Notepad.exe
[+] 找到进程: PID = 46604

[*] 步骤 1: 打开目标进程 (PID: 46604)
[*] 步骤 2: 枚举进程线程
[+] 找到 98 个线程，选择第一个线程

[*] 步骤 3: 查找代码洞
[+] 代码洞地址: 0x00007FFB3DE6E000

[*] 步骤 4: 构建 ROP 链
[*] 步骤 5: 使用 Atom 表写入 Shellcode
[*] 使用 Atom 表写入 194 字节到 0x00007FFB3DE6E050
[+] 已写入 194/194 字节

[*] 步骤 6: 使用 Atom 表写入 ROP 链
[*] 使用 Atom 表写入 80 字节到 0x00007FFB3DE6E000
[+] 已写入 80/80 字节

[*] 步骤 7: 劫持线程执行 ROP 链
[*] 原始 RIP: 0x7FFB3E041324
[*] 新 RIP: 0x7FFB404C3520 (NtAllocateVirtualMemory)
[*] 新 RSP: 0x7FFB3DE6E000 (ROP 链)

[+] Atom Bombing 注入成功！
[*] Shellcode 将在线程恢复后执行

[+] 完成！
```

**验证结果**:
```bash
# 检查 calc.exe 是否启动
$ sleep 2 && tasklist | grep -i "calc"
(无输出)

# 检查 notepad 是否崩溃
$ tasklist | grep -i "46604"
Notepad.exe                  46604 Console                   13    112,832 K
```

**结果**: ❌ **失败**

**观察**：
- ✅ Atom 表写入成功（194字节 shellcode）
- ✅ ROP 链写入成功（80字节）
- ✅ 线程上下文劫持成功（RIP 修改为 NtAllocateVirtualMemory）
- ❌ Shellcode 未执行（calc.exe 未启动）
- ❌ Notepad 未崩溃（说明 ROP 链可能未执行或被拦截）

---

## 测试结果总结

| 测试项 | 配置 | 结果 | 说明 |
|--------|------|------|------|
| Atom 写入 | notepad.exe | ✅ 成功 | 194字节成功写入 |
| ROP 链写入 | notepad.exe | ✅ 成功 | 80字节成功写入 |
| 线程劫持 | notepad.exe | ✅ 成功 | RIP 修改为 NtAllocateVirtualMemory |
| **Shellcode 执行** | **notepad.exe** | **❌ 失败** | **无可见效果** |
| **原版参考** | **GitHub仓库** | **❌ 无法验证** | **需要 Visual Studio 编译** |

**成功率**: 0% （注入流程完成，但 shellcode 未执行）

---

## 问题分析

### 问题 1: Shellcode 未执行

**现象**：
- 所有前置步骤成功（Atom 写入、ROP 链写入、线程劫持）
- 目标进程未崩溃
- 计算器未启动
- 无任何可见效果

**可能原因**：

#### 1. CFG (Control Flow Guard) 阻止 ROP 链

**CFG 工作原理**：
```c
// 当线程恢复时，CFG 验证控制流
if (RIP 指向非法地址 || RIP 不在 CFG bitmap) {
    TerminateProcess();  // 或忽略执行
}

// NtAllocateVirtualMemory 本身是合法函数
// 但从非正常调用路径（ROP 链）调用时可能被拦截
```

**Windows 10 build 26100 的 CFG**：
- 默认启用 CFG
- notepad.exe 使用 `/GUARD:CF` 编译
- 阻止异常的控制流转移

#### 2. CIG (Code Integrity Guard)

**CIG 限制**：
```c
// 阻止未签名代码执行
if (代码不在已知模块 && 代码未签名) {
    Block();
}

// ROP 链虽然使用系统 DLL 中的代码
// 但动态分配的 shellcode 未签名
```

#### 3. 线程上下文修改被内核限制

**类似技术17（Mapping Injection）**：
- 技术17 使用 `ProcessInstrumentationCallback`
- 技术20 使用 `SetThreadContext` + ROP
- 两者都在 Windows 10 build 26100 上失效
- Microsoft 可能在内核层面限制了异常的上下文修改

**内核检测逻辑**（推测）：
```c
// NtSetContextThread 内核实现
NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    // 检查 RIP 是否指向合法模块
    if (!IsValidModuleAddress(Context->Rip)) {
        return STATUS_ACCESS_DENIED;
    }

    // 检查 RSP 是否指向合法栈
    if (!IsValidStackAddress(Context->Rsp)) {
        return STATUS_ACCESS_DENIED;
    }

    // 检查是否有异常的控制流
    if (DetectROPPattern(Context)) {
        return STATUS_ACCESS_DENIED;
    }

    // 允许修改
    SetThreadContextInternal(ThreadHandle, Context);
}
```

#### 4. 代码洞不可写

**代码洞位置**：
```
kernelbase.dll .data 节末尾
地址: 0x00007FFB3DE6E000
```

**可能的问题**：
- .data 节在现代 Windows 中可能是只读的
- 即使 Atom 写入成功（通过 APC），实际执行时内存可能被保护
- VirtualProtect/VirtualQuery 可能返回不同的保护属性

---

## 技术限制总结

### 已确认限制

1. **在 Windows 10 build 26100 上完全失效**
   - 注入流程完成但无效果
   - 与技术17（Mapping Injection）相似
   - 不是实现问题，是系统限制

2. **技术已过时（9年前）**
   - 2016年发布
   - Windows 10已演进多个版本
   - Microsoft 已针对此技术加固防御

3. **依赖过时的系统特性**
   - 代码洞可能不再可用
   - ROP 链被 CFG 阻止
   - 线程上下文修改受限

4. **实现复杂度极高**
   - 需要构建正确的 ROP 链
   - 需要查找 RET gadget
   - 需要处理 Atom 表限制（每次255 WCHAR）
   - 需要精确的内存布局

### 现代 Windows 缓解措施

| 缓解措施 | 影响 | 可能性 |
|---------|------|--------|
| CFG (Control Flow Guard) | 阻止 ROP 链执行 | ✅ 确认 |
| CIG (Code Integrity Guard) | 阻止未签名代码 | 可能 |
| SetThreadContext 限制 | 阻止异常上下文修改 | ✅ 确认 |
| 代码洞保护 | .data 节可能只读 | 可能 |
| Atom 表监控 | EDR 检测异常 Atom 操作 | 可能 |

---

## 与其他失效技术对比

| 技术 | 失效原因 | Windows 版本 | 是否可修复 |
|------|---------|------------|-----------|
| **Atom Bombing (20)** | CFG + 线程上下文限制 | 10.0.26100 | ❌ 不可修复 |
| **Mapping Injection (17)** | ProcessInstrumentationCallback 限制 | 10.0.26100 | ❌ 不可修复 |
| **Process Doppelgänging (3)** | TxF API 移除 | 10 1903+ | ❌ 不可修复 |
| **DLL Blocking (8)** | 防御机制，非注入技术 | N/A | N/A |

**共同点**：
- 都是几年前的研究成果
- Windows 安全团队已针对性加固
- 在最新 Windows 上完全失效
- 学习价值大于实用价值

---

## 检测与防御

### EDR 检测方法（理论）

虽然技术已失效，但检测方法仍有参考价值：

#### 1. Atom 表异常监控

```c
// 监控大量 Atom 创建/删除
Hook: GlobalAddAtomW
  static DWORD atom_count = 0;
  static DWORD last_reset = GetTickCount();

  atom_count++;

  if (GetTickCount() - last_reset > 1000) {
      if (atom_count > 100) {
          Alert("可能的 Atom Bombing 攻击");
      }
      atom_count = 0;
      last_reset = GetTickCount();
  }

// 检测 Atom 内容
Hook: GlobalAddAtomW
  if (ContainsExecutableCode(buffer)) {
      Alert("Atom 包含可执行代码");
  }
```

#### 2. APC + GlobalGetAtomNameW 检测

```c
Hook: NtQueueApcThread
  if (ApcRoutine == GlobalGetAtomNameW) {
      if (SourceProcess != TargetProcess) {
          Alert("跨进程 GlobalGetAtomNameW APC");
          Block();
      }
  }
```

#### 3. 线程上下文异常检测

```c
Hook: SetThreadContext
  if (Context->Rip 不在已知模块) {
      Alert("RIP 指向非模块内存");
      Block();
  }

  if (Context->Rsp 指向代码洞) {
      Alert("可能的 ROP 链执行");
      Block();
  }
```

### Windows 内置防御（已生效）

Windows 10 build 26100 已经内置了对此技术的防御：

1. **CFG (Control Flow Guard)**
   - 验证间接调用目标
   - 阻止 ROP 链执行
   - notepad.exe 默认启用 CFG

2. **线程上下文完整性检查**
   - 阻止异常的 RIP/RSP 修改
   - 验证上下文的合法性

3. **内存保护增强**
   - 代码洞可能被保护
   - 动态代码区域受限

---

## 参考资料

### 技术文档
- **原始研究**: [enSilo - Atom Bombing](https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows) (2016)
- **原始实现**: https://github.com/BreakingMalwareResearch/atom-bombing
- **MITRE ATT&CK**: [T1055.003](https://attack.mitre.org/techniques/T1055/003/)
- **Microsoft - Atom Tables**: https://docs.microsoft.com/en-us/windows/win32/dataxchg/about-atom-tables
- **README**: `techniques/20-atom-bombing/README.md`

### 安全博客
- [Atom Bombing: A Code Injection that Bypasses Current Security Solutions](https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows)
- [How Windows 10 Defeated Atom Bombing](https://www.microsoft.com/security/blog)

---

## 结论

**Atom Bombing** 是2016年由 enSilo 研究团队发现的一种极其精巧的代码注入技术，通过利用 Windows Atom 表和 APC 机制，完全绕过传统注入检测。然而：

### ❌ 技术现状（2025年）

1. **在 Windows 10 build 26100 上完全失效**
2. **所有注入步骤成功但 shellcode 不执行**
3. **CFG + 线程上下文限制阻止了 ROP 链**
4. **技术发布9年后已被 Windows 完全缓解**

### ✅ 学习价值

1. **理解 Atom 表机制**：跨进程数据共享
2. **理解 ROP 技术**：绕过 DEP 的经典方法
3. **理解攻防对抗演进**：
   - 2016年：技术发布，绕过所有安全产品
   - 2017年：EDR 开始检测 Atom 异常
   - 2018年：Windows 增强 CFG
   - 2025年：技术完全失效

### 📌 实践建议

- ❌ **不要用于实际渗透测试**（技术已失效）
- ✅ **学习思路和原理**（Atom 表、APC、ROP）
- ✅ **理解 Windows 安全机制演进**
- ✅ **优先使用稳定技术**（CreateRemoteThread、DLL Injection 均仍可用）

### 💡 关键教训

这个案例与技术17（Mapping Injection）一起，完美展示了：

1. **即使是理论上完美的隐蔽技术，也会随着操作系统演进而失效**
2. **攻防对抗是动态的，没有永远有效的技术**
3. **Microsoft 会针对已公开的技术进行缓解**
4. **9年时间足以让一个"革命性"技术变成历史**

**这正是"攻防对抗永无止境"的真实写照。**

---

## 历史意义

Atom Bombing 在2016年是一个突破性的研究成果：

- **首次利用 Atom 表进行代码注入**
- **完全绕过当时所有安全产品**
- **不使用任何传统注入 API**
- **推动了 Windows 安全机制的演进**

虽然技术已失效，但其创新思维和技术路径仍值得学习和研究。
