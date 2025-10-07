# DLL Injection - 测试指南

## 技术概述

**DLL Injection** 是最经典和广泛使用的 **Process Injection** 技术。与之前学习的 **Process Spawning** 技术（创建新进程）不同，DLL Injection 向**已存在的进程**注入代码。

**原始项目**: [hasherezade/dll_injector](https://github.com/hasherezade/dll_injector)

**MITRE ATT&CK**: [T1055.001 - Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)

### Process Spawning vs Process Injection

**Process Spawning（进程创建注入）- 技术1-11**:
- 创建新进程
- 在进程启动前/早期注入
- 需要目标可执行文件
- 进程由攻击者启动

**Process Injection（进程注入）- 本技术**:
- 注入到已运行的进程
- 不需要重启进程
- 可选择任意目标进程
- 进程可能已在运行

### 核心原理

**利用 Windows DLL 加载机制**:

```
LoadLibrary("C:\\path\\to\\evil.dll")
    ↓
Windows 加载器加载 DLL
    ↓
DLL_PROCESS_ATTACH 回调执行
    ↓
我们的代码在目标进程中运行！
```

**关键问题**：LoadLibrary 是目标进程的函数调用，我们如何从外部触发？

**答案**: CreateRemoteThread

### 技术流程

```
[OpenProcess]  ← 获取目标进程句柄
       ↓
[VirtualAllocEx]  ← 在目标进程分配内存
       ↓
[WriteProcessMemory]  ← 写入 DLL 路径字符串
       ↓
[GetProcAddress(LoadLibraryA)]  ← 获取 LoadLibrary 地址
       ↓
[CreateRemoteThread]  ← 创建远程线程
       ↓
  线程入口点 = LoadLibrary
  线程参数 = DLL 路径
       ↓
[LoadLibrary 在目标进程中执行]
       ↓
[DLL 加载]
       ↓
[DLL_PROCESS_ATTACH 回调执行]  ✓
```

---

## 测试环境

- **操作系统**：Windows 10 x64
- **编译器**：GCC (MinGW-w64) 13.2.0
- **测试日期**：2025-10-08
- **测试工具**：techniques/12-dll-injection/build/dll_injection.exe

---

## 测试步骤

### 1. 编译项目

```bash
cd techniques/12-dll-injection

# 编译DLL和注入器
./build.bat
```

**编译输出：**
```
===================================================================
Building DLL Injection
===================================================================

[*] Step 1: Compiling test_dll.dll...
[+] test_dll.dll compiled successfully

[*] Step 2: Compiling dll_injection.exe...
[+] dll_injection.exe compiled successfully

===================================================================
[+] Build completed successfully!
===================================================================
```

### 2. 修改测试 DLL（添加验证）

为了验证注入成功，我们修改 `test_dll.c` 添加文件创建功能：

```c
case DLL_PROCESS_ATTACH:
    // 创建验证文件
    HANDLE hFile = CreateFileA(
        "C:\\Users\\Public\\dll_injection_verified.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char fileMsg[512];
        sprintf(fileMsg,
            "DLL Injection Verified!\n"
            "Process ID: %lu\n"
            "DLL Handle: 0x%p\n"
            "Technique: CreateRemoteThread + LoadLibrary\n"
            "Status: DLL loaded successfully!\n"
            "DLL_PROCESS_ATTACH executed!\n",
            pid, hinstDLL);
        DWORD written;
        WriteFile(hFile, fileMsg, strlen(fileMsg), &written, NULL);
        CloseHandle(hFile);
    }
    break;
```

**重新编译 DLL：**
```bash
cd build
gcc ../src/test_dll.c -shared -o test_dll.dll -O2 -s
```

### 3. 执行注入测试

**注意**：DLL 路径必须使用绝对路径！

```bash
cd build

# 注入到新创建的进程（推荐）
./dll_injection.exe "C:\Windows\System32\notepad.exe" "C:\Users\29037\CLionProjects\Injection\techniques\12-dll-injection\build\test_dll.dll"
```

**测试输出：**
```
===================================================================
DLL Injection (CreateRemoteThread + LoadLibrary)
Based on: hasherezade/dll_injector
===================================================================

[+] Debug 权限已获取


===================================================================
DLL Injection - 注入到新进程
===================================================================

[*] 目标程序: C:\Windows\System32\notepad.exe
[+] 进程已创建 (PID: 66204)
[*] DLL 路径: C:\Users\29037\CLionProjects\Injection\techniques\12-dll-injection\build\test_dll.dll
[+] LoadLibraryA 地址: 0x00007FFB3F282D80
[+] DLL 路径已写入远程进程: 0x000001EFB1600000
[+] 远程线程已创建，等待执行...
[+] DLL 加载成功，模块句柄: 0x1F1F0000

[+] 注入成功！DLL 已加载到目标进程
[*] 恢复主线程...

===================================================================
[+] DLL Injection 完成！
===================================================================
```

### 4. 验证注入成功

```bash
cat C:\Users\Public\dll_injection_verified.txt
```

**验证结果：**
```
DLL Injection Verified!
Process ID: 66204
DLL Handle: 0x00007FFB1F1F0000
Technique: CreateRemoteThread + LoadLibrary
Status: DLL loaded successfully!
DLL_PROCESS_ATTACH executed!
```

✅ **成功标志**：
- 验证文件被成功创建
- 包含完整的注入详情
- DLL_PROCESS_ATTACH 回调被执行
- DLL 成功加载到目标进程

---

## 测试结果

### ✅ 测试成功

**测试用例：**
- **目标进程**：notepad.exe（新创建）
- **注入 DLL**：test_dll.dll
- **注入方式**：CreateRemoteThread + LoadLibrary

**验证证据：**
1. ✅ 获取 Debug 权限成功
2. ✅ 创建目标进程成功 (PID: 66204)
3. ✅ 获取 LoadLibraryA 地址成功 (0x00007FFB3F282D80)
4. ✅ 在远程进程分配内存成功 (0x000001EFB1600000)
5. ✅ 写入 DLL 路径成功
6. ✅ 创建远程线程成功
7. ✅ DLL 加载成功（模块句柄: 0x1F1F0000）
8. ✅ **关键验证**：DLL_PROCESS_ATTACH 被执行
9. ✅ **验证文件创建**：确认技术有效

---

## 关键发现

### 1. CreateRemoteThread 机制

```c
// 创建远程线程的核心代码
HANDLE hThread = CreateRemoteThread(
    hProcess,           // 目标进程句柄
    NULL,              // 默认安全描述符
    0,                 // 默认栈大小
    (LPTHREAD_START_ROUTINE)pLoadLibrary,  // 线程入口点 = LoadLibrary
    remoteString,      // 线程参数 = DLL 路径
    0,                 // 立即运行
    NULL               // 不需要线程 ID
);

// 等待线程执行完成
WaitForSingleObject(hThread, INJECTION_TIMEOUT);

// 获取返回值（模块句柄）
DWORD hModule;
GetExitCodeThread(hThread, &hModule);
```

**关键点**：
- 线程入口点是 `LoadLibraryA` 函数
- 线程参数是 DLL 路径字符串
- LoadLibrary 的返回值（模块句柄）通过 `GetExitCodeThread` 获取

### 2. LoadLibrary 地址的获取

```c
// 为什么可以直接获取 LoadLibrary 地址？
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
PVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

// 原因：kernel32.dll 在所有进程中的地址相同（Windows 的 ASLR 特性）
// 所以我们进程的 LoadLibrary 地址 = 目标进程的 LoadLibrary 地址
```

**测试结果**：
- LoadLibraryA 地址：`0x00007FFB3F282D80`
- 此地址在所有进程中相同

### 3. DLL 路径要求

**必须使用绝对路径**：

```
❌ 相对路径：test_dll.dll
   → LoadLibrary 失败（目标进程工作目录不同）

✅ 绝对路径：C:\Users\...\test_dll.dll
   → LoadLibrary 成功
```

### 4. DLL_PROCESS_ATTACH 回调

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // ← 这里的代码会在 LoadLibrary 时执行
            // 可以：
            // - 创建文件
            // - 修改内存
            // - Hook API
            // - 启动新线程
            // - 任意代码执行！
            break;
    }
    return TRUE;
}
```

**威力**：
- 完全的代码执行能力
- 在目标进程的地址空间中
- 可以访问进程的所有资源

### 5. 注入方式对比

| 方式 | 优势 | 劣势 | 测试结果 |
|------|------|------|----------|
| **注入到新进程** | 稳定性高 | 需要创建进程 | ✅ 成功 |
| **注入到现有进程** | 不需创建进程 | 权限问题、时序问题 | ⚠️ 依赖目标进程 |

---

## 技术特点

### 优势

1. **简单易用**
   - 代码量少
   - 原理直观
   - 实现简单

2. **功能强大**
   - 完整的 DLL 加载
   - 支持所有 DLL 功能
   - 可导出函数供目标进程调用

3. **广泛应用**
   - 游戏外挂
   - 安全工具（注入监控代码）
   - 恶意软件

4. **灵活性**
   - 可注入任意 DLL
   - 可选择任意目标进程
   - 支持新进程和现有进程

### 劣势

1. **容易被检测**
   - CreateRemoteThread 是明显的注入行为
   - EDR 重点监控
   - 行为特征明显

2. **需要磁盘文件**
   - DLL 必须以文件形式存在
   - 容易被 AV 扫描
   - 留下文件痕迹

3. **权限要求**
   - 需要 PROCESS_CREATE_THREAD
   - 需要 PROCESS_VM_WRITE
   - 可能需要 DEBUG 权限

4. **DLL 路径限制**
   - 必须使用绝对路径
   - 路径长度限制（MAX_PATH）

---

## 与其他技术对比

| 特性 | Process Hollowing | Shellcode Injection | DLL Injection |
|------|-------------------|---------------------|---------------|
| **目标进程** | 新创建 | 现有/新创建 | 现有/新创建 |
| **Payload 类型** | 完整 PE | Shellcode | DLL 文件 |
| **检测难度** | 中 | 低 | **非常低（容易检测）** |
| **实现复杂度** | 高 | 中 | **低** |
| **功能完整性** | 完整程序 | 有限 | **完整 DLL** |
| **磁盘文件** | 需要 | 不需要 | **需要** |

---

## 检测方法

### 1. 行为特征

```python
suspicious_sequence = [
    "OpenProcess(..., PROCESS_CREATE_THREAD | PROCESS_VM_WRITE)",  # 打开进程
    "VirtualAllocEx(...)",                                         # 分配内存
    "WriteProcessMemory(..., dll_path, ...)",                      # 写入DLL路径
    "CreateRemoteThread(..., LoadLibrary, ...)"                    # 创建远程线程
]
```

### 2. API 监控

```c
// Hook CreateRemoteThread
HANDLE WINAPI HookedCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    // 检查线程入口点是否是 LoadLibrary
    if (lpStartAddress == LoadLibraryA || lpStartAddress == LoadLibraryW) {
        Alert("DLL Injection detected!");
    }

    return RealCreateRemoteThread(...);
}
```

### 3. 内存扫描

```c
// 扫描进程内存，查找 DLL 路径字符串
void ScanForDllPaths(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            // 读取内存内容
            BYTE buffer[MAX_PATH];
            ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, MAX_PATH, NULL);

            // 检查是否是 DLL 路径
            if (strstr(buffer, ".dll") || strstr(buffer, ".DLL")) {
                Alert("Suspicious DLL path in memory!");
            }
        }
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }
}
```

### 4. EDR 检测规则

| 检测点 | 风险等级 | 描述 |
|--------|----------|------|
| CreateRemoteThread | **非常高** | 远程线程创建 |
| 线程入口点 = LoadLibrary | **非常高** | 明显的 DLL 注入 |
| 跨进程内存写入 | 高 | 可能的注入准备 |
| LoadLibrary 参数 = 可疑路径 | **非常高** | 加载未知 DLL |

---

## 防御建议

### 对于安全产品

1. **Hook CreateRemoteThread**
   ```c
   // 监控所有远程线程创建
   // 检查入口点是否为 LoadLibrary
   if (lpStartAddress == LoadLibrary*) {
       Alert("DLL Injection attempt!");
   }
   ```

2. **DLL 加载监控**
   ```c
   // Hook LdrLoadDll (ntdll.dll)
   // 记录所有 DLL 加载
   // 检查加载路径是否可疑
   ```

3. **进程保护**
   ```c
   // 启用进程保护
   SetProcessMitigationPolicy(ProcessSignaturePolicy, ...);
   ```

### 对于系统管理员

1. **启用 AppLocker**
   ```powershell
   # 限制 DLL 加载路径
   New-AppLockerPolicy -RuleType Dll -Path "C:\Trusted\*" -Action Allow
   ```

2. **Sysmon 监控**
   ```xml
   <RuleGroup groupRelation="or">
     <CreateRemoteThread onmatch="include">
       <TargetImage condition="contains">LoadLibrary</TargetImage>
     </CreateRemoteThread>
   </RuleGroup>
   ```

3. **最小权限原则**
   - 限制进程的 PROCESS_CREATE_THREAD 权限
   - 使用受保护进程（Protected Process）

---

## 改进建议

### 1. 反射式 DLL 注入

```
不使用 LoadLibrary，而是：
1. 手动加载 PE 到内存
2. 手动处理导入表
3. 手动调用 DllMain

优势：
- 不需要磁盘文件
- 不触发 LoadLibrary 监控
- 更隐蔽
```

### 2. Manual Mapping

```
手动映射 DLL 到目标进程：
1. 读取 DLL 文件
2. 分配内存
3. 复制节
4. 处理重定位
5. 处理导入表
6. 调用入口点

优势：
- 绕过 LoadLibrary 监控
- 更灵活的控制
```

### 3. 其他注入方式

```
- NtCreateThreadEx (替代 CreateRemoteThread)
- QueueUserAPC
- SetThreadContext
- Thread Hijacking
```

---

## 参考资料

### 原始项目

- [hasherezade/dll_injector](https://github.com/hasherezade/dll_injector)

### MITRE ATT&CK

- [T1055.001 - Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)

### 技术文章

- [DLL Injection with CreateRemoteThread](https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection)
- [Windows DLL Injection Basics](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

### 相关技术

- [Reflective DLL Injection (技术15)](../15-reflective-dll-injection/)
- [Shellcode Injection (技术13)](../13-shellcode-injection/)

---

## 总结

### ✅ 技术状态：完全成功

**验证结论**：
- DLL Injection 技术在 Windows 10 x64 上完全有效
- 所有注入步骤执行成功
- DLL 成功加载并执行（通过验证文件确认）
- **关键特点**：经典简单，但容易被检测

### 推荐使用场景

1. **学习研究**：理解进程注入的基本原理
2. **开发工具**：游戏外挂、调试工具
3. **安全测试**：EDR 测试基准
4. **不推荐用于隐蔽攻击**：容易被检测

### 防御建议

1. **CreateRemoteThread 监控**：重点监控此 API
2. **LoadLibrary 监控**：检测可疑 DLL 加载
3. **进程保护**：启用 Protected Process
4. **AppLocker**：限制 DLL 加载路径

---

**测试完成日期**：2025-10-08
**技术状态**：✅ 完全成功
**Windows 兼容性**：✅ Windows 10/11 x64
**检测风险**：⚠️ 高（容易被 EDR 检测）
**实用性**：✅ 高（简单易用）
