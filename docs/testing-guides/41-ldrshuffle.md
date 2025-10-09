# 技术41：LdrShuffle - EntryPoint劫持 测试报告

## 测试环境
- **操作系统**: Windows 11 Build 26100 (24H2)
- **测试时间**: 2025-10-09
- **实现来源**: 参考 RWXstoned/LdrShuffle

## 技术原理

LdrShuffle是一种隐秘的代码执行技术，通过运行时修改已加载DLL的`EntryPoint`字段来重定向执行流。当Windows加载器调用DLL的`DllMain()`时，实际执行的是我们的恶意代码。

### 核心机制

每个Windows进程在PEB（Process Environment Block）中维护`_LDR_DATA_TABLE_ENTRY`结构链表，每个结构描述一个已加载的DLL：

```c
typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY InMemoryOrderLinks;  // 链接到下一个/上一个模块
    PVOID DllBase;                  // DLL基地址
    PVOID EntryPoint;               // ← DllMain()地址 - 我们修改这里
    ULONG SizeOfImage;              // DLL镜像大小
    UNICODE_STRING BaseDllName;     // DLL名称（如"version.dll"）
    ...
    ULONG_PTR OriginalBase;         // ← 我们用这里备份原始EntryPoint
    ...
} LDR_DATA_TABLE_ENTRY2;
```

### DllMain()调用时机

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:  // DLL加载到进程
        case DLL_PROCESS_DETACH:  // DLL正在卸载
        case DLL_THREAD_ATTACH:   // 创建新线程 ← 我们触发这个！
        case DLL_THREAD_DETACH:   // 线程正在销毁
    }
    return TRUE;
}
```

**关键洞察**: 创建新线程会为所有已加载的DLL触发`DLL_THREAD_ATTACH`（除非设置了`DontCallForThreads`标志）。

### 攻击流程

```
┌─────────────────────────────────────────────────────────┐
│ 1. 加载牺牲DLL（如version.dll）                        │
│    - 任何不会导致稳定性问题的DLL                       │
│    - 避免关键DLL（ntdll.dll, kernel32.dll）           │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 2. 在PEB中找到DLL的_LDR_DATA_TABLE_ENTRY              │
│    - 遍历PEB->Ldr->InMemoryOrderModuleList            │
│    - 通过BaseDllName匹配DLL                            │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 3. 备份原始EntryPoint                                  │
│    - 将EntryPoint保存到OriginalBase字段               │
│    - 存储在DATA_T结构以便后续恢复                      │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 4. 用Runner()地址覆盖EntryPoint                        │
│    - EntryPoint现在指向我们的恶意代码                  │
│    - Windows不知道有什么不同！                          │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 5. 通过CreateThread()触发执行                          │
│    - 创建虚拟线程                                       │
│    - Windows为DLL_THREAD_ATTACH调用"DllMain"          │
│    - 实际调用的是Runner()！                             │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│ 6. Runner()执行                                         │
│    - 恢复原始EntryPoint                                 │
│    - 执行恶意API调用                                    │
│    - 调用原始DllMain()（代理）                          │
│    - 线程正常继续                                       │
└─────────────────────────────────────────────────────────┘
```

## 测试步骤

### 测试1：我们的实现

```bash
cd techniques/41-ldrshuffle
echo "" | ./ldrshuffle.exe
```

### 测试2：官方实现对比

```bash
cd reference-ldrshuffle

# 编译官方版本
"/c/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/MSBuild.exe" \
    LdrShuffle.sln //p:Configuration=Release //p:Platform=x64

# 测试LdrShuffle
echo "" | ./x64/Release/LdrShuffle.exe
```

## 测试结果

### ✅ 测试1：我们的实现 - 成功

**输出**:
```
========================================
LdrShuffle - EntryPoint Hijacking
========================================

[*] Loading sacrificial DLL: version.dll
[+] Loaded at: 0x7ffb35f60000

[*] Setting up MessageBoxA() call

[*] Modifying LDR entry for version.dll
[+] Found LDR entry for version.dll
    DllBase: 0x7ffb35f60000
    EntryPoint: 0x7ffb35f61430
    OriginalBase: 0x0
[+] LDR entry modified:
    New EntryPoint: 0x7ff7d8731550 (Runner)
    Backup in OriginalBase: 0x7ffb35f61430

[*] Press ENTER to create thread and trigger execution...
[*] Creating dummy thread to trigger DLL_THREAD_ATTACH
[*] Created dummy thread: 12800
[*] Waiting for Runner to execute...
	[Runner][12800] - called on module 0x00007FFB35F60000 for reason 2
	[Runner][12800] - about to perform call in current thread
	[Runner][12800] - completed

[+] Execution completed!
[+] Return value: 0x1
	[DummyFunction] - thread 12800 started
	[DummyFunction] - thread 12800 exiting

[*] Done!
```

**验证结果**:
- ✅ version.dll成功加载在`0x7ffb35f60000`
- ✅ 找到LDR entry并备份原始EntryPoint `0x7ffb35f61430`
- ✅ EntryPoint被覆盖为Runner地址`0x7ff7d8731550`
- ✅ 创建线程触发DLL_THREAD_ATTACH（reason=2）
- ✅ Runner成功执行，返回值0x1（MessageBox点击OK）
- ✅ MessageBox成功弹出显示"LdrShuffle Execution"

### ✅ 测试2：官方实现 - 成功

**输出**:
```
[UpdateLdr] PEB located at	0x000000DE4CB00000
	[UpdateLdr] PebLdr located at	0x00007FFB40534940
		[UpdateLdr][94724] - identified DLL at 	0x00007FFB3D7A0000
		[UpdateLdr][94724] - backup entry point:	0x00007FFB3D82A1E0
		[UpdateLdr][94724] - new entry point:	0x00007FF67F711550
		[UpdateLdr][94724] - pDte->OriginalBase:	0x000001EF8B8428A0
[*] Press key to artificially create a new thread.
[*] Created dummy thread to run DummyFn [129784]
	[Runner][129784] - called on module 0x00007FFB3D7A0000 for reason 2
	[Runner][129784] - about to perform call in current thread
	[Runner][129784] - completed
[*] Execution over, return code: 1 (0x0000000000000001)
<PRESS KEY TO EXIT>
	[DummyFn] - thread 129784
```

**验证结果**:
- ✅ PEB定位成功
- ✅ DLL在`0x00007FFB3D7A0000`被识别
- ✅ EntryPoint备份：`0x00007FFB3D82A1E0`
- ✅ 新EntryPoint：`0x00007FF67F711550`（Runner）
- ✅ 线程129784成功触发执行
- ✅ 返回值1（MessageBox点击OK）

## 核心发现

### 1. EntryPoint劫持机制

**修改前**:
```
DllBase:      0x7ffb35f60000  (version.dll基地址)
EntryPoint:   0x7ffb35f61430  (真实DllMain)
OriginalBase: 0x0              (未使用)
```

**修改后**:
```
DllBase:      0x7ffb35f60000  (不变)
EntryPoint:   0x7ff7d8731550  (Runner函数)
OriginalBase: 0x7ffb35f61430  (备份真实DllMain)
```

### 2. 调用栈分析

当Runner被Windows调用时，调用栈看起来完全合法：

```
MessageBoxA()                    ← 我们的恶意API
Runner()                         ← 我们的假DllMain
ntdll!LdrpCallInitRoutine()      ← Windows加载器函数
ntdll!LdrpInitializeThread()     ← Windows线程初始化
ntdll!LdrInitializeThunk()       ← Windows内核转换
kernel32!BaseThreadInitThunk()   ← 线程入口点
ntdll!RtlUserThreadStart()       ← 线程启动例程
```

**关键优势**: 调用栈看起来源自合法的Windows内部机制，而不是可疑的`CreateRemoteThread`。

### 3. Loader Lock考虑

当`DllMain()`被调用时，Loader Lock被持有。某些API会死锁：

**不安全的API**（会死锁）:
- `LoadLibrary` / `LoadLibraryEx`
- `FreeLibrary`
- `GetModuleHandle`（有时）

**安全的API**:
- `VirtualAlloc` / `VirtualProtect`
- `CreateThread`
- `Sleep`
- `MessageBoxA`

**复杂API**（需要`createThread = 1`）:
- `InternetOpenW`
- `HttpSendRequestA`
- 大多数wininet/winhttp函数

### 4. OriginalBase的重用

`OriginalBase`字段在DLL加载后通常不使用。我们重新利用它来存储原始的`EntryPoint`：

```c
// 使得Runner()可以找到并恢复原始EntryPoint
OriginalBase = 原始DllMain地址
```

## 优势与创新

### 优势

1. **无可疑API**:
   - ❌ 无`CreateRemoteThread`
   - ❌ 无`QueueUserAPC`
   - ❌ 无`SetThreadContext`
   - ✅ 仅`CreateThread`（触发用，看起来正常）

2. **干净的调用栈**:
   - 执行源自`ntdll!LdrpCallInitRoutine()`
   - 看起来像合法的DLL初始化
   - 绕过基于调用栈的检测

3. **灵活执行**:
   - 可执行任意API和参数
   - 可在新线程运行（复杂API如wininet）
   - 可代理调用以显示合法性

4. **内存驻留**:
   - 无需将shellcode写入磁盘
   - 所有修改都在内存中
   - 与现有已加载DLL配合工作

### 局限

1. **Loader Lock**: 某些API会死锁
2. **稳定性**: 修改关键DLL可能导致崩溃
3. **时机依赖**: 需要线程创建/销毁来触发
4. **检测面**: PEB结构的内存修改可被EDR监控

## 检测与防御

### 检测方法

1. **PEB/LDR完整性监控**:
   - 哈希所有`_LDR_DATA_TABLE_ENTRY`结构
   - 检测`EntryPoint`更改
   - 监控`OriginalBase`字段修改

2. **调用栈分析**:
   - 虽然调用栈看起来合法，但分析来自`DllMain()`的API调用
   - 标记来自DLL初始化的异常API（网络、加密）
   - 关联线程创建与API调用

3. **内存扫描**:
   - 扫描指向DLL范围外的`EntryPoint`
   - 检查`EntryPoint`不在`.text`节中
   - 与磁盘上的PE头验证

4. **行为监控**:
   - 检测短时间内多次PEB访问
   - 监控`EntryPoint`字段的写入操作
   - 关联DLL加载和线程创建模式

### 防御建议

1. **内核回调**: 使用`PsSetLoadImageNotifyRoutine`监控DLL加载
2. **PEB保护**: 实现PEB/LDR结构的完整性检查
3. **调用栈验证**: 深入分析DllMain中的API调用
4. **行为分析**: 建立正常DLL初始化的基线

## 实现对比

### 我们的简化实现
- ✅ 完整的EntryPoint劫持机制
- ✅ Runner函数代理DllMain
- ✅ MessageBoxA演示执行
- ✅ 完整的LDR entry修改和恢复
- ⚠️ 单进程内执行（未实现跨进程注入）

### 官方完整实现
- ✅ LdrShuffle: 当前进程EntryPoint劫持
- ✅ LdrInject: 跨进程EntryPoint劫持
- ✅ 支持复杂API（wininet/winhttp）
- ✅ Cobalt Strike beacon兼容性修改
- ✅ 选择性线程事件过滤

## 使用场景

### 1. 代码执行原语
在当前进程中执行任意代码，而不触发监控以下内容的EDR/AV：
- `CreateThread`
- `QueueUserAPC`
- `SetThreadContext`

### 2. API代理
使用干净的调用栈调用敏感API（如网络函数）：
- API看起来从Windows加载器调用
- 不是从可疑的shellcode或注入的DLL
- 绕过基于调用栈的检测

### 3. 跨进程注入
使用`PROCESS_VM_READ | PROCESS_VM_WRITE`权限：
- 修改远程进程的`_LDR_DATA_TABLE_ENTRY`
- 注入shellcode
- 等待下一次线程创建/销毁
- Shellcode无需`CreateRemoteThread`即可执行

## 参考资源

- **原始研究**: https://github.com/RWXstoned/LdrShuffle
- **DarkLoadLibrary**: https://github.com/bats3c/DarkLoadLibrary
- **MDSec博客**: [Bypassing Image Load Kernel Callbacks](https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/)
- **Windows Internals**: [DLL Loading](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function)

## 总结

LdrShuffle展示了Windows加载器机制的创新利用方式。通过劫持DLL的EntryPoint，我们可以：
- 执行任意代码且调用栈看起来合法
- 避免使用可疑的线程操作API
- 绕过许多基于调用栈的EDR检测

**当前状态（Windows 11 Build 26100）**:
- ✅ EntryPoint劫持完全有效
- ✅ DLL_THREAD_ATTACH触发机制正常工作
- ✅ PEB/LDR结构修改成功
- ✅ MessageBox执行验证通过

技术41（LdrShuffle）成功通过测试，展示了Windows内部机制的深度利用和创新的代码执行方法。这是进程注入技术演进的又一个里程碑，证明了理解Windows内部原理的重要性。
