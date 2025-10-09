# Windows 进程注入技术集合

[English](./README_EN.md) | 简体中文

全面收集 41 种 Windows 进程注入技术的 C 语言实现，涵盖经典方法到前沿研究。

> 📖 **核心参考**: 本项目基于 [itaymigdal/awesome-injection](https://github.com/itaymigdal/awesome-injection) 项目中整理的技术列表和研究资料进行实现和测试。

## 项目介绍

本仓库包含 Windows 进程注入技术的完整实现，从基础概念到高级规避方法系统化组织。每个技术都是独立实现，配有详细文档，解释底层机制、检测策略和实际应用。

**这不是渗透测试框架**。不是红队工具包。这是用于理解 Windows 内部机制、安全研究和防御性编程的参考实现。

## 项目统计

- **41 种技术实现**: 100% 真实可用代码
- **编程语言**: 纯 C 语言，最小化依赖
- **目标平台**: Windows x64（部分支持 x86）
- **构建系统**: MinGW/GCC 兼容

## 技术分类

### 进程操纵技术 (1-5)

利用 Windows 进程创建机制的高级攻击：

1. **Process Hollowing** - 进程镂空 ✅
2. **Transacted Hollowing** - 事务镂空 ✅
3. **Process Doppelgänging** - 进程伪装 ❌
4. **Process Herpaderping** - 进程篡改 ✅
5. **Process Ghosting** - 进程幽灵化 ✅

### 早期执行和回调技术 (6-10)

在进程/线程初始化阶段劫持执行流：

6. **Early Bird APC** - 早期鸟 APC 注入 ✅
7. **Entry Point Injection** - 入口点注入 ✅
8. **DLL Blocking (Ruy-Lopez)** - DLL 阻断注入 ✅
9. **Early Cascade** - 早期级联注入 ✅
10. **Kernel Callback Table** - 内核回调表注入 ✅

### 经典注入技术 (11-20)

Windows 注入技术的基础方法：

11. **Advanced Hollowing** - 高级镂空 ✅
12. **DLL Injection** - DLL 注入 ✅
13. **Shellcode Injection** - Shellcode 注入 ✅
14. **SetWindowsHookEx** - 钩子注入 ✅
15. **Reflective DLL Injection** - 反射式 DLL 注入 ✅
16. **PE Injection** - PE 注入 ✅
17. **Mapping Injection** - 映射注入 ❌
18. **APC Queue Injection** - APC 队列注入 ✅
19. **Thread Hijacking** - 线程劫持 ✅
20. **Atom Bombing** - 原子轰炸 ❌

### 高级规避技术 (21-31)

绕过现代安全防护的创新方法：

21. **Mockingjay** - RWX 节区注入 ✅
22. **PowerLoaderEx** - 共享桌面堆注入 ❌
23. **Threadless Inject** - 无线程注入 ✅
24. **EPI** - DLL 入口点劫持注入 ✅
25. **DLL Notification Injection** - DLL 通知回调注入 ✅
26. **Module Stomping** - 模块践踏注入 ✅
27. **Gadget APC Injection** - Gadget APC 注入 ✅
28. **Process Forking (Dirty Vanity)** - 进程分叉注入 ✅
29. **Function Stomping** - 函数践踏注入 ✅
30. **Caro-Kann** - 加密 Shellcode 内存扫描规避 ⚠️
31. **Stack Bombing** - 栈轰炸注入 ⚠️

### 现代前沿技术 (32-41)

2023-2024 年最新安全研究成果：

32. **GhostInjector** - 幽灵注入器 ❌
33. **GhostWriting** - 幽灵写入 ❌
34. **GhostWriting-2** - 改进版幽灵写入 ❌
35. **Mapping Injection** - 映射注入（增强版）
36. **SetProcessInjection** - ProcessInstrumentationCallback 注入
37. **PoolParty** - Windows 线程池注入（TP_WORK/TP_WAIT/TP_TIMER/TP_IO/TP_JOB/TP_ALPC/TP_DIRECT）✅
38. **Thread Name-Calling** - 线程名称注入 ❌
39. **Waiting Thread Hijacking** - 等待线程劫持 ✅
40. **RedirectThread** - CONTEXT-Only 注入（ROP Gadget + DLL 指针注入）⚠️
41. **LdrShuffle** - EntryPoint 劫持 ✅

## 项目结构

```
Injection/
├── techniques/
│   ├── 01-process-hollowing/
│   ├── 02-transacted-hollowing/
│   ├── ...
│   └── 41-ldrshuffle/
│       ├── src/
│       │   └── ldrshuffle.c
│       ├── build.bat
│       └── README.md
├── README.md
└── TECHNIQUE_VERIFICATION.md
```

每个技术目录包含：
- **src/**: 完整源代码实现
- **build.bat/build.sh**: 独立构建脚本
- **README.md**: 详细技术文档
- **可执行文件**: 编译后的二进制文件

## 构建说明

### 前置要求
- MinGW-w64（Windows 版 GCC）
- Windows SDK 头文件

### 构建单个技术
```batch
cd techniques\01-process-hollowing
build.bat
```

### 构建所有技术
```batch
for /d %d in (techniques\*) do (
    if exist "%d\build.bat" (
        cd "%d" && call build.bat && cd ..\..
    )
)
```

## 使用方法

每个技术都是独立可执行文件，演示注入方法：

```batch
cd techniques\41-ldrshuffle
ldrshuffle.exe
```

大多数实现包含：
- **详细输出**: 显示注入过程的每一步
- **错误处理**: 解释操作失败的原因
- **安全检查**: 执行前验证前置条件

## 文档说明

- **README.md**: 本文件 - 项目概览（中文）
- **README_EN.md**: 英文版项目概览
- **TECHNIQUE_VERIFICATION.md**: 所有 41 种技术的详细技术分解
- **techniques/XX-name/README.md**: 单个技术的深入解析，包含执行流程图

## 安全声明

**本仓库仅用于教育和防御性安全研究。**

这些技术的实现目的是：
- 理解 Windows 安全内部机制
- 开发检测策略
- 改进端点保护
- 培训安全专业人员

未经授权使用这些技术进行非法访问是违法和不道德的。

## 参考仓库

本项目的每个技术都基于原始研究实现。以下是所有参考仓库的完整列表（按技术编号排序）：

### 进程操纵技术 (1-5)
1. [m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing) - Process Hollowing
2. [hasherezade/transacted_hollowing](https://github.com/hasherezade/transacted_hollowing) - Transacted Hollowing
3. [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) - Process Doppelgänging
4. [jxy-s/herpaderping](https://github.com/jxy-s/herpaderping) - Process Herpaderping
5. [hasherezade/process_ghosting](https://github.com/hasherezade/process_ghosting) - Process Ghosting

### 早期执行和回调技术 (6-10)
6. [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) - Early Bird APC (包含 Ruy-Lopez/HookForward)
7. [diversenok/Suspending-Techniques](https://github.com/diversenok/Suspending-Techniques) - Entry Point Injection (AddressOfEntryPoint-injection)
8. [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) - DLL Blocking (包含 Ruy-Lopez/DllBlock)
9. [Cracked5pider/earlycascade-injection](https://github.com/Cracked5pider/earlycascade-injection) - Early Cascade
10. [0xHossam/KernelCallbackTable-Injection-PoC](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC) - Kernel Callback Table

### 经典注入技术 (11-20)
11. [itaymigdal/PichichiH0ll0wer](https://github.com/itaymigdal/PichichiH0ll0wer) - Advanced Hollowing
12. [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - DLL Injection (也用于反射式DLL注入)
13. [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) - Shellcode Injection (参考)
14. [hfiref0x/WinObjEx64](https://github.com/hfiref0x/WinObjEx64) - SetWindowsHookEx (参考)
15. [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - Reflective DLL Injection
16. [AlSch092/PE-Injection](https://github.com/AlSch092/PE-Injection) - PE Injection
17. [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) - Mapping Injection (参考)
18. [0xflux/Rust-APC-Queue-Injection](https://github.com/0xflux/Rust-APC-Queue-Injection) - APC Queue Injection (Rust)
19. [BreakingMalwareResearch/atom-bombing](https://github.com/BreakingMalwareResearch/atom-bombing) - Thread Hijacking
20. [BreakingMalwareResearch/atom-bombing](https://github.com/BreakingMalwareResearch/atom-bombing) - Atom Bombing

### 高级规避技术 (21-31)
21. [caueb/Mockingjay](https://github.com/caueb/Mockingjay) - Mockingjay
22. [BreakingMalware/PowerLoaderEx](https://github.com/BreakingMalware/PowerLoaderEx) - PowerLoaderEx
23. [CCob/ThreadlessInject](https://github.com/CCob/ThreadlessInject) - Threadless Inject
24. [Kudaes/EPI](https://github.com/Kudaes/EPI) - EPI
25. [Dec0ne/DllNotificationInjection](https://github.com/Dec0ne/DllNotificationInjection) 和 [ShorSec/DllNotificationInjection](https://github.com/ShorSec/DllNotificationInjection) - DLL Notification Injection
26. [d1rkmtrr/D1rkInject](https://github.com/d1rkmtrr/D1rkInject) - Module Stomping
27. [LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection](https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection) - Gadget APC Injection
28. [deepinstinct/Dirty-Vanity](https://github.com/deepinstinct/Dirty-Vanity) - Process Forking
29. [Idov31/FunctionStomping](https://github.com/Idov31/FunctionStomping) - Function Stomping
30. [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) - Caro-Kann
31. [maziland/StackBombing](https://github.com/maziland/StackBombing) - Stack Bombing

### 现代前沿技术 (32-41)
32. [woldann/GhostInjector](https://github.com/woldann/GhostInjector) - GhostInjector (依赖: NThread, NThreadOSUtils, Neptune)
33. [c0de90e7/GhostWriting](https://github.com/c0de90e7/GhostWriting) - GhostWriting
34. [fern89/ghostwriting-2](https://github.com/fern89/ghostwriting-2) - GhostWriting-2
35. [antonioCoco/Mapping-Injection](https://github.com/antonioCoco/Mapping-Injection) - Mapping Injection (增强版)
36. [OtterHacker/SetProcessInjection](https://github.com/OtterHacker/SetProcessInjection) - SetProcessInjection
37. [SafeBreach-Labs/PoolParty](https://github.com/SafeBreach-Labs/PoolParty) - PoolParty
38. [hasherezade/thread_namecalling](https://github.com/hasherezade/thread_namecalling) - Thread Name-Calling
39. [hasherezade/waiting_thread_hijacking](https://github.com/hasherezade/waiting_thread_hijacking) - Waiting Thread Hijacking
40. [Friends-Security/RedirectThread](https://github.com/Friends-Security/RedirectThread) - RedirectThread
41. [RWXstoned/LdrShuffle](https://github.com/RWXstoned/LdrShuffle) - LdrShuffle

## 特别感谢

### 核心参考项目
- **[itaymigdal/awesome-injection](https://github.com/itaymigdal/awesome-injection)** - 本项目的核心参考资源，提供了全面的Windows进程注入技术列表和研究方向。我们的41种技术实现主要基于该项目整理的技术分类和参考资料。

### 研究者与组织
- **@hasherezade** - 在 Windows 进程注入领域的多项开创性研究（Process Doppelgänging, Transacted Hollowing, Process Ghosting, Waiting Thread Hijacking, Thread Name-Calling）
- **SafeBreach Labs** - PoolParty 技术套件的完整实现
- **@RWXstoned** - LdrShuffle EntryPoint 劫持技术
- **Friends-Security** - RedirectThread CONTEXT-Only 注入研究
- **@stephenfewer** - Reflective DLL Injection，现代内存注入的基石
- **BreakingMalware Research** - AtomBombing 和 PowerLoaderEx
- **@jxy-s** - Process Herpaderping 时序攻击
- **@m0n0ph1** - Process Hollowing 经典实现
- **@CCob** - Threadless Inject 无线程注入
- **@Idov31** - Function Stomping 技术
- **@S3cur3Th1sSh1t** - Caro-Kann 加密规避
- **@antonioCoco** - Mapping Injection 增强版
- **所有其他研究者** - 在各自领域的贡献

### 社区资源
- [Pinvoke.net](http://pinvoke.net/) - Win32 API 参考
- [Undocumented NT Functions](http://undocumented.ntinternals.net/)
- [Windows Internals Book Series](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) by Mark Russinovich
- [Black Hat 2019 - Process Injection Techniques](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf)
- [DEF CON 23 - Injection on Steroids](https://www.youtube.com/watch?v=6nZw5qLYMm4)

### 开发工具
本项目使用 **[Claude Code](https://claude.com/claude-code)** 开发，这是 Anthropic 的官方 AI 编程助手。Claude Code 在以下方面提供了关键支持：
- 代码实现和调试
- 技术文档编写
- 项目结构组织
- 安全最佳实践建议

## 为什么选择 C 语言？

- **最小化依赖**: 无运行时、无框架，只有 Windows API
- **透明性**: 每个操作都是显式的
- **教育性**: 准确展示 API 层面发生的事情
- **可移植性**: 适用于任何 C 编译器（MinGW、MSVC、Clang）

## 发展路线

本项目已完成 41 种技术的实现。未来可能包括：

- [ ] ARM64 Windows 支持
- [ ] 内核模式注入技术
- [ ] 增强的检测规避分析
- [ ] 性能基准测试套件

## 贡献指南

欢迎以下贡献：
- 现有实现的 bug 修复
- 文档改进
- 新技术实现（需附原始研究归属）
- 检测策略增强

请确保：
1. 代码能用 MinGW-w64 编译
2. 新技术配有详细的 README.md
3. 正确归属研究来源
4. 在 Windows 10/11 上测试

## 测试状态

**测试环境**: Windows 10 Build 26100 (MSYS_NT-10.0-26100 x86_64), GCC (MinGW64)

| 状态 | 含义 |
|-----|------|
| ✅ | 测试成功或完整文档 |
| ❌ | 测试失败或技术已失效 |
| ⚠️ | 部分实现/跳过/需要特殊环境 |

### 已测试技术

**进程操纵技术 (1-5)**:
- **01. Process Hollowing** ✅ - 完整技术文档（手动PE节写入 + PEB ImageBase更新）
- **02. Transacted Hollowing** ✅ - 完整技术文档（NTFS事务 + SEC_IMAGE节映射）
- **03. Process Doppelgänging** ❌ - Windows 10+ 已失效 (NtCreateThreadEx 返回 ACCESS_DENIED)
- **04. Process Herpaderping** ✅ - 镜像节缓存机制有效
- **05. Process Ghosting** ✅ - 删除待处理文件机制有效

**早期执行和回调技术 (6-10)**:
- **06. Early Bird APC** ✅ - 挂起进程 APC 注入成功
- **07. Entry Point Injection** ✅ - 入口点劫持成功
- **08. DLL Blocking** ✅ - 完整技术文档（NtCreateSection Hook + Egg替换机制）
- **09. Early Cascade** ✅ - PROCESS_CREATE_FLAGS_INHERIT_HANDLES + memset 成功
- **10. Kernel Callback Table** ✅ - PEB KernelCallbackTable 劫持成功

**经典注入技术 (11-20)**:
- **11. Advanced Hollowing** ✅ - 改进版镂空成功
- **12. DLL Injection** ✅ - LoadLibrary 注入成功
- **13. Shellcode Injection** ✅ - VirtualAllocEx + WriteProcessMemory 成功
- **14. SetWindowsHookEx** ✅ - 消息钩子注入成功
- **15. Reflective DLL Injection** ✅ - 反射式加载成功
- **16. PE Injection** ✅ - 完整技术文档（自复制PE注入 + 影子进程）
- **17. Mapping Injection** ❌ - Windows 10+ 已失效
- **18. APC Queue Injection** ✅ - 用户模式 APC 队列成功
- **19. Thread Hijacking** ✅ - 线程上下文劫持成功
- **20. Atom Bombing** ❌ - Windows 10+ 已失效

**高级规避技术 (21-31)**:
- **21. Mockingjay** ✅ - RWX 节区利用成功（msys-2.0.dll）
- **22. PowerLoaderEx** ❌ - Windows 10 桌面堆结构变更，已失效
- **23. Threadless Inject** ✅ - Hook 函数触发成功
- **24. EPI** ✅ - DLL 入口点劫持成功
- **25. DLL Notification Injection** ✅ - LdrDllNotification 回调成功
- **26. Module Stomping** ✅ - amsi.dll NtOpenFile 覆盖成功
- **27. Gadget APC Injection** ✅ - ntdll.dll gadget 利用成功
- **28. Process Forking** ✅ - RtlCreateProcessReflection 成功
- **29. Function Stomping** ✅ - CreateFileW PAGE_EXECUTE_WRITECOPY 成功
- **30. Caro-Kann** ⚠️ - 跳过（需要 NASM + MinGW-w64 + API Hashing）
- **31. Stack Bombing** ⚠️ - 部分实现（原版 POC 问题 + 可能失效）

**现代前沿技术 (32-41)**:
- **37. PoolParty** ✅ - TP_WORK 远程插入成功（SafeBreach Labs 官方实现）
- **38. Thread Name-Calling** ❌ - Windows 11 Build 26100 限制 Special User APC（SetThreadDescription APC 超时）
- **39. Waiting Thread Hijacking** ✅ - WrQueue 线程栈返回地址劫持成功（ASLR 会话级一致性验证）
- **40. RedirectThread** ⚠️ - DLL指针注入成功，NtCreateThread + ROP受Windows 11限制（CreateRemoteThread + SetThreadContext有效）
- **41. LdrShuffle** ✅ - PEB LDR EntryPoint劫持成功（DLL_THREAD_ATTACH触发，干净调用栈）

详细测试报告见 `docs/testing-guides/` 目录。

## 许可证

本项目用于教育目的。各个技术可能有不同的许可证 - 详见各技术的 README。

---

**研究、学习、防御。**
