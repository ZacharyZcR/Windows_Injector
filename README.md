# Windows 进程注入技术集合

全面收集 41 种 Windows 进程注入技术的 C 语言实现，涵盖经典方法到前沿研究。

## 项目介绍

本仓库包含 Windows 进程注入技术的完整实现，从基础概念到高级规避方法系统化组织。每个技术都是独立实现，配有详细文档，解释底层机制、检测策略和实际应用。

**这不是渗透测试框架**。不是红队工具包。这是用于理解 Windows 内部机制、安全研究和防御性编程的参考实现。

## 项目统计

- **41 种技术实现**: 100% 真实可用代码
- **编程语言**: 纯 C 语言，最小化依赖
- **目标平台**: Windows x64（部分支持 x86）
- **构建系统**: MinGW/GCC 兼容

## 技术分类

### 经典注入技术 (1-10)
每个 Windows 安全研究者都应该掌握的基础技术：
- CreateRemoteThread 注入
- NtCreateThreadEx 注入
- QueueUserAPC 注入
- SetThreadContext 劫持
- RtlCreateUserThread
- SetWindowsHookEx 挂钩
- 进程镂空（Process Hollowing）
- 线程劫持
- 反射式 DLL 注入
- 模块覆写

### 内存操作技术 (11-20)
高级内存操作技术：
- 手动映射（Manual Mapping）
- PE 注入变体
- AtomBombing
- PROPagate 注入
- 额外窗口内存注入
- DoubleAgent
- CLIPBRDWNDCLASS 注入
- 进程伪装（Process Doppelgänging）
- 事务镂空（Transacted Hollowing）
- 进程篡改（Process Herpaderping）

### Shellcode 执行技术 (21-30)
直接 shellcode 执行原语：
- Early Bird APC 注入
- 线程池等待回调
- Fiber 执行
- 线程本地存储回调
- ALPC 回调注入
- Windows 通知设施
- KernelCallbackTable 操纵
- APC 注入系列
- 服务操纵

### 现代规避技术 (31-41)
来自最新安全研究的前沿技术：
- Ghost Writing（幽灵写入）
- PoolParty 变体（TP_WORK, TP_DIRECT, TP_WAIT, TP_TIMER, TP_IO, TP_JOB, TP_ALPC）
- 等待线程劫持（Waiting Thread Hijacking）
- RedirectThread（ROP Gadget + DLL 指针注入）
- LdrShuffle（入口点劫持）

## 项目结构

```
Injection/
├── techniques/
│   ├── 01-createremotethread/
│   ├── 02-ntcreatethreadex/
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
- **build.bat**: 独立构建脚本
- **README.md**: 详细技术文档
- **可执行文件**: 编译后的二进制文件

## 构建说明

### 前置要求
- MinGW-w64（Windows 版 GCC）
- Windows SDK 头文件

### 构建单个技术
```batch
cd techniques\01-createremotethread
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

- **README.md**: 本文件 - 项目概览
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

## 致谢

本项目的存在离不开安全社区的开创性研究。我们深深感谢：

### 核心研究参考

**经典注入技术**:
- [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) - Microsoft 官方文档
- [NtCreateThreadEx](https://undocumented.ntinternals.net/) - 未公开的 NT API
- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection) by @stephenfewer

**内存操作技术**:
- [Process Hollowing](https://github.com/m0n0ph1/Process-Hollowing) by @m0n0ph1
- [AtomBombing](https://github.com/BreakingMalwareResearch/atom-bombing) by BreakingMalware Research
- [PROPagate](https://github.com/hexacorn/PROPagate) by @hexacorn
- [DoubleAgent](https://github.com/Cybellum/DoubleAgent) by Cybellum
- [Process Doppelgänging](https://github.com/hasherezade/process_doppelganging) by @hasherezade
- [Transacted Hollowing](https://github.com/hasherezade/transacted_hollowing) by @hasherezade
- [Process Herpaderping](https://github.com/jxy-s/herpaderping) by @jxy-s

**高级规避技术**:
- [Ghost Writing](https://github.com/c5pider/Ghost-Writing-Injection) by @c5pider
- [PoolParty](https://github.com/SafeBreach-Labs/PoolParty) by SafeBreach Labs（TP_WORK, TP_WAIT, TP_TIMER, TP_IO, TP_JOB, TP_ALPC, TP_DIRECT）
- [Waiting Thread Hijacking](https://github.com/hasherezade/waiting_thread_hijacking) by @hasherezade
- [RedirectThread](https://github.com/Friends-Security/RedirectThread) by Friends-Security
- [LdrShuffle](https://github.com/RWXstoned/LdrShuffle) by @RWXstoned

**研究论文与文章**:
- [Windows Process Injection in 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf) - Black Hat 2019
- [Injection on Steroids](https://www.youtube.com/watch?v=6nZw5qLYMm4) - DEF CON 23
- [Modern Windows Kernel Exploitation](https://www.youtube.com/watch?v=MJZoy2q5WdA) - Offensive Security Research

**工具灵感来源**:
- [Windows Kernel Explorer](https://github.com/AxtMueller/Windows-Kernel-Explorer) by @AxtMueller
- [Process Hacker](https://github.com/processhacker/processhacker) - 进程检查工具
- [PE-bear](https://github.com/hasherezade/pe-bear) by @hasherezade - PE 分析工具

### 特别感谢

- **@hasherezade**: 在 Process Doppelgänging、Transacted Hollowing 和 Waiting Thread Hijacking 方面的开创性研究
- **SafeBreach Labs**: 提供全面的 PoolParty 技术套件
- **@RWXstoned**: 创新的 LdrShuffle 入口点劫持技术
- **Friends-Security**: RedirectThread 和仅上下文注入研究
- **@stephenfewer**: Reflective DLL Injection，现代内存执行的基础
- **BreakingMalware Research**: AtomBombing 和创造性地使用 Windows 机制
- **Microsoft**: 全面的 Windows 内部机制文档

### 社区资源

- [Pinvoke.net](http://pinvoke.net/) - Win32 API 参考
- [Undocumented NT Functions](http://undocumented.ntinternals.net/)
- [Windows Internals Book Series](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) by Mark Russinovich

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

## 许可证

本项目用于教育目的。各个技术可能有不同的许可证 - 详见各技术的 README。

---

**研究、学习、防御。**
