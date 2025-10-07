# DLL Notification Injection - DLL 通知回调注入

## 技术概述

DLL Notification Injection 是一种"无线程"（Threadless）进程注入技术，通过手动插入自定义条目到 Windows 内部未文档化的 `LdrpDllNotificationList` 双向链表中实现。当目标进程加载或卸载 DLL 时，会自动触发我们注册的回调函数，从而实现代码执行。

## 核心原理

### Windows DLL 通知机制

Windows 提供了 `LdrRegisterDllNotification` 和 `LdrUnregisterDllNotification` API，允许进程注册回调函数来监听 DLL 加载/卸载事件。这些回调存储在 ntdll.dll 的 `LdrpDllNotificationList` 全局链表中。

### 注入流程

```
1. 获取 LdrpDllNotificationList 头地址
   ├─ 注册临时回调（LdrRegisterDllNotification）
   ├─ Cookie 就是 LDR_DLL_NOTIFICATION_ENTRY 指针
   ├─ Cookie->List.Flink 指向链表头
   └─ 注销临时回调（LdrUnregisterDllNotification）

2. 分配远程内存
   ├─ Trampoline Shellcode（Thread Pool Worker）
   ├─ Restore Prologue（恢复链表指针）
   └─ Payload Shellcode（calc.exe）

3. 构造 LDR_DLL_NOTIFICATION_ENTRY
   ├─ Callback = &TrampolineShellcode
   ├─ List.Flink = 原第一个条目地址
   └─ List.Blink = 链表头地址

4. 手动插入链表
   ├─ 修改链表头的 Flink 指向新条目
   └─ 修改原第一个条目的 Blink 指向新条目

5. 等待触发
   └─ 目标进程加载/卸载 DLL 时自动调用 Callback
```

## 关键数据结构

### LDR_DLL_NOTIFICATION_ENTRY

```c
typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY List;                           // 双向链表节点
    PLDR_DLL_NOTIFICATION_FUNCTION Callback;   // 回调函数指针
    PVOID Context;                             // 上下文数据
} LDR_DLL_NOTIFICATION_ENTRY, *PLDR_DLL_NOTIFICATION_ENTRY;
```

### 链表插入图示

```
插入前:
  Head <-> Entry1 <-> Entry2 <-> ... <-> Head

插入后:
  Head <-> NewEntry <-> Entry1 <-> Entry2 <-> ... <-> Head
       ↑            ↑
       |            |
  Head.Flink    Entry1.Blink
```

## Shellcode 组件

### 1. Trampoline Shellcode (~500 字节)

使用 [@C5pider](https://github.com/Cracked5pider) 的 [ShellcodeTemplate](https://github.com/Cracked5pider/ShellcodeTemplate) 项目创建：

- 保存寄存器上下文
- 调用 `TpAllocWork` 创建线程池工作项
- 在新线程中执行 Restore Prologue + Payload
- 恢复寄存器并返回

### 2. Restore Prologue (53 字节)

恢复链表指针，消除痕迹：

```asm
push r14
mov r14, <Head.Flink 地址>
mov dword ptr [r14], <原第一个条目低32位>
mov dword ptr [r14+4], <原第一个条目高32位>
mov r14, <Entry1.Blink 地址>
mov dword ptr [r14], <原链表头地址低32位>
mov dword ptr [r14+4], <原链表头地址高32位>
pop r14
```

### 3. Payload Shellcode (276 字节)

弹出 calc.exe 的 shellcode（来自 [Sektor7](https://institute.sektor7.net/)）。

## 编译与使用

### Windows (build.bat)

```batch
build.bat
```

### Linux/Git Bash (build.sh)

```bash
chmod +x build.sh
./build.sh
```

### 运行

```cmd
build\dll_notification_injection.exe <目标进程名>

示例:
build\dll_notification_injection.exe explorer.exe
build\dll_notification_injection.exe RuntimeBroker.exe
```

## 推荐目标进程

从测试来看，以下进程经常触发 DLL 加载/卸载事件：

1. **explorer.exe** - Windows 资源管理器（推荐）
2. **RuntimeBroker.exe** - Windows 运行时代理
3. **svchost.exe** - 某些服务宿主进程

**注意**: 不是所有进程都频繁加载 DLL，需要提前筛选合适的目标。

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **内存保护**
   - ❌ 当前使用 RWX（读写执行）
   - ✅ 改为 RW → RX（先写入再修改为只读执行）

2. **API 调用**
   - ❌ OpenProcess / ReadProcessMemory / WriteProcessMemory
   - ✅ 使用 NtOpenProcess / NtReadVirtualMemory / NtWriteVirtualMemory
   - ✅ Indirect Syscalls 或 HWSyscalls

3. **Shellcode 混淆**
   - ❌ 明文 shellcode 存储
   - ✅ 加密 shellcode（AES/XOR）
   - ✅ 修改 ShellcodeTemplate 默认哈希值

4. **链表完整性**
   - ✅ 已实现 Restore Prologue
   - ✅ 执行后自动恢复链表指针

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **内存监控** | 检测 ntdll.dll 内部数据段的异常写入（LdrpDllNotificationList） |
| **回调验证** | 枚举 LdrpDllNotificationList，验证所有 Callback 地址是否在合法模块内 |
| **行为分析** | 监控异常的 DLL 加载/卸载触发模式 |
| **API Hook** | Hook LdrRegisterDllNotification，记录所有注册的回调 |
| **完整性检查** | 定期验证系统 DLL 的回调链表是否被篡改 |

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ Threadless | 不使用 CreateRemoteThread/QueueUserAPC/SetThreadContext |
| ✅ 隐蔽性高 | 手动操作内部链表，绕过常规 API 监控 |
| ✅ 自动触发 | 等待目标进程自然加载 DLL 时触发 |
| ✅ 自清理 | Restore Prologue 恢复链表状态 |
| ❌ 目标受限 | 需要选择频繁加载 DLL 的进程 |
| ❌ 版本依赖 | LdrpDllNotificationList 地址可能因 Windows 版本变化 |

## 技术来源

- **原作者**: [@Dec0ne](https://github.com/Dec0ne) (ShorSec)
- **原仓库**: [ShorSec/DllNotificationInjection](https://github.com/ShorSec/DllNotificationInjection)
- **博客文章**: [DLL Notification Injection - ShorSec Blog](https://shorsec.io/blog/dll-notification-injection/)
- **Trampoline**: [@C5pider](https://github.com/Cracked5pider) 的 [ShellcodeTemplate](https://github.com/Cracked5pider/ShellcodeTemplate)
- **Shellcode**: [Sektor7](https://institute.sektor7.net/) 提供的 calc.exe shellcode

## 致谢

- [@C5pider](https://twitter.com/C5pider) - ShellcodeTemplate 项目和 Havoc C2
- [Yxel](https://github.com/janoglezcampos) 和 [@Idov31](https://twitter.com/Idov31) - [Cronos](https://github.com/Idov31/Cronos) 的二进制模式匹配代码
- [@modexpblog](https://twitter.com/modexpblog) - [DLL Notification 结构定义](https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/#dll)
- [@NinjaParanoid](https://twitter.com/NinjaParanoid) - [TpWorkCallback 博客](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)
- [@onlymalware](https://twitter.com/onlymalware) - [UnregisterAllLdrRegisterDllNotification POC](https://github.com/rad9800/misc/blob/main/bypasses/UnregisterAllLdrRegisterDllNotification.c)
- [@x86matthew](https://twitter.com/x86matthew) 和 [@Kharosx0](https://twitter.com/Kharosx0) - GetNtdllBase() 函数建议

## 参考链接

- [DLL Notification Callbacks - modexp](https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/)
- [Proxying DLL Loads - 0xdarkvortex](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)
- [ShellcodeTemplate - Cracked5pider](https://github.com/Cracked5pider/ShellcodeTemplate)
- [Cronos - Idov31](https://github.com/Idov31/Cronos)
