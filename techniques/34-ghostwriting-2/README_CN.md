# Ghostwriting-2 注入技术

## 概述

Ghostwriting-2 是原始 [ghostwriting](https://github.com/c0de90e7/GhostWriting) 技术的重大改进版本。该技术仅使用 `OpenThread`、`GetThreadContext`、`SetThreadContext`、`SuspendThread` 和 `ResumeThread` API 实现线程注入，完全避免了 `WriteProcessMemory`、`CreateRemoteThread`、`QueueUserAPC` 等常见注入API。

## 技术特点

### 相比原始版本的改进

1. **仅需线程ID (TID)**：不需要窗口句柄 (HWND)，可以注入后台进程
2. **无RWX内存**：不使用可读写执行内存，原始版本需要在栈上执行代码
3. **线程不被牺牲**：原始线程可以恢复并继续运行
4. **显著降低复杂度**：Gadget 搜索大大简化
5. **快速执行**：通过命名管道传输 shellcode，不受大小限制，<1秒完成注入
6. **无栈大小限制**：使用堆而非栈，支持任意大小 shellcode

### 核心机制

**数据结构层面**：
- 核心数据流：ROP gadgets → 线程上下文 → 命名管道 → shellcode
- 数据所有权清晰：通过线程上下文劫持控制流
- 零数据复制：使用命名管道直接传输大型 shellcode

**使用的 Gadgets**：
1. `push edx; call eax` - 执行 ROP 链
2. `jmp $` - 阻塞线程等待
3. `ret` - 返回继续执行

## 执行流程

```
1. 查找 gadgets (ntdll.dll, kernelbase.dll)
   ↓
2. 设置 EIP 到 jmp $ gadget，阻塞目标线程
   ↓
3. 等待线程退出内核态（监控 usermode time）
   ↓
4. 推送命名管道名称到栈
   ↓
5. 通过 ROP 调用 CreateFileA 连接管道
   ↓
6. 通过 ROP 调用 VirtualAlloc 分配 RW 内存
   ↓
7. 构建 ROP 链：ReadFile → CloseHandle → VirtualProtect → CreateThread
   ↓
8. 通过管道写入 shellcode
   ↓
9. 执行 ROP 链读取 shellcode 并创建线程
   ↓
10. 恢复原始线程上下文
```

## 检测规避特性

- ✅ 无 `WriteProcessMemory` 调用
- ✅ 无 `CreateRemoteThread` 调用
- ✅ 无 `QueueUserAPC` 调用
- ✅ 无 RWX 内存区域
- ✅ 纯基于合法线程上下文操作
- ✅ 使用系统常见 API (CreateFileA, VirtualAlloc, VirtualProtect, CreateThread)

## 系统要求

**⚠️ 重要：此技术专为 x86 (32位) 架构设计**

- **架构**：x86 (32位) - 依赖 32位寄存器 (EIP, ESP, EAX, EDX)
- **Windows 版本**：
  - ✅ Windows 7 SP1 (build 7601) - 完全测试
  - ✅ Windows 10 22H2 (build 19045) - 完全测试
  - ⚠️ Windows 8.1 (build 9600) - 可能缺少必需的 gadget
  - ✅ Windows 11 (build 22621) - 理论支持

## 编译

### 方法1：使用 Makefile (推荐)

```bash
# 需要 i686-w64-mingw32-gcc (32位 MinGW)
make
```

### 方法2：手动编译

```bash
i686-w64-mingw32-gcc ghost.c -o build/ghost.exe
```

### ⚠️ 注意事项

本项目主体使用 x64 架构，而此技术需要 x86。如果系统中没有 32位 MinGW 编译器，需要：

1. 在 32位 Windows 环境下编译，或
2. 安装 32位交叉编译工具链，或
3. 使用虚拟机/WSL 等环境

## 使用方法

```bash
# 1. 找到目标进程的线程 ID
# 可使用 Process Explorer、tasklist 等工具

# 2. 执行注入
ghost.exe [thread_id]
```

### 示例

```bash
# 注入到线程 ID 1234
ghost.exe 1234
```

**注意**：注入期间目标进程会短暂冻结（<1秒），GUI程序可能显示无响应。

## 技术限制

1. **仅支持 x86**：无法直接用于 x64 进程（需要完全重写）
2. **Gadget 依赖**：某些 Windows 版本可能缺少必需的 gadget
3. **GUI 冻结**：注入 GUI 程序时会短暂冻结，可能引起怀疑
4. **需要线程 ID**：必须先获取目标线程 ID

## 代码文件

- `ghost.c` - 主程序
- `helpers.h` - Gadget 搜索和 ROP 辅助函数
- `shellcode.h` - 示例 shellcode (MessageBox)
- `Makefile` - 编译配置
- `README.md` - 原始英文说明
- `README_CN.md` - 中文说明（本文件）

## 参考资料

- 原始 Ghostwriting 技术: https://github.com/c0de90e7/GhostWriting
- 原始 Ghostwriting-2 仓库: https://github.com/fern89/ghostwriting-2

## 安全研究声明

此代码仅用于安全研究和教育目的。技术展示了如何通过非常规方式实现代码注入，帮助防御者理解攻击向量并改进检测机制。

## 技术评价（Linus 视角）

**好品味指数**: 🟢🟢🟢🟢 (4/5)

**优点**：
- 消除了原版的所有复杂特殊情况
- 数据结构清晰简洁（TID → Context → Pipe → Shellcode）
- Gadget 选择简单实用（3个基础gadget）
- 命名管道消除了栈大小限制（好设计）

**缺点**：
- 仅限 x86（架构限制，非设计问题）
- Gadget 依赖系统版本（实际约束）

**核心洞察**：
> "通过重新审视数据流和简化 gadget 选择，这个技术把原本需要完整反汇编器的复杂问题变成了简单的模式匹配。这就是好品味。"
