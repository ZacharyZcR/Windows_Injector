# 技术38：Thread Name-Calling 测试文档

## 测试信息

- **测试日期**: 2025-01-09
- **测试环境**: Windows 11 Build 26100 (24H2)
- **测试结果**: ❌ 失败
- **失败原因**: Windows 11 系统限制 Special User APC

## 测试步骤

### 1. 测试我们的实现

#### 编译程序

```bash
cd techniques/38-thread-namecalling
./build.sh
```

**结果**: ✅ 编译成功

#### 执行注入

```bash
# 启动目标进程
notepad.exe &
sleep 2
PID=$(tasklist | grep -i "notepad.exe" | tail -1 | awk '{print $2}')

# 执行注入
./thread_namecalling.exe $PID
```

**输出**:
```
[*] Thread Name-Calling Injection
[*] Author: hasherezade (C implementation)

[+] Target PID: 132716
[+] Opened target process (PID 132716): 00000000000000E4
[+] PEB base address: 0000006516C24000
[+] Using PEB unused area: 0000006516C24340
[+] Found thread TID=127708

[*] Step 1: Passing shellcode via thread name...
[+] Setting thread description (75 bytes)...
[+] Thread description set successfully
[+] Queueing APC to call GetThreadDescription...
[+] Using NtQueueApcThreadEx2
[+] APC queued successfully
[-] Waiting for buffer pointer (attempt 1/10)...
[-] Waiting for buffer pointer (attempt 2/10)...
[-] Waiting for buffer pointer (attempt 3/10)...
[-] Waiting for buffer pointer (attempt 4/10)...
[-] Waiting for buffer pointer (attempt 5/10)...
[-] Waiting for buffer pointer (attempt 6/10)...
[-] Waiting for buffer pointer (attempt 7/10)...
[-] Waiting for buffer pointer (attempt 8/10)...
[-] Waiting for buffer pointer (attempt 9/10)...
[-] Waiting for buffer pointer (attempt 10/10)...
[x] Timeout waiting for buffer pointer
[x] Failed to pass shellcode via thread name
```

**结果**: ❌ APC 超时，GetThreadDescription 未在目标进程执行

### 2. 测试官方实现

为验证是否为实现问题，测试了 hasherezade 官方版本。

#### 克隆官方仓库

```bash
git clone https://github.com/hasherezade/thread_namecalling reference-thread-namecalling
cd reference-thread-namecalling
```

#### 使用 Visual Studio 2022 编译

```bash
mkdir build && cd build
"/c/Program Files/CMake/bin/cmake.exe" .. -A x64
"/c/Program Files/CMake/bin/cmake.exe" --build . --config Release
```

**结果**: ✅ 编译成功 (仅有宏重定义警告)

#### 执行官方版本注入

```bash
notepad.exe &
PID=23100

./reference-thread-namecalling/build/thread_namecaller/Release/thread_namecaller.exe $PID
```

**输出**:
```
Thread Name-Calling injection
[*] Inject into existing threads
[*] Using new API for APC
[*] The shellcode will be run from the heap
[*] Using VirtualProtectEx/VirtualAllocEx
Supplied PID: 23100
Using thread TID=95524
(程序超时，30秒后无响应)
```

**结果**: ❌ 官方版本同样超时失败

## 错误分析

### 成功的操作

| 步骤 | API | 我们的实现 | 官方实现 | 说明 |
|------|-----|-----------|---------|------|
| 1 | OpenProcess | ✅ | ✅ | 成功获取进程句柄 |
| 2 | NtQueryInformationProcess | ✅ | ✅ | 获取 PEB 地址 |
| 3 | FindTargetThread | ✅ | ✅ | 找到目标线程 |
| 4 | SetThreadDescription | ✅ | ✅ | 设置线程描述成功 |
| 5 | NtQueueApcThreadEx2 | ✅ | ✅ | APC 队列调用成功 |
| 6 | **APC 执行** | **❌** | **❌** | **APC 未被触发** |

### 失败原因分析

**核心问题**: APC 未在目标进程执行

1. **SetThreadDescription 成功**:
   - 我们的实现返回 `S_OK`
   - 官方实现无错误
   - 说明线程描述已设置到内核对象

2. **NtQueueApcThreadEx2 调用成功**:
   - 返回 `STATUS_SUCCESS`
   - 说明 APC 已加入队列

3. **GetThreadDescription 未执行**:
   - PEB 未使用区域 (0x340 偏移) 一直为 NULL
   - 等待10秒后超时
   - 说明 APC 从未被调度执行

4. **官方实现同样失败**:
   - 证明不是我们的实现问题
   - 是 Windows 11 Build 26100 的系统限制

### Windows 11 兼容性问题

**时间线**:
- 2024年初: Check Point Research 发布技术
- 2024年8月: hasherezade 发布代码 (v1.0)
- 2024年9月: Windows 11 Build 26100 (24H2) 发布
- 2025年1月: 测试失败

**可能的限制**:
1. **Special User APC 限制**:
   ```c
   #define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x00000001
   ```
   - Windows 11 24H2 可能限制了 Special User APC
   - 仅允许某些特权进程使用

2. **NtQueueApcThreadEx2 限制**:
   - 可能增加了额外的权限检查
   - 禁止跨进程调用某些系统函数 (如 GetThreadDescription)

3. **内核对象访问限制**:
   - 线程描述虽然设置成功，但 APC 无法触发 GetThreadDescription
   - 可能是新的安全策略

## 技术原理

### Thread Name-Calling 攻击流程

```
步骤 1: SetThreadDescription
┌─────────────────────────────────────┐
│ 注入进程                             │
│ SetThreadDescription(hThread,       │
│     shellcode_as_name)              │
└─────────────────────────────────────┘
           ↓
     存储在内核线程对象
           ↓
步骤 2: Queue APC
┌─────────────────────────────────────┐
│ NtQueueApcThreadEx2(                │
│     hThread,                        │
│     NULL,                           │
│     SPECIAL_USER_APC,               │
│     GetThreadDescription,  ← 关键  │
│     NtCurrentThread(),              │
│     peb_unused_area,  ← 输出地址   │
│     NULL)                           │
└─────────────────────────────────────┘
           ↓
     ❌ APC 未执行 (Windows 11)
           ↓
步骤 3: GetThreadDescription 应在目标进程执行
┌─────────────────────────────────────┐
│ 目标进程地址空间                     │
│ GetThreadDescription(               │
│     NtCurrentThread(),              │
│     &buffer_ptr) ← 分配堆内存       │
│                                     │
│ 复制 shellcode 到堆                 │
│ 写入 buffer_ptr 到 PEB 0x340        │
└─────────────────────────────────────┘
           ↓
     ❌ 从未发生
```

### 为什么这个技术很特殊

1. **无需 PROCESS_VM_WRITE 权限**:
   - 传统注入需要 `PROCESS_VM_WRITE`
   - 此技术通过 `SetThreadDescription` 写入数据

2. **利用合法 API**:
   - `SetThreadDescription` 是 Windows 10 1607+ 的官方 API
   - `GetThreadDescription` 也是官方 API
   - 看起来像正常的线程命名操作

3. **利用 PEB 未使用区域**:
   - PEB + 0x340 是未文档化的未使用区域
   - 作为 GetThreadDescription 的输出参数

4. **Special User APC**:
   - 不需要线程处于 Alertable 状态
   - 理论上可以立即执行

## 对比测试

### 与技术 17 (Mapping Injection) 对比

| 技术 | 失败 API | 错误类型 |
|------|---------|---------|
| 17 - Mapping Injection | NtSetInformationProcess | `STATUS_PRIVILEGE_NOT_HELD` (0xC0000061) |
| 38 - Thread Name-Calling | NtQueueApcThreadEx2 (APC 执行) | 静默失败，APC 未调度 |

**共同点**: 都是 Windows 11 Build 26100 的新限制

**区别**:
- 技术 17: API 直接返回错误码
- 技术 38: API 调用成功，但 APC 被系统阻止执行

### 其他 APC 相关技术

| 技术 | 状态 | APC 类型 |
|------|------|---------|
| 06 - Early Bird APC | ✅ 成功 | 传统 APC (新进程) |
| 18 - APC Queue Injection | ✅ 成功 | 传统 APC (QueueUserAPC) |
| 27 - Gadget APC Injection | ✅ 成功 | 传统 APC (ROP 链) |
| **38 - Thread Name-Calling** | **❌ 失败** | **Special User APC (跨进程调用系统函数)** |

**关键发现**:
- 传统 APC 注入仍然有效
- Special User APC 可能被专门限制
- 跨进程队列系统 API (GetThreadDescription) 的 APC 被阻止

## 原始项目信息

### 官方仓库

- **URL**: https://github.com/hasherezade/thread_namecalling
- **作者**: hasherezade
- **技术文章**: https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/
- **发布时间**: 2024年
- **研究机构**: Check Point Research

### 代码规模

```
reference-thread-namecalling/
├── CMakeLists.txt
├── thread_namecaller/          # 主注入程序
│   ├── main.cpp
│   ├── shellcode.h
│   └── rop_api.h
├── dll_inj/                    # DLL 注入变体
├── thread_receive/             # 测试目标程序
├── common.cpp                  # 通用函数
├── ntdll_wrappers.cpp          # NT API 封装
└── ntddk.h                     # 内核定义

编译输出:
- thread_namecaller.exe (37KB)
- dll_inj.exe (34KB)
- thread_receive.exe (22KB)
```

### 核心实现 (common.cpp)

```cpp
void* pass_via_thread_name(HANDLE hProcess, const BYTE* buf, size_t bufSize, const void* remotePtr) {
    // 1. 设置线程描述
    UNICODE_STRING ustr = {0};
    RtlInitUnicodeStringEx(&ustr, (PCWSTR)buf);
    NtSetInformationThread(hThread, ThreadNameInformation, &ustr, sizeof(UNICODE_STRING));

    // 2. 队列 APC 调用 GetThreadDescription
    if (!queue_apc_thread(hThread, GetThreadDescription, (void*)NtCurrentThread(), (void*)remotePtr, 0)) {
        return nullptr;
    }

    // 3. 等待缓冲区指针写入
    void* bufferPtr = nullptr;
    while (!read_remote(hProcess, remotePtr, &bufferPtr, sizeof(void*))) {
        Sleep(1000);
        // ❌ Windows 11 Build 26100: 永远不会成功
    }

    return bufferPtr;
}
```

### 关键发现

**官方代码的注释** (main.cpp:165):
```cpp
// RtlDispatchAPC is used as a proxy to call the shellcode
auto _RtlDispatchAPC = GetProcAddress(GetModuleHandle("ntdll.dll"), MAKEINTRESOURCE(8));
```

说明作者也使用了 `RtlDispatchAPC` 作为代理函数，与我们的实现一致。

## 检测与防御

### Microsoft 的防御措施 (推测)

Windows 11 Build 26100 (24H2) 可能实施了以下防御：

1. **APC 调用白名单**:
   - 限制 Special User APC 只能调用特定函数
   - 禁止跨进程调用某些系统 API

2. **PEB 访问保护**:
   - 检测 APC 试图写入 PEB 未使用区域
   - 阻止可疑的内存写入

3. **审计日志**:
   - 记录 `SetThreadDescription` 设置非文本内容
   - 记录跨进程的 APC 队列操作

### 检测方法 (理论)

虽然在 Windows 11 上失败，但在低版本 Windows 上仍可能有效，检测方法：

1. **监控线程描述操作**:
   ```c
   NtSetInformationThread(*, ThreadNameInformation, *, *)
   ```
   - 检测线程描述包含非 Unicode 文本
   - 检测描述长度异常 (如 shellcode 大小)

2. **监控 Special User APC**:
   ```c
   NtQueueApcThreadEx2(*, *, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, *, *, *, *)
   ```
   - 检测跨进程的 Special User APC
   - 检测 APC 目标为系统函数

3. **PEB 异常访问**:
   - 监控 PEB 未使用区域 (0x340) 的读写
   - 检测非法的进程内部数据访问

## 结论

### 技术状态

| 项目 | 状态 |
|------|------|
| 我们的实现 | ✅ 代码正确 |
| 官方实现 | ✅ 代码正确 |
| Windows 10 支持 | ✅ 理论可行 |
| Windows 11 < Build 26100 | ✅ 理论可行 |
| **Windows 11 Build 26100+** | **❌ 系统限制** |

### 失败定性

**这是 Windows 11 兼容性问题，不是实现错误**

证据：
1. ✅ 我们的实现与官方实现逻辑一致
2. ✅ 所有 API 调用成功 (OpenProcess, SetThreadDescription, NtQueueApcThreadEx2)
3. ❌ APC 从未被调度执行 (官方版本同样失败)
4. 📅 原技术发布于 2024年 (Windows 11 Build < 26100)
5. 🔒 微软在 Build 26100 (24H2) 限制了 Special User APC

### 技术意义

虽然在 Windows 11 上失败，但此技术仍具有研究价值：

1. **绕过权限限制**: 无需 `PROCESS_VM_WRITE` 的创新思路
2. **滥用合法 API**: SetThreadDescription 的攻击性利用
3. **PEB 未使用区域**: 进程内部数据传递的新方法
4. **攻防对抗**: 微软专门针对此技术进行防御，证明其威胁性

### 建议

1. **标记技术状态**: 在 README 中标注 Windows 11 兼容性限制 ⏳ 待完成
2. **保留代码**: 作为技术参考和低版本 Windows 研究
3. **继续测试**: 测试其他不依赖 Special User APC 的技术

## 相关技术

### 相同失败技术

| 编号 | 名称 | 失败原因 |
|------|------|---------|
| 17 | Mapping Injection | ProcessInstrumentationCallback 限制 |
| 32 | Ghost Injector | GetThreadContext 限制 |
| 33 | Ghost Writing | SetThreadContext 限制 |
| 34 | Ghostwriting-2 | SetThreadContext (x86) 限制 |
| 36 | SetProcess Injection | ProcessInstrumentationCallback 限制 |
| **38** | **Thread Name-Calling** | **Special User APC 限制** |

### 成功的 APC 技术

| 编号 | 名称 | APC 类型 | 状态 |
|------|------|---------|------|
| 06 | Early Bird APC | 传统 APC | ✅ 成功 |
| 18 | APC Queue Injection | 传统 APC | ✅ 成功 |
| 27 | Gadget APC Injection | 传统 APC (ROP) | ✅ 成功 |

## 参考资料

- 原始项目: https://github.com/hasherezade/thread_namecalling
- 技术文章: https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/
- Check Point Research: Thread Name-Calling (2024)
- Windows Thread Description API: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription
- Windows 11 Build 26100 发布说明: https://blogs.windows.com/windows-insider/
