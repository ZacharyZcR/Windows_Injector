# Function Stomping（函数践踏注入）

## 技术概述

Function Stomping 是一种受 Module Stomping 启发的代码注入技术。与 Module Stomping 覆盖整个模块不同，Function Stomping 仅覆盖目标模块中的**单个函数**，使得目标进程仍可正常使用该模块的其他函数。这种精准的覆盖方式大幅降低了对目标进程的影响，同时保持了高度隐蔽性。

## 核心原理

### Function Stomping vs Module Stomping

| 特性 | Module Stomping | Function Stomping |
|------|----------------|-------------------|
| **覆盖范围** | 整个模块的 .text 节 | 单个函数 |
| **影响范围** | 整个模块不可用 | 仅被覆盖的函数不可用 |
| **稳定性** | 可能导致模块崩溃 | 目标进程其他功能正常 |
| **触发方式** | Hook API | 等待函数被调用 |
| **隐蔽性** | 高 | 极高 |

### 注入流程

```
1. 枚举目标进程模块
   ├─ EnumProcessModules（获取所有模块）
   ├─ GetModuleFileNameExW（获取模块名）
   └─ 查找目标模块（如 kernel32.dll）

2. 获取函数地址
   ├─ GetProcAddress（获取目标函数地址，如 CreateFileW）
   └─ 验证函数是否"可践踏"（函数大小 >= shellcode 大小）

3. 覆盖函数
   ├─ VirtualProtectEx（RX → RWX）
   ├─ WriteProcessMemory（覆盖函数为 shellcode）
   └─ VirtualProtectEx（RWX → WCX，PAGE_EXECUTE_WRITECOPY）

4. 等待触发
   └─ 目标进程调用被覆盖的函数 → shellcode 执行 ✨
```

### 关键技术细节

#### 1. PAGE_EXECUTE_WRITECOPY 保护

使用 `PAGE_EXECUTE_WRITECOPY` 而不是常见的 `PAGE_EXECUTE_READ` 的原因：

- **绕过 Malfind**：Malfind 等内存扫描工具检测 RWX/RX 内存中的可疑代码
- **COW 机制**：WRITECOPY 是 Copy-On-Write 保护，看起来像合法的共享内存
- **参考**：[CyberArk - Masking Malicious Memory Artifacts](https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners)

#### 2. 函数选择标准

**可践踏的函数**：
- ✅ 函数大小 >= shellcode 大小
- ✅ 目标进程会频繁调用（如 CreateFileW, MessageBoxW）
- ✅ 非关键系统函数（避免导致进程崩溃）

**不可践踏的函数**：
- ❌ 函数太小（无法容纳 shellcode）
- ❌ 内联函数（编译器优化）
- ❌ 函数从未被调用（无法触发）

#### 3. 触发机制

**自动触发**：
- 选择目标进程频繁调用的函数（如 GUI 程序的 MessageBoxW）
- 用户操作自然触发（如打开文件触发 CreateFileW）

**手动触发**：
- 从目标进程内部强制调用被覆盖的函数
- 使用 CreateRemoteThread 调用函数地址

## 执行流程图

```
OpenProcess(PROCESS_ALL_ACCESS)
    ↓
EnumProcessModules
    ↓
查找目标模块（kernel32.dll）
    ↓
GetProcAddress("CreateFileW")
    ↓
VirtualProtectEx(PAGE_EXECUTE_READWRITE)
    ↓
WriteProcessMemory(functionBase, shellcode, size)
    ↓
VirtualProtectEx(PAGE_EXECUTE_WRITECOPY) ← 绕过 Malfind
    ↓
等待目标进程调用 CreateFileW
    ↓
Shellcode 执行 ✨
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
# 语法
function_stomping.exe <pid> <shellcode.bin> <module_name> <function_name>

# 示例：覆盖 CreateFileW
start notepad
function_stomping.exe 1234 calc_shellcode.bin kernel32.dll CreateFileW

# 示例：覆盖 MessageBoxW
function_stomping.exe 1234 messagebox_shellcode.bin user32.dll MessageBoxW
```

**输出示例**：
```
[+] Function Stomping Injection POC
[+] Inspired by Module Stomping
[+] Original Research: Ido Veltzman (@Idov31)

[+] Loaded shellcode: 65 bytes

[+] Function Stomping Injection
[+] Target PID: 1234
[+] Target Module: kernel32.dll
[+] Target Function: CreateFileW
[+] Shellcode size: 65 bytes
[+] Opened target process
[+] Function base address: 00007FFE8C6F1234
[+] Changed protection to RW
[+] Successfully stomped the function! (65 bytes written)
[+] Changed protection to WCX (EXECUTE_WRITECOPY)

[+] Function stomping successful!
[!] You MUST call the function 'CreateFileW' from the target process to trigger execution!
[!] Example: If you stomped CreateFileW, the target must call CreateFileW to execute shellcode.

[+] Injection successful!
```

### 触发执行

#### 自动触发（推荐）

选择目标进程会自动调用的函数：

**Notepad.exe**:
- `CreateFileW` - 打开文件（File → Open）
- `MessageBoxW` - 显示消息框（点击菜单）
- `GetOpenFileNameW` - 文件对话框

**Explorer.exe**:
- `CreateFileW` - 打开任何文件/文件夹
- `FindFirstFileW` - 浏览文件夹

**任何 GUI 程序**:
- `MessageBoxW` - 显示消息框
- `CreateWindowExW` - 创建窗口

#### 手动触发

从目标进程内部调用函数：

```c
// 在目标进程中执行（通过其他注入技术）
CreateFileW(L"C:\\test.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
```

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ 极高隐蔽性 | 仅覆盖单个函数，其他功能正常 |
| ✅ 精准覆盖 | 不影响整个模块，降低检测风险 |
| ✅ 绕过内存扫描 | 使用 PAGE_EXECUTE_WRITECOPY 绕过 Malfind |
| ✅ 无需分配内存 | 直接覆盖现有函数，无 VirtualAllocEx |
| ✅ 无 Hook 指令 | 不插入 JMP/CALL，直接覆盖整个函数 |
| ⚠️ 函数限制 | 函数必须足够大以容纳 shellcode |
| ⚠️ 触发依赖 | 需要目标进程调用被覆盖的函数 |
| ⚠️ 单次触发 | 函数被覆盖后，无法恢复原始功能 |

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **Shellcode 存储**
   - ❌ 明文存储
   - ✅ 使用加密/混淆存储

2. **函数选择**
   - ❌ 固定函数（CreateFileW）
   - ✅ 动态选择多个候选函数

3. **内存保护**
   - ✅ 已使用 PAGE_EXECUTE_WRITECOPY（绕过 Malfind）
   - ✅ 可考虑在写入后短暂恢复原始保护

4. **触发方式**
   - ❌ 等待自然调用（可能很久）
   - ✅ 主动触发（如发送窗口消息）

## 函数大小检测

不同函数的大小差异很大，选择函数前需检测：

```c
// 简单的函数大小检测（不准确）
BYTE* nextFunction = GetProcAddress(hModule, "NextFunctionName");
SIZE_T functionSize = nextFunction - functionBase;

if (functionSize >= shellcodeSize) {
    // 可以践踏
}
```

**更准确的方法**：
- 使用 Zydis/Capstone 反汇编
- 查找 RET 指令确定函数边界
- 解析调试符号（PDB）

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **API 监控** | Hook VirtualProtectEx 检测 WCX 保护修改 |
| **内存扫描** | 扫描系统 DLL 函数完整性（与磁盘对比） |
| **行为分析** | 检测 WriteProcessMemory 写入系统 DLL 地址空间 |
| **函数校验** | 定期验证关键函数的前 N 字节 |
| **EDR Hook** | 在函数入口插入 Hook 检测异常执行 |

## 技术来源

- **原作者**: Ido Veltzman (@Idov31)
- **原仓库**: [Idov31/FunctionStomping](https://github.com/Idov31/FunctionStomping)
- **技术博客**: [The Good, The Bad And The Stomped Function](https://idov31.github.io/2022-01-28-function-stomping/)
- **首次公开**: 2022-01-23

## 致谢

- [Ido Veltzman](https://github.com/Idov31) - 技术发现和实现
- [RastaMouse](https://offensivedefence.co.uk/) - C# 版本实现
- [CyberArk](https://www.cyberark.com/) - Masking Malicious Memory 研究

## 参考链接

- [Idov31 Repository](https://github.com/Idov31/FunctionStomping)
- [The Good, The Bad And The Stomped Function](https://idov31.github.io/2022-01-28-function-stomping/)
- [RastaMouse - Module Stomping](https://offensivedefence.co.uk/posts/module-stomping/)
- [CyberArk - Masking Malicious Memory](https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners)

## 重要提示

1. **仅限研究和防御用途**
   - 此技术仅用于安全研究和防御目的
   - 不得用于恶意攻击

2. **函数选择很重要**
   - 不是所有函数都可以践踏
   - 选择被频繁调用的非关键函数
   - 避免覆盖关键系统函数导致崩溃

3. **触发是关键**
   - 函数必须被调用才能执行 shellcode
   - 选择高频调用的函数或主动触发

4. **稳定性考虑**
   - 被覆盖的函数将永久失效
   - 确保目标进程不依赖该函数的返回值
   - 考虑使用 Trampoline 技术恢复部分功能
