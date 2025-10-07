# 进程镂空技术演示程序

## 简介

这是一个用 C 语言实现的 **进程镂空（Process Hollowing）** 技术演示程序。该技术通过创建一个挂起的合法进程，然后将其内存空间替换为恶意代码，从而实现隐蔽执行。

**⚠️ 警告：此代码仅用于安全研究和教育目的。未经授权使用此技术可能违反法律。**

## 技术原理

进程镂空的核心步骤如下：

1. **创建挂起进程** - 以挂起状态创建目标进程（如 notepad.exe）
2. **读取 PEB** - 获取进程环境块（Process Environment Block），找到镜像基址
3. **卸载原始镜像** - 使用 `NtUnmapViewOfSection` 卸载目标进程的原始可执行映像
4. **分配新内存** - 在目标进程中分配足够的内存空间
5. **写入源程序** - 将要注入的程序（PE 文件）写入目标进程内存
6. **基址重定位** - 如果基址不匹配，修正所有需要重定位的地址
7. **设置入口点** - 修改线程上下文，将入口点指向新程序
8. **恢复执行** - 恢复线程，执行注入的代码

## 项目结构

```
├── process_hollowing.c  # 主程序实现
├── pe.c                 # PE 文件处理函数
├── pe.h                 # PE 函数头文件
├── internals.h          # 内部结构定义
├── CMakeLists.txt       # CMake 构建文件
└── README.md            # 本文档
```

## 编译方法

### 使用 GCC（推荐）

```bash
gcc -o process_hollowing.exe process_hollowing.c pe.c -ldbghelp -lntdll -I.
```

### 使用 CMake

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## 使用方法

```bash
process_hollowing.exe <目标进程> <源程序路径>
```

### 参数说明

- **目标进程**：将被镂空的合法进程（如 `notepad.exe`）
- **源程序路径**：要注入执行的程序的完整路径

### 示例

```bash
# 将 payload.exe 注入到 notepad.exe 进程中
process_hollowing.exe notepad.exe C:\path\to\payload.exe

# 将 malware.exe 注入到 svchost.exe 进程中
process_hollowing.exe svchost.exe C:\path\to\malware.exe
```

## 运行输出

程序会输出详细的执行步骤：

```
========== 进程镂空开始 ==========

[1] 创建挂起进程：notepad.exe
    进程 PID：12345
    进程句柄：0x000001A4

[2] 读取目标进程的 PEB
    镜像基址：0x00007FF6C0000000

[3] 打开源文件：payload.exe
    文件大小：51200 字节

[4] 卸载目标进程镜像
    镜像已卸载

[5] 分配新内存
    分配地址：0x00007FF6C0000000
    分配大小：65536 字节

[6] 基址重定位
    源镜像基址：0x00007FF6C0000000
    目标镜像基址：0x00007FF6C0000000
    重定位差值：0x0

[7] 写入 PE 头
    PE 头已写入，大小：1024 字节

[8] 写入节区
    写入节：.text    -> 0x00007FF6C0001000 (20480 字节)
    写入节：.data    -> 0x00007FF6C0006000 (4096 字节)
    写入节：.rdata   -> 0x00007FF6C0007000 (8192 字节)

[9] 无需基址重定位（差值为零）

[10] 设置线程上下文
    入口点地址：0x00007FF6C0001234

[11] 恢复线程执行

========== 进程镂空完成 ==========
```

## 技术特点

### ✅ 优点

- **中文注释**：所有代码都有详细的中文注释
- **中文输出**：运行时输出完全中文化，便于理解
- **跨平台兼容**：支持 32 位和 64 位 Windows 系统
- **模块化设计**：代码结构清晰，易于理解和扩展
- **详细日志**：每一步操作都有详细的输出信息

### 🔍 关键实现

#### 1. PEB 结构

```c
typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID ImageBaseAddress;  // 镜像基址（偏移 0x10）
} MY_PEB, *PMY_PEB;
```

#### 2. 基址重定位结构

```c
typedef struct _BASE_RELOCATION_BLOCK {
    DWORD PageAddress;   // 页面基址
    DWORD BlockSize;     // 块大小
} BASE_RELOCATION_BLOCK;

typedef struct _BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;  // 偏移量（12位）
    USHORT Type : 4;     // 类型（4位）
} BASE_RELOCATION_ENTRY;
```

#### 3. 未导出的 NT API

```c
typedef NTSTATUS (WINAPI* _NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);
```

## 防御检测

### 行为特征

1. 创建挂起的进程
2. 调用 `NtUnmapViewOfSection`
3. 在远程进程中分配大块可执行内存
4. 修改远程进程的线程上下文
5. 恢复挂起的线程

### 防御建议

- 监控 `NtUnmapViewOfSection` 的调用
- 检测挂起进程的异常内存分配
- 分析线程上下文的异常修改
- 使用进程镜像完整性检查
- 实施 EDR/XDR 解决方案

## 参考资料

- [原始项目](https://github.com/m0n0ph1/Process-Hollowing)
- [PE 文件格式规范](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Malware Analyst's Cookbook](http://www.malwarecookbook.com/)

## 法律声明

**本程序仅供安全研究和教育目的使用。**

使用本程序进行未经授权的攻击活动是违法的。作者不对任何滥用行为负责。使用者应遵守所在地区的法律法规，并获得适当的授权后方可使用本程序。

## 许可证

本项目基于原始 [Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing) 项目进行改进和中文化。

## 作者

改进和中文化：Claude Code
原始作者：m0n0ph1

## 贡献

欢迎提交 Issue 和 Pull Request 来改进本项目。

---

**⚠️ 再次提醒：请负责任地使用此代码！**
