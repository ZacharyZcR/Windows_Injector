# Process Hollowing (进程镂空) - 技术文档

## 技术概述

Process Hollowing（进程镂空）是一种高级代码注入技术，通过以下步骤实现：

1. **创建合法进程** - 以挂起状态启动一个合法程序（如 notepad.exe）
2. **掏空内存** - 将目标进程的原始代码从内存中移除
3. **注入恶意代码** - 将自定义 PE 文件写入被掏空的进程空间
4. **劫持执行** - 修改线程入口点，使其执行注入的代码
5. **恢复运行** - 恢复线程，进程以合法身份执行恶意代码

**核心特点**：
- 进程在任务管理器中显示为合法程序（图标、名称、路径均为目标进程）
- 实际执行的是完全不同的代码
- 绕过基于进程名称的检测机制

## 技术原理

### x64 架构关键点

**1. PEB（Process Environment Block）操作**
- PEB 存储在 `Rdx` 寄存器中（x64）
- `PEB + 0x10` 偏移量存储 `ImageBaseAddress`
- 必须更新 PEB 的 ImageBaseAddress，否则进程无法正确初始化

**2. 线程上下文设置**
- `Rcx` 寄存器：入口点地址
- `Rdx` 寄存器：PEB 地址
- `Rip` 寄存器：指令指针（由系统设置）

**3. 关键步骤**
```
创建挂起进程 → 读取 PEB → 分配新内存 → 写入 PE 镜像
→ 更新 PEB ImageBase → 设置入口点 → 恢复线程
```

**最容易忽略的细节**：
必须将新分配的 ImageBase 写回远程进程的 `PEB + 0x10`，否则进程初始化会失败（错误码 0xC0000142）。

## 测试方法

### 环境要求
- Windows 10/11 x64
- MinGW-w64 或 MSVC 编译器
- 管理员权限（可选，某些目标进程可能需要）

### 编译步骤

**1. 编译注入器**
```bash
cd techniques/01-process-hollowing
gcc -o process_hollowing_x64.exe src/process_hollowing_x64.c -O2
```

**2. 编译测试 Payload**
```bash
gcc -o test_payload.exe src/test_payload.c -mwindows -O2
```

### 执行测试

**基本用法**：
```bash
./process_hollowing_x64.exe <目标进程> <源程序路径>
```

**推荐测试案例**：
```bash
# 使用记事本作为宿主进程
./process_hollowing_x64.exe notepad.exe ./test_payload.exe

# 使用命令行作为宿主进程
./process_hollowing_x64.exe cmd.exe ./test_payload.exe
```

### 观察要点

**1. 控制台输出**
成功的注入会显示以下步骤：
```
[1] 读取源 PE 文件
[2] 创建挂起进程
[3] 获取线程上下文（Rdx = PEB 地址）
[4] 读取目标进程的 ImageBaseAddress
[5] 分配新内存
[6] 基址重定位
[7] 写入 PE 头
[8] 写入节区（.text, .data, .rdata 等）
[10] 更新远程 PEB
[11] 设置线程入口点
[12] 恢复线程执行
```

**2. 任务管理器检查**
打开任务管理器，找到新创建的进程：
- **进程名称**：显示为目标进程（如 notepad.exe）
- **进程图标**：显示为目标进程的图标（记事本图标）
- **命令行**：显示为目标进程路径
- **实际行为**：执行的是 payload 代码

**3. 验证成功标志**
- MessageBox 弹出，显示注入成功消息
- 消息框标题显示"🎯 Windows 进程注入测试"
- 消息内容确认"✅ 进程镂空（Process Hollowing）注入成功！"

## 预期效果

### 成功场景

**视觉表现**：
1. 执行注入程序后，立即弹出 MessageBox
2. 任务管理器中出现目标进程（如 notepad.exe）
3. 进程图标和名称与目标进程一致
4. MessageBox 内容显示 payload 的消息

**技术验证**：
- 进程 PID 正常分配
- PEB ImageBaseAddress 正确更新
- 线程入口点指向注入代码
- 所有 PE 节正确加载（.text、.data、.rdata 等）

### 常见问题

**1. 进程立即退出（无错误提示）**
- 原因：TLS（Thread Local Storage）初始化失败
- 解决：使用 MSVC 编译 payload，或禁用 TLS

**2. 错误码 0xC0000142 (STATUS_DLL_INIT_FAILED)**
- 原因：未更新 PEB ImageBaseAddress
- 解决：确保执行步骤 [10] 更新远程 PEB

**3. 错误码 0xC0000005 (ACCESS_VIOLATION)**
- 原因：内存访问权限不足或地址错误
- 解决：检查 VirtualAllocEx 是否成功，确保 PAGE_EXECUTE_READWRITE 权限

**4. 错误码 299 (ERROR_PARTIAL_COPY)**
- 原因：PEB 尚未完全初始化
- 解决：已在代码中添加重试机制

## 技术限制

**1. 架构匹配**
- 目标进程和 payload 必须是相同架构（都是 x64 或都是 x86）
- x64 注入器可以注入 x64 进程
- x86 注入器可以注入 x86 进程

**2. 编译器差异**
- MinGW-w64 编译的 x64 程序包含 TLS，可能导致初始化失败
- MSVC 编译的程序通常没有 TLS，更稳定
- 当前实现已处理 TLS 情况

**3. 基址重定位**
- 如果无法在首选基址分配内存，会在任意地址分配
- 当前实现未完全处理重定位表（Delta ≠ 0 时）
- 大多数情况下可以在首选基址成功分配

## 防御检测

**检测特征**：
1. 进程创建时带 `CREATE_SUSPENDED` 标志
2. 跨进程内存操作（WriteProcessMemory、ReadProcessMemory）
3. 线程上下文修改（SetThreadContext）
4. PEB 结构写入操作
5. 进程的磁盘映像与内存镜像不匹配

**绕过方法**：
- 延迟执行，避免批量操作
- 使用合法签名的目标进程
- 混淆内存操作模式

## 参考资料

- **原始实现（x86）**：[m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
- **x64 参考**：[adamhlt/Process-Hollowing](https://github.com/adamhlt/Process-Hollowing)
- **PE 格式**：[adamhlt/PE-Explorer](https://github.com/adamhlt/PE-Explorer)

## 总结

Process Hollowing 是一种强大的注入技术，通过完全替换进程内存实现隐蔽执行。成功的关键在于正确更新 PEB 的 ImageBaseAddress 和设置线程入口点。测试时应重点观察任务管理器中的进程表现和实际执行效果。
