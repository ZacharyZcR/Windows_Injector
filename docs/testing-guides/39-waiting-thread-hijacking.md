# 技术39：Waiting Thread Hijacking 测试报告

## 测试环境
- **操作系统**: Windows 11 Build 26100 (24H2)
- **测试时间**: 2025-10-09
- **实现来源**: 参考 hasherezade/waiting_thread_hijacking

## 技术原理

Waiting Thread Hijacking 通过以下步骤实现代码注入：

1. **枚举等待线程**：使用 `NtQuerySystemInformation(SystemProcessInformation)` 枚举目标进程的所有线程，筛选处于 `Waiting` 状态的线程
2. **验证返回地址**：读取等待线程栈顶的返回地址（RSP），确认返回地址指向系统DLL（ntdll.dll/kernel32.dll/kernelbase.dll）
3. **写入shellcode**：在目标进程分配内存并写入shellcode（包含stub和payload）
4. **劫持返回地址**：将线程栈上的返回地址覆写为shellcode入口点
5. **等待执行**：当线程从等待状态返回时，会跳转到shellcode执行

### 关键技术点

#### 1. ASLR会话级一致性
系统DLL（ntdll.dll、kernel32.dll、kernelbase.dll）在同一Windows会话的所有进程中加载在相同地址。这意味着：
- 可以在注入器进程中用 `GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)` 检查地址是否属于系统DLL
- 无需在目标进程中枚举模块，避免了远程进程模块枚举的复杂性

#### 2. Wait Reason筛选
常见的等待原因：
- `WrQueue (15)`: 等待队列对象
- `WrUserRequest (13)`: 用户请求等待
- 使用 `0xFFFFFFFF` 可匹配任意等待原因

#### 3. Shellcode结构
官方实现使用两部分shellcode：
- **Stub (59 bytes)**: 保存所有寄存器 → 调用payload → 恢复寄存器 → 跳回原始返回地址
- **Payload (659 bytes)**: 通过PEB遍历动态解析 `kernel32.dll` 和 `WinExec`，执行 `WinExec("calc.exe", SW_SHOW)`

前8字节存储原始返回地址，stub末尾的 `jmp [rip-0x45]` 指令会跳回该地址。

## 测试步骤

### 1. 编译实现
```bash
cd techniques/39-waiting-thread-hijacking
gcc -o waiting_thread_hijacking.exe src/waiting_thread_hijacking.c -lntdll -lpsapi
```

### 2. 启动目标进程
```bash
notepad.exe &
# 获取PID，例如：34272
tasklist | grep -i notepad
```

### 3. 执行注入
```bash
# 使用默认的 WrQueue (15) 等待原因
./waiting_thread_hijacking.exe 34272

# 或使用任意等待原因
./waiting_thread_hijacking.exe 34272 0xFFFFFFFF
```

## 测试结果

### ✅ 测试成功

**测试命令**:
```bash
./waiting_thread_hijacking.exe 34272 0xFFFFFFFF
```

**输出**:
```
========================================
Waiting Thread Hijacking
========================================

[*] Target PID: 34272
[*] Wait reason filter: 4294967295 (0xFFFFFFFF = any)
[*] Found process, analyzing 98 threads
[*] TID 93484: State=Waiting, WaitReason=13
[*] RSP: 0x6319aff218, Return address: 0x7ffb3e24fad2
[-] Return address 0x7ffb3e24fad2 not in any module
[*] TID 123096: State=Waiting, WaitReason=15
[*] RSP: 0x6319bff558, Return address: 0x7ffb403de02e
[*] Return address 0x7ffb403de02e in module: ntdll.dll
[+] Valid system DLL target!
[+] Found suitable thread: TID 123096
[+] Target thread found: TID 123096
[+] RSP: 0x6319bff558
[+] Original return address: 0x7ffb403de02e
[+] Allocated shellcode at: 0x1b0f27c0000 (size: 1342 bytes)
[+] Shellcode written successfully
[+] Shellcode is now executable
[+] Return address overwritten!
[+] Shellcode will execute when thread returns

[+] Injection successful!
[*] Wait for the target thread to return from its waiting state
```

**验证结果**: Calculator应用成功启动（Windows 11中为 `CalculatorApp.exe`）

### 测试分析

1. **找到合适线程**: 在98个线程中找到了TID 123096，WaitReason=15 (WrQueue)
2. **返回地址验证**: 返回地址 `0x7ffb403de02e` 位于 `ntdll.dll`
3. **Shellcode注入**: 成功分配1342字节（59 + 659 + 内存对齐）并写入shellcode
4. **执行成功**: 线程返回时执行shellcode，弹出计算器

## 常见问题

### Q1: 为什么有些等待线程的返回地址无效？
**A**: 某些线程的返回地址可能指向不属于任何模块的内存区域（例如已卸载的DLL、JIT代码等）。只有返回地址在 ntdll/kernel32/kernelbase 中的线程才是安全的劫持目标。

### Q2: 如何选择合适的Wait Reason？
**A**:
- `WrQueue (15)` 通常最可靠，这类线程会在处理队列项时返回
- 如果找不到WrQueue线程，可以使用 `0xFFFFFFFF` 尝试任意等待线程
- 避免选择不会返回的长期等待线程

### Q3: 为什么使用GetModuleHandleExA而不是EnumProcessModules？
**A**:
- ASLR在会话级别一致，系统DLL在所有进程中地址相同
- 在当前进程检查比远程进程枚举模块更快更简单
- 避免了跨进程模块枚举的复杂性和权限问题

## 检测与防御

### 检测方法
1. **栈完整性监控**: 监控线程栈上的返回地址被修改
2. **内存执行监控**: 检测新分配的可执行内存
3. **异常返回检测**: 检测从等待状态返回到非系统DLL的地址

### 防御措施
1. **栈保护**: 使用栈金丝雀（stack canaries）或影子栈
2. **DEP/CFG**: 启用数据执行保护和控制流保护
3. **线程完整性**: 定期验证关键线程的栈完整性
4. **行为监控**: 监控进程异常创建可执行内存和跨进程写入

## 参考资源

- **原始实现**: https://github.com/hasherezade/waiting_thread_hijacking
- **技术原理**: Hijacking waiting threads by overwriting stack return addresses
- **系统DLL ASLR**: Windows session-wide ASLR for system DLLs
- **PEB Walking**: Dynamic API resolution via Process Environment Block traversal
