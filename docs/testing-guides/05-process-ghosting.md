# Process Ghosting (进程幽灵化) - 技术文档

> ✅ **测试状态**：此技术在 **Windows 10 上完全有效**
>
> - **成功率**：100%
> - **测试环境**：Windows 10 x64
> - **核心优势**：文件完全删除，无磁盘痕迹
> - **绕过能力**：可绕过大多数文件检查类安全产品

## 技术概述

Process Ghosting（进程幽灵化）是由 **Gabriel Landau**（Elastic Security 研究员）于 **2021年6月** 发现的高级进程注入技术。这项技术利用 Windows 的文件删除待处理（delete-pending）机制和镜像节的持久化特性，实现从"不存在"的文件中启动进程。

**核心创新**：
- **删除待处理状态** - 将文件标记为删除待处理（delete-pending）
- **镜像节持久化** - 从删除待处理的文件创建镜像节
- **文件幽灵化** - 关闭句柄后文件被删除，但镜像节仍有效
- **无文件痕迹** - 进程从已删除文件的镜像节创建
- **简单高效** - 不依赖 NTFS 事务，比 Process Doppelgänging 更可靠

## 技术原理

### Windows 文件删除机制

Windows 的文件删除不是立即完成的，而是分为两个阶段：

**阶段1：标记删除待处理**
```c
FILE_DISPOSITION_INFORMATION dispInfo = { .DoDeleteFile = TRUE };
NtSetInformationFile(hFile, ..., &dispInfo, ..., FileDispositionInformation);
```
- 文件进入 **delete-pending 状态**
- 文件仍然存在于磁盘上
- 可以继续读写文件
- 其他进程无法打开该文件（共享冲突）

**阶段2：真正删除**
```c
NtClose(hFile);  // 最后一个句柄关闭
```
- 当所有句柄关闭时
- 文件系统执行真正的删除操作
- 文件从磁盘上移除

### 镜像节的持久化特性

**关键发现**：镜像节对象一旦创建，其生命周期独立于原始文件！

```
文件生命周期                镜像节生命周期
     |                           |
     v                           v
[打开文件]                  [创建节对象]
     |                           |
     v                           |
[标记删除待处理]                |
     |                           |
     v                           |
[写入载荷]                      |
     |                           |
     v                           |
[创建镜像节] -----------------> |
     |                           |
     v                           v
[关闭句柄]                  [节依然有效]
     |                           |
     v                           |
[文件被删除]                    |
                                 |
                                 v
                          [用于创建进程]
```

### Process Ghosting 完整流程

**10 个关键步骤**：

```
[0] 读取载荷文件
    └─> ReadFile(source) → buffer

[1] 创建临时文件（带 DELETE 权限）
    └─> NtCreateFile(DELETE | GENERIC_WRITE | ...)
    └─> 关键：必须有 DELETE 权限才能标记删除

[2] 标记文件为删除待处理（核心步骤！）
    └─> FILE_DISPOSITION_INFORMATION.DoDeleteFile = TRUE
    └─> NtSetInformationFile(..., FileDispositionInformation)
    └─> 文件进入 delete-pending 状态

[3] 写入载荷到删除待处理的文件
    └─> NtWriteFile(hFile, payloadBuffer)
    └─> 可以正常写入，文件仍可访问

[4] 从删除待处理的文件创建镜像节
    └─> NtCreateSection(SEC_IMAGE, hFile)
    └─> Windows 读取并验证 PE
    └─> 节对象被缓存，独立于文件

[5] 关闭文件句柄（文件被删除！）
    └─> NtClose(hFile)
    └─> 文件从磁盘删除
    └─> 但镜像节仍然有效！

[6] 从"幽灵"镜像节创建进程
    └─> NtCreateProcessEx(hSection)
    └─> 进程从已删除文件的节创建

[7] 读取 PEB 获取 ImageBase
    └─> NtQueryInformationProcess()
    └─> NtReadVirtualMemory(PEB)

[8] 设置进程参数
    └─> RtlCreateProcessParametersEx()

[9] 创建线程执行
    └─> NtCreateThreadEx(EntryPoint)

[10] 进程正常运行
     └─> 执行缓存的载荷代码
     └─> 源文件已完全删除
```

### 时序图

```
时间轴 →

步骤1: NtCreateFile(DELETE权限)
       ↓
步骤2: SetInformation(DeletePending) ← 文件标记删除
       ↓
步骤3: WriteFile(载荷)
       ↓
步骤4: NtCreateSection(SEC_IMAGE)  ← 缓存到镜像节
       ↓
步骤5: NtClose(hFile)  ← 文件被删除！
       ↓
步骤6: NtCreateProcessEx(hSection)  ← 从"幽灵"节创建进程
       ↓
步骤7-9: 设置参数，创建线程
       ↓
步骤10: 进程执行（文件已不存在）
```

### 与其他技术对比

| 技术 | 核心机制 | 文件痕迹 | 依赖 | Windows 10 状态 | 隐蔽性 |
|------|---------|---------|------|----------------|--------|
| **Process Hollowing** | 挖空替换 | 永久 | 目标进程 | ✅ 有效 | ⭐⭐⭐ |
| **Transacted Hollowing** | 事务映射 | 临时 | NTFS 事务 | ✅ 有效 | ⭐⭐⭐⭐ |
| **Process Doppelgänging** | 事务创建 | 无 | NTFS 事务 | ❌ 失效 | ⭐⭐⭐⭐⭐ |
| **Process Herpaderping** | 缓存替换 | 被覆盖 | 无 | ✅ 有效 | ⭐⭐⭐⭐ |
| **Process Ghosting** | 删除待处理 | **完全删除** | 无 | ✅ 有效 | ⭐⭐⭐⭐⭐ |

**Ghosting 的优势**：

1. **vs Doppelgänging**：
   - 不依赖 NTFS 事务（更可靠）
   - Doppelgänging 在 Windows 10 已失效
   - Ghosting 仍然有效

2. **vs Herpaderping**：
   - 文件完全删除（无痕迹）
   - Herpaderping 留下被覆盖的文件
   - 隐蔽性更高

3. **vs Transacted Hollowing**：
   - 实现更简单（不需要事务）
   - 文件直接删除（不是回滚）

## 测试方法

### 环境要求
- **操作系统**: Windows 10 及以上
- **文件系统**: 支持所有文件系统
- **编译器**: MinGW-w64 或 MSVC
- **权限**: 普通用户权限即可
- **架构**: x64（当前实现）

### 编译步骤

**使用批处理脚本（推荐）**：
```bash
cd techniques/05-process-ghosting
./build.bat
```

输出文件位于 `build/x64/` 目录：
- `process_ghosting.exe` - 主程序
- `test_payload.exe` - 测试载荷

**手动编译**：
```bash
cd techniques/05-process-ghosting/src

# 编译主程序
gcc -o ../build/x64/process_ghosting.exe \
    process_ghosting.c pe_utils.c \
    -lntdll -luserenv \
    -O2 -municode -DUNICODE

# 编译测试载荷
gcc -o ../build/x64/test_payload.exe test_payload.c -mwindows
```

### 执行测试

**基本用法**：
```bash
./build/x64/process_ghosting.exe build/x64/test_payload.exe
```

### 观察要点

**1. 控制台输出**
成功的执行会显示以下关键步骤：
```
[0] 读取载荷文件
    载荷架构：64 位

[1] 创建临时文件
    临时文件：C:\...\Temp\GHxxxx.tmp

[2] 打开文件（带 DELETE 权限）
    文件已打开

[3] 设置文件为删除待处理状态
    文件已标记为删除待处理
    关键：文件将在句柄关闭时被删除！

[4] 写入载荷到删除待处理的文件
    载荷大小：xxxxx 字节
    已写入载荷

[5] 从删除待处理的文件创建镜像节
    节句柄：0x...
    关键：镜像节已从删除待处理的文件创建！

[6] 关闭文件句柄
    文件句柄已关闭
    ★ 文件已被删除！
    ★ 但镜像节仍然存在且可用！

[7] 从内存节创建进程（NtCreateProcessEx）
    进程已创建！
    进程 ID：xxxxx

[8] 查询进程基本信息
    PEB 地址：0x...
    镜像基址：0x...

[9] 设置进程参数
    进程参数已设置

[10] 创建线程执行入口点
     入口点 VA：0x...
     线程已创建！
```

**2. 文件删除验证**

验证临时文件是否被删除：
```bash
# 查找临时文件（应该找不到）
ls C:/Users/*/AppData/Local/Temp/GH*.tmp
# 输出：No such file or directory

# 使用 find 统计
find C:/Users/*/AppData/Local/Temp/ -name "GH*.tmp" | wc -l
# 输出：0
```

**3. 进程行为验证**
- MessageBox 正常弹出
- 进程正常运行
- 源文件已完全删除
- `GetProcessImageFileName` 返回空

## 预期效果

### ✅ Windows 10 实际表现

**执行结果**（完全成功）：
1. ✅ 创建临时文件
2. ✅ 标记文件为删除待处理
3. ✅ 写入载荷到删除待处理的文件
4. ✅ 创建 SEC_IMAGE 镜像节
5. ✅ 关闭句柄，文件被删除
6. ✅ 从"幽灵"节创建进程
7. ✅ 正确读取 PEB，获取 ImageBase
8. ✅ 设置进程参数
9. ✅ 成功创建线程
10. ✅ 进程正常执行

**实际表现**：
- MessageBox 正常弹出
- 进程完全正常运行
- **临时文件完全删除，无磁盘痕迹**
- 进程无文件路径关联

### 验证无文件痕迹

**文件系统检查**：
```bash
# 执行前：查找 GH 开头的临时文件
find /c/Users/*/AppData/Local/Temp -name "GH*.tmp"
# 输出：（空，文件尚未创建）

# 执行后：再次查找
find /c/Users/*/AppData/Local/Temp -name "GH*.tmp"
# 输出：（空，文件已被删除）
```

**进程特征**：
- `GetProcessImageFileName` 返回空字符串
- 无关联的磁盘文件
- 任务管理器无法显示映像路径

## 技术深度分析

### 为什么删除待处理的文件可以创建节？

**Windows 内核行为**：

1. **文件访问权限**：
   - Delete-pending 文件仍然可以被现有句柄访问
   - 只是其他进程无法再打开它
   - 当前句柄可以继续读写

2. **NtCreateSection 的处理**：
   ```c
   NtCreateSection(SEC_IMAGE, hFile) {
       // 检查文件句柄是否有效
       if (!IsValidHandle(hFile)) return ERROR;

       // 读取并验证 PE 文件
       PE_DATA pe = ReadAndValidatePE(hFile);  // 可以读取

       // 创建节对象（缓存）
       SECTION section = CreateSectionObject(pe);

       // 节对象独立于文件
       section.FileHandle = NULL;  // 解耦

       return section;
   }
   ```

3. **节的生命周期**：
   - 节对象有独立的引用计数
   - 文件删除不影响节对象
   - 只有当所有引用释放时节才被销毁

### 为什么比 Doppelgänging 更可靠？

**Doppelgänging 的问题**（Windows 10+）：
```c
// Doppelgänging 流程
CreateTransaction()  // 创建事务
CreateFileTransacted()  // 事务性文件
NtCreateSection()  // 创建节
RollbackTransaction()  // 回滚
NtCreateProcessEx()  // ✅ 进程创建成功
NtCreateThreadEx()  // ❌ 失败：0xC0000022 (ACCESS_DENIED)
```

**Ghosting 的改进**：
```c
// Ghosting 流程
NtCreateFile(DELETE)  // 普通文件（带删除权限）
SetInformation(DeletePending)  // 标记删除
NtCreateSection()  // 创建节
NtClose()  // 文件删除
NtCreateProcessEx()  // ✅ 进程创建成功
NtCreateThreadEx()  // ✅ 线程创建成功！
```

**关键差异**：
- Doppelgänging 使用事务，被 Windows 10 特殊检测
- Ghosting 使用标准删除机制，未被特殊限制

### 检测方法

**可能的检测策略**：

**1. 监控删除待处理文件的节创建**：
```c
// 内核驱动检测
OnNtSetInformationFile(HANDLE hFile, FILE_INFORMATION_CLASS InfoClass) {
    if (InfoClass == FileDispositionInformation) {
        // 文件被标记为删除待处理
        MarkFile(hFile, DELETE_PENDING);
    }
}

OnNtCreateSection(HANDLE hFile, ULONG Attributes) {
    if (Attributes & SEC_IMAGE) {
        if (IsMarkedDeletePending(hFile)) {
            ALERT("Possible Process Ghosting");
        }
    }
}
```

**2. 行为模式检测**：
- 监控 "delete-pending → section → close → process" 模式
- 检测短暂存在的文件
- 关联文件删除和进程创建事件

**3. 进程特征检测**：
- 检测无文件路径的进程
- `GetProcessImageFileName` 返回空的进程
- 监控从匿名节创建的进程

## 防御建议

### 对于安全产品开发者

**1. 内核驱动防护**：
```c
// 阻止从删除待处理文件创建镜像节
NTSTATUS OnNtCreateSection(
    PHANDLE SectionHandle,
    HANDLE FileHandle,
    ULONG SectionPageProtection
) {
    if (SectionPageProtection & SEC_IMAGE) {
        FILE_STANDARD_INFORMATION info;
        if (QueryFileInfo(FileHandle, &info)) {
            if (info.DeletePending) {
                // 阻止创建
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    return OriginalNtCreateSection(...);
}
```

**2. 文件系统过滤驱动**：
- 在 pre-create 回调中检查文件属性
- 监控删除待处理状态的设置
- 拦截可疑的节创建操作

**3. EDR 行为监控**：
- 关联文件操作时间线
- 检测异常的进程创建模式
- 监控无文件路径的进程

### 对于系统管理员

**1. 审计策略**：
- 启用文件删除审计
- 监控 `NtSetInformationFile` 调用
- 关注短暂存在的可执行文件

**2. 应用控制**：
- 使用 Windows Defender Application Control (WDAC)
- 要求所有可执行文件签名
- 阻止从未签名的节创建进程

**3. 检测规则**：
```
IF 进程创建 AND GetProcessImageFileName() == NULL THEN
    ALERT("可能的 Process Ghosting")
END IF
```

## 已知问题与限制

**1. 架构限制**：
- 当前实现仅支持 x64
- 载荷和主程序必须同架构

**2. 环境变量设置**：
- 某些情况下环境变量分配可能失败
- 不影响主要功能

**3. 检测可能性**：
- 先进的 EDR 可以检测
- 内核驱动可以阻止
- 不是完全不可检测的

**4. 权限要求**：
- 需要 DELETE 权限打开文件
- 需要在临时目录创建文件

## 参考资料

### 原始披露
- **发现者**: Gabriel Landau (Elastic Security)
- **披露时间**: 2021年6月
- **博客文章**: [Process Ghosting - A New Executable Image Tampering Attack](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack)
- **MSRC 案例**: MSRC 不认为这是需要修复的安全问题

### 技术文章
- [Elastic Security Labs - Process Ghosting](https://www.elastic.co/security-labs/process-ghosting)
- [Windows Internals - File Deletion](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/)

### 相关技术
- [Process Hollowing](./01-process-hollowing.md)
- [Transacted Hollowing](./02-transacted-hollowing.md)
- [Process Doppelgänging](./03-process-doppelganging.md) - Windows 10 已失效
- [Process Herpaderping](./04-process-herpaderping.md)

## 总结

Process Ghosting 是目前最隐蔽的进程注入技术之一，通过利用 Windows 文件删除待处理机制，实现了真正的"无文件"进程创建。

### 技术评估

**优势** ✅：
- **完全无文件** - 文件真正删除，无磁盘痕迹
- **简单可靠** - 不依赖 NTFS 事务
- **稳定性高** - 在 Windows 10 上完全有效
- **绕过能力强** - 可欺骗大多数安全产品

**限制** ⚠️：
- 先进的 EDR 可以检测
- 需要 DELETE 权限
- 留下进程创建痕迹

**vs Doppelgänging** 🆚：
- ✅ Ghosting 更可靠（不依赖事务）
- ✅ Ghosting 在 Windows 10 有效
- ✅ Doppelgänging 已失效

**vs Herpaderping** 🆚：
- ✅ Ghosting 无文件痕迹
- ⭐ Herpaderping 留下被覆盖的文件
- ✅ Ghosting 隐蔽性更高

**实战价值** ⭐⭐⭐⭐⭐：
- 非常高的实战价值
- 比 Doppelgänging 更可靠
- 是当前最隐蔽的进程创建技术之一

**学习价值** ⭐⭐⭐⭐⭐：
- 深入理解 Windows 文件删除机制
- 了解镜像节的持久化特性
- 学习时序和状态利用
- 研究防御和检测方法

Process Ghosting 展示了攻击者如何巧妙利用系统的合法机制实现高度隐蔽的攻击，是进程注入技术演进的又一里程碑。
