# Transacted Hollowing (事务镂空) - 技术文档

## 技术概述

Transacted Hollowing（事务镂空）是 Process Hollowing 的进化版本，利用 Windows NTFS 事务机制实现无文件落地的代码注入。

**核心创新点**：
1. **利用 NTFS 事务** - 在事务上下文中创建临时文件
2. **创建内存节** - 基于事务性文件创建 SEC_IMAGE 内存节
3. **回滚事务** - 删除磁盘文件，但内存节依然有效
4. **映射到目标进程** - 将内存节映射到新创建的挂起进程
5. **无文件落地** - 整个过程不在磁盘留下持久性文件

**与 Process Hollowing 的区别**：
- **Process Hollowing**: 手动写入 PE 各个节，需要处理重定位、节对齐等细节
- **Transacted Hollowing**: 由 Windows 自动加载 PE，利用内存节映射机制

## 技术原理

### NTFS 事务机制

**什么是 NTFS 事务？**
- Windows Vista+ 引入的事务性文件系统功能
- 支持原子性文件操作（全部成功或全部失败）
- 事务内的文件修改对事务外不可见
- 回滚事务会撤销所有文件更改

**在注入中的应用**：
```
创建事务 → 创建事务性文件 → 写入 PE 数据
→ 创建内存节(基于文件) → 回滚事务(删除文件)
→ 内存节依然有效！
```

### 内存节对象（Section Object）

**SEC_IMAGE 标志**：
- 告诉 Windows 这是一个 PE 镜像文件
- Windows 自动解析 PE 格式
- 自动处理节对齐、重定位、导入表等
- 映射时直接可执行

**关键 API**：
- `NtCreateSection` - 创建内存节对象
- `NtMapViewOfSection` - 映射节到进程地址空间

### 执行流程

**10 个关键步骤**：

1. **读取载荷文件** - 从磁盘加载 PE 文件到内存
2. **创建 NTFS 事务** - 使用 `CreateTransaction`
3. **创建事务性文件** - 使用 `CreateFileTransacted` 创建临时文件
4. **写入载荷** - 将 PE 数据写入事务性文件
5. **创建内存节** - 使用 `NtCreateSection` 创建 SEC_IMAGE 节
6. **回滚事务** - 使用 `RollbackTransaction` 删除文件
7. **创建挂起进程** - 创建目标进程（CREATE_SUSPENDED）
8. **映射内存节** - 使用 `NtMapViewOfSection` 映射到目标进程
9. **更新 PEB** - 修改进程的 ImageBase 和入口点
10. **恢复线程** - 启动进程执行注入代码

### 技术优势

**隐蔽性**：
- 不在磁盘留下持久性 PE 文件
- 绕过文件扫描类杀软
- 临时文件仅存在毫秒级别

**稳定性**：
- Windows 自动处理 PE 加载
- 无需手动处理重定位和导入表
- 支持复杂的 PE 文件（带 TLS、异常处理等）

**兼容性**：
- 支持 x86 和 x64 架构
- 支持所有符合 PE 规范的可执行文件

## 测试方法

### 环境要求
- **操作系统**: Windows Vista 及以上（需要 NTFS 事务支持）
- **文件系统**: NTFS（FAT32 不支持事务）
- **编译器**: MinGW-w64 或 MSVC
- **权限**: 普通用户权限即可（部分目标进程需要管理员权限）

### 编译步骤

**使用批处理脚本（推荐）**：
```bash
cd techniques/02-transacted-hollowing
./build.bat
```

**手动编译**：
```bash
cd techniques/02-transacted-hollowing/src

# 编译主程序
gcc -o ../transacted_hollowing.exe transacted_hollowing.c pe_utils.c \
    -lktmw32 -lntdll -municode -I.

# 编译测试载荷
gcc -o ../test_payload.exe test_payload.c
```

### 执行测试

**基本用法**：
```bash
./transacted_hollowing.exe <载荷路径> [目标进程]
```

**测试案例**：

1. **默认目标进程（svchost.exe）**：
```bash
./transacted_hollowing.exe test_payload.exe
```

2. **指定目标进程（notepad.exe）**：
```bash
./transacted_hollowing.exe test_payload.exe notepad.exe
```

3. **指定其他目标进程**：
```bash
./transacted_hollowing.exe test_payload.exe cmd.exe
./transacted_hollowing.exe test_payload.exe RuntimeBroker.exe
```

### 观察要点

**1. 控制台输出**
成功的执行会显示以下步骤：
```
[0] 读取载荷文件
    载荷架构：64 位

[1] 创建 NTFS 事务
    事务句柄：0x...

[2] 创建事务性文件
    文件路径：C:\Users\...\Temp\THxxxx.tmp

[3] 写入载荷到事务性文件
    载荷大小：xxxxx 字节
    已写入：xxxxx 字节

[4] 创建内存节对象（SEC_IMAGE）
    节句柄：0x...

[5] 回滚事务（删除文件）
    事务已回滚，文件已删除
    内存节创建成功！

[6] 创建挂起的目标进程
    进程 ID：xxxxx

[7] 映射内存节到目标进程
    映射基址：0x...

[8] 更新 PEB 中的 ImageBase
    ImageBase 已更新

[9] 更新线程入口点
    入口点 VA：0x...

[10] 恢复线程执行

========== 事务性镂空完成 ==========
```

**2. 任务管理器验证**
- **进程名称**：显示为目标进程（如 notepad.exe）
- **进程图标**：显示目标进程的图标
- **命令行**：显示目标进程路径
- **实际行为**：执行 payload 代码

**3. 文件系统检查**
```bash
# 事务回滚后，临时文件应该不存在
dir C:\Users\%USERNAME%\AppData\Local\Temp\TH*.tmp
# 应该找不到任何 TH 开头的文件
```

**4. 验证成功标志**
- MessageBox 弹出（test_payload.exe 的默认行为）
- 进程在任务管理器中显示为目标进程
- 临时文件已被删除

## 预期效果

### 成功场景

**正常执行流程**：
1. 创建事务性文件（临时存在于 %TEMP% 目录）
2. 写入 PE 数据到事务性文件
3. 创建内存节对象（SEC_IMAGE）
4. 回滚事务，文件从磁盘消失
5. 创建挂起的目标进程
6. 映射内存节到目标进程
7. 更新 PEB ImageBase
8. 设置线程入口点
9. 恢复线程，执行 payload

**视觉表现**：
- MessageBox 弹出，显示 payload 消息
- 任务管理器显示目标进程名称和图标
- 磁盘上无残留文件

### 常见问题

**1. 错误：无法创建事务（Error 87）**
- **原因**：文件系统不支持事务（FAT32）
- **解决**：确保临时目录在 NTFS 分区上

**2. 错误：创建内存节失败（STATUS_INVALID_IMAGE_FORMAT）**
- **原因**：载荷文件不是有效的 PE 文件
- **解决**：使用 `dumpbin` 或 `objdump` 检查 PE 格式

**3. 错误：映射内存节失败（STATUS_CONFLICTING_ADDRESSES）**
- **原因**：目标进程地址空间冲突
- **解决**：尝试不同的目标进程

**4. 进程创建但立即退出**
- **原因**：载荷文件缺少必要的 DLL
- **解决**：使用 `Dependencies.exe` 检查依赖项，或使用静态链接编译

**5. 权限拒绝（Access Denied）**
- **原因**：目标进程需要更高权限
- **解决**：以管理员身份运行，或选择不同的目标进程

## 技术限制

**1. 系统要求**
- 需要 Windows Vista 及以上（XP 不支持事务）
- 需要 NTFS 文件系统

**2. 架构匹配**
- 载荷和目标进程必须同架构（都是 x64 或都是 x86）
- 当前实现是 x64，不能注入 x86 进程

**3. 文件格式要求**
- 载荷必须是有效的 PE 文件
- PE 头必须正确（否则 SEC_IMAGE 创建失败）

**4. 目标进程限制**
- 受保护的进程（Protected Process）无法注入
- 某些系统进程需要管理员权限

## 防御检测

**检测特征**：

1. **API 调用特征**
   - `CreateTransaction` - 创建文件系统事务
   - `CreateFileTransacted` - 创建事务性文件
   - `RollbackTransaction` - 回滚事务
   - `NtCreateSection` 带 SEC_IMAGE 标志
   - `NtMapViewOfSection` - 映射到远程进程

2. **行为特征**
   - 创建临时文件后立即回滚事务
   - 在挂起状态创建进程（CREATE_SUSPENDED）
   - 修改远程进程的 PEB
   - 调用 `SetThreadContext` 修改线程上下文

3. **文件系统特征**
   - 短暂出现的临时文件（毫秒级别）
   - 事务性文件操作

**绕过方法**：
- 延迟执行各个步骤，避免批量 API 调用
- 使用合法签名的目标进程
- 混淆 API 调用链

**EDR 检测建议**：
- 监控 `CreateTransaction` + `NtCreateSection` 组合
- 检测事务创建后立即回滚的行为
- 监控 SEC_IMAGE 节的创建
- 关联进程创建和 PEB 修改事件

## 与其他技术对比

### vs Process Hollowing
| 特性 | Process Hollowing | Transacted Hollowing |
|------|-------------------|----------------------|
| PE 加载 | 手动写入各节 | Windows 自动加载 |
| 重定位处理 | 需要手动处理 | 自动处理 |
| TLS 支持 | 需要特殊处理 | 自动支持 |
| 文件落地 | 载荷文件持续存在 | 临时文件立即删除 |
| 实现复杂度 | 较高 | 较低 |
| 隐蔽性 | 中等 | 较高 |

### vs Process Doppelgänging
- **Transacted Hollowing**: 使用内存节映射
- **Process Doppelgänging**: 使用 `NtCreateProcessEx` 直接从事务创建进程

## 参考资料

- **原始披露**: hasherezade's PE-sieve 项目
- **NTFS 事务**: [Microsoft TxF Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/transactional-ntfs-portal)
- **内存节对象**: Windows Internals, Part 1, Chapter 10

## 总结

Transacted Hollowing 是一种优雅的注入技术，结合了 NTFS 事务和内存节映射机制。相比传统 Process Hollowing，它实现更简单、稳定性更高、隐蔽性更强。成功的关键在于正确使用事务 API 和 SEC_IMAGE 内存节。测试时应重点观察临时文件的创建和删除过程，以及目标进程的实际行为。
