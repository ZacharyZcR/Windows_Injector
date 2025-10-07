# 事务性镂空技术（Transacted Hollowing）

## 技术简介

**事务性镂空（Transacted Hollowing）** 是一种高级进程注入技术，结合了 **进程镂空（Process Hollowing）** 和 **NTFS 事务机制**。

相比传统的进程镂空，事务性镂空具有更强的隐蔽性：
- 载荷文件不会真正落地到磁盘
- 使用 NTFS 事务后回滚，文件痕迹被删除
- 内存映射为 `SEC_IMAGE`，看起来像正常加载的模块

## 技术原理

### 核心步骤

```
1. 创建 NTFS 事务
   ↓
2. 在事务中创建临时文件
   ↓
3. 将载荷 PE 文件写入事务性文件
   ↓
4. 使用 NtCreateSection 从文件创建内存节（SEC_IMAGE）
   ↓
5. 回滚事务（文件被删除，但内存节仍有效）
   ↓
6. 创建挂起的目标进程
   ↓
7. 使用 NtMapViewOfSection 将内存节映射到目标进程
   ↓
8. 更新 PEB 中的 ImageBaseAddress
   ↓
9. 修改线程上下文中的入口点
   ↓
10. 恢复线程执行载荷代码
```

### 关键 API

| API | 用途 |
|-----|------|
| `CreateTransaction` | 创建 NTFS 事务 |
| `CreateFileTransactedW` | 在事务中创建文件 |
| `NtCreateSection` | 从文件创建内存节 |
| `RollbackTransaction` | 回滚事务，删除文件 |
| `NtMapViewOfSection` | 将内存节映射到进程 |
| `CreateProcessInternalW` | 创建挂起进程（内部 API）|

### 与其他技术的对比

| 技术 | 文件落地 | 内存映射方式 | 隐蔽性 |
|------|----------|--------------|--------|
| **Process Hollowing** | ✅ 需要 | 手动写入 | ⭐⭐⭐ |
| **Transacted Hollowing** | ❌ 不需要 | SEC_IMAGE | ⭐⭐⭐⭐⭐ |
| **Process Doppelgänging** | ❌ 不需要 | SEC_IMAGE | ⭐⭐⭐⭐⭐ |

## 项目结构

```
02-transacted-hollowing/
├── README.md                        # 本文档
├── build.sh                         # Linux/macOS 构建脚本
├── build.bat                        # Windows 构建脚本
├── CMakeLists.txt                   # CMake 构建文件
└── src/                             # 源代码
    ├── transacted_hollowing.c       # 主程序实现
    ├── pe_utils.c                   # PE 文件工具
    ├── pe_utils.h                   # PE 工具头文件
    ├── internals.h                  # NT API 定义
    └── test_payload.c               # 测试载荷
```

## 编译方法

### 使用 GCC（推荐）

```bash
# Linux / macOS / Git Bash
bash build.sh

# Windows CMD
build.bat
```

### 使用 CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### 手动编译

```bash
# 主程序
gcc -o transacted_hollowing.exe \
    src/transacted_hollowing.c src/pe_utils.c \
    -lktmw32 -lntdll -municode -I src

# 测试载荷
gcc -o test_payload.exe src/test_payload.c
```

## 使用方法

### 基本用法

```bash
transacted_hollowing.exe <载荷路径> [目标进程]
```

### 参数说明

- **载荷路径**（必需）：要注入执行的 PE 文件路径
- **目标进程**（可选）：被镂空的目标进程，默认为 `calc.exe`

### 使用示例

```bash
# 使用默认目标（计算器）
transacted_hollowing.exe test_payload.exe

# 指定目标进程
transacted_hollowing.exe test_payload.exe notepad.exe

# 使用完整路径
transacted_hollowing.exe C:\payload.exe C:\Windows\System32\\notepad.exe
```

## 运行示例

```
======================================
      事务性镂空技术演示程序
   Transacted Hollowing Demo
======================================

========== 开始事务性镂空 ==========
载荷文件：test_payload.exe
目标进程：C:\Windows\System32\calc.exe

[0] 读取载荷文件
    载荷架构：64 位

[1] 创建 NTFS 事务
    事务句柄：0x00000128

[2] 创建事务性文件
    文件路径：C:\Users\...\AppData\Local\Temp\TH1234.tmp
    文件句柄：0x0000012C

[3] 写入载荷到事务性文件
    载荷大小：51200 字节
    已写入：51200 字节

[4] 创建内存节对象（SEC_IMAGE）
    节句柄：0x00000130

[5] 回滚事务（删除文件）
    事务已回滚，文件已删除
    内存节创建成功！

[6] 创建挂起的目标进程
    进程 ID：5678
    进程句柄：0x00000134

[7] 映射内存节到目标进程
    映射基址：0x00007FF6C0000000

[8] 更新 PEB 中的 ImageBase
    ImageBase 已更新

[9] 更新线程入口点
    入口点 RVA：0x1000
    入口点 VA：0x00007FF6C0001000

[10] 恢复线程执行

========== 事务性镂空完成 ==========
进程 5678 正在运行载荷代码
```

## 技术特点

### ✅ 优点

1. **无文件落地**
   - 载荷通过事务性文件写入
   - 事务回滚后文件被删除
   - 难以通过文件监控检测

2. **内存映射为 SEC_IMAGE**
   - 以镜像方式映射，像正常加载的模块
   - 节区权限正确设置（非全 RWX）
   - 在进程列表中显示正常

3. **与 PEB 集成**
   - ImageBase 正确写入 PEB
   - 可被正常枚举为主模块
   - 环境更真实

4. **中文化**
   - 完整的中文注释
   - 详细的中文输出
   - 易于理解学习

### ⚠️ 限制

1. **需要管理员权限**
   - 某些目标进程可能需要提权

2. **需要 NTFS 文件系统**
   - 事务机制依赖 NTFS

3. **目标进程必须是新创建的**
   - 不支持注入到已运行的进程

4. **载荷需要有重定位表**
   - 如果基址不匹配需要重定位

## 检测与防御

### 行为特征

1. **创建事务性文件**
   ```
   CreateTransaction
   CreateFileTransactedW
   RollbackTransaction
   ```

2. **从文件创建镜像节**
   ```
   NtCreateSection(SEC_IMAGE)
   ```

3. **使用未导出的 API**
   ```
   CreateProcessInternalW
   ```

4. **修改远程进程内存**
   ```
   WriteProcessMemory (PEB)
   SetThreadContext
   ```

### 检测方法

| 检测点 | 方法 |
|--------|------|
| 事务创建 | 监控 `CreateTransaction` / `CreateFileTransactedW` |
| SEC_IMAGE 节 | 检测未映射到文件的镜像节 |
| PEB 修改 | 监控 `WriteProcessMemory` 到 PEB 区域 |
| 未命名镜像 | 查找没有文件路径的加载模块 |

### 防御建议

1. **EDR/XDR 解决方案**
   - 监控事务性文件 API
   - 检测 SEC_IMAGE 异常使用
   - 跟踪进程创建和内存修改

2. **进程完整性检查**
   - 验证主模块路径
   - 检查镜像是否有效文件

3. **行为分析**
   - 关联事务创建和进程创建
   - 检测回滚事务后的内存映射

## 代码结构

### 关键函数

| 函数 | 功能 |
|------|------|
| `CreateTransactedSection` | 创建事务性内存节 |
| `CreateSuspendedProcess` | 创建挂起进程 |
| `MapSectionToProcess` | 映射节到进程 |
| `UpdateRemoteImageBase` | 更新 PEB ImageBase |
| `UpdateEntryPoint` | 更新线程入口点 |

### 数据流

```
Payload File → Transaction File → Memory Section → Target Process
     ↓                ↓                  ↓              ↓
  Read File    Write + Rollback    Map as Image    Execute
```

## 参考资源

### 原始项目

- [hasherezade/transacted_hollowing](https://github.com/hasherezade/transacted_hollowing)

### 相关技术

- [Process Hollowing](../01-process-hollowing/)
- [Process Doppelgänging](https://github.com/hasherezade/process_doppelganging)
- [Process Ghosting](https://github.com/hasherezade/process_ghosting)

### 技术文章

- [Process Doppelgänging Meets Process Hollowing](https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/)
- [Transacted Hollowing - BlackHat 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf)

### MSDN 文档

- [Kernel Transaction Manager](https://docs.microsoft.com/en-us/windows/win32/ktm/kernel-transaction-manager-portal)
- [NtCreateSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection)
- [Transacted NTFS](https://docs.microsoft.com/en-us/windows/win32/fileio/transactional-ntfs-portal)

## 法律声明

**本程序仅供安全研究和教育目的使用。**

未经授权使用本技术进行攻击活动是违法的。使用者应：
- 遵守所在地区的法律法规
- 仅在授权环境中使用
- 不得用于非法目的

**作者不对任何滥用行为负责。**

## 更新日志

### 2024-10-06

- ✅ 完成事务性镂空技术实现
- ✅ 支持 32/64 位载荷
- ✅ 完整中文注释和文档
- ✅ 测试载荷程序

---

**技术等级**：⭐⭐⭐⭐⭐
**隐蔽性**：⭐⭐⭐⭐⭐
**复杂度**：⭐⭐⭐⭐

**下一步学习**：DLL 注入、反射 DLL 注入
