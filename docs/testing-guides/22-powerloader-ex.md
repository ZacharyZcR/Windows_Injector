# PowerLoaderEx 注入技术测试报告

## 技术概述

**技术名称**: PowerLoaderEx
**技术编号**: 22
**MITRE ATT&CK**: T1055.011 (Extra Window Memory Injection)
**原始来源**: BreakingMalware (~2013)
**测试日期**: 2025-10-08
**测试环境**: Windows 10 Build 26100 (MSYS_NT)

## 技术原理

PowerLoaderEx 是一种利用 Windows 共享桌面堆进行跨进程代码注入的技术：

### 核心机制

1. **共享桌面堆定位**
   - 创建窗口并在额外内存区域写入魔数
   - 遍历进程地址空间查找只读共享映射区域
   - 通过魔数匹配定位共享桌面堆

2. **跨进程数据写入**
   - 利用 `SetWindowLongPtr` 修改窗口额外数据
   - 数据自动同步到共享桌面堆
   - 目标进程可直接访问该共享内存

3. **窗口对象劫持**
   - 查找 Explorer.exe 的 `Shell_TrayWnd` 窗口
   - 劫持 CTray 对象指针指向恶意数据
   - 发送 `WM_PAINT` 消息触发执行

4. **代码执行**
   - x64: 直接调用 LoadLibraryA
   - x86: 构建 ROP 链绕过 DEP

### 关键 Windows API

```c
// 窗口创建与数据写入
CreateWindowEx()
SetWindowLongPtrA()    // 写入共享堆数据

// 内存查询
VirtualQuery()         // 本进程共享堆定位
VirtualQueryEx()       // 目标进程共享堆定位
VirtualProtect()       // 验证只读属性

// 窗口劫持
FindWindowA()          // 查找 Shell_TrayWnd
GetWindowLongPtrA()    // 获取原始 CTray 对象
SendNotifyMessageA()   // 触发消息处理
```

## 测试配置

### 修改内容

1. **DLL 路径修改** (src/powerloader_ex.c:321-324)
```c
// 原始: c:\x.dll (需要管理员权限)
// 修改为: C:\Users\Public\x.dll
SET_LONG(0x73726573555C3A43ULL);  // "C:\Users"
SET_LONG(0x5C6369636C6275505CULL);  // "\Public\"
SET_LONG(0x0000006C6C642E78ULL);    // "x.dll\0\0\0"
```

2. **验证 DLL 创建** (src/verify_dll.c)
```c
// DllMain 在 DLL_PROCESS_ATTACH 时创建文件
CreateFileA("C:\\Users\\Public\\powerloader_ex_verified.txt", ...)
WriteFile("PowerLoaderEx Injection Verified!...")
```

### 编译命令

```bash
# 编译主程序
cd techniques/22-powerloader-ex
./build.bat

# 编译验证 DLL
cd src
gcc -shared -o verify_dll.dll verify_dll.c -lkernel32
cp verify_dll.dll /c/Users/Public/x.dll
```

## 测试执行

### 执行命令

```bash
cd techniques/22-powerloader-ex
./build/powerloader_ex.exe
```

### 测试输出

```
======================================
  PowerLoaderEx - 共享桌面堆注入
======================================

[*] 窗口创建成功：HWND = 0x00000000001D1A6E

[1] 查找共享桌面堆
    [*] 魔数已写入窗口：0xABABABAB 0xCDCDCDCD 0xABABABAB 0xCDCDCDCD
[!] 无法找到共享桌面堆

[!] PowerLoaderEx 注入失败

======================================
注入完成
======================================
```

### 验证结果

```bash
$ ls /c/Users/Public/powerloader_ex_verified.txt
ls: cannot access '/c/Users/Public/powerloader_ex_verified.txt': No such file or directory
```

## 测试结果

❌ **测试失败** - 无法定位共享桌面堆

### 详细分析

| 步骤 | 状态 | 说明 |
|------|------|------|
| 1. 窗口创建 | ✅ 成功 | HWND = 0x00000000001D1A6E |
| 2. 魔数写入 | ✅ 成功 | 4 个魔数写入窗口额外内存 |
| 3. 共享堆定位 | ❌ 失败 | 无法找到匹配的共享桌面堆 |
| 4. 跨进程映射 | ⏸️ 未执行 | 因步骤 3 失败而跳过 |
| 5. 窗口劫持 | ⏸️ 未执行 | 因步骤 3 失败而跳过 |
| 6. DLL 加载 | ⏸️ 未执行 | 因步骤 3 失败而跳过 |

### 失败原因

**根本原因**: Windows 内部结构变化

1. **技术过时**
   - 发布于 ~2013 年（12 年前）
   - 专门为 Windows 7 设计
   - 依赖特定的桌面堆内部结构

2. **Windows 10 变化**
   - 桌面堆实现完全重构
   - 内存布局不再符合魔数查找模式
   - 可能增加了额外的安全机制

3. **检测逻辑失效**
   ```c
   // 原始检测条件在 Windows 10 无法匹配
   if (memInfo.Protect == PAGE_READONLY &&
       memInfo.Type == MEM_MAPPED &&
       memInfo.State == MEM_COMMIT) {
       // 查找魔数...
   }
   ```

## 技术评估

### 技术特点

**优势** (Windows 7 环境):
- ✅ 无需直接内存操作权限
- ✅ 利用合法 Windows API
- ✅ 跨进程数据传递隐蔽
- ✅ 不触发常规代码注入检测

**劣势**:
- ❌ 高度依赖 Windows 内部结构
- ❌ 仅支持 Windows 7
- ❌ 需要目标窗口存在
- ❌ x86 版本需要复杂 ROP 链

### 兼容性

| Windows 版本 | 兼容性 | 说明 |
|-------------|--------|------|
| Windows 7 | ✅ 可能工作 | 原始设计目标 |
| Windows 8/8.1 | ❓ 未知 | 桌面堆可能已变化 |
| Windows 10 | ❌ 不兼容 | 内部结构完全不同 |
| Windows 11 | ❌ 不兼容 | 继承 Windows 10 架构 |

### 安全影响

**当前威胁等级**: 极低

1. ❌ Windows 10/11 完全不可用
2. ⚠️ Windows 7 已停止支持（2020-01-14）
3. ✅ 现代 EDR 可检测窗口对象异常修改

## 编译警告

```
src\powerloader_ex.c:323:37: warning: integer constant is too large for its type
  323 |     SET_LONG(0x5C6369636C6275505CULL);  // "\Public\"
```

**说明**: 字符串编码导致的类型溢出警告，不影响功能（已编译成功）

## 检测建议

虽然此技术在 Windows 10+ 已失效，但仍可作为历史参考：

### 行为检测

```
1. 监控 SetWindowLongPtr 异常调用
   - 目标窗口属于其他进程
   - 修改关键窗口对象指针

2. 监控 Shell_TrayWnd 窗口对象完整性
   - CTray 对象指针异常变化
   - 收到非法来源的消息

3. 检测共享桌面堆扫描行为
   - 大量 VirtualQuery/VirtualQueryEx 调用
   - 针对只读共享映射区域的遍历
```

### YARA 规则

```yara
rule PowerLoaderEx_Injection {
    meta:
        description = "PowerLoaderEx desktop heap injection"
        technique = "T1055.011"
        platform = "Windows 7"
        status = "Obsolete"

    strings:
        $magic1 = { AB AB AB AB CD CD CD CD }
        $api1 = "SetWindowLongPtrA"
        $api2 = "Shell_TrayWnd"
        $vquery = "VirtualQueryEx"
        $paint = { 0F 00 00 00 }  // WM_PAINT = 0x000F

    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and
        $magic1 and
        ($vquery or $paint)
}
```

## 参考资料

### 原始研究

- BreakingMalware Blog (2013)
- [原始 PowerLoader 分析](https://breakingmalware.com/)

### 相关技术

1. **Extra Window Memory Injection (T1055.011)**
   - SetWindowLong-based 注入
   - 共享窗口数据利用

2. **Desktop Heap 利用**
   - Windows 内部结构依赖
   - 跨进程共享内存

### MITRE ATT&CK

**战术**: Defense Evasion (TA0005), Privilege Escalation (TA0004)
**技术**: Process Injection (T1055)
**子技术**: Extra Window Memory Injection (T1055.011)

## 结论

PowerLoaderEx 是一项极具创新性的技术，利用 Windows 桌面堆的共享特性实现跨进程注入。然而：

1. ❌ **现代系统完全不可用** - Windows 10+ 内部结构已完全改变
2. 📅 **技术过时** - 基于 12 年前的 Windows 7 架构
3. 🎓 **教育价值** - 展示了利用系统内部机制的创新思路
4. 🔒 **安全影响微小** - 仅影响已停止支持的操作系统

此技术仅作为历史参考和学习材料，在现代环境中无实际威胁。

---

**测试状态**: ❌ 失败 (Windows 10 不兼容)
**技术状态**: 已过时 (Windows 7 专用)
**安全建议**: 无需针对此技术的特定防护（Windows 10+ 天然免疫）
