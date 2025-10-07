# SetWindowsHookEx DLL Injection

基于 Windows 钩子机制的 DLL 注入技术，利用 `SetWindowsHookEx` API 将 DLL 加载到目标进程。

## 📚 技术原理

### 什么是 Windows 钩子？

Windows 钩子 (Hook) 是一种消息处理机制，允许应用程序监视和拦截系统消息。当在其他进程的线程上设置钩子时，**Windows 会自动将包含钩子过程的 DLL 加载到目标进程**。

### 注入流程

```
1. Injector 查找目标窗口句柄
         ↓
2. 获取窗口的线程 ID (GetWindowThreadProcessId)
         ↓
3. 在本地加载 DLL (LoadLibraryEx + DONT_RESOLVE_DLL_REFERENCES)
   - 不解析依赖，不调用 DllMain
   - 仅获取 DLL 的模块句柄和导出函数地址
         ↓
4. 获取钩子过程地址 (GetProcAddress)
   - DLL 必须导出钩子过程函数 (例如 "NextHook")
         ↓
5. 设置钩子 (SetWindowsHookEx)
   - hookType: 钩子类型 (WH_GETMESSAGE, WH_KEYBOARD 等)
   - hookProc:  钩子过程地址
   - hMod:      DLL 模块句柄
   - threadId:  目标线程 ID
         ↓
6. Windows 自动加载 DLL 到目标进程 ✅
   - DllMain(DLL_PROCESS_ATTACH) 被调用
   - DLL 已在目标进程地址空间
         ↓
7. 发送消息触发钩子 (PostThreadMessage)
   - 触发钩子过程执行
   - DLL 代码在目标进程中运行
         ↓
8. 卸载钩子 (UnhookWindowsHookEx)
   - 钩子被移除
   - 但 DLL 仍保留在目标进程中
```

### 为什么 Windows 要自动加载 DLL？

钩子过程必须在目标进程的地址空间中执行，因为：

1. **消息在目标进程中产生** - 钩子需要在消息产生的进程中处理
2. **访问进程内存** - 钩子可能需要访问目标进程的内存和资源
3. **性能考虑** - 跨进程调用钩子过程会严重影响性能

因此，Windows 会自动将包含钩子过程的 DLL 映射到目标进程的地址空间。

## 🔑 关键 API

### SetWindowsHookEx

```c
HHOOK SetWindowsHookExA(
    int       idHook,      // 钩子类型
    HOOKPROC  lpfn,        // 钩子过程
    HINSTANCE hmod,        // DLL 模块句柄
    DWORD     dwThreadId   // 线程 ID (0 = 全局钩子)
);
```

#### 钩子类型

| 类型 | 值 | 说明 | 全局/线程 |
|------|------|------|-----------|
| `WH_MSGFILTER` | -1 | 消息过滤器钩子 | 线程 |
| `WH_JOURNALRECORD` | 0 | 日志记录钩子 | 全局 |
| `WH_JOURNALPLAYBACK` | 1 | 日志回放钩子 | 全局 |
| `WH_KEYBOARD` | 2 | 键盘钩子 | 线程 |
| **`WH_GETMESSAGE`** | **3** | **获取消息钩子** ✅ | 线程 |
| `WH_CALLWNDPROC` | 4 | 窗口过程调用钩子 | 线程 |
| `WH_CBT` | 5 | CBT 钩子 | 线程/全局 |
| `WH_SYSMSGFILTER` | 6 | 系统消息过滤器钩子 | 全局 |
| `WH_MOUSE` | 7 | 鼠标钩子 | 线程 |
| `WH_DEBUG` | 9 | 调试钩子 | 线程/全局 |
| `WH_SHELL` | 10 | Shell 钩子 | 线程/全局 |
| `WH_FOREGROUNDIDLE` | 11 | 前台空闲钩子 | 线程/全局 |
| `WH_CALLWNDPROCRET` | 12 | 窗口过程返回钩子 | 线程 |
| `WH_KEYBOARD_LL` | 13 | 低级键盘钩子 | 全局 |
| `WH_MOUSE_LL` | 14 | 低级鼠标钩子 | 全局 |

**推荐**: `WH_GETMESSAGE` (3) - 最通用，适用于所有窗口消息

### 钩子过程签名

```c
LRESULT CALLBACK HookProc(
    int    code,     // 钩子代码
    WPARAM wParam,   // 参数 1 (取决于钩子类型)
    LPARAM lParam    // 参数 2 (取决于钩子类型)
);
```

**关键要求**:
- 必须调用 `CallNextHookEx` 传递消息链
- 如果 `code < 0`，必须直接调用 `CallNextHookEx` 而不处理
- 必须导出此函数 (`__declspec(dllexport)`)

### UnhookWindowsHookEx

```c
BOOL UnhookWindowsHookEx(
    HHOOK hhk    // 钩子句柄
);
```

**注意**: 卸载钩子后，DLL **不会**立即从目标进程卸载，会保留直到进程退出。

## 💻 编译

### Windows (使用 GCC)

```bash
build.bat
```

### Linux/macOS (交叉编译)

```bash
./build.sh
```

需要安装 MinGW:
```bash
# Ubuntu/Debian
sudo apt install mingw-w64

# macOS
brew install mingw-w64
```

## 🚀 使用示例

### 基本用法

```bash
# 1. 启动目标程序 (必须是 GUI 程序)
start notepad

# 2. 运行注入器
build\setwindowshookex_injection.exe "无标题 - 记事本" C:\full\path\to\hook.dll

# 3. 注入成功后会显示消息框
```

### 指定钩子类型

```bash
# 使用键盘钩子 (WH_KEYBOARD = 2)
build\setwindowshookex_injection.exe "Calculator" C:\test\hook.dll 2

# 使用鼠标钩子 (WH_MOUSE = 7)
build\setwindowshookex_injection.exe "Calculator" C:\test\hook.dll 7
```

### 查看可用窗口

```bash
# 运行不带参数会列出所有可见窗口
build\setwindowshookex_injection.exe
```

## 📝 DLL 开发要求

### 必须导出钩子过程

```c
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    // 处理钩子消息
    if (code >= 0) {
        // 自定义逻辑...
    }

    // 必须调用 CallNextHookEx 传递消息链
    return CallNextHookEx(NULL, code, wParam, lParam);
}
```

### DllMain 实现

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL 加载到目标进程时执行
            MessageBoxA(NULL, "DLL Injected!", "Success", MB_OK);
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            // DLL 卸载时执行
            break;
    }
    return TRUE;
}
```

## ⚠️ 限制与注意事项

### 技术限制

| 限制 | 说明 |
|------|------|
| **仅限 GUI 进程** | 目标必须有窗口和消息循环 |
| **需要窗口句柄** | 必须知道目标窗口的标题或句柄 |
| **DLL 导出要求** | DLL 必须导出钩子过程函数 |
| **触发要求** | 需要发送消息或用户交互来触发钩子 |
| **DLL 持久性** | UnhookWindowsHookEx 后 DLL 仍保留在进程中 |

### 为什么只能注入 GUI 进程？

1. **消息循环依赖** - 钩子通过 Windows 消息循环工作
2. **user32.dll 依赖** - SetWindowsHookEx 在 user32.dll 中
3. **控制台程序** - 通常没有消息循环，钩子不会被触发

尝试注入控制台程序：
```bash
# ❌ 失败 - 控制台程序没有窗口
build\setwindowshookex_injection.exe "cmd.exe" hook.dll

# ✅ 成功 - GUI 程序有窗口
build\setwindowshookex_injection.exe "记事本" hook.dll
```

## 📊 与其他注入方法的对比

| 特性 | SetWindowsHookEx | CreateRemoteThread | Process Hollowing |
|------|------------------|--------------------|--------------------|
| **注入目标** | 仅 GUI 进程 | 任何进程 | 任何进程 |
| **隐蔽性** | 高 (使用合法 API) | 中 | 高 |
| **需要窗口** | ✅ 是 | ❌ 否 | ❌ 否 |
| **DLL 要求** | 必须导出钩子过程 | 无特殊要求 | 无 (可用 shellcode) |
| **触发方式** | 发送消息 | 自动执行 | 自动执行 |
| **DLL 持久性** | 强 (卸载钩子后仍保留) | 中 | 中 |
| **检测难度** | 低 (合法行为) | 中 (可疑行为) | 高 |
| **权限要求** | 低 (同权限用户) | 中 (可能需要 SeDebugPrivilege) | 高 |
| **跨会话** | ❌ 否 | ❌ 否 | ❌ 否 |

### SetWindowsHookEx 的优势

1. **合法性强** - 使用 Windows 提供的标准 API
2. **不引起警觉** - 许多合法程序使用钩子 (例如输入法、屏幕录制软件)
3. **Windows 自动加载** - 不需要手动分配内存、写入代码
4. **无需 VirtualAllocEx/WriteProcessMemory** - 减少可疑操作

### SetWindowsHookEx 的劣势

1. **仅限 GUI** - 无法注入控制台/服务进程
2. **需要窗口信息** - 必须知道窗口标题或句柄
3. **DLL 要求** - 必须导出特定函数
4. **触发延迟** - 需要等待消息或用户交互

## 🔍 检测与防御

### 检测方法

1. **EnumWindows + GetClassLong** - 检测异常钩子
   ```c
   HHOOK hHook = (HHOOK)GetWindowLongPtr(hwnd, GWLP_WNDPROC);
   ```

2. **进程内存扫描** - 检测未预期的 DLL
   ```c
   EnumProcessModules(hProcess, ...);
   ```

3. **钩子链审计** - 检测钩子链中的可疑 DLL
   ```c
   // 检测系统范围内所有钩子
   ```

4. **EDR/AV 监控** - 监视 SetWindowsHookEx 调用
   - 检测频繁设置钩子的行为
   - 检测从非信任位置加载的 DLL

### 防御措施

1. **应用程序白名单** - 只允许信任的 DLL
2. **代码签名验证** - 验证 DLL 的数字签名
3. **钩子监控** - 定期检查进程的钩子链
4. **内存保护** - 使用 ASLR、DEP 等保护机制

## 🛠️ 高级用法

### 1. 键盘记录器

```c
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION) {
        // wParam = 虚拟键码
        if (wParam == VK_RETURN) {
            // 记录 Enter 键
            LogKeyPress("ENTER");
        } else if (wParam >= 0x41 && wParam <= 0x5A) {
            // 记录字母键
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

        // 拦截关闭消息
        if (pMsg->message == WM_CLOSE) {
            MessageBoxA(NULL, "阻止窗口关闭!", "Hook", MB_OK);
            return 1; // 阻止消息传递
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
            char msg[256];
            sprintf(msg, "左键点击: (%ld, %ld)", pMouse->pt.x, pMouse->pt.y);
            OutputDebugStringA(msg);
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}
```

### 4. 结合 API 钩子

```c
// 在 DLL_PROCESS_ATTACH 中安装 API 钩子
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 使用 MinHook 或 Detours 钩取 API
        MH_Initialize();
        MH_CreateHook(&MessageBoxA, &HookedMessageBoxA, (void**)&OriginalMessageBoxA);
        MH_EnableHook(&MessageBoxA);
    }
    return TRUE;
}
```

## 📚 参考资料

- **MSDN**: [SetWindowsHookEx function](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)
- **MSDN**: [Windows Hooks](https://docs.microsoft.com/en-us/windows/win32/winmsg/hooks)
- **MITRE ATT&CK**: [T1055.012 - Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

## ⚖️ 免责声明

此工具仅用于教育和研究目的。未经授权使用此技术可能违反法律。使用者需自行承担相关责任。

## 🔗 相关技术

- **DLL Injection (CreateRemoteThread)** - `techniques/12-dll-injection/`
- **Shellcode Injection** - `techniques/13-shellcode-injection/`
- **APC Injection** - 异步过程调用注入
- **Thread Hijacking** - 线程劫持注入
