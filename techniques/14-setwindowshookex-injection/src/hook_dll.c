/*
 * SetWindowsHookEx 测试 DLL
 *
 * 这个 DLL 实现了一个简单的钩子过程，用于演示 SetWindowsHookEx 注入。
 *
 * 关键要求:
 * 1. 必须导出 NextHook 函数 (injector 会查找此函数)
 * 2. NextHook 必须调用 CallNextHookEx 传递消息链
 * 3. 钩子过程必须是 CALLBACK 调用约定
 *
 * DLL 加载时会显示一个消息框，证明注入成功。
 */

#include <windows.h>
#include <stdio.h>

// 全局变量
static HINSTANCE g_hInstance = NULL;
static BOOL g_bAlreadyShown = FALSE;

// 显示注入成功消息
void ShowInjectionMessage() {
    // 防止重复显示
    if (g_bAlreadyShown) {
        return;
    }

    g_bAlreadyShown = TRUE;

    DWORD processId = GetCurrentProcessId();
    char message[512] = {0};
    char processPath[MAX_PATH] = {0};

    // 获取进程路径
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess != NULL) {
        DWORD size = MAX_PATH;
        QueryFullProcessImageNameA(hProcess, 0, processPath, &size);
        CloseHandle(hProcess);
    }

    // 构造消息
    snprintf(message, sizeof(message),
        "✅ SetWindowsHookEx 注入成功!\n\n"
        "进程 ID: %lu\n"
        "进程路径: %s\n\n"
        "DLL 已通过 Windows 钩子机制加载到此进程。\n"
        "钩子过程现在可以监视和处理消息。",
        processId,
        strlen(processPath) > 0 ? processPath : "未知"
    );

    MessageBoxA(NULL, message, "SetWindowsHookEx Injection - 成功", MB_OK | MB_ICONINFORMATION);
}

// 钩子过程 - 必须导出此函数
__declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
    /*
     * 钩子过程参数说明:
     *
     * code   - 钩子代码，指示如何处理消息
     *          - 如果 code < 0，必须调用 CallNextHookEx 而不处理
     *          - 如果 code >= 0，可以处理消息
     *
     * wParam - 消息参数 (取决于钩子类型)
     * lParam - 消息参数 (取决于钩子类型)
     *
     * 返回值 - 传递给 CallNextHookEx 的返回值
     */

    // 显示注入成功消息 (仅首次调用)
    if (!g_bAlreadyShown) {
        ShowInjectionMessage();
    }

    // 处理钩子消息
    if (code >= 0) {
        // 这里可以添加自定义逻辑
        // 例如: 记录消息、修改参数、阻止消息等

        // 示例: 简单的消息日志 (注释掉以避免过多输出)
        /*
        char debugMsg[256];
        snprintf(debugMsg, sizeof(debugMsg),
            "[Hook] code=%d, wParam=0x%llx, lParam=0x%llx\n",
            code, (unsigned long long)wParam, (unsigned long long)lParam);
        OutputDebugStringA(debugMsg);
        */
    }

    // 必须调用 CallNextHookEx 传递消息链
    // 参数1: 钩子句柄 (可以为 NULL，Windows 会自动查找)
    // 参数2-4: 传递原始参数
    return CallNextHookEx(NULL, code, wParam, lParam);
}

// DllMain - DLL 入口点
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            /*
             * DLL 首次加载到进程时调用
             *
             * 注意: 当 injector 使用 LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)
             * 在本地加载 DLL 时，DllMain 不会被调用。
             *
             * 但是，当 Windows 通过 SetWindowsHookEx 将 DLL 加载到目标进程时，
             * DllMain 会被正常调用。
             */

            g_hInstance = hinstDLL;

            // 禁用线程通知以提高性能
            DisableThreadLibraryCalls(hinstDLL);

            // 显示注入成功消息
            ShowInjectionMessage();

            break;

        case DLL_PROCESS_DETACH:
            /*
             * DLL 从进程卸载时调用
             *
             * 注意: 即使 UnhookWindowsHookEx 被调用，DLL 也不会立即卸载。
             * DLL 会保留在进程中直到进程退出。
             */

            MessageBoxA(NULL,
                "⚠️ DLL 正在卸载\n\n"
                "钩子 DLL 即将从进程中卸载。",
                "SetWindowsHookEx Injection - 卸载",
                MB_OK | MB_ICONWARNING);

            break;

        case DLL_THREAD_ATTACH:
            // 新线程创建时调用 (已禁用)
            break;

        case DLL_THREAD_DETACH:
            // 线程退出时调用 (已禁用)
            break;
    }

    return TRUE;
}

/*
 * 高级用法示例
 * ==============
 *
 * 1. 键盘钩子 (WH_KEYBOARD)
 * --------------------------
 * __declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
 *     if (code >= 0) {
 *         // wParam = 虚拟键码 (VK_*)
 *         // lParam = 按键信息 (重复计数、扫描码等)
 *
 *         if (wParam == VK_RETURN) {
 *             MessageBoxA(NULL, "你按下了 Enter 键!", "键盘钩子", MB_OK);
 *         }
 *     }
 *     return CallNextHookEx(NULL, code, wParam, lParam);
 * }
 *
 * 2. 鼠标钩子 (WH_MOUSE)
 * ----------------------
 * __declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
 *     if (code >= 0) {
 *         // wParam = 鼠标消息 (WM_LBUTTONDOWN, WM_MOUSEMOVE 等)
 *         // lParam = MOUSEHOOKSTRUCT 指针
 *
 *         MOUSEHOOKSTRUCT* pMouse = (MOUSEHOOKSTRUCT*)lParam;
 *
 *         if (wParam == WM_LBUTTONDOWN) {
 *             char msg[256];
 *             sprintf(msg, "左键点击位置: (%ld, %ld)", pMouse->pt.x, pMouse->pt.y);
 *             MessageBoxA(NULL, msg, "鼠标钩子", MB_OK);
 *         }
 *     }
 *     return CallNextHookEx(NULL, code, wParam, lParam);
 * }
 *
 * 3. 消息钩子 (WH_GETMESSAGE)
 * ---------------------------
 * __declspec(dllexport) LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam) {
 *     if (code >= 0) {
 *         // lParam = MSG 结构指针
 *         MSG* pMsg = (MSG*)lParam;
 *
 *         // 拦截特定消息
 *         if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_ESCAPE) {
 *             MessageBoxA(NULL, "Esc 键被拦截!", "消息钩子", MB_OK);
 *             // 可以修改或丢弃消息
 *         }
 *     }
 *     return CallNextHookEx(NULL, code, wParam, lParam);
 * }
 *
 * 4. API 钩子 (结合 MinHook/Detours)
 * ----------------------------------
 * 在 DLL_PROCESS_ATTACH 中安装 API 钩子，在钩子过程中执行自定义逻辑。
 * 这样可以实现更强大的功能，如拦截 API 调用、修改返回值等。
 */
