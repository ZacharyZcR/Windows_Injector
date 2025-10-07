/**
 * ===================================================================
 * 测试 DLL - 用于验证 DLL Injection
 * ===================================================================
 *
 * 此 DLL 在加载和卸载时会显示消息框，用于验证注入是否成功。
 */

#include <windows.h>
#include <stdio.h>

/**
 * DLL 入口点
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    char message[256];
    DWORD pid = GetCurrentProcessId();

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL 被加载
            sprintf(message,
                    "✅ DLL 已加载！\n\n"
                    "进程 ID: %lu\n"
                    "DLL 句柄: 0x%p\n\n"
                    "这证明 DLL Injection 成功！",
                    pid, hinstDLL);

            MessageBoxA(NULL, message, "DLL Injection - 加载成功", MB_OK | MB_ICONINFORMATION);
            break;

        case DLL_PROCESS_DETACH:
            // DLL 被卸载
            sprintf(message,
                    "⚠️ DLL 正在卸载\n\n"
                    "进程 ID: %lu\n\n"
                    "DLL 即将从进程中移除。",
                    pid);

            MessageBoxA(NULL, message, "DLL Injection - 卸载", MB_OK | MB_ICONWARNING);
            break;

        case DLL_THREAD_ATTACH:
            // 新线程创建
            break;

        case DLL_THREAD_DETACH:
            // 线程终止
            break;
    }

    return TRUE;
}

/**
 * 导出函数示例
 */
__declspec(dllexport) void TestFunction() {
    MessageBoxA(NULL,
                "这是从注入的 DLL 中调用的函数！",
                "DLL Injection - 导出函数",
                MB_OK | MB_ICONINFORMATION);
}
