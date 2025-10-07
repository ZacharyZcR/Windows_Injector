/*
 * Reflective DLL Injection - Test DLL
 *
 * 测试用反射 DLL
 *
 * 这个 DLL 会：
 * 1. 导出 ReflectiveLoader 函数（通过包含 ReflectiveLoader.c）
 * 2. 在加载时显示消息框
 * 3. 演示反射加载成功
 *
 * 编译要求：
 * - 必须定义 REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
 * - 这样才能使用自定义的 DllMain 而不是 ReflectiveLoader.c 中的默认 DllMain
 * - 在构建脚本中已定义
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// 包含反射加载器代码
#include "ReflectiveLoader.c"

// 全局变量：DLL 实例句柄
extern HINSTANCE hAppInstance;

// ========================================
// 自定义 DllMain
// ========================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;
    char message[512] = {0};
    DWORD processId = 0;
    char processPath[MAX_PATH] = {0};

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // 保存实例句柄
            hAppInstance = hinstDLL;

            // 禁用线程通知
            DisableThreadLibraryCalls(hinstDLL);

            // 获取进程信息
            processId = GetCurrentProcessId();

            // 获取进程路径
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcess != NULL) {
                DWORD size = MAX_PATH;
                QueryFullProcessImageNameA(hProcess, 0, processPath, &size);
                CloseHandle(hProcess);
            }

            // 构造消息
            snprintf(message, sizeof(message),
                "✅ 反射 DLL 注入成功!\n\n"
                "进程 ID: %lu\n"
                "进程路径: %s\n\n"
                "DLL 基址: 0x%p\n\n"
                "这个 DLL 通过反射加载器（ReflectiveLoader）加载，\n"
                "没有使用 Windows 的 LoadLibrary API。\n\n"
                "关键特点：\n"
                "• DLL 自己实现 PE 加载器\n"
                "• 不触发 LoadLibrary 相关的 ETW 事件\n"
                "• 不经过标准 DLL 加载流程\n"
                "• 高度隐蔽，难以检测",
                processId,
                strlen(processPath) > 0 ? processPath : "未知",
                hinstDLL
            );

            // 显示消息框
            MessageBoxA(NULL, message, "Reflective DLL Injection - 成功", MB_OK | MB_ICONINFORMATION);

            break;

        case DLL_PROCESS_DETACH:
            // DLL 卸载
            MessageBoxA(NULL,
                "⚠️ 反射 DLL 正在卸载\n\n"
                "DLL 已从进程中移除。",
                "Reflective DLL Injection - 卸载",
                MB_OK | MB_ICONWARNING);
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // 已禁用线程通知
            break;
    }

    return bReturnValue;
}

/*
 * 高级用法示例
 * ==============
 *
 * 1. 导出自定义函数供注入器调用
 * --------------------------------
 * __declspec(dllexport) void CustomFunction(void) {
 *     MessageBoxA(NULL, "Custom Function Called!", "Test", MB_OK);
 * }
 *
 * 2. 实现钩子或 API 拦截
 * ----------------------
 * 在 DLL_PROCESS_ATTACH 中使用 MinHook 或 Detours 安装 API 钩子
 *
 * 3. 加载额外的 DLL
 * -----------------
 * LoadLibraryA("another.dll"); // 在 DLL_PROCESS_ATTACH 中
 *
 * 4. 反调试和反检测
 * -----------------
 * - 检测调试器
 * - 检测虚拟机
 * - 混淆关键代码
 */
