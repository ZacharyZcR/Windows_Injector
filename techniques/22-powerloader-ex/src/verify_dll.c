#include <windows.h>
#include <stdio.h>

/**
 * PowerLoaderEx 验证 DLL
 *
 * 此 DLL 会在加载时创建验证文件
 */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 创建验证文件
        HANDLE hFile = CreateFileA(
            "C:\\Users\\Public\\powerloader_ex_verified.txt",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            const char* content = "PowerLoaderEx Injection Verified!\n"
                                 "Technique: Shared Desktop Heap Injection\n"
                                 "Target: Explorer.exe Shell_TrayWnd\n"
                                 "Method: SetWindowLongPtr CTray Object Hijack\n"
                                 "Status: DLL loaded successfully!\n";
            DWORD written;
            WriteFile(hFile, content, lstrlenA(content), &written, NULL);
            CloseHandle(hFile);
        }
    }
    return TRUE;
}
