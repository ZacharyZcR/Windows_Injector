#include <windows.h>
#include <stdio.h>

/**
 * 简单的触发程序 - 用于测试 Module Stomping
 * 等待用户输入后调用 CreateFile，会触发底层的 NtOpenFile
 */

int main() {
    printf("========== Hook Trigger Program ==========\n");
    printf("This program will auto-trigger NtOpenFile after 15 seconds\n\n");

    printf("Waiting for injection... (PID: %u)\n", GetCurrentProcessId());
    printf("Auto-triggering in: ");

    for (int i = 15; i > 0; i--) {
        printf("%d... ", i);
        fflush(stdout);
        Sleep(1000);
    }

    printf("\n\n[*] Triggering NtOpenFile via CreateFile...\n");

    // 调用 CreateFile 会触发底层的 NtOpenFile
    HANDLE hFile = CreateFileA(
        "C:\\Users\\Public\\trigger_test.txt",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        printf("[+] File opened successfully (NtOpenFile was called)\n");
        CloseHandle(hFile);

        // 创建标记文件，通知注入程序Hook已触发
        HANDLE hMarker = CreateFileA(
            "C:\\Users\\Public\\hook_triggered.marker",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hMarker != INVALID_HANDLE_VALUE) {
            printf("[+] Created marker file for injector\n");
            CloseHandle(hMarker);
        }
    } else {
        printf("[-] Failed to open file: %u\n", GetLastError());
    }

    printf("\nSleeping for 60 seconds to keep process alive...\n");
    Sleep(60000);

    printf("Exiting...\n");
    return 0;
}
