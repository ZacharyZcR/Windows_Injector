#include <windows.h>
#include <stdio.h>

/**
 * 简单的测试载荷程序
 * 用于测试进程镂空技术
 */
int main() {
    // 显示消息框
    MessageBoxA(
        NULL,
        "进程镂空测试成功！\n\n"
        "这个消息框来自被注入的程序。\n"
        "如果你看到这个消息，说明进程镂空技术工作正常。",
        "进程镂空测试",
        MB_OK | MB_ICONINFORMATION
    );

    // 打印到控制台
    printf("=================================\n");
    printf("   进程镂空测试载荷\n");
    printf("=================================\n");
    printf("进程 ID: %d\n", GetCurrentProcessId());
    printf("载荷已成功执行！\n");
    printf("=================================\n");

    // 创建文件作为执行证明
    HANDLE hFile = CreateFileA(
        "process_hollowing_test.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char szMessage[256];
        DWORD dwBytesWritten;

        sprintf(szMessage,
            "进程镂空测试成功!\r\n"
            "进程 ID: %d\r\n"
            "时间: %s\r\n",
            GetCurrentProcessId(),
            __TIMESTAMP__
        );

        WriteFile(hFile, szMessage, strlen(szMessage), &dwBytesWritten, NULL);
        CloseHandle(hFile);

        printf("\n已创建测试文件：process_hollowing_test.txt\n");
    }

    printf("\n按任意键退出...\n");
    getchar();

    return 0;
}
