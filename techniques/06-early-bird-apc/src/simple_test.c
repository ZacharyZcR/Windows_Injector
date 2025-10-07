/**
 * 简单测试载荷 - 写文件验证
 *
 * 这个程序会在 Temp 目录创建一个文件，证明代码被执行了
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    char tempPath[MAX_PATH];
    char filePath[MAX_PATH];

    // 获取 Temp 目录
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(filePath, MAX_PATH, "%s\\early_bird_apc_test.txt", tempPath);

    // 创建文件
    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* message = "Early Bird APC Injection 成功执行！\n";
        DWORD written;
        WriteFile(hFile, message, strlen(message), &written, NULL);
        CloseHandle(hFile);
    }

    // 显示消息框（如果环境支持）
    MessageBoxA(
        NULL,
        "Early Bird APC 注入成功！\n\n已在 Temp 目录创建测试文件。",
        "Early Bird APC Test",
        MB_OK | MB_ICONINFORMATION
    );

    return 0;
}
