/**
 * 写文件测试 Payload
 *
 * 这个程序会在 C:\Users\Public\ 创建一个测试文件
 * 用于验证 Early Bird APC 注入是否成功
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    const char* filePath = "C:\\Users\\Public\\early_bird_test.txt";
    const char* message = "Early Bird APC Injection Success!\n"
                         "Timestamp: ";

    // 获取当前时间
    SYSTEMTIME st;
    GetSystemTime(&st);

    char buffer[256];
    snprintf(buffer, sizeof(buffer),
             "%s%04d-%02d-%02d %02d:%02d:%02d\n",
             message,
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);

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

    if (hFile == INVALID_HANDLE_VALUE) {
        return 1;
    }

    // 写入内容
    DWORD written;
    WriteFile(hFile, buffer, strlen(buffer), &written, NULL);
    CloseHandle(hFile);

    // 显示消息框
    MessageBoxA(
        NULL,
        "Early Bird APC 注入成功！\n\n"
        "已在 C:\\Users\\Public\\early_bird_test.txt 创建测试文件。",
        "Early Bird APC Success",
        MB_OK | MB_ICONINFORMATION
    );

    return 0;
}
