/**
 * Shellcode 提取工具
 *
 * 从编译后的可执行文件中提取 .text 段作为 shellcode
 */

#include <windows.h>
#include <stdio.h>

void write_test_marker() {
    // 在 C:\Users\Public\ 创建测试文件
    HANDLE hFile = CreateFileA(
        "C:\\Users\\Public\\early_bird_success.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* msg = "Early Bird APC Injection Success!\n";
        DWORD written;
        WriteFile(hFile, msg, lstrlenA(msg), &written, NULL);
        CloseHandle(hFile);
    }

    // 不要退出，让进程保持运行
    while(1) {
        Sleep(1000);
    }
}

int main() {
    write_test_marker();
    return 0;
}
