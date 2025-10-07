/**
 * 文件标记器 - 用于验证 Early Bird APC 注入
 *
 * 这个程序会在注入前后检查测试文件，证明 shellcode 被执行
 */

#include <windows.h>
#include <stdio.h>

void create_test_file() {
    const char* filePath = "C:\\Users\\Public\\apc_inject_test.txt";
    const char* message = "Early Bird APC Injection Success!\nProcess was injected via APC mechanism.\n";

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
        DWORD written;
        WriteFile(hFile, message, strlen(message), &written, NULL);
        CloseHandle(hFile);
        printf("✓ 测试文件已创建：%s\n", filePath);
    } else {
        printf("✗ 无法创建测试文件\n");
    }
}

void check_test_file() {
    const char* filePath = "C:\\Users\\Public\\apc_inject_test.txt";

    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[256] = {0};
        DWORD read;
        ReadFile(hFile, buffer, sizeof(buffer) - 1, &read, NULL);
        CloseHandle(hFile);

        printf("\n========================================\n");
        printf("✓ 检测到测试文件！\n");
        printf("========================================\n");
        printf("文件内容：\n%s\n", buffer);
        printf("========================================\n");
        printf("这证明 shellcode 被成功执行！\n");
        printf("========================================\n");
        return;
    }

    printf("\n[*] 测试文件不存在（shellcode 未创建文件）\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("用法：\n");
        printf("  %s create  - 创建测试文件（在注入前删除旧文件）\n", argv[0]);
        printf("  %s check   - 检查测试文件（验证注入是否成功）\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "create") == 0) {
        // 删除旧文件
        DeleteFileA("C:\\Users\\Public\\apc_inject_test.txt");
        printf("[*] 已清理旧的测试文件\n");
    } else if (strcmp(argv[1], "check") == 0) {
        check_test_file();
    } else {
        printf("未知命令：%s\n", argv[1]);
        return 1;
    }

    return 0;
}
