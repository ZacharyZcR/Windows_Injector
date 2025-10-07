#include <windows.h>
#include <stdio.h>

/**
 * 测试载荷程序 - 用于验证事务性镂空技术
 */
int main() {
    // 显示消息框
    MessageBoxA(
        NULL,
        "事务性镂空测试成功！\n\n"
        "这个消息框来自通过事务性镂空技术注入的载荷。\n\n"
        "技术特点：\n"
        "• 载荷文件不落地（事务回滚）\n"
        "• 内存映射为 SEC_IMAGE\n"
        "• 比普通 Process Hollowing 更隐蔽",
        "事务性镂空测试",
        MB_OK | MB_ICONINFORMATION
    );

    // 创建测试文件
    HANDLE hFile = CreateFileA(
        "transacted_hollowing_test.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        char message[512];
        DWORD bytesWritten;

        sprintf(message,
            "========== 事务性镂空测试成功 ==========\r\n"
            "进程 ID: %d\r\n"
            "技术: Transacted Hollowing\r\n"
            "特点: \r\n"
            "  1. 使用 NTFS 事务机制\r\n"
            "  2. 载荷文件不落地\r\n"
            "  3. 内存映射为 SEC_IMAGE\r\n"
            "  4. 更难被检测\r\n"
            "时间: %s\r\n"
            "========================================\r\n",
            GetCurrentProcessId(),
            __TIMESTAMP__
        );

        WriteFile(hFile, message, strlen(message), &bytesWritten, NULL);
        CloseHandle(hFile);

        printf("已创建测试文件：transacted_hollowing_test.txt\n");
    }

    printf("=================================\n");
    printf("   事务性镂空测试载荷\n");
    printf("=================================\n");
    printf("进程 ID: %d\n", GetCurrentProcessId());
    printf("载荷已成功执行！\n");
    printf("=================================\n");
    printf("\n按任意键退出...\n");
    getchar();

    return 0;
}
