/**
 * Entry Point Injection - 测试载荷
 *
 * 这是一个简单的测试程序，用于验证入口点注入是否成功
 */

#include <windows.h>

int main(void) {
    MessageBoxW(
        NULL,
        L"Entry Point Injection 注入成功！\n\n"
        L"这个进程的入口点代码已被替换为 shellcode。",
        L"Entry Point Injection - 测试成功",
        MB_OK | MB_ICONINFORMATION
    );

    return 0;
}
