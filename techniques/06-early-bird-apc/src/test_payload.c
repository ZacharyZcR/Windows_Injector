/**
 * Early Bird APC Injection - 测试载荷
 *
 * 这是一个简单的测试程序，用于验证 Early Bird APC 注入是否成功
 */

#include <windows.h>

int main(void) {
    MessageBoxW(
        NULL,
        L"Early Bird APC 注入成功！\n\n"
        L"这个进程是通过 Early Bird APC Injection 技术启动的。\n"
        L"载荷在进程主线程初始化阶段就已注入。",
        L"Early Bird APC Injection - 测试成功",
        MB_OK | MB_ICONINFORMATION
    );

    return 0;
}
