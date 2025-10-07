/*
 * PE Injection - Test Payload
 *
 * 测试载荷：简单的消息框程序
 * 被注入到目标进程后会弹出消息框
 */

#include <windows.h>

int main(void)
{
    MessageBoxA(NULL,
                "✅ PE 注入成功!\n\n"
                "这个消息框来自被注入的 PE 映像。\n"
                "当前运行在目标进程的地址空间中。",
                "PE Injection - Success",
                MB_OK | MB_ICONINFORMATION);

    return 0;
}
