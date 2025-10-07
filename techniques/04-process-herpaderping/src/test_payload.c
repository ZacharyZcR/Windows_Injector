#include <windows.h>
#include <stdio.h>

/**
 * 测试载荷程序
 * 用于演示 Process Herpaderping 注入技术
 */
int main() {
    // 显示消息框，证明载荷代码成功执行
    MessageBoxW(
        NULL,
        L"恭喜！Process Herpaderping 注入成功！\n\n"
        L"技术特点：\n"
        L"• 磁盘文件已被覆盖\n"
        L"• 但进程执行的是原始载荷\n"
        L"• 安全产品检查磁盘时归因错误\n"
        L"• 不依赖事务，比 Doppelgänging 更简单",
        L"Process Herpaderping 演示",
        MB_OK | MB_ICONINFORMATION
    );

    // 输出调试信息
    printf("\n========== 载荷程序信息 ==========\n");
    printf("进程 ID: %d\n", GetCurrentProcessId());
    printf("进程创建方式: NtCreateProcessEx (从内存节)\n");
    printf("磁盘文件状态: 已被覆盖\n");
    printf("执行内容: 原始载荷（来自缓存的节）\n");
    printf("========== 执行完毕 ==========\n");

    return 0;
}
