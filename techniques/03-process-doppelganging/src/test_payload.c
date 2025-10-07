#include <windows.h>
#include <stdio.h>

/**
 * 测试载荷程序
 * 用于演示 Process Doppelgänging 注入技术
 */
int main() {
    // 显示消息框，证明载荷代码成功执行
    MessageBoxW(
        NULL,
        L"恭喜！Process Doppelgänging 注入成功！\n\n"
        L"技术特点：\n"
        L"• 进程从内存节直接创建\n"
        L"• 无关联文件（GetProcessImageFileName 返回空）\n"
        L"• 事务回滚后文件已删除\n"
        L"• 完全驻留内存执行",
        L"Process Doppelgänging 演示",
        MB_OK | MB_ICONINFORMATION
    );

    // 输出调试信息
    printf("\n========== 载荷程序信息 ==========\n");
    printf("进程 ID: %d\n", GetCurrentProcessId());
    printf("进程创建方式: NtCreateProcessEx (从内存节)\n");
    printf("文件关联: 无 (匿名节)\n");
    printf("========== 执行完毕 ==========\n");

    return 0;
}
