#include <windows.h>
#include <stdio.h>

/**
 * 测试载荷程序
 * 用于演示 Process Ghosting 注入技术
 */
int main() {
    // 显示消息框，证明载荷代码成功执行
    MessageBoxW(
        NULL,
        L"恭喜！Process Ghosting 注入成功！\n\n"
        L"技术特点：\n"
        L"• 文件被标记为删除待处理\n"
        L"• 镜像节从删除待处理的文件创建\n"
        L"• 文件句柄关闭后文件被删除\n"
        L"• 进程从已删除文件的镜像节创建\n"
        L"• GetProcessImageFileName 返回空",
        L"Process Ghosting 演示",
        MB_OK | MB_ICONINFORMATION
    );

    // 输出调试信息
    printf("\n========== 载荷程序信息 ==========\n");
    printf("进程 ID: %d\n", GetCurrentProcessId());
    printf("进程创建方式: NtCreateProcessEx (从已删除文件的镜像节)\n");
    printf("文件状态: 已删除\n");
    printf("镜像节状态: 存在且可用\n");
    printf("========== 执行完毕 ==========\n");

    return 0;
}
