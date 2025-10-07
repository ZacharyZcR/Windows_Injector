/*
 * PE Injection - Test Payload
 *
 * 测试载荷：创建验证文件
 * 被注入到目标进程后会创建验证文件
 */

#include <windows.h>

int main(void)
{
    // 获取当前进程信息
    DWORD processId = GetCurrentProcessId();
    char processPath[MAX_PATH] = {0};

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess != NULL) {
        DWORD size = MAX_PATH;
        QueryFullProcessImageNameA(hProcess, 0, processPath, &size);
        CloseHandle(hProcess);
    }

    // 创建验证文件
    HANDLE hFile = CreateFileA(
        "C:\\Users\\Public\\pe_injection_verified.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* msg1 = "PE Injection Verified!\r\nProcess ID: ";
        const char* msg2 = "\r\nTechnique: PE Injection (Loaded Module Reflection)\r\nStatus: PE image injected and executed successfully!\r\n";

        DWORD written;
        WriteFile(hFile, msg1, lstrlenA(msg1), &written, NULL);

        // 写入PID
        char pidStr[32];
        pidStr[0] = '0' + (processId / 10000) % 10;
        pidStr[1] = '0' + (processId / 1000) % 10;
        pidStr[2] = '0' + (processId / 100) % 10;
        pidStr[3] = '0' + (processId / 10) % 10;
        pidStr[4] = '0' + (processId % 10);
        pidStr[5] = '\0';
        WriteFile(hFile, pidStr, 5, &written, NULL);

        WriteFile(hFile, msg2, lstrlenA(msg2), &written, NULL);
        CloseHandle(hFile);
    }

    return 0;
}
