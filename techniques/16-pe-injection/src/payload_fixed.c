/*
 * PE Injection - Test Payload (Fixed with GetProcAddress)
 *
 * 使用动态API解析，避免IAT依赖
 * 参考：https://github.com/AlSch092/PE-Injection
 */

#include <windows.h>

// API 函数指针类型定义
typedef HMODULE (WINAPI *pGetModuleHandleA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
typedef DWORD (WINAPI *pGetCurrentProcessId)(VOID);

int main(void)
{
    // 手动获取 kernel32.dll 和 GetProcAddress
    // 这两个是编译器保证可用的（CRT依赖）
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 1;

    pGetProcAddress _GetProcAddress = (pGetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
    if (!_GetProcAddress) return 2;

    // 动态解析所需的API
    pCreateFileA _CreateFileA = (pCreateFileA)_GetProcAddress(hKernel32, "CreateFileA");
    pWriteFile _WriteFile = (pWriteFile)_GetProcAddress(hKernel32, "WriteFile");
    pCloseHandle _CloseHandle = (pCloseHandle)_GetProcAddress(hKernel32, "CloseHandle");
    pGetCurrentProcessId _GetCurrentProcessId = (pGetCurrentProcessId)_GetProcAddress(hKernel32, "GetCurrentProcessId");

    if (!_CreateFileA || !_WriteFile || !_CloseHandle || !_GetCurrentProcessId) {
        return 3;
    }

    // 获取当前进程ID
    DWORD processId = _GetCurrentProcessId();

    // 创建验证文件
    HANDLE hFile = _CreateFileA(
        "C:\\Users\\Public\\pe_injection_verified.txt",
        0x40000000, // GENERIC_WRITE
        0,
        NULL,
        2, // CREATE_ALWAYS
        0x80, // FILE_ATTRIBUTE_NORMAL
        NULL
    );

    if (hFile != (HANDLE)-1) {
        const char* msg1 = "PE Injection Verified!\r\nProcess ID: ";
        const char* msg2 = "\r\nTechnique: PE Injection (Loaded Module Reflection)\r\n"
                          "Status: PE image injected and executed successfully!\r\n"
                          "Method: Dynamic API resolution (no IAT dependency)\r\n";

        DWORD written;

        // 计算msg1长度
        int len1 = 0;
        while (msg1[len1]) len1++;
        _WriteFile(hFile, msg1, len1, &written, NULL);

        // 写入PID
        char pidStr[16];
        int idx = 0;
        DWORD temp = processId;
        DWORD divisor = 10000;
        while (divisor > 0) {
            pidStr[idx++] = '0' + (temp / divisor) % 10;
            divisor /= 10;
        }
        pidStr[idx] = '\0';
        _WriteFile(hFile, pidStr, idx, &written, NULL);

        // 计算msg2长度
        int len2 = 0;
        while (msg2[len2]) len2++;
        _WriteFile(hFile, msg2, len2, &written, NULL);

        _CloseHandle(hFile);
    }

    return 0;
}
