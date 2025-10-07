/**
 * ===================================================================
 * Shellcode 生成器 - Kernel Callback Table Injection
 * ===================================================================
 *
 * 生成简单的测试 shellcode
 */

#include <windows.h>
#include <stdio.h>

/**
 * ===================================================================
 * 简单的 Exit shellcode
 * 用于快速测试，调用 ExitProcess(0)
 * ===================================================================
 */
unsigned char shellcode_exit_x64[] = {
    // sub rsp, 0x28
    0x48, 0x83, 0xEC, 0x28,

    // xor ecx, ecx (uExitCode = 0)
    0x31, 0xC9,

    // mov rax, <ExitProcess address>
    // 需要在运行时 patch
    0x48, 0xB8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,

    // call rax
    0xFF, 0xD0,

    // int3 (如果 ExitProcess 失败)
    0xCC
};

/**
 * ===================================================================
 * 写入 shellcode 到文件
 * ===================================================================
 */
BOOL WriteShellcodeToFile(const char* filename, unsigned char* shellcode, DWORD size) {
    HANDLE hFile = CreateFileA(
        filename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file: %s (Error: %lu)\n", filename, GetLastError());
        return FALSE;
    }

    DWORD bytesWritten;
    if (!WriteFile(hFile, shellcode, size, &bytesWritten, NULL) || bytesWritten != size) {
        printf("[-] Failed to write shellcode (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

/**
 * ===================================================================
 * 生成 PIC shellcode
 * ===================================================================
 */
BOOL GeneratePicShellcode(const char* filename) {
    printf("[*] Generating PIC shellcode...\n");
    printf("[*] Current version: Simple exit shellcode for testing\n\n");

    // Patch ExitProcess 地址
    unsigned char shellcode[sizeof(shellcode_exit_x64)];
    memcpy(shellcode, shellcode_exit_x64, sizeof(shellcode_exit_x64));

    // 获取 ExitProcess 地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Failed to get kernel32.dll handle\n");
        return FALSE;
    }

    PVOID pExitProcess = GetProcAddress(hKernel32, "ExitProcess");
    if (!pExitProcess) {
        printf("[-] Failed to get ExitProcess address\n");
        return FALSE;
    }

    // Patch 地址到 shellcode (offset 8)
    memcpy(&shellcode[8], &pExitProcess, sizeof(PVOID));

    printf("[+] ExitProcess address: 0x%p\n", pExitProcess);

    // 写入文件
    if (!WriteShellcodeToFile(filename, shellcode, sizeof(shellcode))) {
        return FALSE;
    }

    printf("[+] Shellcode written to: %s (%d bytes)\n", filename, (int)sizeof(shellcode));
    return TRUE;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Shellcode Generator - Kernel Callback Table Injection\n");
    printf("===================================================================\n\n");

    const char* outputFile = "payload.bin";
    if (argc >= 2) {
        outputFile = argv[1];
    }

    if (!GeneratePicShellcode(outputFile)) {
        printf("\n[-] Failed to generate shellcode!\n");
        return 1;
    }

    printf("\n[+] Shellcode generation completed!\n");
    printf("[*] Use with: kernel_callback_injection.exe %s\n", outputFile);

    return 0;
}
