#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MessageBox shellcode (x64)
// Displays "Hello from Process Forking!" message box
unsigned char messagebox_shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0x8D, 0x15, 0x1A, 0x00, 0x00, 0x00,       // lea rdx, [rip+0x1A]
    0x4C, 0x8D, 0x05, 0x1F, 0x00, 0x00, 0x00,       // lea r8, [rip+0x1F]
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, MessageBoxA
    0xFF, 0xD0,                                     // call rax
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, ExitProcess
    0xFF, 0xD0,                                     // call rax
    // Strings
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x66, 0x72,
    0x6F, 0x6D, 0x20, 0x50, 0x72, 0x6F, 0x63, 0x65,
    0x73, 0x73, 0x20, 0x46, 0x6F, 0x72, 0x6B, 0x69,
    0x6E, 0x67, 0x21, 0x00,                         // "Hello from Process Forking!"
    0x44, 0x69, 0x72, 0x74, 0x79, 0x20, 0x56, 0x61,
    0x6E, 0x69, 0x74, 0x79, 0x00                    // "Dirty Vanity"
};

// Calc shellcode (x64)
// Spawns calc.exe using WinExec
unsigned char calc_shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0x8D, 0x0D, 0x0E, 0x00, 0x00, 0x00,       // lea rcx, [rip+0x0E]
    0xBA, 0x01, 0x00, 0x00, 0x00,                   // mov edx, 1
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, WinExec
    0xFF, 0xD0,                                     // call rax
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, ExitProcess
    0xFF, 0xD0,                                     // call rax
    // String
    0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00 // "calc.exe"
};

void PatchShellcodeAddresses(unsigned char* shellcode, size_t size, const char* type) {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");

    if (strcmp(type, "messagebox") == 0) {
        FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
        FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");

        // Patch MessageBoxA address at offset 0x17
        memcpy(shellcode + 0x17, &pMessageBoxA, 8);
        // Patch ExitProcess address at offset 0x27
        memcpy(shellcode + 0x27, &pExitProcess, 8);
    }
    else if (strcmp(type, "calc") == 0) {
        FARPROC pWinExec = GetProcAddress(hKernel32, "WinExec");
        FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");

        // Patch WinExec address at offset 0x13
        memcpy(shellcode + 0x13, &pWinExec, 8);
        // Patch ExitProcess address at offset 0x21
        memcpy(shellcode + 0x21, &pExitProcess, 8);
    }

    FreeLibrary(hUser32);
    FreeLibrary(hKernel32);
}

BOOL GenerateShellcode(const char* type, const char* output_file) {
    unsigned char* shellcode;
    size_t size;

    if (strcmp(type, "calc") == 0) {
        shellcode = calc_shellcode;
        size = sizeof(calc_shellcode);
        printf("[+] Generating calc.exe shellcode\n");
    }
    else if (strcmp(type, "messagebox") == 0) {
        shellcode = messagebox_shellcode;
        size = sizeof(messagebox_shellcode);
        printf("[+] Generating MessageBox shellcode\n");
    }
    else {
        printf("[-] Unknown shellcode type: %s\n", type);
        return FALSE;
    }

    // Allocate buffer for patched shellcode
    unsigned char* patched = (unsigned char*)malloc(size);
    if (patched == NULL) {
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }

    memcpy(patched, shellcode, size);
    PatchShellcodeAddresses(patched, size, type);

    FILE* file = fopen(output_file, "wb");
    if (file == NULL) {
        printf("[-] Failed to open output file: %s\n", output_file);
        free(patched);
        return FALSE;
    }

    size_t written = fwrite(patched, 1, size, file);
    fclose(file);
    free(patched);

    if (written != size) {
        printf("[-] Failed to write shellcode to file\n");
        return FALSE;
    }

    printf("[+] Shellcode size: %zu bytes\n", size);
    printf("[+] Output file: %s\n", output_file);
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("[+] Process Forking Shellcode Generator\n\n");

    if (argc != 2) {
        printf("Usage: %s <type>\n", argv[0]);
        printf("\n");
        printf("Available types:\n");
        printf("  calc       - Generate calc.exe shellcode\n");
        printf("  messagebox - Generate MessageBox shellcode\n");
        printf("  all        - Generate all shellcode types\n");
        return 1;
    }

    const char* type = argv[1];

    if (strcmp(type, "all") == 0) {
        printf("Generating all shellcode types...\n\n");

        if (!GenerateShellcode("calc", "calc_shellcode.bin")) {
            return 1;
        }
        printf("\n");

        if (!GenerateShellcode("messagebox", "messagebox_shellcode.bin")) {
            return 1;
        }
        printf("\n");

        printf("[+] All shellcode generated successfully!\n");
        return 0;
    }
    else {
        char output_file[256];
        snprintf(output_file, sizeof(output_file), "%s_shellcode.bin", type);

        if (GenerateShellcode(type, output_file)) {
            printf("\n[+] Shellcode generated successfully!\n");
            return 0;
        }
        else {
            return 1;
        }
    }
}
