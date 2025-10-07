/*
 * Shellcode 生成器
 * 用于生成各种测试 shellcode
 */

#include <windows.h>
#include <stdio.h>

// x64 MessageBox shellcode
unsigned char g_MessageBoxShellcode[] = {
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0x8D, 0x15, 0x1B, 0x00, 0x00, 0x00,       // lea rdx, [message]
    0x49, 0x8D, 0x40, 0x30,                         // lea r8, [r8 + 0x30]
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, MessageBoxA
    0xFF, 0xD0,                                     // call rax
    0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
    0xC3,                                           // ret
    // Message string
    'T', 'h', 'r', 'e', 'a', 'd', 'l', 'e', 's', 's', ' ', 'I', 'n', 'j', 'e', 'c', 't', '!', 0x00
};

// x64 calc shellcode
unsigned char g_CalcShellcode[] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

// x64 exit shellcode
unsigned char g_ExitShellcode[] = {
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, ExitProcess
    0xFF, 0xD0                                      // call rax
};

BOOL WriteShellcodeToFile(const char* filename, unsigned char* shellcode, size_t size) {
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
        printf("[!] 无法创建文件：%s（错误码：%lu）\n", filename, GetLastError());
        return FALSE;
    }

    DWORD bytesWritten;
    if (!WriteFile(hFile, shellcode, size, &bytesWritten, NULL) || bytesWritten != size) {
        printf("[!] 写入文件失败（错误码：%lu）\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    printf("[+] Shellcode 已写入：%s（%zu 字节）\n", filename, size);
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("  Shellcode 生成器\n");
    printf("======================================\n\n");

    if (argc < 2) {
        printf("用法：%s <类型> [输出文件]\n\n", argv[0]);
        printf("类型：\n");
        printf("  calc        - 弹出计算器\n");
        printf("  messagebox  - 显示消息框\n");
        printf("  exit        - 退出进程\n\n");
        printf("示例：\n");
        printf("  %s calc payload.bin\n", argv[0]);
        printf("  %s messagebox\n\n", argv[0]);
        return 1;
    }

    const char* type = argv[1];
    char defaultFilename[256];
    sprintf(defaultFilename, "%s_shellcode.bin", type);
    const char* filename = (argc >= 3) ? argv[2] : defaultFilename;

    if (strcmp(type, "calc") == 0) {
        WriteShellcodeToFile(filename, g_CalcShellcode, sizeof(g_CalcShellcode));
    } else if (strcmp(type, "messagebox") == 0) {
        // MessageBox 需要运行时解析地址
        printf("[!] MessageBox shellcode 需要手动解析 user32!MessageBoxA 地址\n");
        printf("[!] 建议使用 msfvenom 或其他工具生成\n");
        printf("[*] 使用 calc shellcode 代替\n");
        WriteShellcodeToFile(filename, g_CalcShellcode, sizeof(g_CalcShellcode));
    } else if (strcmp(type, "exit") == 0) {
        printf("[!] Exit shellcode 需要手动解析 kernel32!ExitProcess 地址\n");
        printf("[!] 建议使用 msfvenom 或其他工具生成\n");
        printf("[*] 使用 calc shellcode 代替\n");
        WriteShellcodeToFile(filename, g_CalcShellcode, sizeof(g_CalcShellcode));
    } else {
        printf("[!] 未知类型：%s\n", type);
        return 1;
    }

    return 0;
}
