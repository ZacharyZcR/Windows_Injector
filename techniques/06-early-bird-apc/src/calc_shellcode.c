/**
 * 计算器 Shellcode 生成器
 *
 * 生成一个简单的 WinExec("calc") shellcode
 */

#include <windows.h>
#include <stdio.h>

/**
 * WinExec("calc", SW_SHOW) shellcode for x64
 *
 * 这是一个经过验证的 shellcode，使用 WinExec 启动计算器
 * 来源：公开的测试 shellcode
 */
unsigned char shellcode[] =
    // WinExec("calc", SW_SHOW) - x64
    "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
    "\xff\xff\x48\xbb\x58\x68\x3a\xf9\x84\x14\x4e\x4d\x48\x31\x58"
    "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xa4\x20\xb9\x1d\x74\xfc"
    "\x8e\x4d\x58\x68\x7b\xa8\xd5\x5c\x1e\x1e\x31\x29\x73\xb0\xc5"
    "\x44\x06\x03\x11\x20\x59\xa8\xc5\x5c\x06\x1d\x09\x68\x7b\xa8"
    "\x95\x44\xce\x0d\x48\x88\x7b\xe9\xcc\x5c\x1e\x4e\x50\xe8\xfa"
    "\xe9\xc7\x44\xde\x7d\x11\x29\x7b\xf8\xd5\x5c\x1e\x1e\x31\x29"
    "\x7a\x30\x85\x54\x8e\x46\x11\x29\x62\x30\xd7\x7c\x86\x1c\x31"
    "\x21\x7b\xb0\xd4\x5c\x06\x1d\x09\x68\x3a\xf9\x84\x14\x4e\x4d";

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("用法：%s <输出文件>\n", argv[0]);
        printf("示例：%s calc_payload.bin\n", argv[0]);
        return 1;
    }

    const char* outputFile = argv[1];
    unsigned int shellcodeSize = sizeof(shellcode) - 1;

    HANDLE hFile = CreateFileA(
        outputFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("错误：无法创建文件（错误码：%u）\n", GetLastError());
        return 1;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, shellcode, shellcodeSize, &bytesWritten, NULL)) {
        printf("错误：写入失败（错误码：%u）\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    printf("✓ 计算器 Shellcode 已生成：%s\n", outputFile);
    printf("  大小：%u 字节\n", bytesWritten);
    printf("  功能：启动 calc.exe\n");

    return 0;
}
