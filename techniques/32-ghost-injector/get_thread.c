#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed\n");
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                printf("[+] Found thread: TID=%lu (PID=%lu)\n", te32.th32ThreadID, pid);
                CloseHandle(hSnapshot);
                return 0;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    printf("[-] No thread found for PID %lu\n", pid);
    CloseHandle(hSnapshot);
    return 1;
}
