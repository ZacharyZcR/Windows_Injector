#include <windows.h>
#include <stdio.h>

int main() {
    // Force load msvcrt.dll
    HMODULE hMsvcrt = LoadLibraryA("msvcrt.dll");
    if (!hMsvcrt) {
        printf("[-] Failed to load msvcrt.dll\n");
        return 1;
    }

    printf("[+] msvcrt.dll loaded successfully at 0x%p\n", hMsvcrt);
    printf("[+] PID: %d\n", GetCurrentProcessId());
    printf("[*] Press any key to exit...\n");

    getchar();

    FreeLibrary(hMsvcrt);
    return 0;
}
