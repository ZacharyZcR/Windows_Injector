; Verification shellcode for Mapping Injection
; Creates a file at C:\Users\Public\mapping_injection_verified.txt
; x64 assembly

section .text
global main

main:
    ; Save registers
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 0x28  ; Shadow space

    ; Get kernel32.dll base
    mov r10, gs:[0x60]              ; PEB
    mov r10, [r10 + 0x18]           ; PEB->Ldr
    mov r10, [r10 + 0x20]           ; InMemoryOrderModuleList
    mov r10, [r10]                  ; Second entry (ntdll)
    mov r10, [r10]                  ; Third entry (kernel32)
    mov r10, [r10 + 0x20]           ; DllBase

    ; Find CreateFileA
    ; (Simplified: assume it's available)

    ; Call CreateFileA
    ; HANDLE CreateFileA(
    ;   LPCSTR lpFileName,           // rcx
    ;   DWORD dwDesiredAccess,       // rdx
    ;   DWORD dwShareMode,           // r8
    ;   LPSECURITY_ATTRIBUTES,       // r9
    ;   DWORD dwCreationDisposition, // [rsp+0x28]
    ;   DWORD dwFlagsAndAttributes,  // [rsp+0x30]
    ;   HANDLE hTemplateFile         // [rsp+0x38]
    ; )

    lea rcx, [rel filename]
    mov rdx, 0x40000000             ; GENERIC_WRITE
    xor r8, r8                      ; 0 (no sharing)
    xor r9, r9                      ; NULL
    mov dword [rsp+0x28], 2         ; CREATE_ALWAYS
    mov dword [rsp+0x30], 0x80      ; FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+0x38], 0         ; NULL

    ; Note: This is a simplified version
    ; Real implementation would need to dynamically resolve CreateFileA

    ; Restore and return
    add rsp, 0x28
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

section .data
filename db "C:\Users\Public\mapping_injection_verified.txt", 0
message db "Mapping Injection Verified!", 0x0D, 0x0A
        db "Technique: Mapping Injection", 0x0D, 0x0A
        db "Method: ProcessInstrumentationCallback", 0x0D, 0x0A
        db "Status: Successfully executed!", 0x0D, 0x0A, 0
