;By AlSch092 @ github

.data

EXTERN HookReturnAddr : QWORD  ;defined in main.cpp (or equivalent)
EXTERN PacketLogCallbackAddr : QWORD

.code

AESEncrypt_CBC128 PROC

    pop r10

    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push rsp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq

    sub rsp, 28h
    call PacketLogCallbackAddr 
    add rsp, 28h

    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsp
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    mov [rsp+18h], rbx
    jmp HookReturnAddr
AESEncrypt_CBC128 ENDP

END
