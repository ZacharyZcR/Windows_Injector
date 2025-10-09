.CODE
PUBLIC LocatePEB
PUBLIC ResolveKernelCallbackTable
PUBLIC WriteKernelCallbackTable

; Retrieving the address of the PEB.
LocatePEB PROC
    mov rax, qword ptr gs:[60h] ; Access PEB in x64
    ret
LocatePEB ENDP

; Retrieving the KernelCallbackTable address from the PEB.
; RCX contains the PEB address, returns KernelCallbackTable address in RAX
ResolveKernelCallbackTable PROC
    mov rax, qword ptr [rcx + 58h] ; Offset for KernelCallbackTable in PEB (0x58)
    ret
ResolveKernelCallbackTable ENDP

; Updating the KernelCallbackTable with a new address.
; RCX = PEB address, RDX = New KernelCallbackTable address
WriteKernelCallbackTable PROC
    mov qword ptr [rcx + 58h], rdx    ; Write the new KernelCallbackTable address
    ret
WriteKernelCallbackTable ENDP

END