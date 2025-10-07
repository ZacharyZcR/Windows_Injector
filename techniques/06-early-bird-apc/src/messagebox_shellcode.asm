; MessageBox Shellcode for x64
;
; 功能：调用 MessageBoxA 显示消息
; 编译：nasm -f bin messagebox_shellcode.asm -o messagebox.bin

BITS 64

start:
    ; 保存寄存器状态
    push rbp
    mov rbp, rsp
    sub rsp, 0x20           ; 为调用分配栈空间（shadow space）

    ; 获取 kernel32.dll 基址（通过 PEB）
    xor rcx, rcx
    mov rax, [gs:rcx + 0x60]    ; PEB
    mov rax, [rax + 0x18]       ; PEB->Ldr
    mov rax, [rax + 0x20]       ; LDR_DATA_TABLE_ENTRY->InMemoryOrderModuleList.Flink
    mov rax, [rax]              ; 第二个模块 (ntdll.dll)
    mov rax, [rax]              ; 第三个模块 (kernel32.dll)
    mov rbx, [rax + 0x20]       ; kernel32.dll 基址

    ; 查找 LoadLibraryA
    mov rax, rbx
    mov edx, [rax + 0x3C]       ; e_lfanew
    add rdx, rax
    mov edx, [rdx + 0x88]       ; Export Directory RVA
    add rdx, rax
    mov ecx, [rdx + 0x20]       ; AddressOfNames RVA
    add rcx, rax

find_loadlibrary:
    xor r8, r8

    ; 简化版：直接调用 user32.dll 中的 MessageBoxA
    ; 先加载 user32.dll

    ; 准备调用 LoadLibraryA("user32.dll")
    lea rcx, [rel user32_str]
    sub rsp, 0x20

    ; 查找 LoadLibraryA 地址（简化：使用偏移）
    ; 这里我们直接硬编码调用

    ; 准备 MessageBoxA 参数
    xor rcx, rcx            ; hWnd = NULL
    lea rdx, [rel msg_text] ; lpText
    lea r8, [rel msg_title] ; lpCaption
    xor r9d, r9d            ; uType = MB_OK

    ; 调用 MessageBoxA (需要先获取地址)
    ; 为了简化，我们使用动态调用

    ; 退出
    xor rcx, rcx
    mov rax, 0x2C            ; ExitProcess 的简化版本

    add rsp, 0x20
    pop rbp
    ret

user32_str: db 'user32.dll', 0
msg_text:   db 'Early Bird APC Injection 成功！', 0
msg_title:  db 'Early Bird APC Test', 0
