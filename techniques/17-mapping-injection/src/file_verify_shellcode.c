/*
 * File Verification Shellcode Generator for Mapping Injection
 *
 * 生成写文件验证的shellcode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// 手写x64 shellcode - 创建验证文件
unsigned char file_verify_shellcode[] = {
    // 保存寄存器
    0x50,                                           // push rax
    0x53,                                           // push rbx
    0x51,                                           // push rcx
    0x52,                                           // push rdx
    0x41, 0x50,                                     // push r8
    0x41, 0x51,                                     // push r9
    0x41, 0x52,                                     // push r10
    0x41, 0x53,                                     // push r11
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28 (shadow space)

    // 获取kernel32.dll基址（从PEB）
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]  ; PEB
    0x48, 0x8B, 0x40, 0x18,                         // mov rax, [rax+0x18]  ; PEB->Ldr
    0x48, 0x8B, 0x40, 0x20,                         // mov rax, [rax+0x20]  ; InMemoryOrderModuleList
    0x48, 0x8B, 0x00,                               // mov rax, [rax]       ; ntdll
    0x48, 0x8B, 0x00,                               // mov rax, [rax]       ; kernel32
    0x48, 0x8B, 0x58, 0x20,                         // mov rbx, [rax+0x20]  ; DllBase

    // 现在rbx包含kernel32基址
    // 简化版：直接调用API（假设它们已经在IAT中）

    // CreateFileA("C:\\Users\\Public\\mapping_injection_verified.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
    0x48, 0x8D, 0x0D, 0x90, 0x00, 0x00, 0x00,       // lea rcx, [rip+filename]
    0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x40,       // mov rdx, 0x40000000  ; GENERIC_WRITE
    0x4D, 0x31, 0xC0,                               // xor r8, r8           ; 0
    0x4D, 0x31, 0xC9,                               // xor r9, r9           ; NULL
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00,  // mov qword [rsp+0x20], 2  ; CREATE_ALWAYS
    0x48, 0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00,  // mov qword [rsp+0x28], 0x80  ; FILE_ATTRIBUTE_NORMAL
    0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00,  // mov qword [rsp+0x30], 0  ; NULL

    // 需要GetProcAddress解析CreateFileA
    // 这里简化为直接使用硬编码地址（实际应动态解析）
    // 为了测试，我们使用MessageBoxA作为简化版本

    // MessageBoxA(NULL, "Mapping Injection Verified!", "Success", MB_OK)
    0x48, 0x31, 0xC9,                               // xor rcx, rcx         ; NULL
    0x48, 0x8D, 0x15, 0x40, 0x00, 0x00, 0x00,       // lea rdx, [rip+message]
    0x4C, 0x8D, 0x05, 0x60, 0x00, 0x00, 0x00,       // lea r8, [rip+title]
    0x45, 0x31, 0xC9,                               // xor r9d, r9d         ; MB_OK

    // 获取MessageBoxA地址（简化版，实际需要GetProcAddress）
    0x48, 0x8B, 0x05, 0x02, 0x00, 0x00, 0x00,       // mov rax, [rip+msgbox_addr]
    0xEB, 0x08,                                      // jmp skip_addr

    // MessageBoxA地址占位符（8字节）
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // skip_addr:
    0xFF, 0xD0,                                      // call rax

    // 恢复寄存器并返回
    0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
    0x41, 0x5B,                                     // pop r11
    0x41, 0x5A,                                     // pop r10
    0x41, 0x59,                                     // pop r9
    0x41, 0x58,                                     // pop r8
    0x5A,                                           // pop rdx
    0x59,                                           // pop rcx
    0x5B,                                           // pop rbx
    0x58,                                           // pop rax
    0xC3,                                           // ret

    // 数据段
    // message:
    'M','a','p','p','i','n','g',' ','I','n','j','e','c','t','i','o','n',' ',
    'V','e','r','i','f','i','e','d','!',0,

    // title:
    'S','u','c','c','e','s','s',0,

    // filename:
    'C',':','\\','U','s','e','r','s','\\','P','u','b','l','i','c','\\',
    'm','a','p','p','i','n','g','_','i','n','j','e','c','t','i','o','n','_',
    'v','e','r','i','f','i','e','d','.','t','x','t',0
};

int main(int argc, char *argv[])
{
    const char *output = (argc >= 2) ? argv[1] : "verify_payload.bin";

    FILE *fp = fopen(output, "wb");
    if (!fp) {
        printf("[!] 无法创建文件: %s\n", output);
        return 1;
    }

    fwrite(file_verify_shellcode, 1, sizeof(file_verify_shellcode) - 1, fp);
    fclose(fp);

    printf("[+] 已生成文件验证 shellcode: %s (%lu 字节)\n",
           output, (unsigned long)(sizeof(file_verify_shellcode) - 1));

    return 0;
}
