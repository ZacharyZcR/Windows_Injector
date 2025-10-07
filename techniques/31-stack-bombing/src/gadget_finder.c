#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

// External memmem function
void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len);

typedef struct {
    DWORD64 address;
    size_t size;
} TEXT_SECTION_INFO;

TEXT_SECTION_INFO GetTextSection(HMODULE mod)
{
    // Parse a module in order to retrieve its text section
    TEXT_SECTION_INFO section_info = { 0 };
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS NtHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeader;

    NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)DosHeader + DosHeader->e_lfanew);
    OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
    SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
    DWORD NumberOfSections = NtHeader->FileHeader.NumberOfSections;

    for (int i = 0; i < NumberOfSections; i++)
    {
        DWORD64 SecSize = SectionHeader->SizeOfRawData;
        if (SecSize != 0)
        {
            if (!memcmp(SectionHeader->Name, ".text", 5))
            {
                section_info.address = (DWORD64)((BYTE*)SectionHeader->VirtualAddress + (DWORD64)DosHeader);
                section_info.size = SectionHeader->SizeOfRawData;
                return section_info;
            }
            else
                SectionHeader++;
        }
        else
            SectionHeader++;
    }

    return section_info;
}

DWORD64 GadgetFinder(const void* const needle, const size_t needle_len)
{
    // Searches a given gadget in the text sections of shared libraries.
    // Text section is the only one which is executable.

    DWORD64 gadget;
    char modules[6][11] = { "ntdll", "kernel32", "user32", "kernelbase", "gdi32", "gdiplus" };

    for (int i = 0; i < 6; i++)
    {
        HMODULE hmod = GetModuleHandleA(modules[i]);
        if (hmod != NULL)
        {
            MODULEINFO modinfo;
            GetModuleInformation(GetCurrentProcess(), hmod, &modinfo, sizeof(modinfo));

            TEXT_SECTION_INFO textSection = GetTextSection(hmod);
            gadget = (DWORD64)memmem((BYTE*)textSection.address, textSection.size, needle, needle_len);
            if (gadget)
                return gadget;
        }
    }
    return 0;
}
