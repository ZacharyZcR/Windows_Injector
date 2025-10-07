#include "pe_utils.h"
#include <stdio.h>

/**
 * 读取文件到内存缓冲区
 */
BYTE* ReadFileToBuffer(const WCHAR* filePath, DWORD* fileSize) {
    HANDLE hFile = CreateFileW(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"错误：无法打开文件 %s，错误码：%d\n", filePath, GetLastError());
        return NULL;
    }

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        wprintf(L"错误：获取文件大小失败\n");
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* buffer = (BYTE*)malloc(size);
    if (!buffer) {
        wprintf(L"错误：分配内存失败\n");
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, size, &bytesRead, NULL) || bytesRead != size) {
        wprintf(L"错误：读取文件失败\n");
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *fileSize = size;
    return buffer;
}

/**
 * 判断 PE 文件是否为 64 位
 */
BOOL IsPE64Bit(BYTE* peBuffer) {
    if (!peBuffer) return FALSE;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    return (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
}

/**
 * 获取 PE 文件的入口点 RVA
 */
DWORD GetEntryPointRVA(BYTE* peBuffer) {
    if (!peBuffer) return 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return ntHeaders->OptionalHeader.AddressOfEntryPoint;
}

/**
 * 获取 PE 文件的 ImageBase
 */
ULONG_PTR GetImageBase(BYTE* peBuffer) {
    if (!peBuffer) return 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return (ULONG_PTR)ntHeaders->OptionalHeader.ImageBase;
}
