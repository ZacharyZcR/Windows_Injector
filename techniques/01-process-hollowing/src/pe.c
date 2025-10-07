#include "pe.h"
#include <stdio.h>

#define BUFFER_SIZE 0x2000

// NtQueryInformationProcess 已在 winternl.h 中声明，直接使用

/**
 * 查找远程进程的 PEB 地址
 */
DWORD FindRemotePEB(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION basicInfo = {0};
    ULONG dwReturnLength = 0;

    // ProcessBasicInformation = 0
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &dwReturnLength
    );

    if (status != 0) {
        printf("错误：NtQueryInformationProcess 失败，状态码：0x%lX\n", status);
        return 0;
    }

    // 返回 PEB 基址
    #ifdef _WIN64
        return (DWORD)(ULONG_PTR)basicInfo.PebBaseAddress;
    #else
        return (DWORD)basicInfo.PebBaseAddress;
    #endif
}

/**
 * 读取远程进程的 PEB
 */
MY_PEB* ReadRemotePEB(HANDLE hProcess) {
    DWORD dwPEBAddress = FindRemotePEB(hProcess);
    if (!dwPEBAddress) {
        return NULL;
    }

    // 分配 PEB 结构
    MY_PEB* pPEB = (MY_PEB*)malloc(sizeof(MY_PEB));
    if (!pPEB) {
        printf("错误：分配 PEB 内存失败\n");
        return NULL;
    }

    // 读取 PEB（我们只需要前面的部分来获取 ImageBaseAddress）
    #ifdef _WIN64
        PVOID pPEBAddr = (PVOID)(ULONG_PTR)dwPEBAddress;
    #else
        PVOID pPEBAddr = (PVOID)dwPEBAddress;
    #endif

    if (!ReadProcessMemory(hProcess, pPEBAddr, pPEB, sizeof(MY_PEB), NULL)) {
        printf("错误：读取 PEB 失败，错误码：%lu\n", GetLastError());
        free(pPEB);
        return NULL;
    }

    return pPEB;
}

/**
 * 获取 NT 头
 */
PIMAGE_NT_HEADERS GetNTHeaders(PVOID pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    return (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBase + pDosHeader->e_lfanew);
}

/**
 * 从缓冲区获取加载的镜像信息
 */
PLOADED_IMAGE GetLoadedImage(PVOID pImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNTHeaders = GetNTHeaders(pImageBase);

    PLOADED_IMAGE pImage = (PLOADED_IMAGE)malloc(sizeof(LOADED_IMAGE));
    if (!pImage) {
        printf("错误：分配 LOADED_IMAGE 内存失败\n");
        return NULL;
    }

    memset(pImage, 0, sizeof(LOADED_IMAGE));

    pImage->FileHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBase + pDosHeader->e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = (PIMAGE_SECTION_HEADER)(
        (ULONG_PTR)pImageBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)
    );

    return pImage;
}

/**
 * 读取远程进程的镜像信息
 */
PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress) {
    // 分配缓冲区读取远程镜像头
    BYTE* lpBuffer = (BYTE*)malloc(BUFFER_SIZE);
    if (!lpBuffer) {
        printf("错误：分配缓冲区失败\n");
        return NULL;
    }

    // 读取远程进程的镜像头
    if (!ReadProcessMemory(hProcess, lpImageBaseAddress, lpBuffer, BUFFER_SIZE, NULL)) {
        printf("错误：读取远程镜像失败\n");
        free(lpBuffer);
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("错误：无效的 DOS 签名\n");
        free(lpBuffer);
        return NULL;
    }

    PLOADED_IMAGE pImage = (PLOADED_IMAGE)malloc(sizeof(LOADED_IMAGE));
    if (!pImage) {
        printf("错误：分配 LOADED_IMAGE 内存失败\n");
        free(lpBuffer);
        return NULL;
    }

    memset(pImage, 0, sizeof(LOADED_IMAGE));

    pImage->FileHeader = (PIMAGE_NT_HEADERS)(lpBuffer + pDosHeader->e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = (PIMAGE_SECTION_HEADER)(
        lpBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)
    );

    // 注意：这里不释放 lpBuffer，因为 pImage 指向其中的数据
    // 调用者需要同时管理这两块内存

    free(lpBuffer);
    return pImage;
}
