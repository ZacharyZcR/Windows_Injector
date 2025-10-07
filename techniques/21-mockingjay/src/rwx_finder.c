/**
 * ===================================================================
 * RWX Section Finder - RWX 节区扫描工具
 * ===================================================================
 *
 * 功能：
 * - 扫描指定目录下的所有 DLL 文件
 * - 识别包含 RWX（可读可写可执行）节区的 DLL
 * - 输出节区详细信息
 *
 * 编译：gcc rwx_finder.c -o rwx_finder.exe -ldbghelp
 * 用法：rwx_finder.exe <目录路径>
 *       rwx_finder.exe C:\Windows\System32
 * ===================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

// ANSI 颜色代码
#define COLOR_GREEN "\033[1;32m"
#define COLOR_RESET "\033[0m"

// ========================================
// 函数声明
// ========================================

BOOL ScanDLLForRWXSections(const char* dllPath);
BOOL IsRWXSection(DWORD characteristics);
void ScanDirectory(const char* directory);

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("  RWX Section Finder\n");
    printf("  查找包含 RWX 节区的 DLL\n");
    printf("======================================\n\n");

    if (argc < 2) {
        printf("用法：%s <目录路径>\n\n", argv[0]);
        printf("示例：\n");
        printf("  %s C:\\Windows\\System32\n", argv[0]);
        printf("  %s \"C:\\Program Files\"\n\n", argv[0]);
        return 1;
    }

    const char* directory = argv[1];

    printf("[i] 扫描目录：%s\n\n", directory);
    ScanDirectory(directory);
    printf("\n[i] 扫描完成！\n");

    return 0;
}

/**
 * ===================================================================
 * 扫描目录中的所有 DLL 文件
 * ===================================================================
 */
void ScanDirectory(const char* directory) {
    char searchPath[MAX_PATH];
    WIN32_FIND_DATAA findData;

    // 构建搜索路径：directory\*.dll
    snprintf(searchPath, sizeof(searchPath), "%s\\*.dll", directory);

    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[!] 无法访问目录：%s\n", directory);
        return;
    }

    int dllCount = 0;
    int rwxCount = 0;

    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char fullPath[MAX_PATH];
            snprintf(fullPath, sizeof(fullPath), "%s\\%s", directory, findData.cFileName);

            dllCount++;

            if (ScanDLLForRWXSections(fullPath)) {
                rwxCount++;
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    printf("\n[i] 统计：扫描 %d 个 DLL，发现 %d 个包含 RWX 节区\n", dllCount, rwxCount);
}

/**
 * ===================================================================
 * 扫描单个 DLL 文件的 RWX 节区
 * ===================================================================
 */
BOOL ScanDLLForRWXSections(const char* dllPath) {
    HANDLE hFile = CreateFileA(
        dllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    // 读取文件到内存
    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        free(fileBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // 解析 PE 头
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(fileBuffer);
        return FALSE;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        free(fileBuffer);
        return FALSE;
    }

    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

    BOOL foundRWX = FALSE;

    // 遍历所有节区
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (IsRWXSection(sectionHeader->Characteristics)) {
            if (!foundRWX) {
                // 第一次找到，打印 DLL 路径
                printf(COLOR_GREEN "[+] 发现 RWX 节区：%s" COLOR_RESET "\n", dllPath);
                foundRWX = TRUE;
            }

            // 打印节区信息
            char sectionName[9] = {0};
            memcpy(sectionName, sectionHeader->Name, 8);

            printf("    节区名：%-8s | 虚拟地址：0x%08X | 大小：%u 字节 | 特性：0x%08X\n",
                   sectionName,
                   sectionHeader->VirtualAddress,
                   sectionHeader->SizeOfRawData,
                   sectionHeader->Characteristics);
        }

        sectionHeader++;
    }

    free(fileBuffer);
    return foundRWX;
}

/**
 * ===================================================================
 * 检查节区是否具有 RWX 权限
 * ===================================================================
 */
BOOL IsRWXSection(DWORD characteristics) {
    return (characteristics & IMAGE_SCN_MEM_READ) &&
           (characteristics & IMAGE_SCN_MEM_WRITE) &&
           (characteristics & IMAGE_SCN_MEM_EXECUTE);
}
