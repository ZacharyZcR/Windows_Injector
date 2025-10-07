#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>
#include <winternl.h>

// winternl.h 已经定义了 PROCESS_BASIC_INFORMATION，这里只需要补充 PEB 结构

// ===== 基址重定位块结构 =====
typedef struct _BASE_RELOCATION_BLOCK {
    DWORD PageAddress;   // 页面基址
    DWORD BlockSize;     // 块大小
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

// ===== 基址重定位条目（使用位域）=====
typedef struct _BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;  // 偏移量（12位）
    USHORT Type : 4;     // 类型（4位）
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

// ===== 计算重定位条目数量的宏 =====
#define CountRelocationEntries(dwBlockSize) \
    ((dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY))

// ===== PEB 结构（精简版）=====
// winternl.h 的 PEB 结构定义不完整，这里使用自定义版本
typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID ImageBaseAddress;  // 镜像基址（偏移 0x10）
    // ... 其他字段省略，我们只需要 ImageBaseAddress
} MY_PEB, *PMY_PEB;

// ===== 未导出的 NT API 函数声明 =====

// 卸载内存视图
typedef NTSTATUS (WINAPI* _NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

#endif // INTERNALS_H
