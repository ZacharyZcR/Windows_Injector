/*
 * Reflective DLL Injection - LoadLibraryR Header
 *
 * 反射加载辅助函数头文件
 *
 * 提供两个核心功能：
 * 1. LoadRemoteLibraryR - 远程注入反射 DLL
 * 2. GetReflectiveLoaderOffset - 查找 ReflectiveLoader 导出函数偏移
 */

#ifndef _LOADLIBRARYR_H
#define _LOADLIBRARYR_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// 内存解引用宏
#define DEREF(name)       *(ULONG_PTR *)(name)
#define DEREF_64(name)    *(DWORD64 *)(name)
#define DEREF_32(name)    *(DWORD *)(name)
#define DEREF_16(name)    *(WORD *)(name)
#define DEREF_8(name)     *(BYTE *)(name)

// ========================================
// 函数声明
// ========================================

/*
 * 将 RVA 转换为文件偏移
 *
 * 参数：
 *   dwRva - 相对虚拟地址（RVA）
 *   uiBaseAddress - PE 文件基址
 *
 * 返回：
 *   文件偏移（File Offset）
 */
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);

/*
 * 在 DLL 的导出表中查找 ReflectiveLoader 函数的文件偏移
 *
 * 参数：
 *   lpReflectiveDllBuffer - DLL 文件在内存中的缓冲区
 *
 * 返回：
 *   ReflectiveLoader 函数的文件偏移，失败返回 0
 */
DWORD GetReflectiveLoaderOffset(VOID *lpReflectiveDllBuffer);

/*
 * 将反射 DLL 注入到远程进程
 *
 * 参数：
 *   hProcess - 目标进程句柄
 *   lpBuffer - DLL 文件内容缓冲区
 *   dwLength - DLL 文件大小
 *   lpParameter - 传递给 DllMain 的参数（可选）
 *
 * 返回：
 *   远程线程句柄，失败返回 NULL
 *
 * 注意：
 *   - hProcess 需要权限: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
 *                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
 *   - DLL 必须导出 ReflectiveLoader 函数
 */
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);

#endif // _LOADLIBRARYR_H
