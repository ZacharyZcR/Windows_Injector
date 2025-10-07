#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>
#include <winternl.h>

// ===== NT 状态码 =====
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_IMAGE_NOT_AT_BASE
#define STATUS_IMAGE_NOT_AT_BASE ((NTSTATUS)0x40000003L)
#endif

// ===== 节对象访问权限 =====
#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | \
                            SECTION_MAP_WRITE | SECTION_MAP_READ | \
                            SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE)
#endif

// ===== 节属性 =====
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

// ===== 内存分配类型 =====
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

// ===== NT API 函数声明 =====

/**
 * 创建节对象（内存段）
 */
typedef NTSTATUS (NTAPI *_NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

/**
 * 将节对象映射到进程地址空间
 */
typedef NTSTATUS (NTAPI *_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

/**
 * 卸载内存视图
 */
typedef NTSTATUS (NTAPI *_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// ===== Kernel32 未导出函数 =====

/**
 * CreateProcessInternalW - 内部进程创建函数
 */
typedef BOOL (WINAPI *_CreateProcessInternalW)(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
);

// ===== 全局函数指针 =====
extern _NtCreateSection NtCreateSection;
extern _NtMapViewOfSection NtMapViewOfSection;
extern _NtUnmapViewOfSection NtUnmapViewOfSection;
extern _CreateProcessInternalW CreateProcessInternalW;

/**
 * 初始化所有 NT API 函数指针
 */
BOOL InitializeNtFunctions();

/**
 * 初始化 Kernel32 未导出函数
 */
BOOL InitializeKernel32Functions();

#endif // INTERNALS_H
