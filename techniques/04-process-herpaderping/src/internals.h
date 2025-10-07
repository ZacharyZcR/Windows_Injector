#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>
#include <winternl.h>

// ===== NT 状态码 =====
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_IMAGE_MACHINE_TYPE_MISMATCH
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH ((NTSTATUS)0x4000000EL)
#endif

// ===== 进程创建标志 =====
#ifndef PROCESS_CREATE_FLAGS_INHERIT_HANDLES
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#endif

// ===== 节对象访问权限 =====
#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS 0x000F001F
#endif

// ===== 节属性 =====
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

// ===== RTL 常量 =====
#ifndef RTL_USER_PROC_PARAMS_NORMALIZED
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#endif

// ===== 扩展的 PEB 结构（包含 ImageBaseAddress） =====
typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
    PVOID ImageBaseAddress;  // 关键字段
} MY_PEB, *PMY_PEB;

// ===== 扩展的 RTL_USER_PROCESS_PARAMETERS 结构 =====
typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StdInputHandle;
    HANDLE StdOutputHandle;
    HANDLE StdErrorHandle;
    UNICODE_STRING CurrentDirectoryPath;
    HANDLE CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingPositionLeft;
    ULONG StartingPositionTop;
    ULONG Width;
    ULONG Height;
    ULONG CharWidth;
    ULONG CharHeight;
    ULONG ConsoleTextAttributes;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopName;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    SIZE_T EnvironmentSize;  // 环境变量大小
} MY_RTL_USER_PROCESS_PARAMETERS, *PMY_RTL_USER_PROCESS_PARAMETERS;

// ===== NT API 函数声明 =====

/**
 * 创建节对象
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
 * 从内存节创建进程（关键 API）
 */
typedef NTSTATUS (NTAPI *_NtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

/**
 * 创建远程线程
 */
typedef NTSTATUS (NTAPI *_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

/**
 * 读取虚拟内存
 */
typedef NTSTATUS (NTAPI *_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);

/**
 * 创建进程参数
 */
typedef NTSTATUS (NTAPI *_RtlCreateProcessParametersEx)(
    PMY_RTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

// ===== 全局函数指针 =====
extern _NtCreateSection NtCreateSection;
extern _NtCreateProcessEx NtCreateProcessEx;
extern _NtCreateThreadEx NtCreateThreadEx;
extern _NtReadVirtualMemory NtReadVirtualMemory;
extern _RtlCreateProcessParametersEx RtlCreateProcessParametersEx;

/**
 * 初始化所有 NT API 函数指针
 */
BOOL InitializeNtFunctions();

#endif // INTERNALS_H
