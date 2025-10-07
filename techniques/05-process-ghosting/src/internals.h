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
#ifndef PS_INHERIT_HANDLES
#define PS_INHERIT_HANDLES 4
#endif

// ===== 对象属性宏 =====
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

// 文件信息类和处置信息在 winternl.h 中已定义，直接使用

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

// ===== 文件打开选项 =====
#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE 0x00000000
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

// ===== 扩展的 PEB 结构（包含 ImageBaseAddress） =====
typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;      // 0x00
    BOOLEAN ReadImageFileExecOptions;   // 0x01
    BOOLEAN BeingDebugged;              // 0x02
    BOOLEAN SpareBool;                  // 0x03
    BYTE Padding0[4];                   // 0x04 对齐到 8 字节
    HANDLE Mutant;                      // 0x08
    PVOID ImageBaseAddress;             // 0x10 关键字段！
    PVOID Ldr;                          // 0x18
    PVOID ProcessParameters;            // 0x20
    PVOID SubSystemData;                // 0x28
    PVOID ProcessHeap;                  // 0x30
    PVOID FastPebLock;                  // 0x38
    PVOID AtlThunkSListPtr;             // 0x40
    PVOID IFEOKey;                      // 0x48
    // ... 更多字段
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
// NtOpenFile, NtSetInformationFile 在 winternl.h 中已声明

/**
 * 写入文件
 */
typedef NTSTATUS (NTAPI *_NtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

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
// NtOpenFile, NtSetInformationFile 使用系统声明，不需要函数指针
extern _NtWriteFile NtWriteFile;
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
