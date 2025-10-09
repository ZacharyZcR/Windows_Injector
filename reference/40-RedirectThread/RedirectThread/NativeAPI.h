#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h> // For CLIENT_ID, INITIAL_TEB etc.

// --- Native API Definitions ---
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// _CLIENT_ID is defined in winternl.h (included via Windows.h)
// Remove our manual definition to avoid redefinition errors.
// Define the pointer type PCLIENT_ID if not already defined by headers.
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _INITIAL_TEB
{                       // Keep INITIAL_TEB definition if not standard
    PVOID Reserved1[3]; // Reserved for internal use
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Reserved2[19]; // Other TEB fields
} INITIAL_TEB, *PINITIAL_TEB;

// NtCreateThread function prototype
typedef NTSTATUS(NTAPI *NtCreateThread_t)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes, // POBJECT_ATTRIBUTES
    IN HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN PCONTEXT ThreadContext,
    IN PINITIAL_TEB InitialTeb,
    IN BOOLEAN CreateSuspended);

// APC related types
typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef VOID(NTAPI *PPS_APC_ROUTINE)(
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3);

typedef NTSTATUS(NTAPI *NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef NTSTATUS(NTAPI *NtQueueApcThreadEx_t)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3);

#define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x00000001

typedef NTSTATUS(NTAPI *NtQueueApcThreadEx2_t)(
    HANDLE ThreadHandle,
    HANDLE ReserveHandle,
    ULONG ApcFlags,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3);

typedef BOOL(WINAPI *QueueUserAPC2_t)(
    PAPCFUNC pfnAPC,
    HANDLE hThread,
    ULONG_PTR dwData1,
    ULONG_PTR dwData2,
    ULONG_PTR dwData3);

typedef VOID(NTAPI *RtlFillMemory_t)(
    OUT PVOID Destination,
    IN SIZE_T Length,
    IN BYTE Fill);

// --- KWAIT_REASON Enum (Commonly known values) ---
typedef enum _KWAIT_REASON
{
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4, // <--- Reason for Sleep/NtDelayExecution
    Suspended = 5,
    UserRequest = 6, // <--- Reason for WaitForSingleObject etc.
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    WrKeyedEvent = 21,
    WrTerminated = 22,
    WrProcessInSwap = 23,
    WrCpuRateControl = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    MaximumWaitReason = 37
} KWAIT_REASON;

// --- THREAD_STATE Enum (Commonly known values) ---
typedef enum _KTHREAD_STATE
{
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5, // <--- State when sleeping or waiting
    Transition = 6,
    DeferredReady = 7,
    GateWait = 8,
    MaximumThreadState = 9
} KTHREAD_STATE;

// --- NtQueryInformationThread --- ADD THIS SECTION ---
// Define ThreadInformationClass if not already available from headers
// #ifndef THREADINFOCLASS
// typedef enum _THREADINFOCLASS {
//    ThreadBasicInformation,       // 0 Y N
//    ThreadTimes,                  // 1 Y N
//    ThreadPriority,               // 2 Y Y
//    ThreadBasePriority,           // 3 Y Y
//    ThreadAffinityMask,           // 4 Y Y
//    ThreadImpersonationToken,     // 5 Y Y
//    ThreadDescriptorTableEntry,   // 6 Y N - Not supported on x64
//    ThreadEnableAlignmentFaultFixup, // 7 Y Y
//    ThreadEventPair,              // 8 N Y
//    ThreadQuerySetWin32StartAddress,// 9 Y Y
//    ThreadZeroTlsCell,            // 10 N Y - Supported starting Vista
//    ThreadPerformanceCount,       // 11 Y N - Supported starting Vista
//    ThreadAmILastThread,          // 12 Y N - Supported starting Vista
//    ThreadIdealProcessor,         // 13 Y Y
//    ThreadPriorityBoost,          // 14 Y Y
//    ThreadSetTlsArrayAddress,     // 15 N Y - Supported starting Vista
//    ThreadIsIoPending,            // 16 Y N - Supported starting Vista
//    ThreadHideFromDebugger,       // 17 N Y - Supported starting Vista
//    ThreadBreakOnTermination,     // 18 N Y - Supported starting Vista
//    ThreadSwitchLegacyState,      // 19 N N
//    ThreadIsTerminated,           // 20 Y N - Supported starting Vista
//    ThreadLastSystemCall,         // 21 Y N - Supported starting Vista SP1
//    ThreadIoPriority,             // 22 Y Y - Supported starting Vista
//    ThreadCycleTime,              // 23 Y N - Supported starting Vista
//    ThreadPagePriority,           // 24 Y Y - Supported starting Windows 7
//    ThreadActualBasePriority,     // 25 Y N
//    ThreadTebInformation,         // 26 Y N - Supported starting Windows 7
//    ThreadCSwitchMon,             // 27 N N - Supported starting Windows 8
//    ThreadCSwitchPteMap,          // 28 N N - Supported starting Windows 8
//    ThreadWow64Context,           // 29 Y Y - Supported starting Windows 8
//    ThreadGroupInformation,       // 30 Y Y - Supported starting Windows 7
//    ThreadUmsInformation,         // 31 N Y - Supported starting Windows 7
//    ThreadCounterProfiling,       // 32 N Y
//    ThreadIdealProcessorEx,       // 33 Y Y - Supported starting Windows 7
//    ThreadCpuSetInformation,      // 34 Y Y - Supported starting Windows 10
//    ThreadCSwitchOptions,         // 35 N N
//    ThreadSuspendCount,           // 36 Y N - Supported starting Windows 10
//    ThreadActualGroupCount,       // 37 Y N
//    ThreadJobInformation,         // 38 Y Y - Supported starting Windows 10
//    MaxThreadInfoClass
//} THREADINFOCLASS;
// #endif

// Define SystemProcessInformation class value
#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

// Structure needed for SystemProcessInformation (Simplified)
// NOTE: Full definition is complex and varies slightly between Windows versions.
// We only need offsets to find thread information.
typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // Should be LARGE_INTEGER
    ULONG HardFaultCount;                // Should be ULONG
    ULONG NumberOfThreadsHighWatermark;  // Should be ULONG
    ULONGLONG CycleTime;                 // Should be ULONGLONG
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority; // Should be KPRIORITY
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // Size varies between x86/x64
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // Variable number of threads
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

// Structure for ThreadBasicInformation
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// Define the function pointer type
typedef NTSTATUS(NTAPI *NtQueryInformationThread_t)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

// Add NtQuerySystemInformation
typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

// --- Global Function Pointers for Native APIs ---
// These are defined in NativeAPI.cpp
extern NtCreateThread_t pNtCreateThread;
extern NtQueueApcThread_t pNtQueueApcThread;
extern NtQueueApcThreadEx_t pNtQueueApcThreadEx;
extern NtQueueApcThreadEx2_t pNtQueueApcThreadEx2;
extern QueueUserAPC2_t pQueueUserAPC2;
extern NtQueryInformationThread_t pNtQueryInformationThread;
extern NtQuerySystemInformation_t pNtQuerySystemInformation;
extern RtlFillMemory_t pRtlFillMemory;

// --- Function Declarations ---
// Loads function pointers for required native APIs.
// Returns true if essential APIs are loaded, false otherwise.
bool LoadNativeAPIs();
