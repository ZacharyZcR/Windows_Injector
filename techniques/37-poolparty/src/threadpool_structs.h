#pragma once

#include <windows.h>
#include <winternl.h>

// Thread Pool 内部结构定义（基于逆向工程）

typedef struct _TP_TASK_CALLBACKS {
    PVOID ExecuteCallback;
    PVOID Unposted;
} TP_TASK_CALLBACKS, *PTP_TASK_CALLBACKS;

typedef struct _TP_TASK {
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    CHAR Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, *PTP_TASK;

typedef struct _TPP_REFCOUNT {
    volatile INT32 Refcount;
} TPP_REFCOUNT, *PTPP_REFCOUNT;

typedef struct _TPP_CALLER {
    PVOID ReturnAddress;
} TPP_CALLER, *PTPP_CALLER;

typedef struct _TPP_PH {
    struct _TPP_PH_LINKS* Root;
} TPP_PH, *PTPP_PH;

typedef struct _TPP_TIMER_SUBQUEUE {
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    PVOID Timer;
    PVOID TimerPkt;
    PVOID Direct;
    UINT32 ExpirationWindow;
    INT32 Padding[1];
} TPP_TIMER_SUBQUEUE, *PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE {
    SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 Padding[1];
} TPP_TIMER_QUEUE, *PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE {
    INT32 WorkerCount;
} TPP_NUMA_NODE, *PTPP_NUMA_NODE;

typedef union _TPP_POOL_QUEUE_STATE {
    INT64 Exchange;
    struct {
        INT32 RunningThreadGoal : 16;
        UINT32 PendingReleaseCount : 16;
        UINT32 QueueLength;
    };
} TPP_POOL_QUEUE_STATE, *PTPP_POOL_QUEUE_STATE;

typedef struct _TPP_QUEUE {
    struct _LIST_ENTRY Queue;
    SRWLOCK Lock;
} TPP_QUEUE, *PTPP_QUEUE;

typedef struct _FULL_TP_POOL {
    struct _TPP_REFCOUNT Refcount;
    LONG Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    PVOID ProximityInfo;
    PVOID WorkerFactory;
    PVOID CompletionPort;
    SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    LONG Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    LONG Padding_241;
    CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, *PFULL_TP_POOL;

typedef union _TPP_WORK_STATE {
    INT32 Exchange;
    struct {
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, *PTPP_WORK_STATE;

typedef struct _TPP_ITE_WAITER {
    struct _TPP_ITE_WAITER* Next;
    PVOID ThreadId;
} TPP_ITE_WAITER, *PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS {
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, *PTPP_PH_LINKS;

typedef struct _TPP_ITE {
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, *PTPP_ITE;

typedef union _TPP_FLAGS_COUNT {
    UINT64 Count : 60;
    UINT64 Flags : 4;
    INT64 Data;
} TPP_FLAGS_COUNT, *PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER {
    volatile union _TPP_FLAGS_COUNT Ptr;
    SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, *PTPP_BARRIER;

typedef struct _TP_CLEANUP_GROUP {
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, *PTP_CLEANUP_GROUP;

// ALPC support (需要在 TPP_CLEANUP_GROUP_MEMBER 之前定义)
typedef struct _ALPC_WORK_ON_BEHALF_TICKET {
    UINT32 ThreadId;
    UINT32 ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, *PALPC_WORK_ON_BEHALF_TICKET;

typedef struct _TPP_CLEANUP_GROUP_MEMBER {
    struct _TPP_REFCOUNT Refcount;
    LONG Padding_233;
    const PVOID* VFuncs;  // TPP_CLEANUP_GROUP_MEMBER_VFUNCS
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    PVOID CleanupGroupCancelCallback;
    PVOID FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union {
        PVOID Callback;
        PVOID WorkCallback;
        PVOID SimpleCallback;
        PVOID TimerCallback;
        PVOID WaitCallback;
        PVOID IoCallback;
        PVOID AlpcCallback;
        PVOID AlpcCallbackEx;
        PVOID JobCallback;
    };
    PVOID Context;
    PVOID ActivationContext;
    PVOID SubProcessTag;
    GUID ActivityId;
    ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    PVOID RaceDll;
    PFULL_TP_POOL Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    LONG CallbackPriority;
    INT32 Padding_234[1];
} TPP_CLEANUP_GROUP_MEMBER, *PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK {
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    union _TPP_WORK_STATE WorkState;
    INT32 Padding_235[1];
} FULL_TP_WORK, *PFULL_TP_WORK;

// Worker Factory 相关定义

typedef enum _WORKERFACTORYINFOCLASS {
    WorkerFactoryTimeout,
    WorkerFactoryRetryTimeout,
    WorkerFactoryIdleTimeout,
    WorkerFactoryBindingCount,
    WorkerFactoryThreadMinimum,
    WorkerFactoryThreadMaximum,
    WorkerFactoryPaused,
    WorkerFactoryBasicInformation,
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation,
    WorkerFactoryThreadBasePriority,
    WorkerFactoryTimeoutWaiters,
    WorkerFactoryFlags,
    WorkerFactoryThreadSoftMaximum,
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, *PWORKER_FACTORY_BASIC_INFORMATION;

// Process handle information
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

// Undocumented Ntdll functions
typedef NTSTATUS (NTAPI *pNtQueryInformationWorkerFactory)(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
);

// Handle access rights
#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020
#define WORKER_FACTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | WORKER_FACTORY_RELEASE_WORKER | \
    WORKER_FACTORY_WAIT | WORKER_FACTORY_SET_INFORMATION | WORKER_FACTORY_QUERY_INFORMATION | \
    WORKER_FACTORY_READY_WORKER | WORKER_FACTORY_SHUTDOWN)
