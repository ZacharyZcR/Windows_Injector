#pragma once
#include "Injection.h"

bool InjectShellcodeUsingAPC(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config);

bool InjectShellcodeUsingQueueUserAPC2(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config);

bool InjectShellcodeUsingNtQueueApcThread(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config);

bool InjectShellcodeUsingNtQueueApcEx(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config);

bool InjectShellcodeUsingNtQueueApcThreadEx2(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config);

bool ExecuteRemoteFunctionViaAPCHijack(
    HANDLE hProcess,
    const InjectionConfig &config, // Pass config for TID, verbose, suspend flag etc.
    LPVOID pfnTargetFunction,      // The function we ultimately want to call
    DWORD64 arg1,                  // Target function's arg 1 (RCX)
    DWORD64 arg2,                  // Target function's arg 2 (RDX)
    DWORD64 arg3,                  // Target function's arg 3 (R8)
    DWORD64 arg4,                  // Target function's arg 4 (R9)
    LPVOID pSleep,                 // Address of Sleep for hijack primitive
    LPVOID loopGadgetAddr          // Address of Loop Gadget for hijack primitive
);

bool PerformRemoteMemoryCopyViaAPCHijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlMoveMemory,           // Address of RtlMoveMemory
    LPVOID pRemoteDestBase,          // Base address in target to write to
    const unsigned char *sourceData, // Local shellcode buffer
    size_t dataSize,                 // Size of shellcode
    LPVOID pSleep,                   // Address of Sleep for hijack primitive
    LPVOID loopGadgetAddr            // Address of Loop Gadget for hijack primitive
);

bool ExecuteRemoteFunctionViaQueueUserAPC2Hijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr);

bool PerformRemoteMemoryCopyViaNtQueueApcThread(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlFillMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep);

bool PerformRemoteMemoryCopyViaNtQueueApcExHijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlMoveMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep,
    LPVOID loopGadgetAddr);

// --- Hijack Primitive using NtQueueApcThreadEx2 ---
bool ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr);

bool GetThreadStateAndWaitReason(DWORD targetTid, KTHREAD_STATE &outState, KWAIT_REASON &outWaitReason, bool verbose);
bool IsThreadSleeping(DWORD targetTid, bool verbose);
bool WaitForThreadToSleep(DWORD targetTid, int timeoutMs, bool verbose);
bool WaitForThreadToRunOrReady(DWORD targetTid, int timeoutMs, bool verbose);
