#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream> // For error reporting if needed

// --- Process and Thread Manipulation Function Declarations ---

// Opens the target process with appropriate access rights.
HANDLE OpenTargetProcess(DWORD pid);

// Opens the target thread with appropriate access rights for APC queuing.
HANDLE OpenTargetThread(DWORD tid);

// Creates a remote thread that simply calls Sleep. (Purpose might need clarification)
HANDLE CreateRemoteSleepThread(HANDLE hProcess, LPVOID pSleepLocal);

// Hijacks an existing thread to execute an infinite loop gadget.
bool HijackThreadToLoop(HANDLE hThread, LPVOID pInfiniteLoopGadget, bool useSuspend);

// Hijacks an existing thread to call VirtualAlloc.
bool HijackThreadToVirtualAlloc(HANDLE hThread, LPVOID pVirtualAllocLocal, SIZE_T allocSize, DWORD allocPerm, bool useSuspend);

// Hijacks an existing thread to execute shellcode at a given address.
bool HijackThreadToShellcode(HANDLE hThread, LPVOID pShellcodeAddr, bool useSuspend);
