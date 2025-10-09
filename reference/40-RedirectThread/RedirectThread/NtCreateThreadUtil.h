#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <vector>      // For shellcode bytes
#include <winternl.h>  // For TEB/Context structures
#include "NativeAPI.h" // For Native API types like PINITIAL_TEB, PCONTEXT

// --- NtCreateThread Utility Function Declarations ---

// Enables the necessary privilege for certain operations (like process interaction).
bool EnableDebugPrivilege();

// Allocates memory for a stack in the remote process.
bool AllocateRemoteStack(HANDLE hProcess, SIZE_T stackSize, PVOID *pStackBase, PVOID *pStackLimit);

// Initializes the TEB structure for the new thread.
bool PrepareInitialTeb(PINITIAL_TEB pInitialTeb, PVOID pStackBase, PVOID pStackLimit);

// Initializes the CONTEXT structure for the new thread.
bool PrepareThreadContext(PCONTEXT pContext, PVOID pStartAddress, PVOID pStackBase);

// Creates a remote thread using the NtCreateThread API.
// Note: This is a lower-level function. Consider if InjectShellcodeUsingNtCreateThread is more appropriate.
bool CreateThreadViaNtCreateThread(HANDLE hProcess, LPVOID functionAddress, DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4, SIZE_T stackSize = 1024 * 1024);

// Allocates memory in the remote process using NtCreateThread technique (potentially via a helper thread).
// Note: This seems unused in the current flow, might be legacy or for a different approach.
LPVOID AllocateMemoryViaNtCreateThread(HANDLE hProcess, DWORD64 baseAddress, SIZE_T size, DWORD allocType, DWORD protect);

// Copies memory to the remote process using NtCreateThread technique (potentially via a helper thread).
// Note: This seems unused in the current flow, might be legacy or for a different approach.
bool PerformRemoteMemoryCopyViaNtCreateThread(HANDLE processHandle, LPVOID memCopyAddress, DWORD64 destinationAddress, const unsigned char *sourceData, size_t dataSize);

// Executes shellcode in the remote process using NtCreateThread technique (potentially via a helper thread).
// Note: This seems unused in the current flow, might be legacy or for a different approach.
bool ExecuteShellcodeViaNtCreateThread(HANDLE processHandle, LPVOID shellcodeAddress);

// High-level function to inject shellcode using the NtCreateThread method.
// This likely orchestrates allocation, copying, and execution via NtCreateThread.
bool InjectShellcodeUsingNtCreateThread(HANDLE hProcess, const std::vector<unsigned char> &shellcodeBytes, SIZE_T allocSize, DWORD allocPerm, bool verbose);
