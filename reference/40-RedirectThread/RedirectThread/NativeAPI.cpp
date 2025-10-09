#include "NativeAPI.h"
#include <iostream> // For std::cerr/std::cout

// Initialize global function pointers
NtCreateThread_t pNtCreateThread = nullptr;
NtQueueApcThread_t pNtQueueApcThread = nullptr;
NtQueueApcThreadEx_t pNtQueueApcThreadEx = nullptr;
NtQueueApcThreadEx2_t pNtQueueApcThreadEx2 = nullptr;
QueueUserAPC2_t pQueueUserAPC2 = nullptr;
NtQueryInformationThread_t pNtQueryInformationThread = nullptr;
NtQuerySystemInformation_t pNtQuerySystemInformation = nullptr;

bool LoadNativeAPIs()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hNtdll || !hKernel32)
    {
        std::cerr << "[!] Failed to get module handle for ntdll.dll or kernel32.dll. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Load NtCreateThread
    pNtCreateThread = (NtCreateThread_t)GetProcAddress(hNtdll, "NtCreateThread");
    if (!pNtCreateThread)
    {
        std::cerr << "[!] Failed to get address for NtCreateThread function." << std::endl;
    }

    // Load NtQueueApcThread functions
    pNtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");
    pNtQueueApcThreadEx = (NtQueueApcThreadEx_t)GetProcAddress(hNtdll, "NtQueueApcThreadEx");
    pNtQueueApcThreadEx2 = (NtQueueApcThreadEx2_t)GetProcAddress(hNtdll, "NtQueueApcThreadEx2");
    pQueueUserAPC2 = (QueueUserAPC2_t)GetProcAddress(hKernel32, "QueueUserAPC2");
    pNtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(hNtdll, "NtQueryInformationThread");
    pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    // pRtlFillMemory = (RtlFillMemory_t)GetProcAddress(hNtdll, "RtlFillMemory");

    if (!pNtQueueApcThread || !pNtQueueApcThreadEx || !pNtQueueApcThreadEx2 || !pNtQueryInformationThread)
    {
        std::cerr << "[!] Failed to get address for one or more NtQueueApcThread* functions." << std::endl;
        if (!pNtQueueApcThread)
            std::cerr << "    - NtQueueApcThread not found.\n";
        if (!pNtQueueApcThreadEx)
            std::cerr << "    - NtQueueApcThreadEx not found.\n";
        if (!pNtQueueApcThreadEx2)
            std::cerr << "    - NtQueueApcThreadEx2 not found.\n";
        if (!pNtQueryInformationThread)
            std::cerr << "    - NtQueryInformationThread not found.\n";
        if (!pNtQuerySystemInformation)
            std::cerr << "    - NtQuerySystemInformation not found.\n";
        // if (!pRtlFillMemory) std::cerr << "    - RtlFillMemory not found.\n";
    }

    if (!pQueueUserAPC2)
    {
        std::cout << "[*] Note: kernel32!QueueUserAPC2 not found (requires Win10 build 1809+). Option --method queueuserapc2 unavailable." << std::endl;
    }

    return true;
}
