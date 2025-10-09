#include "Helpers.h"

bool ValidateTargetProcess(DWORD pid, bool verbose)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_PARAMETER)
        {
            std::cerr << "[!] Process with PID " << pid << " does not exist." << std::endl;
        }
        else
        {
            std::cerr << "[!] Failed to validate process with PID " << pid << ". Error: " << error << std::endl;
        }
        return false;
    }

    // Check if process is actually running
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(hProcess, &exitCode) || exitCode != STILL_ACTIVE)
    {
        std::cerr << "[!] Process with PID " << pid << " is not running (exit code: " << exitCode << ")." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (verbose)
    {
        std::cout << "[*] Validated process with PID " << pid << " exists and is running." << std::endl;
    }

    CloseHandle(hProcess);
    return true;
}

bool ValidateTargetThread(DWORD tid, bool verbose)
{
    HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!hThread)
    {
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_PARAMETER)
        {
            std::cerr << "[!] Thread with TID " << tid << " does not exist." << std::endl;
        }
        else
        {
            std::cerr << "[!] Failed to validate thread with TID " << tid << ". Error: " << error << std::endl;
        }
        return false;
    }

    // Additional check to see if thread is running/alive
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode != STILL_ACTIVE)
    {
        std::cerr << "[!] Thread with TID " << tid << " is not running (exit code: " << exitCode << ")." << std::endl;
        CloseHandle(hThread);
        return false;
    }

    if (verbose)
    {
        std::cout << "[*] Validated thread with TID " << tid << " exists and is active." << std::endl;
    }

    CloseHandle(hThread);
    return true;
}

bool LoadShellcode(const std::string &filepath, std::vector<unsigned char> &bytes)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "[!] Failed to open shellcode file: " << filepath << std::endl;
        return false;
    }

    // Get file size
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Resize vector and read file contents
    bytes.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char *>(bytes.data()), size))
    {
        std::cerr << "[!] Failed to read shellcode file: " << filepath << std::endl;
        return false;
    }

    return true;
}

bool LoadShellcodeEx(const InjectionConfig &config, std::vector<unsigned char> &shellcodeBytes)
{
    // Prioritize directly provided shellcode bytes
    if (!config.shellcodeBytes.empty())
    {
        shellcodeBytes = config.shellcodeBytes;
        if (config.verbose)
        {
            std::cout << "[*] Using " << shellcodeBytes.size() << " bytes of shellcode provided directly." << std::endl;
        }
    }
    // If not provided directly, try loading from file path
    else if (!config.shellcodeFilePath.empty())
    {
        if (!LoadShellcode(config.shellcodeFilePath, shellcodeBytes))
        {
            return false;
        }
        if (config.verbose)
        {
            std::cout << "[*] Loaded " << shellcodeBytes.size() << " bytes of shellcode from " << config.shellcodeFilePath << std::endl;
        }
    }

    // Final validation checks
    if (shellcodeBytes.empty())
    {
        std::cerr << "[!] No shellcode provided for injection (neither direct bytes nor a valid file path was specified)." << std::endl;
        return false;
    }

    if (shellcodeBytes.size() > config.allocSize)
    {
        std::cerr << "[!] Shellcode size (" << shellcodeBytes.size()
                  << " bytes) is larger than requested allocation size (" << config.allocSize
                  << " bytes)." << std::endl;
        return false;
    }

    return true;
}
