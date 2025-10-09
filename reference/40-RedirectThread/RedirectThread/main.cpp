#include "Arguments.h"          // For ParseArguments, PrintConfiguration, print_usage, InjectionConfig
#include "NativeAPI.h"          // For LoadNativeAPIs, pNtCreateThread
#include "NtCreateThreadUtil.h" // For EnableDebugPrivilege
#include "Injection.h"          // For InjectDllPointerOnly, InjectShellcodeContext
#include "Helpers.h"

int main(int argc, char *argv[])
{
    if (argc <= 1)
    {
        print_usage(argv[0]); // From Arguments.h
        return 1;
    }

    // Load Native APIs early
    if (!LoadNativeAPIs())
    {
        std::cerr << "[!] Warning: Failed to load some required native APIs. Certain methods may fail." << std::endl;
    }

    InjectionConfig config;
    if (!ParseArguments(argc, argv, config))
    {
        print_usage(argv[0]);
        return 1;
    }

    // Print effective settings using the dedicated function
    PrintConfiguration(config);

    // Validate target process
    if (!ValidateTargetProcess(config.targetPid, config.verbose))
    {
        std::cerr << "[!] Target process validation failed." << std::endl;
        return 1;
    }
    // Validate target thread if applicable
    if (config.method != DeliveryMethod::CREATETHREAD && config.method != DeliveryMethod::NTCREATETHREAD && config.targetTid == 0 && !ValidateTargetThread(config.targetTid, config.verbose))
    {
        std::cerr << "[!] Target thread validation failed." << std::endl;
        return 1;
    }

    std::cout << "\n[*] Starting injection process...\n"
              << std::endl;

    bool success = false;
    switch (config.mode)
    {
    case InjectionMode::DLL_POINTER:
        success = InjectDllPointerOnly(config);
        break;
    case InjectionMode::SHELLCODE:
        success = Inject(config);
        break;

    default:
        std::cerr << "[!] Invalid injection mode." << std::endl;
        return 1;
    }

    if (success)
    {
        std::cout << "\n[+] Injection successful!" << std::endl;
        return 0;
    }
    else
    {
        std::cerr << "\n[!] Injection failed." << std::endl;
        return 1;
    }
}
