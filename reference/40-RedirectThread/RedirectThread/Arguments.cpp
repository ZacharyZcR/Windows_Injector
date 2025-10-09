#include "Arguments.h"
#include <iostream>
#include <string>
#include <stdexcept> // For std::exception in ParseArguments
#include <iomanip>   // For std::hex/std::dec in PrintConfiguration

// Implementation of ParseArguments (moved from main.cpp)
bool ParseArguments(int argc, char *argv[], InjectionConfig &config)
{
    bool pidProvided = false;
    bool modeProvided = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--pid")
        {
            if (++i < argc)
            {
                try
                {
                    config.targetPid = std::stoul(argv[i]);
                    pidProvided = true;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "[!] Invalid or out-of-range PID: " << argv[i] << " (" << e.what() << ")" << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --pid" << std::endl;
                return false;
            }
        }
        else if (arg == "--inject-dll")
        {
            if (modeProvided)
            {
                std::cerr << "[!] Cannot specify more than one injection mode." << std::endl;
                return false;
            }
            config.mode = InjectionMode::DLL_POINTER;
            modeProvided = true;
        }
        else if (arg == "--inject-shellcode")
        {
            if (modeProvided)
            {
                std::cerr << "[!] Cannot specify more than one injection mode." << std::endl;
                return false;
            }
            if (++i < argc)
            {
                config.mode = InjectionMode::SHELLCODE;
                config.shellcodeFilePath = argv[i];
                modeProvided = true;
            }
            else
            {
                std::cerr << "[!] Missing value for --inject-shellcode" << std::endl;
                return false;
            }
        }
        else if (arg == "--inject-shellcode-bytes")
        {
            if (modeProvided)
            {
                std::cerr << "[!] Cannot specify more than one injection mode." << std::endl;
                return false;
            }
            if (++i < argc)
            {
                config.mode = InjectionMode::SHELLCODE;
                // Parse hex string into bytes
                config.shellcodeBytes.clear();
                std::string hexstr = argv[i];
                size_t len = hexstr.length();
                if (len % 2 != 0)
                {
                    std::cerr << "[!] Shellcode bytes string must have even length (2 hex chars per byte)." << std::endl;
                    return false;
                }
                for (size_t j = 0; j < len; j += 2)
                {
                    std::string byteString = hexstr.substr(j, 2);
                    try
                    {
                        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
                        config.shellcodeBytes.push_back(byte);
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "[!] Invalid hex byte in --inject-shellcode-bytes: " << byteString << " (" << e.what() << ")" << std::endl;
                        return false;
                    }
                }
                modeProvided = true;
            }
            else
            {
                std::cerr << "[!] Missing value for --inject-shellcode-bytes" << std::endl;
                return false;
            }
        }
        else if (arg == "--method")
        {
            if (++i < argc)
            {
                std::string method = argv[i];
                if (method == "CreateRemoteThread")
                    config.method = DeliveryMethod::CREATETHREAD;
                else if (method == "NtCreateThread")
                    config.method = DeliveryMethod::NTCREATETHREAD;
                else if (method == "QueueUserAPC")
                    config.method = DeliveryMethod::QUEUEUSERAPC;
                else if (method == "QueueUserAPC2")
                    config.method = DeliveryMethod::QUEUEUSERAPC2;
                else if (method == "NtQueueApcThread")
                    config.method = DeliveryMethod::NTQUEUEAPCTHREAD;
                else if (method == "NtQueueApcThreadEx")
                    config.method = DeliveryMethod::NTQUEUEAPCTHREADEX;
                else if (method == "NtQueueApcThreadEx2")
                    config.method = DeliveryMethod::NTQUEUEAPCTHREADEX2;
                else
                {
                    std::cerr << "[!] Unknown delivery method: " << method << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --method" << std::endl;
                return false;
            }
        }
        else if (arg == "--context-method")
        {
            if (++i < argc)
            {
                std::string method = argv[i];
                if (method == "rop-gadget")
                    config.contextMethod = ContextMethod::ROP_GADGET;
                else if (method == "two-step")
                    config.contextMethod = ContextMethod::TWO_STEP;
                else
                {
                    std::cerr << "[!] Unknown context method: " << method << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --context-method" << std::endl;
                return false;
            }
        }
        else if (arg == "--tid")
        {
            if (++i < argc)
            {
                try
                {
                    config.targetTid = std::stoul(argv[i]);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "[!] Invalid or out-of-range TID: " << argv[i] << " (" << e.what() << ")" << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --tid" << std::endl;
                return false;
            }
        }
        else if (arg == "--alloc-size")
        {
            if (++i < argc)
            {
                try
                {
                    config.allocSize = std::stoull(argv[i]);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "[!] Invalid or out-of-range value for --alloc-size: " << argv[i] << " (" << e.what() << ")" << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --alloc-size" << std::endl;
                return false;
            }
        }
        else if (arg == "--alloc-perm")
        {
            if (++i < argc)
            {
                try
                {
                    config.allocPerm = std::stoul(argv[i], nullptr, 16);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "[!] Invalid or out-of-range hex value for --alloc-perm: " << argv[i] << " (" << e.what() << ")" << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --alloc-perm" << std::endl;
                return false;
            }
        }
        else if (arg == "--alloc-address")
        {
            if (++i < argc)
            {
                try
                {
                    config.allocAddress = std::stoul(argv[i], nullptr, 16);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "[!] Invalid or out-of-range hex value for --alloc-address: " << argv[i] << " (" << e.what() << ")" << std::endl;
                    return false;
                }
            }
            else
            {
                std::cerr << "[!] Missing value for --alloc-address" << std::endl;
                return false;
            }
        }
        else if (arg == "--use-suspend")
        {
            config.useSuspend = true;
        }
        else if (arg == "--verbose")
        {
            config.verbose = true;
        }
        else if (arg == "--enter-debug")
        {
            config.enterDebug = true;
        }
        else
        {
            std::cerr << "[!] Unknown argument: " << arg << std::endl;
            return false;
        }
    }

    if (!pidProvided)
    {
        std::cerr << "[!] Error: Target PID must be provided using --pid <pid>." << std::endl;
        return false;
    }

    if (!modeProvided)
    {
        std::cerr << "[!] Error: Injection mode must be specified using --inject-dll or --inject-shellcode." << std::endl;
        return false;
    }

    // Basic validation for APC methods requiring TID
    bool isApcMethod = (config.method == DeliveryMethod::QUEUEUSERAPC ||
                        config.method == DeliveryMethod::QUEUEUSERAPC2 ||
                        config.method == DeliveryMethod::NTQUEUEAPCTHREAD ||
                        config.method == DeliveryMethod::NTQUEUEAPCTHREADEX ||
                        config.method == DeliveryMethod::NTQUEUEAPCTHREADEX2);
    if (isApcMethod && config.targetTid == 0)
    {
        std::cerr << "[!] Error: Target TID (--tid) must be provided for APC-based delivery methods." << std::endl;
        return false;
    }

    return true;
}

// Implementation of print_usage (moved from Utils.cpp)
void print_usage(const char *progName)
{

    // Print banner
    std::cout << "\n\n      RedirectThread - Context Injection Tool\n\n";
    std::cout << "      Auhtors: Friends & Security (https://blog.fndsec.net)\n\n";

    std::cout << "Usage: " << progName << " [options]\n"

              << "\nRequired Options:\n"
              << "  --pid <pid>                 Target process ID to inject into\n"
              << "  --inject-dll                Perform DLL injection (hardcoded to \"0.dll\")\n"
              << "  --inject-shellcode <file>   Perform shellcode injection from file\n"
              << "  --inject-shellcode-bytes <hex>  Perform shellcode injection from hex string (e.g. 9090c3)\n"

              << "\nDelivery Method Options:\n"
              << "  --method <method>           Specify code execution method\n"
              << "     CreateRemoteThread       Default, creates a remote thread\n"
              << "     NtCreateThread           Uses NtCreateThread (less traceable)\n"
              << "     QueueUserAPC             Uses QueueUserAPC (requires --tid)\n"
              << "     QueueUserAPC2            Uses QueueUserAPC2 (requires --tid)\n"
              << "     NtQueueApcThread         Uses NtQueueApcThread (requires --tid)\n"
              << "     NtQueueApcThreadEx       Uses NtQueueApcThreadEx (requires --tid)\n"
              << "     NtQueueApcThreadEx2      Uses NtQueueApcThreadEx2 (requires --tid)\n"

              << "\nContext Method Options:\n"
              << "  --context-method <method>   Specify context manipulation method\n"
              << "     rop-gadget               Default, uses ROP gadget technique\n"
              << "     two-step                 Uses a two-step thread hijacking approach\n"

              << "\nAdditional Options:\n"
              << "  --tid <tid>                 Target thread ID (required for APC methods)\n"
              << "  --alloc-size <size>         Memory allocation size in bytes (default: 4096)\n"
              << "  --alloc-perm <hex>          Memory protection flags in hex (default: 0x40)\n"
              << "  --alloc-address <hex>       Specify base address for allocation (hex, optional)\n"
              << "  --use-suspend               Use thread suspension for increased reliability\n"
              << "  --verbose                   Enable verbose output\n"
              << "  --enter-debug               Pause execution at key points for debugger attachment\n"

              << "\nExample:\n"
              << "  " << progName << " --pid 1234 --inject-dll\n"
              << "  " << progName << " --pid 1234 --inject-shellcode payload.bin --verbose\n"
              << "  " << progName << " --pid 1234 --inject-shellcode payload.bin --method NtCreateThread\n"
              << "  " << progName << " --pid 1234 --inject-shellcode-bytes 9090c3 --method QueueUserAPC --tid 5678\n"
              << "  " << progName << " --pid 1234 --inject-shellcode-bytes $bytes --context-method two-step --method NtQueueApcThreadEx2 --tid 5678\n"

              << std::endl;
}

// Implementation of PrintConfiguration (based on logic from main.cpp)
void PrintConfiguration(const InjectionConfig &config)
{
    // Print banner
    std::cout << "\n\n      RedirectThread - Context Injection Tool\n\n";
    std::cout << "      Auhtors: Friends & Security (https://blog.fndsec.net)\n\n";

    std::cout << "[*] Target PID: " << config.targetPid << "\n";
    std::cout << "[*] Injection Mode: ";
    switch (config.mode)
    {
    case InjectionMode::DLL_POINTER:
        std::cout << "DLL Pointer (hardcoded \"0.dll\")\n";
        break;
    case InjectionMode::SHELLCODE:
        if (!config.shellcodeFilePath.empty())
            std::cout << "Shellcode (" << config.shellcodeFilePath << ")\n";
        else if (!config.shellcodeBytes.empty())
            std::cout << "Shellcode (provided as hex bytes, " << config.shellcodeBytes.size() << " bytes)\n";
        else
            std::cout << "Shellcode (no source specified)\n";
        break;

    default:
        std::cout << "Unknown\n";
        break;
    }

    std::cout << "[*] Delivery Method: ";
    switch (config.method)
    {
    case DeliveryMethod::CREATETHREAD:
        std::cout << "CreateRemoteThread\n";
        break;
    case DeliveryMethod::NTCREATETHREAD:
        std::cout << "NtCreateThread\n";
        break;
    case DeliveryMethod::QUEUEUSERAPC:
        std::cout << "QueueUserAPC\n";
        break;
    case DeliveryMethod::QUEUEUSERAPC2:
        std::cout << "QueueUserAPC2\n";
        break;
    case DeliveryMethod::NTQUEUEAPCTHREAD:
        std::cout << "NtQueueApcThread\n";
        break;
    case DeliveryMethod::NTQUEUEAPCTHREADEX:
        std::cout << "NtQueueApcThreadEx\n";
        break;
    case DeliveryMethod::NTQUEUEAPCTHREADEX2:
        std::cout << "NtQueueApcThreadEx2\n";
        break;
    default:
        std::cout << "Unknown\n";
        break; // Should not happen if ParseArguments is correct
    }

    if (config.mode != InjectionMode::DLL_POINTER)
    {
        std::cout << "[*] Context Method: ";
        switch (config.contextMethod)
        {
        case ContextMethod::ROP_GADGET:
            std::cout << "ROP Gadget\n";
            break;
        case ContextMethod::TWO_STEP:
            std::cout << "Two-Step\n";
            break;
        default:
            std::cout << "Unknown\n";
            break;
        }
    }

    bool isApcMethod = (config.method == DeliveryMethod::QUEUEUSERAPC ||
                        config.method == DeliveryMethod::QUEUEUSERAPC2 ||
                        config.method == DeliveryMethod::NTQUEUEAPCTHREAD ||
                        config.method == DeliveryMethod::NTQUEUEAPCTHREADEX ||
                        config.method == DeliveryMethod::NTQUEUEAPCTHREADEX2);

    if (isApcMethod && config.targetTid != 0)
    {
        std::cout << "[*] Target TID: " << config.targetTid << "\n";
    }
    else if (config.targetTid != 0)
    {
        std::cout << "[*] Target TID (specified but not required for method): " << config.targetTid << "\n";
    }

    if (config.mode != InjectionMode::DLL_POINTER)
    {
        std::cout << "[*] Allocation Size: " << config.allocSize << " bytes (0x" << std::hex << config.allocSize << std::dec << ")\n";
        std::cout << "[*] Allocation Permissions: 0x" << std::hex << config.allocPerm << std::dec << "\n";
        std::cout << "[*] Allocation Address: 0x" << std::hex << config.allocAddress << std::dec << "\n";
        std::cout << "[*] Use Suspend/Resume: " << (config.useSuspend ? "Yes" : "No") << "\n";
    }
    std::cout << "[*] Verbose Output: " << (config.verbose ? "Yes" : "No") << "\n";
    std::cout << "[*] Enter Debug: " << (config.enterDebug ? "Yes" : "No") << "\n"
              << std::endl;
}
