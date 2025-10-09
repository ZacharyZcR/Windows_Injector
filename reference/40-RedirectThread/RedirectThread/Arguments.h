#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <iostream> // For print_usage declaration

// --- Configuration Enums ---
enum class InjectionMode
{
    NONE,
    DLL_POINTER,
    SHELLCODE
};

enum class DeliveryMethod
{
    NONE, // Can be used for playing around with specific threads (should force a --tid arg)
    NTCREATETHREAD,
    CREATETHREAD,
    QUEUEUSERAPC,
    QUEUEUSERAPC2,
    NTQUEUEAPCTHREAD,
    NTQUEUEAPCTHREADEX,
    NTQUEUEAPCTHREADEX2
};

enum class ContextMethod
{
    ROP_GADGET,
    TWO_STEP
};

// --- Configuration Structure ---
struct InjectionConfig
{
    DWORD targetPid = 0;
    InjectionMode mode = InjectionMode::NONE;
    DeliveryMethod method = DeliveryMethod::CREATETHREAD;
    ContextMethod contextMethod = ContextMethod::ROP_GADGET;
    bool enterDebug = false;

    // Payload specific
    // std::string dllBasename;
    std::string shellcodeFilePath;
    std::vector<unsigned char> shellcodeBytes; // Keep here as it's part of config, though loaded elsewhere

    // Optional / Method specific
    DWORD targetTid = 0;
    SIZE_T allocSize = 4096;
    DWORD allocPerm = PAGE_EXECUTE_READWRITE;
    DWORD allocAddress = 0x60000;
    bool useSuspend = false;
    bool verbose = false;
};

// --- Function Declarations ---

// Parses command line arguments and populates the InjectionConfig struct.
// Returns true on success, false on failure (e.g., invalid arguments).
bool ParseArguments(int argc, char *argv[], InjectionConfig &config);

// Prints the command line usage instructions.
void print_usage(const char *progName);

// Prints the effective configuration settings derived from arguments.
void PrintConfiguration(const InjectionConfig &config);
