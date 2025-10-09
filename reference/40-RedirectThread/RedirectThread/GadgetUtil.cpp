#define NOMINMAX
#include "GadgetUtil.h"
#include <algorithm> // For std::find
#include <iostream>  // For std::cerr
#include <iomanip>   // For std::setw, std::setfill
#include <limits>    // For std::numeric_limits
#include <cstddef>   // For size_t (just in case)
#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <limits>  // For std::numeric_limits
#include <Psapi.h> // For GetModuleInformation
#include <excpt.h> // For SEH (__try, __except)

// Global variable to hold ExitThread address
DWORD64 g_ExitThreadAddr = 0;

LPVOID FindCharInRemoteProcess(HANDLE processHandle, char targetChar)
{
    if (!processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return nullptr;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPVOID minAddress = sysInfo.lpMinimumApplicationAddress;
    LPVOID maxAddress = sysInfo.lpMaximumApplicationAddress;
    LPVOID currentAddress = minAddress;
    MEMORY_BASIC_INFORMATION mbi;

    while (currentAddress < maxAddress)
    {
        if (VirtualQueryEx(processHandle, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            bool isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ)) != 0;
            bool isCommitted = (mbi.State == MEM_COMMIT);
            bool isGuard = (mbi.Protect & PAGE_GUARD) != 0;

            if (isCommitted && isReadable && !isGuard && mbi.RegionSize > 0)
            {
                // Avoid excessively large allocations, chunk if necessary
                if (mbi.RegionSize > (1024 * 1024 * 100))
                { // 100MB limit
                    // Skip huge region or implement chunking
                }
                else
                {
                    std::vector<char> buffer(mbi.RegionSize);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
                    {
                        if (bytesRead > 0)
                        {
                            const char *bufferStart = buffer.data();
                            const char *bufferEnd = bufferStart + bytesRead;
                            const char *foundIt = std::find(bufferStart, bufferEnd, targetChar);

                            if (foundIt != bufferEnd)
                            {
                                SIZE_T offset = static_cast<SIZE_T>(foundIt - bufferStart);
                                LPVOID foundAddress = static_cast<LPBYTE>(mbi.BaseAddress) + offset;
                                return foundAddress;
                            }
                        }
                    }
                }
            }

            LPBYTE nextAddr = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
            if (nextAddr < static_cast<LPBYTE>(mbi.BaseAddress))
            {
                break;
            }
            currentAddress = nextAddr;
        }
        else
        {
            DWORD queryError = GetLastError();
            SetLastError(queryError);
            break;
        }
    }

    SetLastError(ERROR_NOT_FOUND);
    return nullptr;
}

int GetPushInstructionInfo(const BYTE *instructionBytes, SIZE_T bytesAvailable, int *outRegisterId)
{
    // Constants for registers and opcodes
    constexpr int REG_ID_INVALID = -1;
    constexpr int REG_ID_RAX = 0;
    constexpr int REG_ID_RBX = 1;
    constexpr int REG_ID_RBP = 2;
    constexpr int REG_ID_RSI = 3;
    constexpr int REG_ID_RDI = 4;
    constexpr int REG_ID_R10 = 10;
    constexpr int REG_ID_R11 = 11;
    constexpr int REG_ID_R12 = 12;
    constexpr int REG_ID_R13 = 13;
    constexpr int REG_ID_R14 = 14;
    constexpr int REG_ID_R15 = 15;

    constexpr BYTE REX_PREFIX = 0x41;
    constexpr BYTE PUSH_RAX_OPCODE = 0x50;
    constexpr BYTE PUSH_RBX_OPCODE = 0x53;
    constexpr BYTE PUSH_RBP_OPCODE = 0x55;
    constexpr BYTE PUSH_RSI_OPCODE = 0x56;
    constexpr BYTE PUSH_RDI_OPCODE = 0x57;
    constexpr BYTE PUSH_R10_OPCODE = 0x52; // When prefixed with REX_PREFIX
    constexpr BYTE PUSH_R11_OPCODE = 0x53; // When prefixed with REX_PREFIX
    constexpr BYTE PUSH_R12_OPCODE = 0x54; // When prefixed with REX_PREFIX
    constexpr BYTE PUSH_R13_OPCODE = 0x55; // When prefixed with REX_PREFIX
    constexpr BYTE PUSH_R14_OPCODE = 0x56; // When prefixed with REX_PREFIX
    constexpr BYTE PUSH_R15_OPCODE = 0x57; // When prefixed with REX_PREFIX

    *outRegisterId = REG_ID_INVALID;
    if (bytesAvailable < 1)
    {
        return 0;
    }

    BYTE op1 = instructionBytes[0];

    switch (op1)
    {
    case PUSH_RAX_OPCODE:
        *outRegisterId = REG_ID_RAX;
        return 1;
    case PUSH_RBX_OPCODE:
        *outRegisterId = REG_ID_RBX;
        return 1;
    case PUSH_RBP_OPCODE:
        *outRegisterId = REG_ID_RBP;
        return 1;
    case PUSH_RSI_OPCODE:
        *outRegisterId = REG_ID_RSI;
        return 1;
    case PUSH_RDI_OPCODE:
        *outRegisterId = REG_ID_RDI;
        return 1;
    }

    if (op1 == REX_PREFIX)
    {
        if (bytesAvailable < 2)
        {
            return 0;
        }
        BYTE op2 = instructionBytes[1];
        switch (op2)
        {
        case PUSH_R10_OPCODE:
            *outRegisterId = REG_ID_R10;
            return 2;
        case PUSH_R11_OPCODE:
            *outRegisterId = REG_ID_R11;
            return 2;
        case PUSH_R12_OPCODE:
            *outRegisterId = REG_ID_R12;
            return 2;
        case PUSH_R13_OPCODE:
            *outRegisterId = REG_ID_R13;
            return 2;
        case PUSH_R14_OPCODE:
            *outRegisterId = REG_ID_R14;
            return 2;
        case PUSH_R15_OPCODE:
            *outRegisterId = REG_ID_R15;
            return 2;
        }
    }
    return 0;
}

GadgetInfo FindUniquePushPushRetGadget(HANDLE processHandle)
{
    constexpr BYTE RET_OPCODE = 0xC3;
    constexpr int REG_ID_INVALID = -1;

    GadgetInfo foundGadget;
    if (!processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return foundGadget;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPVOID searchAddress = sysInfo.lpMinimumApplicationAddress;
    LPVOID maxSearchAddress = sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    constexpr SIZE_T READ_CHUNK_SIZE = 65536;
    std::vector<BYTE> buffer(READ_CHUNK_SIZE);

    while (searchAddress < maxSearchAddress &&
           VirtualQueryEx(processHandle, searchAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        ULONG_PTR regionEnd = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= reinterpret_cast<ULONG_PTR>(mbi.BaseAddress))
        {
            break;
        }
        LPVOID nextSearchAddress = reinterpret_cast<LPVOID>(regionEnd);

        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool isCommitted = (mbi.State == MEM_COMMIT);
        bool isGuarded = (mbi.Protect & PAGE_GUARD) != 0;

        if (isCommitted && isExecutable && !isGuarded && mbi.RegionSize > 0)
        {
            LPBYTE currentRegionPtr = static_cast<LPBYTE>(mbi.BaseAddress);
            LPBYTE endRegionPtr = currentRegionPtr + mbi.RegionSize;

            while (currentRegionPtr < endRegionPtr)
            {
                SIZE_T bytesToRead = std::min(READ_CHUNK_SIZE, static_cast<SIZE_T>(endRegionPtr - currentRegionPtr));
                SIZE_T bytesRead = 0;

                if (buffer.size() < bytesToRead)
                {
                    buffer.resize(bytesToRead);
                }

                if (!ReadProcessMemory(processHandle, currentRegionPtr, buffer.data(), bytesToRead, &bytesRead) || bytesRead == 0)
                {
                    goto next_region;
                }

                for (SIZE_T offset = 0; offset <= bytesRead - 3; ++offset)
                { // Min size: PUSH r(1) + PUSH r(1) + RET(1)
                    int regId1 = REG_ID_INVALID;
                    int push1Size = GetPushInstructionInfo(buffer.data() + offset, bytesRead - offset, &regId1);
                    if (push1Size == 0 || regId1 == REG_ID_INVALID)
                        continue;

                    SIZE_T push2Offset = offset + push1Size;
                    if (push2Offset > bytesRead - 2)
                        continue; // Need space for PUSH(min 1) + RET(1)

                    int regId2 = REG_ID_INVALID;
                    int push2Size = GetPushInstructionInfo(buffer.data() + push2Offset, bytesRead - push2Offset, &regId2);
                    if (push2Size == 0 || regId2 == REG_ID_INVALID)
                        continue;
                    if (regId1 == regId2)
                        continue; // Need unique registers

                    SIZE_T retOffset = push2Offset + push2Size;
                    if (retOffset >= bytesRead)
                        continue; // Need space for RET

                    if (buffer[retOffset] == RET_OPCODE)
                    {
                        foundGadget.address = static_cast<LPBYTE>(currentRegionPtr) + offset;
                        foundGadget.regId1 = regId1;
                        foundGadget.regId2 = regId2;
                        return foundGadget;
                    }
                }
                currentRegionPtr += bytesRead;
            }
        }
    next_region:
        searchAddress = nextSearchAddress;
    }

    SetLastError(ERROR_NOT_FOUND);
    return foundGadget;
}

bool SetRegisterContextValue(CONTEXT &context, int regId, DWORD64 value)
{
    constexpr int REG_ID_RAX = 0;
    constexpr int REG_ID_RBX = 1;
    constexpr int REG_ID_RBP = 2;
    constexpr int REG_ID_RSI = 3;
    constexpr int REG_ID_RDI = 4;
    constexpr int REG_ID_R10 = 10;
    constexpr int REG_ID_R11 = 11;
    constexpr int REG_ID_R12 = 12;
    constexpr int REG_ID_R13 = 13;
    constexpr int REG_ID_R14 = 14;
    constexpr int REG_ID_R15 = 15;

    switch (regId)
    {
    case REG_ID_RAX:
        context.Rax = value;
        return true;
    case REG_ID_RBX:
        context.Rbx = value;
        return true;
    case REG_ID_RBP:
        context.Rbp = value;
        return true;
    case REG_ID_RSI:
        context.Rsi = value;
        return true;
    case REG_ID_RDI:
        context.Rdi = value;
        return true;
    case REG_ID_R10:
        context.R10 = value;
        return true;
    case REG_ID_R11:
        context.R11 = value;
        return true;
    case REG_ID_R12:
        context.R12 = value;
        return true;
    case REG_ID_R13:
        context.R13 = value;
        return true;
    case REG_ID_R14:
        context.R14 = value;
        return true;
    case REG_ID_R15:
        context.R15 = value;
        return true;
    default:
        return false;
    }
}



LPVOID FindLocalGadgetInRX(const char *moduleName, const std::vector<BYTE> &gadgetBytes, bool verbose = false)
{
    if (gadgetBytes.empty())
    {
        if (verbose)
            std::cerr << "[!] FindLocalGadgetInRX: Gadget byte vector is empty." << std::endl;
        return NULL;
    }

    HMODULE hModuleLocal = GetModuleHandleA(moduleName);
    if (!hModuleLocal)
    {
        std::cerr << "[!] FindLocalGadgetInRX: GetModuleHandleA failed for " << moduleName << ". Error: " << GetLastError() << std::endl;
        return NULL;
    }

    MODULEINFO modInfo = {0};
    if (!GetModuleInformation(GetCurrentProcess(), hModuleLocal, &modInfo, sizeof(modInfo)))
    {
        std::cerr << "[!] FindLocalGadgetInRX: GetModuleInformation failed for " << moduleName << ". Error: " << GetLastError() << std::endl;
        // Cannot reliably determine module bounds, fallback might be risky or fail.
        return NULL;
    }

    DWORD_PTR moduleBase = (DWORD_PTR)modInfo.lpBaseOfDll;
    DWORD_PTR moduleEnd = moduleBase + modInfo.SizeOfImage;
    const size_t gadgetSize = gadgetBytes.size();

    if (verbose)
    {
        std::cout << "  [Gadget Search] Searching for " << gadgetSize << " byte gadget in " << moduleName
                  << " (Base: 0x" << std::hex << moduleBase << ", End: 0x" << moduleEnd << std::dec << ")" << std::endl;
    }

    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR currentAddress = moduleBase; // Start at the known module base

    // Loop through memory regions within the module boundaries
    while (currentAddress < moduleEnd &&
           VirtualQuery((LPCVOID)currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        DWORD_PTR regionBase = (DWORD_PTR)mbi.BaseAddress;
        DWORD_PTR regionEnd = regionBase + mbi.RegionSize;

        // Ensure the queried region is at least partially within our target module range
        // And check if the region is committed memory
        if (mbi.State == MEM_COMMIT && regionBase < moduleEnd && regionEnd > moduleBase)
        {

            // Check for executable permissions
            bool isExecutable = (mbi.Protect & PAGE_EXECUTE) ||
                                (mbi.Protect & PAGE_EXECUTE_READ) ||
                                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                                (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

            // Check for readable permissions (needed for memcmp)
            // Note: PAGE_EXECUTE often implies read, but being explicit is safer.
            bool isReadable = (mbi.Protect & PAGE_READONLY) ||
                              (mbi.Protect & PAGE_READWRITE) ||
                              (mbi.Protect & PAGE_EXECUTE_READ) ||
                              (mbi.Protect & PAGE_EXECUTE_READWRITE);

            bool isGuarded = (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS);

            if (isExecutable && isReadable && !isGuarded)
            {
                // Calculate the valid scanning range within this region AND the module boundaries
                DWORD_PTR scanStart = std::max(regionBase, moduleBase);
                DWORD_PTR scanEnd = std::min(regionEnd, moduleEnd); // Don't scan past module end

                // Ensure there's enough space for the gadget in the valid scan range
                if (scanStart < scanEnd && (scanEnd - scanStart) >= gadgetSize)
                {
                    if (verbose)
                    {
                        std::cout << "    [Gadget Search] Scanning RX region: 0x" << std::hex << scanStart
                                  << " - 0x" << scanEnd << std::dec << std::endl;
                    }

                    for (DWORD_PTR p = scanStart; p <= scanEnd - gadgetSize; ++p)
                    {
                        bool found = false;
                        // Use Structured Exception Handling (SEH) for robustness
                        __try
                        {
                            if (memcmp((const void *)p, gadgetBytes.data(), gadgetSize) == 0)
                            {
                                found = true;
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                            // Access violation reading location p, skip ahead
                            if (verbose)
                                std::cerr << "    [Gadget Search] Access violation reading 0x" << std::hex << p << std::dec << ". Skipping." << std::endl;
                            // Advance p past the potentially problematic page boundary
                            p = (p & ~0xFFF) + 0x1000 - 1; // Align down, add page, subtract 1 for loop increment
                            if (p < scanStart)
                                p = scanEnd; // Prevent going backward or infinite loop on repeated AVs
                        }

                        if (found)
                        {
                            if (verbose)
                                std::cout << "    [Gadget Search] Found gadget at 0x" << std::hex << (LPVOID)p << std::dec << std::endl;
                            return (LPVOID)p;
                        }
                    }
                }
            }
        }

        // Advance to the next region
        // Important: Check for potential stalls if VirtualQuery reports the same region repeatedly
        if (regionEnd <= currentAddress)
        {
            if (verbose)
                std::cerr << "    [Gadget Search] Memory region end did not advance. Stopping search." << std::endl;
            break;
        }
        currentAddress = regionEnd;
    }

    // Gadget not found
    std::cerr << "[!] Gadget 0x";
    for (BYTE b : gadgetBytes)
    {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cerr << std::dec << " not found in readable/executable regions of " << moduleName << std::endl;
    return NULL;
}
