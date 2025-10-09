#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <vector>   // For FindUniquePushPushRetGadget if needed, and internal use
#include <string>   // For FindCharInRemoteProcess if needed
#include <iostream> // For error reporting if needed

// --- ROP Gadget Constants ---
constexpr int REG_ID_INVALID = -1;

// --- ROP Gadget Structures ---
struct GadgetInfo
{
    LPVOID address = nullptr;
    int regId1 = REG_ID_INVALID;
    int regId2 = REG_ID_INVALID;
};

// --- Global Variables ---
// Defined in GadgetUtil.cpp
extern DWORD64 g_ExitThreadAddr;

// --- ROP Gadget Function Declarations ---
LPVOID FindCharInRemoteProcess(HANDLE processHandle, char targetChar);
int GetPushInstructionInfo(const BYTE *instructionBytes, SIZE_T bytesAvailable, int *outRegisterId);
GadgetInfo FindUniquePushPushRetGadget(HANDLE processHandle);
bool SetRegisterContextValue(CONTEXT &context, int regId, DWORD64 value);
LPVOID FindLocalGadgetInRX(const char *moduleName, const std::vector<BYTE> &gadgetBytes, bool verbose);