//By AlSch092 @ github
#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdint.h>

namespace Hacks
{
	struct HACK 
	{
		UINT64 dwAddress;
		BYTE* szOriginalBytes;
		BYTE* szNewBytes;
		INT nSize;
	};

	VOID WriteHackBytes(HACK hHack, BOOL bEnable);
}

namespace Hooks
{
	VOID InstallHook(void* func2hook, void* payloadFunction);
	VOID WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo);
	VOID RemoveHook(UINT64 HookAddress, INT ByteLength, BYTE* OriginalBytes);
	VOID* AllocatePageNearAddress(void* targetAddr);
}