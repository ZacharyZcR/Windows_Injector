//By AlSch092 @ github
#include "Memory.hpp"

VOID Hacks::WriteHackBytes(HACK hHack, BOOL bEnable) {
	if (bEnable) {
		DWORD dwOldProt;
		VirtualProtect((void*)hHack.dwAddress, hHack.nSize, PAGE_EXECUTE_READWRITE, &dwOldProt);
		memcpy((void*)hHack.dwAddress, (void*)hHack.szNewBytes, hHack.nSize);
	}
	else {
		memcpy((void*)hHack.dwAddress, (void*)hHack.szOriginalBytes, hHack.nSize);
	}
}

void* Hooks::AllocatePageNearAddress(void* targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

void Hooks::WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	uint8_t absJumpInstructions[] =
	{
		0x41, 0x52, //push r10
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r10, addr
		0x41, 0xFF, 0xE2 //jmp r10
	};

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[4], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
}

void Hooks::InstallHook(void* func2hook, void* payloadFunction) //we can avoid using .asm file if we use this function!
{
	void* relayFuncMemory = AllocatePageNearAddress(func2hook);
	Hooks::WriteAbsoluteJump64(relayFuncMemory, payloadFunction); //write relay func instructions

	//now that the relay function is built, we need to install the E9 jump into the target func,
	//this will jump to the relay function
	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the relay function and the instruction immediately AFTER the jmp instruction
	const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)func2hook + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
}

VOID Hooks::RemoveHook(UINT64 HookAddress, INT ByteLength, BYTE* OriginalBytes)
{
	DWORD dwOldProt;
	VirtualProtect((LPVOID)HookAddress, ByteLength, PAGE_EXECUTE_READWRITE, &dwOldProt);
	memcpy((void*)HookAddress, (void*)OriginalBytes, ByteLength);
	VirtualProtect((LPVOID)HookAddress, ByteLength, dwOldProt, &dwOldProt);
}
