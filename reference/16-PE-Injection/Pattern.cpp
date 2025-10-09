//By AlSch092 @ github
#include "Pattern.hpp"

UINT64 GetBaseAddress(const wchar_t* name)
{
	DWORD targetProcessId = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) 
	{
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &processEntry)) 
		{
			do {
				if (wcscmp(processEntry.szExeFile, name) == 0) 
				{
					targetProcessId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}

		CloseHandle(snapshot);
	}

	if (targetProcessId == 0) 
	{
		printf("Target process not found.\n");
		return 1;
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetProcessId);
	if (hProcess == NULL) 
	{
		printf("Failed to open target process.\n");
		return 1;
	}

	HMODULE hMods[1024];
	DWORD cbNeeded;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		if (cbNeeded > 0 && cbNeeded <= sizeof(hMods)) 
		{
			LPVOID baseAddress = hMods[0];
			printf("Base address of the main module: 0x%p\n", baseAddress);
			return (UINT64)baseAddress;
		}
	}

	CloseHandle(hProcess);
	return 0;
}

DWORD GetProcessIdByName(const wchar_t* processName) 
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) 
	{
		return 0;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	DWORD processId = 0;

	if (Process32First(snapshot, &processEntry)) 
	{
		do {
			if (wcscmp(processEntry.szExeFile, processName) == 0) 
			{
				processId = processEntry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &processEntry));
	}

	CloseHandle(snapshot);
	return processId;
}

unsigned int GetRemoteImageSize(const wchar_t* procName) //todo: finish this routine (example still works without it)
{
	return 0;
}

UINT64 FindRemotePattern(const unsigned char* pattern, int length, const wchar_t* procName)
{
	DWORD targetProcessId = GetProcessIdByName(procName);
	if (targetProcessId == 0) 
	{
		printf("Target process not found.\n");
		return 1;
	}

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, targetProcessId);
	if (hProcess == NULL) 
	{
		printf("Failed to open target process.\n");
		return 1;
	}

	SIZE_T bytesRead;
	unsigned char buffer[4096];
	UINT64 base = GetBaseAddress(procName);

	unsigned int processImageSize = GetRemoteImageSize(procName);
	processImageSize = 0x3000; //REMOVE THIS after finishing GetRemoteImageSize function -> the code size for this project is around 0x3000 bytes 

	for (UINT64 i = base; i < (base + processImageSize); i++) //TODO: change +0x3000 to being grabbed dynamically, need to get the image size remotely
	{
		if (!ReadProcessMemory(hProcess, (LPCVOID)i, buffer, sizeof(buffer), &bytesRead)) //very slow method, can be optimized bigly -> call once with imageSize, then remove it from loop, loop over a copy 
		{
			wprintf(L"Couldn't read remote memory@FindRemotePattern: %s, %s", pattern, procName);
			return 0;
		}

		for (size_t i = 0; i < bytesRead - length + 1; i++) 
		{
			if (memcmp(buffer + i, pattern, length) == 0)
			{
				//printf("Pattern found at address: 0x%p\n", (LPVOID)(buffer + i));
				return (UINT64)(buffer + i);
			}
		}
	}

	CloseHandle(hProcess);

	return 0;
}