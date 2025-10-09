/*
Process Injection: Copy current process into target process and begin execution

Topic: Malware/Evasion, Process Manipulation

Can likely be extended to a work as a DLL injector which doesn't rely on LoadLibrary being called (only writable memory is needed in a target process).
-> Change project type to .dll, make second project which loads this project as .dll and call InsertProcess in our dll on the target process.
-> possibly dllexport the InsertProcess function and call it from another project, the DLL will copy all its bytes to the target and then run its DLLMain (you must change main() offset to Dllmain()).

by AlSch092 @ Github, Aug. 6 2023, Updated Dec. 20 2023
*/
#define SUBSYSTEM_WINDOWS
#ifndef SUBSYSTEM_WINDOWS
#define SUBSYSTEM_CONSOLE
#endif

#include <queue>
#include "Pattern.hpp"
#include "Memory.hpp" //memory writing, hooking ,etc
#include "Util.hpp"

using namespace std;

#ifdef SUBSYSTEM_WINDOWS
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
#elif SUBSYSTEM_CONSOLE
int main(int argc, char** argv);  //console version, we're currently using winGUI method
#endif

//global variables, in an actual project these should be better managed in some class

bool g_Injected = false;

const wchar_t* process_target = L"CoolGame.exe";
const UINT64 HookOffset = 0x1234567;

HINSTANCE hInstance = NULL;
HWND hCheckbox_LogOutbound = NULL;

const int IDC_CHECKBOX = 0;

queue<LPBYTE>* SendPacketQueue = new queue<LPBYTE>();

//Function prototypes
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
bool ReflectCurrentModuleToRemoteProcess(DWORD processId);

//Meat and potato of concept
bool ReflectCurrentModuleToRemoteProcess(DWORD processId)
{
	if (g_Injected)
		return false;

	DWORD dwProt = 0;
	DWORD threadId = 0;
	DWORD dwOldProt = 0;

	HMODULE hModule = GetModuleHandle(NULL);

	LPVOID baseAddress = hModule;

	HANDLE hProcess = GetCurrentProcess(); //payload process
	HANDLE targetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	MODULEINFO moduleInfo;
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));
	SIZE_T imageSize = moduleInfo.SizeOfImage; 	//Get the image size

	if (targetProc == NULL)
	{
		printf("Failed to open target process with error %d\n", GetLastError());
		return false;
	}

	LPVOID newImageAddress = VirtualAllocEx(targetProc, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //Allocate memory for the new image in the target process

	if (newImageAddress != NULL)
	{
		BYTE* shadow_proc = new BYTE[imageSize]; //'shadow process' bytes

		g_Injected = true; //needs to go before the memcpy call, otherwise the shadow copy wont reflect this

		//Update the image base address!
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddress + pDosHeader->e_lfanew);

		if (!VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			printf("Failed to VirtualProtect on host process pNtHeaders with error %d\n", GetLastError());
			goto error;
		}

		pNtHeaders->OptionalHeader.ImageBase = (DWORD_PTR)newImageAddress; //non-offset address in image header needs to be updated

		//fix relocations
		PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)baseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		DWORD relocationEntriesCount = 0;
		PDWORD_PTR relocAddress = 0;
		PBASE_RELOCATION_ENTRY relocationRVA = NULL;

		DWORD_PTR deltaImageBase = (DWORD_PTR)newImageAddress - (DWORD_PTR)baseAddress;

		while (relocationTable->SizeOfBlock > 0)
		{
			relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

			for (short i = 0; i < relocationEntriesCount; i++)
			{
				if (relocationRVA[i].Offset)
				{
					relocAddress = (PDWORD_PTR)((DWORD_PTR)baseAddress + relocationTable->VirtualAddress + relocationRVA[i].Offset);

					DWORD dwOldProt = 0;
					if (!VirtualProtect((LPVOID)relocAddress, sizeof(UINT64), PAGE_EXECUTE_READWRITE, &dwOldProt))
					{
						printf("Failed to VirtualProtect on host process relocations with error %d\n", GetLastError());
						goto error;
					}

					*relocAddress += deltaImageBase;
				}
			}
			relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
		}

		memcpy(shadow_proc, baseAddress, imageSize);

		if (!VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), dwOldProt, &dwOldProt)) //change back to old page protections
		{
			printf("Failed to VirtualProtect on host process pNtHeaders with error %d\n", GetLastError());
			goto error;
		}

		SIZE_T nBytesWritten;
		if (!WriteProcessMemory(targetProc, newImageAddress, shadow_proc, imageSize, &nBytesWritten)) //write all sections of image to target process
		{
			printf("Failed to write memory of target process: %d with error %d\n", processId, GetLastError());
			goto error;
		}

		printf("Wrote %d bytes to target process\n", nBytesWritten);

		if (!VirtualProtectEx(targetProc, newImageAddress, imageSize, PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			printf("Failed to VirtualProtectEx on target process memory with error %d\n", GetLastError());
			goto error;
		}

		UINT64 mainFuncOffset = (UINT64)WinMain - (UINT64)moduleInfo.lpBaseOfDll; //Get offset of our main routine, we can use pattern scanning here also

		UINT64 rebased_main = (UINT64)(newImageAddress)+mainFuncOffset; //main is not the 'true start' of a program, but most things should be initialized by the target process and thus we can skip directly to calling main in a new thread.

		printf("rebased_main at %llX\n", rebased_main);

		HANDLE hThread = CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)rebased_main, NULL, 0, &threadId); //now we create a new thread to resume execution at the new image location or some custom spot

		if (hThread == NULL)
		{
			printf("Could not start thread at rebased_main in target process: %d\n", GetLastError());
			goto error;
		}
		else
			return true;

	error:
		g_Injected = false;
		delete[] shadow_proc;
		return false;
	}
	else
	{
		printf("Failed to allocate memory for the new image.\n");
		g_Injected = false;
		return false;
	}

	return true;
}

void InitializeGUI()
{
	WNDCLASSEX wcex = { sizeof(WNDCLASSEX), CS_HREDRAW | CS_VREDRAW, WndProc, 0, 0, 0, 0, LoadCursor(nullptr, IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), nullptr, L"MyWindowClass", LoadIcon(0, IDI_APPLICATION) };
	RegisterClassEx(&wcex);

	HWND hWnd = CreateWindow(L"MyWindowClass", L"Undetected Module", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 500, 400, nullptr, nullptr, 0, nullptr);

	if (!hWnd)
		exit(-1);

	if (!RegisterHotKey(hWnd, 1, MOD_CONTROL | MOD_SHIFT, 'A'))
	{
		MessageBox(nullptr, L"Failed to register hotkey!", L"Error", MB_OK | MB_ICONERROR); //warn but don't stop execution/return
	}

	ShowWindow(hWnd, SW_SHOW);
	UpdateWindow(hWnd);

	MSG msg;
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	UnregisterHotKey(hWnd, 1);
}

extern "C"  //allows our .asm file to view globals
{
	UINT64 HookReturnAddr = 0;
	UINT64 PacketLogCallbackAddr = 0;
	void AESEncrypt_CBC128();
}

void PacketLogCallback(LPBYTE out_packet, const char* encrypt_key) //Called by our .asm hook
{
	unsigned int packet_length = 0;
	memcpy((void*)&packet_length, (void*)&out_packet[0], 4);

	unsigned short opcode = 0;
	memcpy((void*)&opcode, (void*)&out_packet[5], 2); //payload starts after the 5th byte

	if (packet_length < 512) //can use WriteFile for simplest logging method
	{
		char* packet_format = PacketToString(&out_packet[5], packet_length - 5);  //payload starts after the 5th byte

		if (packet_format != NULL)
		{
			WriteHexString("./out.txt", packet_format);

			typedef void*(*_free)(void* ptr);
			_free  __free;
			UINT64 _addr = (UINT64)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "free");

			if (!_addr)
			{
				__free = (_free)_addr;
				__free(packet_format);
			}
		}
	}
}

void InitializeHooks()
{
	UINT64 module = (UINT64)GetModuleHandleW(process_target);

	if (module == NULL)
		return;

	HookReturnAddr = module + HookOffset + 5;
	PacketLogCallbackAddr = (UINT64)&PacketLogCallback;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (!g_Injected) //in the copied version in our target .exe, g_Injected will be TRUE which makes execution skip over this block
	{
		hInstance = hInst;

		if (ReflectCurrentModuleToRemoteProcess(GetTargetThreadIDFromProcName(process_target))) //make sure the architecture of target matches this project
		{
			printf("Successfully inserted process!\n");
			exit(0); //flow moves to here after image is copied to target. host process exits normally
		}
		else
		{
			printf("Failed to insert process!\n");
			exit(-1);
		}
	}

	//!! flow only reaches here from inside the target process, not the local process !!
	InitializeHooks();

	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)InitializeGUI, 0, 0, 0);
	//if you're calling functions in libraries which aren't loaded in the target process, the program will crash. you need to call LoadLibrary here, then build function pointers to whatever function using GetProcAddress.
	//essentially this is shellcode which is inserted to the target as there is no official module loaded through this technique.
	return 0;
}

//Window procedure for the main window
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	hInstance = (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE);

	switch (message)
	{
	case WM_CREATE:
	{
		hCheckbox_LogOutbound = CreateWindow(L"BUTTON", L"Perform Some Action", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 10, 10, 150, 30, hWnd, nullptr, 0, nullptr);
	}break;

	case WM_HOTKEY:

		if (wParam == 1)
		{
			MessageBox(hWnd, L"Hotkey pressed (Ctrl+Shift+A)!", L"Hotkey Pressed", MB_OK | MB_ICONINFORMATION); //simple hotkey example
		}
		break;

	case WM_COMMAND:

		if (LOWORD(wParam) == IDC_CHECKBOX)  //with this technique r8d is 0 with checkbox ticks
		{
			UINT64 module = (UINT64)GetModuleHandleW(process_target);

			if (module == NULL)
				break;

			if (SendMessage(hCheckbox_LogOutbound, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{
				Hooks::InstallHook((void*)(module + HookOffset), AESEncrypt_CBC128);
			}
			else if (SendMessage(hCheckbox_LogOutbound, BM_GETCHECK, 0, 0) == BST_UNCHECKED)
			{
				Hooks::RemoveHook((UINT64)(module + HookOffset), 5, (BYTE*)"\x48\x89\x5c\x24\x18");
			}
		}
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}

	return 0;
}
