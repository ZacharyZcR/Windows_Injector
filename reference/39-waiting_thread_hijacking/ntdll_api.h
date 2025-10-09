#pragma once

#include <Windows.h>

namespace ntapi
{
	LPVOID
		WINAPI
		VirtualAllocEx(
			_In_ HANDLE hProcess,
			_In_opt_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flAllocationType,
			_In_ DWORD flProtect
		)
	{
		NTSTATUS
			NTAPI
			NtAllocateVirtualMemory(
				IN      HANDLE    ProcessHandle,
				IN OUT PVOID * BaseAddress,
				IN      ULONG_PTR ZeroBits,
				IN OUT PSIZE_T   RegionSize,
				IN      ULONG     AllocationType,
				IN      ULONG     Protect
			);

		auto pNtAllocateVirtualMemory = reinterpret_cast<decltype(&NtAllocateVirtualMemory)>(GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory"));
		if (!pNtAllocateVirtualMemory)
		{
			return NULL;
		}
		PVOID requestedAddress = lpAddress;
		SIZE_T requestedSize = dwSize;
		if (pNtAllocateVirtualMemory(hProcess, &requestedAddress, 0, &requestedSize, flAllocationType, flProtect) != 0) {
			return NULL;
		}
		return requestedAddress;
	}

	BOOL
		WINAPI
		WriteProcessMemory(
			_In_ HANDLE hProcess,
			_In_ LPVOID lpBaseAddress,
			_In_reads_bytes_(nSize) LPVOID lpBuffer,
			_In_ SIZE_T nSize,
			_Out_opt_ SIZE_T* lpNumberOfBytesWritten
		)
	{
		NTSTATUS
			NTAPI
			NtWriteVirtualMemory(
				IN HANDLE               ProcessHandle,
				IN PVOID                BaseAddress,
				IN LPVOID               Buffer,
				IN SIZE_T                NumberOfBytesToWrite,
				OUT PSIZE_T              NumberOfBytesWritten OPTIONAL
			);

		auto pNtWriteVirtualMemory = reinterpret_cast<decltype(&NtWriteVirtualMemory)>(GetProcAddress(GetModuleHandleA("ntdll"), "NtWriteVirtualMemory"));
		if (!pNtWriteVirtualMemory)
		{
			return FALSE;
		}
		if (pNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) != 0) {
			return FALSE;
		}
		return TRUE;
	}

	BOOL
		WINAPI
		VirtualProtectEx(
			_In_ HANDLE hProcess,
			_In_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flNewProtect,
			_Out_ PDWORD lpflOldProtect
		)
	{
		NTSTATUS
			NTAPI
			NtProtectVirtualMemory(
				IN HANDLE               ProcessHandle,
				IN OUT PVOID * BaseAddress,
				IN OUT PSIZE_T           NumberOfBytesToProtect,
				IN ULONG                NewAccessProtection,
				OUT PULONG              OldAccessProtection
			);

		auto pNtProtectVirtualMemory = reinterpret_cast<decltype(&NtProtectVirtualMemory)>(GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory"));
		if (!pNtProtectVirtualMemory)
		{
			return FALSE;
		}
		PVOID requestedAddress = lpAddress;
		SIZE_T requestedSize = dwSize;
		if (pNtProtectVirtualMemory(hProcess, &requestedAddress, &requestedSize, flNewProtect, lpflOldProtect) != 0) {
			return FALSE;
		}
		return TRUE;
	}

};
