#include "threads_util.h"

#include <tlhelp32.h>
#include "ntddk.h"

#ifdef _DEBUG
#include <iostream>
#endif

//---

struct AutoBuffer
{
	AutoBuffer() : buf(nullptr), max_size(0), buf_size(0) { }

	~AutoBuffer() {
		if (buf) {
			::free(buf);
			buf = nullptr;
		}
		max_size = 0;
		buf_size = 0;
	}

	BYTE* alloc(size_t _buf_size)
	{
		if (_buf_size > max_size) {
			BYTE* allocated = (BYTE*)::realloc((void*)buf, _buf_size);
			if (!allocated) {
				return nullptr;
			}
			buf = allocated;
			max_size = _buf_size;
		}
		buf_size = _buf_size;
		::memset(buf, 0, max_size);
		return buf;
	}

	BYTE* buf;
	size_t max_size;
	size_t buf_size;
};

//---

bool query_thread_details(IN DWORD tid, OUT threads_util::thread_info& info)
{
	static auto mod = GetModuleHandleA("ntdll.dll");
	if (!mod) return false;

	static auto pNtQueryInformationThread = reinterpret_cast<decltype(&NtQueryInformationThread)>(GetProcAddress(mod, "NtQueryInformationThread"));
	if (!pNtQueryInformationThread)  return false;

	DWORD thAccess = THREAD_QUERY_INFORMATION;
	HANDLE hThread = OpenThread(thAccess, 0, tid);
	if (!hThread)  return false;

	bool isOk = false;
	ULONG returnedLen = 0;
	LPVOID startAddr = 0;
	NTSTATUS status = 0;
	status = pNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(LPVOID), &returnedLen);
	if (status == 0 && returnedLen == sizeof(startAddr)) {
		info.start_addr = (ULONGLONG)startAddr;
		isOk = true;
	}
	CloseHandle(hThread);
	return isOk;
}

bool threads_util::query_threads_details(IN OUT std::map<DWORD, threads_util::thread_info>& threads_info)
{
	for (auto itr = threads_info.begin(); itr != threads_info.end(); ++itr) {
		threads_util::thread_info& info = itr->second;
		if (!query_thread_details(info.tid, info)) return false;
	}
	return true;
}

bool threads_util::fetch_threads_info(IN DWORD pid, OUT std::map<DWORD, thread_info>& threads_info)
{
	static auto mod = GetModuleHandleA("ntdll.dll");
	if (!mod) return false;

	static auto pNtQuerySystemInformation = reinterpret_cast<decltype(&NtQuerySystemInformation)>(GetProcAddress(mod, "NtQuerySystemInformation"));
	if (!pNtQuerySystemInformation)  return false;

	AutoBuffer bBuf;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	while (status != STATUS_SUCCESS) {
		ULONG ret_len = 0;
		status = pNtQuerySystemInformation(SystemProcessInformation, bBuf.buf, (ULONG)bBuf.buf_size, &ret_len);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			if (!bBuf.alloc(ret_len)) {
				return false;
			}
			continue; // try again
		}
		break; //other error, or success
	};

	if (status != STATUS_SUCCESS) {
		return false;
	}

	bool found = false;
	SYSTEM_PROCESS_INFORMATION* info = (SYSTEM_PROCESS_INFORMATION*)bBuf.buf;
	while (info) {
		if (info->UniqueProcessId == pid) {
			found = true;
			break;
		}
		if (!info->NextEntryOffset) {
			break;
		}
		size_t record_size = info->NextEntryOffset;
		if (record_size < sizeof(SYSTEM_PROCESS_INFORMATION)) {
			// Record size smaller than expected, probably it is an old system that doesn not support the new version of this API
#ifdef _DEBUG
			std::cout << "The new version of SYSTEM_PROCESS_INFORMATION is not supported!\n";
#endif
			break;
		}
		info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)info + info->NextEntryOffset);
		if (!info) {
			break;
		}
	}

	if (!found) {
		return false;
	}

	const size_t thread_count = info->NumberOfThreads;
	for (size_t i = 0; i < thread_count; i++) {
		
		const DWORD tid = (DWORD)((ULONGLONG)info->Threads[i].ClientId.UniqueThread);
		auto itr = threads_info.find(tid);
		if (itr == threads_info.end()) {
			threads_info[tid] = thread_info(tid);
		}
		thread_info &threadi = threads_info[tid];
		threadi.is_extended = true;
		threadi.ext.sys_start_addr = (ULONG_PTR)info->Threads[i].StartAddress;
		threadi.ext.state = info->Threads[i].ThreadState;
		threadi.ext.wait_reason = info->Threads[i].WaitReason;
		threadi.ext.wait_time  = info->Threads[i].WaitTime;
	}
	return true;
}
