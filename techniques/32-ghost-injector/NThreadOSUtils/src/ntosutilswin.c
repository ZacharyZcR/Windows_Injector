/**
 * MIT License
 *
 * Copyright (c) 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "ntosutilswin.h"
#include "nmem.h"

#include <psapi.h>
#include <tlhelp32.h>

void *NTHREAD_API find_gadget(uint16_t opcode)
{
	HANDLE proc = GetCurrentProcess();
	if (NULL == proc)
		return NULL;

	HMODULE mods[1024];
	DWORD needed;

	if (!EnumProcessModules(proc, mods, sizeof(mods), &needed))
		return NULL;

	MEMORY_BASIC_INFORMATION mbi;
	register int8_t *addr;

	size_t i;
	for (i = 1; i < (needed / sizeof(HMODULE)); i++) {
		HMODULE mod = mods[i];
		addr = (void *)mod;
		while (true) {
			memset(&mbi, 0, sizeof(mbi));
			if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
				break;

			DWORD protect = mbi.Protect;
			uint64_t l =
				(uint64_t)mbi.BaseAddress - (uint64_t)addr + mbi.RegionSize;

			bool readable = (protect == PAGE_EXECUTE_READ) ||
					(protect == PAGE_EXECUTE_READWRITE);
			bool executable = (protect == PAGE_EXECUTE) || readable;

			if (executable) {
				if (!readable &&
				    !VirtualProtect(addr, l,
						    PAGE_EXECUTE_READWRITE,
						    &protect))
					continue;

				void *ret = memmem(addr, l, (void *)&opcode,
						   sizeof(opcode));
				if (ret != NULL)
					return ret;

				if (!readable)
					VirtualProtect(addr, l, protect,
						       &protect);
			}

			addr += l;
		}
	}

	return NULL;
}

#ifdef NTOSUTILS_TEST

ntid_t NTHREAD_API nosu_dummy_process()
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	BOOL ok = CreateProcessA(NULL, "cmd.exe /c ping 127.0.0.1 -n 6 >nul",
				 NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL,
				 NULL, &si, &pi);

	if (!ok)
		return 0;

	return pi.dwProcessId;
}

void NTHREAD_API nosu_kill_dummy(DWORD process_id)
{
	HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, process_id);
	if (handle == NULL)
		return;

	TerminateProcess(handle, 0);
}

#endif /* ifdef NTOSUTILS_TEST */

nerror_t NTHREAD_API nosu_upgrade(HANDLE thread)
{
	DWORD tid = GetThreadId(thread);
	return nosu_attach((ntid_t)tid);
}

struct thread_n_rip {
	HANDLE thread;
	void *rip;
};

HANDLE NTHREAD_API nosu_find_available_thread(ntid_t *thread_ids,
					      uint16_t thread_id_count)
{
	struct thread_n_rip *list =
		N_ALLOC(thread_id_count * sizeof(struct thread_n_rip));

	if (list == NULL)
		return NULL;

	uint16_t thread_count = 0;
	uint16_t i;
	ntid_t ignored_id = GetCurrentThreadId();

	for (i = 0; i < thread_id_count; i++) {
		ntid_t tid = thread_ids[i];
		if (tid == ignored_id)
			continue;

		HANDLE thread = OpenThread(NTHREAD_ACCESS, false, tid);
		if (thread != NULL) {
			list[thread_count].thread = thread;
			list[thread_count].rip = 0;
			thread_count++;
		}
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	uint16_t re_thread_count = thread_count;
	HANDLE sel_thread = NULL;

	while (re_thread_count > 0) {
		for (i = 0; i < thread_count; i++) {
			HANDLE thread = list[i].thread;
			if (thread == NULL)
				continue;

			if (SuspendThread(thread) == (DWORD)(-1))
				goto nosu_find_avaible_thread_remove;
			if (!GetThreadContext(thread, &ctx))
				goto nosu_find_avaible_thread_remove;

			void *rip = (void *)ctx.Rip;
			void *last_rip = list[i].rip;
			if (last_rip != NULL && last_rip != rip) {
				sel_thread = thread;
				goto nosu_find_avaible_thread_exit;
			} else {
				list[i].rip = rip;

				if (ResumeThread(thread) == (DWORD)(-1)) {
nosu_find_avaible_thread_remove:
					re_thread_count--;
					list[i].thread = NULL;
				}
			}
		}
	}

nosu_find_avaible_thread_exit:

	for (i = 0; i < thread_count; i++) {
		HANDLE thread = list[i].thread;
		if (thread != sel_thread)
			CloseHandle(thread);
	}

	N_FREE(list);
	return sel_thread;
}

uint16_t NTHREAD_API nosu_foreach_threads(DWORD pid,
					  nosu_thread_callback_t callback,
					  void *param)
{
	HANDLE thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (thread_snap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	uint32_t count = 0;
	if (Thread32First(thread_snap, &te32)) {
		do {
			if (te32.th32OwnerProcessID == pid) {
				count++;
				bool b = callback(te32.th32ThreadID, param);
				if (!b)
					break;
			}
		} while (Thread32Next(thread_snap, &te32));
	}

	CloseHandle(thread_snap);
	return count;
}

struct thread_ids_count_size {
	ntid_t *ids;
	uint16_t count;
	size_t size;
};

static bool nosu_get_threads_helper(ntid_t tid, void *param)
{
	struct thread_ids_count_size *params =
		(struct thread_ids_count_size *)param;

	ntid_t *ids = params->ids;
	uint16_t count = params->count;
	size_t size = params->size;

	uint16_t new_count = count + 1;

	size_t acc = new_count * sizeof(ntid_t);
	size_t new_size = size;

	while (acc > new_size)
		new_size = size + 80;

	if (size != new_size) {
		void *new_ids = N_REALLOC(ids, new_size);
		if (new_ids == NULL)
			return false;

		ids = new_ids;
	}

	ids[count] = tid;

	params->ids = ids;
	params->count = new_count;
	params->size = new_size;
	return true;
}

uint16_t NTHREAD_API nosu_get_threads_ex(DWORD pid, ntid_t **thread_ids,
					 size_t *thread_ids_size)
{
	struct thread_ids_count_size param;
	param.ids = *thread_ids;
	param.count = 0;
	param.size = *thread_ids_size;

	nosu_foreach_threads(pid, nosu_get_threads_helper, &param);

	*thread_ids = param.ids;
	*thread_ids_size = param.size;
	return param.count;
}

ntid_t *NTHREAD_API nosu_get_threads(DWORD pid, uint16_t *thread_id_count)
{
	ntid_t *thread_ids = NULL;
	size_t size = 0;
	uint16_t count = nosu_get_threads_ex(pid, &thread_ids, &size);

	*thread_id_count = count;

	void *ids = N_REALLOC(thread_ids, count * sizeof(ntid_t));
	if (ids == NULL)
		return thread_ids;

	return ids;
}

HANDLE NTHREAD_API nosu_find_thread(DWORD pid)
{
	uint16_t thread_count;
	ntid_t *ids = nosu_get_threads(pid, &thread_count);
	if (ids == NULL)
		return NULL;

	return nosu_find_available_thread(ids, thread_count);
}

static ntid_t nosu_get_id_and_close(HANDLE thread)
{
	ntid_t tid = GetThreadId(thread);
	CloseHandle(thread);

	return tid;
}

nerror_t NTHREAD_API nosu_find_nthread(nthread_t *nthread, DWORD pid)
{
	HANDLE thread = nosu_find_thread(pid);
	ntid_t tid = nosu_get_id_and_close(thread);
	return nosu_init_ex(nthread, tid, NTHREAD_FLAG_DONT_SUSPEND);
}

nerror_t NTHREAD_API nosu_find_thread_and_upgrade(DWORD pid)
{
	nthread_t nthread;
	if (HAS_ERR(nosu_find_nthread(&nthread, pid)))
		return GET_ERR(NTOSUTILS_NOSU_FIND_NTHREAD_ERROR);

	return ntu_upgrade(&nthread);
}

#ifdef NTOSUTILS_TEST

bool NTHREAD_API nosu_test()
{
	DWORD pid = nosu_dummy_process();
	if (pid == 0)
		return GET_ERR(NTOSUTILS_DUMMY_PROCESS_ERROR);

	nthread_t nthread;
	if (HAS_ERR(nosu_find_nthread(&nthread, pid)))
		return GET_ERR(NTOSUTILS_NOSU_FIND_NTHREAD_ERROR);

	nosu_kill_dummy(pid);
	return N_OK;
}

#endif /* ifdef NTOSUTILS_TEST */