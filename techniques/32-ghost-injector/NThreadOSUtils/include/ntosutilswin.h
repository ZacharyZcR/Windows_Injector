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

#ifndef __NTHREADOSUTILS_WIN_H__
#define __NTHREADOSUTILS_WIN_H__

#include "ntosutils.h"

#define NTOSUTILS_WIN_ERROR 0x1200
#define NTOSUTILS_WIN_FIND_AVAIBLE_THREAD_ERROR 0x1201
#define NTOSUTILS_NOSU_FIND_NTHREAD_ERROR 0x1202

#ifdef NTOSUTILS_TEST

DWORD NTHREAD_API nosu_dummy_process();

void NTHREAD_API nosu_kill_dummy(DWORD process_id);

#endif // NTOSUTILS_TEST

HANDLE NTHREAD_API nosu_find_available_thread(ntid_t *thread_ids,
					      uint16_t thread_id_count);

nerror_t NTHREAD_API nosu_upgrade(HANDLE thread);

HANDLE NTHREAD_API nosu_find_thread(DWORD pid);

nerror_t NTHREAD_API nosu_find_nthread(nthread_t *nthread, DWORD pid);

nerror_t NTHREAD_API nosu_find_thread_and_upgrade(DWORD pid);

#endif // !__NTHREADOSUTILS_WIN_H__
