/**
 * MIT License
 *
 * Copyright (c) 2024, 2025 Serkan Aksoy
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

/**
 * @file nmutex.h
 * @brief Neptune library - Mutex managment subsystem.
 *
 * This header defines macros wrapping platform-specific mutex operations,
 * providing a uniform interface to initialize, lock, and unlock mutexes.
 *
 * Macros:
 * - `NMUTEX_INIT(mutex)`: Initialize the mutex.
 * - `NMUTEX_LOCK(mutex)`: Acquire the mutex lock.
 * - `NMUTEX_UNLOCK(mutex)`: Release the mutex lock.
 */

#ifndef __NMUTEX_H__
#define __NMUTEX_H__

#include "neptune.h"

#ifdef MODULE

#define NMUTEX struct mutex

#define NMUTEX_INIT(nmutex) mutex_init(&nmutex)
#define NMUTEX_LOCK(nmutex) mutex_lock(&nmutex)
#define NMUTEX_UNLOCK(nmutex) mutex_unlock(&nmutex)

#else // !MODULE

#ifdef _WIN32

#define NMUTEX HANDLE

NEPTUNE_API HANDLE nmutex_init();

NEPTUNE_API void nmutex_lock(HANDLE nmutex);

#define NMUTEX_INIT(nmutex) (nmutex = nmutex_init())
#define NMUTEX_LOCK(nmutex) nmutex_lock(nmutex)
#define NMUTEX_UNLOCK(nmutex) ReleaseMutex(nmutex)
#define NMUTEX_DESTROY(nmutex) CloseHandle(nmutex)

#else // !_WIN32

#define NMUTEX pthread_mutex_t

NEPTUNE_API void nmutex_init(pthread_mutex_t *mutex);

#define NMUTEX_INIT(nmutex) nmutex_init(&nmutex)
#define NMUTEX_LOCK(nmutex) pthread_mutex_lock(&nmutex)
#define NMUTEX_UNLOCK(nmutex) pthread_mutex_unlock(&nmutex)
#define NMUTEX_DESTROY(nmutex) pthread_mutex_destroy(&nmutex)

#endif // !_WIN32
#endif // !MODULE
#endif // !__MUTEX_H__
