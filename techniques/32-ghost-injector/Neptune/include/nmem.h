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
 * @file nmem.h
 * @brief Neptune library - Memory management subsystem.
 *
 * This header defines simple macros that wrap the standard C library
 * memory management functions for allocation, reallocation, and freeing:
 * - `N_ALLOC(size)` for `malloc`
 * - `N_REALLOC(addr, new_size)` for `realloc`
 * - `N_FREE(addr)` for `free`
 *
 * These macros provide a consistent interface for dynamic memory operations
 * throughout the Neptune project.
 */

#ifndef __NMEM_H__
#define __NMEM_H__

#include "neptune.h"

#ifdef MODULE

NEPTUNE_API void *nmem_alloc(size_t size);

NEPTUNE_API void *nmem_realloc(void *ptr, size_t size);

#define N_ALLOC(size) nmem_alloc(size)
#define N_REALLOC(addr, new_size) nmem_realloc(addr, new_size)
#define N_FREE(addr) kfree(addr)

#else // MODULE

#define N_ALLOC(size) malloc(size)
#define N_REALLOC(addr, new_size) realloc(addr, new_size)
#define N_FREE(addr) free(addr)

#endif // MODULE
#endif // !__NMEM_H__
