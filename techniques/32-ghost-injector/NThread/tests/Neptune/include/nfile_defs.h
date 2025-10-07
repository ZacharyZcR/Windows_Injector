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

#ifndef __NFILE_DEFS_H__
#define __NFILE_DEFS_H__

#ifdef MODULE

#include <linux/types.h>
#include <linux/fs.h>

#define NFILE_MAX_PRINTF_LENGTH 256
#define NFILE_MAX_PATH_LENGTH 256

typedef struct file *nfile_t;

#else // !MODULE

#include <stdio.h>
#include <wchar.h>

typedef FILE *nfile_t;

#endif // !MODULE

#ifdef _WIN32

typedef wchar_t nfile_char_t;
#define NFILE_MAX_PATH_LENGTH MAX_PATH

#else // !_WIN32

typedef char nfile_char_t;

#endif // _WIN32

typedef nfile_char_t *nfile_path_t;

#if defined(NFILE_DISABLE_READ) && defined(NFILE_DISABLE_WRITE)
#if NFILE_DISABLE_READ == 1 && NFILE_DISABLE_WRITE == 1

#ifdef NFILE_DISABLE
#undef NFILE_DISABLE
#endif // NFILE_DISABLE

#define NFILE_DISABLE 1

#endif // NFILE_DISABLE_READ == 1 && NFILE_DISABLE_WRITE == 1
#endif // defined(NFILE_DISABLE_READ) && defined(NFILE_DISABLE_WRITE)

#if defined(NFILE_DISABLE) && NFILE_DISABLE == 1

#ifdef NFILE_DISABLE_READ
#undef NFILE_DISABLE_READ
#endif // NFILE_DISABLE_READ

#ifdef NFILE_DISABLE_WRITE
#undef NFILE_DISABLE_WRITE
#endif // NFILE_DISABLE_WRITE

#ifdef NFILE_DISABLE_RDWR
#undef NFILE_DISABLE_RDWR
#endif // NFILE_DISABLE_RDWR

#define NFILE_DISABLE_READ 1
#define NFILE_DISABLE_WRITE 1
#define NFILE_DISABLE_RDWR 1

#else // !defined(NFILE_DISABLE) || NFILE_DISABLE != 1

#if !defined(NFILE_DISABLE_RDWR) || NFILE_DISABLE_RDWR != 1
#if (defined(NFILE_DISABLE_READ) && NFILE_DISABLE_READ == 1) || \
	(defined(NFILE_DISABLE_WRITE) && NFILE_DISABLE_WRITE == 1)

#ifdef NFILE_DISABLE_RDWR
#undef NFILE_DISABLE_RDWR
#endif // NFILE_DISABLE_RDWR

#define NFILE_DISABLE_RDWR 1

#endif // (defined(NFILE_DISABLE_READ) && NFILE_DISABLE_READ == 1) || (defined(NFILE_DISABLE_WRITE) && NFILE_DISABLE_WRITE == 1)
#endif // !defined(NFILE_DISABLE_RDWR) || NFILE_DISABLE_RDWR != 1

#endif // !defined(NFILE_DISABLE) || NFILE_DISABLE != 1
#endif // __NFILE_DEFS_H__