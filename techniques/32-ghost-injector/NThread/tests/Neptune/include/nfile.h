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

#ifndef __NFILE_H__
#define __NFILE_H__

#include "nfile_defs.h"

#ifdef MODULE

#define NFILE_FLUSH(nfile) \
	do {               \
	} while (0)

void nfile_close(nfile_t nfile);

#define NFILE_CLOSE(nfile) nfile_close(nfile)

#else // !MODULE

#define NFILE_FLUSH(nfile) fflush(nfile)
#define NFILE_CLOSE(nfile) fclose(nfile)

#endif // !MODULE

#include "neptune.h"

#ifndef NFILE_API
#define NFILE_API NEPTUNE_API
#endif // !NFILE_API

#ifdef _WIN32
#define NFILE_PATH_GET_LENGTH(nfile_path) ((size_t)wcslen(nfile_path))
#else // !_WIN32
#define NFILE_PATH_GET_LENGTH(nfile_path) ((size_t)strlen(nfile_path))
#endif // !_WIN32

#define NFILE_PATH_CALC_SIZE(length) ((length + 1) * sizeof(nfile_char_t))
#define NFILE_PATH_GET_SIZE(nfile_path) \
	(NFILE_PATH_CALC_SIZE(NFILE_PATH_GET_LENGTH(nfile_path)))
#define NFILE_MAX_PATH_SIZE (NFILE_PATH_CALC_SIZE(NFILE_MAX_PATH_LENGTH))

#if !defined(NFILE_DISABLE) || NFILE_DISABLE != 1

#if !defined(NFILE_DISABLE_READ) || NFILE_DISABLE_READ != 1

NFILE_API nfile_t nfile_open_r(const nfile_path_t pathname);

NFILE_API ssize_t nfile_read_o(nfile_t nfile, ssize_t offset, void *buffer,
			       ssize_t length);

NFILE_API ssize_t nfile_read(nfile_t nfile, void *buffer, ssize_t length);

#define NFILE_OPEN_R(pathname) nfile_open_r(pathname)

#define NFILE_READ_O(nfile, buffer, length, offset) \
	nfile_read_o(nfile, buffer, length, offset)

#define NFILE_READ(nfile, buffer, length) nfile_read(nfile, buffer, length)

#endif // !defined(NFILE_DISABLE_READ) || NFILE_DISABLE_READ != 1

#if !defined(NFILE_DISABLE_WRITE) || NFILE_DISABLE_WRITE != 1

NFILE_API nfile_t nfile_open_w(const nfile_path_t pathname);

NFILE_API ssize_t nfile_write_o(nfile_t nfile, ssize_t offset,
				const void *buffer, ssize_t length);

NFILE_API ssize_t nfile_write(nfile_t nfile, const void *buffer,
			      ssize_t length);

NFILE_API ssize_t nfile_printf_ov(nfile_t nfile, ssize_t offset,
				  const char *format, va_list args);

NFILE_API ssize_t nfile_printf_o(nfile_t nfile, ssize_t offset,
				 const char *format, ...);

NFILE_API ssize_t nfile_printf_v(nfile_t nfile, const char *format,
				 va_list args);

NFILE_API ssize_t nfile_printf(nfile_t nfile, const char *format, ...);

#define NFILE_OPEN_W(pathname) nfile_open_w(pathname)

#define NFILE_WRITE_O(nfile, buffer, length, offset) \
	nfile_write_o(nfile, buffer, length, offset)

#define NFILE_WRITE(nfile, buffer, length) nfile_write(nfile, buffer, length)

#define NFILE_PRINTF_OV(nfile, offset, format, args) \
	nfile_printf_ov(nfile, offset, format, args)

#define NFILE_PRINTF_O(nfile, offset, format, ...) \
	nfile_printf_v(nfile, offset, format, ##__VA_ARGS__)

#define NFILE_PRINTF_V(nfile, format, args) nfile_printf_v(nfile, format, args)

#define NFILE_PRINTF(nfile, format, ...) \
	nfile_printf_v(nfile, format, ##__VA_ARGS__)

#endif // !defined(NFILE_DISABLE_WRITE) || NFILE_DISABLE_WRITE != 1

#if !defined(NFILE_DISABLE_RDWR) || NFILE_DISABLE_RDWR != 1

NFILE_API nfile_t nfile_open_rw(const nfile_path_t pathname);

NFILE_API nfile_t nfile_open_wr(const nfile_path_t pathname);

#endif // !defined(NFILE_DISABLE_RDWR) || NFILE_DISABLE_RDWR != 1

NFILE_API void nfile_delete(const nfile_path_t path);

#define NFILE_DELETE(nfile) nfile_delete(nfile)

NFILE_API ssize_t nfile_get_length(nfile_t nfile);

#define NFILE_GET_LENGTH(nfile) nfile_get_length(nfile)

#endif // !defined(NFILE_DISABLE) || NFILE_DISABLE != 1
#endif // !__NFILE_H__
