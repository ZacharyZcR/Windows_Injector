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
 * @file neptune.h
 * @brief Core configuration and utilities for the Neptune library.
 *
 * This header defines global metadata macros (author, license, version, etc.),
 * macro utilities for argument counting, and portable implementations of
 * common memory search functions (memmem, memstr).
 *
 * Part of the Neptune base library for cross-platform system-level development.
 */

#ifndef __NEPTUNE_H__
#define __NEPTUNE_H__

#ifndef AUTHOR
#define AUTHOR "Serkan Aksoy"
#endif // !AUTHOR

#ifndef LICENSE
#define LICENSE "MIT"
#endif // !LICENSE

#ifndef PROJECT
#define PROJECT "Neptune"
#endif // !PROJECT

#ifndef VERSION
#define VERSION "1.0.0"
#endif // !VERSION

#ifndef DESCRIPTION
#define DESCRIPTION "Neptune for Neptune apps"
#endif // !DESCRIPTION

#ifndef NEPTUNE_MODULERULES_HEADER
#define NEPTUNE_MODULERULES_HEADER "neptune_rules.h"
#endif // !NEPTUNE_MODULERULES_HEADER

#ifndef API_EXPORT
#define API_EXPORT __declspec(dllexport)
#endif // !API_EXPORT

#ifndef API_IMPORT
#define API_IMPORT __declspec(dllimport)
#endif // !API_IMPORT

#ifdef NEPTUNE_API_IMPORT

#ifdef NEPTUNE_API_EXPORT
#error "NEPTUNE_API_EXPORT and NEPTUNE_API_IMPORT cannot be defined at the same time"
#endif // NEPTUNE_API_EXPORT

#ifdef _WIN32
#define NEPTUNE_API API_IMPORT
#endif // _WIN32

#endif // NEPTUNE_API_IMPORT

#ifdef NEPTUNE_API_EXPORT
#ifdef _WIN32
#define NEPTUNE_API API_EXPORT
#endif // _WIN32
#endif // NEPTUNE_API_EXPORT

#ifndef NEPTUNE_API
#define NEPTUNE_API
#endif // !NEPTUNE_API

#ifdef MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mutex.h>

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

#else // !MODULE

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32

#include <windows.h>

typedef SSIZE_T ssize_t;

#else // !_WIN32
#include <pthread.h>
#endif // !_WIN32

#endif // !MODULE

#ifndef LOG_FILE_PATH
#ifdef MODULE
#define LOG_FILE_PATH "/var/log/neptune.log"
#else // !MODULE

#ifdef _WIN32
// #define LOG_FILE_PATH L"neptune.log"
#else // !_WIN32
#define LOG_FILE_PATH "neptune.log"
#endif // !_WIN32

#endif // !MODULE
#endif // !LOG_FILE_PATH

#include "nerror.h"

#define NEPTUNE_GET_ARG_COUNT_EXPANDER(args) NEPTUNE_GET_64TH_ARG args
#define NEPTUNE_GET_ARG_COUNT(...)      \
	NEPTUNE_GET_ARG_COUNT_EXPANDER( \
		(__VA_ARGS__, NEPTUNE_COUNTDOWN_63_TO_0()))

#define NEPTUNE_GET_ARG_COUNT_HELPER(...) NEPTUNE_GET_64TH_ARG(__VA_ARGS__)
#define NEPTUNE_GET_64TH_ARG(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11,     \
			     _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, \
			     _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, \
			     _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, \
			     _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, \
			     _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, \
			     _62, _63, N, ...)                                 \
	N
#define NEPTUNE_COUNTDOWN_63_TO_0()                                         \
	63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, \
		46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, \
		31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, \
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#define NEPTUNE_ERROR 0xba00

#define NEPTUNE_INIT_ERROR 0xba01
#define NEPTUNE_INIT_ERROR_E (NEPTUNE_INIT_ERROR + 127)

#define NEPTUNE_ERROR_E (NEPTUNE_INIT_ERROR_E)

/**
* @brief Initialize the Neptune core system.
*
* This function sets up all global and platform-specific subsystems required by the Neptune library.
* It must be called before using any other Neptune-provided functionality.
*
* @return Error code indicating success or failure of initialization.
*/
nerror_t neptune_init(void);

/**
* @brief Shutdown and clean up the Neptune core system.
*
* This function releases all resources allocated during initialization and runtime.
* It should be called once when the application is finished using the Neptune library.
*/

void neptune_destroy(void);

#ifdef NEPTUNE_ENABLE_MEMMEM

void *memmem_s(const void *haystack, size_t haystacklen, const void *needle,
	       size_t needlelen, size_t skip);

void *memmem_n(const void *haystack, size_t haystacklen, const void *needle,
	       size_t needlelen);

#ifndef memmem

#define NEPTUNE_DEFINE_MEMMEM

void *neptune_memmem(const void *haystack, size_t haystacklen,
		     const void *needle, size_t needlelen);

#define memmem(haystack, haystacklen, needle, needlelen) \
	neptune_memmem(haystack, haystacklen, needle, needlelen)

#endif // !memmem

#ifndef memstr

#define NEPTUNE_DEFINE_MEMSTR

void *neptune_memstr(const void *haystack, const char *needle,
		     size_t haystacklen);

#define memstr(haystack, needle, needlelen) \
	neptune_memstr(haystack, needle, needlelen)

#endif /* !memstr */

#endif // NEPTUNE_ENABLE_MEMMEM

#endif // !__NEPTUNE_H__

#include "log.h"
