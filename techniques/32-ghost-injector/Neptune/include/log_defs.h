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

/**
 * @file log_defs.h
 * @brief Logging level control macros for the Neptune logging system.
 *
 * This file defines the logging level hierarchy used by Neptune, allowing
 * developers to control the verbosity of logging at compile time using the
 * `LOG_LEVEL` macro.
 *
 * Logging levels:
 *   - LOG_LEVEL_1: Basic logging — only critical errors are reported.
 *   - LOG_LEVEL_2: Moderate logging — provides sufficient detail for most runtime diagnostics.
 *   - LOG_LEVEL_3: Verbose logging — outputs everything, typically used during development and testing.
 *
 * Logging can be completely disabled by defining `DISABLE_LOGS`.
 *
 * This header ensures consistency and simplifies conditional logging across
 * different modules of the project.
 */

#include "nfile_defs.h"

#if defined(NFILE_DISABLE_WRITE) && NFILE_DISABLE_WRITE == 1

#ifdef LOG_LEVEL_1
#undef LOG_LEVEL_1
#endif // LOG_LEVEL_1

#ifdef LOG_LEVEL_2
#undef LOG_LEVEL_2
#endif // LOG_LEVEL_2

#ifdef LOG_LEVEL_3
#undef LOG_LEVEL_3
#endif // LOG_LEVEL_3

#ifdef LOG_LEVEL
#undef LOG_LEVEL
#endif // LOG_LEVEL

#endif // defined(NFILE_DISABLE_WRITE) && NFILE_DISABLE_WRITE == 1

#ifdef DISABLE_LOGS

// If logs are disabled, undefine all logging levels
#ifdef LOG_LEVEL
#undef LOG_LEVEL
#define LOG_LEVEL 0
#endif // LOG_LEVEL

#ifdef LOG_LEVEL_3
#undef LOG_LEVEL_3
#endif // LOG_LEVEL_3

#ifdef LOG_LEVEL_2
#undef LOG_LEVEL_2
#endif // LOG_LEVEL_2

#ifdef LOG_LEVEL_1
#undef LOG_LEVEL_1
#endif // LOG_LEVEL_1

#else // !DISABLE_LOGS

// Default logging level (no logs) if not specified
#ifndef LOG_LEVEL
#define LOG_LEVEL 0
#endif // !LOG_LEVEL

// Sanitize LOG_LEVEL to avoid negative values
#if LOG_LEVEL < 0
#undef LOG_LEVEL
#define LOG_LEVEL 0
#endif // LOG_LEVEL < 0

// Define the appropriate macro for the selected log level

#if LOG_LEVEL == 3
#ifndef LOG_LEVEL_3
#define LOG_LEVEL_3
#endif // !LOG_LEVEL_3
#endif // LOG_LEVEL == 3

#if LOG_LEVEL == 2
#ifndef LOG_LEVEL_2
#define LOG_LEVEL_2
#endif // !LOG_LEVEL_2
#endif // LOG_LEVEL == 2

#if LOG_LEVEL == 1
#ifndef LOG_LEVEL_1
#define LOG_LEVEL_1
#endif // !LOG_LEVEL_1
#endif // LOG_LEVEL == 1

// Ensure lower levels are also defined when higher level is enabled

#ifdef LOG_LEVEL_3

#ifndef LOG_LEVEL_2
#define LOG_LEVEL_2
#endif // !LOG_LEVEL_2

#if LOG_LEVEL < 3
#undef LOG_LEVEL
#define LOG_LEVEL 3
#endif // LOG_LEVEL < 3

#endif // LOG_LEVEL_3

#ifdef LOG_LEVEL_2
#ifndef LOG_LEVEL_1
#define LOG_LEVEL_1
#endif // !LOG_LEVEL_1

#if LOG_LEVEL < 2
#undef LOG_LEVEL
#define LOG_LEVEL 2
#endif // LOG_LEVEL < 2

#endif // LOG_LEVEL_2

#ifdef LOG_LEVEL_1
#if LOG_LEVEL < 1
#undef LOG_LEVEL
#define LOG_LEVEL 1
#endif // LOG_LEVEL < 1
#endif // LOG_LEVEL_1

#endif // !DISABLE_LOGS

#ifndef __LOG_DEFS_H__
#define __LOG_DEFS_H__

#ifdef LOG_LEVEL_1

#define LOG_INFO_COLOR COLOR_CYAN
#define LOG_WARN_COLOR COLOR_YELLOW
#define LOG_ERROR_COLOR COLOR_RED

#define LOG_FILE_DONT_CLOSE 0x01
#define LOG_FILE_DONT_FLUSH 0x02

#define LOG_FILE_PRINT_TIME 0x04
#define LOG_FILE_PRINT_TYPE 0x08
#define LOG_FILE_PRINT_MSG 0x10
#define LOG_FILE_PRINT_ENDL 0x20

#define LOG_FILE_COLORABLE 0x80

#ifndef LOG_SFILE_MASK
#ifdef _WIN32

#define LOG_TEMP_SFILE_MASK                                               \
	(LOG_FILE_PRINT_TIME | LOG_FILE_PRINT_TYPE | LOG_FILE_PRINT_MSG | \
	 LOG_FILE_PRINT_ENDL | LOG_FILE_DONT_CLOSE)

#ifdef LOG_FORCE_COLOR
#define LOG_SFILE_MASK LOG_TEMP_SFILE_MASK | LOG_FILE_COLORABLE
#else // !LOG_FORCE_COLOR
#define LOG_SFILE_MASK LOG_TEMP_SFILE_MASK
#endif // !LOG_FORCE_COLOR

#endif // _WIN32
#endif // !LOG_SFILE_MASK

#ifndef LOG_DFILE_MASK

#define LOG_DFILE_MASK                                                    \
	(LOG_FILE_PRINT_TIME | LOG_FILE_PRINT_TYPE | LOG_FILE_PRINT_MSG | \
	 LOG_FILE_PRINT_ENDL)

#endif // !LOG_DFILE_MASK

#define LOG_ERROR_S 0x6100

#define LOG_REALLOC_ERROR 0x6101
#define LOG_NFILE_OPEN_W_ERROR 0x6102

#define LOG_ERROR_E LOG_NFILE_OPEN_W_ERROR

#define LOG_INFO_TEXT "INFO"
#define LOG_WARN_TEXT "WARN"
#define LOG_ERROR_TEXT "ERROR"

#define LOG_CLASS_TIME LOG_FILE_PRINT_TIME
#define LOG_CLASS_TYPE LOG_FILE_PRINT_TYPE
#define LOG_CLASS_MSG LOG_FILE_PRINT_MSG
#define LOG_CLASS_ENDL LOG_FILE_PRINT_ENDL

#endif // LOG_LEVEL_1
#endif // !__LOG_DEFS_H__