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
 * @file log.h
 * @brief Logging interface for the Neptune library.
 *
 * This header provides a minimal and flexible logging system for the Neptune project.
 * It allows outputting messages of different severities (info, warning, error) to one or more
 * registered file streams, with optional formatting features such as timestamps, message types,
 * and colored output.
 *
 * Before using the logging API, the system must be initialized using `log_init()`,
 * and should be cleaned up with `log_destroy()` when no longer needed.
 */

#include "log_defs.h"

#ifdef LOG_LEVEL_1
#ifndef __LOG_H__
#define __LOG_H__

#include "color.h"
#include "nerror.h"

#include "neptune.h"

#ifndef LOG_API
#define LOG_API NEPTUNE_API
#endif // !LOG_API

// Bitmask type for specifying logging behavior
typedef int8_t log_file_flags_t;

// Represents a log output target and its formatting flags
struct log_file {
	nfile_t file; // File or stream to write log output to
	log_file_flags_t file_flags; // Bitmask of LOG_CLASS_* flags
};

typedef struct log_file log_file_t;

/**
 * @brief Set the color for subsequent log messages (if supported).
 * @param color The color to apply to the log output.
 */
LOG_API void log_set_color(color_t color);

/**
 * @brief Register an existing file as a log output target with specific flags.
 * @param file The file to output logs to.
 * @param file_flags Formatting flags.
 * @return Error code.
 */
LOG_API nerror_t log_reg_file_ex(nfile_t file, log_file_flags_t file_flags);

/**
 * @brief Register a new log file by path with default flags.
 * @param path Path to the file to be used for logging.
 * @return Error code.
 */
LOG_API nerror_t log_reg_file(nfile_path_t path);

/**
 * @brief Check if logging output is currently enabled.
 * @return true if logging is active, false otherwise.
 */
LOG_API bool log_can_out(void);

/**
 * @brief Write an informational log message.
 * @param format Format string (printf-style).
 * @param ... Arguments matching the format.
 * @return Error code.
 */
LOG_API nerror_t log_info(const char *format, ...);

/**
 * @brief Write a warning log message.
 * @param format Format string (printf-style).
 * @param ... Arguments matching the format.
 * @return Error code.
 */
LOG_API nerror_t log_warn(const char *format, ...);

/**
 * @brief Write an error log message.
 * @param format Format string (printf-style).
 * @param ... Arguments matching the format.
 * @return Error code.
 */
LOG_API nerror_t log_error(const char *format, ...);

/**
 * @brief Initialize the logging system.
 * @return Error code.
 */
LOG_API nerror_t log_init(void);

/**
 * @brief Clean up and close any log output targets.
 */
LOG_API void log_destroy(void);

/**
 * @brief Core function for writing a formatted log message with a va_list.
 * @param color Color of the log message, of type color_t (e.g., for terminal styling).
 * @param type String representing log type (e.g., "INFO", "ERROR").
 * @param format Format string.
 * @param list va_list containing arguments.
 * @return Error code.
 */
LOG_API nerror_t log_log_v(color_t color, const char *type, const char *format,
			   va_list list);

/**
 * @brief Write a formatted log message with variable arguments.
 * @param color Color of the log message, of type color_t (e.g., for terminal styling).
 * @param type String representing log type (e.g., "INFO", "ERROR").
 * @param format Format string.
 * @param ... Variable arguments.
 * @return Error code.
 */
LOG_API nerror_t log_log(color_t color, const char *type, const char *format,
			 ...);

// Convenience macros for simplified logging

#define LOG_V(color, type, format, list) \
	log_log_v(color, type, format, list) // Log with va_list

#define LOG(color, type, format, ...) \
	log_log(color, type, format,  \
		##__VA_ARGS__) // Log with variadic arguments

#define LOG_INFO(format, ...) \
	log_info(format, ##__VA_ARGS__) // Shorthand for informational logs

#define LOG_WARN(format, ...) \
	log_warn(format, ##__VA_ARGS__) // Shorthand for warning logs

#define LOG_ERROR(format, ...) \
	log_error(format, ##__VA_ARGS__) // Shorthand for error logs

#endif // !__LOG_H__
#else // !LOG_LEVEL_1
#define log_can_out() (false)
#endif // !LOG_LEVEL_1
