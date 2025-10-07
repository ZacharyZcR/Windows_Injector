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
 * @file ntime.h
 * @brief Neptune library - Time management subsystem.
 *
 * Provides basic time-related functionality including initialization,
 * obtaining the current Unix timestamp, measuring elapsed time since
 * subsystem start, and formatting elapsed time as a string.
 *
 * Designed for minimal overhead and cross-platform compatibility.
 */

#ifndef __NTIME_H__
#define __NTIME_H__

#include "neptune.h"

typedef uint64_t ntime_t; /**< Type representing time values */

/**
 * @brief Initialize the time subsystem.
 *
 * This function sets up the necessary state for time measurements,
 * including initializing the system start time reference.
 *
 * @return Error code indicating success or failure.
 */
NEPTUNE_API nerror_t ntime_init(void);

/**
 * @brief Retrieve the current Unix timestamp.
 *
 * Returns the number of seconds elapsed since the Unix epoch (January 1, 1970).
 *
 * @return Current Unix timestamp.
 */
NEPTUNE_API ntime_t ntime_get_unix(void);

/**
 * @brief Get the elapsed time since the time subsystem was initialized.
 *
 * Calculates the time difference between the current time and the
 * stored start time.
 *
 * @return Elapsed time in seconds.
 */
NEPTUNE_API ntime_t ntime_get_elapsed(void);

/**
 * @brief Write the elapsed time as a human-readable string in "HH:MM:SS" format.
 *
 * Formats the elapsed time (since initialization) into a fixed-length string
 * representing hours, minutes, and seconds, and writes it into the provided buffer.
 *
 * @param str Pointer to a character buffer of at least 8 bytes.
 *            The formatted string will have the format "HH:MM:SS" and is NOT null-terminated.
 *
 * @note The buffer must be exactly 8 bytes to hold the output.
 */
NEPTUNE_API void ntime_get_elapsed_str(char *str);

#endif // !__NTIME_H__
