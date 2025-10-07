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

#include "ntime.h"

ntime_t ntime_start;

#ifndef MODULE
#include <time.h>
#endif /* ifndef MODULE */

NEPTUNE_API nerror_t ntime_init(void)
{
	ntime_start = ntime_get_unix();
	return N_OK;
}

NEPTUNE_API ntime_t ntime_get_unix(void)
{
#ifdef MODULE

#include <linux/ktime.h>
#include <linux/timekeeping.h>

	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	return (ntime_t)ts.tv_sec;

#else /* ifndef MODULE */
	return (ntime_t)time(NULL);
#endif /* ifndef MODULE */
}

NEPTUNE_API ntime_t ntime_get_elapsed(void)
{
	return ntime_get_unix() - ntime_start;
}

NEPTUNE_API void ntime_get_elapsed_str(char *str)
{
	ntime_t sec = ntime_get_elapsed();
	ntime_t min = sec / 60;
	ntime_t hour = min / 60;

	sec %= 60;
	min %= 60;
	hour %= 24;

	str[0] = '0' + (char)(hour / 10);
	str[1] = '0' + (char)(hour % 10);
	str[2] = ':';
	str[3] = '0' + (char)(min / 10);
	str[4] = '0' + (char)(min % 10);
	str[5] = ':';
	str[6] = '0' + (char)(sec / 10);
	str[7] = '0' + (char)(sec % 10);
}
