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

#include "log.h"
#include "nfile.h"

#ifdef __LOG_H__

#include "nmutex.h"
#include "ntime.h"
#include "nmem.h"

static log_file_t *log_files = NULL;
static size_t log_file_count = 0;

static NMUTEX log_mutex;

LOG_API nerror_t log_init()
{
	NMUTEX_INIT(log_mutex);

#ifdef LOG_FORCE_COLOR
#ifdef _WIN32

	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (console) {
		DWORD mode;
		GetConsoleMode(console, &mode);
		SetConsoleMode(console,
			       mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}

#endif /* ifdef _WIN32 */
#endif /* ifdef LOG_FORCE_COLOR */

#ifdef LOG_ON_STDOUT
#if LOG_ON_STDOUT == 1

#ifdef stdout
	RET_ERR(log_reg_file_ex(stdout, LOG_SFILE_MASK));
#else /* ifndef stdout */
#error "stdout not defined!"
#endif /* ifndef stdout */

#endif /* if LOG_ON_STDOUT == 1 */
#endif /* ifdef LOG_ON_STDOUT */

#ifdef LOG_FILE_PATH
	RET_ERR(log_reg_file(LOG_FILE_PATH));
#endif /* ifdef LOG_FILE_PATH */

	log_set_color(COLOR_RESET);

	return N_OK;
}

LOG_API void log_destroy()
{
	if (log_files != NULL) {
		while (log_file_count > 0) {
			log_file_count--;
			log_file_t *lf = log_files + log_file_count;
			if (lf == NULL || lf->file != NULL)
				continue;

			if ((lf->file_flags & LOG_FILE_DONT_CLOSE) == 0)
				NFILE_CLOSE(lf->file);
		}
	}

	log_files = NULL;
#ifdef NMUTEX_DESTROY
	NMUTEX_DESTROY(log_mutex);
#endif /* ifdef NMUTEX_DESTROY */
}

LOG_API void log_set_color(color_t color)
{
	if (color == NULL)
		return;

	size_t i;
	for (i = 0; i < log_file_count; i++) {
		log_file_t *lf = log_files + i;
		if ((lf->file_flags & LOG_FILE_COLORABLE) != 0)
			NFILE_WRITE(lf->file, color, strlen(color));
	}
}

LOG_API nerror_t log_reg_file_ex(nfile_t file, log_file_flags_t file_flags)
{
	NMUTEX_LOCK(log_mutex);

	size_t ns = log_file_count + 1;
	void *ptr = N_REALLOC(log_files, ns * sizeof(log_file_t));

	if (ptr == NULL)
		return GET_ERR(LOG_REALLOC_ERROR);

	log_files = ptr;
	log_file_t *nf = log_files + log_file_count;

	nf->file = file;
	nf->file_flags = file_flags;
	log_file_count++;

	NMUTEX_UNLOCK(log_mutex);
	return N_OK;
}

LOG_API nerror_t log_reg_file(nfile_path_t path)
{
	nfile_t file = nfile_open_w(path);
	if (file == NULL)
		return GET_ERR(LOG_NFILE_OPEN_W_ERROR);

	nerror_t error = log_reg_file_ex(file, LOG_DFILE_MASK);
	if (HAS_ERR(error)) {
		NFILE_CLOSE(file);
		return error;
	}

	return 0;
}

static void log_paw_v(log_file_flags_t log_class, const char *format,
		      va_list list)
{
	if (format == NULL)
		format = "(null)";

	size_t i;
	for (i = 0; i < log_file_count; i++) {
		log_file_t *lf = log_files + i;

		va_list args_copy;
		va_copy(args_copy, list);

		nfile_t file = lf->file;
		log_file_flags_t flags = lf->file_flags;

		if ((flags & log_class) == log_class) {
			if (log_class == LOG_CLASS_MSG &&
			    (flags & (LOG_CLASS_TIME | LOG_CLASS_TYPE)) != 0) {
				char splt_msg[] = { ':', ' ' };
				NFILE_WRITE(file, splt_msg, sizeof(splt_msg));
			}

			NFILE_PRINTF_V(file, format, args_copy);

			if ((flags & LOG_FILE_DONT_FLUSH) == 0)
				NFILE_FLUSH(lf->file);
		}

		va_end(args_copy);
	}
}

static void log_paw(log_file_flags_t log_class, const char *format, ...)
{
	va_list list;
	va_start(list, format);

	log_paw_v(log_class, format, list);

	va_end(list);
}

LOG_API bool log_can_out()
{
	return log_file_count > 0;
}

LOG_API nerror_t log_log_v(color_t color, const char *type, const char *format,
			   va_list list)
{
	NMUTEX_LOCK(log_mutex);

	char time[8];
	ntime_get_elapsed_str(time);
	log_set_color(color);

#ifdef MODULE

	log_paw(LOG_CLASS_TIME, "[%.8s]", time);
	log_paw(LOG_CLASS_TIME | LOG_CLASS_TYPE, " ");
	log_paw(LOG_CLASS_TYPE, "[%s]", type);
	log_paw_v(LOG_CLASS_MSG, format, list);
	log_paw(LOG_CLASS_ENDL, "\n");

#else /* ifndef MODULE */

#ifdef _WIN32
	DWORD tid = GetCurrentThreadId();
#else /* ifndef _WIN32 */
	pthread_t tid = pthread_self();
#endif /* ifndef _WIN32 */

	log_paw(LOG_CLASS_TIME, "[%.8s]", time);
	log_paw(LOG_CLASS_TIME | LOG_CLASS_TYPE, " ");
	log_paw(LOG_CLASS_TYPE, "[%lu/%s]", tid, type);
	log_paw_v(LOG_CLASS_MSG, format, list);
	log_paw(LOG_CLASS_ENDL, "\n");

#endif /* ifndef MODULE */

	NMUTEX_UNLOCK(log_mutex);
	return N_OK;
}

LOG_API nerror_t log_log(color_t color, const char *type, const char *format,
			 ...)
{
	va_list list;
	va_start(list, format);

	nerror_t error = log_log_v(color, type, format, list);

	va_end(list);
	return error;
}

#ifndef log_info

LOG_API nerror_t log_info(const char *format, ...)
{
	va_list list;
	va_start(list, format);

	nerror_t error = LOG_V(LOG_INFO_COLOR, LOG_INFO_TEXT, format, list);

	va_end(list);
	return error;
}

#endif /* ifndef log_info */

#ifndef log_warn

LOG_API nerror_t log_warn(const char *format, ...)
{
	va_list list;
	va_start(list, format);

	nerror_t error = LOG_V(LOG_WARN_COLOR, LOG_WARN_TEXT, format, list);

	va_end(list);
	return error;
}

#endif /* ifndef log_warn */

#ifndef log_error

LOG_API nerror_t log_error(const char *format, ...)
{
	va_list list;
	va_start(list, format);

	nerror_t error = LOG_V(LOG_ERROR_COLOR, LOG_ERROR_TEXT, format, list);

	va_end(list);
	return error;
}

#endif /* ifndef log_error */
#endif /* ifdef __LOG_H__ */
