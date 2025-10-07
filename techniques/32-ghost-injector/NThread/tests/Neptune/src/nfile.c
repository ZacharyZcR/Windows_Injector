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

#include "nfile.h"

#ifdef MODULE
#include <linux/uaccess.h>
#endif /* ifdef MODULE */

#if !defined(NFILE_DISABLE) || NFILE_DISABLE != 1

#ifdef MODULE

NFILE_API void nfile_close(nfile_t nfile)
{
	filp_close(nfile, NULL);
}

#endif /* ifdef MODULE */

NFILE_API void nfile_delete(const nfile_path_t path)
{
#ifdef _WIN32
	DeleteFileW(path);
#endif /* ifdef _WIN32 */
}

NFILE_API ssize_t nfile_get_length(nfile_t nfile)
{
#ifdef MODULE

	struct inode *inode = file_inode(nfile);
	if (inode)
		return i_size_read(inode);

	return 0;

#else /* ifndef MODULE */

	long cur_pos = ftell(nfile);
	if (fseek(nfile, 0, SEEK_END) != 0)
		return 0;

	long ret = ftell(nfile);
	fseek(nfile, cur_pos, SEEK_SET);

	return ret;

#endif /* ifndef MODULE */
}

#if !defined(NFILE_DISABLE_READ) || NFILE_DISABLE_READ != 1

NFILE_API nfile_t nfile_open_r(const nfile_path_t pathname)
{
#ifdef MODULE
	return filp_open(pathname, O_RDONLY, 0);
#else /* ifndef MODULE */

#ifdef _WIN32
	return _wfopen(pathname, L"rb");
#else /* ifndef _WIN32 */
	return fopen(pathname, "rb");
#endif /* ifndef _WIN32 */

#endif /* ifndef MODULE */
}

NFILE_API ssize_t nfile_read_o(nfile_t nfile, ssize_t offset, void *buffer,
			       ssize_t length)
{
#ifdef MODULE
	return kernel_read(nfile, buffer, length, (loff_t *)&offset);
#else /* ifndef MODULE */

	if (fseek(nfile, (long)offset, SEEK_SET) == 0)
		return 0;

	return fread(buffer, 1, length, nfile);

#endif /* ifndef MODULE */
}

NFILE_API ssize_t nfile_read(nfile_t nfile, void *buffer, ssize_t length)
{
#ifdef MODULE
	return nfile_read_o(nfile, nfile->f_pos, buffer, length);
#else /* ifndef MODULE */
	return fread(buffer, 1, length, nfile);
#endif /* infdef MODULE */
}

#endif // !defined(NFILE_DISABLE_READ) || NFILE_DISABLE_READ != 1

#if !defined(NFILE_DISABLE_WRITE) || NFILE_DISABLE_WRITE != 1

NFILE_API nfile_t nfile_open_w(const nfile_path_t pathname)
{
#ifdef MODULE
	return filp_open(pathname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
#else /* ifndef MODULE */

#ifdef _WIN32
	return _wfopen(pathname, L"wb");
#else /* ifndef _WIN32 */
	return fopen(pathname, "wb");
#endif /* ifndef _WIN32 */

#endif /* ifndef MODULE */
}

NFILE_API ssize_t nfile_write_o(nfile_t nfile, ssize_t offset,
				const void *buffer, ssize_t length)
{
#ifdef MODULE
	size_t ret = kernel_write(nfile, buffer, length, (loff_t *)&offset);

	nfile->f_pos = offset;
	return ret;
#else /* ifndef MODULE */

	if (fseek(nfile, (long)offset, SEEK_SET) != 0)
		return 0;

	return fwrite(buffer, 1, length, nfile);

#endif /* ifndef MODULE */
}

NFILE_API ssize_t nfile_write(nfile_t nfile, const void *buffer, ssize_t length)
{
#ifdef MODULE
	return nfile_write_o(nfile, nfile->f_pos, buffer, length);
#else /* ifndef MODULE */
	return fwrite(buffer, 1, length, nfile);
#endif /* infdef MODULE */
}

NFILE_API ssize_t nfile_printf_ov(nfile_t nfile, ssize_t offset,
				  const char *format, va_list args)
{
#ifdef MODULE

	char buffer[NFILE_MAX_PRINTF_LENGTH];
	ssize_t length = vscnprintf(buffer, sizeof(buffer), format, args);

	return nfile_write_o(nfile, offset, buffer, length);

#else /* ifndef MODULE */

	if (fseek(nfile, (long)offset, SEEK_SET) != 0)
		return 0;

	return vfprintf(nfile, format, args);

#endif /* ifndef MODULE */
}

NFILE_API ssize_t nfile_printf_o(nfile_t nfile, ssize_t offset,
				 const char *format, ...)
{
	va_list args;
	va_start(args, format);

#ifdef MODULE
	ssize_t ret = nfile_printf_ov(nfile, offset, format, args);
#else /* ifndef MODULE */

	if (fseek(nfile, (long)offset, SEEK_SET) != 0)
		return 0;

	ssize_t ret = vfprintf(nfile, format, args);

#endif /* ifndef MODULE */

	va_end(args);
	return ret;
}

NFILE_API ssize_t nfile_printf_v(nfile_t nfile, const char *format,
				 va_list args)
{
#ifdef MODULE
	return nfile_printf_ov(nfile, nfile->f_pos, format, args);
#else /* ifndef MODULE */
	return vfprintf(nfile, format, args);
#endif /* ifndef MODULE */
}

NFILE_API ssize_t nfile_printf(nfile_t nfile, const char *format, ...)
{
	va_list args;
	va_start(args, format);

#ifdef MODULE
	ssize_t ret = nfile_printf_v(nfile, format, args);
#else /* ifndef MODULE */
	ssize_t ret = vfprintf(nfile, format, args);
#endif /* ifndef MODULE */

	va_end(args);
	return ret;
}

#endif // !defined(NFILE_DISABLE_WRITE) || NFILE_DISABLE_WRITE != 1

#if !defined(NFILE_DISABLE_RDWR) || NFILE_DISABLE_RDWR != 1

NFILE_API nfile_t nfile_open_rw(const nfile_path_t pathname)
{
#ifdef MODULE
	return filp_open(pathname, O_RDWR, 0);
#else /* ifndef MODULE */

#ifdef _WIN32
	return _wfopen(pathname, L"r+b");
#else /* ifndef _WIN32 */
	return fopen(pathname, "rb");
#endif /* ifndef _WIN32 */

#endif /* ifndef MODULE */
}

NFILE_API nfile_t nfile_open_wr(const nfile_path_t pathname)
{
#ifdef MODULE
	return filp_open(pathname, O_RDWR | O_CREAT | O_TRUNC, 0644);
#else /* ifndef MODULE */

#ifdef _WIN32
	return _wfopen(pathname, L"w+b");
#else /* ifndef _WIN32 */
	return fopen(pathname, "w+b");
#endif /* ifndef _WIN32 */

#endif /* ifndef MODULE */
}

#endif // !defined(NFILE_DISABLE_RDWR) || NFILE_DISABLE_RDWR != 1

#endif // !defined(NFILE_DISABLE) || NFILE_DISABLE != 1
