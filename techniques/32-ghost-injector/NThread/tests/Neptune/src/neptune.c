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

#include "neptune.h"
#include "nerror.h"
#include "ntime.h"

typedef nerror_t (*neptune_init_fn)(void);

typedef nerror_t (*neptune_init_fn)(void);
typedef void (*neptune_destroy_fn)(void);

#define NEPTUNE_MODULE_INIT(init_fn)
#define NEPTUNE_MODULE_DESTROY(destroy_fn)
#define NEPTUNE_MODULE(init_fn, destroy_fn)

#include NEPTUNE_MODULERULES_HEADER

#undef NEPTUNE_MODULE
#undef NEPTUNE_MODULE_INIT
#undef NEPTUNE_MODULE_DESTROY

#define NEPTUNE_MODULE_INIT(init_fn) ((neptune_init_fn)(init_fn)),
#define NEPTUNE_MODULE_DESTROY(destroy_fn)
#define NEPTUNE_MODULE(init_fn, destroy_fn) NEPTUNE_MODULE_INIT(init_fn)

neptune_init_fn neptune_init_funcs[] = {
#include NEPTUNE_MODULERULES_HEADER
};

#undef NEPTUNE_MODULE
#undef NEPTUNE_MODULE_INIT
#undef NEPTUNE_MODULE_DESTROY

#define NEPTUNE_MODULE_INIT(init_fn)
#define NEPTUNE_MODULE_DESTROY(destroy_fn) ((neptune_destroy_fn)(destroy_fn)),
#define NEPTUNE_MODULE(init_fn, destroy_fn) NEPTUNE_MODULE_DESTROY(destroy_fn)

neptune_destroy_fn neptune_destroy_funcs[] = {
#include NEPTUNE_MODULERULES_HEADER
};

#undef NEPTUNE_MODULE
#undef NEPTUNE_MODULE_INIT
#undef NEPTUNE_MODULE_DESTROY

nerror_t neptune_init(void)
{
	size_t init_func_count =
		sizeof(neptune_init_funcs) / sizeof(*neptune_init_funcs);

	size_t i;
	for (i = 0; i < init_func_count; i++) {
		if (HAS_ERR(neptune_init_funcs[i]())) {
			nerror_t error =
				GET_ERR(NEPTUNE_INIT_ERROR + (nerror_t)i);
			neptune_destroy();
			return error;
		}
	}

	return N_OK;
}

void neptune_destroy()
{
	size_t destroy_func_count =
		sizeof(neptune_destroy_funcs) / sizeof(*neptune_destroy_funcs);

	size_t i;
	for (i = 0; i < destroy_func_count; i++)
		neptune_destroy_funcs[i]();
}

#ifdef NEPTUNE_ENABLE_MEMMEM

void *memmem_s(const void *haystack, size_t haystacklen, const void *needle,
	       size_t needlelen, size_t skip)
{
	if (haystacklen < needlelen)
		return NULL;

	const void *end = (const void *)((const int8_t *)haystack +
					 haystacklen - needlelen);
	while (haystack <= end) {
		if (memcmp(haystack, needle, needlelen) == 0)
			return (void *)haystack;

		haystack = (void *)(((int8_t *)haystack) + skip);
	}

	return NULL;
}

void *memmem_n(const void *haystack, size_t haystacklen, const void *needle,
	       size_t needlelen)
{
	return memmem_s(haystack, haystacklen, needle, needlelen, needlelen);
}

#ifdef NEPTUNE_DEFINE_MEMMEM

void *neptune_memmem(const void *haystack, size_t haystacklen,
		     const void *needle, size_t needlelen)
{
	return memmem_s(haystack, haystacklen, needle, needlelen, 1);
}

#endif /* ifdef NEPTUNE_DEFINE_MEMMEM */

#ifdef NEPTUNE_DEFINE_MEMSTR

void *neptune_memstr(const void *haystack, const char *needle,
		     size_t haystacklen)
{
	return memmem_s(haystack, haystacklen, needle, strlen(needle), 1);
}

#endif /* ifdef NEPTUNE_DEFINE_MEMSTR */

#endif /* ifdef NEPTUNE_ENABLE_MEMMEM */
