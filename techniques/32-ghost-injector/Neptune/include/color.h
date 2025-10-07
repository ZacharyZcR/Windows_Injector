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

#ifndef __COLOR_H__
#define __COLOR_H__

typedef const char *color_t;

#define COLOR_RESET ((color_t) "\033[0m")
#define COLOR_BLACK ((color_t) "\033[0;30m")
#define COLOR_RED ((color_t) "\033[0;31m")
#define COLOR_GREEN ((color_t) "\033[0;32m")
#define COLOR_YELLOW ((color_t) "\033[0;33m")
#define COLOR_BLUE ((color_t) "\033[0;34m")
#define COLOR_MAGENTA ((color_t) "\033[0;35m")
#define COLOR_CYAN ((color_t) "\033[0;36m")
#define COLOR_WHITE ((color_t) "\033[0;37m")

#define COLOR_BOLD_BLACK ((color_t) "\033[1;30m")
#define COLOR_BOLD_RED ((color_t) "\033[1;31m")
#define COLOR_BOLD_GREEN ((color_t) "\033[1;32m")
#define COLOR_BOLD_YELLOW ((color_t) "\033[1;33m")
#define COLOR_BOLD_BLUE ((color_t) "\033[1;34m")
#define COLOR_BOLD_MAGENTA ((color_t) "\033[1;35m")
#define COLOR_BOLD_CYAN ((color_t) "\033[1;36m")
#define COLOR_BOLD_WHITE ((color_t) "\033[1;37m")

#endif // !__COLOR_H__
