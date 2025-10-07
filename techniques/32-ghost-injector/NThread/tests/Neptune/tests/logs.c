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
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	LOG_INFO("Neptune initilaized!");

#ifdef LOG_LEVEL_1
	LOG_INFO("Test Log");

	char testlog_file[] = "testneptune.log";

#ifdef _WIN32
	wchar_t testlog_file_u[] = L"testneptune.log";
	void *reg_log_file_addr = testlog_file_u;
#else /* ifndef _WIN32 */
	void *reg_log_file_addr = testlog_file;
#endif /* ifndef _WIN32 */

	char testlog_msg[] = "neptune_reigster_log_file check!";

	if (HAS_ERR(log_reg_file(reg_log_file_addr))) {
		printf("reg_log_file failed\n");
		neptune_destroy();
		return 2;
	}

	LOG_INFO(testlog_msg);
#endif /* ifdef LOG_LEVEL_1 */

#ifdef LOG_LEVEL_1
	neptune_destroy();

	FILE *file = fopen(testlog_file, "rb");
	if (file == NULL) {
		printf("file not found\n");
		return 3;
	}

	fseek(file, 0, SEEK_END);
	long file_length = ftell(file);

	if (file_length < sizeof(testlog_msg) + 5) {
		printf("file write error\n");
		return 4;
	}

	long offset = (long)(sizeof(testlog_msg) * (-1));
	fseek(file, offset, SEEK_END);

	char buffer[sizeof(testlog_msg)];
	fread(buffer, 1, sizeof(testlog_msg), file);
	fclose(file);

	if (buffer[sizeof(buffer) - 1] != '\n') {
		printf("Invalid EOL\n");
		return 5;
	}

	buffer[sizeof(buffer) - 1] = 0;

	if (memcmp(testlog_msg, buffer, sizeof(buffer)) != 0) {
		printf("logs not equal\n");
		return 6;
	}

#endif /* ifdef LOG_LEVEL_1 */

	printf("Everything is OK!!!\n");
	return EXIT_SUCCESS;
}
