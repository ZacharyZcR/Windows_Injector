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

#ifndef __NTHREADOSUTILS_H__
#define __NTHREADOSUTILS_H__

#include "ntutils.h"
#include "neptune.h"

#ifdef __WIN32
#include "ntosutilswin.h"
#endif // __WIN32

#ifndef RET_OPCODE
#define RET_OPCODE ((uint8_t)0xC3)
#endif // !RET_OPCODE

#ifndef PUSH_OPCODE_BASE_INDEX
#define PUSH_OPCODE_BASE_INDEX(reg_index) ((uint8_t)(reg_index + 0x50))
#endif // !PUSH_OPCODE_BASE_INDEX

#ifndef PUSH_OPCODE_FROM_INDEX

#define PUSH_OPCODE_FROM_INDEX(reg_index)                                 \
	((reg_index >= 8) ?                                               \
		 ((PUSH_OPCODE_BASE_INDEX(reg_index - 8) << 16) + 0x41) : \
		 PUSH_OPCODE_BASE_INDEX(reg_index))

#endif // ! PUSH_OPCODE_FROM_INDEX

#ifndef PUSH_RBX_OPCODE
#define PUSH_RBX_OPCODE PUSH_OPCODE_FROM_INDEX(NTHREAD_RBX_INDEX)
#endif // !PUSH_RBX_OPCODE

#ifndef PUSH_RBP_OPCODE
#define PUSH_RBP_OPCODE PUSH_OPCODE_FROM_INDEX(NTHREAD_RBP_INDEX)
#endif // !PUSH_RBP_OPCODE

#ifndef PUSH_RDI_OPCODE
#define PUSH_RDI_OPCODE PUSH_OPCODE_FROM_INDEX(NTHREAD_RDI_INDEX)
#endif // !PUSH_RDI_OPCODE

#ifndef PUSH_RSI_OPCODE
#define PUSH_RSI_OPCODE PUSH_OPCODE_FROM_INDEX(NTHREAD_RSI_INDEX)
#endif // !PUSH_RSI_OPCODE

#define RET_OPCODE_HELPER ((uint16_t)(RET_OPCODE << 0x08))

#ifndef PUSH_RBX_RET_OPCODE
#define PUSH_RBX_RET_OPCODE (RET_OPCODE_HELPER + PUSH_RBX_OPCODE)
#endif // !PUSH_RBX_RET_OPCODE

#ifndef PUSH_RBP_RET_OPCODE
#define PUSH_RBP_RET_OPCODE (RET_OPCODE_HELPER + PUSH_RBP_OPCODE)
#endif // !PUSH_RBP_RET_OPCODE

#ifndef PUSH_RDI_RET_OPCODE
#define PUSH_RDI_RET_OPCODE (RET_OPCODE_HELPER + PUSH_RDI_OPCODE)
#endif // !PUSH_RDI_RET_OPCODE

#ifndef PUSH_RSI_RET_OPCODE
#define PUSH_RSI_RET_OPCODE (RET_OPCODE_HELPER + PUSH_RSI_OPCODE)
#endif // !PUSH_RSI_RET_OPCODE

#define REG_OFFSET_FROM_PUSH_RET_OPCODE(opcode) \
	(NTHREAD_REG_INDEX_TO_OFFSET((uint8_t)((opcode - 0x50))))

#ifndef SLEEP_OPCODE
#define SLEEP_OPCODE ((uint16_t)0xFEEB)
#endif // !SLEEP_OPCODE

#define NTOSUTILS_ERROR 0x1100
#define NTOSUTILS_FIND_PUSH_RET_GADGET_ERROR 0x1101
#define NTOSUTILS_TEST_ERROR 0x1102
#define NTOSUTILS_DUMMY_PROCESS_ERROR 0x1103
#define NTOSUTILS_NOSU_INIT_ERROR 0x1104
#define NTOSUTILS_ALLOC_ERROR 0x1105

extern void *NTHREAD_API nosu_push_addr;
extern void *NTHREAD_API nosu_sleep_addr;
extern nthread_reg_offset_t NTHREAD_API nosu_push_offset;

extern uint16_t NTHREAD_API nosu_sleep_opcode;
extern uint16_t NTHREAD_API nosu_push_ret_opcode;

nerror_t NTHREAD_API nosu_global_init();

void *NTHREAD_API find_gadget(uint16_t opcode);

nerror_t NTHREAD_API nosu_init_ex(nthread_t *nthread, ntid_t thread_id,
				  nthread_flags_t flags);

nerror_t NTHREAD_API nosu_init(nthread_t *nthread, ntid_t thread_id);

nerror_t NTHREAD_API nosu_attach(ntid_t thread_id);

#ifdef NTOSUTILS_TEST

bool NTHREAD_API nosu_test();

#endif // NTOSUTILS_TEST

typedef bool (*nosu_thread_callback_t)(ntid_t thread_id, void *param);

uint16_t NTHREAD_API nosu_foreach_threads(DWORD pid,
					  nosu_thread_callback_t callback,
					  void *param);

uint16_t NTHREAD_API nosu_get_threads_ex(DWORD pid, ntid_t **thread_ids,
					 size_t *thread_ids_size);

ntid_t *NTHREAD_API nosu_get_threads(DWORD pid, uint16_t *thread_id_count);

#endif // !__NTHREADOSUTILS_H__
