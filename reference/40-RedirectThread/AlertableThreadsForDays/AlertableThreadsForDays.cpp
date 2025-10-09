#include <windows.h>
#include <stdio.h>
#include <immintrin.h>   // for _mm_pause / YieldProcessor

#define THREAD_COUNT 10

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    DWORD tid = GetCurrentThreadId();
    printf("Thread %lu started\n", tid);

    while (1) {
        // APC APC APC
        DWORD result = SleepEx(INFINITE, TRUE);
        if (result == WAIT_IO_COMPLETION) {
            printf("Thread %lu woke due to APC\n", tid);
        }
    }

    return 0;
}

// Worker thread non alertable
// Can be APC'd with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC -> https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
DWORD WINAPI WorkerThreadNonAlertable(LPVOID)
{
    DWORD tid = GetCurrentThreadId();
    printf("Non-alertable thread %lu started\n", tid);

    for (;;)
        _mm_pause();     // or YieldProcessor(); // or SwitchToThread();   // quick yield, non?alertable

    return 0;
}

/* --------------------  ROP gadget section  -------------------- *
 * We emit: 50 53 C3  ->  push rax  /  push rbx  /  ret
 * Change the opcodes if you want different registers, e.g.
 *   push rcx = 51,      push rdx = 52,      push rdi = 57
 *
 * The pragma makes a new executable/read?only section (.rop$A);
 * __declspec(allocate) places our byte array there.
 * The volatile reference forces the linker to keep the symbol
 * even under /OPT:REF or /Gy (function?level linking).
 */
#pragma section(".rop$A", execute, read)        // executable = .text
__declspec(allocate(".rop$A"))
const unsigned char g_pushrax_pushrbx_ret[3] = { 0x50, 0x53, 0xC3 };

volatile const void* const g_gadget_ref = g_pushrax_pushrbx_ret;
/* -------------------------------------------------------------- */

// Example APC function
VOID CALLBACK ExampleAPC(ULONG_PTR dwParam) {
    printf("APC executed in thread %lu with param: %llu\n", GetCurrentThreadId(), (unsigned long long)dwParam);
}

int main() {
    HANDLE threads[THREAD_COUNT];

    printf("Process PID: %lu\n", GetCurrentProcessId());

    // Spawn 10 worker threads
    for (int i = 0; i < THREAD_COUNT; ++i) {
        threads[i] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        if (!threads[i]) {
            printf("Failed to create thread %d\n", i);
        }
    }

    // Spawn 1 thread non-alertable
	HANDLE nonAlertableThread = CreateThread(NULL, 0, WorkerThreadNonAlertable, NULL, 0, NULL);

    // Main loop: queue an APC every 5 seconds to a random thread
    while (1) {
        Sleep(5000);

        int target = rand() % THREAD_COUNT;
        printf("Queuing APC to thread[%d]\n", target);
        QueueUserAPC(ExampleAPC, threads[target], (ULONG_PTR)(target + 1));
    }

    // Main thread just waits forever
    WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, INFINITE);

    return 0;
}
