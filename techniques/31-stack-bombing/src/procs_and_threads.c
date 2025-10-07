#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef void (WINAPI* RtlGetVersion_FUNC) (OSVERSIONINFOEXW*);

BOOL GetVersionOs(OSVERSIONINFOEX* os)
{
    HMODULE hMod;
    RtlGetVersion_FUNC func;
    OSVERSIONINFOEXW o;
    OSVERSIONINFOEXW* osw = &o;

    hMod = LoadLibraryW(L"ntdll");
    if (hMod)
    {
        func = (RtlGetVersion_FUNC)GetProcAddress(hMod, "RtlGetVersion");
        if (func == 0)
        {
            FreeLibrary(hMod);
            return FALSE;
        }
        ZeroMemory(osw, sizeof(*osw));
        osw->dwOSVersionInfoSize = sizeof(*osw);
        func(osw);

        os->dwBuildNumber = osw->dwBuildNumber;
        os->dwMajorVersion = osw->dwMajorVersion;
        os->dwMinorVersion = osw->dwMinorVersion;
        os->dwPlatformId = osw->dwPlatformId;
        os->dwOSVersionInfoSize = sizeof(*os);
    }
    else
        return FALSE;
    FreeLibrary(hMod);
    return TRUE;
}

DWORD* ListProcessThreads(DWORD dwOwnerPID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;
    DWORD i = 0;
    DWORD* threads = (DWORD*)malloc(1000*sizeof(DWORD));
    ZeroMemory(&te32, sizeof(THREADENTRY32));

    // Take a snapshot of all running threads
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return NULL;

    // Fill in the size of the structure before using it
    te32.dwSize = sizeof(THREADENTRY32);

    // Walk the thread list and find threads of target process
    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == dwOwnerPID) {
                threads[i++] = te32.th32ThreadID;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    threads[i] = 0xcafebabe; // Sentinel value
    CloseHandle(hThreadSnap);
    return threads;
}

DWORD NameToPID(const wchar_t* pProcessName)
{
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W ProcessStruct;
    ProcessStruct.dwSize = sizeof(PROCESSENTRY32W);

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return -1;

    if (Process32FirstW(hSnap, &ProcessStruct) == FALSE)
        return -1;

    do
    {
        if (wcscmp((wchar_t*)(ProcessStruct.szExeFile), pProcessName) == 0)
        {
            CloseHandle(hSnap);
            return ProcessStruct.th32ProcessID;
        }
    } while (Process32NextW(hSnap, &ProcessStruct));

    CloseHandle(hSnap);
    return -1;
}
