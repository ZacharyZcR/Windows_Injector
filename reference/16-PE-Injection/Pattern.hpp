//By AlSch092 @ github
#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Psapi.h>

UINT64 FindRemotePattern(const unsigned char* pattern, int length, const wchar_t* procName);