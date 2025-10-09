//By AlSch092 @ github
#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <tlhelp32.h> 

int GetPacketLength(const char* input);
char* PacketToString(LPBYTE packetStr, int byteLength);
void WriteHexString(const char* filePath, LPBYTE hexString);
void WriteHexString(const char* filePath, char* hexString);

DWORD GetTargetThreadIDFromProcName(const wchar_t * ProcName);