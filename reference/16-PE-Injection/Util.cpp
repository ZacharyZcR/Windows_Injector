//By AlSch092 @ github
#include "Util.hpp"

int g_minPacketLength = 5;

int GetPacketLength(const char* input)
{
	int length = 0;

	for (int i = 0; input[i] != '\0'; i++) {
		if (input[i] == ' ') //spaces don't increase length
			length = length;
		else
			length++;
	}

	length = length / 2;

	return length;
}

char* PacketToString(LPBYTE packetStr, int byteLength)
{
	if (byteLength < g_minPacketLength || byteLength > 2000 || packetStr == NULL)
		return "";

	typedef int(*_sprintf)(char* dest, const char* format, ...);
	_sprintf __sprintf;
	UINT64 _addr = (UINT64)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "sprintf"); //LotL concept, grab addresses at runtime 

	if (!_addr)
		return NULL;

	__sprintf = (_sprintf)_addr;

	typedef void*(*_malloc)(size_t size);
	_malloc __malloc;
	_addr = (UINT64)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "malloc");  //LotL concept, grab addresses at runtime 

	if (!_addr)
		return NULL;

	__malloc = (_malloc)_addr;

	char* newStr = (CHAR*)__malloc((byteLength * 3) + 1); //* 3 since 00[ ] an extra 0 with a space for each byte in the str.
	char convertStr[10] = { 0 };

	for (int i = 0; i < byteLength; i++)
	{
		byte ch = packetStr[i];
		__sprintf(&convertStr[0], "%.2X", ch);
		strcat(newStr, &convertStr[0]);
		strcat(newStr, " ");
	}

	return newStr;
}

void WriteHexString(const char* filePath, LPBYTE hexString)
{
	if (filePath == NULL || hexString == NULL)
		return;

	HANDLE hFile = CreateFileA(filePath, FILE_APPEND_DATA, FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD bytesWritten;
		WriteFile(hFile, hexString, sizeof(hexString), &bytesWritten, nullptr);
		WriteFile(hFile, "\r\n", 4, &bytesWritten, nullptr);
		CloseHandle(hFile);
	}
}

void WriteHexString(const char* filePath, char* hexString)
{
	if (filePath == NULL || hexString == NULL)
		return;

	HANDLE hFile = CreateFileA(filePath, FILE_APPEND_DATA, FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD bytesWritten;
		WriteFile(hFile, hexString, strlen(hexString), &bytesWritten, nullptr);
		WriteFile(hFile, "\r\n", 4, &bytesWritten, nullptr);
		CloseHandle(hFile);
	}
}

DWORD GetTargetThreadIDFromProcName(const wchar_t * ProcName) //get pid from executable/process name
{
	PROCESSENTRY32W pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;

	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		printf("Error: Unable to create toolhelp snapshot!");
		return 0;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32FirstW(thSnapShot, &pe);
	while (retval)
	{
		if (wcscmp(pe.szExeFile, ProcName) == 0)
			return pe.th32ProcessID;

		retval = Process32NextW(thSnapShot, &pe);
	}

	return 0;
}