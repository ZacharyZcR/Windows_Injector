#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>

#include "Arguments.h"

bool ValidateTargetProcess(DWORD pid, bool verbose);
bool ValidateTargetThread(DWORD tid, bool verbose);
bool LoadShellcode(const std::string &filepath, std::vector<unsigned char> &bytes);
bool LoadShellcodeEx(const InjectionConfig &config, std::vector<unsigned char> &shellcodeBytes);