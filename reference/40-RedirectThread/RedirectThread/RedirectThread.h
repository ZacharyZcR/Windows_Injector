#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <memory>
#include <algorithm> // For std::find

// Include separated definitions
#include "Arguments.h"
#include "NativeAPI.h"
#include "GadgetUtil.h"
#include "NtCreateThreadUtil.h"
#include "ProcessThread.h"
#include "Injection.h" // Include core injection logic declarations

