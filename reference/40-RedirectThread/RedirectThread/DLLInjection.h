#pragma once
#include "Injection.h"

// Performs DLL injection using only LoadLibraryA (simpler, less common).
// Assumes the DLL is already present or accessible in the target process context.
bool InjectDllPointerOnly(const InjectionConfig &config);