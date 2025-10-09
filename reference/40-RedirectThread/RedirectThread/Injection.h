#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

#include "Arguments.h"
#include "ProcessThread.h"
#include "GadgetUtil.h"
#include "Helpers.h"

#include "NtCreateThreadUtil.h"
#include "APCInjection.h"
#include "DLLInjection.h"
#include "CreateRemoteThreadUtil h"

bool Inject(const InjectionConfig &config);

