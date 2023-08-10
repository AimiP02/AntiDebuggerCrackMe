#pragma once

#include "pch.h"
#include "Utils.h"

extern "C" int GetCPUID();

DetectResult IsVMwarePresentFiles();
DetectResult IsVMwarePresentDirectory();
DetectResult IsVMwarePresentProcess();
DetectResult IsVMwarePresentCPUID();