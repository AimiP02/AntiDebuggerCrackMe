#pragma once

#include "pch.h"
#include "Utils.h"

DetectResult IsDebuggerPresentPEB();
DetectResult IsDebuggerPresentNtGlobalFlag();
DetectResult IsDebuggerPresentHeapFlags();