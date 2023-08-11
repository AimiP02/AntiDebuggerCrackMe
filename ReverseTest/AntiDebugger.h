#pragma once

#include "pch.h"
#include "Utils.h"

extern "C" void __int2d();

DetectResult IsDebuggerPresentPEB();
DetectResult IsDebuggerPresentNtGlobalFlag();
DetectResult IsDebuggerPresentHeapFlags();
DetectResult IsDebuggerPresentCheckRemoteDebuggerPresent();

DetectResult IsDebuggerPresentProcessDebugPort();
DetectResult IsDebuggerPresentProcessBasicInformation();
DetectResult IsDebuggerPresentProcessDebugObjectHandle();
DetectResult IsDebuggerPresentProcessDebugFlags();

DetectResult IsDebuggerPresentVEH3();
DetectResult IsDebuggerPresentVEH2D();
DetectResult IsDebuggerPresentOutputDebugString();

DetectResult IsDebuggerPresentHardwareDebugRegisters();

DetectResult IsDebuggerPresentSoftwareBreakpoints(PBYTE Addr);

void IsDebuggerPresentHideFromDebugger();