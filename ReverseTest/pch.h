#pragma once

#include <string>
#include <vector>
#include <filesystem>

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <IPTypes.h>
#include <Iphlpapi.h>
#include <icmpapi.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <stdarg.h>
#include <strsafe.h>
#include <tchar.h>
#include <time.h>
#include <TlHelp32.h>
#include <Wbemidl.h>
#include <devguid.h>    // Device guids
#include <winioctl.h>	// IOCTL
#include <intrin.h>		// cpuid()
#include <locale.h>		// 64-bit wchar atoi
#include <powrprof.h>	// check_power_modes()
#include <SetupAPI.h>
#include <algorithm>
#include <cctype>
#include <slpublic.h> // SLIsGenuineLocal

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "Slwga.lib")

enum class DetectResult : int16_t {
	HasDebugger,
	HasVM,
	NoDebugger,
	NoVM,
	Unknown
};