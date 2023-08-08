#include "pch.h"
#include "AntiDebugger.h"

DetectResult IsDebuggerPresentPEB() {
	PPEB pPEB = GetPEB();

	return pPEB->BeingDebugged == 1 ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentNtGlobalFlag() {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return DetectResult::Unknown;
	}

	typedef ULONG(*pFnRtlGetNtGlobalFlags)(VOID);

	pFnRtlGetNtGlobalFlags pRtlGetNtGlobalFlags = (pFnRtlGetNtGlobalFlags)GetProcAddress(hNtdll, "RtlGetNtGlobalFlags");

	ULONG NtGlobalFlags = pRtlGetNtGlobalFlags();

	return NtGlobalFlags & 0x70 ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentHeapFlags() {
	PPEB pPEB = GetPEB();


	return DetectResult::HasDebugger;
}
