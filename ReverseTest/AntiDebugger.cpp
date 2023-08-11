#include "pch.h"
#include "AntiDebugger.h"
#include "Utils.h"

DetectResult IsDebuggerPresentPEB() {
	PPEB pPEB = GetPEB();

	return pPEB->BeingDebugged == 1 ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentNtGlobalFlag() {
	PPEB pPEB = GetPEB();

	PDWORD pNtGlobalFlags = (PDWORD)((PBYTE)pPEB + 0xBC);

	return (pNtGlobalFlags && (*pNtGlobalFlags & 0x70)) ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentHeapFlags() {
	PPEB pPEB = GetPEB();

	PVOID pHeap = *(PVOID*)((PBYTE)pPEB + 0x30);
	PDWORD pFlag = (PDWORD)((PBYTE)pHeap + 0x70);
	PDWORD pForceFlag = (PDWORD)((PBYTE)pHeap + 0x74);
	
	return (*pFlag & ~HEAP_GROWABLE || *pForceFlag != 0) ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentCheckRemoteDebuggerPresent() {
	BOOL IsRemoteDebuggerPresent = FALSE;

	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &IsRemoteDebuggerPresent)) {
		return IsRemoteDebuggerPresent ? DetectResult::HasDebugger : DetectResult::NoDebugger;
	}

	return DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentProcessDebugPort() {
	pFnNtQueryInformationProcess pNtQueryInformationProcess = GetNtQueryInformationProcess();
	if (pNtQueryInformationProcess == nullptr) {
		return DetectResult::Unknown;
	}
	
	DWORD IsDebuggerPresent = FALSE;
	NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &IsDebuggerPresent, sizeof(DWORD) * 2, NULL);
	
	return (status == 0 && IsDebuggerPresent) ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentProcessBasicInformation() {
	pFnNtQueryInformationProcess pNtQueryInformationProcess = GetNtQueryInformationProcess();
	if (pNtQueryInformationProcess == nullptr) {
		return DetectResult::Unknown;
	}

	PROCESS_BASIC_INFORMATION Info;
	NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &Info, sizeof(DWORD) * 2, NULL);

	if (status == 0) {
		HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcSnap == INVALID_HANDLE_VALUE) {
			return DetectResult::Unknown;
		}

		PROCESSENTRY32 ProcEntry;
		ProcEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hProcSnap, &ProcEntry)) {
			do {
				if (ProcEntry.th32ProcessID == Info.UniqueProcessId) {
					if (wcscmp(ProcEntry.szExeFile, L"x64dbg.exe") == 0 ||
						wcscmp(ProcEntry.szExeFile, L"ollydbg.exe") == 0 ||
						wcscmp(ProcEntry.szExeFile, L"ida64.exe") == 0 ||
						wcscmp(ProcEntry.szExeFile, L"DbgX.Shell.exe") == 0 ||
						wcscmp(ProcEntry.szExeFile, L"windbg.exe") == 0) {
						CloseHandle(hProcSnap);
						return DetectResult::HasDebugger;
					}
				}
			} while (Process32Next(hProcSnap, &ProcEntry));
		}
	}

	return DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentProcessDebugFlags() {
	pFnNtQueryInformationProcess pNtQueryInformationProcess = GetNtQueryInformationProcess();
	if (pNtQueryInformationProcess == nullptr) {
		return DetectResult::Unknown;
	}

	const int ProcessDebugFlags = 0x1F;
	DWORD IsDebuggerPresent = FALSE;
	NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugFlags, &IsDebuggerPresent, sizeof(DWORD) * 2, NULL);
	
	return (status == 0 && IsDebuggerPresent) ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentProcessDebugObjectHandle() {
	pFnNtQueryInformationProcess pNtQueryInformationProcess = GetNtQueryInformationProcess();
	if (pNtQueryInformationProcess == nullptr) {
		return DetectResult::Unknown;
	}

	const int ProcessDebugObjectHandle = 0x1E;
	DWORD IsDebuggerPresent = FALSE;
	NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &IsDebuggerPresent, sizeof(DWORD) * 2, NULL);

	return (status == 0 && IsDebuggerPresent) ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentHideFromDebugger() {
	struct AlignedBool {
		alignas(4) bool Value;
	};

	auto pNtSetInformationThread = GetNtSetInformationThread();
	if (pNtSetInformationThread == nullptr) {
		return DetectResult::Unknown;
	}

	auto pNtQueryInformationThread = GetNtQueryInformationThread();
	if (pNtQueryInformationThread == nullptr) {
		return DetectResult::Unknown;
	}

	AlignedBool IsThreadHidden;
	IsThreadHidden.Value = false;

	const int HideFromDebugger = 0x11;

	// Check Hook
	NTSTATUS status = pNtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)HideFromDebugger, &IsThreadHidden, 12345);

	if (status == 0)
		return DetectResult::HasDebugger;

	status = pNtSetInformationThread((HANDLE)0xFFFF, (THREADINFOCLASS)HideFromDebugger, NULL, 0);

	if (status == 0)
		return DetectResult::HasDebugger;

	status = pNtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)HideFromDebugger, NULL, 0);

	if (status == 0) {
		status = pNtQueryInformationThread(GetCurrentThread(), (THREADINFOCLASS)HideFromDebugger, &IsThreadHidden.Value, sizeof(bool), NULL);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
			return DetectResult::HasDebugger;

		if (status == 0) {
			AlignedBool BogusIsThreadHidden;
			BogusIsThreadHidden.Value = false;

			status = pNtQueryInformationThread(GetCurrentThread(), (THREADINFOCLASS)HideFromDebugger, &BogusIsThreadHidden.Value, sizeof(BOOL), NULL);

			if (status != STATUS_INFO_LENGTH_MISMATCH)
				return DetectResult::HasDebugger;

			const size_t UnalignedCheckCount = 8;
			bool BogusUnalignedValues[UnalignedCheckCount];
			int AlignmentErrorCount = 0;

			const size_t MaxAlignmentCheckSuccessCount = 2;

			for (size_t i = 0; i < UnalignedCheckCount; i++) {
				status = pNtQueryInformationThread(GetCurrentThread(), (THREADINFOCLASS)HideFromDebugger, &BogusUnalignedValues[i], sizeof(BOOL), NULL);
				if (status == STATUS_DATATYPE_MISALIGNMENT) {
					AlignmentErrorCount++;
				}
			}

			if (UnalignedCheckCount - AlignmentErrorCount > MaxAlignmentCheckSuccessCount)
				return DetectResult::HasDebugger;
			
			return IsThreadHidden.Value ? DetectResult::NoDebugger : DetectResult::HasDebugger;
		}
	}
	else {
		return DetectResult::HasDebugger;
	}

	return DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentHardwareDebugRegisters() {
	CONTEXT Ctx;
	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(GetCurrentThread(), &Ctx)) {
		if (Ctx.Dr0 != 0 || Ctx.Dr1 != 0 || Ctx.Dr2 != 0 || Ctx.Dr3 != 0) {
			return DetectResult::HasDebugger;
		}
	}
	return DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentSoftwareBreakpoints(PBYTE Addr) {
	return (*Addr == 0xCC) ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

DetectResult IsDebuggerPresentOutputDebugString() {
	DWORD IsDebuggerPresent = FALSE;

	DWORD Val = 0x29A;

	SetLastError(Val);
	OutputDebugString(L"HelloHacker;)");
	if (GetLastError() == Val) {
		IsDebuggerPresent = TRUE;
	}

	return IsDebuggerPresent ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}


static BOOL SwallowedException3 = TRUE;
static BOOL SwallowedException2d = TRUE;

static LONG CALLBACK VectoredHandler3(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
	SwallowedException3 = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		ExceptionInfo->ContextRecord->Rip++;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

DetectResult IsDebuggerPresentVEH3() {
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler3);
	SwallowedException3 = TRUE;

	__debugbreak();

	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException3 ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}

static LONG CALLBACK VectoredHandler2d(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
	SwallowedException2d = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

DetectResult IsDebuggerPresentVEH2D() {
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler2d);
	SwallowedException2d = TRUE;

	__int2d();

	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException2d ? DetectResult::HasDebugger : DetectResult::NoDebugger;
}