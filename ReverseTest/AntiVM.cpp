#include "pch.h"

#include "AntiVM.h"
#include <iostream>

DetectResult IsVMwarePresentFiles() {
	const TCHAR* szPaths[] = {
		_T("System32\\drivers\\vmnet.sys"),
		_T("System32\\drivers\\vmmouse.sys"),
		_T("System32\\drivers\\vmusb.sys"),
		_T("System32\\drivers\\vm3dmp.sys"),
		_T("System32\\drivers\\vmci.sys"),
		_T("System32\\drivers\\vmhgfs.sys"),
		_T("System32\\drivers\\vmmemctl.sys"),
		_T("System32\\drivers\\vmx86.sys"),
		_T("System32\\drivers\\vmrawdsk.sys"),
		_T("System32\\drivers\\vmusbmouse.sys"),
		_T("System32\\drivers\\vmkdb.sys"),
		_T("System32\\drivers\\vmnetuserif.sys"),
		_T("System32\\drivers\\vmnetadapter.sys"),
	};

	WORD dwLength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = L"";
	TCHAR szPath[MAX_PATH] = L"";
	PVOID OldValue = NULL;

	GetWindowsDirectoryW(szWinDir, MAX_PATH);

	for (size_t i = 0; i < dwLength; i++) {
		std::wcout << szPath << std::endl;

		if (IsFileExists(szPath)) {
			return DetectResult::HasVM;
		}
	}

	return DetectResult::NoVM;
}

DetectResult IsVMwarePresentDirectory() {
	TCHAR szProgramFile[MAX_PATH] = L"";
	TCHAR szPath[MAX_PATH] = L"";
	TCHAR szTarget[MAX_PATH] = L"VMWare\\";

	SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombineW(szPath, szProgramFile, szTarget);

	return IsDirExists(szPath) ? DetectResult::HasVM : DetectResult::NoVM;
}

DetectResult IsVMwarePresentProcess() {
	const TCHAR* szProcesses[] = {
		_T("vmtoolsd.exe"),
		_T("vmwaretray.exe"),
		_T("vmwareuser.exe"),
		_T("VGAuthService.exe"),
		_T("vmacthlp.exe"),
	};

	WORD dwLength = sizeof(szProcesses) / sizeof(szProcesses[0]);

	for (size_t i = 0; i < dwLength; i++) {
		if (IsProcessExists(szProcesses[i])) {
			return DetectResult::HasVM;
		}
	}
	return DetectResult();
}

DetectResult IsVMwarePresentCPUID() {
	int Reg[4], FunctionId = 1;
	__cpuid(Reg, FunctionId);
	return (Reg[2] & 0x80000000) ? DetectResult::HasVM : DetectResult::NoVM;
}
