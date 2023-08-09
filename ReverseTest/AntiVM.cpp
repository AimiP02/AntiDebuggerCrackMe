#include "pch.h"

#include "Utils.h"
#include "AntiVM.h"

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

	GetWindowsDirectory(szWinDir, MAX_PATH);

	for (size_t i = 0; i < dwLength; i++) {
		PathCombine(szPath, szWinDir, szPaths[i]);

		if (IsFileExists(szPath)) {
			return DetectResult::HasVM;
		}
	}

	return DetectResult::NoVM;
}

DetectResult IsVMwarePresentDir() {
	TCHAR szProgramFile[MAX_PATH] = L"";
	TCHAR szPath[MAX_PATH] = L"";
	TCHAR szTarget[MAX_PATH] = L"VMWare\\";

	SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);

	return IsDirExists(szPath) ? DetectResult::HasVM : DetectResult::NoVM;
}
