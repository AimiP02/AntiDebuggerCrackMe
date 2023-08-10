#include "pch.h"

#include "Utils.h"

PPEB GetPEB() {
	PPEB pPEB = (PPEB)__readgsqword(0x60);

	return pPEB;
}

template<typename T>
T GetFunc(HMODULE hModule, const char* szFuncName) {
	if (hModule == NULL) {
		return nullptr;
	}

	T pFunc = (T)GetProcAddress(hModule, szFuncName);
	if (pFunc == NULL) {
		return nullptr;
	}

	return pFunc;
}

pFnNtQueryInformationProcess GetNtQueryInformationProcess() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	
	return GetFunc<pFnNtQueryInformationProcess>(hNtdll, "NtQueryInformationProcess");
}

pFnNtSetInformationThread GetNtSetInformationThread() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	
	return GetFunc<pFnNtSetInformationThread>(hNtdll, "NtSetInformationThread");
}

pFnNtQueryInformationThread GetNtQueryInformationThread() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	
	return GetFunc<pFnNtQueryInformationThread>(hNtdll, "NtQueryInformationThread");
}

BOOL IsFileExists(const TCHAR* szPath) {
	DWORD dwAttr = GetFileAttributes(szPath);
	return (dwAttr != INVALID_FILE_ATTRIBUTES && !(dwAttr & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsDirExists(const TCHAR* szPath) {
	DWORD dwAttr = GetFileAttributes(szPath);
	return (dwAttr != INVALID_FILE_ATTRIBUTES && (dwAttr & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsProcessExists(const TCHAR* szProcessName) {
	PROCESSENTRY32 ProcEntry;

	ProcEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	do {
		if (_tcsicmp(ProcEntry.szExeFile, szProcessName) == 0) {
			CloseHandle(hSnapshot);
			return TRUE;
		}
	} while (Process32Next(hSnapshot, &ProcEntry));
	return 0;
}
