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
