#pragma once

#include "pch.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((DWORD)0xC0000004L)
#endif

#ifndef STATUS_DATATYPE_MISALIGNMENT
#define STATUS_DATATYPE_MISALIGNMENT ((DWORD)0x80000002L)
#endif

typedef ULONG(*pFnRtlGetNtGlobalFlags)(VOID);
typedef NTSTATUS(NTAPI* pFnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pFnNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pFnNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

PPEB GetPEB();
pFnNtQueryInformationProcess GetNtQueryInformationProcess();
pFnNtSetInformationThread GetNtSetInformationThread();
pFnNtQueryInformationThread GetNtQueryInformationThread();

BOOL IsFileExists(TCHAR* szPath);
BOOL IsDirExists(TCHAR* szPath);