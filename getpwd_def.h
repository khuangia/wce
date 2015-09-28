#pragma once
#include <Windows.h>

#include <Psapi.h>
#include <process.h>
#include <TlHelp32.h>

#include <Ntsecapi.h>

#pragma comment (lib, "Secur32.lib") 

typedef BYTE _BYTE;
typedef DWORD _DWORD;
typedef WORD _WORD;

struct REMOTE_PARAM_T {
	DWORD dwDecryptAddr;
	DWORD dwLogonSessionEntry;
	LUID LogonId;
	char szAccount[1024];
	char szDomain[1024];
	char szPassword[1024];
	DWORD SessionId;
	DWORD Retn;
};

struct INPUT_PARAM_T {

	char FuncName[1024];
	REMOTE_PARAM_T *pParam;
	size_t paramSize;
};

typedef HMODULE (WINAPI *pfn_LoadLibraryA)(LPCSTR lpFileName);
typedef FARPROC (WINAPI *pfn_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL (WINAPI *pfn_FreeLibrary)(HMODULE hModule);

typedef PVOID (__cdecl *pfn_LookupAccount)(REMOTE_PARAM_T *);

struct CREATE_THREAD_PARAM_T {

	pfn_LoadLibraryA LoadLibraryA;
	pfn_GetProcAddress GetProcAddress;
	pfn_FreeLibrary FreeLibrary;

	char DllFileName[0x400];
	char FuncName[0x400];

	REMOTE_PARAM_T *param;
	size_t paramSize;
};

typedef struct _SSP_CREDENTIAL {
	struct _SSP_CREDENTIAL *Flink;
	struct _SSP_CREDENTIAL *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	DWORD SessionId;
	LSA_UNICODE_STRING Account;
	ULONG unk1;
	ULONG unk2;
	LSA_UNICODE_STRING Domain;
	LSA_UNICODE_STRING Password;
} SSP_CREDENTIAL;

typedef struct _SSP_CREDENTIAL_XP {
	struct _SSP_CREDENTIAL_XP *Flink;
	struct _SSP_CREDENTIAL_XP *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	DWORD SessionId;
	LSA_UNICODE_STRING Account;
	LSA_UNICODE_STRING Domain;
	LSA_UNICODE_STRING Password;
} SSP_CREDENTIAL_XP; 

typedef struct _SSP_CREDENTIAL_W7 {
	struct _SSP_CREDENTIAL_W7 *Flink;
	struct _SSP_CREDENTIAL_W7 *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	DWORD unk3;
	DWORD SessionId;
	LSA_UNICODE_STRING Account;
	LSA_UNICODE_STRING Domain;
	LSA_UNICODE_STRING Password;
} SSP_CREDENTIAL_W7;              

typedef void (__stdcall *pfn_BCryptDecrypt)(wchar_t *, _DWORD);



