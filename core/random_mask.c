#include "engine.h"

#pragma optimize("", off)

typedef struct _MASK_CANDIDATE {
    PVOID pAddress;
    DWORD dwFrameSize;
    CHAR  cName[64];
} MASK_CANDIDATE;

#define MAX_MASK_CANDIDATES 256

MASK_CANDIDATE g_MaskCandidates[MAX_MASK_CANDIDATES];
DWORD g_dwMaskCandidateCount = 0;

VOID ALIOTHScanModuleForMasks(PCHAR pcModuleName) {
    HMODULE hMod = GetModuleHandleA(pcModuleName);
    if (!hMod) return;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hMod + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    if (!pExport) return;
    
    PDWORD pdwNames = (PDWORD)((PBYTE)hMod + pExport->AddressOfNames);
    PDWORD pdwFuncs = (PDWORD)((PBYTE)hMod + pExport->AddressOfFunctions);
    PWORD pwOrdinals = (PWORD)((PBYTE)hMod + pExport->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExport->NumberOfNames && g_dwMaskCandidateCount < MAX_MASK_CANDIDATES; i++) {
        PCHAR pcName = (PCHAR)((PBYTE)hMod + pdwNames[i]);
        PVOID pFunc = (PBYTE)hMod + pdwFuncs[pwOrdinals[i]];
        
        if (strstr(pcName, "Virtual") || strstr(pcName, "Alloc") || 
            strstr(pcName, "Dbg") || strstr(pcName, "Debug") ||
            strstr(pcName, "MiniDump") || strstr(pcName, "CreateProcess") ||
            strstr(pcName, "CreateRemote") || strstr(pcName, "Write") ||
            strstr(pcName, "Protect") || strstr(pcName, "Thread")) continue;
        
        USHORT prefix = *(USHORT*)pcName;
        if (prefix == 0x744E || prefix == 0x775A) continue;
        
        DWORD dwFrame = ALIOTHCalcFrameSize(pFunc);
        if (dwFrame < 0x20 || dwFrame > 0x100) continue;
        
        PVOID pRetAddr = ALIOTHSeekReturnAddress(pFunc);
        if (!pRetAddr || pRetAddr == pFunc) continue;
        
        g_MaskCandidates[g_dwMaskCandidateCount].pAddress = pRetAddr;
        g_MaskCandidates[g_dwMaskCandidateCount].dwFrameSize = dwFrame;
        strncpy_s(g_MaskCandidates[g_dwMaskCandidateCount].cName, 64, pcName, _TRUNCATE);
        g_dwMaskCandidateCount++;
    }
}

DYNAMIC_MASK GetRandomMask() {
    DYNAMIC_MASK m = {0};
    if (g_dwMaskCandidateCount == 0) {
        m = Mask_Worker;
        return m;
    }
    DWORD idx = rand() % g_dwMaskCandidateCount;
    m.pAddress = g_MaskCandidates[idx].pAddress;
    m.dwFrameSize = g_MaskCandidates[idx].dwFrameSize;
    return m;
}
#pragma optimize("", on)
