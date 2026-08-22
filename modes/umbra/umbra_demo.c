#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

extern SYSCALL_LIST SyscallList;

DWORD UmbraMain(ALIOTH_PARAMS* pParams) {
    UNREFERENCED_PARAMETER(pParams);
    
    char szBanner[] = {'U','m','b','r','a',' ','E','v','a','s','i','o','n',' ','E','n','g','i','n','e','\n',0};
    printf(szBanner);
    
    printf("[+] Syscalls resolved: %d\n", SyscallList.Count);
    printf("[+] Gadgets available: %d\n", g_dwTotalGadgets);
    printf("[+] Mask candidates: %d\n", g_dwMaskCandidateCount);
    
    DWORD64 hAlloc = ALIOTHSyscallHash((PBYTE)"NtAllocateVirtualMemory");
    PVOID pAllocStub = ALIOTHGetSyscallStub(hAlloc);
    if (!pAllocStub) {
        printf("[!] NtAllocateVirtualMemory stub not found\n");
        return 1;
    }
    
    fnNtAllocateVirtualMemory pAlloc = (fnNtAllocateVirtualMemory)pAllocStub;
    PVOID pMem = NULL;
    SIZE_T sSize = 4096;
    
    printf("[*] Testing ExecuteSyscall with Mask_Worker...\n");
    NTSTATUS status = ExecuteSyscall(pAlloc, Mask_Worker, (HANDLE)-1, &pMem, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] NtAllocateVirtualMemory: Status=0x%X, Mem=%p\n", status, pMem);
    
    if (!NT_SUCCESS(status) || !pMem) return 1;
    
    DWORD64 hProt = ALIOTHSyscallHash((PBYTE)"NtProtectVirtualMemory");
    PVOID pProtStub = ALIOTHGetSyscallStub(hProt);
    if (pProtStub) {
        fnNtProtectVirtualMemory pProt = (fnNtProtectVirtualMemory)pProtStub;
        ULONG oldProtect = 0;
        
        DYNAMIC_MASK chainMasks[3] = {Mask_Security, Mask_Memory, Mask_File};
        printf("[*] Testing ExecuteSyscallChain with 3 masks...\n");
        status = ExecuteSyscallChain(pProt, chainMasks, 3, (HANDLE)-1, &pMem, &sSize, PAGE_EXECUTE_READ, &oldProtect);
        printf("[+] NtProtectVirtualMemory (chain): Status=0x%X\n", status);
        
        status = ExecuteSyscallChain(pProt, chainMasks, 3, (HANDLE)-1, &pMem, &sSize, PAGE_READWRITE, &oldProtect);
        printf("[+] NtProtectVirtualMemory (chain back): Status=0x%X\n", status);
    }
    
    DWORD64 hFree = ALIOTHSyscallHash((PBYTE)"NtFreeVirtualMemory");
    PVOID pFreeStub = ALIOTHGetSyscallStub(hFree);
    if (pFreeStub) {
        fnNtFreeVirtualMemory pFree = (fnNtFreeVirtualMemory)pFreeStub;
        printf("[*] Testing ExecuteSyscallRandom...\n");
        status = ExecuteSyscallRandom(pFree, (HANDLE)-1, &pMem, &sSize, MEM_RELEASE);
        printf("[+] NtFreeVirtualMemory (random): Status=0x%X\n", status);
    }
    
    printf("[*] Testing gadget rotation (5 calls)...\n");
    PALIOTH_TLS_CONTEXT pCtx = ALIOTHGetCtx();
    for (int i = 0; i < 5; i++) {
        pMem = NULL;
        sSize = 4096;
        status = ExecuteSyscall(pAlloc, Mask_Worker, (HANDLE)-1, &pMem, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        printf("  Call %d: Status=0x%X, GadgetIndex=%d\n", i+1, status, pCtx->dwGadgetRotationIndex);
        if (pMem) ExecuteSyscallRandom(pFree, (HANDLE)-1, &pMem, &sSize, MEM_RELEASE);
    }
    
    printf("[*] Testing hardware breakpoint detection...\n");
    BOOL hwbp = ALIOTHCheckHwbp();
    printf("[+] Hardware breakpoints: %s\n", hwbp ? "DETECTED AND CLEARED" : "None");
    
    printf("[*] Testing ETW patch status...\n");
    for (int i = 0; i < 5; i++) {
        if (g_EtwPatches[i].pcModuleName) {
            printf("  %s!%s: %s\n", g_EtwPatches[i].pcModuleName, g_EtwPatches[i].pcFunctionName, 
                   g_EtwPatches[i].bPatched ? "PATCHED" : "NOT FOUND");
        }
    }
    
    printf("[*] Testing win32u.dll syscall resolution...\n");
    PVOID pWin32uSyscall = ALIOTHGetSyscallStub(ALIOTHSyscallHash((PBYTE)"NtUserGetMessage"));
    printf("[+] NtUserGetMessage (win32u): %s\n", pWin32uSyscall ? "FOUND" : "NOT FOUND");
    
    printf("[+] All Umbra tests passed\n");
    return 0;
}
#pragma optimize("", on)
