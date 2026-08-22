#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

typedef struct _PHYSICAL_MEMORY_RUN {
    PVOID pVirtualAddress;
    PVOID pPhysicalAddress;
    SIZE_T dwSize;
    struct _PHYSICAL_MEMORY_RUN* pNext;
} PHYSICAL_MEMORY_RUN;

static PHYSICAL_MEMORY_RUN* g_pMemoryRuns = NULL;

BOOL WraithDriverlessInit() {
    CHAR sDevice[] = {'\\','\\','.','\\','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
    HANDLE hDevice = CreateFileA(sDevice, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CloseHandle(hDevice);
    
    g_pMemoryRuns = (PHYSICAL_MEMORY_RUN*)LocalAlloc(LPTR, sizeof(PHYSICAL_MEMORY_RUN));
    if (!g_pMemoryRuns) return FALSE;
    
    g_pMemoryRuns->pVirtualAddress = (PVOID)0x100000;
    g_pMemoryRuns->pPhysicalAddress = (PVOID)0x100000;
    g_pMemoryRuns->dwSize = 0x10000000;
    g_pMemoryRuns->pNext = NULL;
    
    return TRUE;
}

BOOL WraithDriverlessReadPhysical(PVOID pPhysicalAddr, PVOID pBuffer, DWORD dwSize) {
    CHAR sDevice[] = {'\\','\\','.','\\','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
    HANDLE hDevice = CreateFileA(sDevice, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    LARGE_INTEGER liOffset = {0};
    liOffset.QuadPart = (LONGLONG)pPhysicalAddr;
    
    BOOL bResult = FALSE;
    DWORD dwRead = 0;
    
    if (SetFilePointerEx(hDevice, liOffset, NULL, FILE_BEGIN)) {
        bResult = ReadFile(hDevice, pBuffer, dwSize, &dwRead, NULL);
    }
    
    CloseHandle(hDevice);
    return bResult && dwRead == dwSize;
}

BOOL WraithDriverlessWritePhysical(PVOID pPhysicalAddr, PVOID pBuffer, DWORD dwSize) {
    CHAR sDevice[] = {'\\','\\','.','\\','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
    HANDLE hDevice = CreateFileA(sDevice, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    LARGE_INTEGER liOffset = {0};
    liOffset.QuadPart = (LONGLONG)pPhysicalAddr;
    
    BOOL bResult = FALSE;
    DWORD dwWritten = 0;
    
    if (SetFilePointerEx(hDevice, liOffset, NULL, FILE_BEGIN)) {
        bResult = WriteFile(hDevice, pBuffer, dwSize, &dwWritten, NULL);
    }
    
    CloseHandle(hDevice);
    return bResult && dwWritten == dwSize;
}

PVOID WraithDriverlessMapPhysical(PVOID pPhysicalAddr, SIZE_T dwSize) {
    CHAR sDevice[] = {'\\','\\','.','\\','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
    HANDLE hDevice = CreateFileA(sDevice, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return NULL;
    
    LARGE_INTEGER liOffset = {0};
    liOffset.QuadPart = (LONGLONG)pPhysicalAddr.
    
    PVOID pVirtual = NULL;
    if (SetFilePointerEx(hDevice, liOffset, NULL, FILE_BEGIN)) {
        pVirtual = ALIOTHAllocVirtualMemory(dwSize, PAGE_READWRITE);
        if (pVirtual) {
            DWORD dwRead = 0;
            ReadFile(hDevice, pVirtual, (DWORD)dwSize, &dwRead, NULL);
            if (dwRead != dwSize) {
                ALIOTHFreeVirtualMemory(pVirtual, dwSize);
                pVirtual = NULL;
            }
        }
    }
    
    CloseHandle(hDevice);
    return pVirtual;
}

PVOID WraithDriverlessFindPhysical(PVOID pVirtualAddr) {
    return pVirtualAddr;
}

BOOL WraithDriverlessReadVirtual(PVOID pVirtualAddr, PVOID pBuffer, DWORD dwSize) {
    return ALIOTHReadVirtualMemory((HANDLE)-1, pVirtualAddr, pBuffer, dwSize, NULL);
}

BOOL WraithDriverlessWriteVirtual(PVOID pVirtualAddr, PVOID pBuffer, DWORD dwSize) {
    return ALIOTHWriteVirtualMemory((HANDLE)-1, pVirtualAddr, pBuffer, dwSize, NULL);
}
#pragma optimize("", on)
