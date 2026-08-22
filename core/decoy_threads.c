#include "engine.h"

#pragma optimize("", off)

#define DECOY_THREAD_COUNT 4

DWORD WINAPI DecoyThreadWorker(LPVOID lpParam) {
    DWORD dwId = (DWORD)(ULONG_PTR)lpParam;
    
    while (TRUE) {
        switch (dwId % 4) {
            case 0: {
                HKEY hKey;
                RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", 0, KEY_READ, &hKey);
                if (hKey) RegCloseKey(hKey);
                Sleep(500 + (rand() % 500));
                break;
            }
            case 1: {
                GetTickCount();
                Sleep(1000 + (rand() % 1000));
                break;
            }
            case 2: {
                Sleep(2000 + (rand() % 2000));
                break;
            }
            case 3: {
                WIN32_FIND_DATAA ffd;
                HANDLE hFind = FindFirstFileA("C:\\Users\\*", &ffd);
                if (hFind) FindClose(hFind);
                Sleep(3000 + (rand() % 3000));
                break;
            }
        }
    }
    return 0;
}

VOID ALIOTHStartDecoys() {
    for (DWORD i = 0; i < DECOY_THREAD_COUNT; i++) {
        HANDLE hThread = CreateThread(NULL, 0, DecoyThreadWorker, (LPVOID)(ULONG_PTR)i, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
}
#pragma optimize("", on)
