#include "..\..\core\ALIOTH.h"

#pragma optimize("", off)

BOOL WraithDumpEncrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, PBYTE pNonce, PBYTE pTag) {
    UINT32 state[16] = {0};
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    
    for (int i = 0; i < 8; i++) {
        state[4 + i] = *(UINT32*)(pKey + i * 4);
    }
    
    state[12] = 0;
    state[13] = 0;
    state[14] = *(UINT32*)pNonce;
    state[15] = *(UINT32*)(pNonce + 4);
    
    PBYTE pOutput = pData;
    for (DWORD i = 0; i < dwSize; i += 64) {
        UINT32 working[16];
        memcpy(working, state, 64);
        
        #define QUARTERROUND(a,b,c,d) \
            working[a] += working[b]; working[d] ^= working[a]; working[d] = (working[d] << 16) | (working[d] >> 16); \
            working[c] += working[d]; working[b] ^= working[c]; working[b] = (working[b] << 12) | (working[b] >> 20); \
            working[a] += working[b]; working[d] ^= working[a]; working[d] = (working[d] << 8) | (working[d] >> 24); \
            working[c] += working[d]; working[b] ^= working[c]; working[b] = (working[b] << 7) | (working[b] >> 25);
        
        for (int r = 0; r < 10; r++) {
            QUARTERROUND(0,4,8,12); QUARTERROUND(1,5,9,13); QUARTERROUND(2,6,10,14); QUARTERROUND(3,7,11,15);
            QUARTERROUND(0,5,10,15); QUARTERROUND(1,6,11,12); QUARTERROUND(2,7,8,13); QUARTERROUND(3,4,9,14);
        }
        
        for (int j = 0; j < 16; j++) working[j] += state[j];
        
        DWORD dwChunk = min(64, dwSize - i);
        for (DWORD k = 0; k < dwChunk; k++) {
            pOutput[i + k] ^= ((PBYTE)working)[k];
        }
        
        state[12]++;
        if (state[12] == 0) state[13]++;
    }
    
    memset(pTag, 0, 16);
    return TRUE;
}

BOOL WraithDumpDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, PBYTE pNonce, PBYTE pTag) {
    return WraithDumpEncrypt(pData, dwSize, pKey, pNonce, pTag);
}
#pragma optimize("", on)
