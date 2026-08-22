#pragma once

#include <windows.h>
#include "ALIOTH_config.h"

#define ALIOTH_MAX_GADGETS 8
#define ALIOTH_MAX_CHAIN_DEPTH 8

typedef struct _ALIOTH_GADGET_ENTRY {
    PVOID pGadgetAddress;
    DWORD dwGadgetType;
    DWORD dwFrameSize;
    DWORD64 dwModuleBase;
} ALIOTH_GADGET_ENTRY, *PALIOTH_GADGET_ENTRY;

typedef struct _ALIOTH_TLS_CONTEXT {
    PVOID   qTableAddr;
    PVOID   qGadgetAddress;
    DWORD   qGadgetType;
    DWORD   qFrameSize;
    PVOID   qSavedReg;
    PVOID   qSavedRetAddr;
    PVOID   qActiveMaskAddress;
    PVOID   qThreadBase;
    PVOID   qRtlUserThreadStart;
    DWORD   qActiveMaskFrame;
    DWORD   qThreadBaseFrame;
    DWORD   qRtlUserThreadStartFrame;

    DWORD   dwGadgetRotationIndex;
    BYTE    bSsnXorKey;
    DWORD   dwDecoyThreadId;

    DWORD   dwChainDepth;
    PVOID   pChainMasks[ALIOTH_MAX_CHAIN_DEPTH];
    DWORD   dwChainFrames[ALIOTH_MAX_CHAIN_DEPTH];

    ALIOTH_GADGET_ENTRY Gadgets[ALIOTH_MAX_GADGETS];
    DWORD   dwGadgetCount;

    BOOL    bInitialized;
    DWORD   dwThreadId;
} ALIOTH_TLS_CONTEXT, *PALIOTH_TLS_CONTEXT;

static DWORD g_dwTlsIndex = TLS_OUT_OF_INDEXES;

__forceinline BOOL ALIOTHTlsInit() {
    if (g_dwTlsIndex == TLS_OUT_OF_INDEXES) {
        g_dwTlsIndex = TlsAlloc();
        if (g_dwTlsIndex == TLS_OUT_OF_INDEXES) return FALSE;
    }
    PALIOTH_TLS_CONTEXT pCtx = (PALIOTH_TLS_CONTEXT)LocalAlloc(LPTR, sizeof(ALIOTH_TLS_CONTEXT));
    if (!pCtx) return FALSE;
    pCtx->dwThreadId = GetCurrentThreadId();
    pCtx->bInitialized = TRUE;
    TlsSetValue(g_dwTlsIndex, pCtx);
    return TRUE;
}

__forceinline PALIOTH_TLS_CONTEXT ALIOTHGetCtx() {
    return (PALIOTH_TLS_CONTEXT)TlsGetValue(g_dwTlsIndex);
}

#define TLS_VAR(name) (ALIOTHGetCtx()->name)

__forceinline VOID ALIOTHTlsCleanup() {
    PALIOTH_TLS_CONTEXT pCtx = ALIOTHGetCtx();
    if (pCtx) {
        LocalFree(pCtx);
        TlsSetValue(g_dwTlsIndex, NULL);
    }
}

__forceinline VOID ALIOTHRotateGadget() {
    PALIOTH_TLS_CONTEXT pCtx = ALIOTHGetCtx();
    if (!pCtx || pCtx->dwGadgetCount == 0) return;
    pCtx->dwGadgetRotationIndex = (pCtx->dwGadgetRotationIndex + 1) % pCtx->dwGadgetCount;
    PALIOTH_GADGET_ENTRY pGadget = &pCtx->Gadgets[pCtx->dwGadgetRotationIndex];
    pCtx->qGadgetAddress = pGadget->pGadgetAddress;
    pCtx->qGadgetType = pGadget->dwGadgetType;
    pCtx->qFrameSize = pGadget->dwFrameSize;
}

__forceinline VOID ALIOTHSetChain(PDYNAMIC_MASK pMasks, DWORD dwCount) {
    PALIOTH_TLS_CONTEXT pCtx = ALIOTHGetCtx();
    if (!pCtx) return;
    pCtx->dwChainDepth = (dwCount > ALIOTH_MAX_CHAIN_DEPTH) ? ALIOTH_MAX_CHAIN_DEPTH : dwCount;
    for (DWORD i = 0; i < pCtx->dwChainDepth; i++) {
        pCtx->pChainMasks[i] = pMasks[i].pAddress;
        pCtx->dwChainFrames[i] = pMasks[i].dwFrameSize;
    }
}
