#pragma once

#include <windows.h>
#include <stdio.h>
#include "ALIOTH_config.h"
#include "tls_context.h"

#define INVALID_SSN ((DWORD64)-1)
#define DEFAULT_FRAME_SIZE 0x28

#define ExecuteSyscall(func_ptr, mask, ...) ( \
    TLS_VAR(qActiveMaskAddress) = (mask).pAddress, \
    TLS_VAR(qActiveMaskFrame) = (mask).dwFrameSize, \
    func_ptr(__VA_ARGS__) \
)

#define ExecuteSyscallChain(func_ptr, masks, count, ...) ( \
    ALIOTHSetChain((masks), (count)), \
    func_ptr(__VA_ARGS__) \
)

#define ExecuteSyscallRandom(func_ptr, ...) ( \
    DYNAMIC_MASK _randMask = GetRandomMask(), \
    TLS_VAR(qActiveMaskAddress) = _randMask.pAddress, \
    TLS_VAR(qActiveMaskFrame) = _randMask.dwFrameSize, \
    func_ptr(__VA_ARGS__) \
)

typedef struct _DYNAMIC_MASK {
    PVOID pAddress;
    DWORD dwFrameSize;
} DYNAMIC_MASK, *PDYNAMIC_MASK;

extern DYNAMIC_MASK Mask_Memory;
extern DYNAMIC_MASK Mask_File;
extern DYNAMIC_MASK Mask_Security;
extern DYNAMIC_MASK Mask_Worker;

typedef struct _SYSCALL_ENTRY {
    PVOID   pAddress;
    DWORD64 dwSsn;
    PVOID   pSyscallRet;
    DWORD64 dwHash;
    DWORD64 dwSsnKey;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

typedef struct _SYSCALL_LIST {
    DWORD Count;
    SYSCALL_ENTRY Entries[ALIOTH_MAX_STUBS];
} SYSCALL_LIST, *PSYSCALL_LIST;

extern void* qTableAddr;
extern void* qGadgetAddress;
extern DWORD qGadgetType;
extern DWORD qFrameSize;
extern void* qSavedReg;
extern void* qSavedRetAddr;
extern void* qActiveMaskAddress;
extern void* qThreadBase;
extern void* qRtlUserThreadStart;
extern DWORD qActiveMaskFrame;
extern DWORD qThreadBaseFrame;
extern DWORD qRtlUserThreadStartFrame;

extern SYSCALL_LIST SyscallList;
extern ALIOTH_GADGET_ENTRY g_GadgetList[ALIOTH_MAX_GADGETS];
extern DWORD g_dwTotalGadgets;
extern MASK_CANDIDATE g_MaskCandidates[MAX_MASK_CANDIDATES];
extern DWORD g_dwMaskCandidateCount;

extern void SetTableAddr(PVOID pTable, PVOID pGadget, DWORD dwType, DWORD dwFrameSize);
extern void Fnc0000();
extern void SyscallExec(PVOID pTlsContext);

BOOL ALIOTHInit();
VOID ALIOTHCleanup();
DWORD64 ALIOTHSyscallHash(PBYTE str);
PVOID ALIOTHGetSyscallStub(DWORD64 dwHash);
PVOID ALIOTHGetStubByIndex(DWORD dwIndex);
DWORD ALIOTHCalcFrameSize(PVOID pFunc);
PVOID ALIOTHSeekReturnAddress(PVOID pBase);
DWORD ALIOTHFindValidGadgets(PCHAR pcModuleName, ALIOTH_GADGET_ENTRY pOutGadgets[], DWORD dwMaxGadgets);
VOID ALIOTHScanModuleForMasks(PCHAR pcModuleName);
BOOL ALIOTHPatchEtw();
VOID ALIOTHRestoreEtw();
BOOL ALIOTHCheckHwbp();
VOID ALIOTHStartDecoys();
DYNAMIC_MASK GetRandomMask();
