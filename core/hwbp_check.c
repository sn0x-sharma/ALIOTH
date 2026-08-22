#include "engine.h"

#pragma optimize("", off)

BOOL ALIOTHCheckHwbp() {
    HANDLE hThread = (HANDLE)-2;
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    DWORD64 hGetCtx = ALIOTHSyscallHash((PCHAR)"NtGetContextThread");
    fnNtGetContextThread pGetCtx = (fnNtGetContextThread)ALIOTHGetSyscallStub(hGetCtx);
    if (!pGetCtx) return FALSE;
    
    NTSTATUS status = ExecuteSyscall(pGetCtx, Mask_Worker, hThread, &ctx);
    if (status != 0) return FALSE;
    
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr7 = 0;
        
        DWORD64 hSetCtx = ALIOTHSyscallHash((PCHAR)"NtSetContextThread");
        fnNtSetContextThread pSetCtx = (fnNtSetContextThread)ALIOTHGetSyscallStub(hSetCtx);
        if (pSetCtx) {
            ExecuteSyscall(pSetCtx, Mask_Worker, hThread, &ctx);
        }
        return TRUE;
    }
    return FALSE;
}
#pragma optimize("", on)
