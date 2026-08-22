EXTERN qTableAddr:QWORD
EXTERN qGadgetAddress:QWORD
EXTERN qGadgetType:DWORD
EXTERN qFrameSize:DWORD
EXTERN qSavedReg:QWORD
EXTERN qSavedRetAddr:QWORD
EXTERN qActiveMaskAddress:QWORD
EXTERN qThreadBase:QWORD
EXTERN qRtlUserThreadStart:QWORD
EXTERN qActiveMaskFrame:DWORD
EXTERN qThreadBaseFrame:DWORD
EXTERN qRtlUserThreadStartFrame:DWORD
EXTERN qGadgetRotationIndex:DWORD
EXTERN qGadgetCount:DWORD
EXTERN Gadgets:QWORD
EXTERN qChainDepth:DWORD
EXTERN pChainMasks:QWORD
EXTERN dwChainFrames:QWORD
EXTERN qSsnXorKey:BYTE

.code

    PUBLIC SetTableAddr
    SetTableAddr PROC
        mov qTableAddr, rcx
        mov qGadgetAddress, rdx
        mov qGadgetType, r8d
        mov qFrameSize, r9d
        xor rax, rax
        inc rax
        ret
    SetTableAddr ENDP

    SyscallExec PROC
        mov r10, rcx
        mov r11, rax
        
        mov [rsp + 8h], rsi
        mov [rsp + 10h], rdi
        mov [rsp + 18h], r8
        mov [rsp + 20h], r9
        
        mov [rcx + 48h], rsp
        
        and rsp, 0FFFFFFFFFFFFFFF0h
        
        xor rax, rax
        mov eax, [rcx + 2Ch]
        add eax, 8
        add eax, [rcx + 50h]
        add eax, 8
        add eax, [rcx + 54h]
        add eax, 8
        add eax, [rcx + 58h]
        
        mov r9, [rcx + 70h]
        test r9, r9
        jz BuildFrames
        
    ChainLoop:
        add eax, 8
        add eax, [rcx + 78h + r9*8 - 8]
        dec r9
        jnz ChainLoop
        
    BuildFrames:
        sub rsp, rax
        mov r8, rsp
        
        xor rax, rax
        mov eax, [rcx + 2Ch]
        mov r9, [rcx + 30h]
        mov [r8 + rax], r9
        
        add eax, 8
        add eax, [rcx + 50h]
        mov r9, [rcx + 40h]
        mov [r8 + rax], r9
        
        add eax, 8
        add eax, [rcx + 54h]
        mov r9, [rcx + 5Ch]
        mov [r8 + rax], r9
        
        add eax, 8
        add eax, [rcx + 58h]
        mov r9, [rcx + 60h]
        mov [r8 + rax], r9
        
        mov r9, [rcx + 70h]
        test r9, r9
        jz DoneChain
        
        mov r10, 0
    ChainPlaceLoop:
        add eax, 8
        add eax, [rcx + 80h + r10*8]
        mov r11, [rcx + 78h + r10*8]
        mov [r8 + rax], r11
        inc r10
        cmp r10, r9
        jl ChainPlaceLoop
        
    DoneChain:
        add eax, 8
        xor r9, r9
        mov [r8 + rax], r9
        
        mov r8, [rcx + 48h]
        mov r9, [r8 + 20h]
        mov r8, [r8 + 18h]
        
        mov rsi, [rcx + 48h]
        add rsi, 28h
        lea rdi, [rsp + 20h]
        mov rcx, 8
        cld
        rep movsq
        
        mov rax, r11
        
        mov eax, [rcx + 68h]
        mov r10, [rcx + 78h]
        mov r10, [r10 + rax*24]
        mov [rcx + 8h], r10
        mov r10d, [rcx + 78h + rax*24 + 8]
        mov [rcx + 10h], r10d
        mov r10d, [rcx + 78h + rax*24 + 12]
        mov [rcx + 14h], r10d
        
        inc eax
        cmp eax, [rcx + 6Ch]
        jl StoreIndex
        xor eax, eax
    StoreIndex:
        mov [rcx + 68h], eax
        
        cmp [rcx + 10h], 0
        je UseRBX
        cmp [rcx + 10h], 1
        je UseRDI
        cmp [rcx + 10h], 2
        je UseRSI
        cmp [rcx + 10h], 3
        je UseRBX
        cmp [rcx + 10h], 4
        je UseR12
        cmp [rcx + 10h], 5
        je UseR13
        cmp [rcx + 10h], 6
        je UseR14
        cmp [rcx + 10h], 7
        je UseR15
        jmp UseRBX
        
    UseRBX:
        mov [rcx + 20h], rbx
        lea rbx, BackFromKernel
        jmp DoCall
    UseRDI:
        mov rdi, [rcx + 48h]
        mov rdi, [rdi + 10h]
        mov [rcx + 20h], rdi
        lea rdi, BackFromKernel
        jmp DoCall
    UseRSI:
        mov rsi, [rcx + 48h]
        mov rsi, [rsi + 8h]
        mov [rcx + 20h], rsi
        lea rsi, BackFromKernel
        jmp DoCall
    UseR12:
        mov [rcx + 20h], r12
        lea r12, BackFromKernel
        jmp DoCall
    UseR13:
        mov [rcx + 20h], r13
        lea r13, BackFromKernel
        jmp DoCall
    UseR14:
        mov [rcx + 20h], r14
        lea r14, BackFromKernel
        jmp DoCall
    UseR15:
        mov [rcx + 20h], r15
        lea r15, BackFromKernel
        jmp DoCall
        
    DoCall:
        push rdx
        shl rax, 5
        mov rdx, [rcx]
        add rdx, rax
        
        mov rax, [rdx + 8h]
        mov rbx, [rdx + 20h]
        xor rax, rbx
        
        mov r11, [rdx + 10h]
        pop rdx
        mov rcx, [rsp + 28h]
        push [rcx + 8h]
        jmp r11
        
    BackFromKernel:
        cmp [rcx + 10h], 0
        je RestRBX
        cmp [rcx + 10h], 1
        je RestRDI
        cmp [rcx + 10h], 2
        je RestRSI
        cmp [rcx + 10h], 3
        je RestRBX
        cmp [rcx + 10h], 4
        je RestR12
        cmp [rcx + 10h], 5
        je RestR13
        cmp [rcx + 10h], 6
        je RestR14
        cmp [rcx + 10h], 7
        je RestR15
        jmp RestRBX
        
    RestRBX: mov rbx, [rcx + 20h]; jmp Fin
    RestRDI: mov rdi, [rcx + 20h]; jmp Fin
    RestRSI: mov rsi, [rcx + 20h]; jmp Fin
    RestR12: mov r12, [rcx + 20h]; jmp Fin
    RestR13: mov r13, [rcx + 20h]; jmp Fin
    RestR14: mov r14, [rcx + 20h]; jmp Fin
    RestR15: mov r15, [rcx + 20h]; jmp Fin
    
    Fin:
        mov rcx, rax
        mov rsp, [rcx + 48h]
        mov rsi, [rsp + 8h]
        mov rdi, [rsp + 10h]
        mov rax, rcx
        ret
    SyscallExec ENDP
    
    PUBLIC SyscallDispatcher
    SyscallDispatcher PROC
        mov r10, rcx
        mov r11, rax
        jmp SyscallExec
    SyscallDispatcher ENDP

end
