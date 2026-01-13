
syscall = {}

function syscall.init()
    syscall.collect_info()
    
    if PLATFORM == "PS4" then
        -- PS4 requires valid syscall wrapper from libkernel .text
        local libkernel_text = read_buffer(LIBKERNEL_BASE, 0x40000)
        -- mov rax, <num>; mov r10, rcx; syscall
        local matches = find_pattern(libkernel_text, "48 c7 c0 ? ? ? ? 49 89 ca 0f 05")
        
        syscall.syscall_wrapper = {}
        for i, offset in ipairs(matches) do
            local num_bytes = libkernel_text:sub(offset + 3, offset + 6)
            local num = string.unpack("<I4", num_bytes)
            syscall.syscall_wrapper[num] = LIBKERNEL_BASE + offset - 1
        end
    elseif PLATFORM == "PS5" then
        -- Can be any syscall wrapper in libkernel
        local gettimeofday = read64(LIBC_OFFSETS.gettimeofday)
        syscall.syscall_address = gettimeofday + 7  -- +7 to skip "mov rax, <num>"
    else
        error("invalid platform " .. PLATFORM)
    end
    
    syscall.resolve(SYSCALL_TABLE)
    
    syscall.do_sanity_check()
end

function syscall.collect_info()
    local INIT_PROC_ADDR_OFFSET = 0x128
    local SEGMENTS_OFFSET = 0x160
    
    local addr_inside_libkernel = read64(LIBC_OFFSETS.gettimeofday)
    local mod_info = malloc(0x300)
    
    local ret = sceKernelGetModuleInfoFromAddr(addr_inside_libkernel, 1, mod_info)
    if ret ~= 0 then
        error("sceKernelGetModuleInfoFromAddr() error: " .. to_hex(ret))
    end
    
    LIBKERNEL_BASE = read64(mod_info + SEGMENTS_OFFSET)
    
    -- Credit to flatz for this technique
    local init_proc_addr = read64(mod_info + INIT_PROC_ADDR_OFFSET)
    local delta = init_proc_addr - LIBKERNEL_BASE
    
    if delta == 0x0 then
        PLATFORM = "PS4"
    elseif delta == 0x10 then
        PLATFORM = "PS5"
    else
        error("failed to determine PLATFORM")
    end
end

function syscall.resolve(list)
    for name, num in pairs(list) do
        if not syscall[name] then
            if PLATFORM == "PS4" then
                if syscall.syscall_wrapper[num] then
                    syscall[name] = func_wrap_with_rax(syscall.syscall_wrapper[num], num)
                else
                    error(string.format("syscall wrapper for %s (%d) not found in libkernel", name, num))
                end
            elseif PLATFORM == "PS5" then
                syscall[name] = func_wrap_with_rax(syscall.syscall_address, num)
            end
        end
    end
end

function syscall.do_sanity_check()    
    local pid = syscall.getpid(20)
    if not (pid and pid ~= 0) then
        error("syscall test failed")
    end
end