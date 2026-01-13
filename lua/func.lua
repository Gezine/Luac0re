
function func_wrap(function_address)
    return function(arg1, arg2, arg3, arg4, arg5, arg6)
        return call_rop(function_address, 0, arg1, arg2, arg3, arg4, arg5, arg6)
    end
end

function func_wrap_with_rax(function_address, rax)
    return function(arg1, arg2, arg3, arg4, arg5, arg6)
        return call_rop(function_address, rax, arg1, arg2, arg3, arg4, arg5, arg6)
    end
end


function get_dlsym_offset()
    local major, minor = FW_VERSION:match("(%d+)%.(%d+)")
    major = tonumber(major)
    minor = tonumber(minor)
    
    if not major or not minor then
        error("Invalid firmware version format: " .. FW_VERSION)
    end
    
    -- Try exact match first
    local version_key = string.format("%d.%02d", major, minor)
    if DLSYM_OFFSETS[version_key] then
        return DLSYM_OFFSETS[version_key]
    end
    
    -- Find closest version within same major
    local available_versions = {}
    for key, offset in pairs(DLSYM_OFFSETS) do
        local v_major, v_minor = key:match("(%d+)%.(%d+)")
        v_major = tonumber(v_major)
        v_minor = tonumber(v_minor)
        
        if v_major == major then
            table.insert(available_versions, {
                key = key,
                minor = v_minor,
                offset = offset
            })
        end
    end
    
    if #available_versions == 0 then
        error("No dlsym offset found for firmware version " .. fw_version)
    end
    
    -- Find version with minimum distance to current minor
    local closest = available_versions[1]
    local min_distance = math.abs(closest.minor - minor)
    
    for _, version in ipairs(available_versions) do
        local distance = math.abs(version.minor - minor)
        if distance < min_distance then
            min_distance = distance
            closest = version
        end
    end
    
    return closest.offset
end

function dlsym(handle, sym)
    if SCE_KERNEL_DLSYM == 0 then
        error("dlsym offset not available for firmware " .. (FW_VERSION or "unknown"))
    end
    
    if type(sym) ~= "string" then
        error("dlsym expects string symbol name")
    end
    
    local addr_out = malloc(0x8)
    
    local result = sceKernelDlsym(handle, sym, addr_out)
    if result == -1 then
        error("dlsym error for symbol: " .. sym)
    end
    
    return read64(addr_out)
end

function init_dlsym()
    assert(FW_VERSION)
    
    local major, minor = FW_VERSION:match("(%d+)%.(%d+)")
    major = tonumber(major)
    minor = tonumber(minor)
    
    if not major or not minor then
        error("Invalid firmware version: " .. FW_VERSION)
    end
    
    if PLATFORM == "PS4" then
        -- PS4: Verify dlsym signature at expected offset
        local base_addr = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr)
        local expected_addr = base_addr - 0x3A0
        
        -- Expected dlsym function signature bytes
        local expected_pattern = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 68 48"
        
        -- Read bytes at expected address
        local signature_bytes = read_buffer(expected_addr, 18)
        
        -- Convert to hex string for comparison
        local hex_string = ""
        for i = 1, #signature_bytes do
            hex_string = hex_string .. string.format("%02X", string.byte(signature_bytes, i))
            if i < #signature_bytes then
                hex_string = hex_string .. " "
            end
        end
        
        -- Verify signature
        if hex_string == expected_pattern then
            SCE_KERNEL_DLSYM = expected_addr
        else
            -- Signature doesn't match, search for it
            local search_start = base_addr - 0x600
            local search_buffer = read_buffer(search_start, 0x1000)
            
            local matches = find_pattern(search_buffer, expected_pattern)
            
            if #matches == 0 then
                send_notification("Warning : PS4 sceKernelDlsym offset not found")
                SCE_KERNEL_DLSYM = 0;
            else
                -- Use first match (offset is 1-based in Lua)
                SCE_KERNEL_DLSYM = search_start + matches[1] - 1
            end
        end
    elseif PLATFORM == "PS5" then
        -- PS5: For firmware > 10.01, calculate offset dynamically
        if major > 10 or major == 10 then
            SCE_KERNEL_DLSYM = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr) - 0x450
            send_notification("Warning : PS5 sceKernelDlsym offset not found\nUsing predicted value " .. to_hex(SCE_KERNEL_DLSYM))
        else
            SCE_KERNEL_DLSYM = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr) - 0x480
        end
    else
        error("Unknown platform: " .. tostring(PLATFORM))
    end
    
    -- Wrap the function for easier calling
    sceKernelDlsym = func_wrap(SCE_KERNEL_DLSYM)
    
end

function dlsym_test()

    sceKernelLoadStartModule = func_wrap(dlsym(LIBKERNEL_HANDLE, "sceKernelLoadStartModule"))

    local libSceNetCtl_HANDLE = sceKernelLoadStartModule("libSceNetCtl.sprx", 0, 0, 0, 0, 0)
    if libSceNetCtl_HANDLE <= 0 or libSceNetCtl_HANDLE >= 0x80000000 then
        error("Failed to load libSceNetCtl.sprx: " .. string.format("0x%08X", libSceNetCtl_HANDLE))
    end

    local libSceNet_HANDLE = sceKernelLoadStartModule("libSceNet.sprx", 0, 0, 0, 0, 0)
    if libSceNet_HANDLE <= 0 or libSceNet_HANDLE >= 0x80000000 then
        error("Failed to load libSceNet.sprx: " .. string.format("0x%08X", libSceNet_HANDLE))
    end

    sceNetCtlInit = func_wrap(dlsym(libSceNetCtl_HANDLE, "sceNetCtlInit"))
    sceNetInit = func_wrap(dlsym(libSceNet_HANDLE, "sceNetInit"))
    sceNetSocket = func_wrap(dlsym(libSceNet_HANDLE, "sceNetSocket"))

end

function init_native_functions()
    calloc                           = func_wrap(read64(EBOOT_OFFSETS.calloc))
    sceKernelOpen                    = func_wrap(read64(EBOOT_OFFSETS.sceKernelOpen))
    sceKernelWrite                   = func_wrap(read64(EBOOT_OFFSETS.sceKernelWrite))
    sceKernelClose                   = func_wrap(read64(EBOOT_OFFSETS.sceKernelClose))
    sceKernelStat                    = func_wrap(read64(EBOOT_OFFSETS.sceKernelStat))
    sceKernelUsleep                  = func_wrap(read64(EBOOT_OFFSETS.sceKernelUsleep))
    sceMsgDialogInitialize           = func_wrap(read64(EBOOT_OFFSETS.sceMsgDialogInitialize))
    sceMsgDialogOpen                 = func_wrap(read64(EBOOT_OFFSETS.sceMsgDialogOpen))
    sceMsgDialogTerminate            = func_wrap(read64(EBOOT_OFFSETS.sceMsgDialogTerminate))
    sceKernelGetModuleInfoFromAddr   = func_wrap(read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr))
    libc_strerror                    = func_wrap(LIBC_OFFSETS.libc_strerror)
    libc_error                       = func_wrap(read64(LIBC_OFFSETS.libc_error))
end
