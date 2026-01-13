-- Make init.lua minimal
-- masticore does not like big init.lua (?)

-- Global variables from masticore
-- FAKE_STRING
-- ADDROF_TABLE
-- WRITE_TABLE
-- ARRAY_ADDR
-- STRING_BASE
-- EBOOT_BASE
-- LIBC_BASE
-- FIOS_BASE
-- LUA_STATE
-- USER_ID
-- call_rop_internal()

-- Stop GC for sanity
collectgarbage("stop")

package.path = package.path .. ";/savedata0/lua/?.lua"

old_error = error

function error(message)
    old_error("\n" .. message)
end

function write_error_log(error_msg)
    local log_file = "/av_contents/content_tmp/lua_log.txt"
    local file = io.open(log_file, "a")
    if file then
        file:write(error_msg)
        file:close()
    end
end

local status, err = xpcall(function()
    require "main"
end, debug.traceback)

if not status then
    write_error_log(err)
    error(err) -- Throw error to masticore
end

-- Removing this will return to masticore 
while true do end
