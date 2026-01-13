require "global"
require "rop"
require "memory"
require "func"
require "misc"
require "syscall"
require "remotelualoader"

init_native_functions()

version_string = "Luac0re 1.0 by Gezine"

syscall.init()
send_notification("syscall initialized")

FW_VERSION = get_fwversion()
send_notification(version_string .. "\nPLATFORM : " ..  PLATFORM .. "\nFW_VERSION : " .. FW_VERSION)

-- From PS5 fw 8.00 sony blocked socket creation with non AF_UNIX domains
if PLATFORM == "PS5" and tonumber(FW_VERSION) >= 8.00 then
    show_dialog("PS5 FW " .. FW_VERSION .. " does not support remote lua loader\nRun lua script locally")
else
    remote_lua_loader(9026)
end
