# Luac0re

Luac0re is a [mast1c0re](https://cturt.github.io/mast1c0re.html) variation that uses Lua scripting for easier exploit development.

## Overview

The original [mast1c0re for Okage](https://github.com/McCaulay/mast1c0re) uses PS2 code execution only, which requires the PS2SDK to compile code.  
Luac0re uses minimal PS2 shellcode to escape ps2emu, then leverages the Lua 5.3 interpreter already embedded in the main executable (originally intended for ps2emu configuration) to simplify code writing and execution.

## Requirements

- PS4 or PS5 console
- Disc or digital version of *Star Wars Racer Revenge* (USA region, CUSA03474)

## Setup Instructions

1. Download the latest [release](https://github.com/Gezine/Luac0re/releases) ZIP file and extract it
2. Copy the `lua` directory and `VMC0.card` file into your savedata
3. For editing savedata, refer to the remote_lua_loader [SETUP guide](https://github.com/shahrilnet/remote_lua_loader/blob/main/SETUP.md)

## Credits

* **[CTurt](https://github.com/CTurt)** - [mast1c0re](https://cturt.github.io/mast1c0re.html) writeup
* **[McCaulay](https://github.com/McCaulay)** - [mast1c0re](https://mccaulay.co.uk/mast1c0re-part-2-arbitrary-ps2-code-execution/) writeup and [Okage](https://github.com/McCaulay/mast1c0re) reference implementation
* **[ChampionLeake](https://github.com/ChampionLeake)** - PS2 *Star Wars Racer Revenge* exploit writeup on [psdevwiki](https://www.psdevwiki.com/ps2/Vulnerabilities)
* **[shahrilnet](https://github.com/shahrilnet) & [null_ptr](https://github.com/n0llptr)** - Code references from [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
* **[Dr.Yenyen](https://github.com/DrYenyen)** - Testing and validation

## Disclaimer

This tool is provided as-is for research and development purposes only. Use at your own risk. The developers are not responsible for any damage, data loss, or other consequences resulting from the use of this software.
