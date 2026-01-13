
PAGE_SIZE = 0x4000
PHYS_PAGE_SIZE = 0x1000

STDIN_FILENO = 0
STDOUT_FILENO = 1
STDERR_FILENO = 2

AF_INET = 2
AF_INET6 = 28
AF_ROUTE = 17
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
IPV6_PKTINFO = 46
INADDR_ANY = 0

SOL_SOCKET = 0xffff  -- options for socket level
SO_REUSEADDR = 4  -- allow local address reuse

PROT_NONE = 0x0
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXECUTE = 0x4
GPU_READ = 0x10
GPU_WRITE = 0x20
GPU_RW = 0x30

MAP_SHARED = 0x1
MAP_PRIVATE = 0x2
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x1000
MAP_NO_COALESCE = 0x400000

O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
O_CREAT = 0x100 
O_TRUNC = 0x1000
O_APPEND = 0x2000
O_NONBLOCK = 0x4000

SIGILL = 4
SIGBUS = 10
SIGSEGV = 11
SA_SIGINFO = 0x4

LIBKERNEL_HANDLE = 0x2001

LIBKERNEL_BASE = 0

PLATFORM = nil
FW_VERSION = nil

-- eboot scratch memory
DIALOG_SCRATCH        = EBOOT_BASE + 0x3C00000
LUA_PIVOT_SCRATCH     = EBOOT_BASE + 0x5C00000

-- ROP gadget constants
RET                   = EBOOT_BASE + 0x72
POP_RAX_RET           = EBOOT_BASE + 0xb50a0
POP_RBX_RET           = EBOOT_BASE + 0xc234
POP_RCX_RET           = EBOOT_BASE + 0x96059
POP_RDI_RET           = EBOOT_BASE + 0x1429
POP_RSI_RET           = EBOOT_BASE + 0xbf2b0
POP_RDX_RET           = EBOOT_BASE + 0xbf5b7
POP_RBP_RET           = EBOOT_BASE + 0x8f
POP_RSP_RET           = EBOOT_BASE + 0x61a70
-- pop r8 ; xor eax, eax ; mov word [rbx], cx ; pop rbx ; pop r14 ; pop rbp ; ret
POP_R8_RET            = LIBC_BASE + 0x1345a
-- mov r9, qword [rbp-0x50] ; mov rbx, qword [rbp-0x40] ; mov eax, 0xFFFFFFFC ; mov esi, 0xFFFFFFFD ; mov edi, 0x00000001 ; add rcx, r8 ; jmp rcx ;
MOV_R9_RET            = FIOS_BASE + 0x4009c
POP_R13_RET           = EBOOT_BASE + 0xbf35d
POP_R14_RET           = EBOOT_BASE + 0x11d0e2
POP_R15_RET           = EBOOT_BASE + 0x1428
-- xchg rax, rbp ; sub al, 0x00 ; movsxd rdx, qword [rcx+rsi*4] ; add rdx, rcx ; jmp rdx ;
XCHG_RAX_RBP          = EBOOT_BASE + 0x7ea4 
SUB_RAX_RDX_RET       = EBOOT_BASE + 0x41a2
-- mov rax, qword [rdi] ; jmp qword [rax+0x20] ;
LUA_PIVOT1            = EBOOT_BASE + 0x1b8640 
-- add al, byte [rax] ; add byte [rax-0x7B], cl ; ror byte [rax-0x77], 0x55 ; mov byte [rdi], cl ; xchg eax, esp ; ret ;
LUA_PIVOT2            = FIOS_BASE + 0x19b32 
MOV_DEREF_RDI_RAX_RET = EBOOT_BASE + 0x75b6c
MOV_RAX_DEREF_RAX_RET = EBOOT_BASE + 0x23ac20


SCE_KERNEL_DLSYM = 0

EBOOT_OFFSETS = {
    calloc                    = EBOOT_BASE + 0x388EC0,
    sceKernelOpen             = EBOOT_BASE + 0x388FB0,
    sceKernelWrite            = EBOOT_BASE + 0x388FA0,
    sceKernelClose            = EBOOT_BASE + 0x388FC0,
    sceKernelStat             = EBOOT_BASE + 0x388FD0,
    sceKernelUsleep           = EBOOT_BASE + 0x389640,
    sceMsgDialogInitialize    = EBOOT_BASE + 0x389128,
    sceMsgDialogOpen          = EBOOT_BASE + 0x389158,
    sceMsgDialogTerminate     = EBOOT_BASE + 0x389418,
}

LIBC_OFFSETS = {
    sceKernelGetModuleInfoFromAddr = LIBC_BASE + 0xCBDA8,
    gettimeofday                   = LIBC_BASE + 0xCBC50,
    libc_strerror                  = LIBC_BASE + 0xADE0,
    libc_error                     = LIBC_BASE + 0xCBC58,
}

SYSCALL_TABLE = {
    read = 0x3,
    write = 0x4,
    open = 0x5,
    close = 0x6,
    setuid = 0x17,
    getuid = 0x18,
    accept = 0x1e,
    pipe = 0x2a,
    mprotect = 0x4a,
    socket = 0x61,
    connect = 0x62,
    bind = 0x68,
    setsockopt = 0x69,
    listen = 0x6a,
    socketex = 0x71,
    getsockopt = 0x76,
    netgetiflist = 0x7d,
    socketpair = 0x87,
    sysctl = 0xca,
    nanosleep = 0xf0,
    sigaction = 0x1a0,
    thr_self = 0x1b0,
    dlsym = 0x24f,
    dynlib_load_prx = 0x252,
    dynlib_unload_prx = 0x253,
    randomized_path = 0x25a,
    is_in_sandbox = 0x249,
    mmap = 0x1dd,
    getpid = 0x14,
    jitshm_create = 0x215,
    jitshm_alias = 0x216,
    unlink = 0xa,
    chmod = 0xf,
    recvfrom = 0x1d,
    getsockname = 0x20,
    rename = 0x80,
    sendto = 0x85,
    mkdir = 0x88,
    rmdir = 0x89,
    stat = 0xbc,
    getdents = 0x110,
    lseek = 0x1de,
    dup = 0x29,
    dup2 = 0x5a,
    fcntl = 0x5c,
    select = 0x5d,
    fstat = 0xbd,
    umtx_op = 0x1c6,
    cpuset_getaffinity = 0x1e7,
    cpuset_setaffinity = 0x1e8,
    rtprio_thread = 0x1d2,
    ftruncate = 0x1e0,
    sched_yield = 0x14b,
    munmap = 0x49,
    thr_new = 0x1c7,
    thr_exit = 0x1af,
    fsync = 0x5f,
    ioctl = 0x36,
    kill = 0x25
}

DLSYM_OFFSETS = { }
