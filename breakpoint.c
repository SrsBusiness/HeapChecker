#include "breakpoint.h"
#include "log.h"

#include <elf.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

static const uint8_t INT3 = 0xcc;

bool
read_addr(pid_t pid, uint64_t addr, uint64_t *dst)
{
    if (addr & 0x7 != 0) {
        error("Read address %p is not quad-word aligned\n", addr);
        return false;
    }
    /* Stupid ptrace, don't return the value if it overlaps with the error code space! */
    errno = 0;
    *dst = (uint64_t)ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (*dst == UINT64_MAX && errno != 0) {
        error("Failed to read quad word at address %p of the target process, errno=%d\n", addr, errno);
        return false;
    }
    return true;
}

bool
write_addr(pid_t pid, uint64_t addr, uint64_t data)
{
    if (addr & 0x7 != 0) {
        error("Read address %p is not quad-word aligned\n", addr);
        return false;
    }
    long ret = ptrace(PTRACE_POKETEXT, pid, addr, data);
    if (ret == -1) {
        error("Failed to write quad word to address %p of the target process, errno=%d\n", addr, errno);
        return false;
    }
    return true;
}

bool
get_regs(pid_t pid, struct user_regs_struct *regs)
{
    struct iovec iov = {
        .iov_base = regs,
        .iov_len = sizeof(*regs),
    };
    long ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    if (ret == -1) {
        error("Failed to read target process's registers\n");
        return false;
    }
    return true;
}

bool
set_regs(pid_t pid, struct user_regs_struct *regs)
{

}

bool
breakpoint_init(pid_t pid, uint64_t addr, enum HEAP_FUNCTION func_id, struct breakpoint *b)
{
    uint64_t addr_aligned = addr & (~0x7);
    uint64_t instr_orig = 0;
    union {
        uint8_t  u8[sizeof(uint64_t) / sizeof(uint8_t)];
        uint64_t u64;
    } instr_int3 = {.u64 = 0};
    if (!read_addr(pid, addr_aligned, &instr_orig)) {
        return false;
    }

    instr_int3.u64 = instr_orig;
    instr_int3.u8[addr - addr_aligned] = INT3;

    *b = (struct breakpoint){
        .addr_real = addr,
        .addr_aligned = addr_aligned,
        .instr_orig = instr_orig,
        .instr_int3 = instr_int3.u64,
        .func_id = func_id,
    };
    return true;
}

bool
set_breakpoint(pid_t pid, const struct breakpoint *b)
{
    return write_addr(pid, b->addr_aligned, b->instr_int3);
}

bool
clear_breakpoint(pid_t pid, const struct breakpoint *b)
{
    return write_addr(pid, b->addr_aligned, b->instr_orig);
}

bool
single_step(pid_t pid)
{
    long ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (ret == -1) {
        error("Failed to single step target process\n");
        return false;
    }
    return true;
}
