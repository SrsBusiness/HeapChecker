#include "trace.h"
#include "log.h"

#include <elf.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

static const uint8_t INT3 = 0xcc;

bool
trace_read_addr(pid_t pid, uint64_t addr, uint64_t *dst)
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
trace_write_addr(pid_t pid, uint64_t addr, uint64_t data)
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
trace_get_regs(pid_t pid, struct user_regs_struct *regs)
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
trace_set_regs(pid_t pid, struct user_regs_struct *regs)
{
    struct iovec iov = {
        .iov_base = regs,
        .iov_len = sizeof(*regs),
    };
    long ret = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
     if (ret == -1) {
        error("Failed to read target process's registers\n");
        return false;
    }
    return true;
}

bool
trace_breakpoint_init(pid_t pid, uint64_t addr, enum HEAP_FUNCTION func_id, struct breakpoint *b)
{
    uint64_t addr_aligned = addr & (~0x7);
    uint64_t instr_orig = 0;
    union {
        uint8_t  u8[sizeof(uint64_t) / sizeof(uint8_t)];
        uint64_t u64;
    } instr_int3 = {.u64 = 0};
    if (!trace_read_addr(pid, addr_aligned, &instr_orig)) {
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
trace_set_breakpoint(pid_t pid, const struct breakpoint *b)
{
    return trace_write_addr(pid, b->addr_aligned, b->instr_int3);
}

bool
trace_clear_breakpoint(pid_t pid, const struct breakpoint *b)
{
    return trace_write_addr(pid, b->addr_aligned, b->instr_orig);
}

bool
trace_single_step(pid_t pid)
{
    long ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (ret == -1) {
        error("Failed to single step target process\n");
        return false;
    }
    
    return trace_wait(pid);
}

bool
trace_wait(pid_t pid)
{
    int status;
    waitpid(pid, &status, 0);
    /* 
     * PTRACE_O_TRACEEXEC is not set, so the child process will receive a SIGTRAP signal
     * and halt here right before the new program begins execution. This gives us a change
     * to set breakpoints at calloc, malloc, realloc, and free() before the program resumes.
     */
    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status != 0) {
            error("Target process exited unexpectedly with status %d\n", exit_status);
        } else {
            info("Target exited normally with status %d\n", exit_status);
        }
        return false;
    }
    
    if (!WIFSTOPPED(status)) {
        error("Target process should have been stopped as a result of ptrace()");
        return false;
    }

    if (WSTOPSIG(status) != SIGTRAP) {
        error("Target process received unexpected signal %d\n", WSTOPSIG(status));  
        return false;
    }
    return true;
}

bool
trace_cont(pid_t pid)
{
    long ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if (ret == -1) {
        error("Failed to continue target process\n");
        return false;
    }
    return true;
}

bool
trace_read_aux_vectors(pid_t pid, uint64_t *base)
{
    struct user_regs_struct regs;
    if (!trace_get_regs(pid, &regs)) {
        return false;
    }
    uint64_t rsp = regs.rsp;
    debug("Child RSP is %p\n", rsp);

    uint64_t argc;
    if (!trace_read_addr(pid, rsp, &argc)) {
        return false;
    }
    debug("Child argc is %u\n", argc);
    
    /* Walk through argv */
    uint64_t argv;
    for (uint64_t i = 0; i < argc; i++) {
        rsp += sizeof(uint64_t);
        if (!trace_read_addr(pid, rsp, &argv)) {
            return false;
        }
        if (argv == 0) {
            error("argv[%u] null\n", i);
            return false;
        }
    }
    
    /* argv is null terminated */
    rsp += sizeof(uint64_t);
    if (!trace_read_addr(pid, rsp, &argv)) {
        return false;
    }
    if (argv != 0) {
        error("argv not null terminated: %p\n", (void *)argv);
        return false;
    }
    debug("Walked through argv\n");
    
    /* Walk through envp */
    uint64_t envp;
    do {
        rsp += sizeof(uint64_t);
        if (!trace_read_addr(pid, rsp, &envp)) {
            return false;
        }
    } while (envp != 0);
    debug("Walked through envp\n");
    
    /* Walk through auxiliary vectors */
    Elf64_auxv_t auxv;
    while (true) {
        rsp += sizeof(uint64_t);
        if (!trace_read_addr(pid, rsp, &auxv.a_type)) {
            return false;
        }
        if (auxv.a_type == AT_NULL) {
            break;
        }
        debug("Auxiliary vector type: %llu\n", auxv.a_type);

        rsp += sizeof(uint64_t);
        if (!trace_read_addr(pid, rsp, &auxv.a_un.a_val)) {
            return false;
        }
        debug("Auxiliary vector value: %p\n", (void *)auxv.a_un.a_val);

        if (auxv.a_type == AT_PHDR) {
            *base = auxv.a_un.a_val - sizeof(Elf64_Ehdr);
        }
    }

    return true;
}
