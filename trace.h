#pragma once

#include "heap.h"
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/user.h>

struct breakpoint {
    uint64_t addr_real;
    uint64_t addr_aligned;
    uint64_t instr_orig;
    uint64_t instr_int3;
    enum HEAP_FUNCTION func_id;
};

bool trace_breakpoint_init(pid_t pid, uint64_t addr, enum HEAP_FUNCTION func_id, struct breakpoint *b);
bool trace_set_breakpoint(pid_t pid, const struct breakpoint *b);
bool trace_clear_breakpoint(pid_t pid, const struct breakpoint *b);
bool trace_single_step(pid_t pid);
bool trace_get_regs(pid_t pid, struct user_regs_struct *regs);
bool trace_set_regs(pid_t pid, struct user_regs_struct *regs);
bool trace_read_addr(pid_t pid, uint64_t addr, uint64_t *dst);
bool trace_write_addr(pid_t pid, uint64_t addr, uint64_t data);
bool trace_wait(pid_t pid);
bool trace_cont(pid_t pid);
bool trace_read_aux_vectors(pid_t pid, uint64_t *base);
