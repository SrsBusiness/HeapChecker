#include "elf_parse.h"
#include "hashmap.h"
#include "heap.h"
#include "log.h"
#include "trace.h"

#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>

const char *heap_func_names[] = {
    "calloc",
    "malloc",
    "realloc",
    "reallocarray",
    "free"
};

static int exit_status = 0;
struct cli_options {
    int verbose;
    int num_remaining_args;
    char **remaining_args;
};

static inline void
usage(char *argv0)
{
    printf(
        "Usage: %s [options] [command]\n"
        "Options: \n"
        "    --help|-h          Display this information\n"
        "    --verbose|-v       Enable verbose logging\n",
        argv0);
}

/* Returns true if program should continue, false if it should exit immediately */
static inline bool
parse_args(int argc, char **argv, struct cli_options *opts)
{
    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, 0, 0},
	};

    opts->verbose = false;

    int option = 0;
   
    while ((option = getopt_long(argc, argv, "hv", long_options, NULL)) != -1) {
        switch(option) {
        case 'v':
            opts->verbose = true;
            break;
        case 'h':
            exit_status = 0;
            usage(argv[0]);
            return false;
        case '?':
            usage(argv[0]);
        default:
            exit_status = 1;
            return false;
        }
    }

    opts->num_remaining_args = argc - optind;
    if (opts->num_remaining_args <= 0) {
        usage(argv[0]);
        return false;
    }
    opts->remaining_args = &argv[optind];

    return true;
}

bool
set_heap_breakpoints(pid_t pid, struct Heap_Func_Addrs *addrs, struct hashmap *breakpoints)
{
    for (enum HEAP_FUNCTION func_id = HEAP_FUNC_FIRST; func_id < HEAP_FUNC_COUNT; func_id++) {
        uint64_t addr = addrs->addrs[func_id];
        if (addr == 0) {
            debug("No symbol %s found in binary\n", heap_func_names[func_id]);
            continue;
        }
        struct breakpoint *b = malloc(sizeof(*b));
        if (b == NULL) {
            return false;
        }
        if (!trace_breakpoint_init(pid, addr, func_id, b)) {
            return false;
        }
        if (!trace_set_breakpoint(pid, b)) {
            return false;
        }
        if (!hashmap_add(breakpoints, (void *)b->addr_real, b)) {
            error("Failed to add breakpoint to hashmap\n");
            return false;
        }
        debug("Set breakpoint at %s (%p)\n", heap_func_names[func_id], addr);
    }
    return true;
}

uint64_t
hash_addr(void *addr)
{
    return (uint64_t)addr * 2654435761;
}

bool
equals_addr(void *x, void *y)
{
    return x == y; 
}

struct buffer {
    uint64_t addr;
    uint64_t len;
};

/* caller has set return breakpoint */
bool
handle_calloc(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, uint64_t nmemb, uint64_t size)
{
    /* Continue until return */
    if (!trace_cont(pid) ||
        !trace_wait(pid)) {
        return false;
    }

    struct user_regs_struct regs;
    if (!trace_get_regs(pid, &regs)) {
        return false;
    }
    
    debug("calloc(%llu, %llu) -> %p\n", nmemb, size, (void *)regs.rax);
    if (regs.rax != 0) {
        struct buffer *b = malloc(sizeof(*b));
        *b = (struct buffer){.addr = regs.rax, .len = nmemb * size};
        hashmap_add(buffers, (void *)b->addr, b);
    }

    /* let caller clear return breakpoint */

    return true;
}

bool
handle_malloc(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, uint64_t size)
{
    /* Continue until return */
    if (!trace_cont(pid) ||
        !trace_wait(pid)) {
        return false;
    }

    struct user_regs_struct regs;
    if (!trace_get_regs(pid, &regs)) {
        return false;
    }

    debug("malloc(%llu) -> %p\n", size, (void *)regs.rax);
    if (regs.rax != 0) {
        struct buffer *b = malloc(sizeof(*b));
        *b = (struct buffer){.addr = regs.rax, .len = size};
        hashmap_add(buffers, (void *)b->addr, b);
    }

    /* let caller clear return breakpoint */

    return true;
}

bool
handle_realloc(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, void *ptr, uint64_t size)
{
    /* Continue until return */
    if (!trace_cont(pid) ||
        !trace_wait(pid)) {
        return false;
    }

    struct user_regs_struct regs;
    if (!trace_get_regs(pid, &regs)) {
        return false;
    }
    
    debug("realloc(%p, %llu) -> %p\n", ptr, size, (void *)regs.rax);
    if (regs.rax != 0) {
        struct buffer *b = hashmap_get(buffers, ptr);
        if (b == NULL) {
            /* bug */
            error("Cannot find record of buffer at %p resized by realloc()\n", ptr);
            return false;
        }
        if ((void *)regs.rax == ptr) {
            /* resize */
            b->len = size;
        } else {
            /* new buffer */
            hashmap_del(buffers, ptr);
            *b = (struct buffer){.addr = regs.rax, .len = size};
            hashmap_add(buffers, (void *)regs.rax, b);
        }
    } /* else no op */
    return true;
}

bool
handle_reallocarray(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, void *ptr, uint64_t nmemb, uint64_t size) {
    /* Continue until return */
    if (!trace_cont(pid) ||
        !trace_wait(pid)) {
        return false;
    }

    struct user_regs_struct regs;
    if (!trace_get_regs(pid, &regs)) {
        return false;
    }

    debug("reallocarray(%p, %llu, %llu) -> %p\n", ptr, nmemb, size, (void *)regs.rax);
    if (regs.rax != 0) {
        struct buffer *b = hashmap_get(buffers, ptr);
        if (b == NULL) {
            /* bug */
            error("Cannot find record of buffer at %p resized by reallocarray()\n", ptr);
            return false;
        }
        if ((void *)regs.rax == ptr) {
            /* resize */
            b->len = nmemb * size;
        } else {
            /* new buffer */
            hashmap_del(buffers, ptr);
            *b = (struct buffer){.addr = regs.rax, .len = nmemb * size};
            hashmap_add(buffers, (void *)regs.rax, b);
        }
    } /* else no op */
    return true;
}

/*
 * free() is the simplest to handle because it returns void. This means we have no
 * reason to set a breakpoint on its return address to capture the return value
 */
bool
handle_free(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, void *ptr)
{
    debug("free(%p)\n", ptr);
    if (ptr == NULL) {
        return true;
    }
    struct buffer *b = hashmap_get(buffers, (void *)ptr);
    if (b == NULL) {
        /*
         * This could be an invalid free() error with the target program rather
         * than a bug/error in this program. We should therefore just log it and
         * return true
         */
        info("Invalid free() of ptr %p\n", (void *)ptr);
    } else {
        hashmap_del(buffers, (void *)ptr);
        free(b);
    }
    return true;
}

/*
 * At the end of this function we should be good to go back to the top of the
 * main loop and continue the target process
 */
bool
handle_breakpoint(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers)
{
    struct user_regs_struct regs = {};    
    if (!trace_get_regs(pid, &regs)) {
        return false;
    }

    /* Reset RIP to the address of the INT3 we injected */
    regs.rip--;
    uint64_t break_addr = regs.rip;
    struct breakpoint *b = hashmap_get(breakpoints, (void *)break_addr);

    /* These probably indicate a bug in this program somewhere */
    if (b == NULL) {
        error("Target process hit breakpoint at unexpected address\n");
        return false;
    }
    if (b->func_id < HEAP_FUNC_FIRST || b->func_id > HEAP_FUNC_LAST) {
        error("Target process hit unexpected breakpoint\n");
        return false;
    }
    
    /* Read return address we are in calloc, malloc, realloc, or reallocarray*/
    uint64_t return_addr = 0;
    struct breakpoint ret = {};
    
    if (b->func_id != HEAP_FREE) {
        if (!trace_read_addr(pid, regs.rsp, &return_addr)) {
            error("Failed to read return address\n");
            return false;
        }
        if (!trace_breakpoint_init(pid, return_addr, HEAP_NONE, &ret)) {
            error("Failed to initialize return breakpoint\n");
            return false;
        }
        if (!trace_set_breakpoint(pid, &ret)) {
            error("Failed to set return breakpoint\n");
            return false;
        }
    }

    /*
     * Clear the breakpoint, write the new RIP value into the target process,
     * and single step
     */

    if (!trace_clear_breakpoint(pid, b) ||
        !trace_set_regs(pid, &regs) ||
        !trace_single_step(pid)) {
        return false;
    }

    /*
     * Now that we've executed the original instruction at the breakpoint address,
     * we can reset the breakpoint
     */

    if (!trace_set_breakpoint(pid, b)) {
        return false;
    }

    /*
     * Note it is possible but unlikely for the first instruction to have
     * overwritten one of the registers containing function arguments, but we
     * have them saved still in regs.
     * Each function handles arguments slightly differently so we'll branch off
     * into separate helper functions for each
     */

    bool success = false;
    switch (b->func_id) {
    case HEAP_CALLOC:
        success = handle_calloc(pid, breakpoints, buffers, regs.rdi, regs.rsi);
        break;
    case HEAP_MALLOC:
        success = handle_malloc(pid, breakpoints, buffers, regs.rdi);
        break;
    case HEAP_REALLOC:
        success = handle_realloc(pid, breakpoints, buffers, (void *)regs.rdi, regs.rsi);
        break;
    case HEAP_REALLOCARRAY:
        success = handle_reallocarray(pid, breakpoints, buffers, (void *)regs.rdi, regs.rsi, regs.rdx);
        break;
    case HEAP_FREE:
        success = handle_free(pid, breakpoints, buffers, (void *)regs.rdi);
        break;
    default:
        /* unreachable */ 
        break;
    }

    if (b->func_id != HEAP_FREE) {
        /* clear return address breakpoint */
        if(!trace_clear_breakpoint(pid, &ret)) {
            return false;
        }
        if (!trace_get_regs(pid, &regs)) {
            return false;
        }
        regs.rip--;
        if (!trace_set_regs(pid, &regs)) {
            return false;
        }
    }
    return success;
}

bool
trace_target(char **argv, struct Heap_Func_Addrs *func_addrs)
{
    /* We have everything we need to exec and trace the target process */
    pid_t pid = fork();     
    if (pid == 0) { /* child */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(
            argv[0],
            argv);
        return 1;
    } else if (pid < 0) {
        error("Failed to fork target process\n");
        return false;
    }

    /* Parent */
    if (!trace_wait(pid)) {
        return false;
    }
    
    /* initialize hashmaps */ 
    struct hashmap breakpoints,
                     buffers;
    if (!hashmap_init(&breakpoints, 4096, hash_addr, equals_addr)) {
        error("Failed to initialize breakpoints map\n");
        return false;
    }

    if (!hashmap_init(&buffers, 4096, hash_addr, equals_addr)) {
        error("Failed to initialize buffers map\n");
        return false;
    }
    
    if (!set_heap_breakpoints(pid, func_addrs, &breakpoints)) {
        error("Failed to set breakpoints at calloc, malloc, realloc, reallocarray, and free\n");
        return false;
    }
    while (true) {
        if (!trace_cont(pid)){
            return false;
        }

        if (!trace_wait(pid)) {
            /* Child could be expected to exit normally here */
            break;
        }

        if (!handle_breakpoint(pid, &breakpoints, &buffers)) {
            return false;
        }
    }
    
    /* Print leaked buffers */ 
    uint64_t num_leaked = 0;
    info("Leak summary:\n");
    for (uint64_t i = 0; i < buffers.capacity; i++) {
        struct kv_pair kv = buffers.entries[i];
        if (kv.k == NULL) {
            continue;
        }
        struct buffer *b = kv.v;
        info("Buffer at %p of length %llu\n", (void *)b->addr, b->len);
        free(b);
        num_leaked++; 
    }
    info("%llu buffers leaked\n", num_leaked);
    hashmap_destroy(&buffers); 

    /* destroy breakpoints hashmap */
    for (uint64_t i = 0; i < breakpoints.capacity; i++) {
        struct kv_pair kv = breakpoints.entries[i];
        if (kv.k == NULL) {
            continue;
        }
        free(kv.v);
    }
    hashmap_destroy(&breakpoints);
    return true;
}

int
main(int argc, char **argv)
{
    struct cli_options options = {};
    if (!parse_args(argc, argv, &options)) {
        return exit_status;
    }
    
    if (options.verbose) {
        verbose_on();
    }

    const char *filename = options.remaining_args[0];
    
    /* Stat the file to get its size */
    struct stat st;
    stat(filename, &st);

    uint8_t *elf_raw_data = malloc(st.st_size);
    debug("Parsing %s as an ELF binary\n", filename);
    FILE *f = fopen(filename, "r");
    fread(elf_raw_data, sizeof(uint8_t), st.st_size, f);
    fclose(f);

    struct ELF64_Data parsed_ELF = {};
    bool parse_success = parse_elf64(elf_raw_data, st.st_size, &parsed_ELF);
    free(elf_raw_data);
    if (!parse_success) {
        exit_status = 1;
        goto cleanup;
        return 1;
    }

    struct Heap_Func_Addrs func_addrs = {};
    get_PLT_addresses(&parsed_ELF, &func_addrs);

    trace_target(options.remaining_args, &func_addrs); 
   
cleanup:
    fflush(stdout);
    fflush(stderr);
    ELF64_Data_destroy(&parsed_ELF);
    return exit_status;
}
