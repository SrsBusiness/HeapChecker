#include "breakpoint.h"
#include "elf_parse.h"
#include "heap.h"
#include "log.h"
#include "hashmap.h"

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
#include <sys/wait.h>
#include <sys/ptrace.h>

const char *heap_func_names[] = {
    "calloc",
    "malloc",
    "realloc",
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
        if (!breakpoint_init(pid, addr, func_id, b)) {
            return false;
        }
        if (!set_breakpoint(pid, b)) {
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

bool
wait_pid(pid_t pid) {
    int status;
    waitpid(pid, &status, 0);
    /* 
     * PTRACE_O_TRACEEXEC is not set, so the child process will receive a SIGTRAP signal
     * and halt here right before the new program begins execution. This gives us a change
     * to set breakpoints at calloc, malloc, realloc, and free() before the program resumes.
     */
    if (WIFEXITED(status)) {
        error("Target process exited unexpectedly with status %d\n", WEXITSTATUS(status));
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
handle_calloc(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, uint64_t rsp, uint64_t nmemb, uint64_t size)
{
    /* Read return address */
    uint64_t return_addr = 0;
    if (!read_addr(pid, rsp, &return_addr)) {
        error("Failed to read return address\n");
        return false;
    }

    struct breakpoint ret = {};
    if (!breakpoint_init(pid, return_addr, HEAP_NONE, &ret)) {
        error("Failed to initialize return breakpoint\n");
    }



    struct buffer *b = malloc(sizeof(*b));
    *b = (struct buffer){};


    return true;
}

bool
handle_malloc(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers)
{
    return true;
}

bool
handle_realloc(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers)
{
    return true;
}


/*
 * free() is the simplest to handle because it returns void. This means we have no
 * reason to set a breakpoint on its return address to capture the return value
 */
bool
handle_free(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers, uint64_t ptr)
{
    return true;
}

bool
handle_breakpoint(pid_t pid, struct hashmap *breakpoints, struct hashmap *buffers)
{
    struct user_regs_struct regs = {};    
    if (!get_regs(pid, &regs)) {
        return false;
    }

    /* RIP is now 1 more than the address of the INT3 we wrote */
    regs.rip--;
    uint64_t break_addr = regs.rip;
    struct breakpoint *b = hashmap_get(breakpoints, (void *)break_addr);
    if (b == NULL) {
        error("Target process hit breakpoint at unexpected address\n");
        return false;
    }
    
    /* Read return address */
    uint64_t return_addr = 0;
    struct breakpoint ret = {};

    switch(b->func_id) {
    case HEAP_CALLOC:
    case HEAP_MALLOC:
    case HEAP_REALLOC:
        if (!read_addr(pid, regs.rsp, &return_addr)) {
            error("Failed to read return address\n");
            return false;
        }
        if (!breakpoint_init(pid, return_addr, HEAP_NONE, &ret)) {
            error("Failed to initialize return breakpoint\n");
        }
        break;
    }


    clear_breakpoint(pid, b);


    bool success = false;
    switch (b->func_id) {
    case HEAP_CALLOC:
        success = handle_calloc(pid, breakpoints, buffers, regs.rsp, regs.rdi, regs.rsi);
        break;
    case HEAP_MALLOC:
        success = handle_malloc(pid, breakpoints, buffers);
        break;
    case HEAP_REALLOC:
        success = handle_realloc(pid, breakpoints, buffers);
        break;
    case HEAP_FREE:
        success = handle_free(pid, breakpoints, buffers, regs.rdi);
        break;
    default:
        error("Target process hit unexpected breakpoint\n");
        break;
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
    if (!wait_pid(pid)) {
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
        error("Failed to set breakpoints at calloc, malloc, realloc, and free\n");
        return false;
    }
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    while (true) {
        debug("Waiting for breakpoint\n");
        if (!wait_pid(pid)) {
            return false;
        }

        if (!handle_breakpoint(pid, &breakpoints, &buffers)) {
            return false;
        }
    }
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
