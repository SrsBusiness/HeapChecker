#pragma once

#include <stdint.h>

enum HEAP_FUNCTION {
    HEAP_NONE = -1,
    HEAP_FUNC_FIRST,
    HEAP_CALLOC = HEAP_FUNC_FIRST,
    HEAP_MALLOC,
    HEAP_REALLOC,
    HEAP_REALLOCARRAY,
    HEAP_FREE,
    HEAP_FUNC_LAST = HEAP_FREE,
    HEAP_FUNC_COUNT
};

extern const char *heap_func_names[HEAP_FUNC_COUNT];

struct Heap_Func_Addrs {
    uint64_t addrs[HEAP_FUNC_COUNT];
};
