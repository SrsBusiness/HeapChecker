#include "log.h"
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static bool verbose = false;

void 
verbose_toggle()
{
    verbose = !verbose;
}

void
verbose_on()
{
    verbose = true;
}

void verbose_off()
{
    verbose = false;
}

int
debug(const char *fmt, ...)
{
    if (!verbose) {
        return 0;
    }
    va_list ap;
    va_start(ap, fmt);

    /* sizeof includes '\0', strlen does not */
    uint64_t debug_fmt_len = sizeof("DEBUG: ") + strlen(fmt);
    char *debug_fmt = calloc(debug_fmt_len, 1);
    strncat(debug_fmt, "DEBUG: ", debug_fmt_len);
    strncat(debug_fmt, fmt, debug_fmt_len);
    int ret = vprintf(debug_fmt, ap);
    free(debug_fmt);
    va_end(ap);
    return ret;
}

int
info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    /* sizeof includes '\0', strlen does not */
    uint64_t info_fmt_len = sizeof("INFO: ") + strlen(fmt);
    char *info_fmt = calloc(info_fmt_len, 1);
    strncat(info_fmt, "INFO: ", info_fmt_len);
    strncat(info_fmt, fmt, info_fmt_len);
    int ret = vprintf(info_fmt, ap);
    free(info_fmt);
    va_end(ap);
    return ret;
}

int
error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    /* sizeof includes '\0', strlen does not */
    uint64_t error_fmt_len = sizeof("ERROR: ") + strlen(fmt);
    char *error_fmt = calloc(error_fmt_len, 1);
    strncat(error_fmt, "ERROR: ", error_fmt_len);
    strncat(error_fmt, fmt, error_fmt_len);
    int ret = vfprintf(stderr, error_fmt, ap);
    free(error_fmt);
    va_end(ap);
    return ret;
}
