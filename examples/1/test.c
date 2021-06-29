#include <stdlib.h>
#include <stdio.h>

int main() {
    void *x1 = NULL, *x2, *x4, *x8, *x16, *x32;
    x1 = calloc(1, 1);
    x2 = calloc(2, 1);
    x4 = calloc(4, 1);
    x8 = calloc(8, 1);
    x16 = calloc(16, 1);
    x16 = realloc(x16, 32);
    x32 = malloc(32);
    x32 = reallocarray(x32, 2, 32);
    printf("malloc: %p\n", malloc);
    free(x1);
    free(x2);
    free(x4);
    free(x8);
    free(x16);
    free(x32);

    return 0;
}
