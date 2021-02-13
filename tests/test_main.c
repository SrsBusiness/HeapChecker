#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


#include "test_hashmap.h"


int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_hashmap_resize),
        cmocka_unit_test(test_hashmap_basic),
        cmocka_unit_test(test_hashmap_collision),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
