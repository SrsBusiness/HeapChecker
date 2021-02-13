#pragma once

#include "hashmap.h"

static inline uint64_t
hash(void *elem)
{
    return (uint64_t)elem;
}

static inline bool
equals(void *a, void *b)
{
    return a == b;
}

static inline void
test_hashmap_basic(void **state)
{
    /* test basic operations */
    struct hashmap map;
    assert_true(hashmap_init(&map, 64, hash, equals));
    assert_int_equal(map.capacity, 64);
    assert_int_equal(map.length, 0);
    assert_non_null(map.entries);
    assert_ptr_equal(map.hash, hash);
    assert_ptr_equal(map.equals, equals);

    /* Add 5, 5 */
    assert_true(hashmap_add(&map, (void *)5, (void *)5));
    assert_int_equal(map.capacity, 64);
    assert_int_equal(map.length, 1);
    assert_true(hashmap_contains(&map, (void *)5));
    assert_ptr_equal(hashmap_get(&map, (void *)5), (void *)5);

    /* Add 5, 5 again */
    assert_true(hashmap_add(&map, (void *)5, (void *)5));
    assert_int_equal(map.capacity, 64);
    assert_int_equal(map.length, 1);
    assert_true(hashmap_contains(&map, (void *)5));
    assert_ptr_equal(hashmap_get(&map, (void *)5), (void *)5);

    /* Add 5, 7 */
    assert_true(hashmap_add(&map, (void *)5, (void *)7));
    assert_int_equal(map.capacity, 64);
    assert_int_equal(map.length, 1);
    assert_true(hashmap_contains(&map, (void *)5));
    assert_ptr_equal(hashmap_get(&map, (void *)5), (void *)7);

    /* Test the negative of hashmap_contains() */
    assert_false(hashmap_contains(&map, (void *)6)); 

    /* Deleting 6 should have no effect */
    hashmap_del(&map, (void *)6);
    assert_int_equal(map.capacity, 64);
    assert_int_equal(map.length, 1);
    assert_true(hashmap_contains(&map, (void *)5));

    /* Delete 5 */
    hashmap_del(&map, (void *)5);
    assert_int_equal(map.capacity, 64);
    assert_int_equal(map.length, 0);
    assert_false(hashmap_contains(&map, (void *)5));

    hashmap_destroy(&map);
    assert_null(map.entries);
}

static inline void
test_hashmap_resize(void **state)
{
    struct hashmap map;
    assert_true(hashmap_init(&map, 64, hash, equals));
    for (uint64_t i = 1; i <= 32; i++) {
        assert_true(hashmap_add(&map, (void *)i, (void *)i));
    }
    assert_int_equal(map.length, 32);
    assert_int_equal(map.capacity, 64);

    assert_true(hashmap_add(&map, (void *)33, (void *)33));
    
    assert_int_equal(map.length, 33);
    assert_int_equal(map.capacity, 128);
    
    for (uint64_t i = 1; i <= 33; i++) {
        assert_true(hashmap_contains(&map, (void *)i));
    }

    for (uint64_t i = 1; i <= 33; i++) {
        hashmap_del(&map, (void *)i);
    }

    assert_int_equal(map.length, 0);
    hashmap_destroy(&map);
}

static inline void
test_hashmap_collision(void **state)
{
    struct hashmap map;
    assert_true(hashmap_init(&map, 64, hash, equals));

    assert_true(hashmap_add(&map, (void *)5, (void *)5));
    assert_true(hashmap_add(&map, (void *)69, (void *)69));
    assert_int_equal(map.length, 2);
    assert_true(hashmap_contains(&map, (void *)5));
    assert_true(hashmap_contains(&map, (void *)69));
    assert_ptr_equal(hashmap_get(&map, (void *)5), (void *)5);
    assert_ptr_equal(hashmap_get(&map, (void *)69), (void *)69);

    assert_true(hashmap_add(&map, (void *)133, (void *)133));
    assert_int_equal(map.length, 3);
    assert_true(hashmap_contains(&map, (void *)5));
    assert_true(hashmap_contains(&map, (void *)69));
    assert_true(hashmap_contains(&map, (void *)133));
    assert_ptr_equal(hashmap_get(&map, (void *)5), (void *)5);
    assert_ptr_equal(hashmap_get(&map, (void *)69), (void *)69);
    assert_ptr_equal(hashmap_get(&map, (void *)133), (void *)133);

    hashmap_destroy(&map);
}
