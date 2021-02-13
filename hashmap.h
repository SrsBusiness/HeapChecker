#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct hashmap {
    uint64_t capacity;
    uint64_t length;
    struct kv_pair *entries;
    uint64_t (*hash)(void *);
    bool (*equals)(void *, void *);
};

struct kv_pair {
    void *k;
    void *v;
};

bool
hashmap_init(
    struct hashmap *map,
    uint64_t capacity,
    uint64_t (*hash)(void *),
    bool (*equals)(void *, void *));
void hashmap_destroy(struct hashmap *map);
bool hashmap_contains(struct hashmap *map, void *key);
void *hashmap_get(struct hashmap *map, void *key);
bool hashmap_add(struct hashmap *map, void *key, void *val);
void hashmap_del(struct hashmap *map, void *key);
