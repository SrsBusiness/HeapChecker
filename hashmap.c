#include "hashmap.h"

/*
 * File-static helpers ********************************************************
 */

static inline uint64_t
probe(uint64_t index, uint64_t capacity)
{
    /* linear, could make it quadratic if necessary */
    uint64_t next = (index + 1) % capacity;
    return next;
}

/* caller must keep map->length consistent! */
static inline bool
hashmap_add_without_resize(struct hashmap *map, void *key, void *val)
{
    uint64_t index = map->hash(key) % map->capacity;
    struct kv_pair *entries = map->entries;
    while (entries[index].k != NULL && !map->equals(entries[index].k, key)) {
        index = probe(index, map->capacity);
    }
    bool new = entries[index].k != key;
    entries[index] = (struct kv_pair){.k = key, .v = val};
    return new;
}

static inline bool
hashmap_find(struct hashmap *map, void *key, uint64_t *index_out)
{
    bool found = false;
    uint64_t index = map->hash(key) % map->capacity;
    struct kv_pair *entries = map->entries;
    while (entries[index].k != NULL) {
        if (map->equals(entries[index].k, key)) {
            found = true;
            break;
        }
        index = probe(index, map->capacity);
    }
    if (index_out != NULL) {
        *index_out = index;
    }
    return found; 
}

static inline bool
resize_if_needed(struct hashmap *map)
{
    uint64_t load_factor = (map->length + 1) * 100 / map->capacity;
    if (load_factor <= 50) {
        return true;
    }
    
    uint64_t capacity_old = map->capacity;
    struct kv_pair *entries_old = map->entries;
    map->capacity *= 2;
    map->entries = calloc(map->capacity, sizeof(map->entries[0]));
    /* map->length not changing, no need to update */
    if (map->capacity != 0 && map->entries == NULL) {
        return false;
    }

    for (uint64_t i = 0; i < capacity_old; i++) {
        if (entries_old[i].k != NULL &&
            !hashmap_add_without_resize(map, entries_old[i].k, entries_old[i].v)) {
            return false;
        }
    }
    
    free(entries_old);
    return true;
}


/*
 * API ************************************************************************
 */

bool
hashmap_init(
    struct hashmap *map,
    uint64_t capacity,
    uint64_t (*hash)(void *),
    bool (*equals)(void *, void *))
{
    *map = (struct hashmap){
        .capacity = capacity,
        .length = 0,
        .entries = calloc(capacity, sizeof(struct kv_pair)),
        .hash = hash,
        .equals = equals,
    };
    return capacity == 0 || map->entries != NULL;
}

void
hashmap_destroy(struct hashmap *map)
{
    free(map->entries);
    map->entries = NULL;
}

bool
hashmap_contains(struct hashmap *map, void *key)
{
    return hashmap_find(map, key, NULL);
}

void *
hashmap_get(struct hashmap *map, void *key)
{
    uint64_t index = 0;
    bool found = hashmap_find(map, key, &index);
    if (found) {
        return map->entries[index].v;
    } else {
        return NULL;
    }
}

/*
 * Adds key, val to the map if it doesn't already exist. Do nothing
 * if it already exists.
 *
 * Returns false on errors including
 *     - Failed to resize map
 */
bool
hashmap_add(struct hashmap *map, void *key, void *val)
{
    if (!resize_if_needed(map)) {
        return false;
    }
    
    if (hashmap_add_without_resize(map, key, val)) {
        map->length++;
    }
    return true;
}

/* deletes the key and its value from the map */
void
hashmap_del(struct hashmap *map, void *key)
{
    uint64_t index = 0;
    if (hashmap_find(map, key, &index)) {
        map->length--;
        map->entries[index] = (struct kv_pair){.k=NULL, .v = NULL};
    }
}
