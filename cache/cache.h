#ifndef __CACHE_H__
#define __CACHE_H__

#include <stdint.h>
#include <stdbool.h>
#include "map.h"

typedef struct cache_s cache_t;

cache_t *cache_init(int cache_size);
void cache_free(cache_t *cache);

int cache_insert(cache_t *cache, elm_t *key, elm_t *val, void (*evict_cb)(elm_t *),
                 bool evictable);
int cache_get(cache_t *cache, elm_t *key, elm_t **val);
int cache_evict(cache_t *cache, elm_t *key);

// Allow the cache entry to be evicted.  For example, if the entry is a write
// which has not been flushed yet it will be inserted as evictable == false.
// Once the entry has been flushed it can be set evictable == true.
int cache_set_evictable(cache_t *cache, elm_t *key);

#endif // __CACHE_H__
