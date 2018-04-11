#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "cache.h"
#include "map.h"

int map_test() {
    int ret = 0;
    map_t *map = map_init();

    uint64_t i;

    for (i = 0; i < 20; i++) {
        uint64_t t = i;
        p_key_t *key = make_key(&t, sizeof(uint64_t));

        uint64_t *z = malloc(sizeof(uint64_t));
        *z = i;
        ret = map_put(map, key, (void *)z);

        if (ret != 0) {
            printf("Failed to insert into map - err : %d\n", ret);
            return -1;
        }
        free(key->ptr);
        free(key);
    }


    for (i= 0; i < 20; i++) {
        uint64_t t = i;
        p_key_t *key = make_key(&t, sizeof(uint64_t));

        uint64_t *val = map_get(map, key);

        printf("Get i: %" PRId64 " val: %" PRId64 "\n", i, *val);
        map_delete(map, key);
        free(val);
        free(key->ptr);
        free(key);
    }

    map_free(map);

    return 0;
}

// This is a test callback when a key/val is evicted.
void
test_evict(void *val) {
    // Only thing to do in our case is free the val
    printf("%s() - val: %s\n", __FUNCTION__, val);
    free(val);
}

// This is the format of a cache entry key.
typedef struct cache_key_s {
    uint64_t    inode_number;
    uint64_t    offset;
} cache_key_t;

void build_cache_key(uint64_t i, uint64_t offset, cache_key_t **ck, p_key_t **k) {
    *ck = malloc(sizeof(cache_key_t));
    (*ck)->inode_number = i;
    (*ck)->offset = offset;
    *k = make_key(*ck, sizeof(cache_key_t));
}

int cache_test() {
    int ret = 0;
    bool evictable = true;
    int num_loops = 20;

    // Make the cache 1 entry less than we need so that we
    // force an evicition during insertion.
    cache_t *cache = cache_init(1024 * (num_loops - 1));

    uint64_t  i=0;

    uint64_t cur_offset = 0;
    cache_key_t *ck = NULL;
    p_key_t *key = NULL;
    for (i = 0; i < num_loops; i++) {
        // First come up with a cache key
        build_cache_key(i, cur_offset, &ck, &key);

        cur_offset += 1024*1024;

        // Now dummy up a sample buffer
        uint64_t buf_sz = 1024;
        char *buf = malloc(buf_sz);
        sprintf(buf, "Hello world i: %" PRId64, i);

        // Insert into cache
        ret = cache_insert(cache, key, (void *)buf, buf_sz, test_evict, true);

        if (ret != 0) {
            printf("Failed to insert into cache - err : %s\n", strerror(ret));
            return -1;
        }

        free(ck);
        free(key->ptr);
        free(key);
    }

    // Set half the entries to not be evictable
    cur_offset = 0;
    for (i = 0; i < num_loops; i++) {
        // First come up with a cache key
        build_cache_key(i, cur_offset, &ck, &key);

        cur_offset += 1024*1024;

        if (i % 2) {
            cache_set_evictable(cache, key);
        }
        free(ck);
        free(key->ptr);
        free(key);
    }

    cur_offset = 0;
    for (i= 0; i < num_loops; i++) {
        // First come up with a cache key
        build_cache_key(i, cur_offset, &ck, &key);

        cur_offset += 1024*1024;

        char *val = NULL;
        int ret = (uint64_t)cache_get(cache, key, (void **)&val);
        if (!ret) {
            cache_key_t *tmp_ck = key->ptr;
            printf("Get tmp_ck --- inode: %" PRId64 " offset: %" PRId64 " val: %s ret: %d\n",
                    tmp_ck->inode_number, tmp_ck->offset, val, ret);
            cache_evict(cache, key);
        } else {
            // When this key was evicted, the callback already freed the memory.
            printf("Get ck -- inode: %" PRId64 " offset: %" PRId64 \
                " ret: %d - key 18 should have already been evicted\n", ck->inode_number,
                ck->offset, ret);
        }
        free(ck);
        free(key->ptr);
        free(key);
    }

    cache_free(cache);

    return 0;
}

int main() {
    int ret = map_test();
    if (ret != 0) {
        printf("Map test failed\n");
        return -1;
    }

    ret = cache_test();
    if (ret != 0) {
        printf("Cache test failed\n");
    }

    return 0;
}