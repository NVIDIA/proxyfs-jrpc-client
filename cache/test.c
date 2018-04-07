#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cache.h"
#include "map.h"

int map_test() {
    int ret = 0;
    map_t *map = map_init();

    uint64_t i;

    for (i = 0; i < 20; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        ret = map_put(map, key, (void *)i);
        if (ret != 0) {
            printf("Failed to insert into map - err : %d\n", ret);
            return -1;
        }
        free(key);
    }


    for (i= 0; i < 20; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        uint64_t val = (uint64_t)map_get(map, key);
        printf("Get %s %016llx\n", key, i);
        map_delete(map, key);
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

int cache_test() {
    int ret = 0;
    bool evictable = true;
    int num_loops = 20;

    // Make the cache 1 entry less than we need so that we
    // force an evicition during insertion.
    cache_t *cache = cache_init(16 * (num_loops - 1));

    uint64_t  i=0;

    for (i = 0; i < num_loops; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        char *val = (char *)malloc(20);
        sprintf(val, "%016lld", i+1000);

        ret = cache_insert(cache, key, (void *)val, strlen(val), test_evict, true);

        if (ret != 0) {
            printf("Failed to insert into cache - err : %s\n", strerror(ret));
            return -1;
        }
    }

    // Set half the entries to not be evictable
    for (i = 0; i < num_loops; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);

        if (i % 2) {
            cache_set_evictable(cache, key);
        }
        free(key);
    }

    for (i= 0; i < 20; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        char *val = NULL;
        int ret = (uint64_t)cache_get(cache, key, (void **)&val);
        if (!ret) {
            printf("Get %s %s ret: %d\n", key, val, ret);
            cache_evict(cache, key);
        } else {
            // When this key was evicted, the callback already freed the memory.
            printf("Get %s %s ret: %d - key 12 should have already been evicted\n", key, val, ret);
        }
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