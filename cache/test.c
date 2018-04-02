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
    }


    for (i= 0; i < 20; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        uint64_t val = (uint64_t)map_get(map, key);
        printf("Get %s %016llx\n", key, i);
        map_delete(map, key);
    }

    map_free(map);

    return 0;
}

int cache_test() {
    int ret = 0;
    cache_t *cache = cache_init(1024);

    uint64_t  i=0;

    for (i = 0; i < 20; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        char *val = (char *)malloc(20);
        sprintf(val, "%016lld", i+1000);

        ret = cache_insert(cache, key, (void *)val, strlen(val), NULL);
        if (ret != 0) {
            printf("Failed to insert into cache - err : %d\n", ret);
            return -1;
        }
    }

    for (i= 0; i < 20; i++) {
        char *key = (char *)malloc(20);
        sprintf(key, "%016llx", i);
        char *val;
        int ret = (uint64_t)cache_get(cache, key, (void **)&val);
        printf("Get %s %s\n", key, val);
        cache_evict(cache, key);
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