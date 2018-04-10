#ifndef __map_h__
#define __map_h__

#include <stdint.h>

typedef struct elm_s {
    void     *ptr;
    uint64_t ptr_size;
} elm_t;

typedef struct map_s map_t;

map_t *map_init();
void map_free(map_t *map);

elm_t *map_get(map_t *map, elm_t *key);
int map_put(map_t *map, elm_t *key, elm_t *val);
void map_delete(map_t *map, elm_t *key);

#endif // __map_h__