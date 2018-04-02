#ifndef __map_h__
#define __map_h__

typedef struct map_s map_t;

map_t *map_init();
void map_free(map_t *map);

void *map_get(map_t *map, char *key);
int map_put(map_t *map, char *key, void *val);
void map_delete(map_t *map, char *key);

#endif // __map_h__