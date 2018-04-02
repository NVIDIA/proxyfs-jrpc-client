#ifndef __CACHE_H__
#define __CACHE_H__

typedef struct cache_s cache_t;

cache_t *cache_init(int cache_size);
void cache_free(cache_t *cache);

int cache_insert(cache_t *cache, char *key, void *val, int size, void (*evict_cb)(void *));
int cache_get(cache_t *cache, char *key, void **val);
int cache_evict(cache_t *cache, char *key);

#endif // __CACHE_H__