#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include "proxyfs.h"
#include "cache/cache.h"
#include "cache/map.h"

typedef struct mount_pvt_s {
    uint64_t cache_line_size;
    cache_t *cache;
    map_t   *rplans;
} mount_pvt_t;

#endif // __INTERNAL_H__