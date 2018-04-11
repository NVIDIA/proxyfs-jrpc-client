#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "key.h"

p_key_t *make_key(void *src, uint64_t size) {
    p_key_t *key = malloc(sizeof(p_key_t));
    memset(key, 0, sizeof(p_key_t));
    key->ptr = malloc(size);
    key->ptr_size = size;
    bcopy(src, key->ptr, size);

    return key;
}
