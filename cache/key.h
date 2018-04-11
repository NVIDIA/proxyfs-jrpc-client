#ifndef __key_h__
#define __key_h__

#include <stdint.h>

typedef struct p_key_s {
    void     *ptr;
    uint64_t ptr_size;
} p_key_t;

// Function to make a key and initialize it
p_key_t *make_key(void *src, uint64_t size);

#endif // __key_h__