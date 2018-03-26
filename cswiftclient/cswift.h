#ifndef __CSWIFT_H__
#define __CSWIFT_H__

#include <stdbool.h>
#include <string.h>

typedef struct tag_s {
    char *key;
    char *val;

    struct tag_s *next;
} tag_t;

typedef struct header_s {
    int tag_count;
    tag_t *tags;   // list of tags
} header_t;

typedef struct range_s {
    int   start;
    int   end;
    char *data;
    int   data_size;
} range_t;

int csw_get_auth_token(int fd, char *server, int port, char *usr, char *key, char **auth_token);
int csw_get_request(int fd, char *path, char *server, int port, char *auth_token, range_t *ranges, int range_count);
int csw_get_response(int fd, header_t **headers, range_t *ranges, int range_count);

int csw_put_chunk_start(int fd, char *path, char *auth_token, header_t *hdr);
int csw_put_chunk_data(int fd, char *body, int len);
int csw_put_chunk_close(int fd);

void csw_free_header(header_t *hdr);

#endif // __CSWIFT_H__