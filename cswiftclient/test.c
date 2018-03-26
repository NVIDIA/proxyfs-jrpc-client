#include <stdio.h>
#include "cswift.h"
#include "sock_pool.h"

int main(int argc, char **argv) {

    if (argc != 3) {
        printf("USAGE: %s <server> <port>\n", argv[0]);
        return -1;
    }

    char *server = argv[1];
    int port = atoi(argv[2]);
    char *file_path = argv[3];

    csw_sock_pool_t *pool = csw_sock_pool_alloc(server, port, 10);
    if (pool == NULL) {
        printf("Failed to allocate pool\n");
        return -1;
    }

    int fd = csw_sock_get(pool);
    if (fd < 0) {
        printf("Failed to get socket from pool - err %d\n", fd);
        return -1;
    }

    char *auth_token = NULL;
    int err = csw_get_auth_token(fd, server, port, "test:tester", "testing", &auth_token);
    if (err < 0) {
        printf("Failed to get auth token - err %d\n", err);
        return -1;
    }

    range_t *ranges = (range_t *)malloc(sizeof(range_t) * 3);

    ranges[0].start = 1;
    ranges[0].end = 10;
    ranges[0].data = (char *)malloc(10);
    bzero(ranges[0].data, 10);
    ranges[0].data_size = 10;

    ranges[1].start = 5;
    ranges[1].end = 15;
    ranges[1].data = (char *)malloc(10);
    bzero(ranges[1].data, 10);
    ranges[1].data_size = 10;

    ranges[2].start = 25;
    ranges[2].end = 35;
    ranges[2].data = (char *)malloc(10);
    bzero(ranges[2].data, 10);
    ranges[2].data_size = 10;

    char *path = strdup("/v1/AUTH_test/cswift/main.c");

    err = csw_get_request(fd, path, server, port, auth_token, ranges, 3);
    if (err != 0) {
        printf("get_request failed with err = %d\n", err);
        return -1;
    }

    header_t *hdr = NULL;
    err = csw_get_response(fd, &hdr, ranges, 3);
    if (err != 0) {
        printf("get_response failed with err = %d\n", err);
        return -1;
    }

    int i = 0;
    for (i = 0; i < 3; i++) {
        printf("range %d <%d-%d>: %s\n", i, ranges[i].start, ranges[i].end, ranges[i].data);
    }

    csw_sock_put(pool, fd);
}