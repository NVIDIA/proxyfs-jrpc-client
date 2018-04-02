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

    char *path = strdup("/v1/AUTH_test/test1/zeros");

    range_t *ranges = (range_t *)malloc(sizeof(range_t) * 1);

    int io_size = 65536;
    int i = 0;
    int start = 0;
    for (i = 0, start = 0; i <  1600; i++, start +=io_size) {
        ranges[0].start = start;
        ranges[0].end = start + io_size;
        ranges[0].data = (char *)malloc(io_size);
        ranges[0].data_size = io_size;

        err = csw_get_request(fd, path, server, port, auth_token, ranges, 1);
        if (err != 0) {
            printf("get_request failed with err = %d\n", err);
            return -1;
        }

        header_t *hdr = NULL;
        err = csw_get_response(fd, &hdr, ranges, 1);
        if (err != 0) {
            printf("get_response failed with err = %d\n", err);
            return -1;
        }

        csw_free_header(hdr);
        free(ranges[0].data);
    }

    csw_sock_put(pool, fd);

    return 0;
}