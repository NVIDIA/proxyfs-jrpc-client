#ifndef __PROXYFS_IO_REQ_H__
#define __PROXYFS_IO_REQ_H__

#include <proxyfs.h>
#include <inttypes.h>

#include "cswiftclient/sock_pool.h"
extern char *swift_server;
extern int swift_port;
extern csw_sock_pool_t *global_swift_pool;
#define GLOBAL_SWIFT_POOL_COUNT 100

typedef enum {
    REQ_WRITE    = 1001,
    REQ_READ     = 1002,
    REQ_READPLAN = 1003
} io_req_type_t;

typedef struct {
    uint64_t   op_type;
    uint64_t   mount_id;
    uint64_t   inode_number;
    uint64_t   offset;
    uint64_t   length;
} io_req_hdr_t;

typedef struct {
    uint64_t   error;
    uint64_t   io_size;
} io_resp_hdr_t;

int proxyfs_read_req(proxyfs_io_request_t *req, int sock_fd);
int proxyfs_read_plan_req(proxyfs_io_request_t *req, int sock_fd);
int proxyfs_write_req(proxyfs_io_request_t *req, int sock_fd);

#endif // __PROXYFS_IO_REQ_H__