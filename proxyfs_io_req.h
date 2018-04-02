#ifndef __PROXYFS_IO_REQ_H__
#define __PROXYFS_IO_REQ_H__

#include <proxyfs.h>
#include <inttypes.h>

#include "cswiftclient/cswift.h"
#include "cswiftclient/sock_pool.h"
extern char *swift_server;
extern int swift_port;
extern csw_sock_pool_t *global_swift_pool;
#define GLOBAL_SWIFT_POOL_COUNT 100

extern int direct_io;
#define MAX_READ_RETRY 10 // Max retry if we fail to get the data for the read plan from swift.

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


typedef struct read_obj_s {
    range_t   *ranges;
    int        range_count;
    char      *obj_path;
    int        fd;

    struct read_obj_s *next;
} read_obj_t;

typedef struct read_io_plan_s {
    read_obj_t  *objs;
    int         objs_count;
    char        *data;
    int         data_size;
} read_io_plan_t;

typedef struct read_plan_range_s {
    char     *obj_path;
    uint64_t obj_start;
    uint64_t offset;
    uint64_t size;
} read_plan_range_t;

typedef struct read_plan_s {
    uint64_t inode_number;
    uint64_t file_size;
    uint64_t range_count;
    read_plan_range_t  *ranges;
} read_plan_t;

int proxyfs_read_req(proxyfs_io_request_t *req, int sock_fd);
int proxyfs_read_plan_req(proxyfs_io_request_t *req, int sock_fd);
int proxyfs_write_req(proxyfs_io_request_t *req, int sock_fd);

#endif // __PROXYFS_IO_REQ_H__