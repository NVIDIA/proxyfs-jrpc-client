#include "proxyfs.h"
#include "debug.h"
#include "proxyfs_io_req.h"
#include "cache/cache.h"
#include "internal.h"
#include "socket.h"

#include "cswiftclient/cswift.h"
#include "cswiftclient/sock_pool.h"

#include "proxyfs_io_req.h"

static int read_no_cache(proxyfs_io_request_t *req, int sock_fd);
static int read_seg_cache(proxyfs_io_request_t *req, int sock_fd);
static int read_file_cache(proxyfs_io_request_t *req, int sock_fd);

static int get_data(mount_pvt_t *pvt, char *path, uint64_t offset, uint64_t length, char **data, int *data_size);

static void insert_range(read_obj_t *obj, int start, int count, char *buf);
static int read_io_plan_rec_add(read_io_plan_t *rp, char *buf, int count, int obj_start, char *obj_path);
static read_io_plan_t *build_read_io_plan(read_plan_t *rp, proxyfs_io_request_t *req);
static int get_read_io_plan_data(read_io_plan_t *rp);
static void free_read_io_plan(read_io_plan_t *rp);

static read_plan_t *buf_to_readplan(char *buf, uint64_t offset);
static int get_read_plan(mount_handle_t *mh, uint64_t ino, uint64_t offset, uint64_t length, int sock_fd, read_plan_t **rpp);
static void free_read_plan(read_plan_t *rp);

int proxyfs_read_plan_req(proxyfs_io_request_t *req, int sock_fd) {
    if ((req == NULL) || (req->mount_handle == NULL) || (req->data == NULL)) {
        return EINVAL;
    }

    switch (read_io_type) {
    case NO_CACHE: return read_no_cache(req, sock_fd);
    case SEG_CACHE: return read_seg_cache(req, sock_fd);
    case FILE_CACHE: return read_file_cache(req, sock_fd);
    }

    return EINVAL; // we don't know the type of read function to use.
}

static int read_no_cache(proxyfs_io_request_t *req, int sock_fd) {
    read_plan_t *rp;

    mount_handle_t *mh = req->mount_handle;
    mount_pvt_t *pvt = (mount_pvt_t *)mh->pvt_data;

    int ret = get_read_plan(mh, req->inode_number, req->offset, req->length, sock_fd, &rp);
    if (ret != 0) {
        req->error = ret;
        return 0;
    }

    read_io_plan_t *io_plan = build_read_io_plan(rp, req);
    free_read_plan(rp);
    if (io_plan == NULL) {
        req->error = EIO;
        return 0;
    }

    ret = get_read_io_plan_data(io_plan);
    req->out_size = io_plan->data_size;

    free_read_io_plan(io_plan);
    req->error = ret;

    return 0;
}

static int read_seg_cache(proxyfs_io_request_t *req, int sock_fd) {
    read_plan_t *rp;

    mount_handle_t *mh = req->mount_handle;
    mount_pvt_t *pvt = (mount_pvt_t *)mh->pvt_data;
    int err = 0;

retry:
    err = get_read_plan(mh, req->inode_number, req->offset, req->length, sock_fd, &rp);
    if (err != 0) {
        req->error = err;
        return 0;
    }

    read_io_plan_t *io_plan = build_read_io_plan(rp, req);
    free_read_plan(rp);
    if (io_plan == NULL) {
        req->error = EIO;
        return 0;
    }

    int i;

    char key[512];

    for (i = 0; i < io_plan->objs_count; i++) {
        read_obj_t *obj = &io_plan->objs[i];

        int idx;
        for (idx = 0; idx < obj->range_count; idx++) {
            int fill_cnt;
            uint64_t off;
            int buf_off = 0;

            range_t *range = &obj->ranges[idx];

            for (off = range->start; off <= range->end; off += fill_cnt, buf_off += fill_cnt)  {
                uint64_t seg = off / pvt->cache_line_size;
                sprintf(key, "%s_%016llx", obj->obj_path, seg);

                char *data = NULL;
                int err = cache_get(pvt->cache, key, (void **)&data);
                if (err != 0) {
                    if (err != ENOENT) {
                        free_read_io_plan(io_plan);
                        req->error = err;
                        return 0;
                    }

                    int data_size;
                    int err = get_data(pvt, key, seg * pvt->cache_line_size, pvt->cache_line_size, &data, &data_size);
                    if (err != 0) {
                        free_read_io_plan(io_plan);
                        // Failed to read from the key, we have a stale plan, start all over again!
                        goto retry;
                    }

                    cache_insert(pvt->cache, key, data, data_size, NULL);
                }

                fill_cnt = pvt->cache_line_size - (off % pvt->cache_line_size);
                if (fill_cnt > obj->ranges[idx].end - off + 1) {
                    fill_cnt = obj->ranges[idx].end - off + 1;
                }

                bcopy(&range->data[buf_off], &data[off % pvt->cache_line_size], fill_cnt);
            }
        }
    }

    req->error = 0;
    req->out_size = io_plan->data_size;
    return 0;
}

static int read_file_cache(proxyfs_io_request_t *req, int sock_fd) {

    read_plan_t *rp;

    mount_handle_t *mh = req->mount_handle;
    mount_pvt_t *pvt = (mount_pvt_t *)mh->pvt_data;

    int err = 0;

    char key[50];


    uint64_t off = req->offset;
    uint64_t end = req->offset + req->length;
    uint64_t fill_cnt = 0;
    int buf_off = 0;

    sprintf(key, "%016llx_size", req->inode_number);
    int size;
    err = cache_get(pvt->cache, key, (void **)&size);
    if (err != 0) {
        if (err != ENOENT) {
            req->error = err;
            return 0;
        }

        proxyfs_stat_t *stp;
        err = proxyfs_get_stat(mh, req->inode_number, &stp);
        if (err != 0) {
            req->error = err;
            return 0;
        }

        size = stp->size;
        free(stp);
        cache_insert(pvt->cache, key, (void *)(intptr_t)size, sizeof(int), NULL);
    }

    if (end > size) {
        end = size;
    }

    char *req_data = (char *)req->data;

    for (off = req->offset; off < end; off += fill_cnt, buf_off += fill_cnt) {
        fill_cnt = pvt->cache_line_size - off % pvt->cache_line_size;

        if (end - off < fill_cnt) {
            fill_cnt = end - off;
        }

        uint64_t seg = off / pvt->cache_line_size;
        sprintf(key, "%016llx_%016llx", req->inode_number, seg);
        char *data;
        err = cache_get(pvt->cache, key, (void **)&data);
        if (err != 0) {
            if (err != ENOENT) {
                req->error = err;
                return 0;
            }

            proxyfs_io_request_t cache_req = *req;
            cache_req.offset = seg * pvt->cache_line_size;
            cache_req.length = pvt->cache_line_size;
            cache_req.data = data = (char *)malloc(pvt->cache_line_size);

            err = read_no_cache(&cache_req, sock_fd);
            if (err != 0 || cache_req.error != 0) {
                req->error = cache_req.error;
                free(cache_req.data);
                return err;
            }

            cache_insert(pvt->cache, key, data, pvt->cache_line_size, NULL);
        }


        bcopy(&data[off % pvt->cache_line_size], &req_data[buf_off], fill_cnt);
    }

    req->error = 0;
    req->out_size = end - req->offset;

    return 0;
}

int get_data(mount_pvt_t *pvt, char *path, uint64_t offset, uint64_t length, char **data, int *data_size) {
        // TBD: Optimize the code to work with available sockets instead of waiting for all the sockets to become available.
    range_t range;
    range.start = offset;
    range.end = offset + length - 1;
    range.data = (char *)malloc(length);
    range.data_size = 0;

    int fd = csw_sock_get(global_swift_pool);
    int err = csw_get_request(fd, path, swift_server, swift_port, NULL, &range, 1);
    if (err == 0) {
        err = csw_get_response(fd, NULL, &range, 1);
    }
    csw_sock_put(global_swift_pool, fd);

    return err;
}

static void free_read_io_plan(read_io_plan_t *rp) {
    if (rp == NULL) {
        return;
    }

    read_obj_t *objs = rp->objs;
    while (objs) {
        read_obj_t *tmp = objs;
        objs = objs->next;
        free(tmp->ranges);
        free(tmp->obj_path);
        free(tmp);
    }

    free(rp);
}

static void insert_range(read_obj_t *obj, int start, int count, char *buf) {
    obj->ranges = (range_t *)realloc(obj->ranges, sizeof(range_t) * (obj->range_count + 1));
    obj->ranges[obj->range_count].start = start;
    obj->ranges[obj->range_count].end = start + count;
    obj->ranges[obj->range_count].data = buf;
    obj->ranges[obj->range_count].data_size = count;
    obj->range_count++;
}

static int read_io_plan_rec_add(read_io_plan_t *rp, char *buf, int count, int obj_start, char *obj_path) {
    // Check if the object is already present, if so, then add the entry:
    int i = 0;
    read_obj_t *obj = rp->objs;
    for (i = 0; i < rp->objs_count && obj != NULL; i++, obj = obj->next) {
        if (strcmp(obj->obj_path, obj_path) == 0) {
            insert_range(obj, obj_start, count, buf);
            return 0;
        }
    }

    obj = (read_obj_t *)malloc(sizeof(read_obj_t));
    obj->obj_path = strdup(obj_path);
    obj->range_count = obj->fd = 0;
    obj->ranges = NULL;
    obj->next = rp->objs;
    rp->objs = obj;
    rp->objs_count++;

    insert_range(obj, obj_start, count, buf);

    return 0;
}

static int get_read_io_plan_data(read_io_plan_t *rp) {
    int i = 0;
    int err = 0;
    read_obj_t *obj = rp->objs;

    mount_handle_t *mt = rp->req->mount_handle;
    mount_pvt_t *pvt = mt->pvt_data;

    // TBD: Optimize the code to work with available sockets instead of waiting for all the sockets to become available.
    for (i = 0; i < rp->objs_count && obj != NULL; i++, obj = obj->next) {
        if (!obj->obj_path || (strcmp(obj->obj_path, "") == 0)) { // skip holes, buffer is already zero filled.
            continue;
        }
        obj->fd = csw_sock_get(global_swift_pool);
    }

    for (i = 0, obj = rp->objs; i < rp->objs_count && obj != NULL; i++, obj = obj->next) {
        if (!obj->obj_path || (strcmp(obj->obj_path, "") == 0)) { // skip holes, buffer is already zero filled.
            continue;
        }
        int err = csw_get_request(obj->fd, obj->obj_path, swift_server, swift_port, NULL, obj->ranges, obj->range_count);
        if (err != 0) {
            goto done;
        }
    }

    for (i = 0, obj = rp->objs; i < rp->objs_count && obj != NULL; obj = obj->next) {
        if (!obj->obj_path || (strcmp(obj->obj_path, "") == 0)) { // skip holes, buffer is already zero filled.
            continue;
        }
        int err = csw_get_response(obj->fd, NULL, obj->ranges, obj->range_count);
        if (err != 0) {
            goto done;
        }
    }

done:
    for (i = 0, obj = rp->objs; i < rp->objs_count && obj != NULL; i++, obj = obj->next) {
        if (!obj->obj_path || (strcmp(obj->obj_path, "") == 0)) { // skip holes, buffer is already zero filled.
            continue;
        }
        csw_sock_put(global_swift_pool, obj->fd);
    }

    return -err;
}

static read_io_plan_t *build_read_io_plan(read_plan_t *rp, proxyfs_io_request_t *req) {
    uint64_t start = req->offset;
    int count;

    if (start > rp->file_size) {
        count = 0;
    } else if ((start + req->length) > rp->file_size) {
        count = rp->file_size - start;
    } else {
        count = req->length;
    }

    // Walk through the file read_plan to build io read_plan:
    read_io_plan_t *io_rp = (read_io_plan_t *)malloc(sizeof(read_io_plan_t));
    bzero(io_rp, sizeof(read_io_plan_t));

    io_rp->req = req;
    io_rp->data = req->data;
    io_rp->data_size = count;

    int i;
    int buf_idx = 0;
    for (i = 0; i < rp->range_count && count > 0; i++) {
        if ((rp->ranges[i].offset + rp->ranges[i].size) < start) {
            continue;
        }

        uint64_t read_in_rec = rp->ranges[i].size + rp->ranges[i].offset - start;
        uint64_t elm_start = rp->ranges[i].obj_start + start - rp->ranges[i].offset;
        uint64_t elm_count = read_in_rec > count ? count : read_in_rec;
        count -= elm_count;
        start += elm_count;
        read_io_plan_rec_add(io_rp, &((char *)req->data)[buf_idx], elm_count, elm_start, rp->ranges[i].obj_path);
    }

    return io_rp;
}

// buffer format:
//      uint64_t inode_numer // for this readplan
//      uint64_t buf_size //covered bu the readplan
//      uint64_t range_count
//      <range records - range_count>:
//          char *obj_path - NULL terminated.
//          uint64_t start
//          uint64_t count

static read_plan_t *buf_to_readplan(char *buf, uint64_t offset) {
    read_plan_t *rp = (read_plan_t *)malloc(sizeof(read_plan_t));
    bzero(rp, sizeof(read_plan_t));

    rp->file_size = *((uint64_t *)buf);
    buf += 8;

    rp->read_plan_size = *((uint64_t *)buf);
    buf += 8;

    rp->range_count = *((uint64_t *)buf);
    buf += 8;
    int i = 0;

    rp->ranges = (read_plan_range_t *)malloc(sizeof(read_plan_range_t) * rp->range_count);
    bzero(rp->ranges, sizeof(read_plan_range_t) * rp->range_count);

    uint64_t rec_size = 0;
    for (i = 0; i < rp->range_count; i++, offset += rec_size) {
        char *obj_path = buf;
        buf += strlen(buf);
        int start = *((uint64_t *)buf);
        buf += 8;
        rec_size = *((uint64_t *)buf);
        buf += 8;
        rp->ranges[i].obj_path = strdup(obj_path);
        rp->ranges[i].obj_start = start;
        rp->ranges[i].offset = offset;
        rp->ranges[i].size = rec_size;
    }

    return rp;
}

static int get_read_plan(mount_handle_t *mh, uint64_t ino, uint64_t offset, uint64_t length, int sock_fd, read_plan_t **rpp) {
    int err = 0;
     io_req_hdr_t req_hdr = {
        .op_type      = REQ_READPLAN,
        .mount_id     = mh->mount_id,
        .inode_number = ino,
        .offset       = offset,
        .length       = length,
    };

    io_resp_hdr_t resp_hdr;

    *rpp = NULL;

    err = write_to_socket(sock_fd, &req_hdr, sizeof(req_hdr));
    if (err != 0) {
        return err;
    }

    // Receive response header
    err = read_from_socket(sock_fd, &resp_hdr, sizeof(resp_hdr));
    if (err != 0) {
        return err;
    }

    if (resp_hdr.error != 0) {
        return resp_hdr.error;
    }

    if (resp_hdr.io_size == 0) {
        return EIO;
    }

    char *read_plan_buf = (char *)malloc(resp_hdr.io_size);
    err = read_from_socket(sock_fd, read_plan_buf, resp_hdr.io_size);
    if (err != 0) {
        err = -err;
        if ((err == EPIPE) || (err == ENODEV) || (err = EBADF)) {
            // TBD: Build a proper error handling mechanism to retry the operation.
            PANIC("Failed to read response from proxyfsd <-> rpc client socket\n");
        }

        free(read_plan_buf);
        return err;
    }

    read_plan_t *rp = buf_to_readplan(read_plan_buf, offset);
    rp->inode_number = ino;
    *rpp = rp;
    free(read_plan_buf);

    return 0;
}

static void free_read_plan(read_plan_t *rp) {
    if (rp == NULL) {
        return;
    }

    free(rp->ranges);
    free(rp);
}