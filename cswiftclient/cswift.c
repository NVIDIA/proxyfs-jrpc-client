#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include "cswift.h"
#include "sock_pool.h"
#include "internal.h"

int csw_get_auth_token(int fd, char *server, int port, char *usr, char *key, char **auth_token) {
    int len = strlen("GET /auth/v1.0 HTTP/1.1\r\nHost:_:_\r\nUser-Agent: ProxyFS\r\nAccept: */*\r\nX-Auth-User: _\r\nX-Auth-Key: _\r\n\r\n");
    len += strlen(server) +  10 + strlen(usr) + strlen(key);
    int err = 0;

    char *req_buf = (char *)malloc(len);
    bzero(req_buf, len);

    sprintf(req_buf, "GET /auth/v1.0 HTTP/1.1\r\nHost:%s:%d\r\nUser-Agent: ProxyFS\r\nAccept: */*\r\nX-Auth-User: %s\r\nX-Auth-Key: %s\r\n\r\n", server, port, usr, key);
    err = csw_sock_write(fd, req_buf, strlen(req_buf));
    if (err < 0) {
        return err;
    }

    free(req_buf);

    int status = csw_read_status_code(fd, NULL);
    if (status < 0) {
        return -ENOENT;
    }

    header_t *hdr;
    err = csw_read_header(fd, &hdr);
    if (err != 0) {
        return err;
    }

    if (status < 200 || status >= 300) {
        return status;
    }

    err = -ENOENT;
    tag_t *tag = hdr->tags;
    while (tag != NULL) {
        if (strcmp(tag->key, "X-Storage-Token") == 0) {
            *auth_token = strdup(tag->val);
            err = 0;
            break;
        }
        tag = tag->next;
    }

    csw_free_header(hdr);
    return err;
}

int csw_get_request(int fd, char *path, char *server, int port, char *auth_token, range_t *ranges, int range_count) {
    int i, idx;
    int len = strlen("GET /v1/_ HTTP/1.1\r\nHost: _:_\r\nUser-Agent: ProxyFS\r\nRange: bytes=_\r\n\r\n");

    len += strlen(path) + strlen(server) + 10 + 22 * range_count;

    if (auth_token != NULL) {
        len += strlen(auth_token) + strlen("X-Auth-Token: ");
    }
    char *req_buf = (char *)malloc(len);
    bzero(req_buf, len);

    if (auth_token == NULL) {
        sprintf(req_buf, "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: ProxyFS\r\nRange: bytes=", path, server, port);
    } else {
        sprintf(req_buf, "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: ProxyFS\r\nX-Auth-Token:%s\r\nRange: bytes=", path, server, port, auth_token);
    }

    for (i = 0; i < range_count; i++) {
        idx = strlen(req_buf);
        sprintf(&req_buf[idx], "%d-%d", ranges[i].start, ranges[i].end);
        if (i != range_count - 1) {
            idx = strlen(req_buf);
            sprintf(&req_buf[idx], ",");
        }
    }

    idx = strlen(req_buf);
    sprintf(&req_buf[idx], "\r\n\r\n");

    // Write the request to socket: TBD: apply a retry loop logic here.
    int ret = csw_sock_write(fd, req_buf, strlen(req_buf));

    if (ret != strlen(req_buf)) {
        free(req_buf);
        return -1;
    }

    free(req_buf);
    return 0;
}

int csw_get_response(int fd, header_t **headersp, range_t *ranges, int range_count) {

    int status = csw_read_status_code(fd, NULL);
    if (status < 200 || status >= 300) {
        return -ENOENT;
    }

    header_t *hdr;
    int err = csw_read_header(fd, &hdr);
    if (err != 0) {
        return err;
    }

    int i;

    if (range_count == 1) {
        ranges[0].data_size = csw_get_content_length(hdr);
        if (ranges[0].data_size == 0) {
            csw_free_header(hdr);
            return 0;
        }

        err = csw_sock_read(fd, ranges[0].data, ranges[0].data_size);
        if (err <= 0) {
            if (err == 0) {
                err = -EBADF;
            }
            csw_free_header(hdr);
            return err;
        }

        return 0;
    }

    int bsize = csw_get_boundary_info(hdr, NULL);
    char *boundary = (char *)malloc(bsize + 4);
    int start = 0;
    int end = 0;
    char *line = NULL;
    for (i = 0; i < range_count; i++) {
        err = csw_sock_read(fd, boundary, bsize + 4); // boundary start info
        if (err != bsize + 4) {
            csw_free_header(hdr);
            return -EIO;
        }

        tag_t *tag;
        err = csw_read_tag(fd, &tag); // Content type.
        if (err != 0) {
            csw_free_header(hdr);
            return err;
        }
        csw_free_tag(tag);

        err = csw_read_tag(fd, &tag); // Content range start-end
        if (err != 0) {
            csw_free_header(hdr);
            return err;
        }
        err = csw_get_content_range(tag, &start, &end); // Content range start-end
        csw_free_tag(tag);
        if (err != 0) {
            csw_free_header(hdr);
            return err;
        }

        err = csw_read_line(fd, &line);
        if (err != 0) {
            csw_free_header(hdr);
            return err;
        }
        if (line != NULL) {
            free(line); // Should be NULL, if we are free something wrong!
            return -EIO;
        }

        ranges[i].data_size = end - start + 1;
        // assert ranges[i].start == start and ranges[i].end == end
        err = csw_sock_read(fd, ranges[i].data, ranges[i].data_size);
        if (err != ranges[i].data_size) {
            csw_free_header(hdr);
            return -EIO;
        }

        err = csw_read_line(fd, &line);
        if (err != 0) {
            csw_free_header(hdr);
            return err;
        }
        if (line != NULL) {
            free(line); // Should be NULL, if we are free something wrong!
            return -EIO;
        }
    }

    err = csw_sock_read(fd, boundary, bsize + 4); // read the final boundary last.
    if (err != bsize + 4) {
        csw_free_header(hdr);
        return -EIO;
    }

    if (headersp ) {
        *headersp = hdr;
    } else {
        csw_free_header(hdr);
    }

    return 0;
}

int csw_put_chunk_start(int fd, char *path, char *auth_token, header_t *hdr) {
    return -ENOTSUP;
}

int csw_put_chunk_data(int fd, char *body, int len) {
    return -ENOTSUP;
}

int csw_put_chunk_close(int fd) {
    return -ENOTSUP;
}

#if 0

    // First read the response headers:
    // int err = read_headers(fd, headers);
    //

    // read_range()
    // First read the response headers.
    int error = csw_read_headers(fd, headers, &bytes_read);
    if (error) {
        return error;
    }
    fprintf(stderr, "%s() dump response headers!!!!\n", __FUNCTION__);
    csw_print_headers(*headers);

    // TODO - better check??? Other status codes?
    if ((strcmp("200 OK", csw_find_value(*headers, "HTTP/1.1")) != 0) &&
        (strcmp("206 Partial Content", csw_find_value(*headers, "HTTP/1.1")) != 0)) {
        error = EIO;
        return error;
    }

    // TODO - handle multipart response
    // Read body directly into buf passed from VFS
    error = csw_read_body(fd, *headers, ranges, range_index);

    return error;
}

// Read the body length and the body from the socket and put into range
// entry.
//
// We already read all the headers from the socket.  Rest is just the body.
int
csw_read_body(int fd, csw_header_t *headers, csw_range_t *ranges, int range_index) {

    if (fd <= 0) {
        return ENOENT;
    }

    if (csw_find_value(headers, "Content-Length") == NULL)  {
        // NOTE: This may happen if we get a chunked response to a GET.
        //
        // We do not think that Swift does this but it is something to be
        // aware of.
        printf("ERROR: read_body() returned NULL!");
        return EIO;
    }
    int content_length = atoi(csw_find_value(headers, "Content-Length"));

    int bytes_read = 0;
    int bytes_already_read = 0;
    while (1) {
        // TODO - be consistent - use csw_socket_read() or not everywhere
        bytes_read = read(fd, (ranges[range_index].buf + bytes_already_read),
            (content_length - bytes_already_read));
        if (bytes_read < 0) {
            if (errno == EAGAIN) {
                continue;
            }

            // TODO - assume we will die here if problem talking to
            // Swift proxy server in any case other than rcnt > 0?
        }

        bytes_already_read += bytes_read;
        if (bytes_already_read == content_length) {
            break;
        }
    }

    if (bytes_already_read != content_length) {
        printf("%s(): total_bytes_read: %d content_length: %d !!!!!!!\n",
            __FUNCTION__, bytes_already_read, content_length);
    }
    ranges[range_index].buf_len = bytes_already_read;

    return 0;
}


void
csw_print_headers(csw_header_t *headers) {
    printf("headers->free_count: %d headers->count: %d\n", headers->free_count,
        headers->count);

    int i;
    for (i = 0; i < headers->count; i++) {
        printf("headers->tags[%d].key: %s - headers->tags[%d].vals: %s\n", i,
            headers->tags[i].key, i, headers->tags[i].vals);
    }
}

// Free headers data structure and associated memory
void
csw_free_headers(csw_header_t **headers) {
    free((*headers)->rbuf);
    (*headers)->rbuf = NULL;
    free(*headers);
    *headers = NULL;
}

char *
csw_find_value(csw_header_t *headers, char *h) {
    int i;
    for (i = 0; i < headers->count; i++) {
        if (strcmp(headers->tags[i].key, h) == 0) {
            return headers->tags[i].vals;
        }
    }
    return NULL;
}

// Add this new header to headers.
void
csw_add_header(csw_header_t *headers, char *h) {

    // TODO - do remalloc() if free_count == 0
    headers->free_count -= 1;
    int index = headers->count;
    headers->count += 1;

    headers->tags[index].key = h;
}

// Add/Replace value of header indexed by headers->count
void
csw_add_value(csw_header_t *headers, char *v) {
    int index = headers->count - 1;
    headers->tags[index].vals = v;
}

// Read all of the headers off the socket and put into header_t struct.
//
// NOTE: While reading this code, it is important to understand the response
// buffer looks like this example response for a GET:
//      "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nAccept-Ranges: bytes\r\n"
//      "Last-Modified: Tue, 27 Feb 2018 22:10:58 GMT\r\n"
//      "Etag: 6d21ca1eb0f2e97dec7007e243f8c91c\r\nX-Timestamp: 1519769457.25783\r\n"
//      "Content-Type: application/octet-stream\r\nX-Trans-Id: txd4b308ca61584416b6901-005a95d775"
//      "\r\nX-Openstack-Request-Id: txd4b308ca61584416b6901-005a95d775\r\nDate: Tue, 27 Feb 2018"
//      " 22:11:01 GMT\r\n\r\nthis is CHUNK #1"
//
// read_headers() reads everything from the socket up to the body.  The body in the above
// example is "this is CHUNK #1".
int
csw_read_headers(int fd, csw_header_t **headers, int *total_bytes_read) {

    if (fd <= 0) {
        return ENOENT;
    }

    int rcnt;                   // Number of bytes currently read
    int rbuf_pos;                // Current position within rbuf
    int cr_cnt, lf_cnt;         // Count of \r and \n seen
    bool already_reading_value = false; // True if we are in the middle of reading
                                // the value of a header since a value can
                                // include delimiters like ":".
    bool wait_head = true;      // Waiting to see first byte of header
    bool wait_value = false;    // Waiting to see first byte of value
    bool first_value = true;    // The first value is not delimited by a :.
                                // Therefore, set this flag so we correctly
                                // pickup header - "HTTP/1.1" and value "200 OK".
    char *rbuf = malloc(1024);  // Buffer used to read data from socket.

    // TODO - remalloc rbuf if too small?
    // TODO - how do we free rbuf since headers points to it's contents?
    //        probably should be doing strdup()?

    // Initially, create room for 20 header entries.
    // TODO - cleaner way? remalloc()???

    // Want caller to be able to just do "free(headers);"
    int h_entries = 20;
    int h_size = sizeof(csw_header_t) + sizeof(csw_tag_t *) + (sizeof(csw_tag_t) * h_entries);
    *headers = malloc(h_size);
    memset(*headers, 0, h_size);
    (*headers)->free_count = 20;
    (*headers)->rbuf = rbuf;

    // We read the headers 1 byte at a time
    *total_bytes_read = 0;
    while (1) {
        // TODO - be consistent - use csw_socket_read() everywhere or not...
        rcnt = read(fd, (rbuf + *total_bytes_read), 1);
        if (rcnt < 0) {
            if (errno == EAGAIN) {
                continue;
            }

            // TODO - assume we will die here if problem talking to 
            // Swift proxy server in any case other than rcnt > 0?
        }

        rbuf_pos = *total_bytes_read;
        *total_bytes_read += rcnt;

        // We hit the end of this header.  Wait for value.
        //
        // This is only true if the value does not include a ":"
        // which headers like Last-Modified do.
        if (rbuf[rbuf_pos] == ':') {
            if (!already_reading_value) {
                rbuf[rbuf_pos] = '\0';
                wait_value = true;
            }
            continue;
        }

        // We are at the end of a header or end of all headers.
        if (rbuf[rbuf_pos] == '\r') {
            rbuf[rbuf_pos] = '\0';
            cr_cnt++;
            already_reading_value = false;
            continue;
        }

        // We are waiting for either another header or
        // the end of the headers.
        if (rbuf[rbuf_pos] == '\n') {
            lf_cnt++;
            wait_head = true;
            already_reading_value = false;

            // If we have reached the end of the headers we
            // will see \r\n\r\n.  Break here since the rest
            // is the body of the message.
            if ((cr_cnt == 2) && (lf_cnt == 2)) {
                break;
            }
        } else {
            // Now we are either reading header, value or " ".
            cr_cnt = 0;
            lf_cnt = 0;

            if (rbuf[rbuf_pos] == ' ') {
                if (first_value) {
                    rbuf[rbuf_pos] = '\0';
                    wait_value = true;
                    first_value = false;
                }
            } else if (wait_head) {
                    csw_add_header(*headers, &rbuf[rbuf_pos]);
                    wait_head = false;
                } else {
                    if (wait_value) {
                        csw_add_value(*headers, &rbuf[rbuf_pos]);
                        already_reading_value = true;
                        wait_value = false;
                    } else {
                        // The current character is from a header
                        // or a value but is not the first character.
                        continue;
                    }
            }
        }
    }

    // rbuf will be freed with call to free_headers()
    return 0;
}

// Write body of length body_len to socket on FD.
// If FD is 0, it means this is the PUT CHUNK open.
// An FD will be retrieved from the pool and it will be
// returned for use with other PUT CHUNKs for this inode number.
int
csw_put_chunk(char *physPath, char *body, uint64_t body_len, int *fd) {
    int err = 0;

    // PUT request for this chunk.  Use max int and unit64_t as string plus add
    // a fudge factor.
    // TODO - clean up calculation of buffer size
    int buf_len =
        strlen("PUT %s HTTP/1.1\r\nHost: 256.256.256.256:2147483647\r\nUser-Agent: ProxyFS\r\nTransfer-Encoding: chunked\r\n\r\n%X\r\n");
    buf_len += strlen(physPath) + strlen("18446744073709551615") + 10;

    char *buf = malloc(buf_len);
    memset(buf, 0, buf_len);
    buf[0] = '\0';

    // If fd == 0 it means this is the first PUT CHUNK.
    // Get and FD and make sure to return it to the caller.
    if (*fd == 0) {
        *fd = csw_get_fd();

        // Now write headers
        sprintf(buf,
            "PUT %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: ProxyFS\r\nTransfer-Encoding: chunked\r\n\r\n",
            physPath, cswift_server, cswift_port);

        // Send header for PUT
        uint64_t bytes_written  = write(*fd, buf, strlen(buf));
        printf("SEND HEADER - Write returned - bytes_written: %llu strlen(buf): %ld buf: %s\n", bytes_written, strlen(buf), buf);
        if (bytes_written != strlen(buf)) {
            printf("csw_sock_write() failed with err: %d - %s\n", err, strerror(err));
            goto done;
        }
    }

    // Write the length of the CHUNK
    buf[0] = '\0';
    sprintf(buf, "%llX\r\n", body_len);

    // TODO - change to use csw_sock_write() all places!!!

    uint64_t bytes_written = write(*fd, buf, strlen(buf));
    printf("SEND CHUNK LENGTH - Write returned - err: %d strlen(buf): %ld buf: %s\n", err, strlen(buf), buf);
    if (bytes_written != strlen(buf)) {
        printf("csw_sock_write() failed with bytes_written: %llu strlen(buf): %ld\n", bytes_written, strlen(buf));
        goto done;
    }

    // Send the payload of this chunk
    bytes_written = write(*fd, body, body_len);
    printf("SEND PAYLOAD - Write returned - bytes_written: %llu body_len: %llu body: %s\n", bytes_written, body_len, body);
    if (bytes_written != body_len) {
        printf("csw_sock_write() failed with bytes_written: %llu body_len: %llu\n", bytes_written, body_len);
        goto done;
    }

    // Send the termination string for this chunk
    buf[0] = '\0';
    sprintf(buf, "%s", LFCR);
    bytes_written = write(*fd, buf, strlen(buf));
    if (bytes_written != strlen(buf)) {
        printf("%s() failed with bytes_written: %llu strlen(buf): %ld\n", __FUNCTION__, bytes_written, strlen(buf));
        goto done;
    }

done:
    free(buf);

    // TODO - setp proper error return
    return err;
}

int
csw_put_chunk_close(int fd) {
    int err = 0;

    int buf_len = 1 + strlen(LFCR) + strlen(LFCR) + 1;

    char *buf = malloc(buf_len);
    memset(buf, 0, buf_len);
    buf[0] = '\0';

    // Write the length of the CHUNK
    sprintf(buf, "0%s%s", LFCR, LFCR);
printf("SEND CHUNK CLOSE - buf: %s buf_len: %d\n", buf, buf_len);
    uint64_t bytes_written = write(fd, buf, buf_len);
    if (bytes_written != buf_len) {
        printf("%s() failed with bytes_written: %llu strlen(buf): %ld\n", __FUNCTION__, bytes_written, strlen(buf));
        goto done;
    }

    csw_header_t *headers = NULL;
    int total_bytes_read;
    csw_read_headers(fd, &headers, &total_bytes_read);

    csw_print_headers(headers);

    // TODO - better check??? Other status codes?
    if ((strcmp("200 OK", csw_find_value(headers, "HTTP/1.1")) != 0) &&
        (strcmp("206 Partial Content", csw_find_value(headers, "HTTP/1.1")) != 0)) {
        err = EIO;
        goto done;
    }

done:
    free(buf);

    // Release the FD we are using
    csw_release_fd(fd);

    // TODO - set proper error return
    return err;
}

#endif