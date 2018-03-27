#include "cswift.h"
#include "internal.h"

int csw_read_line(int fd, char **bufp) {
    int ret = 0;

    int alloc_size = 256;
    char *line = (char *)malloc(512);

    int consumed = 0;
    bool cr = false;
    int idx = 0;

    while (1) {
        consumed++;
        if (consumed >= alloc_size) {
            alloc_size += alloc_size;
            line = realloc(line, alloc_size);
        }

        int ret = read(fd, &line[idx], 1);
        if (ret <= 0) {
            free(line);
            return -EIO;
        }

        if ((cr == true) && line[idx] == '\n') {
            line[idx+1] = '\0';
            break;
        }

        if (line[idx] == '\r') {
            cr = true;
        } else {
            cr = false;
        }

        idx++;
    }

    if (strlen(line) == 2) {
        // Read a empty line - return NULL:
        free(line);
        *bufp = NULL;
        return 0;
    }

    line[strlen(line) - 2] = '\0';
    *bufp = line;
    return strlen(line);
}

int csw_read_tag(int fd, tag_t **tagp) {
    char *line, *line_start;

    int err = csw_read_line(fd, &line);
    if (line == NULL || err <= 0) {
        *tagp = NULL;
        return 0;
    }

    line_start = line;

    tag_t *tag = (tag_t *)malloc(sizeof(tag_t));
    bzero(tag, sizeof(tag_t));

    char *key = strsep(&line, ":");
    tag->key = strdup(key);

    while (line != NULL && line[0] == ' ') {
        line = &line[1];
    }

    if (line != NULL) {
        tag->val = strdup(line);
    }

    free(line_start);

    *tagp = tag;
    return 0;
}

void csw_free_tag(tag_t *tag) {
    if (tag == NULL) {
        return;
    }

    if (tag->key != NULL) {
        free(tag->key);
    }

    if (tag->val != NULL) {
        free(tag->val);
    }

    free(tag);
}

int csw_read_header(int fd, header_t **hdrp) {
    int err = 0;
    header_t *hdr = (header_t *)malloc(sizeof(header_t));
    bzero(hdr, sizeof(header_t));

    tag_t *tag;

    while (((err = csw_read_tag(fd, &tag)) == 0) && tag != NULL) {
        tag->next = hdr->tags;
        hdr->tags = tag;
        hdr->tag_count++;
    }

    if (err != 0) {
        csw_free_header(hdr);
        return err;
    }

    if (hdr->tag_count == 0) {
        free(hdr);
        return -ENOENT;
    }

    *hdrp = hdr;
    return 0;
}

void csw_free_header(header_t *hdr) {
    if (hdr == NULL) {
        return;
    }
    while (hdr->tags != NULL) {
        tag_t *tag = hdr->tags;
        hdr->tags = tag->next;
        csw_free_tag(tag);
    }

    free(hdr);
}

int csw_read_status_code(int fd, char **status_infop) {
    char *line, *line_start;

    int err = csw_read_line(fd, &line);
    if (err < 0) {
        if (status_infop) {
            *status_infop = NULL;
        }
        return err;
    }

    line_start = line;

    // Example format of the status line: HTTP/1.1 206 Partial Content\r\n
    char *token = strsep(&line, " ");
    token = strsep(&line, " ");
    if (token == NULL) {
        free(line_start);
        return -ENOENT;
    }

    int status = atoi(token);
    if (status_infop) {
        if (line != NULL) {
            *status_infop = strdup(line);
        } else {
            *status_infop = NULL;
        }
    }

    free(line_start);

    return status;
}

int csw_get_content_range(tag_t *tag, int *start, int *end) {
    if (tag == NULL) {
        return -ENOENT;
    }

    char *val = strdup(tag->val);
    char *val_start = val;

    // Example value format: bytes 11-15/5227
    char *tmp = strsep(&val, " "); // remobyte "bytes "
    char *range = strsep(&val, "/");
    if (range == NULL) {
        free(val_start);
        return -ENOENT;
    }
    char *marker = strsep(&range, "-");
    if (marker == NULL) {
        free(val_start);
        return -ENOENT;
    }

    if (range == NULL) {
        free(val_start);
        return -ENOENT;
    }

    *start = atoi(marker);
    *end = atoi(range);
    free(val_start);
    return 0;
}

int csw_get_boundary_info(header_t *hdr, char **boundaryp) {
    if (hdr == NULL) {
        return 0;
    }

    tag_t *tag = hdr->tags;
    while (tag != NULL) {
        if (strcmp(tag->key, "Content-Type") == 0) {
            char *val = strdup(tag->val);
            char *val_start = val;
            char *boundry = strsep(&val, "=");
            if (val == NULL) {
                free(val_start);
                return 0;
            }
            int len = strlen(val);
            if (boundaryp != NULL) {
                *boundaryp = strdup(val);
            }
            free(val_start);
            return len;
        }

        tag = tag->next;
    }

    return 0;
}

int csw_get_content_length(header_t *hdr) {
    if (hdr == NULL) {
        return 0;
    }

    tag_t *tag = hdr->tags;
    while(tag != NULL) {
        if (strcmp(tag->key, "Content-Length") == 0) {
            return atoi(tag->val);
        }
        tag = tag->next;
    }

    return 0;
}