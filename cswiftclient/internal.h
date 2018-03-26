#ifndef __CSW_INTERNAL_H__
#define __CSW_INTERNAL_H__

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

#include "cswift.h"

int csw_read_line(int fd, char **bufp);
int csw_read_tag(int fd, tag_t **tagp);
int csw_read_header(int fd, header_t **hdrp);
int csw_read_status_code(int fd, char **status_infop);
void csw_free_tag(tag_t *tag);

int csw_get_content_length(header_t *hdr);
int csw_get_content_range(tag_t *tag, int *start, int *end);
int csw_get_boundary_info(header_t *hdr, char **boundaryp);

#endif // __CSW_INTERNAL_H__