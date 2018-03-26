#ifndef __CSW_SOCK_POOL_H__
#define __CSW_SOCK_POOL_H__

#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>

typedef struct csw_sock_pool csw_sock_pool_t;

csw_sock_pool_t *csw_sock_pool_alloc(char *server, int port, int count);
void csw_sock_pool_free(csw_sock_pool_t *pool);
int csw_sock_get(csw_sock_pool_t *pool);
void csw_sock_put(csw_sock_pool_t *pool, int fd);

int csw_sock_read(int fd, char *buf, int len);
int csw_sock_write(int fd, const char* buf, int len);

#endif // __CSW_SOCK_POOL_H__