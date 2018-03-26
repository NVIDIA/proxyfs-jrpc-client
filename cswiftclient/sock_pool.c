#include "sock_pool.h"

typedef struct sock_entry_s {
    int fd;
    struct sock_entry_s *next;
} sock_entry_t;

struct csw_sock_pool {
    int count;

    sock_entry_t *mem_pool;
    sock_entry_t *busy_pool;
    sock_entry_t *free_pool;

    pthread_mutex_t pool_lock;
    pthread_cond_t  pool_cv;
};

static struct addrinfo *sock_addrinfo(char* hostname, int port) {
    // Lookup the IP address of the host.  By default, getaddrinfo(3) chooses
    // the best IP address for a host according to RFC 3484. I believe this
    // means it will perfer IPv6 addresses if they exist and this host can reach
    // them.  In theory, multiple addresses can be returned and this code should
    // cycle through them until it finds one that works.  This code just uses
    // the first one.
    struct addrinfo    *info;
    char                portstr[20];
    int                 err;

    snprintf(portstr, sizeof(portstr), "%d", port);
    err = getaddrinfo(hostname, portstr, NULL, &info);
    if (err != 0) {
        printf("ERROR: sockopen(): getaddrinfo(%s) returned %s\n", hostname, gai_strerror(err));
        return NULL;
    }
    if (info->ai_family != AF_INET && info->ai_family != AF_INET6) {
        printf("ERROR: %s(): got unkown address family %d for hostname %s\n",
                __FUNCTION__, info->ai_family, hostname);
        return NULL;
    }

    // Set errno to zero before system calls
    errno = 0;
    return info;
}

static int sock_open(struct addrinfo *info) {
    // Create the socket
    int sockfd = socket(info->ai_family, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("ERROR: %s(): %s opening %s socket\n", __FUNCTION__, strerror(errno),
                info->ai_family == AF_INET ? "AF_INET" : "AF_INET6");
        return -1;
    }

    // Connect to the far end
    if (connect(sockfd, info->ai_addr, info->ai_addrlen) < 0) {
        printf("ERROR: %s(): %s connecting socket\n", __FUNCTION__, strerror(errno));
        return -1;
    }

    int flag = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0) {
        printf("ERROR %s() - %s setting TCP_NODELAY option\n", __FUNCTION__,
            strerror(errno));
        return -1;
    }

    return sockfd;
}

static void sock_list_close(sock_entry_t *head, int count) {
    int i = 0;
    for (i = 0; i < count && head != NULL; i++, head = head->next) {
        int fd = head->fd;
        close(fd);
    }
}

csw_sock_pool_t *csw_sock_pool_alloc(char *server, int port, int count) {
    struct addrinfo *info = sock_addrinfo(server, port);
    if (info == NULL) {
        return NULL;
    }

    csw_sock_pool_t *pool = (csw_sock_pool_t *)malloc(sizeof(csw_sock_pool_t));
    if (!pool) {
        free(info);
        return NULL;
    }

    pool->mem_pool = (sock_entry_t *)malloc(sizeof(sock_entry_t) * count);
    if (!pool->mem_pool) {
        free(info);
        free(pool);
        return NULL;
    }
    bzero(pool->mem_pool, sizeof(sock_entry_t) * count);

    pool->free_pool = pool->mem_pool;
    pool->busy_pool = NULL;

    int i = 0;
    for (i = 0; i < count; i++, pool->count++) {
        sock_entry_t *ent = &pool->mem_pool[i];
        ent->next = &pool->mem_pool[i+1];
        ent->fd = sock_open(info);
        if (ent->fd < 0) {
            csw_sock_pool_free(pool);
            free(info);
            return NULL;
        }
    }
    pool->mem_pool[count - 1].next = NULL;

    pthread_mutex_init(&pool->pool_lock, NULL);
    pthread_cond_init(&pool->pool_cv, NULL);

    free(info);

    return pool;
}

void csw_sock_pool_free(csw_sock_pool_t *pool) {
    if (pool == NULL) {
        return;
    }

    sock_list_close(pool->mem_pool, pool->count);
    pthread_cond_destroy(&pool->pool_cv);
    pthread_mutex_destroy(&pool->pool_lock);

    free(pool->mem_pool);
    free(pool);
}

int csw_sock_get(csw_sock_pool_t *pool) {
    if (pool == NULL) {
        return -1;
    }

    pthread_mutex_lock(&pool->pool_lock);
    while (pool->free_pool == NULL) {
        pthread_cond_wait(&pool->pool_cv, &pool->pool_lock);
    }

    sock_entry_t *ent = pool->free_pool;
    pool->free_pool = ent->next;
    ent->next = pool->busy_pool;
    pool->busy_pool = ent;
    int fd = ent->fd;
    pthread_mutex_unlock(&pool->pool_lock);

    return fd;
}

void csw_sock_put(csw_sock_pool_t *pool, int fd) {
    if (pool == NULL) {
        return;
    }

    pthread_mutex_lock(&pool->pool_lock);
    if (pool->busy_pool == NULL) {
        pthread_mutex_unlock(&pool->pool_lock);
        return;
    }
    sock_entry_t *ent = pool->busy_pool;
    pool->busy_pool = ent->next;
    ent->fd = fd;
    ent->next = pool->free_pool;
    pool->free_pool = ent;
    pthread_cond_signal(&pool->pool_cv);
    pthread_mutex_unlock(&pool->pool_lock);
}

int csw_sock_read(int fd, char* buf, int len) {
    int i = 0;
    int bytes_read = 0;

    for (i = 0; i < len; i+= bytes_read) {
        bytes_read = read(fd, &buf[i], len - bytes_read);
        if (bytes_read <= 0) {
            if (bytes_read == -EAGAIN) {
                bytes_read = 0;
                usleep(10000); // TBD: set to a configurable value.
                continue;
            }
            if (bytes_read == 0) {
                bytes_read = -EIO;
            }
            return bytes_read;
        }
    }

    return bytes_read;
}

int csw_sock_write(int fd, const char* buf, int len) {
    int i = 0;
    int bytes_wrote = 0;

    for (i = 0; i < len; i+= bytes_wrote) {
        bytes_wrote = write(fd, &buf[i], len - bytes_wrote);
        if (bytes_wrote <= 0) {
            if (bytes_wrote == -EAGAIN) {
                bytes_wrote = 0;
                usleep(10000); // TBD: set to a configurable value.
                continue;
            }

            if (bytes_wrote == 0) {
                bytes_wrote = -EIO;
            }
            return bytes_wrote;
        }
    }

    return bytes_wrote;
}