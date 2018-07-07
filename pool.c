// Create and manage a pool of sockets - useful for concurrent operations that need to send data over sockets concurrently.

// APIs:
/*
 * sock_pool_t *sock_pool_create(char *server, int port, int count);
 * int sock_pool_get(sock_pool_t *pool);
 * void sock_pool_put(sock_pool_t *pool, int sock_fd);
 * void sock_pool_put_badfd(sock_pool_t *pool, int sock_fd);
 * int sock_pool_select(sock_pool_t *pool);
 * int sock_pool_destroy(sock_pool_t *pool);
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "socket.h"
#include "debug.h"
#include "pool.h"
#include "fault_inj.h"

void sock_list_free(sock_info_t *list);

// sock_pool_create: Create a socket pool with the specified (count) number of sockets. Later the caller
//                   can request a socket from the pool and put back after use, via Get()/Put().
sock_pool_t *sock_pool_create(char *server, int port, int count)
{
    DPRINTF("sock_pool_create: pool size %d\n", count);

    // Create the socket
    if ( fail(RPC_CONNECT_FAULT) ) {
        // Fault-inject case
        errno = ECONNREFUSED;
        return NULL;
    }

    sock_pool_t *pool = (sock_pool_t *)malloc(sizeof(sock_pool_t));
    if (pool == NULL) {
        PANIC("sock_pool_create(): could not malloc memory for sock_pool_t");
    }
    bzero(pool, sizeof(sock_pool_t));

    pool->server = strdup(server);
    pool->network = strdup("tcp");
    if (pool->server == NULL || pool->network == NULL) {
        PANIC("sock_pool_create(): could not malloc memory for 'tcp' or for server name: '%s'", server);
    }
    pool->port = port;
    pool->pool_count = count;
    pthread_mutex_init(&pool->pool_lock, NULL);
    pthread_cond_init(&pool->pool_cv, NULL);
    pool->available_count = count;
    pool->busy_pool = NULL;
    pool->free_pool = NULL;
    pool->fd_list = (int *)malloc(sizeof(int) * count);
    if (pool->fd_list == NULL) {
        PANIC("sock_pool_create(): could not malloc memory for %d file descriptors", count);
    }
    bzero(pool->fd_list, sizeof(int) * count);

    int i = 0;
    for (i = 0; i < pool->pool_count; i++) {
        sock_info_t *sock_info = (sock_info_t *)malloc(sizeof(sock_info_t));
        if (sock_info == NULL) {
            PANIC("sock_pool_create(): could not malloc memory for sock_info_t number %d", i);
        }
        bzero(sock_info, sizeof(sock_info_t));

        sock_info->sock_idx = i;
        pool->fd_list[i] = -1;

        if (i == 0) {
            pool->free_pool = sock_info;
            sock_info->next = NULL;
        } else {
            sock_info->next = pool->free_pool;
            pool->free_pool = sock_info;
        }
    }

    // verify we can open a connection
    int         fd = sock_pool_get(pool);
    if (fd < 0) {
        goto errout;
    }
    sock_pool_put(pool, fd);

    return pool;

errout:
    // close any open sockets (this can't really happen)
    if (pool->fd_list != NULL) {
        int     i;
        for (i = 0; i < pool->pool_count; i++) {
            if (pool->fd_list[i] >= 0) {
                close(pool->fd_list[i]);
                pool->fd_list[i] = -1;
            }
        }
    }

    // its OK to call free() or sock_list_free() with a NULL pointer
    sock_list_free(pool->free_pool);
    free(pool->fd_list);
    free(pool->server);
    free(pool->network);
    free(pool);

    if (errno == 0) {
        errno = EBADF;
    }
    return NULL;
}

// sock_pool_get: Will return a socket fd from the free pool. If there is no socket in the free pool, this
//                routine will block until a socket becomes available.
//
// If a socket cannot be opened, -1 is returned.
int sock_pool_get(sock_pool_t *pool)
{
    if (pool == NULL) {
        errno = EBADF;
        return -1;
    }

    pthread_mutex_lock(&pool->pool_lock);
    while (pool->available_count <= 0 || pool->pool_blocked) {
        pthread_cond_wait(&pool->pool_cv, &pool->pool_lock);
    }

    // If the first socket is not open then all of them must be closed -- open
    // all of them.  This is necessary because sock_pool_select() is not
    // informed when we open a new socket, so it will not be in the list of fd
    // passed to select(2) and sock_pool_select() will not find out a packet
    // arrived on the new socket until the next time out or a packet arrives on
    // a different socket.
    if (pool->fd_list[0] < 0) {

        DPRINTF("sock_pool_get(): opening sockets");
        int     i;
        for (i = 0; i < pool->pool_count; i++) {
            if (pool->fd_list[i] >= 0) {
                PANIC("sock_pool_get(): found an unexpected open socket at index %d", i);
            }

            pool->fd_list[i] = sock_open(pool->server, pool->port);

            // if an open failed, close them all and leave
            if (pool->fd_list[i] < 0) {
                int     errno_save = errno;
                DPRINTF("sock_pool_get(): open of socket %d failed: %s", i, strerror(errno_save));

                int     j;
                for (j = 0; j < i; j++) {
                    sock_close(pool->fd_list[j]);
                    pool->fd_list[j] = -1;
                }

                errno = errno_save;
                return -1;
            }
        }
    }

    pool->available_count--;
    sock_info_t *sock_info = pool->free_pool;
    pool->free_pool = sock_info->next;
    sock_info->next = pool->busy_pool;
    pool->busy_pool = sock_info;

    pthread_mutex_unlock(&pool->pool_lock);

    return pool->fd_list[sock_info->sock_idx];
}

// sock_pool_put: Put back the socket into free pool. Will wakeup if anyone is waiting for a socket.
void sock_pool_put(sock_pool_t *pool, int sock_fd)
{
    if (pool == NULL) {
        return;
    }

    pthread_mutex_lock(&pool->pool_lock);

    sock_info_t *prev = pool->busy_pool;
    sock_info_t *head = pool->busy_pool;

    while (head != NULL) {
        if (pool->fd_list[head->sock_idx] != sock_fd) {
            prev = head;
            head = head->next;
            continue;
        }

        if (pool->busy_pool == head) {
            pool->busy_pool = head->next;
        } else {
            prev->next = head->next;
        }

        head->next = pool->free_pool;
        pool->free_pool = head;

        pool->available_count++;

        pthread_cond_signal(&pool->pool_cv);

        break;
    }

    pthread_mutex_unlock(&pool->pool_lock);
}

// sock_pool_put_badfd: Put a socket back to the pool after a read() or write()
// on the socket failed.
//
// This code assumes that all the connections in the pool are bad so it blocks
// new get requests, returns the socket to the pool and waits until all other
// outstanding sockets are returned.  Then it closes all the sockets, unblocks
// the pool and lets callers to sock_pool_get() try to re-open them.
void sock_pool_put_badfd(sock_pool_t *pool, int sock_fd)
{
    pthread_mutex_lock(&pool->pool_lock);

    // the first thread to notice will clean things up
    if (pool->pool_blocked) {
        pthread_mutex_unlock(&pool->pool_lock);
        sock_pool_put(pool, sock_fd);
        return;
    }

    // block any new get requests
    pool->pool_blocked = true;
    pthread_mutex_unlock(&pool->pool_lock);

    sock_pool_put(pool, sock_fd);

    // wait until all fd are released
    pthread_mutex_lock(&pool->pool_lock);
    while (pool->available_count < pool->pool_count) {
        pthread_cond_wait(&pool->pool_cv, &pool->pool_lock);
    }

    // close all the file descriptors
    //
    // TODO: what if one of the fd was good and there's an outstanding request
    // on it?
    int         i;
    for (i = 0; i < pool->pool_count; i++) {
        if (pool->fd_list[i] >= 0) {
            close(pool->fd_list[i]);
            pool->fd_list[i] = -1;
        }
    }

    // unblock the pool and wake any waiters
    pthread_mutex_lock(&pool->pool_lock);
    pool->pool_blocked = false;
    pthread_cond_broadcast(&pool->pool_cv);
    pthread_mutex_unlock(&pool->pool_lock);
}

// sock_pool_select: Will return a fd that has data to read. If a non-zero timeout value is specified,
//                   select will wait for the timeout period and if no data to read will return 0.
//
// NOTE: if something is blocked on this select call and other code calls
//       sock_pool_destroy()/_create() sock_pool_put_badfd(), the sock fds will
//       have changed out from under the select. In that case, the select may
//       time out or return an error. The next select will succeed. This
//       manifests as unexpected 5-second (or whatever the timeout) delays in
//       getting responses from ProxyFS.
int sock_pool_select(sock_pool_t *pool, int timeout_in_secs)
{
    if (pool == NULL) {
        return -1;
    }

    DPRINTF("pool_count=%d pool[0]=%d pool[1]=%d timeout=%d\n", pool->pool_count, pool->fd_list[0], pool->fd_list[1], timeout_in_secs);
    struct timeval tv;
    struct timeval *tvptr = NULL;
    if (timeout_in_secs != 0) {
        tv.tv_sec = timeout_in_secs;
        tv.tv_usec = 0;
        tvptr = &tv;
    }

    fd_set set;
    FD_ZERO(&set);

    int i = 0;
    int high_fd = 0;
    for (i = 0; i < pool->pool_count; i++) {
        if (pool->fd_list[i] > 0) {
            FD_SET(pool->fd_list[i], &set);
        }
        if (pool->fd_list[i] > high_fd) {
            high_fd = pool->fd_list[i];
        }
    }

    tvptr = &tv;
    int ret = select(high_fd + 1, &set, NULL, NULL, tvptr); // Will wait indefinitely if tvptr == NULL.

    if (ret <= 0) {
        return ret;
    }

    for (i = 0; i < pool->pool_count; i++) {
        if (pool->fd_list[i] < 0) {
            continue;
        }
        if (FD_ISSET(pool->fd_list[i], &set)) {
            return pool->fd_list[i];
        }
    }

    return -1; // ERROR: select said there is atleast 1 fd to read, but no bit is set in FD_SET.
}

// sock_pool_destroy: Will close all the sockets and destroy the pool. If force is set to true, will close the sockets in
//                    both free and busy pool, otherwise, will return EBUSY if busy pool is not empty.
int sock_pool_destroy(sock_pool_t *pool, bool force)
{
    if (pool == NULL) {
        return EINVAL;
    }

    DPRINTF("sock_pool_destroy: pool size %d\n", pool->pool_count);

    pthread_mutex_lock(&pool->pool_lock);

    if ((force != true) && (pool->busy_pool != NULL)) {
        // Can't destroy the pool when there are outstanding requests.
        pthread_mutex_unlock(&pool->pool_lock);
        return EBUSY;
    }

    sock_list_free(pool->busy_pool);
    sock_list_free(pool->free_pool);

    pthread_cond_destroy(&pool->pool_cv);
    pthread_mutex_unlock(&pool->pool_lock);
    pthread_mutex_destroy(&pool->pool_lock);

    if (pool->fd_list != NULL) {
        int     i;
        for (i = 0; i < pool->pool_count; i++) {
            if (pool->fd_list[i] >= 0) {
                close(pool->fd_list[i]);
                pool->fd_list[i] = -1;
            }
        }

        free(pool->fd_list);
    }

    if (pool->network != NULL) {
        free(pool->network);
    }

    if (pool->server != NULL) {
        free(pool->server);
    }

    free(pool);

    return 0;
}

void sock_list_free(sock_info_t *list)
{
    while (list) {
        sock_info_t *head = list;
        list = head->next;
        free(head);
    }
}
