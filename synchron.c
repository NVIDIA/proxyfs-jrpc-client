
#include "synchron.h"
#include "debug.h"

#include <string.h>

// synchron_init is used to protect synchron_mutexattrp
//
mutex_t                         synchron_lock = MUTEX_DECL_INITIALIZER;
pthread_mutexattr_t * volatile  synchron_mutexattrp = NULL;

void synchron_init(void);

// Initialize a mutex to be an non-recursive, error checking mutex
//
void
mutex_init(mutex_t *mtxp)
{
    int         rc;

    synchron_init();
    rc = pthread_mutex_init(mtxp, synchron_mutexattrp);
    if (rc != 0) {
        PANIC("pthread_mutex_init() failed with error: %s", strerror(rc));
    }

}

// Lock a mutex
//
void
mutex_lock(mutex_t *mtxp)
{
    int         rc;
    rc = pthread_mutex_lock(mtxp);
    if (rc != 0) {
        PANIC("pthread_mutex_lock() failed with error: %s", strerror(rc));
    }
}

// Unlock a mutex (will panic if it was not locked by this thread)
void
mutex_unlock(mutex_t *mtxp)
{
    int         rc;
    rc = pthread_mutex_unlock(mtxp);
    if (rc != 0) {
        PANIC("pthread_mutex_unlock() failed with error: %s", strerror(rc));
    }
}

void
synchron_init(void)
{
    pthread_mutexattr_t *       attrp;
    int                         rc;

    // Strictly speaking, checking synchron_mutexattrp without getting the lock
    // is wrong.  An optimizing compiler could perform the assignment to
    // synchron_mutexattrp before it finishes initializing the attributes or a
    // CPU could perform the stores out of order (although x86_64will not do
    // that).  The calls to mutex_lock()/mutex_unlock() create a memory barrier
    // to prevent that from happening.
    mutex_lock(&synchron_lock);

    if (synchron_mutexattrp != NULL) {
        mutex_unlock(&synchron_lock);
        return;
    }

    attrp = (pthread_mutexattr_t *)malloc(sizeof(pthread_mutexattr_t));
    pthread_mutexattr_init(attrp);

    rc = pthread_mutexattr_settype(attrp, PTHREAD_MUTEX_ERRORCHECK_NP);
    if (rc != 0) {
        PANIC("pthread_mutexattr_settype() failed with error: %s", strerror(rc));
    }
    synchron_mutexattrp = attrp;

    mutex_unlock(&synchron_lock);
    return;
}
