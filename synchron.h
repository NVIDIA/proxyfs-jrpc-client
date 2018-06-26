/**
 * Syncronization primitives with error checking
 */

#ifndef __PFS_SYNCHRON_H__
#define __PFS_SYNCHRON_H__

#include <pthread.h>

// Define a "new" mutex type so we can add additional debug code later.
//
// These are error checking, non-recursive mutexes.
//
typedef pthread_mutex_t mutex_t;

// This can be used to initialize static mutex declarations (a call to
// mutex_init() is not required).  It is used as:
//
// mutex_t mylock = MUTEX_DECL_INITIALIZER;
//
#define MUTEX_DECL_INITIALIZER  PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP

// Initialize a mutex before use.
//
extern void     mutex_init(pthread_mutex_t *);

// Lock and unlock a pthread_mutex.  Panic if any errors occur.
//
extern void     pfs_mutex_lock(pthread_mutex_t *);
extern void     pfs_mutex_unlock(pthread_mutex_t *);

#endif  // #ifndef __PFS_SYNCHRON_H__
