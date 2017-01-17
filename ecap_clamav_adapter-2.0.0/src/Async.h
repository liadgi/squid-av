/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_ASYNC_H
#define ECAP_CLAMAV_ADAPTER_ASYNC_H

// a pthreads wrapper to allow compilation without pthreads support

#ifdef HAVE_PTHREAD
#include <pthread.h>
#else

#include <cerrno>

union pthread_mutex_t {};
union pthread_mutexattr_t {};
union pthread_attr_t {};

typedef unsigned long int pthread_t;

#ifndef ENOTSUP
#ifdef EOPNOTSUPP
#define ENOTSUP EOPNOTSUPP
#else
#define ENOTSUP 95
#endif /* EOPNOTSUPP */
#endif /* ENOTSUP */

extern "C" {
int pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *) { return ENOTSUP; }
int pthread_mutex_destroy(pthread_mutex_t *) { return ENOTSUP; }
int pthread_mutex_trylock(pthread_mutex_t *) { return ENOTSUP; }
int pthread_mutex_lock(pthread_mutex_t *) { return ENOTSUP; }
int pthread_mutex_unlock(pthread_mutex_t *) { return ENOTSUP; }
int pthread_attr_init(pthread_attr_t *) { return ENOTSUP; }
int pthread_attr_destroy(pthread_attr_t *) { return ENOTSUP; }
int pthread_attr_setdetachstate(pthread_attr_t *, int) { return ENOTSUP; }
int pthread_create(pthread_t *__restrict, const pthread_attr_t *, void *(*)(void *), void *) { return ENOTSUP; }
} // extern "C"

#endif // HAVE_PTHREAD

#endif
