/*************************************************************************
* @file ah_pthread.h
* @brief pthread wrapper APIs
*
*
*************************************************************************/

#ifndef __AH_PTHREAD_H__
#define __AH_PTHREAD_H__

#include <pthread.h>
#include <errno.h>

#include "ah_assert.h"
#include "ah_logging.h"

/*******************************************************************
  pthread locking APIs
  Most of these are done as macros so that the stack crawl when the
  fatal occurs is in the calling program
*******************************************************************/

#define ah_pthread_mutex_init_default(mutex) \
	do { \
		int rc = pthread_mutex_init(mutex, NULL); \
		ah_fatal_if(rc != 0, "Can't initialize pthread mutex"); \
	} while (0)

#define ah_pthread_mutex_init(mutex, attr) \
	do { \
		int rc = pthread_mutex_init(mutex, attr); \
		ah_fatal_if(rc != 0, "Can't initialize pthread mutex"); \
	} while (0)

static inline boolean ah_pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	int rc = pthread_mutex_trylock(mutex);
	if (likely(rc == 0)) {
		return TRUE;
	}
	ah_fatal_if_debug(rc != EBUSY, "Unexpected error from pthread_mutex_trylock (%d)", rc);
	return FALSE;
}

#define ah_pthread_cond_destroy(cond)       (void)pthread_cond_destroy(cond)
#define ah_pthread_mutex_destroy(mutex)     (void)pthread_mutex_destroy(mutex)

#if AH_BUILD_RELEASE

#define ah_pthread_mutex_lock(mutex)        (void)pthread_mutex_lock(mutex)
#define ah_pthread_mutex_unlock(mutex)      (void)pthread_mutex_unlock(mutex)
#define ah_pthread_cond_init(cond, attr)    (void)pthread_cond_init(cond, attr)

#else

#define ah_pthread_mutex_lock(mutex) \
	do { \
		int rc = pthread_mutex_lock(mutex); \
		ah_fatal_if(rc != 0, "Can't lock pthread mutex"); \
	} while (0)

#define ah_pthread_mutex_unlock(mutex) \
	do { \
		int rc = pthread_mutex_unlock(mutex); \
		ah_fatal_if(rc != 0, "Can't unlock pthread mutex"); \
	} while (0)


#define ah_pthread_cond_init(cond, attr) \
	do { \
		int rc = pthread_cond_init(cond, attr); \
		ah_fatal_if(rc != 0, "Can't init condition variable"); \
	} while (0)

#endif

/*******************************************************************
  pthread threading APIs
*******************************************************************/

/* All aerohive pthreads should use either SCHED_OTHER or SCHED_RR */
#define AH_CLI_PTHREAD_POLICY           SCHED_OTHER
#define AH_SNMP_PTHREAD_POLICY          SCHED_OTHER
#define AH_SKELETON_PTHREAD_POLICY      SCHED_RR

/* All SCHED_OTHER policy phreads always use priority = 0 */
/* Only SCHED_RR policy pthreads need to define priority here */
/* 1 - lowest priority, 99 - highest priority */
#define AH_SKELETON_PTHREAD_PRIORITY     1

/* pthread function type */
typedef void *(*ah_pthread_func_ptr)(void *);

int ah_pthread_create(pthread_t *pTid, ah_pthread_func_ptr func, void *arg, int policy, int priority, boolean inheritsched);

int ah_pthread_setschedparam(pthread_t tid, int policy, int priority);

void ah_signal_maskall(int blcok);
void ah_signal_mask(int block, int signum);
void ah_ptheard_setaffinity(int cpu);

#endif /* __AH_PTHREAD_H__ */
