#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>  // this needs to be included before ah_pthread.h
#undef _GNU_SOURCE

#include "ah_pthread.h"
#include "ah_lib.h"

/*
 * ah_pthread_create
 *
 * create a POSIX thread.
 *
 * pTid - return the pthead ID, no pthread ID is returned if NULL is passed.
 * func - thread function.
 * arg  - thread argument.
 * policy - schedule policy: one of SCHED_RR, SCHED_OTHER.
 * priority - schedule priority:
 *            1 - 99 if policy = SCHED_RR, ignored for SCHED_OTHER.
 * inheritsched - whether inherit scheduler policy and priority from parent.
 *            1 - inherit from parent, policy and priority is ignored.
 *            0 - no inherit.
 *
 * Returns 0 if succeeded, errno if failed.
 */
int ah_pthread_create(pthread_t *pTid, ah_pthread_func_ptr func, void *arg, int policy, int priority, boolean inheritsched)
{
	int rc;
	pthread_attr_t attr;
	struct sched_param param;
	int inherit;
	pthread_t tid;

	if (policy != SCHED_OTHER && policy != SCHED_RR && policy != SCHED_FIFO) {
		return EINVAL;
	}

	if (policy == SCHED_OTHER) {
		priority = 0;
	}

	if (inheritsched) {
		inherit = PTHREAD_INHERIT_SCHED;
	} else {
		inherit = PTHREAD_EXPLICIT_SCHED;
	}

	pthread_attr_init(&attr);
	rc = pthread_attr_setschedpolicy(&attr, policy);
	AH_CHECK_RC(rc);
	memset(&param, 0, sizeof(param));
	param.sched_priority = priority;
	rc = pthread_attr_setschedparam(&attr, &param);
	AH_CHECK_RC(rc);
	rc = pthread_attr_setinheritsched(&attr, inherit);
	AH_CHECK_RC(rc);

	/* Create the thread */
	rc = pthread_create(&tid, &attr, func, arg);
	AH_CHECK_RC(rc);

	if (pTid) {
		*pTid = tid;
	}

	return rc;
}


/* ah_pthread_setschedparam
 *
 * set scheduler parameter of running thread.
 *
 * policy - schedule policy: one of SCHED_RR, SCHED_OTHER.
 * priority - schedule priority:
 *            1-99 if policy = SCHED_RR, ignored for SCHED_OTHER.
 *
 * Returns 0 if succeeded, errno if failed.
 */
int ah_pthread_setschedparam(pthread_t tid, int policy, int priority)
{
	struct sched_param param;

	if (policy != SCHED_OTHER && policy != SCHED_RR) {
		return EINVAL;
	}

	if (policy == SCHED_OTHER) {
		priority = 0;
	}

	memset(&param, 0, sizeof(param));
	param.sched_priority = priority;

	return (pthread_setschedparam(tid, policy, &param));
}

void ah_signal_maskall(int block)
{
	sigset_t    mask;

	sigemptyset(&mask);
	sigfillset(&mask);

	if (block) {
		pthread_sigmask(SIG_BLOCK, &mask, NULL);
	} else {
		pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
	}

}


void ah_signal_mask(int block, int signum)
{
	sigset_t    mask;

	sigemptyset(&mask);
	sigaddset(&mask, signum);

	if (block) {
		pthread_sigmask(SIG_BLOCK, &mask, NULL);
	} else {
		pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
	}
}

void ah_ptheard_setaffinity(int cpu)
{
	cpu_set_t cpuset;
	pthread_t thread;
	int ret;

	thread = pthread_self();
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		ah_log_old(AH_LOG_WARNING, "failed to set cpu affinity to cpu%d\n", cpu);
		return;
	}
	ah_log_old(AH_LOG_WARNING, "set thread cpu affinity to cpu%d\n", cpu);
}

