#include <unistd.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include "ah_nptimer.h"
#include "ah_lib.h"
#include "ah_event.h"

/*
 * timer resolution 1 sec
 */
#define AP_NPTIMER_STOPPED   0x01            /* timer already stopped */
#define AP_NPTIMER_CALLING   0x02            /* timer is calling */
struct ah_nptimer_ {
	struct ah_nptimer_    *at_prev;     /* double link list */
	struct ah_nptimer_    *at_next;
	uint8_t                  at_flag;
	int16_t                 at_count;
	uint32_t                 at_fire;     /* when to fire the timer, sec since this instance is started */
	ah_nptimer_callback_t  at_func;
	void                  *at_data;
};
#define is_ah_nptimer_stopped(t) ( (t)->at_flag & AP_NPTIMER_STOPPED)
#define is_ah_nptimer_calling(t) ( (t)->at_flag & AP_NPTIMER_CALLING)
#define set_ah_nptimer_stopped(t)   do{ (t)->at_flag |= AP_NPTIMER_STOPPED; } while(0)
#define unset_ah_nptimer_stopped(t) do{ (t)->at_flag &= ~AP_NPTIMER_STOPPED; } while(0)
#define set_ah_nptimer_calling(t)   do{ (t)->at_flag |= AP_NPTIMER_CALLING; } while(0)
#define unset_ah_nptimer_calling(t) do{ (t)->at_flag &= ~AP_NPTIMER_CALLING; } while(0)

#define NPTIME_TIC_SEC 1    /* tic every 1 second */
#define NPTIMER_TIC_SYS   128  /* every how many <tic> to make sys call to get current time */

/* Global vars */
static ah_nptimer_t    *timerhead;   /* all timer in a double link-list */
static ah_nptimer_t    *timertail;
pthread_mutex_t  tq_lock = PTHREAD_MUTEX_INITIALIZER; /* timer-queue-lock */

/* must call it when tq_lock is locked */
static void ah_nptimer_dec_ref(ah_nptimer_t *t)
{
	--t->at_count;
	if (t->at_count < 0) {
		ah_log_old(LOG_CRIT, "nptimer: double free.");
	}
	if (0 == t->at_count) {
		free(t);
	}

	return;
}

/* must call it when tq_lock is locked */
static void ah_nptimer_stop_internal(ah_nptimer_t *t)
{
	set_ah_nptimer_stopped(t);
	if ((NULL == t->at_prev) && (NULL == t->at_next) && (t != timerhead)) {
		/* not in queue */
		return;
	}
	if ( t->at_prev ) {
		t->at_prev->at_next = t->at_next;
	} else {
		timerhead = t->at_next;
	}

	if (NULL !=  t->at_next ) {
		t->at_next->at_prev = t->at_prev;
	} else {
		timertail = t->at_prev;
	}

	t->at_prev = NULL;
	t->at_next = NULL;
	return;
}

/* must call it when tq_lock is locked */
static void ah_add_nptimer_to_queue(ah_nptimer_t *t, uint32_t delta_sec)
{
	ah_nptimer_t *after_this;
	ah_nptimer_t *before_this;

	t->at_fire = ah_sys_up_sec() + delta_sec;
	after_this = timertail;
	before_this = NULL;

	while ( after_this && after_this->at_fire > t->at_fire ) {
		before_this = after_this;
		after_this = after_this->at_prev;
	}

	t->at_prev = after_this;
	t->at_next = before_this;

	if ( NULL == after_this ) {
		timerhead = t;
	} else {
		after_this->at_next = t;
	}
	if ( NULL == before_this ) {
		timertail = t;
	} else {
		before_this->at_prev = t;
	}
	return;
}

/*
 * how many sec until the timer fire.
 */
int ah_nptimer_time2fire (ah_nptimer_t *t)
{
	int sys_up_sec;

	if (NULL == t) {
		return -1;
	}

	if (pthread_mutex_lock(&tq_lock) != 0) {
		ah_assert(FALSE);
		return -1;
	}
	if (is_ah_nptimer_calling(t)) {
		pthread_mutex_unlock(&tq_lock);
		return 0;
	}
	if ((NULL == t->at_next) && (NULL == t->at_prev)) {
		pthread_mutex_unlock(&tq_lock);
		return -2;
	}
	pthread_mutex_unlock(&tq_lock);

	sys_up_sec = ah_sys_up_sec();
	if (sys_up_sec >= t->at_fire) {
		return 0;
	}
	return t->at_fire - sys_up_sec;
}
/*
 * poll the timer queue, call any expired timer's callback.
 */
void ah_nptimer_poll (void)
{
	ah_nptimer_t *t = NULL;

	for ( ; ; ) {
		if (pthread_mutex_lock(&tq_lock) != 0) {
			ah_assert(FALSE);
			return;
		}

		if (   (NULL == timerhead)
			   || (timerhead->at_fire > ah_sys_up_sec()) ) {
			pthread_mutex_unlock(&tq_lock);
			break;
		}
		t = timerhead;
		timerhead = t->at_next;

		if ( NULL == timerhead ) {
			timertail = NULL;
		} else {
			timerhead->at_prev = NULL;
		}

		/* clean up t's forw/back ptr */
		t->at_prev = NULL;
		t->at_next = NULL;

		/* prevent it be deleted when calling timer's callback */
		++t->at_count;

		set_ah_nptimer_calling(t);
		pthread_mutex_unlock(&tq_lock);

		/* NOTE: it's the callback's responsibility to free/reset/etc.
		   to handle the timer ptr correctly */
		ah_assert(NULL != t->at_func);
		t->at_func(t, t->at_data);
		if (pthread_mutex_lock(&tq_lock) != 0) {
			ah_assert(FALSE);
			return;
		}
		unset_ah_nptimer_calling(t);
		ah_nptimer_dec_ref(t);
		pthread_mutex_unlock(&tq_lock);
	}

	return;
}
#if 0
/*
 * delete all timers from the queue
 * NOTE: caller should make sure not reference the timer ptr anymore.
 *       cause the mem got freed.
 * return: how many timer got deleted. -1 on error
 */
int ah_nptimer_flush (void)
{
	int rc = 0;
	ah_nptimer_t *t;

	if (pthread_mutex_lock(&tq_lock) != 0) {
		ah_assert(FALSE);
		return -1;
	}

	while ( (t = timerhead) ) {

		timerhead = t->at_next;

		if ( !timerhead ) {
			timertail = NULL;
		} else {
			timerhead->at_prev = NULL;
		}

		/* clean up t's forw/back ptr */
		unset_ah_nptimer_start(t);
		ah_free(t);
		rc ++;
	}

	pthread_mutex_unlock(&tq_lock);

	return rc;
}
#endif
/*
 * init nptimer
 */
int ah_nptimer_init (void)
{
	static boolean already_init = FALSE;

	if (already_init) {
		return 0;
	}

	timerhead = timertail = NULL;

	already_init = TRUE;
	return 0;
}
/*
 * change the timer callback argument,
 * return the old ptr to <arg>;
 */
void *ah_nptimer_chg_arg (ah_nptimer_t *t, void *arg)
{
	void *old_arg;

	ah_assert(t);

	old_arg = t->at_data;
	t->at_data = arg;

	return old_arg;
}
ah_nptimer_callback_t ah_nptimer_chg_func (ah_nptimer_t *t, ah_nptimer_callback_t func)
{
	ah_nptimer_callback_t old_func;

	ah_assert(t);

	old_func = t->at_func;
	t->at_func = func;

	return old_func;
}
/*
 * create a timer, return the ptr, or NULL if error
 * NOTE: once the <callback> is called, it indicate that this timer is taken out of the timer queue
 *       so if <callback> need a perodic timer, it's his responsibility to add the timer back into the queue
 */
ah_nptimer_t *ah_nptimer_create(ah_nptimer_callback_t callback, void *arg)
{
	ah_nptimer_t *t;

	if (NULL == callback) {
		return NULL;
	}

	t = (ah_nptimer_t *)ah_calloc(1, sizeof(ah_nptimer_t));
	if (NULL == t) {
		return NULL;
	}

	t->at_func = callback;
	t->at_data = arg;
	t->at_count = 1;

	return t;
}

/*
 * delete amrp timer, stop it if not yet. caller's responsibility to take care t->at_data
 */
void ah_nptimer_delete (ah_nptimer_t *t)
{
	if ( NULL == t ) {
		return;
	}

	ah_assert(NULL !=  t->at_func );
	if (pthread_mutex_lock(&tq_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	ah_nptimer_stop_internal(t);
	ah_nptimer_dec_ref(t);

	pthread_mutex_unlock(&tq_lock);
	return;
}

/* should call it in timer's callback function */
void ah_nptimer_continue(ah_nptimer_t *t, uint32_t delta_sec)
{
	ah_assert( t && t->at_func );

	if (pthread_mutex_lock(&tq_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	if (   (NULL != t->at_prev)
		   || (NULL != t->at_next)
		   || (t == timerhead)
		   || (is_ah_nptimer_stopped(t))) {
		/* already in queue again or stopped */
		pthread_mutex_unlock(&tq_lock);
		return;
	}

	ah_add_nptimer_to_queue(t, delta_sec);

	pthread_mutex_unlock(&tq_lock);
	return;
}

/*
 * caller's responsibility to make sure <t> is not start yet
 * <t> must have a callback_func.
 * <delta_sec> is the 'how many sec from now the timer should be fired
 */
void ah_nptimer_start (ah_nptimer_t *t, uint32_t delta_sec)
{
	ah_assert( t && t->at_func );

	if (pthread_mutex_lock(&tq_lock) != 0) {
		ah_assert(FALSE);
		return;
	}
	ah_nptimer_stop_internal(t);

	ah_add_nptimer_to_queue(t, delta_sec);
	unset_ah_nptimer_stopped(t);
	pthread_mutex_unlock(&tq_lock);
	return;
}
/*
 * stop the given timer. if timer is not start yet, it's not an error, just return.
 */
void ah_nptimer_stop (ah_nptimer_t *t)
{
	ah_assert(NULL != t);
	if (pthread_mutex_lock(&tq_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	ah_nptimer_stop_internal(t);
	pthread_mutex_unlock(&tq_lock);
	return;
}
