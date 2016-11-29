#include <unistd.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include "ah_syscall.h"
#include "ah_lib.h"
#include "ah_config.h"
#include "ah_ptimer.h"
#include "ah_pthread.h"

/*
 * timer resolution 1 sec
 */

#define AP_PTIMER_STOPPED   0x01            /* timer already stopped */
#define AP_PTIMER_CALLING   0x02            /* timer is calling */
struct ah_ptimer_ {
	struct ah_ptimer_    *ap_prev;     /* double link list */
	struct ah_ptimer_    *ap_next;
	uint8_t                  ap_flag;
	int16_t                 ap_count;
	uint32_t                 ap_fire;     /* when to fire the timer, sec since this instance is started */
	ah_ptimer_callback_t   ap_func;
	void                  *ap_data;
};
#define is_ah_ptimer_stopped(t) ( (t)->ap_flag & AP_PTIMER_STOPPED)
#define is_ah_ptimer_calling(t) ( (t)->ap_flag & AP_PTIMER_CALLING)
#define set_ah_ptimer_stopped(t)   do{ (t)->ap_flag |= AP_PTIMER_STOPPED; } while(0)
#define unset_ah_ptimer_stopped(t) do{ (t)->ap_flag &= ~AP_PTIMER_STOPPED; } while(0)
#define set_ah_ptimer_calling(t)   do{ (t)->ap_flag |= AP_PTIMER_CALLING; } while(0)
#define unset_ah_ptimer_calling(t) do{ (t)->ap_flag &= ~AP_PTIMER_CALLING; } while(0)

#define PTIME_TIC_SEC    1    /* tic every 1 second */
#define PTIMER_TIC_SYS   128  /* every how many <tic> to make sys call to get current time */

/* Global vars */
static ah_ptimer_t     *ah_ptimer_head;   /* all timers in double link-list */
static ah_ptimer_t     *ah_ptimer_tail;
static int         ap_sys_up_sec;

static pthread_mutex_t  ap_lock = PTHREAD_MUTEX_INITIALIZER; /* timer-queue-lock */
static boolean ah_ptimer_already_init = FALSE;  /* indicate if ptimer have been init */

/* must call it when ap_lock is locked */
static void ah_ptimer_dec_ref(ah_ptimer_t *t)
{
	--t->ap_count;
	if (t->ap_count < 0) {
		ah_log_old(LOG_CRIT, "ptimer: double free.");
	}
	if (0 == t->ap_count) {
		free(t);
	}

	return;
}

/* must call it when ap_lock is locked */
static void ah_ptimer_stop_internal(ah_ptimer_t *t)
{
	set_ah_ptimer_stopped(t);
	if ((NULL == t->ap_prev) && (NULL == t->ap_next) && (t != ah_ptimer_head)) {
		/* not in queue */
		return;
	}
	if (t->ap_prev) {
		t->ap_prev->ap_next = t->ap_next;
	} else {
		ah_ptimer_head = t->ap_next;
	}

	if (NULL !=  t->ap_next) {
		t->ap_next->ap_prev = t->ap_prev;
	} else {
		ah_ptimer_tail = t->ap_prev;
	}

	t->ap_prev = NULL;
	t->ap_next = NULL;
	return;
}

/* must call it when ap_lock is locked */
static void ah_add_ptimer_to_queue(ah_ptimer_t *t, uint32_t delta_sec)
{
	ah_ptimer_t *after_this;
	ah_ptimer_t *before_this;

	t->ap_fire = ap_sys_up_sec + delta_sec;
	after_this = ah_ptimer_tail;
	before_this = NULL;

	while (after_this && after_this->ap_fire > t->ap_fire) {
		before_this = after_this;
		after_this = after_this->ap_prev;
	}

	t->ap_prev = after_this;
	t->ap_next = before_this;

	if (NULL == after_this) {
		ah_ptimer_head = t;
	} else {
		after_this->ap_next = t;
	}
	if (NULL == before_this) {
		ah_ptimer_tail = t;
	} else {
		before_this->ap_prev = t;
	}
	return;
}

/*
 * how many sec until the timer fire.
 */
int ah_ptimer_time2fire(ah_ptimer_t *t)
{
	int sys_up_sec;

	if (NULL == t) {
		return -1;
	}

	if (pthread_mutex_lock(&ap_lock) != 0) {
		ah_assert(FALSE);
		return -1;
	}
	if (is_ah_ptimer_calling(t)) {
		pthread_mutex_unlock(&ap_lock);
		return 0;
	}
	if ((NULL == t->ap_next) && (NULL == t->ap_prev)) {
		pthread_mutex_unlock(&ap_lock);
		return -2;
	}
	pthread_mutex_unlock(&ap_lock);

	sys_up_sec = ah_sys_up_sec();
	if (sys_up_sec >= t->ap_fire) {
		return 0;
	}
	return t->ap_fire - sys_up_sec;
}
/*
 * poll the timer queue, call any expired timer's callback.
 */
void ah_ptimer_poll(void)
{
	ah_ptimer_t *t = NULL;

	for (; ;) {
		if (pthread_mutex_lock(&ap_lock) != 0) {
			ah_assert(FALSE);
			return;
		}

		if ((NULL == ah_ptimer_head)
			|| (ah_ptimer_head->ap_fire > ap_sys_up_sec)) {
			pthread_mutex_unlock(&ap_lock);
			break;
		}
		t = ah_ptimer_head;
		ah_ptimer_head = t->ap_next;

		if (NULL == ah_ptimer_head) {
			ah_ptimer_tail = NULL;
		} else {
			ah_ptimer_head->ap_prev = NULL;
		}

		/* clean up t's forw/back ptr */
		t->ap_prev = NULL;
		t->ap_next = NULL;

		/* prevent it be deleted when calling timer's callback */
		++t->ap_count;

		set_ah_ptimer_calling(t);
		pthread_mutex_unlock(&ap_lock);

		/* NOTE: it's the callback's responsibility to free/reset/etc.
		   to handle the timer ptr correctly */
		ah_assert(NULL != t->ap_func);
		t->ap_func(t, t->ap_data);
		if (pthread_mutex_lock(&ap_lock) != 0) {
			ah_assert(FALSE);
			return;
		}
		unset_ah_ptimer_calling(t);
		ah_ptimer_dec_ref(t);
		pthread_mutex_unlock(&ap_lock);
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
int ah_ptimer_flush(void)
{
	int rc = 0;
	ah_ptimer_t *t;

	if (pthread_mutex_lock(&ap_lock) != 0) {
		ah_assert(FALSE);
		return -1;
	}

	while ((t = ah_ptimer_head)) {

		ah_ptimer_head = t->ap_next;

		if (!ah_ptimer_head) {
			ah_ptimer_tail = NULL;
		} else {
			ah_ptimer_head->ap_prev = NULL;
		}

		/* clean up t's forw/back ptr */
		unset_ah_ptimer_start(t);
		ah_free(t);
		rc ++;
	}

	pthread_mutex_unlock(&ap_lock);

	return rc;
}
#endif

/*
 * return -1 if error
 */
static int _ah_sys_up_sec(void)
{
	struct sysinfo si;
	int i = 0;

	/* try 10 times if fail to extract sysinfo */
	while (sysinfo(&si) < 0 && i < 10) {
		i++;
	}

	if (i >= 10) {
		return -1;
	}

	return si.uptime;
}
/*
 * public API for getting sys_up_sec.
 * if ptimer inited, we just use the cached tic second to save a sys-call
 * otherwise, do syscall to get sys_up_sec
 */
int ah_sys_up_sec(void)
{
	return (ah_ptimer_already_init == TRUE) ?
		   ap_sys_up_sec :
		   _ah_sys_up_sec();
}
/*
 * sys alarm sig handler
 */
static void ptimer_tic(int sig)
{
	static uint32_t tic_count = PTIMER_TIC_SYS;
	int time_now;

	/* not do sys call each sec */
	if (!(--tic_count)) {

		/* try the sys call get time */
		time_now = _ah_sys_up_sec();

		/* sys call fail */
		if (time_now < 0) {
			ap_sys_up_sec += PTIME_TIC_SEC;
			tic_count = 1;
		}

		/* sys call ok */
		else {
			ap_sys_up_sec = time_now;
			tic_count = PTIMER_TIC_SYS;
		}
	} else {
		ap_sys_up_sec += PTIME_TIC_SEC;
	}

	/* linux follow System V semantics, reset signal handler to dflt.
	 * so no same alarm would prempt this handler. we set the tic handler again
	 * after poll all the timer, so we are non-prempt at process level
	 */
#if 0
	if (signal(SIGALRM, ptimer_tic) == SIG_ERR) {
		ah_err_old("proc %d fail install SIGALRM handler\n", getpid());
		ah_assert(FALSE);
	}
#endif
	return;
}
/*
 * init nptimer
 */
int ah_ptimer_init(void)
{
	struct itimerval alarm_tic;

	if (ah_ptimer_already_init) {
		return 0;
	}

	ah_ptimer_head = ah_ptimer_tail = NULL;
	ap_sys_up_sec = _ah_sys_up_sec();

	if (ap_sys_up_sec < 0) {
		return -1;
	}

	/* sys timer will send SIGALRM */
	if (signal(SIGALRM, ptimer_tic) == SIG_ERR) {
		return -1;
	}

	/* setup sys tic */
	memset((void *)&alarm_tic, 0, sizeof(alarm_tic));
	alarm_tic.it_interval.tv_sec = PTIME_TIC_SEC;
	alarm_tic.it_value.tv_sec = PTIME_TIC_SEC;
	setitimer(ITIMER_REAL, &alarm_tic, NULL);
	ah_ptimer_already_init = TRUE;
	return 0;
}
/*
 * change the timer callback argument,
 * return the old ptr to <arg>;
 */
void *ah_ptimer_chg_arg(ah_ptimer_t *t, void *arg)
{
	void *old_arg;

	ah_assert(t);

	old_arg = t->ap_data;
	t->ap_data = arg;

	return old_arg;
}
/*
 * create a timer, return the ptr, or NULL if error
 * NOTE: once the <callback> is called, it indicate that this timer is taken out of the timer queue
 *       so if <callback> need a perodic timer, it's his responsibility to add the timer back into the queue
 */
ah_ptimer_t *ah_ptimer_create(ah_ptimer_callback_t callback, void *arg)
{
	ah_ptimer_t *t;

	if (NULL == callback) {
		return NULL;
	}

	t = (ah_ptimer_t *)ah_calloc(1, sizeof(ah_ptimer_t));
	if (NULL == t) {
		return NULL;
	}

	t->ap_func = callback;
	t->ap_data = arg;
	t->ap_count = 1;

	return t;
}

/*
 * delete amrp timer, stop it if not yet. caller's responsibility to take care t->ap_data
 */
void ah_ptimer_delete(ah_ptimer_t *t)
{
	if (NULL == t) {
		return;
	}

	ah_assert(NULL !=  t->ap_func);
	if (pthread_mutex_lock(&ap_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	ah_ptimer_stop_internal(t);
	ah_ptimer_dec_ref(t);

	pthread_mutex_unlock(&ap_lock);
	return;
}

/* should call it in timer's callback function */
void ah_ptimer_continue(ah_ptimer_t *t, uint32_t delta_sec)
{
	ah_assert(t && t->ap_func);

	if (pthread_mutex_lock(&ap_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	if ((NULL != t->ap_prev)
		|| (NULL != t->ap_next)
		|| (t == ah_ptimer_head)
		|| (is_ah_ptimer_stopped(t))) {
		/* already in queue again or stopped */
		pthread_mutex_unlock(&ap_lock);
		return;
	}

	ah_add_ptimer_to_queue(t, delta_sec);

	pthread_mutex_unlock(&ap_lock);
	return;
}

/*
 * caller's responsibility to make sure <t> is not start yet
 * <t> must have a callback_func.
 * <delta_sec> is the 'how many sec from now the timer should be fired
 */
void ah_ptimer_start(ah_ptimer_t *t, uint32_t delta_sec)
{
	ah_assert(t && t->ap_func);

	if (pthread_mutex_lock(&ap_lock) != 0) {
		ah_assert(FALSE);
		return;
	}
	ah_ptimer_stop_internal(t);

	ah_add_ptimer_to_queue(t, delta_sec);
	unset_ah_ptimer_stopped(t);
	pthread_mutex_unlock(&ap_lock);
	return;
}
/*
 * stop the given timer. if timer is not start yet, it's not an error, just return.
 */
void ah_ptimer_stop(ah_ptimer_t *t)
{
	ah_assert(NULL != t);
	if (pthread_mutex_lock(&ap_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	ah_ptimer_stop_internal(t);
	pthread_mutex_unlock(&ap_lock);
	return;
}

static boolean timer_thread_running = FALSE;
/* timer-queue-lock */
static pthread_mutex_t  pmpt_timer_lock = PTHREAD_MUTEX_INITIALIZER;
static ah_ptimer_t     *pmpt_timer_head;   /* all timers in double link-list */
static ah_ptimer_t     *pmpt_timer_tail;
/* init preempt timer */
static int ah_pmpt_timer_setup(void)
{
	struct itimerval alarm_tic;

	if (timer_thread_running) {
		return 0;
	}

	pmpt_timer_head = pmpt_timer_tail = NULL;
	ap_sys_up_sec = _ah_sys_up_sec();

	if (ap_sys_up_sec < 0) {
		return -1;
	}

	/* sys timer will send SIGALRM */
	if (signal(SIGALRM, ptimer_tic) == SIG_ERR) {
		return -1;
	}

	/* setup sys tic */
	memset((void *)&alarm_tic, 0, sizeof(alarm_tic));
	alarm_tic.it_interval.tv_sec = PTIME_TIC_SEC;
	alarm_tic.it_value.tv_sec = PTIME_TIC_SEC;
	setitimer(ITIMER_REAL, &alarm_tic, NULL);

	return 0;
}

/* must call it when pmpt_timer_lock is locked */
static void ah_pmpt_timer_dec_ref(ah_ptimer_t *t)
{
	--t->ap_count;
	if (t->ap_count < 0) {
		ah_log_old(LOG_CRIT, "preempt timer: double free.");
	}
	if (0 == t->ap_count) {
		ah_assert(is_ah_ptimer_stopped(t));
		free(t);
	}

	return;
}

static void ah_add_pmpt_timer_to_queue(ah_ptimer_t *t, uint32_t delta_sec)
{
	ah_ptimer_t *after_this;
	ah_ptimer_t *before_this;

	t->ap_fire = ap_sys_up_sec + delta_sec;
	after_this = pmpt_timer_tail;
	before_this = NULL;

	while (after_this && after_this->ap_fire > t->ap_fire) {
		before_this = after_this;
		after_this = after_this->ap_prev;
	}

	t->ap_prev = after_this;
	t->ap_next = before_this;

	if (NULL == after_this) {
		pmpt_timer_head = t;
	} else {
		after_this->ap_next = t;
	}
	if (NULL == before_this) {
		pmpt_timer_tail = t;
	} else {
		before_this->ap_prev = t;
	}
	return;
}

/* must call it when pmpt_timer_lock is locked */
static void ah_pmpt_timer_stop_internal(ah_ptimer_t *t)
{
	set_ah_ptimer_stopped(t);
	if ((NULL == t->ap_prev) && (NULL == t->ap_next) && (t != pmpt_timer_head)) {
		return;
	}
	if (t->ap_prev) {
		t->ap_prev->ap_next = t->ap_next;
	} else {
		pmpt_timer_head = t->ap_next;
	}

	if (NULL !=  t->ap_next) {
		t->ap_next->ap_prev = t->ap_prev;
	} else {
		pmpt_timer_tail = t->ap_prev;
	}

	t->ap_prev = NULL;
	t->ap_next = NULL;
	return;
}

void *ah_pmpt_timer_chg_arg(ah_ptimer_t *t, void *arg)
{
	void *old_arg;

	ah_assert(t);

	old_arg = t->ap_data;
	t->ap_data = arg;

	return old_arg;
}

int ah_pmpt_timer_time2fire(ah_ptimer_t *t)
{
	int sys_up_sec;

	if (NULL == t) {
		return -1;
	}

	if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
		ah_assert(FALSE);
		return -1;
	}
	if ((NULL == t->ap_next) && (NULL == t->ap_prev) && (t != pmpt_timer_head)) {
		pthread_mutex_unlock(&pmpt_timer_lock);
		return -2;
	}
	pthread_mutex_unlock(&pmpt_timer_lock);

	sys_up_sec = ap_sys_up_sec;
	if (sys_up_sec >= t->ap_fire) {
		return 0;
	}
	return t->ap_fire - sys_up_sec;
}

/*
 * poll the timer queue, call any expired timer's callback.
 */
void ah_pmpt_timer_poll(void)
{
	ah_ptimer_t *t = NULL;

	for (; ;) {
		if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
			ah_assert(FALSE);
			return;
		}

		if ((NULL == pmpt_timer_head)
			|| (pmpt_timer_head->ap_fire > ap_sys_up_sec)) {
			pthread_mutex_unlock(&pmpt_timer_lock);
			break;
		}
		t = pmpt_timer_head;
		pmpt_timer_head = t->ap_next;

		if (NULL == pmpt_timer_head) {
			pmpt_timer_tail = NULL;
		} else {
			pmpt_timer_head->ap_prev = NULL;
		}

		/* clean up t's forw/back ptr */
		t->ap_prev = NULL;
		t->ap_next = NULL;

		/* prevent it be deleted when calling timer's callback */
		++t->ap_count;

		set_ah_ptimer_calling(t);
		pthread_mutex_unlock(&pmpt_timer_lock);

		/* NOTE: it's the callback's responsibility to free/reset/etc.
		   to handle the timer ptr correctly */
		ah_assert(NULL != t->ap_func);
		t->ap_func(t, t->ap_data);
		if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
			ah_assert(FALSE);
			return;
		}
		unset_ah_ptimer_calling(t);
		ah_pmpt_timer_dec_ref(t);
		pthread_mutex_unlock(&pmpt_timer_lock);
	}

	return;
}

void ah_pmpt_timer_stop(ah_ptimer_t *t)
{
	ah_assert(NULL != t);
	if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	ah_pmpt_timer_stop_internal(t);
	pthread_mutex_unlock(&pmpt_timer_lock);
	return;
}

/* should call it in timer's callback function */
void ah_pmpt_timer_continue(ah_ptimer_t *t, uint32_t delta_sec)
{
	/* sanity check */
	ah_assert(t && t->ap_func);

	if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	if ((NULL != t->ap_prev)
		|| (NULL != t->ap_next)
		|| (t == pmpt_timer_head)
		|| (is_ah_ptimer_stopped(t))) {
		/* already in queue again or stopped */
		pthread_mutex_unlock(&pmpt_timer_lock);
		return;
	}

	ah_add_pmpt_timer_to_queue(t, delta_sec);

	pthread_mutex_unlock(&pmpt_timer_lock);
	return;
}

void ah_pmpt_timer_start(ah_ptimer_t *t, uint32_t delta_sec)
{
	ah_assert(t && t->ap_func);

	if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
		ah_assert(FALSE);
		return;
	}
	ah_pmpt_timer_stop_internal(t);

	ah_add_pmpt_timer_to_queue(t, delta_sec);
	unset_ah_ptimer_stopped(t);
	pthread_mutex_unlock(&pmpt_timer_lock);
	return;
}

ah_ptimer_t *ah_pmpt_timer_create(ah_ptimer_callback_t callback, void *arg)
{
	ah_ptimer_t *t;

	if (NULL == callback) {
		return NULL;
	}

	t = (ah_ptimer_t *)ah_calloc(1, sizeof(ah_ptimer_t));
	if (NULL == t) {
		return NULL;
	}

	t->ap_func = callback;
	t->ap_data = arg;
	t->ap_count = 1;

	return t;
}

void ah_pmpt_timer_delete(ah_ptimer_t *t)
{
	if (NULL == t) {
		return;
	}

	ah_assert(NULL !=  t->ap_func);
	if (pthread_mutex_lock(&pmpt_timer_lock) != 0) {
		ah_assert(FALSE);
		return;
	}

	ah_pmpt_timer_stop_internal(t);
	ah_pmpt_timer_dec_ref(t);

	pthread_mutex_unlock(&pmpt_timer_lock);
	return;
}

static void *ah_pmpt_timer_thread(void *arg)
{
	ah_signal_mask(FALSE, SIGALRM);
	if (ah_pmpt_timer_setup() < 0) {
		return NULL;
	}

	timer_thread_running = TRUE;
	for (; ;) {
		/* select(0, NULL, NULL, NULL, NULL); */
		ah_sleep(1);
		ah_pmpt_timer_poll();
	}
	return NULL;
}

/* should call it in main function firstly */
int ah_pmpt_timer_init(pthread_t *timer_id)
{
	int count = 0;

	ah_signal_mask(TRUE, SIGALRM);
	/* Create event sub-thread */
	if (ah_pthread_create(timer_id, ah_pmpt_timer_thread,
						  NULL, SCHED_RR,
						  AH_PRIORITY_CTRL, 0) != 0) {
		ah_err_old("ah_pthread_create failed");
		return -1;
	}
	/* Check if sub-thread is actually succeeded */
	while ((!timer_thread_running) && ((count++) < 10)) {
		ah_sleep(1);
	}

	if (!timer_thread_running) {
		ah_err_old("Can not run timer thread");
		if (NULL != timer_id) {
			*timer_id = -1;
		}
		return -1;
	}

	return 0;
}

/* like func ah_sys_up_sec
 * if ptimer inited, return value is unsigned int.
 */
unsigned int ah_sys_uptime(void)
{
	ah_assert((ah_ptimer_already_init == TRUE) || (timer_thread_running == TRUE));
	return ap_sys_up_sec;
}
