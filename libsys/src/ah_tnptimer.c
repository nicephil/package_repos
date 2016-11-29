#include <unistd.h>
#include <sys/sysinfo.h>
#include "ah_pthread.h"
#include "ah_tnptimer.h"
#include "ah_lib.h"
#include "ah_event.h"
#include "ah_atomics.h"

/*
 * timer resolution 1 sec
 */
#define AP_NPTIMER_STOPPED   0x01            /* timer already stopped */
#define AP_NPTIMER_CALLING   0x02            /* timer is calling */

struct ah_tnptimer_ {
	struct ah_tnptimer_    *at_prev;     /* double link list */
	struct ah_tnptimer_    *at_next;
	uint8_t                at_flag;
	int16_t                at_count;
	uint32_t               at_fire;     /* when to fire the timer, sec since this instance is started */
	ah_tnptimer_callback_t at_func;
	void                   *at_data;
};

struct ah_tnptimer_lst_ {
	ah_tnptimer_t    *timerhead;
	ah_tnptimer_t    *timertail;
	pthread_mutex_t  tq_lock;     /* timer-queue-lock */
};

#define is_ah_tnptimer_stopped(t) ( (t)->at_flag & AP_NPTIMER_STOPPED)
#define is_ah_tnptimer_calling(t) ( (t)->at_flag & AP_NPTIMER_CALLING)
#define set_ah_tnptimer_stopped(t)   do{ (t)->at_flag |= AP_NPTIMER_STOPPED; } while(0)
#define unset_ah_tnptimer_stopped(t) do{ (t)->at_flag &= ~AP_NPTIMER_STOPPED; } while(0)
#define set_ah_tnptimer_calling(t)   do{ (t)->at_flag |= AP_NPTIMER_CALLING; } while(0)
#define unset_ah_tnptimer_calling(t) do{ (t)->at_flag &= ~AP_NPTIMER_CALLING; } while(0)
#define is_entry_in_list(t, lst)     ((t)->at_prev != NULL || (t)->at_next != NULL || (t) == (lst)->timerhead)

#define NPTIME_TIC_SEC 1    /* tic every 1 second */
#define NPTIMER_TIC_SYS   128  /* every how many <tic> to make sys call to get current time */

/* must call it when lst->tq_lock is locked */
static void ah_tnptimer_dec_ref(ah_tnptimer_t *t)
{
	ah_assert_debug(t->at_count >= 1 && t->at_count <= 256);
	if (ah_atomic_dec(t->at_count) == 0) {
		free(t);
	}
}

/* must call it when lst->tq_lock is locked */
static void ah_tnptimer_stop_internal(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t)
{
	ah_assert_debug(lst != NULL);

	set_ah_tnptimer_stopped(t);
	if (is_entry_in_list(t, lst)) {
		if (t->at_prev != NULL) {
			t->at_prev->at_next = t->at_next;
		} else {
			lst->timerhead = t->at_next;
		}

		if (t->at_next != NULL) {
			t->at_next->at_prev = t->at_prev;
		} else {
			lst->timertail = t->at_prev;
		}

		t->at_prev = NULL;
		t->at_next = NULL;
	}
}

/* must call it when lst->tq_lock is locked */
static void ah_add_tnptimer_to_queue(ah_tnptimer_lst_t *lst,
									 ah_tnptimer_t *t,
									 uint32_t delta_sec)
{
	ah_tnptimer_t *after_this;
	ah_tnptimer_t *before_this;

	ah_assert_debug(lst != NULL);

	t->at_fire = ah_sys_up_sec() + delta_sec;
	after_this = lst->timertail;
	before_this = NULL;

	while (after_this != NULL && after_this->at_fire > t->at_fire) {
		before_this = after_this;
		after_this = after_this->at_prev;
	}

	t->at_prev = after_this;
	t->at_next = before_this;

	if (after_this == NULL) {
		lst->timerhead = t;
	} else {
		after_this->at_next = t;
	}
	if (before_this == NULL) {
		lst->timertail = t;
	} else {
		before_this->at_prev = t;
	}
}
/*
 * how many sec until the timer fire.
 */
int ah_tnptimer_time2fire(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t)
{
	int sys_up_sec;

	ah_assert_debug(lst != NULL);
	ah_assert_debug(t != NULL);

	ah_pthread_mutex_lock(&lst->tq_lock);
	if (is_ah_tnptimer_calling(t)) {
		ah_pthread_mutex_unlock(&lst->tq_lock);
		return 0;
	}
	if ((t->at_next == NULL) && (t->at_prev == NULL)) {
		ah_pthread_mutex_unlock(&lst->tq_lock);
		return -2;
	}
	ah_pthread_mutex_unlock(&lst->tq_lock);

	sys_up_sec = ah_sys_up_sec();
	if (sys_up_sec >= t->at_fire) {
		return 0;
	}
	return t->at_fire - sys_up_sec;
}
/*
 * poll the timer queue, call any expired timer's callback.
 */
void ah_tnptimer_poll(ah_tnptimer_lst_t *lst)
{
	ah_tnptimer_t *t = NULL;

	ah_assert_debug(lst != NULL);

	for (; ;) {
		ah_pthread_mutex_lock(&lst->tq_lock);

		if ((lst->timerhead == NULL)
			|| (lst->timerhead->at_fire > ah_sys_up_sec())) {
			ah_pthread_mutex_unlock(&lst->tq_lock);
			break;
		}
		t = lst->timerhead;
		lst->timerhead = t->at_next;

		if (lst->timerhead == NULL) {
			lst->timertail = NULL;
		} else {
			lst->timerhead->at_prev = NULL;
		}

		/* clean up t's forw/back ptr */
		t->at_prev = NULL;
		t->at_next = NULL;

		/* prevent it be deleted when calling timer's callback */
		ah_atomic_inc(t->at_count);

		set_ah_tnptimer_calling(t);
		ah_pthread_mutex_unlock(&lst->tq_lock);

		/* NOTE: it's the callback's responsibility to free/reset/etc.
		   to handle the timer ptr correctly */
		ah_assert(t->at_func != NULL);
		t->at_func(lst, t, t->at_data);
		ah_pthread_mutex_lock(&lst->tq_lock);
		unset_ah_tnptimer_calling(t);
		ah_tnptimer_dec_ref(t);
		ah_pthread_mutex_unlock(&lst->tq_lock);
	}
}

/*
 * init thread nptimer
 */
ah_tnptimer_lst_t *ah_tnptimer_init()
{
	ah_tnptimer_lst_t *lst;

	if ((lst = (ah_tnptimer_lst_t *)ah_calloc(1, sizeof(ah_tnptimer_lst_t))) != NULL) {
		ah_pthread_mutex_init(&lst->tq_lock, NULL); /* init queue lock */
		lst->timerhead = lst->timertail = NULL;
	}

	return lst;
}

/*
 * change the timer callback argument,
 * return the old ptr to <arg>;
 */
void *ah_tnptimer_chg_arg(ah_tnptimer_t *t, void *arg)
{
	void *old_arg;

	ah_assert_debug(t != NULL);

	old_arg = t->at_data;
	t->at_data = arg;

	return old_arg;
}
/*
 * create a nptimer, return the ptr, or NULL if error
 * NOTE: once the <callback> is called, it indicate that this timer is taken out of the timer queue
 *       so if <callback> need a perodic timer, it's his responsibility to add the timer back into the queue
 */

ah_tnptimer_t *ah_tnptimer_create(ah_tnptimer_callback_t callback, void *arg)
{
	ah_tnptimer_t *t;

	ah_assert(callback != 0);

	t = (ah_tnptimer_t *)ah_calloc(1, sizeof(ah_tnptimer_t));
	if (t != NULL) {
		t->at_func = callback;
		t->at_data = arg;
		t->at_count = 1;
	}

	return t;
}

/*
 * delete thread nptimer, stop it if not yet. caller's responsibility to take care t->at_data
 */
void ah_tnptimer_delete(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t)
{
	ah_assert(lst != NULL);

	if (t != NULL) {
		ah_assert(t->at_func != NULL);
		ah_pthread_mutex_lock(&lst->tq_lock);
		ah_tnptimer_stop_internal(lst, t);
		ah_tnptimer_dec_ref(t);
		ah_pthread_mutex_unlock(&lst->tq_lock);
	}
}

/* should call it in timer's callback function */
void ah_tnptimer_continue(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t, uint32_t delta_sec)
{
	ah_assert(NULL != lst);
	ah_assert(t && t->at_func);

	ah_pthread_mutex_lock(&lst->tq_lock);

	if (!is_entry_in_list(t, lst) && !is_ah_tnptimer_stopped(t)) {
		ah_add_tnptimer_to_queue(lst, t, delta_sec);
	}

	ah_pthread_mutex_unlock(&lst->tq_lock);
}

/*
 * caller's responsibility to make sure <t> is not start yet
 * <t> must have a callback_func.
 * <delta_sec> is the 'how many sec from now the timer should be fired
 */
void ah_tnptimer_start(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t, uint32_t delta_sec)
{
	ah_assert(NULL != lst);
	ah_assert(t && t->at_func);

	ah_pthread_mutex_lock(&lst->tq_lock);
	ah_tnptimer_stop_internal(lst, t);
	ah_add_tnptimer_to_queue(lst, t, delta_sec);
	unset_ah_tnptimer_stopped(t);
	ah_pthread_mutex_unlock(&lst->tq_lock);
}

/*
 * stop the given timer. if timer is not start yet, it's not an error, just return.
 */
void ah_tnptimer_stop(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t)
{
	ah_assert(lst != NULL);
	ah_assert(t != NULL);

	ah_pthread_mutex_lock(&lst->tq_lock);
	ah_tnptimer_stop_internal(lst, t);
	ah_pthread_mutex_unlock(&lst->tq_lock);
}
