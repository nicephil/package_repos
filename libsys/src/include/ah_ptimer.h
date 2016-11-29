#ifndef __AH_PREEMPTIVE_TIMER_H__
#define __AH_PREEMPTIVE_TIMER_H__

#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>


/*****************************************************
 * preemptive timer API                              *
 *                                                   *
 *   preemptive timer use the same algorithm as non- *
 *   preemptive timer, but in a different link-list. *
 *   and all the ptimer is called from the ah_event  *
 *   thread, which is created by init ah_event_lib.  *
 *   That's also why it's called preemptive-timer,   *
 *   because timer callback could preempt the main   *
 *   thread code at any time(depeneding on the sys   *
 *   scheduler).                                     *
 *   It's important for the user to take care sync   *
 *   between timer callback and other thread code    *
 *****************************************************/
/* !!! NOTE: to use the following timer API, you must call ah_event_init(...) first !!! */
/*
 * data structure
 */
typedef struct ah_ptimer_ ah_ptimer_t;
typedef void (*ah_ptimer_callback_t)(ah_ptimer_t *, void *);
/*
 * API
 */
ah_ptimer_t *ah_ptimer_create(ah_ptimer_callback_t callback, void *arg);
extern void          ah_ptimer_delete (ah_ptimer_t *t);
extern void          ah_ptimer_start  (ah_ptimer_t *t, uint32_t delta_sec);
extern void          ah_ptimer_stop   (ah_ptimer_t *t);
extern void          ah_ptimer_continue(ah_ptimer_t *t, uint32_t delta_sec);
//extern int           ah_ptimer_flush  (void);
extern void         *ah_ptimer_chg_arg (ah_ptimer_t *t, void *arg);

/*
 * how long timer going to be fire,
 * return error(-1), timer_not_started(-2), time-to-fire-in-sec(>=0)
 */
extern int ah_ptimer_time2fire (ah_ptimer_t *t);


int ah_pmpt_timer_init(pthread_t *timer_id);
void ah_pmpt_timer_poll(void);

ah_ptimer_t *ah_pmpt_timer_create(ah_ptimer_callback_t callback, void *arg);
int ah_pmpt_timer_time2fire (ah_ptimer_t *t);
void ah_pmpt_timer_stop(ah_ptimer_t *t);
void ah_pmpt_timer_continue(ah_ptimer_t *t, uint32_t delta_sec);
void ah_pmpt_timer_start(ah_ptimer_t *t, uint32_t delta_sec);
void ah_pmpt_timer_delete(ah_ptimer_t *t);
void *ah_pmpt_timer_chg_arg (ah_ptimer_t *t, void *arg);

#endif/*__AH_PREEMPTIVE_TIMER_H__*/
