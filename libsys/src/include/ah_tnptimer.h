#ifndef __AH_THREAD_NONPREEMPTIVE_TIMER_H__
#define __AH_THREAD_NONPREEMPTIVE_TIMER_H__

#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <stdint.h>
#include "ah_atomics.h"

/****************************
 * per thread non-preemptive timer API *
 ****************************/

/*
 * thread np timer data structure prototype
 */
typedef struct ah_tnptimer_ ah_tnptimer_t;
typedef struct ah_tnptimer_lst_ ah_tnptimer_lst_t;
typedef void (*ah_tnptimer_callback_t)(ah_tnptimer_lst_t *lst, ah_tnptimer_t *, void *);

/*
 * np timer external API
 */
extern ah_tnptimer_lst_t *ah_tnptimer_init (void);
ah_tnptimer_t     *ah_tnptimer_create (ah_tnptimer_callback_t callback, void *arg);
extern void               ah_tnptimer_delete (ah_tnptimer_lst_t *lst, ah_tnptimer_t *t);
extern void               ah_tnptimer_start (ah_tnptimer_lst_t *lst, ah_tnptimer_t *t, uint32_t delta_sec);
extern void               ah_tnptimer_continue(ah_tnptimer_lst_t *lst, ah_tnptimer_t *t, uint32_t delta_sec);
extern void               ah_tnptimer_stop (ah_tnptimer_lst_t *lst, ah_tnptimer_t *t);
extern void               ah_tnptimer_poll (ah_tnptimer_lst_t *lst);
extern void              *ah_tnptimer_chg_arg (ah_tnptimer_t *t, void *arg);

/*
 * how long timer going to be fire,
 * return error(-1), timer_not_started(-2), time-to-fire-in-sec(>=0)
 */
extern int ah_tnptimer_time2fire (ah_tnptimer_lst_t *lst, ah_tnptimer_t *t);


#endif/*__AH_THREAD_NONPREEMPTIVE_TIMER_H__*/
