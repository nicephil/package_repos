/*********************************************************
 AEROHIVE CONFIDENTIAL

 Copyright [2006] - [2011] Aerohive Networks, Inc.
 All Rights Reserved.

 NOTICE: All information herein is and remains the property
 of Aerohive Networks, Inc. and its suppliers, if any.

 The intellectual and technical concepts contained herein
 are proprietary to Aerohive Networks, Inc. and its
 suppliers and may be covered by U.S. and foreign patents
 and/or pending patent applications, and are protected by
 trade secret and copyright law.

 Disclosure, dissemination or reproduction of this
 information or the intellectual or technical concepts
 expressed by this information is prohibited unless prior
 written permission is obtained from Aerohive Networks, Inc.
 **********************************************************/
#ifndef __AH_NONPREEMPTIVE_TIMER_H__
#define __AH_NONPREEMPTIVE_TIMER_H__

#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <stdint.h>

#include <ah_types.h>

/****************************
 * non-preemptive timer API *
 ****************************/

/*
 * np timer data structure prototype
 */
typedef struct ah_nptimer_ ah_nptimer_t;
typedef void (*ah_nptimer_callback_t)(ah_nptimer_t *, void *);

/*
 * np timer external API
 */
extern int           ah_nptimer_init (void);

ah_nptimer_t *ah_nptimer_create(ah_nptimer_callback_t callback, void *arg);
extern void          ah_nptimer_delete (ah_nptimer_t *t);
extern void          ah_nptimer_start (ah_nptimer_t *t, uint32_t delta_sec);
extern void          ah_nptimer_continue(ah_nptimer_t *t, uint32_t delta_sec);
extern void          ah_nptimer_stop (ah_nptimer_t *t);
extern void          ah_nptimer_poll (void);
//extern  int          ah_nptimer_flush (void);
extern void         *ah_nptimer_chg_arg (ah_nptimer_t *t, void *arg);
extern ah_nptimer_callback_t ah_nptimer_chg_func (ah_nptimer_t *t, ah_nptimer_callback_t func);

/*
 * how long timer going to be fire,
 * return error(-1), timer_not_started(-2), time-to-fire-in-sec(>=0)
 */
extern int ah_nptimer_time2fire (ah_nptimer_t *t);


#endif/*__AH_NONPREEMPTIVE_TIMER_H__*/
