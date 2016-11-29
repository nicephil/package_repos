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
/*
 *  FILE   : queue.c
 *  AUTHOR : Jeffrey Hunter
 *  WEB    : http://www.iDevelopment.info
 *  NOTES  : Implement all functions required
 *           for a Queue data structure.
 */
#ifndef     _AH_CAPWAP_STAT_QUEUE_H_
#define     _AH_CAPWAP_STAT_QUEUE_H_

#include    "ah_syscall.h"


typedef struct {
	int capacity;
	int front;
	int rear;
	int size;
	ah_capwap_statis_request_t *array;
} ah_capwap_stat_queue_t;

static  inline int ah_capwap_stat_queue_is_empty(ah_capwap_stat_queue_t *queue)
{
	return (queue->size == 0);
}

static  inline int ah_capwap_stat_queue_is_full(ah_capwap_stat_queue_t *queue)
{
	return (queue->size == queue->capacity); /****/
}

static  inline void ah_capwap_stat_queue_make_empty(ah_capwap_stat_queue_t   *queue)
{
	queue->size = 0;
	queue->front = 1;
	queue->rear = 0;

	return;
}

static  inline ah_capwap_stat_queue_t *ah_capwap_stat_queue_create_queue(int max_element)
{
	ah_capwap_stat_queue_t *queue;

	queue = (ah_capwap_stat_queue_t *)ah_malloc(sizeof(ah_capwap_stat_queue_t));
	if (queue == NULL) {
		return NULL;
	}

	queue->array = (ah_capwap_statis_request_t *)malloc(
					   sizeof(ah_capwap_statis_request_t) * max_element);
	if (queue->array == NULL) {
		ah_free(queue);
		return NULL;
	}

	queue->capacity = max_element;
	ah_capwap_stat_queue_make_empty(queue);

	return queue;
}


static inline void ah_capwap_stat_queue_dispose_queue(ah_capwap_stat_queue_t *queue)
{
	if (queue != NULL) {
		ah_free(queue->array);
		ah_free(queue);
	}

	return;
}

static inline int ah_capwap_stat_queue_succ(int value, ah_capwap_stat_queue_t *queue)
{
	if (++value == queue->capacity) {
		value = 0;
	}

	return value;
}


static  inline  int ah_capwap_stat_queue_enqueue
(
	const ah_capwap_statis_request_t *x,
	ah_capwap_stat_queue_t *queue
)
{
	int rc = 0;

	if (ah_capwap_stat_queue_is_full(queue)) {
		rc = 0;
	} else {
		rc = ++queue->size;
		queue->rear = ah_capwap_stat_queue_succ(queue->rear, queue);
		ah_memcpy(&queue->array[queue->rear], x, sizeof(ah_capwap_statis_request_t));
	}

	return rc;
}


static inline int ah_capwap_stat_queue_front
(
	ah_capwap_statis_request_t *x,
	ah_capwap_stat_queue_t *queue
)
{
	int         rc = 1;

	if (!ah_capwap_stat_queue_is_empty(queue)) {
		ah_memcpy(x, &(queue->array[queue->front]), sizeof(ah_capwap_statis_request_t));
		rc = 0;
	}

	return rc;
}


static  inline void ah_capwap_stat_queue_dequeue(ah_capwap_stat_queue_t *queue)
{

	if (ah_capwap_stat_queue_is_empty(queue)) {
		;
	} else {
		queue->size--;
		queue->front = ah_capwap_stat_queue_succ(queue->front, queue);
	}

	return;
}

static inline int ah_capwap_stat_queue_front_and_dequeue
(
	ah_capwap_statis_request_t *x,
	ah_capwap_stat_queue_t *queue
)
{
	int     rc = 0;

	if (ah_capwap_stat_queue_is_empty(queue)) {
		rc = 1;
	} else {
		queue->size--;
		ah_memcpy(x, &queue->array[queue->front], sizeof(ah_capwap_statis_request_t));
		queue->front = ah_capwap_stat_queue_succ(queue->front, queue);
	}

	return rc;
}

#endif

