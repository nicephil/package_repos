#include "ah_event_internal.h"
#include "ah_event.h"

#define EVENT_EXIT_MAGIC_CODE 911911u

/* Event thread state */
enum {
	EVENT_THREAD_INIT = 0,  // Not started yet
	EVENT_THREAD_RUNNING,   // Running
	EVENT_THREAD_EXIT,      // To Exit
	EVENT_THREAD_FAILED     // Failed

};

static ah_event_ctrl_t *ah_event_ctrl = NULL;

/*
 * Event processing function
 */
static int ah_event_process_msg(const char *buf, uint len)
{
	int      event_debug;
	uint16_t   eid;
	ah_event_msg_t *event_msg = (ah_event_msg_t *)buf;
	ah_event_proc_vector_t func = NULL;
	ah_kevent_proc_vector_t kfunc = NULL;

	/* mpi msg is 4-byte aligned */
	ah_assert(event_msg->em_len + sizeof(*event_msg) <= len);

	eid = event_msg->em_eid;

	if (event_msg->em_flag & AH_EVT_FLAG_FROM_KERNEL) {

		ah_assert(is_kevent_valid(eid));

		/* event debug is in shared memory */
		event_debug = ah_event_debug ||
					  (ah_event_ctrl->event_shm->rcvr_maps[eid][(ah_event_ctrl->module_id) / AH_TOTAL_BITS_IN_WORD]
					   & AH_EVENT_DEBUG_MASK);

		ah_dbg_old(event_debug, "receive kevent \"%s\", size=%u\n",
				   eid2name(eid), event_msg->em_len);


		kfunc = ah_event_ctrl->kevent_vector[eid];
        if (NULL != kfunc) {
            kfunc(eid, event_msg->em_len, event_msg->em_data);
        }
	} else {

		if (AH_EVENT_MAX_NUM == eid) {
			if ((event_msg->em_len == sizeof(uint32_t))
				&& (EVENT_EXIT_MAGIC_CODE == *((uint32_t *)event_msg->em_data))) {
				return -1;
			} else {
				ah_err_old("module %d receive wrong exit info", ah_event_ctrl->module_id);
				return 0;
			}
		}
		ah_assert(eid < AH_EVENT_MAX_NUM);

		/* event debug is in shared memory */
		event_debug = ah_event_debug ||
					  (ah_event_ctrl->event_shm->rcvr_maps[eid][(ah_event_ctrl->module_id) / AH_TOTAL_BITS_IN_WORD]
					   & AH_EVENT_DEBUG_MASK);

		ah_dbg_old(event_debug, "receive event \"%s\", size=%u\n",
				   ah_eventid_to_name(eid), event_msg->em_len);

		func = ah_event_ctrl->event_vectors[eid];
        if (NULL != func) {
            func(eid, event_msg->em_len, event_msg->em_data);
        }
	}

	return 0;
}

static int ah_block_event_process_msg(const char *buf, uint len, uint32_t mpi_port)
{
	int      event_debug;
	uint16_t   eid;
	ah_event_msg_t *event_msg = (ah_event_msg_t *)buf;
	ah_block_event_proc_vector_t func = NULL;
	int rc;
	ah_event_reply_t reply;

	/* mpi msg is 4-byte aligned */
	ah_assert(event_msg->em_len + sizeof(*event_msg) <= len);

	eid = event_msg->em_eid;

	if (AH_EVENT_MAX_NUM == eid) {
		if ((event_msg->em_len == sizeof(uint32_t))
			&& (EVENT_EXIT_MAGIC_CODE == *((uint32_t *)event_msg->em_data))) {
			return -1;
		} else {
			ah_err_old("module %d receive wrong exit info", ah_event_ctrl->module_id);
			return 0;
		}
	}
	ah_assert(eid < AH_EVENT_MAX_NUM);

	/* event debug is in shared memory */
	event_debug = ah_event_debug ||
				  (ah_event_ctrl->event_shm->rcvr_maps[eid][(ah_event_ctrl->module_id) / AH_TOTAL_BITS_IN_WORD]
				   & AH_EVENT_DEBUG_MASK);

	ah_dbg_old(event_debug, "receive event \"%s\", size=%u\n",
			   ah_eventid_to_name(eid), event_msg->em_len);

	func = ah_event_ctrl->block_event_vector;


	if (NULL != func) {
		rc = func(eid, event_msg->em_len, event_msg->em_data);
		reply.rc = rc;
		ah_event_sendto(AH_EVENT_BLOCK_CALL_REPLY, sizeof(reply), &reply, mpi_port,
						event_msg->em_seq);
	}
	return 0;
}

/* Event library subthread */
static void *ah_old_event_subthread(void *arg)
{
	int rc = 0;
	char *mpi_buf = NULL;
	event_cookie *event = (event_cookie *)arg;

	/* install SIGALRM handler for timer */
	if (event_start_timer) {
		if (ah_ptimer_init() < 0) {
			ah_err_old("pid %d fail init timer", getpid());
			exit(1);
		}
	}

	/* initialize MPI buffer */
	mpi_buf = ah_mpi_malloc(AH_EVENT_MAX_LEN);
	if (NULL == mpi_buf) {
		ah_err_old("failed to malloc buffer for event lib");
		event->state = EVENT_THREAD_FAILED;
		return NULL;
	}

	event->state = EVENT_THREAD_RUNNING;

	/* Start main loop */
	for (; ;) {

		/* poll timer queue after unblocked from select */
		ah_ptimer_poll();
		/* Waiting for message or signal */
		rc = ah_mpi_recvfrom(event->mpi_fd, mpi_buf, AH_EVENT_MAX_LEN, NULL);
		if (rc <= 0) {
			continue;
		}

		/* Process MPI msg */
		if (ah_event_process_msg(mpi_buf, rc) < 0) {
			event->state = EVENT_THREAD_EXIT;
			ah_mpi_free(mpi_buf);
			break;
		}
	}

	return NULL;
}

/* Event library subthread */
static void *ah_event_subthread(void *arg)
{
	int rc = 0;
	char *mpi_buf = NULL;
	event_cookie *event = (event_cookie *)arg;

	/* initialize MPI buffer */
	mpi_buf = ah_mpi_malloc(AH_EVENT_MAX_LEN);
	if (NULL == mpi_buf) {
		ah_err_old("failed to malloc buffer for event lib");
		event->state = EVENT_THREAD_FAILED;
		return NULL;
	}

	event->state = EVENT_THREAD_RUNNING;

	/* Start main loop */
	for (; ;) {

		/* Waiting for message or signal */
		rc = ah_mpi_recvfrom(event->mpi_fd, mpi_buf, AH_EVENT_MAX_LEN, NULL);
		if (rc <= 0) {
			continue;
		}

		/* Process MPI msg */
		if (ah_event_process_msg(mpi_buf, rc) < 0) {
			event->state = EVENT_THREAD_EXIT;
			ah_mpi_free(mpi_buf);
			break;
		}
	}

	return NULL;
}

/* Event library subthread */
static void *ah_block_event_subthread(void *arg)
{
	int rc = 0;
	char *mpi_buf = NULL;
	event_cookie *event = (event_cookie *)arg;
	uint32_t mpi_port;

	/* initialize MPI buffer */
	mpi_buf = ah_mpi_malloc(AH_EVENT_MAX_LEN);
	if (NULL == mpi_buf) {
		ah_err_old("failed to malloc buffer for event lib");
		event->state = EVENT_THREAD_FAILED;
		return NULL;
	}

	event->state = EVENT_THREAD_RUNNING;

	/* Start main loop */
	for (; ;) {

		/* Waiting for message or signal */
		rc = ah_mpi_recvfrom(event->mpi_fd, mpi_buf, AH_EVENT_MAX_LEN, &mpi_port);
		if (rc <= 0) {
			continue;
		}

		/* Process MPI msg */
		if (ah_block_event_process_msg(mpi_buf, rc, mpi_port) < 0) {
			event->state = EVENT_THREAD_EXIT;
			ah_mpi_free(mpi_buf);
			break;
		}
	}

	return NULL;
}

/************************************************************************
 * Start event subthread
 *
 * Description:
 *      This function creates event subthread.
 *
 * INPUT:
 *      event_ctrl - Event control data
 *      i - high or low priority event thread index
 * OUTPUT:
 *      event_tid - pointer to hold thread ID
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_start_subthread(ah_event_ctrl_t *event_ctrl,
							 int i,
							 pthread_t *event_tid)
{
	int priority;
	int count = 0;

	ah_assert(event_ctrl->event[i].mpi_fd >= 0);
	event_ctrl->event[i].state = EVENT_THREAD_INIT;
	ah_event_ctrl = event_ctrl;

	/* Create event sub-thread */
	if (AH_LOWEST_EVENT_IDX == i) {

		if (ah_pthread_create(event_tid,
							  ah_event_subthread,
							  &event_ctrl->event[i], SCHED_OTHER,
							  AH_PRIORITY_NORMAL, 0) != 0) {
			ah_err_old("ah_pthread_create failed");
			return -1;
		}

	} else {
		if (AH_LO_EVENT_IDX == i || AH_BLOCK_EVENT_IDX == i) {
			priority = AH_PRIORITY_MGT;
		} else {
			ah_assert(AH_HI_EVENT_IDX == i);
			priority = AH_PRIORITY_CTRL;
		}

		if (ah_pthread_create(event_tid,
							  (AH_BLOCK_EVENT_IDX == i) ? ah_block_event_subthread :
							  (AH_LO_EVENT_IDX == i) ?
							  ah_old_event_subthread : ah_event_subthread,
							  &event_ctrl->event[i], SCHED_RR,
							  priority, 0) != 0) {
			ah_err_old("ah_pthread_create failed");
			return -1;
		}
	}

	/* Check if sub-thread is actually succeeded */
	if (event_ctrl->event[i].state == EVENT_THREAD_INIT) {
		usleep(50000);
	}

	while ((event_ctrl->event[i].state == EVENT_THREAD_INIT)
		   && (count++) < 10) {
		ah_sleep(1);
	}

	if (event_ctrl->event[i].state != EVENT_THREAD_RUNNING) {
		ah_err_old("Can not run %s priority event thread",
				   (AH_LOWEST_EVENT_IDX == i) ? "lowest" :
				   (AH_LO_EVENT_IDX == i) ? "low" : "high");
		*event_tid = -1;
		return -1;
	}

	return 0;
}

/************************************************************************
 * Start event subthread
 *
 * Description:
 *      This function creates event subthread.
 *
 * INPUT:
 *      i - high or low priority event thread index
 * OUTPUT:
 *
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_cleanup_subthread(int i)
{
	int count = 0;
	uint32_t mpi_port;
	uint32_t exit_code = EVENT_EXIT_MAGIC_CODE;
	int ret;
	int   mpi_fd;
	char *mpi_msg;
	ah_event_msg_t *event_msg;

	if (AH_LOWEST_EVENT_IDX == i) {
		mpi_port = MPI_MOD2PID(ah_event_ctrl->module_id,
							   AH_SUB_MOD_ID_LOWEST_EVENT);
	} else if (AH_LO_EVENT_IDX == i) {
		mpi_port = MPI_MOD2PID(ah_event_ctrl->module_id,
							   AH_SUB_MOD_ID_EVENT);
	} else if (AH_BLOCK_EVENT_IDX == i) {
		mpi_port = MPI_MOD2PID(ah_event_ctrl->module_id,
							   AH_SUB_MOD_ID_BLOCK_EVENT);
	} else {
		ah_assert(AH_HI_EVENT_IDX == i);
		mpi_port = MPI_MOD2PID(ah_event_ctrl->module_id,
							   AH_SUB_MOD_ID_HI_EVENT);
	}

	if (EVENT_THREAD_RUNNING != ah_event_ctrl->event[i].state) {
		return 0;
	}

	/* stop the thread */
	mpi_msg = ah_mpi_malloc(sizeof(*event_msg) + sizeof(exit_code));
	if (NULL == mpi_msg) {
		ah_err_old("failed allocated mpi buffer");
		return -1;
	}

	/* Contruct event message */
	event_msg = (ah_event_msg_t *)mpi_msg;
	event_msg->em_eid = AH_EVENT_MAX_NUM;
	event_msg->em_len = sizeof(exit_code);
	event_msg->em_flag &= ~AH_EVT_FLAG_FROM_KERNEL;
	memcpy(event_msg->em_data, &exit_code, sizeof(exit_code));

	if (ah_event_ctrl->event[AH_LO_EVENT_IDX].mpi_fd >= 0) {
		mpi_fd = ah_event_ctrl->event[AH_LO_EVENT_IDX].mpi_fd;
	} else if (ah_event_ctrl->event[AH_HI_EVENT_IDX].mpi_fd >= 0) {
		mpi_fd = ah_event_ctrl->event[AH_HI_EVENT_IDX].mpi_fd;
	} else if (ah_event_ctrl->event[AH_BLOCK_EVENT_IDX].mpi_fd >= 0) {
		mpi_fd = ah_event_ctrl->event[AH_BLOCK_EVENT_IDX].mpi_fd;
	} else {
		ah_mpi_free(mpi_msg);
		return 0;
	}
	ret = ah_mpi_sendto(mpi_fd, mpi_msg,
						sizeof(*event_msg) + sizeof(exit_code), mpi_port);
	ah_mpi_free(mpi_msg);
	if (ret < 0) {
		return -1;
	}
	ret = 0;

	/* wait until it's stopped */
	if (ah_event_ctrl->event[i].state == EVENT_THREAD_RUNNING) {
		usleep(50000);
	}
	while ((ah_event_ctrl->event[i].state == EVENT_THREAD_RUNNING)
		   && ((count++) < 10)) {
		ah_sleep(1);
	}

	if (ah_event_ctrl->event[i].state != EVENT_THREAD_EXIT) {
		ah_err_old("event thread not stopped");
		ret = -1;
	}

	return ret;
}
