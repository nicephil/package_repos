#ifndef  _AH_EVENT_INTERNAL_H
#define  _AH_EVENT_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <sys/select.h>
//#include <asm/page.h>  /*comment the line for building goldengate platform */
#include <signal.h>

#include "ah_types.h"
#include "ah_assert.h"
#include "ah_syscall.h"
#include "ah_pthread.h"
#include "ah_lib.h"
#include "ah_mpi.h"
#include "ah_smpi.h"
#include "ah_event.h"
#include "ah_shm.h"

//#define AH_EVENT_MAX_RCVRS      64
#define AH_EVENT_MAX_RCVRS  (AH_MODULE_ID_BITMAP_SIZE * AH_TOTAL_BITS_IN_WORD)
//#define AH_EVENT_NAME_MAX_LEN   32
#define AH_EVENT_SHM_MODE       0777
#define AH_EVENT_DEBUG_MASK     0x00000001      /* bit 0 of rcvr map is debug control */

/* Event subscriber list */
typedef uint32_t ah_event_rcvr_map_t;

/* Data structure for event lib shared memory */
typedef struct {
	ah_event_rcvr_map_t     rcvr_maps[AH_EVENT_MAX_NUM][AH_MODULE_ID_BITMAP_SIZE];
} ah_event_shm_t;

#define AH_LO_EVENT_IDX     0
#define AH_HI_EVENT_IDX     1
#define AH_LOWEST_EVENT_IDX 2
#define AH_BLOCK_EVENT_IDX  3
#define AH_BLOCK_REPLY_IDX  4
#define AH_EVENT_IDX_MAX    5
typedef struct {
	int mpi_fd; /* MPI msg send/receive handle for event thread */
	int state;  /* event thread state */
} event_cookie;

/* Event lib control structure */
typedef struct {
	boolean                 initialized;
	//int                     shmid;
	//uint32_t                  shmsize;
	uint32_t                  module_id;
	event_cookie            event[AH_EVENT_IDX_MAX];

	/* Event semaphore for locking between different processes */
	ah_sem_t                semid;
	ah_event_shm_t          *event_shm;
	/* Generic event lock */
	//pthread_mutex_t         event_lock;

	/* Event processing vector array */
	ah_event_proc_vector_t  event_vectors[AH_EVENT_MAX_NUM]; /* hold the subscribed user evt callback */
	ah_kevent_proc_vector_t  kevent_vector[AH_KEVENT_MAX];    /* hold the subscribed kevt callback */
	ah_block_event_proc_vector_t block_event_vector;

	//int                     kevt_fd;                         /* ioctl fd for kevent sub/un-sub */

	/* Event sub thread */
	//pthread_t               event_tid;
} ah_event_ctrl_t;

extern int ah_event_debug;
extern boolean event_start_timer;

int ah_event_start_subthread(ah_event_ctrl_t *event_ctrl,
							 int i,
							 pthread_t *event_tid);
int ah_event_cleanup_subthread(int i);

#endif /* _AH_EVENT_INTERNAL_H */
