#ifndef _AH_MPI_DENUG_H_
#define _AH_MPI_DEBUG_H_

#include "ah_types.h"
#include "ah_smpi.h"
#include "ah_lib.h"
#include "ah_assert.h"
#include "ah_shm.h"
typedef struct ah_mpi_debug_conf_ {
	uchar      flag;
#define AH_MPI_DEBUG_RECV       0x01
#define AH_MPI_DEBUG_SEND       0x02
#define AH_MPI_DEBUG_DUMP_RECV  0x04
#define AH_MPI_DEBUG_DUMP_SEND  0x08
#define AH_MPI_DEBUG_ALL        0xff
#define AH_MPI_DEBUG_DUMP_RECV_TRUE  (AH_MPI_DEBUG_DUMP_RECV | AH_MPI_DEBUG_RECV)
#define AH_MPI_DEBUG_DUMP_SEND_TRUE  (AH_MPI_DEBUG_DUMP_SEND | AH_MPI_DEBUG_SEND)
} ah_mpi_debug_conf_t;

typedef struct ah_mpi_debug_table_ {
	ah_mpi_debug_conf_t info[AH_MOD_ID_MAX + 1][AH_SUB_MOD_ID_MAX + 1];
} ah_mpi_debug_table_t;

typedef struct ah_mpi_debug_ctrl_ {
	boolean               initialized;
	int                     shmid;
	uint32_t                shmsize; /* (AH_MOD_ID_MAX + 1) * (AH_SUB_MOD_ID_MAX + 1) */
	ah_mpi_debug_table_t    *debug_table;
	/*semaphore for locking between different processes */
	ah_sem_t                semid;
} ah_mpi_debug_ctrl_t;


#ifdef AH_DEBUG_FEATURE
#define ah_mpi_dbg(pid, type, fmt, arg...) do { \
		int      mid; \
		int      sid; \
		uchar      flag; \
		mid  = MPI_PID2MID((pid)); \
		sid  = MPI_PID2SID((pid)); \
		if((is_mid_valid(mid) && is_sid_valid(sid))) { \
			flag  = (ah_mpi_debug_ctrl.debug_table)->info[mid][sid].flag; \
			if ((type) & (flag)) { \
				__ah_dbg_old(" ", __LINE__, #type, fmt, ##arg); \
			} \
		} \
	} while(0)
#else
#define ah_mpi_dbg(pid, type, fmt, arg...)
#endif


extern ah_mpi_debug_ctrl_t ah_mpi_debug_ctrl;
extern int   ah_mpi_debug_init(void);
extern int   ah_mpi_debug_set(int mid, int sid, uchar flag);
extern int   ah_mpi_debug_unset(int mid, int sid, uchar flag);
extern void  ah_mpi_debug_dump(int pid, const uchar *buf, uint len, uchar flag);

#define ah_mpi_debug_dump_recv(_pid, _buf, _len) ah_mpi_debug_dump((_pid), (const uchar *)(_buf), (_len), AH_MPI_DEBUG_DUMP_RECV);
#define ah_mpi_debug_dump_send(_pid, _buf, _len) ah_mpi_debug_dump((_pid), (const uchar *)(_buf), (_len), AH_MPI_DEBUG_DUMP_SEND);
#endif
