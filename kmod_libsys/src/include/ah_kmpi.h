#ifndef _AEROS_KMPI_H
#define _AEROS_KMPI_H

#include "ah_smpi.h"
#include "ah_types.h"
#include "ah_kevent.h"
#include "ah_ssysapi.h"

/*
 * kernel mpi APIs.
 * only support send/recv mpi msg from/to userspace process for now
 * -Yong Kang [Mon 04 Dec 2006 04:58:32 PM PST]
 *
 * typical usage:
        1. ah_kmpi_open (...);            //open mpi msg channel
        2. buf = ah_kmpi_malloc (...);    // malloc msg buffer
        3. ah_kmpi_send (buf);            // send msg to user process
   NOTE: recv call back will be called automatically
 *
 */
extern char *ah_kmpi_malloc (size_t len);
extern int   ah_kmpi_open (uint16_t kid, int (*recv_func)(char *buf, int len, uint32_t port_mid));
extern void  ah_kmpi_close (int mh);
/*
 * once <buf> been send, caller can't reference the symbol anymore!!!
 * (that's also why we don't have kmpi_free())
 */
#define ah_kmpi_k2u_send(m, buf, len, port)    ah_kmpi_send((m), MPI_MSG_T_UCAST_K2U, (buf), (len), (port))
#define ah_kmpi_k2k_send(m, buf, len, port)    ah_kmpi_send((m), MPI_MSG_T_UCAST_K2K, (buf), (len), (port))

extern int   ah_kmpi_send (int mh, int msg_type, char *buf, int len, uint32_t mpi_port);

/*
 * kernel event send API.
 * caller need malloc/free <data>
 * return 0 if kevent send to all subscriber, -1 if any subscriber failed.
 */
extern int ah_kevent_send (ah_kevent_t eid, void *data, uint16_t data_size);

extern int ah_ktrap_send(ah_sys_kmod_t mod, uint trap_level, ah_trap_info_t *trap_info, const char *fmt, ...);

#endif
