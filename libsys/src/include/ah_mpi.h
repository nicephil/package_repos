#ifndef _AEROS_MPI_H
#define _AEROS_MPI_H

#include <sys/types.h>
/*
 * following APIs is provided for user process IPC machanism in Aeros.
 * typecal usage steps are like:

        1. mh  = ah_mpi_open (my_mid, my_sid);
        2. buf = ah_mpi_malloc (max_size);
        3. ah_mpi_sendto (... dst_mid, dst_sid) or ah_mpi_sendto_kernel (... dst_kid);
        4. ah_mpi_recvfrom (...)
        5. ah_mpi_free(buf) and ah_mpi_close (mh)
*/

extern int   ah_mpi_open (uint32_t mpi_port);        /* open MPI channel for send/recv */
extern void  ah_mpi_close (int mh);                /* close MPI channel */
extern char *ah_mpi_malloc (size_t size);          /* get a MPI message buffer ptr of <size> bytes */
extern void  ah_mpi_free (char *buf);              /* free a MPI message buffer ptr */
extern int   ah_mpi_recvfrom (int mh, char *buf, size_t len,
							  uint32_t *mpi_port);           /* blocking call of recv MPI msg from channel <mh> */
extern int   ah_mpi_sendto (int mh, char *buf, size_t len,
							uint32_t mpi_port);              /* non-blocking call of send MPI msg to channel <mh> */
extern int   ah_mpi_sendto_kernel (int mh, char *buf, size_t len,
								   uint16_t kid);            /* non-blocking call send msg to kernel module <kid> */
extern uint16_t mh2mid (int mh);   /* return module ID (AH_MOD_ID_INVALID could be returned if the mh is invalid */
extern uint16_t mh2sid (int mh);   /* return sub-module ID (AH_SUB_MOD_ID_INVALID could be returned if the mh is invalid */
extern int mh2sock(int mh);
extern int ah_mpi_attempt_open(uint32_t mpid);
extern int ah_mpi_forward_sendto(int mh,
								 char *buf,
								 size_t len,
								 uint32_t mpi_port,
								 uint32_t *psrc_port);

#endif
