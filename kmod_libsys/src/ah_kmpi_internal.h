#ifndef __AH_KMPI_INTERNAL_H__
#define __AH_KMPI_INTERNAL_H__

/*******************************************/
/* kmpi module internal header file        */
/* Author: Yong Kang                       */
/* Date: [Thu 16 Nov 2006 03:15:32 PM PST] */
/*******************************************/

/*
 * handy ah_logk for kmpi module
 */
#define mpi_logk(lvl, fmt, arg...)      ah_logk(AH_SYS_KMOD_MPI, lvl, fmt, ##arg)
#define mpi_dbgk(lvl, fmt, arg...)      ah_dbgk(AH_SYS_KMOD_MPI, lvl, fmt, ##arg)

/*
 * constant define
 */
#define AH_KEVENT_DEV_NAME "ah_kevent"

/*
 * mpi intra-module APIs
 */
int __init ah_kevent_init(void);
void __exit ah_kevent_exit(void);

#endif /*__AH_KMPI_INTERNAL_H__*/
