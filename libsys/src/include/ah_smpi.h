#ifndef _AEROS_SMPI_H
#define _AEROS_SMPI_H

#ifndef __KERNEL__
#include <sys/socket.h>
#endif
#include <linux/netlink.h>

#include "ah_types.h"
#include "ah_mod_id.h"
/*
 * take one netlink proto number for Aerohive IPC
 * NOTE: must NOT enable ethertap in kernel, see linux/netlink.h for detail
 */
#define NETLINK_AHIPC           17

/*
 * user process sub-module ID table (per module-id)
 * pls update sid2name(...) as well when add new sub-module
 */
typedef enum {
	AH_SUB_MOD_ID_MIN = 0,    /* common sub module end */
	AH_SUB_MOD_ID_MAIN = AH_SUB_MOD_ID_MIN,  /* the main module, i.e. the main thread */
	AH_SUB_MOD_ID_CLI,        /* CLI subagent */
	AH_SUB_MOD_ID_LOWEST_EVENT,/* Lowest event sub-thread */
	AH_SUB_MOD_ID_EVENT,      /* Event sub-thread */
	AH_SUB_MOD_ID_HI_EVENT,    /* High event sub-thread */
	AH_SUB_MOD_ID_BLOCK_EVENT, /* Block event channel, not separate thread */
	AH_SUB_MOD_ID_BLOCK_REPLY, /* Block reply channel should be different from request channel,
                                    * in order to support sender and receiver in the same module. */
	AH_SUB_MOD_ID_MAX,
	AH_SUB_MOD_ID_INVALID = AH_SUB_MOD_ID_MAX
} ah_sub_mod_t;
#define sid2name(sid) ( ((sid)==AH_SUB_MOD_ID_MAIN)? "main": \
						((sid)==AH_SUB_MOD_ID_CLI)? "cli": \
						((sid)==AH_SUB_MOD_ID_LOWEST_EVENT)? "lowestevtlib": \
						((sid)==AH_SUB_MOD_ID_EVENT)? "evtlib": \
						((sid)==AH_SUB_MOD_ID_HI_EVENT)? "hievtlib": \
						((sid)==AH_SUB_MOD_ID_BLOCK_EVENT)? "blockevt": \
						((sid)==AH_SUB_MOD_ID_BLOCK_REPLY)? "blockreply": \
						"n/a" )

/*
 * kernel module id table
 * pls update kid2name(...) as well when add new kernel module ID
 */
typedef enum {
	AH_KMOD_ID_MIN = 0,
	AH_KMOD_ID_FE  = AH_KMOD_ID_MIN, /* forwarding engine */
	AH_KMOD_ID_KEVT,                 /* kevent */
	AH_KMOD_ID_FLOW,
	AH_KMOD_ID_MAX,
	AH_KMOD_ID_INVALID = AH_KMOD_ID_MAX
} ah_kmod_id_t;
#define kid2name(kid) ( ((kid)==AH_KMOD_ID_FE)? "FE": \
						((kid)==AH_KMOD_ID_KEVT)? "KEVENT": \
						((kid)==AH_KMOD_ID_FLOW)? "FLOW": \
						"N/A" )

/*
 * validate <mid/sid/kid>
 */
#define is_mid_valid(mid) ( (mid) < AH_MOD_ID_MAX )
#define is_sid_valid(sid) ( (sid) < AH_SUB_MOD_ID_MAX )
#define is_kid_valid(kid) ( (kid) < AH_KMOD_ID_MAX )

/*
 * handy macro to form the mpi_port
 */
#define MPI_MOD2PID(mid,sid)      ( (((sid)<<16)&0xffff0000) | (mid&0x0000ffff) )
#define MPI_PID2SID(pid)          ( (pid)>>16 & 0x0000ffff )
#define MPI_PID2MID(pid)          ( (pid)     & 0x0000ffff )

/************************************************************
 * following defination is here only because user space API *
 * and kernel API share some data structure, so pls don't   *
 * reference following symbol if you are NOT coding kmpi/mpi*
 * internal code !!!                                        *
 ************************************************************/
/*
 * both KMPI and MPI msg layout is as following: ( 4-byte alignment)
 *
 * struct nlmsghdr *nlh
   0                              16                               31
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        nlh->nlmsg_len                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         nlh->nlmsg_type       |       nlh->nlmsg_flags        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        nlh->nlmsg_seq                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        nlh->nlmsg_pid                         | <---  src mid/sid
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        mph->mh_magic                          | <---  magic number to protect the MPI hdr
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        mph->mh_cookie                         | <---  mpi cookie (to_kernel: dst kid, from_kernel: not_used)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       user data start                         | <---  user data start
   ~                              ...                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {              /* better to be 4-byte align !!! */
	uint32_t    mh_magic;   /* a 32-bit magic number to identify the MPI msg buffer */
	long      mh_cookie;  /* used differently by kernel/userspace, during send/recv */
} ah_mpi_hdr_t;

/*
 * mpi supported msg type
 * kernel already defined <NLMSG_NOOP/NLMSG_ERROR/NLMSG_DONE/NLMSG_OVERRUN>
 * don't know the detail, but don't want to dig it out now, so just define
 * our value using the high byte of the 2-byte nlmsg_type field!
 * -Yong Kang [Mon 04 Dec 2006 03:22:39 PM PST]
 */
#define MPI_MSG_T_UCAST_U2U   0x0100 /* unicast msg from user to user */
#define MPI_MSG_T_UCAST_K2U   0x0200 /* unicast msg from kernel to user */
#define MPI_MSG_T_UCAST_U2K   0x0300 /* unicast msg from user to kernel */
#define MPI_MSG_T_UCAST_K2K   0x0400 /* unicast msg from kernel to kernel */
#define MPI_MAGIC_NUM         ( 0xefefefef )
/*
 * handy macros
 */
#define MPI_HDR_SPACE             ( NLMSG_LENGTH(0) + sizeof(ah_mpi_hdr_t) )    /* mpi hdr length (including nlh) */
#define MPI_MSG_SPACE(len)        ( NLMSG_ALIGN (len + MPI_HDR_SPACE) )
#define MPI_NLH2DAT(nlh)          ( (char*) (((char*)(nlh)) + MPI_HDR_SPACE) )
#define MPI_DAT2NLH(dat)          ( (struct nlmsghdr*) (((char*)(dat)) - MPI_HDR_SPACE) )
#define MPI_NLH2MPH(nlh)          ( (ah_mpi_hdr_t*) (((char*)(nlh)) + NLMSG_LENGTH(0)) )
#define MPI_DAT2MPH(dat)          ( (ah_mpi_hdr_t*) (((char*)(dat)) - sizeof(ah_mpi_hdr_t)) )
#define MPI_DAT2COOKIE(dat)       ( MPI_DAT2MPH(dat)->mh_cookie )
#define MPI_NLH2COOKIE(nlh)       ( MPI_NLH2MPH(nlh)->mh_cookie )
#define is_valid_mpi_data(dat)    ( MPI_DAT2MPH(dat)->mh_magic == MPI_MAGIC_NUM )
#define is_valid_mpi_nlh(nlh)     ( MPI_NLH2MPH(nlh)->mh_magic == MPI_MAGIC_NUM )
#define set_mpi_nhl_valid(nlh)    ( MPI_NLH2MPH(nlh)->mh_magic =  MPI_MAGIC_NUM )
#define set_mpi_nhl_cookie(nlh,c) ( MPI_NLH2MPH(nlh)->mh_cookie =  (long)(c))



#endif
