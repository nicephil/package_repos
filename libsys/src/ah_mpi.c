#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "ah_types.h"
#include "ah_smpi.h"
#include "ah_mpi.h"
#include "ah_syscall.h"
#include "ah_lib.h"
#include "ah_assert.h"
#include "ah_mpi_debug.h"
#include "ah_tlv_msg_s.h"
#include "ah_cmd_s.h"

/*
 * lib global vars
 */
int debug_mpi = 0;

typedef struct {
	int      ms_sock;               /* socket id for msg passing */
	uint32_t   ms_port;               /* mpi port number */
	uint16_t   ms_mh;                 /* table index of the entry */
} ah_mpi_tbl_t;

#define MPI_PORT_TBL_MAX 128            /* max simultanous opened mpi channel supported */

static ah_mpi_tbl_t *mpi_port_tbl[MPI_PORT_TBL_MAX];


int mh2sock(int mh)
{
	ah_assert(mh < MPI_PORT_TBL_MAX);
	ah_assert(mh >= 0);

	return (NULL != mpi_port_tbl[mh]) ? mpi_port_tbl[mh]->ms_sock : -1;
}

uint16_t mh2mid(int mh)
{
	ah_assert(mh < MPI_PORT_TBL_MAX);

	return mpi_port_tbl[mh] ?
		   MPI_PID2MID(mpi_port_tbl[mh]->ms_port) :
		   AH_MOD_ID_INVALID;
}
uint16_t mh2sid(int mh)
{
	ah_assert(mh < MPI_PORT_TBL_MAX);

	return mpi_port_tbl[mh] ?
		   MPI_PID2SID(mpi_port_tbl[mh]->ms_port) :
		   AH_SUB_MOD_ID_INVALID;
}
/*
 * get a free slot
 * return -1 if no free slot available
 */
static int get_mh(void)
{
	int i;

	for (i = 0; i < MPI_PORT_TBL_MAX; i++) {

		if (!mpi_port_tbl[i]) {
			return i;
		}
	}
	return -1;
}

/*
 * IPC is implemented via PF_NETLINK domain socket, mid + sid uniquely identify a MPI sock
 * return: -1 on error, a non-negative integer as the handle to the mpi channel
 */
int ah_mpi_open_internal(uint32_t mpid, boolean attempt_bind)
{
	int fd;
	int mh = -1;
	int reuse = 1;
	struct sockaddr_nl local;
	struct linger linger;
	int rcvbuf_size = 0;
	unsigned int length = sizeof(rcvbuf_size);

	/*
	 * construct the sock addr
	 */
	ah_memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = mpid;
	local.nl_groups = 0; /* subscribe to netlink mcast grp later */

	/*
	     * create/bind sock
	     */
	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_AHIPC);
	if (fd < 0) {
		ah_err_old("mpi socket error %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		ah_err_old("mpi set reuse address option error: %s", strerror(errno));
		close(fd);
		return -1;
	}

	linger.l_onoff = 1;
	linger.l_linger = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0) {
		ah_err_old("mpi set linger option error: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, &length) < 0) {
		ah_err_old("mpi get max receive buff size  error: %s", strerror(errno));
		close(fd);
		return -1;
	}
	rcvbuf_size *= 4;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
		ah_err_old("mpi set max receive buff size  error: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		if (!attempt_bind) {
			ah_err_old("mpi bind netlink socket error: %s",
					   strerror(errno));
		}
		close(fd);
		return -1;
	}

	/*
	 * maintain state in side the lib for this <mpid>
	 */
	if ((mh = get_mh()) < 0) {
		ah_err_old("not free mpi slot available!\n");
		close(fd);
		return -1;
	}

	if (0 != fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		ah_err_old("mpi failed to set close-on-exec");
		close(fd);
		return -1;
	}

	if (!(mpi_port_tbl[mh] = (ah_mpi_tbl_t *)ah_calloc(1, sizeof(ah_mpi_tbl_t)))) {
		ah_err_old("mpi alloc error: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	mpi_port_tbl[mh]->ms_sock = fd;
	mpi_port_tbl[mh]->ms_port = mpid;
	mpi_port_tbl[mh]->ms_mh   = mh;

#if 0
	ah_log_old(AH_LOG_INFO, "mpi open: %s/%s(0x%x) ok!\n",
			   mid2name(MPI_PID2MID(mpid)),
			   sid2name(MPI_PID2SID(mpid)),
			   mpid);
#endif
	if (ah_mpi_debug_init() != 0) {
		ah_log_old(AH_LOG_ERR, "Error init ah_mpi_debug_init in %s/%s\n",
				   mid2name(MPI_PID2MID(mpid)),
				   sid2name(MPI_PID2SID(mpid)));
	} else {
		ah_mpi_debug_unset((MPI_PID2MID(mpid)),
						   (MPI_PID2SID(mpid)), AH_MPI_DEBUG_ALL);
	}

	return mh;
}

int ah_mpi_attempt_open(uint32_t mpid)
{
	return ah_mpi_open_internal(mpid, TRUE);
}

int ah_mpi_open(uint32_t mpid)
{
	return ah_mpi_open_internal(mpid, FALSE);
}

/*
 * free a mpi channel handle <mh>
 */
void ah_mpi_close(int mh)
{
	if (mh < 0 || mh >= MPI_PORT_TBL_MAX) {
		ah_assert(mh > 0);
		ah_assert(mh < MPI_PORT_TBL_MAX);
		return;
	}

	/*
	 * clear state inside this lib
	 */
	if (mpi_port_tbl[mh]) {
		close(mpi_port_tbl[mh]->ms_sock);
		ah_log_old(AH_LOG_INFO, "mpi close %s/%s(0x%x)\n",
				   mid2name(MPI_PID2MID(mpi_port_tbl[mh]->ms_port)),
				   sid2name(MPI_PID2SID(mpi_port_tbl[mh]->ms_port)),
				   mpi_port_tbl[mh]->ms_port);
		ah_free(mpi_port_tbl[mh]);
		mpi_port_tbl[mh] = NULL;
	}
}
/*
 * malloc a mpi message buffer
 * return NULL if fail.
 */
char *ah_mpi_malloc(size_t size)
{
	char *p;

	ah_assert(size > 0);

	/*
	 * malloc the required mem space
	 */
	if (!(p = (char *) ah_malloc(MPI_MSG_SPACE(size)))) {
		ah_err_old("MPI alloc fail: %s\n", strerror(errno));
		return NULL;
	}

	/*
	 * set magic mark
	 */
	set_mpi_nhl_valid(p);

	/*
	 * return ptr to data start
	 */
	return MPI_NLH2DAT(p);
}
/*
 * free the <buf> being allocated by <ah_mpi_alloc>
 */
void ah_mpi_free(char *buf)
{
	if (buf) {
		if (!is_valid_mpi_data(buf)) {
			ah_err_old("MPI free non-mpi buffer 0x%8x\n", buf);
			ah_assert(FALSE);
			return;
		}
		ah_free(MPI_DAT2NLH(buf));
	}
}

/*
 * a blocking call for recv MPI messages. the call will block the calling thread
 * until got some msg.
 * <mh>: the mpi handle got by <ah_mpi_open>
 * <buf>: ptr of the data buffer got by <ah_mpi_alloc>
 * <len>: size of <buf> in byte
 * <mid>: if not null, will fill the sending module ID
 * <sid>: if not null, will fill the sending sub-module ID
 *
 * return: number of bytes recvd, < 0 on error.
 */
int ah_mpi_recvfrom(int mh, char *buf, size_t len, uint32_t *mpi_port)
{
	int rc;
	struct nlmsghdr *nlh;
	struct nlmsgerr *errmsg = NULL;
	size_t size;
#if 1
	fd_set rfd;
	struct timeval tv;
#endif

	if (!buf || !len || mh < 0) {
		ah_err_old("bad pass-in parm: mpi handle(%d) buf(%x) len(%d)\n", mh, buf, len);
		return -1;
	}

	/*
	 * get the sock fd
	 */
	if (!mpi_port_tbl[mh]) {
		ah_err_old("%d is not an opened mpi handle\n", mh);
		ah_assert(FALSE);
		return -1;
	}

	/*
	 * validate <buf> is a mpi buffer
	 */
	if (!is_valid_mpi_data(buf)) {
		ah_err_old("bad MPI buffer (0x%8x)\n", buf);
		ah_assert(FALSE);
		return -1;
	}

	/*
	 * offset the buf head ptr
	 */
	nlh  = MPI_DAT2NLH(buf);
	size = len + MPI_HDR_SPACE;

#if 1
	if ((mpi_port_tbl[mh]->ms_sock < 0) || (mpi_port_tbl[mh]->ms_sock >= FD_SETSIZE)) {
		ah_err_old("bad MPI fd %d (FD_SETSIZE=%d)\n", mpi_port_tbl[mh]->ms_sock, FD_SETSIZE);
		return -1;
	}
	FD_ZERO(&rfd);
	FD_SET(mpi_port_tbl[mh]->ms_sock, &rfd);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	do {
		rc = select(mpi_port_tbl[mh]->ms_sock + 1, &rfd, 0, 0, &tv);
	} while ((rc < 0) && errno == EINTR);

	/*
	 * relay sys-call error code to caller
	 */
	if (rc <= 0) { // timeout == 0
		return rc;
	}
#endif

	rc = recvfrom(mpi_port_tbl[mh]->ms_sock, (void *)nlh, size, 0, (struct sockaddr *) NULL, NULL);

	ah_mpi_dbg((mpi_port_tbl[mh])->ms_port, AH_MPI_DEBUG_RECV,
			   "mpi  pid: %d mod: %s, submod: %s,  sock fd: %d, recv from "
			   "mod: %s, submod: %s, result: %d\n",
			   getpid(),
			   mid2name(MPI_PID2MID(mpi_port_tbl[mh]->ms_port)),
			   sid2name(MPI_PID2SID(mpi_port_tbl[mh]->ms_port)),
			   mpi_port_tbl[mh]->ms_sock,
			   mid2name(MPI_PID2MID(nlh->nlmsg_pid)),
			   sid2name(MPI_PID2SID(nlh->nlmsg_pid)),
			   rc);

	if (rc < MPI_HDR_SPACE) {
		ah_err_old("MPI recv return code %d <%s>\n",
				   rc, (rc < 0) ? strerror(errno) : "too short msg");
		errno = EBADMSG;
		return -1;
	}

	ah_mpi_debug_dump_recv(mpi_port_tbl[mh]->ms_port, nlh, nlh->nlmsg_len);

	/*
	     * socket got something
	 */
	ah_assert(is_valid_mpi_nlh(nlh));

	ah_dbg_old(debug_mpi, "mpi recv port(0x%x) -> port(0x%x) %d bytes data\n",
			   nlh->nlmsg_pid, mpi_port_tbl[mh]->ms_port, rc - MPI_HDR_SPACE);

	/*
	 * no idea how could it be those value, but anyway left changming's original code here.
	 * - Yong Kang [Mon 04 Dec 2006 03:27:22 PM PST]
	 */
	switch (nlh->nlmsg_type) {
	case NLMSG_NOOP:
	case NLMSG_OVERRUN:
		ah_log_old(AH_LOG_INFO, "### mlmsg type 0x%x\n", nlh->nlmsg_type);
		return 0;

	case NLMSG_ERROR:
		errmsg = NLMSG_DATA(nlh);
		ah_err_old("MPI recv NACK from netlink: %d\n", (errmsg != NULL) ? errmsg->error : 0); /* !errmsg is ACK? */
		return -1;
	}

	if (mpi_port) {
		*mpi_port = nlh->nlmsg_pid;
	}

	/*
	 * return data length
	 */
	return rc - MPI_HDR_SPACE;
}
/*
 * send mpi msg <buf> of length <len> to <mid/sid> via the MPI channel <mh>
 * return -1 on error, 0 if ok.
 */
static int _ah_mpi_sendto(int mh,
						  char *buf,
						  size_t len,
						  uint32_t mpi_port,
						  boolean to_kernel,
						  uint32_t *psrc_port)
{
	int rc;
	struct nlmsghdr *nl;
	struct sockaddr_nl remote;      /* remote peer address */
	uint32_t src_port;
	static uint32_t sendto_err_other = 0;
	static uint32_t sendto_all = 0;
	static uint32_t sendto_err_blk = 0;

	if (!buf || !len) {
		ah_err_old("MPI bad msg: buf(0x%08x) length(%d) to port(0x%x)\n",
				   buf, len, mpi_port);
		return -1;
	}

	if (!mpi_port_tbl[mh]) {
		ah_err_old("MPI can't find opened handle(%d)\n", mh);
		return -1;
	}

	if (!is_valid_mpi_data(buf)) {
		ah_assert(FALSE);
		return -1;
	}

	/*
	 * offset the buf head ptr
	 */
	nl = MPI_DAT2NLH(buf);

	/*
	 * set mpi hdr
	 */
	src_port = (NULL == psrc_port) ? mpi_port_tbl[mh]->ms_port : *psrc_port;
	nl->nlmsg_len   = MPI_MSG_SPACE(len);
	nl->nlmsg_flags = NLM_F_REQUEST;
	nl->nlmsg_type  = (to_kernel ? MPI_MSG_T_UCAST_U2K : MPI_MSG_T_UCAST_U2U);
	nl->nlmsg_pid   = src_port;       /* src port in nlmsg hdr */
	set_mpi_nhl_cookie(nl, mpi_port);                  /* dst port in cookie */

	/*
	 * if destined for the kernel, both nl_pid and nl_groups should be
	 * supplied with 0
	 */
	memset(&remote, 0, sizeof(struct sockaddr_nl));
	remote.nl_family = AF_NETLINK;
	remote.nl_groups = 0x0;
	remote.nl_pid = to_kernel ? 0x0 : mpi_port;

	if (debug_mpi)  {
		ah_dbg_old(debug_mpi, "MPI send %s(0x%x) -> (0x%x) %d bytes\n",
				   to_kernel ? "to kernel " : "",
				   src_port,
				   mpi_port, len);

		ah_hexdump((uchar *)nl, nl->nlmsg_len);
	}

	rc = sendto(mpi_port_tbl[mh]->ms_sock, nl, nl->nlmsg_len, MSG_DONTWAIT,
				(struct sockaddr *) &remote, sizeof(remote));

	sendto_all++;
	if (rc < 0) {
		if (rc == -EAGAIN) {
			sendto_err_blk++;
		} else {
			sendto_err_other++;
		}
	}

	ah_mpi_dbg(src_port, AH_MPI_DEBUG_SEND,
			   "mpi  pid: %d mod: %s, submod: %s,  sock fd: %d, send to "
			   "mod: %s, submod: %s, result: %d, counters: all %d, err_blks %d, err_others %d\n",
			   getpid(),
			   mid2name(MPI_PID2MID(src_port)),
			   sid2name(MPI_PID2SID(src_port)),
			   mpi_port_tbl[mh]->ms_sock,
			   mid2name(MPI_PID2MID(mpi_port)),
			   sid2name(MPI_PID2SID(mpi_port)),
			   rc, sendto_all, sendto_err_blk, sendto_err_other);

	ah_mpi_debug_dump_send(src_port, nl, nl->nlmsg_len);

	return rc;
}

/*
 * forward send from user to user
 */
int ah_mpi_forward_sendto(int mh,
						  char *buf,
						  size_t len,
						  uint32_t mpi_port,
						  uint32_t *psrc_port)
{
	return _ah_mpi_sendto(mh, buf, len, mpi_port, FALSE, psrc_port);
}

/*
 * send from user to user
 */
int ah_mpi_sendto(int mh, char *buf, size_t len, uint32_t mpi_port)
{
	return _ah_mpi_sendto(mh, buf, len, mpi_port, FALSE, NULL);
}
/*
 * send from user to kernel
 */
int ah_mpi_sendto_kernel(int mh, char *buf, size_t len, uint16_t kid)
{
	return _ah_mpi_sendto(mh, buf, len, kid, TRUE, NULL);
}

ah_tlv_t *ah_mpi_add_tlv(ah_tlv_hdr_t **_tlvh,
						 ushort      t, ushort l, void *v)
{
	ah_tlv_hdr_t *tlvh = *_tlvh;
	ah_tlv_t *tlvp;
	uint16_t tlv_space = AH_TLVSIZE(l);       /* to-be added tlv size */

	/*
	 * make sure no buffer overflow
	 */
	if (tlv_space > AH_MAX_TLV_BUF_SIZE) {
		ah_log_old(AH_LOG_INFO, "#### tlv_space = %d\n", tlv_space);
		ah_assert(0);
		return NULL;
	}

	/*
	 * alloc a tlvh if not yet.
	 */
	if (NULL == tlvh) {
		tlvh = (ah_tlv_hdr_t *)
			   ah_mpi_malloc(AH_CLI_MAX_RECV_LEN);
		if (NULL == tlvh) {
			ah_log_old(AH_LOG_ERR, "cli agent failed to init tlv buf\n");
			return NULL;
		}
		tlvh->alloc_len = AH_CLI_MAX_RECV_LEN;
		tlvh->used_len = sizeof(*tlvh);
		tlvh->num_blks = 0;
		*_tlvh = tlvh;
	}

	/*
	 * fill-in this tlv
	 */
	tlvp = (ah_tlv_t *)((char *)tlvh + tlvh->used_len);
	tlvp->type = t;
	tlvp->len = l;

	if (v) {
		memcpy(tlvp->val, v, l);
	} else {
		/* cli might resv the space, so zero it out */
		memset((void *)tlvp->val, 0, l);
	}

	tlvh->used_len += tlv_space;
	tlvh->num_blks++;

	return tlvp;
}
