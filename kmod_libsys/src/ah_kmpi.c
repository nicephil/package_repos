/*
 * include only kernel header files that are part of kernel source tree
 * No libc and its include files
 * include linux/string.h for string manipulation functions if needed
 */
#include <linux/module.h>   /* Needed by all LKM modules */
#include <linux/kernel.h>
#include <linux/init.h>     /* Needed for the macros */

#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#ifdef KERNEL26
#include <linux/security.h>
#endif
#include <net/sock.h>
#include <linux/notifier.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#include <linux/mutex.h>
#endif
#include <net/if_inet6.h>
#include <net/addrconf.h>


#include "ah_kmpi_internal.h"
#include "ah_ksyscall.h"
//#include "ah_ssysapi.h"
//#include "ah_ksys_dev.h"
#include "ah_kmpi.h"
#include "ah_kdbg.h"
#include "ah_kassert.h"

/* ********* -begin- module description ******* */
#define MODULE_NAME "ah_mpi"
#define LKM_KMPI_VERSION "1.0"
#define LKM_KMPI_DESC   "lkm ah mpi code"
#define LKM_KMPI_AUTHOR "www.aerohive.com"

/* module info displayed by modinfo command */
MODULE_VERSION(LKM_KMPI_VERSION);
MODULE_DESCRIPTION(LKM_KMPI_DESC);
MODULE_SUPPORTED_DEVICE("Aerohive's Wireless Devices");
MODULE_AUTHOR(LKM_KMPI_AUTHOR);
MODULE_LICENSE("Aerohive Wireless Inc.");


/*
 * The callback function is called in the context of the sendto() system call
 * invoked by the sending process.
 * It is okay to process the netlink message inside input() thus it has to be fast.
 * TBD: When the processing of netlink message takes a long time, however, we want to keep
 * it out of callback() to avoid blocking other system calls from entering the kernel.
 */
typedef struct {
	uint16_t       kt_kid;           /* socket for msg passing */
	uint16_t       kt_seq;           /* sequence number */
	uint32_t       kt_grp;           /* mutilcast groups as destination */
	int        (*kt_rcv)(char *buf, int len, uint32_t mpi_port);  /* msg recv callback func */
} ah_kmpi_tbl_t;

static struct sock  *kmpi_sock;         /* kernel netlink socket mpi */
static ah_kmpi_tbl_t kmpi_tbl[AH_KMOD_ID_MAX]; /* less than 100 byte, so don't trouble to malloc */

static DEFINE_MUTEX(kmpi_mutex);
static inline void kmpi_lock(void)
{
	mutex_lock(&kmpi_mutex);
}

static inline void kmpi_unlock(void)
{
	mutex_unlock(&kmpi_mutex);
}


static int kmpi_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	uint16_t kid;
	uint16_t flags;
	int rc;


	/*
	 * validate msg
	 */
	if ( skb->len < MPI_HDR_SPACE ||         /* skb buf must bigger than mpi hdr */
		 nlh->nlmsg_len < MPI_HDR_SPACE ||   /* nlh len must bigger than mpi hdr */
		 skb->len < nlh->nlmsg_len ||        /* skb len must bigger than nlh len */
		 !is_valid_mpi_nlh (nlh) ) {         /* must have the magic signature */

		mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg, fail sanity check!\n");
		return -EINVAL;
	}

	flags = nlh->nlmsg_flags;

	if ( !(flags & NLM_F_REQUEST) ||  /* only support nlmsg request */
		 flags & NLM_F_MULTI ||       /* don't support multi part msg */
		 flags & MSG_TRUNC ) {        /* don't support truncated msg */

		mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg, invalid flag 0x%04x\n", flags);
		return -EINVAL;
	}

	if (nlh->nlmsg_type == MPI_MSG_T_UCAST_K2K) {
		kid  = MPI_PID2MID (nlh->nlmsg_pid);
	} else {
		kid = MPI_PID2MID (MPI_NLH2COOKIE (nlh));
	}

	if (!is_kid_valid(kid)) {
		mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg: unknow kid %d!\n", kid);
		return -ENODEV;
	}

	/*
	 * security check
	 */
	if (nlh->nlmsg_type != MPI_MSG_T_UCAST_K2K && security_netlink_recv(skb, CAP_NET_ADMIN)) {
		mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg, fail security check\n");
		return -EPERM;
	}

	mpi_dbgk (KDBG_MPI_BASIC, "kmpi recv: mpi_port(%d) -> (%s) %d bytes\n",
			  nlh->nlmsg_pid, kid2name(kid), nlh->nlmsg_len);

	/*
	 * validate kmpi state
	 */
	if ( ! kmpi_tbl[kid].kt_rcv ) {
		mpi_dbgk (KDBG_MPI_BASIC, "mpi msg drop for kmod(%s): no open channel\n",
				  kid2name(kid));
		return -ENOENT;
	}

	rc =  kmpi_tbl[kid].kt_rcv (MPI_NLH2DAT(nlh),                /* data buf ptr */
								nlh->nlmsg_len - MPI_HDR_SPACE,  /* data buf len */
								nlh->nlmsg_pid);                 /* src mpi_port */

	/*
	 * we don't use the callback return code yet, might use it in future
	 */
	mpi_dbgk (KDBG_MPI_BASIC, "kmod(%s) recv mpi msg done, return code %d\n",
			  kid2name(kid), rc);

	return 0;

}

static void kmpi_rcv(struct sk_buff *skb)
{
	kmpi_lock();
	netlink_rcv_skb(skb, &kmpi_rcv_msg);
	kmpi_unlock();
}


/*
 * handle linux kernel net-device event notify
 * NOTE: this routine will relay the supported kernel dev event to
 *       userspace's ah_kevent. If any kernel module want to handle the
 *       linux dev event, it should use the existing mechanism in linux kernel.
 */
static int kevent_if_chg_handler (struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;
	ah_kevent_if_change_t msg;

	/*
	 * only handle certain dev with ah_dev attached
	 */
	if (!dev || !dev2ahdev(dev) ||
		!(AH_SYS_DEV_IS_AP(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_PORTAL(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_BACKHAUL(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_ETH_ACCESS(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_ETH_BRIDGE(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_TUNNEL(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_MGT(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_SUB_INTERFACE(dev2ahdev(dev)) ||
		  AH_SYS_DEV_IS_WAN(dev2ahdev(dev)))) {
		mpi_logk (AH_LOG_INFO, "ignore event 0x%x from %s\n",
				  event, dev2name(dev));
		return NOTIFY_DONE;
	}

	msg.kic_ifindex = dev->ifindex;
	strlcpy(msg.kic_ifname, dev->name, IFNAMSIZ);

	msg.kic_flag = 0;
	if (AH_SYS_DEV_IS_WIRELESS(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_WIRELESS;
	}
	if (AH_SYS_DEV_IS_BACKHAUL(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_BACKHAUL;
	}
	if (AH_SYS_DEV_IS_ETH_BRIDGE(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_BRIDGE;
	}
	if (!AH_SYS_DEV_IS_PHYSICAL(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_VIRTUAL;
	}
	if (AH_SYS_DEV_IS_MGT(dev2ahdev(dev)) || AH_SYS_DEV_IS_SUB_INTERFACE(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_MGT;
	}
	if (AH_SYS_DEV_IS_PORTAL(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_PORTAL;
	}
	if (AH_SYS_DEV_IS_WAN(dev2ahdev(dev))) {
		msg.kic_flag |= AH_DEV_TYPE_WAN;
	}
	/*
	 * convert the kernel event type to ah_kevent_t
	 */
	switch (event) {

	case NETDEV_UP:

		/* event admin UP, if no carrier, don't trigger ah-kevent-up */
		if (netif_carrier_ok(dev))  {
			msg.kic_type = AH_KEVENT_IF_UP;
			break;
		}

		mpi_logk (AH_LOG_INFO, "ignore NETDEV_UP event, %s no carrier!\n", dev2name(dev));
		return NOTIFY_DONE;

	case NETDEV_DOWN:

		msg.kic_type = AH_KEVENT_IF_DOWN;
		break;

	case NETDEV_CHANGE: /* Notify device flag change */

		/* we only check the carrier bit, to trigger if up/down kevent */
		msg.kic_type =  (!netif_carrier_ok(dev)) ?  AH_KEVENT_IF_DOWN :
						(dev->flags & IFF_UP) ?     AH_KEVENT_IF_UP :
						AH_KEVENT_IF_INVALID;

		if (msg.kic_type == AH_KEVENT_IF_INVALID) {
			mpi_logk (AH_LOG_INFO, "ignore NETDEV_CHANGE event from %s\n", dev2name(dev));
			return NOTIFY_DONE;
		}

		break;


	case NETDEV_REBOOT: /* Tell a protocol stack a network interface detected a hardware crash and restarted */

		msg.kic_type = AH_KEVENT_IF_REBOOT;
		break;

	case NETDEV_CHANGEMTU:
		msg.kic_type = AH_KEVENT_IF_CHANGEMTU;
		msg.kic_mtu  = dev->mtu;
		break;

	case NETDEV_CHANGEADDR:
		msg.kic_type = AH_KEVENT_IF_CHANGEMAC;
		memcpy (msg.kic_mac, dev->dev_addr, 6);
		break;

	case NETDEV_GOING_DOWN:
		msg.kic_type = AH_KEVENT_IF_GOING_DOWN;
		break;

	case NETDEV_CHANGENAME:
		msg.kic_type = AH_KEVENT_IF_CHANGENAME;
		break;

	/* not support following event yet */
	case NETDEV_REGISTER:
	case NETDEV_UNREGISTER:
	default:
		mpi_logk (AH_LOG_INFO, "drop unsupported event 0x%x from %s\n",
				  event, dev2name(dev));
		return NOTIFY_DONE;
	}

	ah_kevent_send (AH_KEVENT_IF_CHANGE, (void *)&msg, sizeof(msg));

	mpi_logk (AH_LOG_INFO, "%s notify kevent %s, type %s(%d)\n",
			  dev2name(dev), eid2name(AH_KEVENT_IF_CHANGE),
			  kevent_if_chg2name(msg.kic_type), msg.kic_type);

	return NOTIFY_DONE;
}


/*
 * malloc the kmpi skb
 * reture the data start ptr.
 */
char *ah_kmpi_malloc (size_t len)
{
	struct sk_buff *skb;
	size_t size;
	struct nlmsghdr *nlh;

	size = MPI_MSG_SPACE(len);

	/* allocate socket buffer */
	if (!(skb = alloc_skb(size, GFP_ATOMIC))) {
		mpi_logk (AH_LOG_WARNING, "kmpi malloc %d bytes failed\n", size);
		return NULL;
	}

	nlh = (struct nlmsghdr *) skb_put (skb, MPI_HDR_SPACE);

	set_mpi_nhl_valid  (nlh);
	set_mpi_nhl_cookie (nlh, skb);

	return MPI_NLH2DAT(nlh);
}
/*
 * send kmpi msg to a user space thread
 * NOTE: after send msg, caller
 *       can not use the <buf> anymore. a new buffer
 *       must be allocated again for another msg.
 * <mh>:  kmpi handler got by kmpi_open(...)
 * <buf>: buffer ptr got by kmpi_malloc(...)
 * <len>: length to be Tx.
 * <mid>: dst user process module ID
 * <sid>: dst user process sub-module ID
 * return -1 on error, 0 if ok.
 */

extern int kernel_trace_dump;

int ah_kmpi_send (int mh, int msg_type, char *buf, int len, uint32_t mpi_port)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int rc;
	static long tx_fail_counter = 0;

	/*
	 * chg to if (...) prevent kernel crash
	 */
	ah_kassert (kmpi_sock);
	ah_kassert (buf);
	ah_kassert (is_valid_mpi_data(buf));
	ah_kassert (is_kid_valid(kmpi_tbl[mh].kt_kid)); /* must have open the channel */
	ah_kassert (kmpi_tbl[mh].kt_rcv);               /* must have set the recv_func */


	mpi_dbgk (KDBG_MPI_INFO, "kmpi send: (%s) -> mpi_port(0x%x) %d bytes\n",
			  kid2name(kmpi_tbl[mh].kt_kid), mpi_port, len);

	/*
	 * !NOTE: nobody should get skb from cookie anymore beyond this point.
	 */
	skb = (struct sk_buff *) MPI_DAT2COOKIE(buf);
	ah_kassert (skb);
	skb_put (skb, len);    /* mpi hdr already being skb_put when malloc */

	nlh = MPI_DAT2NLH (buf);
	nlh->nlmsg_len   = MPI_HDR_SPACE + len;
	nlh->nlmsg_type  = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid   = MPI_MOD2PID (kmpi_tbl[mh].kt_kid, 0); /* src_pid, kernel module don't have sub-kmod-id yet */

	/*
	 * the <skb> has been passed to netlink sock, will be freed there!
	 */
	if ((rc = netlink_unicast (kmpi_sock, skb, mpi_port, MSG_DONTWAIT)) < 0) {
		/* Log once for every 10 failure */
		if (!(tx_fail_counter % 1000) && !kernel_trace_dump) {
			mpi_logk( AH_LOG_INFO, "kmpi failed netlink_unicast, counter %d: code(%d)\n", tx_fail_counter, rc);
		}
		tx_fail_counter++;
	}

	return rc;
}

/*
 * common callback function to dequeue the packets from the netlink socket
 * Note this function is called in the context of the sendto() system call.
 * if the procedure is short and fast, it's ok. Otherwise  we need to use a
 * dedicated kernel thread to perform the following steps indefinitely
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static void ah_kmpi_recv_skb (struct sock *sk, int len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	uint16_t kid;
	uint16_t flags;
	int rc;

	while ((skb = skb_dequeue(&sk->sk_receive_queue))) {
		nlh = (struct nlmsghdr *)skb->data;

		/*
		 * validate msg
		 */
		if ( skb->len < MPI_HDR_SPACE ||         /* skb buf must bigger than mpi hdr */
			 nlh->nlmsg_len < MPI_HDR_SPACE ||   /* nlh len must bigger than mpi hdr */
			 skb->len < nlh->nlmsg_len ||        /* skb len must bigger than nlh len */
			 !is_valid_mpi_nlh (nlh) ) {         /* must have the magic signature */

			mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg, fail sanity check!\n");
			goto next;
		}

		flags = nlh->nlmsg_flags;

		if ( !(flags & NLM_F_REQUEST) ||  /* only support nlmsg request */
			 flags & NLM_F_MULTI ||       /* don't support multi part msg */
			 flags & MSG_TRUNC ) {        /* don't support truncated msg */

			mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg, invalid flag 0x%04x\n", flags);
			if (flags & NLM_F_ACK) {
				netlink_ack(skb, nlh, -EFAULT);
			}
			goto next;
		}

		if (nlh->nlmsg_type == MPI_MSG_T_UCAST_K2K) {
			kid  = MPI_PID2MID (nlh->nlmsg_pid);
		} else {
			kid = MPI_PID2MID (MPI_NLH2COOKIE (nlh));
		}

		if (!is_kid_valid(kid)) {
			mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg: unknow kid %d!\n", kid);
			if (flags & NLM_F_ACK) {
				netlink_ack(skb, nlh, -ENODEV);
			}
			goto next;
		}

		/*
		 * security check
		 */
		if (nlh->nlmsg_type != MPI_MSG_T_UCAST_K2K && security_netlink_recv(skb)) {
			mpi_dbgk (KDBG_MPI_BASIC, "drop kmpi recv msg, fail security check\n");
			if (flags & NLM_F_ACK) {
				netlink_ack(skb, nlh, -EPERM);
			}
			goto next;
		}

		mpi_dbgk (KDBG_MPI_BASIC, "kmpi recv: mpi_port(%d) -> (%s) %d bytes\n",
				  nlh->nlmsg_pid, kid2name(kid), nlh->nlmsg_len);

		/*
		 * validate kmpi state
		 */
		if ( ! kmpi_tbl[kid].kt_rcv ) {
			mpi_dbgk (KDBG_MPI_BASIC, "mpi msg drop for kmod(%s): no open channel\n",
					  kid2name(kid));
			if (flags & NLM_F_ACK) {
				netlink_ack(skb, nlh, -ENOENT);
			}
			goto next;
		}

		rc =  kmpi_tbl[kid].kt_rcv (MPI_NLH2DAT(nlh),                /* data buf ptr */
									nlh->nlmsg_len - MPI_HDR_SPACE,  /* data buf len */
									nlh->nlmsg_pid);                 /* src mpi_port */

		/*
		 * we don't use the callback return code yet, might use it in future
		 */
		mpi_dbgk (KDBG_MPI_BASIC, "kmod(%s) recv mpi msg done, return code %d\n",
				  kid2name(kid), rc);

		/*
		 * sending ack back if required so, not supported yet
		 */
		if (flags & NLM_F_ACK) {
			netlink_ack(skb, nlh, 0);
		}

next:
		kfree_skb(skb);
	}
}
#endif
/*
 * handle netlink socket notifier
 */
static int ah_kmpi_notifier_call (struct notifier_block *this, unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;

	/*
	 * we do nothing if user close a socket, just log it
	 */
	if (n->protocol == NETLINK_AHIPC)
		mpi_logk( AH_LOG_INFO, "socket is %s, pid(%d), protocol(%d)\n",
				  event == NETLINK_URELEASE ? "closed" : "unknown",
				  n->pid,
				  n->protocol);

	return NOTIFY_DONE;
}
static struct notifier_block ah_kmpi_notifier = {
	.notifier_call  = ah_kmpi_notifier_call,
};
/*
 * open a kmpi channel, so that other kmod can use it to send/recv msg
 * when a msg arrive, the <recv_func> will be called by passing the <buf>/<len>
 * <kid>: the calling kernel module ID
 * <recv_func>: the msg recv call back routine
 * NOTE: if <recv_func> should be simple and quick, otherwise, need chg mpi to use kernel thread.
 *       also, if <recv_func> need hold the msg, must memcpy to it's own buf, the original msg
 *       will be freed after <recv_func> return.
 *
 * return -1 on error, <mh> on success.
 */
int ah_kmpi_open (uint16_t kid, int (*recv_func)(char *buf, int len, uint32_t mpi_port))
{
	if ( !is_kid_valid(kid) ) {
		ah_kassert (is_kid_valid(kid));
		mpi_logk( AH_LOG_CRIT, "in valid kmod ID %u\n", kid);
		return -1;
	}
	if (!recv_func) {
		mpi_logk( AH_LOG_CRIT, "NULL callback func for %s\n", kid2name(kid));
		return -1;
	}

	kmpi_tbl[kid].kt_kid = kid;
	kmpi_tbl[kid].kt_grp = 0x0; /* no mcast support yet [Fri 01 Dec 2006 04:55:37 PM PST] */
	kmpi_tbl[kid].kt_seq = 0x0;
	kmpi_tbl[kid].kt_rcv = recv_func;

	mpi_logk (AH_LOG_INFO, "kmod(%s) open mpi channel\n", kid2name(kid));

	return kid;
}
/*
 * close the ipc handle
 */
void ah_kmpi_close (int mh)
{
	if (mh < AH_KMOD_ID_MAX) {

		mpi_logk (AH_LOG_INFO, "kmod(%s) close mpi channel\n", kid2name(kmpi_tbl[mh].kt_kid));

		kmpi_tbl[mh].kt_kid = AH_KMOD_ID_INVALID;
		kmpi_tbl[mh].kt_grp = 0x0;
		kmpi_tbl[mh].kt_seq = 0x0;
		kmpi_tbl[mh].kt_rcv = NULL;
	}
}

static struct notifier_block kevent_if_chg_notifier = {
	.notifier_call = kevent_if_chg_handler
};

#if defined(AH_SUPPORT_IPV6)

static int ah_ipv6_addrconf_notifier_func (struct notifier_block *unused, unsigned long event,
		void *ptr)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)ptr;
	struct net_device *dev = NULL;
	struct inet6_dev *in6_dev = NULL;
	ah_kevent_if_change_t msg;


	in6_dev = ifa->idev;
	if (unlikely(in6_dev == NULL)) {
		goto out;
	}

	dev = in6_dev->dev;
	if (unlikely(dev == NULL)) {
		goto out;
	}

	memset(&msg, 0, sizeof(msg));

	msg.kic_ifindex = dev->ifindex;
	strlcpy(msg.kic_ifname, dev->name, IFNAMSIZ);

	msg.kic_flag = 0;

	ipv6_addr_copy(&msg.kic_ipv6_addr.ipv6_addr, &ifa->addr);
	msg.kic_ipv6_addr.pfxlen = ifa->prefix_len;
	msg.kic_ipv6_addr.flags = ifa->flags;

	if (event == NETDEV_UP) {
		msg.kic_type = AH_KEVENT_IF_IPV6_ADDR_ADD;
	} else if (event == NETDEV_DOWN) {
		msg.kic_type = AH_KEVENT_IF_IPV6_ADDR_DEL;
	} else {
		/* no other event for now, just ignore */
		goto out;
	}

	ah_kevent_send (AH_KEVENT_IF_CHANGE, (void *)&msg, sizeof(msg));

out:
	return NOTIFY_DONE;
}

/*
 * Register to register_inet6addr_notifier()
 */
static struct notifier_block ah_ipv6_addrconf_notifier = {
	.notifier_call = ah_ipv6_addrconf_notifier_func
};
#endif  /* #if defined(AH_SUPPORT_IPV6) */

/*
 * module init function
 * always use __init or __initdata to free the initilization code/data
 * because it will never get used again after initialization
 * This is to avoid wasting precious physical kernel memory
 */
static int __init lkm_mpi_init(void)
{
	int rc, i;

	mpi_dbgk (KDBG_MPI_INFO, "KMPI module init\n");

	/*
	 * open the kernel netlink socket
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))
	if ( !(kmpi_sock = netlink_kernel_create(NETLINK_AHIPC, RTNLGRP_NONE, ah_kmpi_recv_skb, THIS_MODULE)) ) {
		mpi_logk( AH_LOG_CRIT, "failed open kmpi socket\n");
		rc = -1;
		goto done;
	}
#else
	if ( !(kmpi_sock = netlink_kernel_create(&init_net, NETLINK_AHIPC, RTNLGRP_NONE, kmpi_rcv, NULL, THIS_MODULE)) ) {
		mpi_logk( AH_LOG_CRIT, "failed open kmpi socket\n");
		rc = -1;
		goto done;
	}
#endif

	netlink_register_notifier(&ah_kmpi_notifier);

	for (i = AH_KMOD_ID_MIN; i < AH_KMOD_ID_MAX; i++) {
		kmpi_tbl[i].kt_kid = AH_KMOD_ID_INVALID;
	}

	/*
	 * kevent init
	 */
	if ( (rc = ah_kevent_init()) < 0 ) {
		mpi_logk( AH_LOG_ERR, "kevent failed to init !\n");
		goto done;
	}

	rc = register_netdevice_notifier (&kevent_if_chg_notifier);

#if defined(AH_SUPPORT_IPV6)
	rc = register_inet6addr_notifier(&ah_ipv6_addrconf_notifier);
#endif


done:
	return rc;
}
/*
 * module exit function
 * always use __exit or __exitdata to exit code/data
 * although __exit has no effect for loadable modules.
 * However, in case the module is built into the kernel
 * it will cause the omission of the function because the
 * build-in function does not need a clean up function
 */
static void __exit lkm_mpi_exit(void)
{
	mpi_dbgk(KDBG_MPI_INFO, "kmpi exit!\n");

	if (kmpi_sock) {
		sock_release(kmpi_sock->sk_socket);
		netlink_unregister_notifier(&ah_kmpi_notifier);
		kmpi_sock = NULL;
	}

	/*
	 * clean up kevent
	 */
	ah_kevent_exit();
}
/*
 * use the following macros (the new mathod) instead of using hardcoded functions:
 * int init_module(void) and void cleanup_module(void) defined in linux/init.h
 * init_module() and cleanup_module() are called by insmod and rmmod commands respectively
 */
module_init(lkm_mpi_init);
module_exit(lkm_mpi_exit);

EXPORT_SYMBOL(ah_kmpi_open);
EXPORT_SYMBOL(ah_kmpi_close);
EXPORT_SYMBOL(ah_kmpi_malloc);
EXPORT_SYMBOL(ah_kmpi_send);

