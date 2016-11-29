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
/***************************************************************************/
/* Aerohive kernel event implementation.                                   */
/* This file implement the event notification table in kernel within MPI   */
/* module, and leverage the MPI unicast capability to deliver the kernel   */
/* event to any registered applications                                    */
/* Author: Yong Kang                                                       */
/* Date: [Wed 15 Nov 2006 03:54:27 PM PST]                                 */
/***************************************************************************/
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#include <linux/config.h>
#include <linux/devfs_fs_kernel.h>
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#include <linux/ah_kernel.h>
#include "ah_ssysapi.h"
#include "ah_ksyscall.h"
#include "ah_device.h"
#include "ah_kmpi_internal.h"
#include "ah_smpi.h"
#include "ah_kmpi.h"
#include "ah_kevent.h"
#include "ah_kassert.h"
#include "ah_kdbg.h"

#include "ah_itk.h"
#include "ah_trap.h"
#include "ah_types.h"
#include "ah_log_id.h"
/* kevent subscriber list */
typedef uint32_t ah_kevent_rcvr_map_t;

static int kevt_mh = -1;

/*
 * each kevent-ID maitain a bitmask about
 * which module has subscribed to this kevent,
 * NOTE:  if max module number > 32, expand the bitmask
 */
/* expand bitmap word numer because we have more than 64 module */
static ah_kevent_rcvr_map_t kevt_subscriber[AH_KEVENT_MAX][AH_MODULE_ID_BITMAP_SIZE];
#define kevt_subscriber_clear(eid)    \
	do {                                  \
		int i;         \
		for (i = 0; i < AH_MODULE_ID_BITMAP_SIZE; i++) { \
			kevt_subscriber[(eid)][i] = 0x0;   \
		} \
	} while(0)

#define kevt_subscriber_set(eid,mid)    \
	do {                                  \
		kevt_subscriber[(eid)][(mid)/AH_TOTAL_BITS_IN_WORD] |= ((ah_kevent_rcvr_map_t)1)<<((mid)%AH_TOTAL_BITS_IN_WORD);   \
	} while(0)

#define kevt_subscriber_unset(eid,mid)    \
	do {                                  \
		kevt_subscriber[(eid)][(mid)/AH_TOTAL_BITS_IN_WORD] &=  ~(((ah_kevent_rcvr_map_t)1)<<((mid)%AH_TOTAL_BITS_IN_WORD));   \
	} while(0)

/*
 * <mid> is the subscriber module-ID
 */
#define FOREACH_SUBSCRIBER_IN_KEVENT(mid,eid) \
	for ( (mid)=AH_MOD_ID_MIN; is_mid_valid(mid); (mid)++ ) \
		if (kevt_subscriber[(eid)][(mid)/AH_TOTAL_BITS_IN_WORD] & (((ah_kevent_rcvr_map_t)1)<<((mid)%AH_TOTAL_BITS_IN_WORD)))


/*
 * init bitmask table,
 * return 0 if ok, -1 on error
 */
static int kevt_subscriber_init (void)
{
	int i;

	/*
	 * clear the event subscriber bitmask
	 */
	for (i = 0; i < AH_KEVENT_MAX; i++) {
		kevt_subscriber_clear(i);
	}

	return 0;
}
/*
 * send kevent <eid>, with <data>/<size> as the carried msg
 * NOTE: caller alloc/free <data>
 * return 0 if ok, -1 on error
 */
int ah_kevent_send (ah_kevent_t eid, void *data, uint16_t data_size)
{
	int rc = 0;
	int total_rc = 0;
	uint32_t mpi_port;
	ah_event_msg_t *msg_hdr;
	uint16_t msg_size;
	uint16_t mid;

	ah_kassert (data_size < AH_EVENT_MAX_LEN);

	/*
	 * sanity check
	 */
	if (!is_kevent_valid(eid) || kevt_mh < 0) {
		ah_kassert (is_kevent_valid(eid));
		ah_kassert (kevt_mh >= 0);
		mpi_logk (AH_LOG_ERR, "drop illegal kevent: %s(%d) %d bytes!\n",
				  eid2name(eid), eid, data_size);
		return -1;
	}

	/*
	 * add hdr space
	 */
	msg_size = data_size + sizeof(ah_event_msg_t);
	/*
	 * send to each subscriber
	 */
	FOREACH_SUBSCRIBER_IN_KEVENT (mid, eid) {

		/*
		 * have to mpi_malloc buf for each subscriber, cause kmpi is using unicast
		 * mechanism. (mcast won't save much as well)
		 */
		if (!(msg_hdr = (ah_event_msg_t *)ah_kmpi_malloc (msg_size))) {

			/* if malloc fail, don't bother try next subscriber, log err and return */
			mpi_logk (AH_LOG_ERR, "kevent %s(%d) fail alloc msg buffer %d bytes\n",
					  kid2name((ah_kmod_id_t)eid), eid, msg_size); /* cast to enum, avoid compiler warning */
			return -1;
		}

		/*
		 * send msg to this subscriber
		 */
		msg_hdr->em_eid = eid;
		msg_hdr->em_len = data_size;                 /* attached data length */
		msg_hdr->em_flag |= AH_EVT_FLAG_FROM_KERNEL; /* mark this evt from kernel */
		memcpy (msg_hdr->em_data, data, data_size);
		if (eid < AH_KEVENT_LOW_PRIO_MIN) {
			mpi_port = MPI_MOD2PID(mid, AH_SUB_MOD_ID_LOWEST_EVENT);
		} else if (eid < AH_KEVENT_HIGH_PRIO_MIN) {
			mpi_port = MPI_MOD2PID(mid, AH_SUB_MOD_ID_EVENT);
		} else {
			mpi_port = MPI_MOD2PID(mid, AH_SUB_MOD_ID_HI_EVENT);
		}
		rc = ah_kmpi_k2u_send (kevt_mh, (char *)msg_hdr, msg_size, mpi_port);

		mpi_dbgk (KDBG_MPI_INFO, "send %d bytes kevent %s(%d) to module %s(%d) %s\n",
				  data_size, eid2name(eid), eid, mid2name(mid), mid, (rc < 0) ? "FAIL" : "OK");

		if (rc < 0) {
			total_rc = -1;
		}
	}

	return total_rc;
}
/*
 * we use ioctl to set info from user, not use mpi to recv anything yet
 */
static int ah_kevent_recv (char *buf, int len, uint32_t mpi_port)
{
	mpi_logk (AH_LOG_INFO, "!warning: kevent drop %d bytes from mpi_port(%u)\n",
			  len, mpi_port);
	return 0;
}



/******************************
 * kevent char device vectors *
 ******************************/
static loff_t ah_kevt_llseek (struct file *file, loff_t offset, int origin)
{
	printk(KERN_INFO "[%s:%d] %s no-op!\n", __FILE__, __LINE__, __FUNCTION__);
	return -ESPIPE;
}

static ssize_t ah_kevt_read (struct file *file, char __user *buf, size_t count,
							 loff_t *offset)
{
	/* nothing to do */
	printk(KERN_INFO "[%s:%d] %s no-op!\n", __FILE__, __LINE__, __FUNCTION__);
	return 0;
}

static ssize_t ah_kevt_write (struct file *file, const char __user *buf, size_t count,
							  loff_t *offset)
{
	/* nothing to do */
	printk(KERN_INFO "[%s:%d] %s no-op!\n", __FILE__, __LINE__, __FUNCTION__);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
long ah_kevt_ioctl (struct file *file, unsigned int cmd,
					unsigned long arg)
#else
int ah_kevt_ioctl (struct inode *inode, struct file *file, unsigned int cmd,
				   unsigned long arg)
#endif

{
	ah_event_msg_t msg; /* we share the same structure when sending the kevent */

	/*
	 * get message header
	 */
	if (copy_from_user(&msg, (void *)arg, sizeof(msg))) {
		mpi_logk (AH_LOG_ERR, "fail copy from user @ 0x%08x %d bytes\n", arg, sizeof(msg));
		return -EFAULT;
	}

	/*
	 *  borrow <msg->em_len> to be the subscriber module-ID
	 */
	if ( !is_kevent_valid(msg.em_eid) || !is_mid_valid(msg.em_len) ) {
		mpi_logk (AH_LOG_ERR, "drop illegal kevent %s(%d) by subscriber %s(%d)\n",
				  eid2name(msg.em_eid), msg.em_eid, mid2name(msg.em_len), msg.em_len);
		return -EINVAL;
	}

	switch ( cmd ) {
	case AH_KEVT_SUBSCRIBE:
		kevt_subscriber_set (msg.em_eid, msg.em_len);
		break;

	case AH_KEVT_UNSUBSCRIBE:
		kevt_subscriber_unset (msg.em_eid, msg.em_len);

		break;

	case AH_ITK_IOCTL_LOG:
		{
			ah_mac_t mac;
			ah_mac_t bssid;
			memset(&mac, 0x11, sizeof(mac));
			memset(&bssid, 0x33, sizeof(bssid));
			ct_terminate(AH_CT_MOD_80211, &mac, &bssid,
						 FALSE, "kernel call for %m", &mac);

			/*test code for pci alert*/
			{
				ah_itk_pci_alert_info  itk_alert;
				int      test_id = 5;
				char      node_id[MACADDR_LEN] = {AH_OUI_0, AH_OUI_1, AH_OUI_2,  0x0e, 0x52, 0x80};
				memset(&itk_alert, 0, sizeof(ah_itk_pci_alert_info));

				memcpy(itk_alert.node_id, node_id, MACADDR_LEN);
				itk_alert.alert_type = AH_ITK_PCI_UDP_FLOOD; /*9*/
				itk_alert.violation_counter = 101;
				itk_alert.src_ip = 177935466; /*10.155.20.106*/
				itk_alert.dst_ip = 177935467;/*10.155.20.107*/
				memcpy(itk_alert.dst_mac, node_id, MACADDR_LEN);
				if (TRUE == ah_pci_alert_enable()) {
					ah_itk_pci_alert(&itk_alert, "this is test %d for kernel.", test_id);
				}
			}
		}
		//mpi_logk(AH_LOG_ERR, "Receive IOCTL(AH_ITK_IOCTL_LOG)\n");
		break;

	default:
		mpi_logk (AH_LOG_ERR, "unsupported kevent cmd %d\n", cmd);
		return -EINVAL;
	}

#if 0
	/* following debug too noisy */
	mpi_logk (AH_LOG_INFO,
			  "module(%s) %ssubscribed to kevent (%s)\n",
			  mid2name(msg.em_len), (cmd == AH_KEVT_SUBSCRIBE) ? "" : "un", eid2name(msg.em_eid));
#endif
	return 0;
}

static int ah_kevt_open (struct inode *inode, struct file *file)
{
	/* nothing to do */
	return 0;
}

static int ah_kevt_release (struct inode *inode, struct file *file)
{
	/* nothing to do */
	return 0;
}

static struct file_operations ah_kevt_fops = {
	.owner      = THIS_MODULE,
	.llseek     = ah_kevt_llseek,
	.read       = ah_kevt_read,
	.write      = ah_kevt_write,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	.unlocked_ioctl     = ah_kevt_ioctl,
#else
	.ioctl      = ah_kevt_ioctl,
#endif
	.open       = ah_kevt_open,
	.release    = ah_kevt_release,
};
int __init ah_kevent_init(void)
{
	int rc;

	rc = kevt_subscriber_init ();
	if (rc < 0) {
		goto out;
	}

	kevt_mh = ah_kmpi_open (AH_KMOD_ID_KEVT, ah_kevent_recv);
	if (kevt_mh < 0) {
		goto out;
	}


	rc = register_chrdev (AH_MPI_DEV_MAJOR, AH_KEVENT_DEV_NAME, &ah_kevt_fops);
	if (rc < 0) {
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	rc = devfs_mk_dir(AH_KEVENT_DEV_NAME);
	if (rc < 0) {
		goto out;
	}
#endif

	ah_kevent_send_ptr = &ah_kevent_send;

out:
	if (rc < 0) {
		mpi_logk (AH_LOG_ERR, "Fail init kernel event!\n");
	}
	return rc;
}

void __exit ah_kevent_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	devfs_remove(AH_KEVENT_DEV_NAME);
#endif
	unregister_chrdev(AH_MPI_DEV_MAJOR, AH_KEVENT_DEV_NAME);
	ah_kmpi_close (kevt_mh);
	kevt_mh = -1;
	mpi_logk (AH_LOG_INFO, "remove device %s\n", AH_KEVENT_DEV_NAME);
}

EXPORT_SYMBOL(ah_kevent_send);

int ah_ktrap_send(ah_sys_kmod_t mod, uint trap_level, ah_trap_info_t *trap_info, const char *fmt, ...)
{
	va_list args;
	int len = 0;

	if (mod < 0 || mod >= AH_MAX_SYS_KMODS) {
		return 0;
	}
	if (!ah_kmod_ctl[mod].logenable || (trap_level & AH_LOG_LEVEL_MASK) > ah_kmod_ctl[mod].loglevel) {
		return 0;
	}

	trap_info->level = trap_level;
	(void)ah_sprintk(trap_info->desc, "[%s]: ", ah_kmod_ctl[mod].name);
	len = strlen(trap_info->desc);

	va_start(args, fmt);
	ah_vsnprintk(trap_info->desc + len, sizeof(trap_info->desc) - len, fmt, args);
	va_end(args);

	return ah_kevent_send(AH_KEVENT_TRAP, trap_info, sizeof(ah_trap_info_t));

}
EXPORT_SYMBOL(ah_ktrap_send);
