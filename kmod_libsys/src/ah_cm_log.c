/*********************************************************
 * AEROHIVE CONFIDENTIAL
 *
 * Copyright [2006] - [2011] Aerohive Networks, Inc.
 * All Rights Reserved.
 *
 * NOTICE: All information herein is and remains the property
 * of Aerohive Networks, Inc. and its suppliers, if any.
 *
 * The intellectual and technical concepts contained herein
 * are proprietary to Aerohive Networks, Inc. and its
 * suppliers and may be covered by U.S. and foreign patents
 * and/or pending patent applications, and are protected by
 * trade secret and copyright law.
 *
 * Disclosure, dissemination or reproduction of this
 * information or the intellectual or technical concepts
 * expressed by this information is prohibited unless prior
 * written permission is obtained from Aerohive Networks, Inc.
 **********************************************************/

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/spinlock.h>
#endif

#include "ah_types.h"

#ifdef __KERNEL__
#include "ah_ssysapi.h"
#include "ah_ksyscall.h"
#include "ah_kdbg.h"
#include "ah_kassert.h"
#include "ah_ksys_dev.h"
#endif

/* #include "ah_sys_ioctl.h" */

#include "ah_itk.h"
#include "ah_cm_api.h"

#ifdef __KERNEL__
#include "ah_itk_kernel.h"
#include "ah_cm_kernel_sess.h"
#else
#include "ah_itk_user.h"
#endif


int ah_cm_exception_report(
	uint              if_idx,
	const uchar *addr,
	ah_cm_mod_t       module,
	ah_mac_t         *bssid,
	int               current_step,
	boolean         trigger,
	boolean         success,
	int               problem_id)
{
	char *buf = NULL, *pos = NULL;
	int        len = 0;
	ct_event_t *event = NULL;
	ah_cm_exception_msg_t  *prob_msg = NULL;
	int      rc;

	/* no need to report */
	/* return 0; */

	buf = AH_ITK_MALLOC(sizeof(ct_event_t) + 1 + sizeof(ah_cm_exception_msg_t) + 1);
	if (NULL == buf) {
		AH_CM_LOG_ERR("%s: ah_malloc() retun NULL!\n", __func__);
		return -1;
	}

	pos = buf;

	/* fill in the event header */
	event = (ct_event_t *)pos;
	event->cte_type = AH_ITK_TYPE_CM_PROBLEM;
	event->cte_len = 0; /* set later */
	pos += sizeof(ct_event_t);

	/* set flag to indicate if need to check problem rule in capwap */
	*pos = 1;  /* 0 if don't need to check, 1 if need to check */
	pos += 1;

	/*

	ah_ct_convert_report_net(report_net);
	ah_ct_dump_report(report);

	*/
	/* fill in exception data fields */
	prob_msg = (ah_cm_exception_msg_t *)pos;
	prob_msg->if_idx = if_idx;
	AH_MACADDR_COPY(&prob_msg->addr, addr);
	AH_MACADDR_COPY(&prob_msg->bssid, bssid);
	prob_msg->module       = module;
	prob_msg->current_step = current_step;
	prob_msg->trigger      = trigger;
	prob_msg->success      = success;
	prob_msg->problem_id   = problem_id;
	pos += sizeof(ah_cm_exception_msg_t);

	len = pos - buf;
	event->cte_len = len - sizeof(ct_event_t);

	rc = AH_ITK_EVENT_SEND(len, buf);
	if (0 != rc) {
		AH_ITK_ERR("%s: ah_event_send(AH_EVENT_ITK_NOTIFY) failed(rc=%d)\n",
				   __func__, rc);
	}
	AH_ITK_FREE(buf);

	return 0;
}

#ifdef __KERNEL__

EXPORT_SYMBOL(ah_cm_exception_report);

#endif

