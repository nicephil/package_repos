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

#ifdef __KERNEL__
#include "ah_itk_kernel.h"
#else
#include "ah_itk_user.h"
#endif

int pci_alert_report(ah_itk_pci_alert_info *pci_alert, const char *fmt, ...)
{
	char *para = NULL;
	uint32_t    len = 0;
	int      obj_len = 0;
	va_list args;
	int      rc = 0;

	if ((NULL == pci_alert) || (NULL == fmt)) {
		AH_ITK_ERR("pci_alert(fmt=%s): Invalid paramters!\n", (fmt ? fmt : "NULL"));
		return -1;
	}

	para = AH_ITK_MALLOC(AH_CT_MAX_REPORT_BUF);
	if (!para) {
		AH_ITK_ERR("pci_alert(): ah_malloc(para) retun NULL!\n");
		return -1;
	}

	/*
	 * 2 bytes: itk type, 2 bytes: payload len, various bytes: payload
	 */
	*(uint16_t *)(para) = AH_ITK_TYPE_PCI_ALERT;
	len += sizeof(uint16_t);
	*(uint16_t *)(para + len) = 0;
	len += sizeof(uint16_t);
	memcpy(para + len, pci_alert, sizeof(ah_itk_pci_alert_info));
	len += sizeof(ah_itk_pci_alert_info);

	/*reporting subsystem*/
	va_start(args, fmt);
	obj_len = AH_ITK_VSNPRINTF(para + len + sizeof(uint16_t), (AH_CT_MAX_REPORT_BUF - len - sizeof(uint16_t)), fmt, args);
	va_end(args);
	if (obj_len < 0) {
		AH_ITK_ERR("pci_alert(): ah_vsnprintf() return %d!\n", obj_len);
		AH_ITK_FREE(para);
		return -1;
	}
	if (obj_len > AH_CT_MAX_REPORT_STR) {
		AH_ITK_ERR("pci_alert(): claim(len=%d) exceed buffer(%d)!\n",
				   obj_len, AH_CT_MAX_REPORT_STR);
		AH_ITK_FREE(para);
		return -1;
	}
	*(uint16_t *)(para + len) = obj_len;
	len += (sizeof(uint16_t) + obj_len);
	/*fill payload len*/
	*(uint16_t *)(para + sizeof(uint16_t)) = (len - 2 * sizeof(uint16_t));

	rc = AH_ITK_EVENT_SEND(len, para);
	if (rc != 0) {
		AH_ITK_ERR("pci_alert(): ah_event_send(AH_EVENT_ITK_NOTIFY) failed(rc=%d)\n", rc);
	}
	AH_ITK_FREE(para);

	return 0;
}
#ifdef __KERNEL__
EXPORT_SYMBOL(pci_alert_report);
#endif

struct ah_ct_report_para {
	int8_t      *buf;
	ct_event_t *event;
	ah_ct_event_report_t *report;
	ah_ct_event_report_addon_t *addon;
	va_list args;
	int      rc;
	int      len;
	int      claim_len;
	table_entry_t entry;
};

int ct_report(uint32_t ct_enum_mod, ah_mac_t *mac, ah_mac_t *bssid,
			  int current_step, int total_step, boolean success, const char *fmt, ...)
{
	struct ah_ct_report_para *para = NULL;
	/* parameters check */
	if ((NULL == mac) || (NULL == bssid) || (NULL == fmt)) {
		AH_ITK_ERR("ct_log(step=%d/%d, fmt=%s): Invalid paramters!\n",
				   current_step, total_step, (fmt ? fmt : "NULL"));
		return -1;
	}
	if (ct_enum_mod >= AH_CT_MOD_MAX) {
		AH_ITK_ERR("ct_log(): Invalid modid(%d) great than max(%d)\n",
				   ct_enum_mod, AH_CT_MOD_MAX);
		return -1;
	}

	para = AH_ITK_MALLOC(sizeof(struct ah_ct_report_para));
	if (!para) {
		AH_ITK_ERR("ct_log(): ah_malloc(para) retun NULL!\n");
		return -1;
	}
	memset(para, 0, sizeof(struct ah_ct_report_para));

	para->rc = ah_ct_mac2entry(mac, &para->entry);
	if (0 != para->rc) {
		/* no need to report */
		AH_ITK_FREE(para);
		return 0;
	}

	para->buf = AH_ITK_MALLOC(AH_CT_MAX_REPORT_BUF + 1);
	if (NULL == para->buf) {
		AH_ITK_ERR("ct_log(): ah_malloc() retun NULL!\n");
		AH_ITK_FREE(para);
		return -1;
	}

	para->event = (ct_event_t * )(para->buf + para->len);
	/* fill in the event header */
	para->event->cte_type = AH_ITK_TYPE_CLIENT_TRACE;
	para->event->cte_len = 0;   /* set later */
	para->len += sizeof(ct_event_t);

	/* fill in the entry */
	memcpy(para->event->cte_data, &para->entry, sizeof(table_entry_t));
	para->len += sizeof(table_entry_t);

	/* fill in the report */
	para->report = (ah_ct_event_report_t * )(para->buf + para->len);
	AH_MACADDR_COPY(&para->report->cer_mac, mac);
	AH_MACADDR_COPY(&para->report->cer_bssid, bssid);
	para->report->cer_module = ct_enum_mod;
	para->report->cer_time = AH_ITK_TIME(NULL);
	para->report->cer_current_step = current_step;
	para->report->cer_total_step = total_step;
	para->report->cer_success = success;
	para->report->cer_claim_len = 0;    /* set later */
	para->len += sizeof(ah_ct_event_report_t);

	/* add variable length field: claim */
	va_start(para->args, fmt);
	para->claim_len = AH_ITK_VSNPRINTF((char *)(para->buf + para->len), AH_CT_MAX_REPORT_BUF - para->len, fmt, para->args);
	va_end(para->args);
	if (para->claim_len < 0) {
		AH_ITK_ERR("ct_log(): ah_vsnprintf() return %d!\n", para->claim_len);
		AH_ITK_FREE(para->buf);
		AH_ITK_FREE(para);
		return -1;
	}
	if (para->claim_len > AH_CT_MAX_REPORT_STR) {
		AH_ITK_ERR("ct_log(): claim(len=%d) exceed buffer(%d)!\n",
				   para->claim_len, AH_CT_MAX_REPORT_STR);
		AH_ITK_FREE(para->buf);
		AH_ITK_FREE(para);
		return -1;
	}
	para->report->cer_claim_len = para->claim_len;
	para->len += para->claim_len;

	/* add field for later modification */
	para->addon = (ah_ct_event_report_addon_t * )(para->buf + para->len);
	para->addon->cer_level = AH_CT_LEVEL_BASIC;
	para->len += sizeof(ah_ct_event_report_addon_t);

	para->event->cte_len = para->len - sizeof(ct_event_t);

	para->rc = AH_ITK_EVENT_SEND(para->len, para->buf);
	if (0 != para->rc) {
		AH_ITK_ERR("ct_log(mod=%d, fmt=%s): ah_event_send(AH_EVENT_ITK_NOTIFY) failed(rc=%d)\n",
				   ct_enum_mod, fmt, para->rc);
	}
	AH_ITK_FREE(para->buf);
	AH_ITK_FREE(para);
	return 0;
}

#ifdef __KERNEL__
EXPORT_SYMBOL(ct_report);
#endif

int ct_report_level(uint8_t flag, uint32_t ct_enum_mod, ah_mac_t *mac, ah_mac_t *bssid, int if_index, uint32_t    level,
					int current_step, int total_step, boolean success, ah_cm_sess_req_t *cm_sess, const char *fmt, ...)
{
	struct ah_ct_report_para *para = NULL;
	ah_itk_cm_report_t *cm_report  = NULL;
	ah_itk_cm_sess_t   *ct_cm_sess    = NULL;

	/* parameters check */
	if ((NULL == mac) || (NULL == bssid) || (NULL == fmt)) {
		AH_ITK_ERR("ct_report_level(step=%d/%d, fmt=%s): Invalid paramters!\n",
				   current_step, total_step, (fmt ? fmt : "NULL"));
		return -1;
	}
	if (ct_enum_mod >= AH_CT_MOD_MAX) {
		AH_ITK_ERR("ct_report_level(): Invalid modid(%d) great than max(%d)\n",
				   ct_enum_mod, AH_CT_MOD_MAX);
		return -1;
	}

	para = AH_ITK_MALLOC(sizeof(struct ah_ct_report_para));
	if (!para) {
		AH_ITK_ERR("ct_report_level(): ah_malloc(para) retun NULL!\n");
		return -1;
	}
	memset(para, 0, sizeof(struct ah_ct_report_para));


	para->rc = ah_ct_mac2entry(mac, &para->entry);
	if (0 != para->rc && !(flag & (~0x01))) {
		/* no need to report */
		AH_ITK_FREE(para);
		return 0;
	}

	if (0 != para->rc) {
		/* if no cookie entry, add a cookie 0 */
		AH_MACADDR_COPY(&para->entry.ce_mac, mac);
		para->entry.ce_cookie_cnt = 1;
		para->entry.ce_cookie[0]  = 0;
	}

	para->buf = AH_ITK_MALLOC(AH_CT_MAX_REPORT_BUF + 1);
	if (NULL == para->buf) {
		AH_ITK_ERR("ct_report_level(): ah_malloc() retun NULL!\n");
		AH_ITK_FREE(para);
		return -1;
	}

	para->event = (ct_event_t * )(para->buf + para->len);
	/* fill in the event header */
	para->event->cte_type = AH_ITK_TYPE_CLIENT_TRACE;
	para->event->cte_len = 0;   /* set later */
	para->len += sizeof(ct_event_t);

	/* fill in the entry */
	memcpy(para->event->cte_data, &para->entry, sizeof(para->entry));
	para->len += sizeof(para->entry);

	/* fill in the cm session */
	ct_cm_sess = (ah_itk_cm_sess_t *)(para->buf + para->len);
	if (cm_sess && cm_sess->sessnum) {
		ct_cm_sess->sessnum = cm_sess->sessnum;
		memcpy(ct_cm_sess->sess, cm_sess->sess, ct_cm_sess->sessnum * sizeof(ah_cm_sess_attr_t));
	} else {
		ct_cm_sess->sessnum = 0;
	}

	para->len += sizeof(ah_itk_cm_sess_t) + ct_cm_sess->sessnum * sizeof(ah_cm_sess_attr_t);

	/* fill in the report */
	para->report = (ah_ct_event_report_t * )(para->buf + para->len);
	AH_MACADDR_COPY(&para->report->cer_mac, mac);
	AH_MACADDR_COPY(&para->report->cer_bssid, bssid);
	para->report->cer_module = ct_enum_mod;
	para->report->cer_time = AH_ITK_TIME(NULL);
	para->report->cer_current_step = current_step;
	para->report->cer_total_step = total_step;
	para->report->cer_success = success;
	para->report->cer_claim_len = 0;    /* set later */
	para->len += sizeof(ah_ct_event_report_t);

	/* add variable length field: claim */
	va_start(para->args, fmt);
	para->claim_len = AH_ITK_VSNPRINTF((char *)(para->buf + para->len), AH_CT_MAX_REPORT_BUF - para->len, fmt, para->args);
	va_end(para->args);
	if (para->claim_len < 0) {
		AH_ITK_ERR("ct_report_level(): ah_vsnprintf() return %d!\n", para->claim_len);
		AH_ITK_FREE(para->buf);
		AH_ITK_FREE(para);
		return -1;
	}
	if (para->claim_len > AH_CT_MAX_REPORT_STR) {
		para->claim_len = AH_CT_MAX_REPORT_STR;
	}
	para->report->cer_claim_len = para->claim_len;
	para->len += para->claim_len;

	/* add field for later modification */
	para->addon = (ah_ct_event_report_addon_t * )(para->buf + para->len);
	para->addon->cer_level = level;
	para->len += sizeof(ah_ct_event_report_addon_t);

	/* add client monitor 2.0 related parameters, if problem is detected automatically */
	cm_report = (ah_itk_cm_report_t *)(para->buf + para->len);
	cm_report->flag = flag;
	/* for client monitor 1.0 or 2.0 which will fetch session id in capwap module */
	/* send ifindex for 2.0 log  */
	cm_report->instance_id = (flag & 0x02) ? (uint32_t)if_index : 0;
	cm_report->sessid_len  = 0;
	para->len += sizeof(ah_itk_cm_report_t) + cm_report->sessid_len;

	para->event->cte_len = para->len - sizeof(ct_event_t);

	para->rc = AH_ITK_EVENT_SEND(para->len, para->buf);
	if (0 != para->rc) {
		AH_ITK_ERR("ct_report_level(mod=%d, fmt=%s): ah_event_send(AH_EVENT_ITK_NOTIFY) failed(rc=%d)\n",
				   ct_enum_mod, fmt, para->rc);
	}
	AH_ITK_FREE(para->buf);
	AH_ITK_FREE(para);
	return 0;
}

#ifdef __KERNEL__
EXPORT_SYMBOL(ct_report_level);
#endif

int dp_log(uint16_t end_flag, uint16_t vlan, uint32_t ip, uint8_t masklen, uint32_t default_gw, uint32_t dns,
		   const char *fmt, ...)
{
	int      rc;
	int8_t      *buf;
	dhcp_probe_entry_t *dp;
	int      len = 0;
	ct_event_t *event;
	ah_dp_event_report_t *report;
	va_list args;
	int      claim_len;

	buf = AH_ITK_MALLOC(AH_CT_MAX_REPORT_BUF + 1);
	if (NULL == buf) {
		AH_ITK_ERR("dp_log(): ah_malloc() retun NULL!\n");
		return -1;
	}

	event = (ct_event_t * )(buf + len);
	/* fill in the event header */
	event->cte_type = AH_ITK_TYPE_DHCP_PROBE;
	event->cte_len = 0; /* set later */
	len += sizeof(ct_event_t);

	/* fill in the dp_entry */
	dp = (dhcp_probe_entry_t * )(event + 1);
	rc = ah_dp_get(dp);
	len += sizeof(dhcp_probe_entry_t);

	/* fill in the report */
	report = (ah_dp_event_report_t * )(dp + 1);
	report->end_flag = end_flag;
	report->vlan_id = vlan;
	report->ip = ip;
	report->mask_len = masklen;
	report->gateway = default_gw;
	report->dns = dns;

	report->claim_len = 0;  /* set later */
	len += sizeof(ah_dp_event_report_t);

	/* add variable length field: claim */
	va_start(args, fmt);
	claim_len = AH_ITK_VSNPRINTF((char *)(buf + len), AH_CT_MAX_REPORT_BUF - len, fmt, args);
	va_end(args);
	if (claim_len < 0) {
		AH_ITK_ERR("dp_log(): ah_vsnprintf() return %d!\n", claim_len);
		AH_ITK_FREE(buf);
		return -1;
	}
	if (claim_len > AH_CT_MAX_REPORT_STR) {
		AH_ITK_ERR("dp_log(): claim(len=%d) exceed buffer(%d)!\n",
				   claim_len, AH_CT_MAX_REPORT_STR);
		AH_ITK_FREE(buf);
		return -1;
	}
	report->claim_len = claim_len;

	len += claim_len;
	event->cte_len = len - sizeof(ct_event_t);

	rc = AH_ITK_EVENT_SEND(len, buf);
	if (0 != rc) {
		AH_ITK_ERR("dp_log(): ah_event_send(AH_EVENT_ITK_NOTIFY) failed(rc=%d)\n", rc);
	}
	AH_ITK_FREE(buf);
	return 0;
}



