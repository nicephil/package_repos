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
/* STD C */
#include <time.h>

/* aerohive header */
#include "ah_syscall.h"
#include "ah_assert.h"

#include "ah_cmd_s.h"
#include "capwap/ah_cli_agt_auto.h"
#include "ah_dbg_agent.h"
#include "ah_dcd_api.h"
#include "ah_tpa_api.h"

/* ITK header */
#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_itk.h"
#include "ah_itk.h"
#include "ah_cm_api.h"

/*
   ah_syslib_init
 */

extern int32_t ah_itk_show(ah_cmd_handle_t *cmd);

void ah_ct_show(ah_cmd_handle_t *cmd, client_tracing_table_t *table)
{
	ah_cli_printf(cmd, "\tClient Trace Table(sta_num=%d):\n",
				  TABLE_ENTRY_NUM(table));

	int      index;
	int      i;
	table_entry_t *entry;
	for (index = 0; index < TABLE_ENTRY_NUM(table); index++) {
		entry = GET_TABLE_ENTRY(table, index);

		ah_cli_printf(cmd, "\tEntry(%m cookie_num=%d): ",
					  GET_ENTRY_MAC(entry), COOKIE_NUM(entry));

		for (i = 0; i < COOKIE_NUM(entry); i++) {
			ah_cli_printf(cmd, "%d ", GET_COOKIE(entry, i));
		}

		ah_cli_printf(cmd, "\n");
	}
}

void ah_dp_show(ah_cmd_handle_t *cmd, dhcp_probe_entry_t *dp)
{
	ah_cli_printf(cmd, "\n\tDhcp Probe Array(num=%d):", dp->dp_cnt);
	int      i;

	for (i = 0; i < dp->dp_cnt; i++) {
		ah_cli_printf(cmd, "\n\tCookie=%d vlan=(%d, %d)",
					  dp->dp_cookie[i], dp->dp_vlan_min[i], dp->dp_vlan_max[i]);
	}

	ah_cli_printf(cmd, "\n");
}

void ah_itk_show_data(ah_cmd_handle_t *cmd, ah_itk_data_t *data, char *title)
{
	ah_cli_printf(cmd, "%s", title);
	ah_ct_show(cmd, &data->itk_ct);
	ah_dp_show(cmd, &data->itk_dp);
}

int ah_ct_show_table(ah_cmd_handle_t *cmd, ah_ct_cli_show_table_cmd_data_t *ptr)
{
	int32_t    rc;
	ah_itk_data_t data;
	rc = ah_itk_get_kernel(&data);
	if (0 != rc) {
		ah_cli_printf(cmd, "ITK: Get structure failed!");
		return -1;
	}
	ah_itk_show_data(cmd, &data, "\n\n\n\nKernel:\n");

	rc = ah_itk_get(&data);
	if (0 == rc) {
		return -1;
	}
	ah_itk_show_data(cmd, &data, "\n\n\n\nApplication:\n");
	return 0;
}

int ah_itk_ct_del_all()
{
	int      rc = 0;
	ah_itk_data_t data;
	client_tracing_table_t *table = NULL;
	int      index;
	table_entry_t *entry;

	if (ah_itk_get(&data) == 0) {
		return -1;
	}
	table = &data.itk_ct;
	for (index = 0; index < TABLE_ENTRY_NUM(table); index++) {
		entry = GET_TABLE_ENTRY(table, index);
		rc = ah_itk_ct_del((ah_mac_t *)GET_ENTRY_MAC(entry), AH_CT_CLI_COOKIE);
	}

	return rc;
}


int ah_ct_update_mac(ah_cmd_handle_t *cmd, ah_ct_cli_update_mac_cmd_data_t *ptr)
{
	int      rc;
	if (AH_CMD_TYPE(cmd) == AH_CMD_TYPE_UNSET) {
		if (ptr->valid.sta_mac) {
			rc = ah_itk_ct_del((ah_mac_t *)ptr->sta_mac, AH_CT_CLI_COOKIE);
		} else {
			rc = ah_itk_ct_del_all();
		}
	} else {
		rc = ah_itk_ct_add((ah_mac_t *)ptr->sta_mac, AH_CT_CLI_COOKIE);
	}
	if (rc == AH_ITK_ERRCODE_MAC_NUM_MAX) {
		ah_cli_printf(cmd, "warning: the max number of mac is reached\n");
	}
	return rc;
}


static int ah_ct_cli_show_cm2_from_file(ah_cmd_handle_t *cmd)
{
	int      wait_count = 0;
	int      auth_exist = 0;
	int      capwap_exist = 0;

	while (wait_count < 10) {
		if (access(AH_CM_AUTH_CLI_SHOW_FILE, F_OK) == 0) {
			auth_exist = 1;
		}
		if (access(AH_CM_CAPWAP_CLI_SHOW_FILE, F_OK) == 0) {
			capwap_exist = 1;
		}
		if ((!auth_exist || !capwap_exist) && (wait_count < 9)) {
			wait_count++;
			sleep(1);
			continue;
		}

		/* print auth */
		FILE *fp = NULL;
		char buff[AH_CM_PRINT_BUF_LEN] = {0};

		ah_cli_printf(cmd, "\n\n---------Auth Module CM2.0 data---------\n");

		fp = fopen(AH_CM_AUTH_CLI_SHOW_FILE, "r");
		if (fp == NULL) {
			ah_cli_printf(cmd, "Can not open file:%s\n", AH_CM_AUTH_CLI_SHOW_FILE);
		} else {
			while (fgets(buff, (AH_CM_PRINT_BUF_LEN - 1), fp) != NULL) {
				ah_cli_printf(cmd, buff);
			}
			fclose(fp);
			unlink(AH_CM_AUTH_CLI_SHOW_FILE);
		}

		/* print capwap */
		ah_cli_printf(cmd, "\n\n---------CAPWAP Module CM2.0 data---------\n");
		fp = fopen(AH_CM_CAPWAP_CLI_SHOW_FILE, "r");
		if (fp == NULL) {
			ah_cli_printf(cmd, "Can not open file:%s, CAPWAP maybe not enable\n", AH_CM_CAPWAP_CLI_SHOW_FILE);
		} else {
			while (fgets(buff, (AH_CM_PRINT_BUF_LEN - 1), fp) != NULL) {
				ah_cli_printf(cmd, buff);
			}
			fclose(fp);
			unlink(AH_CM_CAPWAP_CLI_SHOW_FILE);
		}
		/* print radius server, may not exist */
		ah_cli_printf(cmd, "\n\n---------Radius Module CM2.0 data---------\n");
		fp = fopen(AH_CM_RADSRV_CLI_SHOW_FILE, "r");
		if (fp == NULL) {
			ah_cli_printf(cmd, "Note:Can not open file:%s, Radius server maybe not enable\n",
						  AH_CM_RADSRV_CLI_SHOW_FILE);
		} else {
			while (fgets(buff, (AH_CM_PRINT_BUF_LEN - 1), fp) != NULL) {
				ah_cli_printf(cmd, buff);
			}
			fclose(fp);
			unlink(AH_CM_RADSRV_CLI_SHOW_FILE);
		}

		return 0;
	}

	return -1;
}


static int ah_cm_dump_kernel_report_entry(ah_cmd_handle_t *cmd)
{
	int total_cnt = 0, i, cnt = 0, rc = 0, chunk_cnt = AH_CM_ENTRY_DUMP_CHUNK_CNT;
	ah_itk_io_t msg;

	memset(&msg, 0, sizeof(ah_itk_io_t));
	rc = ah_syslib_cm_set_val_rsp(AH_CM_EVENT_DUMP_RPT_CNT, 0, &msg);
	if (rc < 0) {
		ah_cli_printf(cmd, "ERROR: Cannot get report entry counter\n");
		goto out;
	}
	total_cnt = msg.u.cm.u.val;

	ah_cli_printf(cmd, "\n\n---------Kernel Module CM2.0 data---------\n");
	ah_cli_printf(cmd, "Report table entry number:%d\n", total_cnt);

	for (cnt = 0; cnt < total_cnt && chunk_cnt == AH_CM_ENTRY_DUMP_CHUNK_CNT; cnt += chunk_cnt) {
		memset(&msg, 0, sizeof(ah_itk_io_t));
		rc = ah_syslib_cm_set_val_rsp(AH_CM_EVENT_DUMP_RPT, cnt, &msg);

		if (rc != 0) {
			ah_cli_printf(cmd, "ERROR: error code in reading report entry..\n");
			goto out;
		}

		chunk_cnt = 0;
		for (i = 0; i < AH_CM_ENTRY_DUMP_CHUNK_CNT; i++) {
			if (!msg.u.cm.u.rsp[i].ifidx) {
				break;
			}
			chunk_cnt++;
			ah_cli_printf(cmd, "%d) station:%m, interface:%s\n",
						  cnt + i + 1,
						  msg.u.cm.u.rsp[i].addr,
						  ah_cm_ifindex2info(msg.u.cm.u.rsp[i].ifidx));
		}
	}


out:
	return rc;
}

int ah_show_cm2_info(ah_cmd_handle_t *cmd, ah_ct_cli_show_cm2_cmd_data_t *ptr)
{
	int      rc = 0;

	ah_cli_printf(cmd, "Show client monitor v2.0 information\n");
	ah_cli_printf(cmd, "client monitor v2.0 is %s\n",
				  ah_dcd_cm_is_enabled() ? "enabled" : "disabled");

	ah_event_send(AH_EVENT_CM_SHOW_INFO, 0, NULL);
	ah_cm_dump_kernel_report_entry(cmd);
	ah_ct_cli_show_cm2_from_file(cmd);

	return rc;
}



int ah_ct_test(ah_cmd_handle_t *cmd, ah_ct_cli_test_cmd_data_t *ptr)
{
	int      rc;
	ah_itk_ioctl_log();
	rc = ct_progress(AH_CT_MOD_80211,
					 (ah_mac_t *)ptr->sta_mac, (ah_mac_t *)ptr->sta_mac,
					 1, 3, "It's a test for %m", ptr->sta_mac);
	if (rc < 0) {
		ah_cli_printf(cmd, "ct_detail() failed!\n");
	}
	return 0;
}

char *ah_ct_mod_name[] = {
	"802.11",
	"RADIUS",
	"AUTH",
	"DHCP",

	NULL
};

char *ah_ct_level_name[] = {
	"basic",
	"info",
	"detail",

	NULL
};
#define GET_REPORT_ADDON(report) \
	(ah_ct_event_report_addon_t* )((uint8_t* )(report + 1) + report->cer_claim_len)

void ah_ct_to_cli(ah_ct_event_report_t *report)
{
	char buf[AH_CT_MAX_REPORT_BUF];
	char tmp[AH_CT_MAX_REPORT_STR];
	char fmt[] = "%-25s %-10s %-10s %-8s %-5s %-20s";
	int      len = 0;
	int      off = 0;
	ah_ct_event_report_addon_t *addon = GET_REPORT_ADDON(report);

	ah_log_old(AH_LOG_INFO, fmt,
			   "Time", "AP", "stage", "level", "step", "claim");
	/* time */
	struct tm tm;
	time_t time = report->cer_time;
	localtime_r(&time, &tm);
	asctime_r(&tm, tmp);

	/* remove the last '\n' */
	tmp[ah_strlen(tmp) - 1] = '\0';

	len = ah_sprintf(buf + off, "%-25s ", tmp);
	off += len;

	/* AP-name */
	ah_tpa_get_hostname(tmp);
	len = ah_sprintf(buf + off, "%-10s ", tmp);
	off += len;

	/* stage */
	len = ah_sprintf(buf + off, "%-10s ", ah_ct_mod_name[report->cer_module]);
	off += len;

	/* level */
	len = ah_sprintf(buf + off, "%-8s ", ah_ct_level_name[addon->cer_level]);
	off += len;

	/* step */
	if (0 == report->cer_total_step) {
		ah_sprintf(tmp, "%s",
				   (report->cer_success ? "SUCC" : "FAIL"));
	} else {
		ah_sprintf(tmp, "%d/%d",
				   report->cer_current_step, report->cer_total_step);
	}
	len = ah_sprintf(buf + off, "%-5s ", tmp);
	off += len;

	/* claim */
	ah_snprintf(tmp, report->cer_claim_len + 1, "%s",
				(char *)report->cer_claim);
	tmp[report->cer_claim_len] = '\0';
	len = ah_sprintf(buf + off, "%-20s", tmp);
	off += len;

	ah_log_old(AH_LOG_INFO, buf);
}

typedef struct {
	uint16_t    event_type;
	uint32_t    cookie;
	uint32_t    data_len;
	uint8_t    data[0];
} __packed ah_capwap_event_report_data_t;

void ah_itk_send_event(uint16_t event_type, uint32_t cookie,
					   uint32_t    len, uint8_t *data)
{
	uint32_t    size = len + sizeof(ah_capwap_event_report_data_t);
	ah_capwap_event_report_data_t *buf = (ah_capwap_event_report_data_t *)ah_malloc(size);
	if (NULL == buf) {
		ah_err_old("ah_malloc(ah_capwap_event_report_data_t) failed!\n");
		return ;
	}

	buf->event_type = htons(event_type);
	buf->cookie = htonl(cookie);
	buf->data_len = htonl(len);
	ah_memcpy(buf + 1, data, len);
	ah_dbg_old(capwap_itk, "ITK: Send capwap-event(type=%d, cookie=%d, len=%d)",
			   event_type, cookie, len);
	ah_capwap_send_event_itself(size, (char *)buf, AH_CAPWAP_EVENT_SEND_RESPONSE);
	ah_free(buf);
}

void ah_ct_convert_report_net(ah_ct_event_report_t *report)
{
	ah_ct_event_report_addon_t *addon = GET_REPORT_ADDON(report);

	report->cer_time = htonl(report->cer_time);
	report->cer_module = htonl(report->cer_module);
	report->cer_current_step = htons(report->cer_current_step);
	report->cer_total_step = htons(report->cer_total_step);
	report->cer_success = htons(report->cer_success);
	report->cer_claim_len = htons(report->cer_claim_len);

	addon->cer_level = htonl(addon->cer_level);
}

void ah_ct_dump_report(ah_ct_event_report_t *report)
{
	ah_ct_event_report_addon_t *addon = GET_REPORT_ADDON(report);
	ah_dbg_old(capwap_itk, "ITK-ct: module(%s) in AP(%m) report sta(%m): claim(len=%d, %.*s, level=%d) step(%d/%d) %s",
			   ah_ct_mod_name[report->cer_module],
			   &report->cer_bssid, &report->cer_mac,
			   report->cer_claim_len, report->cer_claim_len, report->cer_claim,
			   addon->cer_level,
			   report->cer_current_step, report->cer_total_step,
			   (report->cer_success ? "SUCCESS" : "FAILED")
			  );
}
/* use for determine the udp-packet sequence */
static uint32_t ah_itk_ct_seq = 0;

#define AH_CT_GET_CM2REPORT(report) \
	(ah_itk_cm_report_t *)((uint8_t* )(report + 1) + report->cer_claim_len + sizeof(ah_ct_event_report_addon_t))

void ah_itk_send_cmlog(uint16_t event_type, uint32_t cookie,
					   uint32_t    len, uint8_t *data, char *session_id)
{
	uint32_t    datalen = len + (session_id ? ah_strlen(session_id) : 0);
	uint32_t    size = sizeof(ah_capwap_event_report_data_t) + datalen;
	ah_capwap_event_report_data_t *buf = (ah_capwap_event_report_data_t *)ah_malloc(size);
	if (NULL == buf) {
		ah_err_old("ah_malloc(ah_capwap_event_report_data_t) failed!\n");
		return ;
	}

	buf->event_type = htons(event_type);
	buf->cookie = htonl(cookie);
	buf->data_len = htonl(datalen);

	/* copy raw data */
	ah_memcpy(buf + 1, data, len);

	/* copy session id */
	if (session_id) {
		ah_memcpy((uint8_t *)(buf + 1) + len, session_id, ah_strlen(session_id));
	}
	ah_dbg_old(capwap_itk, "ITK: Send cm 2.0 capwap-event(type=%d, cookie=%d, len=%d)",
			   event_type, cookie, datalen);
	ah_capwap_send_event_itself(size, (char *)buf, AH_CAPWAP_EVENT_SEND_RESPONSE);
	ah_free(buf);
}

int ah_ct_send_cmlog(ah_cm_sess_id_t *sess_id, uint sess_num, void *arg)
{
	ah_ct_cmlog_req_t *cmlog_req = (ah_ct_cmlog_req_t *)arg;

	/* increase instance id if start log is received */
	ah_cm_rpt_upd_sess_inst(sess_id, cmlog_req->report);

	ah_dbg_old(capwap_itk, "ITK: Send cm 2.0 log(module=%s, session id=%s, instance id=%d)",
			   ah_ct_mod_name[ntohl(cmlog_req->report->cer_module)],
			   sess_id->session_id, sess_id->instance_id);

	cmlog_req->cm2report->instance_id = htonl(sess_id->instance_id);
	cmlog_req->cm2report->sessid_len  = ah_strlen(sess_id->session_id);
	ah_itk_send_cmlog(AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING,
					  cmlog_req->cookie, cmlog_req->len, (uint8_t *)cmlog_req->report, sess_id->session_id);

	return 0;
}


/* fetch session id and instance id */
void ah_ct_proc_cmlog(uint32_t cookie, uint32_t len,
					  ah_itk_cm_sess_t *ct_cm_sess, ah_ct_event_report_t *report, ah_itk_cm_report_t *cm2report)
{
	uint      i = 0;
	int      rc = -1;

	if (ct_cm_sess->sessnum == 0) {
		ah_ct_cmlog_req_t cmlog_req = {
			.cookie    = cookie,
			.len       = len,
			.report    = report,
			.cm2report = cm2report,
		};

		/* if the sessid len is zero, the instance_id is ifindex which the station is connected to */
		ah_dbg_old(capwap_itk, "ITK-ct: module(%s) in AP(ifmac=%m, ifindex=%d) report sta(%m): fetch cm 2.0 session id",
				   ah_ct_mod_name[ntohl(report->cer_module)],
				   &report->cer_bssid, cm2report->instance_id, &report->cer_mac);

		rc = ah_cm_rpt_foreach_session((uchar *)&report->cer_mac,
									   cm2report->instance_id, TRUE,
									   ah_ct_send_cmlog,
									   (void *)&cmlog_req);

		return;
	}

	/* if sessnum is not zero, the log must be from RADIUS server */
	for (i = 0; i < ct_cm_sess->sessnum; i++) {
		/* generate session id according to ct_cm_sess */
		char        session_id[AH_CM_SESSION_ID_MAX_LEN] = {0};    /* string type for session id */
		ah_snprintf(session_id,
					AH_CM_SESSION_ID_MAX_LEN,
					CM_SESS_ADDR_FORMAT CM_SESS_ADDR_FORMAT "%8x%8x%.8x",
					MAC2STR((uchar *)&report->cer_mac), MAC2STR((uchar *)&report->cer_bssid),
					ct_cm_sess->sess[i].tm, ct_cm_sess->sess[i].rand, ct_cm_sess->sess[i].sess_type);

		ah_dbg_old(capwap_itk, "ITK: Send cm 2.0 log(module=%s, session id=%s, instance id=%d)",
				   ah_ct_mod_name[ntohl(report->cer_module)], session_id, ct_cm_sess->sess[i].instance_id);

		cm2report->instance_id = htonl(ct_cm_sess->sess[i].instance_id);
		cm2report->sessid_len  = ah_strlen(session_id);
		ah_itk_send_cmlog(AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING,
						  cookie, len, (uint8_t *)report, session_id);
	}

	return;
}


void ah_ct_proc_event(uint8_t *buf, int len)
{
	ah_itk_cm_report_t *cm2report = NULL;
	table_entry_t *entry = (table_entry_t *)buf;
	ah_itk_cm_sess_t *ct_cm_sess = (ah_itk_cm_sess_t *)(entry + 1);
	ah_ct_event_report_t *report = (ah_ct_event_report_t *)((uint8_t *)(ct_cm_sess + 1) +
								   AH_ITK_CM_SESSLEN(ct_cm_sess));
	len -= (sizeof(table_entry_t) + sizeof(ah_itk_cm_sess_t) + AH_ITK_CM_SESSLEN(ct_cm_sess));

	ah_ct_event_report_t *report_net = (ah_ct_event_report_t *)ah_malloc(len);
	if (NULL == report_net) {
		return ;
	}
	ah_memcpy(report_net, report, len);

	cm2report = AH_CT_GET_CM2REPORT(report_net);
	ah_ct_convert_report_net(report_net);
	ah_ct_dump_report(report);

	if (cm2report->flag & 0x02) {
		ah_dbg_old(capwap_itk, "ITK-ct: module(%s) in AP(%m) report sta(%m): client monitor 2.0 log(flag %x)",
				   ah_ct_mod_name[report->cer_module],
				   &report->cer_bssid, &report->cer_mac, cm2report->flag);
	}

	int      index;
	uint32_t    cookie;
	for (index = 0; index < COOKIE_NUM(entry); index++) {
		cookie = GET_COOKIE(entry, index);
		if (AH_CT_CLI_COOKIE == cookie) {
			ah_ct_to_cli(report);
		} else if (0 == cookie || cookie > AH_CT_HM_COOKIE_MIN) {
			report_net->cer_seq = htonl(ah_itk_ct_seq);
			ah_itk_ct_seq++;

			if (cm2report->flag & 0x02) {
				ah_ct_proc_cmlog(cookie, len, ct_cm_sess, report_net, cm2report);
				/* cm2.0 log should only be sent once, so remove cm2.0 info after it's sent. */
				cm2report->flag &= ~0x02;
				/* restore to original value */
				if (cm2report->sessid_len != 0) {
					cm2report->sessid_len  = 0;
					cm2report->instance_id = 0;
				}
			} else {
				ah_itk_send_event(AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING, cookie,
								  len, (uint8_t *)report_net);
			}
		} else {
			ah_err_old("itk-ct: Invalid cookie(%d) found!\n", cookie);
		}
	}

	ah_free(report_net);
}

void ah_dp_convert_report_net(ah_dp_event_report_t *report)
{
	report->end_flag = htons(report->end_flag);
	report->vlan_id = htons(report->vlan_id);
	report->mask_len = htons(report->mask_len);
	report->claim_len = htons(report->claim_len);
}

void ah_itk_dbg_dp_report(ah_dp_event_report_t *report)
{
	if (!capwap_itk) {
		return ;
	}
	ah_dbg_old(capwap_itk, "dp_report: flag=%d, ip=%i, vlanid=%d, mask_len=%d, gw=%i, dns=%i, claim(len=%d, %.*s)",
			   report->end_flag, report->ip, report->vlan_id, report->mask_len,
			   report->gateway, report->dns, report->claim_len, report->claim_len, (char *)report->claim);
}

static char *ah_capwap_get_pci_alert_type_str(uint32_t alert_type)
{
	return (((alert_type) == AH_ITK_PCI_PROBE_REQUEST) ? "probe request" : \
			((alert_type) == AH_ITK_PCI_PROBE_RESPONSE) ? "probe response" : \
			((alert_type) == AH_ITK_PCI_ASSOC_REQUEST) ? "association request" : \
			((alert_type) == AH_ITK_PCI_ASSOC_RESPONSE) ? "association response" : \
			((alert_type) == AH_ITK_PCI_DEASSOC) ? "disassociation" : \
			((alert_type) == AH_ITK_PCI_AUTH) ? "authentication" : \
			((alert_type) == AH_ITK_PCI_DEAUTH) ? "deauthentication" : \
			((alert_type) == AH_ITK_PCI_EAPOL) ? "EAPOL" : \
			((alert_type) == AH_ITK_PCI_ICMP_FLOOD) ? "ICMP flood" : \
			((alert_type) == AH_ITK_PCI_UDP_FLOOD) ? "UDP flood" : \
			((alert_type) == AH_ITK_PCI_SYN_FLOOD) ? "SYN flood" : \
			((alert_type) == AH_ITK_PCI_ARP_FLOOD) ? "ARP flood" : \
			((alert_type) == AH_ITK_PCI_ADDRESS_SWEEP) ? "address sweep" : \
			((alert_type) == AH_ITK_PCI_PORT_SCAN) ? "port scan" : \
			((alert_type) == AH_ITK_PCI_IP_SPOOF) ? "IP spoof" : \
			((alert_type) == AH_ITK_PCI_RADIUS_ATTACK) ? "RADIUS attack" : \
			((alert_type) == AH_ITK_PCI_TCP_SYN_CHECK) ? "TCP Sync check" : \
			((alert_type) == AH_ITK_PCI_IP_FIREWALL_VIOLATION) ? "IP Firewall Violation" : \
			((alert_type) == AH_ITK_PCI_MAC_FIREWALL_VIOLATION) ? "MAC Firewall Violation" : \
			((alert_type) == AH_ITK_PCI_MAC_FILTER_VIOLATION) ? "MAC Filter Violation" : \
			"Unknown PCI alert type");
}

static int ah_pci_alert_report_object(char *buff, const char *obj_mac, const int32_t obj_ip)
{
	char      *para = buff;
	int      len = 0;

	para += sizeof(uint16_t); /*for object len*/
	if (is_ah_mac_zero(obj_mac)) {
		/*invalid source mac*/
		if (obj_ip == 0) {
			/*invalid source ip*/
		} else {
			len += ah_sprintf(para, "IP:%i", obj_ip);
		}
	} else {
		if (obj_ip == 0) {
			/*invalid source ip*/
			len += ah_sprintf(para, "MAC:%m", obj_mac);
		} else {
			len += ah_sprintf(para, "MAC:%m, IP:%i", obj_mac, obj_ip);
		}
	}
	/*fill object len*/
	*(uint16_t *)(buff) = htons(len);

	/*total len = object len + sizeof(uint16_t)*/
	len += sizeof(uint16_t);

	return len;
}

static void ah_pci_proc_event(uint8_t *buf, int len)
{
	ah_itk_pci_alert_info *alert_info = (ah_itk_pci_alert_info *)(buf);
	char      *pkt_buff = NULL;
	uint16_t    pkt_len = 0;
	char      obj_str[AH_CT_MAX_REPORT_STR + 1] = {0};
	char      hive_mac[MACADDR_LEN] = {0};

	/*payload:
	  6 bytes: node id;
	  2 bytes: alert type;
	  4 bytes: violation counter
	  2 bytes: Source object (Optional String: IP address or MAC address) len;
	  various bytes: Source object;
	  2 bytes: Destination object (Optional String: IP address or MAC address) len;
	  various bytes: Destination object;
	  2 bytes: Reporting subsystem len;
	  various bytes: Reporting subsystem;
	  */
	if (capwap_itk) {
		ah_dbg_old(capwap_itk, "Receive PCI alert payload from AP:\n");
		ah_hexdump((uchar *)buf, len);
	}

	pkt_buff = ah_malloc(AH_CAPWAP_BUF_LEN);
	if (pkt_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: malloc for PCI alert information failed, malloc len:%d\n", AH_CAPWAP_BUF_LEN);
		return;
	}

	ah_dbg_old(capwap_itk, "PCI alert information:\n");
	/*fill node id*/
	ah_dcd_get_mac_byname(default_hvi_name(), hive_mac);
	ah_dbg_old(capwap_itk, "Node id: %m\n", hive_mac);
	ah_memcpy(pkt_buff, hive_mac, MACADDR_LEN);
	pkt_len += MACADDR_LEN;

	/*fill alert type*/
	ah_dbg_old(capwap_itk, "Alert type: %s(id:%d)\n", ah_capwap_get_pci_alert_type_str(alert_info->alert_type),
			   (alert_info->alert_type));
	*(uint16_t *)(pkt_buff + pkt_len) = htons(alert_info->alert_type);
	pkt_len += sizeof(uint16_t);

	/*fill violation counter*/
	ah_dbg_old(capwap_itk, "Violation counter: %d\n", alert_info->violation_counter);
	*(uint32_t *)(pkt_buff + pkt_len) = htonl(alert_info->violation_counter);
	pkt_len += sizeof(uint32_t);

	/*fill source object string*/
	ah_dbg_old(capwap_itk, "Source object mac:%m, ip:%i\n", alert_info->src_mac, alert_info->src_ip);
	pkt_len += ah_pci_alert_report_object(pkt_buff + pkt_len, alert_info->src_mac, alert_info->src_ip);

	/*fill destination object string*/
	ah_dbg_old(capwap_itk, "Destination object mac:%m, ip:%i\n", alert_info->dst_mac, alert_info->dst_ip);
	pkt_len += ah_pci_alert_report_object(pkt_buff + pkt_len, alert_info->dst_mac, alert_info->dst_ip);

	/*fill reporting subsystem*/
	ah_memset(obj_str, 0, AH_CT_MAX_REPORT_STR + 1);
	ah_memcpy(obj_str, (buf + sizeof(ah_itk_pci_alert_info) + sizeof(uint16_t)), *(uint16_t *)(buf + sizeof(ah_itk_pci_alert_info)));
	ah_dbg_old(capwap_itk, "Reporting subsystem: %s\n", obj_str);

	*(uint16_t *)(pkt_buff + pkt_len) = htons(ah_strlen(obj_str));
	pkt_len += sizeof(uint16_t);
	ah_memcpy(pkt_buff + pkt_len, obj_str, ah_strlen(obj_str));
	pkt_len += ah_strlen(obj_str);

	if (capwap_itk) {
		ah_dbg_old(capwap_itk, "Send PCI alert payload to HM:\n");
		ah_hexdump((uchar *)pkt_buff, pkt_len);
	}

	ah_itk_send_event(AH_CAPWAP_EVENT_PCI_ALERT, 0, pkt_len, (uint8_t *)pkt_buff);

	ah_free(pkt_buff);

	return;
}

void ah_dp_proc_event(uint8_t *buf, int len)
{
	dhcp_probe_entry_t *dp = (dhcp_probe_entry_t *)buf;
	ah_dp_event_report_t *report = (ah_dp_event_report_t *)(dp + 1);

	int      index;
	uint32_t    cookie;

	ah_dp_event_report_t host;
	ah_memcpy(&host, report, sizeof(host));
	ah_itk_dbg_dp_report(report);

	for (index = 0; index < dp->dp_cnt; index++) {
		cookie = dp->dp_cookie[index];
		if (AH_CT_CLI_COOKIE == cookie) {
			//ah_dp_to_cli(report);
		} else if (cookie > AH_CT_HM_COOKIE_MIN) {
			if ((report->end_flag) || ((report->vlan_id >= dp->dp_vlan_min[index])
									   && (report->vlan_id <= dp->dp_vlan_max[index]))) {

				if (report->end_flag) {
					ah_dbg_old(capwap_itk, "remove dp_cookie(%d) for flag(%d)",
							   cookie, report->end_flag);
					/* sepcial handling: remove all cookie for nms*/
					ah_dp_del(AH_CT_HM_CLEAR_COOKIE);
				}

				ah_dp_convert_report_net(report);
				ah_itk_send_event(AH_CAPWAP_EVENT_DHCP_PROBE, cookie,
								  len - sizeof(dhcp_probe_entry_t), (uint8_t *)report);
				ah_memcpy(report, &host, sizeof(host));
			}
		} else {
			ah_err_old("itk-dp: Invalid cookie(%d) found!\n", cookie);
		}
	}
}

void ah_cm_prob_proc_event(uint8_t *buf, int len)
{
	uint8_t    *data = buf + 1;
	int      datalen = len - 1;
	char      *pos = NULL;
	if (*buf) {
		ah_cm_exception_msg_t *prob_msg = (ah_cm_exception_msg_t *)data;
		pos = (char *)((char *)prob_msg + sizeof(ah_cm_exception_msg_t));
		ah_dbg_old(capwap_itk, "ITK: recv CM2.0 %s exception of sta %m on %s, "
				   "module %s, problem id %s, trigger=%s, current step=%d",
				   (prob_msg->module == AH_CM_MOD_80211) ? "Association" :
				   (prob_msg->module == AH_CM_MOD_DHCP || prob_msg->module == AH_CM_MOD_DNS
					|| prob_msg->module == AH_CM_MOD_ARP) ? "Networking" : "Unknown",
				   (char *)&prob_msg->addr, ah_cm_ifindex2info(prob_msg->if_idx),
				   ah_cm_module2name(prob_msg->module),
				   ah_cm_problem_id2str(prob_msg->problem_id),
				   prob_msg->trigger ? "Yes" : "No", prob_msg->current_step);

		ah_cm_remote_detect(prob_msg->if_idx, (uchar *)&prob_msg->addr, prob_msg->module, &prob_msg->bssid,
							prob_msg->current_step, prob_msg->trigger, prob_msg->success, prob_msg->problem_id);

	} else {
		ah_cm_prob_msg_t *prob_msg = (ah_cm_prob_msg_t *)(data + sizeof(int));
		pos = (char *)((char *)prob_msg + sizeof(ah_cm_prob_msg_t));
		char       session_id[AH_CM_SESSION_ID_MAX_LEN] = {0};    /* string type for session id */
		uint      timestamp = ntohl(prob_msg->timestamp);
		time_t time = timestamp;
		/* get session id */
		memcpy(session_id, pos + 1, *pos);

		ah_dbg_old(capwap_itk, "Client Monitor: Send CM2.0 problem to HM(station=%m, "
				   "problem id=%s, timestamp=%s, count=%d, session id=%s, instance id=%d)",
				   &prob_msg->client_mac,
				   ah_cm_problem_id2str(ntohl(prob_msg->problem_id)),
				   ctime((time_t *)&time), ntohl(prob_msg->count),
				   session_id, ntohl(prob_msg->instance_id));

		if (!capwap_itk) {
			ah_log_old(AH_LOG_INFO, "Client Monitor: Send CM2.0 problem to HM(station=%m, "
					   "problem id=%s, timestamp=%s, count=%d, session id=%s, instance id=%d)",
					   &prob_msg->client_mac,
					   ah_cm_problem_id2str(ntohl(prob_msg->problem_id)),
					   ctime((time_t *)&time), ntohl(prob_msg->count),
					   session_id, ntohl(prob_msg->instance_id));
		}

		ah_itk_send_event(AH_CAPWAP_EVENT_CLIENT_MONITOR_PROBLEM,
						  0, datalen, (uint8_t *)data);
	}

}

void ah_itk_proc_event(uint32_t size, void *data)
{
	ct_event_t *event = (ct_event_t *)data;
	/* need check the event_header field */
	ah_dbg_old(capwap_itk, "ITK: receive event(type=%d, len=%d) %d bytes",
			   event->cte_type, event->cte_len, size);
	ah_assert(event);
	ah_assert((event->cte_len + sizeof(ct_event_t)) == size);

	switch (event->cte_type) {
	case AH_ITK_TYPE_CLIENT_TRACE:
		ah_ct_proc_event(event->cte_data, event->cte_len);
		break;

	case AH_ITK_TYPE_DHCP_PROBE:
		ah_dp_proc_event(event->cte_data, event->cte_len);
		break;

	case AH_ITK_TYPE_PCI_ALERT:
		ah_pci_proc_event(event->cte_data, event->cte_len);
		break;

	case AH_ITK_TYPE_CM_PROBLEM:
		ah_cm_prob_proc_event(event->cte_data, event->cte_len);
		break;

	case AH_ITK_TYPE_CM_NOTIFY:
		ah_cm_rpt_proc_event(event->cte_data, event->cte_len);
		break;

	case AH_ITK_TYPE_CM_CONFIG:
		ah_cm_config_proc_event(event->cte_data, event->cte_len);
		break;

	default:
		break;
	}
	return ;
}

void ah_itk_capwap_disconnect(void)
{
#if 0
	ah_itk_total_clear();
#endif
	uint32_t    cookie = AH_CT_HM_CLEAR_COOKIE;
	ah_itk_ct_del(NULL, cookie);
	ah_dp_del(cookie);
	ah_itk_ct_seq = 0;
}
