#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_mpi.h"
#include "ah_event.h"

#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_func.h"
#include "ah_dbg_agent.h"
#include "ah_capwap_api.h"
#include "ah_capwap_hvcom.h"
#include "ah_ipv6_shared.h"

/***************************************************************************
 *
 * Function:  ah_capwap_proc_kevent
 *
 * Purpose:   process box kevent
 *
 * Inputs:    event_id: event id
 *            size: event size
 *            data: event data
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_proc_kevent(ah_kevent_t event_id, uint32_t size, void *data)
{
	ah_kevent_if_change_t *pin =  NULL;
	int           if_type = 0;
	ah_ipaddr46_t portal_ip;

	if (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
		return;
	}

	ah_log_old(AH_LOG_INFO, "CAPWAP receive kevent %s, eventid = %d, size = %d\n", eid2name(event_id), event_id, size);

	switch (event_id) {
	case AH_KEVENT_IF_CHANGE:
		/*interface up kevent only in capwap discovery or sulking state*/
		if ((ah_capwap_info.state != AH_CAPWAP_SULKING) && (ah_capwap_info.state != AH_CAPWAP_DISCOVERY)) {
			return;
		}
		pin = (ah_kevent_if_change_t *)data;
		if ( size != sizeof(ah_kevent_if_change_t)) {
			ah_err_old("CAPWAP receive wrong size in event AH_KEVENT_IF_CHANGE! (size = %d)\n", size);
			return;
		}
		if (AH_KEVENT_IF_UP != pin->kic_type) {
			return;
		}
		if (ah_dcd_get_dev_type(pin->kic_ifindex, (uint32_t *)&if_type) < 0) {
			ah_err_old("CAPWAP get interface type error !(ifindex = %d)\n", pin->kic_ifindex);
			return;
		}
		/*interface must be backhaul*/
		if ((AH_DEV_TYPE_BACKHAUL & if_type) == 0) {
			return;
		}
		/*We should check the AP is portal or not, if AP is portal, wifix up event should be discard*/
		ah_set_ipaddr46_all_zero(&portal_ip);
		portal_ip = ah_amrp_lib_who_is_my_portal();
		if (ah_capwap_is_portal(&portal_ip)
			&& strstr(pin->kic_ifname, AH_IF_RADIO_PREFIX) != NULL) {
			ah_dbg_old(capwap_info, "AP is portal and up interface is wifix, skip this event.");
			return;
		}
		ah_capwap_para.event = AH_CAPWAP_EVENT_INTERFACE_UP;
		ah_log_old(AH_LOG_INFO, "CAPWAP: receive backhaul interface(%s) up event.", pin->kic_ifname);
		ah_capwap_set_chg_ac_flag(AH_CAPWAP_DONT_CHG_AC);
		ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
		break;

	case AH_KEVENT_ITK_NOTIFY:
#if 0
		ah_itk_proc_event(size, data);
#endif
		break;

	default:
		ah_err_old("CAPWAP receive unknown kevent! (event id:%d)\n", event_id);
		break;
	}

	if (ah_capwap_para.event != AH_CAPWAP_EVENT_WAIT) {
		/*second set time out flag*/
		ah_capwap_interrupt_listen();
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_send_event2buf
 *
 * Purpose:   send the event data to capwap event buffer
 *
 * Inputs:    event_type: event type
 *            event_len: event size
 *            event: event data
 *            frag_id: the fixed frag id
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_send_event2buf(uint32_t event_type, uint32_t event_len, char *event, uint frag_id)
{
	int      rc = -1;

	if (ah_capwap_info.state == AH_CAPWAP_RUN && ah_capwap_para.event_flag == AH_CAPWAP_EVENT_SND_ON
		&& ah_capwap_info.event != AH_CAPWAP_CHG_EVENT_SND_PKT && ah_capwap_info.event != AH_CAPWAP_CHG_EVENT_RCV_PKT) {
		rc = ah_capwap_event_save_msg(event_type, event_len, event, frag_id);
	} else { /*if not in run, drop it*/
		ah_capwap_para.event = AH_CAPWAP_EVENT_WAIT;
		ah_capwap_increase_packet_drop_conn_counter();
		if (ah_capwap_info.state != AH_CAPWAP_RUN) {
			ah_capwap_increase_event_packet_counter(AH_CAPWAP_INCREASE_EVENT_DROP_CONN_COUNTER, event_type);
		} else {
			ah_capwap_increase_event_packet_counter(AH_CAPWAP_INCREASE_EVENT_DROP_DSAB_COUNTER, event_type);
		}
		ah_log_old(AH_LOG_WARNING, "CAPWAP: discard event message (type:%d) because CAPWAP status is not RUN or event flag is not enable\n",
				   event_type);
	}
	if (rc != -1) {
		ah_capwap_para.event = event_type;
	}

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_add_event_normal_head
 *
 * Purpose:   add a event head to capwap event buffer
 *
 * Inputs:    event: event data
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_add_event_normal_head(char *event)
{
#define AH_CAPWAP_EVENT_SUB_SEQ 0

	*(uint16_t *)(event + AH_CAPWAP_EVENT_MSG_TOL_FRAG_OFFSET) = htons(1);
	*(uint16_t *)(event + AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET) = htons(1);
	*(uint32_t *)(event + AH_CAPWAP_EVENT_MSG_SEQ_FRAG_OFFSET) = htonl(AH_CAPWAP_EVENT_SUB_SEQ);

	return;
}

typedef struct _ah_capwap_eventid2pkttype_t_s {
	uint16_t    event_id;                 /*aerohive event id*/
	uint16_t    packet_type;              /*CAPWAP protocol TLV type*/
} ah_capwap_eventid2pkttype_t;

static ah_capwap_eventid2pkttype_t ah_capwap_event2type[] = {
	{AH_EVENT_STA_STATS, AH_CAPWAP_EVENT_STATISTICAL},
	{AH_EVENT_CAPWAP_IDP_PUSH, AH_CAPWAP_EVENT_IDP},
	{AH_EVENT_REBOOT_FAILED, AH_CAPWAP_EVENT_REBOOT_FAILED},
	{AH_EVENT_CAPWAP_TRAP, AH_CAPWAP_EVENT_SEND_TRAP},
	{AH_EVENT_PKT_CPT_STAT_RESP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_LOCATION_TRACK_OUT, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_DCD_RESPONE_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_INTERFACE_MAP_OUT, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_VPN_RESP_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_CFG_VER_CHANGED, AH_CAPWAP_EVENT_CFG_VER_CHGED},
	{AH_EVENT_RESP_ACTIVE_WEB_DIR, AH_CAPWAP_EVENT_CWP_DIR},
	{AH_EVENT_HOSTNAME_CHG, AH_CAPWAP_EVENT_HOSTNAME_CHG},
	{AH_EVENT_DCD_MGT0_HIVE_CHG, AH_CAPWAP_EVENT_MGT0_HIVE_CHG},
	{AH_EVENT_RADIUS_TEST_RESPONSE, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_TV_WEBUI_REQ_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_RADIUS_LDAP_TREE_RESP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_RADIUS_AD_RETRIVE_RESP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_RADIUS_QUERY_AD_INFO_RESP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_DCM_SND_PKT, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_VPN_REPORT_RESPONCE_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_L7D_APP_REPORT_READY_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
#ifdef AH_SUPPORT_NAAS
	{AH_EVENT_NAAS_RESPONSE, AH_CAPWAP_EVENT_SEND_RESPONSE},
#endif
#if defined(AH_SUPPORT_IDP)
	{AH_EVENT_IDP_AP_CLF_DA_SEND, AH_CAPWAP_EVENT_SEND_RESPONSE},
#endif
#ifdef AH_SUPPORT_PSE
	{AH_EVENT_PSE_INFO_REPORT_RESPOND, AH_CAPWAP_EVENT_SEND_RESPONSE},
#endif
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	{AH_EVENT_BGD_RESP_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
#endif
	{AH_EVENT_OTP_RESPONCE_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
#ifdef AH_SUPPORT_RADSEC
	{AH_EVENT_RADSEC_CERT_CREATION_RESP, AH_CAPWAP_EVENT_SEND_RESPONSE},
#endif
	{AH_EVENT_L7D_RESPONSE_CAPWAP, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_L7D_SIGNATURE_VERSION_NOTIFY, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_CAPWAP_RESPONSE_USBNET_STATUS, AH_CAPWAP_EVENT_SEND_RESPONSE},
	{AH_EVENT_RADSEC_PROXY_INFO_RESP, AH_CAPWAP_EVENT_SEND_RESPONSE},
};

static uint ah_capwap_eventid2type_num = sizeof(ah_capwap_event2type) / sizeof(ah_capwap_event2type[0]);

/***************************************************************************
 *
 * Function:  ah_capwap_get_type_from_eventid
 *
 * Purpose:   get CAPWAP protocol TLV type id from aerohive event id
 *
 * Inputs:    event_id: event id
 *
 * Output:    void
 *
 * Returns:   CAPWAP protocol TLV type id
 *
 **************************************************************************/
static inline int ah_capwap_get_type_from_eventid(uint16_t event_id)
{
	int      i = 0;

	for (i = 0; i < ah_capwap_eventid2type_num; i ++) {
		if (event_id == ah_capwap_event2type[i].event_id) {
			return ah_capwap_event2type[i].packet_type;
		}
	}
	ah_log_old(AH_LOG_ERR, "CAPWAP: can not get CAPWAP event TLV type from event (%s).", ah_eventid_to_name(event_id));

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_server_change_by_cli
 *
 * Purpose:   handle capwap server changed by CLI
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
static void ah_capwap_server_change_by_cli()
{
	/*set ac priority*/
	ah_capwap_info.acpri = AH_CAPWAP_GET_AC_MANUAL;
	/*first set event rcv flag*/
	ah_capwap_para.event = AH_CAPWAP_EVENT_NMS_IP_CHGD;
	ah_capwap_set_reconnect_reason(AH_CAPWAP_RECONNECT_HM_IP_CHANGED);
	ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
	ah_capwap_set_reconnect_schedule(AH_CAPWAP_RECONNECT_NOW);
	ah_dbg_old(capwap_ha, "nms name changed, set current choose to Initial");

	return;
}

static ah_ptimer_t *ah_capwap_mp_portal_timer = NULL;

/***************************************************************************
 *
 * Function:  ah_capwap_handle_mp_portal_timer
 *
 * Purpose:   handle CAPWAP MP Portal timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static void ah_capwap_handle_mp_portal_timer(ah_ptimer_t *timername, void *timerparameter)
{
	char      event_info[100];
	uint32_t    event_len = 0;

	/*because this event is not called the ah_capwap_send_event, so we need fill the head to the event information manully*/
	ah_capwap_add_event_normal_head(event_info);
	*(char *)(event_info + AH_CAPWAP_EVENT_MSG_START) = (char)(ah_capwap_para.portal_info);
	event_len = AH_CAPWAP_EVENT_MSG_START + sizeof(char);
	ah_capwap_send_event2buf(AH_CAPWAP_EVENT_PORT, event_len, event_info, AH_CAPWAP_FRAG_NUM_INVALID);
	ah_log_old(AH_LOG_INFO, "CAPWAP send MP-Portal information:%s", ah_capwap_para.portal_info ? "Portal" : "MP");

	ah_capwap_interrupt_listen();

	if (ah_capwap_mp_portal_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_mp_portal_timer);
		ah_capwap_mp_portal_timer = NULL;
	}

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_mp_portal_timer
 *
 * Purpose:   set CAPWAP MP Portal timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static int ah_capwap_set_mp_portal_timer(void)
{
#define AH_CAPWAP_MP_PORTAL_TIMER_INTVAL (5)

	if (ah_capwap_mp_portal_timer != NULL) {
		/*Timer is running*/
		return 0;
	}

	ah_capwap_mp_portal_timer = ah_pmpt_timer_create(ah_capwap_handle_mp_portal_timer, NULL);
	if (ah_capwap_mp_portal_timer == NULL) {
		ah_err_old("CAPWAP create MP Portal timer failed!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "CAPWAP start MP Portal timer %d second\n", AH_CAPWAP_MP_PORTAL_TIMER_INTVAL);
	ah_pmpt_timer_start(ah_capwap_mp_portal_timer, AH_CAPWAP_MP_PORTAL_TIMER_INTVAL);

	return 0;
}

void ah_capwap_exec_delta_cfg(void *data)
{

	FILE *fp = NULL;
	char *buf = NULL;
	char *ptr;
	char *fname;
	struct stat st;
	size_t len = 0;
	ssize_t read;
	uint32_t cnt;
	char *line = NULL;
	uint8_t cond;
	uint16_t line_num;
	uint32_t    seq_num;

	fname = (char *)data;
	ah_dbg_old(capwap_cli, "CAPWAP: exec cli from file %s", fname);
	fp = fopen(fname, "r");
	if (!fp) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: open file %s failed!\n", fname);
		goto OUT;
	}

	if (fstat(fileno(fp), &st) < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: exec fstat(%s) failed!\n", fname);
		goto OUT;
	}

	buf = (char *)calloc(st.st_size + sizeof(seq_num), 1);
	if (!buf) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: malloc memory for delta-cfg file read, size %d failed\n", st.st_size + sizeof(seq_num));
		goto OUT;
	}
	ptr = buf;

	cond = 0;
	line_num = 0;
	while (cond != 3 && (read = getline(&line, &len, fp)) != -1) {
		ah_dbg_old(capwap_cli, "parse delta config: line: %4d :%s", line_num, line);
		line_num++;
		if (0 == cond) {
			if (line[0] != '0') {
				ah_log_old(AH_LOG_ERR, "CAPWAP: delat-conf file transmitted by HM failed!\n"
						   "reason: %s", line);
				break;
			}
			cond++;
		} else if (1 == cond) {
			seq_num = atoi(line);
			*((uint32_t *)ptr) = seq_num;
			cond++;
		} else if (2 == cond) {
			if (strncmp(line, "=====", 5) == 0) {
				cond++;
				break;
			}
		}
	}
	if (cond != 3) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: format of delat-conf file is wrong!\n");
		goto OUT;
	}

	cnt = 0;
	ptr = buf + sizeof(seq_num);
	while ((read = getline(&line, &len, fp)) != -1) {
		ah_dbg_old(capwap_cli, "exec getline from file %s :%s", fname, line);
		if (strncmp(line, "=====", 5) == 0) {
			continue;
		}
		ah_strncpy(ptr, line, read);
		ptr += read;
		cnt += read;
	}

	ah_capwap_cli_ui_rcv_data(buf, sizeof(seq_num) + cnt);

OUT:
	if (line) {
		free(line);
	}
	if (buf) {
		free(buf);
	}
	if (fp) {
		fclose(fp);
	}

	unlink(fname);
}

/**
 * @brief put device IPV6 global/link local address info to trap message
 * @param[in] trap_data buffer to be filled
 * @param[out] addr6_num address number
 * @return filled buffer length.
 * @note
 */
static int ah_capwap_trap_add_dev_ipv6(ah_capwap_device_ip_change_data_t *trap_data, uint8_t *addr6_num)
{
	uint8_t i;
	int ret_data_len = 0;
	ah_if_ipv6_addr_t global_if_ipv6_addr;
	struct in6_addr wtp_gw_ipv6;
	struct in6_addr local_ipv6_addr;

	/* One device one IPV6 default gateway, get it one time */
	if (ah_dcd_get_default_gw_byname_ipv6(AH_CAPWAP_MGT, &wtp_gw_ipv6) != 0) {
		ipv6_addr_set_to_any(&wtp_gw_ipv6);
		ah_dbg_old(capwap_trap, "CAPWAP:get device IPV6 default gateway failed!\n");
	}

	/* begin: add device global IPV6 address info */
	for (i = 0; i < AH_MGT0_GLOBAL_ADDR6_NUM_MAX; i++) {
		trap_data->item_length = sizeof(ah_capwap_device_ip_change_data_t);
		trap_data->ipv6_addr_type = STATION_IPV6_GLOBAL_ADDRES;

		/* fill ipv6 global IP address */
		if (ah_get_if_ipv6_global_addrs_by_name(default_hvi_name(), &global_if_ipv6_addr) != 0) {
			ah_dbg_old(capwap_trap, "CAPWAP: get device IPV6 global address failed.\n");
			break;
		}
		ipv6_addr_copy(&trap_data->ipv6_addr, &global_if_ipv6_addr.ipv6_addr);

		/* fill ipv6 global address prefix */
		trap_data->ipv6_prefix = htonl(global_if_ipv6_addr.pfxlen);

		/* fill IPV6 global IP address default gateway */
		ipv6_addr_copy(&trap_data->ipv6_default_gateway, &wtp_gw_ipv6);

		ah_dbg_old(capwap_trap, "Device IP change trap: IPV6:%pI6c/%d, default gateway:%pI6c",
				   &trap_data->ipv6_addr, global_if_ipv6_addr.pfxlen, &trap_data->ipv6_default_gateway);

		/* offset a structure size */
		ret_data_len += trap_data->item_length;
		trap_data ++;
		*addr6_num += 1;
	}
	/* end: add device global IPV6 address info */

	/* begin: add device link local IPV6 address info, only 1 local addr, no need loop */
	trap_data->item_length = sizeof(ah_capwap_device_ip_change_data_t);
	trap_data->ipv6_addr_type = STATION_IPV6_LOCAL_ADDRES;

	/*fill link local address */
	if (ah_tpa_get_mgt0_link_local(&local_ipv6_addr) != 0) {
		ah_dbg_old(capwap_trap, "CAPWAP: get device local IPV6 address from SCD failed.\n");
		return ret_data_len;
	}
	ipv6_addr_copy(&trap_data->ipv6_addr, &local_ipv6_addr);

	/* fill link local address prefix len: 64 */
	trap_data->ipv6_prefix = htonl(IPV6_LINK_LOCAL_ADDR_PREFIX_LEN);

	/* fill link local address default gateway */
	ipv6_addr_copy(&trap_data->ipv6_default_gateway, &wtp_gw_ipv6);

	/* linklocal address has the fixed length prefix, not the same as global address */
	ah_dbg_old(capwap_trap, "Device IP change trap: IPV6:%pI6c/%d, default gateway:%pI6c",
			   &trap_data->ipv6_addr, IPV6_LINK_LOCAL_ADDR_PREFIX_LEN, &trap_data->ipv6_default_gateway);

	/* offset a structure size */
	ret_data_len += trap_data->item_length;
	*addr6_num += 1;

	return ret_data_len;
}

/**
 * @brief Put device IPV4 address info to trap message
 * @param[in] trap buffer to be filled
 * @param[out] NULL
 * @return 0 is success, -1 is failed
 * @note
 */
static int ah_capwap_trap_add_dev_ipv4(ah_capwap_device_ip_change_trap_t *trap)
{
	uint wtp_mask = 0;
	uint wtp_ip = 0;
	uint wtp_gateway = 0;

	/*get WTP IP/GATEWAY from dcd*/
	if (ah_dcd_get_addr_byname(AH_CAPWAP_MGT, (uint *)&wtp_ip, (uint *)&wtp_mask) < 0) {
		ah_dbg_old(capwap_trap, "CAPWAP:Get IP/mask from DCD error!\n");
		return -1;
	}
	/*wtp_ip is network order*/
	trap->ipv4_addr = wtp_ip;
	/*wtp_mask is network order*/
	trap->ipv4_netmask = wtp_mask;

	/*get WTP GATEWAY from dcd*/
	(void)ah_dcd_get_default_gw_byname(AH_CAPWAP_MGT, (uint *)&wtp_gateway);
	/*wtp_gateway is network order*/
	trap->ipv4_default_gateway = wtp_gateway;
	ah_dbg_old(capwap_trap, "Device IP change trap: IPV4:%i/%i, default gateway:%i",
			   trap->ipv4_addr, trap->ipv4_netmask, trap->ipv4_default_gateway);
	return 0;
}

/**
 * @brief If AP and HM to establish a IPV4 connection, send trap to HM only when IPV6 address changes
 *        If AP and HM to establish a IPV6 connection, send trap to HM only when IPV4 address changes
 * @param[in] null
 * @param[out] null
 * @return null
 * @note
 */
static void ah_capwap_send_dev_ip_change_trap()
{
	/* For hm display need update dev IP address info */
	int rc = 0;
	int data_max_len ;
	int data_len ;
	int max_size;
	int size;
	uint8_t addr6_num = 0;
	ah_capwap_device_ip_change_trap_t *trap = NULL;

	data_max_len = sizeof(ah_capwap_device_ip_change_data_t) * AH_MGT0_ADDR6_NUM_MAX;
	max_size = sizeof(ah_capwap_device_ip_change_trap_t) + data_max_len;
	trap = ah_malloc(max_size);
	if (trap == NULL) {
		ah_err_old("Send device IP change trap to hm malloc failed.\n");
		goto out;
	}
	memset(trap, 0, max_size);
	trap->trap_type = AH_CAPWAP_DEVICE_IP_CHANGE_TRAP_TYPE;
	(void)ah_capwap_trap_add_dev_ipv4(trap);
	data_len = ah_capwap_trap_add_dev_ipv6((ah_capwap_device_ip_change_data_t *)trap->data, &addr6_num);
	size = sizeof(ah_capwap_device_ip_change_trap_t) + data_len;
	trap->data_len = htons(size - 3); /* first struct three bytes */
	trap->ipv6_addr_num = addr6_num;

	ah_dbg_old(capwap_trap, "send trap(AH_MSG_TRAP_DEV_IP_CHANGE) immediately (size:%d, data len:%d, ipv6_addr_num:%d)", size, data_len,
			   addr6_num);
	rc = ah_capwap_send_trap(size, trap, AH_MSG_TRAP_DEV_IP_CHANGE);
	ah_dbg_old(capwap_trap, "CAPWAP send device IP trap to Capwap %s", rc ? "failed" : "successfully");
out:
	if (trap != NULL) {
		ah_free(trap);
	}
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_proc_event
 *
 * Purpose:   process box event
 *
 * Inputs:    event_id: event id
 *            size: event size
 *            data: event data
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_proc_event(ah_event_t event_id, uint32_t size, void *data)
{
	struct timeval cli_srv_timer = {3, 0};
	int      dw_img_rst = -1;

	if (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
		return;
	}

	ah_log_old(AH_LOG_INFO, "receive event %s: eventid = %d: length = %d\n", ah_eventid_to_name(event_id), event_id, size);

	switch (event_id) {
	case AH_EVENT_NMSSVR_CHG:
		ah_log_old(AH_LOG_INFO, "CAPWAP_HM: receive HM's IP changed by DHCP!\n");
		/*set ac priority*/
		ah_capwap_info.acpri = AH_CAPWAP_GET_AC_DHCP;
		/*first set event rcv flag*/
		ah_capwap_para.event = AH_CAPWAP_EVENT_NMS_IP_CHGD;
		ah_capwap_set_reconnect_reason(AH_CAPWAP_RECONNECT_HM_IP_CHANGED);
		ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
		ah_capwap_set_reconnect_schedule(AH_CAPWAP_RECONNECT_NOW);
		ah_dbg_old(capwap_ha, "nms name changed, set current choose to Initial");
		break;
	case AH_EVENT_NMSSVR_CHG_MANUAL:
		ah_log_old(AH_LOG_INFO, "CAPWAP_HM receive HM's IP changed by CLI!\n");
		ah_capwap_server_change_by_cli();
		break;
	case AH_EVENT_IP_CHANGE:
		capwap_mgt0_ip = ((ah_event_data_ip_chg_t *)data)->ip_addr;
		ah_log_old(AH_LOG_INFO, "CAPWAP receive box ip changed event! now mgt0 ip:%i\n", capwap_mgt0_ip);
		/*first set event rcv flag*/
		ah_capwap_para.event = AH_CAPWAP_EVENT_HOST_IP_CHGD;
		ah_capwap_set_reconnect_reason(AH_CAPWAP_RECONNECT_HOST_IP_CHANGED);
		/*need find HM from initial work flow*/
		ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
		break;
	case AH_EVENT_IPV6_CHANGE:
		{
			ah_log_old(AH_LOG_INFO, "event %s(%d) received\n", ah_eventid_to_name(event_id), event_id);
			if (sizeof(ah_event_data_ipv6_chg_t) != size) {
				ah_err_old("ERROR: Wrong size of data for event (%s)",
						   ah_eventid_to_name(event_id));
				break;
			}
			capwap_mgt0_ipv6.af = AF_INET6;
			memcpy(&capwap_mgt0_ipv6.u_ipv6_addr, &((ah_event_data_ipv6_chg_t *)data)->ipv6_addr,
				   sizeof(struct in6_addr));
			ah_dbg_old(capwap_ha, "update capwap mgt0 IPv6 address to %pI46c", &capwap_mgt0_ipv6);
			ah_capwap_send_dev_ip_change_trap();
			break;
		}
	case AH_EVENT_SYS_READY:
		ah_log_old(AH_LOG_INFO, "CAPWAP receive system ready event!\n");
		break;
	case AH_EVENT_CAPWAP_IDP_PUSH_ALL:
		ah_log_old(AH_LOG_INFO, "CAPWAP receive IDP push all event!\n");
		if (ah_capwap_info.state == AH_CAPWAP_RUN) {
			ah_capwap_para.event = AH_CAPWAP_EVENT_IDP;
			ah_capwap_event_save_msg(AH_CAPWAP_EVENT_IDP, size, (char *)data, AH_CAPWAP_FRAG_NUM_INVALID);
		} else { /*if not in run ,only save it*/
			//ah_capwap_event_save_msg(AH_CAPWAP_EVENT_IDP, size, (char *)data);
			return;
		}
		break;
	case AH_EVENT_AMRP_PORTAL_CHG:
		if (size != sizeof(ah_ipaddr46_t) || data == NULL) {
			ah_err_old("CAPWAP receive an error portal changed event!(event size:%d)\n", size);
			return;
		}
		ah_log_old(AH_LOG_INFO, "CAPWAP receive portal changed event! current portal ip:%pI46c\n", (ah_ipaddr46_t *)(data));

		/*set portal info */
		if (ah_capwap_is_portal((ah_ipaddr46_t * )data)) {
			ah_capwap_para.portal_info = AH_CAPWAP_IS_PORT;
		} else {
			ah_capwap_para.portal_info = AH_CAPWAP_NOT_PORT;
		}

		ah_capwap_set_mp_portal_timer();
		return;
	case AH_EVENT_PPSK_SELF_REG_INFO_CAPWAP:
		if (ah_capwap_send_trap(size, data, AH_MSG_TRAP_SELF_REG_INFO) < 0) {
			ah_err_old("%s: Capwap send trap failed.", __func__);
		}
		return;
	case AH_EVENT_STATISTICAL_RECV_DCD:
		ah_dbg_old(capwap_stat, "CAPWAP receive dcd collection finish event! (pdata = %x)\n", data);
		if (NULL != data) {
			ah_capwap_stat_recv_dcd_data((ah_dcd_finish_colletction_event_t *)data);
		}
		break;
	case AH_EVENT_CM_SHOW_INFO:
		ah_dbg_old(capwap_stat, "CAPWAP receive event %s(%d) received\n",
				   ah_eventid_to_name(event_id), event_id);
		ah_cm_dump_data(AH_CM_CAPWAP_SHOW_FILE, TRUE);
		break;
	case AH_EVENT_STATISTICAL_RECV_AMRP:
		ah_dbg_old(capwap_stat, "CAPWAP receive amrp collection finish event! (pdata = %x)\n", data);
		if (NULL != data) {
			ah_capwap_stat_recv_amrp_data(size, (ah_amrp_finish_colletction_event_t *)data);
		}
		break;
	case AH_EVENT_STATISTICAL_RECV_AUTH:
		ah_dbg_old(capwap_stat, "CAPWAP receive auth collection finish event! (pdata = %x)\n", data);
		if (NULL != data) {
			ah_capwap_stat_recv_auth_data((ah_auth_finish_colletction_event_t *)data);
		}
		break;
	/*in this part, CAPWAP receive the event send by API ah_event_send*/
	case AH_EVENT_CAPWAP_HTTP_GET_DELTA_CFG:
		ah_log_old(AH_LOG_INFO, "CAPWAP receive delta config download finish event!\n");
		if (NULL != data) {
			ah_capwap_exec_delta_cfg(data);
		}
		break;
	case AH_EVENT_CFG_VER_CHANGED:
	case AH_EVENT_RESP_ACTIVE_WEB_DIR:
	case AH_EVENT_HOSTNAME_CHG:
	case AH_EVENT_DCD_MGT0_HIVE_CHG:
		ah_log_old(AH_LOG_INFO, "CAPWAP receive %s event!\n", ah_eventid_to_name(event_id));
		ah_capwap_send_event_itself(size, data, ah_capwap_get_type_from_eventid(event_id));
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
		if (event_id == AH_EVENT_DCD_MGT0_HIVE_CHG) {
			ah_capwap_handle_hive_chg_4_bonjour();
		}
#endif
		break;
	/*In this part, CAPWAP receive the aerohive event and sent to HM (ah_capwap_send_event or ah_capwap_send_event_payload)*/
	case AH_EVENT_CAPWAP_IDP_PUSH:
	case AH_EVENT_STA_STATS:
	case AH_EVENT_REBOOT_FAILED:
	case AH_EVENT_CAPWAP_TRAP:
	case AH_EVENT_PKT_CPT_STAT_RESP:
	case AH_EVENT_LOCATION_TRACK_OUT:
	case AH_EVENT_DCD_RESPONE_CAPWAP:
	case AH_EVENT_INTERFACE_MAP_OUT:
	case AH_EVENT_VPN_RESP_CAPWAP:
	case AH_EVENT_RADIUS_TEST_RESPONSE:
	case AH_EVENT_TV_WEBUI_REQ_CAPWAP:
	case AH_EVENT_RADIUS_LDAP_TREE_RESP:
	case AH_EVENT_RADIUS_AD_RETRIVE_RESP:
	case AH_EVENT_RADIUS_QUERY_AD_INFO_RESP:
	case AH_EVENT_DCM_SND_PKT:
	case AH_EVENT_RADSEC_PROXY_INFO_RESP:
#ifdef AH_SUPPORT_NAAS
	case AH_EVENT_NAAS_RESPONSE:
#endif
	case AH_EVENT_VPN_REPORT_RESPONCE_CAPWAP:
	case AH_EVENT_L7D_APP_REPORT_READY_CAPWAP:
	case AH_EVENT_OTP_RESPONCE_CAPWAP:
#if defined(AH_SUPPORT_IDP)
	case AH_EVENT_IDP_AP_CLF_DA_SEND:
#endif
#ifdef AH_SUPPORT_PSE
	case AH_EVENT_PSE_INFO_REPORT_RESPOND:
#endif
#ifdef AH_SUPPORT_RADSEC
	case AH_EVENT_RADSEC_CERT_CREATION_RESP:
#endif
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	case AH_EVENT_BGD_RESP_CAPWAP:
#endif

	case AH_EVENT_L7D_RESPONSE_CAPWAP:
	case AH_EVENT_L7D_SIGNATURE_VERSION_NOTIFY:
#ifdef AH_SUPPORT_MULTIWAN
	case AH_EVENT_CAPWAP_RESPONSE_USBNET_STATUS:
#endif

		ah_log_old(AH_LOG_INFO, "CAPWAP: receive %s event!, length:%d\n", ah_eventid_to_name(event_id), size);
		ah_capwap_send_event2buf(ah_capwap_get_type_from_eventid(event_id), size, (char *)data, AH_CAPWAP_FRAG_NUM_INVALID);
		break;
	case AH_EVENT_CLI_SRV_RESTART:
		ah_log_old(AH_LOG_INFO, "CAPWAP receive cli server restart event\n");
		/*waitting for CLI server ok*/
		while (select(0, NULL, NULL, NULL, &cli_srv_timer) != 0) {
		}
		ah_capwap_cli_ui_restart();
		break;
	case AH_EVENT_ITK_NOTIFY:
		ah_itk_proc_event(size, data);
		break;
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	case AH_EVENT_BGD_SERVICE_INFO:
		ah_capwap_handle_bonjour_notify(data);
		break;
#endif
	case AH_EVENT_CAPWAP_DISCONNECT:
		ah_itk_capwap_disconnect();
		break;
	case AH_EVENT_DWIMG_COMPLETE:
		dw_img_rst = *(int *)data;
		if (ah_capwap_hvcom_chkres_portal_by_time()) {
			if (ah_capwap_hvcom_snd_res(0, AH_CAPWAP_HVCOM_MSG_DOWNIMG, dw_img_rst, 0, NULL) < 0) {
				ah_dbg_old(capwap_hvcom, "capwap HiveComm receive download image complete event but send to hm failed.\n");
			}
		}
		break;
	default:
		ah_err_old("CAPWAP receive an unknown event (event id is %d)!\n", event_id);
		break;
	}

	if (ah_capwap_para.event != AH_CAPWAP_EVENT_WAIT) {
		/*second set time out flag*/
		ah_capwap_interrupt_listen();
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_send_event_itself
 *
 * Purpose:   capwap send event to capwap module
 *
 * Inputs:    event_id: event id
 *            event_len: event size
 *            event_msg:data
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_send_event_itself(uint32_t event_len, const char *event_msg, uint32_t event_id)
{
	char      msg[AH_CAPWAP_EVENT_MAX_LEN + 100] = {0};
	int      pkt_int;
	int      pkt_del;
	int      i = 0;
	int      cpy_pkt_len = 0;
	int      snd_len = 0;
	uint32_t    sub_seq = 0;
	struct timeval tv;
	struct timezone tz;

	ah_dbg_old(capwap_info, "Receive capwap event itself, length(%d), event_id(%d)\n", event_len, event_id);
	/*add lock for other thread call it*/

	/*no message information need send*/
	if (event_len > AH_CAPWAP_EVENT_MAX_LEN * AH_CAPWAP_NORMAL_EVENT_MAX_PKT) {
		ah_err_old("CAPWAP:Send buffer length is error!current len:(%d) max len:(%d)", event_len,
				   (AH_CAPWAP_EVENT_MAX_LEN * AH_CAPWAP_NORMAL_EVENT_MAX_PKT));

		return;
	}

	/*generate the rand sub_seq*/
	gettimeofday(&tv, &tz);
	srand(tv.tv_sec + tv.tv_usec);
	sub_seq = 1 + (int)(AH_CAPWAP_EVENT_MAX_RAND * rand() / (RAND_MAX + 1.0));

	/*need fragment the message*/
	pkt_int = event_len / AH_CAPWAP_EVENT_MAX_LEN;
	pkt_del = event_len % AH_CAPWAP_EVENT_MAX_LEN;

	/*calculator the total packet need send*/
	if (pkt_del != 0) {
		pkt_int ++;
	}
	/*no event message, only need add cur_msg/total_msg*/
	if (pkt_del == 0 && pkt_int == 0) {
		pkt_int = 1;
	}

	/*add total_msg/cur_msg*/
	*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_TOL_FRAG_OFFSET) = htons((uint16_t)(pkt_int));

	/*add sub_seq*/
	*(uint32_t *)(msg + AH_CAPWAP_EVENT_MSG_SEQ_FRAG_OFFSET) = htonl(sub_seq);

	cpy_pkt_len = AH_CAPWAP_EVENT_MAX_LEN;
	for (i = 0; i < pkt_int; i++) {
		*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET) = htons((uint16_t)(i + 1));
		/*copy message*/
		if (i == (pkt_int - 1)) { /*the last part*/
			cpy_pkt_len = pkt_del ? pkt_del : AH_CAPWAP_EVENT_MAX_LEN;
			memcpy((msg + AH_CAPWAP_EVENT_MSG_START), (event_msg + (i * AH_CAPWAP_EVENT_MAX_LEN)), cpy_pkt_len);
			snd_len = cpy_pkt_len + AH_CAPWAP_EVENT_MSG_START;
		} else { /*not the last part*/
			memcpy((msg + AH_CAPWAP_EVENT_MSG_START), (event_msg + (i * AH_CAPWAP_EVENT_MAX_LEN)), AH_CAPWAP_EVENT_MAX_LEN);
			snd_len = cpy_pkt_len + AH_CAPWAP_EVENT_MSG_START;
		}

		ah_capwap_send_event2buf(event_id, snd_len, msg, AH_CAPWAP_FRAG_NUM_INVALID);
		ah_dbg_old(capwap_info, "Send capwap event itself send to buff: total:%d current:%d seq_num:%d length:%d\n",
				   ntohs(*(uint16_t *)(msg)), ntohs(*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET)), sub_seq, snd_len);
	}

	/*interrupt the capwap loop to deal with event*/
	if (ah_capwap_para.event != AH_CAPWAP_EVENT_WAIT) {
		ah_capwap_interrupt_listen();
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_ini_eventlist
 *
 * Purpose:   capwap event initial
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int  ah_capwap_ini_eventlist()
{
	pthread_t event_tid;

	if (ah_event_init(AH_MOD_ID_CAPWAP, &event_tid) < 0) {
		ah_event_cleanup();
		sleep(2);
		if (ah_event_init(AH_MOD_ID_CAPWAP, &event_tid) < 0) {
			ah_err_old("CAPWAP initial event failed\n");
			return -1;
		}
	}
#if 0
	if (ah_pthread_setschedparam(event_tid, SCHED_RR, AH_PRIORITY_MGT) != 0) {
		ah_err_old("CAPWAP set event thread priority failed");
		return -1;
	}
#endif
	/* subscribe to some events */
	ah_event_subscribe(AH_EVENT_NMSSVR_CHG, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_NMSSVR_CHG_MANUAL, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_IP_CHANGE, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_SYS_READY, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CAPWAP_HTTP_GET_DELTA_CFG, ah_capwap_proc_event);
#if defined(AH_SUPPORT_IDP)
	ah_event_subscribe(AH_EVENT_CAPWAP_IDP_PUSH, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CAPWAP_IDP_PUSH_ALL, ah_capwap_proc_event);
#endif
	ah_event_subscribe(AH_EVENT_AMRP_PORTAL_CHG, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_STATISTICAL_RECV_DCD, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_STATISTICAL_RECV_AMRP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_STATISTICAL_RECV_AUTH, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_REBOOT_FAILED, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CAPWAP_TRAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CFG_VER_CHANGED, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_RESP_ACTIVE_WEB_DIR, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_HOSTNAME_CHG, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CLI_SRV_RESTART, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_PKT_CPT_STAT_RESP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_LOCATION_TRACK_OUT, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_ITK_NOTIFY, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CAPWAP_DISCONNECT, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_STA_STATS, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_DCD_RESPONE_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_CM_SHOW_INFO, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_DWIMG_COMPLETE, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_INTERFACE_MAP_OUT, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_DCD_MGT0_HIVE_CHG, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_VPN_RESP_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_RADIUS_TEST_RESPONSE, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_TV_WEBUI_REQ_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_RADIUS_LDAP_TREE_RESP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_RADIUS_AD_RETRIVE_RESP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_RADIUS_QUERY_AD_INFO_RESP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_DCM_SND_PKT, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_PPSK_SELF_REG_INFO_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_IPV6_CHANGE, ah_capwap_proc_event);
#ifdef AH_SUPPORT_NAAS
	ah_event_subscribe(AH_EVENT_NAAS_RESPONSE, ah_capwap_proc_event);
#endif
	ah_event_subscribe(AH_EVENT_VPN_REPORT_RESPONCE_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_L7D_APP_REPORT_READY_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_L7D_RESPONSE_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_L7D_SIGNATURE_VERSION_NOTIFY, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_OTP_RESPONCE_CAPWAP, ah_capwap_proc_event);
#if defined(AH_SUPPORT_IDP)
	ah_event_subscribe(AH_EVENT_IDP_AP_CLF_DA_SEND, ah_capwap_proc_event);
#endif
#ifdef AH_SUPPORT_PSE
	ah_event_subscribe(AH_EVENT_PSE_INFO_REPORT_RESPOND, ah_capwap_proc_event);
#endif

#ifdef AH_SUPPORT_RADSEC
	ah_event_subscribe(AH_EVENT_RADSEC_CERT_CREATION_RESP, ah_capwap_proc_event);
#endif
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	ah_event_subscribe(AH_EVENT_BGD_RESP_CAPWAP, ah_capwap_proc_event);
	ah_event_subscribe(AH_EVENT_BGD_SERVICE_INFO, ah_capwap_proc_event);
#endif
#ifdef AH_SUPPORT_MULTIWAN
	ah_event_subscribe(AH_EVENT_CAPWAP_RESPONSE_USBNET_STATUS, ah_capwap_proc_event);
#endif
	ah_event_subscribe(AH_EVENT_RADSEC_PROXY_INFO_RESP, ah_capwap_proc_event);

	/*kernal event*/
	ah_kevent_subscribe(AH_KEVENT_IF_CHANGE, ah_capwap_proc_kevent);
#if defined(AH_SUPPORT_IDP)
	ah_kevent_subscribe(AH_KEVENT_IDP_STA, ah_capwap_proc_kevent);
#endif
	ah_kevent_subscribe(AH_KEVENT_ITK_NOTIFY, ah_capwap_proc_kevent);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_delete_eventlist
 *
 * Purpose:   capwap event clean
 *
 **************************************************************************/
void ah_capwap_delete_eventlist()
{
	/* unsubscribe from the events */
	ah_event_unsubscribe(AH_EVENT_NMSSVR_CHG);
	ah_event_unsubscribe(AH_EVENT_NMSSVR_CHG_MANUAL);
	ah_event_unsubscribe(AH_EVENT_IP_CHANGE);
	ah_event_unsubscribe(AH_EVENT_SYS_READY);
	ah_event_unsubscribe(AH_EVENT_CAPWAP_HTTP_GET_DELTA_CFG);
#if defined(AH_SUPPORT_IDP)
	ah_event_unsubscribe(AH_EVENT_CAPWAP_IDP_PUSH);
	ah_event_unsubscribe(AH_EVENT_CAPWAP_IDP_PUSH_ALL);
#endif
	ah_event_unsubscribe(AH_EVENT_AMRP_PORTAL_CHG);
	ah_event_unsubscribe(AH_EVENT_REBOOT_FAILED);
	ah_event_unsubscribe(AH_EVENT_STATISTICAL_RECV_DCD);
	ah_event_unsubscribe(AH_EVENT_STATISTICAL_RECV_AMRP);
	ah_event_unsubscribe(AH_EVENT_STATISTICAL_RECV_AUTH);
	ah_event_unsubscribe(AH_EVENT_CAPWAP_TRAP);
	ah_event_unsubscribe(AH_EVENT_CFG_VER_CHANGED);
	ah_event_unsubscribe(AH_EVENT_RESP_ACTIVE_WEB_DIR);
	ah_event_unsubscribe(AH_EVENT_HOSTNAME_CHG);
	ah_event_unsubscribe(AH_EVENT_CLI_SRV_RESTART);
	ah_event_unsubscribe(AH_EVENT_PKT_CPT_STAT_RESP);
	ah_event_unsubscribe(AH_EVENT_LOCATION_TRACK_OUT);
	ah_event_unsubscribe(AH_EVENT_ITK_NOTIFY);
	ah_event_unsubscribe(AH_EVENT_CAPWAP_DISCONNECT);
	ah_event_unsubscribe(AH_EVENT_STA_STATS);
	ah_event_unsubscribe(AH_EVENT_DCD_RESPONE_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_DWIMG_COMPLETE);
	ah_event_unsubscribe(AH_EVENT_INTERFACE_MAP_OUT);
	ah_event_unsubscribe(AH_EVENT_DCD_MGT0_HIVE_CHG);
	ah_event_unsubscribe(AH_EVENT_VPN_RESP_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_RADIUS_TEST_RESPONSE);
	ah_event_unsubscribe(AH_EVENT_TV_WEBUI_REQ_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_RADIUS_LDAP_TREE_RESP);
	ah_event_unsubscribe(AH_EVENT_RADIUS_AD_RETRIVE_RESP);
	ah_event_unsubscribe(AH_EVENT_RADIUS_QUERY_AD_INFO_RESP);
	ah_event_unsubscribe(AH_EVENT_DCM_SND_PKT);
	ah_event_unsubscribe(AH_EVENT_PPSK_SELF_REG_INFO_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_IPV6_CHANGE);
	ah_event_unsubscribe(AH_EVENT_L7D_SIGNATURE_VERSION_NOTIFY);
	ah_event_unsubscribe(AH_EVENT_L7D_RESPONSE_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_CM_SHOW_INFO);
#ifdef AH_SUPPORT_NAAS
	ah_event_unsubscribe(AH_EVENT_NAAS_RESPONSE);
#endif
	ah_event_unsubscribe(AH_EVENT_VPN_REPORT_RESPONCE_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_L7D_APP_REPORT_READY_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_OTP_RESPONCE_CAPWAP);
#if defined(AH_SUPPORT_IDP)
	ah_event_unsubscribe(AH_EVENT_IDP_AP_CLF_DA_SEND);
#endif
	/*kernal event*/
	ah_kevent_unsubscribe(AH_KEVENT_IF_CHANGE);
#if defined(AH_SUPPORT_IDP)
	ah_kevent_unsubscribe(AH_KEVENT_IDP_STA);
#endif
#ifdef AH_SUPPORT_PSE
	ah_event_unsubscribe(AH_EVENT_PSE_INFO_REPORT_RESPOND);
#endif

#ifdef AH_SUPPORT_RADSEC
	ah_event_unsubscribe(AH_EVENT_RADSEC_CERT_CREATION_RESP);
	ah_event_unsubscribe(AH_EVENT_RADSEC_PROXY_INFO_RESP);
#endif
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	ah_event_unsubscribe(AH_EVENT_BGD_RESP_CAPWAP);
	ah_event_unsubscribe(AH_EVENT_BGD_SERVICE_INFO);
#endif
#ifdef AH_SUPPORT_MULTIWAN
	ah_event_unsubscribe(AH_EVENT_CAPWAP_RESPONSE_USBNET_STATUS);
#endif

	ah_kevent_unsubscribe(AH_KEVENT_ITK_NOTIFY);
	/* clean up event lib */
	ah_event_cleanup();
	return;
}

static ah_ptimer_t *ah_capwap_reconn_timer = NULL;

/***************************************************************************
 *
 * Function:  ah_capwap_handle_reconn_timer
 *
 * Purpose:   handle CAPWAP reconnect timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
void ah_capwap_handle_reconn_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_reconn_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_reconn_timer);
		ah_capwap_reconn_timer = NULL;
	}

	ah_log_old(AH_LOG_INFO, "CAPWAP receive HM's IP changed by offset timer expired!\n");
	ah_dbg_old(capwap_info, "CAPWAP receive HM's IP changed by offset timer expired!\n");
	ah_capwap_server_change_by_cli();
	ah_capwap_interrupt_listen();

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_reconn_timer
 *
 * Purpose:   set CAPWAP reconnect timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_set_reconn_timer(time_t reconn_time)
{
	if (ah_capwap_reconn_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_reconn_timer);
		ah_capwap_reconn_timer = NULL;
	}
	ah_capwap_reconn_timer = ah_pmpt_timer_create(ah_capwap_handle_reconn_timer, NULL);
	if (ah_capwap_reconn_timer == NULL) {
		ah_err_old("CAPWAP create reconnect timer failed!\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "CAPWAP start reconnect timer :%d\n", reconn_time);
	ah_pmpt_timer_start(ah_capwap_reconn_timer, reconn_time);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_cancel_reconn_timer
 *
 * Purpose:   cancel CAPWAP reconnect timer
 *
 * Inputs:    void
 *
 * Output:    void
 * Function:  ah_capwap_cancel_reconn_timer
 *
 * Function:  ah_capwap_cancel_reconn_timer
 *
 * Purpose:   cancel CAPWAP reconnect timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_cancel_reconn_timer(time_t reconn_time)
{
	if (ah_capwap_reconn_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_reconn_timer);
		ah_capwap_reconn_timer = NULL;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_reconn_time
 *
 * Purpose:   get CAPWAP reconnect timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int32_t ah_capwap_get_reconn_time()
{
	if (ah_capwap_reconn_timer != NULL) {
		return ah_pmpt_timer_time2fire(ah_capwap_reconn_timer);
	}

	return -1;
}

static ah_ptimer_t *ah_capwap_detection_timer = NULL;
static int ah_capwap_checking_connection_to_host(uint server_ip)
{
#define AH_CAPWAP_MAX_INFO_LEN (256)
	FILE *fp = NULL;
	char      linebuf[AH_CAPWAP_MAX_INFO_LEN] = {0};
	int      ping_send = 0;
	int      rc = -1;

	ah_sprintf(linebuf, "ping -c 1 -w 10 %i", htonl(server_ip));
	ah_dbg_old(capwap_cli, "Ready %s\n", linebuf);

	fp = ah_popen(linebuf, "r");
	if (fp == NULL) {
		ah_err_old("CAPWAP: Try to testing %s failed.", linebuf);
		return rc;
	}
	while (fgets(linebuf, AH_CAPWAP_MAX_INFO_LEN, fp) != NULL) {
		if (strstr(linebuf, "100% packet loss") != 0) {
			goto OUT;
		} else if (strstr(linebuf, "packets transmitted,") != 0) {
			ping_send = 1;
		}
	}
	if (ping_send) {
		rc = 0;
	}

OUT:
	pclose(fp);
	return rc;
}

static uint ah_capwap_detect_time_value = 0;
void ah_capwap_handle_detection_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_dbg_old(capwap_cli, "CAPWAP start detection!\n");
	ah_capwap_increase_detection_number();

	if (ah_capwap_checking_connection_to_host(ah_capwap_info.acip) == 0) {
		ah_dbg_old(capwap_cli, "ping successfully");
	} else {
		ah_capwap_increase_detection_failed_number();
		ah_dbg_old(capwap_cli, "ping failed");
	}
	if (ah_capwap_detection_timer != NULL) {
		ah_pmpt_timer_continue(ah_capwap_detection_timer, ah_capwap_detect_time_value);
	}

	return ;
}

int ah_capwap_set_detection_timer(time_t detect_time)
{
	if (ah_capwap_detection_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_detection_timer);
		ah_capwap_detection_timer = NULL;
	}
	ah_capwap_detection_timer = ah_pmpt_timer_create(ah_capwap_handle_detection_timer, NULL);
	if (ah_capwap_detection_timer == NULL) {
		ah_err_old("CAPWAP create detection timer failed!\n");
		return -1;
	}
	ah_dbg_old(capwap_cli, "CAPWAP start detection timer :%d\n", detect_time);
	ah_pmpt_timer_start(ah_capwap_detection_timer, detect_time);
	ah_capwap_detect_time_value = detect_time;

	return 0;
}

int ah_capwap_cancel_detection_timer(time_t detect_time)
{
	if (ah_capwap_detection_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_detection_timer);
		ah_capwap_detection_timer = NULL;
		ah_capwap_detect_time_value = 0;
	}

	return 0;
}

int32_t ah_capwap_get_detection_timer()
{
	if (ah_capwap_detection_timer != NULL) {
		return ah_pmpt_timer_time2fire(ah_capwap_detection_timer);
	}

	return -1;
}
ah_ptimer_t *ah_capwap_stat_update_timer = NULL;
int ah_capwap_stat_update_timer_interval = 0;
void ah_capwap_handle_stat_update_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_dbg_old(capwap_cli, "CAPWAP stat update timer time out!\n");

	if (ah_capwap_info.state == AH_CAPWAP_RUN) {
		ah_capwap_statis_request_t     req;
		memset((void *)&req, 0, sizeof(ah_capwap_statis_request_t));
		req.table_num = 0;
		ah_dbg_old(capwap_stat, "CAPWAP collect stat data actively.");
		ah_capwap_stat_collect_data(&req);
	}
	/* When the timer interval is 0, indicate the AP does not need to report statistics activly to HM,
	thus do not need to start the timer, add the judges in code, if the timer interval is 0,
	return directly and not create the timer.*/
	if (ah_capwap_stat_update_timer_interval == AH_CAPWAP_TIMER_STAT_UPDATE_DFT) {
		return;
	}
	if (ah_capwap_stat_update_timer != NULL) {
		ah_pmpt_timer_continue(ah_capwap_stat_update_timer, ah_capwap_stat_update_timer_interval * 60);
	} else {
		ah_log_old(AH_LOG_ERR, "ah_capwap_stat_update_timer is NULL");
	}
	return ;
}

void ah_capwap_set_stat_update_timer()
{
	if (ah_capwap_para.enable != AH_CAPWAP_ENABLE) {
		return;
	}
	/* When the timer interval is 0, indicate the AP does not need to report statistics activly to HM,
	thus do not need to start the timer, add the judges in code, if the timer interval is 0,
	return directly and not create the timer.*/
	if (ah_capwap_stat_update_timer_interval == AH_CAPWAP_TIMER_STAT_UPDATE_DFT) {
		return;
	}
	if (ah_capwap_stat_update_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_stat_update_timer);
		ah_capwap_stat_update_timer = NULL;
	}
	ah_capwap_stat_update_timer = ah_pmpt_timer_create(ah_capwap_handle_stat_update_timer, NULL);
	if (ah_capwap_stat_update_timer == NULL) {
		ah_err_old("CAPWAP create stat update timer failed!\n");
		return;
	}
	ah_dbg_old(capwap_cli, "CAPWAP start stat update timer, interval is %d minutes\n", ah_capwap_stat_update_timer_interval);
	ah_pmpt_timer_start(ah_capwap_stat_update_timer, ah_capwap_stat_update_timer_interval * 60);

	return;
}

void ah_capwap_cancel_stat_update_timer()
{
	ah_dbg_old(capwap_cli, "CAPWAP cancel stat update timer\n");
	if (ah_capwap_stat_update_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_stat_update_timer);
		ah_capwap_stat_update_timer = NULL;
	}

	return;
}


