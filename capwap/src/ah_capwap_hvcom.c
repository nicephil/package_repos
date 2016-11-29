#ifndef _AH_CAPWAP_HVCOM_C
#define _AH_CAPWAP_HVCOM_C

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list.h>
#include <unistd.h>
#include "ah_types.h"
#include "ah_netconst.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_assert.h"
#include "ah_usr_lib.h"
#include "ah_ptimer.h"
#include "ah_errno.h"
#include "ah_dcd_api.h"
#include "ah_nbrcom_api.h"
#include "ah_dbg_agent.h"
#include "capwap/ah_cli_agt_auto.h"
#include "ah_capwap_def.h"
#include "ah_capwap_api.h"
#include "ah_capwap_types.h"
#include "ah_capwap_cli_ui.h"
#include "ah_capwap_func.h"
#include "ah_img_api.h"
#include "ah_capwap_hvcom.h"
#include "ah_capwap_tcp.h"
#include "ah_capwap_recovery.h"

static ah_ptimer_t *ah_capwap_hvcom_chkres_timer = NULL;
static ah_capwap_hvcom_nbr_queue_t ah_capwap_hvcom_rcvhm_reqs[AH_CAPWAP_HVCOM_CONCUR_REQ_NUM];
static ah_capwap_hvcom_portal_apinfo_t ah_capwap_hvcom_portal;
static char ah_capwap_hvcom_scp_pwd[AH_CAPWAP_HVCOM_SCP_PWD_LEN];
static uint32_t ah_capwap_hvcom_saveimg_need_donext_times = 0;

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_add_user
 *
 * Purpose:   create scp account use for distribute download image
 *
 * Inputs:    void
 * Output:    void
 *
 * Returns:   success:0, fail:-1
 *
 **************************************************************************/
static int ah_capwap_hvcom_add_user(void)
{
	struct timeval tv;
	struct timezone tz;
	uchar      self_mac[MACADDR_LEN] = { 0 };
	int      retval = -1;

	if (ah_add_user(AH_CAPWAP_HVCOM_SCP_USER) < 0) {
		ah_err_old("capwap HiveComm add scp user failed.\n");
		return -1;
	}
	ah_memset(ah_capwap_hvcom_scp_pwd, 0, AH_CAPWAP_HVCOM_SCP_PWD_LEN);

	gettimeofday(&tv, &tz);
	ah_dcd_get_mac_byname(default_hvi_name(), (char *)self_mac);
	ah_snprintf(ah_capwap_hvcom_scp_pwd, AH_CAPWAP_HVCOM_SCP_PWD_LEN ,
				"%02x%02x%02x%d", self_mac[4], self_mac[3], self_mac[5], tv.tv_usec);

	if (ah_strlen(ah_capwap_hvcom_scp_pwd) == 0) {
		ah_strcpy(ah_capwap_hvcom_scp_pwd, AH_CAPWAP_HVCOM_SCP_PWD_DFT);
	}

	retval = ah_passwd_crypt(AH_CAPWAP_HVCOM_SCP_USER, ah_capwap_hvcom_scp_pwd, 0);
	if (retval < 0) {
		ah_err_old("capwap HiveComm crypt scp password failed.\n");
		return -1;
	}

	return 0;
}

static void ah_capwap_hvcom_portal_apinfo_init(void)
{
	int      idx = 0;
	ah_capwap_hvcom_portal.ip = 0;
	ah_capwap_hvcom_portal.last_rcvreq_time = 0;
	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		ah_capwap_hvcom_portal.seq_num[idx] = 0;
	}
	pthread_mutex_init(&ah_capwap_hvcom_portal.lock, NULL);
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_update_portal_apinfo
 *
 * Purpose:   update hiveAP receive request last time
 *
 * Inputs:    void
 * Output:    void
 *
 * Returns:   TRUE, FALSE
 *
 **************************************************************************/
static void ah_capwap_hvcom_update_portal_apinfo(uint32_t ip, uint32_t seq_num)
{
	int      idx = 0;
	uint      sec = 0;
	uint      msec = 0;

	(void)ah_get_system_uptime(&sec, &msec);

	pthread_mutex_lock(&ah_capwap_hvcom_portal.lock);
	if (ah_capwap_hvcom_portal.ip != ip) {
		/* changed portal server need inital request cookies */
		for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
			ah_capwap_hvcom_portal.seq_num[idx] = 0;
		}
		ah_capwap_hvcom_portal.ip = ip;
		ah_capwap_hvcom_portal.seq_num[0] = seq_num;
	} else {
		for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
			if (ah_capwap_hvcom_portal.seq_num[idx] == 0) {
				ah_capwap_hvcom_portal.seq_num[idx] = seq_num;
				break;
			}
		}
		if (idx == AH_CAPWAP_HVCOM_CONCUR_REQ_NUM) {
			ah_capwap_hvcom_portal.seq_num[0] = seq_num;
			ah_dbg_old(capwap_hvcom, "capwap HiveComm receive request more than define againg first.\n");
		}
	}
	ah_capwap_hvcom_portal.last_rcvreq_time = sec;
	pthread_mutex_unlock(&ah_capwap_hvcom_portal.lock);

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_chkres_portal
 *
 * Purpose:   this function for check is it response exec result to
 *            portal hiveAP
 *
 * Inputs:    void
 * Output:    void
 *
 * Returns:   TRUE, FALSE
 *
 **************************************************************************/
boolean ah_capwap_hvcom_chkres_portal(uint32_t seq_num)
{
	int      idx = 0;
	uint      sec = 0;
	uint      msec = 0;
	uint32_t    ip = 0;
	ulong      last_rcvreq_time = 0;
	boolean found = FALSE;

	pthread_mutex_lock(&ah_capwap_hvcom_portal.lock);
	ip = ah_capwap_hvcom_portal.ip;
	last_rcvreq_time = ah_capwap_hvcom_portal.last_rcvreq_time;
	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		if (ah_capwap_hvcom_portal.seq_num[idx] == seq_num) {
			ah_capwap_hvcom_portal.seq_num[idx] = 0; /* init */
			found = TRUE;
			break;
		}
	}
	pthread_mutex_unlock(&ah_capwap_hvcom_portal.lock);

	if (!found) {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm chceck response portal the seqnum = %d not found.\n", seq_num);
		return FALSE;
	}

	(void)ah_get_system_uptime(&sec, &msec);
	/*if ((ip == 0) || ((sec - last_rcvreq_time) > AH_CAPWAP_HVCOM_PORTALAP_AGING_INTERVAL)) {  we saved seq_num no need check time */
	if (ip == 0) {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm portal AP no need reply it ip = %i, cur = %d, last_rcvreq_time = %d.\n", ip, sec,
				   last_rcvreq_time);
		return FALSE;
	}

	return TRUE;
}

/*  When receive download image completed event, haven't contain
 *  portal request cookie ID, we can't check is it need to reply
 *  portal according to cookie ID, need according to ip and last
 *  receive request time check is it need reply to portak HiveAP
 */
boolean ah_capwap_hvcom_chkres_portal_by_time(void)
{
	uint32_t    ip = 0;
	ulong      last_rcvreq_time = 0;
	uint      sec = 0;
	uint      msec = 0;

	pthread_mutex_lock(&ah_capwap_hvcom_portal.lock);
	ip = ah_capwap_hvcom_portal.ip;
	last_rcvreq_time = ah_capwap_hvcom_portal.last_rcvreq_time;
	pthread_mutex_unlock(&ah_capwap_hvcom_portal.lock);

	if (0 == ip) {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm portal ip address is zero.\n");
		return FALSE;
	}

	(void)ah_get_system_uptime(&sec, &msec);
	if ((last_rcvreq_time != 0)
		&& ((sec - last_rcvreq_time) > AH_CAPWAP_HVCOM_PORTALAP_AGING_INTERVAL)) {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm portal info timeout current = %d, last_rcvreq_time = %d no need reply.\n", sec, last_rcvreq_time);
		return FALSE;
	}

	return TRUE;
}

static uint32_t ah_capwap_hvcom_get_portal_ip(void)
{
	uint32_t    ip = 0;

	pthread_mutex_lock(&ah_capwap_hvcom_portal.lock);
	ip = ah_capwap_hvcom_portal.ip;
	pthread_mutex_unlock(&ah_capwap_hvcom_portal.lock);

	return ip;
}

static int ah_capwap_hvcom_get_req_queue_by_seqnum(uint32_t seq_num)
{
	int      idx = 0;

	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
		if (ah_capwap_hvcom_rcvhm_reqs[idx].seq_num == seq_num) {
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
			return idx;
		}

		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
	}

	return AH_CAPWAP_HVCOM_CONCUR_REQ_NUM;
}

static int ah_capwap_hvcom_get_ready_req_queue(void)
{
	int      idx = 0;

	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
		if ((ah_capwap_hvcom_rcvhm_reqs[idx].seq_num != 0)
			&& (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type != 0)
			&& (ah_capwap_hvcom_rcvhm_reqs[idx].state == AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_READY)) {
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
			return idx;
		}

		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
	}

	return AH_CAPWAP_HVCOM_CONCUR_REQ_NUM;
}

static boolean ah_capwap_hvcom_chk_req_exist(uint32_t msg_type)
{
	int      idx = 0;

	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

		if ((ah_capwap_hvcom_rcvhm_reqs[idx].seq_num != 0)
			&& (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == msg_type)) {
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
			return TRUE;
		}

		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
	}

	return FALSE;
}

static void ah_capwap_hvcom_req_queue_init(int queue_id)
{
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;

	ah_assert((queue_id >= 0) && (queue_id < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM));

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list) {
		entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
		list_del(&entity->node);
		ah_free(entity);
		entity = NULL;
	}

	ah_capwap_hvcom_rcvhm_reqs[queue_id].msg_type = 0;
	ah_capwap_hvcom_rcvhm_reqs[queue_id].timeout = AH_CAPWAP_HVCOM_REQ_TIMEOUT;
	ah_capwap_hvcom_rcvhm_reqs[queue_id].count = 0;
	ah_capwap_hvcom_rcvhm_reqs[queue_id].seq_num = 0;
	ah_capwap_hvcom_rcvhm_reqs[queue_id].res_type = AH_CAPWAP_HVCOM_RESHM_TYPE_BUTT;
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_BUTT;
	if (ah_capwap_hvcom_rcvhm_reqs[queue_id].msg != NULL) {
		ah_free(ah_capwap_hvcom_rcvhm_reqs[queue_id].msg);
		ah_capwap_hvcom_rcvhm_reqs[queue_id].msg = NULL;
	}
	ah_capwap_hvcom_rcvhm_reqs[queue_id].msg_len = 0;

	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_req_queues_init
 *
 * Purpose:   init the requests list as empty
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
static void ah_capwap_hvcom_req_queues_init(void)
{
	int      idx = 0;

	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		ah_capwap_hvcom_rcvhm_reqs[idx].msg_type = 0;
		ah_capwap_hvcom_rcvhm_reqs[idx].timeout = AH_CAPWAP_HVCOM_REQ_TIMEOUT;
		ah_capwap_hvcom_rcvhm_reqs[idx].count = 0;
		ah_capwap_hvcom_rcvhm_reqs[idx].seq_num = 0;
		ah_capwap_hvcom_rcvhm_reqs[idx].res_type = AH_CAPWAP_HVCOM_RESHM_TYPE_BUTT;
		ah_capwap_hvcom_rcvhm_reqs[idx].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_BUTT;
		ah_capwap_hvcom_rcvhm_reqs[idx].msg = NULL;
		ah_capwap_hvcom_rcvhm_reqs[idx].msg_len = 0;
		INIT_LIST_HEAD(&ah_capwap_hvcom_rcvhm_reqs[idx].list);
		pthread_mutex_init(&ah_capwap_hvcom_rcvhm_reqs[idx].lock, NULL);
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_nbr_queue_add
 *
 * Purpose:   add the HM send command ip list to wait result list
 *
 * Inputs:    ah_capwap_hvcomm_nbr_t *entity : point of one ip entity
 *
 * Output:    void
 *
 * Returns:   0: add entity success, -1:add entity failed
 *
 **************************************************************************/
static int ah_capwap_hvcom_nbr_queue_add(int queue_id, ah_capwap_hvcom_nbr_t entity)
{
	ah_capwap_hvcom_nbr_t *new_entity = NULL;

	ah_assert((queue_id >= 0) && (queue_id < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM));

#if 0
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *tmp_entity = NULL;

	list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list) {
		tmp_entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
		if ((ah_memcmp(tmp_entity->mac, entity.mac, MACADDR_LEN) == 0) &&
			(tmp_entity->ip == entity.ip)) {
			/* this AP node is existed */
			return 0;
		}
	}
#endif

	/* add node to request list */
	new_entity = (ah_capwap_hvcom_nbr_t *)ah_malloc(sizeof(ah_capwap_hvcom_nbr_t));
	if (new_entity == NULL) {
		ah_err_old("capwap HiveComm add entity malloc memory failed.\n");
		return -1;
	}

	new_entity->ip = entity.ip;
	ah_memcpy(new_entity->mac, entity.mac, MACADDR_LEN);
	new_entity->result = entity.result;
	new_entity->snd_time = entity.snd_time;
	new_entity->status = entity.status;

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	list_add_tail(&new_entity->node, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list);
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	return 0;
}

static int ah_capwap_hvcom_sndpkt(uint16_t optmsg_type, uint32_t msg_type,
								  uint32_t    seq_num, uint32_t ip, uint32_t playload_len, void *playload)
{
	/**************************************************************

	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      opt-msg-type             |           msg-type
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	                                |        seq_num
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	                                |        palyload length
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	                                |    palyload
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	**************************************************************/
	int      retval = -1;
	uchar      *buff = NULL;
	uchar      *p = NULL;
	uint32_t    len = 0;

	ah_assert(optmsg_type < AH_CAPWAP_HVCOM_OPTMSG_BUTT);
	ah_assert(msg_type < AH_CAPWAP_HVCOM_MSG_BUTT);

	buff = (uchar *)ah_malloc(AH_CAPWAP_HVCOM_NBRPKT_HDR_LEN + playload_len);
	if (buff == NULL) {
		ah_err_old("capwap HiveComm send packet malloc memory failed.\n");
		return -1;
	}

	p = buff;
	*(uint16_t *)p = htons(optmsg_type);
	p += sizeof(uint16_t);

	*(uint32_t *)p = htonl(msg_type);
	p += sizeof(uint32_t);

	*(uint32_t *)p = htonl(seq_num);
	p += sizeof(uint32_t);

	*(uint32_t *)p = htonl(playload_len);
	p += sizeof(uint32_t);

	if (NULL != playload) {
		ah_memcpy(p, playload, playload_len);
	}
	len = AH_CAPWAP_HVCOM_NBRPKT_HDR_LEN + playload_len;

	retval = ah_hc3t_onetime_send(ip, buff, len);
	if (retval < 0) {
		ah_free(buff);
		buff = NULL;
		ah_log_old(AH_LOG_WARNING, "capwap HiveComm call NBrcom send packet failed.(retval = %d, ip = %i, len = %d)\n", retval, ip, len);
		return -1;
	}

	if (capwap_hvcom_packet) {
		ah_dbg_old(capwap_hvcom_packet, "capwap HiveComm call NBrcom send packet to %i.(length = %d).\n", ip, len);
		ah_hexdump(buff, len);
	}

	ah_free(buff);
	buff = NULL;

	return 0;
}

static int ah_capwap_hvcom_analyse_cancel_save_img(uint32_t seq_num, uint len, char *buff)
{
	int      rc = 0;

	/* stop transfer data from portal */
	rc = ah_system_stop_transfer_data(AH_INTERRUPT_SCP);

	if (ah_capwap_hvcom_chkres_portal(seq_num)) {
		rc = ah_capwap_hvcom_snd_res(seq_num, AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL, rc, 0, NULL);
		if (rc < 0) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm cancel send response via NBrcom failed.\n");
			return -1;
		}
	}
	return 0;
}

static int ah_capwap_hvcom_analyse_cmd(uint32_t seq_num, uint len, char *buff)
{
	char      *p = NULL;
	uint32_t    cmd_str_len = 0;
	int      retval = -1;

	ah_assert(buff != NULL);

	if (len < sizeof(uint32_t)) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm invalid cmmand string.(len = %d)\n", len);
		return -1;
	}

	p = buff;
	cmd_str_len = ntohl(*(uint32_t *)p);
	if (cmd_str_len == 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm invalid command cli length is zero.\n");
		return -1;
	}

	/* rewirte the cli length field to seq num, use htonl transfer it because
	 * sequence number ntohl before, but the cli ui will do ntohl again
	 */
	*(uint32_t *)p = htonl(seq_num);

	ah_dbg_old(capwap_hvcom, "capwap HiveComm recevie cli : %s.\n", (buff + sizeof(uint32_t)));/* cli string contain '\n' */

	retval = ah_capwap_cli_ui_rcv_data(buff, len);
	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm call cli ui failed.\n");
		return -1;
	}

	return 0;
}

#ifdef AH_BONJOUR_GATEWAY_SUPPORT

static int ah_capwap_hvcom_snd_http_proxy_auth_res(uint32_t seq_num, uint32_t ip)
{
	char      *palyload = NULL;
	uint32_t    playload_len = 0;
	char      proxy_auth_name[AH_MAX_STR_PARM_LEN + 1] = {0}; /*proxy authentication name*/
	char      proxy_auth_pswd[AH_MAX_STR_PARM_LEN + 1] = {0}; /*proxy authentication password*/
	int32_t    len = 0;
	int      rc = -1;
	ah_capwap_tlv_attr_t *attr = NULL;

	ah_capwap_get_tcp_http_proxy_auth_name_pswd(proxy_auth_name, proxy_auth_pswd);
	/* encode payload message */
	if (!proxy_auth_name[0]) {
		ah_log_old(AH_LOG_WARNING, "no capwap http proxy authetication information send");
		return -1;
	}
	len = sizeof(ah_capwap_tlv_attr_t) * 2 + strlen(proxy_auth_name) + strlen(proxy_auth_pswd);

	ah_log_old(AH_LOG_INFO, "capwap current http proxy information:user %s passwd %s\n",
			   proxy_auth_name, proxy_auth_pswd);
	/* 4(result code) + 4(error info len) + info len*/
	playload_len = len + (sizeof(uint32_t) * 2);

	palyload = (char *)ah_malloc(playload_len);
	if (palyload == NULL) {
		ah_err_old("capwap HiveComm send http proxy response malloc memory failed.\n");
		return -1;
	}

	/* fill the palyload content */
	*(uint32_t *)palyload = htonl(0);
	*(uint32_t *)(palyload + sizeof(uint32_t)) = htonl(len);

	if (len > 0) {
		attr = (ah_capwap_tlv_attr_t *)(palyload + (sizeof(uint32_t) * 2));
		attr->type = htons(AH_CAPWAP_GEN_TLV | AH_CAPWAP_TLV_HTTP_PROXY_USERNAME);
		attr->lorv = htonl(strlen(proxy_auth_name));
		ah_memcpy(attr + 1, proxy_auth_name, strlen(proxy_auth_name));

		attr = (ah_capwap_tlv_attr_t *)(palyload + (sizeof(uint32_t) * 2) +
										sizeof(ah_capwap_tlv_attr_t) + strlen(proxy_auth_name));
		attr->type = htons(AH_CAPWAP_GEN_TLV | AH_CAPWAP_TLV_HTTP_PROXY_PASSWORD);
		attr->lorv = htonl(strlen(proxy_auth_pswd));
		ah_memcpy(attr + 1, proxy_auth_pswd, strlen(proxy_auth_pswd));
	}

	/* send HTTP proxy auth user/pwd back */
	rc = ah_capwap_hvcom_sndpkt(AH_CAPWAP_HVCOM_OPTMSG_RESPONSE,
								AH_CAPWAP_HVCOM_MSG_HTTP_PROXY_AUTH, seq_num, ip,
								playload_len, palyload);
	ah_free(palyload);
	palyload = NULL;

	if (rc < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send http proxy response failed.\n");
		return -1;
	}
	ah_log_old(AH_LOG_INFO, "capwap HiveComm respond http proxy information done.\n");
	return 0;
}

static int ah_capwap_hvcom_update_http_proxy_auth(uint32_t ip, uint32_t msg_type, uint32_t seq_num, uint32_t playload_len,
		char      *playload)
{
	int32_t    rst_code = 0;
	char      proxy_auth_name[AH_MAX_STR_PARM_LEN + 1] = {0}; /*proxy authentication name*/
	char      proxy_auth_pswd[AH_MAX_STR_PARM_LEN + 1] = {0}; /*proxy authentication password*/
	int data_len, alen;
	uint16_t type;
	char      *tmp = NULL;
	ah_capwap_tlv_attr_t *attr = NULL;

	ah_assert(playload != NULL);
	/* check the playload is it contain return code and error message length */
	if (playload_len < (sizeof(uint32_t) * 2)) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm update result input invalid packet.(playload_len = %d)\n", playload_len);
		return -1;
	}

	/* get return code */
	rst_code = ntohl(*(int32_t *)playload);
	data_len = playload_len - (sizeof(uint32_t) * 2);
	attr = (ah_capwap_tlv_attr_t *)(playload + (sizeof(uint32_t) * 2));
	while (data_len > 0) {
		type = ntohs(attr->type);
		ah_dbg_old(capwap_info, "decode type = 0x%x, current total length %d", type, data_len);
		/* Handle value attributes */
		if ((type & AH_CAPWAP_GEN_MASK) == AH_CAPWAP_GEN_TV) {
			type &= ~AH_CAPWAP_GEN_MASK;
			switch (type) {
			default:
				break;
			}
			data_len -= sizeof(*attr);
			attr++;
			continue;
		}

		type = ntohs(attr->type);
		alen = ntohl(attr->lorv);

		/* Check that the attribute fit in the packet */
		if (data_len < alen) {
			break;
		}
		switch (type) {
		case AH_CAPWAP_TLV_HTTP_PROXY_USERNAME:
			memcpy(proxy_auth_name, attr + 1, ntohl(attr->lorv));
			break;
		case AH_CAPWAP_TLV_HTTP_PROXY_PASSWORD:
			memcpy(proxy_auth_pswd, attr + 1, ntohl(attr->lorv));
			break;
		default:
			break;
		}
		tmp = (char *)attr;
		attr = (ah_capwap_tlv_attr_t *)(tmp + sizeof(*attr) + alen);
		data_len -= (sizeof(*attr) + alen);
	}

	ah_log_old(AH_LOG_INFO, "get http proxy info: username %s password %s from %i %s",
			   proxy_auth_name, proxy_auth_pswd, ip, rst_code ? "failed" : "successfully");
	ah_capwap_set_tcp_http_proxy_auth(proxy_auth_name, proxy_auth_pswd);
	ah_capwap_save_proxy_auth(proxy_auth_name, proxy_auth_pswd);
	ah_capwap_set_tcp_http_proxy_cfg_method(AH_CAPWAP_HTTP_PROXY_CONF_BY_BONJOUR);

	return 0;
}

int ah_capwap_get_http_proxy_auth_data(uint32_t seq_num, uint32_t ip)
{
	char      buf[AH_CAPWAP_HVCOM_REQUEST_HTTP_PROXY_MSG_LEN] = {0};
	int32_t    len = 0;
	int      rc = -1;

	len = ah_snprintf(buf + sizeof(uint32_t),
					  (AH_CAPWAP_HVCOM_REQUEST_HTTP_PROXY_MSG_LEN - sizeof(uint32_t)),
					  "%s\n", "Request HTTP proxy auth data");

	*(uint32_t *)buf = htonl(len); /* request message length */

	rc = ah_capwap_hvcom_sndpkt(AH_CAPWAP_HVCOM_OPTMSG_REQUEST,
								AH_CAPWAP_HVCOM_MSG_HTTP_PROXY_AUTH, seq_num, ip,
								(len + sizeof(uint32_t)), buf);
	if (rc < 0) {
		ah_log_old(AH_LOG_WARNING, "capwap HiveComm send packet to %i failed.\n", ip);
		return -1;
	}
	ah_log_old(AH_LOG_INFO, "capwap HiveComm request http proxy information from %i\n", ip);
	return 0;
}
#endif

static int ah_capwap_hvcom_req_handle(uint32_t ip, uint len, char *buff)
{
	char      *p = NULL;
	uint32_t    msg_type = 0;
	uint32_t    seq_num = 0;
	int      retval = -1;
	uint      offset = 0;
	uint      playload_len = 0;

	ah_assert(buff != NULL);

	p = buff;
	/* offset optmsg type */
	p += sizeof(uint16_t);
	offset += sizeof(uint16_t);

	/* get message type */
	msg_type = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);
	offset += sizeof(uint32_t);

	/* get sequence number */
	seq_num = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);
	offset += sizeof(uint32_t);

	/* get playload length */
	playload_len = ntohl((*(uint32_t *)p));
	offset += sizeof(uint32_t);

	/* update portal info */
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	if (msg_type != AH_CAPWAP_HVCOM_MSG_HTTP_PROXY_AUTH) {
		ah_capwap_hvcom_update_portal_apinfo(ip, seq_num);
	}
#else
	ah_capwap_hvcom_update_portal_apinfo(ip, seq_num);
#endif

	switch (msg_type) {
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG:
	case AH_CAPWAP_HVCOM_MSG_CLI:
		retval = ah_capwap_hvcom_analyse_cmd(seq_num, playload_len, buff + offset);
		break;
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL:
		retval = ah_capwap_hvcom_analyse_cancel_save_img(seq_num, 0, NULL);
		break;
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	case AH_CAPWAP_HVCOM_MSG_HTTP_PROXY_AUTH:
		retval = ah_capwap_hvcom_snd_http_proxy_auth_res(seq_num, ip);
		break;
#endif
	default:
		ah_log_old(AH_LOG_ERR, "capwap HiveComm request message type not support.(msg_type = %d)\n", msg_type);
		return -1;
	}

	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm analyse request failed.(msg_type = %d)\n", msg_type);
		return -1;
	}

	return 0;
}

static int ah_capwap_hvcom_gen_save_img_cmd(uint32_t seq_num, ah_capwap_hvcom_nbr_t *entity)
{
#define AH_CAPWAP_HVCOM_SAVEIMG_CMDSTR_LEN 256
#define AH_CAPWAP_HVCOM_IMG_TMP "/tmp/aeros.img"

	char      buff[AH_CAPWAP_HVCOM_SAVEIMG_CMDSTR_LEN] = { 0 };
	int32_t    len = 0;
	int      retval = -1;
	uint32_t    ip = 0;
	uint32_t    netmask = 0;

	if (ah_dcd_get_addr_byname(default_hvi_name(), &ip, &netmask) < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm save image get itself ip address failed.\n");
		return -1;
	}

	len = ah_snprintf(buff + sizeof(uint32_t),
					  (AH_CAPWAP_HVCOM_SAVEIMG_CMDSTR_LEN - sizeof(uint32_t)),
					  "save image scp://%s@%i:%s no-prompt _password %s\n",
					  AH_CAPWAP_HVCOM_SCP_USER, ip,  AH_CAPWAP_HVCOM_IMG_TMP, ah_capwap_hvcom_scp_pwd);

	*(uint32_t *)buff = htonl(len); /* cli length */

	retval = ah_capwap_hvcom_sndpkt(AH_CAPWAP_HVCOM_OPTMSG_REQUEST,
									AH_CAPWAP_HVCOM_MSG_DOWNIMG,
									seq_num,
									entity->ip,
									(len + sizeof(uint32_t)),
									buff);
	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send packet failed.\n");
		return -1;
	}

	return 0;
}

static int ah_capwap_hvcom_update_entity(int queue_id,  ah_capwap_hvcom_nbr_t *entity)
{
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *tmp_entity = NULL;
	boolean found = FALSE;

	ah_assert((queue_id >= 0) && (queue_id < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM));
	ah_assert(entity != NULL);

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list) {
		tmp_entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
		if (ah_memcmp(tmp_entity->mac, entity->mac, MACADDR_LEN) == 0) {
			found = TRUE;
			tmp_entity->status = entity->status;
			tmp_entity->snd_time = entity->snd_time;
			tmp_entity->result = entity->result;
			break;
		}
	}

	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	if (!found) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm update entiy info not found.(mac = %m)\n", entity->mac);
		return -1;
	}

	return 0;
}

static int ah_capwap_hvcom_save_img_last(int queue_id)
{
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;
	ah_capwap_hvcom_nbr_t portal_entity;
	uint32_t    res_completed_count = 0;
	uint      sec = 0;
	uint      msec = 0;
	boolean has_last = FALSE;
	uint32_t    req_entity_count = 0;
	uint32_t    req_seq_num = 0;
	uint32_t    req_analyse_state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_BUTT;

	ah_assert((queue_id >= 0) && (queue_id < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM));

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list) {
		entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
		if ((entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_COMPLETE)
			|| (entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_COMPLETE)
			|| (entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_TIMEOUT)
			|| (entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL)) {
			res_completed_count++;
		} else if (entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_LAST_SEND) {
			ah_memcpy(&portal_entity, entity, sizeof(ah_capwap_hvcom_nbr_t));
			has_last = TRUE;
		} else {
			;/* do nothing */
		}
	}
	req_entity_count = ah_capwap_hvcom_rcvhm_reqs[queue_id].count;
	req_seq_num = ah_capwap_hvcom_rcvhm_reqs[queue_id].seq_num;
	req_analyse_state = ah_capwap_hvcom_rcvhm_reqs[queue_id].state;

	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	if (!has_last) {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm upgrade image get last no contain portal.\n");
		return 0;
	}

	if ((req_analyse_state == AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_END)
		&& (req_entity_count == (res_completed_count + 1))) {
		if (ah_capwap_hvcom_gen_save_img_cmd(req_seq_num, &portal_entity) < 0) {
			portal_entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL;
			portal_entity.result = AH_RC_ERR_AP_CAPWAP_HVCOM_SEND_FAIL;
			ah_capwap_hvcom_update_entity(queue_id, &portal_entity);
			ah_log_old(AH_LOG_ERR, "capwap HiveComm send portal AP save image failed.\n");
			return -1;
		}

		(void)ah_get_system_uptime(&sec, &msec);
		portal_entity.snd_time = sec;
		portal_entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_PENDING;
		ah_capwap_hvcom_update_entity(queue_id, &portal_entity);

		/* clear distribution upgrading flg for response process to hm */
		unlink(AH_TMP_DTN_UPGRADE_SW_DW_FLG);
	} else {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm check upgrade contain portal but other desn't completed.(total = %d, completed = %d)\n",
				   req_entity_count, res_completed_count);
	}

	return 0;
}

static int ah_capwap_hvcom_save_img_next(int queue_id)
{
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;
	ah_capwap_hvcom_nbr_t tmp_entity;
	boolean has_next = FALSE;
	uint      sec = 0;
	uint      msec = 0;
	uint32_t    req_seq_num = 0;

	ah_assert((queue_id >= 0) && (queue_id < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM));

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list) {
		entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
		if (entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_READY) {
			ah_memcpy(&tmp_entity, entity, sizeof(ah_capwap_hvcom_nbr_t));
			has_next = TRUE;
			break;
		}

	}
	req_seq_num = ah_capwap_hvcom_rcvhm_reqs[queue_id].seq_num;

	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	if (has_next) {
		if (ah_capwap_hvcom_gen_save_img_cmd(req_seq_num, &tmp_entity) < 0) {
			tmp_entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL;
			tmp_entity.result = AH_RC_ERR_AP_CAPWAP_HVCOM_SEND_FAIL;
			ah_capwap_hvcom_update_entity(queue_id, &tmp_entity);

			pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
			ah_capwap_hvcom_saveimg_need_donext_times++;
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

			ah_log_old(AH_LOG_ERR, "capwap HiveComm get next AP download image failed.\n");
			return -1;
		}

		(void)ah_get_system_uptime(&sec, &msec);
		tmp_entity.snd_time = sec;
		tmp_entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_PENDING;
		ah_capwap_hvcom_update_entity(queue_id, &tmp_entity);
	} else {
		if (ah_capwap_hvcom_save_img_last(queue_id) < 0) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm get last AP download image failed.\n");
			return -1;
		}
	}

	return 0;
}

static int ah_capwap_hvcom_update_result(uint32_t ip, uint32_t msg_type, uint32_t seq_num, uint32_t playload_len,
		char      *playload)
{
	int      idx = 0;
	int32_t    rst_code = 0;
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;
	ah_capwap_hvcom_nbr_t *tmp = NULL;
	boolean update_flg = FALSE;
	boolean found = FALSE;

	ah_assert(playload != NULL);

	/* check the playload is it contain return code and error message length */
	if (playload_len < (sizeof(uint32_t) * 2)) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm update result input invalid packet.(playload_len = %d)\n", playload_len);
		return -1;
	}

	/* get return code */
	rst_code = ntohl(*(int32_t *)playload);

	/*
	 * current not reply error info for hm, desn't to anylse it
	 */
	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
		if ((ah_capwap_hvcom_rcvhm_reqs[idx].seq_num == seq_num)
			|| ((msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG)
				&& (msg_type == ah_capwap_hvcom_rcvhm_reqs[idx].msg_type) && (seq_num == 0))) {
			update_flg = FALSE;
			list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[idx].list) {
				entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
				if (entity->ip == ip) {
					/* update send status and return code */
					entity->result = rst_code;
					if ((msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG) && (seq_num == 0)) {   /* download image */
						entity->status = AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_COMPLETE;
						ah_capwap_hvcom_saveimg_need_donext_times++;
					} else {
						entity->status = AH_CAPWAP_HVCOM_MSG_STATUS_COMPLETE;
						/* if the AP exec save image complete, we need get next AP do download image
						 * for prevent the AP drop download image complete event.
						 */
						ah_capwap_hvcom_saveimg_need_donext_times++;
					}
					update_flg = TRUE;
					break;
				}
			} /* end list_for_each_safe */

			if (update_flg) {
				pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
				break;
			}
		}
		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
	}

	ah_dbg_old(capwap_hvcom, "capwap HiveComm update result msg_type = %d, seq_num = %d, update_flg = %d, rst_code = %d.\n", msg_type, seq_num,
			   update_flg, rst_code);
	/* if the HiveComm message is cancel distribution upgrade image,
	 * and the cancel success response need to change upgrade image
	 * result to AH_RC_ERR_CLT_CAPWAP_HVCOM_CANCEL
	 */
	if (update_flg) {
		if ((msg_type  == AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL) && (rst_code == AH_INTERRUPT_STATUS_OK)) {

			for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {

				pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

				if (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG) {
					list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[idx].list) {
						tmp = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
						if (ah_memcmp(entity->mac, tmp->mac, MACADDR_LEN) == 0) {
							tmp->status = AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_CANCEL;
							tmp->result = AH_RC_ERR_AP_CAPWAP_HVCOM_CANCEL;
							found = TRUE;
							break;
						}
					}
				}

				pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

				if (found) {
					break;
				}
			}
			ah_dbg_old(capwap_hvcom, "capwap HiveComm update result cancel found = %d\n", found);
		}
	} else {
		ah_dbg_old(capwap_hvcom, "capwap HiveComm not find item for update result.(msg_type = %d, seq_num = %d)\n", msg_type, seq_num);
	}

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_res_handler
 *
 * Purpose:   if this portal HiveAP for HM, HM will call the portal HiveAP for
 *            send commands to another HiveAP in hive, then this HiveAP will
 *            receive response for another HiveAP
 *
 * Inputs:    ah_uint16_t msg_type : the hive comm message type
 *                                   AH_CAPWAP_HVCOMM_MSG_CLI
 *                                   AH_CAPWAP_HVCOMM_MSG_DOWNIMG
 *            ah_uint32_t len  : packet length
 *            ah_uchar_t *buff : packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
static int ah_capwap_hvcom_res_handle(uint32_t ip, uint len, char *buff)
{
	uint32_t    msg_type = 0;
	uint32_t    seq_num = 0;
	char      *p = NULL;
	uint32_t    playload_len = 0;
	uint      offset = 0;
	int      retval = 0;

	ah_assert(buff != NULL);

	p = buff;
	/* offset the optmsg type */
	p += sizeof(uint16_t);
	offset += sizeof(uint16_t);

	/* get message type */
	msg_type = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);
	offset += sizeof(uint32_t);

	/* get sequence number */
	seq_num = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);
	offset += sizeof(uint32_t);

	/* get playload length */
	playload_len = ntohl(*(uint32_t *)p);
	offset += sizeof(uint32_t);

	switch (msg_type) {
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG:
	case AH_CAPWAP_HVCOM_MSG_CLI:
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL:
		retval = ah_capwap_hvcom_update_result(ip, msg_type, seq_num, playload_len, buff + offset);
		break;
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	case AH_CAPWAP_HVCOM_MSG_HTTP_PROXY_AUTH:
		retval = ah_capwap_hvcom_update_http_proxy_auth(ip, msg_type, seq_num, playload_len, buff + offset);
		break;
#endif
	default:
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive message not support.(msg_type = %d)\n", msg_type);
		return -1;
	}

	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm update result failed.(msg_type = %d)\n", msg_type);
		return -1;
	}


	return 0;
}

static int ah_capwap_hvcom_cancel_save_img(uint32_t seq_num, uint32_t len, char *buff)
{
	int      retval = 0;
	uint      sec = 0;
	uint      msec = 0;
	int      idx = 0;
	int      queue_id = 0;
	uint16_t    cur_read_len = 0;
	int      status = AH_CAPWAP_HVCOM_MSG_STATUS_BUTT;
	char      *p = NULL;
	char      *tmp = NULL;
	uint32_t    total_entity_len = 0;
	uint16_t    single_apinfo_len = 0;
	ah_capwap_hvcom_nbr_t entity;
	ah_capwap_hvcom_nbr_t *ap = NULL;
	struct list_head *pos;
	struct list_head *n;
	boolean found = FALSE;

	ah_assert(NULL != buff);

	queue_id = ah_capwap_hvcom_get_req_queue_by_seqnum(seq_num);
	if (queue_id == AH_CAPWAP_HVCOM_CONCUR_REQ_NUM) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm exec cmd get queue id by sequence failed.(seq_num = %d)\n", seq_num);
		return -1;
	}

	if (len < AH_CAPWAP_HVCOM_MIN_EVTMSG_DATA_LEN) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive event message %d data length %d invalid.\n", AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL, len);
		ah_capwap_hvcom_req_queue_init(queue_id);
		return -1;
	}

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_START;

	p = buff;
	/* offset message type */
	p += sizeof(uint32_t);

	/* get length of ap list */
	total_entity_len = ntohs(*(uint16_t *)p);
	p += sizeof(uint16_t);

	ah_assert((len - (sizeof(uint32_t) + sizeof(uint16_t) + total_entity_len)) >= 5);

	/* get response type */
	tmp = buff + sizeof(uint32_t) + sizeof(uint16_t) + total_entity_len;
	ah_capwap_hvcom_rcvhm_reqs[queue_id].res_type = *(char *)tmp;
	tmp += sizeof(char);

	/* get timeout value */
	ah_capwap_hvcom_rcvhm_reqs[queue_id].timeout = ntohl(*(uint32_t *)tmp);
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	while (cur_read_len < total_entity_len) {
		single_apinfo_len = ntohs(*(uint16_t *)p);
		p += sizeof(uint16_t);
		cur_read_len += sizeof(uint16_t);

		ah_assert(single_apinfo_len == (MACADDR_LEN + sizeof(uint32_t)));

		ah_memcpy(entity.mac, p, MACADDR_LEN);
		p += MACADDR_LEN;

		entity.ip = *(uint32_t *)p;
		p += sizeof(uint32_t);

		entity.result = 0;
		entity.snd_time = 0;
		entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_READY;
		found = FALSE;

		for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {

			pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

			if (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG) {
				list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[idx].list) {
					ap = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
					if (ah_memcmp(ap->mac, entity.mac, MACADDR_LEN) == 0) {
						if ((status == AH_CAPWAP_HVCOM_MSG_STATUS_READY)
							|| (status == AH_CAPWAP_HVCOM_MSG_STATUS_LAST_SEND)) {
							ap->status = AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_CANCEL;
							ap->result = AH_RC_ERR_AP_CAPWAP_HVCOM_CANCEL;
							entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_COMPLETE;
							entity.result = AH_INTERRUPT_STATUS_OK;
						} else {
							status = ap->status;
						}

						found = TRUE;
						break;
					}
				}
			}

			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

			if (found) {
				break;
			}
		}

		/* check if areadly send save image command need send cancel to the HiveAP */
		if ((status != AH_CAPWAP_HVCOM_MSG_STATUS_BUTT) || (!found)) {
			if ((status == AH_CAPWAP_HVCOM_MSG_STATUS_PENDING)
				|| (status == AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_COMPLETE)
				|| (status == AH_CAPWAP_HVCOM_MSG_STATUS_TIMEOUT)
				|| (!found)) {
				retval = ah_capwap_hvcom_sndpkt(AH_CAPWAP_HVCOM_OPTMSG_REQUEST,
												AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL,
												seq_num,
												entity.ip,
												0,
												NULL);
				if (retval < 0) {
					ah_log_old(AH_LOG_ERR, "capwap HiveComm send cancel distribution upgrade image failed.\n");
					entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL;
					entity.result = AH_INTERRUPT_STATUS_FAILED;
				} else {
					entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_PENDING;
					(void)ah_get_system_uptime(&sec, &msec);
					entity.snd_time = sec;
				}
			} else {
				entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_COMPLETE;
				entity.result = AH_INTERRUPT_STATUS_FAILED;
			}
		}

		retval = ah_capwap_hvcom_nbr_queue_add(queue_id, entity);
		if (retval < 0) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm add cancel entity to queue %d failed.", queue_id);
		} else {
			pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
			ah_capwap_hvcom_rcvhm_reqs[queue_id].count++;
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
		}

		cur_read_len += single_apinfo_len;
	} /* end while (cur_read_len < total_entity_len) */

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_END;
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	return 0;
}

static int ah_capwap_hvcom_save_img(uint32_t seq_num, uint32_t len, char *buff)
{
	char      *p = NULL;
	char      *tmp = NULL;
	uint16_t    total_apinfo_len = 0;
	uint16_t    single_apinfo_len = 0;
	uint16_t    cur_read_len = 0;
	ah_capwap_hvcom_nbr_t entity;
	int      queue_id = 0;
	uint32_t    msg_type = 0;
	uint16_t    snd_count = 0;
	int      retval = -1;
	uint      sec = 0;
	uint      msec = 0;
	uint32_t    self_ipaddr = 0;
	uint32_t    self_netmask = 0;

	ah_assert(buff != NULL);

	if (ah_dcd_get_addr_byname(default_hvi_name(), &self_ipaddr, &self_netmask) < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm get itself ip address failed.\n");
		return -1;
	}

	queue_id = ah_capwap_hvcom_get_req_queue_by_seqnum(seq_num);
	if (queue_id == AH_CAPWAP_HVCOM_CONCUR_REQ_NUM) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm save image get queue id by sequence failed.(seq_num = %d)\n", seq_num);
		return -1;
	}

	if (len <  AH_CAPWAP_HVCOM_MIN_EVTMSG_DATA_LEN) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive event message data length is invalid.(len = %d)\n", len);
		ah_capwap_hvcom_req_queue_init(queue_id);
		return -1;
	}

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_START;

	p = buff;
	/* offset message type */
	msg_type = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);

	/* get total HiveAPs node length */
	total_apinfo_len = ntohs(*(uint16_t *)p);
	p += sizeof(uint16_t);

	ah_assert((len - (sizeof(uint32_t) + sizeof(uint16_t) + total_apinfo_len)) >= 5);

	/* get response type */
	tmp = buff + (sizeof(uint32_t) + sizeof(uint16_t) + total_apinfo_len);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].res_type = *(char *)tmp;
	tmp += sizeof(char);

	/* get timeout value */
	ah_capwap_hvcom_rcvhm_reqs[queue_id].timeout = ntohl(*(uint32_t *)tmp);
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	while (cur_read_len < total_apinfo_len) {
		single_apinfo_len = ntohs(*(uint16_t *)p);
		p += sizeof(uint16_t);
		cur_read_len += sizeof(uint16_t);

		if (single_apinfo_len != (MACADDR_LEN + sizeof(uint32_t))) {
			ah_assert(0);
			cur_read_len += single_apinfo_len;
			p += single_apinfo_len;
			continue; /* not mac + ip invalid */
		}

		/* add to list */
		ah_memcpy(entity.mac, p, MACADDR_LEN);
		p += MACADDR_LEN;

		entity.ip = *(uint32_t *)p;
		p += sizeof(uint32_t);

		entity.result = 0;
		entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_READY;
		entity.snd_time = 0;

		/* check is it entity is itself, if yes didn't send save image current,
		 * because save image success will del image sofware, will do it after
		 * all HiveAPs execute complete in hive.
		 */
		if ((self_ipaddr == entity.ip)
			&& (total_apinfo_len > (sizeof(uint16_t) + MACADDR_LEN + sizeof(uint32_t)))) {
			entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_LAST_SEND;
		} else {
			if (snd_count < AH_CAPWAP_HVCOM_MAXSCP_CONCUR_NUM) {
				retval = ah_capwap_hvcom_gen_save_img_cmd(seq_num, &entity);
				if (retval < 0) {
					ah_log_old(AH_LOG_ERR, "capwap HiveComm send save image command failed.(ip = %i)\n", entity.ip);
					entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL;
					entity.result = AH_RC_ERR_AP_CAPWAP_HVCOM_SEND_FAIL;
				} else {
					entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_PENDING;
					snd_count++;
					(void)ah_get_system_uptime(&sec, &msec);
					entity.snd_time = sec;
				}
			}
		}

		if (ah_capwap_hvcom_nbr_queue_add(queue_id, entity) < 0) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm add entity to queue failed.(ip = %i)\n", entity.ip);
		} else {
			pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
			ah_capwap_hvcom_rcvhm_reqs[queue_id].count++;
			if (entity.status == AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL) {
				ah_capwap_hvcom_saveimg_need_donext_times++;
			}
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
		}

		cur_read_len += single_apinfo_len;
	}

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_END;
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	return 0;
}

static int ah_capwap_hvcom_exec_cmd(uint32_t seq_num, uint32_t len, char *buff)
{
	char      *p = NULL;
	char      *tmp = NULL;
	int      queue_id = 0;
	uint32_t    entity_len = 0;
	uint32_t    total_entity_len = 0;
	uint32_t    cur_len = 0;
	ah_capwap_hvcom_nbr_t entity;
	int      retval = -1;
	uint      sec = 0;
	uint      msec = 0;
	uint      cli_opt_offset = 0;

	ah_assert(buff != NULL);

	queue_id = ah_capwap_hvcom_get_req_queue_by_seqnum(seq_num);
	if (queue_id == AH_CAPWAP_HVCOM_CONCUR_REQ_NUM) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm exec cmd get queue id by sequence failed.(seq_num = %d)\n", seq_num);
		return -1;
	}

	if (len <  AH_CAPWAP_HVCOM_MIN_EVTMSG_DATA_LEN) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive event message data length is invalid.(len = %d)\n", len);
		ah_capwap_hvcom_req_queue_init(queue_id);
		return -1;
	}

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_START;

	p = buff;
	/* offset message type */
	p += sizeof(uint32_t);

	/* get total HiveAPs entity length */
	total_entity_len = ntohs(*(uint16_t *)p);
	p += sizeof(uint16_t);

	/* cli option offset length 4(msg_type) + 2(size of ap list) + vary(ap list length) + 1(res flag) + 4(timeout)*/
	cli_opt_offset = (sizeof(uint32_t) * 2) + sizeof(uint16_t) + total_entity_len + sizeof(char);
	ah_assert((len - cli_opt_offset) >= 4);

	/* get response type */
	tmp = buff;
	tmp += (sizeof(uint32_t) + sizeof(uint16_t) + total_entity_len);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].res_type = *(char *)tmp;
	tmp += sizeof(char);

	/* get timeout value*/
	ah_capwap_hvcom_rcvhm_reqs[queue_id].timeout = ntohl(*(uint32_t *)tmp);
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	while (cur_len < total_entity_len) {
		entity_len = ntohs(*(uint16_t *)p);
		p += sizeof(uint16_t);

		if (entity_len != (MACADDR_LEN + sizeof(uint32_t))) {
			ah_assert(0);
			p += entity_len;
			cur_len = cur_len + (sizeof(uint16_t) + entity_len);
			continue;
		}

		ah_memcpy(entity.mac, p, MACADDR_LEN);
		p += MACADDR_LEN;

		entity.ip = *(uint32_t *)p;
		p += sizeof(uint32_t);

		entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_READY;
		entity.result = 0;
		entity.snd_time = 0;

		/* send cli optoins */
		retval = ah_capwap_hvcom_sndpkt(AH_CAPWAP_HVCOM_OPTMSG_REQUEST,
										AH_CAPWAP_HVCOM_MSG_CLI,
										seq_num,
										entity.ip,
										len - cli_opt_offset,
										buff + cli_opt_offset);
		if (retval < 0) {
			ah_dbg_old(capwap_hvcom, "capwap HiveComm send cli command failed.(ip = %i)\n", entity.ip);
			entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL;
			entity.result = AH_RC_ERR_AP_CAPWAP_HVCOM_SEND_FAIL;
		} else {
			entity.status = AH_CAPWAP_HVCOM_MSG_STATUS_PENDING;
			(void)ah_get_system_uptime(&sec, &msec);
			entity.snd_time = sec;
		}

		if (ah_capwap_hvcom_nbr_queue_add(queue_id, entity) < 0) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm add queue entity faile.(ip = %i)\n", entity.ip);
		} else {
			pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
			ah_capwap_hvcom_rcvhm_reqs[queue_id].count++;
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
		}

		cur_len = cur_len + (sizeof(uint16_t) + entity_len);
	}

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	ah_capwap_hvcom_rcvhm_reqs[queue_id].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_END;
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	return 0;
}

static int ah_capwap_hvcom_snd_hm_res_single(uint32_t seq_num, uint32_t msg_type, ah_capwap_hvcom_nbr_t *entity)
{
	char      *buff = NULL;
	char      *p = NULL;
	uint32_t    evtpkt_hdr_len = 0;
	uint32_t    evtpkt_entity_len = 0;

	ah_assert(entity != NULL);

	/* 2(event type) + 4(cookie) + 4(data length) */
	evtpkt_hdr_len = sizeof(uint16_t) + (sizeof(uint32_t) * 2);
	/* 4(message type) + 2(length of ap list) + 2(length of ap) + 6(ap mac) + 4(return code) */
	evtpkt_entity_len = sizeof(uint32_t) + (sizeof(uint16_t) * 2) + MACADDR_LEN + sizeof(uint32_t);

	buff = (char *)ah_malloc(evtpkt_hdr_len + evtpkt_entity_len);
	if (buff == NULL) {
		ah_err_old("capwap HiveComm send single response to hm malloc memory failed.\n");
		return -1;
	}

	p = buff;
	/* fill event type */
	*(uint16_t *)p = htons(AH_CAPWAP_EVENT_HVCOM);
	p += sizeof(uint16_t);

	/* fill sequence number */
	*(uint32_t *)p = htonl(seq_num);
	p += sizeof(uint32_t);

	/* fill data length */
	*(uint32_t *)p = htonl(evtpkt_entity_len);
	p += sizeof(uint32_t);

	/* fill message type */
	*(uint32_t *)p = htonl(msg_type);
	p += sizeof(uint32_t);

	/* fill size of ap list length */
	*(uint16_t *)p = htons(sizeof(uint16_t) + MACADDR_LEN + sizeof(uint32_t));
	p += sizeof(uint16_t);

	/* fill ap entity length */
	*(uint16_t *)p = htons(MACADDR_LEN + sizeof(uint32_t));
	p += sizeof(uint16_t);

	/* fill mac address */
	ah_memcpy(p, entity->mac, MACADDR_LEN);
	p += MACADDR_LEN;

	/* fill return code */
	*(uint32_t *)p = htonl(entity->result);

	/* send event to hm */
	ah_capwap_send_event_itself((evtpkt_hdr_len + evtpkt_entity_len),
								buff,
								AH_CAPWAP_EVENT_SEND_RESPONSE);
	if (capwap_hvcom_packet) {
		ah_dbg_old(capwap_hvcom_packet, "capwap HiveComm send single result event response to hm.(length = %d)\n",
				   (evtpkt_hdr_len + evtpkt_entity_len));
		ah_hexdump((uchar *)buff, (evtpkt_hdr_len + evtpkt_entity_len));
	}

	ah_free(buff);
	buff = NULL;

	return 0;
}

static int ah_capwap_hvcom_snd_hm_res_all(int queue_id)
{
	char      *buff = NULL;
	char      *p = NULL;
	char      *tmp = NULL;
	uint32_t    evtpkt_hdr_len = 0;
	uint32_t    evtpkt_entity_len = 0;
	uint32_t    evtpkt_entity_total_len = 0;
	uint32_t    buff_len = 0;
	uint32_t    cur_len = 0;
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;

	ah_assert((queue_id >= 0) && (queue_id < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM));

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	/* 2(event type) + 4(cookie) + 4(data length) + 4(message type) + 2(length of ap list) */
	evtpkt_hdr_len = sizeof(uint16_t) + (sizeof(uint32_t) * 3) + sizeof(uint16_t);
	/* 2(length of ap) + 6(ap mac) + 4(return code) */
	evtpkt_entity_len = sizeof(uint16_t) + MACADDR_LEN + sizeof(uint32_t);
	evtpkt_entity_total_len = ah_capwap_hvcom_rcvhm_reqs[queue_id].count * evtpkt_entity_len;
	buff_len = evtpkt_hdr_len + evtpkt_entity_total_len;

	buff = (char *)ah_malloc(buff_len);
	if (buff == NULL) {
		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
		ah_err_old("capwap HiveComm all response for hm malloc memory failed.\n");
		return -1;
	}

	p = buff;
	/* fill packet header */
	*(uint16_t *)p = htons(AH_CAPWAP_EVENT_HVCOM);
	p += sizeof(uint16_t);
	cur_len += sizeof(uint16_t);

	/* fill sequence number */
	*(uint32_t *)p = htonl(ah_capwap_hvcom_rcvhm_reqs[queue_id].seq_num);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);

	/* fill data length message type + 2(length of ap list) + total entity len */
	*(uint32_t *)p = htonl(sizeof(uint32_t) + sizeof(uint16_t) + evtpkt_entity_total_len);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);

	/* fill message type */
	*(uint32_t *)p = htonl(ah_capwap_hvcom_rcvhm_reqs[queue_id].msg_type);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);

	/* fill HiveAPs list length */
	*(uint16_t *)p = htons(evtpkt_entity_total_len);
	p += sizeof(uint16_t);
	cur_len += sizeof(uint16_t);

	list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[queue_id].list) {
		entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
		if ((cur_len + evtpkt_entity_len) > buff_len) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm send all response for hm buff will overfllow.\n");
			ah_assert(0);
			break; /* Waring: buff will overfllow !!!!!!!!! */
		}

		tmp = p;
		tmp += sizeof(uint16_t); /* offset length of ap entity */

		ah_memcpy(tmp, entity->mac, MACADDR_LEN);
		tmp += MACADDR_LEN;

		*(uint32_t *)tmp = htonl(entity->result);
		*(uint16_t *)p = htons(MACADDR_LEN + sizeof(uint32_t));

		cur_len += evtpkt_entity_len;
		p += evtpkt_entity_len;
	}

	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	ah_capwap_send_event_itself(buff_len, buff, AH_CAPWAP_EVENT_SEND_RESPONSE);

	if (capwap_hvcom_packet) {
		ah_dbg_old(capwap_hvcom_packet, "capwap HiveComm send all results event response to hm.(length = %d)\n", buff_len);
		ah_hexdump((uchar *)buff, buff_len);
	}

	ah_free(buff);
	buff = NULL;

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_rcvpkt
 *
 * Purpose:   this is a callback fucntion for NBrcom receive packet
 *
 * Inputs:    ah_uint32_t ip : remote neigbor ip address
 *            ah_int_t len   : packet length
 *            ah_void_t *buff: packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
static void ah_capwap_hvcom_rcvpkt(ah_ipaddr46_t *ip, int len, void *buff)
{
	/**************************************************************

	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      opt-msg-type             |           msg-type
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	                                |        seq_num
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	                                |        palyload length
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	                                |    palyload
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	**************************************************************/
	uint16_t    optmsg_type = 0;
	int      retval = -1;

	if (capwap_hvcom_packet) {
		ah_dbg_old(capwap_hvcom_packet, "capwap HiveComm receive packet from %i via NBrcom.(length = %d)\n", ip, len);
		ah_hexdump((uchar *)buff, len);
	}

	if ((len < AH_CAPWAP_HVCOM_NBRPKT_HDR_LEN) || (buff == NULL)) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive packet from NBrcom invalid packet.\n");
		return;
	}
	/* TODO, feature owner need handle IPv6 change */
	if (ip->af != AF_INET) {
		return;
	}

	optmsg_type = ntohs(*(uint16_t *)buff);
	switch (optmsg_type) {
	case AH_CAPWAP_HVCOM_OPTMSG_REQUEST:
		retval = ah_capwap_hvcom_req_handle(ip->u_ipv4, len, (char *)buff);
		break;
	case AH_CAPWAP_HVCOM_OPTMSG_RESPONSE:
		retval = ah_capwap_hvcom_res_handle(ip->u_ipv4, len, (char *)buff);
		break;
	default:
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive packet from NBrcom operate type not support.(optmsg_type = %d)\n", optmsg_type);
		return;
	}

	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm analyse receive packet from NBrcom failed.(optmsg_type = %d)\n", optmsg_type);
	}

	return;
}

static int ah_capwap_hvcom_msg_process(void)
{
	uint32_t    seq_num = 0;
	char      *buff = NULL;
	uint32_t    msg_type = 0;
	uint32_t    data_len = 0;
	int      retval = -1;
	int      queue_id = 0;

	queue_id = ah_capwap_hvcom_get_ready_req_queue();
	if (queue_id == AH_CAPWAP_HVCOM_CONCUR_REQ_NUM) {
		return 0;
	}

	pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
	msg_type = ah_capwap_hvcom_rcvhm_reqs[queue_id].msg_type;
	seq_num = ah_capwap_hvcom_rcvhm_reqs[queue_id].seq_num;
	data_len = ah_capwap_hvcom_rcvhm_reqs[queue_id].msg_len;
	buff = (char *)ah_malloc(data_len);
	if (buff == NULL) {
		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);
		ah_err_old("capwap HiveComm process event message malloc memory failed.\n");
		return -1;
	}
	ah_memcpy(buff, ah_capwap_hvcom_rcvhm_reqs[queue_id].msg, data_len);
	pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[queue_id].lock);

	ah_dbg_old(capwap_hvcom, "capwap HiveComm get message to process.(msg_type = %d)\n", msg_type);

	switch (msg_type) {
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG:
		retval = ah_capwap_hvcom_save_img(seq_num, data_len, buff);
		break;
	case AH_CAPWAP_HVCOM_MSG_CLI:
		retval = ah_capwap_hvcom_exec_cmd(seq_num, data_len, buff);
		break;
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL:
		retval = ah_capwap_hvcom_cancel_save_img(seq_num, data_len, buff);
		break;
	default:
		ah_free(buff);
		buff = NULL;
		ah_log_old(AH_LOG_ERR, "capwap HiveComm not support this message type.(msg_type = %d)", msg_type);
		return -1;
	}

	ah_free(buff);
	buff = NULL;

	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send request via NBrcom failed.(msg_type = %d)\n", msg_type);
		return -1;
	}

	return 0;
}

static void *ah_capwap_hvcom_pthread(void *argv)
{
	int      idx = 0;
	boolean do_next_flg = FALSE;
	int      i = 0;
	int      saveimg_need_donext_times = 0;

	while (1) {
		/* check receive message from hm and send it */
		ah_capwap_hvcom_msg_process();

		/* check is it need to get next HiveAP download image, if message type is distrbuted upgrade image */
		do_next_flg = FALSE;
		for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
			pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

			/* haven't request skip it */
			if ((ah_capwap_hvcom_rcvhm_reqs[idx].seq_num == 0)
				&& (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == 0)) {
				pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
				continue;
			}

			if ((ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG)
				&& (ah_capwap_hvcom_saveimg_need_donext_times > 0)) {
				do_next_flg = TRUE;
				saveimg_need_donext_times = ah_capwap_hvcom_saveimg_need_donext_times;
				pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
				break;
			}

			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
		}

		if (do_next_flg) {
			for (i = 0; i < saveimg_need_donext_times; i++) {
				if (ah_capwap_hvcom_save_img_next(idx) < 0) {
					ah_log_old(AH_LOG_ERR, "capwap HiveComm process get next AP download image failed.\n");
				} else {
					pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
					if (ah_capwap_hvcom_saveimg_need_donext_times > 0) {
						ah_capwap_hvcom_saveimg_need_donext_times--;
					}
					pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
				}
			}
		}

		sleep(1);
	}

	return NULL;
}

static void ah_capwap_hvcom_clear_img_file(void)
{
	unlink(AH_IMG_TMP);
	unlink(AH_TMP_DTN_UPGRADE_SW_DW_FLG);
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_chkres_handler
 *
 * Purpose:   this function is a timer callback, it is use for check the ip list
 *            entity send but not response timeout or not
 *
 * Inputs:    ah_ptimer_t *ptimer : point of  ah_ptimer
 *            ah_void_t *arg
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
static void ah_capwap_hvcom_chkres_handle(ah_ptimer_t *ptimer, void *arg)
{
	int      idx = 0;
	uint      sec = 0;
	uint      msec = 0;
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;
	uint32_t    res_completed_count = 0;
	int      retval = -1;
	uint      save_img_timeout_count = 0;
	uint32_t    req_analyse_state = 0;
	uint32_t    res_type = 0;
	uint32_t    req_entity_count = 0;
	int      msg_type = 0;

	ah_assert(ptimer != NULL);

	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

		/* haven't request skip it */
		if ((ah_capwap_hvcom_rcvhm_reqs[idx].seq_num == 0)
			&& (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == 0)) {
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
			continue;
		}

		/* init */
		res_completed_count = 0;
		save_img_timeout_count = 0;
		req_analyse_state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_BUTT;
		res_type = AH_CAPWAP_HVCOM_RESHM_TYPE_BUTT;
		req_entity_count = 0;
		(void)ah_get_system_uptime(&sec, &msec);
		msg_type = ah_capwap_hvcom_rcvhm_reqs[idx].msg_type;

		list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[idx].list) {
			entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
			switch (entity->status) {
			case AH_CAPWAP_HVCOM_MSG_STATUS_COMPLETE:
			case AH_CAPWAP_HVCOM_MSG_STATUS_TIMEOUT:
			case AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL:
			case AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_CANCEL:
				if (ah_capwap_hvcom_rcvhm_reqs[idx].res_type == AH_CAPWAP_HVCOM_RESHM_TYPE_SINGLE) {
					/* make single response for hm */
					retval = ah_capwap_hvcom_snd_hm_res_single(ah_capwap_hvcom_rcvhm_reqs[idx].seq_num,
							 ah_capwap_hvcom_rcvhm_reqs[idx].msg_type,
							 entity);
					if (retval < 0) {
						ah_log_old(AH_LOG_ERR, "capwap HiveComm send single response to hm failed.\n");
					} else {
						entity->status = AH_CAPWAP_HVCOM_MSG_STATUS_RESPONSED;
						if (ah_capwap_hvcom_rcvhm_reqs[idx].count > 0) {
							ah_capwap_hvcom_rcvhm_reqs[idx].count--;
						}
					}
				} else {
					res_completed_count++;
				}

				/* check if distrbution download image and has been cancel need do next */
				if ((ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG)
					&& (entity->status == AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_CANCEL)) {
					ah_capwap_hvcom_saveimg_need_donext_times++;
				}
				break;
			case AH_CAPWAP_HVCOM_MSG_STATUS_PENDING:
			case AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_COMPLETE:
				/* check this request is it timeout */
				if ((sec - entity->snd_time) >= ah_capwap_hvcom_rcvhm_reqs[idx].timeout) {
					/* beacuse we do get next save image, if we receive download completed, here didn't do it again */
					if ((ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG)
						&& (entity->status != AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_COMPLETE)) {
						ah_capwap_hvcom_saveimg_need_donext_times++;
					}
					entity->status = AH_CAPWAP_HVCOM_MSG_STATUS_TIMEOUT;
					if (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL) {
						entity->result = AH_INTERRUPT_STATUS_FAILED;
					} else {
						entity->result = AH_RC_ERR_CLT_CAPWAP_HVCOM_TIMEOUT;
					}
				}
				break;
			case AH_CAPWAP_HVCOM_MSG_STATUS_READY:
			case AH_CAPWAP_HVCOM_MSG_STATUS_LAST_SEND:
			case AH_CAPWAP_HVCOM_MSG_STATUS_RESPONSED:
				/* do nothing */
				break;
			default:
				ah_assert(0);
				break;
			}
		} /* end list_for_each_safe */

		req_analyse_state = ah_capwap_hvcom_rcvhm_reqs[idx].state;
		res_type = ah_capwap_hvcom_rcvhm_reqs[idx].res_type;
		req_entity_count = ah_capwap_hvcom_rcvhm_reqs[idx].count;
		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

		/* all request send completed, check response and send to result for hm */
		if (req_analyse_state == AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_END) {
			if ((res_type == AH_CAPWAP_HVCOM_RESHN_TYPE_ALL)
				&& (req_entity_count == res_completed_count)) {
				retval = ah_capwap_hvcom_snd_hm_res_all(idx);
				if (retval < 0) {
					ah_log_old(AH_LOG_ERR, "capwap HiveComm send all response to hm failed.\n");
				} else {
					ah_capwap_hvcom_req_queue_init(idx);
					if (msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG) {
						ah_capwap_hvcom_clear_img_file();
					}
				}
			} else if ((res_type == AH_CAPWAP_HVCOM_RESHM_TYPE_SINGLE)
					   && (req_entity_count == 0)) {
				ah_capwap_hvcom_req_queue_init(idx);
				if (msg_type == AH_CAPWAP_HVCOM_MSG_DOWNIMG) {
					ah_capwap_hvcom_clear_img_file();
				}
			} else {
				; /* nothing to do */
			}
		}
	}

	ah_pmpt_timer_continue(ptimer, AH_CAPWAP_HVCOM_CHKRES_INTERVAL);

	return;
}

static int ah_capwap_hvcom_chkres_timer_init(void)
{
	if (ah_capwap_hvcom_chkres_timer == NULL) {
		ah_capwap_hvcom_chkres_timer = ah_pmpt_timer_create(ah_capwap_hvcom_chkres_handle, NULL);
		if (ah_capwap_hvcom_chkres_timer == NULL) {
			return -1;
		}
	}

	ah_pmpt_timer_start(ah_capwap_hvcom_chkres_timer, AH_CAPWAP_HVCOM_CHKRES_INTERVAL);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_init
 *
 * Purpose:   initialize hive comm must use parameters and register callback
 *            function in NBrcom to receive packet
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0:successful, -1:failed
 *
 **************************************************************************/
int ah_capwap_hvcom_init(void)
{
	ah_hc_para_t para;
	pthread_t capwap_hvcom_pid;
	int      retval = 0;

	/* initialize neighbor queue for wait HM ip list */
	ah_capwap_hvcom_req_queues_init();

	/* add hive comm scp user */
	ah_capwap_hvcom_add_user();

	/* create capwap hive comm check response timer */
	if (ah_capwap_hvcom_chkres_timer_init() < 0) {
		ah_err_old("capwap HiveComm create check result timer fialed.");
		return -1;
	}

	/* create pthread */
	retval = ah_pthread_create(&capwap_hvcom_pid,
							   ah_capwap_hvcom_pthread,
							   NULL,
							   SCHED_RR,
							   AH_PRIORITY_MGT, 0);
	if (retval < 0) {
		ah_err_old("capwap HiveComm create pthread failed.(retval = %d)", retval);
		return -1;
	}

	/* register callback for NBrcom to receive packet */
	ah_memset(&para, 0, sizeof(para));
	para.mod_id = AH_MOD_ID_CAPWAP;
	para.app_id = AH_APP_CAPWAP;
	para.tcp_cb = ah_capwap_hvcom_rcvpkt;
	para.udp_cb = NULL;

	if (ah_hc_register(&para) < 0) {
		ah_err_old("capwap HiveComm register to nbrcom failed.");
		return -1;
	}

	/* init portal info */
	ah_capwap_hvcom_portal_apinfo_init();

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_msg_handler
 *
 * Purpose:   the capwap client receive hive comm contrl message handler
 *
 * Inputs:    ah_char_t *buff  : capwap hive comm contrl message
 *            ah_uint32_t len  : packet length
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_hvcom_msg_handle(uint32_t len, char *buff)
{
	uint32_t    seq_num = 0;
	char      *p = NULL;
	uint32_t    msg_type = 0;
	uint32_t    data_len = 0;
	int      offset = 0;
	int      idx = 0;

	if (capwap_hvcom_packet) {
		ah_dbg_old(capwap_hvcom_packet, "capwap HiveComm receive request message from hm.(length = %d)\n", len);
		ah_hexdump((uchar *)buff, len);

	}

	if ((len < AH_CAPWAP_HVCOM_EVTMSG_HDR_LEN) || (buff == NULL)) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm receive event message invalid.(len = %d)\n", len);
		return -1;
	}

	p = buff;
	/* offset event type */
	p += sizeof(uint16_t);
	offset += sizeof(uint16_t);

	/* get sequence number */
	seq_num = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);
	offset += sizeof(uint32_t);

	/* offset flag */
	p += sizeof(char);
	offset += sizeof(char);

	/* get data length */
	data_len = ntohl(*(uint32_t *)p);
	p += sizeof(uint32_t);
	offset += sizeof(uint32_t);

	/* get the message type */
	msg_type = ntohl(*(uint32_t *)p);
	switch (msg_type) {
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG:
		if (ah_capwap_hvcom_chk_req_exist(AH_CAPWAP_HVCOM_MSG_DOWNIMG)) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm areadly has upgrade image request.\n");
			return -1;
		}
		break;
	case AH_CAPWAP_HVCOM_MSG_CLI:
		/* nothing do */
		break;
	case AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL:
		if (!ah_capwap_hvcom_chk_req_exist(AH_CAPWAP_HVCOM_MSG_DOWNIMG)) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm cancel upgrade image, but no ugrade image request existed.\n");
			return -1;
		}
		if (ah_capwap_hvcom_chk_req_exist(AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL)) {
			ah_log_old(AH_LOG_ERR, "capwap HiveComm cancel upgrade image request existed.\n");
			return -1;
		}
		break;
	default:
		ah_log_old(AH_LOG_ERR, "capwap HiveComm not support this message type.(msg_type = %d)", msg_type);
		return -1;
	}

	/* get empty queue and save this request message */
	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
		if ((ah_capwap_hvcom_rcvhm_reqs[idx].seq_num == 0)
			&& (ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == 0)) {

			ah_capwap_hvcom_rcvhm_reqs[idx].msg = (char *)ah_malloc(data_len);
			if (ah_capwap_hvcom_rcvhm_reqs[idx].msg == NULL) {
				pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
				ah_err_old("capwap HiveComm malloc memory save event message failed.\n");
				return -1;
			}

			ah_capwap_hvcom_rcvhm_reqs[idx].seq_num = seq_num;
			ah_capwap_hvcom_rcvhm_reqs[idx].msg_type = msg_type;
			ah_capwap_hvcom_rcvhm_reqs[idx].msg_len = data_len;
			ah_memcpy(ah_capwap_hvcom_rcvhm_reqs[idx].msg, buff + offset, data_len);
			ah_capwap_hvcom_rcvhm_reqs[idx].state = AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_READY;

			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
			break;

		}
		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
	}

	if (idx == AH_CAPWAP_HVCOM_CONCUR_REQ_NUM) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm no enough resource save request.\n");
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_snd_res
 *
 * Purpose:   when receive hive comm message and execute completed, will
 *            call this function for response for portal HiveAP
 *
 * Inputs:    ah_uint32_t seq_num  : cookie id
 *            ah_uint32_t msg_type : execute message type
 *            ah_uint32_t result   : execute result
 *            ah_uint16_t len      : if have infomation for response to portal
 *                                   HiveAP, the info length
 *            ah_char_t *buff      : info string
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_hvcom_snd_res(uint32_t seq_num, uint32_t msg_type, uint32_t result, uint16_t len, char *buff)
{
	int      retval = -1;
	char      *palyload = NULL;
	uint32_t    playload_len = 0;
	int      count = 0;

	/* 4(result code) + 4(error info len) + info len*/
	playload_len = len + (sizeof(uint32_t) * 2);

	palyload = (char *)ah_malloc(playload_len);
	if (palyload == NULL) {
		ah_err_old("capwap HiveComm send command response malloc memory failed.\n");
		return -1;
	}

	/* fill the palyload content */
	*(uint32_t *)palyload = htonl(result);
	*(uint32_t *)(palyload + sizeof(uint32_t)) = htonl(len);
	if (len > 0) {
		ah_memcpy(palyload + (sizeof(uint32_t) * 2), buff, len);
	}

	while (retval < 0) {
		/* send cli execute result response to portal HiveAP */
		retval = ah_capwap_hvcom_sndpkt(AH_CAPWAP_HVCOM_OPTMSG_RESPONSE,
										msg_type,
										seq_num,
										ah_capwap_hvcom_get_portal_ip(),
										playload_len,
										palyload);
		if (count++ >= AH_CAPWAP_HVCOM_RES_TIMEOUT / 10) {
			break;
		}
		sleep(10);
	}

	ah_free(palyload);
	palyload = NULL;

	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send command response failed.\n");
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hvcom_snd_cmd_res
 *
 * Purpose:   cli command execute completed send result to portal HiveAP
 *
 * Inputs:    ah_uint32_t seq_num  : cookie id
 *            ah_char_t *res_file_path : cli command execute result file
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_hvcom_snd_cmd_res(uint32_t seq_num, char *res_file_path)
{
	struct stat fp_buf;
	FILE *fp = NULL;
	uint32_t    result = 0;
	int      retval = -1;

	ah_assert(res_file_path != NULL);

	if (stat(res_file_path, &fp_buf) < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send execute command result read %s failed.\n", res_file_path);
		return -1;
	}

	if (fp_buf.st_size == 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send execute command result failed, file %s size is zero.\n", res_file_path);
		return -1;
	}

	fp = fopen(res_file_path, "r");
	if (fp == NULL) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send execute command result open %s failed.\n", res_file_path);
		return -1;
	}

#if 0 /* if hivecomm need response error info to hm open these */
	char      *buff = NULL;
	uint16_t    info_len = 0;
	buff = (char *)ah_malloc(fp_buf.st_size);
	if (buff == NULL) {
		fclose(fp);
		ah_err_old("capwap HiveComm send execute command result malloc memory failed.\n");
		return -1;
	}

	fread(buff, sizeof(char), fp_buf.st_size, fp);
#endif
	if (fread(&result, sizeof(uint32_t), 1, fp) != 1) {
		fclose(fp);
		ah_err_old("%s: Read file failed.", __func__);
		return -1;
	}
	fclose(fp);

	retval = ah_capwap_hvcom_snd_res(seq_num, AH_CAPWAP_HVCOM_MSG_CLI, result, 0, NULL);
	if (retval < 0) {
		ah_log_old(AH_LOG_ERR, "capwap HiveComm send command result failed.\n");
		return -1;
	}

	return 0;
}

/* _show capwap hvcom status */
int ah_capwap_show_hvcom_status(ah_cmd_handle_t *cmd, ah_capwap_cli_show_hvcom_status_cmd_data_t *ptr)
{
	int      idx = 0;
	struct list_head *pos;
	struct list_head *n;
	ah_capwap_hvcom_nbr_t *entity = NULL;
	uint      sec = 0;
	uint      msec = 0;

	ah_assert(cmd != NULL);
	ah_assert(ptr != NULL);

	(void)ah_get_system_uptime(&sec, &msec);

	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		pthread_mutex_lock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);

		if ((ah_capwap_hvcom_rcvhm_reqs[idx].msg_type == 0)
			&& (ah_capwap_hvcom_rcvhm_reqs[idx].count == 0)) {
			pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
			continue;
		}
		/* request global info */
		ah_cli_printf(cmd, "queue index : %d\n", idx);
		ah_cli_printf(cmd, "message type : %d\n", ah_capwap_hvcom_rcvhm_reqs[idx].msg_type);
		ah_cli_printf(cmd, "sequence number : %d\n", ah_capwap_hvcom_rcvhm_reqs[idx].seq_num);
		ah_cli_printf(cmd, "response type : %d\n", ah_capwap_hvcom_rcvhm_reqs[idx].res_type);
		ah_cli_printf(cmd, "request timeout : %d\n", ah_capwap_hvcom_rcvhm_reqs[idx].timeout);
		ah_cli_printf(cmd, "request analyse state: %d\n", ah_capwap_hvcom_rcvhm_reqs[idx].state);
		ah_cli_printf(cmd, "current uptime : %d\n", sec);
		ah_cli_printf(cmd, "queue entities list : \n");
		/* request entity info */
		list_for_each_safe(pos, n, &ah_capwap_hvcom_rcvhm_reqs[idx].list) {
			entity = list_entry(pos, ah_capwap_hvcom_nbr_t, node);
			ah_cli_printf(cmd, "  MAC address : %m\n", entity->mac);
			ah_cli_printf(cmd, "  IP address : %i\n", entity->ip);
			ah_cli_printf(cmd, "  send status : %d\n", entity->status);
			ah_cli_printf(cmd, "  send time : %d\n", entity->snd_time);
			ah_cli_printf(cmd, "  result : %d\n", entity->result);
		}
		ah_cli_printf(cmd, "total entities : %d\n", ah_capwap_hvcom_rcvhm_reqs[idx].count);
		ah_cli_printf(cmd, "\n");

		pthread_mutex_unlock(&ah_capwap_hvcom_rcvhm_reqs[idx].lock);
	}

	/* show portal HiveAP info */
	pthread_mutex_lock(&ah_capwap_hvcom_portal.lock);
	ah_cli_printf(cmd, "Portal AP IP address : %i\n", ah_capwap_hvcom_portal.ip);
	ah_cli_printf(cmd, "Last receive request time : %d\n", ah_capwap_hvcom_portal.last_rcvreq_time);
	ah_cli_printf(cmd, "Request sequences :");
	for (idx = 0; idx < AH_CAPWAP_HVCOM_CONCUR_REQ_NUM; idx++) {
		ah_cli_printf(cmd, " %d", ah_capwap_hvcom_portal.seq_num[idx]);
	}
	ah_cli_printf(cmd, "\n");
	pthread_mutex_unlock(&ah_capwap_hvcom_portal.lock);
	return 0;
}

int ah_capwap_test_hvcom(ah_cmd_handle_t *cmd, ah_capwap_cli_test_hvcom_cmd_data_t *ptr)
{
	int      retval = -1;
	char      *buff = NULL;
	char      *p = NULL;
	uint      len = 0;
	//ah_char_t mac1[6] = {0x00, 0x19, 0x77, 0x02, 0xe9, 0x40};
	//ah_char_t mac2[6] = {0x00, 0x19, 0x77, 0x02, 0xfc, 0x43};
	//ah_char_t mac3[6] = {0x00, 0x19, 0x77, 0x02, 0xec, 0x80};
	//ah_char_t *ipstr1 = "10.155.20.146";
	//ah_char_t *ipstr2 = "10.155.20.124";
	//ah_char_t *ipstr3 = "10.155.20.138";
	//struct in_addr inp;
	char      cmd_str[128] = { 0 };
	struct timeval tv;
	struct timezone tz;
	uint32_t    sub_seq = 0;
	uint32_t    msg_type = 0;

	ah_assert(cmd != NULL);
	ah_assert(ptr != NULL);

	if (ah_strcmp(ptr->type, "saveimg") == 0) {
		msg_type = AH_CAPWAP_HVCOM_MSG_DOWNIMG;
	} else if (ah_strcmp(ptr->type, "reboot") == 0) {
		msg_type = AH_CAPWAP_HVCOM_MSG_CLI;
		ah_snprintf(cmd_str, 128, "reboot offset 00:00:10 no-prompt\n");
	} else {
		ah_cli_printf(cmd, "capwap HiveComm test failed, input option cannot support it.\n");
		return -1;
	}

	//ah_cli_printf(cmd, "capwap HiveComm test send message %d to %i, MAC address %m.\n", msg_type, ptr->dest_ip, ptr->dest_mac);

	buff = (char *)ah_malloc(1300);
	if (buff == NULL) {
		ah_cli_printf(cmd, "capwap HiveComm test malloc memory failed.\n");
		return -1;
	}
	ah_memset(buff, 0, 1300);

	gettimeofday(&tv, &tz);
	srand(tv.tv_sec + tv.tv_usec);
	sub_seq = 1 + (int)(5000.0 * rand() / ((1 << 15) + 1.0));

	p = buff;
	/* fill event type */
	*(uint16_t *)p = htons(AH_CAPWAP_EVENT_HVCOM);
	p += sizeof(uint16_t);
	len += sizeof(uint16_t);

	/* fill cookie id */
	*(uint32_t *)p = htonl(sub_seq);
	p += sizeof(uint32_t);
	len += sizeof(uint32_t);

	/* fill flag */
	*(char *)p = 0x00;
	p += sizeof(char);
	len += sizeof(char);

	/* offset data length */
	//*(uint32_t *)p = htonl(35+4+ah_strlen(cmd1));
	if (msg_type == AH_CAPWAP_HVCOM_MSG_CLI) {
		*(uint32_t *)p = htonl(23 + 4 + ah_strlen(cmd_str));
	} else {
		*(uint32_t *)p = htonl(23);
	}
	p += sizeof(uint32_t);
	len += sizeof(uint32_t);

	/* message type */
	*(uint32_t *)p = htonl(msg_type);
	p += sizeof(uint32_t);
	len += sizeof(uint32_t);

	/* ap list length */
	*(uint16_t *)p = htons(12);
	p += sizeof(uint16_t);
	len += sizeof(uint16_t);

	/* one ap length */
	*(uint16_t *)p = htons(10);
	p += sizeof(uint16_t);
	len += sizeof(uint16_t);

	/* fill mac */
	ah_memcpy(p, ptr->dest_mac, MACADDR_LEN);
	p += MACADDR_LEN;
	len += MACADDR_LEN;

	/* fill ip */
	//inet_aton(ipstr1, &inp);
	//*(uint32_t *)p = inp.s_addr;
	*(uint32_t *)p = htonl(ptr->dest_ip);
	p += sizeof(uint32_t);
	len += sizeof(uint32_t);

	/* fill res type */
	*p = 0x01;
	p += sizeof(char);
	len += sizeof(char);

	/* fill time out */
	*(uint32_t *)p = htonl(300);
	p += sizeof(uint32_t);
	len += sizeof(uint32_t);

	if (msg_type == AH_CAPWAP_HVCOM_MSG_CLI) {
		/* fill cli len */
		*(uint32_t *)p = htonl(ah_strlen(cmd_str));
		p += sizeof(uint32_t);
		len += sizeof(uint32_t);

		ah_memcpy(p, cmd_str, ah_strlen(cmd_str));
		len += ah_strlen(cmd_str);
	}

	retval = ah_capwap_hvcom_msg_handle(len, buff);
	if (retval < 0) {
		ah_free(buff);
		buff = NULL;
		ah_cli_printf(cmd, "capwap HiveComm test call ah_capwap_hvcom_msg_handle failed.\n");
		return -1;
	}

	ah_free(buff);
	buff = NULL;

	return 0;
}

#endif
