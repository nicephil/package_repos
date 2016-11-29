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
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <error.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "ah_lib.h"
#include "ah_shm.h"
#include "ah_scd_api.h"
#include "ah_event.h"
#include "ah_syscall.h"
#include "ah_trap.h"
#include "ah_capwap_api.h"
#include "ah_alarm.h"


/***************************************************************************
 *
 * Function:   ah_capwap_send_event
 *
 * Purpose:    send event to CAPWAP and add a certain capwap event hdr
 *
 * Inputs:     event_id: event id
 *             event_len: event size
 *             event_msg:data
 *
 * Output:     void
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
int ah_capwap_send_event(ah_event_t event_id, int event_len, void *event_msg)
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

	/*no message information need send*/
	if (event_len < 0 || event_len > AH_CAPWAP_EVENT_MAX_LEN * AH_CAPWAP_NORMAL_EVENT_MAX_PKT) {
		ah_err_old("CAPWAP send buffer length is error!current len(%d) max len(%d)", event_len,
				   (AH_CAPWAP_EVENT_MAX_LEN * AH_CAPWAP_NORMAL_EVENT_MAX_PKT));
		return -1;
	}

	gettimeofday(&tv, &tz);

	/*generate the rand sub_seq*/
	srand(tv.tv_sec + tv.tv_usec);
	sub_seq = 1 + (int)(AH_CAPWAP_EVENT_MAX_RAND * rand() / (RAND_MAX + 1.0));

	/*need seperate the message*/
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
	*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_TOL_FRAG_OFFSET) = htons((int16_t)(pkt_int));

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
			memcpy((msg + AH_CAPWAP_EVENT_MSG_START), (event_msg + (i * AH_CAPWAP_EVENT_MAX_LEN)), cpy_pkt_len);
			snd_len = cpy_pkt_len + AH_CAPWAP_EVENT_MSG_START;
		}

		/*send event*/
		if (ah_event_send(event_id, snd_len, msg) != 0) {
			ah_err_old("Send CAPWAP event error!\n");
			return -1;
		}
	}

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_send_trap
 *
 * Purpose:    send trap to CAPWAP and add a certain capwap trap hdr
 *
 * Inputs:     trap_len: trap length
 *             trap_msg:data
 *
 * Output:     void
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
int ah_capwap_send_trap(int16_t trap_len, void *trap_msg, long trap_type)
{
	int32_t    trap_id = 0;
	char      *trap_buff = NULL;
	int      rc = 0;
	ah_trap_data_with_id_t *trap_data_p = NULL;

	trap_id = msgget(AH_MSG_QUE_TRAP, IPC_CREAT | 0666);
	if (trap_id < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: can not get message queue id to send trap\n");
		return -1;
	}

	trap_buff = malloc(trap_len + sizeof(ah_trap_data_with_id_t));
	if (trap_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: can not malloc buffer to send trap, malloc len:%d\n", trap_len + sizeof(long));
		return -1;
	}
	trap_data_p = (ah_trap_data_with_id_t *)trap_buff;

	trap_data_p->trap_type = trap_type;
	trap_data_p->trap_type_id = AH_MSG_TRAP_NOT_STORE_ID;
	trap_data_p->clear = 0;
	trap_data_p->send2hm_now = 0;
	trap_data_p->data_len = trap_len;
	ah_memcpy(trap_data_p->data, trap_msg, trap_len);

	rc = msgsnd(trap_id, trap_buff, trap_len + sizeof(ah_trap_data_with_id_t) - sizeof(long), IPC_NOWAIT);
	if (rc == -1) {
		ah_log_old(AH_LOG_WARNING, "CAPWAP: send trap to message queue failed, reason:%s\n",
				   (errno == EAGAIN) ? "Trap buffer full" : strerror(errno));
	}
	free(trap_buff);

	return rc;
}

/***************************************************************************
 *
 * Function:   ah_capwap_send_trap_with_id
 *
 * Purpose:    send trap to CAPWAP and add a certain capwap trap hdr
 *
 * Inputs:     trap_len: trap length
 *             trap_msg:data
 *             trap_type_id: type id
 *             clear: clear the alarm or not
 *
 * Output:     void
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
int ah_capwap_send_trap_with_id(int16_t trap_len, void *trap_msg, long trap_type, long trap_type_id, boolean clear)
{
	int32_t    trap_id = 0;
	char      *trap_buff = NULL;
	int      rc = 0;
	ah_trap_data_with_id_t *trap_data_p = NULL;

	trap_id = msgget(AH_MSG_QUE_TRAP, IPC_CREAT | 0666);
	if (trap_id < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: can not get message queue id to send trap\n");
		return -1;
	}

	trap_buff = malloc(trap_len + sizeof(ah_trap_data_with_id_t));
	if (trap_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: can not malloc buffer to send trap, malloc len:%d\n", trap_len + sizeof(long));
		return -1;
	}
	trap_data_p = (ah_trap_data_with_id_t *)trap_buff;

	trap_data_p->trap_type = trap_type;
	trap_data_p->trap_type_id = trap_type_id;
	trap_data_p->clear = clear;
	trap_data_p->send2hm_now = 0;
	trap_data_p->data_len = trap_len;
	ah_memcpy(trap_data_p->data, trap_msg, trap_len);

	rc = msgsnd(trap_id, trap_buff, trap_len + sizeof(ah_trap_data_with_id_t) - sizeof(long), IPC_NOWAIT);
	if (rc == -1) {
		ah_log_old(AH_LOG_WARNING, "CAPWAP: send trap to message queue failed, reason:%s\n",
				   (errno == EAGAIN) ? "Trap buffer full" : strerror(errno));
	}
	free(trap_buff);

	return rc;
}
/***************************************************************************
 *
 * Function:   ah_capwap_is_connecting
 *
 * Purpose:    get current capwap connect status
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    if connecting, return 1, if not connecting, return 0. failed return -1
 *
 **************************************************************************/
inline int ah_capwap_is_connecting()
{
	int capwap_status = 0;

	if (ah_tpa_get_capwap_status(&capwap_status) < 0) {
		return -1;
	}

	return ((capwap_status == AH_CAPWAP_HAS_RUN) ? 1 : 0);
}

#if AH_SUPPORT_UPGRADE_SAFELY
/************************************************************************
 *
 * Function:  ah_capwap_get_conn_info
 *
 * Purpose:   get capwap connection info
 *
 * Input:     N/A
 *
 * Output:    connection status, protocol and port
 *
 * Returns:   success:0 failed return -1;
 *
 *************************************************************************/
int ah_capwap_get_conn_info(ah_capwap_conn_info_t *conn_info)
{
	if (ah_tpa_get_capwap_conn_info(conn_info) < 0) {
		return -1;
	}
	return 0;
}

/************************************************************************
 *
 * Function:  ah_capwap_set_conn_info
 *
 * Purpose:   set capwap connection info to kernel struct
 *
 * Input:     connection info
 *
 * Output:    N/A
 *
 * Returns:   success:0 failed return -1;
 *
 *************************************************************************/
int ah_capwap_set_conn_info(ah_capwap_conn_info_t *conn_info)
{
	int ah_sysdev_fd = -1;
	int rc = 0;

	ah_sysdev_fd = open(AH_SYS_DEV_NAME, O_RDWR);
	if (ah_sysdev_fd < 0) {
		ah_err_old("open device %s failed\n", AH_SYS_DEV_NAME);
		rc = -1;
		goto out;
	}

	/* set to kernel, for force rate limit and stop PM supervision used */
	if (ioctl(ah_sysdev_fd, AH_SYS_IOCTL_SET_CAPWAP_CONN_INFO, &conn_info) == -1) {
		ah_err_old("sys ioctl %d failed", AH_SYS_IOCTL_SET_CAPWAP_CONN_INFO);
		rc = -1;
		goto out;
	}

out:
	if (ah_sysdev_fd >= 0) {
		close(ah_sysdev_fd);
	}
	return rc;
}
#endif

/**
 * @brief format IPV6 address and num.
 * @param[in] addr6_num IPV6 address num.
 * @param[in] addr6 IPV6 address.
 * @param[out] pbuf format string.
 * @return retlen length of format string.
 * @note the string format is as follows:
 *   Number of client IPV6 address item    1 byte
 *   IPV6 address type                     1 byte
 *   Client IPV6 address                   16 byte
 *   Other items of client IPV6 address   (1 + 16) * n
 */
uint16_t ah_capwap_save_sta_addr6(uchar *pbuf, uchar addr6_num, const struct in6_addr *addr6)
{
	uchar i = 0;
	uchar retlen = 0;

	/* station IPV6 address num */
	*pbuf = addr6_num;
	pbuf++;
	retlen++;
	for (i = 0; i < addr6_num; i++) {
		if (ah_is_ipv6_linklocal(&addr6[i])) {
			*pbuf = STATION_IPV6_LOCAL_ADDRES;
		} else {
			*pbuf = STATION_IPV6_GLOBAL_ADDRES;
		}
		pbuf++;
		retlen++;
		memcpy(pbuf, &addr6[i], sizeof(struct in6_addr));

		pbuf += sizeof(struct in6_addr);
		retlen += sizeof(struct in6_addr);
	}
	return retlen;
}

/**************************************************************************
 * Name: ah_capwap_stat_save_ass
 * Function: write table to buf
 * Parameters:
 *           ah_capwap_stat_ass_table_t  *table
 *           ah_uchar_t                  *buf
 * Returns: 0 --- OK
 *************************************************************************/
int    ah_capwap_stat_save_ass
(
	ah_capwap_stat_ass_table_t  *table,
	uchar                  *buf
)
{
	uchar          *pos = buf;
	uchar          len;
	uint32_t         *temp;
	uint32_t           i;
	uint16_t          addr6_len;

	table->if_index = htonl(table->if_index);

	/* client mac not change */

	/* convert client rssi */
	table->rssi = htonl(table->rssi);

	/* convert client linkuptime */
	table->linkup_time = htonl(table->linkup_time);

	table->vlan = htonl(table->vlan);
	table->user_profileId = htonl(table->user_profileId);
	table->channel = htonl(table->channel);
	table->last_txrate = htonl(table->last_txrate);
	table->last_rxrate = htonl(table->last_rxrate);

	table->rx_data_frames = htonl(table->rx_data_frames);
	table->rx_data_octes = htonl(table->rx_data_octes);
	table->rx_mgt_frames = htonl(table->rx_mgt_frames);
	table->rx_uc_frames = htonl(table->rx_uc_frames);
	table->rx_mc_frames = htonl(table->rx_mc_frames);
	table->rx_bc_frames = htonl(table->rx_bc_frames);
	table->rx_mic_failure = htonl(table->rx_mic_failure);

	table->tx_data_frames = htonl(table->tx_data_frames);
	table->tx_data_octets = htonl(table->tx_data_octets);
	table->tx_mgt_frames = htonl(table->tx_mgt_frames);
	table->tx_uc_frames = htonl(table->tx_uc_frames);
	table->tx_mc_frames = htonl(table->tx_mc_frames);
	table->tx_bc_frames = htonl(table->tx_bc_frames);

	memcpy(pos, table, offsetof(ah_capwap_stat_ass_table_t, host_name));
	pos += offsetof(ah_capwap_stat_ass_table_t, host_name);

	/* save client hostname */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->host_name, len,
									AH_CAPWAP_STAT_HOSTNAME_MAX_LEN);

	/* save client SSID */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->ssid_name, len,
									AH_CAPWAP_STAT_SSIDNAME_MAX_LEN);

	/* save client username */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->user_name, len,
									AH_CAPWAP_STAT_USERNAME_MAX_LEN);

	/* convert 4 * uint32_t */
	temp = &table->tx_be_data_frames;
	for (i = 0; i < 4; i++, temp++) {
		*temp = htonl(*temp);
	}

	/* convert 2 * uint64 */
	table->tx_air_time = htonll(table->tx_air_time);
	table->rx_air_time = htonll(table->rx_air_time);
	/* table->client_bssid  no changed (6 bytes)*/

	/* convert ts */
	table->ts = htonl(table->ts);

	/* save 42 bytes */
	memcpy(pos, &table->tx_be_data_frames, sizeof(uint8_t) * 42);
	pos += sizeof(uint8_t) * 42;
	/* save if name  */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->if_name, len,
									AH_CAPWAP_STAT_IFNAME_MAX_LEN);

	/* save if name  */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->soft_env, len,
									AH_CAPWAP_STAT_SOFTENV_MAX_LEN);

	/* save client health */
	ah_memcpy(pos, &table->ipnet_conn_score, sizeof(uint8_t) * 4);
	pos += sizeof(uint8_t) * 4;
	/* save dhcp option 55 string */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->option55, len,
									AH_CAPWAP_STAT_DHCP_OPTION55_MAX_LEN);

	/* user profile name */
	AH_CAPWAP_STAT_SAVE_STAT_STRING(pos, table->prof_name, len, AH_MAX_STR_PARM_LEN);
	/* snr */
	*(int16_t *)pos = htons(table->snr);
	pos += sizeof(int16_t);

	/* mba */
	*pos = table->mba_used;
	pos += sizeof(uint8_t);

	/* managedStatus */
	*(uint16_t *)pos = htons(table->mgt_stus);
	pos += sizeof(uint16_t);

	/* station IPV6 addrss and address num */
	addr6_len = ah_capwap_save_sta_addr6(pos, table->sta_addr6_num, table->sta_addr6);
	pos += addr6_len;

	return ((int)(pos - buf));
}

#define AH_CAPWAP_MALLOC_EVENT_PKT(length)  (malloc((length) + sizeof(ah_capwap_out_msg_hdr_t)))

/***************************************************************************
 *
 * Function:   ah_capwap_get_request_type
 *
 * Purpose:    get capwap request type
 *
 * Inputs:     rst_data: request data
 *
 * Output:     N/A
 *
 * Returns:    if success, return request type, otherwise return -1
 *
 **************************************************************************/
inline int ah_capwap_get_request_type(void *rst_data)
{
	if (rst_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input get CAPWAP request type failed, the pointer is null.");
		return -1;
	}

	return ntohs(((ah_capwap_in_msg_hdr_t *)rst_data)->msg_type);
}

/***************************************************************************
 *
 * Function:   ah_capwap_get_request_header
 *
 * Purpose:    get capwap request header
 *
 * Inputs:     rst_data: request data
 *
 * Output:     rst_hdr: request header
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
inline int ah_capwap_get_request_header(ah_capwap_in_msg_hdr_t *rst_hdr, void *rst_data)
{
	if (rst_hdr == NULL || rst_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input get CAPWAP request header failed, the pointer is null.");
		return -1;
	}

	rst_hdr->msg_type = ntohs(((ah_capwap_in_msg_hdr_t *)rst_data)->msg_type);
	rst_hdr->cookie = ntohl(((ah_capwap_in_msg_hdr_t *)rst_data)->cookie);
	rst_hdr->flag = ((ah_capwap_in_msg_hdr_t *)rst_data)->flag;
	rst_hdr->data_len = ntohl(((ah_capwap_in_msg_hdr_t *)rst_data)->data_len);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_get_request_data
 *
 * Purpose:    get capwap request data address
 *
 * Inputs:     rst_data: request data
 *
 * Output:     N/A
 *
 * Returns:    the address of capwap request data (NULL is no data or error)
 *
 **************************************************************************/
inline char *ah_capwap_get_request_data(void *rst_data)
{
	if (rst_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input get CAPWAP request data failed, the pointer is null.");
		return NULL;
	}

	/*no data, only a header*/
	if (((ah_capwap_in_msg_hdr_t *)rst_data)->data_len == 0) {
		return NULL;
	}

	return (rst_data + sizeof(ah_capwap_in_msg_hdr_t));

}

/***************************************************************************
 *
 * Function:   ah_capwap_get_request_data_len
 *
 * Purpose:    get capwap request data length
 *
 * Inputs:     rst_data: request data
 *
 * Output:     N/A
 *
 * Returns:    the length of capwap request data
 *
 **************************************************************************/
inline int ah_capwap_get_request_data_len(const void *rst_data)
{
	if (rst_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input get CAPWAP request data length failed, the pointer is null.");
		return -1;
	}

	return (ntohl(((ah_capwap_in_msg_hdr_t *)rst_data)->data_len));

}

/***************************************************************************
 *
 * Function:   ah_capwap_get_request_payload
 *
 * Purpose:    get capwap request payload data
 *
 * Inputs:     rst_data: request data
 *
 * Output:     payload_len: payload length
 *             payload: the address of payload
 *
 * Returns:    0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_get_request_payload(const void *rst_data, uint32_t *payload_len, char **payload)
{
	if (rst_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input get CAPWAP request data failed, the pointer is null.");
		return -1;
	}

	*payload_len = (ntohl(((ah_capwap_in_msg_hdr_t *)rst_data)->data_len));
	if (*payload_len == 0) {
		*payload = NULL;
		return 0;
	}

	*payload = (char *)(rst_data) + sizeof(ah_capwap_in_msg_hdr_t);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_set_response_header
 *
 * Purpose:    set capwap response header
 *
 * Inputs:     rst_hdr: request hdr
 *             data_len: the payload datalen
 *
 * Output:     rps_buff: response buff
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
inline int ah_capwap_set_response_header(void *rps_buff, ah_capwap_in_msg_hdr_t *rst_hdr, uint32_t data_len)
{
	if (rst_hdr == NULL || rps_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "Input set CAPWAP reponse header failed, the pointer is null.");
		return -1;
	}

	((ah_capwap_out_msg_hdr_t *)rps_buff)->msg_type = htons(rst_hdr->msg_type);
	((ah_capwap_out_msg_hdr_t *)rps_buff)->cookie = htonl(rst_hdr->cookie);
	((ah_capwap_out_msg_hdr_t *)rps_buff)->data_len = htonl(data_len);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_set_response_data
 *
 * Purpose:    set capwap response data
 *
 * Inputs:     rst_data: request data
 *             data_len: the payload datalen
 *             event_data: event data buffer
 *
 * Output:     rps_buff: response buff
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
inline int ah_capwap_set_response_data(void *rsp_buff, void *rst_data, uint32_t data_len, const void *event_data)
{
	if (rsp_buff == NULL || rst_data == NULL || event_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input set CAPWAP reponse data failed, the pointer is null.");
		return -1;
	}
	/*fill header to HM*/
	((ah_capwap_out_msg_hdr_t *)rsp_buff)->msg_type = ((ah_capwap_in_msg_hdr_t *)event_data)->msg_type;
	((ah_capwap_out_msg_hdr_t *)rsp_buff)->cookie = ((ah_capwap_in_msg_hdr_t *)event_data)->cookie;
	((ah_capwap_out_msg_hdr_t *)rsp_buff)->data_len = htonl(data_len);
	/*fill payload*/
	ah_memcpy(rsp_buff + sizeof(ah_capwap_out_msg_hdr_t), rst_data, data_len);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_get_response_data_len
 *
 * Purpose:    get capwap response data length
 *
 * Inputs:     rps_data: response buffer
 *
 * Output:     N/A
 *
 * Returns:    the length of capwap response
 *
 **************************************************************************/
inline int ah_capwap_get_response_data_len(void *rps_data)
{
	if (rps_data == NULL) {
		ah_log_old(AH_LOG_ERR, "Input get CAPWAP response data length failed, the pointer is null.");
		return -1;
	}

	return (ntohl(((ah_capwap_out_msg_hdr_t *)rps_data)->data_len) + sizeof(ah_capwap_out_msg_hdr_t));

}

/***************************************************************************
 *
 * Function:   ah_capwap_send_event_payload
 *
 * Purpose:    send CAPWAP event payload to capwap
 *
 * Inputs:     event_id: event id
 *             payload: payload
 *             payload_len: the payload length
 *             data: the event data receive from CAPWAP
 *
 * Output:     N/A
 *
 * Returns:    0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_send_event_payload(ah_event_t event_id, void *payload, uint32_t payload_len, const void *data)
{
	char      *rsp_buff = NULL;
	int      rc = -1;

	rsp_buff = AH_CAPWAP_MALLOC_EVENT_PKT(payload_len);
	if (rsp_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "Malloc malloc for send event payload failed, malloc length:%d", payload_len);
		goto OUT;
	}

	if (ah_capwap_set_response_data(rsp_buff, payload, payload_len, data) == -1) {
		ah_log_old(AH_LOG_ERR, "Fill payload to response buffer failed");
		goto OUT;
	}

	if (ah_capwap_send_event(event_id, ah_capwap_get_response_data_len(rsp_buff), rsp_buff) == -1) {
		ah_log_old(AH_LOG_ERR, "Send event (%s) payload to capwap failed.\n", ah_eventid_to_name(event_id));
		goto OUT;
	}
	rc = 0;
OUT:
	if (rsp_buff != NULL) {
		free(rsp_buff);
	}
	return rc;
}

/***************************************************************************
 *
 * Function:   ah_capwap_set_response_data_actively
 *
 * Purpose:    set capwap response data not required by HM
 *
 * Inputs:     rst_data: request data
 *             data_len: the payload datalen
 *             capwap_id: CAPWAP packet type id
 *
 * Output:     rps_buff: response buff
 *
 * Returns:    if success, return 0, otherwise return -1
 *
 **************************************************************************/
inline int ah_capwap_set_response_data_actively(void *rsp_buff, void *rst_data, uint32_t data_len, const uint16_t capwap_id)
{
	if (rsp_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "Input set CAPWAP reponse data failed, the pointer is null.");
		return -1;
	}
	/*fill header to HM*/
	((ah_capwap_out_msg_hdr_t *)rsp_buff)->msg_type = htons(capwap_id);
	((ah_capwap_out_msg_hdr_t *)rsp_buff)->cookie = htonl(0);
	((ah_capwap_out_msg_hdr_t *)rsp_buff)->data_len = htonl(data_len);
	/*fill payload*/
	if (rst_data != NULL) {
		ah_memcpy(rsp_buff + sizeof(ah_capwap_out_msg_hdr_t), rst_data, data_len);
	}

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_send_event_payload_actively
 *
 * Purpose:    send CAPWAP event payload to capwap not required by HM
 *
 * Inputs:     event_id: event id
 *             payload: payload
 *             payload_len: the payload length
 *             CAPWAP_ID: CAPWAP message type id
 *
 * Output:     N/A
 *
 * Returns:    0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_send_event_payload_actively(ah_event_t event_id, void *payload, uint32_t payload_len, const uint16_t capwap_id)
{
	char      *rsp_buff = NULL;
	int      rc = -1;

	rsp_buff = AH_CAPWAP_MALLOC_EVENT_PKT(payload_len);
	if (rsp_buff == NULL) {
		ah_log_old(AH_LOG_ERR, "Malloc malloc for send event payload failed, malloc length:%d", payload_len);
		goto OUT;
	}

	if (ah_capwap_set_response_data_actively(rsp_buff, payload, payload_len, capwap_id) == -1) {
		ah_log_old(AH_LOG_ERR, "Fill payload to response buffer failed");
		goto OUT;
	}

	if (ah_capwap_send_event(event_id, ah_capwap_get_response_data_len(rsp_buff), rsp_buff) == -1) {
		ah_log_old(AH_LOG_ERR, "Send event (%s) payload to capwap failed.\n", ah_eventid_to_name(event_id));
		goto OUT;
	}
	rc = 0;
OUT:
	if (rsp_buff != NULL) {
		free(rsp_buff);
	}
	return rc;
}

int ah_capwap_get_shm(ah_capwap_recovery_t **shm)
{
	int      shmid;

	ah_assert(NULL != shm);

	shmid = shmget(AH_CAPWAP_SHM_ID, sizeof(ah_capwap_recovery_t), IPC_EXCL);
	if (shmid == -1) {
		ah_log_old(AH_LOG_ERR, "Get capwap share memory failed.\n");
		return -1;
	}

	*shm = (ah_capwap_recovery_t *)shmat(shmid, NULL, 0);
	if (*shm == (ah_capwap_recovery_t *) - 1) {
		ah_log_old(AH_LOG_ERR, "Attatch capwap share memory failed.\n");
		return -1;
	}

	return 0;
}


int ah_capwap_send_generic_alarm(ah_capwap_generic_alarm_item_t *items, long trap_type_id, boolean clear)
{
	ah_capwap_generic_alarm_hdr_t header;
	ah_capwap_generic_alarm_item_t *pitem = items;
	int      total_len = 0;
	int      item_len = 0;
	int      item_num = 0;
	char      *trap;
	char      *p;
	int      rc = 0;

	memset(&header, 0, sizeof(header));

	/* calculate the length */
	total_len += sizeof(header);
	while (pitem != NULL) {
		item_len = AH_GENERIC_ALARM_ITEM_HEAD_LEN + pitem->desc_len
				   + AH_GENERIC_ALARM_ITEM_TAG_HEAD_LEN + pitem->tag3_len;
		total_len += item_len;
		++item_num;
		pitem = pitem->next;
	}
	pitem = items;

	/* init the trap buffer */
	trap = malloc(total_len);
	if (trap == NULL) {
		ah_err_old("%s: out of memory", __func__);
		return -1;
	}
	memset(trap, 0, total_len);
	p = trap;

	/* fill the header */
	header.trap_type = AH_MSG_TRAP_GENERIC_ALARM;
	header.length = htons(total_len
						  - sizeof(uint8_t) - sizeof(uint16_t)); /* exclude trap_type and length */
	header.item_num = htons(item_num);
	memcpy(p, &header, sizeof(header));
	p += sizeof(header);

	/* fill items */
	while (pitem != NULL) {
		/* item length */
		*(uint16_t *)p = htons(pitem->length);
		p += sizeof(uint16_t);

		/* alarm id */
		*(uint16_t *)p = htons(pitem->alarm_id);
		p += sizeof(uint16_t);

		/* severity */
		*p = pitem->severity;
		++p;

		/* description length */
		*p = pitem->desc_len;
		++p;

		/* description */
		if (pitem->desc_len != 0 && pitem->desc != NULL) {
			memcpy(p, pitem->desc, pitem->desc_len);
			p += pitem->desc_len;
		}

		/* tag1 */
		*(int32_t *)p = htonl(pitem->tag1);
		p += sizeof(int32_t);

		/* tag2 */
		*(int32_t *)p = htonl(pitem->tag2);
		p += sizeof(int32_t);

		/* tag3 */
		*p = pitem->tag3_len;
		++p;
		if (pitem->tag3_len != 0 && pitem->tag3 != NULL) {
			memcpy(p, pitem->tag3, pitem->tag3_len);
			p += pitem->tag3_len;
		}

		pitem = pitem->next;
	}

	if (ah_capwap_send_trap_with_id(total_len, (void *)trap, AH_MSG_TRAP_GENERIC_ALARM, trap_type_id, clear) != 0) {
		ah_err_old("%s: Send trap AH_MSG_TRAP_GENERIC_ALARM to capwap failed\n", __func__);
		rc = -1;
		goto ERR;
	}
ERR:
	free(trap);
	return rc;
}

