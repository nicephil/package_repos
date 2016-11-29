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
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include<sys/stat.h>

#include "ah_types.h"
#include "ah_trap.h"
#include "ah_syscall.h"
#include "ah_dbg_agent.h"
#include "ah_capwap_api.h"

#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_func.h"
#include "ah_db_api.h"
#include "ah_alarm.h"
#include "ah_shm.h"
#include "ah_lib.h"


static uint32_t trap_seq = 0;
/*trap type (1 byte) + data len (2 bytes)*/
#define AH_CAPWAP_TRAP_FIXED_LEN 3
#define AH_TRAP_MAX_BUFF_LEN 1300

static int lock_semid = -1;
static int lock_init = 0;
static int ah_capwap_alarms_resending = 0;

/*
 *     desc:    get the sempaphore for cache list
 *     return:  success  - semID
 *              failure  - -1
 */

static int  ah_lock_sem_init()
{
	if (lock_init == 1) {
		return 0;
	}

	lock_semid = ah_sem_create(AH_CAPWAP_TRAP_DB_SEM_ID, 1);
	if (lock_semid == -1) {
		ah_err_old("capwap trap DB: ah_sem_create failed.\n");
		return -1;
	}

	lock_init = 1;
	return 0;
}

static int ah_lock_p(void)
{
	if (!lock_init) {
		if (ah_lock_sem_init() < 0) {
			ah_err_old("capwap trap DB: init lock sem failed./n");
			return -1;
		}
	}
	/* P() */
	ah_sem_wait(lock_semid);

	return 0;
}

static void ah_lock_v(void)
{
	/* V() */
	ah_sem_signal(lock_semid);
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_trap_header
 *
 * Purpose:   generate all the trap common part
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
void ah_capwap_fill_trap_header(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   0             1               2               3               4
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |    data length          |   length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length     |                   describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |              code                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/*fill trap type*/
	*(char *)(p) = trap->data.trap_type;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap type is:%d\n", trap->data.trap_type);
	/*skip 2 bytes for fill total len*/
	p += sizeof(uint16_t);
	cur_len += sizeof(uint16_t);
	/*fill object name len (all the trap name is the same and at the first byte)*/
	*(char *)(p) = strlen(trap->data.failure_trap.name);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill object name*/
	memcpy(p, trap->data.failure_trap.name, strlen(trap->data.failure_trap.name));
	p += strlen(trap->data.failure_trap.name);
	cur_len += strlen(trap->data.failure_trap.name);
	ah_dbg_old(capwap_trap, "trap object name:%s, length:%d\n", trap->data.failure_trap.name, strlen(trap->data.failure_trap.name));
	/*fill description len*/
	*(char *)(p) = strlen(trap->desc);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill description*/
	memcpy(p, trap->desc, strlen(trap->desc));
	p += strlen(trap->desc);
	cur_len += strlen(trap->desc);
	ah_dbg_old(capwap_trap, "trap description:%s, length:%d\n", trap->desc, strlen(trap->desc));
	/*fill code, now it is 0 (except connect changed trap)*/
	*(uint32_t *)(p) = htonl(trap->msg_id);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap code:%d\n", trap->msg_id);

	*buff_len = cur_len;
	ah_dbg_old(capwap_trap, "fill trap header len:%d\n", *buff_len);

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_failure_trap
 *
 * Purpose:   generate failure trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_failure_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   Failure trap info format:
	   0             1               2               3               4
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |    data length          |   length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length     |                   describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |              code                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |   severity  |propable cause| failure set |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill severity*/
	*(char *)(p) = trap->level;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap severity:%d\n", trap->level);
	/*fill propable cause*/
	*(char *)(p) = (char)(trap->data.failure_trap.cause);
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap propable cause:%d\n", trap->data.failure_trap.cause);
	/* fill failure set */
	*(char *)(p) = (char)trap->data.failure_trap.set;
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap failure set:%d\n", trap->data.failure_trap.set);

	*buff_len = cur_len;

	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);

	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_threshold_trap
 *
 * Purpose:   generate threshold change trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_threshold_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   Threshold trap info format:
	   0             1               2               3               4
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |         data length |       length        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |             code                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |             current value                              |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |             threshold high                     |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |             threshold low                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill current value*/
	*(uint32_t *)(p) = htonl(trap->data.threshold_trap.cur_val);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap current value:%d\n", trap->data.threshold_trap.cur_val);
	/*fill threshold high*/
	*(uint32_t *)(p) = htonl(trap->data.threshold_trap.threshold_high);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap high value:%d\n", trap->data.threshold_trap.threshold_high);
	/*fill threshold low*/
	*(uint32_t *)(p) = htonl(trap->data.threshold_trap.threshold_low);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap low value:%d\n", trap->data.threshold_trap.threshold_low);

	*buff_len = cur_len;

	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);

	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_state_change_trap
 *
 * Purpose:   generate state change trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_state_change_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   State change trap info format:
	   0             1               2               3               4
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |   data length       | length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          code                              |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |previous state|current state|                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill privious state*/
	*(char *)(p) = trap->data.state_change_trap.pre_state;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap privious state:%d\n", trap->data.state_change_trap.pre_state);
	/*fill current state*/
	*(char *)(p) = trap->data.state_change_trap.cur_state;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap current state:%d\n", trap->data.state_change_trap.cur_state);

	*buff_len = cur_len;

	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_connection_change_trap
 *
 * Purpose:   generate connection change trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_connection_change_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	uint8_t string_len = 0;

	/*
	   Connection change info format:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |  data length        | length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          code                              |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          if index                          |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Remote ID
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |current state | object type     |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                        client ip               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |length      |client host name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | length     |client user name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | length     |client SSID¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |CWP used   |auth method  |encrypt method|mac protocol|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          client VLAN                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          client user profile id                |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          client channel                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | length             |if name...                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | rssi          |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	char *p = NULL;
	uint16_t cur_len = 0;
	uint16_t sta_addr6_len = 0;
	int32_t i;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill interface index*/
	*(uint32_t *)(p) = htonl(trap->data.connection_change_trap.if_index);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap interface index:%d\n", trap->data.connection_change_trap.if_index);
	/*fill Remote id*/
	memcpy(p, trap->data.connection_change_trap.remote_id, MACADDR_LEN);
	p += MACADDR_LEN;
	cur_len += MACADDR_LEN;
	ah_dbg_old(capwap_trap, "trap remote id:%m\n", trap->data.connection_change_trap.remote_id);
	/*fill current state*/
	*(char *)(p) = (char)trap->data.connection_change_trap.cur_state;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap current state:%d\n", trap->data.connection_change_trap.cur_state);
	/*fill object type*/
	*(char *)(p) = (char)trap->data.connection_change_trap.object_type;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap object type:%d\n", trap->data.connection_change_trap.object_type);
	/*fill client ip*/
	*(uint32_t *)(p) = htonl(trap->data.connection_change_trap.client_ip);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap client ip:%i\n", htonl(trap->data.connection_change_trap.client_ip));
	/*fill client host name len*/
	*(char *)(p) = strlen(trap->data.connection_change_trap.host_name);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill client host name*/
	memcpy(p, trap->data.connection_change_trap.host_name, strlen(trap->data.connection_change_trap.host_name));
	p += strlen(trap->data.connection_change_trap.host_name);
	cur_len += strlen(trap->data.connection_change_trap.host_name);
	ah_dbg_old(capwap_trap, "trap client host name :%s, len:%d",
			   trap->data.connection_change_trap.host_name, strlen(trap->data.connection_change_trap.host_name));
	/*fill client user name len*/
	*(char *)(p) = strlen(trap->data.connection_change_trap.user_name);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill client user name*/
	memcpy(p, trap->data.connection_change_trap.user_name, strlen(trap->data.connection_change_trap.user_name));
	p += strlen(trap->data.connection_change_trap.user_name);
	cur_len += strlen(trap->data.connection_change_trap.user_name);
	ah_dbg_old(capwap_trap, "trap client username :%s, len:%d",
			   trap->data.connection_change_trap.user_name, strlen(trap->data.connection_change_trap.user_name));
	/*fill client ssid len*/
	*(char *)(p) = strlen(trap->data.connection_change_trap.ssid);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill client ssid*/
	memcpy(p, trap->data.connection_change_trap.ssid, strlen(trap->data.connection_change_trap.ssid));
	p += strlen(trap->data.connection_change_trap.ssid);
	cur_len += strlen(trap->data.connection_change_trap.ssid);
	ah_dbg_old(capwap_trap, "trap client username :%s, len:%d",
			   trap->data.connection_change_trap.ssid, strlen(trap->data.connection_change_trap.ssid));
	/*fill cwp used*/
	*(char *)(p) = (char)trap->data.connection_change_trap.client_cwp_used;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap cwp used :%d", trap->data.connection_change_trap.client_cwp_used);
	/*fill auth method*/
	*(char *)(p) = (char)trap->data.connection_change_trap.client_auth_method;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap auth method :%d", trap->data.connection_change_trap.client_auth_method);
	/*fill encrypt method*/
	*(char *)(p) = (char)trap->data.connection_change_trap.client_encrypt_method;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap encrypt method :%d", trap->data.connection_change_trap.client_encrypt_method);
	/*fill mac protocol*/
	*(char *)(p) = (char)trap->data.connection_change_trap.client_mac_proto;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap mac protocol :%d", trap->data.connection_change_trap.client_mac_proto);
	/*fill client vlan id*/
	*(uint32_t *)(p) = htonl(trap->data.connection_change_trap.client_vlan);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap client vlan id :%d", trap->data.connection_change_trap.client_vlan);
	/*fill user profile id*/
	*(uint32_t *)(p) = htonl(trap->data.connection_change_trap.client_upid);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap user profile id :%d", trap->data.connection_change_trap.client_upid);
	/*fill client channel*/
	*(uint32_t *)(p) = htonl(trap->data.connection_change_trap.client_channel);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap client channel :%d", trap->data.connection_change_trap.client_channel);
	/*fill BSSID*/
	memcpy(p, trap->data.connection_change_trap.b_ssid, MACADDR_LEN);
	p += MACADDR_LEN;
	cur_len += MACADDR_LEN;
	ah_dbg_old(capwap_trap, "trap bssid:%m", trap->data.connection_change_trap.b_ssid);
	/*fill association time*/
	*(uint32_t *)(p) = htonl(trap->data.connection_change_trap.association_time);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap association time :%d", trap->data.connection_change_trap.association_time);
	/*fill client ifname len*/
	*(char *)(p) = strlen(trap->data.connection_change_trap.if_name);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill ifname*/
	memcpy(p, trap->data.connection_change_trap.if_name, strlen(trap->data.connection_change_trap.if_name));
	p += strlen(trap->data.connection_change_trap.if_name);
	cur_len += strlen(trap->data.connection_change_trap.if_name);
	ah_dbg_old(capwap_trap, "trap ifname :%s, len:%d",
			   trap->data.connection_change_trap.if_name, strlen(trap->data.connection_change_trap.if_name));

	/* fill rssi */
	*(int32_t *)(p) = htonl(trap->data.connection_change_trap.rssi);
	p += sizeof(int32_t);
	cur_len += sizeof(int32_t);
	ah_dbg_old(capwap_trap, "trap sta's rssi :%d", trap->data.connection_change_trap.rssi);

	/* user profile name len*/
	string_len = strlen(trap->data.connection_change_trap.prof_name);
	*(uint8_t *)(p) = string_len;
	p += sizeof(uint8_t);
	cur_len += sizeof(uint8_t);

	/* user profile name*/
	memcpy(p, trap->data.connection_change_trap.prof_name, string_len);
	p += string_len;
	cur_len += string_len;
	ah_dbg_old(capwap_trap, "trap user profile name :%s, len:%d", trap->data.connection_change_trap.prof_name, string_len);

	/* fill SNR */
	*(int16_t *)p = htons((int16_t)trap->data.connection_change_trap.snr);
	p += sizeof(int16_t);
	cur_len += sizeof(int16_t);
	ah_dbg_old(capwap_trap, "trap sta's SNR:%d\n", trap->data.connection_change_trap.snr);

	/* fill MAC based auth */
	*p = trap->data.connection_change_trap.client_mac_based_auth_used;
	p += sizeof(uchar);
	cur_len += sizeof(uchar);
	ah_dbg_old(capwap_trap, "trap MBA used:%d\n", trap->data.connection_change_trap.client_mac_based_auth_used);

	string_len = strlen(trap->data.connection_change_trap.os);
	*(uint8_t *)(p) = string_len;
	p += sizeof(uint8_t);
	cur_len += sizeof(uint8_t);
	memcpy(p, trap->data.connection_change_trap.os, string_len);
	p += string_len;
	cur_len += string_len;
	ah_dbg_old(capwap_trap, "trap os name :%s, len:%d", trap->data.connection_change_trap.os, string_len);
	string_len = strlen((char *)trap->data.connection_change_trap.option55);
	*(uint8_t *)(p) = string_len;
	p += sizeof(uint8_t);
	cur_len += sizeof(uint8_t);
	memcpy(p, trap->data.connection_change_trap.option55, string_len);
	p += string_len;
	cur_len += string_len;
	ah_dbg_old(capwap_trap, "option55 :%s, len:%d", trap->data.connection_change_trap.option55, string_len);

	/* fill managedStatus */
	*(uint16_t *)p = htons((int16_t)trap->data.connection_change_trap.mgt_stus);
	p += sizeof(uint16_t);
	cur_len += sizeof(int16_t);
	ah_dbg_old(capwap_trap,  "trap management status:%d\n", trap->data.connection_change_trap.mgt_stus);

	sta_addr6_len = ah_capwap_save_sta_addr6((uchar *)p, trap->data.connection_change_trap.sta_addr6_num,
					trap->data.connection_change_trap.sta_addr6);
	cur_len += sta_addr6_len;
	ah_dbg_old(capwap_trap,  "connection change trap sta addr6_num:%d\n", trap->data.connection_change_trap.sta_addr6_num);
	if (capwap_trap) {
		for (i = 0; i < trap->data.connection_change_trap.sta_addr6_num; i ++) {
			ah_dbg_old(capwap_trap,  "connection change trap sta addr6[%d]:%pI6c\n", i, &trap->data.connection_change_trap.sta_addr6[i]);
		}
	}
	*buff_len = cur_len;
	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_client_info_trap
 *
 * Purpose:   generate client info trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_client_info_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   Client info trap info format:
	   0             1               2               3               4
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |   data length       | length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                code                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | length     |client SSID¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          Client MAC
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |        client ip
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |length      |client host name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | length     |client user name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	char *p = NULL;
	uint16_t cur_len = 0;
	uint16_t sta_addr6_len = 0;
	int32_t i;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill ssid len*/
	*(char *)(p) = strlen(trap->data.client_info_trap.ssid);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill ssid*/
	memcpy(p, trap->data.client_info_trap.ssid, strlen(trap->data.client_info_trap.ssid));
	p += strlen(trap->data.client_info_trap.ssid);
	cur_len += strlen(trap->data.client_info_trap.ssid);
	ah_dbg_old(capwap_trap, "trap ssid:%s, length:%d\n", trap->data.client_info_trap.ssid, strlen(trap->data.client_info_trap.ssid));
	/*fill client mac*/
	memcpy(p, trap->data.client_info_trap.client_mac, MACADDR_LEN);
	p += MACADDR_LEN;
	cur_len += MACADDR_LEN;
	ah_dbg_old(capwap_trap, "trap client mac:%m\n", trap->data.client_info_trap.client_mac);
	/*fill client ip*/
	*(uint32_t *)(p) = htonl(trap->data.client_info_trap.client_ip);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap client ip:%i\n", htonl(trap->data.client_info_trap.client_ip));
	/*fill client hostname len*/
	*(char *)(p) = strlen(trap->data.client_info_trap.host_name);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill client hostname*/
	memcpy(p, trap->data.client_info_trap.host_name, strlen(trap->data.client_info_trap.host_name));
	p += strlen(trap->data.client_info_trap.host_name);
	cur_len += strlen(trap->data.client_info_trap.host_name);
	ah_dbg_old(capwap_trap, "trap hostname:%s, length:%d\n", trap->data.client_info_trap.host_name,
			   strlen(trap->data.client_info_trap.host_name));
	/*fill client username len*/
	*(char *)(p) = strlen(trap->data.client_info_trap.user_name);
	p += sizeof(char);
	cur_len += sizeof(char);
	/*fill client username*/
	memcpy(p, trap->data.client_info_trap.user_name, strlen(trap->data.client_info_trap.user_name));
	p += strlen(trap->data.client_info_trap.user_name);
	cur_len += strlen(trap->data.client_info_trap.user_name);
	ah_dbg_old(capwap_trap, "trap user name:%s, length:%d\n", trap->data.client_info_trap.user_name,
			   strlen(trap->data.client_info_trap.user_name));

	/*fill client management status*/
	*(uint16_t *)(p) = htons(trap->data.client_info_trap.mgt_stus);
	p += sizeof(uint16_t);
	cur_len += sizeof(uint16_t);
	ah_dbg_old(capwap_trap, "Client info management status:%d", trap->data.client_info_trap.mgt_stus);

	/**
	 * fill station IPV6 address and num
	 */
	sta_addr6_len = ah_capwap_save_sta_addr6((uchar *)p, trap->data.client_info_trap.sta_addr6_num,
					trap->data.client_info_trap.sta_addr6);
	cur_len += sta_addr6_len;
	ah_dbg_old(capwap_trap,  "client info trap sta addr6_num:%d\n", trap->data.client_info_trap.sta_addr6_num);
	if (capwap_trap) {
		for (i = 0; i < trap->data.client_info_trap.sta_addr6_num; i ++) {
			ah_dbg_old(capwap_trap,  "client info trap sta addr6[%d]:%pI6c\n", i, &trap->data.client_info_trap.sta_addr6[i]);
		}
	}

	*buff_len = cur_len;

	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_power_info_trap
 *
 * Purpose:   generate power info trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_power_info_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   Power info event trap info format:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |   data length         |   length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                 code                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                   power source             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |PoEEth0On  |            PoEEth0Pwr
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | PoEEth1On  |           PoEEth1Pwr
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |
	   +-+-+-+-+-+-+-+-+-+-+-
	 */

	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill power source*/
	*(uint32_t *)(p) = htonl(trap->data.power_info_trap.power_src);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap powr source:%d\n", trap->data.power_info_trap.power_src);
	/*fill PoE Eth0 On*/
	*(char *)(p) = trap->data.power_info_trap.eth0_on;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr eth0 On:%d\n", trap->data.power_info_trap.eth0_on);
	/*fill PoE Eth0 Pwr*/
	*(uint32_t *)(p) = htonl(trap->data.power_info_trap.eth0_pwr);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap powr eth0 power:%d\n", trap->data.power_info_trap.eth0_pwr);
	/*fill PoE Eth1 On*/
	*(char *)(p) = trap->data.power_info_trap.eth1_on;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr eth1 On:%d\n", trap->data.power_info_trap.eth1_on);
	/*fill PoE Eth1 Pwr*/
	*(uint32_t *)(p) = htonl(trap->data.power_info_trap.eth1_pwr);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap powr eth1 power:%d\n", trap->data.power_info_trap.eth1_pwr);
	/*fill eth0 speed*/
	*(char *)(p) = trap->data.power_info_trap.eth0_speed;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr eth0 speed:%d\n", trap->data.power_info_trap.eth0_speed);
	/*fill eth1 speed*/
	*(char *)(p) = trap->data.power_info_trap.eth1_speed;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr eth1 speed:%d\n", trap->data.power_info_trap.eth1_speed);
	/*fill wifi0 settting*/
	*(char *)(p) = trap->data.power_info_trap.wifi0_setting;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr wifi0 setting:%d\n", trap->data.power_info_trap.wifi0_setting);
	/*fill wifi1 settting*/
	*(char *)(p) = trap->data.power_info_trap.wifi1_setting;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr wifi1 setting:%d\n", trap->data.power_info_trap.wifi1_setting);
	/*fill wifi2 settting*/
	*(char *)(p) = trap->data.power_info_trap.wifi2_setting;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap powr wifi2 setting:%d\n", trap->data.power_info_trap.wifi2_setting);

	*buff_len = cur_len;

	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_channel_power_trap
 *
 * Purpose:   generate channel power trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *            *severity: the trap level
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_channel_power_trap(const ah_trap_msg_t  *trap, char *trap_buff, uint16_t *buff_len)
{
	/*
	   Channel power change event trap info format:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |  data length        | length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      code                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                   ifindex                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |            Radio channel               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |            Radio Tx Power                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |            Beacon Interval               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/*fill trap header*/
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/*fill ifindex*/
	*(uint32_t *)(p) = htonl(trap->data.channel_power_trap.if_index);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap ifindex:%d\n", trap->data.channel_power_trap.if_index);
	/*fill radio channel*/
	*(uint32_t *)(p) = htonl(trap->data.channel_power_trap.radio_channel);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap radio channel:%d\n", trap->data.channel_power_trap.radio_channel);
	/*fill radio tx power*/
	*(uint32_t *)(p) = htonl(trap->data.channel_power_trap.radio_tx_power);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap radio tx power:%d\n", trap->data.channel_power_trap.radio_tx_power);
	/*fill radio beacon interval */
	*(uint32_t *)(p) = htonl(trap->data.channel_power_trap.beacon_interval);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap radio beacon interval:%u\n", trap->data.channel_power_trap.beacon_interval);

	*buff_len = cur_len;

	/*fill total len*/
	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_interface_alert_trap
 *
 * Purpose:   generate interface alert trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_interface_alert_trap(const ah_trap_msg_t *trap,
									   char      *trap_buff, uint16_t *buff_len)
{
	/*
	   Power info event trap info format:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |   data length         |   length         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                 code                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                   ifindex                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |failure set   | Severity  | CU threshold | Running average |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Short term cu|Snapshot| CRC errorthreshold | CRC error rate|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |
	   +-+-+-+-+-+-+-+-+-+-+-
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;

	p = trap_buff;
	/* fill trap header */
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;
	/* fill ifindex */
	*(uint32_t *)(p) = htonl(trap->data.interference_alert_trap.if_index);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "trap interface alert ifindex:%d\n", trap->data.interference_alert_trap.if_index);

	/* fill failure set */
	*p = (char)trap->data.interference_alert_trap.set;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap interface alert failure set:%d\n", trap->data.interference_alert_trap.set);

	/*fill severity*/
	*p = (char)trap->level;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap interface alert severity set:%d\n", trap->level);

	/* fill Interference CU threshold */
	*p = (char)trap->data.interference_alert_trap.interference_thres;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap interface CU threshold:%d\n", trap->data.interference_alert_trap.interference_thres);

	/* fill Running average interference CU */
	*p = (char)trap->data.interference_alert_trap.ave_interference;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap interface Running average interference CU:%d\n", trap->data.interference_alert_trap.ave_interference);

	/* fill Short term interference CU */
	*p = (char)trap->data.interference_alert_trap.short_interference;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap interface Short term interference CU:%d\n", trap->data.interference_alert_trap.short_interference);

	/* fill Snapshot interference */
	*p = (char)trap->data.interference_alert_trap.snap_interference;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "trap interface Snapshot:%d\n", trap->data.interference_alert_trap.snap_interference);

	/* fill CRC error rate threshold */
	*p = (char)trap->data.interference_alert_trap.crc_err_rate_thres;
	p += sizeof(char);
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "CRC error rate threshold:%d\n", trap->data.interference_alert_trap.crc_err_rate_thres);

	/* fill CRC error rate*/
	*p = (char)trap->data.interference_alert_trap.crc_err_rate;
	cur_len += sizeof(char);
	ah_dbg_old(capwap_trap, "CRC error rate:%d\n", trap->data.interference_alert_trap.crc_err_rate);

	*buff_len = cur_len;

	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_bw_sentinel_trap
 *
 * Purpose:   generate bandwidth sentinal trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_bw_sentinel_trap(const ah_trap_msg_t *trap,
								   char      *trap_buff, uint16_t *buff_len)
{
	/*
	   Bandwidth sentinal trap:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |   data length         |   length         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                 code                      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                   ifindex                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                 client mac                            |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     client mac          |    bandwidth sentinal status|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |bandwidth sentinal status| Guaranteed bandwidth        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Guaranteed bandwidth    | Actual bandwidth            |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	   | Actual bandwidth        | Action Taken                |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	   | Action Taken            |                             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;

	ah_assert(trap != NULL);
	ah_assert(trap_buff != NULL);
	ah_assert(buff_len != NULL);

	p = trap_buff;

	/* fill trap header */
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;

	/* fill trap bw sentinel ifindex */
	*(uint32_t *)p = htonl(trap->data.bw_sentinel_trap.if_index);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "bw sentinel trap ifindex:%d\n", trap->data.bw_sentinel_trap.if_index);

	/* fill trap bw sentinel mac */
	memcpy(p, trap->data.bw_sentinel_trap.client_mac, AH_CAPWAP_MAC_LEN);
	p += AH_CAPWAP_MAC_LEN;
	cur_len += AH_CAPWAP_MAC_LEN;
	ah_dbg_old(capwap_trap, "bw sentinel trap client mac:%s\n", trap->data.bw_sentinel_trap.client_mac);

	/* fill trap bw sentinel status */
	*(uint32_t *)p = htonl(trap->data.bw_sentinel_trap.bw_sentinel_status);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "bw sentinel trap status:%d\n", trap->data.bw_sentinel_trap.bw_sentinel_status);

	/* fill trap bw sentinel guaranteed value */
	*(uint32_t *)p = htonl(trap->data.bw_sentinel_trap.gbw);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "bw sentinel trap guaranteed:%d\n", trap->data.bw_sentinel_trap.gbw);

	/* fill trap bw sentinel actual value */
	*(uint32_t *)p = htonl(trap->data.bw_sentinel_trap.actual_bw);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "bw sentinel trap actual:%d\n", trap->data.bw_sentinel_trap.actual_bw);

	/* fill trap bw action taken value */
	*(uint32_t *)p = htonl(trap->data.bw_sentinel_trap.action_taken);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "bw sentinel trap action taken:%d\n", trap->data.bw_sentinel_trap.action_taken);

	/* fill trap bw channel util */
	*p = trap->data.bw_sentinel_trap.chnl_util;
	p++;
	cur_len++;

	/* fill trap bw interference util */
	*p = trap->data.bw_sentinel_trap.interference_util;
	p++;
	cur_len++;

	/* fill trap bw tx util */
	*p = trap->data.bw_sentinel_trap.tx_util;
	p++;
	cur_len++;

	/* fill trap bw rx util */
	*p = trap->data.bw_sentinel_trap.rx_util;
	cur_len++;
	ah_dbg_old(capwap_trap,
			   "bw sentinel trap channel ultil:%u, bw sentinel trap interference ultil:%u, bw sentinel trap tx ultil:%u, bw sentinel trap rx ultil:%u\n",
			   trap->data.bw_sentinel_trap.chnl_util, trap->data.bw_sentinel_trap.interference_util, trap->data.bw_sentinel_trap.tx_util,
			   trap->data.bw_sentinel_trap.rx_util);

	*buff_len = cur_len;

	*(uint16_t *)(trap_buff + sizeof(char)) = htons(*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap len:%d\n", *buff_len);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_stats_alarm_trap
 *
 * Purpose:   generate statistic report alarm trap
 *
 * Inputs:    *trap: the trap data struct
 *            *trap_info: the description for trap
 *
 * Output:    *trap_buff: the capwap trap buffer
 *            *buff_len: the capwap trap length
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_stats_alarm_trap(const ah_trap_msg_t *trap,
								   char      *trap_buff, uint16_t *buff_len)
{
	/*
	   statistic report trap:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap type  |   data length         |   length         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | Object name¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  length    |    describe¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                 code                      |      level
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                   ifindex                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                 client mac                            |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | ssid length|            ssid name
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |alert type|  ThresholdValue
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	            |    ShortTermValue
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	            |    SnapshotValue
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	            |   Severity |  failure state
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	 */
	char      *p = NULL;
	uint16_t    cur_len = 0;
	int      str_len = 0;

	ah_assert(NULL != trap);
	ah_assert(NULL != trap_buff);
	ah_assert(NULL != buff_len);

	p = trap_buff;

	/* fill trap header */
	ah_capwap_fill_trap_header(trap, p, &cur_len);
	p += cur_len;

	/* fill stats alarm trap level */
	*(uchar *)p = trap->data.alarm_alert_trap.level;
	p += sizeof(uchar);
	cur_len += sizeof(uchar);
	ah_dbg_old(capwap_trap, "stats alarm trap level:%d\n", trap->data.alarm_alert_trap.level);

	/* fill stats alarm trap ifindex */
	*(uint32_t *)p = htonl(trap->data.alarm_alert_trap.if_index);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "stats alarm trap ifindex:%d\n", trap->data.alarm_alert_trap.if_index);

	/* fill stats alarm trap client mac */
	ah_memcpy(p, trap->data.alarm_alert_trap.client_mac, AH_CAPWAP_MAC_LEN);
	p += AH_CAPWAP_MAC_LEN;
	cur_len += AH_CAPWAP_MAC_LEN;
	ah_dbg_old(capwap_trap, "stats alarm trap client mac:%m\n", trap->data.alarm_alert_trap.client_mac);

	/* fill stats alarm trap ssid length */
	str_len = ah_strlen(trap->data.alarm_alert_trap.ssid);
	*(uchar *)p = str_len;
	p += sizeof(uchar);
	cur_len += sizeof(uchar);
	ah_dbg_old(capwap_trap, "stats alarm trap ssid length:%d\n", str_len);

	/* fill stats ssid name */
	if (str_len > 0) {
		ah_memcpy(p, trap->data.alarm_alert_trap.ssid, str_len);
		p += str_len;
		cur_len += str_len;
		ah_dbg_old(capwap_trap, "stats alarm trap ssid name:%s\n", trap->data.alarm_alert_trap.ssid);
	}

	/* fill stats alert type */
	*(uchar *)p = trap->data.alarm_alert_trap.alert_type;
	p += sizeof(uchar);
	cur_len += sizeof(uchar);
	ah_dbg_old(capwap_trap, "stats alarm trap alert type:%d\n", trap->data.alarm_alert_trap.alert_type);

	/* fill stats ThresholdValue */
	*(uint32_t *)p = htonl(trap->data.alarm_alert_trap.thres_interference);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "stats alarm trap threshold value:%d\n", trap->data.alarm_alert_trap.thres_interference);

	/* fill stats ShortTermValue */
	*(uint32_t *)p = htonl(trap->data.alarm_alert_trap.short_interference);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "stats alarm trap short term value:%d\n", trap->data.alarm_alert_trap.short_interference);

	/* fill stats SnapshotValue */
	*(uint32_t *)p = htonl(trap->data.alarm_alert_trap.snap_interference);
	p += sizeof(uint32_t);
	cur_len += sizeof(uint32_t);
	ah_dbg_old(capwap_trap, "stats alarm trap snapshot value:%d\n", trap->data.alarm_alert_trap.snap_interference);

	/* fill stats Severity */
	*(uchar *)p = trap->level;
	p += sizeof(uchar);
	cur_len += sizeof(uchar);
	ah_dbg_old(capwap_trap, "stats alarm trap severity:%d\n", trap->level);

	/* fill stats failure state */
	*(uchar *)p = trap->data.alarm_alert_trap.set;
	cur_len += sizeof(uchar);
	ah_dbg_old(capwap_trap, "stats alarm trap failure state:%d\n", trap->data.alarm_alert_trap.set);

	*buff_len = cur_len;

	*(uint16_t *)(trap_buff + sizeof(uchar)) = (*buff_len - AH_CAPWAP_TRAP_FIXED_LEN);
	ah_dbg_old(capwap_trap, "total trap length:%d\n", *buff_len);

	return 0;
}


static void ah_capwap_active_alarm_show_cb(AH_DB_FILE dbf, ah_db_datum key, void *arg)
{
	uint32_t    size = 0;
	uchar      *data = NULL;
	ah_cmd_handle_t *cmd = (ah_cmd_handle_t *)arg;
	ah_trap_data_with_id_t *trap_data_p = NULL;


	/* fetch item size */
	if ((ah_db_fetch_size(dbf, key.dptr, key.dsize, &size) < 0)
		|| (size == 0)) {
		ah_err_old("CAPWAP: fetch failed\n");
		goto out;
	}

	data = (uchar *)ah_calloc(1, size);
	if (data == NULL) {
		ah_err_old("CAPWAP: malloc memory failed\n");
		goto out;
	}

	if (ah_db_fetch_bykey(dbf, key, data) < 0) {
		ah_err_old("CAPWAP: fetch capwap trap data failed!\n");
		free(data);
		data = NULL;
		goto out;
	}
	trap_data_p = (ah_trap_data_with_id_t *)data;

	ah_cli_printf(cmd, "%-8d 0x%-10x %-8s %-8s %-8d\n", trap_data_p->trap_type,
				  trap_data_p->trap_type_id,
				  trap_data_p->clear == AH_MSG_TRAP_CLEAR ? "Yes" : "No",
				  trap_data_p->send2hm_now ? "Yes" : "No",
				  trap_data_p->data_len);

	free(data);
out:
	return;
}

int ah_capwap_show_active_alarms(ah_cmd_handle_t *cmd)
{
	AH_DB_FILE dbf = NULL;
	int      rc = 0;

	ah_lock_p();
	if ((dbf = ah_db_open(AH_MSG_TRAP_DB)) == NULL) {
		ah_err_old("CAPWAP: open capwap trap database failed : %s\n", AH_MSG_TRAP_DB);
		rc = -1;
		goto out;
	}
	ah_cli_printf(cmd, "ah_capwap_alarms_resending = %s\n%-8s %-10s %-8s %-8s %-8s\n",
				  ah_capwap_alarms_resending ? "Yes" : "No", "MsgType", "AlarmID", "Clear", "Send2HM", "DataLen");
	ah_db_foreach(dbf, ah_capwap_active_alarm_show_cb, cmd);
out:
	if (dbf != NULL) {
		ah_db_close(dbf);
	}
	ah_lock_v();
	return rc;
}

static void ah_capwap_walk_db2send_active_alarm(AH_DB_FILE dbf, ah_db_datum key, void *arg)
{

	long      trap_type_id = AH_MSG_TRAP_NOT_STORE_ID;
	uint32_t    size = 0;
	uchar      *data = NULL;
	ah_trap_data_with_id_t *trap_data_p = NULL;


	/* fetch item size */
	if ((ah_db_fetch_size(dbf, key.dptr, key.dsize, &size) < 0)
		|| (size == 0)) {
		ah_err_old("CAPWAP: fetch trap db size failed\n");
		goto out;
	}

	data = (uchar *)ah_calloc(1, size);
	if (data == NULL) {
		ah_err_old("CAPWAP: malloc memory size=%d failed\n", size);
		goto out;
	}

	if (ah_db_fetch_bykey(dbf, key, data) < 0) {
		ah_err_old("CAPWAP: fetch capwap trap data failed!\n");
		goto out;
	}
	trap_data_p = (ah_trap_data_with_id_t *)data;
	trap_type_id = trap_data_p->trap_type_id;
	trap_data_p->send2hm_now = TRUE;
	ah_capwap_alarms_resending = 1;

	if (ah_db_store(dbf, &trap_type_id, sizeof(trap_type_id),
					data, size) < 0) {
		ah_err_old("CAPWAP: store trap data failed, internal alarm ID 0x%x\n", trap_type_id);
		goto out;
	}

out:
	if (data) {
		ah_free(data);
	}

	return;
}


static int ah_capwap_get_active_alarm_buff(AH_DB_FILE dbf, ah_db_datum key, void *arg)
{

	long      trap_type_id = AH_MSG_TRAP_NOT_STORE_ID;
	uint32_t    size = 0;
	uchar      *data = NULL;
	ah_trap_data_with_id_t *trap_data_p = NULL;
	char *ret_buff = (char *)arg;
	int found = 0;


	/* fetch item size */
	if ((ah_db_fetch_size(dbf, key.dptr, key.dsize, &size) < 0)
		|| (size == 0)) {
		ah_err_old("CAPWAP: fetch trap db size failed\n");
		goto out;
	}

	data = (uchar *)ah_calloc(1, size);
	if (data == NULL) {
		ah_err_old("CAPWAP: malloc memory size=%d failed\n", size);
		goto out;
	}

	if (ah_db_fetch_bykey(dbf, key, data) < 0) {
		ah_err_old("CAPWAP: fetch capwap trap data failed!\n");
		goto out;
	}
	memcpy(ret_buff, data, size);
	trap_data_p = (ah_trap_data_with_id_t *)data;
	trap_type_id = trap_data_p->trap_type_id;
	if (trap_data_p->send2hm_now) {
		found = 1;
		trap_data_p->send2hm_now = FALSE;
	}

	if (ah_db_store(dbf, &trap_type_id, sizeof(trap_type_id),
					data, size) < 0) {
		ah_err_old("CAPWAP: store trap data failed, internal alarm ID 0x%x\n", trap_type_id);
		goto out;
	}

out:
	if (data) {
		ah_free(data);
	}

	return found;
}

int ah_capwap_get_one_active_alarm(char *ret_buff)
{
	AH_DB_FILE dbf = NULL;
	int rc = -1;
	int found = 0;

	ah_lock_p();
	if ((dbf = ah_db_open(AH_MSG_TRAP_DB)) == NULL) {
		ah_err_old("CAPWAP: open capwap trap database failed : %s\n", AH_MSG_TRAP_DB);
		goto out;
	}


	found = ah_db_foreach_found(dbf, ah_capwap_get_active_alarm_buff, ret_buff);
	/* not found any alarm to send, set flag to 0 */    
	if (found == 0) {
		ah_capwap_alarms_resending = 0;
	} else {
		rc = 0;
	}

out:
	if (dbf != NULL) {
		ah_db_close(dbf);
	}
	ah_lock_v();
	return rc;
}

int ah_capwap_resend_active_alarm(void)
{
	AH_DB_FILE dbf = NULL;
	int      rc = 0;

	ah_lock_p();
	if ((dbf = ah_db_open(AH_MSG_TRAP_DB)) == NULL) {
		ah_err_old("CAPWAP: open capwap trap database failed : %s\n", AH_MSG_TRAP_DB);
		rc = -1;
		goto out;
	}

	ah_db_foreach(dbf, ah_capwap_walk_db2send_active_alarm, NULL);
out:
	if (dbf != NULL) {
		ah_db_close(dbf);
	}
	ah_lock_v();
	return rc;
}

static int ah_capwap_update_trap_db(long trap_type_id, boolean clear, char *trap_buff, int buff_len)
{

	AH_DB_FILE dbf = NULL;
	int      rc = -1;

	ah_lock_p();
	if ((dbf = ah_db_open(AH_MSG_TRAP_DB)) == NULL) {
		ah_err_old("CAPWAP: open capwap trap database failed : %s\n", AH_MSG_TRAP_DB);
		goto out;
	}

	if (clear == AH_MSG_TRAP_SET) {
		/* stored to db */
		if (ah_db_store(dbf, &trap_type_id, sizeof(trap_type_id),
						trap_buff, buff_len) < 0) {
			ah_err_old("CAPWAP: store trap type id 0x%x failed!\n", trap_type_id);
			goto out;
		}
		ah_dbg_old(capwap_trap, "capwap store alarm data to db, internal alarm ID:0x%x clear:%d data len:%d\n",

				   trap_type_id, clear, buff_len);
		if (capwap_trap) {
			ah_dbg_old(capwap_trap, "capwap store trap buffer to DB:\n");
			ah_hexdump((uchar *)trap_buff, buff_len);
		}
	} else {
		/* remove from db */
		if (!ah_db_exists(dbf, (char *)&trap_type_id, sizeof(trap_type_id))) {
			goto out;
		}
		if (ah_db_delete(dbf, &trap_type_id, sizeof(trap_type_id)) < 0) {
			ah_err_old("delete trap type id 0x%x db entry failed!\n", trap_type_id);
			goto out;
		}
		ah_dbg_old(capwap_trap, "capwap remove alarm data from db, internal alarm ID:0x%x clear:%d data len:%d\n",

				   trap_type_id, clear, buff_len);
	}
	rc = 0;

out:
	if (dbf != NULL) {
		ah_db_close(dbf);
	}
	ah_lock_v();
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_trap_buff
 *
 * Purpose:   generate capwap trap buff and send to HM
 *
 * Inputs:    *trap: the trap data struct
 *
 * Output:    void
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_trap_buff(const ah_trap_msg_t  *trap)
{
	/*
	   Trap event:
	   0            1            2            3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | request sequence number                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     sequence number                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap info ¡­
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	char trap_buff[AH_TRAP_MAX_BUFF_LEN] = {0};
	uint16_t trap_len = 0;
	int buff_len = 0;

	/*fill request sequence number (4 bytes)*/
	*(uint32_t *)(trap_buff) = 0;
	buff_len += sizeof(uint32_t);
	/*fill sequenct number (4 bytes)*/
	*(uint32_t *)(trap_buff + buff_len) = htonl(trap_seq);
	buff_len += sizeof(uint32_t);
	/*fill trap info*/
	switch (trap->data.trap_type) {
	case AH_FAILURE_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive failure trap!\n");
		ah_capwap_gen_failure_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_THRESHOLD_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive threshold trap!\n");
		ah_capwap_gen_threshold_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_STATE_CHANGE_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive state change trap!\n");
		ah_capwap_gen_state_change_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_CONNECTION_CHANGE_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive connection change trap!\n");
		if ((trap->msg_id & LOG_AUTH_CONNECT_DOWN) == LOG_AUTH_CONNECT_DOWN
			/* in wireless mode, driver will send this trap, so drop it here
			 * in wired mode, no driver send it, we need send the trap here*/
			&& !ah_is_ethernet_ifname((char *)trap->data.connection_change_trap.if_name)) {
			ah_dbg_old(capwap_trap, "CAPWAP drop disconnection trap because Driver will send associate event inluce this information! msg_id:%x\n",
					   trap->msg_id);
			return 0;
		}
		ah_capwap_gen_connection_change_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_POWER_INFO_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive power info trap!\n");
		ah_capwap_gen_power_info_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_CHANNEL_POWER_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive channel power trap!\n");
		ah_capwap_gen_channel_power_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_CLIENT_INFO_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive client info trap!\n");
		ah_capwap_gen_client_info_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_INTERFERENCE_ALERT_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive interface alert trap!\n");
		ah_capwap_gen_interface_alert_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_BW_SENTINEL_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive bandwidth sentinel trap!\n");
		ah_capwap_gen_bw_sentinel_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	case AH_ALARM_ALERT_TRAP_TYPE:
		ah_dbg_old(capwap_trap, "CAPWAP receive stats alarm trap!\n");
		ah_capwap_gen_stats_alarm_trap(trap, (trap_buff + buff_len), &trap_len);
		break;
	default:
		ah_dbg_old(capwap_trap, "CAPWAP receive unkown trap! (id=%d)\n", trap->data.trap_type);
		return 0;
	}
	/*total len*/
	buff_len += trap_len;
	ah_dbg_old(capwap_trap, "Send capwap trap sequence number:%d, total len:%d\n", trap_seq, buff_len);
	if (capwap_trap) {
		ah_dbg_old(capwap_trap, "printf capwap send trap buffer:\n");
		ah_hexdump((uchar *)trap_buff, buff_len);
	}
	/*send the trap information to event buffer*/
	ah_capwap_send_event_itself(buff_len, trap_buff, AH_CAPWAP_EVENT_SEND_TRAP);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_other_trap_buff
 *
 * Purpose:   generate capwap other type trap buff and send to HM
 *
 * Inputs:    *trap_info: the description for trap
 *            trap_len: the trap length
 *
 * Output:    void
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_other_trap_buff(char *trap_info, int trap_len)
{
	/*
	   Trap event:
	   0               1               2               3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | request sequence number                                     |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | sequence number                                             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | trap info ...                                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	char      trap_buff[AH_TRAP_MAX_BUFF_LEN] = {0};
	int      buff_len = 0;

	ah_dbg_old(capwap_trap, "CAPWAP receive other type trap!\n");
	/*fill request sequence number (4 bytes)*/
	*(uint32_t *)(trap_buff) = 0;
	buff_len += sizeof(uint32_t);
	/*fill sequenct number (4 bytes)*/
	*(uint32_t *)(trap_buff + buff_len) = htonl(trap_seq);
	buff_len += sizeof(uint32_t);
	/*fill trap info*/
	ah_memcpy(trap_buff + buff_len, trap_info, trap_len);
	buff_len += trap_len;

	ah_dbg_old(capwap_trap, "Send capwap trap sequence number:%d, total len:%d\n", trap_seq, buff_len);
	if (capwap_trap) {
		ah_dbg_old(capwap_trap, "print capwap send trap buffer:\n");
		ah_hexdump((uchar *)trap_buff, buff_len);
	}
	/*send the trap information to event buffer*/
	ah_capwap_send_event_itself(buff_len, trap_buff, AH_CAPWAP_EVENT_SEND_TRAP);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_gen_error_cli_trap
 *
 * Purpose:   generate capwap error cli trap
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 is success, others is failed
 *
 **************************************************************************/
int ah_capwap_gen_error_cli_trap()
{
	FILE *fp = NULL;
	int      rc = -1;
	char      *trap_buff = NULL;
	uint32_t    buff_len = 0;
	struct stat file_buf ;

	fp = fopen(AH_CAPWAP_ERROR_CLI_FILE, "r");
	if (fp == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: read file %s failed, maybe there have not error cli information, (%s)\n",
				   AH_CAPWAP_ERROR_CLI_FILE, strerror(errno));
		goto OUT;
	}

	if (stat(AH_CAPWAP_ERROR_CLI_FILE, &file_buf) < 0) {
		ah_err_old("%s: fetch file's info failed.", __func__);
		goto OUT;
	}
	buff_len = file_buf.st_size;

	if ((trap_buff = malloc(buff_len)) == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: malloc for send execute cli failed information to HM faied, malloc len:%d\n", buff_len);
		goto OUT;
	}
	if (fread(trap_buff, sizeof(char), buff_len, fp) != buff_len) {
		ah_log_old(AH_LOG_WARNING, "CAPWAP: read file %s information failed, reason:%s\n", AH_CAPWAP_ERROR_CLI_FILE, strerror(errno));
		goto OUT;
	}

	ah_dbg_old(capwap_cli, "Send capwap execute cli failed information, total len:%d\n", buff_len);
	if (capwap_cli) {
		ah_dbg_old(capwap_cli, "print capwap execute cli failed information:\n");
		ah_hexdump((uchar *)trap_buff, buff_len);
	}
	/*send information to HM*/
	ah_capwap_send_event_itself(buff_len, trap_buff, AH_CAPWAP_EVENT_CLI);

	/*delete file*/
	unlink(AH_CAPWAP_ERROR_CLI_FILE);

	rc = 0;
OUT:
	if (fp != NULL) {
		fclose(fp);
	}

	if (trap_buff != NULL) {
		free(trap_buff);
		trap_buff = NULL;
	}

	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_trap
 *
 * Purpose:   the main thread for get trap information
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   NULL
 *
 **************************************************************************/
void *ah_capwap_get_trap()
{
#define AH_CAPWAP_MAX_SEND_TRAP_BUFFER 20
	char      trap_buf[AH_CAPWAP_EVENT_MAX_LEN + 100] = {0};
	ah_trap_msg_t *trap_info = NULL;
	ulong      trap_type = 0;
	int      trap_len = 0;
	int      trap_msg_id = 0;
	uint      buff_num = 0;
	boolean check_error_cli = FALSE;
	int      rc = 0;
	long      trap_type_id = AH_MSG_TRAP_NOT_STORE_ID;
	boolean clear = 0;
	ah_trap_data_with_id_t *trap_data_p = NULL;

	trap_msg_id = msgget(AH_MSG_QUE_TRAP, IPC_CREAT | 0666);
	if (trap_msg_id < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: Can not get trap message queue id! reason:%s\n", strerror(errno));
		return NULL;
	}

	while (1) {
		if (ah_capwap_info.state == AH_CAPWAP_RUN && ah_capwap_para.event_flag == AH_CAPWAP_EVENT_SND_ON
			&& ah_capwap_info.event != AH_CAPWAP_CHG_EVENT_SND_PKT && ah_capwap_info.event != AH_CAPWAP_CHG_EVENT_RCV_PKT) {
			/*check if the event buffer less than AH_CAPWAP_MAX_SEND_TRAP_BUFFER, then don't get trap information*/
			buff_num = ah_capwap_get_free_buffer_count(0);
			if (buff_num <= AH_CAPWAP_MAX_SEND_TRAP_BUFFER) {
				ah_dbg_old(capwap_trap, "no enough capwap event buffer can be used to send trap to HM, waiting...\n");
				ah_sleep(1);
				continue;
			}
			/*report error cli information*/
			if (check_error_cli && (access(AH_CAPWAP_ERROR_CLI_FILE, F_OK) == 0)) {
				rc = ah_capwap_gen_error_cli_trap();
			}
			/*send successfully. don't check again*/
			if (check_error_cli && rc == 0) {
				check_error_cli = FALSE;
			}
			ah_memset(trap_buf, 0x00, AH_CAPWAP_EVENT_MAX_LEN);
			if (ah_capwap_alarms_resending &&
				(ah_capwap_get_one_active_alarm(trap_buf) == 0)) {
				trap_data_p = (ah_trap_data_with_id_t *)trap_buf;
				trap_type = trap_data_p->trap_type;
				trap_type_id = trap_data_p->trap_type_id;
				clear = trap_data_p->clear;
				trap_len = trap_data_p->data_len;
				ah_dbg_old(capwap_trap, "Get trap information from DB,  "
						   "total len:%d, data len %d, trap type:%d internal alarm ID:0x%x clear:%d\n",
						   trap_len + sizeof(ah_trap_data_with_id_t), trap_len, trap_type, trap_type_id, clear);
			} else {
				/*get the trap infomation from message queue*/
				trap_len = msgrcv(trap_msg_id, trap_buf, AH_CAPWAP_EVENT_MAX_LEN, 0, MSG_NOERROR | IPC_NOWAIT);
				if (trap_len == -1) {
					if (errno != ENOMSG) {
						ah_log_old(AH_LOG_ERR, "CAPWAP: receive trap from message failed! reason:%s\n", strerror(errno));
					}
					ah_sleep(1);
					continue;
				}
				/*get trap type*/
				trap_data_p = (ah_trap_data_with_id_t *)trap_buf;
				trap_type = trap_data_p->trap_type;
				trap_type_id = trap_data_p->trap_type_id;
				clear = trap_data_p->clear;
				/* update the trap db */
				if (trap_type_id != AH_MSG_TRAP_NOT_STORE_ID) {
					ah_capwap_update_trap_db(trap_type_id, clear, trap_buf, trap_len + sizeof(long));
				}

				ah_dbg_old(capwap_trap, "Get trap information, total len:%d, data len %d, trap type:%d internal alarm ID:0x%x clear:%d\n",
						   trap_len, trap_data_p->data_len, trap_type, trap_type_id, clear);
				trap_len = trap_data_p->data_len;
			}
			switch (trap_type) {
			case AH_MSG_TRAP_TYPE:
				trap_info = (ah_trap_msg_t *)(trap_data_p->data);
				/*general capwap trap packet*/
				ah_capwap_gen_trap_buff(trap_info);
				break;
			case AH_MSG_TRAP_TB:
			case AH_MSG_TRAP_ASD:
#ifdef AH_VPN_ENABLE
			case AH_MSG_TRAP_VPN:
#endif
			case AH_MSG_TRAP_SSID_BIND_UNBIND:
			case AH_MSG_TRAP_STA_LEAVE_STATS:
			case AH_MSG_TRAP_BSSID_SPOOFING:
			case AH_MSG_TRAP_STA_OS_INFO:
			case AH_MSG_TRAP_RADIUSD_LDAP_ALARM:
			case AH_MSG_TRAP_CAPWAP_DELAY:
			case AH_MSG_TRAP_REPORT_CWP_INFO:
			case AH_MSG_TRAP_SELF_REG_INFO:
			case AH_MSG_TRAP_DFS_BANG:
#ifdef AH_SUPPORT_PSE
			case AH_MSG_TRAP_PSE:
#endif
#ifdef AH_SUPPORT_VOIP_QOS
			case AH_MSG_TRAP_VOIP_QOS_POLICING:
#endif
			case AH_MSG_TRAP_GENERIC_ALARM:
			case AH_MSG_TRAP_POE:
			case AH_MSG_TRAP_DEV_IP_CHANGE:
				ah_capwap_gen_other_trap_buff(trap_data_p->data, trap_len);
				break;
			default:
				ah_log_old(AH_LOG_INFO, "CAPWAP: receive an unknown trap type, type is:%d\n", trap_type);
				continue;
			}
			/*increase trap seqence number*/
			trap_seq ++;
			ah_usleep(0, 100000);
		} else {
			/*get the trap infomation from message queue*/
			trap_len = msgrcv(trap_msg_id, trap_buf, AH_CAPWAP_EVENT_MAX_LEN, 0, MSG_NOERROR | IPC_NOWAIT);
			if (trap_len == -1) {
				if (errno != ENOMSG) {
					ah_log_old(AH_LOG_ERR, "CAPWAP: receive trap from message failed! reason:%s\n", strerror(errno));
				}
				ah_sleep(1);
				continue;
			}
			/*get trap type*/
			trap_data_p = (ah_trap_data_with_id_t *)trap_buf;
			trap_type = trap_data_p->trap_type;
			trap_type_id = trap_data_p->trap_type_id;
			clear = trap_data_p->clear;
			ah_dbg_old(capwap_trap, "Get trap information, total len:%d, data len %d, trap type:%d internal alarm ID:0x%x clear:%d\n",
					   trap_len, trap_data_p->data_len, trap_type, trap_type_id, clear);
			/* update the trap db */
			if (trap_type_id != AH_MSG_TRAP_NOT_STORE_ID) {
				ah_capwap_update_trap_db(trap_type_id, clear, trap_buf, trap_len + sizeof(long));
			} else {
				ah_log_old(AH_LOG_INFO, "CAPWAP is disconnected, discard trap message, "
						   "total len:%d trap type:%d internal alarm ID:0x%x clear:%d\n",
						   trap_len, trap_type, trap_type_id, clear);
			}
			ah_usleep(0, 100000);
			check_error_cli = TRUE;
		}
	}

	return NULL;
}



