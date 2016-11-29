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
#ifndef AH_CAPWAP_DEF_H
#include "ah_capwap_api.h"

#define AH_CAPWAP_DEF_H

#define AH_CAPWAP_DBG                       1
#define AH_CAPWAP_PORT_INVALID              0
#define AH_CAPWAP_MAX_FRAG_ID               1024
#define AH_CAPWAP_FRAG_NUM_INVALID          (AH_CAPWAP_MAX_FRAG_ID + 1)
#define AH_CAPWAP_PORT                      12222
#define AH_CAPWAP_HTTP_DEFAULT_PORT         80
#define AH_CAPWAP_BROADCAST                 0xffffffff
#define AH_CAPWAP_MAC_LEN                   6
#define AH_CAPWAP_WTP_SN_LEN                15
#define MAX_WTP_NAME_LEN                    40
#define AH_CAPWAP_BUF_LEN                   1500
#define AH_CAPWAP_MGT                       default_hvi_name()
#define AH_CAPWAP_FRAG_MAX_NUM              60
/*distinguish capwap request packet and response packet*/
#define AH_CAPWAP_PKT_RQST_SEQ              256
#define AH_CAPWAP_ECHO_HAS_RCV              0
#define AH_CAPWAP_ECHO_HAS_SND              1
#define AH_CAPWAP_EVENT_SND_OFF             0
#define AH_CAPWAP_EVENT_SND_ON              1
#define AH_CAPWAP_NOT_PORT                  0
#define AH_CAPWAP_IS_PORT                   1
#define AH_CAPWAP_VERSION                   7
#define AH_CAPWAP_DTLS_PASS_DFT             "dfAWErt3e454-69-3-2=#on()?22334$"
#define AH_CAPWAP_DONT_CHG_AC               1
#define AH_CAPWAP_NEED_CHG_AC               0

/*CAPWAP STATE*/
#define AH_CAPWAP_START                     0
#define AH_CAPWAP_GET_HOST_IP               1
#define AH_CAPWAP_GET_NMS_IP                2
#define AH_CAPWAP_IDLE                      3
#define AH_CAPWAP_DISCOVERY                 4
#define AH_CAPWAP_DTLS_SETUP                5
#define AH_CAPWAP_DTLS_TDWN                 6
#define AH_CAPWAP_SULKING                   7
#define AH_CAPWAP_JOIN                      8
#define AH_CAPWAP_RUN                       9
#define AH_CAPWAP_END                       10

/*CAPWAP TIMER TYPE*/
#define AH_CAPWAP_TIMER_NONE                0
#define AH_CAPWAP_TIMER_DISCOVERY           1
#define AH_CAPWAP_TIMER_ECHO                2
#define AH_CAPWAP_TIMER_MAXDISCOVERY        3
#define AH_CAPWAP_TIMER_NEIGHBORDEAD        4
#define AH_CAPWAP_TIMER_RESPONSE            5
#define AH_CAPWAP_TIMER_RETRANSMIT          6
#define AH_CAPWAP_TIMER_SILENT              7
#define AH_CAPWAP_TIMER_WAITJOIN            8
#define AH_CAPWAP_TIMER_IDLE                9
#define AH_CAPWAP_TIMER_GET_NMS             10
#define AH_CAPWAP_TIMER_EVENT               11
#define AH_CAPWAP_TIMER_DTLS_CUT            12
#define AH_CAPWAP_TIMER_DTLS_CONN           13

/*THE DEFAULT VALUE FOR CAPWAP TIMER*/
#define AH_CAPWAP_TIMER_NONE_DFT            0
#define AH_CAPWAP_TIMER_RESPONSE_DFT        1
#define AH_CAPWAP_TIMER_IDLE_DFT            1
#define AH_CAPWAP_TIMER_RESTRANSMIT_DFT     3
#define AH_CAPWAP_TIMER_GET_NMS_DFT         3
#define AH_CAPWAP_TIMER_DISCOVERY_DFT       5
#define AH_CAPWAP_TIMER_DTLS_CUT_DFT        5
#define AH_CAPWAP_TIMER_MAXDISCOVERY_DFT    10
#define AH_CAPWAP_TIMER_SILENT_DFT          15
#define AH_CAPWAP_TIMER_ECHO_DFT            30
#define AH_CAPWAP_TIMER_EVENT_DFT           30
#define AH_CAPWAP_TIMER_WAITJOIN_DFT        60
#define AH_CAPWAP_TIMER_DTLS_CONN_DFT       60
#define AH_CAPWAP_TIMER_NEIGHBORDEAD_DFT    105
#define AH_CAPWAP_TIMER_STAT_UPDATE_DFT    0

/*CAPWAP PACKET TYPE*/
#define AH_CAPWAP_DISCOVERY_REQUEST         1
#define AH_CAPWAP_DISCOVERY_RESPONSE        2
#define AH_CAPWAP_JOIN_REQUEST              3
#define AH_CAPWAP_JOIN_RESPONSE             4
#define AH_CAPWAP_EVENT_REQUEST             9
#define AH_CAPWAP_EVENT_RESPONSE            10
#define AH_CAPWAP_CHGSTATE_EVENT_REQUEST    11
#define AH_CAPWAP_CHGSTATE_EVENT_RESPONSE   12
#define AH_CAPWAP_ECHO_REQUEST              13
#define AH_CAPWAP_ECHO_RESPONSE             14
/*Aerohive private packet*/
#define AH_CAPWAP_CONFIG_REQUEST            1001
#define AH_CAPWAP_CONFIG_RESPONSE           1002
#define AH_CAPWAP_IDP_REQUEST               1003
#define AH_CAPWAP_IDP_RESPONSE              1004
#define AH_CAPWAP_CHG_EVENT_REQUEST         1005
#define AH_CAPWAP_CHG_EVENT_PESPONSE        1006
#define AH_CAPWAP_CLI_REQUEST               1007
#define AH_CAPWAP_CLI_RESPONSE              1008
#define AH_CAPWAP_STA_REQUEST               1009
#define AH_CAPWAP_STA_RESPONSE              1010
#define AH_CAPWAP_ABORT_IMAGE_REQUEST       1011
#define AH_CAPWAP_ABORT_IMAGE_RESPONSE      1012
#define AH_CAPWAP_GET_CWP_DIR_REQUEST       1013
#define AH_CAPWAP_GET_CWP_DIR_RESPONSE      1014
#define AH_CAPWAP_SSH_KEY_REQUEST           1015
#define AH_CAPWAP_SSH_KEY_RESPONSE          1016
#define AH_CAPWAP_INFORMATION_REQUEST       1017
#define AH_CAPWAP_INFORMATION_RESPONSE      1018
#define AH_CAPWAP_EVENT_INFO_REQUEST        1019
#define AH_CAPWAP_EVENT_INFO_RESPONSE       1020
#define AH_CAPWAP_MAX_MSG_NUM               1021

/*CAPWAP COUNTER DEFAULT VALUE*/
#define AH_CAPWAP_MAXRETRY_COUNT_DFT        2
#define AH_CAPWAP_MAXDISCOVERY_COUNT_DFT    3
#define AH_CAPWAP_DTLS_MAX_RETRY_DFT        3

/*CAPWAP EVENT TYPE*/
#define AH_CAPWAP_EVENT_NONE                0
#define AH_CAPWAP_WAIT_CLI                  1
#define AH_CAPWAP_WAIT_SND_PKT              2
#define AH_CAPWAP_SND_PKT                   3
#define AH_CAPWAP_RCV_PKT                   4
#define AH_CAPWAP_CHG_EVENT_SND_PKT         5
#define AH_CAPWAP_CHG_EVENT_RCV_PKT         6
#define AH_CAPWAP_SND_EVENT                 7
#define AH_CAPWAP_RCV_EVENT                 8
#define AH_CAPWAP_DTLS_HANDSHAKE            9
#define AH_CAPWAP_DTLS_DISCONN              10

/*CAPWAP SEND PACKET MODE*/
#define AH_CAPWAP_SND_BROADCAST             1
#define AH_CAPWAP_SND_UNICAST               2

/*CAPWAP GET AC IP MODE*/
#define AH_CAPWAP_GET_AC_MANUAL             0
#define AH_CAPWAP_GET_AC_DHCP               1
#define AH_CAPWAP_GET_AC_BROADCAST          2
#define AH_CAPWAP_GET_AC_INIT               3

/*CAPWAP ENABLE OR DISABLE*/
#define AH_CAPWAP_ENABLE                    1
#define AH_CAPWAP_DISABLE                   0

/*CAPWAP DISCOVERY BROADCAST ENABLE OR DISABLE*/
#define AH_CAPWAP_DISCOVERY_BROADCAST_ENABLE     0
#define AH_CAPWAP_DISCOVERY_BROADCAST_DISABLE    1

/*CAPWAP RECEIVE EVENT FLAG*/
#define AH_CAPWAP_EVENT_WAIT                0
#define AH_CAPWAP_EVENT_NMS_IP_CHGD         1
#define AH_CAPWAP_EVENT_HOST_IP_CHGD        2
#define AH_CAPWAP_EVENT_INTERFACE_UP        3
#define AH_CAPWAP_EVENT_RECONNECT           4

/*THESE EVENTS MUST BE SEND BY EVENT REQUEST PKT*/
#define AH_CAPWAP_EVENT_SND_START           6000
#define AH_CAPWAP_EVENT_IDP                 6001
/*because the 6002 is used for the option event switch pass by HM*/
#define AH_CAPWAP_EVENT_PORT                6101
#define AH_CAPWAP_EVENT_CLI                 6102
#define AH_CAPWAP_EVENT_DOWNLOAD            6103
#define AH_CAPWAP_EVENT_STATISTICAL         6104    /* send statistical data */
#define AH_CAPWAP_EVENT_REBOOT_FAILED       6105
#define AH_CAPWAP_EVENT_CFG_VER_CHGED       6106
#define AH_CAPWAP_EVENT_CWP_DIR             6107
#define AH_CAPWAP_EVENT_SSH_KEY             6108
#define AH_CAPWAP_EVENT_HOSTNAME_CHG        6109
#define AH_CAPWAP_EVENT_MGT0_HIVE_CHG       6110
#define AH_CAPWAP_EVENT_SEND_TRAP           6200
#define AH_CAPWAP_INFO_QUERY_REQUEST        6210
#define AH_CAPWAP_INFO_QUERY_RESPONSE       6211
#define AH_CAPWAP_EVENT_GET_REQUEST         6212
#define AH_CAPWAP_EVENT_SEND_RESPONSE       6213
#define AH_CAPWAP_EVENT_QUERY_RESULT        6214
#define AH_CAPWAP_EVENT_SND_END             6500

/*the max event type number for event counter*/
#define AH_CAPWAP_MAX_EVENT_COUNTER_TYPE    13

/*CAPWAP TIMER OUT FLAG*/
#define AH_CAPWAP_TIMER_DONE                0
#define AH_CAPWAP_TIMER_WAIT                1

/*CAPWAP DTLS ENABLE*/
#define AH_CAPWAP_DTLS_DISABLE              0
#define AH_CAPWAP_DTLS_ENABLE               1

/*CAPWAP DTLS ALWAYS ACCEPT BOOTSTRAP PASSPHRASE*/
#define AH_CAPWAP_DTLS_ACCEPT_BOOTSTRAP_ENABLE  1
#define AH_CAPWAP_DTLS_ACCEPT_BOOTSTRAP_DISABLE 0

/*CAPWAP DTLS PACKET IN*/
#define AH_CAPWAP_ERROR_PKT                 0
#define AH_CAPWAP_CLEAR_PKT                 1
#define AH_CAPWAP_DTLS_PKT                  2

#define AH_CAPWAP_DTLS_NEGOTIATION_DISABLE  0
#define AH_CAPWAP_DTLS_NEGOTIATION_ENABLE   1

/*CAPWAP compress packet header*/
#define AH_CAPWAP_CLI_COMPRESS_PACKET  1
#define AH_CAPWAP_COMPRESS_FLAG_LEN    1
#define AH_CAPWAP_UNCOMPRESS_SIZE_LEN  4

typedef enum {
	AH_CAPWAP_RECONNECT_ENABLE_CHANGED = 1000,
	AH_CAPWAP_RECONNECT_DTLS_CHANGED,
	AH_CAPWAP_RECONNECT_PORT_CHANGED,
	AH_CAPWAP_RECONNECT_HOST_IP_CHANGED,
	AH_CAPWAP_RECONNECT_HM_IP_CHANGED,
	AH_CAPWAP_RECONNECT_BOX_REBOOT,
	AH_CAPWAP_RECONNECT_TIMEOUT,
	AH_CAPWAP_RECONNECT_UNKNOWN,
	AH_CAPWAP_RECONNECT_UPGRADE_IMG,
	AH_CAPWAP_RECONNECT_CONF_ROLBCK,
	AH_CAPWAP_RECONNECT_TRANSFER_MODE_CHANGED,
	AH_CAPWAP_RECONNECT_PROXY_NAME_CHANGED,
	AH_CAPWAP_RECONNECT_PROXY_AUTH_CHANGED,
	AH_CAPWAP_RECONNECT_PROXY_CONTENT_LEN_CHANGED,
	AH_CAPWAP_RECONNECT_IMG_ROLBCK,
	AH_CAPWAP_RECONNECT_REASON_MAX,
} ah_capwap_reconnect_reason;

typedef enum {
	AH_CAPWAP_CHOOSE_AC_INIT = 0,
	AH_CAPWAP_CHOOSE_AC_PRIMARY,
	AH_CAPWAP_CHOOSE_AC_PRIMARY_TCP,
	AH_CAPWAP_CHOOSE_AC_BACKUP,
	AH_CAPWAP_CHOOSE_AC_BACKUP_TCP,
	AH_CAPWAP_CHOOSE_AC_FIXED,
	AH_CAPWAP_CHOOSE_AC_FIXED_TCP,
	AH_CAPWAP_CHOOSE_AC_BROADCAST,
	AH_CAPWAP_CHOOSE_AC_PREDEFINE_UDP,
	AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP,
	AH_CAPWAP_CHOOSE_AC_BROADCAST_PREDEFINE,
	AH_CAPWAP_CHOOSE_AC_DHCP,
	AH_CAPWAP_CHOOSE_AC_DHCP_TCP,
	AH_CAPWAP_CHOOSE_AC_DHCP_BACKUP,
	AH_CAPWAP_CHOOSE_AC_DHCP_BACKUP_TCP,
} ah_capwap_choose_ac_level;

typedef enum {
	AH_CAPWAP_INFO_DELETE_COOKIE = 1,
	AH_CAPWAP_INFO_SYSTEM_TOPOLOGY,
	AH_CAPWAP_INFO_WEBUI_TV_FOUND_STUDS,
	AH_CAPWAP_INFO_WEBUI_TV_DEL_STUDS,
} ah_capwap_info_query_type;

#define AH_CAPWAP_UINT64_STR_LEN 40

#define AH_CAPWAP_ERROR_CLI_FILE "/tmp/capwap_error_cli"

/*CAPWAP got next status macro*/
#define AH_CAPWAP_GOTO_NEXT_STATUS  1
#define AH_CAPWAP_KEEP_CURR_STATUS  0

typedef enum {
	AH_CAPWAP_INCREASE_EVENT_SEND_PKT_COUNTER = 1,
	AH_CAPWAP_INCREASE_EVENT_LOST_PKT_COUNTER,
	AH_CAPWAP_INCREASE_EVENT_DROP_CONN_COUNTER,
	AH_CAPWAP_INCREASE_EVENT_DROP_BUFF_COUNTER,
	AH_CAPWAP_INCREASE_EVENT_DROP_DSAB_COUNTER,
} ah_capwap_event_counter_op_type;

typedef enum {
	AH_CAPWAP_RECONNECT_NEXT = 0,
	AH_CAPWAP_RECONNECT_NOW,
} ah_capwap_reconnect_schedul_type;

/***************************************/
/*some debug function to check OpenSSL hung (Bug13930)*/
#define AH_CAPWAP_ADD_DTLS_CONNECT_FAILED_NUM (ah_capwap_dtls_connect_failed_number ++)
#define AH_CAPWAP_CLR_DTLS_CONNECT_FAILED_NUM (ah_capwap_dtls_connect_failed_number = 0)
#define AH_CAPWAP_GET_DTLS_CONNECT_FAILED_NUM (ah_capwap_dtls_connect_failed_number)

#define AH_CAPWAP_SET_DTLS_READ_STATUS (ah_capwap_dtls_read_status = 1)
#define AH_CAPWAP_CLR_DTLS_READ_STATUS (ah_capwap_dtls_read_status = 0)
#define AH_CAPWAP_GET_DTLS_READ_STATUS (ah_capwap_dtls_read_status)
/***************************************/

#endif


