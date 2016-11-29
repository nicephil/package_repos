#ifndef _AH_CAPWAP_API_H
#define _AH_CAPWAP_API_H

#include "ah_event.h"






#define AH_IMG_HW_REVISION_LEN 20
#define AH_OEM_NAME "hive"
#define AH_OEM_VENDOR_ID "hive"
#define AH_OEM_AP_NAME "hivemanager"
#define AH_OEM_HM_NAME "hivemanager"
#define AH_CAPWAP_DFT_PREDEFINE_NAME "aaa.com"
#define AH_OEM_DFT_SRV "hivemanager"

#define  AH_CAPWAP_NOT_RUN 0
#define  AH_CAPWAP_HAS_RUN 1

#define AH_MAX_STR_256_LEN 256

typedef struct ah_nms_names_s {
    char first[128];
    char second[128];
} ah_nms_names_t;

































#define AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH "/f/etc/capwap_predefine_server_name"
#define AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH_RESET_CONFIG "capwap_predefine_server_name"

#define AH_CAPWAP_EVENT_MSG_START (2*sizeof(uint16_t) + sizeof(uint32_t))
#define AH_CAPWAP_EVENT_MSG_TOL_FRAG_OFFSET (0)
#define AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET (sizeof(uint16_t))
#define AH_CAPWAP_EVENT_MSG_SEQ_FRAG_OFFSET (2*sizeof(uint16_t))

#define AH_CAPWAP_EVENT_MAX_LEN   1300

#define AH_CAPWAP_NORMAL_EVENT_MAX_PKT   200

/* for CLI event or important event used */
#define AH_CAPWAP_SPECIAL_EVENT_MAX_PKT  5

#define AH_CAPWAP_EVENT_MAX_PKT   (AH_CAPWAP_NORMAL_EVENT_MAX_PKT + AH_CAPWAP_SPECIAL_EVENT_MAX_PKT)
#define AH_CAPWAP_EVENT_MAX_RAND  5000.0

#define     AH_CAPWAP_STAT_TBL_ALL      0
#define     AH_CAPWAP_STAT_TBL_NBR      1
#define     AH_CAPWAP_STAT_TBL_XIF      2
#define     AH_CAPWAP_STAT_TBL_ASS      3
#define     AH_CAPWAP_STAT_TBL_RADIO    4
#define     AH_CAPWAP_STAT_TBL_VIF      5
#define     AH_CAPWAP_STAT_TBL_RADATTR  6
#define     AH_CAPWAP_STAT_TBL_WIRED_ASS  7
#define     AH_CAPWAP_STAT_TBL_MAX      AH_CAPWAP_STAT_TBL_WIRED_ASS

/**
 * define the IPV6 address type to work with HM, Must be
 * consistent with the definition of the HM side.
 */
#define STATION_IPV6_GLOBAL_ADDRES 1
#define STATION_IPV6_LOCAL_ADDRES  2

/* table type:please keep the order */
typedef enum {
	AH_STATISTICAL_TABLE_NONE,
	AH_STATISTICAL_TABLE_NEIGHBOUR,
	AH_STATISTICAL_TABLE_XIF,
	AH_STATISTICAL_TABLE_ASSOCIATION,
	AH_STATISTICAL_TABLE_RADIOSTATUS,
	AH_STATISTICAL_TABLE_VIFSTATUS,
	AH_STATISTICAL_TABLE_RADIOATTRIBUTE,
	AH_STATISTICAL_TABLE_WIRED_ASSOC,
	AH_STATISTICAL_TABLE_MAX = AH_STATISTICAL_TABLE_WIRED_ASSOC,
} ah_stat_table_type_t;

/* use for capwap hvcom scp accont */
#define AH_CAPWAP_HVCOM_SCP_USER "AerohiveHiveCommadmin"
#define AH_CAPWAP_HVCOM_SCP_PWD_DFT "aerohive"
#define AH_CAPWAP_HVCOM_SCP_PWD_LEN 32

/*  put string to a buf
 *  pbuf -- buf where save string
 *  string --- string to be save
 *  len --- a variable will repesent the len of string
 *  max_len --- max string len
*/
#define AH_CAPWAP_STAT_SAVE_STAT_STRING(pbuf, string, len, max_len)             \
	do{                                                                 \
		(len) = ah_strlen((char  *)(string));                      \
		(len) = ((len) >= (max_len)) ? (max_len) : (len);                \
		*(uint8_t *)pbuf = (uint8_t)len;                          \
		pbuf++;                                                         \
		\
		if ((len) > 0){                                                 \
			ah_memcpy((pbuf), (string), (len));                     \
			(pbuf) += (len);                                        \
		}                                                               \
	}while(0)

#if (__BYTE_ORDER != __BIG_ENDIAN)
#define htonll(x) \
	((u_int64_t)( \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000000000ffULL) << 56) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000000000ff00ULL) << 40) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000000000ff0000ULL) << 24) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000ff000000ULL) <<  8) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000ff00000000ULL) >>  8) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000ff0000000000ULL) >> 24) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00ff000000000000ULL) >> 40) | \
				  (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0xff00000000000000ULL) >> 56) ))
#else
#define htonll(x) (u_int64_t)(x)
#endif

#define     AH_STATISTICAL_TABLE_SET_REQUESTED(request, table_id)   \
	((request) |= (1 <<(table_id)))
#define     AH_STATISTICAL_TABLE_RESET_REQUESTED(request, table_id) \
	((request) &= (~(1 <<(table_id))))
#define     AH_STATISTICAL_TABLE_IS_REQUESTED(request, table_id)    \
	((request) & (1 << (table_id)))

#define     AH_STATISTICAL_DCD_IS_REQUESTED(request)                \
	(AH_STATISTICAL_TABLE_IS_REQUESTED((request), AH_STATISTICAL_TABLE_XIF))\
	|| (AH_STATISTICAL_TABLE_IS_REQUESTED((request), AH_STATISTICAL_TABLE_ASSOCIATION))\
	|| (AH_STATISTICAL_TABLE_IS_REQUESTED((request), AH_STATISTICAL_TABLE_RADIOSTATUS))\
	|| (AH_STATISTICAL_TABLE_IS_REQUESTED((request), AH_STATISTICAL_TABLE_VIFSTATUS))   \
	|| (AH_STATISTICAL_TABLE_IS_REQUESTED((request), AH_STATISTICAL_TABLE_RADIOATTRIBUTE))

#define     AH_STATISTICAL_AMRP_IS_REQUESTED(request)                \
	(AH_STATISTICAL_TABLE_IS_REQUESTED((request), AH_STATISTICAL_TABLE_NEIGHBOUR))

#define     AH_STATISTICAL_AUTH_IS_REQUESTED(request)                \
	(AH_STATISTICAL_TABLE_IS_REQUESTED((request),  AH_STATISTICAL_TABLE_WIRED_ASSOC))

/* define the struct a request of a table */
#define     AH_CAPWAP_STATIS_MAX_KEY            128
typedef struct {
	uint            ifindex;
	uchar           mac[6];             /* just valid when table_id = AH_STATISTICAL_TABLE_ASSOCIATION */
} ah_capwap_stat_table_key_t;

typedef struct {
	uchar       table_id;               /* table_id */
	uchar       key_number;             /* number of rows requested */
	ah_capwap_stat_table_key_t   key[AH_CAPWAP_STATIS_MAX_KEY];         /* ifindex of row */
} ah_capwap_statis_table_t;

typedef struct {
	uint32_t                    nms_seq_no;         /* seq_no of nms */
	uchar                       table_num;          /* number of tables request*/
	ah_capwap_statis_table_t    table[AH_STATISTICAL_TABLE_MAX + 1];   /* table info */
	uint                        bitmap;             /* bitmap of request */
} ah_capwap_statis_request_t;


/* define structure of event */
typedef struct {
	ushort          mod_id;
	uint            seq_no;     /* sequence used by statistic feature */
	uint            ifindex;    /* ifindex of table requested */
} ah_capwap_stat_cokie_t;

#define     AH_STAT_MAX_TEMPFILENAME_LEN        32

/* common message header from HM, net order */
typedef struct {
	uint16_t        msg_type;       /* message type */
	uint32_t        cookie;         /* cookie */
	uint8_t         flag;           /* flag */
	uint32_t        data_len;       /* payload length */
} __attribute__((__packed__)) ah_capwap_in_msg_hdr_t;

/* common message header to HM, net order */
typedef struct {
	uint16_t        msg_type;       /* message type */
	uint32_t        cookie;         /* cookie */
	uint32_t        data_len;       /* payload length */
} __attribute__((__packed__)) ah_capwap_out_msg_hdr_t;


#pragma pack (1)
/* define structure of table */
typedef struct {
	uint32_t        if_index;
	uchar           ap_id[6];
	uint32_t        link_cost;
	uint32_t        rssi;
	uint32_t        linkup_time;
	uint8_t         lint_type;

	uint32_t        rx_data_frame;
	uint32_t        rx_data_octets;
	uint32_t        rx_mgt_frames;
	uint32_t        rx_uc_frames;
	uint32_t        rx_mc_frames;
	uint32_t        rx_bc_frames;
	uint32_t        tx_data_frames;
	uint32_t        tx_mgt_frames;
	uint32_t        tx_data_octets;
	uint32_t        tx_uc_frames;
	uint32_t        tx_mc_frames;
	uint32_t        tx_bc_frames;
	/* add for 3.1 */
	uint32_t        tx_be_data_frames;
	uint32_t        tx_bg_data_frames;
	uint32_t        tx_vi_data_frames;
	uint32_t        tx_vo_data_frames;
} ah_capwap_stat_nbr_table_t;

#define     AH_CAPWAP_STAT_IFNAME_MAX_LEN       32
#define     AH_CAPWAP_STAT_SSIDNAME_MAX_LEN     32
#define     AH_CAPWAP_STAT_HOSTNAME_MAX_LEN     32
#define     AH_CAPWAP_STAT_USERNAME_MAX_LEN     128
#define     AH_CAPWAP_STAT_SOFTENV_MAX_LEN      32
#define     AH_CAPWAP_STAT_DHCP_OPTION55_MAX_LEN   255
#define     AH_CAPWAP_STAT_ADDR6_TYPE_LEN       1
#define     AH_CAPWAP_STAT_SINGLE_ADDR6_LEN    sizeof(struct in6_addr)
#define     AH_CAPWAP_STAT_ADDR6_MAX_LEN       (AH_CAPWAP_STAT_SINGLE_ADDR6_LEN * AH_MAX_NUM_STA_ADDRS6)
typedef struct {
	uint32_t        if_index;
	uint8_t         if_promiscuous;
	uint8_t         if_type;
	uint8_t         if_mode;
	uint8_t         if_name[AH_CAPWAP_STAT_IFNAME_MAX_LEN + 1];
	uint8_t         ssid_name[AH_CAPWAP_STAT_SSIDNAME_MAX_LEN + 1];
	uint8_t         if_conf_mode;               /* 1:Access; 2:Backhaul */
	uint8_t         if_admin_status;            /* 1:Up; 2:Down 3: testing */
	uint8_t         if_oper_status;             /* 1:Up; 2:Down */
	uint8_t         mac_addr[MACADDR_LEN];  /* for vap, it is bssid. */
} ah_capwap_stat_xif_table_t;

#define AH_MAX_STR_PARM_LEN 32
#define AH_MAX_STR_64_LEN 64
typedef struct {
#define STAT_MAC_LEN         6
	uint32_t     if_index;
	uint8_t      mac[STAT_MAC_LEN];
	int32_t      rssi;
	uint32_t     linkup_time;
	uint8_t      auth_method;
	uint8_t      encrypt_method;
	uint8_t      mac_protocol;
	uint8_t      cwp_used;
	uint32_t     vlan;
	uint32_t     user_profileId;
	uint32_t     channel;
	uint32_t     last_txrate;
	uint32_t     last_rxrate;
	uint32_t     rx_data_frames;
	uint32_t     rx_data_octes;
	uint32_t     rx_mgt_frames;
	uint32_t     rx_uc_frames;
	uint32_t     rx_mc_frames;
	uint32_t     rx_bc_frames;
	uint32_t     rx_mic_failure;
	uint32_t     tx_data_frames;
	uint32_t     tx_mgt_frames;
	uint32_t     tx_data_octets;
	uint32_t     tx_uc_frames;
	uint32_t     tx_mc_frames;
	uint32_t     tx_bc_frames;
	uint32_t     ip;
	uint8_t      host_name[AH_CAPWAP_STAT_HOSTNAME_MAX_LEN + 1];
	uint8_t      ssid_name[AH_CAPWAP_STAT_SSIDNAME_MAX_LEN + 1];
	uint8_t      user_name[AH_CAPWAP_STAT_USERNAME_MAX_LEN + 1];
	/* add for 3.1 */
	uint32_t     tx_be_data_frames;
	uint32_t     tx_bg_data_frames;
	uint32_t     tx_vi_data_frames;
	uint32_t     tx_vo_data_frames;

	/* add for 3.2 */
	uint64_t     rx_air_time;
	uint64_t     tx_air_time;
	uint8_t      client_bssid[STAT_MAC_LEN];
	uint32_t     ts;        /* the difference,
                                  measured in seconds, between the current time and midnight, January 1, 1970 UTC. */
	/* add for 3.5 */
	char       if_name[AH_CAPWAP_STAT_IFNAME_MAX_LEN + 1];
	/* add for 3.5r3 BeiJing */
	char       soft_env[AH_CAPWAP_STAT_SOFTENV_MAX_LEN + 1];
	/* add for 4.0r1 */
	char       ipnet_conn_score;
	char       app_health_score;
	char       radio_link_score;
	char       overall_score;
	char       option55[AH_CAPWAP_STAT_DHCP_OPTION55_MAX_LEN + 1];
	char       prof_name[AH_MAX_STR_PARM_LEN + 1];
	int16_t      snr;
	uint8_t      mba_used;
	uint16_t     mgt_stus;  /* bit0: CM; bit1: Social Login;bit2:IDM, others reserved.*/
	uint8_t      sta_addr6_num;
	struct in6_addr sta_addr6[AH_MAX_NUM_STA_ADDRS6];
	/*If add new item, we must change the data length for macro AH_DCD_ASSOCIATION_TABLE_FIXED_SIZE(ah_capwap_statistic.h)*/
} __packed ah_capwap_stat_ass_table_t;

typedef struct {
	uint32_t        if_index;
	uint32_t        tx_data_frames;
	uint32_t        tx_non_beacon_mgt_frames;
	uint32_t        tx_uc_data_frames;
	uint32_t        tx_mc_data_frames;
	uint32_t        tx_bc_data_frames;
	uint32_t        tx_beacon_frames;
	uint32_t        tx_total_retries;
	uint32_t        tx_frames_dropped;
	uint32_t        tx_frames_error;
	uint32_t        tx_fe_or_excessive_hw_retries;
	uint32_t        rx_data_frames;
	uint32_t        rx_uc_data_frames;
	uint32_t        rx_mc_data_frames;
	uint32_t        rx_bc_data_frames;
	uint32_t        rx_mgt_frames;
	uint32_t        rx_frames_dropped;
	/* add for 3.1 */
	uint32_t        tx_be_data_frames;
	uint32_t        tx_bg_data_frames;
	uint32_t        tx_vi_data_frames;
	uint32_t        tx_vo_data_frames;
	uint32_t        tx_rts_failures;
	/* add for 3.2 */
	uint64_t        rx_air_time;
	uint64_t        tx_air_time;
	/* added for 3.4 */
	uint32_t        bandwidth;
} ah_capwap_stat_radio_table_t;


typedef  struct {
	uint32_t        if_index;
	uint32_t        rx_data_frames;
	uint32_t        rx_uc_frames;
	uint32_t        rx_mc_frames;
	uint32_t        rx_bc_frames;
	uint32_t        rx_error_frames;
	uint32_t        rx_dropped_frames;
	uint32_t        tx_data_frames;
	uint32_t        tx_uc_frames;
	uint32_t        tx_mc_frames;
	uint32_t        tx_bc_frames;
	uint32_t        tx_error_frames;
	uint32_t        tx_dropped_frames;
	/* add for 3.1 */
	uint32_t        tx_be_data_frames;
	uint32_t        tx_bg_data_frames;
	uint32_t        tx_vi_data_frames;
	uint32_t        tx_vo_data_frames;
	/* add for 3.2 */
	uint64_t        rx_air_time;
	uint64_t        tx_air_time;
} ah_capwap_stat_vif_table_t;

typedef enum {
	AH_CAPWAP_EVENT_HANDLE_MITIGATION = 1,
	AH_CAPWAP_EVENT_LOCATION_TRACKING,
	AH_CAPWAP_EVENT_SHOW_CAPTURE_INTERFACE,
	AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING,
	AH_CAPWAP_EVENT_DHCP_PROBE,
	AH_CAPWAP_EVENT_POE = 8,
	AH_CAPWAP_EVENT_INTERFACE_MAP,
	AH_CAPWAP_EVENT_LCDP_NEIGHBORS,
	AH_CAPWAP_EVENT_HVCOM,
	AH_CAPWAP_EVENT_VPN_STATUS = 12,
	AH_CAPWAP_EVENT_PCI_ALERT = 13,
	AH_CAPWAP_EVENT_STATS_REPORT = 14,
	AH_CAPWAP_EVENT_RADIUS_TEST,
	AH_CAPWAP_EVENT_TV_NO_FOUND_STUDS,
	AH_CAPWAP_EVENT_RETRIVE_AD_INFO = 17,
	AH_CAPWAP_EVENT_LDAP_TREE_INFO = 18,
	AH_CAPWAP_EVENT_DOMAIN_JOINED = 19,
	AH_CAPWAP_EVENT_TV_REPORT = 20,
#ifdef ATH_SUPPORT_SPECTRAL
	AH_CAPWAP_EVENT_SEND_SPECTRAL_DATA = 21,
#endif
	AH_CAPWAP_EVENT_DCM_INFO = 22,
	AH_CAPWAP_EVENT_TV_NOTIFY_DEL_CLASS = 23,
	AH_CAPWAP_EVENT_TV_NOTIFY_LESSON_PLAN = 25,
	AH_CAPWAP_EVENT_WAN_VPN_AVAILABLE = 26,
#ifdef AH_SUPPORT_NAAS
	AH_CAPWAP_EVENT_NAAS_RESPONSE = 27,
#endif
#if defined(AH_SUPPORT_IDP)
	AH_CAPWAP_EVENT_IDP_AP_CLF_DA_SEND = 28,
	AH_CAPWAP_EVENT_IDP_AP_CLF_HM_SNED = 29,
#endif
#ifdef AH_SUPPORT_PSE
	AH_CAPWAP_EVENT_PSE_INFO_REPORT_REQUEST = 30,
#endif
	AH_CAPWAP_EVENT_BRD_OTP = 31,
#ifdef AH_SUPPORT_CPM
	AH_CAPWAP_EVENT_CLT_PERF_MONITOR = 33,
#endif

#ifdef AH_SUPPORT_RADSEC
	AH_CAPWAP_EVENT_RADSEC_CERT_CREATION = 32,
	AH_CAPWAP_EVENT_RADSEC_CERT_RENEW_RES = 35,
#endif
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	AH_CAPWAP_EVENT_BONJOUR_GATEWAY = 34,
#endif
	AH_CAPWAP_EVENT_L7D_APP_REPORT_READY = 36,
	AH_CAPWAP_EVENT_PRESENCE = 37,

	AH_CAPWAP_EVENT_GET_L7_STATS = 41,
	AH_CAPWAP_EVENT_L7_SIGNATURE_VERSION_NOTIFY = 42,
#ifdef AH_SUPPORT_MULTIWAN
	AH_CAPWAP_EVENT_USBNET_STATUS = 43,
#endif
	AH_CAPWAP_EVENT_SWITCH_PORT_UTILIZATION = 44,
	AH_CAPWAP_EVENT_CLIENT_MONITOR_PROBLEM = 46,  /* client monitor problem */
	AH_CAPWAP_EVENT_RADSEC_PROXY_INFO = 47,
	AH_CAPWAP_EVENT_SWITCH_PORT_CAVC_AP = 48,

#ifdef AH_SUPPORT_IBEACON
	AH_CAPWAP_EVENT_IBEACON_STATUS_REQUEST = 49,
#ifdef AH_SUPPORT_IBEACON_MONITOR_EVT_TO_HM
	AH_CAPWAP_EVENT_IBEACON_MONITOR_REQUEST = 50,
#endif
#endif
	AH_CAPWAP_EVENT_BUTT = 51,
} ah_capwap_event_handle_type;

typedef struct {
	uint32_t        if_index;
	uint32_t        channel;
	uint32_t        tx_power;
	uint32_t        noise_floor;
	uint32_t        beacon_interval;
	uint32_t        eirp_power;
	int            phymode;
} ah_capwap_stat_radio_attr_t;
#pragma pack ()

/*CAPWAP DTLS PASS (PSK) Max length*/
#define AH_CAPWAP_DTLS_MAX_PHRASE_LEN       32
#define AH_CAPWAP_DTLS_MIN_PHRASE_LEN       16
#define AH_CAPWAP_DTLS_MAX_PSK_LEN          64
#define AH_CAPWAP_DTLS_FOOTPRINT_LEN        2

/*CAPWAP client VHM name length */
#define AH_CAPWAP_MAX_VHM_NAME_LEN 64

typedef enum _ah_capwap_dtls_key_type_t {
	AH_DTLS_PASSPHRASE = 0,
	AH_DTLS_MANUL_PSK
} ah_capwap_dtls_key_type_t;

/*the value for configure CAPWAP timer CLI*/
typedef struct _ah_capwap_timer_cli_t {
	uint32_t    discovery_interval;    /*AH_CAPWAP_TIMER_DISCOVERY*/
	uint32_t    echo_interval;         /*AH_CAPWAP_TIMER_ECHO*/
	uint32_t    max_discovery_interval;/*AH_CAPWAP_TIMER_MAXDISCOVERY*/
	uint32_t    neighbordead_interval; /*AH_CAPWAP_TIMER_NEIGHBORDEAD*/
	uint32_t    silent_interval;       /*AH_CAPWAP_TIMER_SILENT*/
	uint32_t    waitjoin_interval;     /*AH_CAPWAP_TIMER_WAITJOIN*/
	uint32_t    event_interval;        /*AH_CAPWAP_TIMER_EVENT*/
	uint32_t    dtls_cut_interval;     /*AH_CAPWAP_TIMER_DTLS_CUT*/
	uint32_t    dtls_conn_interval;    /*AH_CAPWAP_TIMER_DTLS_CONN*/
	uint32_t    stat_update_interval;    /*AH_CAPWAP_TIMER_STAT_UPDATE*/
} ah_capwap_timer_cli_t;

/*the value for configure CAPWAP counter CLI*/
typedef struct _ah_capwap_counter_cli_t {
	uint32_t    max_discoveries;       /*MaxDiscoveries times*/
	uint32_t    max_retransmit;        /*MaxRetransmit times*/
	uint32_t    max_dtls_retry;        /*Max dtls retry connect times*/
} ah_capwap_counter_cli_t;

/*the value for configure CAPWAP DTLS CLI*/
typedef struct _ah_capwap_dtls_cli_t {
	uint32_t    dtls_enable;                             /*the flag indicate dtls enable or disable*/
	uint32_t    dtls_next_enable;                        /*the flag indicate dtls next connect enable or disable*/
	char      dtls_bootstrap;                            /*always accept bootstrap passphrase(Enabled|Disabled)*/
	ah_capwap_dtls_key_type_t dtls_key_type;             /*dtls key type (MANUAL|PASSPHRASE)*/
	char      dtls_psk[AH_CAPWAP_DTLS_MAX_PSK_LEN + 1];  /*dtls PSK*/
	char      cur_keyid;                                 /*current dtls key id*/
	char      bak_keyid;                                 /*backup dtls key id*/
	char      dtls_cur_phrase[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1];  /*passphrase for current index*/
	char      dtls_bak_phrase[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1];  /*passphrase for backup index*/
	char      dtls_dft_phrase[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1];  /*passphrase for default index*/
	char      dtls_dft_footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1]; /*passphrase footprint for default index*/
	char      dtls_cur_footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1]; /*passphrase footprint for current index*/
	char      dtls_bak_footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1]; /*passphrase footprint for backup index*/
} ah_capwap_dtls_cli_t;

/*All need recovery CLI for CAPWAP*/
typedef struct _ah_capwap_recovery_t {
	ah_capwap_timer_cli_t  timer_cli;     /*config CAPWAP timer CLI*/
	ah_capwap_counter_cli_t counter_cli;  /*config CAPWAP counter CLI*/
	ah_capwap_dtls_cli_t dtls_cli;        /*config CAPWAP DTLS CLI*/
	int      enable;               /*config CAPWAP enable CLI*/
	int      capwap_port;          /*config CAPWAP port CLI*/
	int      event_flag;           /*config CAPWAP event enable CLI*/
	boolean init;                         /*flag for CAPWAP share memory initialized or not*/
	uchar      dtls_negotiation; /*flag for dtls negotiation*/
	uint32_t    reconnect_reason;  /*CAPWAP reconnect reason*/
	char      vhm_name[AH_CAPWAP_MAX_VHM_NAME_LEN + 1]; /*capwap virtual hive manager */
	uchar      transfer_mode;          /*capwap transfer mode*/
	char      proxy_name[AH_MAX_STR_64_LEN + 1];       /*proxy name*/
	int      proxy_port;         /*proxy port*/
	char      proxy_auth_name[AH_MAX_STR_PARM_LEN + 1];       /*proxy auth name*/
	char      proxy_auth_pswd[AH_MAX_STR_PARM_LEN + 1];       /*proxy auth pswd*/
	uint32_t    proxy_content_len;   /*proxy conten length*/
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	char       proxy_cfg_method;
	char       bonjour_service_type;
#endif
	int      enable_discovery_bcast;      /* disable CAPWAP discovery method broadcast */
} ah_capwap_recovery_t;

/**
 * Format of GENERIC alarm
 * +---------------------------------------------------+
 * |    Name             Size (octet)   Description
 * +---------------------------------------------------
 * | Trap type           1              113
 * +---------------------------------------------------
 * | Data length         2              The following data length, not include this 2 bytes.
 * +---------------------------------------------------
 * | Number of item      2
 * +---------------------------------------------------
 * | (Start one item)
 * | Length of one item  2
 * +---------------------------------------------------
 * | Alarm id            2              alarm type
 * +---------------------------------------------------
 * | Severity            1              Alarm severity:
 * |                                            1 - clear alarm
 * |                                            2 - info
 * |                                            3 - minor
 * |                                            4 - major
 * |                                            5 - critical
 * +---------------------------------------------------
 * | Description length  1
 * +---------------------------------------------------
 * | Description         Vary           Alarm description
 * +---------------------------------------------------
 * | Tag1                4              Default value is -1
 * +---------------------------------------------------
 * | Tag2                4              Default value is -1
 * +---------------------------------------------------
 * | Tag3 length         1              Default value is 0
 * +---------------------------------------------------
 * | Tag3                Vary
 * +---------------------------------------------------
 * | Next item ...
 * +---------------------------------------------------
 */
typedef struct _ah_capwap_generic_alarm_hdr_t {
	uint8_t      trap_type;   /* Fixed value: 113 */
	uint16_t     length;
	uint16_t     item_num;
} __attribute__((__packed__)) ah_capwap_generic_alarm_hdr_t;

#define AH_GENERIC_ALARM_TAG1_DFT       (-1)
#define AH_GENERIC_ALARM_TAG2_DFT       (-1)
#define AH_GENERIC_ALARM_TAG3_DFT       (0)
typedef struct _ah_capwap_generic_alarm_item_t {
	/* The byte order of all of the attributes should be host order */
#define AH_GENERIC_ALARM_ITEM_HEAD_LEN \
	(sizeof(uint16_t) + sizeof(uint16_t) + \
	 sizeof(uint8_t) + sizeof(uint8_t))

	uint16_t     length;
	uint16_t     alarm_id;
	uint8_t      severity;
	uint8_t      desc_len;
	char         *desc;

#define AH_GENERIC_ALARM_ITEM_TAG_HEAD_LEN \
	(sizeof(int32_t) + sizeof(int32_t) + sizeof(uint8_t))
	int32_t      tag1;
	int32_t      tag2;
	uint8_t      tag3_len;
	char         *tag3;

	struct _ah_capwap_generic_alarm_item_t *next;
} ah_capwap_generic_alarm_item_t;

extern int ah_capwap_send_event(ah_event_t event_id, int event_len, void *event_msg);
extern inline int ah_capwap_is_connecting();
#if AH_SUPPORT_UPGRADE_SAFELY
extern int ah_capwap_get_conn_info(ah_capwap_conn_info_t *conn_info);
extern int ah_capwap_set_conn_info(ah_capwap_conn_info_t *conn_info);
#endif
extern int ah_capwap_send_trap(int16_t trap_len, void *trap_msg, long trap_type);
extern int ah_capwap_send_trap_with_id(int16_t trap_len, void *trap_msg, long trap_type, long trap_type_id,
									   boolean clear);
extern int ah_capwap_send_generic_alarm(ah_capwap_generic_alarm_item_t *items, long trap_type_id, boolean clear);
extern int ah_capwap_stat_save_ass(ah_capwap_stat_ass_table_t  *table, uchar *buf);

extern inline int ah_capwap_get_request_type(void *rst_data);
extern inline int ah_capwap_get_request_header(ah_capwap_in_msg_hdr_t *rst_hdr, void *rst_data);
extern inline char *ah_capwap_get_request_data(void *rst_data);
extern inline int ah_capwap_get_request_data_len(const void *rst_data);
extern inline int ah_capwap_set_response_header(void *rps_buff, ah_capwap_in_msg_hdr_t *rst_hdr, uint32_t data_len);
extern inline int ah_capwap_set_response_data(void *rst_buff, void *rps_data, uint32_t data_len, const void *event_data);
extern  inline int ah_capwap_get_response_data_len(void *rps_data);
extern int ah_capwap_send_event_payload(ah_event_t event_id, void *payload, uint32_t payload_len, const void *data);
extern int ah_capwap_get_request_payload(const void *rst_data, uint32_t *payload_len, char **payload);
extern int ah_capwap_send_event_payload_actively(ah_event_t event_id, void *payload, uint32_t payload_len,
		const uint16_t capwap_id);
extern int ah_capwap_get_shm(ah_capwap_recovery_t **shm);
extern uint16_t ah_capwap_save_sta_addr6(uchar *pbuf, uchar addr6_num, const struct in6_addr *addr6);
#endif
