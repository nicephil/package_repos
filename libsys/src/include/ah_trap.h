#ifndef AH_TRAP_H
#define AH_TRAP_H

#include "ah_net.h"
#include "ah_ipv6_shared.h"

#define AH_MAX_TRAP_OBJ_NAME  64
#define AH_MAX_TRAP_SSID_NAME 32
#define AH_MAX_TRAP_HOST_NAME 32
#define AH_MAX_TRAP_USER_NAME 128
#define AH_MAX_TRAP_PROF_NAME 32
#define AH_MAX_TRAP_IF_NAME   16

#define AH_TRAP_OVER_SNMP_BIT   0x1
#define AH_TRAP_OVER_CAPWAP_BIT 0x2

#define AH_MSG_QUE_TRAP         0x100
#define AH_MSG_TRAP_TYPE        1
#define AH_MSG_TRAP_TB          2
#define AH_MSG_TRAP_ASD         3
#ifdef AH_VPN_ENABLE
#define AH_MSG_TRAP_VPN         4
#endif
#define AH_MSG_TRAP_SSID_BIND_UNBIND    5
#define AH_MSG_TRAP_STA_LEAVE_STATS     6
#define AH_MSG_TRAP_BSSID_SPOOFING      7
#define AH_MSG_TRAP_STA_OS_INFO         8
#define AH_MSG_TRAP_RADIUSD_LDAP_ALARM  9
#define AH_MSG_TRAP_CAPWAP_DELAY        10
#define AH_MSG_TRAP_SELF_REG_INFO       11
#define AH_MSG_TRAP_DFS_BANG                     12
#ifdef AH_SUPPORT_PSE
#define AH_MSG_TRAP_PSE                 13
#endif
#ifdef AH_SUPPORT_VOIP_QOS
#define AH_MSG_TRAP_VOIP_QOS_POLICING   14
#endif
//#define AH_MSG_TRAP_CONNECTION_ALARM    15
#define AH_MSG_TRAP_REPORT_CWP_INFO    15
#define AH_MSG_TRAP_POE                16
#define AH_MSG_TRAP_DEV_IP_CHANGE      17

#define POWER_ALARM_ID          100 // smaller than 100 will be used by client.
#define USBMODEM_SIM_STATUS_ALARM_ID      101
#define AH_MSG_ALARM_ID_IDM_CERT_INVALID  102
#define AH_MSG_ALARM_ID_NONE_RADSEC_PROXY 103 //There is none Radsec proxy server in DA domain;

/* generic alarm severity. */
#define AH_MSG_TRAP_GENERIC_ALARM_SEV_CLEAR    1
#define AH_MSG_TRAP_GENERIC_ALARM_SEV_INFO     2
#define AH_MSG_TRAP_GENERIC_ALARM_SEV_MINOR    3
#define AH_MSG_TRAP_GENERIC_ALARM_SEV_MAJOR    4
#define AH_MSG_TRAP_GENERIC_ALARM_SEV_CRITICAL 5

#define AH_MSG_TRAP_GENERIC_ALARM         113 //according to HM, 113 is generic alarm type
#define LDAP_ALARM_TRAP_TYPE              107 //107 is the trap type for ldap alaem


/* trap object name string define */
#define AH_TRAP_OBJ_CLIENT_MGMT         "Client Management"
#define AH_TRAP_OBJ_AMRP_MGMT           "AMRP Management"
#define AH_TRAP_OBJ_HARDWARE_CPU        "Hardware CPU"
#define AH_TRAP_OBJ_HARDWARE_MEM        "Hardware Memory"
#define AH_TRAP_OBJ_AUTH                "Authentication"
#define AH_TRAP_OBJ_INTERFACE           "Interface"
#define AH_TRAP_OBJ_L2DOS               "L2 DOS"
#define AH_TRAP_OBJ_SCREEN              "Screen"
#define AH_TRAP_OBJ_HARDWARE_RADIO      "Hardware Radio"
#define AH_TRAP_OBJ_CAPWAP              "CAPWAP"
#define AH_TRAP_OBJ_CONFIG              "Configuration"
#define AH_TRAP_OBJ_PRODUCT_LICENSE     "Product License"

/*
 * TruthValue ::= TEXTUAL-CONVENTION
 * STATUS       current
 * DESCRIPTION            "Represents a boolean value."
 * SYNTAX       INTEGER { true(1), false(2) }
 */
#define AH_SNMP_TRUE            1
#define AH_SNMP_FALSE           2

/*
 * AhProbableCause ::= TEXTUAL-CONVENTION
 * STATUS        current
 * DESCRIPTION   "It defines the problem probable cause for Aerohive AP."
 * SYNTAX        INTEGER {
 *                 ahClear                  (0),
 *                 ahUnknown                (1),
 *                 ahFlashFailure           (2),
 *                 ahFanFailure             (3),
 *                 ahPowerSupplyFailure     (4),
 *                 ahSoftwareUpgradeFailure (5),
 *                 ahRadioFailure           (6)
 *               }
 */
#define AH_FAILURE_TRAP_CLEAR             0
#define AH_FAILURE_TRAP_UNKNOWN           1
#define AH_FAILURE_TRAP_FLASH             2
#define AH_FAILURE_TRAP_FAN               3
#define AH_FAILURE_TRAP_POWER_SUPPLY      4
#define AH_FAILURE_TRAP_SOFTWARE_UPGRADE  5
#define AH_FAILURE_TRAP_RADIO_FAILURE     6
#define AH_FAILURE_TRAP_CONF_FAILED       7


/*
 * AhState ::= TEXTUAL-CONVENTION
 * STATUS        current
 * DESCRIPTION   "It defines the state for interfaces."
 * SYNTAX        INTEGER {
 *                 ahUp     (1), -- interface up
 *                 ahDown   (2)  -- interface down
 *               }
 */
#define AH_TRAP_STATE_UP      1
#define AH_TRAP_STATE_DOWN    2
#define AH_TRAP_STATE_BACKUP  3
#define AH_TRAP_STATE_ACTIVE  4

/*
 * ahObjectType  OBJECT-TYPE
 *      SYNTAX          INTEGER {
 *                       clientLink   (1),   -- client link
 *                       neighborLink (2)    -- neighbor link
 *                      }
 */
#define AH_TRAP_OBJECT_CLIENT_LINK    1
#define AH_TRAP_OBJECT_NEIGHBOR_LINK  2

/* ahIDPType OBJECT-TYPE
 * SYNTAX          INTEGER {
 *                        rogue         (1),
 *                        valid         (2),
 *                        external      (3)
 *                       }
 */
#define AH_TRAP_IDP_ROGUE        1
#define AH_TRAP_IDP_VALID        2
#define AH_TRAP_IDP_EXTERNAL     3

/* ahIDPCompliance OBJECT-TYPE
 *  SYNTAX          INTEGER {
 *                        open_policy       (1),
 *                        wep_policy        (2),
 *                        wpa_policy        (4),
 *                        wmm_policy        (8),
 *                        oui_policy        (16),
 *                        ssid_policy       (32),
 *                        short_preamble_policy (64),
 *                        short_beacon_policy (128),
 *                        ad_hoc_policy     (256)
 *                       }
 */
#define AH_TRAP_IDP_COMP_OPEN_POLOCY        1
#define AH_TRAP_IDP_COMP_WEP_POLOCY         2
#define AH_TRAP_IDP_COMP_WPA_POLOCY         4
#define AH_TRAP_IDP_COMP_WMM_POLOCY         8
#define AH_TRAP_IDP_COMP_OUI_POLOCY         16
#define AH_TRAP_IDP_COMP_SSID_POLOCY        32
#define AH_TRAP_IDP_COMP_S_PREAMBLE_POLOCY  64
#define AH_TRAP_IDP_COMP_S_BEACON_POLOCY    128
#define AH_TRAP_IDP_COMP_AD_HOC_POLOCY      256

/*
 * ahStationType  OBJECT-TYPE
 *       SYNTAX          INTEGER {
 *                        station_ap       (1),
 *                        station_client   (2)
 *                        }
 */
#define AH_TRAP_IDP_STATION_AP         1
#define AH_TRAP_IDP_STATION_CLIENT     2
#define AH_TRAP_IDP_STATION_OTHERS     3


/*
 * ahIDPStationData OBJECT-TYPE
 *  SYNTAX          INTEGER {
 *                       open_policy       (1),
 *                       wep_policy        (2),
 *                       wpa_policy        (4),
 *                       wmm_policy        (8),
 *                       short_preamble_policy (64),
 *                       short_beacon_policy (128),
 *                       ad_hoc_policy     (256)
 *                       }
 */
#define AH_TRAP_IDP_SDATA_OPEN_POLOCY        1
#define AH_TRAP_IDP_SDATA_WEP_POLOCY         2
#define AH_TRAP_IDP_SDATA_WPA_POLOCY         4
#define AH_TRAP_IDP_SDATA_WMM_POLOCY         8
#define AH_TRAP_IDP_SDATA_S_PREAMBLE_POLOCY  64
#define AH_TRAP_IDP_SDATA_S_BEACON_POLOCY    128
#define AH_TRAP_IDP_SDATA_AD_HOC_POLOCY      256

/*
 * ahRemoved  OBJECT-TYPE
 * SYNTAX          INTEGER {
 *                removed_false    (0),
 *                removed_true     (1)
 *                }
 */
#define AH_TRAP_IDP_REMOVED_FALSE   0
#define AH_TRAP_IDP_REMOVED_TRUE    1

/*
 * AhInterfaceMode ::= TEXTUAL-CONVENTION
 * STATUS        current
 * DESCRIPTION   "Interface role types"
 * SYNTAX        INTEGER {
 *                 ahNotUsed    (0), -- interface is not used
 *                 ahAccess     (1), -- interface is used for access
 *                 ahBackhaul   (2), -- interface is used for backhaul
 *                 ahBridge     (3)  -- interface is used for bridge
 *                 ahDual       (4)  -- interface is used for dual
 *                }
 */
enum {
	AH_TRAP_INTERFACE_MODE_NOT_USED,
	AH_TRAP_INTERFACE_MODE_ACCESS,
	AH_TRAP_INTERFACE_MODE_BACKHAUL,
	AH_TRAP_INTREFACE_MODE_BRIDGE,
	AH_TRAP_INTREFACE_MODE_DUAL
};

/*
 * ahPowerSrc OBJECT-TYPE
        SYNTAX          INTEGER {
                            adaptor    (0),
                            poe        (1)
                         }
        MAX-ACCESS      not-accessible
        STATUS          current
        DESCRIPTION     "It indicates whether the power source is from
                        adaptor or PoE. If the power source is adaptor,
                        PoE information in the trap shall be ignored."
        ::= { ahNotificationVarBind 28}
 */
#define AH_TRAP_POWER_SOURCE_ADAPTOR    0
#define AH_TRAP_POWER_SOURCE_POE        1
#define AH_TRAP_POWER_SOURCE_POEAF      2
#define AH_TRAP_POWER_SOURCE_POEAT      3

/*
AhAuthenticationMethod ::= TEXTUAL-CONVENTION
   STATUS        current
   DESCRIPTION   "Authentication method supported within Aerohive AP"
   SYNTAX        INTEGER {
                       cwp          (0),
                       open         (1),
                       wep-open     (2),
                       wep-shared   (3),
                       wpa-psk      (4),
                       wpa2-psk     (5),
                       wpa-8021x    (6),
                       wpa2-8021X   (7),
                       wpa-auto-psk   (8),
                       wpa-auto-8021x (9),
                       dynamic-wep  (10),
                       8021x        (11)
                 }
 */
#define AH_TRAP_AUTH_METHOD_CWP             0
#define AH_TRAP_AUTH_METHOD_OPEN            1
#define AH_TRAP_AUTH_METHOD_WEP_OPEN        2
#define AH_TRAP_AUTH_METHOD_WEP_SHARED      3
#define AH_TRAP_AUTH_METHOD_WPA_PSK         4
#define AH_TRAP_AUTH_METHOD_WPA2_PSK        5
#define AH_TRAP_AUTH_METHOD_WPA_8021X       6
#define AH_TRAP_AUTH_METHOD_WPA2_8021X      7
#define AH_TRAP_AUTH_METHOD_WPA_AUTO_PSK    8
#define AH_TRAP_AUTH_METHOD_WPA_AUTO_8021X  9
#define AH_TRAP_AUTH_METHOD_DYNAMIC_WEP     10
#define AH_TRAP_AUTH_METHOD_802DOT1X        11

/*
AhEncrytionMethod ::= TEXTUAL-CONVENTION
   STATUS        current
   DESCRIPTION   "Encryption method supported within Aerohive AP"
   SYNTAX        INTEGER {
                   AES        (0),
                   TKIP       (1),
                   WEP        (2),
                   Non        (3)
                 }
 */
#define AH_TRAP_ENCRYPT_METHOD_AES      0
#define AH_TRAP_ENCRYPT_METHOD_TKIP     1
#define AH_TRAP_ENCRYPT_METHOD_WEP      2
#define AH_TRAP_ENCRYPT_METHOD_NON      3


/*
AhMACProtocol ::= TEXTUAL-CONVENTION
   STATUS        current
   DESCRIPTION   "Radio Mode"
   SYNTAX        INTEGER {
                   ah11a        (0), -- A mode
                   ah11b        (1), -- B mode
                   ah11g        (2)  -- G mode
                   ah11na       (3), -- NA mode
                   ah11ng       (4)  -- NG mode
                 }
 */
#define AH_TRAP_MAC_PROTO_11A        0
#define AH_TRAP_MAC_PROTO_11B        1
#define AH_TRAP_MAC_PROTO_11G        2
#define AH_TRAP_MAC_PROTO_11NA       3
#define AH_TRAP_MAC_PROTO_11NG       4
#define AH_TRAP_MAC_PROTO_11AC       5
#define AH_TRAP_MAC_PROTO_ETH        8

/*                       linkdown (1),  -- Interface shutdown
                         eth10   (2),   -- 10 Mbps
                         eth100  (3),   -- 100 Mbps
                         eth1000 (4)    -- 1000 Mbps
 */
#define AH_TRAP_ETH_SPEED_DOWN          1
#define AH_TRAP_ETH_SPEED_10            2
#define AH_TRAP_ETH_SPEED_100           3
#define AH_TRAP_ETH_SPEED_1000          4

/*
     invalid  (0),   -- Interface is invalid
     linkdown (1),   -- Interface shutdown
     config   (2),   -- User configured Wi-Fi tx-rx chain
     tx2rx3   (3)   -- Maximum transmit chain 2 and maximum receive chain 3
*/
#define AH_TRAP_WIFI_SETTING_INVALID        0
#define AH_TRAP_WIFI_SETTING_LINKDOWN       1
#define AH_TRAP_WIFI_SETTING_CONFIG         2
#define AH_TRAP_WIFI_SETTING_TX2RX3         3

/*
    0 -- good-client-but-does-not-meet-sla
    1 -- good-client-meet-sla   (acting as "clear" previous trap)
    2 -- bad-client
*/
#define AH_TRAP_GOOD_CLIENT_NOT_MEET_SLA    0
#define AH_TRAP_GOOD_CLIENT_MEET_SLA        1
#define AH_TRAP_BAD_CLIENT                  2

/*
   1 -- interface level alert
   2 -- client level alert
 */
#define AH_TRAP_INTERFACE_LEVEL_ALERT       1
#define AH_TRAP_CLIENT_LEVEL_ALERT          2

/*
   0 -- The CRC error rate only applies to interface level alert
   1 -- The TX drop rate is calculated based on the max retried TX frames over total unicast TX frames
   2 -- The TX retry rate is calculated based on the total retries over total unicast TX frames
   3 -- The RX drop rate is calculated based on the dropped RX frames over total RX frames
   4 -- The The airtime percentage is the sum of both TX and RX airtime percentages
 */
#define AH_TRAP_CRC_ERROR_RATE              0
#define AH_TRAP_TX_DROP_RATE                1
#define AH_TRAP_TX_RETRY_RATE               2
#define AH_TRAP_RX_DROP_RATE                3
#define AH_TRAP_AIRTIME_PERCENTAGE          4

typedef struct ah_failure_trap_t {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     cause;
	int                     set;
} ah_failure_trap_t;

typedef struct ah_threshold_trap_t {
	char        name[AH_MAX_TRAP_OBJ_NAME + 1];
	int         cur_val;
	int         threshold_high;
	int         threshold_low;
} ah_threshold_trap_t;

typedef struct ah_state_change_trap_t {
	char       name[AH_MAX_TRAP_OBJ_NAME + 1];
	int        pre_state;
	int        cur_state;
	int        operation_mode;
} ah_state_change_trap_t;

typedef struct ah_connection_change_trap_t {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	char                    ssid[AH_MAX_TRAP_SSID_NAME + 1];
	char                    host_name[AH_MAX_TRAP_HOST_NAME + 1];
	char                    user_name[AH_MAX_TRAP_USER_NAME + 1];
	int                     if_index;
	int                     object_type;
	uchar                   remote_id[6];
	uchar                   b_ssid[6];
	int                     cur_state;
	uint32_t                client_ip;
	int                     client_auth_method;
	int                     client_encrypt_method;
	int                     client_mac_proto;
	int                     client_vlan;
	int                     client_upid;
	int                     client_channel;
	int                     client_cwp_used;
	uint32_t                association_time;
	char                    if_name[AH_MAX_TRAP_IF_NAME + 1];
	int32_t                 rssi;
	char                    prof_name[AH_MAX_TRAP_PROF_NAME + 1];
	int32_t                 snr;
	uchar                   client_mac_based_auth_used;
	char                    os[AH_MAX_NAME_LEN + 1];
	uchar                   option55[AH_UCHAR_MAX + 1];
	uint16_t                mgt_stus;  /* bit0: CM; bit1: Social Login;bit2:IDM, others reserved.*/
	uint8_t                 sta_addr6_num;
	struct in6_addr         sta_addr6[AH_MAX_NUM_STA_ADDRS6];
} ah_connection_change_trap_t;

/* ah_connection_change_trap_t.rssi */
#define AH_TRAP_STA_RSSI_DEFAULT (0)

typedef struct ah_idp_ap_event_trap_t {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     if_index;
	uchar                   remote_id[6];
	int                     idp_type;
	int                     idp_channel;
	int                     idp_rssi;
	int                     idp_compliance;
	char                    ssid[AH_MAX_TRAP_SSID_NAME + 1];
	int                     station_type;
	int                     station_data;
	int                     idp_removed;
	int                     idp_innet;
} ah_idp_ap_event_trap_t;

typedef struct ah_client_info_trap_t {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	char                    ssid[AH_MAX_TRAP_SSID_NAME + 1];
	uchar                   client_mac[6];
	char                    host_name[AH_MAX_TRAP_HOST_NAME + 1];
	char                    user_name[AH_MAX_TRAP_USER_NAME + 1];
	uint32_t                client_ip;
	uint16_t                mgt_stus;  /* bit0: CM; bit1: Social Login;bit2:IDM, others reserved.*/
	uint8_t                 sta_addr6_num;
	struct in6_addr         sta_addr6[AH_MAX_NUM_STA_ADDRS6];
} ah_client_info_trap_t;

typedef struct {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     power_src;
	int                     eth0_on;
	int                     eth1_on;
	int                     eth0_pwr;
	int                     eth1_pwr;
	int                     eth0_speed;
	int                     eth1_speed;
	int                     wifi0_setting;
	int                     wifi1_setting;
	int                     wifi2_setting;
} ah_power_info_trap_t;

typedef struct {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     if_index;
	int                     radio_channel;
	int                     radio_tx_power;
	uint                    beacon_interval;
} ah_channel_power_trap_t;

typedef struct {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     if_index;
	uchar                   remote_id[6];
	uchar                   bssid[6];
	int                     removed;
	uint32_t                discover_age;
	uint32_t                update_age;
} ah_idp_mitigate_trap_t;

typedef struct {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     if_index;
	int                     interference_thres;
	int                     ave_interference;
	int                     short_interference;
	int                     snap_interference;
	int                     crc_err_rate_thres;
	int                     crc_err_rate;
	int                     set;
} ah_interference_alert_trap_t;

typedef struct {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     if_index;
	uchar                   client_mac[6];
	int                     bw_sentinel_status;
	int                     gbw;
	int                     actual_bw;
	/* bit maps to indicate which action has been taken on this client */
	uint                    action_taken;
	uint8_t                 chnl_util;
	uint8_t                 interference_util;
	uint8_t                 tx_util;
	uint8_t                 rx_util;
} ah_bw_sentinel_trap_t;

typedef struct {
	char                    name[AH_MAX_TRAP_OBJ_NAME + 1];
	int                     if_index;
	uchar                   client_mac[6];
	int                     level;
	char                    ssid[AH_MAX_TRAP_SSID_NAME + 1];
	int                     alert_type;
	int                     thres_interference;
	int                     short_interference;
	int                     snap_interference;
	int                     set;
} ah_alarm_alert_trap_t;

typedef enum ah_trap_type {
	AH_FAILURE_TRAP_TYPE = 1,
	AH_THRESHOLD_TRAP_TYPE,
	AH_STATE_CHANGE_TRAP_TYPE,
	AH_CONNECTION_CHANGE_TRAP_TYPE,
	AH_IDP_AP_EVENT_TRAP_TYPE,
	AH_CLIENT_INFO_TRAP_TYPE,
	AH_POWER_INFO_TRAP_TYPE,
	AH_CHANNEL_POWER_TYPE,
	AH_IDP_MITIGATE_TRAP_TYPE,
	AH_INTERFERENCE_ALERT_TRAP_TYPE,
	AH_BW_SENTINEL_TRAP_TYPE,
	AH_ALARM_ALERT_TRAP_TYPE,
	AH_TRAP_TYPE_MAX
} ah_trap_type;

typedef struct ah_trap_data_t {
	ah_trap_type            trap_type;
	union {
		ah_failure_trap_t           failure_trap;
		ah_threshold_trap_t         threshold_trap;
		ah_state_change_trap_t      state_change_trap;
		ah_connection_change_trap_t connection_change_trap;
		ah_idp_ap_event_trap_t      idp_ap_event_trap;
		ah_client_info_trap_t       client_info_trap;
		ah_power_info_trap_t        power_info_trap;
		ah_channel_power_trap_t     channel_power_trap;
		ah_idp_mitigate_trap_t      idp_mitigate_trap;
		ah_interference_alert_trap_t interference_alert_trap;
		ah_bw_sentinel_trap_t        bw_sentinel_trap;
		ah_alarm_alert_trap_t        alarm_alert_trap;
	};
} ah_trap_data_t;

typedef struct {
	int             level;
	ah_trap_data_t  data;
	char            desc[512];
} ah_trap_info_t;

typedef struct {
	ah_trap_data_t  data;
	int      level; /* transformed to SNMP level*/
	int      msg_id; /* code field */
	char            desc[128];
} ah_trap_msg_t;

/**@struct for ipv6 include addr type and addr.
*/
typedef struct {
	char  addr_type;
	struct  in6_addr sta_addr6;
} __attribute__ ((packed)) ah_sta_addr6 ;

typedef struct {
#define STAT_MAC_LEN         6
#define MAX_DESCRIBLE_LEN   128
#define MAX_OBJ_NAME_LEN    4
#define     AH_CAPWAP_STAT_NAME_MAX_LEN     32
	uint8_t     trap_id;
	uint16_t    data_len;
	uint8_t     obj_name_len;
	uint8_t     obj_name[4];
	uint32_t    reason_code;
	uint8_t     des_len;
	uint8_t     describle[MAX_DESCRIBLE_LEN];
	uint32_t    disassoc_time;
	uint32_t        if_index;
	uint8_t         mac[STAT_MAC_LEN];
	uint32_t        rssi;
	uint32_t        linkup_time;
	uint8_t         auth_method;
	uint8_t         encrypt_method;
	uint8_t         mac_protocol;
	uint8_t         cwp_used;
	uint32_t        vlan;
	uint32_t        user_profileId;
	uint32_t        channel;
	uint32_t        last_txrate;
	uint32_t        last_rxrate;
	uint32_t        rx_data_frames;
	uint32_t        rx_data_octes;
	uint32_t        rx_mgt_frames;
	uint32_t        rx_uc_frames;
	uint32_t        rx_mc_frames;
	uint32_t        rx_bc_frames;
	uint32_t        rx_mic_failure;
	uint32_t        tx_data_frames;
	uint32_t        tx_mgt_frames;
	uint32_t        tx_data_octets;
	uint32_t        tx_uc_frames;
	uint32_t        tx_mc_frames;
	uint32_t        tx_bc_frames;
	uint32_t        ip;
	uint8_t         host_name[AH_CAPWAP_STAT_NAME_MAX_LEN + 1];
	uint8_t         ssid_name[AH_CAPWAP_STAT_NAME_MAX_LEN + 1];
	uint8_t         user_name[AH_CAPWAP_STAT_NAME_MAX_LEN + 1];
	/* add for 3.1 */
	uint32_t        tx_be_data_frames;
	uint32_t        tx_bg_data_frames;
	uint32_t        tx_vi_data_frames;
	uint32_t        tx_vo_data_frames;

	/* add for 3.2 */
	uint64_t        rx_air_time;
	uint64_t        tx_air_time;
	uint8_t         client_bssid[STAT_MAC_LEN];
	uint32_t        ts;        /* the difference,
                      measured in seconds, between the current time and midnight, January 1, 1970 UTC. */
	/* add for 3.5 */
	char            if_name[AH_CAPWAP_STAT_NAME_MAX_LEN + 1];
	uchar           sta_addr6_num;
	ah_sta_addr6    sta_addr6[AH_MAX_NUM_STA_ADDRS6];
} __attribute__ ((packed)) ah_capwap_sta_leave_stats_trap_t ;



typedef struct {
#define STAT_MAC_LEN         6
#define MAX_DESCRIBLE_LEN   128
#define     AH_CAPWAP_STAT_NAME_MAX_LEN     32
	uint8_t         trap_id;
	uint16_t        data_len;
	uint8_t         obj_len;
	int8_t          obj_name[AH_CAPWAP_STAT_NAME_MAX_LEN];
	uint8_t         des_len;
	int8_t          describle[MAX_DESCRIBLE_LEN];
	uint32_t        ifindex;
	uint8_t         bssid[STAT_MAC_LEN];
	uint8_t         attack_mac[STAT_MAC_LEN];
	uint32_t        attack_count;
	uint16_t        protocol;
	uint32_t        target_ip;
	uint32_t        source_ip;
	uint8_t         severity;
} __attribute__ ((packed)) ah_capwap_bssid_spoofing_trap_t;

#define AH_CAPWAP_STA_OS_INFO_TRAP_ID 106
typedef struct {
	uint8_t    trap_id;
	uint16_t    data_len;
	uint8_t    sta_mac[6];
	uint8_t    os_len;
	uint8_t    data[0];
} __attribute__ ((packed)) ah_capwap_sta_os_info_trap_t;

#define SLEF_REG_INFO_TRAP_TYPE    109
typedef struct ah_capwap_self_reg_trap_s {
	uint8_t    trap_type;
	uint16_t    length;
	uint8_t    sta_mac[MACADDR_LEN];
	uint32_t    expire;
	uint8_t    data[0];
} __packed ah_capwap_self_reg_trap_t;

#define CWP_SELF_REG_EXPIRE_TIME       (24*60*60)   /*one day*/

#define REPORT_CWP_INFO_BUF_MAX_LEN               2000
#define REPORT_CWP_INFO_OBJ_NAME_LEN_BYTE         1
#define REPORT_CWP_DESCRIBE_lEN_BYTE              2
#define REPORT_CWP_NUMB_OF_KEYVAL_PAIR_BYTE       1
#define REPORT_CWP_KEYVAL_PAIR_LEN_BYTE           1
#define REPORT_CWP_INFO_TRAP_TYPE                 114
typedef struct {
	uint8_t     trap_type;
	uint16_t    data_len;
	uchar       mac_addr[MACADDR_LEN];
	char       data[0];
} __packed ah_capwap_report_guest_info_data_t;

#define AH_CAPWAP_DEVICE_IP_CHANGE_TRAP_TYPE                 116
typedef struct {
	uint8_t  trap_type;
	ushort   data_len;
	uint     ipv4_addr;
	uint     ipv4_netmask;
	uint     ipv4_default_gateway;
	uint8_t  ipv6_addr_num;
	char     data[0];
} __packed ah_capwap_device_ip_change_trap_t;
typedef struct {
	uint8_t  item_length;
	uint8_t  ipv6_addr_type;
	struct in6_addr ipv6_addr;
	uint     ipv6_prefix;
	struct in6_addr ipv6_default_gateway;
} __packed ah_capwap_device_ip_change_data_t;

#endif /* AH_TRAP_H */
