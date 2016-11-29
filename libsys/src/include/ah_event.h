#ifndef  _AH_EVENT_H
#define  _AH_EVENT_H

#include "ah_types.h"
#include "ah_pthread.h"
#include "ah_nptimer.h"
#include "ah_tnptimer.h"
#include "ah_kevent.h"
#include "ah_ptimer.h"
#include "ah_net.h"
#include "ah_ipv6_shared.h"
#include "ah_trap.h"

#define AH_EVENT_RC_GENERIC_ERROR       -1
#define AH_EVENT_RC_SEND_INCOMPLETE     -2

/* value include in event data */
#define AH_DCD_MODE_ACCESS_ETH0                 0 /* TODO: need to modify for FastEthernet0 mode */
#define AH_DCD_MODE_BACKHAUL_ETH0               1 /* TODO: need to modify for FastEthernet0 mode */
#define AH_DCD_MODE_BRIDGE_ETH0                 2
#define AH_DCD_MODE_WAN_ETH0                    3
#define AH_DCD_MODE_NULL_ETH0                   4

#define AH_DCD_MODE_WAN_WLAN                    3  /*yes, it's the same with AH_DCD_MODE_WAN_ETH0*/
#define AH_DCD_MODE_ACCESS_WLAN                    0  /*yes, it's the same with AH_DCD_MODE_ACCESS_ETH0*/

#define AH_INCREASE_VLAN_GROUP_REF_CNT           1  /* vlan-group ref_cnt add 1*/
#define AH_DECREASE_VLAN_GROUP_REF_CNT          0  /* vlan-group ref_cnt   sub 1*/
/* Event ID
 * For each event added to the enum, please add its name to
 * ah_eventid_to_name() function
 */
typedef enum {
/*
 * reserve 0 - 100 for hive broadcast receivers ONLY. Because these 
 * events could be relayed to neighboring APs, the event numbers 
 * for hive broadcast should never be changed or reused across 
 * different releases. 
 */
 
	AH_EVENT_HIVE_START = 0,

	AH_EVENT_HIVE_RECEIVE_CLEAR_CACHE = 0, /* receive hive broadcasted clear cache event */
	AH_EVENT_HIVE_RECEIVE_UPDATE_CACHE = 1, /* receive hive broadcasted update roaming cache by tlv format */
	AH_EVENT_HIVE_RECEIVE_MACDOS = 2,         /*Receive hive broadcasted MACDOS info*/
	AH_EVENT_HIVE_END = 100,

/* ============================================ */
 /* !!!!! Important: All non-hive-broadcast events should be added AFTER this */

	AH_EVENT_NMSSVR_CHG,
	AH_EVENT_NMSSVR_CHG_MANUAL,


	AH_EVENT_CWP_USER_JOIN,         /* one user join by cwp */
	AH_EVENT_CWP_AUTH_FAIL,         /* cwp radius auth failed, for trap */

	AH_EVENT_DCDAUTH_RESPONSE,      /* dcd give response to auth */

	AH_EVENT_RM_CACHE,              /*event to auth new cache coming*/
	AH_EVENT_RM_NB_JOIN,        /*event to auth to tell new neighbor joining*/

	AH_EVENT_USER_PROFILE_VLAN_CHG, /* User profile vlan id change */

	AH_EVENT_CTL_PKT_CRYPT_REQUEST, /* used by amrp module to send event to auth module to get control packet encryption info */

	AH_EVENT_RM_NBR_UPDATE,         /* rm nbr config change  */
	AH_EVENT_RM_PORT_CHG,           /* rm port config change  */

	AH_EVENT_L3_CONFIG,             /*L3 Configuration event*/
	AH_EVENT_CLEAR_TUN,             /*Clear gre tunnel event*/

	AH_EVENT_AMRP_DEL_STA, /* amrp deleta a STA from routing */
	AH_EVENT_AMRP_ADD_STA, /* amrp add a STA in routing */
	AH_EVENT_AMRP_VPN_TIMEOUT, /* amrp detect GRE gateway timeout */

	AH_EVENT_AMRP_PORTAL_CHG,       /* amrp change portal */
	AH_EVENT_RADIUS_DOS_CFG,        /* DCD send RADIUS DOS config 2 AUTH */

	AH_EVENT_CAPWAP_HTTP_GET_DELTA_CFG, /*event for CAPWAP only*/
	AH_EVENT_CAPWAP_IDP_PUSH,       /*event for CAPWAP only*/
	AH_EVENT_CAPWAP_IDP_PULL,       /*event for CAPWAP only*/
	AH_EVENT_CAPWAP_IDP_PUSH_ALL,   /*event for CAPWAP only*/


	AH_EVENT_AMRP_METRIC_UPDATE,    /* amrp metric update, send from scd to dcd */

	AH_EVENT_STATISTICAL_SEND_DCD,  /* statistical send event to dcd */
	AH_EVENT_STATISTICAL_RECV_DCD,  /* statistical recv event from dcd */
	AH_EVENT_STATISTICAL_SEND_AMRP, /* statistical send event to amrp */
	AH_EVENT_STATISTICAL_RECV_AMRP, /* statistical recv event from amrp */
	AH_EVENT_STATISTICAL_SEND_AUTH,  /* statistical send event to auth */
	AH_EVENT_STATISTICAL_RECV_AUTH,  /* statistical recv event from auth */

	AH_EVENT_BRIDGE_STATUS_CHANGE,  /* ethx interface's bridge status change */
	/* which is used to pass info from another thread to low event thread.
	 * (these threads are in same process)
	 */
	AH_EVENT_UDPDATE_ALG_INFO,
	AH_EVENT_CAPWAP_TRAP,                   /*send trap to CAPWAP*/
	AH_EVENT_REBOOT_FAILED,                 /* send reboot failed from SCD*/
	AH_EVENT_DELTA_CONFIG_FINISH,           /*delta config from HM finished */
	AH_EVENT_WEBUI_INFORM_CAPWAP_SRV,       /*inform capwap server enable or disable*/
	AH_EVENT_MONITOR_DEBUG_CHANGE,
	AH_EVENT_WAN_IF_TEST_CFG_CHANGE,        /* inform track-ip group use for wan test change*/
	AH_EVENT_TRACK_IP_ACTIONS,              /* inform action to start */
	AH_EVENT_TRACK_IP_STAT_QUERY,           /* query action status */
	AH_EVENT_CAPTURE_START,                 /* inform packet capture start */
	AH_EVENT_CAPTURE_DONE,                  /* inform packet capture done */
	AH_EVENT_MESHFO_CHANGE,                 /* mesh failover change */
	AH_EVENT_POWER_CONFIG_CHANGED,          /* Power changed */
	AH_EVENT_CWP_LOGOFF,                    /* user logoff from web-page */
	AH_EVENT_AUTH_QUERY_SESSION_INFO,
	AH_EVENT_DISASSOC_STA,                  /* disassociate a station */
	AH_EVENT_DYNAMIC_AUTH_CHG,
	AH_EVENT_CFG_VER_CHANGED,               /* cli config version changed */
	AH_EVENT_WEBUI_CLNT_PORTAL_CHGED,       /* WebUI portal changed */
	AH_EVENT_AUTH_QUERY_STATION_INFO,
	AH_EVENT_QUERY_ACTIVE_WEB_DIR,
	AH_EVENT_RESP_ACTIVE_WEB_DIR,
	AH_EVENT_WEBUI_CLNT_HOSTNAME_CHGED,     /* WebUI hostname changed */
	AH_EVENT_SYSLOGD_CONF_UPDATE,           /* update syslogd conf */
	AH_EVENT_TRAPD_CONF_UPDATE,           /* update trapd conf */
	AH_EVENT_ASM_BEHAVIOR_SUBSCRIBE,        /*request behavior criteria*/
	AH_EVENT_ASM_BEHAVIOR_RECONNECTING,     /* AirScreen reconnecting instance */
	AH_EVENT_ASM_BEHAVIOR_REPORT,           /* detection engine notify framework */
	AH_EVENT_ASM_ACTION_DEAUTH,             /* AirScreen deauth action */
	AH_EVENT_ASM_ACTION_LOCALBAN,           /* AirScreen deauth local ban */
	AH_EVENT_ASM_PROCESS_RESULT,
	AH_EVENT_STA_OWNER_QUERY_REQ,           /* station owner query request */
	AH_EVENT_STA_OWNER_QUERY_RESP,          /* station owner query response */
	AH_EVENT_AUTH_SYNC,                     /* send event to auth, request resubmit all client event again */
	AH_EVENT_RADIUS_USER_NOTIFY,            /*RADIUS server local user*/
	AH_AUTH_REGEN_AUTO_PPSK,
	AH_AUTH_REGEN_ALL_AUTO_PPSK,
	AH_EVENT_PKT_CPT_STAT_QUERY,            /*capwap query packet capture statistic information request*/
	AH_EVENT_PKT_CPT_STAT_RESP,             /*capwap query packet capture statistic information response*/
	AH_EVENT_LOCATION_TRACK_IN,             /*capwap query location track request*/
	AH_EVENT_LOCATION_TRACK_OUT,            /*capwap query location track response*/
	AH_EVENT_CAPWAP_EXEC_CLI,               /*capwap server execute CLI event*/
	AH_EVENT_ITK_NOTIFY,                    /* it-tool-kit notify event to capwap-client */
	AH_EVENT_CAPWAP_REQUEST_DCD,            /*CAPWAP send request to DCD*/
	AH_EVENT_DCD_RESPONE_CAPWAP,            /*DCD send response to CAPWAP*/
	AH_EVENT_STA_STATS,                     /* event carry the last stats of a sta */
	AH_EVENT_INTERFACE_MAP_IN,              /*capwap query interface map infor request*/
	AH_EVENT_INTERFACE_MAP_OUT,             /*capwap query interface map infor response*/
	AH_EVENT_TUNNEL_SI_CHANGE,              /* set secure ip route for self traffic go through tunnel */
	AH_EVENT_AMRP_ETH_INFO,                 /* set amrp interface ethx info */
	AH_EVENT_TUNNEL_HB_CHANGE,              /*change amrp vpn tunnel heartbeat parameters */
	AH_EVENT_ETH_ALLOW_VLAN_CHG,            /* ethernet allowed vlan chg */
	AH_EVENT_DWIMG_COMPLETE,                /* use for distribute SW upgrade notify portal HiveAP download image completed */
	AH_EVENT_CAPWAP_REQ_VPN,                /*CAPWAP query VPN */
	AH_EVENT_VPN_RESP_CAPWAP,               /*VPN respond to CAPWAP*/
	AH_EVENT_RADIO_LOAD_QUERY,              /* query nbr ap radio load */
	AH_EVENT_HDD_NBR_INFO,                  /* high density nbr ap info */
	AH_EVENT_TV_WEBUI_REQ_CAPWAP,           /* techear view request capwap send to HM for find students */
	AH_EVENT_TV_CAPWAP_REQ_WEBUI,           /* HM send find result students to webui via capwap client */
	AH_EVENT_STA_OS_INFO,                   /* notify the station client OS info */
	AH_EVENT_MB_ALLOC_REQUEST,              /* mac-bind allocation request */
	AH_EVENT_MB_ALLOC_RESPONSE,             /* mac-bind allocation response */
	AH_EVENT_RT_STA_UPDATE,                 /* auth update the runtime station change */
	AH_EVENT_FE_ALG_CFG_CHG,                /* FE cli config ALG */
	AH_EVENT_IDP_DA_PULL,
	AH_EVENT_VPN_TUNNEL_CHANGE,             /* VPN tunnel status change */
	AH_EVENT_VPN_XAUTH_UNSET,
	AH_EVENT_DEFAULT_ROUTE_CHANGE,          /* default gateway route change */
	AH_EVENT_INTF_DEFAULT_ROUTE_CHANGE_RESERVED,     /* move AH_EVENT_INTF_DEFAULT_ROUTE_CHANGE to the high event */
	AH_EVENT_DEFAULT_IPV6_ROUTE_CHANGE,     /* default gateway route change */
	AH_EVENT_IPV6_INTF_DEFAULT_ROUTE_CHANGE,/* default gateway route change */
	AH_EVENT_TUN_EXCEPTION_CHANGE,          /* tunnel exception list change */
	AH_EVENT_TUN_EXCEPTION_ACTION_CHANGE,   /* user profile tunnel exception change */
	AH_EVENT_TUN_EXCEPTION_PBR_HOSTNAME_CHANGE, /* tunnel exception pbr hostname change */
	AH_EVENT_DNS_PROXY_ADD_DEL_RT,          /* DNS proxy require add-del route */
	AH_EVENT_VPN_REPORT_SND_FILE,           /* send vpn report file to HM */
	AH_EVENT_VPN_REPORT_RESPONCE_CAPWAP,
	AH_EVENT_VPN_REPORT_REQUEST_CAPWAP,
	AH_EVENT_VPN_REPORT_SAVE_DATA_2FLASH,
	AH_EVENT_L7D_APP_REPORT_READY_CAPWAP,   /* send l7 application report to HM */
	AH_EVENT_L7D_APP_REPROT_UPLOADED,       /* notify l7 application report uploaded */
	AH_EVENT_L7D_APP_REPROT_UPLOADED_FAILED,/* notify l7 application report uploaded failure */
	AH_EVENT_VOIP_QOS_STATUS_UPDATE,        /* VoIP QoS Policing status update */
	AH_EVENT_PSE_INFO_REPORT_REQUEST,       /* CAPWAP request DCD to report normal PSE port info */
	AH_EVENT_PSE_INFO_REPORT_RESPOND,       /* DCD respond to CAPWAP to report normal PSE port info */
	AH_EVENT_SWD_PORT_LINK_CHANGED,         /* switch HW event: port link status changed */
	AH_EVENT_SWD_PORT_STATUS_CHANGED,       /* port status has been updated by link changed event */
	AH_EVENT_SWD_PORT_AN_DONE,              /* switch HW event: port auto-negotiation done */
	AH_EVENT_SWD_FDB_ADDR_LEARNED,          /* switch HW event: FDB new address learned */
	AH_EVENT_SWD_FDB_ADDR_AGED,             /* switch HW event: FDB entry aged */
	AH_EVENT_SWD_FDB_CLEAR_BY_MSTP_KEY, /* clear mac entry by port and vlan bitmap */
	AH_EVENT_SWD_PORT_CHANNEL_CHANGE, /*switch event: Port Channel active port change*/
	AH_EVENT_SWD_PORT_CHANNEL_ACTIVE_PORT_CHANGE, /*switch event: Port Channel change*/
	AH_EVENT_SWD_SPAN_DESTINATION_PORT_CHANGE,/*switch event:Destination port change*/
	AH_EVENT_BLOCK_CALL,                    /* blockable event mechanism */
	AH_EVENT_BLOCK_CALL_REPLY,              /* blockable event reply */
	AH_EVENT_SWD_FDB_ADDR_NOTIFY,           /* SWD to notify AUTH: FDB entry aged or learned */
	AH_EVENT_SWD_VOICE_VLAN_NOTIFY,         /* SWD to notify LLDP: VOICE VLAN changed */
	AH_EVENT_SWD_VLAN_CHANGE_NOTIFY,      /* SWD to nofify STP: VLAN change */
	AH_EVENT_SWD_VLAN_LIST_CHANGE_NOTIFY,   /* SWD to nofify STP: Vlan list change */
	AH_EVENT_SWD_VLAN_PORT_CHANGE_NOTIFY,
	AH_EVENT_SWD_VLAN_LIST_PORT_CHANGE_NOTIFY,       /* SWD to notify STP, port add or del from vlan list */
	AH_EVENT_SWD_VLAN_IF_RECOVER,             /* SWD to notify DCD if vlan recover */
	AH_EVENT_SWD_SET_SECURE_ACCESS_MAC,     /* add/delete secure access mac to FDB */
	AH_EVENT_AUTH_STA_INFO,
	AH_EVENT_L7D_APPID,                     /* L7d internal events */
	AH_EVENT_SWD_IF_TYPE_CHANGE,
	AH_EVENT_STP_PORT_STATE,           /* mstp stp event state change*/
	AH_EVENT_CAPWAP_REQUEST_L7D,
	AH_EVENT_L7D_RESPONSE_CAPWAP,
	AH_EVENT_L7D_SIGNATURE_VERSION_NOTIFY,
	AH_EVENT_L7D_APP_SIG_IMAGE_READY,
	AH_EVENT_BRD_WEBSEC_OPENDNS_CFG_CHANGE,
	AH_EVENT_RADSEC_PROXY_INFO_REQ, /* CAPWAP send radsec proxy info request */
	AH_EVENT_RADSEC_PROXY_INFO_RESP, /* send radsec proxy info response */
	AH_EVENT_TRAP, /* Send trap event*/

	AH_EVENT_LOW_PRIO_MAX,
	/* ------------------------------------------------- */
	AH_EVENT_HIGH_PRIO_MIN = AH_EVENT_LOW_PRIO_MAX,
	AH_EVENT_CAPWAP_CONNECT,        /* capwap connect to the HM*/
	AH_EVENT_CAPWAP_DISCONNECT,     /*capwap disconnect to th HM*/
	AH_EVENT_DCD_LOCK_RADIOS,       /* dcd lock radios for timebomb */
	AH_EVENT_DCD_UNLOCK_RADIOS,     /* dcd unlock radios for timebomb */
	AH_EVENT_SWD_LOCK_VLAN,         /* swd lock vlan for timebomb, supported in chesapeake*/
	AH_EVENT_SWD_UNLOCK_VLAN,       /* swd unlock vlan for timebomb, supported in chesapeake*/
	AH_EVENT_WEB_SRV_RESTART,       /* Web server restart */
	AH_EVENT_CLI_SRV_RESTART,       /* Cli server restart */
	AH_EVENT_SYS_READY,             /*System ready event*/
	AH_EVENT_DHCPC_REQUEST,         /* trigger dhcp client to do something */
	AH_EVENT_DHCPS_CFG_CHG,         /* DHCP server config change  */
	AH_EVENT_DNS_CFG_CHG,           /* DNS server config change  */
	AH_EVENT_RADIUSD_NOTIFY,        /*RADIUS server nodify event*/

	AH_EVENT_GW_CHANGE,             /* default gateway chg */
	AH_EVENT_CAPWAP_CLIENT_CHG,
	/* Auth Module Send */
	AH_EVENT_AUTH_JOIN,             /*one user succe login */
	AH_EVENT_AUTH_LEAVE,            /*one user leave */
	AH_EVENT_XMT_RM_CACHE,          /*xmt rm cache to amrp*/
	AH_EVENT_RESP_CWP_USER_JOIN,
	AH_EVENT_RESP_CWP_LOGOFF,
	AH_EVENT_AUTH_RESP_SESSION_INFO,
	AH_EVENT_AUTH_RESP_STATION_INFO,
	AH_EVENT_CTL_PKT_CRYPT_RESPONSE,/* used by auth module to send event to amrp module for control packet encryption */
	AH_EVENT_AUTHDCD_REQUEST,       /* auth request info from dcd */
	AH_EVENT_AUTHDCD_REMOVE_MAC_OBJECT_ELEMENT,
	AH_EVENT_AUTHDCD_ADD_MAC_OBJECT_ELEMENT,
	AH_EVENT_SCHD_SUB_REF,

	AH_EVENT_DCD_ADD_HIVEID,        /* add hiveid */
	AH_EVENT_DCD_DEL_HIVEID,        /* delete hiveid */
	AH_EVENT_DCD_IF_CHANGE,         /* interface change */
	AH_EVENT_DCD_BIND_HIVEID,       /* bind hiveid to hvi */

	AH_EVENT_MGT0_VLAN_CHG,
	AH_EVENT_HOSTNAME_CHG,
	AH_EVENT_IP_CHANGE,             /* mgt0 IP address change */
	AH_EVENT_ETHX_IP_CHANGE,         /* ethx IP address change */
	AH_EVENT_TUNNEL_IP_CHANGE,      /* tunnel IP address change */
	AH_EVENT_PPPX_IP_CHANGE,         /* pppx IP address change */
	AH_EVENT_USBX_IP_CHANGE,         /* usbx IP address change */
	AH_EVENT_VAP_IP_CHANGE,         /* wifix.y IP address change */
	AH_EVENT_VMGT_IP_CHANGE,         /* mgtx.y IP address change */
	AH_EVENT_VMGT_SUBNET_CHANGE,     /* mgtx.y IP address change across subnet*/
	AH_EVENT_VMGT_IF_REMOVAL,         /* mgtx.y interface removal */
	AH_EVENT_VAP_SSID_CHANGE,       /* wifix.y ssid change */
	AH_EVENT_SSID_CHANGE,           /* ssid create or destory */
	AH_EVENT_IPV6_CHANGE,           /* mgt0 IPV6 address change */
	AH_EVENT_ETHX_IPV6_CHANGE,       /* ethx IPV6 address change */
	AH_EVENT_TUNNEL_IPV6_CHANGE,      /* tunnel IPV6 address change */
	AH_EVENT_PPPX_IPV6_CHANGE,         /* pppx IPV6 address change */
	AH_EVENT_USBX_IPV6_CHANGE,         /* usbx IPV6 address change */
	AH_EVENT_VAP_IPV6_CHANGE,         /* wifix.y IPV6 address change */
	AH_EVENT_VMGT_IPV6_CHANGE,         /* mgtx.y IPV6 address change */
	AH_EVENT_BGD_IPV6_CHANGE,
	AH_EVENT_VMGT_IPV6_SUBNET_CHANGE,     /* mgtx.y IPv6 address change across subnet*/
	AH_EVENT_DHCPV6C_REQUEST,
	AH_EVENT_IP_VERSION_PREFERENCE,
	AH_EVENT_SYS_REBOOT,            /* system reboot */
	AH_EVENT_DCD_MGT0_HIVE_CHG,     /*MGT0 bind hiveid changed*/
	AH_EVENT_CURR_CFG_VALID_CHG,    /* current config valid status change */
	AH_EVENT_USR_IP_VALID_CHG,      /* user IP (DHCP IP or static IP) valid status change */

	AH_EVENT_RADIUS_VLAN_CHG,       /* VLAN changed from RADIUS */
	AH_EVENT_RADIUS_TEST_REQUEST,   /*CAPWAP send RADIUS test request*/
	AH_EVENT_RADIUS_TEST_RESPONSE, /*RADIUS send RADIUS test response*/
	AH_EVENT_REMOTE_SNIF_DATA_PORT_CHG,  /*Remote snffier data port changed*/
	AH_EVENT_RADIUS_LDAP_TREE_REQ, /* CAPWAP send ldap tree query request */
	AH_EVENT_RADIUS_LDAP_TREE_RESP,/* Send the ldap tree query response to CAPWAP */
	/* AH_EVENT_RADIUS_AD_RETRIVE_REQ: retrive the AD's basic info by full domain name, return short name, server IP, etc. */
	AH_EVENT_RADIUS_AD_RETRIVE_REQ, /* CAPWAP send AD retrive info request */
	AH_EVENT_RADIUS_AD_RETRIVE_RESP,/* Send the AD retrive info response to CAPWAP */
	/* AH_EVENT_RADIUS_QUERY_AD_INFO_REQ: return which domain AP joined */
	AH_EVENT_RADIUS_QUERY_AD_INFO_REQ, /* CAPWAP send query ad info request */
	AH_EVENT_RADIUS_QUERY_AD_INFO_RESP,/* Send the query ad info response to CAPWAP */
	AH_EVENT_DCM_ENABLE,  /*Send Data Collection Enable*/
	AH_EVENT_DCM_DISABLE,  /*Send Data Collection Disable*/
	AH_EVENT_DCM_SND_PKT,  /*Send Data Collection to CAPWAP*/
	AH_EVENT_AMRP_DA_CHG, /* AMRP my-da change event */
	AH_EVENT_INFORM_PM_MONITOR, /*Inform pm monitor module dynamic*/
	AH_EVENT_PPSK_SELF_REG_INFO_CAPWAP, /* Send ppsk-self-reg info to capwap for sending trap */
	AH_EVENT_NAAS_REQUEST,  /*Get NAAS request from CAPWAP*/
	AH_EVENT_NAAS_RESPONSE,/*Send NAAS resonse to CAPWAP*/
	AH_EVENT_DCD_LOCK_LAN,  /*NAAS LOCK LAN PORT*/
	AH_EVENT_DCD_UNLOCK_LAN, /*NAAS UNLOCK LAN PORT*/
	AH_EVENT_RMC_QUERY_USER, /* request username from roaming cache */
	AH_EVENT_RMC_REPONSE_USER, /* auth response username from roaming cache */
	AH_EVENT_VPN_DAEMON_RESTART, /* VPN module restart */
	AH_EVENT_BRD_RESTART, /* BRD module restart */
	AH_EVENT_BRD_PPPOE_REQUEST, /* request to start/stop PPPoE */
	AH_EVENT_BRD_DDNS_ENABLE_STATUS, /* brd ddns enable status */


	AH_EVENT_WAN_IFMON_IF_STATE_CHANGE,      /* WAN interface's state changed by track ip test */

	AH_EVENT_PPSK_RAD_SRV_CHG_DHCP, /* update auth config for dhcp options changed */
	AH_EVENT_IDP_AP_CLF_HM_SEND, /*HM Send AP classify info to AP*/
	AH_EVENT_IDP_AP_CLF_DA_SEND, /*DA Send msg to HM*/
	AH_EVENT_BGD_ENABLE_CHANGE, /* BGD enable change */
	AH_EVENT_BGD_NOTIFY,        /* BGD notify event */
	AH_EVENT_VLAN_SCAN_NOTIFY,  /* VLAN add or delete event */
	AH_EVENT_BGD_IP_CHANGE,     /* bgd0.x IP address change */
	AH_EVENT_PM_RESTART_ROUTING_DAEMON, /* PM restarts routing daemon */
	AH_EVENT_FIRMWARE_UPDATE,   /* before, after firmware upgrade */
	AH_EVENT_DHCPC_DEFAULT_ROUTE_NOTIFY, /* DHCP client default route setting notify */
	AH_EVENT_DHCPC_DNS_UPDATE, /* DHCP client DNS setting update */
	AH_EVENT_MGTXY_CHANGE,      /* mgt0.x interface add or delete */
	AH_EVENT_AMRP_BDD,          /* amrp send out event for known (BDD) Bonjour Designated Device */
	AH_EVENT_AMRP_MYBDD_CHG,   /* amrp tell whether myself is BDD */
	AH_EVENT_AMRP_REALM_ID_CHANGE, /* amrp send out event for Bonjour Realm id change */
	AH_EVENT_IPFW_CLEAR_NETWORKS_SESSION, /* IPFW clear sessions for specified networks */
	AH_EVENT_IPFW_CLEAR_MARKED_SESSION, /* IPFW clear sessions for specified mark */
	AH_EVENT_DCDAUTH_PPSK_RESPONSE, /* dcd send PPSK configuration */
	AH_EVENT_OTP_REQUEST_CAPWAP,
	AH_EVENT_OTP_RESPONCE_CAPWAP,
	AH_EVENT_OTP_CWP,
	AH_EVENT_STATIC_ROUTE_CHANGE, /* non-default-gateway static route change */
	AH_EVENT_MDM_PASSED_REQ,    /* tell auth set MDM status passed */
	AH_EVENT_MDM_PASSED_RESP,   /* receve from auth set MDM status done */
	AH_EVENT_RADSEC_CERT_CREATION_REQ, /* CAPWAP send cert creation request */
	AH_EVENT_RADSEC_CERT_CREATION_RESP,/* Send the certificate signing request to CAPWAP */
	AH_EVENT_RADSEC_NOTIFY,            /* RADSEC proxy notify event */
	AH_EVENT_RADSEC_CERT_STATUS,       /* RadSec certificate status notification */
	AH_EVENT_RADSEC_CERT_RENEW_RES,    /* HM send the certificate renew result */
	AH_EVENT_RADSEC_IDM_CONNECT_LOST,  /* Proxy server lost the connection with ID manager*/
	AH_EVENT_RADSEC_ELCT_GET_CDDT_INFO,   /* arbiter get the candidate info by event for radsec auto-election */
	AH_EVENT_AUTO_RENEW_IDM_CERT,   /*Auto renew IDM cert for IDM self-register function*/
	AH_EVENT_CAPWAP_REQ_BGD,    /*CAPWAP query BGD */
	AH_EVENT_BGD_RESP_CAPWAP,   /*BGD respond to CAPWAP*/
	AH_EVENT_DNS_ALG_UPDATE_WG, /* Update walled garden by DNS alg */
	AH_EVENT_AMRP_REMOTE_STA_SET, /* when armp learn new remote sta, send out this event */
	AH_EVENT_CONFROLBCK_ACSPSTATE_QUERY, /* config rollback query ACSP select channel complete?? */
	AH_EVENT_BR_MODE_ENABLE_CHANGE,  /* BR mode enable change */
	AH_EVENT_BGD_SERVICE_INFO,           /* BGD service */
	AH_EVENT_BGD_PRIORITY_CHG,           /* BDD priortiy changed, notify AMRP */
	AH_EVENT_REG_SERVICE,       /* config dynamic server */
	AH_EVENT_INFO_SERVICE,      /* receive dynamic server infomation */
	AH_EVENT_REQ_SERVICE,       /* request dynamic server infomation */
	AH_EVENT_QUERY_SERVICE,     /* query dynamic server informaton */
	AH_EVENT_RADSEC_RADIUS_STARTUP,    /* local RADIUS startup notification */
	AH_EVENT_SWD_CAPWAP_REQUEST,  /* request switch info */
	AH_EVENT_SWD_CAPWAP_RESPONE,  /* switch response */
	AH_EVENT_SWD_CAPWAP_PORT_INFO_CHANGED_NOTIFY,
	AH_EVENT_VPN_TUNNEL_NAT_POLICY_CFG, /* add or remove nat policy on tunnel*/
	AH_EVENT_AUTH_SCHED_STAT_CHG, /* set the schedule status disable/enable */
	AH_EVENT_BRD_AUTH,
	AH_EVENT_CAPWAP_REQUEST_USBNET_STATUS,
	AH_EVENT_CAPWAP_RESPONSE_USBNET_STATUS,
	AH_EVENT_BRD_USBMODEM_PRIMARY_WAN_NOTIFY,
	AH_EVENT_UP_TUNNEL_POLICY_CHG, /* user profile bind or unbind tunnel policy  */
	AH_EVENT_MDM_AW_PROC_COMPLIANT, /* Process Compliant status for Airwatch */
	AH_EVENT_VPN_TUNNEL_RENEW,   /* tunnel phase1 rekey */
	AH_EVENT_AMRP_ONEWAY_TIMEOUT, /* AMRP one-way neighbor timeout detected */
	AH_EVENT_CHAN_SLT_ENABLE, /* acsd channel selection activate */
	AH_EVENT_BGSCAN_CFG, /* bgscan config set */
	AH_EVENT_ACSD_RESTART,
	AH_EVENT_ACSD_IF_CFG, /* acsd per interface cfg */
	AH_EVENT_ACSD_SCAN_REQ, /* acsd scan req */
	AH_EVENT_ACSD_SCAN_DONE, /* acsd scan complete */
	AH_EVENT_ACSD_CCA_STATS_UPD, /* acsd cca stats update */
	AH_EVENT_HIVE_BROADCAST,     /* broadcast to entire hive including different L3 subnets */
	AH_EVENT_HIVE_BROADCAST_L2,  /* broadcast to hive members in the same subnet */
	AH_EVENT_RDS_RESTART,           /* restart radius */
	AH_EVENT_INTF_DEFAULT_ROUTE_CHANGE,     /* default gateway route change */
	AH_EVENT_AUTH_ETH_IF_RESTART,   /* Restart ETH interface */
	AH_EVENT_ACPP_QUERY_URL_INFO,  /* Cgic query redirce URL FOR acpp*/
	AH_EVENT_ACPP_RESP_URL_INFO,   /* auth response redirce URL to cgic*/
	AH_EVENT_ACPP_GRD_CHG,              /* The garden for ACPP changed*/
	AH_EVENT_AUTH_QUERY_MDM_STATION_INFO, /* cgic query staion info for acm */
	AH_EVENT_AUTH_RESP_MDM_STATION_INFO,  /* auth response acm relative station info to cgic*/
	AH_EVENT_HAPD_UPDATE_UPP_CFG, /* user profile policy changed */
	AH_EVENT_CM_INFO,       /* client monitor info message */
	AH_EVENT_QUERY_IDM_PROXY,       /* notify auth to find dynamic server infomation */
	AH_EVENT_DCD_IBEACON_CFG_CHANGE,    /* iBeacon config change event */
	AH_EVENT_DCD_IBEACON_USB_ATTACH_CHANGE, /* iBeacon USB device attach/detach*/
	AH_EVENT_CM_SHOW_INFO,   /* CLI show client monitor information */
	AH_EVENT_CAVC_AP_CHANGE,
	AH_EVENT_CAVC_AP_TUNNEL_CREATE,
	AH_EVENT_CAVC_CLIENT_JOIN,             /*one client succe login */
	AH_EVENT_CAVC_CLIENT_LEAVE,            /*one client leave */
	AH_EVENT_CAVC_SW_MAC,
	AH_EVENT_ACL_USER_PROFILE_DEL,
	AH_EVENT_ACL_USER_PROFILE_ATTRIBUTE_CHANGE,
	AH_EVENT_AMRP_AEROHIVE_DEV,      /* detect Aerohive AP */
	AH_EVENT_CFG_FILE_CHG,            /* config file changed */
	AH_EVENT_TUN_EXCEPTION_PBR_HOSTNAME_IP_LIST_CHANGE, /* tunnel exception pbr hostname IP list change */
	AH_EVENT_VLAN_GROUP_RANGE_CHG,     /* vlan-group's range change */
	AH_EVENT_SUPPLICANT_STATUS_UPDATE, /* WPA supplicant status change */
	AH_EVENT_WPS_CMD_INFO, /* notify wpa supplicant to update config */

	AH_EVENT_REQUEST_NODE_FOR_STA,     /* request node IP for a remote station */
	AH_EVENT_REPLY_NODE_FOR_STA,       /* reply node IP for a remote station */
	AH_EVENT_VRRP_MASTER_RENEW,
	AH_EVENT_BRD_WAN_SM_NO_WAN,         /* WAN failover status changed to NO_WAN */
	AH_EVENT_NBRCOM_IP_UPDATE,      /* update self IPv4 or IPv6 address */
	AH_EVENT_ADD_RMNBR_BRIDGE_BY_STA,
	AH_EVENT_MAX_NUM
} ah_event_t;

typedef struct ah_event_reply_ {
	int rc;
} ah_event_reply_t;

#ifdef AH_BONJOUR_GATEWAY_SUPPORT
struct amrp_bdd_event_ {
	ah_ipaddr46_t abe_ipv46;
	uint8_t  abe_mask; /* BDD mask */
#define ABE_TYPE_SET 0   /* add */
#define ABE_TYPE_UNSET 1 /* delete */
	uint8_t  abe_type;
	uint16_t abe_hopcnt; /* amrp hopcnt */
};
#endif

typedef struct amrp_event_del_sta_ {
	ah_mac_t aeds_mac;    /* the STA mac */
	ah_mac_t aeds_ifmac;  /* the interface mac */
#define AEDS_FLAG_ROAM_AWAY  0x00000001 /* STA roaming away */
#define AEDS_FLAG_TUNN_DOWN  0x00000002 /* inxp/dnxp STA detach from tunnel */
#define AEDS_FLAG_UNRAOM     0x00000004 /* dnxp STA unroamed */
#define AEDS_FLAG_AMRP_ERROR 0x00000008 /* dnxp STA unroamed */
#define AEDS_FLAG_VAP_DOWN   0x00000010 /* vap shutdown */
#define AEDS_FLAG2STR(f) ( ((f) & AEDS_FLAG_ROAM_AWAY)? "STA roam away": \
						   ((f) & AEDS_FLAG_TUNN_DOWN)? "L3 tun down": \
						   ((f) & AEDS_FLAG_UNRAOM)? "STA unroam": \
						   ((f) & AEDS_FLAG_AMRP_ERROR)? "AMRP error": \
						   ((f) & AEDS_FLAG_VAP_DOWN)? "VAP shut down": \
						   "unknown" )
	uint32_t   aeds_flag;
} amrp_event_del_sta_t;
/*
 * amrp add sta event
 */
typedef struct amrp_event_add_sta_ {
	ah_mac_t aeas_mac;      /* the STA mac */
	int      aeas_ifindex;  /* the interface mac */
} amrp_event_add_sta_t;
/*
 * amrp notify vpn peer timeout
 */
typedef struct amrp_event_vpn_timeout_ {
	int      aevt_ifindex; /* tunnel interface ifindex */
	uint32_t   aevt_gre_gw_ipv4;
} amrp_event_vpn_timeout_t;

/*
 * amrp declare newly learned remote sta
 */
typedef struct amrp_event_remote_sta_ {
	ah_mac_t aers_sta_mac;     /* mac-addr of this STA */
	uint16_t   aers_flag;        /* not used yet(Apr/19/12), for future expansion... */
	uint32_t   aers_node_ipv4;   /* (in network order) to which AP this STA associated (could be 0.0.0.0, mean dont' know) */
} amrp_event_remote_sta_t;

/*
 * amrp notify portal change event.
 * 0.0.0.0 means no portal available, otherwise, the value is the portal IPv4 address
 * in network byte order
 */
typedef struct amrp_event_portal_chg_ {
	ah_ipaddr46_t aepc_ipv46;
} amrp_event_portal_chg_t;

/*
 * amrp send event to auth for sync the stations.
 * ifindex is 0 means sync all interface, otherwise, sync the stations on the interface
 */
typedef struct amrp_event_sync_sta_ {
	int   ifindex;
} amrp_event_sync_sta_t;

/*
 * BRD send event to auth to relearn nas_ip and src_ip
 */
typedef struct brd_auth_event_ {
	int dummy;
} brd_auth_event_t;

extern char *ah_eventid_to_name (ah_event_t eid);

/* Event processing vector */
typedef void (*ah_event_proc_vector_t)(ah_event_t event_id, uint32_t size, void *data);
typedef void (*ah_kevent_proc_vector_t)(ah_kevent_t kevent_id, uint32_t size, void *data);
typedef int (*ah_block_event_proc_vector_t)(ah_event_t event_id, uint32_t size, void *data);
//int ah_event_sendonly_init(uint16_t module_id, uint16_t sub_mod_id, pthread_t *event_tid);

int ah_event_init(uint16_t module_id, pthread_t *event_tid);
void ah_event_end_ptimer(void);
int ah_event_cleanup(void);
int ah_event_subscribe(ah_event_t event_id, ah_event_proc_vector_t vector);
int ah_event_unsubscribe(ah_event_t event_id);
int ah_event_verify(ah_event_t event_id);
int ah_event_send(ah_event_t event_id, uint32_t size, void *data);
int ah_event_set_debug(ah_event_t event_id, boolean enable);
int has_ah_event_init (void);
int ah_event_dump_rcvr_map(void);

int ah_kevent_unsubscribe(ah_kevent_t kevent_id);
int ah_kevent_subscribe (ah_kevent_t kevent_id, ah_kevent_proc_vector_t vector);

int ah_event_sendto(ah_event_t event_id, uint32_t size, void *data, uint32_t mpi_port, uint16_t seq);
int ah_block_event_start_subthread(ah_block_event_proc_vector_t vector);
int ah_event_block_send(ah_event_t event_id, uint32_t size, void *data, uint32_t dest_mod);
int ah_trap_send(uint trap_level, ah_trap_info_t *trap_info, const char *fmt, ...);


#endif /* _AH_EVENT_H */
