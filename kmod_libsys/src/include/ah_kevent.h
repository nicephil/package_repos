#ifndef __AH_KEVENT_H__
#define __AH_KEVENT_H__

#ifdef __KERNEL__
#include <linux/if.h>
#else
#include <net/if.h>
#endif

#include "ah_netconst.h"
#include "ah_ipv6_shared.h"

#define AH_EVENT_MAX_LEN        6000 /* requested by huizhao to support large wifi driver stats data, which is using kevent */

#define AH_LOW_EVT        1
#define AH_HIGH_EVT       2
#define AH_LOWEST_EVT     4
#define AH_ALL_EVTS       (AH_LOW_EVT | AH_HIGH_EVT | AH_LOWEST_EVT)

/*
 * kernel event id
 */
typedef enum {
	AH_KEVENT_L7_PKT = 0,           /* l7 packet event */
	AH_KEVENT_SFLOW_DATA,           /* sflow data */
	AH_KEVENT_LOWEST_PRIO_MAX,
	/* ------------------------------------------------- */
	AH_KEVENT_LOW_PRIO_MIN = AH_KEVENT_LOWEST_PRIO_MAX,
	AH_KEVENT_IDP_AP,           /* IDP AP event */
	AH_KEVENT_LCS,                  /* LCS location event */
	AH_KEVENT_SYNC_FE_SESSION,      /* recv packets for session sync */
	AH_KEVENT_FE_STA_INFO,          /* Client info */
	AH_KEVENT_FE_ALG_PKT,           /* ALG data */
	AH_KEVENT_FE_ALG_HTTP_PKT,      /* http ALG data */
	AH_KEVENT_FE_IF_VLAN,           /* kevent for interface vlan */
	AH_KEVENT_FE_L7_APP,            /* kevent for L7 app */
	AH_KEVENT_ASM_BEHAVIOR_REPORT,  /* Problematic behavior report */
	AH_KEVENT_ASM_PROCESS_RESULT,   /* report process result */
	AH_KEVENT_IDP_STA,              /* IDP STA event */
	AH_KEVENT_ITK_NOTIFY,           /* it-tool-kit notify kevent to capwap-client */
	AH_KEVENT_STA_STATS,            /* client stats event, used for sending client last stats */
	AH_KEVENT_LOW_PRIO_MAX,
	/* ------------------------------------------------- */
	AH_KEVENT_HIGH_PRIO_MIN = AH_KEVENT_LOW_PRIO_MAX,
	AH_KEVENT_IF_CHANGE,         /* interface change */
	AH_KEVENT_RESET_BUTTON,         /* reset button pressed, system will reboot */
	AH_KEVENT_ACSPNBR,              /* ACSP neighbor event */
	AH_KEVENT_ACSPCHAN,             /* ACSP channel/power selection event */
	AH_KEVENT_WIFI_STA,             /* Wifi station event */
	AH_KEVENT_WIFI_FAILURE,         /* Wifi hardware failure */
	AH_KEVENT_MAC_LEARN_ENTRY,      /* MAC learn entry */
	AH_KEVENT_UNROAM_STATION,       /* Station unroamed */
	AH_KEVENT_AH_DEV_TYPE_CHANAGE,  /* notify any changed in ah_dev structure, mode (access/backhaul) for now */
	AH_KEVENT_CHAN_CHANGE,          /* channel change (user requested) */
	AH_KEVENT_RADIO_STUCK,          /* radio frame stuck */
	AH_KEVENT_RADIO_DFS,            /* DFS related event */
	AH_KEVENT_DEV_BIND,             /* interface is bound */
	AH_KEVENT_DEV_UNBIND,           /* interface is unbound */
	AH_KEVENT_STA_OWNER_RLS_CHG,    /* station owner release change */
	AH_KEVENT_BSSID_SPOOFING,       /* used to send trap for BSSID spoofing */
	AH_KEVENT_SECURITY_BREACH,      /* wifi security breach */
	AH_KEVENT_LAN_PORT_LINK_STATUS_CHGD, /*LAN port link status changed*/
	AH_KEVENT_PSE_ERROR,            /* PSE met something error, e.g. overload/short */
	AH_KEVENT_PSE_INFO,             /* PSE normal info change report, e.g total power, port state, PD class */
	AH_KEVENT_FE_ALG_DHCP_PKT,      /* DHCP ALG data */
	AH_KEVENT_UDEV_TX_TIMEOUT,      /* USB device tx timeout */
	AH_KEVENT_LED_UPDATE,      /* switch led update commands. */
	AH_KEVENT_PWR_UPDATE,      /* switch power update. */
	AH_KEVENT_SFP_STATUS_CHANGED,   /* XG port PHY/SFP status changed */
	AH_KEVENT_DHCPV6_MODE,
	AH_KEVENT_VLAN_SCAN_CHG,
#if defined(AH_SUPPORT_DOS)
	AH_KEVENT_DOS,                  /* DoS station event */
#endif
	AH_KEVENT_TRAP,                 /* Send trap kevent */
	AH_KEVENT_MAX                   /* we only support up to 32 kevent, have to change ah_kevent.c if want more than that */
} ah_kevent_t;
#define is_kevent_valid(eid)    ( (eid) < AH_KEVENT_MAX )
#define eid2name(eid) ( \
						((eid)==AH_KEVENT_IF_CHANGE)? "KEVT_IF_CHG": \
						((eid)==AH_KEVENT_RESET_BUTTON)? "KEVT_RST_BTN": \
						((eid)==AH_KEVENT_ACSPNBR)? "KEVT_ACSP_NBR": \
						((eid)==AH_KEVENT_ACSPCHAN)? "KEVT_ACSP_CHAN": \
						((eid)==AH_KEVENT_IDP_AP)? "KEVT_IDP_AP": \
						((eid)==AH_KEVENT_IDP_STA)? "KEVT_IDP_STA": \
						((eid)==AH_KEVENT_LCS)? "KEVT_LCS": \
						((eid)==AH_KEVENT_WIFI_STA)? "KEVT_WIFI_STA": \
						((eid)==AH_KEVENT_WIFI_FAILURE)? "KEVT_WIFI_FAILURE": \
						((eid)==AH_KEVENT_FE_STA_INFO)? "KEVT_FE_STA_INFO": \
						((eid)==AH_KEVENT_SYNC_FE_SESSION)? "KEVT_SYNC_FE_SESSION": \
						((eid)==AH_KEVENT_FE_ALG_PKT)? "KEVT_ALG_PKT": \
						((eid)==AH_KEVENT_FE_ALG_HTTP_PKT)? "KEVT_HTTP_ALG_PKT": \
						((eid)==AH_KEVENT_MAC_LEARN_ENTRY)? "KEVT_MAC_LEARN_ENTRY": \
						((eid)==AH_KEVENT_UNROAM_STATION)? "KEVT_STATION_UNROAM" : \
						((eid)==AH_KEVENT_DEV_BIND)? "KEVT_DEV_BIND" : \
						((eid)==AH_KEVENT_DEV_UNBIND)? "KEVT_DEV_UNBIND" : \
						((eid)==AH_KEVENT_CHAN_CHANGE)? "KEVT_CHAN_CHG" : \
						((eid)==AH_KEVENT_AH_DEV_TYPE_CHANAGE)? "KEVT_AH_DEV_TYPE_CHANGE" : \
						((eid)==AH_KEVENT_RADIO_STUCK)?"KEVT_RADIO_STUCK" : \
						((eid)==AH_KEVENT_RADIO_DFS)? "KEVT_RADIO_DFS" : \
						((eid)==AH_KEVENT_FE_IF_VLAN)? "KEVT_FE_IF_VLAN" : \
						((eid)==AH_KEVENT_ASM_BEHAVIOR_REPORT)? "KEVT_ASM_PROB_BEHAVIOR" : \
						((eid)==AH_KEVENT_ASM_PROCESS_RESULT)? "KEVT_ASM_PROC_RESULT" : \
						((eid)==AH_KEVENT_ITK_NOTIFY)? "AH_KEVENT_ITK_NOTIFY" : \
						((eid)==AH_KEVENT_STA_OWNER_RLS_CHG)?"KEVT_STA_OWNER_RLS_CHG" : \
						((eid)==AH_KEVENT_BSSID_SPOOFING)?"KEVT_STA_BSSID_SPOOFING" : \
						((eid)==AH_KEVENT_SECURITY_BREACH)?"AH_KEVENT_SECURITY_BREACH" : \
						((eid)==AH_KEVENT_STA_STATS)?"AH_KEVENT_STA_STATS" : \
						((eid)==AH_KEVENT_LAN_PORT_LINK_STATUS_CHGD)?"LAN port link status changed" : \
						((eid)==AH_KEVENT_PSE_ERROR)?"PSE port power error" : \
						((eid)==AH_KEVENT_PSE_INFO)?"PSE port info report" : \
						((eid)==AH_KEVENT_FE_ALG_DHCP_PKT)?"DHCP ALG data" : \
						((eid)==AH_KEVENT_UDEV_TX_TIMEOUT)?"USB device tx timeout" : \
						((eid)==AH_KEVENT_L7_PKT)?"KEVT_L7_PKT" : \
						((eid)==AH_KEVENT_FE_L7_APP)?"KEVT_FE_L7_APP" : \
						((eid)==AH_KEVENT_UDEV_TX_TIMEOUT)?"USB device tx timeout" : \
						((eid)==AH_KEVENT_LED_UPDATE)?"KEVT_LED_BTN" : \
						((eid)==AH_KEVENT_PWR_UPDATE)?"Chesapeake Power source change." : \
						((eid)==AH_KEVENT_SFP_STATUS_CHANGED)?"XG PHY/SFP status changed" : \
						((eid)==AH_KEVENT_SFLOW_DATA)?"sflow data" : \
						((eid)==AH_KEVENT_DHCPV6_MODE)?"DHCPV6 mode" :\
						((eid)==AH_KEVENT_VLAN_SCAN_CHG)?"VLAN discovery" :\
						((eid)==AH_KEVENT_DOS)?"DoS event" :\
						((eid)==AH_KEVENT_TRAP)?"Send trap kevent" :\
						"n/a" \
					  )
/*
 * this struct carry the info of <AH_KEVENT_IF_CHANGE> kevents
 */
typedef enum {
	AH_KEVENT_IF_INVALID  =  0, /* invalid if chg type */
	AH_KEVENT_IF_UP,            /* interface up */
	AH_KEVENT_IF_DOWN,          /* interface down */
	AH_KEVENT_IF_REBOOT,        /* interface hardware crash and restarted */
	AH_KEVENT_IF_CHANGEMTU,     /* interface mtu change */
	AH_KEVENT_IF_CHANGEMAC,     /* mac addr chg */
	AH_KEVENT_IF_CHANGENAME,    /* interface name change */
	AH_KEVENT_IF_GOING_DOWN,     /* interface will be down soon */
	AH_KEVENT_IF_IPV6_ADDR_ADD, /* add a ipv6 address to interface */
	AH_KEVENT_IF_IPV6_ADDR_DEL  /* delete a ipv6 address from interface */
} ah_kevent_if_change_type_t;
#define kevent_if_chg2name(t) ( \
								(t) == AH_KEVENT_IF_INVALID?    "INVALID": \
								(t) == AH_KEVENT_IF_UP?         "IF_UP": \
								(t) == AH_KEVENT_IF_DOWN?       "IF_DOWN": \
								(t) == AH_KEVENT_IF_REBOOT?     "IF_REBOOT": \
								(t) == AH_KEVENT_IF_CHANGEMTU?  "IF_MTU": \
								(t) == AH_KEVENT_IF_CHANGEMAC?  "IF_MAC": \
								(t) == AH_KEVENT_IF_CHANGENAME? "IF_NAME": \
								(t) == AH_KEVENT_IF_GOING_DOWN? "IF_GOING_DOWN":\
								(t) == AH_KEVENT_IF_IPV6_ADDR_ADD? "IF_IPV6_ADDR_ADD":\
								(t) == AH_KEVENT_IF_IPV6_ADDR_DEL? "IF_IPV6_ADDR_DEL":\
								"n/a" )

typedef enum {
	AH_KEVENT_RSTBTN_REBOOT = 1,
	AH_KEVENT_RSTBTN_RESTORE_FACTORY
} ah_kevent_reset_button_t;
typedef struct {

	ah_kevent_if_change_type_t kic_type;
	int         kic_ifindex;
	uint        kic_flag;        /* interface flag */
	char        kic_ifname[IFNAMSIZ];    /* for AH_KEVENT_IF_CHANGENAME, it's the new name */
#define kic_mtu  kic_data_.kic_mtu_
#define kic_mac  kic_data_.kic_mac_
#define kic_ipv6_addr kic_data_.ipv6_addr
	union  {
		uint32_t kic_mtu_;        /* for AH_KEVENT_IF_CHANGEMTU, it's the new mtu */
		uint8_t  kic_mac_[6];     /* for AH_KEVENT_IF_CHANGEMAC, it's the new mac addr */
		ah_if_ipv6_addr_t ipv6_addr;    /* for AH_KEVENT_IF_IPV6_ADDR_ADD / DEL, only ipv6_addr and prefixlen makes sense */
	} kic_data_;

} ah_kevent_if_change_t;

typedef struct {

	int if_index;
	int dev_type;       /* as defined in ah_types.h (AH_DEV_TYPE_BACKHAUL ..) */

} ah_kevent_ah_dev_change_t;

typedef enum {
	AH_KEVENT_DHCPV6_STATEFUL,
	AH_KEVENT_DHCPV6_STATELESS
} ah_kevent_dhcpv6_type_t;

typedef struct {
	char ifname[IFNAMSIZ];
	ah_kevent_dhcpv6_type_t type;
} ah_kevent_dhcpv6_mode_t;

/* station owner release state change */
typedef struct {
	int                  vap_ifindex;            /* vap interface index */
	int                  radio_ifindex;          /* radio interface index */
	uint8_t              sta_mac[MACADDR_LEN];   /* client mac: broadcast mac means all STAs of the VAP */
	uint8_t              release;                /* release or not */
} ah_kevent_sta_owner_rls_chg_t;

typedef struct {
	uint16_t  vlan;
	uint8_t   prefix_len;
	uint8_t   unused;
	struct in6_addr subnet_prefix;
} ah_vlan_disc_t;

typedef struct {
#define VLAN_SCAN_OP_SET     1   /* add */
#define VLAN_SCAN_OP_UNSET   0   /* delete */
	uint8_t   opcode;
	uint8_t   flags;
	uint16_t  num;
	ah_vlan_disc_t vlan_disc_entries[0];
} ah_vlan_scan_chg_event_t;

/***************************************************************
  following structure is for event implementation internal use
  pls, don't use those symbol if you are NOT coding inside the
  eventlib or keventlib
 ***************************************************************/
/*
 * Event message format
 */
typedef struct {
	uint16_t em_eid;
	uint16_t em_len;                  /* size of attached data(not including hdr space) */
	uint16_t em_seq;
#define AH_EVT_FLAG_FROM_KERNEL 0x0001  /* set if event generated from kernel, unset if generated from user */
	uint16_t em_flag;                 /* make the structure 2-byte alignment */
	uint8_t  em_data[0];
} ah_event_msg_t;

#define AH_KEVT_SUBSCRIBE   1
#define AH_KEVT_UNSUBSCRIBE 2
#define AH_ITK_IOCTL_LOG    3

#endif /*__AH_KEVENT_H__*/
