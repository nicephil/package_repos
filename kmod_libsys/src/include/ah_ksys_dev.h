#ifndef _AH_KSYS_DEV_H_
#define _AH_KSYS_DEV_H_

#include <linux/netdevice.h>
#include <linux/version.h>
#include "ah_types.h"
#include "ah_kglobal.h"


enum {

	AH_COUNTER_HTTP_PORT_IDX,
	AH_COUNTER_HTTPS_PORT_IDX,
	AH_COUNTER_TELNET_PORT_IDX,
	AH_COUNTER_SSH_PORT_IDX,
	AH_COUNTER_DNS_PORT_IDX,
	AH_COUNTER_FTP_PORT_IDX,
	AH_COUNTER_DHCP_PORT_IDX,
	AH_COUNTER_OTHER_PORT_IDX,
	AH_COUNTER_MAX_PORT_IDX,

};

/* values for ah_sys_dev_t->hash field */
enum {

	AH_ETH0_HASH_INDEX  = 0,
	AH_ETH1_HASH_INDEX,
#ifdef AH_SUPPORT_INTERFACE_EMU
	AH_ETH2_HASH_INDEX,
	AH_ETH3_HASH_INDEX,
	AH_ETH4_HASH_INDEX,
#endif
	AH_RED0_HASH_INDEX,
	AH_AGG0_HASH_INDEX,
	AH_WIFI0_HASH_INDEX,
	AH_WIFI1_HASH_INDEX,
	AH_WL0_HASH_INDEX,
	AH_WL1_HASH_INDEX,
#ifdef AH_SUPPORT_USBNET
	AH_USB0_HASH_INDEX,
#endif

};


struct ah_sys_dev_ {

	struct net_device *dev;  /* pointer to the parent net device */

	/* backhoul redundant interface */
	ah_sys_dev_t *parent_ah_dev;      /* pointer to parent ah device in case of ethx bound to red0 */

	spinlock_t mem_dev_list_lock;       /* lock to protect the member list */
	struct hlist_head mem_dev_list_head;
	int mem_dev_cnt;
	int active_mem_dev_cnt;

	struct hlist_node mem_dev_list;

	/* switch special: start */
	struct hlist_head mac_sess_list; /* link mac sess to logical device, by ah_fdb_mac_sess_list_lock */
	ushort      port_idx;
	ushort      up_attribute;
	ushort      lan_index; /* for VLAN interface */
	ushort      unused;
	/* switch special: end */

	uchar           state;
#define AH_SYS_DEV_ST_NULL      0    /* AH dev is not intialized yet */
#define AH_SYS_DEV_ST_READY     1    /* AH dev is ready to process traffic */
#define AH_SYS_DEV_ST_SET_STATE(ah_dev, val)  \
	(ah_dev)->state = val
#define AH_SYS_DEV_ST_IS_NULL(ah_dev)  \
	((ah_dev)->state == AH_SYS_DEV_ST_NULL)
#define AH_SYS_DEV_ST_IS_READY(ah_dev)  \
	((ah_dev)->state == AH_SYS_DEV_ST_READY)

	uchar            enable;
#define AH_ALG_SIP_ENABLE_FLG           0x1     /* 1: enabled, 0: disabled */
#define AH_ALG_IS_SIP_ENABLE(ah_dev) \
	((ah_dev)->enable & AH_ALG_SIP_ENABLE_FLG)
#define AH_ALG_SET_SIP_ENABLE(ah_dev) \
	(ah_dev)->enable |= AH_ALG_SIP_ENABLE_FLG
#define AH_ALG_CLR_SIP_ENABLE(ah_dev) \
	(ah_dev)->enable &= ~AH_ALG_SIP_ENABLE_FLG

	uchar            zone_id;
	uchar            hash;                      /* used when picking member interface for agg0 */

	uint             dev_type;
#define AH_SYS_DEV_TYPE_WIRELESS                    0x00000001  /* dev is wireless */
#define AH_SYS_DEV_TYPE_AP                          0x00000002  /* dev is a access point */
#define AH_SYS_DEV_TYPE_PORTAL                      0x00000004  /* dev is a portal */
#define AH_SYS_DEV_TYPE_BACKHAUL                    0x00000008  /* dev is a backhaul */
#define AH_SYS_DEV_TYPE_WMESH                       0x00000010  /* dev is in 4-addr mode */
#define AH_SYS_DEV_TYPE_MGT                         0x00000020  /* dev is a MGT */
#define AH_SYS_DEV_TYPE_PHYSICAL                    0x00000040  /* dev is physical device */
#define AH_SYS_DEV_TYPE_MUX                         0x00000080  /* dev is mux device in switch */
#define AH_SYS_DEV_TYPE_SUB_IF                      0x00000100  /* mgt0.x interface */
#define AH_SYS_DEV_TYPE_WAN                         0x00000200  /* WAN interface to go to internet */
#define AH_SYS_DEV_TYPE_BGD                         0x00000400  /* bgd0.x interface for bonjour gateway */
#define AH_SYS_DEV_TYPE_REDUNDANT                   0x00000800  /* set for reg0/agg0 */
#define AH_SYS_DEV_TYPE_TUNNEL                      0x00001000  /* tunnel device */
#define AH_SYS_DEV_TYPE_ETH_ACCESS                  0x00002000  /* dev is a ethernet access mode */
#define AH_SYS_DEV_TYPE_ETH_BRIDGE                  0x00004000  /* dev is a ethernet trunk mode */
#define AH_SYS_DEV_TYPE_VLAN                        0x00008000  /* dev is vlan device in switch */
#define AH_SYS_DEV_TYPE_SENSOR                      0x00020000  /* dev is radio sensor */

#define AH_SYD_DEV_TYPE_ETH_MODE_MASK  \
	(AH_SYS_DEV_TYPE_BACKHAUL | AH_SYS_DEV_TYPE_ETH_ACCESS  | \
	 AH_SYS_DEV_TYPE_ETH_BRIDGE | AH_SYS_DEV_TYPE_WAN)

#define AH_SYD_DEV_IS_LAND(ah_dev)  \
	(!((ah_dev)->dev_type & AH_SYS_DEV_TYPE_WIRELESS) && \
	 ((ah_dev)->dev_type & AH_SYD_DEV_TYPE_ETH_MODE_MASK))

#define AH_SYS_DEV_CLR_ETH_MODE(ah_dev)  \
	do { (ah_dev)->dev_type &= ~AH_SYD_DEV_TYPE_ETH_MODE_MASK; } while(0)

#define AH_SYS_DEV_IS_ETH_ACCESS(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_ETH_ACCESS)
#define AH_SYS_DEV_SET_ETH_ACCESS(ah_dev)  \
	do {  \
		(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_ETH_ACCESS; \
		set_ah_dev_zone_access (ah_dev); \
	} while(0)

#define AH_SYS_DEV_CLR_ETH_ACCESS(ah_dev)  \
	do { (ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_ETH_ACCESS; } while(0)


#define AH_SYS_DEV_IS_ETH_BRIDGE(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_ETH_BRIDGE)
#define AH_SYS_DEV_SET_ETH_BRIDGE(ah_dev)  \
	do { \
		(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_ETH_BRIDGE; \
		set_ah_dev_zone_access (ah_dev); \
	} while(0)

#define AH_SYS_DEV_CLR_ETH_BRIDGE(ah_dev)  \
	do { (ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_ETH_BRIDGE; } while(0)

#define AH_SYS_DEV_IS_WIRELESS(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_WIRELESS)
#define AH_SYS_DEV_SET_WIRELESS(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_WIRELESS

#define AH_SYS_DEV_IS_AP(ah_dev)        \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_AP)
	/* don't use this macro, use ah_sys_dev_set_ap() instead */
#define AH_SYS_DEV_SET_AP(ah_dev)      \
	do { \
		(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_AP; \
		set_ah_dev_zone_access(ah_dev); \
	} while (0)

	/* don't use this macro, use ah_sys_dev_clr_ap() instead */
#define AH_SYS_DEV_CLR_AP(ah_dev)      \
	(ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_AP;

#define AH_SYS_DEV_IS_SENSOR(ah_dev)        \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_SENSOR)
	/* don't use this macro, use ah_sys_dev_set_ap() instead */
#define AH_SYS_DEV_SET_SENSOR(ah_dev)      \
	do { \
		(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_SENSOR; \
		set_ah_dev_zone_access(ah_dev); \
	} while (0)

	/* don't use this macro, use ah_sys_dev_clr_ap() instead */
#define AH_SYS_DEV_CLR_SENSOR(ah_dev)      \
	(ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_SENSOR;

#define AH_SYS_DEV_IS_PORTAL(ah_dev)    \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_PORTAL)
	/* don't use this macro, use ah_sys_dev_set_portal() instead */
#define AH_SYS_DEV_SET_PORTAL(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_PORTAL;
	/* don't use this macro, use ah_sys_dev_clr_portal() instead */
#define AH_SYS_DEV_CLR_PORTAL(ah_dev)  \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_PORTAL);

#define AH_SYS_DEV_IS_BACKHAUL(ah_dev)    \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_BACKHAUL)
	/* don't use this macro, use ah_sys_dev_set_backhaul() instead */
#define AH_SYS_DEV_SET_BACKHAUL(ah_dev) \
	do { \
		(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_BACKHAUL; \
		set_ah_dev_zone_backhaul(ah_dev); \
	} while (0)

	/* don't use this macro, use ah_sys_dev_clr_backhaul() instead */
#define AH_SYS_DEV_CLR_BACKHAUL(ah_dev) \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_BACKHAUL);                   \

#define AH_SYS_DEV_IS_WMESH(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_WMESH)
#define AH_SYS_DEV_SET_WMESH(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_WMESH

#define AH_SYS_DEV_CLR_WMESH(ah_dev)  \
	(ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_WMESH

#define AH_SYS_DEV_IS_MGT(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_MGT)
#define AH_SYS_DEV_SET_MGT(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_MGT

#define AH_SYS_DEV_IS_MUX(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_MUX)
#define AH_SYS_DEV_SET_MUX(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_MUX

#define AH_SYS_DEV_IS_TUNNEL(ah_dev)    \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_TUNNEL)
#define AH_SYS_DEV_SET_TUNNEL(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_TUNNEL

#define AH_SYS_DEV_IS_PHYSICAL(ah_dev)  \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_PHYSICAL)
#define AH_SYS_DEV_SET_PHYSICAL(ah_dev)  \
	(ah_dev)->dev_type |= AH_SYS_DEV_TYPE_PHYSICAL

#define AH_SYS_DEV_IS_REDUNDANT(ah_dev) \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_REDUNDANT)
#define AH_SYS_DEV_SET_REDUNDANT(ah_dev) \
	((ah_dev)->dev_type |= AH_SYS_DEV_TYPE_REDUNDANT)
#define AH_SYS_DEV_CLR_REDUNDANT(ah_dev) \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_REDUNDANT)

#define AH_SYS_DEV_IS_SUB_INTERFACE(ah_dev) \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_SUB_IF)
#define AH_SYS_DEV_SET_SUB_INTERFACE(ah_dev) \
	((ah_dev)->dev_type |= AH_SYS_DEV_TYPE_SUB_IF)
#define AH_SYS_DEV_CLR_SUB_INTERFACE(ah_dev) \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_SUB_IF)

#define AH_SYS_DEV_IS_VLAN_INTERFACE(ah_dev) \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_VLAN)
#define AH_SYS_DEV_SET_VLAN_INTERFACE(ah_dev) \
	((ah_dev)->dev_type |= AH_SYS_DEV_TYPE_VLAN)
#define AH_SYS_DEV_CLR_VLAN_INTERFACE(ah_dev) \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_VLAN)

#define AH_SYS_DEV_IS_BGD_INTERFACE(ah_dev) \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_BGD)
#define AH_SYS_DEV_SET_BGD_INTERFACE(ah_dev) \
	((ah_dev)->dev_type |= AH_SYS_DEV_TYPE_BGD)
#define AH_SYS_DEV_CLR_BGD_INTERFACE(ah_dev) \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_BGD)

#define AH_SYS_DEV_IS_WAN(ah_dev) \
	((ah_dev)->dev_type & AH_SYS_DEV_TYPE_WAN)
#define AH_SYS_DEV_SET_WAN(ah_dev) \
	((ah_dev)->dev_type |= AH_SYS_DEV_TYPE_WAN)
#define AH_SYS_DEV_CLR_WAN(ah_dev) \
	((ah_dev)->dev_type &= ~AH_SYS_DEV_TYPE_WAN)

#define AH_SYS_DEV_IS_EGRESS_SPECIAL(ah_dev)    \
	((ah_dev)->dev_type &                       \
	 (AH_SYS_DEV_TYPE_MGT | AH_SYS_DEV_TYPE_SUB_IF |    \
	  AH_SYS_DEV_TYPE_BGD | AH_SYS_DEV_TYPE_VLAN |      \
	  AH_SYS_DEV_TYPE_WAN | AH_SYS_DEV_TYPE_MUX))

	uint           flag;

#define AH_SYS_DEV_INTER_STATION_TRAFFIC_DISABLE    0x00000001  /* set for access interface to disable intra ssid traffic */
#define AH_SYS_DEV_DEF_ROUTE_INSTALLED              0x00000002  /* interface on which default route is setup */
#define AH_SYS_DEV_CWP_POPUP_ENABLED                0x00000004  /* cwp pop-up window enabled */
#define AH_SYS_DEV_CWP_LOCAL_ENABLED                0x00000008  /* CWP local enabled */
#define AH_SYS_DEV_CWP_PT_ENABLED                   0x00000010  /* CWP pass through enabled */
#define AH_SYS_DEV_1X_ENABLED                       0x00000020  /* 8021x enabled on Ethernet interface */
#define AH_SYS_DEV_8021P_MARKING                    0x00000040  /* dev uses 802.1p marking */
#define AH_TCP_SYN_CHK_ENABLED                      0x00000080  /* tcp-syn-check enabled */
#define AH_SYS_DEV_MAC_LEARN_ENABLE                 0x00000100  /* dev MAC learning flag */
#define AH_SYS_DEV_ACCESS_CONSOLE                   0x00000200  /* access console device */
#define AH_SYS_DEV_TELNET_ENABLED                   0x00000400  /* telnet enabled */
#define AH_SYS_DEV_SSH_ENABLED                      0x00000800  /* ssh enabled */
#define AH_SYS_DEV_PING_ENABLED                     0x00001000  /* ping enabled */
#define AH_SYS_DEV_SNMP_ENABLED                     0x00002000  /* snmp enabled */
#define AH_SYS_DEV_MEMBER_INTERFACE                 0x00004000  /* set for ethx if it's a member interface */
#define AH_SYS_DEV_PRIMARY_MEMBER_INTERFACE         0x00008000  /* set for ethx if it's a primary member interface */
#define AH_SYS_DEV_HOST_BASED                       0x00010000  /* host-based enabled on Ethernet interface */
#define AH_SYS_DEV_ETH_BH_WITH_ACCESS               0x00020000  /* wired backhaul with access interfaces on the same link */
#define AH_SYS_DEV_CM_ENABLED                       0x00040000  /* client monitor 2.0 enabled */
#define AH_SYS_DEV_BLOCK_MCAST                      0x00080000

#define AH_SYS_DEV_CWP_MASK             (AH_SYS_DEV_CWP_LOCAL_ENABLED  | AH_SYS_DEV_CWP_PT_ENABLED)

#define AH_SYS_DEV_IS_8021P_MARKING(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_8021P_MARKING)
#define AH_SYS_DEV_SET_8021P_MARKING(ah_dev)  \
	(ah_dev)->flag |= AH_SYS_DEV_8021P_MARKING
#define AH_SYS_DEV_UNSET_8021P_MARKING(ah_dev)  \
	(ah_dev)->flag &= (~AH_SYS_DEV_8021P_MARKING)

#define AH_SYS_DEV_IS_MAC_LEARN(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_MAC_LEARN_ENABLE)
#define AH_SYS_DEV_SET_MAC_LEARN(ah_dev) \
	(ah_dev)->flag |= AH_SYS_DEV_MAC_LEARN_ENABLE
#define AH_SYS_DEV_CLR_MAC_LEARN(ah_dev) \
	(ah_dev)->flag &= ~AH_SYS_DEV_MAC_LEARN_ENABLE

#define AH_SYS_DEV_IS_CWP_ANY_ENABLED(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_CWP_MASK)
#define AH_SYS_DEV_CLR_CWP(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_CWP_MASK)

#define AH_SYS_DEV_IS_CWP_PT_ENABLED(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_CWP_PT_ENABLED)
#define AH_SYS_DEV_SET_CWP_PT_ENABLED(ah_dev) \
	do { \
		(ah_dev)->flag &= ~AH_SYS_DEV_CWP_MASK; \
		(ah_dev)->flag |= AH_SYS_DEV_CWP_PT_ENABLED; \
	} while (0)
#define AH_SYS_DEV_CLR_CWP_PT_DISABLED(ah_dev) \
	(ah_dev)->flag &= ~AH_SYS_DEV_CWP_PT_ENABLED

#define AH_SYS_DEV_IS_CWP_LOCAL_ENABLED(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_CWP_LOCAL_ENABLED)
#define AH_SYS_DEV_SET_CWP_LOCAL_ENABLED(ah_dev) \
	do { \
		(ah_dev)->flag &= ~AH_SYS_DEV_CWP_MASK; \
		(ah_dev)->flag |= AH_SYS_DEV_CWP_LOCAL_ENABLED; \
	} while (0)
#define AH_SYS_DEV_CLR_CWP_LOCAL_DISABLED(ah_dev) \
	(ah_dev)->flag &= AH_SYS_DEV_CWP_LOCAL_ENABLED

#define AH_SYS_DEV_IS_1X_ENABLED(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_1X_ENABLED)
#define AH_SYS_DEV_SET_1X_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_1X_ENABLED)
#define AH_SYS_DEV_CLR_1X_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_1X_ENABLED)

#define AH_SYS_DEV_IS_HOST_BASED(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_HOST_BASED)
#define AH_SYS_DEV_SET_HOST_BASED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_HOST_BASED)
#define AH_SYS_DEV_CLR_HOST_BASED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_HOST_BASED)

#define AH_SYS_DEV_IS_TELNET_ENABLED(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_TELNET_ENABLED)
#define AH_SYS_DEV_SET_TELNET_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_TELNET_ENABLED)
#define AH_SYS_DEV_CLR_TELNET_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_TELNET_ENABLED)

#define AH_SYS_DEV_IS_SSH_ENABLED(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_SSH_ENABLED)
#define AH_SYS_DEV_SET_SSH_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_SSH_ENABLED)
#define AH_SYS_DEV_CLR_SSH_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_SSH_ENABLED)

#define AH_SYS_DEV_IS_SNMP_ENABLED(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_SNMP_ENABLED)
#define AH_SYS_DEV_SET_SNMP_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_SNMP_ENABLED)
#define AH_SYS_DEV_CLR_SNMP_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_SNMP_ENABLED)

#define AH_SYS_DEV_IS_PING_ENABLED(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_PING_ENABLED)
#define AH_SYS_DEV_SET_PING_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_PING_ENABLED)
#define AH_SYS_DEV_CLR_PING_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_PING_ENABLED)

#define AH_SYS_DEV_IS_TCP_SYN_CHK_ENABLED(ah_dev) \
	((ah_dev)->flag & AH_TCP_SYN_CHK_ENABLED)
#define AH_SYS_DEV_SET_TCP_SYN_CHK_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_TCP_SYN_CHK_ENABLED)
#define AH_SYS_DEV_CLR_TCP_SYN_CHK_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_TCP_SYN_CHK_ENABLED)

#define AH_SYS_DEV_IS_MEMBER_INTERFACE(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_MEMBER_INTERFACE)
#define AH_SYS_DEV_SET_MEMBER_INTERFACE(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_MEMBER_INTERFACE)
#define AH_SYS_DEV_CLR_MEMBER_INTERFACE(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_MEMBER_INTERFACE)

#define AH_SYS_DEV_IS_PRIMARY_MEMBER_INTERFACE(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_PRIMARY_MEMBER_INTERFACE)
#define AH_SYS_DEV_SET_PRIMARY_MEMBER_INTERFACE(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_PRIMARY_MEMBER_INTERFACE)
#define AH_SYS_DEV_CLR_PRIMARY_MEMBER_INTERFACE(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_PRIMARY_MEMBER_INTERFACE)

#define AH_SYS_DEV_IS_INTER_STATION_TRAFFIC_DISABLE(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_INTER_STATION_TRAFFIC_DISABLE)
#define AH_SYS_DEV_SET_INTER_STATION_TRAFFIC_DISABLE(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_INTER_STATION_TRAFFIC_DISABLE)
#define AH_SYS_DEV_CLR_INTER_STATION_TRAFFIC_DISABLE(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_INTER_STATION_TRAFFIC_DISABLE)

#define AH_SYS_DEV_IS_DEF_ROUTE_INSTALLED(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_DEF_ROUTE_INSTALLED)
#define AH_SYS_DEV_SET_DEF_ROUTE_INSTALLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_DEF_ROUTE_INSTALLED)
#define AH_SYS_DEV_CLR_DEF_ROUTE_INSTALLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_DEF_ROUTE_INSTALLED)

#define AH_SYS_DEV_IS_CWP_POPUP_ENABLED(ah_dev)     \
	((ah_dev)->flag & AH_SYS_DEV_CWP_POPUP_ENABLED)
#define AH_SYS_DEV_SET_CWP_POPUP_ENABLED(ah_dev)     \
	((ah_dev)->flag |= AH_SYS_DEV_CWP_POPUP_ENABLED)
#define AH_SYS_DEV_CLR_CWP_POPUP_ENABLED(ah_dev)     \
	((ah_dev)->flag &= ~AH_SYS_DEV_CWP_POPUP_ENABLED)

#define AH_SYS_DEV_IS_ACCESS_CONSOLE(ah_dev)        \
	((ah_dev)->flag & AH_SYS_DEV_ACCESS_CONSOLE)
#define AH_SYS_DEV_SET_ACCESS_CONSOLE(ah_dev)        \
	((ah_dev)->flag |= AH_SYS_DEV_ACCESS_CONSOLE)
#define AH_SYS_DEV_CLR_ACCESS_CONSOLE(ah_dev)        \
	((ah_dev)->flag &= ~AH_SYS_DEV_ACCESS_CONSOLE)

#define AH_SYS_DEV_IS_ETH_BH_WITH_ACCESS(ah_dev)        \
	((ah_dev)->flag & AH_SYS_DEV_ETH_BH_WITH_ACCESS)
#define AH_SYS_DEV_SET_ETH_BH_WITH_ACCESS(ah_dev)        \
	((ah_dev)->flag |= AH_SYS_DEV_ETH_BH_WITH_ACCESS)
#define AH_SYS_DEV_CLR_ETH_BH_WITH_ACCESS(ah_dev)        \
	((ah_dev)->flag &= ~AH_SYS_DEV_ETH_BH_WITH_ACCESS)

#define AH_SYS_DEV_IS_CM_ENABLED(ah_dev)  \
	((ah_dev)->flag & AH_SYS_DEV_CM_ENABLED)
#define AH_SYS_DEV_SET_CM_ENABLED(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_CM_ENABLED)
#define AH_SYS_DEV_CLR_CM_ENABLED(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_CM_ENABLED)

#define AH_SYS_DEV_IS_BLOCK_MCAST(ah_dev) \
	((ah_dev)->flag & AH_SYS_DEV_BLOCK_MCAST)
#define AH_SYS_DEV_SET_BLOCK_MCAST(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_BLOCK_MCAST)
#define AH_SYS_DEV_CLR_BLOCK_MCAST(ah_dev) \
	((ah_dev)->flag &= ~AH_SYS_DEV_BLOCK_MCAST)

#define AH_SYS_DEV_ALL_PROTO_MASK     (AH_SYS_DEV_TELNET_ENABLED | \
									   AH_SYS_DEV_SSH_ENABLED    | \
									   AH_SYS_DEV_SNMP_ENABLED   | \
									   AH_SYS_DEV_PING_ENABLED)
#define AH_SYS_DEV_SET_ALL_PROTOOCOLS(ah_dev) \
	((ah_dev)->flag |= AH_SYS_DEV_ALL_PROTO_MASK)

	/* unique ID that's generated per SSID */
#define AH_SYS_DEV_SET_SSID(__ah_dev, __ssid)               ((__ah_dev)->ssid = (__ssid))
#define AH_SYS_DEV_GET_SSID(__ah_dev)                       ((__ah_dev)->ssid)
	int ssid;


	/* ageout time for mac learnt entries */
	int ah_mac_entry_ageout_time;

	struct hlist_node eth_dev_list;
	/* hash list by VLAN id */
	struct hlist_node lan_dev_list;
};

#define AH_GET_PARENT_DEVICE(ah_dev)                    ((ah_dev)->parent_ah_dev ? (ah_dev)->parent_ah_dev->dev : NULL)
#define AH_SET_PARENT_DEVICE(ah_dev, __parent_ah_dev)   ((ah_dev)->parent_ah_dev = (__parent_ah_dev))

#define AH_IS_DEVICE_RED0(ah_dev)                       ((ah_dev)->hash == AH_RED0_HASH_INDEX)
#define AH_IS_DEVICE_AGG0(ah_dev)                       ((ah_dev)->hash == AH_AGG0_HASH_INDEX)
#define AH_IS_DEVICE_WIFI0(ah_dev)                      ((ah_dev)->hash == AH_WIFI0_HASH_INDEX)
#define AH_IS_DEVICE_WIFI1(ah_dev)                      ((ah_dev)->hash == AH_WIFI1_HASH_INDEX)
#define AH_IS_DEVICE_ETH0(ah_dev)                       ((ah_dev)->hash == AH_ETH0_HASH_INDEX)
#define AH_IS_DEVICE_ETH1(ah_dev)                       ((ah_dev)->hash == AH_ETH1_HASH_INDEX)

/* the following events will be passed to each registered module */
#define AH_DEV_EVENT_INIT       1       /* AH dev is created */
#define AH_DEV_EVENT_DELETE     2       /* AH dev is deleted */
#define AH_DEV_EVENT_CHG_FLAG   3       /* AH dev flag has been changed */

#define dev2ahdev(dev) ((ah_sys_dev_t *)((dev)->ah_dev))
#define ahdev2dev(ah_dev) (ah_dev->dev)
#define get_ahdev_zone(ah_dev)  ((ah_dev)->zone_id)

#define set_ah_dev_zone_access(ah_dev)      ((ah_dev)->zone_id = AH_ZONE_ACCESS)
#define set_ah_dev_zone_backhaul(ah_dev)    ((ah_dev)->zone_id = AH_ZONE_BACKHAUL)

/*
 * priority in sk_buff is used for
 * 802.1p priority:         bit[2:0]
 * 802.11E user priority:   bit[2:0]
 * 802.11E access category: bit[4:3]
 * user profile id:         bit[15:8]
 */
#define AH_DEV_PRIORITY_MASK            0x0007
#define AH_DEV_PRIORITY_POS             0
#define AH_DEV_ACCESS_CATEGORY_MASK     0x0018
#define AH_DEV_ACCESS_CATEGORY_POS      3

#define AH_DEV_SET_PRIORITY(priority, val) \
	((priority & (~AH_DEV_PRIORITY_MASK)) \
	 | ((val << AH_DEV_PRIORITY_POS) & AH_DEV_PRIORITY_MASK))
#define AH_DEV_GET_PRIORITY(priority) \
	((priority & AH_DEV_PRIORITY_MASK) >> AH_DEV_PRIORITY_POS)

#define AH_DEV_SET_ACCESS_CATEGORY(priority, val) \
	(((priority) & (~AH_DEV_ACCESS_CATEGORY_MASK)) \
	 | (((val) << AH_DEV_ACCESS_CATEGORY_POS) & AH_DEV_ACCESS_CATEGORY_MASK))
#define AH_DEV_GET_ACCESS_CATEGORY(priority) \
	(((priority) & AH_DEV_ACCESS_CATEGORY_MASK) >> AH_DEV_ACCESS_CATEGORY_POS)

#define AH_SERVICE_DEFAULT_QOS          2   /* default to best effort */

#define AH_DEV_SET_QOS(_skb, _val) skb2ahb(_skb)->ab_qos = (_val)
#define AH_DEV_GET_QOS(_skb) skb2ahb(_skb)->ab_qos

#define AH_DEV_SET_USER_PROFILE_ID(_skb, _val) set_ahb_upid(_skb, _val)
#define AH_DEV_GET_USER_PROFILE_ID(_skb) skb2upid(_skb)


#endif /* _AH_KSYS_DEV_H_ */

