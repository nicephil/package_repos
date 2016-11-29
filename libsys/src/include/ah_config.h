#ifndef _AH_CONFIG_H_
#define _AH_CONFIG_H_



#include <ah_types.h>
#include <ah_netconst.h>


#define AH_ERR ah_err_old("***func: %s\n", __FUNCTION__)


/* define thread priorities */
#define AH_PRIORITY_WATCHDOG    99 /* Should only used by feed dog thread */
#define AH_PRIORITY_SUPERVISION 98
#define AH_PRIORITY_CTRL        10
#define AH_PRIORITY_MGT         5
#define AH_PRIORITY_NORMAL      0

#define AH_SPEC_LOG_HEAD   "::SPECIAL_LOG::T"
#define AH_SPEC_LOG_CLEAR_LOG           1
#define AH_SPEC_LOG_FLASH_LOG           2


/* some common const*/
#define AH_MAX_NAME_LEN 32

/* For mac bypass*/
#define AH_MAX_BIND_MAC_OBJECT_NUM      8


/* Some constants for 802.11 configuration */
#define AH_MAX_SSID                     64      /* Max number of SSID */
#define AH_MAX_SO                       (AH_MAX_SSID+AH_MAX_ETH+1)   /* Max number of security object: ssid num + eth num + default so*/
#ifdef AH_SUPPORT_WPA_SUPP_WIRED
#define AH_MAX_SUPP_OBJ                 4       /* Max number of supplicant object*/
#endif
#define AH_MAX_HIVEID                   4       /* Max number of HIVEID */
#ifdef AH_SUPPORT_MACSEC
#define AH_MAX_MACSEC_CA                64      /*Max number of macsec connectivity association*/
#endif
#ifndef AH_MINI
#define AH_MAX_ASSOCS                   100     /* radio max allowed stations */
#define AH_MAX_ACCESS_VIF_PER_RADIO     16      /* Max number virtual access interface per radio */
#else
#define AH_MAX_ASSOCS                   32     /* radio max allowed stations for BR100*/
#define AH_MAX_ACCESS_VIF_PER_RADIO     8      /* Max number virtual access interface per radio for BR100*/
#endif
#define AH_MAX_BACKHAUL_VIF_PER_RAIOD   1       /* Max number of virtual backhaul interfaces per radio */
#define AH_MAX_RADIO_VIF \
	(AH_MAX_ACCESS_VIF_PER_RADIO * AH_MAX_RADIO)
/* Max number of virtual interfaces */
#define AH_MAX_MGT                      (1)     /* Max number of mgt interfaces */

#ifdef AH_CVG_AS_AP
#define AH_MAX_MGT_VIF                  (1024)    /* Max number of virtual mgt interfaces */
#else
#define AH_MAX_MGT_VIF          (16)
#endif

#ifdef AH_MULTI_VPNS_BUILD
#define AH_MAX_TUNNEL_IF                (256)     /* Max number of tunnel interfaces */
#else
#define AH_MAX_TUNNEL_IF                (2)     /* Max number of tunnel interfaces */
#endif

#ifdef AH_BONJOUR_GATEWAY_SUPPORT
#define AH_MAX_BGD_VIF                  (16)    /* Max number of Bonjour Gateway interfaces */
#else
#define AH_MAX_BGD_VIF                  (0)     /* Max number of Bonjour Gateway interfaces */
#endif

#define AH_MAX_IF \
	(AH_MAX_RADIO_VIF + AH_MAX_RADIO \
	 + AH_MAX_AGG + AH_MAX_RED \
	 + AH_MAX_MGT + AH_MAX_MGT_VIF \
	 + AH_MAX_ETH + AH_MAX_TUNNEL_IF + AH_MAX_BGD_VIF)   /* Max number of interfaces */

#define AH_ETH_LIKE_MAX     (AH_MAX_AGG + AH_MAX_RED + AH_MAX_ETH)


#define AH_MAX_HIVEID_LEN               32      /* Max string length for hive id */
#define AH_MAX_HIVEPASSWD_LEN           64      /* Max string length for hive id */
#define AH_MAX_SSID_LEN                 32      /* Max string length for ssid */
#ifdef AH_SUPPORT_MACSEC
#define AH_MAX_MACSEC_CA_LEN            32      /* Max string length for macsec ca*/
#endif

#define AH_MAX_HOSTNAME_LEN     256 /* Max string length for hostname */

/* defines for user profile */
#define AH_PROFILE_ID_HOST_PKT          0x1000 /* special user profile id for host pkt */
#define AH_PROFILE_ID_INVALID           0      /* user profile id not found */
#define AH_PROFILE_ID_DEFAULT           0      /* default user profile id */

/* defines for device types */
#define AH_DEV_TYPE_WIRELESS            0x01    /* wireless or wire */
#define AH_DEV_TYPE_BACKHAUL            0x02    /* backhaul or access */
#define AH_DEV_TYPE_BRIDGE              0x04
#define AH_DEV_TYPE_VIRTUAL             0x08    /* virtual or physical */
#define AH_DEV_TYPE_MGT                 0x10    /* management */
#define AH_DEV_TYPE_PORTAL              0x20    /* portal */
#define AH_DEV_TYPE_REDUNDANT           0x40    /* red0 and agg0 */
#define AH_DEV_TYPE_TUNNEL              0x80    /* vpn tunnel interface */
#define AH_DEV_TYPE_WAN                 0x100   /* wan interface */
#define AH_DEV_TYPE_HIDDEN              0x200   /* physical interface */

/**************************************************************************************
max username length, used by auth, dcd, driver.
The macro "AH_MAX_USERNAME_LEN" contains 128 valid characters.
***************************************************************************************/
#define AH_MAX_USERNAME_LEN             (128)
#define AH_MAX_CLIENT_ID_LEN    AH_MAX_USERNAME_LEN
#define AH_MAX_USERNAME_LEN_ORIGINAL    (32)  /* max username length, defined in the old version. */

/******************************************************************
max extensive username length, used by auth, dcd, driver.
The macro "AH_MAX_EXT_USERNAME_LEN" contains 2 string terminators.
*******************************************************************/
#define AH_MAX_EXT_USERNAME_LEN (AH_MAX_USERNAME_LEN - AH_MAX_USERNAME_LEN_ORIGINAL + 2)

/* define default wifi country code */
#define AH_CTRY_DEFAULT 840
#define AH_CTRY_CANADA  124

#ifdef __KERNEL__
#define AH_BITS_IN_INTEGER            (sizeof(int) * BITS_PER_BYTE)
#else
#define AH_BITS_IN_INTEGER            (sizeof(int) * CHAR_BITS)
#endif
#define AH_BITS_IN_INTEGER_MASK       (AH_BITS_IN_INTEGER - 1)

#define AH_MAX_TUNNELS 128

#endif /* _AH_CONFIG_H_ */

