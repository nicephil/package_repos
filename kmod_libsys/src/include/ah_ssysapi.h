/**
 * @file ah_ssysapi.h
 * @brief Header file containing user/kernel shared definition/API
 *
 */
#ifndef _AH_SSYSAPI_H
#define _AH_SSYSAPI_H

/************************************************************/
/* User/Kernel shared definition/API                        */
/************************************************************/

#include "ah_types.h"
#include "ah_log_types.h"
#include "ah_net.h"

/* Kernel module list known by system top module */
typedef enum {
	AH_SYS_KMOD_SYSTOP = 0,
	AH_SYS_KMOD_MPI,
	AH_SYS_KMOD_FE,
	AH_SYS_KMOD_FE_ARP,
	AH_SYS_KMOD_QOS,
	AH_SYS_KMOD_MESH,
	AH_SYS_KMOD_ROUTING,
	AH_SYS_KMOD_AHTEST,
	AH_SYS_KMOD_MAC,
	AH_SYS_KMOD_WIFI,
	AH_SYS_KMOD_BOARD,
	AH_SYS_KMOD_AUTH,
	AH_SYS_KMOD_SCREEN,
	AH_SYS_KMOD_ALG,
	AH_SYS_KMOD_ETH,
	AH_SYS_KMOD_SEC,
	AH_SYS_KMOD_VPN,
	AH_SYS_KMOD_8021X,
	AH_SYS_KMOD_KERNEL,
	AH_SYS_KMOD_USBNET,
	AH_SYS_KMOD_CM,
	AH_SYS_KMOD_NONE,
	AH_MAX_SYS_KMODS
} ah_sys_kmod_t;

enum {
	IEEE80211_DEAUTH_REASON_NONE = 0,
	IEEE80211_DEAUTH_REASON_IDLE_OUT = 4,
	IEEE80211_DEAUTH_REASON_MAX,
};

/* Please add a name for each module defined in "ah_sys_kmod_t" */
/* Used by sysctl to set debug/log options for the module */
#define AH_SYS_KMOD_NAME_MAX_LEN    16
#define AH_SYS_KMOD_SYSTOP_NAME     "systop"
#define AH_SYS_KMOD_MPI_NAME        "mpi"
#define AH_SYS_KMOD_FE_NAME     "fe"
#define AH_SYS_KMOD_FE_ARP_NAME     "fe_arp"
#define AH_SYS_KMOD_QOS_NAME        "qos"
#define AH_SYS_KMOD_MESH_NAME       "mesh"
#define AH_SYS_KMOD_ROUTING_NAME    "routing"
#define AH_SYS_KMOD_AHTEST_NAME     "ahtest"
#define AH_SYS_KMOD_MAC_NAME            "mac"
#define AH_SYS_KMOD_WIFI_NAME           "wifi"
#define AH_SYS_KMOD_BOARD_NAME          "board"
#define AH_SYS_KMOD_AUTH_NAME           "auth"
#define AH_SYS_KMOD_SCREEN_NAME         "screen"
#define AH_SYS_KMOD_ALG_NAME            "alg"
#define AH_SYS_KMOD_ETH_NAME            "eth"
#define AH_SYS_KMOD_SEC_NAME            "security"
#define AH_SYS_KMOD_VPN_NAME            "vpn"
#define AH_SYS_KMOD_8021X_NAME          "dot1x"
#define AH_SYS_KMOD_KERNEL_NAME         "kernel"
#define AH_SYS_KMOD_USBNET_NAME         "usbnet"
#define AH_SYS_KMOD_CM_NAME             "cm"
#define AH_SYS_KMOD_NONE_NAME              ""


#define AH_LOGLEVEL_SYSCTL_NAME(kmod_name) \
	"debug.ahsys."kmod_name".loglevel"
#define AH_LOGLEVEL_SYSCTL_FILE(kmod_name) \
	"/proc/sys/debug/ahsys/"kmod_name"/loglevel"
#define AH_LOGENABLE_SYSCTL_NAME(kmod_name) \
	"debug.ahsys."kmod_name".logenable"
#define AH_LOGENABLE_SYSCTL_FILE(kmod_name) \
	"/proc/sys/debug/ahsys/"kmod_name"/logenable"
#define AH_DBGENABLE_SYSCTL_NAME(kmod_name) \
	"debug.ahsys."kmod_name".dbgenable"
#define AH_DBGENABLE_SYSCTL_FILE(kmod_name) \
	"/proc/sys/debug/ahsys/"kmod_name"/dbgenable"
#define AH_DBGCTL_SYSCTL_NAME(kmod_name,dbgctl_name) \
	"debug.ahsys."kmod_name"."dbtctl_name
#define AH_DBGCTL_SYSCTL_FILE(kmod_name, dbgctl_name) \
	"/proc/sys/debug/ahsys/"kmod_name"/"dbgctl_name

typedef enum {
	EVT_INVALID_TYPE,
	EVT_NODE_REFCNT_INC,
	EVT_NODE_REFCNT_DEC,
	EVT_TYPE_MAX
} ah_evt_type_t;

typedef struct evt {
	uint32_t        evt_jiffies;
	ah_evt_type_t   evt_type;
	unsigned long   evt_u64[7];
} ah_evt_t; /* 64 bytes per event */

/************************************************************/
/* Kernel only definition/API                               */
/************************************************************/
#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/percpu.h>
#include "ah_types.h"
#include "ah_trap.h"


#if defined(AH_SUPPORT_KGDB)
void ah_log_evt(ah_evt_type_t evtype, u64 u640, u64 u641, u64 u642, u64 u643,
				u64 u644, u64 u645, u64 u646);
int register_km_action(char *acname, void (*accb)(char *));
#else
#define ah_log_evt(evtype, u640, u641, u642, u643, u644, u645, u646)
#define register_km_action(acname, accb)
#endif
/*
 * handy macro <d> is a struct net_devuce ptr.
 */
#define dev2name(d)  ( (d)? (d)->name: "N/A" )

/* Control structure for sysctl array */
typedef struct {
	char name[AH_SYS_KMOD_NAME_MAX_LEN + 1];
	struct ctl_table_header *sysctl_header;
	struct ctl_table *sysctls;
	int loglevel;
	int logenable;
	int dbgenable;

} ah_kmod_ctl_t;

int ah_vsprintk(char *buf, const char *fmt, va_list args);
int ah_vsnprintk(char *buf, size_t n, const char *fmt, va_list args);
int ah_sprintk(char *buf, const char *fmt, ...);
int ah_printk(const char *fmt, ...);
void ah_hexdumpk(const uchar *buf, uint size);
/* Use ah_dbgk */
extern int __ah_dbgk(const char *file, int line, ah_sys_kmod_t mod, const char *type, int doit, const char *fmt, ...);
extern int __ah_dbgk_varg(const char *file, int line, ah_sys_kmod_t mod, const char *fmt, va_list args);
extern uint16_t ah_crc16k(uint8_t *bp, uint16_t len);
extern uint32_t ah_get_hive_hashk(char *hivename, char *hivepasswd);

extern ah_kmod_ctl_t ah_kmod_ctl[AH_MAX_SYS_KMODS];
extern DEFINE_PER_CPU(uint, g_total_pkt_cnt);

#define is_kmod_dbg_on(kmod,doit)   (ah_kmod_ctl[(kmod)].dbgenable & (doit))

/*
 * Debug utility for kernel programming
 */
#ifdef AH_DEBUG_FEATURE
#ifdef AH_BUILD_RELEASE
/* Release version */
#define ah_dbgk(mod, doit, fmt, arg...) do {\
		if (is_kmod_dbg_on(mod,doit)) { \
			__ah_dbgk(" ", __LINE__, mod, #doit, doit, fmt, ##arg); \
		} \
	} while(0)
#else
/* Development version */
#define ah_dbgk(mod, doit, fmt, arg...) do {\
		if (is_kmod_dbg_on(mod,doit)) { \
			__ah_dbgk(__FILE__, __LINE__, mod, #doit, doit, fmt, ##arg); \
		} \
	} while(0)
#endif
#else
#define ah_dbgk(mod, doit, fmt, arg...)
#endif

/* Log utility for kernel programming */
int ah_logk(ah_sys_kmod_t mod, ah_log_level_t level, const char *fmt, ...);
int ah_logk_flash(ah_sys_kmod_t mod, ah_log_level_t level, const char *fmt, ...);

/* Dump hex buffer */
int ah_hexk(ah_sys_kmod_t mod, int doit,  const void *buf, uint size);

/* Register debug control variables through sysctl */
/* Return:  NULL if failed, valid handle if succeeded */
void *ah_register_debug_sysctl(ah_sys_kmod_t mod, char *dbgctl_name, int *dbgctl_p);

/* Unregister debug control variables through sysctl */
/* Must pass the sysctl handle returned by ah_register_debug_sysctl */
void ah_unregister_debug_sysctl(void *sysctl_handle);

int ah_sys_get_product_name(char *str, int size);
int ah_sys_is_product_name(const char *name);
#ifdef CONFIG_BAY
int ah_sys_is_product_ap245x(void);
#endif
int ah_sys_get_next_default_macaddr(int *indexp, uint8_t *mac_addr);
int ah_sys_led_pic_available(void);
int ah_sys_is_product_outdoor(void);
int ah_sys_is_product_single_radio(void);
int ah_sys_tpm_3204_be_used(void);
boolean ah_is_self_mac(ah_mac_t *mac);

/* kernel client info table query API(exposed to wifi-driver */
boolean is_client_5G_capable(ah_mac_t *mac);
boolean is_client_releasable(ah_mac_t *mac);
/* Kernel hang debug APIs */
void ah_kernel_hang_update_pkt(void);


#endif /* __KERNEL__ */

#endif /* _AH_KSSYSAPI_H */
