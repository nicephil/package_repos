#ifndef __AH_LIB_H__
#define __AH_LIB_H__

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>
#include <string.h>

#include "ah_overrides.h"
#include "ah_logging.h"
#include "ah_assert.h"
#include "ah_config.h" // for AH_LOG_INFO
#include "ah_trap.h" // for ah_trap_data_t
#include "ah_queue.h" // for TAILQ_ENTRY
#include "ah_ipv6_shared.h" // for ah_ipaddr46_t




/* hash table support */
typedef int (*hash_tbl_iterate_func_t) (void
										*data);    /* callback when iterating elements in hash table, return: (0) - keep looping, (-1) - stop looping */
typedef int (*hash_tbl_cmp_func_t) (void *key1, void *key2);    /* compare keys, key1<key2(-1)  key1=key2(0) key1>key2(1) */
typedef void (*hash_tbl_flush_func_t) (void *data);     /* callback for flush a hash table */


typedef struct hash_tbl_ele_ {
	void *he_key;           /* key */
	void *he_data;          /* attached data */
	TAILQ_ENTRY (hash_tbl_ele_) he_row_list;       /* for hash collision */
} hash_tbl_ele_t;

typedef struct hash_tbl_row_ {
	uint16_t hr_index;        /* index of the hash table */
	TAILQ_HEAD (htr_q1_, hash_tbl_ele_) hr_list;
} hash_tbl_row_t;

struct hash_tbl_ {
#define AH_HT_NAMT_LEN 32
	char     ht_name[AH_HT_NAMT_LEN]; /* name of the table */
	uint32_t ht_cnt;          /* total element in table */
	uint16_t ht_size;         /* how many rows in this table */
	uint16_t ht_keylen;       /* length of key */
	hash_tbl_cmp_func_t ht_cmp_func;        /* callback to compare keys */
	hash_tbl_row_t *ht_table;       /* real table memory */
};

typedef struct hash_tbl_ hash_tbl_t;

#define get_htbl_cnt(t) ((t)->ht_cnt)

static inline int hash_tbl_cmp_nlri (void *i1, void *i2)
{
	return memcmp(i1, i2, 5);
}

extern int hash_tbl_cmp_int (void *i1, void *i2);
extern int hash_tbl_cmp_mac (void *m1, void *m2);
extern int hash_tbl_cmp_uint32_t (void *i1, void *i2);
extern hash_tbl_t *hash_tbl_init (char *name, uint16_t bucket_size, uint16_t key_len, hash_tbl_cmp_func_t cmp_handler);
extern int hash_tbl_cmp_ipv46 (void *i1, void *i2);
extern void hash_tbl_free (hash_tbl_t *tbl);
extern void *hash_tbl_find (hash_tbl_t *tbl, void *key);
extern int hash_tbl_insert (hash_tbl_t *tbl, void *key, void *data);
extern void *hash_tbl_remove (hash_tbl_t *tbl, void *key);
extern int hash_tbl_iterate (hash_tbl_t *tbl, hash_tbl_iterate_func_t func);
extern void hash_tbl_flush (hash_tbl_t *t, hash_tbl_flush_func_t f);
//extern void ah_print_err(int rc, const char *msg);

/*
 * a trim down version of printf, support %i for ipv4 address, and %m for mac-addr
 * e.g:
 *   uint32_t ipv4;
 *   uint8_t  mac[6];
 *   ah_printf("IP=%i MAc=%m\n",ipv4,mac);
 *
 * need libah.a,
 * e.g: add following line in the Makefile
 *   DEPLIBS = -lah
 *
 */
extern int ah_vsprintf(char *buf, const char *fmt, va_list args);
extern int ah_vsnprintf(char *buf, size_t n, const char *fmt, va_list args);
extern int ah_sprintf(char *buf, const char *fmt, ...);
extern int ah_printf(const char *fmt, ...);
extern int ah_snprintf(char *buf, size_t size, const char *format, ...);
extern void ah_dumpbuf (void *buf, uint16_t len);
extern void ah_hexdump(const uchar *buf, uint len);
extern int ah_sys_up_sec (void); /* return the sys_up_sec, -1 on error */
extern unsigned int ah_sys_uptime(void);
extern uint8_t ipv4_netmask2len (uint32_t mask); /* <mask> is in network byte order */
extern uint32_t name2uint32_hash (char *name); /* <name> is '\0' ended string, no mas limitation */
extern int ip2mac (uint32_t ip, uint8_t *mac, char *buf, int buf_len);
extern int ah_arpping(uint32_t yiaddr, uint32_t ip, uchar *smac, uchar *dmac, char *interface);
extern uint16_t ah_crc16 (uint8_t *bp, uint16_t len);
extern uint32_t ah_get_hive_hash (char *hivename, char *hivepasswd);

/*
 * pls don't use this 2 API except in ah_event_thread.c
 */
extern int ah_ptimer_init (void);
extern void ah_ptimer_poll (void);

extern struct hostent *ah_gethostbyname(const char *name);

/* resolve IPv6 address from domain name */
int ah_gethostbyname_ipv6(const char *name, struct sockaddr_in6 *addrs, int *addrs_cnt);
/* without scope ID if link-local address */
int ah_gethostbyname_ipv6_only_addr(const char *name, struct in6_addr *addrs, int *addrs_cnt);


int ah_gethostbyname_ipv46(const char *name, ah_ipaddr46_t *addrs, int *addrs_cnt);

int ah_gethostbyname_ipv4_and_ipv6(const char *name,
								   struct in_addr *addrs_ipv4, int *addrs_ipv4_cnt,
								   struct in6_addr *addrs_ipv6, int *addrs_ipv6_cnt);


int ah_get_system_uptime(uint *psec, uint *pmsec);
struct hostent *ah_gethostentbyname(const char *name);

extern ssize_t ah_write(int fd, const void *buf, size_t count);
extern ssize_t ah_read(int fd, void *buf, size_t count);
extern int ah_open(const char *pathname, int flags);
extern int ah_open2(const char *pathname, int flags, mode_t mode);
extern int ah_close(int fd);
extern int ah_hardcopy_file(const char* dst, const char* src);
extern void ah_cp_directory(char *dst_path, char *src_path);
extern int ah_sleep(uint32_t sec);
extern int ah_usleep(uint32_t sec, uint32_t usec);
extern int ah_non_interrupt_sleep(uint32_t sec);
extern int ah_background_open_tty(const char *ttyname);
extern int ah_pstack(void);

extern int read_interface(const char *if_name,
						  int *ifindex,
						  uint *ip_addr,
						  uint *netmask,
						  uchar *mac_addr);
int ah_ifname_user_to_internal(char *int_ifname,
							   char *user_ifname);
int ah_ifname_internal_to_user(char *user_ifname,
							   char *int_ifname);
boolean ah_is_ethernet_ifname(char *int_ifname);
#ifdef AH_VPN_ENABLE
boolean ah_is_l2tunnel_ifname(char *int_ifname);
#endif
boolean ah_is_eth_ifname(char *int_ifname);
boolean ah_is_usbnet_ifname(char *int_ifname);
#ifdef AH_SUPPORT_USBNET
boolean ah_is_usb_ifname(const char *int_ifname);
#endif
#ifdef AH_SUPPORT_MULTIWAN
boolean ah_is_wlan_ifname(char *int_ifname);
boolean ah_is_usbnet_ppp_ifname(char *int_ifname);
#endif
boolean ah_is_p_ifname(char *int_ifname);
extern int get_system_start_interval(uint *start_time);
extern int ah_process_exist(const char *pname, int *retpid);
extern int ah_file_exist(const char *file);
int ah_sched_setscheduler(pid_t pid, int policy, int priority);
boolean ah_filename_valid(char *filename);
boolean ah_ifname_exist(const char *ifname);
boolean ah_ifindex_exist(int ifindex);
int ah_check_yesno(const char *printinfo);
int ah_file_size_is_nonzero(const char *file);
int ah_remove_path(const char *path);
int ah_mkdirs(char *dirs, int mode);

typedef enum {
	IP_VALID = 0,
	IP_MAYBE,
	IP_WRONG
} ah_ipaddr_valid_t;
ah_ipaddr_valid_t ah_ipaddr_check(const char *ip_str);
char *ah_strcasestr(char *haystack, char *needle);

void ah_hex2bin(const char *hex, uint8_t *bin, int hex_len);
void ah_bin2hex(const uint8_t *bin, char *hex, int bin_len);
boolean ah_is_str_hex(char *str);
void ah_str_to_hex(char *str, unsigned char *hex, int len);

/**
 * @brief print error
 * @param rc error code to print
 * @param msg extra msg to print with the error
 */
static inline void ah_print_err(int rc, const char *msg)
{
	if (msg != NULL) {
		ah_err_old("Error %d returned (%s)", rc , msg);
	} else {
		ah_err_old("Error %d returned", rc);
	}
}

/* MACRO to check return code - DEPRECATED */
#define AH_CHECK_RC(rc) \
	{ \
		if (rc != 0) \
		{ \
			ah_err_old("AH_CHECK_RC failed, rc = %d", rc); \
			return rc; \
		} \
	}

/**
 * @brief print error if rc != 0
 * @param rc error code to check for 0 or not
 * @param msg extra msg to print with the error
 * @return true if an error occurred, false if not
 */
static inline boolean ah_check_err_deprecated(int rc, const char *msg)
{
	if (rc != 0) {
		ah_print_err(rc, msg);
		return TRUE;
	}
	return FALSE;
}

/*
 * level is one of ah_log_level_t
 */
#define ah_openlog(name) \
	openlog(name, LOG_PID, LOG_USER)
#define ah_setlogmask(mask) \
	setlogmask(mask)

#define MACRO_NOT_SUPPORT_1X_ON_ETHERNET


/* end */

int16_t ah_vlan_search_by_idx(unsigned char *vlan_bm, int idx);

#endif /*__AH_LIB_H__*/
