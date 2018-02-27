#ifndef __WLAN_SERVICES_H_
#define __WLAN_SERVICES_H_
#include <netinet/in.h>


enum PORT_EAABLE
{
    ENABLE = 1,
    DISABLE = 0,    
};



enum RADIO_DEVICE_MODE 
{
    RADIO_DEVICE_MODE_NORMAL = 0,
    RADIO_DEVICE_MODE_MONITOR
};


#define MAX_RADIO_COUNT  2
#define MAX_MBSS_COUNT  8    
#define ST_MAX_COUNT 16   

#define WLAN_SSID_MAX_LENGTH    33
#define WLAN_KEY_MAX_LENGTH     65
#define ACL_NAME_MAX_LENGTH     16
#define PORTAL_SCHEME_NAME_MAX_LENGTH     64
#define TIMER_NAME_MAX_LENGTH     32
#define RADIUS_SCHEME_NAME_MAX_LENGTH   17
#define PPSK_KEYS_URL_MAX_LENGTH 256

enum WLAN_STA_CIPHER {
    WLAN_STA_CIPHER_WEP = 0, 
    WLAN_STA_CIPHER_TKIP = 1, 
    WLAN_STA_CIPHER_AES_OCB = 2, 
    WLAN_STA_CIPHER_AES_CCM = 3, 
    WLAN_STA_CIPHER_WAPI = 4, 
    WLAN_STA_CIPHER_CKIP = 5, 

    WLAN_STA_CIPHER_NONE = 6, 

    WLAN_STA_CIPHER_MAX
};

struct wlan_radio_config {
    int beacon_interval;    //in ms
    int max_power;
    int dtim;               // beacon slot
    int fragment_threshold;
    int rts_threshold;
    int short_gi;
    unsigned char atf;
    unsigned char amsdu;
    unsigned char ampdu;
    unsigned char mode;
    unsigned char device_mode;	//normal or monitor
    unsigned char channel;
    unsigned char distance;             // in kilometer
    unsigned char bandwidth;            // 20M or 40M Hz
    unsigned char preamble;             // refer to enum WLAN_PREAMBLE
    unsigned char dot11nonly;
    unsigned char dot11aconly;
    unsigned char protection_mode;      // refer to enum WLAN_PROTECTION_MODE
    unsigned char   rssi_access_enable;
    unsigned char   bcast_ratelimit_enable;
    unsigned int    bcast_ratelimit_cir;
    unsigned int    bcast_ratelimit_cbs;
    int             rssi_access_threshold;
    unsigned int    debug_switch;    /* for wlan driver radio debugging */
    unsigned int    basic_rateset;      /* add for rateset */
    unsigned int    supported_rateset;
    unsigned int    disabled_rateset;
    unsigned int    basic_mcs;
    unsigned int    supported_mcs;/* end */
    int beacon_rate;
    int manage_rate;

    char country[4];        // used 2 or 3 chars, aligned to 4 bytes
    char scan_template[33];
#if OK_PATCH
    int client_max;
#endif
};

typedef struct radio_info
{
    struct wlan_radio_config radio;
    int id;
    int enable;
    int count;
    int service[MAX_MBSS_COUNT];
}radio_info;

typedef struct wlan_radio_info
{
    int num;
    radio_info radioinfo[MAX_RADIO_COUNT];
}wlan_radio_info;

struct wlan_wep40_key {
    char    key_type;   // refer enum WLAN_BSS_KEY_TYPE
    char    key_crypt;  // refer enum WLAN_BSS_KEY_CRYPT
    char    key_len;    // actually key length, no include '\0'
    char    key[22];    // longest format: WEP108
};

struct wlan_wep108_key {
    char    key_type;   // refer enum WLAN_BSS_KEY_TYPE
    char    key_crypt;  // refer enum WLAN_BSS_KEY_CRYPT
    char    key_len;    // actually key length, no include '\0'
    char    key[54];    // longest format: WEP108
};

struct wpa_key {
    char    key_type;   // refer enum WLAN_BSS_KEY_TYPE
    char    key_crypt;  // refer enum WLAN_BSS_KEY_CRYPT
    char    key_len;    // actually key length, no include '\0'
    char    key[130];    // longest format: hex64
};

enum WLAN_OPMODE{
    WLAN_OPMODE_AP,
    WLAN_OPMODE_STA,
    
    WLAN_OPMODE_MAX
};

struct wlan_service_template {
    int     id;
    int     client_max;
    int     ref_count;
    unsigned int    ptk_lifetime;
    unsigned int    gtk_lifetime;

    char    opmode; //refer WLAN_OPMODE
    char    wds;
    char    used;
    char    service_enabled;    // service template enable state, generate by enabled & ssid_ctrl .....
    char    enabled;        // service template enabled or not
    char    ptk_enabled;
    char    gtk_enabled;
    char beacon_ssid_hide;
    char    cipher;     // refer enum WLAN_CIPHER
    char    auth;       // refer enum WLAN_AUTH
	char	m2u_enabled;	//for m2u
	
    /* Begin: add for rate limit */
    unsigned int dynamic_uplink_rate_limit;
    unsigned int dynamic_downlink_rate_limit;
    unsigned int static_uplink_rate_limit;
    unsigned int static_downlink_rate_limit;    
    /* End */
    char ssid[WLAN_SSID_MAX_LENGTH];
    char radius_scheme[RADIUS_SCHEME_NAME_MAX_LENGTH + 1];
	char portal_scheme[PORTAL_SCHEME_NAME_MAX_LENGTH + 1];
	char acl[ACL_NAME_MAX_LENGTH + 1];
	char timer_scheme[TIMER_NAME_MAX_LENGTH + 1];
    char bssid[6]; //specify ap in sta-mode

    char    wds_autopath;    //autopath
    char    wds_acl;     //use wds specified acl
    
    char    manage_template;     //indicate manage_template
    char    mgt_enable;    //manage feature 1:up ,0:down
    unsigned int manage_ip; //manage feature
    unsigned int manage_mask; //manage feature 0~32
    
    char    pmf;    //0:disabled, 1:optional, 2:mandatory
	char    ssid_ctrl;       // ssid control state 1: up, -1:down
    char    wep_key_slot;   // only used when @cipher = WLAN_CIPHER_WEP
    struct  wlan_wep40_key      wep40_key[4];
    struct  wlan_wep108_key     wep108_key[4];
    struct  wpa_key             wpa_key;

#if OK_PATCH
    int bandwidth_priority;
    int client_isolation;
    int type;
    char ppsk_keys_url[PPSK_KEYS_URL_MAX_LENGTH];
#endif
};

typedef struct service_template
{
    int num;
    struct wlan_service_template wlan_st_info[ST_MAX_COUNT];
}service_template;



enum EN_DOT11_RADIO_MODE {
    DOT11_RADIO_MODE_A = 1 << 0,
    DOT11_RADIO_MODE_B = 1 << 1,
    DOT11_RADIO_MODE_G = 1 << 2,
    DOT11_RADIO_MODE_N = 1 << 3,
    DOT11_RADIO_MODE_AC = 1 << 4,
};


enum WLAN_PREAMBLE {
    WLAN_PREAMBLE_SHORT = 0, 
    WLAN_PREAMBLE_LONG, 
};

enum WLAN_PROTECTION_MODE {
    WLAN_PROTECTION_NONE = 0, 
    WLAN_PROTECTION_CTS_TO_SELF, 
    WLAN_PROTECTION_RTS_CTS, 

    WLAN_PROTECTION_MAX
};

enum WLAN_CIPHER {
    WLAN_CIPHER_NONE = 0, 
    WLAN_CIPHER_WEP40,
    WLAN_CIPHER_WEP108,
    WLAN_CIPHER_TKIP,
    WLAN_CIPHER_CCMP,
    WLAN_CIPHER_CCMP_TKIP,

    WLAN_CIPHER_MAX,
};

enum WLAN_AUTH {
    WLAN_AUTH_OPEN = 0,
    WLAN_AUTH_SHARED, 
    WLAN_AUTH_WPA_PSK, 
    WLAN_AUTH_WPA2_PSK, 
    WLAN_AUTH_WPA2_RADIUS,
    WLAN_AUTH_WPA_MIXED_PSK,
    WLAN_AUTH_PPSK,

    WLAN_AUTH_MAX
};

enum WLAN_KEY_CRYPT {
    WLAN_KEY_CRYPT_PLAIN = 0,
    WLAN_KEY_CRYPT_CIPHER,

    WLAN_KEY_CRYPT_MAX,
};

enum WLAN_KEY_TYPE {
    WLAN_KEY_TYPE_ASCII = 0,
    WLAN_KEY_TYPE_HEX,

    WLAN_KEY_TYPE_MAX
};

enum WLAN_BSS_TYPE {
    WLAN_BSS_TYPE_VAP = 0,
    WLAN_BSS_TYPE_STA,
    WLAN_BSS_TYPE_MAX
};



struct wlan_sta_status {
    unsigned int    caps;       // refer to enum WLAN_STA_CAPS 
    unsigned int        node_flags;
    unsigned short int  aid;    // associate id
    unsigned short int  channel;// useful when STA, WDS mode
    unsigned short int  txpower;
    unsigned short int  tx_rate;   // in Mbps
    unsigned short int  rx_rate;   // in Mbps
    unsigned short int  rssi;
    unsigned short int  idle;   // in second
    unsigned short int  cipher; // refer to enum WLAN_STA_CIPHER
    unsigned int        assoc_time; // in second
    unsigned int        link_quality; // 0 (bad), 1 (fair), or 2 (best)
    struct in_addr  ipv4;
    struct in6_addr ipv6;
    unsigned char mac[6];
};

#define CFG_WLAN_ACL_PACKAGE  "wlan_acl"
#define CFG_WLAN_ACL_POLICY_OPTION    "policy"
#define CFG_WLAN_ACL_MACLIST_OPTION   "maclist"
#define MAX_MACLIST_COUNT 128
#define MAX_ACL_SCHEME_COUNT 16

#define CFG_WLAN_ACL_POLICY_PERMIT_VALUE  "permit"
#define CFG_WLAN_ACL_POLICY_DENY_VALUE    "deny"

enum {
    WLAN_ACL_POLICY_OPEN,
    WLAN_ACL_POLICY_ALLOW = 1,
    WLAN_ACL_POLICY_DENY,
    WLAN_ACL_POLICY_FLUSH,
    
    WLAN_ACL_POLICY_MAX
};

struct wlan_acl_mac {
    unsigned char mac[6];
};

struct wlan_acl_status {
    char name[ACL_NAME_MAX_LENGTH + 1];
    int policy;
    int count;
    struct wlan_acl_mac *maclist; 
};

struct wlan_acl_stats {
    int acl_count;
    struct wlan_acl_status *acl; 
};


#define WIFI_CFG_PACKAGE "wireless"
#define WIFI_CFG_SECTION_DEVICE "wifi-device"
#define WIFI_CFG_OPTION_COUNTRY "country"
extern int wlan_get_radio_count(int *count);

#define WLAN_DEFAULT_COUNTRY_CODE "CN"
extern int wlan_get_country(char *country);
extern int wlan_set_country(const char *country);
extern int wlan_undo_country(void);


extern int wlan_set_beacon_ssid_hide(int stid, int value);
extern int wlan_set_client_max(int stid, int value);
extern int wlan_set_auth(int stid, int auth);
extern int wlan_set_service_template_enable(int stid, int enable);




#define WLAN_CFG_SERVICE_TEMPLATE_PACKAGE "wlan_service_template"
extern int wlan_service_template_get_all(struct service_template *stcfg);
extern int wlan_undo_service_template(int stid);


#define WLAN_CFG_RADIO_PACKAGE   "wireless"
/*
 * fetch all radio config from /etc/config/wlan_radio
 */
extern int wlan_radio_get_all(struct wlan_radio_info *rdcfg);



extern int wlan_undo_bind(int radio, int stid);
extern int wlan_undo_service_template_enable(int stid);
extern int wlan_get_valid_stid(void);
extern int wlan_create_service_template(int stid);
extern int wlan_set_ssid(int stid, const char *ssid);
extern int wlan_set_portal_scheme(int service_template, char *portal_scheme);
extern int wlan_set_beacon_ssid_hide(int stid, int value);
extern int wlan_set_radio_enable(int radio_id, int enable);
extern int wlan_set_mode(int radio_id, int mode);
extern int wlan_set_channel(int radio_id, int value);
extern int wlan_set_max_power(int radio_id, int value);
extern int wlan_set_dtim(int radio_id, int value);
extern int wlan_set_frag_threshold(int radio_id, int value);
extern int wlan_set_rts_threshold(int radio_id, int value);
extern int wlan_set_short_gi(int radio_id, int value);
extern int wlan_set_ampdu(int radio_id, int enable);
extern int wlan_set_amsdu(int radio_id, int enable);
extern int wlan_set_dot11nonly(int radio_id, int dot11nonly);
extern int wlan_set_dot11aconly(int radio_id, int dot11aconly);
extern int wlan_set_bandwidth(int radio_id, int bandwidth);
extern int wlan_set_distance(int radio_id, int value);
extern int wlan_set_preamble(int radio_id, int preamble);
extern int wlan_set_protection_mode(int radio_id, int mode);
extern int wlan_set_beacon_interval(int radio_id, int value);
extern int wlan_set_rssi_threshold(int radio_id, int value);
extern int wlan_set_rssi(int radio_id, int enable);
extern int wlan_set_radio_client_max(int radio_id, int max);
extern int wlan_set_bind(int radio_id, int stid);
extern int wlan_set_bcast_ratelimit_enable(int radio_id, int value);
extern int wlan_set_cipher(int stid, int cipher);
extern int wlan_set_wep40_key(int stid, int slot, int type, int crypt, const char *key);
extern int wlan_set_wep108_key(int stid, int slot, int type, int crypt, const char * key);
extern int wlan_set_psk(int stid, const char * password, int crypt, int type);
extern int wlan_set_radius_scheme(int stid, const char * name);
extern int wlan_set_ptk_lifetime(int stid, int value);
extern int wlan_set_ptk_lifetime_enable(int stid, int value);
extern int wlan_set_gtk_lifetime(int stid, int value);
extern int wlan_set_gtk_lifetime_enable(int stid, int value);
#if OK_PATCH
// add bandwidth_priority and client_isolation
extern int wlan_set_bandwidth_priority(int stid, int value);
extern int wlan_set_client_isolation(int stid, int value);
extern int wlan_set_nettype(int stid, int value);
extern int wlan_set_ppsk_keys_url(int stid, char *value);
#endif
extern int wlan_set_static_client_uplink_rate_limit_value(int stid, unsigned int value);
extern int wlan_set_dynamic_client_uplink_rate_limit_value(int stid, unsigned int value);
extern int wlan_undo_dynamic_client_uplink_rate_limit_value(int stid);
extern int wlan_undo_static_client_uplink_rate_limit_value(int stid);
extern int wlan_set_static_client_downlink_rate_limit_value(int stid, unsigned int value);
extern int wlan_set_dynamic_client_downlink_rate_limit_value(int stid, unsigned int value);
extern int wlan_undo_dynamic_client_downlink_rate_limit_value(int stid);
extern int wlan_undo_static_client_downlink_rate_limit_value(int stid);
extern int wlan_get_stid_by_ssid(char *ssid, int *stid);
extern int wlan_get_ifname_by_bssid(int bssid, char *ifname);
extern int wlan_se_isolation(int radioid, int stid, int value);
extern int wlan_get_acl_all(struct wlan_acl_stats **acls);
extern int wlan_free_acl_all(struct wlan_acl_stats *acls);
extern int wlan_undo_acl_scheme(int stid);
extern int acl_scheme_undo_maclistall(const char *name);
extern int acl_scheme_delete(const char *name);
extern int acl_scheme_create(const char *name);
extern int acl_scheme_set_policy(const char *name, int policy);
extern int acl_scheme_set_maclist(const char *name, char *mac);
extern int wlan_set_acl_scheme(int stid, const char *acl_scheme);
#endif /*__WLAN_SERVICES_H_ */
