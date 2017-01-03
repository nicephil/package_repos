#ifndef __WLAN_SERVICES_H_
#define __WLAN_SERVICES_H_
#include <netinet/in.h>


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

#define WLAN_SSID_MAX_LENGTH    33
#define WLAN_KEY_MAX_LENGTH     65
#define ACL_NAME_MAX_LENGTH     16
#define PORTAL_SCHEME_NAME_MAX_LENGTH     32
#define TIMER_NAME_MAX_LENGTH     32

enum WLAN_BSS_TYPE {
    WLAN_BSS_TYPE_VAP = 0,
    WLAN_BSS_TYPE_STA,
    WLAN_BSS_TYPE_MAX
};



#define ACL_NAME_MAX_LENGTH     16

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

struct wlan_acl_mac {
    unsigned char mac[6];
};

struct wlan_acl_status {
    char name[ACL_NAME_MAX_LENGTH + 1];
    int policy;
    int count;
    struct wlan_acl_mac * maclist; 
};

struct wlan_acl_stats {
    int acl_count;
    struct wlan_acl_status * acl; 
};


#define WIFI_CFG_PACKAGE "wireless"
#define WIFI_CFG_SECTION_DEVICE "wifi-device"
#define WIFI_CFG_OPTION_COUNTRY "country"
extern int if_get_radio_count(int *count);

int wlan_get_country(char *country);
int wlan_set_country(const char *country);
#define WIFI_CFG_RADIO0_OPTION_COUNTRY_TUPLE "wireless.@wifi-iface[0].country"
#define WIFI_CFG_RADIO1_OPTION_COUNTRY_TUPLE "wireless.@wifi-iface[0].country"
#define WIFI_COUNTRY_DEFAULT "156"
int wlan_undo_country(void);




#endif /*__WLAN_SERVICES_H_ */
