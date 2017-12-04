#ifndef __DEVCTRL_PROTOCOL_H__
#define __DEVCTRL_PROTOCOL_H__

#define DEVCTRL_BLOCK_HEADER_LEN    20
typedef struct devctrl_block{
#define COOKIE_LENGTH   8    
    unsigned char version;
    char cookie[COOKIE_LENGTH];
    unsigned short type;
    unsigned char compressed;
    unsigned int orig_len;
    unsigned int len;
    char *data;
} devctrl_block_s;

#define NAT_VLAN_FIX_LEN     19
struct nat_vlan_info {
    unsigned short len;
    int id;
    unsigned char type;
    int ip;
    int mask;
    int gw;
};

struct nat_vlan_list {
    unsigned char num;
    struct nat_vlan_info *info;
};

#define DEVINFO_FIX_LEN     40    
typedef struct device_info{
    char mac[6];
    char iptype;
    int  ip;
    int  netmask;
    int  gateway;
    int  uptime;
    char snlen;
    char *sn;
    char namelen;
    char *name;
    unsigned short mtu;
    char verlen;
    char *version;
    int  cfg_version;
    int  cfg_code;
    char mode;
    struct nat_vlan_list natlist;
    char wds_mode;
    char cn_len;
    char country[4];
} device_info_s;

#define WLAN_RADIO_STATUS_FIXLEN        (18)

#define WLAN_STA_STATUS_FIXLEN          (36 + 18 + 8) /* don't include updated/ssid/user */
#define WLAN_STA_QUERY_FIXLEN           (35 + 18 + 8)/* don't include stat/updated/ssid/user */
#define WLAN_STA_UPDATE_FIXLEN          (17 + 4 + 42 + 2) /* only include len/mac/ip/portal_mode/name_len+ rssi */
#define WLAN_INTERFACE_INFO_FIXLEN      36 /* include struct device_interface_info */
#define WDS_TUNNEL_INFO_FIXLEN          18 /* include struct wds_tunnel_info */

typedef enum {
    RSSI_LEVEL_EXCELLENT = 0,
    RSSI_LEVEL_GOOD,
    RSSI_LEVEL_LOW,
    RSSI_LEVEL_MAX,
} rssi_level_e;

#if OK_PATCH
#define MAX_AUTH_USERNAME_LEN 64
#define MAX_CLIENT_TYPE_LEN 32
#define MAX_LOCATION_LEN 64
#define SYS_INTF_NAME_SIZE 24
#endif

struct wlan_radio_stat {
    unsigned short len;
    unsigned char ifname_len;
    char ifname[SYS_INTF_NAME_SIZE+1];
    unsigned char chan_util;
    unsigned char  error_rate;
    unsigned char retry_rate;
    int noise_level;
    unsigned int tx_rate;
    unsigned int rx_rate;
};

struct wlan_sta_stat {
    char updated;
    unsigned short len; 
    char state;
    unsigned char mac[6];
    unsigned long long time_ms;
    int uptime;
    char radioid;
    char ssid_len;
    char ssid[33];
    char auth;
    char cipher;
    char portal;
    int ip;
    int portal_mode;
    char name_len;
    char user[MAX_AUTH_USERNAME_LEN + 1];
    char ps_len;
    char ps_name[33]; /* portal scheme */
    char bssid[6];
    int rssi;
    int channel;
    int vlan;
    rssi_level_e rs_level;
    int mode;
    unsigned char bandwidth;
    char client_type_len;
    char client_type[MAX_CLIENT_TYPE_LEN + 1];
    char client_hostname_len;
    char client_hostname[HOST_NAME_MAX + 1];
    char location_len;
    char location[MAX_LOCATION_LEN + 1];
    unsigned long long txB;
    unsigned long long delta_txB;
    unsigned long long rxB;
    unsigned long long delta_rxB;
    unsigned int atxrb;
    unsigned int arxrb;
    unsigned char error_rate;
    unsigned char retry_rate;
    unsigned int ntxrt;
    unsigned int nrxrt;
    unsigned long long ts;
    unsigned char psmode;
};

enum {
    WLAN_STA_TYPE_STAUS = 0,
    WLAN_STA_TYPE_UPDATE,
    WLAN_STA_TYPE_QUERY
};

typedef struct devctrl_fraglist {
    int id;
    int order;
    CWList list;
} devctrl_fraglist_s;

#define UPDATEINFO_FIX_LEN     15  
struct device_update_info {
    char iptype;
    int  ip;
    int  netmask;
    int  gateway;
    char len;
    char hostname[HOST_NAME_MAX + 1];
    char wds_mode;
};

struct device_interface_info {
    unsigned short len;
    char interface_len;
    char interface_name[SYS_INTF_NAME_SIZE];
    char state;
    unsigned char mac[6];
    int pvid;
    char ssid_len;
    char ssid[33];
    unsigned int ip_address;
    unsigned int mask_address;
    int channel;
    int txpower;
    int mode;
    unsigned char bandwidth;
};

struct ssh_tunnel_cmd {
    int type;
    int local_port;
    int remote_port;
    char server[64 + 1];
    char user[33];
    char pwd[33];
};

struct ssh_tunnel_result {
    int type;
    int code;
    int state;
    int local_port;
    int remote_port;
    char server[64 + 1];
};

struct wds_tunnel_info {
    unsigned short len;
    unsigned char mac[6];
    char mode;
    char err_code;
    char status;
    char level;
    unsigned char uplink[6];
};

struct cli_exec_result {
    int code;
    int len;
    char *result;
};

#define RATE_STA_FIX_LEN     25  
struct if_flow_stat {
    char name[SYS_INTF_NAME_SIZE];
#if !OK_PATCH
    struct netif_flow_stat sta;
#endif
};

struct if_rate_stas {
    int num;
    struct if_flow_stat *stas;
};

extern CWBool parse_devctrlreq_msg(CWProtocolMessage *Msg, devctrl_block_s *Controlinfo) ;
extern CWBool assemble_devctrlresp_elem(CWProtocolMessage *msgPtr, devctrl_block_s *Controlblock);
extern CWBool assemble_devctrlresp_msg(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, 
    int PMTU, int seqNum, CWProtocolResultCode resultCode);
extern CWBool assemble_devctrlresp_frag(CWProtocolMessage **completeMsgPtr, 
    int *fragmentsNumPtr, int PMTU, int seqNum, int msgTypeValue, 
    CWProtocolMessage *msgElems, int is_crypted);
extern CWBool parse_devctrlreq_frag(char *buf, int readBytes, CWProtocolMessage *reassembledMsg, CWBool *dataFlagPtr);
extern CWBool assemble_dev_updateinfo(char **info, int *len);
extern CWBool assemble_vendor_devinfo(char **info, int *len);
extern CWBool assemble_wlan_radio_status_elem(char **payload, int *len, struct wlan_radio_stat *stats, int count);
extern CWBool assemble_wlan_sta_status_elem(char **payload, int *len,
    struct wlan_sta_stat *stas, int count, int type);
extern CWBool assemble_interface_info_elem(char **payload, int *len,
    struct device_interface_info *stas, int count);
extern CWBool assemble_wds_info_elem(char **payload, int *len,
    struct wds_tunnel_info *stas, int count);
extern CWBool assemble_cli_result_elem(char **payload, int *len, struct cli_exec_result *result);
extern CWBool assemble_rate_sta_elem(char **payload, int *len, struct if_rate_stas *result);
extern CWBool WTPEventRequest_devctrlresp(int type, int value);
#endif
