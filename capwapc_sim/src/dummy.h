#ifndef __DUMMY_H__
#define __DUMMY_H__

#define CAPWAPC_LISTEN_ADDRESS    "/var/run/wtp"

struct product_info {
    char    company[12];    // short name
    char    production[20]; // formed at compiled time, used by inner program
    char    model[24];      // come from manufactory data, seen by custom
    char    mac[20];
    char    bootloader_version[24];
    char    software_version[24];
    char    software_inner_version[24];
    char    hardware_version[24];
    char    production_match[16];
    char    serial[36];
    unsigned long   software_buildtime;
    unsigned long   bootloader_buildtime;
};

typedef struct interface_info
{
    int id;
    unsigned char type;
    unsigned char enable;
    unsigned char dns_count;
    char address[33];
    char netmask[33];
    char dns_server[3][33];
    char default_address[33];
    char default_netmask[33];
    char desc[81];
}interface_info;

typedef enum {
    CAPWAPC_STATE_DISABLE = 0,
    CAPWAPC_STATE_INIT,
    CAPWAPC_STATE_SULKING,
    CAPWAPC_STATE_DISCOVERY,
    CAPWAPC_STATE_JOIN,
    CAPWAPC_STATE_CONFIGURE,
    CAPWAPC_STATE_DATA_CHECK,
    CAPWAPC_STATE_RUN,
    CAPWAPC_STATE_RESET,
    CAPWAPC_STATE_MAX,
} capwapc_state_e;

struct capwapc_status {
    capwapc_state_e state;
    char server_name[32];
    char server_addr[16];
};

extern int cfg_get_product_info(struct product_info * info);
extern int vlan_get_manage_vlaninfo(interface_info *info);
extern char *dc_get_handresult(void);
extern int dc_json_machine(const char *data);
extern void set_product_mac(const char *mac);
extern void set_product_sn(const char *sn);
#endif
