#ifndef __MISC_SERVICES_H
#define __MISC_SERVICES_H
#include <uci.h>

extern int uci_visit_package(const char *package, 
        int (*visitor)(struct uci_package *, void *arg),
        void *arg);

#define PRODUCTINFO_CFG_PACKAGE  "productinfo"
#define PRODUCTINFO_OPTION_PRODUCTION "production"
#define PRODUCTINFO_OPTION_SERIAL "serial"
#define PRODUCTINFO_OPTION_MAC "mac"
#define PRODUCTINFO_OPTION_MAC_COUNT "mac_count"

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


extern int cfg_get_product_info(struct product_info * info);



#define WIFI_CFG_PACKAGE "wireless"
#define WIFI_SECTION_DEVICE "wifi-device"
#define WIFI_OPTION_ENABLE "enable"


extern int if_get_radio_count(int *count);



#define NETWORK_CFG_PACKAGE "network"
#define NETWORK_SECTION_LAN "lan"
#define NETWORK_OPTION_DEVICE "device"
#define NETWORK_OPTION_IFNAME "ifname"
#define NETWORK_OPTION_PROTO "proto"
#define NETWORK_OPTION_TYPE "type"

typedef struct interface_info
{
    int id;
    unsigned char type;
    unsigned char enable;
    unsigned char nat_enable;
    unsigned char dns_count;
    char address[33];
    char netmask[33];
    char dns_server[3][33];
    char default_address[33];
    char default_netmask[33];
    char pppoe_user[65];
    char pppoe_pass[65];
    char pppoe_acname[65];
    char pppoe_servicesname[65];
    char pppoe_mtu[65];
    char desc[81];
}interface_info;

extern int get_manage_ifinfo(interface_info *info);


#endif /* __MISC_SERVICES_H */
