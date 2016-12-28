#ifndef __MISC_SERVICES_H
#define __MISC_SERVICES_H

#define PRODUCTINFO_CFG_PACKAGE  "productioninfo"
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

#endif
