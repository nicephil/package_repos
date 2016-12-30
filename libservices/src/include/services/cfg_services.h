#ifndef __CFG_SERVICES_H
#define __CFG_SERVICES_H
#include <uci.h>

/* visitor */
extern int cfg_visit_package(const char *package, 
        int (*visitor)(struct uci_package *p, void *arg),
        void *arg);

extern int cfg_visit_section(const char *section_tuple, 
        int (*visitor)(struct uci_section *p, void *arg),
        void *arg);

/* option */
extern int cfg_get_option_value(const char *option_tuple, char *value, int len);
extern int cfg_set_option_value(const char *option_tuple, char *value);
extern int cfg_add_option_list_value(const char *option_tuple, char *list_value);
extern int cfg_del_option_list_value(const char *option_tuple, char *list_value);
extern int cfg_del_option(const char *option_tuple);

/* section */
extern int cfg_add_section(const char *section_tuple, const char *section_name);
extern int cfg_del_section(const char *section_tuple);

extern void cfg_disable_version_notice(void);
extern void cfg_enable_version_notice(void);
extern void cfg_update_notice(void);

#define OKCFG_OPTION_VERSION_STR "okcfg.config.version"
extern void cfg_set_version(int version);
extern int cfg_get_version(void);



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

#endif /* __CFG_SERVICES_H */
