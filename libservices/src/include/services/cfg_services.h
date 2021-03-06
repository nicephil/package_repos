#ifndef __CFG_SERVICES_H
#define __CFG_SERVICES_H
#include <uci.h>

/*
 * @brief go through whole config package
 * @param [in] package the package name. e.g. portal
 * @param [in] visitor the callback function
 * @param [in] arg will pass to visitor callback function
 * @return -1 means failure, otherwise return code from visitor
 */
extern int cfg_visit_package(const char *package_tuple, 
        int (*visitor)(struct uci_package *p, void *arg),
        void *arg);

/*
 * @brief go through whole config package in specific path
 * @param [in] path the specific path e.g. /tmp/state
 * @param [in] package the package name. e.g. portal
 * @param [in] visitor the callback function
 * @param [in] arg will pass to visitor callback function
 * @return -1 means failure, otherwise return code from visitor
 */
extern int cfg_visit_package_with_path(const char *path, const char *package_tuple, 
        int (*visitor)(struct uci_package *p, void *arg),
        void *arg);
/*
 * @brief go through section
 * @param [in] section_tuple e.g. portal.aa
 * @param [in] visitor call back function
 * @param [in] arg will pass to call back function
 * @return -1 means failure, otherwise return code from visitor
 */
extern int cfg_visit_section(const char *section_tuple, 
        int (*visitor)(struct uci_section *p, void *arg),
        void *arg);

/* @brief get the value according to whole option tuple
 * @param [in] option_tuple e.g. portal.bb.url
 * @param [out] value fetched value
 * @param [in] the length of value
 * @return 0 means success, otherwise means failure
 */
extern int cfg_get_option_value(const char *option_tuple, char *value, int len);

/* @brief get the value according to whole option tuple
 * @param [in] path the specific path e.g. /tmp/state
 * @param [in] option_tuple e.g. portal.bb.url
 * @param [out] value fetched value
 * @param [in] the length of value
 * @return 0 means success, otherwise means failure
 */
extern int cfg_get_option_value_with_path(const char *path, const char *option_tuple, char *value, int len);

/*
 * @brief set the value according to whole option tuple, will create one option
 * if not found
 * @param [in] option_tuple e.g. portal.bb.url
 * @param [in] value set to option
 * @return 0 means success, otherwise means failure
 */
extern int cfg_set_option_value(const char *option_tuple, const char *value);

/*
 * @brief set the int value according to whole option tuple, will create one option
 * if not found
 * @param [in] option_tuple e.g. portal.bb.timeslot
 * @param [in] value set to option
 * @return 0 means success, otherwise means failure
 */
extern int cfg_set_option_value_int(const char *option_tuple, int value);

/*
 * @brief add the list value according to option tuple
 * @param [in] option_tuple e.g. portal.bb.ip='192.168.1.1/255.255.255.0'
 * @param [in] the value of list
 * @return 0 means success, otherwise means failure
 */
extern int cfg_add_option_list_value(const char *option_tuple, char *list_value);

/*
 * @brief delete the list value according to option tuple
 * @param [in] option_tuple e.g. portal.bb.ip='192.168.1.1/255.255.255.0'
 * @return 0 means success, otherwise means failure
 */
extern int cfg_del_option_list_value(const char *option_tuple);

/*
 * @brief delete the option according to option tuple
 * @param [in] option_tuple e.g. portal.bb.url
 * @return 0 means success, otherwise means failure
 */
extern int cfg_del_option(const char *option_tuple);

/*
 * @brief add the name of section
 * @param [in] package_tuple e.g. portal.aa
 * @param [in] section_type_name e.g. config aa aa
 * @return 0 means success, otherwise means failure
 */
extern int cfg_add_section(const char *package_tuple, const char *section_type_name);

/*
 * @breif add the section with name and type. e.g. system.ntp.timeserver
 * @param [in] package_tuple e.g. system
 * @param [in] section_type e.g. ntp
 * @param [in] section_name e.g. timeserver
 * @return 0 means success, otherwise failure
 */
extern int cfg_add_section_with_name_type(const char *package_tuple, const char *section_name, const char *section_type);

/*
 * @brief delete the section
 * @param [in] section_tuple e.g. portal.aa
 * @return 0 means success, otherwise means failure
 */
extern int cfg_del_section(const char *section_tuple);





extern void cfg_disable_version_notice(void);
extern void cfg_enable_version_notice(void);
extern void cfg_update_notice(void);

#define OKCFG_OPTION_VERSION_STR "okcfg.config.version"
extern void cfg_set_version(int version);
extern int cfg_get_version(void);



#define PRODUCTINFO_CFG_PACKAGE  "productinfo"
#define PRODUCTINFO_OPTION_PRODUCTION "production"
#define PRODUCTINFO_OPTION_MODEL "model"
#define PRODUCTINFO_OPTION_SERIAL "serial"
#define PRODUCTINFO_OPTION_MAC "mac"
#define PRODUCTINFO_OPTION_SWVERSION "swversion"
#define PRODUCTINFO_OPTION_BOOTVERSION "bootversion"
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


extern int cfg_is_ubnt_pro(void);
extern int cfg_is_ubnt_lite(void);
extern int cfg_is_w282(void);
extern int cfg_is_a750(void);
extern int cfg_is_a751(void);
extern int cfg_is_wa115ac(void);
extern int cfg_is_wl8200_it2(void);
extern int cfg_get_product_info(struct product_info * info);
enum upgrade_failed_e{
    MTDDEV_GET_FAILED = -1,
    VERSION_MATCH_FAILED = -2,
    IMG_UPGRADE_FAILED = -3,
    BOOTIMG_SET_FAILED = -4
};
extern int cfg_upgrade_image(const char *imagefile);


extern int execute_cmd(const char *cmd, char *result, int len);

#endif /* __CFG_SERVICES_H */
