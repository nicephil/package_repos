#ifndef __NMSC_UTIL_H__
#define __NMSC_UTIL_H__
#include <syslog.h>
#include "nmsc/nmsc.h"

#define CAPWAPC_LATER_EXEC_NOTHING  0
#define CAPWAPC_LATER_EXEC_RESTART  1
#define CAPWAPC_LATER_EXEC_STOP     2

#define nmsc_log(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define nmsc_debug(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)

extern void log_node_pair(struct node_pair_save pair);
extern void log_node_paires(struct node_pair_save *paires, int size);
extern void dc_cawapc_later_action(int action);

/* is default integer config value from nms in json format? */
static inline int is_default_integer_config(int integer)
{
    return (integer == 0xfffff);
}

/* is default char config from nms in json format? */
static inline int is_default_string_config(const char *string)
{
    return (string[0] == '-' && string[1] == '-' && string[2] == '-' && string[3] == 0);
}

static inline int dc_generate_error_code(int error)
{
    return ((error & 0xffff) << 16);
}

#define CHECK_DEFAULT_INTEGER_CONFIG(json_cfg, def_cfg) \
    do { \
        if (is_default_integer_config(json_cfg)) { \
            json_cfg = def_cfg; \
        } \
    }while (0)

#define CHECK_DEFAULT_STRING_CONFIG(item) \
    do { \
        if (is_default_string_config(json_cfg.item)) { \
            if (strlen(def_cfg.item) > 0) { \
                strcpy(json_cfg.item, def_cfg.item); \
            } \
            else {\
                return dc_error_defcfg_noexist; \
            } \
        } \
    }while (0)


#include "util/list.h"
enum {
    NMSC_DELAY_OP_LOG = (0 << 1),
};

struct nmsc_delay_op {
    int (*operator)(void *reserved);
    void *reserved;
};

struct nmsc_delay_op_node {
    struct list_head  list;
    struct nmsc_delay_op node;
};

extern void nmsc_delay_op_init(void);
extern int nmsc_delay_op_done(void);
extern void nmsc_delay_op_release(void);
extern void nmsc_delay_op_new(int (*operator)(void *reserved), void *param, int size);
extern int nmsc_delay_op_log(void *reserved) ;
extern int nmsc_delay_op_dhcpd(void *reserved);
extern int nmsc_delay_op_dhcpd_ethif(void *reserved);
extern int nmsc_delay_op_version(void *reserved);
extern int nmsc_delay_op_save_all(void *reserved);
extern int nmsc_delay_op_wds_acl(void *reserved); 
extern int nmsc_delay_op_wds_mode(void *reserved); 
extern int nmsc_delay_op_bind_wlan_scan(void *reserved);
#endif
