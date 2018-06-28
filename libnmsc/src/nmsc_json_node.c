#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <strings.h>
#include <errno.h>
#include "nmsc/nmsc.h"
#include "nmsc_util.h"
#include "json/json.h"


#include "services/hostname_services.h"
#include "services/capwapc_services.h"
#include "services/portal_services.h"
#include "services/wlan_services.h"
#include "services/ntpclient_services.h"
#include "services/log_services.h"
#include "services/dns_services.h"
#include "services/vlan_services.h"
#include "services/dnsset_services.h"
#include "services/cfg_services.h"
#include "services/util_services.h"
#include "services/time_range_services.h"
#include "services/aaad_services.h"

#define SCHEME_TIME_RANGE_MAXSIZE 16
#define PERIODIC_TIME_RANGE_MAXSIZE 16
#define SCHEME_TIME_RANGE_NAME_MAXSIZE 32

#if OK_PATCH
struct bandsteering_config {
        int enable;
            int retry_threshold;
                int aging_time;
};

struct bandsteering_suppress_config {
        int enable;
            int suppress_threshold;
};
struct vlan_shownode {
    int id;
    char is_routedif;
    char ifname[24];
    char desc[81];
    char name[33];
};
struct vlan_showinfo {
    int num;
    struct vlan_shownode *nodes;
};
#endif



struct service_template_json {
    char ssid[WLAN_SSID_MAX_LENGTH];
    char key[65];
    char radius_scheme[RADIUS_SCHEME_NAME_MAX_LENGTH + 1];
    char portal_scheme[PORTAL_SCHEME_NAME_MAX_LENGTH + 1];
    char acl_scheme[ACL_NAME_MAX_LENGTH + 1];
    char time_scheme[SCHEME_TIME_RANGE_NAME_MAXSIZE+1];
    int  stid;
    int  beacon_ssid_hide;
    int  client_max;
    int  auth;
    int  cipher;
    int  key_crypt;
    int  key_type;
    int  wep_key_slot;
    int  gtk_enabled;
    int  gtk_lifetime;
    int  ptk_enabled;
    int  ptk_lifetime;
    int  uplink_limit_enable;
    int  uplink_limit_mode;
    int  uplink_limit_rate;
    int  downlink_limit_enable;
    int  downlink_limit_mode;
    int  downlink_limit_rate;
    int  m2u_enable;
    int  ts_enable;
    char ts_ip[33];
    char ts_netmask[33];
#if OK_PATCH
    int  bandwidth_priority;
    int client_isolation;
    int type;
    char ppsk_keys_url[PPSK_KEYS_URL_MAX_LENGTH];
    int enabled;
#endif
};
            
struct service_templates {
    int num;
    struct service_template_json *config;
};

struct mbss_bind {
    char ssidname[33];
};
struct radio_json {
    int id;
    int mode;
    int channel;
    int max_power;
    int dot11nonly;
    int dot11aconly;
    int ampdu;
    int bandwidth;
    int distance;
    int preamble;
    int protection_mode;
    int beacon_interval;
    int dtim;
    int fragment_threshold;
    int rts_threshold;
    int short_gi;
    int mbss_num;
    int rssi_access;
    int rssi_access_threshold;
    struct mbss_bind mbss[MAX_MBSS_COUNT];
    int bcst_ratelimt;
    int bcst_ratelimt_cir;
    int bcst_ratelimt_cbs;
    int air_time_fairness;
    char air_scan[33];
#if OK_PATCH
    int client_max;
#endif
};

struct radio_list {
    int num;
    struct radio_json config[MAX_RADIO_COUNT];
} ;

struct wlan_acl_schemes {
    int configed;
    int num;
    struct wlan_acl_status *config;
};

struct wlan_rrm{
    int configed;
    unsigned int dot11a_basic;
    unsigned int dot11a_support;
    unsigned int dot11g_basic;
    unsigned int dot11g_support;
    unsigned int dot11n_basis_mcs;
    unsigned int dot11n_supoort_mcs;
    unsigned int dot11a_fbcrate;
    double dot11g_fbcrate;
    unsigned int dot11a_fmgrate;
    double dot11g_fmgbrate;
};

struct permit_json{
    unsigned int start;
    unsigned int stop;
};

struct time_limit_json{
    char name[SCHEME_TIME_RANGE_NAME_MAXSIZE+1];
    int period;
    int count;
    struct permit_json permit[PERIODIC_TIME_RANGE_MAXSIZE];
    int days[8];
};

struct time_limit_schemes{
    int configed;
    int num;
    struct time_limit_json config[SCHEME_TIME_RANGE_MAXSIZE];
};

struct band_steering{
    int configed;
    struct bandsteering_config bs_json;
    struct bandsteering_suppress_config bs_support_json;   
};

struct dns_set_key 
{
    char key[DNS_KEY_MAXLEN + 1];
} ;

struct dns_set_scheme
{
    char name[DNS_SETNAME_MAXLEN + 1];
    int  num;
    struct dns_set_key *keylist;
} ;

struct dns_set_schemes{
    int num;
    struct dns_set_scheme *config;
};

enum {
    STEP_UNBIND = 0,
    STEP_OTHERS
};

struct rate_optimization{
    int configed;
    int enable;
};

#define DOT11A_MODE     1
#define DOT11G_MODE     2

struct igmp_group {
    char address[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")]; /* support ipv4/ipv6 */
};

struct igmp_snooping_s {
    int configed;
    int enable;
    int group_threshold;
    int member_threshold;
    int age_time;
    int mf_policy; /* 1: forward all 2: drop unknow 3: drop all */
    int m2u_auto_adopt;
    int sg_num;
    struct igmp_group *sta_groupes;
};

struct portal_preauth {
    int configed;
    int enable;
};

struct arp_optimize {
    int configed;
    int enable;
    int policy;
};

struct wlan_scan_template {
    int configed;
    int num;
    struct wscan_template *config;
};

struct wlan_scan_bind_info {
    char cRadioName[33];
    char cRadioWScanName[33];
};

#define WSCAN_TEMPLATE_MAX_LEN 32
#define WSCAN_CHANNEL_MAX_NUM 36
struct wscan_template {
    char name[WSCAN_TEMPLATE_MAX_LEN+1];
    char channels[2*WSCAN_CHANNEL_MAX_NUM];
    int type;
    int period;
    int intval;
    int rd_bits;
};



int dc_hdl_node_default(struct json_object *obj, struct node_pair_save *paires, int size)
{
    int i, ret, obj_saved;
    json_type type = json_object_get_type(obj);

    if (type != json_type_object && type != paires->type) {
        nmsc_log("Json %s type match failed:%d:%d", paires->key ? paires->key : "NULL", 
            type, paires->type);
        return dc_error_obj_type;
    }

    switch (type) {
        case json_type_int:
            *((int *)(paires->value)) = json_object_get_int(obj);
            break;

        case json_type_double:
            *((double *)(paires->value)) = json_object_get_double(obj);
            break;    

        case json_type_string:
            strncpy((char *)paires->value, json_object_get_string(obj), paires->size - 1);
            break;

        case json_type_object:
            {
                json_object_object_foreach(obj, key, val) {
                    obj_saved = 0;
                    for (i = 0; i < size; i++) {
                        if (!strcasecmp(key, paires[i].key)) {
                            obj_saved = 1;
                            if ((ret = dc_hdl_node_default(val, &(paires[i]), 1)) != 0) {
                                return ret;
                            }
                            break;
                        }
                    }
                    if (!obj_saved) {
                        nmsc_log("Unknow json obj :%s", key);
                        /* Only handle recognized, others will be ignored */
                        //return dc_error_save_obj;
                    }
                }
            }
            break;

        default:
            nmsc_log("Unsovlued the Json type :%d", type);
            return dc_error_obj_type;
    }
    
    return 0;
}

int dc_hdl_node_type(struct json_object *obj)
{
    int type = 0, ret, node = dc_node_type;
    struct node_pair_save pair = {
        .key   = "type",
        .type  = json_type_int,
        .value = &type,
        .size  = sizeof(type),
    };
    
    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);

    /* full config */
    if (type == 0) {
        int retv = system("cp -rf /etc/defcfg/* /etc/config/. ");
        if (retv == -1) {
            nmsc_log("system error: %s",strerror(errno));
        }
    }
    
    return 0;
}

int dc_hdl_node_version(struct json_object *obj)
{
    int version = 0, ret, node = dc_node_config_version;
    struct node_pair_save pair = {
        .key   = "config_version",
        .type  = json_type_int,
        .value = &version,
        .size  = sizeof(version),
    };

    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);



    nmsc_delay_op_new(nmsc_delay_op_version, &version, sizeof(version));
    
    return 0;
}

static int dc_hdl_node_auth_url(struct json_object *obj)
{
    char auth_url[255] = {};
    int ret, node = dc_node_hostname;
    struct node_pair_save pair = {
        .key   = "auth_url",
        .type  = json_type_string,
        .value = auth_url,
        .size  = sizeof(auth_url),
    };
    
    if (json_object_get_type(obj) != json_type_string) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);




    if (!strlen(auth_url) || is_default_string_config(auth_url)) {
        if ((ret = portald_scheme_update_auth_url(NULL)) != 0) {
            nmsc_log("Set auth_url %s failed for %d.", auth_url, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        } 
    }
    else {
        if ((ret = portald_scheme_update_auth_url(auth_url)) != 0) {
            nmsc_log("Set auth_url %s failed for %d.", auth_url, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        } 
    }
    return 0;
}


static int dc_hdl_node_hostname(struct json_object *obj)
{
    char hostname[255] = {};
    int ret, node = dc_node_hostname;
    struct node_pair_save pair = {
        .key   = "hostname",
        .type  = json_type_string,
        .value = hostname,
        .size  = sizeof(hostname),
    };
    
    if (json_object_get_type(obj) != json_type_string) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);




    if (!strlen(hostname) || is_default_string_config(hostname)) {
        if ((ret = hostname_undo()) != 0) {
            nmsc_log("Undo hostname failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    else {
        if ((ret = hostname_set(hostname)) != 0) {
            nmsc_log("Set hostname failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    return 0;
}

static int dc_hdl_node_zone(struct json_object *obj)
{
    char zone[128] = {};
    int ret, node = dc_node_zone;
    struct node_pair_save pair = {
        .key   = "zone",
        .type  = json_type_string,
        .value = zone,
        .size  = sizeof(zone),
    };
    
    if (json_object_get_type(obj) != json_type_string) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);




    if (!strlen(zone) || is_default_string_config(zone)) {
        if ((ret = zone_undo()) != 0) {
            nmsc_log("Undo timezone failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    else {
        if ((ret = zone_set(zone)) != 0) {
            nmsc_log("Set timezone failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    return 0;
}

static int dc_hdl_node_location(struct json_object *obj)
{
    char location[65] = {};
    int ret, node = dc_node_location;
    struct node_pair_save pair = {
        .key   = "location",
        .type  = json_type_string,
        .value = location,
        .size  = sizeof(location),
    };
    
    if (json_object_get_type(obj) != json_type_string) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);
    



    if (!strlen(location) || is_default_string_config(location)) {
        if ((ret = capwapc_undo_location()) != 0) {
            nmsc_log("Undo location failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    else {
        if ((ret = capwapc_set_location(location)) != 0) {
            nmsc_log("Set location failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    return 0;
}

static int dc_hdl_node_domain_name(struct json_object *obj)
{
    char domain_name[33] = {};
    int ret, node = dc_node_system;
    struct node_pair_save pair = {
        .key   = "domain_name",
        .type  = json_type_string,
        .value = domain_name,
        .size  = sizeof(domain_name),
    };
    
    if (json_object_get_type(obj) != json_type_string) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);




    if (strlen(domain_name) > 0) {
        if ((ret = capwapc_set_domain(domain_name)) != 0) {
            nmsc_log("Set domain name %s config failed for %d.", domain_name, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }

        if ((ret = portald_scheme_update_domain(domain_name)) != 0) {
            nmsc_log("Set domain name %s failed for %d.", domain_name, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        } 
    }
    else {
        if ((ret = capwapc_undo_domain()) != 0) {
            nmsc_log("Undo domain name config failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }

        if ((ret = portald_scheme_update_domain(NULL)) != 0) {
            nmsc_log("Delete domain name failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    
    return 0;
}

static int dc_hdl_node_country(struct json_object *obj)
{
    char country[4] = {};
    int ret, node = dc_node_country_code;
    struct node_pair_save pair = {
        .key   = "country_code",
        .type  = json_type_string,
        .value = country,
        .size  = sizeof(country),
    };
    
    if (json_object_get_type(obj) != json_type_string) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);



    
    if (!strlen(country) || is_default_string_config(country)) {
        ret = wlan_undo_country();
        if (ret) {
            nmsc_log("Undo country code failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    else {
        ret = wlan_set_country(country);
        if (ret) {
            nmsc_log("Set country code %s failed for %d.", country, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }

    return 0;
}

int dc_hdl_node_system(struct json_object *obj)
{
    struct subnode_handler {
        char *key;
        int (*subnode_handler)(struct json_object *obj);
    };

    struct subnode_handler system_subnodes[] = {
        {"hostname", dc_hdl_node_hostname},
        {"zone", dc_hdl_node_zone},
        {"location", dc_hdl_node_location},
        {"country_code", dc_hdl_node_country},
        {"domain_name", dc_hdl_node_domain_name},
        {"auth_url", dc_hdl_node_auth_url}
    };
    int i, obj_saved, ret, node = dc_node_system;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    json_object_object_foreach(obj, key, val) {
        obj_saved = 0;
        for (i = 0; i < sizeof(system_subnodes)/sizeof(system_subnodes[0]); i++) {
            if (!strcasecmp(key, system_subnodes[i].key)) {
                obj_saved = 1;
                if ((ret = system_subnodes[i].subnode_handler(val)) != 0) {
                    return ret;
                }
            }
        }
        if (!obj_saved) {
            nmsc_log("Unknow json obj :%s", key);
            /* Only handle recognized, others will be ignored */
            //return dc_error_code(dc_error_save_obj, node, 0);
        }
    }

    return 0;
}

int dc_hdl_node_usrmanage(struct json_object *obj)
{
    /* not supported yet */
#if !OK_PATCH
    int i, ret, node = dc_node_users;
    struct json_object *array;
    struct local_userinfo useres;
    struct node_pair_save paires[] = {
        {"name",     json_type_string, NULL, sizeof(useres.userlist[0].name)},
        {"password", json_type_string, NULL, sizeof(useres.userlist[0].pwd)},
        {"level",    json_type_int,    NULL, sizeof(useres.userlist[0].level)},
        {"cipher",   json_type_int,    NULL, sizeof(useres.userlist[0].ciphered)}
    };    
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&useres, 0, sizeof(useres));
    for(i = 0; i < json_object_array_length(obj); i++) {
        paires[0].value = useres.userlist[useres.num].name;
        paires[1].value = useres.userlist[useres.num].pwd;
        paires[2].value = &(useres.userlist[useres.num].level);
        paires[3].value = &(useres.userlist[useres.num].ciphered);
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            return ret;
        }
        useres.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    usrmanage_undoall();
    for (i = 0; i < useres.num; i++) {
        if ((ret = usrmanage_setname(useres.userlist[i].name)) != 0) {
            nmsc_log("Set user %s failed for %d.", useres.userlist[i].name, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }

        if ((ret = usrmanage_setpwd(useres.userlist[i].name, 
            useres.userlist[i].pwd, useres.userlist[i].ciphered)) != 0) {
            nmsc_log("Set user %s pwd failed for %d.", useres.userlist[i].name, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }

        if ((usrmanage_setlevel(useres.userlist[i].name, useres.userlist[i].level)) != 0) {
            nmsc_log("Set user %s level failed for %d.", useres.userlist[i].name, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
#endif
    return 0;
}

int dc_hdl_node_ntp(struct json_object *obj)
{
    struct ntpclient_info  def_cfg, json_cfg;
    struct node_pair_save paires[] = {
        {"enabled", json_type_int,    &json_cfg.enabled, 4},
        {"period",  json_type_int,    &json_cfg.period,  4},
        {"servers", json_type_string, NULL, sizeof(json_cfg.server[0])}
    };  
    struct json_object *array;
    int i, j, obj_saved, ret, node = dc_node_ntp;

    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_obj_type;
    }

    memset(&json_cfg, 0, sizeof(json_cfg));
    
    json_object_object_foreach(obj, key, val) {
        obj_saved = 0;
        for (i = 0; i < sizeof(paires)/sizeof(paires[0]); i++) {
            if (!strcasecmp(key, paires[i].key)) {
                obj_saved = 1;
                if (json_object_get_type(val) == json_type_array) {
                    for(j = 0; j < json_object_array_length(val) && j < MAX_NTP_SERVER; j++) {
                        paires[i].value = json_cfg.server[json_cfg.num];

                        array = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(array, &paires[i], 1))!= 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        json_cfg.num++;
                        log_node_pair(paires[i]);
                    }
                }
                else {
                    if ((ret = dc_hdl_node_default(val, &paires[i], 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_pair(paires[i]);
                }
                break;                
            }
        }
        if (!obj_saved) {
            nmsc_log("Unknow json obj :%s", key);
            /* Only handle recognized, others will be ignored */
            // return dc_error_code(dc_error_save_obj, node, 0);
        }
    }



    memset(&def_cfg, 0, sizeof(def_cfg));
    if (ntpclient_get_defcfg(&def_cfg) != 0 
        && (is_default_integer_config(json_cfg.enabled)
        || is_default_integer_config(json_cfg.period))) {
        return dc_error_code(dc_error_defcfg_noexist, node, 0);
    }
    
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.enabled, def_cfg.enabled);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.period, def_cfg.period);

    if ((ret = ntpclient_set_update_period(json_cfg.period)) != 0
        ) {
        nmsc_log("Ntpclient update period failed for %d.", ret);
        return dc_error_code(dc_error_commit_failed, node, ret);
    }

    ntpclient_undo_all_server();
    if (!is_default_string_config(json_cfg.server[0])) {    
        for (i = 0; i < json_cfg.num; i++) {
            if ((ret = ntpclient_add_server(json_cfg.server[i])) != 0) {
                nmsc_log("Ntpclient update period failed for %d.", ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }    
        }
    }
    if (json_cfg.enabled) { 
        if ((ret = ntpclient_enabled()) != 0) {
            nmsc_log("Ntpclient enable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    } else {
        if ((ret = ntpclient_disabled()) != 0) {
            nmsc_log("Ntpclient enable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    
    return 0;
}

int dc_hdl_node_dns(struct json_object *obj)
{
    struct dnses {
        int num;
        char server[MAX_DNS_COUNT][65];
    }dnses;
    struct node_pair_save paires = {
        .key   = "servers",
        .type  = json_type_array,
        .value = NULL,
        .size  = MAX_DNS_COUNT,
    }; 
    struct json_object *array;
    struct in_addr addr;
    int j, obj_saved, ret = 0, node = dc_node_dns;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    memset(&dnses, 0, sizeof(dnses));

    json_object_object_foreach(obj, key, val) {
        obj_saved = 0;
        if (json_object_get_type(val) != json_type_array) {
            return dc_error_code(dc_error_obj_type, node, 0);
        }
        
        if (!strcasecmp(key, paires.key)) {
            obj_saved = 1;
            if (paires.type == json_type_array) {
                paires.type = json_type_string;
                paires.size = sizeof(dnses.server[0]);
                for(j = 0; j < json_object_array_length(val) && j < MAX_DNS_COUNT; j++) {
                    paires.value = dnses.server[dnses.num];
                    
                    array = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(array, &paires, 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    dnses.num++;
                    
                    log_node_pair(paires);
                }
            }
            break;                
        }
        if (!obj_saved) {
            nmsc_log("Unknow json obj :%s", key);
        }
    }


    dns_undo_global_all();
    for (j = 0; j < dnses.num; j++) {
        if (strlen(dnses.server[j]) > 0) {
            inet_pton(AF_INET, dnses.server[j], (void *)&addr);
            if ((ret = dns_set_global(addr)) < 0) {
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }
    }

    return 0;
}

int dc_hdl_node_radius(struct json_object *obj)
{
    struct radius_scheme_json json_cfg, cur_cfg;    
    struct node_pair_save paires[] = {
        {"scheme",             json_type_string, NULL, sizeof(json_cfg.config[0].name)},
        /* primary authentication server */
        {"pri_auth_ip",        json_type_string, NULL, sizeof(json_cfg.config[0].primary_auth_ip)},
        {"pri_auth_port",      json_type_int,    NULL, sizeof(json_cfg.config[0].primary_auth_port)},
        {"pri_auth_key_crypt", json_type_int,    NULL, sizeof(json_cfg.config[0].primary_acct_key_crypt)},
        {"pri_auth_key",       json_type_string, NULL, sizeof(json_cfg.config[0].primary_auth_key)},
        /* primary accounting server */    
        {"pri_acc_ip",         json_type_string, NULL, sizeof(json_cfg.config[0].primary_acct_ip)},
        {"pri_acc_port",       json_type_int,    NULL, sizeof(json_cfg.config[0].primary_acct_port)},
        {"pri_acc_key_crypt",  json_type_int,    NULL, sizeof(json_cfg.config[0].primary_acct_key_crypt)},
        {"pri_acc_key",        json_type_string, NULL, sizeof(json_cfg.config[0].primary_acct_key)},
        /* secondary authentication server */
        {"sec_auth_ip",        json_type_string, NULL, sizeof(json_cfg.config[0].secondary_auth_ip)},
        {"sec_auth_port",      json_type_int,    NULL, sizeof(json_cfg.config[0].secondary_auth_port)},
        {"sec_auth_key_crypt", json_type_int,    NULL, sizeof(json_cfg.config[0].secondary_auth_key_crypt)},
        {"sec_auth_key",       json_type_string, NULL, sizeof(json_cfg.config[0].secondary_auth_key)},
        /* secondary accounting server */    
        {"sec_acc_ip",         json_type_string, NULL, sizeof(json_cfg.config[0].secondary_acct_ip)},
        {"sec_acc_port",       json_type_int,    NULL, sizeof(json_cfg.config[0].secondary_acct_port)},
        {"sec_acc_key_crypt",  json_type_int,    NULL, sizeof(json_cfg.config[0].secondary_acct_key_crypt)},
        {"sec_acc_key",        json_type_string, NULL, sizeof(json_cfg.config[0].secondary_acct_key)}
    };   
    struct json_object *array;
    struct in_addr  ip;
    int i, j, ret, node = dc_node_radiuss;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&json_cfg, 0, sizeof(json_cfg));
    for(i = 0; i < json_object_array_length(obj); i++) {    
        paires[0].value = json_cfg.config[json_cfg.num].name;

        /* primary authentication server */
        paires[1].value = json_cfg.config[json_cfg.num].primary_auth_ip;
        paires[2].value = &(json_cfg.config[json_cfg.num].primary_auth_port);
        paires[3].value = &(json_cfg.config[json_cfg.num].primary_auth_key_crypt);
        paires[4].value = json_cfg.config[json_cfg.num].primary_auth_key;
        
        /* primary accountint server */
        paires[5].value = json_cfg.config[json_cfg.num].primary_acct_ip;
        paires[6].value = &(json_cfg.config[json_cfg.num].primary_acct_port);
        paires[7].value = &(json_cfg.config[json_cfg.num].primary_acct_key_crypt);
        paires[8].value = json_cfg.config[json_cfg.num].primary_acct_key;

        /* secondary authentication server */
        paires[9].value = json_cfg.config[json_cfg.num].secondary_auth_ip;
        paires[10].value = &(json_cfg.config[json_cfg.num].secondary_auth_port);
        paires[11].value = &(json_cfg.config[json_cfg.num].secondary_auth_key_crypt);
        paires[12].value = json_cfg.config[json_cfg.num].secondary_auth_key;
        
        /* secondary accountint server */
        paires[13].value = json_cfg.config[json_cfg.num].secondary_acct_ip;
        paires[14].value = &(json_cfg.config[json_cfg.num].secondary_acct_port);
        paires[15].value = &(json_cfg.config[json_cfg.num].secondary_acct_key_crypt);
        paires[16].value = json_cfg.config[json_cfg.num].secondary_acct_key;
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            return dc_error_code(ret, node, 0);
        }
        json_cfg.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }




    memset(&cur_cfg, 0, sizeof(cur_cfg));
    if ((ret = radius_scheme_get_all(&cur_cfg)) != 0) {
        nmsc_log("Get all radius scheme failed for %d.", ret);
        return dc_error_code(dc_error_commit_failed, node, ret);
    }

    for (i = 0; i < cur_cfg.num; i++) {
        for (j = 0; j < json_cfg.num; j++) {
            if (!strcmp(cur_cfg.config[i].name, json_cfg.config[j].name)) {
                break;
            }
        }
        if (j >= json_cfg.num) {
            if ((ret = radius_scheme_delete_force(cur_cfg.config[i].name)) != 0) {
                nmsc_log("Delete radius scheme %s failed for %d.", cur_cfg.config[i].name, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }
    }

    for (j = 0; j < json_cfg.num; j++) {
        for (i = 0; i < cur_cfg.num; i++) {
            if (!strcmp(cur_cfg.config[i].name, json_cfg.config[j].name)) {
                if (memcmp(&cur_cfg.config[i], &json_cfg.config[j], sizeof(cur_cfg.config[i]))) {
                    /* same name, but the config was changed */
                    if ((ret = radius_scheme_delete_force(cur_cfg.config[i].name)) != 0) {
                        nmsc_log("Delete radius scheme %s failed for %d.", cur_cfg.config[i].name, ret);
                        return dc_error_code(dc_error_commit_failed, node, ret);
                    }
                    
                    i = cur_cfg.num;
                }
                break;
            }
        }
        if (i >= cur_cfg.num) {
            struct radius_scheme_config_json *scheme = &(json_cfg.config[j]);
            if ((ret = radius_scheme_create(scheme->name)) != 0) {
                nmsc_log("Create radius scheme %s failed for %d.", scheme->name, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
            
            if (strlen(scheme->primary_auth_ip) > 0) {
                ip.s_addr = inet_addr(scheme->primary_auth_ip);
                if ((ret = radius_scheme_set_pri_auth(scheme->name, ip, scheme->primary_auth_port,
                    scheme->primary_auth_key_crypt, scheme->primary_auth_key)) != 0) {
                    nmsc_log("Set radius scheme %s primary auth failed for %d.", scheme->name, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }

            if (strlen(scheme->primary_acct_ip) > 0) {
                ip.s_addr = inet_addr(scheme->primary_acct_ip);
                if ((ret = radius_scheme_set_pri_acct(scheme->name, ip, scheme->primary_acct_port,
                    scheme->primary_acct_key_crypt, scheme->primary_acct_key)) != 0) {
                    nmsc_log("Set radius scheme %s primary acct failed for %d.", scheme->name, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }

            if (strlen(scheme->secondary_auth_ip) > 0) {
                ip.s_addr = inet_addr(scheme->secondary_auth_ip);
                if ((ret = radius_scheme_set_sec_auth(scheme->name, ip, scheme->secondary_auth_port,
                    scheme->secondary_auth_key_crypt, scheme->secondary_auth_key)) != 0) {
                    nmsc_log("Set radius scheme %s secondary auth failed for %d.", scheme->name, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }

            if (strlen(scheme->secondary_acct_ip) > 0) {
                ip.s_addr = inet_addr(scheme->secondary_acct_ip);
                if ((ret = radius_scheme_set_sec_acct(scheme->name, ip, scheme->secondary_acct_port,
                    scheme->secondary_acct_key_crypt, scheme->secondary_acct_key)) != 0) {
                    nmsc_log("Set radius scheme %s secondary acct failed for %d.", scheme->name, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }
        }
    }
    
    return 0;
}

static int dc_hdl_node_dhcpd_pool(struct json_object *obj)
{
#if !OK_PATCH
#define IP_BUF_LEN (sizeof("xxx.xxx.xxx.xxx") + 1)
#define DEFAULT_LEASE_TIME  1440 /* in minutes */
    struct pool_item {
        char name[33];
        char network[IP_BUF_LEN]; 
        char mask[IP_BUF_LEN];
        char min_addr[IP_BUF_LEN];
        char max_addr[IP_BUF_LEN];
        char gateway[IP_BUF_LEN];
        char dns[2][IP_BUF_LEN];
        char domain_name[IP_BUF_LEN];
        int lease;
    };
    struct pool_list {
        int num;
        struct pool_item *config;
    } pool_list;
    
    struct node_pair_save paires[] = {
        {"pool_name",   json_type_string, NULL, sizeof(((struct pool_item *)0)->name)},
        {"network",     json_type_string, NULL, sizeof(((struct pool_item *)0)->network)},
        {"mask",        json_type_string, NULL, sizeof(((struct pool_item *)0)->mask)},
        {"min_address", json_type_string, NULL, sizeof(((struct pool_item *)0)->min_addr)},
        {"max_address", json_type_string, NULL, sizeof(((struct pool_item *)0)->max_addr)},
        {"gateway",     json_type_string, NULL, sizeof(((struct pool_item *)0)->gateway)},
        {"dns1",        json_type_string, NULL, sizeof(((struct pool_item *)0)->dns[0])},
        {"dns2",        json_type_string, NULL, sizeof(((struct pool_item *)0)->dns[1])},
        {"domain_name", json_type_string, NULL, sizeof(((struct pool_item *)0)->domain_name)},
        {"lease",       json_type_int,    NULL, sizeof(((struct pool_item *)0)->lease)},
    };   
    struct json_object *array;
    int i, size, ret, node = dc_node_dhcpd;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    /* first: delete all existed dynamic pool list */
    dhcpd_pool_dynamic_delete_all();
    
    size = json_object_array_length(obj);
    if (size <= 0) {
        return 0;
    }

    /* second: get new dynamic pool config from NMS */
    memset(&pool_list, 0, sizeof(struct pool_list));
    pool_list.config = malloc(size * sizeof(struct pool_item));
    if (pool_list.config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(pool_list.config, 0, size * sizeof(struct pool_item));

    for(i = 0; i < size; i++) {    
        paires[0].value = pool_list.config[pool_list.num].name;
        paires[1].value = pool_list.config[pool_list.num].network;
        paires[2].value = pool_list.config[pool_list.num].mask;
        paires[3].value = pool_list.config[pool_list.num].min_addr;
        paires[4].value = pool_list.config[pool_list.num].max_addr;
        paires[5].value = pool_list.config[pool_list.num].gateway;
        paires[6].value = pool_list.config[pool_list.num].dns[0];
        paires[7].value = pool_list.config[pool_list.num].dns[1];
        paires[8].value = pool_list.config[pool_list.num].domain_name;
        paires[9].value = &(pool_list.config[pool_list.num].lease);
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            ret = dc_error_code(ret, node, 0);
            goto ERROR_OUT;
        }
        pool_list.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    /* third: Set new dynamic pool config */
    for (i = 0; i < pool_list.num; i++) {
        struct pool_item *iterm = (struct pool_item *)(pool_list.config + i);
        struct in_addr net, netmask, low, high, gw, dns;
        
        ret = dhcpd_pool_dynamic_create(iterm->name);
        if (ret != 0) {
            nmsc_log("Create dhcpd dynamic pool %s failed for %d.", iterm->name, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }

        inet_aton(iterm->network,  &net);
        inet_aton(iterm->mask,     &netmask);
        inet_aton(iterm->min_addr, &low);
        inet_aton(iterm->max_addr, &high);
        ret = dhcpd_pool_dynamic_set_network(iterm->name, net, netmask, low, high);
        if (ret != 0) {
            nmsc_log("Set dhcpd dynamic pool %s network %s:%s:%s:%s failed for %d.", 
                iterm->name, iterm->network, iterm->mask, iterm->min_addr, iterm->max_addr, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }

        if (iterm->gateway[0]) {
            inet_aton(iterm->gateway, &gw);
            ret = dhcpd_pool_dynamic_set_gateway(iterm->name, gw);
            if (ret != 0) {
                nmsc_log("Set dhcpd dynamic pool %s gatway %s failed for %d.", 
                    iterm->name, iterm->gateway, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        if (iterm->dns[0][0]) {
            inet_aton(iterm->dns[0], &dns);
            ret = dhcpd_pool_dynamic_set_dns(iterm->name, dns);
            if (ret != 0) {
                nmsc_log("Set dhcpd dynamic pool %s dns %s failed for %d.", 
                    iterm->name, iterm->dns[0], ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        if (iterm->dns[1][0]) {
            inet_aton(iterm->dns[1], &dns);
            ret = dhcpd_pool_dynamic_set_dns(iterm->name, dns);
            if (ret != 0) {
                nmsc_log("Set dhcpd dynamic pool %s dns %s failed for %d.", 
                    iterm->name, iterm->dns[1], ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        if (iterm->domain_name[0]) {
            ret = dhcpd_pool_dynamic_set_domain_name(iterm->name, iterm->domain_name);
            if (ret != 0) {
                nmsc_log("Set dhcpd dynamic pool %s domain name %s failed for %d.", 
                    iterm->name, iterm->domain_name, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        CHECK_DEFAULT_INTEGER_CONFIG(iterm->lease, DEFAULT_LEASE_TIME);
        ret = dhcpd_pool_dynamic_set_expired(iterm->name, iterm->lease);
        if (ret && ret != CMP_ERR_COMMIT_FAIL) {
            nmsc_log("Set dhcpd dynamic pool %s lease time %d minutes failed for %d.", 
                iterm->name, iterm->lease, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    
    ret = 0;
ERROR_OUT:
    if (pool_list.config) {
        free(pool_list.config);
    }
    return ret;

#undef IP_BUF_LEN

#else
    return 0;
#endif
}

static int dc_hdl_node_dhcpd_staticbind(struct json_object *obj)
{
#if !OK_PATCH
#define MAC_BUF_LEN (sizeof("xx:xx:xx:xx:xx:xx") + 1)
#define IP_BUF_LEN (sizeof("xxx.xxx.xxx.xxx") + 1)
    struct bind_item {
        char mac[MAC_BUF_LEN];
        char ip[IP_BUF_LEN];
    };
    struct bind_list {
        int num;
        struct bind_item *config;
    } bind_list;
    struct node_pair_save paires[] = {
        {"macaddress", json_type_string, NULL, sizeof(((struct bind_item *)0)->mac)},
        {"ip",         json_type_string, NULL, sizeof(((struct bind_item *)0)->ip)},
    };   
    struct json_object *array;
    int i, size, ret, node = dc_node_dhcpd;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    /* first: delete all existed static bind list */
    dhcpd_pool_static_del_ip_all();

    size = json_object_array_length(obj);
    if (size <= 0) {
        return 0;
    }

    memset(&bind_list, 0, sizeof(struct bind_list));
    bind_list.config = malloc(size * sizeof(struct bind_item));
    if (bind_list.config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(bind_list.config, 0, size * sizeof(struct bind_item));

    /* second: get new static bind list from NMS */
    for(i = 0; i < size; i++) {    
        paires[0].value = bind_list.config[bind_list.num].mac;
        paires[1].value = bind_list.config[bind_list.num].ip;
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            ret = dc_error_code(ret, node, 0);
            goto ERROR_OUT;
        }
        bind_list.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    /* third: add new static bind list */
    for (i = 0; i < bind_list.num; i++) {
        struct bind_item *iterm = (struct bind_item *)(bind_list.config + i);
        struct in_addr ip;
        char mac[6];

        inet_aton(iterm->ip, &ip);
        if_ether_aton(iterm->mac, (unsigned char *)mac);
        ret = dhcpd_pool_static_add_ip(mac, ip);
        if (ret != 0) {
            nmsc_log("Set dhcpd static bind %s:%s failed for %d.", 
                iterm->mac, iterm->ip, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    
    ret = 0;
ERROR_OUT:
    if (bind_list.config) {
        free(bind_list.config);
    }
    return ret;
    
#undef MAC_BUF_LEN
#undef IP_BUF_LEN
#else
    return 0;
#endif
}

static int dc_hdl_node_dns_proxy(struct json_object *obj)
{
#if !OK_PATCH
    int enable = -1, ret, node = dc_node_dns_proxy;
    struct node_pair_save pair = {
        .key   = "enable",
        .type  = json_type_int,
        .value = &enable,
        .size  = sizeof(enable),
    };
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);

    if (enable >= 0) {
        if (enable) {
            ret = DNSMASQ_ProcEnable();
        }
        else {
            ret = DNSMASQ_ProcDisable();
        }
        if (ret) {
            nmsc_log("%s dns proxy failed for %d.", enable ? "Enable":"Disable", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    
#endif
    return 0;
}

static int dc_hdl_node_route_forward(struct json_object *obj)
{
#if !OK_PATCH
    int enable = -1, ret, node = dc_node_route_forward;
    struct node_pair_save pair = {
        .key   = "route_forward",
        .type  = json_type_int,
        .value = &enable,
        .size  = sizeof(enable),
    };
    
    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);

    if (enable >= 0) {
        if (enable) {
            ret = route_set_global_forward(1);
        }
        else {
            ret = route_set_global_forward(0);
        }
        if (ret) {
            nmsc_log("%s route forward failed for %d.", enable ? "Enable":"Disable", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }
    
#endif
    return 0;
}

int dc_hdl_node_network(struct json_object *obj)
{
    /* not supported yet */
#if !OK_PATCH
    struct subnode_handler {
        char *key;
        int (*subnode_handler)(struct json_object *obj);
    };

    struct subnode_handler system_subnodes[] = {
        {"dhcp_server_pools",    dc_hdl_node_dhcpd_pool},
        {"dhcp_server_bindings", dc_hdl_node_dhcpd_staticbind},
        {"dns_proxy",            dc_hdl_node_dns_proxy},
        {"route_forward",        dc_hdl_node_route_forward}
    };
    int i, obj_saved, ret, node = dc_node_dhcpd;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    json_object_object_foreach(obj, key, val) {
        obj_saved = 0;
        for (i = 0; i < sizeof(system_subnodes)/sizeof(system_subnodes[0]); i++) {
            if (!strcasecmp(key, system_subnodes[i].key)) {
                obj_saved = 1;
                if ((ret = system_subnodes[i].subnode_handler(val)) != 0) {
                    return ret;
                }
            }
        }
        if (!obj_saved) {
            nmsc_log("Unknow json obj :%s", key);
        }
    }

    /* fix bug 3337 */
    dhcpd_apply();

#endif
    return 0;
}

int dc_hdl_node_ethif(struct json_object *obj)
{
    /* not supported yet */
#if !OK_PATCH
#define MAX_ETH_IF_NUM  16
    struct ethif {
        char name[SYS_INTF_NAME_SIZE + 1];
        int dhcpd_enabled;
        int mode;
    };
    struct ethif_list {
        int num;
        struct ethif config[MAX_ETH_IF_NUM];
    };

    struct ethif_list ethifes;
    struct node_pair_save paires[] = {
        {"name",         json_type_string,    NULL, sizeof(ethifes.config[0].name)},
        {"dhcpd_enable", json_type_int,       NULL, sizeof(ethifes.config[0].dhcpd_enabled)},
        {"mode",         json_type_int,       NULL, sizeof(ethifes.config[0].mode)},
    }; 
    struct json_object *array;
    int i, j, ret, size, count, node = dc_node_ethif;
    struct if_attrs * attrs = NULL;    
    struct if_address * addrs = NULL;  
    struct netifd_link_stats * stats = NULL;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&ethifes, 0, sizeof(ethifes));
    size = json_object_array_length(obj);
    for(i = 0; i < json_object_array_length(obj); i++) {    
        paires[0].value = ethifes.config[ethifes.num].name;
        paires[1].value = &(ethifes.config[ethifes.num].dhcpd_enabled);
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            return dc_error_code(ret, node, 0);
        }
        ethifes.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    ret = netifd_get_all_interfaces((IF_PHYTYPE_ETH | IF_PHYTYPE_GIGA_ETH), &count, &attrs, &addrs, &stats);
    if (ret) {
        nmsc_log("List all interface failed for %d.", ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        goto ERROR_OUT;
    }

    for (i = 0; i < count; i++) {
        /* for eth or geth interface only */
        if (attrs[i].type != IF_PHYTYPE_ETH && attrs[i].type != IF_PHYTYPE_GIGA_ETH) {
            continue;
        }

        if (!if_is_runon_layer_3(attrs[i].status)) {
            continue;
        }

        for (j = 0; j < ethifes.num; j++) {
            if (strcmp(attrs[i].name, ethifes.config[j].name) == 0) {
                break;
            }
        }

        if (j >= ethifes.num) {
            if (netifd_get_interface_enabled(attrs[i].name)) {
                netifd_set_enable(attrs[i].name, 0);
                ret = netifd_set_linkmode(attrs[i].name, IF_LINKMODE_BRIDGE);
                netifd_set_enable(attrs[i].name, 1);
            }
            else {
                ret = netifd_set_linkmode(attrs[i].name, IF_LINKMODE_BRIDGE);
            }

            if (ret && ret != CMP_ERR_COMMIT_FAIL && ret != CMP_ERR_NO_ACCESS) {
                nmsc_log("Set interface %s to bridge mode failed for %d.", attrs[i].name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
            
            nat_set_enable(attrs[i].name, 0);
        }
    }

    for (j = 0; j < ethifes.num; j++) {
        for (i = 0; i < count; i++) {
            if (strcmp(attrs[i].name, ethifes.config[j].name) == 0) {
                break;
            }
        }

        if (i >= count) {
            nmsc_log("Interface %s does not existed.", ethifes.config[j].name);
            ret = dc_error_code(dc_error_commit_failed, node, -1);
            goto ERROR_OUT;
        }
        
        if (!if_is_runon_layer_3(attrs[i].status)) {
            if (netifd_get_interface_enabled(attrs[i].name)) {
                netifd_set_enable(attrs[i].name, 0);
                ret = netifd_set_linkmode(attrs[i].name, IF_LINKMODE_ROUTE);
                netifd_set_enable(attrs[i].name, 1);
            }
            else {
                ret = netifd_set_linkmode(attrs[i].name, IF_LINKMODE_ROUTE);
            }

            if (ret && ret != CMP_ERR_COMMIT_FAIL) {
                nmsc_log("Set interface %s to bridge mode failed for %d.", attrs[i].name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (ethifes.config[j].mode == 1) { /* enable NAT from NMS */
            ret = nat_set_enable(attrs[i].name, 1);
            if (ret && ret != CMP_ERR_COMMIT_FAIL) {
                nmsc_log("Enable NAT on interface %s failed for %d.", attrs[i].name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        nmsc_delay_op_new(nmsc_delay_op_dhcpd_ethif, &(ethifes.config[j]), sizeof(struct ethif));
    }
    
    ret = 0;
ERROR_OUT:
    if (attrs) {            
        free(attrs);        
    }        
    
    if (addrs) {           
        free(addrs);        
    }        
    
    if (stats) {            
        free(stats);        
    }
    return ret;
#else
    return 0;
#endif
}

int dc_hdl_node_vlan(struct json_object *obj)
{
    struct vlan {
        int   id;
        char name[33];
        char desc[33];
    };
    struct vlan_list {
        int num;
        struct vlan config[VLAN_MAX_COUNT];
    } ;
    struct vlan_list vlanes;
    struct node_pair_save paires[] = {
        {"id",    json_type_int,    NULL, sizeof(vlanes.config[0].id)},
        {"name",  json_type_string, NULL, sizeof(vlanes.config[0].name)},
        {"desc",  json_type_string, NULL, sizeof(vlanes.config[0].desc)}
    };   
    struct json_object *array;
    int i, j, ret, *idlist, listnum, node = dc_node_vlans;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&vlanes, 0, sizeof(vlanes));
    for(i = 0; i < json_object_array_length(obj); i++) {    
        paires[0].value = &(vlanes.config[vlanes.num].id);
        paires[1].value = vlanes.config[vlanes.num].name;
        paires[2].value = vlanes.config[vlanes.num].desc;
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            return dc_error_code(ret, node, 0);
        }
        vlanes.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }






    listnum = vlan_list_id(&idlist);
    if (listnum > 0) {
        for (i = 0; i < listnum; i++) {
            for (j = 0; j < vlanes.num; j++) {
                if (idlist[i] == vlanes.config[j].id) {
                    break;
                }
            }
            /* existing vlan not in json_cfg, so delete it */
            if (j >= vlanes.num) {
                if ((ret = vlan_destroy(idlist[i], idlist[i])) != 0) {
                    nmsc_log("Delete vlan %d failed for %d.", idlist[i], ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    goto ERROR_OUT;
                }
            }
        }
    }

    for (j = 0; j < vlanes.num; j++) {
        for (i = 0; i < listnum; i++) {
            if (idlist[i] == vlanes.config[j].id) {
                break;
            }
        }

        /* new json_cfg vlan, need create it */
        if (i >= listnum) {
            ret = vlan_create(vlanes.config[j].id, vlanes.config[j].id);
            if (ret != 0) {
                nmsc_log("Create vlan %d failed for %d.", vlanes.config[j].id, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }
        if (is_default_string_config(vlanes.config[j].name)) {
            vlan_undo_name(vlanes.config[j].id);
        }
        else {
            vlan_set_name(vlanes.config[j].id, vlanes.config[j].name);
        }

        if (is_default_string_config(vlanes.config[j].desc)) {
            vlan_undo_desc(vlanes.config[j].id);
        }
        else {
            vlan_set_desc(vlanes.config[j].id, vlanes.config[j].desc);
        }
    }
    ret = 0;
ERROR_OUT:    
    vlan_list_id_free(&idlist);

    return ret;
}

static int dc_nat_vlan_reserved(struct vlan_showinfo *info)
{
#if !OK_PATCH
    int i;

    for (i = 0; i < info->num; i++) {
        if (nat_get_enable(info->nodes[i].ifname)) {
            nmsc_log("Interface %s nat enabled, do nothing.", 
                        info->nodes[i].name);
            memmove(&info->nodes[i], &info->nodes[i + 1], (info->num - i - 1) * sizeof(info->nodes[0]));
            info->num--;
            i--;
        }
    }

    return info->num;
#else
    return 0;
#endif
}

int dc_hdl_node_vlan_interface(struct json_object *obj)
{
#if !OK_PATCH
    /* not supported */
#define DEFAULT_DHCPD_ENABLE    0   /* default disable */
    struct vlan_interface {
        int  id;
        char desc[33];
        int dhcpd_enable;
    };
    struct vlan_interface_list {
        int num;
        struct vlan_interface config[16];
    } ;
    struct vlan_interface_list vlan_interfaces;
    struct node_pair_save paires[] = {
        {"id",           json_type_int,    NULL, sizeof(vlan_interfaces.config[0].id)},
        {"desc",         json_type_string, NULL, sizeof(vlan_interfaces.config[0].desc)},
        {"dhcpd_enable", json_type_int,    NULL, sizeof(vlan_interfaces.config[0].dhcpd_enable)},
    };   
    struct json_object *array;
    struct vlan_showinfo info;
    int i, j, ret, num, node = dc_node_vlan_interfaces;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&vlan_interfaces, 0, sizeof(vlan_interfaces));
    for(i = 0; i < json_object_array_length(obj); i++) {    
        paires[0].value = &(vlan_interfaces.config[vlan_interfaces.num].id);
        paires[1].value = vlan_interfaces.config[vlan_interfaces.num].desc;
        paires[2].value = &(vlan_interfaces.config[vlan_interfaces.num].dhcpd_enable);
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
            return dc_error_code(ret, node, 0);
        }
        vlan_interfaces.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    num = vlan_list_all(&info);
    num = dc_nat_vlan_reserved(&info);
    for (i = 0; i < num; i++) {
        if (info.nodes[i].is_routedif == 1) {
            for (j = 0; j < vlan_interfaces.num; j++) {
                if (info.nodes[i].id == vlan_interfaces.config[j].id) {
                    break;
                }
            }
            if (j >= vlan_interfaces.num) {
                if ((ret = vlan_destroy_interface(info.nodes[i].id, info.nodes[i].id)) != 0) {
                    nmsc_log("Delete the vlan %d interface failed for %d.", 
                        info.nodes[i].id, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }
        }
    }

    for (j = 0; j < vlan_interfaces.num; j++) {        
        for (i = 0; i < num; i++) {
            if (info.nodes[i].id == vlan_interfaces.config[j].id) {
                break;
            }
        }
        if (i >= num) {
            /* vlan does not exist */
            nmsc_log("VLAN %d does not exist.", vlan_interfaces.config[j].id);
            return dc_error_code(dc_error_obj_data, node, 0);
        }
        if (info.nodes[i].is_routedif != 1) {
            if ((ret = vlan_create_interface(vlan_interfaces.config[j].id, 
                vlan_interfaces.config[j].id)) != 0) {
                nmsc_log("Create the vlan %d interface failed for %d.", 
                        vlan_interfaces.config[j].id, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }
        if (is_default_string_config(vlan_interfaces.config[j].desc)) {
            vlan_interface_undo_desc(vlan_interfaces.config[j].id);
        }
        else {
            vlan_interface_set_desc(vlan_interfaces.config[j].id, vlan_interfaces.config[j].desc);
        }
        
        CHECK_DEFAULT_INTEGER_CONFIG(vlan_interfaces.config[j].dhcpd_enable, DEFAULT_DHCPD_ENABLE);

        nmsc_delay_op_new(nmsc_delay_op_dhcpd, &(vlan_interfaces.config[j]), sizeof(struct vlan_interface));
    }
    vlan_list_all_free(&info);

#endif
    return 0;    
}

static int dc_hdl_node_alg(struct json_object *obj)
{
#if !OK_PATCH
    struct alg_enable{
        int tftp;
        int ftp;
        int pptp;
        int irc;
        int sip;
        int h323;
        int snmp;
        int netbios;
    };
    struct alg_enable alg_config = {1, 1, 1, 1, 1, 1, 1, 1}; /* default all enabled */
    struct node_pair_save paires[] = {
        {"TFTP",     json_type_int, &(alg_config.tftp),    sizeof(alg_config.tftp)},
        {"FTP",      json_type_int, &(alg_config.ftp),     sizeof(alg_config.ftp)},
        {"PPTP",     json_type_int, &(alg_config.pptp),    sizeof(alg_config.pptp)},
        {"IRC",      json_type_int, &(alg_config.irc),     sizeof(alg_config.irc)},
        {"SIP",      json_type_int, &(alg_config.sip),     sizeof(alg_config.sip)},
        {"H323",     json_type_int, &(alg_config.h323),    sizeof(alg_config.h323)},
        {"SNMP",     json_type_int, &(alg_config.snmp),    sizeof(alg_config.snmp)},
        {"NETBIOS",  json_type_int, &(alg_config.netbios), sizeof(alg_config.netbios)}
    };   
    int ret = 0, node = dc_node_alg;

    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
        return dc_error_code(ret, node, 0);
    }
    log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));

#define ALG_ENABLE(ident, enable, reason) \
    do {\
        if (reason) { \
            nmsc_log("Set alg %s %d failed for %d.", (ident), (enable), (reason)); \
            return (dc_error_code(dc_error_commit_failed, node, (reason))); \
        } \
    } while(0)

    ret = nat_alg_set_enable(NAT_ALG_TFTP, alg_config.tftp);
    ALG_ENABLE("TFTP", alg_config.tftp, ret);

    ret = nat_alg_set_enable(NAT_ALG_FTP, alg_config.ftp);
    ALG_ENABLE("FTP", alg_config.ftp, ret);

    ret = nat_alg_set_enable(NAT_ALG_PPTP, alg_config.pptp);
    ALG_ENABLE("PPTP", alg_config.pptp, ret);

#endif
    return 0;
}

int dc_hdl_node_nat(struct json_object *obj)
{
    /* not supported yet */
#if !OK_PATCH
    struct subnode_handler {
        char *key;
        int (*subnode_handler)(struct json_object *obj);
    };

    struct subnode_handler system_subnodes[] = {
        {"alg", dc_hdl_node_alg},
    };
    int i, obj_saved, ret, node = dc_node_system;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    json_object_object_foreach(obj, key, val) {
        obj_saved = 0;
        for (i = 0; i < sizeof(system_subnodes)/sizeof(system_subnodes[0]); i++) {
            if (!strcasecmp(key, system_subnodes[i].key)) {
                obj_saved = 1;
                if ((ret = system_subnodes[i].subnode_handler(val)) != 0) {
                    return ret;
                }
            }
        }
        if (!obj_saved) {
            nmsc_log("Unsolved the nat key: %s", key);
        }
    }

#endif
    return 0;

}

int dc_hdl_node_dialer(struct json_object *obj)
{
    struct dialer {
        char name[33];
        int  dial_type;
        char sta_ip[16];
        char sta_netmask[16];
        char gw[16];
        char pppoe_user[65];
        char pppoe_pass[65];
        char pppoe_acname[65];
        char pppoe_servicesname[65];
        int mtu;
    };
    struct dialer_list {
        int num;
        struct dialer config[VLAN_MAX_COUNT];
    } ;
    struct dialer_list dialeres;
    struct node_pair_save paires[] = {
        {"name",         json_type_string, NULL, sizeof(dialeres.config[0].name)},
        {"type",         json_type_int,    NULL, sizeof(dialeres.config[0].dial_type)},
        {"ip",           json_type_string, NULL, sizeof(dialeres.config[0].sta_ip)},
        {"netmask",      json_type_string, NULL, sizeof(dialeres.config[0].sta_netmask)},
        {"gateway",      json_type_string, NULL, sizeof(dialeres.config[0].gw)},
        {"username",     json_type_string, NULL, sizeof(dialeres.config[0].pppoe_user)},
        {"password",     json_type_string, NULL, sizeof(dialeres.config[0].pppoe_pass)},
        {"mtu",          json_type_int,    NULL, sizeof(dialeres.config[0].mtu)},
        {"service_name", json_type_string, NULL, sizeof(dialeres.config[0].pppoe_servicesname)},
        {"ac_name",      json_type_string, NULL, sizeof(dialeres.config[0].pppoe_acname)},
    };   
    struct json_object *array;
    char interface_name[32];
    int i, j, id, ret, node = dc_node_dialers;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&dialeres, 0, sizeof(dialeres));
    for(i = 0; i < json_object_array_length(obj); i++) {    
        paires[0].value = dialeres.config[dialeres.num].name;
        paires[1].value = &(dialeres.config[dialeres.num].dial_type);
        paires[2].value = dialeres.config[dialeres.num].sta_ip;
        paires[3].value = dialeres.config[dialeres.num].sta_netmask;
        paires[4].value = dialeres.config[dialeres.num].gw;
        paires[5].value = dialeres.config[dialeres.num].pppoe_user;
        paires[6].value = dialeres.config[dialeres.num].pppoe_pass;
        paires[7].value = &(dialeres.config[dialeres.num].mtu);
        paires[8].value = dialeres.config[dialeres.num].pppoe_servicesname;
        paires[9].value = dialeres.config[dialeres.num].pppoe_acname;
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
            return dc_error_code(ret, node, 0);
        }
        dialeres.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }



    vlan_interface_info *info = NULL;
    if ((ret = vlan_get_dialer_info(&info)) != 0 || info == NULL) {
        nmsc_log("Get dialer failed for %d.", ret);
        return dc_error_code(dc_error_commit_failed, node, ret);
    }

    for (i = 0; i < info->count; i++) {
        for (j = 0; j < dialeres.num; j++) {
            ret = sscanf(dialeres.config[j].name, VLAN_INTERFACE_PREFIX"%d", &id);
            if (ret == 1 && info->info[i].id == id) {
                break;
            }
        }
        /* existing vlan interface setting is not in config, undo it */
        if (j >= dialeres.num && info->info[i].type != IP_TYPE_NONE) {
            vlan_get_ifname(info->info[i].id, interface_name);
            dialer_undo(interface_name, info->info[i].type);
        }
    }

    /* go through config and setting it */
    for (j = 0; j < dialeres.num; j++) {
        ret = 0;
        sscanf(dialeres.config[j].name, VLAN_INTERFACE_PREFIX"%d", &id);
        vlan_get_ifname(id, interface_name);
        if (dialeres.config[j].dial_type == IP_TYPE_DHCP) { /* DHCP */
            ret = dialer_set_dhcp(interface_name);
        }
        else if (dialeres.config[j].dial_type == IP_TYPE_STATIC) { /* STATIC */ 
            ret = dialer_static_set_ipv4(interface_name, 
                dialeres.config[j].sta_ip, dialeres.config[j].sta_netmask, dialeres.config[j].gw);
        }
        else { /* NONE */
            /* try to undo dialer all */
            dialer_undo(interface_name, IP_TYPE_DHCP);
            dialer_undo(interface_name, IP_TYPE_STATIC);
        }
        if (ret) {
            nmsc_log("Set the interface %s dialer type %d failed for %d.", 
                dialeres.config[j].name, dialeres.config[j].dial_type, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            break;
        }
    }

    free(info);
    ret = 0;
    return ret;
}

static int dc_parse_node_service_template(struct json_object *obj, 
    void *jsoncfg)
{
    struct service_templates *service_templates = (struct service_templates *)jsoncfg;
    struct service_template_json service_template;
    struct node_pair_save paires[] = {
        {"ssid",                  json_type_string, NULL, sizeof(service_template.ssid)},
        {"ssid_hide",             json_type_int,    NULL, sizeof(service_template.beacon_ssid_hide)},
        {"client_max",            json_type_int,    NULL, sizeof(service_template.client_max)},
        {"auth",                  json_type_int,    NULL, sizeof(service_template.auth)},
        {"cipher",                json_type_int,    NULL, sizeof(service_template.cipher)},
        {"key_crypt",             json_type_int,    NULL, sizeof(service_template.key_crypt)},
        {"key_type",              json_type_int,    NULL, sizeof(service_template.key_type)},
        {"key",                   json_type_string, NULL, sizeof(service_template.key)},
        {"wep_key_slot",          json_type_int,    NULL, sizeof(service_template.wep_key_slot)},
        {"radius_scheme",         json_type_string, NULL, sizeof(service_template.radius_scheme)},            
        {"gtk_enabled",           json_type_int,    NULL, sizeof(service_template.gtk_enabled)},  
        {"gtk_lifetime",          json_type_int,    NULL, sizeof(service_template.gtk_lifetime)},  
        {"ptk_enabled",           json_type_int,    NULL, sizeof(service_template.ptk_enabled)},  
        {"ptk_lifetime",          json_type_int,    NULL, sizeof(service_template.ptk_lifetime)}, 
        {"portal_scheme",         json_type_string, NULL, sizeof(service_template.portal_scheme)},
        {"uplink_limit_enable",   json_type_int,    NULL, sizeof(service_template.uplink_limit_enable)},    
        {"uplink_limit_mode",     json_type_int,    NULL, sizeof(service_template.uplink_limit_mode)}, 
        {"uplink_limit_rate",     json_type_int,    NULL, sizeof(service_template.uplink_limit_rate)}, 
        {"downlink_limit_enable", json_type_int,    NULL, sizeof(service_template.downlink_limit_enable)}, 
        {"downlink_limit_mode",   json_type_int,    NULL, sizeof(service_template.downlink_limit_mode)}, 
        {"downlink_limit_rate",   json_type_int,    NULL, sizeof(service_template.downlink_limit_rate)},  
        {"mac_acl_scheme",        json_type_string, NULL, sizeof(service_template.acl_scheme)},
        {"time_limit_scheme",     json_type_string, NULL, sizeof(service_template.time_scheme)}, 
        {"m2u_enable",            json_type_int,    NULL, sizeof(service_template.m2u_enable)}, 
        {"ts_enable",             json_type_int,    NULL, sizeof(service_template.ts_enable)}, 
        {"ts_ip",                 json_type_string, NULL, sizeof(service_template.ts_ip)}, 
        {"ts_netmask",            json_type_string, NULL, sizeof(service_template.ts_netmask)}, 
#if OK_PATCH
        {"bandwidth_priority",    json_type_int,    NULL, sizeof(service_template.bandwidth_priority)}, 
        {"client_isolation",      json_type_int,    NULL, sizeof(service_template.client_isolation)}, 
        {"type",                  json_type_int,    NULL, sizeof(service_template.type)}, 
        {"ppsk_keys_url",         json_type_string, NULL, sizeof(service_template.ppsk_keys_url)}, 
        {"enabled",               json_type_int,    NULL, sizeof(service_template.enabled)}, 
#endif
    };   
    struct json_object *array;
    int i, j, ret, size, node = dc_node_service_template;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    if (size <= 0) {
        service_templates->num = 0;
        service_templates->config = NULL;
        return 0;
    }

    service_templates->config = malloc(size * sizeof(struct service_template_json));
    if (service_templates->config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(service_templates->config, 0, size * sizeof(struct service_template_json));
    
    for(i = 0; i < size; i++) {   
        j = 0;
        paires[j++].value = service_templates->config[service_templates->num].ssid;
        paires[j++].value = &(service_templates->config[service_templates->num].beacon_ssid_hide);
        paires[j++].value = &(service_templates->config[service_templates->num].client_max);
        paires[j++].value = &(service_templates->config[service_templates->num].auth);
        paires[j++].value = &(service_templates->config[service_templates->num].cipher);
        paires[j++].value = &(service_templates->config[service_templates->num].key_crypt);
        paires[j++].value = &(service_templates->config[service_templates->num].key_type);
        paires[j++].value = service_templates->config[service_templates->num].key;
        paires[j++].value = &(service_templates->config[service_templates->num].wep_key_slot);
        paires[j++].value = service_templates->config[service_templates->num].radius_scheme;
        paires[j++].value = &(service_templates->config[service_templates->num].gtk_enabled);
        paires[j++].value = &(service_templates->config[service_templates->num].gtk_lifetime);
        paires[j++].value = &(service_templates->config[service_templates->num].ptk_enabled);
        paires[j++].value = &(service_templates->config[service_templates->num].ptk_lifetime);
        paires[j++].value = service_templates->config[service_templates->num].portal_scheme;
        paires[j++].value = &(service_templates->config[service_templates->num].uplink_limit_enable);
        paires[j++].value = &(service_templates->config[service_templates->num].uplink_limit_mode);
        paires[j++].value = &(service_templates->config[service_templates->num].uplink_limit_rate);
        paires[j++].value = &(service_templates->config[service_templates->num].downlink_limit_enable);
        paires[j++].value = &(service_templates->config[service_templates->num].downlink_limit_mode);
        paires[j++].value = &(service_templates->config[service_templates->num].downlink_limit_rate);
        paires[j++].value = service_templates->config[service_templates->num].acl_scheme;
        paires[j++].value = service_templates->config[service_templates->num].time_scheme;
        paires[j++].value = &(service_templates->config[service_templates->num].m2u_enable);
        paires[j++].value = &(service_templates->config[service_templates->num].ts_enable);
        paires[j++].value = service_templates->config[service_templates->num].ts_ip;
        paires[j++].value = service_templates->config[service_templates->num].ts_netmask;
#if OK_PATCH
        paires[j++].value = &(service_templates->config[service_templates->num].bandwidth_priority);
        paires[j++].value = &(service_templates->config[service_templates->num].client_isolation);
        paires[j++].value = &(service_templates->config[service_templates->num].type);
        paires[j++].value = &(service_templates->config[service_templates->num].ppsk_keys_url);
        paires[j++].value = &(service_templates->config[service_templates->num].enabled);
#endif
        
        service_templates->config[service_templates->num].uplink_limit_enable = -1;
        service_templates->config[service_templates->num].downlink_limit_enable = -1;

        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
            free(service_templates->config);
            service_templates->config = NULL;
            return dc_error_code(ret, node, 0);
        }
        service_templates->num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    return 0;
}

static int dc_parse_node_radio(struct json_object *obj, void *jsoncfg)
{
    struct radio_list *radios = (struct radio_list *)jsoncfg;

    struct node_pair_save paires[] = {
        {"id",                      json_type_int,      NULL, sizeof(radios->config[0].id)},
        {"channel",                 json_type_int,      NULL, sizeof(radios->config[0].channel)},
        {"max_power",               json_type_int,      NULL, sizeof(radios->config[0].max_power)},
        {"mode",                    json_type_int,      NULL, sizeof(radios->config[0].mode)},
        {"dot11nonly",              json_type_int,      NULL, sizeof(radios->config[0].dot11nonly)},
        {"a_mpdu",                  json_type_int,      NULL, sizeof(radios->config[0].ampdu)},
        {"beacon_interval",         json_type_int,      NULL, sizeof(radios->config[0].beacon_interval)},
        {"distance",                json_type_int,      NULL, sizeof(radios->config[0].distance)},
        {"dtim",                    json_type_int,      NULL, sizeof(radios->config[0].dtim)},
        {"fragment_threshold",      json_type_int,      NULL, sizeof(radios->config[0].fragment_threshold)},
        {"preamble",                json_type_int,      NULL, sizeof(radios->config[0].preamble)},            
        {"protection_mode",         json_type_int,      NULL, sizeof(radios->config[0].protection_mode)},  
        {"rts_threshold",           json_type_int,      NULL, sizeof(radios->config[0].rts_threshold)},  
        {"short_gi",                json_type_int,      NULL, sizeof(radios->config[0].short_gi)}, 
        {"bandwidth",               json_type_int,      NULL, sizeof(radios->config[0].bandwidth)},                 
        {"rssi_access",             json_type_int,      NULL, sizeof(radios->config[0].rssi_access)},
        {"rssi_access_threshold",   json_type_int,      NULL, sizeof(radios->config[0].rssi_access_threshold)},    
        {"dot11aconly",             json_type_int,      NULL, sizeof(radios->config[0].dot11aconly)},
        {"broadcast_rate_limit",    json_type_int,      NULL, sizeof(radios->config[0].bcst_ratelimt)},
        {"broadcast_cir",           json_type_int,      NULL, sizeof(radios->config[0].bcst_ratelimt_cir)},
        {"Broadcast_cbs",           json_type_int,      NULL, sizeof(radios->config[0].bcst_ratelimt_cbs)},
        {"airtime_fairness",        json_type_int,      NULL, sizeof(radios->config[0].air_time_fairness)},
        {"air_scan",                json_type_string,   NULL, sizeof(radios->config[0].air_scan)},
#if OK_PATCH
        {"client_max",              json_type_int,      NULL, sizeof(radios->config[0].client_max)},
#endif
    }; 
    struct node_pair_save subpaires[] = {
        {"ssid_names",  json_type_string, NULL, sizeof(radios->config[0].mbss[0].ssidname)},
    };
    
    struct json_object *array, *subarray;
    int i, j, size, subsize, ret, node = dc_node_radio;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    radios->num = 0;
    for(i = 0; i < size && i < MAX_RADIO_COUNT; i++) {    
        paires[0].value = &(radios->config[radios->num].id);
        paires[1].value = &(radios->config[radios->num].channel);
        paires[2].value = &(radios->config[radios->num].max_power);
        paires[3].value = &(radios->config[radios->num].mode);
        paires[4].value = &(radios->config[radios->num].dot11nonly);
        paires[5].value = &(radios->config[radios->num].ampdu);
        paires[6].value = &(radios->config[radios->num].beacon_interval);
        paires[7].value = &(radios->config[radios->num].distance);
        paires[8].value = &(radios->config[radios->num].dtim);
        paires[9].value = &(radios->config[radios->num].fragment_threshold);
        paires[10].value = &(radios->config[radios->num].preamble);
        paires[11].value = &(radios->config[radios->num].protection_mode);
        paires[12].value = &(radios->config[radios->num].rts_threshold);
        paires[13].value = &(radios->config[radios->num].short_gi);
        paires[14].value = &(radios->config[radios->num].bandwidth);
        paires[15].value = &(radios->config[radios->num].rssi_access);
        paires[16].value = &(radios->config[radios->num].rssi_access_threshold);
        paires[17].value = &(radios->config[radios->num].dot11aconly);
        /* added for broadcast ratelimit */
        radios->config[radios->num].bcst_ratelimt = -1; /* flag for set nothing about broadcast ratelimit */
        paires[18].value = &(radios->config[radios->num].bcst_ratelimt);
        paires[19].value = &(radios->config[radios->num].bcst_ratelimt_cir);
        paires[20].value = &(radios->config[radios->num].bcst_ratelimt_cbs);
        /* added for atf */
        radios->config[radios->num].air_time_fairness = -1;
        paires[21].value = &(radios->config[radios->num].air_time_fairness);
        /* added for wlan scan */
        paires[22].value =  radios->config[radios->num].air_scan;
#if OK_PATCH
        paires[23].value = &(radios->config[radios->num].client_max);
#endif
        
        
        array = json_object_array_get_idx(obj, i);
        json_object_object_foreach(array, key, val) {
            if (json_object_get_type(val) == json_type_array) {
                subsize = json_object_array_length(val);
                for(j = 0; j < subsize && j < MAX_MBSS_COUNT; j++) { 
                    subpaires[0].value = radios->config[radios->num].mbss[j].ssidname;
                
                    subarray = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    radios->config[radios->num].mbss_num = j + 1;
                    log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                }
            }
            else {
                for (j = 0; j < sizeof(paires)/sizeof(paires[0]); j++) {
                    
                    if (!strcasecmp(key, paires[j].key)) {
                        if ((ret = dc_hdl_node_default(val, &(paires[j]), 1)) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_pair(paires[j]);
                    }
                }
            }
        }
        radios->num++;
    }

    return 0;
}

static int dc_parse_node_portal_scheme(struct json_object *obj, 
    void *jsoncfg)
{
    struct portal_schemes *portal_schemes = (struct portal_schemes *)jsoncfg;
    struct portal_scheme_cfg *portal_scheme = (struct portal_scheme_cfg *)0;
    struct node_pair_save paires[] = {
        {"scheme",          json_type_string, NULL, sizeof(portal_scheme->scheme_name)},
        {"enable",          json_type_int,    NULL, sizeof(portal_scheme->enable)},
        {"url",             json_type_string, NULL, sizeof(portal_scheme->uri_path)},
        {"Auth_ip",         json_type_int,    NULL, sizeof(portal_scheme->auth_ip)},
        {"wechat_ip",       json_type_int,    NULL, sizeof(portal_scheme->wechat_ip)},    
        {"domain_set_name", json_type_string, NULL, sizeof(portal_scheme->dns_set)},
    };  
    
    struct json_object *array, *subarray;
    int i, j, ret, size, subsize, node = dc_node_portal_scheme;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    if (size <= 0) {
        portal_schemes->num = 0;
        portal_schemes->config = NULL;
        return 0;
    }

    portal_schemes->config = malloc(size * sizeof(struct portal_scheme_cfg));
    if (portal_schemes->config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(portal_schemes->config, 0, size * sizeof(struct portal_scheme_cfg));
    
    for(i = 0; i < size; i++) {   
        j = 0;
        paires[j++].value = portal_schemes->config[portal_schemes->num].scheme_name;
        paires[j++].value = &(portal_schemes->config[portal_schemes->num].enable);
        paires[j++].value = portal_schemes->config[portal_schemes->num].uri_path;
        paires[j++].value = &(portal_schemes->config[portal_schemes->num].auth_ip);
        paires[j++].value = &(portal_schemes->config[portal_schemes->num].wechat_ip);
        paires[j++].value = portal_schemes->config[portal_schemes->num].dns_set;

        array = json_object_array_get_idx(obj, i);
        json_object_object_foreach(array, key, val) {
            if (json_object_get_type(val) == json_type_array) {
                subsize = json_object_array_length(val);
                if (!strcasecmp(key, "whitelist_ip")) {
                    struct node_pair_save subpaires[] = {
                        {"ip",      json_type_int, NULL, sizeof(portal_scheme->ip_list[0].ip)},
                        {"netmask", json_type_int, NULL, sizeof(portal_scheme->ip_list[0].masklen)},
                    };
                    
                    for(j = 0; j < subsize && j < PORTAL_MAX_IP_ACCESS_LIST; j++) { 
                        subpaires[0].value = &(portal_schemes->config[portal_schemes->num].ip_list[j].ip);
                        subpaires[1].value = &(portal_schemes->config[portal_schemes->num].ip_list[j].masklen);
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        portal_schemes->config[portal_schemes->num].ip_num = j + 1;
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    }
                }
                else if (!strcasecmp(key, "whitelist_domain")) {
                    struct node_pair_save subpaires[] = {
                        {"domain_name", json_type_string, NULL, sizeof(portal_scheme->domain_list[0])},
                    };
                    
                    for(j = 0; j < subsize && j < PORTAL_MAX_HOST_ACCESS_LIST; j++) { 
                        subpaires[0].value = portal_schemes->config[portal_schemes->num].domain_list[j];
      
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        portal_schemes->config[portal_schemes->num].domain_num = j + 1;
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    }
                }
            }
            else {
                for (j = 0; j < sizeof(paires)/sizeof(paires[0]); j++) {
                    if (!strcasecmp(key, paires[j].key)) {
                        if ((ret = dc_hdl_node_default(val, &(paires[j]), 1)) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_pair(paires[j]);
                    }
                }
            }
        }
        
        portal_schemes->num++;
    }
    return 0;
}

static int dc_parse_node_client_isolation(struct json_object *obj, 
    void *jsoncfg)
{
    int *client_isolation = (int *)jsoncfg, ret, node = dc_node_client_isolation;
    struct node_pair_save pair = {
        .key   = "client_isolation",
        .type  = json_type_int,
        .value = client_isolation,
        .size  = sizeof(*client_isolation),
    };
    
    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);

    return 0;
}

static int dc_parse_node_acl_scheme(struct json_object *obj, void *jsoncfg)
{
    struct wlan_acl_schemes *acl_schemes = (struct wlan_acl_schemes *)jsoncfg;
    struct wlan_acl_status *acl_scheme = (struct wlan_acl_status *)0;
    struct node_pair_save paires[] = {
        {"name",   json_type_string, NULL, sizeof(acl_scheme->name)},
        {"policy", json_type_int,    NULL, sizeof(acl_scheme->policy)},
        {"macs",   json_type_array,  NULL, 0},
    };  
    struct json_object *array, *subarray;
    int i, j, ret, size, subsize, node = dc_node_acl_scheme;
    
    acl_schemes->configed = 1;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    if (size <= 0) {
        acl_schemes->num = 0;
        acl_schemes->config = NULL;
        return 0;
    }

    acl_schemes->config = malloc(size * sizeof(struct wlan_acl_status));
    if (acl_schemes->config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(acl_schemes->config, 0, size * sizeof(struct wlan_acl_status));

    for(i = 0; i < size; i++) {   
        paires[0].value = acl_schemes->config[acl_schemes->num].name;
        paires[1].value = &(acl_schemes->config[acl_schemes->num].policy);

        array = json_object_array_get_idx(obj, i);
        json_object_object_foreach(array, key, val) {
            if (json_object_get_type(val) == json_type_array) {
                subsize = json_object_array_length(val);
                if (!strcasecmp(key, "macs")) {
                    #define MAC_BUF_LEN 18 /* xx:xx:xx:xx:xx:xx, include terminate char */
                    char *mac_list = (char *)malloc(subsize * MAC_BUF_LEN); 
                    struct node_pair_save subpaires[] = {
                        {"macs",  json_type_string, NULL, MAC_BUF_LEN},
                    };
                    if (mac_list == NULL) {
                        return dc_error_code(dc_error_system, node, 0);
                    }
                    else {
                        memset(mac_list, 0, subsize * MAC_BUF_LEN);
                    }
                    
                    for(j = 0; j < subsize; j++) { 
                        subpaires[0].value = mac_list + (MAC_BUF_LEN * j);
                        
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            free(mac_list);
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    }

                    acl_schemes->config[acl_schemes->num].maclist = (struct wlan_acl_mac *)malloc(subsize * sizeof(struct wlan_acl_mac)); 
                    if (acl_schemes->config[acl_schemes->num].maclist == NULL) {
                        free(mac_list);
                        return dc_error_code(dc_error_system, node, 0);
                    }
                    for(j = 0; j < subsize; j++) { 
                        if (if_ether_aton(mac_list + (MAC_BUF_LEN * j), 
                            acl_schemes->config[acl_schemes->num].maclist[j].mac ) < 0){
                            nmsc_log("Bad mac addres:%s.", (mac_list + (MAC_BUF_LEN * j)));
                            continue;
                        }
                        acl_schemes->config[acl_schemes->num].count++;
                    }
                    free(mac_list);                    
                }
            }
            else {
                for (j = 0; j < sizeof(paires)/sizeof(paires[0]); j++) {
                    if (!strcasecmp(key, paires[j].key)) {
                        if ((ret = dc_hdl_node_default(val, &(paires[j]), 1)) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_pair(paires[j]);
                    }
                }
            }
        }
        
        acl_schemes->num++;
    }
    return 0;
}

static int RateGet(unsigned int * buff, int size, int mode, int *rate)
{
    int i;
    int value = 0;

    for(i = 0; i < size; i++){
        if(DOT11A_MODE == mode){
            if(6 == buff[i]){
                value = value | (0x01 << 0);
            }else if(9 == buff[i]){
                value = value | (0x01 << 1);
            }else if(12 == buff[i]){
                value = value | (0x01 << 2);
            }else if(18 == buff[i]){
                value = value | (0x01 << 3);
            }else if(24 == buff[i]){
                value = value | (0x01 << 4);
            }else if(36 == buff[i]){
                value = value | (0x01 << 5);
            }else if(48 == buff[i]){
                value = value | (0x01 << 6);
            }else if(54 == buff[i]){
                value = value | (0x01 << 7);
            }else{
                *rate = i;
                return 1;
            }
        }else if(DOT11G_MODE == mode){
            if(1 == buff[i]){
                value = value | (0x01 << 0);
            }else if(2 == buff[i]){
                value = value | (0x01 << 1);
            }else if(5 == buff[i]){
                value = value | (0x01 << 2);
            }else if(11 == buff[i]){
                value = value | (0x01 << 3);
            }else if(6 == buff[i]){
                value = value | (0x01 << 4);
            }else if(9 == buff[i]){
                value = value | (0x01 << 5);
            }else if(12 == buff[i]){
                value = value | (0x01 << 6);
            }else if(18 == buff[i]){
                value = value | (0x01 << 7);
            }else if(24 == buff[i]){
                value = value | (0x01 << 8);
            }else if(36 == buff[i]){
                value = value | (0x01 << 9);
            }else if(48 == buff[i]){
                value = value | (0x01 << 10);
            }else if(54 == buff[i]){
                value = value | (0x01 << 11);
            }else{
                *rate = i;
                return 1;
            }
        }
    }

    *rate = value;

    return 0;
}


static int dc_parse_node_rrm(struct json_object *obj, void *jsoncfg)
{
    struct wlan_rrm *rrm_info = (struct wlan_rrm *)jsoncfg;
    
    unsigned int dot11a_basic_str[32] = {0};
    unsigned int dot11a_support_str[32] = {0};
    double dot11g_basic_str[32] = {0};
    double dot11g_support_str[32] = {0};
    
    struct node_pair_save paires[] = {
        {"dot11n_basic_mcs",       json_type_int,   &rrm_info->dot11n_basis_mcs,   sizeof(rrm_info->dot11n_basis_mcs)},
        {"dot11n_support_mcs",     json_type_int,   &rrm_info->dot11n_supoort_mcs, sizeof(rrm_info->dot11n_supoort_mcs)},
        {"dot11a_fixed_beaconrate",json_type_int,   &rrm_info->dot11a_fbcrate,   sizeof(rrm_info->dot11a_fbcrate)},
        {"dot11a_fixed_mgrrate",   json_type_int,   &rrm_info->dot11a_fmgrate,   sizeof(rrm_info->dot11a_fmgrate)},
        {"dot11g_fixed_beaconrate",json_type_double,&rrm_info->dot11g_fbcrate,   sizeof(rrm_info->dot11g_fbcrate)},
        {"dot11g_fixed_mgrrate",   json_type_double,&rrm_info->dot11g_fmgbrate,  sizeof(rrm_info->dot11g_fmgbrate)}
    };  
    struct json_object *subarray;
    int i, j, ret, subsize, node = dc_node_rrm;
    int rate_value = 0;
    
    rrm_info->configed = 1;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    json_object_object_foreach(obj, key, val) {
        if (json_object_get_type(val) == json_type_array) {
            subsize = json_object_array_length(val);
            if (!strcasecmp(key, "dot11a_basic")) {
                struct node_pair_save subpaires[] = {
                    {"dot11a_basic",  json_type_int, NULL, sizeof(dot11a_basic_str)},
                };
                
                for(j = 0; j < subsize; j++) { 
                    subpaires[0].value = &dot11a_basic_str[j];
                    
                    subarray = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(subarray, subpaires, 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_paires(subpaires, 1);
                }

                if(is_default_integer_config(dot11a_basic_str[0])){
                    rrm_info->dot11a_basic = 0xfffff;
                }else{
                    ret = RateGet(dot11a_basic_str, subsize, DOT11A_MODE, &rate_value);
                    if(ret){
                        nmsc_log("Unknow dot11a rrm rate type %d:%d", rate_value, dot11a_basic_str[rate_value]);
                        return dc_error_code(dc_error_commit_failed, node, 0);
                    } 
                    rrm_info->dot11a_basic = rate_value;
                }
            }else if(!strcasecmp(key, "dot11a_support")){
                struct node_pair_save subpaires[] = {
                    {"dot11a_support",  json_type_int, NULL, sizeof(dot11a_support_str)},
                };
                
                for(j = 0; j < subsize; j++) { 
                    subpaires[0].value = &dot11a_support_str[j];
                    
                    subarray = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(subarray, subpaires, 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_paires(subpaires, 1);
                }

                if(is_default_integer_config(dot11a_support_str[0])){
                    rrm_info->dot11a_support = 0xfffff;
                }else{
                    ret = RateGet(dot11a_support_str, subsize, DOT11A_MODE, &rate_value);
                    if(ret){
                        nmsc_log("Unknow dot11a rrm rate type %d:%d", rate_value, dot11a_support_str[rate_value]);
                        return dc_error_code(dc_error_commit_failed, node, 0);
                    } 
                    rrm_info->dot11a_support = rate_value;
                }
            }else if(!strcasecmp(key, "dot11g_basic")){
                struct node_pair_save subpaires[] = {
                    {"dot11g_basic",  json_type_double, NULL, sizeof(dot11g_basic_str)},
                };
                unsigned int basic_ratelist[32];
                
                for(j = 0; j < subsize; j++) { 
                    subpaires[0].value = &dot11g_basic_str[j];
                    
                    subarray = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(subarray, subpaires, 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_paires(subpaires, 1);

                    basic_ratelist[j] = (unsigned int )dot11g_basic_str[j];
                }

                if(is_default_integer_config(basic_ratelist[0])){
                    rrm_info->dot11g_basic = 0xfffff;
                }else{
                    ret = RateGet(basic_ratelist, subsize, DOT11G_MODE, &rate_value);
                    if(ret){
                        nmsc_log("Unknow dot11g rrm rate type %d:%d", rate_value, basic_ratelist[rate_value]);
                        return dc_error_code(dc_error_commit_failed, node, 0);
                    } 
                    rrm_info->dot11g_basic = rate_value;
                }
            }else if(!strcasecmp(key, "dot11g_support")){
                struct node_pair_save subpaires[] = {
                    {"dot11g_support",  json_type_double, NULL, sizeof(dot11g_support_str)},
                };
                unsigned int basic_ratelist[32];
                
                for(j = 0; j < subsize; j++) { 
                    subpaires[0].value = &dot11g_support_str[j];
                    
                    subarray = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(subarray, subpaires, 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_paires(subpaires, 1);
                    basic_ratelist[j] = (unsigned int )dot11g_support_str[j];
                }

                if(is_default_integer_config(basic_ratelist[0])){
                    rrm_info->dot11g_support = 0xfffff;
                }else{
                    ret = RateGet((unsigned int *)basic_ratelist, subsize, DOT11G_MODE, &rate_value);
                    if(ret){
                        nmsc_log("Unknow dot11g rrm rate type %d:%d", rate_value, basic_ratelist[rate_value]);
                        return dc_error_code(dc_error_commit_failed, node, 0);
                    } 
                    rrm_info->dot11g_support = rate_value;
                }
            }
        }
        else {
            for (i = 0; i < sizeof(paires)/sizeof(paires[0]); i++) {
                if (!strcasecmp(key, paires[i].key)) {
                    if ((ret = dc_hdl_node_default(val, &paires[i], 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_pair(paires[i]);
                }
            }
        }
    }
    
    return 0;
}

static int dc_parse_node_time_limit(struct json_object *obj, void *jsoncfg)
{
    struct time_limit_schemes *time_schemes = (struct time_limit_schemes *)jsoncfg;
    struct time_limit_json *time_scheme = (struct time_limit_json *)0;
    struct node_pair_save paires[] = {
        {"name",        json_type_string, NULL, sizeof(time_scheme->name)},
        {"period",      json_type_int,    NULL, sizeof(time_scheme->period)},   
    };  
    struct json_object *array, *subarray;
    int i, j, ret, size, subsize, node = dc_node_ssid_timerange;
    
    time_schemes->configed = 1;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    if (size <= 0) {
        time_schemes->num = 0;
        return 0;
    }

    for(i = 0; i < size; i++) {   
        paires[0].value = time_schemes->config[time_schemes->num].name;
        paires[1].value = &(time_schemes->config[time_schemes->num].period);

        array = json_object_array_get_idx(obj, i);
        json_object_object_foreach(array, key, val) {
            if (json_object_get_type(val) == json_type_array) {
                subsize = json_object_array_length(val);
                if (!strcasecmp(key, "permits")) {

                    struct node_pair_save subpaires[] = {
                        {"start",   json_type_int, NULL, sizeof(int)},
                        {"stop",    json_type_int, NULL, sizeof(int)},    
                    };
                    
                    for(j = 0; j < subsize; j++) { 
                        subpaires[0].value = &time_schemes->config[time_schemes->num].permit[j].start;
                        subpaires[1].value = &time_schemes->config[time_schemes->num].permit[j].stop;
                        
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                        time_schemes->config[time_schemes->num].count++;
                    }                  
                }else if (!strcasecmp(key, "days")) {

                    struct node_pair_save subpaires[] = {
                        {"days",   json_type_int, NULL, sizeof(int)},
                    };
                    
                    for(j = 0; j < subsize; j++) { 
                        subpaires[0].value = &time_schemes->config[time_schemes->num].days[j];
                        
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    }                  
                }
            }
            else {
                for (j = 0; j < sizeof(paires)/sizeof(paires[0]); j++) {
                    if (!strcasecmp(key, paires[j].key)) {
                        if ((ret = dc_hdl_node_default(val, &(paires[j]), 1)) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_pair(paires[j]);
                    }
                }
            }
        }
        
        time_schemes->num++;
    }
    return 0;
}

static int dc_parse_node_band_steering(struct json_object *obj, void *jsoncfg)
{
    struct band_steering *bs_config = (struct band_steering *)jsoncfg;
    struct node_pair_save paires[] = {
        {"enable",              json_type_int,    &bs_config->bs_json.enable,                       sizeof(bs_config->bs_json.enable)},
        {"agings",              json_type_int,    &bs_config->bs_json.aging_time,                   sizeof(bs_config->bs_json.aging_time)},
        {"try_times",           json_type_int,    &bs_config->bs_json.retry_threshold,              sizeof(bs_config->bs_json.retry_threshold)},
        {"suppress",            json_type_int,    &bs_config->bs_support_json.enable,               sizeof(bs_config->bs_support_json.enable)},
        {"suppress_threshold",  json_type_int,    &bs_config->bs_support_json.suppress_threshold,   sizeof(bs_config->bs_support_json.suppress_threshold)},    
    };  

    int ret, node = dc_node_band_steer;

    bs_config->configed = 1;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
        return dc_error_code(ret, node, 0);
    }
    log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));

    return 0;
}

static int dc_parse_node_dns_set(struct json_object *obj, void *jsoncfg)
{
    struct dns_set_schemes *setes = (struct dns_set_schemes *)jsoncfg;
    struct node_pair_save paires[] = {
        {"name", json_type_string, NULL, sizeof(((struct dns_set_scheme *)0)->name)},
    };  
    struct json_object *array, *subarray;
    int i, j, ret, size, subsize, node = dc_node_acl_scheme;
        
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    if (size <= 0) {
        setes->num = 0;
        setes->config = NULL;
        return 0;
    }

    setes->config = malloc(size * sizeof(struct dns_set_scheme));
    if (setes->config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(setes->config, 0, size * sizeof(struct dns_set_scheme));

    for(i = 0; i < size; i++) {   
        paires[0].value = setes->config[setes->num].name;

        array = json_object_array_get_idx(obj, i);
        json_object_object_foreach(array, key, val) {
            if (json_object_get_type(val) == json_type_array) {
                subsize = json_object_array_length(val);
                if (!strcasecmp(key, "keys")) {
                    struct node_pair_save subpaires[] = {
                        {"keys", json_type_string, NULL, sizeof(((struct dns_set_key *)0)->key)},
                    };
                    struct dns_set_key *keylist = malloc(subsize * sizeof(((struct dns_set_key *)0)->key));
                    
                    if (keylist == NULL) {
                        return dc_error_code(dc_error_system, node, 0);
                    }
                    else {
                        setes->config[setes->num].keylist = keylist; 
                        memset(keylist, 0, subsize * sizeof(((struct dns_set_key *)0)->key));
                        setes->config[setes->num].num = subsize;
                    }
                    
                    for(j = 0; j < subsize; j++) { 
                        subpaires[0].value = (keylist + j);
                        
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    }
                }
            }
            else {
                for (j = 0; j < sizeof(paires)/sizeof(paires[0]); j++) {
                    if (!strcasecmp(key, paires[j].key)) {
                        if ((ret = dc_hdl_node_default(val, &(paires[j]), 1)) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_pair(paires[j]);
                    }
                }
            }
        }
        
        setes->num++;
    }
    
    return 0;
}

static int dc_parse_node_rate_optmize(struct json_object *obj, 
    void *jsoncfg)
{
    struct rate_optimization *rate_optmize = (struct rate_optimization *)jsoncfg;
    int ret, node = dc_node_rate_optimize;
    struct node_pair_save pair = {
        .key   = "rate_optimize",
        .type  = json_type_int,
        .value = &(rate_optmize->enable),
        .size  = sizeof(rate_optmize->enable),
    };

    rate_optmize->configed = 1;
    
    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);
    return 0;
}

static int dc_parse_node_igmp_snooping(struct json_object *obj, 
    void *jsoncfg)
{
    struct igmp_snooping_s *igmp = (struct igmp_snooping_s *)jsoncfg;
    struct node_pair_save paires[] = {
        {"Igmp_snooping",           json_type_int, &(igmp->enable),           sizeof(igmp->enable)},
        {"group_threshold",         json_type_int, &(igmp->group_threshold),  sizeof(igmp->group_threshold)},
        {"group_member_threshold",  json_type_int, &(igmp->member_threshold), sizeof(igmp->member_threshold)},
        {"aging_time",              json_type_int, &(igmp->age_time),         sizeof(igmp->age_time)},
        {"multicast_forward_policy",json_type_int, &(igmp->mf_policy),        sizeof(igmp->mf_policy)},
        {"m2u_audo_adopt",          json_type_int, &(igmp->m2u_auto_adopt),   sizeof(igmp->m2u_auto_adopt)},
            
    };  
    struct json_object *array;
    int i, j, ret, size, node = dc_node_igmp;

    igmp->configed = 1;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    json_object_object_foreach(obj, key, val) {
        if (json_object_get_type(val) == json_type_array) {
            if (!strcasecmp("static_groups", key)) {
                struct node_pair_save subpaires[] = {
                    {"group", json_type_string, NULL, sizeof(((struct igmp_group *)0)->address)},
                };
                
                if (igmp->sta_groupes) {
                    free(igmp->sta_groupes);
                    igmp->sta_groupes = NULL;
                }
                igmp->sg_num = 0;
                
                size = json_object_array_length(val);
                if (size <= 0) {
                    continue;
                }
                
                igmp->sta_groupes = (struct igmp_group *)malloc(size * sizeof(struct igmp_group));
                for (j = 0; j < size; j++) {
                    subpaires[0].value = igmp->sta_groupes[igmp->sg_num].address;

                    array = json_object_array_get_idx(val, j);
                    if ((ret = dc_hdl_node_default(array, &(subpaires[0]), 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_pair(subpaires[0]);
                    
                    igmp->sg_num ++;
                }
                
            }
            else {
                nmsc_log("Unknow json obj :%s", key);
            }
        }
        else {
            for (i = 0; i < sizeof(paires)/sizeof(paires[0]); i++) {
                if (!strcasecmp(key, paires[i].key)) {
                    if ((ret = dc_hdl_node_default(val, &(paires[i]), 1)) != 0) {
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_pair(paires[i]);
                }
            }
        }
    }

    return 0;
}

static int dc_parse_node_portal_preauth(struct json_object *obj, 
    void *jsoncfg)
{
    struct portal_preauth *preauth = (struct portal_preauth *)jsoncfg;
    int ret, node = dc_node_portal_preauth;
    struct node_pair_save pair = {
        .key   = "portal_preauth",
        .type  = json_type_int,
        .value = &(preauth->enable),
        .size  = sizeof(preauth->enable),
    };

    preauth->configed = 1;
    
    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);
    
    return 0;
}

static int dc_hdl_node_portal_preauth(struct portal_preauth *preauth)
{
#if !OK_PATCH
    int ret = 0, node = dc_node_portal_preauth;

    if (preauth->configed) {
        if (preauth->enable) {
            ret = portal_preauth_enable();
        }
        else {
            ret = portal_preauth_disable();
        }

        if (ret && ret != CMP_ERR_COMMIT_FAIL) {
            nmsc_log("Set portal preauth %s failed for %d.", 
                preauth->enable ? "enable" : "disable", ret);
            ret = dc_error_code(dc_error_commit_failed, node, 0);
        }
        else {
            ret = 0;
        }
    }
    
    return ret;
#else
    return 0;
#endif
}

static int dc_hdl_node_rate_optmize(struct rate_optimization *rate_optimize)
{
#if !OK_PATCH
    int ret;

    if (rate_optimize->configed) {
        if (rate_optimize->enable) {
            ret = wlan_set_rate_control_optimize(1);
        }
        else {
            ret = wlan_set_rate_control_optimize(0);
        }

        if (ret && ret != CMP_ERR_COMMIT_FAIL) {
            nmsc_log("Set wlan rate control optimize %s failed for %d.", 
                rate_optimize->enable ? "enable" : "disable", ret);
        }
    }
    
#endif
    return 0;
}


/* must called by STEP_UNDO_BIND first to unbind as from st
 * then called by STEP_OTHERS to do other things.
 */
static int dc_hdl_node_acl_scheme(int step, 
    struct service_template *oldst, struct service_templates *newst, 
    struct wlan_acl_stats *oldas, struct wlan_acl_schemes *newas)
{
    int i, j, ret, node = dc_node_acl_scheme;;
     
    if (STEP_UNBIND == step) {
        /* first: unbind from serveric template */
        for (i = 0; i < oldst->num; i++) {
            /* don't care abourt return value */
            wlan_undo_acl_scheme(oldst->wlan_st_info[i].id);
        }
    }
    else {
        /* second: undo all the old acl schemes */
        if (oldas != NULL) {
            for (i = 0; i < oldas->acl_count; i++) {
                acl_scheme_undo_maclistall(oldas->acl[i].name);
                acl_scheme_delete(oldas->acl[i].name);
            }
        }

        /* third: create new as */
        for (i = 0; i < newas->num; i++) {
            ret = 0;
            ret = acl_scheme_create(newas->config[i].name);
            if (ret) {
                nmsc_log("Create acl scheme %s failed for %d.", newas->config[i].name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
            
            ret = acl_scheme_set_policy(newas->config[i].name, 
                newas->config[i].policy);
            if (ret) {
                nmsc_log("Set acl scheme %s policy %d failed for %d.", 
                    newas->config[i].name, newas->config[i].policy, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            for (j = 0; j < newas->config[i].count; j++) {
                char    macaddr[18]={0};
                sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                        newas->config[i].maclist[j].mac[0], 
                        newas->config[i].maclist[j].mac[1], 
                        newas->config[i].maclist[j].mac[2], 
                        newas->config[i].maclist[j].mac[3], 
                        newas->config[i].maclist[j].mac[4], 
                        newas->config[i].maclist[j].mac[5]);
                
                ret = acl_scheme_set_maclist(newas->config[i].name, macaddr);
                if (ret) {
                    nmsc_log("Set acl scheme %s mac %s failed for %d.", 
                        newas->config[i].name, macaddr, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
        }

        /* last: bind new as to the new st */
        for (i = 0; i < newst->num; i++) {
            if (strlen(newst->config[i].acl_scheme) > 0) {
                ret = wlan_set_acl_scheme(newst->config[i].stid, 
                    newst->config[i].acl_scheme);
                if (ret) {
                    nmsc_log("Bind acl scheme %s to the service template %s with stid %d for %d.", 
                        newst->config[i].acl_scheme, newst->config[i].ssid,
                        newst->config[i].stid, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
        }
        
    }
    
    return 0;
}

static int dc_hdl_node_rrm(struct wlan_rrm *news)
{
#if !OK_PATCH
    int i, ret, node = dc_node_rrm;
    struct wmac_init_param  radio_info;
    DOT11_RADIO_CAP_S   caps_info[DOT11_RADIO_NUM_MAX];
    char interface_name[20] = {0};
    int dot11a_disable = 255, dot11g_disable = 4095;
     
    ret = DOT11_GetHardwareInfo(&radio_info, &caps_info[0]);
    if(ret){
        nmsc_log("Get radio information failed for %d.", ret);
        return ret;
    }

    if(0 == news->dot11a_basic && 0 == news->dot11g_basic){
        return 0;
    }

    for(i = 0; i < radio_info.uRadioNums; i++){
        memset(interface_name, 0, sizeof(interface_name));
        if((ret = if_form_name(0, i, IF_PHYTYPE_WLAN,  interface_name)) < 0){
            nmsc_log("Get Radio %d interface name failed for %d.", i, ret);
            return ret;
        }
        if(DOT11_IsRadio5G(radio_info.linkname[i])){

            if(is_default_integer_config(news->dot11a_basic)){
                ret = wlan_set_driver_radio_11a_basic_rateset(interface_name, 0);
                news->dot11a_basic = 0x15;
            }else{
                if(news->dot11a_basic){
                    ret = wlan_set_driver_radio_11a_basic_rateset(interface_name, news->dot11a_basic);
                }
            }

            if(ret != 0){
                nmsc_log("Set %s dot11a basic rateset %d failed for %d.", interface_name, news->dot11a_basic, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            if(is_default_integer_config(news->dot11a_support)){
                ret = wlan_set_driver_radio_11a_supported_rateset(interface_name, 0);
                news->dot11a_support = 0xEA;
            }else{
                if(news->dot11a_support){
                    ret = wlan_set_driver_radio_11a_supported_rateset(interface_name, news->dot11a_support);
                }
            }
            if(ret != 0){
                nmsc_log("Set %s dot11a supported rateset %d failed for %d.", interface_name, news->dot11a_support, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            dot11a_disable = dot11a_disable ^ (news->dot11a_basic | news->dot11a_support);
            if(dot11a_disable){
                ret = wlan_set_driver_radio_11a_disabled_rateset(interface_name, dot11a_disable);
                if(ret != 0){
                    nmsc_log("Set %s dot11a disabled rateset %d failed for %d.", interface_name, dot11a_disable, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
            
        }else{
            if(is_default_integer_config(news->dot11g_basic)){
                ret = wlan_set_driver_radio_11g_basic_rateset(interface_name, 0);
                news->dot11g_basic = 0xF;
            }else{
                if(news->dot11g_basic){
                    ret = wlan_set_driver_radio_11g_basic_rateset(interface_name, news->dot11g_basic);
                }
            }
            if(ret != 0){
                nmsc_log("Set %s dot11g basic rateset %d failed for %d.", interface_name, news->dot11g_basic, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
            
            if(is_default_integer_config(news->dot11g_support)){
                ret = wlan_set_driver_radio_11g_supported_rateset(interface_name, 0);
                news->dot11g_support = 0xFF0;
            }else{
                if(news->dot11g_support){
                    ret = wlan_set_driver_radio_11g_supported_rateset(interface_name, news->dot11g_support);
                }
            }
            if(ret != 0){
                nmsc_log("Set %s dot11g supported rateset %d failed for %d.", interface_name, news->dot11g_support, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
            
            dot11g_disable = dot11g_disable ^ (news->dot11g_basic | news->dot11g_support);
            if(dot11g_disable){
                ret = wlan_set_driver_radio_11g_disabled_rateset(interface_name, dot11g_disable);
                if(ret != 0){
                    nmsc_log("Set %s dot11g disabled rateset %d failed for %d.", interface_name, dot11g_disable, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
        }
        if(is_default_integer_config(news->dot11n_basis_mcs)){
            ret = wlan_set_driver_radio_11n_basic_mcs(interface_name, 0);
        }else{
            ret = wlan_set_driver_radio_11n_basic_mcs(interface_name, news->dot11n_basis_mcs);
        }
        if(ret != 0){
            if(is_default_integer_config(news->dot11n_supoort_mcs)){
                ret = wlan_set_driver_radio_11n_supported_mcs(interface_name, 15);
            }else{
                ret = wlan_set_driver_radio_11n_supported_mcs(interface_name, news->dot11n_supoort_mcs);
            }
            if(ret != 0){
                nmsc_log("Set %s dot11n supported mcs %d failed for %d.", interface_name, news->dot11n_supoort_mcs, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            if(is_default_integer_config(news->dot11n_basis_mcs)){
                ret = wlan_set_driver_radio_11n_basic_mcs(interface_name, 0);
            }else{
                ret = wlan_set_driver_radio_11n_basic_mcs(interface_name, news->dot11n_basis_mcs);
            }
            if(ret != 0){
                nmsc_log("Set %s dot11n basic mcs %d failed for %d.", interface_name, news->dot11n_basis_mcs, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
        }
        else { 
            if(is_default_integer_config(news->dot11n_supoort_mcs)){
                ret = wlan_set_driver_radio_11n_supported_mcs(interface_name, 15);
            }else{
                ret = wlan_set_driver_radio_11n_supported_mcs(interface_name, news->dot11n_supoort_mcs);
            }
            if(ret != 0){
                nmsc_log("Set %s dot11n supported mcs %d failed for %d.", interface_name, news->dot11n_supoort_mcs, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
        }
    }

    if (!news->dot11a_fbcrate || is_default_integer_config(news->dot11a_fbcrate)) {
        ret = wlan_undo_beacon_rate_5g();
    }
    else {
        ret = wlan_set_beacon_rate_5g(news->dot11a_fbcrate);
    }
    if (ret && ret != CMP_ERR_COMMIT_FAIL) {
        nmsc_log("%s dot11a fix beacon rate %u failed for %d.", 
            news->dot11a_fbcrate ? "Set" : "Undo", news->dot11a_fbcrate, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }

    if (!(int)news->dot11g_fbcrate || is_default_integer_config((int)news->dot11g_fbcrate)) {
        ret = wlan_undo_beacon_rate_2g();
    }
    else {
        ret = wlan_set_beacon_rate_2g((int)news->dot11g_fbcrate);
    }
    if (ret && ret != CMP_ERR_COMMIT_FAIL) {
        nmsc_log("%s dot11g fix beacon rate %u failed for %d.", 
            news->dot11g_fbcrate ? "Set" : "Undo", (int)news->dot11g_fbcrate, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }

    if (!news->dot11a_fmgrate || is_default_integer_config(news->dot11a_fmgrate)) {
        ret = wlan_undo_manage_rate_5g();
    }
    else {
        ret = wlan_set_manage_rate_5g(news->dot11a_fmgrate);
    }
    if (ret && ret != CMP_ERR_COMMIT_FAIL) {
        nmsc_log("%s dot11a fix manage rate %u failed for %d.", 
            news->dot11a_fmgrate ? "Set" : "Undo", news->dot11a_fmgrate, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }

    if (!(int)news->dot11g_fmgbrate || is_default_integer_config((int)news->dot11g_fmgbrate)) {
        ret = wlan_undo_manage_rate_2g();
    }
    else {
        ret = wlan_set_manage_rate_2g((int)news->dot11g_fmgbrate);
    }
    if (ret && ret != CMP_ERR_COMMIT_FAIL) {
        nmsc_log("%s dot11g fix manage rate %u failed for %d.", 
            news->dot11g_fmgbrate ? "Set" : "Undo", (int)news->dot11g_fmgbrate, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }
    
#endif
    return 0;
}

static int dc_hdl_node_time_limit(int step, 
    struct service_template *oldst, struct service_templates *newst, 
     struct scheme_time_range *oldtl, struct time_limit_schemes *newtl)
{
#define SECONDS_PER_HOUR    3600
#define SECONDS_PER_MINUTE  60
#define HOURS_PER_DAY       24
    int i, j, ret, node = dc_node_ssid_timerange;
    int start_day, start_hour, start_minute, stop_day, stop_hour, stop_minute; 
     
    if (STEP_UNBIND == step) {
        /* first: unbind from serveric template */
        for (i = 0; i < oldst->num; i++) {
            /* don't care abourt return value */
            wlan_undo_timer_scheme(oldst->wlan_st_info[i].id);
        }
    }
    else {
        /* second: undo all the old time range */
        while(oldtl != NULL){
            ret = 0;
            ret = time_range_scheme_delete(oldtl->name);
            if (ret) {
                nmsc_log("Delete %s time_range failed for %d.", 
                    oldtl->name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
            oldtl = oldtl->next;
        }
        
        /* third: create new tl */
        for (i = 0; i < newtl->num; i++) {
            ret = 0;
            ret = time_range_scheme_create(newtl->config[i].name);
            if (ret) {
                nmsc_log("Create time limit %s failed for %d.", newtl->config[i].name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            if (1 == newtl->config[i].period){
                #define WEEK_DAILY  8
                for (j = 0; j < newtl->config[i].count; j++) {
                    start_hour = newtl->config[i].permit[j].start / SECONDS_PER_HOUR;
                    start_minute = newtl->config[i].permit[j].start % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;

                    stop_hour = newtl->config[i].permit[j].stop / SECONDS_PER_HOUR;
                    stop_minute = newtl->config[i].permit[j].stop % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;
                    
                    ret = time_range_scheme_add_periodic(newtl->config[i].name, WEEK_DAILY, start_hour, start_minute,\
                        WEEK_DAILY, stop_hour, stop_minute);
                    if (ret) {
                        nmsc_log("Time limit %s add periodic satrt %02d:%02d to end %02d:%02d failed for %d.", \
                        newtl->config[i].name, start_hour, start_minute, stop_hour, stop_minute, ret);
                        ret = dc_error_code(dc_error_commit_failed, node, ret);
                        return ret;
                    }
                }
            }
            else if (2 == newtl->config[i].period) {
                for (j = 0; j < newtl->config[i].count; j++) {
                    start_hour = newtl->config[i].permit[j].start / SECONDS_PER_HOUR;
                    start_minute = newtl->config[i].permit[j].start % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;

                    stop_hour = newtl->config[i].permit[j].stop / SECONDS_PER_HOUR;
                    stop_minute = newtl->config[i].permit[j].stop % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;

                    start_day = start_hour / HOURS_PER_DAY;
                    stop_day = stop_hour / HOURS_PER_DAY;
                    start_hour = start_hour % HOURS_PER_DAY;
                    stop_hour = stop_hour % HOURS_PER_DAY;

                    /* day 0 to 6 mean monday to sunday from NMS, but it mean sunday to satuarday for local */
                    start_day = (start_day + 1) % 7;
                    stop_day = (stop_day + 1) % 7;

                    ret = time_range_scheme_add_periodic(newtl->config[i].name, start_day, start_hour, start_minute,\
                            stop_day, stop_hour, stop_minute);
                    if (ret) {
                        nmsc_log("Time limit %s add periodic satrt %02d:%02d:%02d to end %02d:%02d:%02d failed for %d.", \
                        newtl->config[i].name, start_day, start_hour, start_minute, stop_day, stop_hour, stop_minute, ret);
                        ret = dc_error_code(dc_error_commit_failed, node, ret);
                        return ret;
                    }
                }
            }
        }

        /* last: bind new tl to the new st */
        for (i = 0; i < newst->num; i++) {
            if (strlen(newst->config[i].time_scheme) > 0) {
                ret = wlan_set_timer_scheme(newst->config[i].stid, 
                    newst->config[i].time_scheme);
                if (ret) {
                    nmsc_log("Bind time limit %s to the service template %s with stid %d for %d.", 
                        newst->config[i].time_scheme, newst->config[i].ssid,
                        newst->config[i].stid, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
        }  
    }
    
    return 0;
}

static int dc_hdl_node_band_steering(struct band_steering *news)
{
#if !OK_PATCH
    int ret, node = dc_node_band_steer;
    
    struct band_steering def_cfg = {
        .bs_json.enable = 0,
        .bs_json.retry_threshold = 0,
        .bs_json.aging_time = 3600,
        .bs_support_json.enable  = 0,
        .bs_support_json.suppress_threshold = 40,
    };

    //get band steering default config
    CHECK_DEFAULT_INTEGER_CONFIG(news->bs_json.enable, def_cfg.bs_json.enable);
    CHECK_DEFAULT_INTEGER_CONFIG(news->bs_json.retry_threshold, def_cfg.bs_json.retry_threshold);
    CHECK_DEFAULT_INTEGER_CONFIG(news->bs_json.aging_time, def_cfg.bs_json.aging_time);
    CHECK_DEFAULT_INTEGER_CONFIG(news->bs_support_json.enable, def_cfg.bs_support_json.enable);
    CHECK_DEFAULT_INTEGER_CONFIG(news->bs_support_json.suppress_threshold, def_cfg.bs_support_json.suppress_threshold);

    //if band steer enable, config aging time and enable
    
    ret = wlan_set_bandsteering_aging_time(news->bs_json.aging_time);
    if(ret && ret != CMP_ERR_COMMIT_FAIL){
        nmsc_log("Set bandsteering aging time %d failed for %d.", news->bs_json.aging_time, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }

    /*NMS is not support band steer retry threshold
    ret = wlan_set_bandsteering_retry_threshold(news->bs_json.retry_threshold);
    if(ret && ret != CMP_ERR_COMMIT_FAIL){
        nmsc_log("Set bandsteering retry threshold %d failed for %d.", news->bs_json.retry_threshold, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }*/
    
    if(news->bs_json.enable){
        ret = wlan_set_bandsteering(1);
        if(ret && ret != CMP_ERR_COMMIT_FAIL){
            nmsc_log("Set bandsteering enable failed for %d.", ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            return ret;
        }
    }else{
        ret = wlan_set_bandsteering(0);
        if(ret && ret != CMP_ERR_COMMIT_FAIL){
            nmsc_log("Set bandsteering disable failed for %d.", ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            return ret;
        }
    }

    /*NMS is not support band steer support  
    //if band steer support enable, config suppress threshold and enable
    
    ret = wlan_set_bandsteering_suppress_threshold(news->bs_support_json.suppress_threshold);
    if(ret && ret != CMP_ERR_COMMIT_FAIL){
        nmsc_log("Set bandsteering suppress threshold %d failed for %d.", news->bs_support_json.suppress_threshold, ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret);
        return ret;
    }
    
    if(news->bs_support_json.enable){    
        ret = wlan_set_bandsteering_suppress(1);
        if(ret && ret != CMP_ERR_COMMIT_FAIL){
            nmsc_log("Set bandsteering suppress enable failed for %d.", ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            return ret;
        }
    }else{
        ret = wlan_set_bandsteering_suppress(0);
        if(ret && ret != CMP_ERR_COMMIT_FAIL){
            nmsc_log("Set bandsteering suppress disable failed for %d.", ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            return ret;
        }
    }*/
    
#endif
    return 0;
}

static int dc_hdl_node_dns_set(int step, struct portal_schemes *oldps, 
    struct portal_schemes *newps, struct dns_set_schemes *newds)
{
    int i, j, ret, node = dc_node_dns_set;

    if (step == STEP_UNBIND) {
        /* first: unbind from portal scheme */
        if (oldps != NULL) {
            for (i = 0; i < oldps->num; i++) {
                portal_scheme_undo_dnsset(oldps->config[i].scheme_name);
            }
        }

        /* second: delete all dns set list */
        DNSSET_S *oldds = dnsset_cfg_getall();
        if (oldds != NULL) {
            while (oldds) {
                dnsset_destroy(oldds->name);
                oldds = oldds->next;
            }
            dnsset_cfg_free(oldds);
        }
    }
    else {
        /* third: set the new dns set config from NMS */
        for (i = 0; i < newds->num; i++) {
            struct dns_set_scheme *ds = &(newds->config[i]);
            
            ret = dnsset_create(ds->name);
            if (ret != 0) {
                nmsc_log("Create dns set %s failed for %d.", ds->name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
            
            dnsset_disable(ds->name);
            for (j = 0; j < ds->num; j++) {
                ret = dnsset_add_key(ds->name, ds->keylist[j].key);
                if (ret != 0) {
                    nmsc_log("Add dns set %s key %s failed for %d.", 
                        ds->name, ds->keylist[j].key, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
            ret = dnsset_enable(ds->name);
            if (ret != 0) {
                nmsc_log("Enable dns set %s failed for %d.", ds->name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
        }

        /* bind: bind new dns set to the new ps */
        for (i = 0; i < newps->num; i++) {
            if (newps->config[i].dns_set[0]) {
                ret = portal_scheme_set_dnsset(newps->config[i].scheme_name, 
                    newps->config[i].dns_set);

                if (ret != 0) {
                    nmsc_log("Set portal scheme %s dns set %s failed for %d.", 
                        newps->config[i].scheme_name, newps->config[i].dns_set, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    return ret;
                }
            }
        }
    }
    return 0;
}

static int dc_hdl_node_igmp_snooping(struct igmp_snooping_s *igmp)
{
#if !OK_PATCH
    int i, ret, node = dc_node_igmp, mf_policy = MCAST_POLICY_ACCEPT_ALL;
    const struct igmp_snooping_s igmp_def = {
        .enable = 0,
        .group_threshold = 256,
        .member_threshold = 256,
        .age_time = 260,
        .mf_policy = 1, /* it mean MCAST_POLICY_ACCEPT_ALL */
        .m2u_auto_adopt = 0,
    };

    CHECK_DEFAULT_INTEGER_CONFIG(igmp->enable, igmp_def.enable);
    CHECK_DEFAULT_INTEGER_CONFIG(igmp->group_threshold, igmp_def.group_threshold);
    CHECK_DEFAULT_INTEGER_CONFIG(igmp->member_threshold, igmp_def.member_threshold);
    CHECK_DEFAULT_INTEGER_CONFIG(igmp->age_time, igmp_def.age_time);
    CHECK_DEFAULT_INTEGER_CONFIG(igmp->mf_policy, igmp_def.mf_policy);
    CHECK_DEFAULT_INTEGER_CONFIG(igmp->m2u_auto_adopt, igmp_def.m2u_auto_adopt);
    
    if (igmp->enable) {
        ret = igmp_snooping_enable();
    }
    else {
        ret = igmp_snooping_disable();
    }
    if (ret) {
        nmsc_log("Set IGMP snooping %s failed for %d.", igmp->enable ? "enable":"disable", ret);
        goto ERROR;
    }

    ret = igmp_snooping_set_group_threshold(igmp->group_threshold);
    if (ret) {
        nmsc_log("Set IGMP snooping group threshold %d failed for %d.", igmp->group_threshold , ret);
        goto ERROR;
    }

    ret = igmp_snooping_set_client_threshold(igmp->member_threshold);
    if (ret) {
        nmsc_log("Set IGMP snooping client threshold %d failed for %d.", igmp->member_threshold , ret);
        goto ERROR;
    }

    ret = igmp_snooping_set_client_aging_time(igmp->age_time);
    if (ret) {
        nmsc_log("Set IGMP snooping aging time %d failed for %d.", igmp->age_time , ret);
        goto ERROR;
    }

    if (igmp->m2u_auto_adopt) {
        ret = igmp_snooping_m2u_auto_adapt_enable();
    }
    else {
        ret = igmp_snooping_m2u_auto_adapt_disable();
    }
    if (ret) {
        nmsc_log("Set M2U auto adapt %s failed for %d.", igmp->m2u_auto_adopt ? "enable":"disable", ret);
        goto ERROR;
    }

    switch(igmp->mf_policy) {
        case 1:
            mf_policy = MCAST_POLICY_ACCEPT_ALL;
            break;

        case 2:
            mf_policy = MCAST_POLICY_DROP_UNKNOWN;
            break;

        case 3:
            mf_policy = MCAST_POLICY_DROP_ALL;
            break;

        default:
            nmsc_log("Unknow multicast foward policy %d, set to default.", igmp->mf_policy);
            mf_policy = MCAST_POLICY_ACCEPT_ALL;
            break;
    }
    ret = igmp_snooping_set_multicast_forward_policy(mf_policy);
    if (ret) {
        nmsc_log("Set multicast foward policy %d:%d failed for %d.", 
            mf_policy, igmp->mf_policy, ret);
        goto ERROR;
    }

    igmp_snooping_undo_static_group_all();
    for (i = 0; i < igmp->sg_num; i++) {
        ret = igmp_snooping_set_static_group(igmp->sta_groupes[i].address);
        if (ret) {
            nmsc_log("Set IGMP snooping static group %s failed for %d.", 
                igmp->sta_groupes[i].address, ret);
            goto ERROR;
        }
    }

    return 0;

ERROR:
    ret = dc_error_code(dc_error_commit_failed, node, ret);
    return ret;
#else
    return 0;
#endif
}

static int dc_parse_node_arp_optimize(struct json_object *obj, 
    void *jsoncfg)
{
    struct arp_optimize *arp_op = (struct arp_optimize *)jsoncfg;
    int ret, node = dc_node_arp_optimize;
    struct node_pair_save paires[] = {
        {"enable",  json_type_int,  &(arp_op->enable),  sizeof(arp_op->enable)},
        {"policy",  json_type_int,  &(arp_op->policy),  sizeof(arp_op->policy)},
    }; 

    arp_op->configed = 1;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    if ((ret = dc_hdl_node_default(obj,  paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    
    return 0;
}

static int dc_parse_node_air_scan(struct json_object *obj, void *jsoncfg)
{
    struct wlan_scan_template *ws_templates = (struct wlan_scan_template *)jsoncfg;
    struct wscan_template *ws_template = (struct wscan_template *)0;
    struct node_pair_save paires[] = {
        {"name",            json_type_string, NULL, sizeof(ws_template->name)},
        {"scan_type",       json_type_int,    NULL, sizeof(ws_template->type)},
        {"scan_period",     json_type_int,    NULL, sizeof(ws_template->period)},
        {"scan_interval",   json_type_int,    NULL, sizeof(ws_template->intval)},  
        {"list_channel",    json_type_array,  NULL, 0},    
    };  
    struct json_object *array, *subarray;
    int i, j, ret, size, subsize, node = dc_node_wlan_scan;
    
    ws_templates->configed = 1;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    size = json_object_array_length(obj);
    if (size <= 0) {
        ws_templates->num = 0;
        ws_templates->config = NULL;
        return 0;
    }

    ws_templates->config = malloc(size * sizeof(struct wscan_template));
    if (ws_templates->config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(ws_templates->config, 0, size * sizeof(struct wscan_template));

    for(i = 0; i < size; i++) {   
        paires[0].value = ws_templates->config[ws_templates->num].name;
        paires[1].value = &(ws_templates->config[ws_templates->num].type);
        paires[2].value = &(ws_templates->config[ws_templates->num].period);
        paires[3].value = &(ws_templates->config[ws_templates->num].intval);

        array = json_object_array_get_idx(obj, i);
        json_object_object_foreach(array, key, val) {
            if (json_object_get_type(val) == json_type_array) {
                subsize = json_object_array_length(val);
                if (!strcasecmp(key, "list_channel")) {

                    int iChannelList[128] = {};
                    memset(iChannelList, 0, sizeof(iChannelList));
                    
                    struct node_pair_save subpaires[] = {
                        {"list_channel",  json_type_int, NULL, sizeof(int)},
                    };
                    
                    for(j = 0; j < subsize; j++) { 
                        subpaires[0].value = &iChannelList[j];
                        
                        subarray = json_object_array_get_idx(val, j);
                        if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    }
                    
                    for(j = 0; j < subsize; j++) { 
                        char cChannel[6] = {};
                        memset(cChannel, 0, sizeof(cChannel));

                        if(j == (subsize - 1)){
                            sprintf(cChannel, "%d", iChannelList[j]);
                        }else{
                            sprintf(cChannel, "%d,", iChannelList[j]);
                        }
                        strcat(ws_templates->config[ws_templates->num].channels, cChannel);   
                    } 

                }
            }
            else {
                for (j = 0; j < sizeof(paires)/sizeof(paires[0]); j++) {
                    if (!strcasecmp(key, paires[j].key)) {
                        if ((ret = dc_hdl_node_default(val, &(paires[j]), 1)) != 0) {
                            return dc_error_code(ret, node, 0);
                        }
                        log_node_pair(paires[j]);
                    }
                }
            }
        }
        
        ws_templates->num++;
    }
    return 0;
}

 
static int dc_hdl_node_arp_optimize(struct arp_optimize *arp_op)
{
#if !OK_PATCH
    int ret = 0, node = dc_node_arp_optimize;

    if (arp_op->configed) {
        CHECK_DEFAULT_INTEGER_CONFIG(arp_op->enable, 0);
        
        if (arp_op->enable) {
            ret = wlan_set_arp_optimize_enable(1);
        }
        else {
            ret = wlan_set_arp_optimize_enable(0);
        }

        if (ret && ret != CMP_ERR_COMMIT_FAIL) {
            nmsc_log("Set arp optimize %s failed for %d.", 
                arp_op->enable ? "enable" : "disable", ret);
            ret = dc_error_code(dc_error_commit_failed, node, 0);
        }
        else {
            ret = 0;
        }
    }
    
    return ret;
#else
    return 0;
#endif
}


static int dc_hdl_node_wlan_scan(struct wlan_scan_template *ws_op)
{
#if !OK_PATCH
    int ret = 0, node = dc_node_wlan_scan;
    int i;

    if (ws_op->configed) {
        
        ret = wlan_scan_undo_all_template();
        if (ret) {
            nmsc_log("Del all wlan scan failed for %d.", ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            return ret;
        }
        
        for (i = 0; i < ws_op->num; i++) {
            ret = wlan_scan_create_template(ws_op->config[i].name);
            if (ret) {
                nmsc_log("Create wlan scan %s failed for %d.", ws_op->config[i].name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
            
            ret = wlan_scan_set_intval(ws_op->config[i].name, ws_op->config[i].intval);
            if (ret) {
                nmsc_log("Set wlan scan %s intval %d failed for %d.", 
                    ws_op->config[i].name, ws_op->config[i].intval, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            ret = wlan_scan_set_period(ws_op->config[i].name, ws_op->config[i].period);
            if (ret) {
                nmsc_log("Set wlan scan %s period %d failed for %d.", 
                    ws_op->config[i].name, ws_op->config[i].period, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }

            if(ws_op->config[i].type == 1){
                ret = wlan_scan_set_channel(ws_op->config[i].name, WSCAN_COUNTRY_CHANNEL, NULL);
            }else if(ws_op->config[i].type == 2){
                ret = wlan_scan_set_channel(ws_op->config[i].name, WSCAN_WORK_CHANNEL, NULL);
            }else if(ws_op->config[i].type == 3){
                ret = wlan_scan_set_channel(ws_op->config[i].name, WSCAN_DCA_CHANNEL, ws_op->config[i].channels);
            }
            
            if (ret) {
                nmsc_log("Set wlan scan %s type %d channel list %s failed for %d.", 
                    ws_op->config[i].name, ws_op->config[i].type, ws_op->config[i].channels, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                return ret;
            }
        } 
    }
    
    return ret;
#else
    return 0;
#endif
}


static inline int if_support_11ac(unsigned int id)
{
    if (id == 1) {
        return 1;
    } else {
        return 0;
    }
}

int dc_hdl_node_wlan(struct json_object *obj)
{
    struct service_templates st_json_cfg;
    struct radio_list rd_json_cfg;
    struct portal_schemes ps_json_cfg;
    struct dns_set_schemes ds_json_cfg;

    int ci_json_cfg = 0;
    struct wlan_acl_schemes as_json_cfg;
    struct wlan_rrm rrm_json_cfg;
    struct time_limit_schemes tl_json_cfg;
    struct band_steering bs_json_cfg;
    struct rate_optimization ro_json_cfg;
    struct igmp_snooping_s is_json_cfg;
    struct portal_preauth pp_json_cfg;
    struct arp_optimize ao_json_cfg;
    struct wlan_scan_template ws_json_cfg;

    struct service_template *st_cur_cfg = NULL;
    struct wlan_radio_info *rd_cur_cfg = NULL;
    struct portal_schemes ps_cur_cfg;

    struct wlan_acl_stats *as_cur_cfg = NULL;
    struct scheme_time_range *tl_cur_cfg = NULL;

    struct service_template_json st_def_cfg = {
        .beacon_ssid_hide = 0,
        .client_max = 127,
        .auth = WLAN_AUTH_OPEN,
        .cipher = WLAN_CIPHER_NONE,
        .key_crypt = WLAN_KEY_CRYPT_PLAIN,
        .key_type = WLAN_KEY_TYPE_ASCII,
        .gtk_enabled = 0,
        .gtk_lifetime = 86400,
        .ptk_enabled = 0,
        .ptk_lifetime = 3600,
        .wep_key_slot = 1,
        .m2u_enable = 0,
#if OK_PATCH
        .bandwidth_priority = 3,
        .client_isolation = 0,
        .type = 0,
        .enabled = 1
#endif
    };
    
    struct radio_json rd0_def_cfg = {
        .id = 0,
        .mode = (DOT11_RADIO_MODE_G | DOT11_RADIO_MODE_N),
        .channel = 6,
        .max_power = 5,
        .dot11nonly = 0,
        .ampdu = 1,
        .bandwidth = 0,
        .distance = 1,
        .preamble = 0,
        .protection_mode = 1,
        .beacon_interval = 100,
        .dtim = 1,
        .fragment_threshold = 2346,
        .rts_threshold = 2347,
        .short_gi = 1,
        .rssi_access = 0,
        .rssi_access_threshold = -92,
        .bcst_ratelimt = 0, 
        .bcst_ratelimt_cir = 10,
        .bcst_ratelimt_cbs = 30,
        .air_time_fairness = 0,
#if OK_PATCH
        .client_max = 127,
#endif
    };

    struct radio_json rd1_def_cfg = {
        .id = 1,
        .mode = (DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N),
        .channel = 149,
        .max_power = 0,
        .dot11nonly = 0,
        .ampdu = 1,
        .bandwidth = 0,
        .distance = 1,
        .preamble = 0,
        .protection_mode = 1,
        .beacon_interval = 100,
        .dtim = 1,
        .fragment_threshold = 2346,
        .rts_threshold = 2347,
        .short_gi = 1,
        .rssi_access = 0,
        .rssi_access_threshold = -87,
        .bcst_ratelimt = 0, 
        .bcst_ratelimt_cir = 10,
        .bcst_ratelimt_cbs = 30,
        .air_time_fairness = 0,
#if OK_PATCH
        .client_max = 127,
#endif
    };

    struct radio_json rd1_def_cfg_11ac = {
        .id = 1,
        .mode = DOT11_RADIO_MODE_AC,
        .channel = 149,
        .max_power = 0,
        .dot11nonly = 0,
        .dot11aconly = 0,
        .ampdu = 1,
        .bandwidth = 0,
        .distance = 1,
        .preamble = 0,
        .protection_mode = 1,
        .beacon_interval = 100,
        .dtim = 1,
        .fragment_threshold = 2346,
        .rts_threshold = 2347,
        .short_gi = 1,
        .rssi_access = 0,
        .rssi_access_threshold = -87,
        .bcst_ratelimt = 0, 
        .bcst_ratelimt_cir = 10,
        .bcst_ratelimt_cbs = 30,
        .air_time_fairness = 0,
#if OK_PATCH
        .client_max = 127,
#endif
    };
    
    struct subnode_parser {
        char *key;
        int (*subnode_parser)(struct json_object *obj, void *jsoncfg);
        void *param;
    };

    struct subnode_parser system_subnodes[] = {
        {"ssids",               dc_parse_node_service_template,  &st_json_cfg},
        {"radios",              dc_parse_node_radio,             &rd_json_cfg},
        {"portal_schemes",      dc_parse_node_portal_scheme,     &ps_json_cfg},
        {"client_isolation",    dc_parse_node_client_isolation,  &ci_json_cfg},
        {"mac_acl_schemes",     dc_parse_node_acl_scheme,        &as_json_cfg},
        {"rrm",                 dc_parse_node_rrm,               &rrm_json_cfg}, 
        {"time_limit_schemes",  dc_parse_node_time_limit,        &tl_json_cfg},  
        {"band_steering",       dc_parse_node_band_steering,     &bs_json_cfg}, 
        {"domain_sets",         dc_parse_node_dns_set,           &ds_json_cfg}, 
        {"rate_optimize",       dc_parse_node_rate_optmize,      &ro_json_cfg},
        {"igmp_snooping",       dc_parse_node_igmp_snooping,     &is_json_cfg},     
        {"portal_preauth",      dc_parse_node_portal_preauth,    &pp_json_cfg},
        {"arp_optimize",        dc_parse_node_arp_optimize,      &ao_json_cfg},
        {"air_scan",            dc_parse_node_air_scan,          &ws_json_cfg},    
    };

    int i, j, k, r, m, obj_saved, ret, stid, node = dc_node_wlan, later_enable = 0;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0); 
    }

    memset(&st_json_cfg, 0, sizeof(st_json_cfg));
    memset(&rd_json_cfg, 0, sizeof(rd_json_cfg));
    memset(&ps_json_cfg, 0, sizeof(ps_json_cfg));
    memset(&as_json_cfg, 0, sizeof(as_json_cfg));
    memset(&rrm_json_cfg, 0, sizeof(rrm_json_cfg));
    memset(&tl_json_cfg, 0, sizeof(tl_json_cfg));
    memset(&bs_json_cfg, 0, sizeof(bs_json_cfg));
    memset(&ds_json_cfg, 0, sizeof(ds_json_cfg));
    memset(&ro_json_cfg, 0, sizeof(ro_json_cfg));
    memset(&is_json_cfg, 0, sizeof(is_json_cfg));
    memset(&pp_json_cfg, 0, sizeof(pp_json_cfg));
    memset(&ao_json_cfg, 0, sizeof(ao_json_cfg));
    memset(&ws_json_cfg, 0, sizeof(ws_json_cfg));

    ps_cur_cfg.config = NULL;

    json_object_object_foreach(obj, key, val) {
        obj_saved = 0;
        for (i = 0; i < sizeof(system_subnodes)/sizeof(system_subnodes[0]); i++) {
            if (!strcasecmp(key, system_subnodes[i].key)) {
                obj_saved = 1;
                if ((ret = system_subnodes[i].subnode_parser((val), system_subnodes[i].param)) != 0) {
                    goto ERROR_OUT;
                }
            }
        }
        if (!obj_saved) {
            nmsc_log("Unknow json obj :%s", key);
            /* Only handle recognized, others will be ignored */
            // ret = dc_error_code(dc_error_save_obj, node, 0); 
            // goto ERROR_OUT;
        }
    }





    st_cur_cfg = (struct service_template *)malloc(sizeof(struct service_template));
    if (!st_cur_cfg) {
        ret = dc_error_code(dc_error_system, node, 0); 
        goto ERROR_OUT;
    }
    memset(st_cur_cfg, 0, sizeof(struct service_template));
    if ((ret = wlan_service_template_get_all(st_cur_cfg)) != 0) {
        nmsc_log("Get all service tempate failed for %d.", ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret); 
        goto ERROR_OUT;
    }
    rd_cur_cfg = (struct wlan_radio_info *)malloc(sizeof(struct wlan_radio_info));
    if (!rd_cur_cfg) {
        ret = dc_error_code(dc_error_system, node, 0); 
        goto ERROR_OUT;
    }
    memset(rd_cur_cfg, 0, sizeof(struct wlan_radio_info));
    if ((ret = wlan_radio_get_all(rd_cur_cfg)) != 0) {
        nmsc_log("Get all radio information failed for %d.", ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret); 
        goto ERROR_OUT;
    }

    memset(&ps_cur_cfg, 0, sizeof(struct portal_schemes));
    if ((ret = portal_scheme_get_all(&ps_cur_cfg)) != 0) {
        nmsc_log("Get all portal scheme failed for %d.", ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret); 
        goto ERROR_OUT;
    }

    /* no cfg from NMS for the as, need to do nothing */
    if (as_json_cfg.configed) {
        if ((ret = wlan_get_acl_all(&as_cur_cfg)) != 0) {
            nmsc_log("Get all acl scheme failed for %d.", ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }

        ret = dc_hdl_node_acl_scheme(STEP_UNBIND, st_cur_cfg, &st_json_cfg,
            as_cur_cfg, &as_json_cfg);
        if (ret) {
            nmsc_log("Handle acl scheme failed for %d.", ret);
            goto ERROR_OUT;
        }
    }

    if(tl_json_cfg.configed) {
        tl_cur_cfg = get_time_range_byname(NULL);

        if(tl_cur_cfg){
            ret = dc_hdl_node_time_limit(STEP_UNBIND, st_cur_cfg, &st_json_cfg,
                tl_cur_cfg, &tl_json_cfg);
            if (ret) {
                nmsc_log("Handle time limit failed for %d.", ret);
                goto ERROR_OUT;
            }
        }
    }



    /* Try to delete service template */
    for (i = 0; i < st_cur_cfg->num; i++) {
        for (j = 0; j < st_json_cfg.num; j++) {
            /* check the st if exist in new json config */
            if (!strcmp(st_cur_cfg->wlan_st_info[i].ssid, st_json_cfg.config[j].ssid)) {
                break;
            }
        }
        stid = st_cur_cfg->wlan_st_info[i].id;
        if (j >= st_json_cfg.num) {
            /* st dones not exist in json cfg, undo bind first, then delete  */
            for (k = 0; k < rd_cur_cfg->num; k++) {
                for (r = 0; r < sizeof(rd_cur_cfg->radioinfo[k].service)/sizeof(rd_cur_cfg->radioinfo[k].service[0]); r++) {                    
                    if (rd_cur_cfg->radioinfo[k].service[r] == stid) {
                        wlan_undo_bind(rd_cur_cfg->radioinfo[k].id, stid);
                        break;
                    }
                }
            }

            /* unbind portal scheme before undo service template */
            wlan_undo_portal_scheme(stid);
            if ((ret = wlan_undo_service_template(stid)) != 0) {
                nmsc_log("Undo service template %d failed for %d.", stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }
    }


    for (j = 0; j < st_json_cfg.num; j++) {
        for (i = 0; i < st_cur_cfg->num; i++) {
            if (!strcmp(st_cur_cfg->wlan_st_info[i].ssid, st_json_cfg.config[j].ssid)) {
                /* if same ssid but different portal scheme, now we unbind portal scheme first */
                if (strcmp(st_cur_cfg->wlan_st_info[i].portal_scheme, st_json_cfg.config[j].portal_scheme)) {
                    wlan_undo_portal_scheme(st_cur_cfg->wlan_st_info[i].id);
                }
            }
        }
    }
    /* Already unbind portal scheme from service template, now we can delete 
     * such portal schemes that only exist in the ps_cur_cfg
     */

    /* Unbind dns set from portal scheme */
    ret = dc_hdl_node_dns_set(STEP_UNBIND, &ps_cur_cfg, NULL, NULL);
    if (ret != 0) {
        nmsc_log("Handle dns set config failed for %d.", ret);
        goto ERROR_OUT; 
    }
    
    for (i = 0; i < ps_cur_cfg.num; i++) {
        for (j = 0; j < ps_json_cfg.num; j++) {
            if (!strcmp(ps_cur_cfg.config[i].scheme_name, 
                ps_json_cfg.config[j].scheme_name)) {
                break;
            }
        }

        if (j >= ps_json_cfg.num) {
            /* can not find in the new json config from NMS, so delete it */
            ret = portal_scheme_destroy(ps_cur_cfg.config[i].scheme_name);
            if (ret != 0) {
                nmsc_log("Delete portal scheme %s failed for %d.", 
                    ps_cur_cfg.config[i].scheme_name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }
    }

    /* now we can set both new or old portal schemes config as the json config from NMS */
    for (i = 0; i < ps_json_cfg.num; i++) {
        struct portal_scheme_cfg *ps_json = &(ps_json_cfg.config[i]);

        ret = portal_scheme_create(ps_json->scheme_name);
        if (ret  != 0) { /* if scheme exist although return 0 */
            nmsc_log("Create portal scheme %s failed for %d.", ps_json->scheme_name, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT; 
        }

        /* never to empty the url even the nms config is null */
        if (strlen(ps_json->uri_path) > 0) { 
            ret = portal_scheme_uri(ps_json->scheme_name, ps_json->uri_path);
            if (ret != 0) {
                nmsc_log("Set portal scheme %s uri %s failed for %d.", 
                    ps_json->scheme_name, ps_json->uri_path, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }

        if (ps_json->auth_ip) {
            char strauth[32], strwechat[32], *ptrwechat = NULL;
            struct in_addr inauth;

            inauth.s_addr = ps_json->auth_ip;

            strcpy(strauth, inet_ntoa(inauth));
            if (ps_json->wechat_ip) {
                struct in_addr inwechat;
                inwechat.s_addr = ps_json->wechat_ip;
                strcpy(strwechat, inet_ntoa(inwechat));
                ptrwechat = strwechat;
            }
            ret = portal_scheme_blackip(ps_json->scheme_name, strauth, ptrwechat);
            if (ret != 0) {
                nmsc_log("Set portal scheme %s authip %s and wecharip %s failed for %d.", 
                    ps_json->scheme_name, strauth, strwechat, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }

        ret = portal_scheme_flush_ipacl(ps_json->scheme_name);
        if (ret != 0) {
            nmsc_log("Flush portal scheme %s ip acl failed for %d.", 
                ps_json->scheme_name, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT; 
        }
        for (k = 0; k < ps_json->ip_num; k++) {
            struct in_addr inipacl;
            char stripacl[32];

            inipacl.s_addr = ps_json->ip_list[k].ip;
            strcpy(stripacl, inet_ntoa(inipacl));
            ret = portal_scheme_add_ipacl(ps_json->scheme_name, stripacl,
                ps_json->ip_list[k].masklen);
            if (ret != 0) {
                nmsc_log("Add portal scheme %s ip acl %s/%d failed for %d.", 
                    ps_json->scheme_name, stripacl, ps_json->ip_list[k].masklen, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }

        /* TODO: domain name related need to handle later  */        
        if (ps_json->enable) {
            if ((ret = portal_scheme_enable(ps_json->scheme_name)) != 0) {
                nmsc_log("Enable portal scheme %s failed for %d.", ps_json->scheme_name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }
        else {
            if ((ret = portal_scheme_disable(ps_json->scheme_name)) != 0) {
                nmsc_log("Disable portal scheme %s failed for %d.", ps_json->scheme_name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }
        }
    }

    /* Process new dns set config from NMS */
    ret = dc_hdl_node_dns_set(STEP_OTHERS, NULL, &ps_json_cfg, &ds_json_cfg);
    if (ret != 0) {
        nmsc_log("Handle dns set config failed for %d.", ret);
        goto ERROR_OUT; 
    }

    /* recover to the default value */
    for (j = 0; j < st_json_cfg.num; j++) {
        struct service_template_json *st_json = &(st_json_cfg.config[j]);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->beacon_ssid_hide, st_def_cfg.beacon_ssid_hide);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->client_max, st_def_cfg.client_max);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->auth, st_def_cfg.auth);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->cipher, st_def_cfg.cipher);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->key_crypt, st_def_cfg.key_crypt);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->key_type, st_def_cfg.key_type);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->gtk_enabled, st_def_cfg.gtk_enabled);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->gtk_lifetime, st_def_cfg.gtk_lifetime);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->ptk_enabled, st_def_cfg.ptk_enabled);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->ptk_lifetime, st_def_cfg.ptk_lifetime);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->wep_key_slot, st_def_cfg.wep_key_slot);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->m2u_enable, st_def_cfg.m2u_enable);
#if OK_PATCH
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->bandwidth_priority, st_def_cfg.bandwidth_priority);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->client_isolation, st_def_cfg.client_isolation);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->type, st_def_cfg.type);
        CHECK_DEFAULT_INTEGER_CONFIG(st_json->enabled, st_def_cfg.enabled);
#endif
    }

    for (j = 0; j < st_json_cfg.num; j++) {
        struct service_template_json *st_json = &(st_json_cfg.config[j]);

        for (i = 0; i < st_cur_cfg->num; i++) {
            if (!strcmp(st_cur_cfg->wlan_st_info[i].ssid, st_json->ssid)) {
                break;
            }
        }
    
        if (i < st_cur_cfg->num) {
            /* the ssid already existed in the current config, check if change the config */
            struct wlan_service_template *st_cur = &(st_cur_cfg->wlan_st_info[i]);
                if (!strcmp(st_json->radius_scheme, st_cur->radius_scheme)
                    && st_json->beacon_ssid_hide == st_cur->beacon_ssid_hide
                    && st_json->client_max == st_cur->client_max
                    && st_json->auth == st_cur->auth
                    && st_json->cipher == st_cur->cipher
                    && st_json->gtk_enabled == st_cur->gtk_enabled
                    && st_json->gtk_lifetime == st_cur->gtk_lifetime
                    && st_json->ptk_enabled == st_cur->ptk_enabled
                    && st_json->ptk_lifetime == st_cur->ptk_lifetime
                    && st_json->wep_key_slot == st_cur->wep_key_slot
                    && st_json->m2u_enable == st_cur->m2u_enabled
#if OK_PATCH
                    && st_json->bandwidth_priority == st_cur->bandwidth_priority
                    && st_json->client_isolation == st_cur->client_isolation
                    && st_json->type == st_cur->type
                    && st_json->enabled == st_cur->enabled
#endif
                    ) {
                    if (st_json->cipher == WLAN_CIPHER_WEP40) {
                        if (st_json->key_crypt == st_cur->wep40_key[0].key_crypt
                            && st_json->key_type == st_cur->wep40_key[0].key_type
                            && !strcmp(st_json->key, st_cur->wep40_key[0].key)) {
                            continue;
                        }
                    }
                    else if (st_json->cipher == WLAN_CIPHER_WEP108) {
                        if (st_json->key_crypt == st_cur->wep108_key[0].key_crypt
                            && st_json->key_type == st_cur->wep108_key[0].key_type
                            && !strcmp(st_json->key, st_cur->wep108_key[0].key)) {
                            continue;
                        }
                    }
                    else {
                        if (st_json->key_crypt == st_cur->wpa_key.key_crypt
                            && st_json->key_type == st_cur->wpa_key.key_type
                            && !strcmp(st_json->key, st_cur->wpa_key.key)) {
                            continue;
                        }
                    }
                }
            /* if change the st config, save the stid and disable it, then will be set config  */
            stid = st_cur_cfg->wlan_st_info[i].id;
            wlan_undo_service_template_enable(stid);
            /* st is changed, undo bind first, then change template  */
            for (k = 0; k < rd_cur_cfg->num; k++) {
                for (r = 0; r < sizeof(rd_cur_cfg->radioinfo[k].service)/sizeof(rd_cur_cfg->radioinfo[k].service[0]); r++) {                    
                    if (rd_cur_cfg->radioinfo[k].service[r] == stid) {
                        wlan_undo_bind(rd_cur_cfg->radioinfo[k].id, stid);
                        break;
                    }
                }
            }
        }
        else {
            /* does't not exist, get free stid and create it */
            stid = wlan_get_valid_stid();
            if ((ret = wlan_create_service_template(stid)) != 0) {
                nmsc_log("Create service template %d failed for %d.", stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT;
            }

            ret = wlan_set_ssid(stid, st_json->ssid);
            if (ret) {
                nmsc_log("Set service template %d ssid %s failed for %d.", stid, st_json->ssid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT;
            }
        }
        st_json->stid = stid;

        if (strlen(st_json->portal_scheme)) {
            /* bind new portal scheme directly */
            ret = wlan_set_portal_scheme(st_json->stid, st_json->portal_scheme);
            if (ret != 0) {
                nmsc_log("Set portal scheme %s to service template %d failed for %d.", 
                    st_json->portal_scheme, st_json->stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT; 
            }  
        }
        
        ret = wlan_set_beacon_ssid_hide(stid, st_json->beacon_ssid_hide);
        if (ret) {
            nmsc_log("Set service template %d beacon_ssid hide %d failed for %d.", stid,st_json->beacon_ssid_hide, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        ret = wlan_set_client_max(stid, st_json->client_max);
        if (ret) {
            nmsc_log("Set service template %d client_max %d failed for %d.", stid,st_json->client_max, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }        
        
        ret = wlan_set_auth(stid, st_json->auth);
        if (ret) {
            nmsc_log("Set service template %d auth %d failed for %d.", stid,st_json->auth, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        ret = wlan_set_cipher(stid, st_json->cipher);
        if (ret) {
            nmsc_log("Set service template %d cipher %d failed for %d.", stid,st_json->cipher, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        if (st_json->cipher == WLAN_CIPHER_WEP40) {
            ret = wlan_set_wep40_key(stid, st_json->wep_key_slot, 
                st_json->key_type, st_json->key_crypt, st_json->key);
        } 
        else  if (st_json->cipher == WLAN_CIPHER_WEP108) {
            ret = wlan_set_wep108_key(stid, st_json->wep_key_slot, 
                st_json->key_type, st_json->key_crypt, st_json->key);
        }
        else if (st_json->auth == WLAN_AUTH_WPA_PSK || st_json->auth == WLAN_AUTH_WPA2_PSK 
            || st_json->auth == WLAN_AUTH_WPA_MIXED_PSK) {
            ret = wlan_set_psk(stid, st_json->key, st_json->key_crypt, st_json->key_type);
        }
        
        if (ret) {
            nmsc_log("Set service template %d key %s failed for %d.", stid,st_json->key, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        ret = wlan_set_ptk_lifetime(stid, st_json->ptk_lifetime);
        if (ret) {
            nmsc_log("Set service template %d ptk_lifetime %d failed for %d.", stid, 
                st_json->ptk_lifetime, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        ret = wlan_set_ptk_lifetime_enable(stid, st_json->ptk_enabled);
        if (ret) {
            nmsc_log("Set service template %d ptk_enabled %d failed for %d.", stid, 
                st_json->ptk_enabled,  ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        ret = wlan_set_gtk_lifetime(stid, st_json->gtk_lifetime);
        if (ret) {
            nmsc_log("Set service template %d gtk_lifetime %d failed for %d.", stid, 
                st_json->gtk_lifetime, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        
        ret = wlan_set_gtk_lifetime_enable(stid, st_json->gtk_enabled);
        if (ret) {
            nmsc_log("Set service template %d gtk_enabled %d failed for %d.", stid, 
                st_json->gtk_enabled, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
		}

		if (strlen(st_json->radius_scheme) > 0) { 
			ret = wlan_set_radius_scheme(stid, st_json->radius_scheme); 
			if (ret) { 
				nmsc_log("Set service template %d radius_scheme %s failed for %d.", stid,st_json->radius_scheme, ret); 
				ret = dc_error_code(dc_error_commit_failed, node, ret);  
				goto ERROR_OUT; 
			} 
		}

#if OK_PATCH
        // add bandwidth_priority and client_isolation, guest network type
        ret = wlan_set_bandwidth_priority(stid, st_json->bandwidth_priority);
        if (ret) {
            nmsc_log("Set service template %d bandwidth_priority %d failed for %d.", stid, 
                st_json->bandwidth_priority, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }

        ret = wlan_set_client_isolation(stid, st_json->client_isolation);
        if (ret) {
            nmsc_log("Set service template %d client_isolation %d failed for %d.", stid, 
                st_json->client_isolation, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }

        ret = wlan_set_nettype(stid, st_json->type);
        if (ret) {
            nmsc_log("Set service template %d guest network type %d failed for %d.", stid, 
                st_json->type, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
        ret = wlan_set_ppsk_keys_url(stid, st_json->ppsk_keys_url);
        if (ret) {
            nmsc_log("Set service template %d guest network type %d failed for %d.", stid, 
                st_json->type, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
#endif

        //add for rate limit
        if(1 == st_json->uplink_limit_enable){//enable
            if(1 == st_json->uplink_limit_mode){//static
                ret = wlan_set_static_client_uplink_rate_limit_value(stid, st_json->uplink_limit_rate);
                if (ret) {
                    nmsc_log("Set service template %d static uplink limit rate %d failed for %d.", stid, 
                        st_json->uplink_limit_rate, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret); 
                    goto ERROR_OUT;
                }
            }else if(2 == st_json->uplink_limit_mode){//dynamic
                ret = wlan_set_dynamic_client_uplink_rate_limit_value(stid, st_json->uplink_limit_rate);
                if (ret) {
                    nmsc_log("Set service template %d dynamic uplink limit rate %d failed for %d.", stid, 
                        st_json->uplink_limit_rate, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret); 
                    goto ERROR_OUT;
                }
            }
        }else if(0 == st_json->uplink_limit_enable){//disable
            ret = wlan_undo_dynamic_client_uplink_rate_limit_value(stid);
            if (ret) {
                nmsc_log("Set service template %d undo dynamic uplink limit rate failed for %d.", stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT;
            }
            ret = wlan_undo_static_client_uplink_rate_limit_value(stid);  
            if (ret) {
                nmsc_log("Set service template %d undo static uplink limit rate failed for %d.", stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT;
            }
        }

        if(1 == st_json->downlink_limit_enable){//enable
            if(1 == st_json->downlink_limit_mode){//static
                ret = wlan_set_static_client_downlink_rate_limit_value(stid, st_json->downlink_limit_rate);
                if (ret) {
                    nmsc_log("Set service template %d static downlink limit rate %d failed for %d.", stid, 
                        st_json->downlink_limit_rate, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret); 
                    goto ERROR_OUT;
                }
            }else if(2 == st_json->downlink_limit_mode){//dynamic
                ret = wlan_set_dynamic_client_downlink_rate_limit_value(stid, st_json->downlink_limit_rate);
                if (ret) {
                    nmsc_log("Set service template %d dynamic downlink limit rate %d failed for %d.", stid, 
                        st_json->downlink_limit_rate, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret); 
                    goto ERROR_OUT;
                }
            }
        }else if(0 == st_json->downlink_limit_enable){//disable
            ret = wlan_undo_dynamic_client_downlink_rate_limit_value(stid);
            if (ret) {
                nmsc_log("Set service template %d undo dynamic uplink downlink rate failed for %d.", stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT;
            }
            ret = wlan_undo_static_client_downlink_rate_limit_value(stid);  
            if (ret) {
                nmsc_log("Set service template %d undo static limit downlink rate failed for %d.", stid, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret); 
                goto ERROR_OUT;
            }
        }
        //end for rate limit

        ret = wlan_set_service_template_enable(stid, st_json->enabled);
        if (ret) {
            nmsc_log("Enable service template %d failed for %d.", stid, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret); 
            goto ERROR_OUT;
        }
    }




    /* get all radio information again */
    memset(rd_cur_cfg, 0, sizeof(struct wlan_radio_info));
    if ((ret = wlan_radio_get_all(rd_cur_cfg)) != 0) {
        nmsc_log("Get all radio information failed for %d.", ret);
        ret = dc_error_code(dc_error_commit_failed, node, ret); 
        goto ERROR_OUT;
    }

    for (i = 0; i < rd_cur_cfg->num; i++) {
        for (j = 0; j < rd_json_cfg.num; j++) {
            if (rd_cur_cfg->radioinfo[i].id == rd_json_cfg.config[j].id) {
                break;
            }
        }

        if (j >= rd_json_cfg.num) {
            /* at least one radio cfg noexist in the json cfg, how to do? */
            nmsc_log("Radio %d config does not exist in the json config.", rd_cur_cfg->radioinfo[i].id);
            ret = dc_error_code(dc_error_node_noexixt, node, 0); 
            goto ERROR_OUT;
        }

        struct radio_info *rd_cur = &(rd_cur_cfg->radioinfo[i]);
        struct radio_json *rd_def;
        struct radio_json *rd_json = &(rd_json_cfg.config[j]);
        
        if (rd_json->id == 0) {
            rd_def = &rd0_def_cfg;
        }
        else if (rd_json->id == 1) {
            if (if_support_11ac(rd_json->id)) {
                rd_def = &rd1_def_cfg_11ac;
            }
            else {
                rd_def = &rd1_def_cfg;
            }
        }
        else {
            /* don't know which radio */
            nmsc_log("Don't know witch radio with the id %d.", rd_json->id);
            ret = dc_error_code(dc_error_node_noexixt, node, 0);
            goto ERROR_OUT;
            break;
        }

        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->mode, rd_def->mode);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->channel, rd_def->channel);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->max_power, rd_def->max_power);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->dot11nonly, rd_def->dot11nonly);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->dot11aconly, rd_def->dot11aconly);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->ampdu, rd_def->ampdu);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->bandwidth, rd_def->bandwidth);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->distance, rd_def->distance);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->preamble, rd_def->preamble);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->protection_mode, rd_def->protection_mode);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->beacon_interval, rd_def->beacon_interval);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->dtim, rd_def->dtim);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->fragment_threshold, rd_def->fragment_threshold);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->rts_threshold, rd_def->rts_threshold);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->short_gi, rd_def->short_gi);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->rssi_access, rd_def->rssi_access);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->rssi_access_threshold, rd_def->rssi_access_threshold);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->bcst_ratelimt, rd_def->bcst_ratelimt);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->bcst_ratelimt_cir, rd_def->bcst_ratelimt_cir);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->bcst_ratelimt_cbs, rd_def->bcst_ratelimt_cbs);
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->air_time_fairness, rd_def->air_time_fairness);
#if OK_PATCH
        CHECK_DEFAULT_INTEGER_CONFIG(rd_json->client_max, rd_def->client_max);
#endif
        
        if (rd_cur->enable) {
            /* disable it as rd_cur config is different from rd_json */
            if (rd_cur->radio.mode != rd_json->mode
                || rd_cur->radio.dot11nonly != rd_json->dot11nonly
                || rd_cur->radio.dot11aconly != rd_json->dot11aconly
                || rd_cur->radio.bandwidth != rd_json->bandwidth
                || rd_cur->radio.preamble != rd_json->preamble
                || rd_cur->radio.beacon_interval != rd_json->beacon_interval
                || rd_cur->radio.dtim != rd_json->dtim
                || rd_cur->radio.short_gi != rd_json->short_gi
                || rd_cur->radio.ampdu != rd_json->ampdu) {
                wlan_set_radio_enable(rd_json->id, 0);
            }
            else {
               /* rd_cur config is same as rd_json, check bind */ 
                for (k = 0; k < rd_cur->count; k++) {
                    char *ssid = NULL;
                    if (rd_cur->service[k] < 0) {
                        continue;
                    }

                    /* rd_cur binded ssid in st_json_cfg */
                    for (r = 0; r < st_json_cfg.num; r++) {
                        if (st_json_cfg.config[r].stid == rd_cur->service[k]) {
                            ssid = st_json_cfg.config[r].ssid;
                        }
                    }

                    if (ssid == NULL) {
                        nmsc_log("Can't find the ssid with the stid %d.", rd_cur->service[k]);
                        ret = dc_error_code(dc_error_commit_failed, node, 0);
                        goto ERROR_OUT;
                    }
                    
                    for (r = 0; r < rd_json->mbss_num; r++) {
                        if (!strcmp(ssid, rd_json->mbss[r].ssidname)) {
                            break;
                        }
                    }
                    if (r >= rd_json->mbss_num) {
                        wlan_set_radio_enable(rd_json->id, 0);
                        break;
                    }
                }

                for (r = 0; r < rd_json->mbss_num; r++) {
                    for (k = 0; k < rd_cur->count; k++) {
                        char *ssid = NULL;
                        if (rd_cur->service[k] < 0) {
                            continue;
                        }

                        for (m = 0; m < st_json_cfg.num; m++) {
                            if (st_json_cfg.config[m].stid == rd_cur->service[k]) {
                                ssid = st_json_cfg.config[m].ssid;
                                break;
                            }
                        }

                        if (ssid == NULL) {
                            nmsc_log("Can't find the ssid with the stid %d.", rd_cur->service[k]);
                            ret = dc_error_code(dc_error_commit_failed, node, 0);
                            goto ERROR_OUT;
                        }

                        if (!strcmp(ssid, rd_json->mbss[r].ssidname)) {
                            break;
                        }
                    }

                    if (k >= rd_cur->count) {
                        wlan_set_radio_enable(rd_json->id, 0);
                        break;
                    }
                }
                
            }
        }

        if (rd_cur->radio.mode != rd_json->mode) {
            ret = wlan_set_mode(rd_json->id, rd_json->mode);
            if (ret) {
                nmsc_log("Set radio %d mode %d failed for %d.", 
                    rd_json->id, rd_json->mode, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.channel != rd_json->channel) {
            ret = wlan_set_channel(rd_json->id, rd_json->channel);
            if (ret) {
                nmsc_log("Set radio %d channel %d failed for %d.", 
                    rd_json->id, rd_json->channel, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.max_power != rd_json->max_power) {
            ret = wlan_set_max_power(rd_json->id, rd_json->max_power);
            if (ret) {
                nmsc_log("Set radio %d max_power %d failed for %d.", 
                    rd_json->id, rd_json->max_power, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.dtim != rd_json->dtim) {
            ret = wlan_set_dtim(rd_json->id, rd_json->dtim);
            if (ret) {
                nmsc_log("Set radio %d dtim %d failed for %d.", 
                    rd_json->id, rd_json->dtim, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.fragment_threshold != rd_json->fragment_threshold) {
            ret = wlan_set_frag_threshold(rd_json->id, rd_json->fragment_threshold);
            if (ret) {
                nmsc_log("Set radio %d fragment_threshold %d failed for %d.", 
                    rd_json->id, rd_json->fragment_threshold, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }
        
        if (rd_cur->radio.rts_threshold != rd_json->rts_threshold) {
            ret = wlan_set_rts_threshold(rd_json->id, rd_json->rts_threshold);
            if (ret) {
                nmsc_log("Set radio %d rts_threshold %d failed for %d.", 
                    rd_json->id, rd_json->rts_threshold, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (1/* rd_cur->radio.short_gi != rd_json->short_gi */) {
            ret = wlan_set_short_gi(rd_json->id, rd_json->short_gi);
            if (ret) {
                nmsc_log("Set radio %d short_gi %d failed for %d:%d.", 
                    rd_json->id, rd_json->short_gi, ret,  rd_json->mode);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (1/* rd_cur->radio.ampdu != rd_json->ampdu */) {
            ret = wlan_set_ampdu(rd_json->id, rd_json->ampdu);
            if (ret) {
                nmsc_log("Set radio %d ampdu %d failed for %d.", 
                    rd_json->id, rd_json->ampdu, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.dot11nonly != rd_json->dot11nonly) {
            ret = wlan_set_dot11nonly(rd_json->id, rd_json->dot11nonly);
            if (ret) {
                nmsc_log("Set radio %d dot11nonly %d:%d failed for %d.", 
                    rd_json->id, rd_json->dot11nonly, rd_cur->radio.dot11nonly, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.dot11aconly != rd_json->dot11aconly) {
            ret = wlan_set_dot11aconly(rd_json->id, rd_json->dot11aconly);
            if (ret) {
                nmsc_log("Set radio %d dot11aconly %d:%d failed for %d.", 
                    rd_json->id, rd_json->dot11aconly, rd_cur->radio.dot11aconly, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (1/* rd_cur->radio.bandwidth != rd_json->bandwidth */) {
            ret = wlan_set_bandwidth(rd_json->id, rd_json->bandwidth);
            if (ret) {
                nmsc_log("Set radio %d bandwidth %d failed for %d.", 
                    rd_json->id, rd_json->bandwidth, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.distance != rd_json->distance) {
            ret = wlan_set_distance(rd_json->id, rd_json->distance);
            if (ret) {
                nmsc_log("Set radio %d distance %d failed for %d.", 
                    rd_json->id, rd_json->distance, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.preamble != rd_json->preamble) {
            ret = wlan_set_preamble(rd_json->id, rd_json->preamble);
            if (ret) {
                nmsc_log("Set radio %d preamble %d failed for %d.", 
                    rd_json->id, rd_json->preamble, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.protection_mode != rd_json->protection_mode) {
            ret = wlan_set_protection_mode(rd_json->id, rd_json->protection_mode);
            if (ret) {
                nmsc_log("Set radio %d protection_mode %d failed for %d.", 
                    rd_json->id, rd_json->protection_mode, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_cur->radio.beacon_interval != rd_json->beacon_interval) {
            ret = wlan_set_beacon_interval(rd_json->id, rd_json->beacon_interval);
            if (ret) {
                nmsc_log("Set radio %d beacon_interval %d failed for %d.", 
                    rd_json->id, rd_json->beacon_interval, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }
        
        if(rd_json->rssi_access){
            ret = wlan_set_rssi_threshold(rd_json->id, rd_json->rssi_access_threshold);
            if (ret) {
                nmsc_log("Set radio %d rssi threshold %d failed for %d.", 
                    rd_json->id, rd_json->rssi_access_threshold, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        
            ret = wlan_set_rssi(rd_json->id, 1);
            if (ret) {
                nmsc_log("Set radio %d rssi enable failed for %d.", rd_json->id, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }else{
            ret = wlan_set_rssi(rd_json->id, 0);
            if (ret) {
                nmsc_log("Set radio %d rssi disable failed for %d.", rd_json->id, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

#if OK_PATCH
        if (rd_cur->radio.client_max != rd_json->client_max) {
            ret = wlan_set_radio_client_max(rd_json->id, rd_json->client_max);
            if (ret) {
                nmsc_log("Set radio %d client_max %d failed for %d.", 
                    rd_json->id, rd_json->client_max, ret);   
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }
#endif

        /* added for broadcast rate limit */
        if (rd_json->bcst_ratelimt >= 0) {
            if (rd_json->bcst_ratelimt) {
                ret = wlan_set_bcast_ratelimit_enable(rd_json->id, 1);
            }
            else {
                ret = wlan_set_bcast_ratelimit_enable(rd_json->id, 0);
            }
            if (ret) {
                nmsc_log("Set radio %d broadcast ratelimit %s failed for %d.", 
                    rd_json->id, rd_json->bcst_ratelimt ? "enable" : "disable", ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }

            ret = wlan_set_bcast_ratelimit_param(rd_json->id, rd_json->bcst_ratelimt_cir, rd_json->bcst_ratelimt_cbs);
            if (ret) {
                nmsc_log("Set radio %d broadcast ratelimit parameter %d:%d failed for %d.", 
                    rd_json->id, rd_json->bcst_ratelimt_cir, rd_json->bcst_ratelimt_cbs, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }

        if (rd_json->air_time_fairness >= 0) {
            ret = wlan_set_atf(rd_json->id, !!rd_json->air_time_fairness);
            if (ret) {
               nmsc_log("Set radio %d atf %s failed for %d.", 
                    rd_json->id, rd_json->air_time_fairness ? "enable" : "disable", ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }


        /* unbind st, as st's ssid not set on this radio */
        for (k = 0; k < rd_cur->count; k++) {
            char *ssid;
            if (rd_cur->service[k] < 0) {
                continue;
            }

            for (r = 0; r < st_json_cfg.num; r++) {
                if (st_json_cfg.config[r].stid == rd_cur->service[k]) {
                    ssid = st_json_cfg.config[r].ssid;
                }
            }

            if (ssid == NULL) {
                continue;
            }
                    
            for (r = 0; r < rd_json->mbss_num; r++) {
                if (!strcmp(ssid, rd_json->mbss[r].ssidname)) {
                    break;
                }
            }
            if (r >= rd_json->mbss_num) {
                wlan_undo_bind(rd_json->id, rd_cur->service[k]);
            }
        }

        /* bind rd_json's new or changed st */
        for (r = 0; r < rd_json->mbss_num; r++) {
            for (k = 0; k < rd_cur->count; k++) {
                char *ssid = NULL;
                if (rd_cur->service[k] < 0) {
                    continue;
                }

                for (m = 0; m < st_json_cfg.num; m++) {
                    if (st_json_cfg.config[m].stid == rd_cur->service[k]) {
                        ssid = st_json_cfg.config[m].ssid;
                        break;
                    }
                }

                if (ssid == NULL) {
                    nmsc_log("Can't find the ssid with the stid %d.", rd_cur->service[k]);
                    ret = dc_error_code(dc_error_commit_failed, node, 0);
                    goto ERROR_OUT;
                }
                        
                if (!strcmp(ssid, rd_json->mbss[r].ssidname)) {
                    break;
                }
            }

            if (k >= rd_cur->count) {
                stid = -1;
                for (m = 0; m < st_json_cfg.num; m++) {
                    if (!strcmp(rd_json->mbss[r].ssidname, st_json_cfg.config[m].ssid)) {
                        stid = st_json_cfg.config[m].stid;
                    }
                }

                if (stid < 0) {
                    nmsc_log("Find the stid %d with ssid[%d] %s failed.", 
                        stid, r, rd_json->mbss[r].ssidname);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    goto ERROR_OUT;
                }

                if (later_enable) {
                    ret = wlan_set_service_template_enable(stid, st_json_cfg.config[m].enabled);
                    if (ret) {
                        nmsc_log("Enable service template %d failed for %d.", stid, ret);
                        ret = dc_error_code(dc_error_commit_failed, node, ret); 
                        goto ERROR_OUT;
                    }
                }

                ret = wlan_set_bind(rd_json->id, stid);

                if (ret) {
                    nmsc_log("Set the radio %d mbss bind %d:%d failed for %d.", rd_json->id, 0, stid, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    goto ERROR_OUT;
                }
            }
        }
    }

    /* no cfg from NMS for the as, need to do nothing */
    if (as_json_cfg.configed) {
        ret = dc_hdl_node_acl_scheme(STEP_OTHERS, st_cur_cfg, &st_json_cfg,
            as_cur_cfg, &as_json_cfg);
        if (ret) {
            nmsc_log("Handle acl scheme failed for %d.", ret);
            goto ERROR_OUT;
        }
    }

    if(tl_json_cfg.configed){
        ret = dc_hdl_node_time_limit(STEP_OTHERS, st_cur_cfg, &st_json_cfg,
            tl_cur_cfg, &tl_json_cfg);
        if (ret) {
            nmsc_log("Handle time limit failed for %d.", ret);
            goto ERROR_OUT;
        }
    }







    ret = 0;
ERROR_OUT:
    

    if (st_cur_cfg) {
        free(st_cur_cfg);
    }

    if (rd_cur_cfg) {
        free(rd_cur_cfg);
    }

    if (ps_cur_cfg.config) {
        portal_scheme_free_all(&ps_cur_cfg);
    }

    if (as_cur_cfg) {
        wlan_free_acl_all(as_cur_cfg);
    }

    if(tl_cur_cfg){
        free_scheme_time_range(tl_cur_cfg);
    }

    if (st_json_cfg.config) {
        free(st_json_cfg.config);
    }

    if (ps_json_cfg.config) {
        free(ps_json_cfg.config);
    }

    if (as_json_cfg.config) {
        if (as_json_cfg.config->maclist) {
            free(as_json_cfg.config->maclist);
        }
        free(as_json_cfg.config);
    }

    if (ds_json_cfg.config) {
        for (i = 0; i < ds_json_cfg.num; i++) {
            if (ds_json_cfg.config[i].keylist) {
                free(ds_json_cfg.config[i].keylist);
            }
        }
        free(ds_json_cfg.config);
    }

    if (is_json_cfg.sta_groupes) {
        free(is_json_cfg.sta_groupes);
    }

    if (ws_json_cfg.config) {
        free(ws_json_cfg.config);
    }
    
    return ret;
}

int dc_hdl_node_vlan_port(struct json_object *obj)
{
    struct vlan_port {
        char name[33];
        int  rdid;
        int  type;
        int  pvid;
        char pvlan[255];
    } vlan_port;
    struct vlan_portes {
        int num;
        struct vlan_port *config;
    } vlan_portes;

    struct node_pair_save paires[] = {
        {"name",    json_type_string, NULL, sizeof(vlan_port.name)},
        {"type",    json_type_int,    NULL, sizeof(vlan_port.type)},
        {"pvlan",   json_type_int,    NULL, sizeof(vlan_port.pvid)},
        {"permits", json_type_string, NULL, sizeof(vlan_port.pvlan)},
        {"radio",   json_type_int,    NULL, sizeof(vlan_port.rdid)}
    };   
    struct json_object *array;
    int i, ret = 0, size, node = dc_node_ports;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    size = json_object_array_length(obj);
    if (size <= 0) {
        return 0;
        //return dc_error_code(dc_error_obj_data, node, 0); 
    }

    memset(&vlan_portes, 0, sizeof(vlan_portes));
    vlan_portes.config = malloc(size * sizeof(struct vlan_port));
    if (vlan_portes.config == NULL) {
        ret = dc_error_code(dc_error_system, node, 0);
        goto ERROR_OUT;
    }
    memset(vlan_portes.config, 0, size * sizeof(struct vlan_port));
    
    for(i = 0; i < json_object_array_length(obj); i++) {    
        paires[0].value = vlan_portes.config[vlan_portes.num].name;
        paires[1].value = &(vlan_portes.config[vlan_portes.num].type);
        paires[2].value = &(vlan_portes.config[vlan_portes.num].pvid);
        paires[3].value = vlan_portes.config[vlan_portes.num].pvlan;
        paires[4].value = &(vlan_portes.config[vlan_portes.num].rdid);
        
        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
            ret = dc_error_code(ret, node, 0);
            goto ERROR_OUT;
        }
        vlan_portes.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }




    for (i = 0; i < vlan_portes.num; i++) {
        struct vlan_port *config;
        char *pvlan, sec[255];
        int start, end, sec_flag;
        
        config = &(vlan_portes.config[i]);
        /* convert ssid to ifname */
        if (config->rdid != -1) {
            int stid;
            wlan_get_stid_by_ssid(config->name, &stid);
            wlan_get_ifname_by_stid(config->rdid, stid, config->name);
        }
        
        if (config->type == 0) {
            config->type = VLAN_PORT_TYPE_ACCESS;
        }
        else {
            config->type = VLAN_PORT_TYPE_TRUNK;
            continue;
        }

        if ((ret = vlan_set_type(config->name, config->type)) != 0) {
            nmsc_log("Set port %s type %d:%d failed for %d.", config->name, 
                config->type, config->rdid, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            goto ERROR_OUT;
        }

        if ((ret = vlan_set_pvid(config->name, config->pvid, config->type)) != 0) {
            nmsc_log("Set port %s pvid %d failed for %d.", config->name, 
                config->pvid, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            goto ERROR_OUT;
        }
        continue;

        if (!strcasecmp(config->pvlan, "all")) {
            ret = vlan_permit_all(config->name);
            if (ret) {
                nmsc_log("Set port %s permit all failed for %d.", config->name, ret);
                ret = dc_error_code(dc_error_commit_failed, node, ret);
                goto ERROR_OUT;
            }
        }
        else {
            vlan_undo_permit_all(config->name);
            
            pvlan = config->pvlan;
            while (strlen(pvlan) > 0) {
                sec_flag = sscanf(pvlan, "%[^,]", sec);
                if (sec_flag != 1) {
                    strcpy(sec, pvlan);
                }
                ret = sscanf(sec, "%d-%d", &start, &end);
                if (ret != 2) {
                    start = end = atoi(sec);
                }

                if (!(start >= 1 && start <= 4094
                    && end >= 1 && end <= 4094)) {
                    nmsc_log("Bad vlan id form %d to %d.", start, end);
                    ret = dc_error_code(dc_error_obj_data, node, 0);
                    goto ERROR_OUT;
                }

                if ((ret = vlan_permit(config->name, start, end)) != 0) {
                    nmsc_log("Set port %s permit vlan form %d to %d failed for %d.", config->name, 
                        start, end, ret);
                    ret = dc_error_code(dc_error_commit_failed, node, ret);
                    goto ERROR_OUT;
                }

                if (sec_flag == 1) { 
                    pvlan += strlen(sec) + 1;

                }
                else {
                    break;
                }
            }
        }
    }
    ret = 0;
ERROR_OUT:
    if (vlan_portes.config) {
        free(vlan_portes.config);
    }

    return ret;
}

int dc_hdl_node_interface(struct json_object *obj)
{
    struct if_enable {
        int enable;
        char name[33];
    };
    struct if_enable_list {
        int num;
        struct if_enable *config;
    };

    struct if_enable_list interfaces;
    struct node_pair_save paires[] = {
        {"enabled",  json_type_int,    NULL, sizeof(int)},
        {"name",     json_type_string, NULL, 33},
    };  

    struct json_object *array;
    int i, ret, size, node = dc_node_interfaces;
    
    if (json_object_get_type(obj) != json_type_array) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    size = json_object_array_length(obj);
    if (size <= 0) {
        return 0;
    }

    memset(&interfaces, 0, sizeof(interfaces));
    interfaces.config = malloc(size * sizeof(struct if_enable));
    if (interfaces.config == NULL) {
        return dc_error_code(dc_error_system, node, 0);
    }
    memset(interfaces.config, 0, size * sizeof(struct if_enable));
    
    for(i = 0; i < size; i++) {    
        paires[0].value = &(interfaces.config[interfaces.num].enable);
        paires[1].value = interfaces.config[interfaces.num].name;

        array = json_object_array_get_idx(obj, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
            free(interfaces.config);
            return dc_error_code(ret, node, 0);
        }
        interfaces.num++;
        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
    }

    for (i = 0; i < interfaces.num; i++) {
        if ((ret = network_set_enable(interfaces.config[i].name, interfaces.config[i].enable)) != 0) {
            nmsc_log("Set the interface %s enable %d failed for %d.", 
                    interfaces.config[i].name, interfaces.config[i].enable, ret);
            ret = dc_error_code(dc_error_commit_failed, node, ret);
            break;
        } else {
            ret = 0;
        }
    }
    
    free(interfaces.config);

    return ret;    
}

int dc_hdl_node_capwap(struct json_object *obj)
{
    struct capwapc_config def_cfg, cur_cfg, json_cfg;

    struct node_pair_save paires[] = {
        {"enabled",       json_type_int,    &(json_cfg.enable),    sizeof(json_cfg.enable)},
        {"master_server", json_type_string, json_cfg.mas_server,   sizeof(json_cfg.mas_server)},
        {"slave_server",  json_type_string, json_cfg.sla_server,   sizeof(json_cfg.sla_server)},
        {"control_port",  json_type_int,    &(json_cfg.ctrl_port), sizeof(json_cfg.ctrl_port)},
        {"echo_interval", json_type_int,    &(json_cfg.echo_intv), sizeof(json_cfg.echo_intv)},
        {"mtu",           json_type_int,    &(json_cfg.mtu),       sizeof(json_cfg.mtu)}
    };  
    int ret, node = dc_node_capwap;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&json_cfg, 0, sizeof(json_cfg));

    if ((ret = dc_hdl_node_default(obj, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
        return dc_error_code(ret, node, 0);
    }
    log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));

    memset(&def_cfg, 0, sizeof(def_cfg));
    if (capwapc_get_defcfg(&def_cfg) != 0 
        && (is_default_integer_config(json_cfg.enable)
        || is_default_integer_config(json_cfg.ctrl_port)
        || is_default_integer_config(json_cfg.echo_intv)
        || is_default_integer_config(json_cfg.mtu)
        || is_default_string_config(json_cfg.mas_server)
        || is_default_string_config(json_cfg.sla_server))) {
        return dc_error_code(dc_error_defcfg_noexist, node, 0);
    }
    
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.enable, def_cfg.enable);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.ctrl_port, def_cfg.ctrl_port);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.echo_intv, def_cfg.echo_intv);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.mtu, def_cfg.mtu);
    CHECK_DEFAULT_STRING_CONFIG(mas_server);
    CHECK_DEFAULT_STRING_CONFIG(sla_server);




    memset(&cur_cfg, 0, sizeof(cur_cfg));
    if (capwapc_get_curcfg(&cur_cfg) != 0 
        || (json_cfg.enable != cur_cfg.enable
        || json_cfg.ctrl_port != cur_cfg.ctrl_port
        || json_cfg.echo_intv != cur_cfg.echo_intv
        || json_cfg.mtu != cur_cfg.mtu
        || strcmp(json_cfg.mas_server, cur_cfg.mas_server) != 0
        || strcmp(json_cfg.sla_server, cur_cfg.sla_server) != 0)) {

        if (strcmp(json_cfg.mas_server, cur_cfg.mas_server) != 0) {
            if (strlen(json_cfg.mas_server) > 0) {
                if ((ret = capwapc_set_masterserver(json_cfg.mas_server)) != 0) {
                    nmsc_log("Set capwap master server %s failed for %d.", 
                        json_cfg.mas_server, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }
            else {
                if ((ret = capwapc_undo_masterserver()) != 0) {
                    nmsc_log("Undo capwap master server %s failed for %d.", 
                        json_cfg.mas_server, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }
        }

        if (strcmp(json_cfg.sla_server, cur_cfg.sla_server) != 0) {
            if (strlen(json_cfg.sla_server) > 0) {
                if((ret = capwapc_set_slaveserver(json_cfg.sla_server)) != 0) {
                    nmsc_log("Set capwap slave server %s failed for %d.", 
                        json_cfg.mas_server, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }
            else {
                if((ret = capwapc_undo_slaveserver()) != 0) {
                    nmsc_log("Undo capwap slave server %s failed for %d.", 
                        json_cfg.mas_server, ret);
                    return dc_error_code(dc_error_commit_failed, node, ret);
                }
            }
        }
        
        if (json_cfg.ctrl_port != cur_cfg.ctrl_port) {
            if ((ret = capwapc_set_ctrlport(json_cfg.ctrl_port)) != 0) {
                nmsc_log("Set capwap server control port %d failed for %d.", 
                        json_cfg.ctrl_port, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        if (json_cfg.echo_intv != cur_cfg.echo_intv) {
            if ((ret = capwapc_set_echointv(json_cfg.echo_intv)) != 0) {
                nmsc_log("Set capwap server echo_intv %d failed for %d.", 
                        json_cfg.echo_intv, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        if (json_cfg.mtu != cur_cfg.mtu) {
            if ((ret = capwapc_set_mtu(json_cfg.mtu)) != 0) {
                nmsc_log("Set capwap server mtu %d failed for %d.", 
                        json_cfg.mtu, ret);
                return dc_error_code(dc_error_commit_failed, node, ret);
            }
        }

        if (json_cfg.enable) {
            dc_cawapc_later_action(CAPWAPC_LATER_EXEC_RESTART);           
        }
        else {
            dc_cawapc_later_action(CAPWAPC_LATER_EXEC_STOP);
        }
    }
    else {
        nmsc_log("Same capwap config, do nothing.");
    }

    return 0;
}

int dc_hdl_node_probe(struct json_object *obj)
{
    /* not support yet */
#if !OK_PATCH
    struct probe_config{
        int enable;
        int type;
        char server[129];
        int port;
        int report_interval;
    };
    struct probe_config json_cfg;

    struct node_pair_save paires[] = {
        {"enabled",         json_type_int,    &(json_cfg.enable),           sizeof(json_cfg.enable)},
        {"type",            json_type_int,    &(json_cfg.type),             sizeof(json_cfg.type)},
        {"server",          json_type_string, json_cfg.server,              sizeof(json_cfg.server)},
        {"port",            json_type_int,    &(json_cfg.port),             sizeof(json_cfg.port)},
        {"report_interval", json_type_int,    &(json_cfg.report_interval),  sizeof(json_cfg.report_interval)}
    };  
    int ret, node = dc_node_probe;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&json_cfg, 0, sizeof(json_cfg));

    if ((ret = dc_hdl_node_default(obj, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
        return dc_error_code(ret, node, 0);
    }
    log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));

    ret = wifi_sensor_disable();
    /* if set sensor disabled, no more config from NMS */
    if (json_cfg.enable == 0) {
        if (ret && ret != CMP_ERR_COMMIT_FAIL) {
            nmsc_log("Disable wifi sensor failed for %d.",  ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
        return 0;
    }

    switch (json_cfg.type) {
        case 1: /* type udp */
            ret = wifi_sensor_report_server_udp(json_cfg.server, json_cfg.port);
            break;

        case 2: /* type taodian */
            ret = wifi_sensor_report_server_taodian(json_cfg.server, json_cfg.port);
            break;

        default: /* unkonw type */
            nmsc_log("Unresolved wifi sensor type %d.", json_cfg.type);
            return dc_error_code(dc_error_obj_data, node, json_cfg.type);
    }
    if(ret != 0){
        nmsc_log("Set wifi sensor type %d server %s port %d failed for %d.", 
            json_cfg.type, json_cfg.server, json_cfg.port, ret);
        return dc_error_code(dc_error_commit_failed, node, ret);
    }

    if((ret = wifi_sensor_report_interval(json_cfg.report_interval)) != 0){
        nmsc_log("Set wifi sensor report interval %d failed for %d.", 
                    json_cfg.report_interval, ret);
        return dc_error_code(dc_error_commit_failed, node, ret);
    }

    if(1 == json_cfg.enable){
        if((ret = wifi_sensor_enable()) != 0){
            nmsc_log("Set wifi sensor enable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }

#endif
    return 0;
}

int dc_hdl_node_log(struct json_object *obj)
{
    log_infocenter def_cfg, json_cfg;
    int server_enable = 0;

    struct node_pair_save paires[] = {
        {"enabled",             json_type_int,    &(json_cfg.center.enable),    sizeof(json_cfg.center.enable)},
        {"log_server_enable",   json_type_int,    &(server_enable),             sizeof(server_enable)},
        {"server",              json_type_string, json_cfg.host.ip,             sizeof(json_cfg.host.ip)},
        {"log_server_level",    json_type_int,    &(json_cfg.host.level),       sizeof(json_cfg.host.level)},
        {"log_buffer_enable",   json_type_int,    &(json_cfg.buffer.enable),    sizeof(json_cfg.buffer.enable)},
        {"log_buffer_level",    json_type_int,    &(json_cfg.buffer.level),     sizeof(json_cfg.buffer.level)}    
    };  
    int ret, node = dc_node_log;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&json_cfg, 0, sizeof(json_cfg));
    json_cfg.host.level = LOG_DEBUG;
    json_cfg.buffer.level = LOG_DEBUG;

    if ((ret = dc_hdl_node_default(obj, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
        return dc_error_code(ret, node, 0);
    }
    log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));

    memset(&def_cfg, 0, sizeof(def_cfg));
    if (log_get_defcfg(&def_cfg) != 0 
        && (is_default_integer_config(json_cfg.center.enable)
        || is_default_integer_config(json_cfg.host.level)
        || is_default_integer_config(json_cfg.buffer.enable)
        || is_default_integer_config(json_cfg.buffer.level)
        || is_default_string_config(json_cfg.host.ip))) {
        return dc_error_code(dc_error_defcfg_noexist, node, 0);
    }

    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.center.enable, def_cfg.center.enable);
    CHECK_DEFAULT_STRING_CONFIG(host.ip);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.host.level, def_cfg.host.level);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.buffer.enable, def_cfg.buffer.enable);
    CHECK_DEFAULT_INTEGER_CONFIG(json_cfg.buffer.level, def_cfg.buffer.level);

    if(1 == json_cfg.center.enable){
        if((ret = log_enable_infocenter()) != 0){
            nmsc_log("Infocenter set log enable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }else{
        if((ret = log_undo_infocenter()) != 0){
            nmsc_log("Infocenter set log disable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }

    if(1 == server_enable){
        if((ret = log_set_hostip(json_cfg.host.ip)) != 0){
            nmsc_log("Infocenter set log host ip %s failed for %d.", json_cfg.host.ip, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
        if((ret = log_set_hostlevel(json_cfg.host.level)) != 0){
            nmsc_log("Infocenter set log host level %d failed for %d.", json_cfg.host.level, ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }else{
        if((ret = log_undo_hostip()) != 0){
            nmsc_log("Infocenter undo log host ip failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
        if((ret = log_undo_hostlevel()) != 0){
            nmsc_log("Infocenter undo log host level failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }

    if(1 == json_cfg.buffer.enable){
        if((ret = log_enable_buffer()) != 0){
            nmsc_log("Infocenter set log buffer enable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
        if((ret = log_set_bufferlevel(json_cfg.buffer.level)) != 0){
            nmsc_log("Infocenter set log buffer level failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }else{
        if((ret = log_undo_buffer()) != 0){
            nmsc_log("Infocenter set log buffer disable failed for %d.", ret);
            return dc_error_code(dc_error_commit_failed, node, ret);
        }
    }

    nmsc_delay_op_new(nmsc_delay_op_log, &json_cfg.center.enable, sizeof(json_cfg.buffer.level));
    
    return 0;
}

int dc_hdl_node_wds(struct json_object *obj)
{
    /* not supported yet */
#if !OK_PATCH

//#define MAC_BUF_LEN (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx") + 1)

    struct static_repeater{
        char repeater[MAC_BUF_LEN];
        char uplink[MAC_BUF_LEN];
    };
    struct wds_json{
        int enable;
        int role;
        char netid[33];
        int backhole;
        int auth;
        char key[65];
        int max_level;
        int auto_repeater_discovery;
        char acl[33];
        int static_repeater_count;
        struct static_repeater *config;
    }json_cfg;

    struct node_pair_save paires[] = {
        {"enable",                  json_type_int,    &(json_cfg.enable),                       sizeof(json_cfg.enable)},
        {"role",                    json_type_int,    &(json_cfg.role),                         sizeof(json_cfg.role)},
        {"netid",                   json_type_string, json_cfg.netid,                           sizeof(json_cfg.netid)},
        {"backhole",                json_type_int,    &(json_cfg.backhole),                     sizeof(json_cfg.backhole)},
        {"auth",                    json_type_int,    &(json_cfg.auth),                         sizeof(json_cfg.auth)},
        {"key",                     json_type_string, json_cfg.key,                             sizeof(json_cfg.key)},
        {"max_level",               json_type_int,    &(json_cfg.max_level),                    sizeof(json_cfg.max_level)},
        {"auto_repeater_discovery", json_type_int,    &(json_cfg.auto_repeater_discovery),      sizeof(json_cfg.auto_repeater_discovery)},
        {"acl_scheme",              json_type_string, json_cfg.acl,                      sizeof(json_cfg.acl)},
    };  
    struct json_object *subarray;
    int i, ret, subsize, node = dc_node_wds;
    
    if (json_object_get_type(obj) != json_type_object) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }

    memset(&json_cfg, 0, sizeof(json_cfg));

    json_object_object_foreach(obj, key, val) {
        if (json_object_get_type(val) == json_type_array) {
            //subsize = json_object_array_length(val);
            if (!strcasecmp(key, "static_repeaters")) {
                struct node_pair_save subpaires[] = {
                    {"repeater",    json_type_string, NULL, sizeof(((struct static_repeater *)0)->repeater)},
                    {"uplink",      json_type_string, NULL, sizeof(((struct static_repeater *)0)->uplink)},
                };

                if (json_cfg.config) {
                    free(json_cfg.config); 
                    json_cfg.config = NULL;
                }
                json_cfg.static_repeater_count = 0;

                subsize = json_object_array_length(val);
                if(subsize < 0){
                    continue;
                }

                json_cfg.config = (struct static_repeater *)malloc(subsize * sizeof(struct static_repeater));
                if (json_cfg.config == NULL) {
                    return dc_error_code(dc_error_system, node, 0);
                }
                memset(json_cfg.config, 0, subsize * sizeof(struct static_repeater));

                for(i = 0; i < subsize; i++) {
                    subpaires[0].value = json_cfg.config[i].repeater;
                    subpaires[1].value = json_cfg.config[i].uplink;

                    subarray = json_object_array_get_idx(val, i);
                    if ((ret = dc_hdl_node_default(subarray, subpaires, sizeof(subpaires)/sizeof(subpaires[0]))) != 0) {
                        if(json_cfg.config){
                            free(json_cfg.config);
                        }
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_paires(subpaires, sizeof(subpaires)/sizeof(subpaires[0]));
                    
                    json_cfg.static_repeater_count++;
                }
            }
        }else{
            for (i = 0; i < sizeof(paires)/sizeof(paires[0]); i++) {
                if (!strcasecmp(key, paires[i].key)) {
                    if ((ret = dc_hdl_node_default(val, &paires[i], 1)) != 0) {
                        if(json_cfg.config){
                            free(json_cfg.config);
                        }
                        return dc_error_code(ret, node, 0);
                    }
                    log_node_pair(paires[i]);
                }
            }
        }
    }

    if(1 == json_cfg.enable){
        if(1 == json_cfg.role){
            WDS_enter_rootap_config();
            /*wds set netid*/
            if((ret = WDS_set_netid_rootap(json_cfg.netid)) != 0){
                nmsc_log("Wds set root netid %s failed for %d.", json_cfg.netid, ret);
                goto err;
            }

            /*wds set backhole*/
            if(0 == json_cfg.backhole){
                if((ret = WDS_set_defult_backhaul_2g()) != 0){
                    nmsc_log("Wds set root defult backhole 2g failed for %d.", ret);
                    goto err;
                }
            }else{
                if((ret = WDS_set_defult_backhaul_5g()) != 0){
                    nmsc_log("Wds set root defult backhole 2g failed for %d.", ret);
                    goto err;
                }
            }

            /*wds set auth and key*/
            if(0 != json_cfg.auth){
                if((ret = WDS_set_rootap_key(WDS_CRYPT_CIPHER, json_cfg.key)) != 0){
                    nmsc_log("Wds set root cipher key:%s failed for %d.", json_cfg.key, ret);
                    goto err;
                }
            }else{
                if((ret = WDS_clean_rootap_key()) != 0){
                    nmsc_log("Wds undo root cipher failed for %d.", ret);
                    goto err;
                }
            }

            /*wds set max-level*/
            if((ret = WDS_set_maxlevel(json_cfg.max_level)) != 0){
                nmsc_log("Wds set root max_level %d failed for %d.", json_cfg.max_level, ret);
                goto err;
            }

            /*wds set auto-repeater discovery*/
            if(0 == json_cfg.auto_repeater_discovery){
                if((ret = WDS_set_discover_disable()) != 0){
                    nmsc_log("Wds disable root auto-repeater discovery failed for %d.", ret);
                    goto err;
                }
            }else{
                if((ret = WDS_set_discover_enable()) != 0){
                    nmsc_log("Wds enable root auto-repeater discovery failed for %d.", ret);
                    goto err;
                }
            }

            /*wds set acl*/
            #if 0
            ret = WDS_set_acl(json_cfg.acl);
            if(ret != 0 && ret != CMP_ERR_COMMIT_FAIL){
                nmsc_log("wds set acl %s failed for %d.", json_cfg.acl, ret);
                goto err;
            }
            #endif
            nmsc_delay_op_new(nmsc_delay_op_wds_acl, json_cfg.acl, sizeof(json_cfg.acl));
            /*wds set static_repeater*/
            if((ret = WDS_delall_uplink_opt()) != 0){
                nmsc_log("Wds del all uplink failed for %d.", ret);
                goto err;
            }
            
            for(i = 0; i < json_cfg.static_repeater_count; i++){
                char repeater_mac[6];
                char uplink_mac[6];

                memset(repeater_mac, 0, sizeof(repeater_mac));
                memset(uplink_mac, 0, sizeof(uplink_mac));
                                
                StrToMacAddr(json_cfg.config[i].repeater, repeater_mac);
                StrToMacAddr(json_cfg.config[i].uplink, uplink_mac);
                
                if((ret = WDS_add_uplink_opt(repeater_mac, uplink_mac)) != 0){
                    nmsc_log("Wds set repeater ap mac %s uplink mac %s failed for %d.", json_cfg.config[i].repeater, json_cfg.config[i].uplink, ret);
                    goto err;
                }
            }

            /*wds set root role*/
            #if 0
            ret = WDS_set_mode_rootap();
            if(ret != 0 && ret != CMP_ERR_COMMIT_FAIL){
                nmsc_log("Wds set root role failed for %d.", ret);
                goto err;
            }
            #endif
        }
        nmsc_delay_op_new(nmsc_delay_op_wds_mode, &(json_cfg.role), sizeof(json_cfg.role));

    }else{
        if((ret = WDS_clean_mode()) != 0){
            nmsc_log("Wds set disable failed for %d.", ret);
            goto err;
        }
    }

    if(json_cfg.config){
        free(json_cfg.config);
    }

    return 0;
err:
    if(json_cfg.config){
        free(json_cfg.config);
    }


    return dc_error_code(dc_error_commit_failed, node, ret);
#else
    return 0;
#endif
}

int dc_hdl_node_save_config(struct json_object *obj)
{

    int save = 0, ret, node = dc_node_save_config;
    struct node_pair_save pair = {
        .key   = "save_config",
        .type  = json_type_int,
        .value = &save,
        .size  = sizeof(save),
    };

    if (json_object_get_type(obj) != json_type_int) {
        return dc_error_code(dc_error_obj_type, node, 0);
    }
    
    if ((ret = dc_hdl_node_default(obj, &pair, 1)) != 0) {
        return dc_error_code(ret, node, 0);
    }

    log_node_pair(pair);
    
    if (save) {
        nmsc_delay_op_new(nmsc_delay_op_save_all, NULL, 0);
    }

    return 0;
}

