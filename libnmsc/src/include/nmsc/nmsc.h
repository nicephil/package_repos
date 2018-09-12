#ifndef __NMSC_H__
#define __NMSC_H__

#include "json/json.h"
 
/* both dc_eror and dc_node will notiy to the NMS,
 * need keep the order to synchronize with NMS
 * so all the follow-up to last
 */
typedef enum dc_error {
    dc_error_system         = 1,
    dc_error_json_format,
    dc_error_obj_type,
    dc_error_node_noexixt,
    dc_error_obj_data,      /*5*/
    dc_error_unknow_obj,
    dc_error_save_obj,
    dc_error_defcfg_noexist,
    dc_error_commit_failed, 
    dc_error_imgdown_failed, /*10*/
    dc_error_imgupgrade_failed,
    dc_error_invalid_imgversion,
    dc_error_uploadtechsupport_failed,
    dc_error_ssh_host_not_allow_connect,
    dc_error_ssh_username_or_password,  /*15*/
    dc_error_ssh_bad_listense_port,
    dc_error_ssh_connection_already_exist,
    dc_error_unsupport_cmd,
    dc_error_unreport_info,
} dc_error;

typedef enum dc_node {
    dc_node_common          = 1,
    dc_node_type,
    dc_node_config_version,
    dc_node_hostname, 
    dc_node_location,        /* 5 */
    dc_node_system,       
    dc_node_users,         
    dc_node_ntp,          
    dc_node_dns,           
    dc_node_radiuss,         /* 10 */
    dc_node_vlans,        
    dc_node_vlan_interfaces,
    dc_node_dialers,
    dc_node_service_template,
    dc_node_radio,           /* 15 */
    dc_node_wlan,
    dc_node_ports,
    dc_node_interfaces,
    dc_node_capwap,
    dc_node_save_config,     /* 20 */
    dc_node_sta_kickoff,
    dc_node_image_upgrade,
    dc_node_reboot,
    dc_node_portal_scheme,
    dc_node_portal_offline,  /* 25 */
    dc_node_portal_authentication,
    dc_node_probe,
    dc_node_upload_techsupport,
    dc_node_log,
    dc_node_client_isolation,/* 30 */
    dc_node_acl_scheme,
    dc_node_rrm,
    dc_node_ssid_timerange,
    dc_node_band_steer,
    dc_node_dhcpd,           /* 35 */ 
    dc_node_dns_set,
    dc_node_ssh_tunnel,
    dc_node_alg,
    dc_node_rate_optimize,
    dc_node_igmp,            /* 40 */
    dc_node_ethif,
    dc_node_portal_preauth,
    dc_node_dns_proxy,
    dc_node_route_forward,
    dc_node_arp_optimize,    /* 45 */
    dc_node_wds, 
    dc_node_country_code, 
    dc_node_wlan_scan,
    dc_node_zone,
    dc_node_dfs_toggle,    /* 50 */
} dc_node;

struct node_pair_save {
    char *key;
    json_type type;
    void *value;
    int size;
};

static inline int dc_error_code(int type, int node, int error)
{
    int code = 0;
    int reason = ((error >> 16) & 0xffff);

    code |= (0xff & type) << 24;
    code |= (0xff & node) << 16;
    if (reason != 0xffff) {
        code |= reason;
    }

    return code;
}

extern int dc_json_machine(const char *data);
extern char *dc_get_handresult(void);
extern int dc_get_handcode(void);
extern int dc_restart_cawapc(void);
extern int dc_stop_cawapc(void);
extern int dc_is_handle_doing(void);
extern int dc_hdl_node_default(struct json_object *obj, struct node_pair_save *paires, int size);
#endif
