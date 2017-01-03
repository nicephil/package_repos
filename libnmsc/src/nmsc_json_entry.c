#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "json/json.h"
#include "nmsc/nmsc.h"
#include "nmsc_util.h"
#include "nmsc_json_node.h"

const dc_json_node dc_nodes[] = {
    {"type",            dc_hdl_node_type},
    {"config_version",  dc_hdl_node_version},
    {"system",          dc_hdl_node_system},
    {"users",           dc_hdl_node_usrmanage}, /* not supported */
    {"ntp",             dc_hdl_node_ntp},
    {"dns",             dc_hdl_node_dns},
    {"radiuss",         dc_hdl_node_radius}, /* not supported */
    {"network",         dc_hdl_node_network}, /* not supported */
    {"ether_interfaces",dc_hdl_node_ethif}, /* not supported */
    {"vlans",           dc_hdl_node_vlan},
    {"vlan_interfaces", dc_hdl_node_vlan_interface}, /* not supported */
    {"nat",             dc_hdl_node_nat},  /* not supported */
    {"dialers",         dc_hdl_node_dialer}, /* not supported */
    {"wlan",            dc_hdl_node_wlan}, /* TODO */
    {"ports",           dc_hdl_node_vlan_port}, /* ? */
    {"interfaces",      dc_hdl_node_interface},
    {"capwap",          dc_hdl_node_capwap},
    {"probe",           dc_hdl_node_probe},  /* not supported */
    {"log",             dc_hdl_node_log},
    {"wds",             dc_hdl_node_wds},   /* not supported */
    {"save_config",     dc_hdl_node_save_config}
};
#define DC_JSON_NODES_COUNT  sizeof(dc_nodes)/sizeof(dc_nodes[0])
#define foreach_dc_nodes(node) \
int ll; \
for (ll = 0; ({if(ll < DC_JSON_NODES_COUNT) node = &(dc_nodes[ll]); ll < DC_JSON_NODES_COUNT;}); ll++)
    
static inline const dc_json_node* dc_get_json_node(const char *key)
{
    const dc_json_node *node;

    foreach_dc_nodes(node) {
        if (!strcmp(node->key, key)) {
            return node;
        }
    }

    return NULL;
}

int dc_hdl_entry_singleobj(struct json_object *obj, const char *obj_key)
{
    const dc_json_node *node = NULL;

    node = dc_get_json_node(obj_key);
    if (node) {
        nmsc_log("Tye to handle the %s node's json config.", obj_key);
        return node->node_handler(obj);
    }

    nmsc_log("Can not find the %s node's handler.", obj_key);

    /* Only handle recognized, others will be ignored */
    return 0; //dc_error_code(dc_error_node_noexixt, dc_node_common, 0);
}

int dc_hdl_entry_multiobj(struct json_object *obj, const char *obj_key)
{
    int ret = 0;

    /* unused param */
    obj_key = obj_key;
    
    json_object_object_foreach(obj, key, val) {  
        if ((ret = dc_hdl_entry_singleobj(val, key)) != 0) {
            return ret;
        }
    }
   
    return 0;
}


