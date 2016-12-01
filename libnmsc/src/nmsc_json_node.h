#ifndef __NMSC_JSON_NODES_H__
#define __NMSC_JSON_NODES_H__

typedef struct dc_json_node {
    char *key;
    int (*node_handler)(struct json_object *obj);
} dc_json_node;

extern int dc_hdl_node_type(struct json_object *obj);
extern int dc_hdl_node_version(struct json_object *obj);
extern int dc_hdl_node_system(struct json_object *obj);
extern int dc_hdl_node_usrmanage(struct json_object *obj);
extern int dc_hdl_node_ntp(struct json_object *obj);
extern int dc_hdl_node_dns(struct json_object *obj);
extern int dc_hdl_node_radius(struct json_object *obj);
extern int dc_hdl_node_network(struct json_object *obj);
extern int dc_hdl_node_ethif(struct json_object *obj);
extern int dc_hdl_node_vlan(struct json_object *obj);
extern int dc_hdl_node_vlan_interface(struct json_object *obj);
extern int dc_hdl_node_nat(struct json_object *obj);
extern int dc_hdl_node_dialer(struct json_object *obj);
extern int dc_hdl_node_wlan(struct json_object *obj);
extern int dc_hdl_node_vlan_port(struct json_object *obj);
extern int dc_hdl_node_interface(struct json_object *obj);
extern int dc_hdl_node_capwap(struct json_object *obj);
extern int dc_hdl_node_probe(struct json_object *obj);
extern int dc_hdl_node_log(struct json_object *obj);
extern int dc_hdl_node_wds(struct json_object *obj);
extern int dc_hdl_node_save_config(struct json_object *obj);
#endif
