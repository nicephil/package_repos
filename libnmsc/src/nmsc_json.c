#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include "nmsc/nmsc.h"
#include "nmsc_util.h"
#include "json/json.h"
#include "nmsc_json_entry.h"
#include "nmsc_json.h"

const dc_json_entry dc_entries[] = {
    {0,  "type",            dc_hdl_entry_singleobj},
    {10, "mgmt",            dc_hdl_entry_multiobj},
    {20, "server",          dc_hdl_entry_multiobj},
    {25, "network",         dc_hdl_entry_singleobj},   
    {26, "ether_interfaces",dc_hdl_entry_singleobj},
    {30, "vlans",           dc_hdl_entry_singleobj},
    {40, "vlan_interfaces", dc_hdl_entry_singleobj},
    {45, "nat",             dc_hdl_entry_singleobj},    
    {50, "dialers",         dc_hdl_entry_singleobj},
    {55, "wds",             dc_hdl_entry_singleobj},
    {60, "wlan",            dc_hdl_entry_singleobj},         
    {70, "ports",           dc_hdl_entry_singleobj},        
    {80, "interfaces",      dc_hdl_entry_singleobj},
    {90, "save_config",     dc_hdl_entry_singleobj},
    {99, "config_version",  dc_hdl_entry_singleobj}
};
#define DC_JSON_ENTRIES_COUNT  sizeof(dc_entries)/sizeof(dc_entries[0])
#define foreach_dc_entries(entry) \
int ii; \
for (ii = 0; ({if(ii < DC_JSON_ENTRIES_COUNT) entry = &(dc_entries[ii]); ii < DC_JSON_ENTRIES_COUNT;}); ii++)

struct dc_handle_result {
    int  code;
    char key[32];
} g_handle_result;

static int g_hanndle_doing = 0;
static int g_capwapc_exec_later = CAPWAPC_LATER_EXEC_NOTHING;

void dc_cawapc_later_action(int action)
{
    g_capwapc_exec_later = action;
}

int dc_restart_cawapc(void)
{
    int ret = (g_capwapc_exec_later == CAPWAPC_LATER_EXEC_RESTART);

    g_capwapc_exec_later = CAPWAPC_LATER_EXEC_NOTHING;
    
    return ret;
}

int dc_stop_cawapc(void)
{
    int ret = (g_capwapc_exec_later == CAPWAPC_LATER_EXEC_STOP);

    g_capwapc_exec_later = CAPWAPC_LATER_EXEC_NOTHING;
    
    return ret;
}

static void dc_reset_handle_result(void)
{
    memset(&g_handle_result, 0, sizeof(g_handle_result));
}

static void dc_set_handle_result(int code, char *key)
{
    g_handle_result.code = code;
    strncpy(g_handle_result.key, key, sizeof(g_handle_result.key) - 1);
}

static void dc_get_handle_result(struct dc_handle_result *result)
{
    memcpy(result, &g_handle_result, sizeof(struct dc_handle_result));    
}

int dc_get_handcode(void)
{
    return (g_handle_result.code);
}

char *dc_get_handresult(void)
{
    struct dc_handle_result result;
    json_object *resp_obj = NULL;
    char *json_string;
    
    resp_obj = json_object_new_object();
    if (!resp_obj) {
        return NULL;
    }
    
    dc_get_handle_result(&result);

    json_object_object_add(resp_obj, "code", json_object_new_int(result.code));    
    if (result.code && strlen(result.key) > 0) {
        json_object_object_add(resp_obj, "desc", json_object_new_string(result.key));
    }

    json_string = malloc(strlen(json_object_to_json_string(resp_obj)) + 1);
    if (!json_string) {
        return NULL;
    }
    strcpy(json_string, json_object_to_json_string(resp_obj));
    json_object_put(resp_obj);

    return json_string;
}

static inline void dc_handle_doing(void)
{
    g_hanndle_doing = 1;
}

static inline void dc_handle_done(void)
{
    g_hanndle_doing = 0;
}

int dc_is_handle_doing(void)
{
    return (g_hanndle_doing == 1);
}


int dc_json_machine(const char *data)
{
    struct json_object *root;
    const struct dc_json_entry *dc_entry;
    int ret = 0, entry_handled;

    dc_reset_handle_result();
        
    root = json_tokener_parse(data);
    if (is_error(root)) {
        nmsc_log("Parse config from NMS failed.");
        dc_set_handle_result(dc_error_code(dc_error_json_format, dc_node_common, 0), "Parse failed");
        return dc_error_json_format;
    }

    dc_handle_doing();
#if !OK_PATCH
    cfg_disable_version_notice();
#endif
    nmsc_delay_op_init();
    foreach_dc_entries(dc_entry) {  
        json_object_object_foreach(root, key, val) {
            if (!strcmp(dc_entry->key, key)) {
                nmsc_log("Tye to handle the %s entry's json config.", dc_entry->key);
                ret = dc_entry->json_handler(val, key);
                if (ret != 0) {
                    nmsc_log("Handle the module %s config data failed for reason code: %d.", 
                        dc_entry->key, ret);
                    dc_set_handle_result(ret, key);
                    goto ERROR_OUT;
                }
                break;
            }
        }
    }
    ret = nmsc_delay_op_done();
    if (ret) {
        dc_set_handle_result(ret, "Config commit failed.");
        goto ERROR_OUT;
    }

    json_object_object_foreach(root, key, val) {
        entry_handled = 0;
        foreach_dc_entries(dc_entry) { 
            if (!strcmp(dc_entry->key, key)) {
                entry_handled = 1;
                break;
            }
        }
        if (!entry_handled) {
             /* Only handle recognized, others will be ignored */
            nmsc_log("Can not find the module %s entry.", key);
            //dc_set_handle_result(dc_error_code(dc_error_unknow_obj, dc_node_common, 0), key);
            //return dc_error_unknow_obj;
        }
    }

ERROR_OUT:  
#if !OK_PATCH
    cfg_enable_version_notice();
#endif
    dc_handle_done();
    nmsc_delay_op_release();
    json_object_put(root);
        
    return ret;
}

