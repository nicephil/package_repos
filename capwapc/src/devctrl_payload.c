#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h> 
#include <time.h>
#include <sqlite3.h>
#include "CWWTP.h"
#include "devctrl_protocol.h"
#include "devctrl_payload.h"
#include "devctrl_notice.h"
#include "json/json.h"
#include "nmsc/nmsc.h"

#include "services/cfg_services.h"
#include "services/portal_services.h"
#include "services/wlan_services.h"

extern void log_node_paires(struct node_pair_save *paires, int size);

static inline char *dc_generate_json_result(int code)
{
    json_object *resp_obj = NULL;
    char *json_string;
    
    resp_obj = json_object_new_object();
    if (!resp_obj) {
        return NULL;
    }
    
    json_object_object_add(resp_obj, "code", json_object_new_int(code));    

    json_string = malloc(strlen(json_object_to_json_string(resp_obj)) + 1);
    if (!json_string) {
        json_object_put(resp_obj);
        return NULL;
    }
    strcpy(json_string, json_object_to_json_string(resp_obj));
    json_object_put(resp_obj);

    return json_string;
}

static inline int dc_response(char *payload, int length, devctrl_block_s *dc_block)
{
    devctrl_block_s dc_resp;
    int ret = 0; 

    dc_resp.version    = dc_block->version;
    memcpy(dc_resp.cookie, dc_block->cookie, sizeof(dc_resp.cookie));
    dc_resp.type       = 1;       /* payload between nms and device */
    dc_resp.compressed = 0;       /* no compress */
    dc_resp.orig_len   = length; 
    dc_resp.len        = length; 
    dc_resp.data       = payload;
    
    if (!WTPEventRequest_devctrlresp(CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE, 
        (int)(&dc_resp))) {
        ret = -1;
        CWDebugLog("Send WTPEventReq with device control resopnse element failed.");
    }
    
    return ret;
}

static int dc_default_finished(void *reserved)
{
    if (reserved) {
        free(reserved);
    }
    
    return 0;
}

static int dc_json_config_handler(struct tlv *payload, void **reserved)
{
    int ret;
    char terminated;

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    ret = dc_json_machine(payload->v);
    payload->v[payload->l] = terminated;

    return ret;
}

static int dc_json_config_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0; 
    
    json_data = dc_get_handresult();
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* config result with json format */
    save_payload_type(payload, DC_PAYLOAD_CONFIG_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

static int dc_json_config_finished(void *reserved)
{
    system("/lib/okos/restartservices.sh");
    dc_stop_cawapc();
    dc_restart_cawapc();


    if (reserved) {
        free(reserved);
    }
    return 0;
}

static inline int dc_set_ratelimit_sta(const char *mac, int tx_rate_limit, int rx_rate_limit)
{
    char buf[128];
    sprintf(buf, "/lib/okos/setratelimit.sh %s %d %d", mac, tx_rate_limit, rx_rate_limit);
    system(buf);
    return 0;
}

static inline int dc_set_whitelist_sta(const char *mac, int time, int action)
{
    char buf[128];
    sprintf(buf, "/lib/okos/setwhitelist.sh %s %d %d", mac, time, action);
    system(buf);
    return 0;
}

static inline int dc_set_blacklist_sta(const char *mac, int time, int action)
{
    char buf[128];
    sprintf(buf, "/lib/okos/setblacklist.sh %s %d %d", mac, time, action);
    system(buf);
    return 0;
}

static inline int dc_kickoff_sta(const char *ssid, char *mac)
{
    char buf[128];
    sprintf(buf, "iwconfig 2>/dev/null | awk \'/ath/{system(\"iwpriv \"$1\" kickmac %s\");}\'", mac);
    system(buf);

    return 0;
}

static int dc_sta_kickoff_handler(struct tlv *payload, void **reserved)
{
    struct kickoff_cmd {
        char mac[32];
        char ssid[33];
    };
    struct kickoff_cmd json_cfg;
    struct node_pair_save paires[] = {
        {"mac",   json_type_string, json_cfg.mac,       sizeof(json_cfg.mac)},
        {"ssid",  json_type_string, json_cfg.ssid,       sizeof(json_cfg.ssid)},
    }; 
    struct json_object *root, *array;
    int ret, i=0;
    char terminated;

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    

    if (json_object_get_type(root) != json_type_object) {
        ret = dc_error_obj_type;
        goto ERROR_OUT;
    }    
    json_object_object_foreach(root, key, val) {
        if (!strcasecmp(key, "clients") && json_object_get_type(val) == json_type_array) {
            for (i = 0; i < json_object_array_length(val); i++) {
                memset(&json_cfg, 0, sizeof(json_cfg));
                
                array = json_object_array_get_idx(val, i);
                if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
                    goto ERROR_OUT;
                }

                log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));
                
                if ((ret = dc_kickoff_sta(json_cfg.ssid, json_cfg.mac)) != 0) {
                    CWLog("Try to kick off sta %s attached the ssid %s failed for %d.", 
                        json_cfg.mac, json_cfg.ssid, ret);
                    ret = dc_error_commit_failed;
                    goto ERROR_OUT;
                }
            }
        }
    }

ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }
    
    if (ret) {
        *reserved = malloc(sizeof(int));
        if (*reserved) {
            *((int *)(*reserved)) = ret;
        }
    }
    
    return ret;
}

static int dc_sta_kickoff_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code = 0; 

    if (reserved) { /* it means something wrong during handling */
        code = *((int *)reserved);
        code = dc_error_code(code, dc_node_sta_kickoff,  0);
    }
    json_data = dc_generate_json_result(code);
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* kickoff result with json format */
    save_payload_type(payload, DC_PAYLOAD_STA_KICKOFF_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

static int dc_sta_query_response(devctrl_block_s *dc_block, void *reserved)
{
    struct wlan_sta_stat *stas = NULL;
    char *payload, *data = NULL;
    int paylength = 0, ret = 0, count = 0; 

    count = dc_get_wlan_sta_stats(&stas, 0);
    if (assemble_wlan_sta_status_elem(&data, &paylength, stas, count, WLAN_STA_TYPE_QUERY) != CW_TRUE) {
        CWLog("Get wlan client stat count %d but assmeble query msg failed.", count);
        goto err;
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto err;});

    /* sta query result with json format */
    save_payload_type(payload, DC_PAYLOAD_STA_QUERY_RESULT);
    save_payload_length(payload + 2, paylength);

    if (data) {
        CW_COPY_MEMORY(payload + 6, data, paylength);
        free(data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
err:
    if(stas){
        free(stas);
    }
    
    return ret;
}

static int dc_image_upgrade_handler(struct tlv *payload, void **reserved)
{
#define CST_IMG_TMP_FILE    "/tmp/okos_tmp.img"
    struct image_upgrade_cmd {
        char src[256];
        char usr[33];
        char pwd[33];
        int  action;
        int  timeout;
    };
    struct image_upgrade_cmd json_cfg;
    struct node_pair_save paires[] = {
        {"source",   json_type_string, json_cfg.src,       sizeof(json_cfg.src)},
        {"user",     json_type_string, json_cfg.usr,       sizeof(json_cfg.usr)},
        {"password", json_type_string, json_cfg.pwd,       sizeof(json_cfg.pwd)},
        {"delay",    json_type_int,    &(json_cfg.action), sizeof(json_cfg.action)},
        {"timeout",  json_type_int,    &(json_cfg.timeout), sizeof(json_cfg.timeout)}
    }; 
    struct json_object *root;
    int ret;
    char terminated, cmd[256];

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    

    memset(&json_cfg, 0, sizeof(json_cfg));
    json_cfg.timeout = 1200; /* same with NMS defualt timeout 20 minutes */
    if ((ret = dc_hdl_node_default(root, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
        goto ERROR_OUT;
    }

    sprintf(cmd, "wget -q -T %d -O - \'%s\' | tail -c +65 | tar xzf - -O > %s", json_cfg.timeout, json_cfg.src, CST_IMG_TMP_FILE);
    ret = system(cmd);
    if (ret) {
        CWDebugLog("Running cmd %s failed.", cmd);
        ret = dc_error_imgdown_failed;
        sprintf(cmd, "rm -rf %s", CST_IMG_TMP_FILE);
        system(cmd);
        goto ERROR_OUT;
    }
    ret = cfg_upgrade_image(CST_IMG_TMP_FILE);
    //sprintf(cmd, "rm -rf %s", CST_IMG_TMP_FILE);
    //system(cmd);
    CWDebugLog("Upgrade image result %d.", ret);
    if (ret == VERSION_MATCH_FAILED) {
        ret = dc_error_invalid_imgversion;
        goto ERROR_OUT;
    }
    else if (ret != 0) {
        ret = dc_error_imgupgrade_failed;
        goto ERROR_OUT;
    }

    /* yes, i don't care the jsco_cfg.action */
ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }
    if (ret) {
        *reserved = malloc(sizeof(int));
        if (*reserved) {
            *((int *)(*reserved)) = ret;
        }
    }
    
    return ret;
}

static int dc_image_upgrade_response(devctrl_block_s *dc_block, void *reserved)
{
#if !OK_PATCH
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code = 0; 

    if (reserved) { /* it means something wrong during handling */
        code = *((int *)reserved);
        code = dc_error_code(code, dc_node_image_upgrade,  0);
    }
    json_data = dc_generate_json_result(code);
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* image upgrade result with json format */
    save_payload_type(payload, DC_PAYLOAD_IMAGE_UPGRADE_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
#else
    return 0;
#endif
}

static int dc_reboot_handler(struct tlv *payload, void **reserved)
{
    return system("/sbin/reboot -f");
}

static int dc_reboot_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code; 

    /* execute here, it means reboot failed */
    code = dc_error_code(dc_error_commit_failed, dc_node_reboot,  0);
    json_data = dc_generate_json_result(code);
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* config result with json format */
    save_payload_type(payload, DC_PAYLOAD_REBOOT_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

enum {
    OT_KICKOFF = 1,
    OT_OFFLINE,
    OT_KICKOFF_OFFLINE,
    OT_SET_BLACKLIST,
    OT_UNSET_BLACKLIST,
    OT_SET_WHITELIST,
    OT_UNSET_WHITELIST,
    OT_RATELIMIT
} OPERATE_TYPE;

static int dc_portal_offline_handler(struct tlv *payload, void **reserved)
{
    struct portal_cmd {
        char mac[20];
        char scheme[PORTAL_NAME_MAX_LENGTH + 1];
        int time;
        int tx_rate_limit;
        int rx_rate_limit;
    };
    struct portal_cmd json_cfg = {0};
    struct node_pair_save paires[] = {
        {"mac",           json_type_string, json_cfg.mac,    sizeof(json_cfg.mac)},
        {"portal_scheme", json_type_string, json_cfg.scheme, sizeof(json_cfg.scheme)},
        {"time", json_type_int, &(json_cfg.time), sizeof(json_cfg.time)},
        {"tx_rate_limit", json_type_int, &(json_cfg.tx_rate_limit), sizeof(json_cfg.tx_rate_limit)},
        {"rx_rate_limit", json_type_int, &(json_cfg.rx_rate_limit), sizeof(json_cfg.rx_rate_limit)},

    }; 
    int operate_type;
    struct node_pair_save ot_paire[] = {
        {"operate_type", json_type_int, &operate_type, sizeof(operate_type)}
    };
    struct json_object *root, *array;
    int ret, size, i;
    char terminated;

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    


    {
        json_object_object_foreach(root, key, val) {
            if (!strcmp(key, "operate_type")) {
                if ((ret = dc_hdl_node_default(val, ot_paire, sizeof(ot_paire)/sizeof(ot_paire[0])))!= 0) {
                    goto ERROR_OUT;
                }
                log_node_paires(ot_paire, sizeof(ot_paire)/sizeof(ot_paire[0]));
                break;
            }
        }
    }

    json_object_object_foreach(root, key, val) {
        if (!strcmp(key, "clients")){
            if (json_object_get_type(val) != json_type_array) {
                ret = dc_error_obj_type;
                goto ERROR_OUT;
            }
            break;
        }
    }


    size = json_object_array_length(val);
    if (size <= 0) {
        ret = 0;
        goto ERROR_OUT;
    }

    for(i = 0; i < size; i++) { 
        memset(&json_cfg, 0, sizeof(json_cfg));

        array = json_object_array_get_idx(val, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
            goto ERROR_OUT;
        }

        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));


        switch(operate_type) {
            case OT_KICKOFF:
                if ((ret = dc_kickoff_sta(NULL, json_cfg.mac)) != 0) {
                    CWLog("Try to kick off sta %s attached the ssid %s failed for %d.", 
                            json_cfg.mac, "ALL", ret);
                    ret = dc_error_commit_failed;
                    goto ERROR_OUT;
                }
                break;
            case OT_OFFLINE:
                if ((ret = portal_scheme_del_sta(json_cfg.scheme, json_cfg.mac)) != 0) {
                    CWLog("Deauth the sta %s form the  portal scheme %s failed for %d.", 
                            json_cfg.mac, json_cfg.scheme, ret);
                    ret = dc_error_commit_failed;
                    goto ERROR_OUT;
                }
                break;
            case OT_KICKOFF_OFFLINE:
                if ((ret = portal_scheme_del_sta(json_cfg.scheme, json_cfg.mac)) != 0) {
                    CWLog("Deauth the sta %s form the  portal scheme %s failed for %d.", 
                            json_cfg.mac, json_cfg.scheme, ret);
                    ret = dc_error_commit_failed;
                    goto ERROR_OUT;
                }
                if ((ret = dc_kickoff_sta(NULL, json_cfg.mac)) != 0) {
                    CWLog("Try to kick off sta %s attached the ssid %s failed for %d.", 
                            json_cfg.mac, "ALL", ret);
                    ret = dc_error_commit_failed;
                    goto ERROR_OUT;
                }
                break;
            case OT_SET_BLACKLIST:
                if ((ret = dc_set_blacklist_sta(json_cfg.mac, json_cfg.time, 1) != 0)) {
                    CWLog("Try to set blacklist sta %s attached the ssid %s failed for time %d.", 
                            json_cfg.mac, "ALL", json_cfg.time);
                }
                break;
            case OT_UNSET_BLACKLIST:
                if ((ret = dc_set_blacklist_sta(json_cfg.mac, json_cfg.time, 0) != 0)) {
                    CWLog("Try to unset blacklist sta %s attached the ssid %s failed for time %d.", 
                            json_cfg.mac, "ALL", json_cfg.time);
                }
                break;
            case OT_SET_WHITELIST:
                if ((ret = dc_set_whitelist_sta(json_cfg.mac, json_cfg.time, 1) != 0)) {
                    CWLog("Try to set whitelist sta %s attached the ssid %s failed for time %d.", 
                            json_cfg.mac, "ALL", json_cfg.time);
                }
                break;
            case OT_UNSET_WHITELIST:
                if ((ret = dc_set_whitelist_sta(json_cfg.mac, json_cfg.time, 0) != 0)) {
                    CWLog("Try to unset whitelist sta %s attached the ssid %s failed for time %d.", 
                            json_cfg.mac, "ALL", json_cfg.time);
                }
                break;
            case OT_RATELIMIT:
                if ((ret = dc_set_ratelimit_sta(json_cfg.mac, json_cfg.tx_rate_limit, json_cfg.rx_rate_limit) != 0)) {
                    CWLog("Try to set ratelimit sta %s attached the ssid %s failed for tx_rate_limit %d rx_rate_limit %d.", 
                            json_cfg.mac, "ALL", json_cfg.tx_rate_limit, json_cfg.rx_rate_limit);
                }
                break;
            default:
                    CWLog("Unknown operate_type %d, sta %s, portal_scheme %s, time %d,  tx_rate_limit %d rx_rate_limit %d.", 
                            operate_type, json_cfg.mac, json_cfg.scheme, json_cfg.time, json_cfg.tx_rate_limit, json_cfg.rx_rate_limit);
                    ret = dc_error_commit_failed;
                    goto ERROR_OUT;
                break;
        }

    }

    
    ret = 0;
ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }
    
    if (ret) {
        *reserved = malloc(sizeof(int));
        if (*reserved) {
            *((int *)(*reserved)) = ret;
        }
    }
    
    return ret;
}

static int dc_portal_offline_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code = 0; 

    if (reserved) { /* it means something wrong during handling */
        code = *((int *)reserved);
        code = dc_error_code(code, dc_node_portal_offline,  0);
    }
    json_data = dc_generate_json_result(code);
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* config result with json format */
    save_payload_type(payload, DC_PAYLOAD_PORTAL_OFFLINE_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

static int dc_portal_authentication_handler(struct tlv *payload, void **reserved)
{
    struct portal_authentication_cmd {
        char mac[20];
        char scheme[PORTAL_NAME_MAX_LENGTH + 1];
        unsigned int remain_time;
    };
    struct portal_authentication_cmd json_cfg;
    struct node_pair_save paires[] = {
        {"mac",           json_type_string, json_cfg.mac,    sizeof(json_cfg.mac)},
        {"portal_scheme", json_type_string, json_cfg.scheme, sizeof(json_cfg.scheme)},
        {"remain_time",   json_type_int,    &(json_cfg.remain_time), sizeof(json_cfg.remain_time)},    
    }; 
    struct json_object *root, *array;
    int ret, size, i;
    char terminated;

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    

    json_object_object_foreach(root, key, val) {
        if (!strcmp(key, "clients")){
            if (json_object_get_type(val) != json_type_array) {
                ret = dc_error_obj_type;
                goto ERROR_OUT;
            }
            break;
        }
    }


    size = json_object_array_length(val);
    if (size <= 0) {
        ret = 0;
        goto ERROR_OUT;
    }
    
    for(i = 0; i < size; i++) { 
        memset(&json_cfg, 0, sizeof(json_cfg));
        
        array = json_object_array_get_idx(val, i);
        if ((ret = dc_hdl_node_default(array, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
            goto ERROR_OUT;
        }

        log_node_paires(paires, sizeof(paires)/sizeof(paires[0]));

#if !OK_PATCH
        if ((ret = portal_scheme_authentication(json_cfg.scheme, json_cfg.mac, json_cfg.remain_time)) != 0) {
            CWLog("Set portal scheme %s for the sta %s authtime %d failed for %d.", 
                json_cfg.scheme, json_cfg.mac, json_cfg.remain_time, ret);
            ret = dc_error_commit_failed;
            goto ERROR_OUT;
        }
#endif
    }
    
    ret = 0;
ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }
    
    if (ret) {
        *reserved = malloc(sizeof(int));
        if (*reserved) {
            *((int *)(*reserved)) = ret;
        }
    }
    
    return ret;
}

static int dc_portal_authentication_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code = 0; 

    if (reserved) { /* it means something wrong during handling */
        code = *((int *)reserved);
        code = dc_error_code(code, dc_node_portal_authentication,  0);
    }
    json_data = dc_generate_json_result(code);
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* config result with json format */
    save_payload_type(payload, DC_PAYLOAD_PORTAL_AUTHENTICATION_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

static int dc_upload_techsupport_handler(struct tlv *payload, void **reserved)
{
#define SUPPORT_FILE	    "tech_data.tar"
#define TECH_SUPPORT_FILE	"/tmp/tech_data.tar"
    enum {
        UPLOAD_BY_FTP = 1,
        
    };
    struct upload_tech_cmd {
        int type;
        char server[65];
        int port;
        char path[128];
        char user[33];
        char pwd[33];
    };
    char local_str[256] = {0};
    char local_hostname[33] = {0};
    char local_time[16] = {0};
    struct upload_tech_cmd json_cfg;
    struct node_pair_save paires[] = {
        {"type",     json_type_int,    &(json_cfg.type), sizeof(json_cfg.type)},
        {"server",   json_type_string, json_cfg.server,  sizeof(json_cfg.server)},
        {"port",     json_type_int,    &(json_cfg.port), sizeof(json_cfg.port)},
        {"path",     json_type_string, json_cfg.path,    sizeof(json_cfg.path)},    
        {"user",     json_type_string, json_cfg.user,    sizeof(json_cfg.user)},
        {"password", json_type_string, json_cfg.pwd,     sizeof(json_cfg.pwd)},
    }; 
    struct json_object *root;
    int ret;
    time_t timer;
    struct tm *tblock;
    char terminated, cmd[256];

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    

    if (json_object_get_type(root) != json_type_object) {
        ret = dc_error_obj_type;
        goto ERROR_OUT;
    }

    if ((ret = dc_hdl_node_default(root, paires, sizeof(paires)/sizeof(paires[0]))) != 0) {
        goto ERROR_OUT;
    }

    log_node_paires(paires, sizeof(paires)/sizeof(paires[0])); 

    memset(local_hostname, 0, sizeof(local_hostname));
    hostname_get(local_hostname, sizeof(local_hostname));

    memset(local_time, 0, sizeof(local_time));
    timer=time(NULL);
    tblock = localtime(&timer);
    sprintf(local_time,"%04d%02d%02d%02d%02d%02d", tblock->tm_year + 1900, tblock->tm_mon, tblock->tm_mday, \
        tblock->tm_hour, tblock->tm_min, tblock->tm_sec);

    memset(local_str, 0, sizeof(local_str));
    if(!strcmp(json_cfg.path, "---")){
        sprintf(local_str,"%s_%s_%s", local_hostname, local_time, SUPPORT_FILE);
    }else{
        if(json_cfg.path[strlen(json_cfg.path) - 1] == '/'){
            sprintf(local_str,"%s%s_%s_%s", json_cfg.path, local_hostname, local_time, SUPPORT_FILE);
        }else{
            sprintf(local_str,"%s/%s_%s_%s", json_cfg.path, local_hostname, local_time, SUPPORT_FILE);
        }
    }
    
    

    switch (json_cfg.type) {
        case UPLOAD_BY_FTP:
            if (json_cfg.port == 0xfffff) {
                json_cfg.port = 21;
            }
            if(0 == strlen(json_cfg.user) && 0 == strlen(json_cfg.pwd)){
                sprintf(cmd, "ftpput -P %d \"%s\" %s %s", 
                    json_cfg.port, json_cfg.server, local_str, TECH_SUPPORT_FILE);
            }else{
                sprintf(cmd, "ftpput -u \"%s\" -p \"%s\" -P %d \"%s\" %s %s", 
                    json_cfg.user, json_cfg.pwd, json_cfg.port, json_cfg.server, local_str, TECH_SUPPORT_FILE);
            }
            break;
            
        default:
            goto ERROR_OUT;
    }

    create_tech_support_file();

    ret = system(cmd);
    system("rm -rf /tmp/tech_support.tar");
    if (ret) {
        CWDebugLog("Running cmd %s failed.", cmd);
        ret = dc_error_uploadtechsupport_failed;
        goto ERROR_OUT;
    }
    system("rm -rf /etc/flash_cfg/panic.tar.gz");
    
    ret = 0;
ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }
    
    if (ret) {
        *reserved = malloc(sizeof(int));
        if (*reserved) {
            *((int *)(*reserved)) = ret;
        }
    }
    
    return ret;
}

static int dc_upload_techsupport_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code = 0; 

    if (reserved) { /* it means something wrong during handling */
        code = *((int *)reserved);
        code = dc_error_code(code, dc_node_upload_techsupport,  0);
    }
    json_data = dc_generate_json_result(code);
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* image upgrade result with json format */
    save_payload_type(payload, DC_PAYLOAD_UPLOAD_TECHSUPPORT_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

//CREATE TABLE IFINFO(IFNAME,STATE,MAC,VLAN,SSID,IPADDR,MASKADDR,CHAN,TXPOWER,MODE,BANDWIDTH);
static int _sql_callback(void *cookie, int argc, char **argv, char **szColName)
{
    static int row = 0;
    if (*(int*)cookie == -1) {
        row = 0;
        *(int*)cookie = atoi(argv[0]);
        return 0;
    }

    struct device_interface_info *info = (struct device_interface_info *)cookie;
    /*IFNAME*/
    if (argv[0]) {
        strncpy(info[row].interface_name, argv[0], SYS_INTF_NAME_SIZE-1);
        info[row].interface_len=strlen(info[row].interface_name);
    }

    /*STATE*/
    if (argv[1]) {
        info[row].state = atoi(argv[1]);
    } else {
        info[row].state = 0;
    }

    /*MAC*/
    if (argv[2]) {
        /* mac address */
        char *s = argv[2], *e;
        int i = 0;
        for (i = 0; i < 6; i++) {
            info[row].mac[i] = s ? strtoul(s, &e, 16) : 0;
            if (s) {
                s = (*e) ? e + 1 : e;
            }
        }
    }

    /*VLAN*/
    if (argv[3]) {
        info[row].pvid = atoi(argv[3]);
    }

    /*SSID*/
    if (argv[4]) {
        strncpy(info[row].ssid, argv[4], 32);
        info[row].ssid_len = strlen(info[row].ssid);
    }

    /*IPADDR*/
    if (argv[5]) {
        info[row].ip_address = inet_addr(argv[5]);
    }


    /*MASKADDR*/
    if (argv[6]) {
        info[row].mask_address = inet_addr(argv[5]);
    }

    /*CHAN*/
    if (argv[7]) {
        info[row].channel = atoi(argv[7]);
    }

    /*TXPOWER*/
    if (argv[8]) {
        info[row].txpower = atoi(argv[8]);
    }
        
    /*MODE*/
    if (argv[9]) {
        if (!strcmp(argv[9], "ac") || !strcmp(argv[9], "11ac")) {
            info[row].mode = DOT11_RADIO_MODE_AC;
        } else if (!strcmp(argv[9], "na")) {
            info[row].mode = DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N;
        } else if (!strcmp(argv[9], "ng") || !strcmp(argv[9], "11ng")) {
            info[row].mode = DOT11_RADIO_MODE_G | DOT11_RADIO_MODE_N;
        } else if (!strcmp(argv[9], "a")) {
            info[row].mode = DOT11_RADIO_MODE_A;
        } else if (!strcmp(argv[9], "g")) {
            info[row].mode = DOT11_RADIO_MODE_G;
        } else if (!strcmp(argv[9], "n")) {
            info[row].mode = DOT11_RADIO_MODE_N;
        }
    }

    /*BANDWIDTH*/
    if (argv[10]) {
        int bw = 0;
        sscanf(argv[10],"HT%2d", &bw);
        info[row].bandwidth = bw;
    }

    row ++;

    return 0;
}

static int dc_get_interface_info(struct device_interface_info **info)
{
    const char *sql_count_str="SELECT count(*) FROM IFINFO";
    const char *sql_str="SELECT * FROM IFINFO";
    sqlite3 *db = NULL;
    char *pErrMsg = NULL; 
    int ret = 0;
    int count = -1;

    ret = sqlite3_open("/tmp/ifaceinfo.db", &db);
    if (ret != SQLITE_OK) {
        CWLog("open database failure:%s", sqlite3_errmsg(db));
        ret = -1;
        goto __cleanup;
    }

    ret = sqlite3_exec(db, sql_count_str, _sql_callback, &count, &pErrMsg);
    if (ret != SQLITE_OK) {
        CWLog("SQL create error: %s\n", pErrMsg);
        ret = -2;
        goto __cleanup;
    }

    *info = (struct device_interface_info *)malloc(count * sizeof(struct device_interface_info));
    if (*info == NULL) {
        CWLog("SQL create error: %s\n", pErrMsg);
        ret = -3;
        goto __cleanup;
    }
    memset(*info, 0, count * sizeof(struct device_interface_info));

    ret = sqlite3_exec(db, sql_str, _sql_callback, *info, &pErrMsg);
    if (ret != SQLITE_OK) {
        CWLog("SQL create error: %s\n", pErrMsg);
        ret = -4;
    }

    ret = count;

__cleanup:
    if (db) {
        sqlite3_close(db);
    }
    if(pErrMsg) {
        free(pErrMsg);
    }
    return ret;
}

static int dc_interface_info_response(devctrl_block_s *dc_block, void *reserved)
{
    struct device_interface_info *inter_info = NULL;
    char *payload, *data = NULL;
    int paylength = 0, ret = 0, count = 0; 

    count = dc_get_interface_info(&inter_info);
    if (inter_info == NULL || count <= 0) { 
        goto err;
    }
    
    if (assemble_interface_info_elem(&data, &paylength, inter_info, count) != CW_TRUE){
        CWLog("Get interface info count %d but assmeble query msg failed.", count);
        goto err;
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto err;});

    /* interface info result with json format */
    save_payload_type(payload, DC_PAYLOAD_INTERFACE_INFO_RESULT);
    save_payload_length(payload + 2, paylength);

    if (data) {
        CW_COPY_MEMORY(payload + 6, data, paylength);
        free(data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
err:
    if(inter_info){
        free(inter_info);
    }
    
    return ret;
}

static int dc_portal_ssh_tunnel_handler(struct tlv *payload, void **reserved)
{
    struct ssh_tunnel_result result;
    struct ssh_tunnel_cmd json_cfg;
    int error_code = 0;
    struct node_pair_save paires[] = {
        {"type",        json_type_int,    &(json_cfg.type),        sizeof(json_cfg.type)},
        {"port",        json_type_int,    &(json_cfg.local_port),  sizeof(json_cfg.local_port)},
        {"remote_port", json_type_int,    &(json_cfg.remote_port), sizeof(json_cfg.remote_port)},
        {"server",      json_type_string, json_cfg.server,         sizeof(json_cfg.server)},
        {"username",    json_type_string, json_cfg.user,           sizeof(json_cfg.user)},
        {"password",    json_type_string, json_cfg.pwd,            sizeof(json_cfg.pwd)},
    }; 
    struct json_object *root;
    int ret;
    char terminated;

    memset(&result, 0, sizeof(result));
    result.type = -1;

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    

    memset(&json_cfg, 0, sizeof(json_cfg));
    if ((ret = dc_hdl_node_default(root, paires, sizeof(paires)/sizeof(paires[0])))!= 0) {
        goto ERROR_OUT;
    }

    result.type = json_cfg.type;
    result.state = json_cfg.type == 1 ? 0 : 1;
    strcpy(result.server, json_cfg.server);
    result.local_port = json_cfg.local_port;
    result.remote_port = json_cfg.remote_port;
    
#if !OK_PATCH
    ssh_tunnel_info tunnel_info;
    switch (json_cfg.type) {
        case 0: /* query */
            ret = get_ssh_reverse_tunnel_info(&tunnel_info, &error_code);
            if(ret != 0){
                CWLog("Get SSH Reverse tunnel info error %d failed for %d.", error_code, ret);
                ret = dc_error_commit_failed;
                goto ERROR_OUT;
            }
            if(1 == error_code)
                result.state = 0;
            else
                result.state = 1; 
            /*query create ssh reverse tunnel success and have info*/
            if(result.state == 0){
                strcpy(result.server, tunnel_info.ip_address);
                result.remote_port = tunnel_info.port;
                result.local_port = 22;
            }
            break;

        case 1: /* open */
            /*ret = sshd_set(1);
            if(ret != 0){
                CWLog("Set SSH server enable failed for %d.", ret);
                ret = dc_error_commit_failed;
                result.state = 1;
                goto ERROR_OUT;
            }*/
            ret = ssh_set_reverse_tunnel(json_cfg.server, json_cfg.remote_port, json_cfg.user, json_cfg.pwd);
            if(ret != 0){
                CWLog("Create ssh reverse tunnel failed for %d.", ret);
                //sshd_set(0);
                
                switch(ret){
                    case CMP_ERR_NO_SUCH_INSTANCE:
                        ret = dc_error_ssh_host_not_allow_connect;
                        break;
                    case CMP_ERR_WRONG_VALUE:
                        ret = dc_error_ssh_username_or_password;
                        break;
                    case CMP_ERR_WRONG_TYPE:
                        ret = dc_error_ssh_bad_listense_port;
                        break;
                    case CMP_ERR_COMMIT_FAIL:
                        ret = dc_error_ssh_connection_already_exist;
                        break;    
                }
                
                result.state = 1;
                goto ERROR_OUT;
            }
            result.state = 0;
            break;

        case 2: /* close */
            ret = ssh_undo_reverse_tunnel();
            if(ret != 0){
                CWLog("Close ssh reverse tunnel failed for %d.", ret);
                ret = dc_error_commit_failed;
                goto ERROR_OUT;
            }
            /*ret = sshd_set(0);
            if(ret != 0){
                CWLog("Set SSH server disable failed for %d.", ret);
                ret = dc_error_commit_failed;
                goto ERROR_OUT;
            }*/
            result.state = 1;
            break;

        default:
            ret = dc_error_obj_data;
            break;
    }
#endif

ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }

    result.code = ret;

    *reserved = malloc(sizeof(struct ssh_tunnel_result));
    if (*reserved) {
        memcpy(*reserved, &result, sizeof(struct ssh_tunnel_result));
    }
    
    return ret;
}

static int dc_sta_ssh_tunnel_response(devctrl_block_s *dc_block, void *reserved)
{
    char *json_data = NULL, *payload;
    int paylength = 0, ret = 0, code = 0; 

    if (!reserved) { /* it means malloc failed */
        code = dc_error_code(dc_error_system, dc_node_ssh_tunnel, 0);
        json_data = dc_generate_json_result(code);
    }
    else {
        struct ssh_tunnel_result *result = (struct ssh_tunnel_result *)reserved;
        struct node_pair_save paires[] = {
            {"code",        json_type_int,    &(result->code),        sizeof(result->code)},
            {"state",       json_type_int,    &(result->state),       sizeof(result->state)},
            {"server",      json_type_string, result->server,         sizeof(result->server)},
            {"port",        json_type_int,    &(result->local_port),  sizeof(result->local_port)},
            {"remote_port", json_type_int,    &(result->remote_port), sizeof(result->remote_port)},
        }; 
        int i, num, len = 0, size = 256; /* 256 is enough */
        
        json_data = malloc(size);
        if (json_data != NULL) {
            code = result->code;
            if (code != 0) {
                code = dc_error_code(code, dc_node_ssh_tunnel, 0);
                result->code = code;
            }
            memset(json_data, 0, size);

            if (result->type == 0) {
                /* type 0: query request, need response all information */
                num = 5;
            }
            else {
                /* type != 0: is not query request, only response with code and state */
                num = 2;
            }
            len += snprintf(json_data + len, size - len, "{");
            for (i= 0; i < num; i++) {
                if (paires[i].type == json_type_int) {
                    len += snprintf(json_data + len, size - len, 
                        "\"%s\":%d", paires[i].key, *((int *)paires[i].value));
                }
                else {
                    len += snprintf(json_data + len, size - len, 
                        "\"%s\":\"%s\"", paires[i].key, (char *)paires[i].value);
                }

                if (i < num - 1) {
                    len += snprintf(json_data + len, size - len, ", ");
                }
            }
            len += snprintf(json_data + len, size - len, "}");
        }
    }
    
    if (json_data) {
        paylength = strlen(json_data);
        CWLog("Response data: %s:%d.", json_data, paylength);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data); return -1;});

    /* kickoff result with json format */
    save_payload_type(payload, DC_PAYLOAD_SSH_TUNNEL_RESULT);
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
    
    return ret;
}

static int dc_get_wds_info(struct wds_tunnel_info **info)
{
#if !OK_PATCH
   int iRet = 0;
   int iPos = 0;
   int iSize = 0;
   int iCount = 0;
   WDS_AP_INFO_S stApInfo;
   struct wds_tunnel_info *pWdsInfo= NULL;

   while(1){

        memset(&stApInfo, 0, sizeof(stApInfo)); 
        iRet = WDS_Service_GetApInfoAll(iPos, &stApInfo);
        if (CMP_ERR_NO_ERR != iRet) {
            CWLog("Get WDS forward table information failed. Ret: %d\n", iRet);
            return -1;
        }

        if (0 == stApInfo.iIsContinue) {
            break;
        }

        if(iCount >= iSize){
            iSize += 5;
            if(iCount == 0){
                pWdsInfo = (struct wds_tunnel_info *)malloc(iSize * sizeof(struct wds_tunnel_info));
            }else{
                pWdsInfo = (struct wds_tunnel_info *)realloc(pWdsInfo, iSize * sizeof(struct wds_tunnel_info));
            }

            if(pWdsInfo == NULL){
                CWLog("Fialed to malloc Wds Info in get wds info");
                return -1;
            }
        } 

        /*get wds info*/
        memcpy(pWdsInfo[iCount].mac, &stApInfo.acDevMac, sizeof(pWdsInfo[iCount].mac));
        pWdsInfo[iCount].mode = stApInfo.iMode;
        pWdsInfo[iCount].err_code = stApInfo.iErr;
        pWdsInfo[iCount].status = stApInfo.iStatus;
        pWdsInfo[iCount].level = stApInfo.iLevel;
        memcpy(pWdsInfo[iCount].uplink, &stApInfo.acUpLinkMac, sizeof(pWdsInfo[iCount].uplink));

        iCount++;
        
        /* requeset next postion fwd information */
        iPos = stApInfo.iPos + 1;

   }

   *info = pWdsInfo;

   return iCount;
#else
   return 0;
#endif
}

static int dc_wds_tunnel_response(devctrl_block_s *dc_block, void *reserved)
{
    struct wds_tunnel_info *wds_info = NULL;
    char *payload, *data = NULL;
    int paylength = 0, ret = 0, count = 0; 

    count = dc_get_wds_info(&wds_info);
    if (wds_info == NULL || count < 0) { 
        goto err;
    }

    if (assemble_wds_info_elem(&data, &paylength, wds_info, count) != CW_TRUE){
        CWLog("Get wds info count %d but assmeble query msg failed.", count);
        goto err;
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto err;});

    /* wds info result with json format */
    save_payload_type(payload, DC_PAYLOAD_WDS_TUNNEL_RESULT);
    save_payload_length(payload + 2, paylength);

    if (data) {
        CW_COPY_MEMORY(payload + 6, data, paylength);
        free(data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
err:
    if(wds_info){
        free(wds_info);
    }
    
    return ret;
}

static int GetCLIResultInfo(char **result)
{
#if !OK_PATCH
#define CLI_TO_NMS_FILE     "/tmp/cli2nms" 

    int iFileSize = 0;
    int iFileFd = 0;
    int iFileReadSize = 0;
    
    char *pszResultInfo = NULL;
    struct stat stFileStat;

    /*pszResultInfo = (char *)malloc(20);
    if(pszResultInfo == NULL){
        CWLog("Malloc nms2cli result info failed.");
        return -2;
    }
    memset(pszResultInfo, 0, 20);
    strcpy(pszResultInfo, "Just test.");

    *result = pszResultInfo;
    
    return strlen("Just test.");*/

    if (stat(CLI_TO_NMS_FILE, &stFileStat) == 0){ 
        iFileSize =  stFileStat.st_size; 
    } else{
        CWLog("Get Result file size failed.");
        return -1;
    }

    iFileFd = open(CLI_TO_NMS_FILE, O_RDONLY);
    if(iFileFd < 0){
        CWLog("Open result file failed.");    
        return -1;
    }
    
    pszResultInfo = (char *)malloc(iFileSize);
    if(pszResultInfo == NULL){
        close(iFileFd);
        CWLog("Malloc nms2cli result info failed.");
        return -2;
    }
    memset(pszResultInfo, 0, iFileSize);

    iFileReadSize = read(iFileFd, pszResultInfo, iFileSize);

    close(iFileFd);
    
    if(iFileReadSize != iFileSize){
        CWLog("Read size %d, but stat size %d.", iFileReadSize, iFileSize);
        return -2;
    }

    *result = pszResultInfo;

    return iFileSize;
#else
    return 0;
#endif
}

static int is_private_cmd(const char *cmd, int len)
{
    return (len > 2 && cmd[0] == '_' && cmd[1] == '_' && cmd[2] != 'h' && cmd[2] != 'H');
}
#define UPGRADE_OEM_CODE    0xffffe
static int upgrade_oem_pkg(char *cmd, int len, struct cli_exec_result **result)
{
#if !OK_PATCH
#define OEM_PKG_FILE "/tmp/oempkg"
#define EXEC_SUCCESS "Execute Success!"
#define EXEC_FAILED "Execute Failed!"
#define BLANK_CHAR  ' '
#define MAX_ARGV    16
    enum {
        ug_ftp = 0,
        ug_tftp,
        ug_http,
        ug_max
    };
    char *p = cmd, *blank, *argv[MAX_ARGV], *user = NULL, *pwd = NULL, *file = NULL, *src = NULL, sys_cmd[256];
    int argc = 0, pos = 0, i, type = ug_max, sys_len = 0, ret;

    struct cli_exec_result *rst = (struct cli_exec_result *)malloc(sizeof(struct cli_exec_result));
    if (rst == NULL) {
        return -1;
    }
    
    if (p[len - 1] == '\r' || p[len - 1] == '\n') {
        p[len - 1] = 0;
        len--;
    }
    do {
        while (*p == BLANK_CHAR && (p - p) < len) {
            p++;
            pos++;
        }

        if (p - p >= len) {
            break;
        }
        blank = strchr(p, BLANK_CHAR);
        if (blank != NULL) {
            if (pos + (blank-p) <= len) {
                argv[argc++] = p;
                pos += (blank - p);

                *blank = 0;
                pos++;
                p = blank + 1;
            }
            else {
                argv[argc++] = p;
                p[len - pos] = 0;
                pos = len;
                break;
            }
                
        }
        else {
            argv[argc++] = p;
            p[len - pos] = 0;
            pos = len;
            break;
        }
    }while(pos < len && argc < MAX_ARGV);

    memset(sys_cmd, 0, sizeof(sys_cmd));
    
    for (i = 0; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 't':
                    type = ug_tftp;
                    sys_len = sprintf(sys_cmd, "%s", "tftp");
                    break;

                case 'f':
                    type = ug_ftp;
                    sys_len = sprintf(sys_cmd, "%s", "ftpget");
                    break;

                case 'h':
                    type = ug_http;
                    sys_len = sprintf(sys_cmd, "%s", "wget -q -T 300");
                    break;

                case 'u':
                    i++;
                    user = argv[i];
                    break;
                    
                case 'p':
                    i++;
                    pwd = argv[i];
                    break;

                case 's':
                    i++;
                    src = argv[i];
                    break;
                    
                case 'n':
                    i++;
                    file = argv[i];
                    break;

                default:
                    break;
            }
        }
    }  

    if (type == ug_ftp) {
        if (user != NULL) {
            sys_len += sprintf(sys_cmd + sys_len, " -u \"%s\"", user);
        }
        if (pwd != NULL) {
            sys_len += sprintf(sys_cmd + sys_len, " -p \"%s\"", pwd);
        }

        sys_len += sprintf(sys_cmd + sys_len, " %s %s %s", src, OEM_PKG_FILE, file);
    }
    else if (type == ug_tftp) {
        sys_len += sprintf(sys_cmd + sys_len, "  -g -r \"%s\" -l %s %s", file, OEM_PKG_FILE, src);
    }
    else if (type == ug_http) {
        sys_len += sprintf(sys_cmd + sys_len, "  -O %s %s %s", file, OEM_PKG_FILE, src);
    }

    CWDebugLog("Running upgrade oem-pkg cmd:%s.", sys_cmd);
    
    ret = system(sys_cmd);
    if (ret == 0) {
        sprintf(sys_cmd, "mkWebPkg -f %s", OEM_PKG_FILE);
        ret = system(sys_cmd);
        CWDebugLog("Running load oem-pkg cmd(%d):%s.", ret, sys_cmd);
    }
    if (ret == 0) {
        rst->code = UPGRADE_OEM_CODE;
        rst->len = strlen(EXEC_SUCCESS);
        rst->result = (char *)malloc(rst->len);
        if (rst->result != NULL) {
            strncpy(rst->result, EXEC_SUCCESS, rst->len);
        }
        else {
            rst->len = 0;
        }
    }
    else {
        rst->code = ret;
         rst->len = strlen(EXEC_FAILED);
         rst->result = (char *)malloc(rst->len);
         if (rst->result != NULL) {
            strncpy(rst->result, EXEC_FAILED, rst->len);
         }
         else {
            rst->len = 0;
         }
    }

    *result = rst;
    
#endif
    return 0;    
}

static int do_private_cmd(char *cmd, int len, struct cli_exec_result **result)
{
#define UPGRADE_OEM_PKG "__oempkg"
    if (!strncmp(cmd, UPGRADE_OEM_PKG, strlen(UPGRADE_OEM_PKG))) {
        return upgrade_oem_pkg(cmd, len, result);
    }

    *result = NULL;
    return 0;
}

static int do_simulate_cli(char *cmd, int len, struct cli_exec_result **result)
{
#if !OK_PATCH 
#define CLI_CMD_STR "cst_cli -c "
#define CLI_CMD_LEN strlen(CLI_CMD_STR)
#define CLI_NOT_REPORT      "CLI not report any info."

    char *pszCmd = NULL;
    int iCliRet = 0;
    struct cli_exec_result  *pstCliResultInfo = NULL;
    char  *pszResult = NULL;
    char *pszNoReport = NULL;

    while (*cmd == ' ' && len > 0) {
        cmd++;
        len--;
    }
    if (is_private_cmd(cmd, len)) {
        return do_private_cmd(cmd, len, result);
    }

    pszCmd = (char *)malloc(len + CLI_CMD_LEN + strlen("\"\""));
    if(!pszCmd){
        CWLog("Failed to malloc cmd_str in %s.", __func__);
        return -1;
    }

    sprintf(pszCmd, "%s\"%s\"", CLI_CMD_STR, cmd);

    CWDebugLog("NMS to cli cmd:%s.", pszCmd);
    
    system(pszCmd);

    if(pszCmd)
        free(pszCmd);

    pstCliResultInfo = (struct cli_exec_result *)malloc(sizeof(struct cli_exec_result));
    if(!pstCliResultInfo){
        CWLog("Failed to malloc struct cli_exec_result in %s.", __func__);
        return -1;
    }

    memset(pstCliResultInfo, 0, sizeof(struct cli_exec_result));

    iCliRet = GetCLIResultInfo(&pszResult);
    if(iCliRet > 0){
        pstCliResultInfo->code = 0;
        pstCliResultInfo->len = iCliRet;
        pstCliResultInfo->result = pszResult;
    }else{
        pszNoReport = (char *)malloc(strlen(CLI_NOT_REPORT));
        if(!pszNoReport){
            CWLog("Failed to malloc no report string in %s.", __func__);
            return -1;
        }
        strcpy(pszNoReport, CLI_NOT_REPORT);
        pstCliResultInfo->code = dc_error_unreport_info;
        pstCliResultInfo->len = strlen(CLI_NOT_REPORT);
        pstCliResultInfo->result = pszNoReport;
    }
    
    *result = pstCliResultInfo;
        
#endif
    return 0;
}

static int dc_cli_handler(struct tlv *payload, void **reserved)
{
    struct cli_exec_result *cli_result = NULL;
    int ret = 0;
    char terminated;

    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;    
    ret = do_simulate_cli(payload->v, payload->l, &cli_result);
    payload->v[payload->l] = terminated;
    *reserved = cli_result;
    
    return ret;
}

static int dc_cli_response(devctrl_block_s *dc_block, void *reserved)
{
#define NOT_SUPPORT "Not support"
    char *payload, *data = NULL;
    int paylength = 0, ret = 0; 

    if (reserved != NULL) {
        struct cli_exec_result *cli_result = (struct cli_exec_result *)reserved;
        if (assemble_cli_result_elem(&data, &paylength, cli_result) != CW_TRUE){
            CWLog("Assemle cli result msg failed.");
            goto err;
        }
    }
    else {
        struct cli_exec_result cli_result;

        cli_result.code = dc_error_unsupport_cmd;
        cli_result.len = strlen(NOT_SUPPORT);
        cli_result.result = NOT_SUPPORT;
        
        if (assemble_cli_result_elem(&data, &paylength, &cli_result) != CW_TRUE){
            CWLog("Assemle cli result msg failed.");
            goto err;
        }
    }

    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto err;});

    save_payload_type(payload, DC_PAYLOAD_CLI_RESULT);
    save_payload_length(payload + 2, paylength);

    if (data) {
        CW_COPY_MEMORY(payload + 6, data, paylength);
        free(data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);
err:
    
    return ret;
}

static int dc_cli_finished(void *reserved)
{
    struct cli_exec_result *cli_result = (struct cli_exec_result *)reserved;
    
    if (cli_result) {
        if (cli_result->result) {
            free(cli_result->result);
            cli_result->result = NULL;
        }
        if (cli_result->code == UPGRADE_OEM_CODE) {
            return system("/sbin/reboot -f");
        }
        free(cli_result);
    }
    
    return 0;
}

static int dc_flowsta_handler(struct tlv *payload, void **reserved)
{
#define CALC_RATE_PERIOD    2
    struct json_object *root, *array;
    int ret, i, period = CALC_RATE_PERIOD, if_num = 0;
    char terminated;
    struct node_pair_save perd_paire[] = {
        {"period", json_type_int, &period, sizeof(period)}
    }; 
    struct node_pair_save if_paire[] = {
        {"interfaces", json_type_string, NULL, SYS_INTF_NAME_SIZE}
    }; 
    struct if_flow_stat *if_stas = NULL;
    struct if_rate_stas *rate_stas = NULL;


    terminated = payload->v[payload->l];
    payload->v[payload->l] = 0;
    root = json_tokener_parse(payload->v);
    payload->v[payload->l] = terminated;

    if (is_error(root)) {
        ret = dc_error_json_format;
        goto ERROR_OUT;
    }    

    if (json_object_get_type(root) != json_type_object) {
        ret = dc_error_obj_type;
        goto ERROR_OUT;
    }    

    if (1) {
        json_object_object_foreach(root, key, val) {
            if (!strcasecmp(key, "period")) {
                if ((ret = dc_hdl_node_default(val, perd_paire, sizeof(perd_paire)/sizeof(perd_paire[0])))!= 0) {
                    goto ERROR_OUT;
                }
                log_node_paires(perd_paire, sizeof(perd_paire)/sizeof(perd_paire[0]));
                break;
            }
        }
    }

#if !OK_PATCH
    struct netif_stat_arg arg;
    arg.period = period;
    arg.stamp_before = 0;
    
    if (1) {
        json_object_object_foreach(root, key, val) {
            if (!strcasecmp(key, "interfaces") && json_object_get_type(val) == json_type_array) {
                if_num = json_object_array_length(val);
                if (if_num <= 0) {
                    struct if_attrs *attrs = NULL;

                    if_num = 0;
                    if_get_interfaces(IF_PHYTYPE_ETH|IF_PHYTYPE_GIGA_ETH, &if_num, &attrs, NULL, NULL);
                    if (if_num > 0) {
                        if_stas = (struct if_flow_stat *)malloc(if_num * sizeof(struct if_flow_stat));
                        if (if_stas == NULL) {
                            CWLog("System error: malloc failed.");
                            ret = dc_error_system;
                            goto ERROR_OUT;
                        }
                        memset(if_stas, 0, if_num * sizeof(struct if_flow_stat));
                        for (i = 0; i < if_num && attrs; i++) {
                            strncpy(if_stas[i].name, attrs[i].name, sizeof(if_stas[i].name));
                            strncpy(arg.name, attrs[i].name, sizeof(arg.name));
                            if ((ret = system_get_interface_abbr_stats(&arg, &(if_stas[i].sta))) != 0) {
                                CWLog("Get interface %s stat failed for %d.", arg.name, ret);
                            }
                        }
                    }
                    
                    if (attrs) {
                        free(attrs);
                    }
                }
                else {
                    if_stas = (struct if_flow_stat *)malloc(if_num * sizeof(struct if_flow_stat));
                    if (if_stas == NULL) {
                        CWLog("System error: malloc failed.");
                        ret = dc_error_system;
                        goto ERROR_OUT;
                    }
                    memset(if_stas, 0, if_num * sizeof(struct if_flow_stat));
                    for (i = 0; i < if_num; i++) {
                        array = json_object_array_get_idx(val, i);
                        if_paire[0].value = if_stas[i].name;
                        if_paire[0].size = sizeof(if_stas[i].name);
                        if ((ret = dc_hdl_node_default(array, if_paire, sizeof(if_paire)/sizeof(if_paire[0])))!= 0) {
                            if (if_stas) {
                                free(if_stas);
                                if_stas = NULL;
                            }
                            goto ERROR_OUT;
                        }
                        log_node_paires(if_paire, sizeof(if_paire)/sizeof(if_paire[0]));
                        strncpy(arg.name, if_stas[i].name, sizeof(arg.name));
                        if ((ret = system_get_interface_abbr_stats(&arg, &(if_stas[i].sta))) != 0) {
                            CWLog("Get interface %s stat failed for %d.", arg.name, ret);
                        }
                    }
                }
            }
        }
    }
#endif

    ret = 0;

ERROR_OUT: 
    if (!is_error(root)) {
        json_object_put(root);
    }

    rate_stas = malloc(sizeof(struct if_rate_stas));
    if (rate_stas) {
        rate_stas->stas = if_stas;
        if (rate_stas->stas != NULL) {
            rate_stas->num = if_num;
        }
        else {
            rate_stas->num = 0;
        }
    }

    *reserved = rate_stas;
    return ret;
}

static int dc_flowsta_response(devctrl_block_s *dc_block, void *reserved)
{
    char *payload, *data = NULL;
    int paylength = 0, ret = 0; 

    if (reserved != NULL) {
        struct if_rate_stas *stas = (struct if_rate_stas*)reserved;
        
        if (assemble_rate_sta_elem(&data, &paylength, stas) != CW_TRUE) {
            CWLog("Assemle rate sta result msg failed.");
        }
    }
    else {
        struct if_rate_stas stas;
        
        stas.num = 0;
        if (assemble_rate_sta_elem(&data, &paylength, &stas) != CW_TRUE) {
            CWLog("Assemle rate sta result msg failed.");
        }
    }

    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {return -1;});

    save_payload_type(payload, DC_PAYLOAD_FLOWSTA_RESULT);
    save_payload_length(payload + 2, paylength);

    if (data) {
        CW_COPY_MEMORY(payload + 6, data, paylength);
        free(data);
    }

    ret = dc_response(payload, paylength + 6, dc_block);

    CW_FREE_OBJECT(payload);

    return ret;
}

static int dc_flowsta_finished(void *reserved)
{
    struct if_rate_stas *rate_result = (struct if_rate_stas *)reserved;
    
    if (rate_result) {
        if (rate_result->stas) {
            free(rate_result->stas);
            rate_result->stas = NULL;
        }
        
        free(rate_result);
    }
    
    return 0;
}

struct dc_payloadfunc_table dc_payload_handler[] = {
    {DC_PAYLOAD_JSON_CONFIG, 
        dc_json_config_handler, dc_json_config_response, dc_json_config_finished},
        
    {DC_PAYLOAD_STA_KICKOFF_REQ, 
        dc_sta_kickoff_handler, dc_sta_kickoff_response, dc_default_finished},
        
    {DC_PAYLOAD_STA_QUERY_REQ, 
        NULL /* nothing need to do */, dc_sta_query_response,  NULL},
        
    {DC_PAYLOAD_IMAGE_UPGRADE_REQ, 
        dc_image_upgrade_handler, dc_image_upgrade_response, dc_default_finished},
        
    {DC_PAYLOAD_REBOOT_REQ, 
        dc_reboot_handler, dc_reboot_response, NULL},

    {DC_PAYLOAD_PORTAL_OFFLINE_REQ, 
        dc_portal_offline_handler, dc_portal_offline_response, dc_default_finished},

    {DC_PAYLOAD_PORTAL_AUTHENTICATION_REQ, 
        dc_portal_authentication_handler, dc_portal_authentication_response, dc_default_finished},   

    {DC_PAYLOAD_UPLOAD_TECHSUPPORT_REQ, 
        dc_upload_techsupport_handler, dc_upload_techsupport_response, dc_default_finished}, 

    {DC_PAYLOAD_INTERFACE_INFO_REQ, 
        NULL, dc_interface_info_response, NULL},

    {DC_PAYLOAD_SSH_TUNNEL_REQ, 
        dc_portal_ssh_tunnel_handler, dc_sta_ssh_tunnel_response, dc_default_finished},

    {DC_PAYLOAD_WDS_TUNNEL_REQ, 
        NULL, dc_wds_tunnel_response, NULL},

    {DC_PAYLOAD_CLI_REQ, 
        dc_cli_handler, dc_cli_response, dc_cli_finished},

    {DC_PAYLOAD_FLOWSTA_REQ, 
        dc_flowsta_handler, dc_flowsta_response, dc_flowsta_finished},
};


static struct dc_payloadfunc_table *dc_get_payload_func(int type)
{
    int i;

    for (i = 0; i < (sizeof(dc_payload_handler)/sizeof(dc_payload_handler[0])); i++) {
        if (type == dc_payload_handler[i].type) {
            return &(dc_payload_handler[i]);
        }
    }

    return NULL;
}

int dc_task_handler(devctrl_block_s *dc_block)
{
    struct dc_payloadfunc_table *func;
    struct tlv tlv;
    char *payload = dc_block->data;
    int totallen = 0, ret = 0;

    if (dc_block->len < sizeof(tlv.t) + sizeof(tlv.l)) {
        CWLog("Received devctrl control message from NMS with so small length: %d", 
            dc_block->len);
        return -1;
    }
    
    while (totallen < dc_block->len) {
        /* get payload type */
        tlv.t = get_payload_type(payload);
        payload += sizeof(tlv.t);

        /* get payload length */
        tlv.l = get_payload_length(payload);
        payload += sizeof(tlv.l);
        
        totallen += sizeof(tlv.t) + sizeof(tlv.l) + tlv.l;
        if (totallen > dc_block->len) {
            CWLog("Received devctrl control message from NMS with bad length: %d:%d:%d", 
                totallen, tlv.l ,dc_block->len);
            /* invalid data length */
            ret = -1;
            break;
        }
        /* get payload */
        tlv.v = payload;
        
        CWLog("Received data type %d from NMS with length: %d", tlv.t, tlv.l);

        func = dc_get_payload_func(tlv.t);
        if (func) {
            void *arg = NULL;
            
            if (func->handler) {                
                ret = func->handler(&tlv, &arg);
            }

            if (func->response) {
                ret += func->response(dc_block, arg);
            }

            if (func->finished) {
                ret += func->finished(arg);
            }
        }
        if (ret) {
            CWLog("Handle devctrl control message elemet(%d) failed for %d.", 
                tlv.t ,ret);
            break;
        }
        payload += tlv.l;
    }
    
    return ret;
}


