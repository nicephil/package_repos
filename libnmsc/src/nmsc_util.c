#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nmsc_util.h"
#if !OK_PATCH
#include "services/log_services.h"
#include "services/dhcpd_services.h"
#include "services/wds_services.h"
#include "if/if_pub.h"
#include "cmp/cmp_pub.h"
#endif
#include "cfg/cfg.h"

//extern struct wlan_scan_bind_info;

void log_node_pair(struct node_pair_save pair)
{
    if (pair.type == json_type_int) {
        if (is_default_integer_config(*((int *)(pair.value)))) {
            nmsc_debug("%s = %d:default", pair.key, *((int *)(pair.value)));
        }
        else {
            nmsc_debug("%s = %d", pair.key, *((int *)(pair.value)));
        }
    }
    else if (pair.type == json_type_double) {
            nmsc_debug("%s = %lf", pair.key, *((double *)(pair.value)));
    }
    else if (pair.type == json_type_string) {
        if (is_default_string_config((char *)(pair.value)))
            nmsc_debug("%s = %s:default", pair.key, (char *)(pair.value));
        else
            nmsc_debug("%s = %s", pair.key, (char *)(pair.value));
    }
    else {
        nmsc_debug("%s:unknow type %d", pair.key, pair.type);
    }
}

void log_node_paires(struct node_pair_save *paires, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        log_node_pair(paires[i]);
    }
}


LIST_HEAD(g_nmsc_delay_op_list); 

void nmsc_delay_op_init(void)
{
    INIT_LIST_HEAD(&g_nmsc_delay_op_list);
}

int nmsc_delay_op_done(void)
{
    struct nmsc_delay_op_node *node;
    int ret = 0;

    list_for_each_entry(node, &g_nmsc_delay_op_list, list) {
        if (node->node.operator) {
            ret = node->node.operator(node->node.reserved);
            if (ret) {
                break;
            }
        }
    }

    return ret;
}

void nmsc_delay_op_release(void)
{
    struct nmsc_delay_op_node *node, *tmp;

    list_for_each_entry_safe(node, tmp, &g_nmsc_delay_op_list, list) {
        list_del(&(node->list));
        if (node->node.reserved) {
            free(node->node.reserved);
        }
        free(node);
    }
}

void nmsc_delay_op_new(int (*operator)(void *reserved), void *param, int size)
{
    struct nmsc_delay_op_node *node;
    void *reserved = NULL;

    node = (struct nmsc_delay_op_node *)malloc(sizeof(struct nmsc_delay_op_node));
    if (node == NULL) {
        return;
    }
    if (param && size > 0) {
        reserved = malloc(size);
        if (reserved == NULL) {
            free(node);
            return;
        }
        memcpy(reserved, param, size);
    }
    
    INIT_LIST_HEAD(&(node->list));
    node->node.operator = operator;
    node->node.reserved = reserved;

    list_add_tail(&(node->list), &g_nmsc_delay_op_list);
}

int nmsc_delay_op_log(void *reserved) 
{
#if !OK_PATCH
    int ret = log_set_bufferlevel(*(int *)reserved);

    if (ret != 0) {
        nmsc_log("Infocenter set log buffer level %d failed for %d.", *(int *)reserved, ret);
        goto ERROR_OUT;
    }

    return 0;
ERROR_OUT:
    return dc_error_code(dc_error_commit_failed, dc_node_log, ret);
#else
    return 0;
#endif
}

int nmsc_delay_op_dhcpd(void *reserved) 
{
#if !OK_PATCH
    struct vlan_interface {
        int  id;
        char desc[33];
        int dhcpd_enable;
    } *vif = (struct vlan_interface *)reserved;
    char ifname[SYS_INTF_NAME_SIZE];
    int ret;

    if (vif) {
        if_form_name(0, vif->id, IF_PHYTYPE_VLAN,  ifname);
        if (vif->dhcpd_enable) {
            ret = dhcpd_enable_interface(ifname);
        }
        else {
            ret = dhcpd_disable_interface(ifname);
        }
        
        if (!(ret == 0 || ret == CMP_ERR_COMMIT_FAIL ||  
            (ret == CMP_ERR_WRONG_VALUE && vif->dhcpd_enable == 0))) {
            nmsc_log("Set %s dhcpd %s failed for %d.", ifname, 
               vif->dhcpd_enable ? "enable" : "disable" , ret);
            goto ERROR_OUT;
        }
        else {
            /* fix bug 3337 */
            dhcpd_apply();
        }
    }

    return 0;
ERROR_OUT:
    return dc_error_code(dc_error_commit_failed, dc_node_dhcpd, ret);
#else
    return 0;
#endif
}

int nmsc_delay_op_dhcpd_ethif(void *reserved) 
{
#if !OK_PATCH
    struct ethif {
        char name[SYS_INTF_NAME_SIZE + 1];
        int dhcpd_enabled;
    };
    struct ethif *ethif = (struct ethif *)reserved;
    int ret;

    if (ethif) {
        if (ethif->dhcpd_enabled) {
            ret = dhcpd_enable_interface(ethif->name);
        }
        else {
            ret = dhcpd_disable_interface(ethif->name);
        }
        
        if (!(ret == 0 || ret == CMP_ERR_COMMIT_FAIL ||  
            (ret == CMP_ERR_WRONG_VALUE && ethif->dhcpd_enabled == 0))) {
            nmsc_log("Set %s dhcpd %s failed for %d.", ethif->name, 
               ethif->dhcpd_enabled ? "enable" : "disable" , ret);
            goto ERROR_OUT;
        }
        else {
            /* fix bug 3337 */
            dhcpd_apply();
        }
    }

    return 0;
ERROR_OUT:
    return dc_error_code(dc_error_commit_failed, dc_node_dhcpd, ret);
#else
    return 0;
#endif
}

int nmsc_delay_op_version(void *reserved) 
{
#if !OK_PATCH
    if (reserved) {
        int version = *((int *)reserved);
        cfg_set_version(version);

        nmsc_log("New config version %d:%d.\n", version, cfg_get_version());
    }

#endif
    return 0;
}

int nmsc_delay_op_wds_acl(void *reserved) 
{
#if !OK_PATCH
    int ret;
    char *acWdsAcl = reserved;

    if (*acWdsAcl != '\0') {
        ret = WDS_set_acl(acWdsAcl);
        if(ret != 0 && ret != CMP_ERR_COMMIT_FAIL){
            nmsc_log("Wds set acl %s failed for %d.", acWdsAcl, ret);
        }
    }
    else{
        ret = WDS_clean_acl();
        if(ret != 0){
            nmsc_log("Wds clean acl failed for %d.", ret);
            goto ERROR_OUT;
        }
    }
    
    return 0;
ERROR_OUT:
    return dc_error_code(dc_error_commit_failed, dc_node_wds, ret);
#else
    return 0;
#endif
}

int nmsc_delay_op_wds_mode(void *reserved) 
{
#if !OK_PATCH
    int ret;

    if (reserved) {
        int iWdsMode = *(int *)reserved;
        if(iWdsMode == 1){
            ret = WDS_set_mode_rootap();
            if(ret != 0 && ret != CMP_ERR_COMMIT_FAIL) {
                nmsc_log("Wds set root role failed for %d.", ret);
                goto ERROR_OUT;
            }
            else {
                if(ret == CMP_ERR_COMMIT_FAIL){
                    ret = WDS_sync_config();
                    if(ret){
                        nmsc_log("Wds sync config failed for %d.", ret);
                        goto ERROR_OUT;
                    }
                }
            }
        }
    }

    return 0;
ERROR_OUT:
    return dc_error_code(dc_error_commit_failed, dc_node_wds, ret);
#else
    return 0;
#endif
}

int nmsc_delay_op_bind_wlan_scan(void *reserved)
{
#if !OK_PATCH
    int ret;

    if (reserved) {
        struct wlan_scan_bind_info {
            char cRadioName[33];
            char cRadioWScanName[33];
        };
        struct wlan_scan_bind_info  info= *(struct wlan_scan_bind_info *)reserved;
        ret = wlan_bind_scan_tempate(info.cRadioName, info.cRadioWScanName);
        if(ret){
            nmsc_log("Wlan scan %s bind %s failed for %d.",info.cRadioWScanName, info.cRadioName, ret);
            goto ERROR_OUT;
        }
    }
     return 0;
ERROR_OUT:
     return dc_error_code(dc_error_commit_failed, dc_node_wlan_scan, ret);
#else
     return 0;
#endif
}


int nmsc_delay_op_save_all(void *reserved) 
{
#if !OK_PATCH
    int ret = cfg_save_all(0);

    if (ret) {
        nmsc_log("Save config all failed for %d.", ret);
        goto ERROR_OUT;
    }

    return 0;
ERROR_OUT:
    return dc_error_code(dc_error_commit_failed, dc_node_config_version, ret);
#else
    return 0;
#endif
}
