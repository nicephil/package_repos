#include <time.h> 
#include <arpa/inet.h>
#include "CWWTP.h"
#include "devctrl_protocol.h"
#include "devctrl_payload.h"
#include "devctrl_notice.h"

#include "services/cfg_services.h"

#define WLAN_STA_STAUS_TIMER    30

static CWTimerID g_sta_notice_timerid = -1;

static inline rssi_level_e dc_rssi2level(int rssi) 
{
    if (rssi >= -65) {
        return RSSI_LEVEL_EXCELLENT;
    }
    else if (rssi >= -75) {
        return RSSI_LEVEL_GOOD;
    }
    else {
        return RSSI_LEVEL_LOW;
    }
}

static int fetch_station_info_visitor(struct uci_package *p, void *arg)
{
    struct uci_element *e1, *e2;
    int index = 0;
    struct wlan_sta_stat_all {
        int count;
        struct wlan_sta_stat **stas;
    };
    struct wlan_sta_stat_all *all = (struct wlan_sta_stat_all *)arg;

    struct wlan_sta_stat *stas = NULL;

    uci_foreach_element(&p->sections, e1) {
        all->count ++;
    }
    if (!all->count) {
        stas = NULL;
        return 0;
    }
    stas = (struct wlan_sta_stat *)malloc(all->count * sizeof(struct wlan_sta_stat));
    memset(stas, 0, all->count * sizeof(struct wlan_sta_stat));
    index = 0;
    uci_foreach_element(&p->sections, e1) {
        struct uci_section *s = uci_to_section(e1);
        uci_foreach_element(&s->options, e2) {
            struct uci_option *o = uci_to_option(e2);
            if (!strcmp(o->e.name, "ifname")) {
                continue;
            }else if (!strcmp(o->e.name, "mac")) {
                char mac[22] = {0};
                strcpy(mac, o->v.string);
                char *s = mac;
                char *e;
                int i;
                for (i = 0; i < 6; i++) {
                    stas[index].mac[i] = s ? strtoul(s, &e, 16) : 0;
                    if (s) {
                        s = (*e) ? e + 1 : e;
                    }
                }
            } else if (!strcmp(o->e.name, "chan")) {
                stas[index].channel = atoi(o->v.string);
            } else if (!strcmp(o->e.name, "rssi")) {
                stas[index].rssi = atoi(o->v.string);
            } else if (!strcmp(o->e.name, "assoctime")) {
                struct  timeval    tv;
                int hours=0, minutes=0, seconds=0;
                if(sscanf(o->v.string, "%d:%d:%d", &hours, &minutes, &seconds)) {
                    stas[index].uptime = hours*60*60 + minutes*60 + seconds;
                }
                gettimeofday(&tv,NULL);
                stas[index].time_ms = ((unsigned long long)tv.tv_sec*1000 + tv.tv_usec/1000) - (stas[index].uptime*1000);
            } else if (!strcmp(o->e.name, "ipaddr")) {
                struct in_addr net;
                inet_aton(o->v.string, &net);
                stas[index].ip = net.s_addr;
            } else if (!strcmp(o->e.name, "radioid")) {
                stas[index].radioid = atoi(o->v.string);
            } else if (!strcmp(o->e.name, "bssid")) {
                char mac[22] = {0};
                strcpy(mac, o->v.string);
                char *s = mac;
                char *e;
                int i;
                for (i = 0; i < 6; i++) {
                    stas[index].bssid[i] = s ? strtoul(s, &e, 16) : 0;
                    if (s) {
                        s = (*e) ? e + 1 : e;
                    }
                }
            } else if (!strcmp(o->e.name, "authentication")) {
                if (!strcmp(o->v.string, "open")) {
                    stas[index].auth = 0;
                } else {
                    stas[index].auth = 5;
                }
            } else if (!strcmp(o->e.name, "portal_scheme")) {
                strcpy(stas[index].ps_name, o->v.string);
                stas[index].ps_len = strlen(stas[index].ps_name);
                stas[index].portal = 1;
            } else if (!strcmp(o->e.name, "ssid")) {
                strcpy(stas[index].ssid, o->v.string);
                stas[index].ssid_len = strlen(stas[index].ssid);
            } else if (!strcmp(o->e.name, "vlan")) {
                stas[index].vlan = atoi(o->v.string);
            } else if (!strcmp(o->e.name, "portal_mode")) {
                stas[index].portal_mode = atoi(o->v.string);
            } else if (!strcmp(o->e.name, "portal_user")) {
                strncpy(stas[index].user, o->v.string, sizeof(stas[index].user)-1);
                stas[index].name_len = strlen(stas[index].user);
            }
        }
        index ++;
    }
    *(all->stas) = stas;
    return 0;
}

static int wlan_get_sta_info(struct wlan_sta_stat **stas)
{
    struct wlan_sta_stat_all {
        int count;
        struct wlan_sta_stat **stas;
    };

    struct wlan_sta_stat_all all;
    all.count = 0;
    all.stas = stas;
    int ret = 0;

    system("/lib/getstainfo.sh");

    ret = cfg_visit_package_with_path("/tmp/stationinfo", "stationinfo", fetch_station_info_visitor, (void*)&all);
    if (ret) {
        return -1;
    }

    return all.count;
}

static int inline dc_reserves_stas(struct wlan_sta_stat **sta_list, 
    int totalsize, int cursize, struct wlan_sta_stat *newstas, int count)
{
    struct wlan_sta_stat * stas = *sta_list;
    
    if (cursize + count > totalsize || stas == NULL) {
        if (count > 5) {
            totalsize += count;
        }
        else {
            totalsize += 5;
        }
        if (stas == NULL) {
            stas = (struct wlan_sta_stat *)malloc(totalsize *sizeof(struct wlan_sta_stat));
        }
        else  {
            stas = (struct wlan_sta_stat *)realloc(stas, totalsize * sizeof(struct wlan_sta_stat));
        }
    }

    if (stas == NULL) {
        return -1;
    }

    memcpy(&(stas[cursize]), newstas, (count * sizeof(struct wlan_sta_stat)));
    *sta_list = stas;
    return totalsize;
}

int dc_get_wlan_sta_stats(struct wlan_sta_stat **stas, int diff)
{
#define UPTIME_DIFF   1 /* s */
    static struct wlan_sta_stat *pre_stas = NULL;
    static int pre_count = 0;
    struct wlan_sta_stat *cur_stas = NULL, *rse_stas = NULL, *cur, *pre;
    int i, j, cur_count, res_count = 0, totalsize = 0;

    cur_count = wlan_get_sta_info(&cur_stas);
    if (cur_count < 0 && cur_stas == NULL) {
        return -1;
    }

    if (diff == 1) {
        for (i = 0; i < cur_count; i++) {
            cur = &(cur_stas[i]);
            for (j = 0; j < pre_count; j++) {
                pre = &(pre_stas[j]);
                if (!memcmp(cur->mac, pre->mac, sizeof(cur->mac))) {
                    /* Roaming form pre radio to cur radio or reassocation with same radio */
                    if (cur->radioid != pre->radioid || cur->uptime < WLAN_STA_STAUS_TIMER) { 
                        pre->state = 1; /* disassociation form pre radio */
                        pre->updated = 0; /* fix bug 2776: need reset to 0 */
                        totalsize = dc_reserves_stas(&rse_stas, totalsize, res_count, pre, 1);
                        if (totalsize < 0) {
                            res_count = -1;
                            goto FREE_STAS;
                        }
                        res_count += 1;
                        
                        /* assocation with current radio */
                        totalsize = dc_reserves_stas(&rse_stas, totalsize, res_count, cur, 1);
                        if (totalsize < 0) {
                            res_count = -1;
                            goto FREE_STAS;
                        }
                        res_count += 1;
                    }
                    else {
                        /* sta update notice */
                        if (pre->ip != cur->ip /* new ip */
                            || pre->rs_level != cur->rs_level
                            || pre->portal_mode != cur->portal_mode /* new portal mode */
                            || pre->name_len != cur->name_len /* new username */
                            || strncmp(pre->user, cur->user, pre->name_len) != 0) {
                            cur->updated = 1;
                            
                            totalsize = dc_reserves_stas(&rse_stas, totalsize, res_count, cur, 1);
                            if (totalsize < 0) {
                                res_count = -1;
                                goto FREE_STAS;
                            }
                            res_count += 1;
                        }
                    }
                    break;
                }
            }

            /* cur mac does't include in pre stas, it association with our AP in current period */
            if (j >= pre_count) {
                totalsize = dc_reserves_stas(&rse_stas, totalsize, res_count, cur, 1);
                if (totalsize < 0) {
                    res_count = -1;
                    goto FREE_STAS;
                }
                res_count += 1;
            }
        }

        for (j = 0; j < pre_count; j++) {
            pre = &(pre_stas[j]);
            for (i = 0; i < cur_count; i++) {
                cur = &(cur_stas[i]);
                if (!memcmp(cur->mac, pre->mac, sizeof(cur->mac))) {
                    break;
                }
            }
            /* pre mac does't include in cur stas, it disassociation form our AP */
            if (i >= cur_count) {
                pre->state = 1;
                pre->updated = 0; /* fix bug 2776: need reset to 0 */
                totalsize = dc_reserves_stas(&rse_stas, totalsize, res_count, pre, 1);
                if (totalsize < 0) {
                    res_count = -1;
                    goto FREE_STAS;
                }
                res_count += 1;
            }
        }
    }
    else {
        if (cur_count > 0) {
            totalsize = dc_reserves_stas(&rse_stas, totalsize, res_count, cur_stas, cur_count);
            if (totalsize < 0) {
                res_count = -1;
                goto FREE_STAS;
            }
            res_count += cur_count;
        }
    }

FREE_STAS:
    if (pre_stas) {
        free(pre_stas);
    }
    pre_stas = cur_stas;
    pre_count = cur_count;

    *stas = rse_stas;
    
    return res_count;
}
 
static void dc_sta_notice_timer_handler(void *arg) 
{
    struct wlan_sta_stat *stas = NULL;
    devctrl_block_s dc_resp;
    char *payload = NULL, *data = NULL;
    int count = 0, paylength = 0, totalsize = 0; 

    count = dc_get_wlan_sta_stats(&stas,1);
    if (stas == NULL || count <= 0) { 
        goto RESTART_TIMER;
    }

    /* WLAN sta status: association or dis association */
    if (assemble_wlan_sta_status_elem(&data, &paylength, stas, count, WLAN_STA_TYPE_STAUS) != CW_TRUE) {
        CWLog("Get wlan client diff stat count %d but assmeble staus msg failed.", count);
        goto RESTART_TIMER;
    }
    if (data != NULL && paylength > 0) {    
        /* 2bytes type + 4bytes length */
        CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto RESTART_TIMER;});

        /* sta status notice */
        save_payload_type(payload, DC_PAYLOAD_STA_STAUS_NOTICE);
        save_payload_length(payload + 2, paylength);
        
        if (data) {
            CW_COPY_MEMORY(payload + 6, data, paylength);
            free(data);
            data = NULL;
        }
        totalsize += (paylength + 6);
    }

    /* WLAN sta status update: acquire ip or poartal authed */
    if (assemble_wlan_sta_status_elem(&data, &paylength, stas, count, WLAN_STA_TYPE_UPDATE) != CW_TRUE) {
        CWLog("Get wlan client diff stat count %d but assmeble update msg failed.", count);
        goto RESTART_TIMER;
    }
    if (data != NULL && paylength > 0) {
        if (payload != NULL) {
            /* 2bytes type + 4bytes length */
            payload = (char *)realloc(payload, (totalsize + paylength + 6));
            if (payload == NULL) {
                goto RESTART_TIMER;
            }
        }
        else {
            CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto RESTART_TIMER;});
        }

        /* sta update info notice */
        save_payload_type(payload + totalsize, DC_PAYLOAD_STA_INFO_NOTICE);
        save_payload_length(payload + totalsize + 2, paylength);
        
        if (data) {
            CW_COPY_MEMORY(payload + totalsize + 6, data, paylength);
            free(data);
        }
        totalsize += (paylength + 6);
    }

    if (payload != NULL && totalsize > 0) {
        memset(&dc_resp, 0, sizeof(dc_resp));
        dc_resp.type       = 1;       /* payload between nms and device */
        dc_resp.compressed = 0;       /* no compress */
        dc_resp.orig_len   = totalsize; 
        dc_resp.len        = totalsize; 
        dc_resp.data       = payload;
        
        if (!WTPEventRequest_devctrlresp(CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE, 
            (int)(&dc_resp))) {
            CWDebugLog("Send WTPEventReq with device control resopnse element failed.");
        }
       
        CW_FREE_OBJECT(payload);
    }

RESTART_TIMER:
    if (stas) {
        free(stas);
    }
    if (dc_start_sta_notice_timer() != 0) {
        CWDebugLog("Start sta status notice timer failed.");
    }
    return;
}

int dc_start_sta_notice_timer(void) 
{	  
	g_sta_notice_timerid = timer_add(WLAN_STA_STAUS_TIMER, 0, &dc_sta_notice_timer_handler, NULL);
	
	if (g_sta_notice_timerid == -1)	{
        CWLog("Add sta status notice timer failed.");
        return -1;
    }

	return 0;
}

int dc_stop_sta_notice_timer(void)
{
    int ret = 0, i, times = 1;

    for (i = 0; i < 4; ++i) {
        ret = timer_rem(g_sta_notice_timerid, NULL);
        if (ret != 0 && g_sta_notice_timerid >= 0) {
            times = (1 << i);
            CWDebugLog("Stop sta notice timer %d failed, will try to stop again after %d seconds.", 
                g_sta_notice_timerid, times);
            sleep(times);
        }
        else {
            if (i > 0) {
                CWDebugLog("Stop sta notice timer %d success now.", g_sta_notice_timerid);
            }
            break;
        }
    }

	CWDebugLog_D("Wlan sta stats Timer Stopped");
    
	return 0;
}
 
void dc_dev_update_notice(void) 
{
    devctrl_block_s dc_resp;
    char *payload = NULL, *data = NULL;
    int paylength = 0; 

    if (assemble_dev_updateinfo(&data, &paylength) != CW_TRUE) {
        return;
    }

    if (data != NULL) {    
        /* 2bytes type + 4bytes length */
        CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(data);});

        /* sta status notice */
        save_payload_type(payload, DC_PAYLOAD_DEV_UPDATE_NOTICE);
        save_payload_length(payload + 2, paylength);
        
        if (data) {
            CW_COPY_MEMORY(payload + 6, data, paylength);
            free(data);
            data = NULL;
        }

        memset(&dc_resp, 0, sizeof(dc_resp));
        dc_resp.type       = 1;       /* payload between nms and device */
        dc_resp.compressed = 0;       /* no compress */
        dc_resp.orig_len   = paylength + 6; 
        dc_resp.len        = paylength + 6; 
        dc_resp.data       = payload;
        
        if (!WTPEventRequest_devctrlresp(CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE, 
            (int)(&dc_resp))) {
            CWDebugLog("Send WTPEventReq with device control resopnse element failed.");
        }
       
        CW_FREE_OBJECT(payload);
    }

    return;
}

void dc_wds_tunnel_update_notice(struct wds_tunnel_info *pWdsInfo) 
{
    devctrl_block_s dc_resp;
    char *payload = NULL, *data = NULL;
    int paylength = 0; 

    if (assemble_wds_info_elem(&data, &paylength, pWdsInfo, 1) != CW_TRUE) {
        return;
    }

    if (data != NULL) {    
        /* 2bytes type + 4bytes length */
        CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(data);});

        /* wds tunnel notice*/
        save_payload_type(payload, DC_PAYLOAD_WDS_TUNNEL_RESULT);
        save_payload_length(payload + 2, paylength);
        
        if (data) {
            CW_COPY_MEMORY(payload + 6, data, paylength);
            free(data);
            data = NULL;
        }

        memset(&dc_resp, 0, sizeof(dc_resp));
        dc_resp.type       = 1;       /* payload between nms and device */
        dc_resp.compressed = 0;       /* no compress */
        dc_resp.orig_len   = paylength + 6; 
        dc_resp.len        = paylength + 6; 
        dc_resp.data       = payload;
        
        if (!WTPEventRequest_devctrlresp(CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE, 
            (int)(&dc_resp))) {
            CWDebugLog("Send WTPEventReq with device control resopnse element failed.");
        }
       
        CW_FREE_OBJECT(payload);
    }

    return;
}

int WTPProcWDSBuffer(struct wds_tunnel_info **info)
{
#if !OK_PATCH
    struct wds_tunnel_info *pWdsInfo= NULL;
    char acWdsBuffer[512] = {};
    char *pWdsBuf = acWdsBuffer;
    int iFd = 0;
    int iWdsBufLen = 0;
    unsigned short usType = 0;
    unsigned short usLen = 0;

    memset(acWdsBuffer, 0, sizeof(acWdsBuffer));

    iFd = open(WDS_NMS_IPC_PATH, O_RDONLY); 
    if(iFd < 0){
        CWLog("Open WTP_WDS_FILE error.");
        return -1; 
    }

    util_file_lock(iFd);
    iWdsBufLen = read(iFd, acWdsBuffer, sizeof(acWdsBuffer) - 1);
    util_file_unlock(iFd);

    close(iFd);

    pWdsInfo = (struct wds_tunnel_info *)malloc(sizeof(struct wds_tunnel_info));
    memset(pWdsInfo, 0, sizeof(struct wds_tunnel_info));

    while(iWdsBufLen){
        usType = ntohs(*(unsigned short *)pWdsBuf);
        usLen = ntohs(*(unsigned short *)(pWdsBuf + 2));

        switch(usType){
            case WDS_NMS_DEVMAC:
                memcpy(pWdsInfo->mac, pWdsBuf + 4, usLen - 4);
                break;
            case WDS_NMS_MODE:
                pWdsInfo->mode = *(pWdsBuf + 4);
                break;
            case WDS_NMS_ERR:
                pWdsInfo->err_code = *(pWdsBuf + 4);
                break;
            case WDS_NMS_STATUS:
                pWdsInfo->status = *(pWdsBuf + 4);
                break;
            case WDS_NMS_LEVLE:
                pWdsInfo->level = *(pWdsBuf + 4);
                break;
            case WDS_NMS_UPLINKMAC:
                memcpy(pWdsInfo->uplink, pWdsBuf + 4, usLen - 4);
                break;
            default:
                break;
        }

        iWdsBufLen -= usLen;
        pWdsBuf += usLen;
    }

    *info = pWdsInfo;

#endif
    return 0;
}

void get_wds_sigusr(int signo)
{
    struct wds_tunnel_info *pWdsInfo = NULL;
    int ret = 0;

    CWLog("Get wds signo %d.", signo);
    ret = WTPProcWDSBuffer(&pWdsInfo);
    if(ret){ 
        CWLog("Get WDS info error.");
        goto err;
    }

    dc_wds_tunnel_update_notice(pWdsInfo);

err:
    if(pWdsInfo){
        free(pWdsInfo);
    }

    return;
}
