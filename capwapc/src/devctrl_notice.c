#include <time.h> 
#include <arpa/inet.h>
#include "CWWTP.h"
#include "devctrl_protocol.h"
#include "devctrl_payload.h"
#include "devctrl_notice.h"
#if !OK_PATCH
#include "services/wlan_services.h"
#include "services/vlan_services.h"
#include "services/wds_services.h"
#include "cmp/cmp_pub.h"
#include "util/util.h"
#endif

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

static int wlan_get_sta_info(struct wlan_sta_stat **stas)
{
#if !OK_PATCH
    int count = 0, size = 0;
    int i, j, k, ret, num;
    struct wmac_init_param  radio_init;
    struct wlan_radio_status   radio;
    DOT11_RADIO_CAP_S   caps[DOT11_RADIO_NUM_MAX];
    struct wlan_sta_stat *sta_list = NULL;
    static char radio_count = -1;

    if(radio_count <= 0){
        if (DOT11_GetHardwareInfo(&radio_init, &caps[0]) == DOT11_OK) {
            radio_count = radio_init.uRadioNums;
        }
    }

    for (i = 0; i < radio_count; ++i) {
        ret = wlan_get_radio_status(i, &radio);
        if (ret != CMP_ERR_NO_ERR) {
            CWDebugLog("WLAN radio %d does not exist.", i);
        }
        else {
            struct wlan_bss_status bss;
            
            if (radio.enable) {
                struct wlan_service_template stspec, *stcur;
                
                for (j = 0; j < radio.bss_count; ++j) {
                    ret = wlan_get_bss_status(radio.bss[j], &bss);
                    if (ret == 0) {
                        struct wlan_sta_status  * sta, *s;
                        struct if_attrs attrs;
                        port_vlan_info portinfo;
                        int vlan = 1;
                        
                        num = wlan_get_sta_list(bss.linkname, &sta);
                        if (num <= 0 || sta == NULL) {
                            continue;
                        }

/* BEGIN: modified by zjye to fix bug 3617 2016-4-11 */
#if 0
                        vlan_get_pvid(bss.linkname, &vlan);                        
#else
                        portinfo.port_pvid = -1;
                        eth_get_vlan_info(IF_PHYTYPE_WLAN_BSS, bss.id, &portinfo);
                        if (portinfo.port_pvid <= 0) {
                            vlan = 1;
                        }
                        else {
                            vlan = portinfo.port_pvid;
                        }
#endif
/* END: modified by zjye to fix bug 3617 2016-4-11 */
                        if_get_attrs_by_linkname(bss.linkname, &attrs, NULL);
                        
                        memset(&stspec, 0, sizeof(stspec));
                        strncpy(stspec.ssid, bss.ssid, sizeof(stspec.ssid) - 1);
                        if (wlan_service_template_by_ssid(&stspec) == 0 && strlen(stspec.portal_scheme) > 0) {
                            stcur = &stspec;
                        }
                        else {
                            stcur = NULL;
                        }
                        s = sta;
                        for (k = 0; k < num; ++k) {
                            struct  timeval    tv;
                            if (count >= size) {
                                size += 5;
                                if (count == 0) {
                                    sta_list = (struct wlan_sta_stat *)malloc(size *sizeof(struct wlan_sta_stat));
                                }
                                else  {
                                    sta_list = (struct wlan_sta_stat *)realloc(sta_list, size * sizeof(struct wlan_sta_stat));
                                }
                                if(sta_list == NULL){
                                    CWLog("Failed to malloc station in get station.");
                                    return -1;
                                }
                            }
                            sta_list[count].auth = bss.auth;
                            sta_list[count].cipher = bss.crypt;
                            sta_list[count].ip = s->ipv4.s_addr;
                            memcpy(sta_list[count].mac, s->mac, sizeof(sta_list[count].mac));
                            sta_list[count].state = 0;
                            sta_list[count].radioid = i;
                            strncpy(sta_list[count].ssid, bss.ssid, sizeof(sta_list[count].ssid) - 1);
                            sta_list[count].ssid_len = strlen(bss.ssid);
                            sta_list[count].uptime = s->assoc_time;
                            gettimeofday(&tv,NULL);
                            sta_list[count].time_ms = ((unsigned long long)tv.tv_sec*1000 + tv.tv_usec/1000) - (s->assoc_time*1000);
                            sta_list[count].updated = 0;
                            if (stcur == NULL) {
                                sta_list[count].portal = 0;
                                sta_list[count].portal_mode = 0;
                                sta_list[count].name_len = 0;
                                sta_list[count].user[0] = 0;
                                sta_list[count].ps_len = 0; 
                                sta_list[count].ps_name[0] = 0;
                            }
                            else {
                                sta_list[count].portal = 1;
                                sta_list[count].portal_mode = 0;
                                sta_list[count].name_len = 0;
                                sta_list[count].user[0] = 0;
                                sta_list[count].ps_len = strlen(stcur->portal_scheme);
                                strcpy(sta_list[count].ps_name, stcur->portal_scheme);

                                int fd = 0, cmd = PORTAL_IOC_GET_AUTHSTA;
                                portal_op_arg arg;
                                portal_auth_cfg_t auinfo;

                                memset(&auinfo, 0, sizeof(portal_auth_cfg_t));
                                memcpy(auinfo.clientmac, s->mac, ETH_ALEN);
                                strncpy(arg.portal_scheme_name, stcur->portal_scheme, PORTAL_SCHEME_NAME_MAX);
                                arg.datalen = sizeof(portal_auth_cfg_t);
                                arg.pointer = &auinfo;
                                fd = open(PORTAL_DEV_NAME, O_RDWR);
                                if (fd >= 0)
                                {
                                    if (ioctl(fd, cmd, &arg) < 0) {
#if 0
                                        CWLog("Get portal info from %s for client %02X:%02X:%02X:%02X:%02X:%02X failed.",
                                            stcur->portal_scheme, auinfo.clientmac[0], auinfo.clientmac[1], auinfo.clientmac[2],
                                            auinfo.clientmac[3], auinfo.clientmac[4], auinfo.clientmac[5]);
#endif
                                    }
                                    else {
                                        sta_list[count].portal_mode = auinfo.authmode;
                                        sta_list[count].name_len = auinfo.namelen;
                                        strcpy(sta_list[count].user, auinfo.username);
                                    }
                                    close(fd);
                                }
                            }
                            memcpy(sta_list[count].bssid, attrs.dev_addr.sa_data, sizeof(sta_list[count].bssid));
                            sta_list[count].rssi = s->rssi - 95;
                            sta_list[count].rs_level = dc_rssi2level(sta_list[count].rssi);
                            sta_list[count].channel = bss.channel;
                            sta_list[count].vlan = vlan;
                            
                            count++;
                            ++s;
                        }
                        free(sta);
                    }
                }
            }
        }
    }
    
    *stas = sta_list;

    return count;
#else
    struct wlan_sta_stat *sta_list = NULL;
    sta_list = (struct wlan_sta_stat *)malloc(sizeof(struct wlan_sta_stat));
    memset(sta_list, 0, sizeof(struct wlan_sta_stat));
    sta_list->updated = 0;
    sta_list->len = 0; 
    sta_list->state = 0;

    /* mac address */
    char mac[20] = "00:11:22:33:44";
    char *s = mac;
    char *e;
    int i;
    for (i = 0; i < 6; i++) {
        sta_list->mac[i] = s ? strtoul(s, &e, 16) : 0;
        if (s) {
            s = (*e) ? e + 1 : e;
        }
    }

    sta_list->time_ms = 200;
    sta_list->uptime = 400;
    sta_list->radioid = 1;
    strcpy(sta_list->ssid, "oakridge");
    sta_list->ssid_len = strlen(sta_list->ssid+1);
    sta_list->auth = 0;
    sta_list->cipher = 0;
    sta_list->portal = 1;

    struct in_addr addr;
    inet_aton("192.168.10.123", &addr);
    sta_list->ip = addr.s_addr;

    sta_list->portal_mode = 1;
    sta_list->name_len = 0;
    strcpy(sta_list->ps_name, "123"); /* portal scheme */
    sta_list->ps_len = strlen(sta_list->ps_name);
    strcpy(sta_list->bssid, "oakridge");
    sta_list->rssi = 30;
    sta_list->channel = 124;
    sta_list->vlan = 0;
    sta_list->rs_level = 1;
    *stas = sta_list;
    return 1;
#endif
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
