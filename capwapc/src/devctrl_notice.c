#include <time.h> 
#include <arpa/inet.h>
#include "CWWTP.h"
#include "devctrl_protocol.h"
#include "devctrl_payload.h"
#include "devctrl_notice.h"

#include "services/cfg_services.h"
#include "services/wlan_services.h"
#include "sqlite3.h"

#define WLAN_STA_STAUS_TIMER    5

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

//CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME)
static int _sql_callback(void *cookie, int argc, char **argv, char **szColName)
{
    static int row = 0;
    if (*(int*)cookie == -1) {
        row = 0;
        *(int*)cookie = atoi(argv[0]);
        return 0;
    }

    struct wlan_sta_stat *stas = (struct wlan_sta_stat *)cookie;

    /*MAC*/
    if (argv[0]) {
        /* mac address */
        char *s = argv[0], *e;
        int i = 0;
        for (i = 0; i < 6; i++) {
            stas[row].mac[i] = s ? strtoul(s, &e, 16) : 0;
            if (s) {
                s = (*e) ? e + 1 : e;
            }
        }
    }

    /*IFNAME*/
    /*argv[1]*/

    /*CHAN*/
    if (argv[2]) {
        stas[row].channel = atoi(argv[2]);
    } else {
        stas[row].channel = 0;
    }

    /*RSSI*/
    if (argv[3]) {
        stas[row].rssi = atoi(argv[3]) - 95;
        stas[row].rs_level = dc_rssi2level(stas[row].rssi);
    }

    /*ASSOCTIME*/
    if (argv[4]) {
        int hours=0,minutes=0,seconds=0;
        if (sscanf(argv[4], "%d:%d:%d", &hours, &minutes, &seconds)) {
            stas[row].uptime = hours*60*60 + minutes*60 + seconds;
        }
        struct timeval tv = {0};
        gettimeofday(&tv,NULL);
        stas[row].time_ms = ((unsigned long long)tv.tv_sec*1000 + tv.tv_usec/1000) - (stas[row].uptime*1000);
    }
    
    /*RADIOID*/
    if (argv[5]) {
        stas[row].radioid = atoi(argv[5]);
    }

    /*BSSID*/
    if (argv[6]) {
        char mac[22] = {0};
        strcpy(mac, argv[6]);
        char *s = mac;
        char *e;
        int i;
        for (i = 0; i < 6; i++) {
            stas[row].bssid[i] = s ? strtoul(s, &e, 16) : 0;
            if (s) {
                s = (*e) ? e + 1 : e;
            }
        }
    }

    /*IPADDR*/
    if (argv[7]) {
        stas[row].ip = inet_addr(argv[7]);
    }

    /*AUTHENTICATION*/
    if (argv[8]) {
        if (strcmp(argv[8], "open")) {
            stas[row].auth = 5;
        }
    }

    /*PORTAL_SCHEME*/
    if (argv[9]) {
        strcpy(stas[row].ps_name, argv[9]);
        stas[row].ps_len = strlen(stas[row].ps_name);
        if (stas[row].ps_len) {
            stas[row].portal = 1;
        }
    }
    
    /*SSID*/
    if (argv[10]) {
        strcpy(stas[row].ssid, argv[10]);
        stas[row].ssid_len = strlen(stas[row].ssid);
    }

    /*VLAN*/
    if (argv[11]) {
        stas[row].vlan = atoi(argv[11]);
    }

    /*PORTAL_MODE*/
    if (argv[12]) {
        stas[row].portal_mode = atoi(argv[12]);
    }

    /*PORTAL_USER*/
    if (argv[13]) {
        strncpy(stas[row].user, argv[13], sizeof(stas[row].user)-1);
        stas[row].name_len = strlen(stas[row].user);
    }

    /*SMODE*/
    if (argv[14]) {
        if (!strcmp(argv[14], "ac") || !strcmp(argv[14], "11ac")) {
            stas[row].mode = DOT11_RADIO_MODE_AC;
        } else if (!strcmp(argv[14], "na")) {
            stas[row].mode = DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N;
        } else if (!strcmp(argv[14], "ng") || !strcmp(argv[14], "11ng")) {
            stas[row].mode = DOT11_RADIO_MODE_G | DOT11_RADIO_MODE_N;
        } else if (!strcmp(argv[14], "a")) {
            stas[row].mode = DOT11_RADIO_MODE_A;
        } else if (!strcmp(argv[14], "g")) {
            stas[row].mode = DOT11_RADIO_MODE_G;
        } else if (!strcmp(argv[14], "n")) {
            stas[row].mode = DOT11_RADIO_MODE_N;
        }
    }

    /*SBW*/
    if (argv[15]) {
        int bw = 0;
        if (strstr(argv[15], "VHT")) {
            sscanf(argv[15],"VHT%2d", &bw);
            stas[row].bandwidth = bw;
        } else {
            sscanf(argv[15],"HT%2d", &bw);
            stas[row].bandwidth = bw;
        }
    }

    /*NTXRT*/
    if (argv[16]) {
        stas[row].ntxrt = atoi(argv[16]);
    }

    /*NRXRT*/
    if (argv[17]) {
        stas[row].nrxrt = atoi(argv[17]);
    }

    /*TXB*/
    if (argv[18]) {
        stas[row].txB = atoll(argv[18]);
    }

    /*RXB*/
    if (argv[19]) {
        stas[row].rxB = atoll(argv[19]);
    }

    //syslog(LOG_ERR, "sql:%x%x txB:%s:%lld rxB:%s:%lld", stas[row].mac[4], stas[row].mac[5], argv[18], stas[row].txB, argv[19], stas[row].rxB);

    /*ATXRB*/
    if (argv[20]) {
        //stas[row].atxrb = atoi(argv[20]);
    }
    
    /*ARXRB*/
    if (argv[21]) {
        //stas[row].arxrb = atoi(argv[21]);
    }

    /*TXFS*/
    /*argv[22]*/

    /*REXS*/
    /*argv[23]*/

    /*TS*/
    if (argv[24]) {
        stas[row].ts = atoll(argv[24]);
    }

    /*client type*/

    /*hostname*/
    if (argv[25]) {
        strncpy(stas[row].client_hostname, argv[25], HOST_NAME_MAX);
        stas[row].client_hostname_len = strlen(stas[row].client_hostname);
    }

    /*location*/
    cfg_get_option_value(CAPWAPC_CFG_OPTION_LOCATION_TUPLE, stas[row].location, MAX_LOCATION_LEN);
    stas[row].location_len = strlen(stas[row].location);
    
    row ++;

    return 0;
}

static int wlan_get_sta_info_db(void *stats)
{
    struct wlan_sta_stat_all {
        int count;
        struct wlan_sta_stat **stas;
    };
    struct wlan_sta_stat_all *all = (struct wlan_sta_stat_all *)stats;

    const char *sql_count_str="SELECT count(*) FROM STATSINFO";
    const char *sql_str="SELECT * FROM STATSINFO";
    sqlite3 *db = NULL;
    char *pErrMsg = NULL; 
    int ret = 0;
    int count = -1;

    ret = sqlite3_open("/tmp/statsinfo.db", &db);
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
    all->count = count;

    *(all->stas) = (struct wlan_sta_stat *)malloc(count * sizeof(struct wlan_sta_stat));
    if (*(all->stas) == NULL) {
        CWLog("SQL create error: %s\n", pErrMsg);
        ret = -3;
        goto __cleanup;
    }
    memset(*(all->stas), 0, count * sizeof(struct wlan_sta_stat));

    ret = sqlite3_exec(db, sql_str, _sql_callback, *(all->stas), &pErrMsg);
    if (ret != SQLITE_OK) {
        CWLog("SQL create error: %s\n", pErrMsg);
        ret = -4;
    }

    ret = 0;

__cleanup:
    if (db) {
        sqlite3_close(db);
    }
    if(pErrMsg) {
        free(pErrMsg);
    }
    return ret;
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

    system("/lib/okos/getstainfo.sh");

    ret = wlan_get_sta_info_db((void*)&all);
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
            struct wlan_sta_stat *stas_tmp;
            stas_tmp = (struct wlan_sta_stat *)realloc(stas, totalsize * sizeof(struct wlan_sta_stat));
            if (stas_tmp) {
                stas=stas_tmp;
            }
        }
    }

    if (stas == NULL) {
        return -1;
    }

    memcpy(&(stas[cursize]), newstas, (count * sizeof(struct wlan_sta_stat)));
    *sta_list = stas;
    return totalsize;
}

static int dc_get_wlan_radio_stats(struct wlan_radio_stat **stats)
{
    int count = 2;
    struct wlan_radio_stat *cur_stats = NULL;
    cur_stats = (struct wlan_radio_stat *)malloc(count*sizeof(struct wlan_radio_stat));
    if (cur_stats == NULL) {
        count  = 0;
        return count;
    }
    strcpy(cur_stats[0].ifname, "wifi1");
    cur_stats[0].ifname_len = strlen(cur_stats[0].ifname);
    cur_stats[0].chan_util = 20;
    cur_stats[0].error_rate = 1;
    cur_stats[0].retry_rate = 3;
    cur_stats[0].snr = 40;
    cur_stats[0].tx_rate = 1024;
    cur_stats[0].rx_rate = 4096;

    strcpy(cur_stats[1].ifname, "wifi0");
    cur_stats[1].ifname_len = strlen(cur_stats[1].ifname);
    cur_stats[1].chan_util = 60;
    cur_stats[1].error_rate = 10;
    cur_stats[1].retry_rate = 30;
    cur_stats[1].snr = 20;
    cur_stats[1].tx_rate = 1024;
    cur_stats[1].rx_rate = 2048;

    *stats = cur_stats;

    return count;
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
                    /* Roaming from pre radio to cur radio or reassocation with same radio */
                    if (cur->radioid != pre->radioid || cur->uptime < WLAN_STA_STAUS_TIMER) { 
                        pre->state = 1; /* disassociation from pre radio */
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
                        if (1||pre->ip != cur->ip /* new ip */
                                || pre->rs_level != cur->rs_level
                                || pre->portal_mode != cur->portal_mode /* new portal mode */
                            || pre->name_len != cur->name_len /* new username */
                            || strncmp(pre->user, cur->user, pre->name_len) != 0) {
                            cur->updated = 1;
                            cur->delta_txB = cur->txB - pre->txB;
                            cur->delta_rxB = cur->rxB - pre->rxB;
                            cur->atxrb = (cur->delta_txB * 8) / (cur->ts - pre->ts) / 1024;
                            cur->arxrb = (cur->delta_rxB * 8) / (cur->ts - pre->ts) / 1024;
                            //syslog(LOG_ERR, "O%x%x===>dtxB:%d drxB:%d txB:%d rxB:%d atx:%d arx:%d", pre->mac[4], pre->mac[5],  pre->delta_txB, pre->delta_rxB, pre->txB, pre->rxB, pre->atxrb, pre->arxrb);
                            //syslog(LOG_ERR, "N%x%x+++>%d %d %d %d %d %d", cur->mac[4], cur->mac[5], cur->delta_txB, cur->delta_rxB, cur->txB, cur->rxB, cur->atxrb, cur->arxrb);
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
            char * payload_tmp;
            payload_tmp = (char *)realloc(payload, (totalsize + paylength + 6));
            if (payload_tmp == NULL) {
                goto RESTART_TIMER;
            } else {
                payload = payload_tmp;
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

    /* radio status */
    struct wlan_radio_stat *radio_stats = NULL;
    count = dc_get_wlan_radio_stats(&radio_stats);
    if (radio_stats == NULL || count <= 0) { 
        goto RESTART_TIMER;
    }
    /* WLAN radio status notification */
    if (assemble_wlan_radio_status_elem(&data, &paylength, radio_stats, count) != CW_TRUE) {
        CWLog("Get wlan radio stats count %d but assmeble update msg failed.", count);
        goto RESTART_TIMER;
    }
    if (data != NULL && paylength > 0) {
        if (payload != NULL) {
            /* 2bytes type + 4bytes length */
            char * payload_tmp;
            payload_tmp = (char *)realloc(payload, (totalsize + paylength + 6));
            if (payload_tmp == NULL) {
                goto RESTART_TIMER;
            } else {
                payload = payload_tmp;
            }
        }
        else {
            CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {goto RESTART_TIMER;});
        }

        /* radio status  notice */
        save_payload_type(payload + totalsize, DC_PAYLOAD_RADIO_STATUS_NOTICE);
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
    if (radio_stats) {
        free(radio_stats);
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
