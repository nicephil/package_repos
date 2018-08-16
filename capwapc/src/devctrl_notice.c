#include <time.h> 
#include <arpa/inet.h>
#include "CWWTP.h"
#include "devctrl_protocol.h"
#include "devctrl_payload.h"
#include "devctrl_notice.h"
#include <sys/wait.h>

#include "services/cfg_services.h"
#include "services/wlan_services.h"
#include "sqlite3.h"

#define WLAN_STA_STAUS_TIMER   10


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

//CREATE TABLE ${tablename}(MAC,IFNAME,CHAN,RSSI,ASSOCTIME,RADIOID,BSSID,IPADDR,AUTHENTICATION,PORTAL_SCHEME,SSID,VLAN,PORTAL_MODE,PORTAL_USER,SMODE,SBW,NTXRT,NRXRT,TXB,RXB,ATXRB,ARXRB,TXFS,RXES,TS,HOSTNAME,WANTXB,WANRXB,GWADDR,MINRSSI,MAXRSSI)
static int _sql_callback(void *cookie, int argc, char **argv, char **szColName)
{
    static int row = 0;
    if (*(int*)cookie == -1) {
        row = 0;
        *(int*)cookie = atoi(argv[0]);
        return 0;
    }

    struct wlan_sta_stat_all {
        int count;
        struct wlan_sta_stat **stas;
    };
    struct wlan_sta_stat_all *all = (struct wlan_sta_stat_all *)cookie;
    struct wlan_sta_stat *stas = *(all->stas);
    if (row >= all->count) {
        return 0;
    }

    /*MAC*/
    if (argv[0] && strlen(argv[0])) {
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
    if (argv[2] && strlen(argv[2])) {
        stas[row].channel = atoi(argv[2]);
    } else {
        stas[row].channel = 0;
    }

    /*RSSI*/
    if (argv[3] && strlen(argv[3])) {
        stas[row].rssi = atoi(argv[3]) - 95;
        stas[row].rs_level = dc_rssi2level(stas[row].rssi);
    }

    /*ASSOCTIME*/
    if (argv[4] && strlen(argv[4])) {
        int hours=0,minutes=0,seconds=0;
        if (sscanf(argv[4], "%d:%d:%d", &hours, &minutes, &seconds)) {
            stas[row].uptime = hours*60*60 + minutes*60 + seconds;
        }
        struct timeval tv = {0};
        gettimeofday(&tv,NULL);
        stas[row].time_ms = ((unsigned long long)tv.tv_sec*1000 + tv.tv_usec/1000) - (stas[row].uptime*1000);
    }
    
    /*RADIOID*/
    if (argv[5] && strlen(argv[5])) {
        stas[row].radioid = atoi(argv[5]);
    }

    /*BSSID*/
    if (argv[6] && strlen(argv[6])) {
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
    if (argv[7] && strlen(argv[7])) {
        stas[row].ip = inet_addr(argv[7]);
    }

    /*AUTHENTICATION*/
    if (argv[8] && strlen(argv[8])) {
        if (strcmp(argv[8], "open")) {
            stas[row].auth = 5;
        }
    }

    /*PORTAL_SCHEME*/
    if (argv[9] && strlen(argv[9])) {
        strcpy(stas[row].ps_name, argv[9]);
        stas[row].ps_len = strlen(stas[row].ps_name);
        if (stas[row].ps_len) {
            stas[row].portal = 1;
        }
    }
    
    /*SSID*/
    if (argv[10] && strlen(argv[10])) {
        strcpy(stas[row].ssid, argv[10]);
        stas[row].ssid_len = strlen(stas[row].ssid);
    }

    /*VLAN*/
    if (argv[11] && strlen(argv[11])) {
        stas[row].vlan = atoi(argv[11]);
    }

    /*PORTAL_MODE*/
    if (argv[12] && strlen(argv[12])) {
        stas[row].portal_mode = atoi(argv[12]);
    }

    /*PORTAL_USER*/
    if (argv[13] && strlen(argv[13])) {
        strncpy(stas[row].user, argv[13], sizeof(stas[row].user)-1);
        stas[row].name_len = strlen(stas[row].user);
    }


    /*SBW*/ /*handle SBW first, and it will be overwritten by following SMODE*/
    if (argv[15] && strlen(argv[15])) {
        int bw = 0;
        if (strstr(argv[15], "VHT")) {
            sscanf(argv[15],"VHT%2d", &bw);
            stas[row].bandwidth = bw;
        } else {
            sscanf(argv[15],"HT%2d", &bw);
            stas[row].bandwidth = bw;
        }
    }

    /*SMODE*/
    if (argv[14] && strlen(argv[14])) {
        if (!strcmp(argv[14], "ac") || !strcmp(argv[14], "11ac")) {
            stas[row].mode = DOT11_RADIO_MODE_AC;
        } else if (!strcmp(argv[14], "na") || !strcmp(argv[14], "11na")) {
            stas[row].mode = DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N;
        } else if (!strcmp(argv[14], "ng") || !strcmp(argv[14], "11ng")) {
            stas[row].mode = DOT11_RADIO_MODE_G | DOT11_RADIO_MODE_N;
        } else if (!strcmp(argv[14], "a") || !strcmp(argv[14], "11a")) {
            stas[row].mode = DOT11_RADIO_MODE_A;
            stas[row].bandwidth = 20;
        } else if (!strcmp(argv[14], "b") || !strcmp(argv[14], "11b")) {
            stas[row].mode = DOT11_RADIO_MODE_B;
            stas[row].bandwidth = 20;
        } else if (!strcmp(argv[14], "g") || !strcmp(argv[14], "11g")) {
            stas[row].mode = DOT11_RADIO_MODE_G;
            stas[row].bandwidth = 20;
        } else if (!strcmp(argv[14], "n") || !strcmp(argv[14], "11n")) {
            stas[row].mode = DOT11_RADIO_MODE_N;
        }
    } else {
        stas[row].mode = DOT11_RADIO_MODE_G | DOT11_RADIO_MODE_N;
    }


    /*NTXRT*/
    if (argv[16] && strlen(argv[16])) {
        stas[row].ntxrt = atoi(argv[16]);
    }

    /*NRXRT*/
    if (argv[17] && strlen(argv[17])) {
        stas[row].nrxrt = atoi(argv[17]);
    }

    /*TXB*/
    if (argv[18] && strlen(argv[18])) {
        stas[row].txB = strtoull(argv[18], NULL, 10);
    }

    /*RXB*/
    if (argv[19] && strlen(argv[19])) {
        stas[row].rxB = strtoull(argv[19], NULL, 10);
    }

    //syslog(LOG_ERR, "sql:%x%x txB:%s:%lld rxB:%s:%lld", stas[row].mac[4], stas[row].mac[5], argv[18], stas[row].txB, argv[19], stas[row].rxB);

    /*ATXRB*/
    if (argv[20] && strlen(argv[20])) {
        //stas[row].atxrb = atoi(argv[20]);
    }
    
    /*ARXRB*/
    if (argv[21] && strlen(argv[21])) {
        //stas[row].arxrb = atoi(argv[21]);
    }

    /*TXFS*/
    /*argv[22]*/

    /*REXS*/
    /*argv[23]*/

    /*TS*/
    if (argv[24] && strlen(argv[24])) {
        stas[row].ts = strtoull(argv[24], NULL, 10);
    }

    /*client type*/

    /*hostname*/
    if (argv[25] && strlen(argv[25])) {
        strncpy(stas[row].client_hostname, argv[25], HOST_NAME_MAX);
        stas[row].client_hostname_len = strlen(stas[row].client_hostname);
    }

    /*psmode*/
    if (argv[26] && strlen(argv[26])) {
        stas[row].psmode = atoi(argv[26]);
    }

    /*WANTXB*/
    if (argv[27] && strlen(argv[27])) {
        stas[row].wan_txB = strtoull(argv[27], NULL, 10);
    }

    /*WANRXB*/
    if (argv[28] && strlen(argv[28])) {
        stas[row].wan_rxB = strtoull(argv[28], NULL, 10);
    }

    /*GWADDR*/
    if (argv[29] && strlen(argv[29])) {
        stas[row].gwaddr = inet_addr(argv[29]);
    }

    /*MINRSSI*/
    if (argv[30] && strlen(argv[30])) {
        stas[row].min_rssi = atoi(argv[30]) - 95;
    }

    /*MAXRSSI*/
    if (argv[31] && strlen(argv[31])) {
        stas[row].max_rssi = atoi(argv[31]) - 95;
    }

    /*PORTAL_STATUS*/
    if (argv[32] && strlen(argv[32])) {
        stas[row].portal_status = atoi(argv[32]);
    } else {
        stas[row].portal_status = 1;
    }

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

    sqlite3_busy_timeout(db, 500);

    ret = sqlite3_exec(db, sql_count_str, _sql_callback, &count, &pErrMsg);
    if (ret != SQLITE_OK) {
        CWLog("SQL create error: %s, line:%d\n", pErrMsg, __LINE__);
        ret = -2;
        goto __cleanup;
    }

    all->count = count;
    if (count < 0) {
        ret = -2;
        goto __cleanup;
    }

    if (count > 0) {
        *(all->stas) = (struct wlan_sta_stat *)malloc(count * sizeof(struct wlan_sta_stat));
        if (*(all->stas) == NULL) {
            CWLog("SQL create error: malloc err\n");
            ret = -3;
            goto __cleanup;
        }
        memset(*(all->stas), 0, count * sizeof(struct wlan_sta_stat));

        ret = sqlite3_exec(db, sql_str, _sql_callback, all, &pErrMsg);
        if (ret != SQLITE_OK) {
            CWLog("SQL create error: %s, line:%d\n", pErrMsg, __LINE__);
            ret = -4;
            goto __cleanup;
        }
    }

    if (db) {
        sqlite3_close(db);
    }
    if (pErrMsg) {
        free(pErrMsg);
        pErrMsg = NULL;
    }
    return 0;

__cleanup:
    if (*(all->stas)) {
        free(*(all->stas));
        *(all->stas) = NULL;
    }
    all->count = -1;
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

    int ret = system("nice -n -20 /lib/okos/upstabycron.sh");
    if (ret == -1 || (ret != -1 && WEXITSTATUS(ret))) {
        CWLog("database is updating");
        *stas = NULL;
        return -1;
    }

    struct wlan_sta_stat_all all;
    all.count = 0;
    all.stas = stas;

    ret = wlan_get_sta_info_db((void*)&all);
    if (ret) {
        *stas = NULL;
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
        count  = -1;
        return count;
    }

    FILE *stream = NULL;
    int chutil = 0;
    int per = 0;
    int ret = 0;
    float tx_rate = 0;
    int noise_level = 0;

    strcpy(cur_stats[0].ifname, "wifi1");
    cur_stats[0].ifname_len = strlen(cur_stats[0].ifname);

    stream = popen("[ ! -f /tmp/restartservices.lock ] && apstats -r -i wifi1 | awk -F'[= ]+' '{if(match($1$2,\"ChannelUtilization\"))chutil=$4;if(match($1$2,\"TotalPER\"))per=$4;}END{print chutil\"_\"per}'", "r");
    ret = fscanf(stream, "%d_%d", &chutil, &per);
    cur_stats[0].chan_util=(unsigned char)(chutil*100/255);
    cur_stats[0].error_rate=(unsigned char)per;
    cur_stats[0].retry_rate = per/11;
    if (ret != 2) {
        cur_stats[0].chan_util = 0;
        cur_stats[0].error_rate = 0;
        cur_stats[0].retry_rate = 0;
    }
    pclose(stream);

    stream = popen("[ ! -f /tmp/restartservices.lock ] && iwconfig ath60 | awk -F'[: =]+' '{if(match($2$3,\"BitRate\"))bitrate=$4;if(match($2$3,\"LinkQuality\"))noise=$11;}END{print bitrate\"_\"noise}' ", "r");
    ret = fscanf(stream, "%f_%d", &tx_rate, &noise_level);
    cur_stats[0].tx_rate=(unsigned int)tx_rate;
    cur_stats[0].noise_level=noise_level;
    if ( ret != 2) {
        cur_stats[0].tx_rate = 0;
        cur_stats[0].noise_level = -97;
    }
    pclose(stream);

    cur_stats[0].rx_rate = cur_stats[0].tx_rate;



    strcpy(cur_stats[1].ifname, "wifi0");
    cur_stats[1].ifname_len = strlen(cur_stats[1].ifname);

    stream = popen("[ ! -f /tmp/restartservices.lock ] && apstats -r -i wifi0 | awk -F'[= ]+' '{if(match($1$2,\"ChannelUtilization\"))chutil=$4;if(match($1$2,\"TotalPER\"))per=$4;}END{print chutil\"_\"per}' ", "r");
    ret = fscanf(stream, "%d_%d", &chutil, &per);
    cur_stats[1].chan_util=(unsigned char)(chutil*100/255);
    cur_stats[1].error_rate=(unsigned char)per;
    cur_stats[1].retry_rate = per/11;
    if (ret != 2) {
        cur_stats[1].chan_util = 0;
        cur_stats[1].error_rate = 0;
        cur_stats[1].retry_rate = 0;
    }
    pclose(stream);

    stream = popen("[ ! -f /tmp/restartservices.lock ] && iwconfig ath50 | awk -F'[: =]+' '{if(match($2$3,\"BitRate\"))bitrate=$4;if(match($2$3,\"LinkQuality\"))noise=$11;}END{print bitrate\"_\"noise}' ", "r");
    ret = fscanf(stream, "%f_%d", &tx_rate, &noise_level);
    cur_stats[1].tx_rate=(unsigned int)tx_rate;
    cur_stats[1].noise_level=noise_level;
    if ( ret != 2) {
        cur_stats[1].tx_rate = 0;
        cur_stats[1].noise_level = -97;
    }
    pclose(stream);

    cur_stats[1].rx_rate = cur_stats[1].tx_rate;


    *stats = cur_stats;

    return count;
}
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
int dc_get_wlan_sta_stats(struct wlan_sta_stat **stas, int diff)
{
    pthread_mutex_lock(&stats_mutex);
#define UPTIME_DIFF   1 /* s */
    static struct wlan_sta_stat *pre_stas = NULL;
    static int pre_count = 0;
    struct wlan_sta_stat *cur_stas = NULL, *rse_stas = NULL, *cur, *pre;
    int i, j, cur_count = -1, res_count = 0, totalsize = 0;

    cur_count = wlan_get_sta_info(&cur_stas);
    CWLog("threadid:%d, cur_count:%d, pre_count=%d, cur_stas:%p, pre_stas:%p, diff=%d\n", pthread_self(), cur_count, pre_count, cur_stas, pre_stas, diff);
    if (cur_count < 0 && cur_stas == NULL) {
        pthread_mutex_unlock(&stats_mutex);
        return -1;
    }

    if (diff == 1) {
        for (i = 0; i < cur_count; i++) {
            cur = &(cur_stas[i]);
            if (!memcmp(cur->mac, "\x00\x00\x00\x00\x00\x00", sizeof(cur->mac)) || cur->ssid_len == 0) {
                CWLog("---->mac is warning:%lld,mac=%02x%02x%02x%02x,ssid_len=%d,cur->txB=%lld,cur->rxB=%lld", cur->ts, cur->mac[2], cur->mac[3], cur->mac[4], cur->mac[5], cur->ssid_len, cur->txB, cur->rxB);
            }
            for (j = 0; j < pre_count; j++) {
                pre = &(pre_stas[j]);
                if (!memcmp(cur->mac, pre->mac, sizeof(cur->mac))) {
                    /* Roaming from pre radio to cur radio or reassocation with same radio */
                    if (cur->radioid != pre->radioid || (cur->uptime != pre->uptime && cur->uptime < WLAN_STA_STAUS_TIMER)) { 
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
                            || strncmp(pre->user, cur->user, pre->name_len) != 0
                            || pre->psmode != cur->psmode) {
                            cur->updated = 1;
                            if (cur->ts <= pre->ts) {
                                cur->delta_txB = 0;
                                cur->delta_rxB = 0;
                                cur->delta_wan_txB = 0;
                                cur->delta_wan_rxB = 0;
                                cur->atxrb = pre->atxrb;
                                cur->arxrb = pre->arxrb;
                                cur->wan_atxrb = pre->wan_atxrb;
                                cur->wan_arxrb = pre->wan_arxrb;
                                //syslog(LOG_ERR, "mac is warning:O%x%x===>ts:%lld dtxB:%lld drxB:%lld txB:%lld rxB:%lld atx:%d arx:%d", pre->mac[4], pre->mac[5],  pre->ts, pre->delta_txB, pre->delta_rxB, pre->txB, pre->rxB, pre->atxrb, pre->arxrb);
                                //syslog(LOG_ERR, "mac is warning:N%x%x+++>%lld %lld %lld %lld %lld %d %d", cur->mac[4], cur->mac[5], cur->ts, cur->delta_txB, cur->delta_rxB, cur->txB, cur->rxB, cur->atxrb, cur->arxrb);
                            } else {
                                if (cur->txB > pre->txB && pre->txB != 0) {
                                    cur->delta_txB = cur->txB - pre->txB;
                                } else {
                                    cur->delta_txB = 0;
                                }
                                if (cur->rxB > pre->rxB && pre->rxB !=0) {
                                    cur->delta_rxB = cur->rxB - pre->rxB;
                                } else {
                                    cur->delta_rxB = 0;
                                }
                                if (cur->wan_txB > pre->wan_txB && pre->wan_txB !=0) {
                                    cur->delta_wan_txB = cur->wan_txB - pre->wan_txB;
                                } else {
                                    cur->delta_wan_txB = 0;
                                }
                                if(cur->wan_rxB > pre->wan_rxB && pre->wan_rxB !=0) {
                                    cur->delta_wan_rxB = cur->wan_rxB - pre->wan_rxB;
                                } else {
                                    cur->delta_wan_rxB = 0;
                                }
                                cur->atxrb = (unsigned int)(((long double)cur->delta_txB * 8) / (cur->ts - pre->ts) / 1024);
                                cur->arxrb = (unsigned int)(((long double)cur->delta_rxB * 8) / (cur->ts - pre->ts) / 1024);
                                cur->wan_atxrb = (unsigned int)(((long double)cur->delta_wan_txB * 8) / (cur->ts - pre->ts) / 1024);
                                cur->wan_arxrb = (unsigned int)(((long double)cur->delta_wan_rxB * 8) / (cur->ts - pre->ts) / 1024);
                            }
                                
                            //syslog(LOG_ERR, "O%x%x===>ts:%lld dtxB:%lld drxB:%lld txB:%lld rxB:%lld atx:%d arx:%d", pre->mac[4], pre->mac[5],  pre->ts, pre->delta_txB, pre->delta_rxB, pre->txB, pre->rxB, pre->atxrb, pre->arxrb);
                            //syslog(LOG_ERR, "N%x%x+++>%lld %lld %lld %lld %lld %d %d", cur->mac[4], cur->mac[5], cur->ts, cur->delta_txB, cur->delta_rxB, cur->txB, cur->rxB, cur->atxrb, cur->arxrb);
                            //syslog(LOG_ERR, "OW%x%x===>dwan_txB:%lld dwan_rxB:%lld wan_txB:%lld wan_rxB:%lld wan_atx:%d wan_arx:%d", pre->mac[4], pre->mac[5],  pre->delta_wan_txB, pre->delta_wan_rxB, pre->wan_txB, pre->wan_rxB, pre->wan_atxrb, pre->wan_arxrb);
                            //syslog(LOG_ERR, "NW%x%x+++>%lld %lld %lld %lld %d %d", cur->mac[4], cur->mac[5], cur->delta_wan_txB, cur->delta_wan_rxB, cur->wan_txB, cur->wan_rxB, cur->wan_atxrb, cur->wan_arxrb);
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

    pthread_mutex_unlock(&stats_mutex);
    *stas = rse_stas;
    
    return res_count;
}


static void dc_sta_notice_timer_handler(void *arg);
CW_THREAD_RETURN_TYPE dc_sta_notice_handler(void *arg) 
{
    time_t start, end;
    int cost;
    while(1) {
        time(&start);
        dc_sta_notice_timer_handler(NULL);
        time(&end);
        cost=(int)difftime(end,start);
        if (cost < WLAN_STA_STAUS_TIMER) {
            sleep(WLAN_STA_STAUS_TIMER-cost);
        } else {
            CWLog("xxxxxcost:%d", cost);
        }
    }
}
 
static void dc_sta_notice_timer_handler(void *arg) 
{
    struct wlan_sta_stat *stas = NULL;
    struct wlan_radio_stat *radio_stats = NULL;
    devctrl_block_s dc_resp = {0};
    char *payload = NULL, *data = NULL;
    int count = 0, paylength = 0, totalsize = 0; 

    CWDebugLog_F("-->sta notice handler In1:%d, cout:%d", clock(), count);
    count = dc_get_wlan_sta_stats(&stas,1);
    if (stas != NULL && count > 0) { 

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
                char * payload_tmp = NULL;
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
    }

    CWDebugLog_F("-->sta notice handler In2:%d, count:%d", clock(), count);
    /* radio status */
    count = dc_get_wlan_radio_stats(&radio_stats);
    if (radio_stats != NULL && count > 0) { 
        /* WLAN radio status notification */
        if (assemble_wlan_radio_status_elem(&data, &paylength, radio_stats, count) != CW_TRUE) {
            CWLog("Get wlan radio stats count %d but assmeble update msg failed.", count);
            goto RESTART_TIMER;
        }
        if (data != NULL && paylength > 0) {
            if (payload != NULL) {
                /* 2bytes type + 4bytes length */
                char * payload_tmp = NULL;
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
    }

    CWDebugLog_F("-->sta notice handler In3:%d, count:%d", clock(), count);

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

    CWDebugLog_F("-->sta notice handler In4:%d", clock());

RESTART_TIMER:
    if (payload) {
        CW_FREE_OBJECT(payload);
    }
    if (stas) {
        free(stas);
    }
    if (radio_stats) {
        free(radio_stats);
    }
    return;
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
