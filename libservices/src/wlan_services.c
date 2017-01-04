#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "services/cfg_services.h"
#include "services/wlan_services.h"

int if_get_radio_count (int *count)
{
    struct uci_context *ctx = NULL;
    struct uci_package *p = NULL;
    struct uci_element *e = NULL;
    int ret = 0;
    *count = 0;

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "no enough memory\n");
        return -1;
    }

    uci_load(ctx, WIFI_CFG_PACKAGE, &p);
    if(!p) {
        syslog(LOG_ERR, "no such package:%s\n", WIFI_CFG_PACKAGE);
        ret = -1;
        goto _free;
    }

    uci_foreach_element(&p->sections, e) {
        struct uci_section *s_cur = uci_to_section(e);
        if (!strcmp(s_cur->type, WIFI_CFG_SECTION_DEVICE)) {
            *count ++;
        }
    }

_free:
    if (ctx && p) {
        uci_unload(ctx, p);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
    return ret;
}

static int wlan_radio_list(struct uci_package *p, void *arg)
{
    struct uci_element *e1, *e2;
    struct uci_section *s;
    struct uci_option *o;
    int num= 0;
    int st_num, bss_num;
    int id = 0;
    
    wlan_radio_info *info = (wlan_radio_info *)arg;

    uci_foreach_element(&p->sections, e1) {
        s = uci_to_section(e1);
        if (sscanf(s->e.name, "WLAN_Radio%d", &id) != 1) {
            continue;
        }
        info->radioinfo[num].id = id;
        uci_foreach_element(&s->options, e2) {
            o = uci_to_option(e2);
            if (o->type == UCI_TYPE_STRING) {   
                if(!strcmp(o->e.name, "rssi_access"))
                {
                    if (!strcmp(o->v.string, "enabled"))
                        info->radioinfo[num].radio.rssi_access_enable = ENABLE;
                    else
                        info->radioinfo[num].radio.rssi_access_enable = DISABLE;
                    /* atf */
                }else if(!strcmp(o->e.name, "atf")) {
                    if (!strcmp(o->v.string, "enabled"))
                        info->radioinfo[num].radio.atf = ENABLE;
                    else
                        info->radioinfo[num].radio.atf = DISABLE;
                    /* atf - end*/
                }else if(!strcmp(o->e.name, "rssi_access_threshold")) {
                    info->radioinfo[num].radio.rssi_access_threshold = atoi(o->v.string);;
                }else if(!strcmp(o->e.name, "beacon_interval"))
                {
                    info->radioinfo[num].radio.beacon_interval = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "max_power"))
                {
                    if (strcmp(o->v.string, "auto"))
                        info->radioinfo[num].radio.max_power = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "dtim"))
                {
                    info->radioinfo[num].radio.dtim = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "fragment_threshold"))
                {
                    info->radioinfo[num].radio.fragment_threshold = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "rts_threshold"))
                {
                    info->radioinfo[num].radio.rts_threshold = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "a_mpdu"))  {
                    if (!strcmp(o->v.string, "enabled"))
                        info->radioinfo[num].radio.ampdu = ENABLE;
                    else
                        info->radioinfo[num].radio.ampdu = DISABLE;
                }else if (!strcmp(o->e.name, "short_gi"))  {
                    if (!strcmp(o->v.string, "enabled"))
                        info->radioinfo[num].radio.short_gi= ENABLE;
                    else
                        info->radioinfo[num].radio.short_gi= DISABLE;
                }else if (!strcmp(o->e.name, "device_mode")) {
                    if (!strcmp(o->v.string, "monitor"))
						info->radioinfo[num].radio.device_mode = RADIO_DEVICE_MODE_MONITOR;
					else
						info->radioinfo[num].radio.device_mode = RADIO_DEVICE_MODE_NORMAL;
                }else if (!strcmp(o->e.name, "mode"))  {
                    if (!strcmp(o->v.string, "11ac"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N | DOT11_RADIO_MODE_AC;
                    else if (!strcmp(o->v.string, "an"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N;
                    else if (!strcmp(o->v.string, "gn"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_G | DOT11_RADIO_MODE_N;
                    else if (!strcmp(o->v.string, "a"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_A;
                    else if (!strcmp(o->v.string, "g"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_G;
                    else if (!strcmp(o->v.string, "n"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_N;
                }else if(!strcmp(o->e.name, "channel"))
                {
                    if (strcmp(o->v.string, "auto"))
                        info->radioinfo[num].radio.channel = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "distance"))
                {
                    info->radioinfo[num].radio.distance= atoi(o->v.string);
                }else if(!strcmp(o->e.name, "bandwidth"))
                {
                    info->radioinfo[num].radio.bandwidth= atoi(o->v.string);
                }else if (!strcmp(o->e.name, "dot11nonly"))  {
                    if (!strcmp(o->v.string, "enabled"))
                        info->radioinfo[num].radio.dot11nonly= ENABLE;
                    else
                        info->radioinfo[num].radio.dot11nonly= DISABLE;
                }else if (!strcmp(o->e.name, "dot11aconly"))  {
                    if (!strcmp(o->v.string, "enabled"))
                        info->radioinfo[num].radio.dot11aconly= ENABLE;
                    else
                        info->radioinfo[num].radio.dot11aconly= DISABLE;
                }else if (!strcmp(o->e.name, "preamble"))  {
                    if (!strcmp(o->v.string, "short"))
                        info->radioinfo[num].radio.preamble= WLAN_PREAMBLE_SHORT;
                    else
                        info->radioinfo[num].radio.preamble = WLAN_PREAMBLE_LONG;
                }else if (!strcmp(o->e.name, "protection_mode"))  {
                    if (!strcmp(o->v.string, "cts-to-self"))
                        info->radioinfo[num].radio.protection_mode = WLAN_PROTECTION_CTS_TO_SELF;
                    else if (!strcmp(o->v.string, "none"))
                        info->radioinfo[num].radio.protection_mode = WLAN_PROTECTION_NONE;
                    else if (!strcmp(o->v.string, "rts-cts"))
                        info->radioinfo[num].radio.protection_mode = WLAN_PROTECTION_RTS_CTS;
                }else if (!strcmp(o->e.name, "bcast_ratelimit"))  {
                    if (!strcmp(o->v.string, "enabled")) {
                        info->radioinfo[num].radio.bcast_ratelimit_enable = 1;
                    }
                    else {
                        info->radioinfo[num].radio.bcast_ratelimit_enable = 0;
                    }
                }else if (!strcmp(o->e.name, "bcast_ratelimit_cir"))  {
                    info->radioinfo[num].radio.bcast_ratelimit_cir = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "bcast_ratelimit_cbs"))  {
                    info->radioinfo[num].radio.bcast_ratelimit_cbs = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "scan_tempate"))
                {
                    strncpy(info->radioinfo[num].radio.scan_template, o->v.string, sizeof(info->radioinfo[num].radio.scan_template) - 1);
                }else if(!strcmp(o->e.name,"enabled"))
                {
                    if(!strcmp(o->v.string, "enabled")) {
                        info->radioinfo[num].enable = ENABLE;
                    }
                    else {
                        info->radioinfo[num].enable = DISABLE;
                    }
                }
            }else
            {
                struct uci_element * e3;
                int count = 0;
                uci_foreach_element(&o->v.list, e3) {
                    if (!strcmp(o->e.name, "bind"))  {
                        sscanf(e3->name, "%d-%d", &bss_num, &st_num);
                        info->radioinfo[num].service[count] = st_num;
                        info->radioinfo[num].wlan_bss[count] = bss_num;
                        ++count;
                    }
                    
                }
                info->radioinfo[num].count = count;
            }
        }
        num++;
    }
    info->num = num;

    return 0;
}

int wlan_radio_get_all(struct wlan_radio_info *rdcfg)
{
    return cfg_visit_package(WLAN_CFG_RADIO_PACKAGE, wlan_radio_list, rdcfg);
}


int wlan_undo_service_template(int stid)
{
    //wlan_service_template.@ServiceTemplate0[0]=ServiceTemplate0
    char tuple[128];
    sprintf(tuple, "wlan_service_template.@ServiceTemplate%d[0]", stid);
    cfg_del_section(tuple);

    return 0;
}

static int wlan_service_template_list(struct uci_package *p, void *arg)
{
    struct uci_element *e1, *e2;
    struct uci_section *s;
    struct uci_option *o;
    int num= 0;
    int id;
    
    service_template *stinfo = (service_template *)arg;

    uci_foreach_element(&p->sections, e1) {
        s = uci_to_section(e1);
        sscanf(s->e.name, "ServiceTemplate%d", &id);
        stinfo->wlan_st_info[num].id = id;
        uci_foreach_element(&s->options, e2) {
            o = uci_to_option(e2);
            if (o->type == UCI_TYPE_STRING) {   
                if (!strcmp(o->e.name, "service_template"))  {
                    if (!strcmp(o->v.string, "enabled"))
                        stinfo->wlan_st_info[num].enabled= ENABLE;
                    else
                        stinfo->wlan_st_info[num].enabled = DISABLE;
                }else if(!strcmp(o->e.name, "cipher"))
                {
                    if (!strcmp(o->v.string, "ccmp"))
                        stinfo->wlan_st_info[num].cipher = WLAN_CIPHER_CCMP;
                    else if(!strcmp(o->v.string, "ccmp-tkip"))
                        stinfo->wlan_st_info[num].cipher = WLAN_CIPHER_CCMP_TKIP;
                    else if(!strcmp(o->v.string, "tkip"))
                        stinfo->wlan_st_info[num].cipher = WLAN_CIPHER_TKIP;
                    else if(!strcmp(o->v.string, "wep108"))
                        stinfo->wlan_st_info[num].cipher = WLAN_CIPHER_WEP108;
                    else if(!strcmp(o->v.string, "wep40"))
                        stinfo->wlan_st_info[num].cipher = WLAN_CIPHER_WEP40;
                }else if (!strcmp(o->e.name, "radius_scheme"))
                {
                    strncpy(stinfo->wlan_st_info[num].radius_scheme, 
                            o->v.string, sizeof(stinfo->wlan_st_info[num].radius_scheme) - 1);
                }else if (!strcmp(o->e.name, "acl"))
                {
                    strncpy(stinfo->wlan_st_info[num].acl, 
                            o->v.string, sizeof(stinfo->wlan_st_info[num].acl) - 1);
                }else if (!strcmp(o->e.name,"portal_scheme")){
                    strncpy(stinfo->wlan_st_info[num].portal_scheme, 
                            o->v.string, sizeof(stinfo->wlan_st_info[num].portal_scheme) - 1);
                }else if (!strcmp(o->e.name,"ssid_time_range")){
                    strncpy(stinfo->wlan_st_info[num].timer_scheme, 
                            o->v.string, sizeof(stinfo->wlan_st_info[num].timer_scheme) - 1);
                }else if(!strcmp(o->e.name, "beacon_ssid_hide"))
                {
                    if (!strcmp(o->v.string, "enabled"))
                        stinfo->wlan_st_info[num].beacon_ssid_hide = ENABLE;
                    else
                        stinfo->wlan_st_info[num].beacon_ssid_hide = DISABLE;
                }else if(!strcmp(o->e.name, "client_max"))
                {
                    stinfo->wlan_st_info[num].client_max = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "authentication"))
                {
                    if (!strcmp(o->v.string, "open"))
                        stinfo->wlan_st_info[num].auth = WLAN_AUTH_OPEN;
                    else if(!strcmp(o->v.string, "shared"))
                        stinfo->wlan_st_info[num].auth = WLAN_AUTH_SHARED;
                    else if(!strcmp(o->v.string, "wpa-auto-psk"))
                        stinfo->wlan_st_info[num].auth = WLAN_AUTH_WPA_MIXED_PSK;
                    else if(!strcmp(o->v.string, "wpa-psk"))
                        stinfo->wlan_st_info[num].auth = WLAN_AUTH_WPA_PSK;
                    else if(!strcmp(o->v.string, "wpa2-psk"))
                        stinfo->wlan_st_info[num].auth = WLAN_AUTH_WPA2_PSK;
                    else if(!strcmp(o->v.string, "wpa2-radius"))
                        stinfo->wlan_st_info[num].auth = WLAN_AUTH_WPA2_RADIUS;
                }else if(!strcmp(o->e.name, "ptk_lifetime"))
                {
                    stinfo->wlan_st_info[num].ptk_lifetime = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "gtk_lifetime"))
                {
                    stinfo->wlan_st_info[num].gtk_lifetime = atoi(o->v.string);
                }else if(!strcmp(o->e.name, "ptk_enabled"))
                {
                    if (!strcmp(o->v.string, "enabled"))
                        stinfo->wlan_st_info[num].ptk_enabled = ENABLE;
                    else if (!strcmp(o->v.string, "disabled"))
                        stinfo->wlan_st_info[num].ptk_enabled = DISABLE;
                }else if (!strcmp(o->e.name, "gtk_enabled"))  {
                    if (!strcmp(o->v.string, "enabled"))
                        stinfo->wlan_st_info[num].gtk_enabled = ENABLE;
                    else if (!strcmp(o->v.string, "disabled"))
                        stinfo->wlan_st_info[num].gtk_enabled = DISABLE;
                }else if (!strcmp(o->e.name, "wep_key_slot"))  { 
                    stinfo->wlan_st_info[num].wep_key_slot = atoi(o->v.string);
                }else if (!strcmp(o->e.name, "psk_key_type"))  {
                    if (!strcmp(o->v.string, "passphrase"))
                        stinfo->wlan_st_info[num].wpa_key.key_type = WLAN_KEY_TYPE_ASCII;
                    else 
                        stinfo->wlan_st_info[num].wpa_key.key_type = WLAN_KEY_TYPE_HEX;
                }else if (!strcmp(o->e.name, "psk_key_crypt"))  {
                    if (!strcmp(o->v.string, "plain"))
                        stinfo->wlan_st_info[num].wpa_key.key_crypt = WLAN_KEY_CRYPT_PLAIN;
                    else 
                        stinfo->wlan_st_info[num].wpa_key.key_crypt = WLAN_KEY_CRYPT_CIPHER;
                }else if (!strcmp(o->e.name, "wep40_key_type_1"))  {
                    if (!strcmp(o->v.string, "passphrase"))
                        stinfo->wlan_st_info[num].wep40_key[0].key_type = WLAN_KEY_TYPE_ASCII;
                    else 
                        stinfo->wlan_st_info[num].wep40_key[0].key_type = WLAN_KEY_TYPE_HEX;
                }else if (!strcmp(o->e.name, "wep40_key_crypt_1"))  {
                    if (!strcmp(o->v.string, "plain"))
                        stinfo->wlan_st_info[num].wep40_key[0].key_crypt = WLAN_KEY_CRYPT_PLAIN;
                    else 
                        stinfo->wlan_st_info[num].wep40_key[0].key_crypt = WLAN_KEY_CRYPT_CIPHER;
                }else if (!strcmp(o->e.name, "wep108_key_type_1"))  {
                    if (!strcmp(o->v.string, "passphrase"))
                        stinfo->wlan_st_info[num].wep108_key[0].key_type = WLAN_KEY_TYPE_ASCII;
                    else 
                        stinfo->wlan_st_info[num].wep108_key[0].key_type = WLAN_KEY_TYPE_HEX;
                }else if (!strcmp(o->e.name, "wep108_key_crypt_1"))  {
                    if (!strcmp(o->v.string, "plain"))
                        stinfo->wlan_st_info[num].wep108_key[0].key_crypt = WLAN_KEY_CRYPT_PLAIN;
                    else 
                        stinfo->wlan_st_info[num].wep108_key[0].key_crypt = WLAN_KEY_CRYPT_CIPHER;
                }else if(!strcmp(o->e.name, "ssid"))
                {
                    strncpy(stinfo->wlan_st_info[num].ssid, o->v.string, sizeof(stinfo->wlan_st_info[num].ssid)-1);
                }else if(!strcmp(o->e.name, "wep40_key_1"))
                {
                    strncpy(stinfo->wlan_st_info[num].wep40_key[0].key, o->v.string, sizeof(stinfo->wlan_st_info[num].wep40_key[0].key)-1);
                }else if(!strcmp(o->e.name, "wep108_key_1"))
                {
                    strncpy(stinfo->wlan_st_info[num].wep108_key[0].key, o->v.string, sizeof(stinfo->wlan_st_info[num].wep108_key[0].key)-1);
                }else if(!strcmp(o->e.name, "psk_key"))
                {
                    strncpy(stinfo->wlan_st_info[num].wpa_key.key, o->v.string, sizeof(stinfo->wlan_st_info[num].wpa_key.key)-1);
                }else if(!strcmp(o->e.name, "dynamic_uplink_ratelimit"))
                {
                    stinfo->wlan_st_info[num].dynamic_uplink_rate_limit= atoi(o->v.string);
                }else if(!strcmp(o->e.name, "dynamic_downlink_ratelimit"))
                {
                    stinfo->wlan_st_info[num].dynamic_downlink_rate_limit= atoi(o->v.string);
                }else if(!strcmp(o->e.name, "static_uplink_ratelimit"))
                {
                    stinfo->wlan_st_info[num].static_uplink_rate_limit= atoi(o->v.string);
                }else if(!strcmp(o->e.name, "static_downlink_ratelimit"))
                {
                    stinfo->wlan_st_info[num].static_downlink_rate_limit= atoi(o->v.string);
                } else if(!strcmp(o->e.name, "m2u_enable"))
				{
                    if (!strcmp(o->v.string, "enabled"))
						stinfo->wlan_st_info[num].m2u_enabled = 1;
					else
						stinfo->wlan_st_info[num].m2u_enabled = 0;
				}
                else if(!strcmp(o->e.name, "pmf"))
                {
                    if (!strcmp(o->v.string, "mandatory"))
                        stinfo->wlan_st_info[num].pmf = 2;
                    else if (!strcmp(o->v.string, "optional"))
                        stinfo->wlan_st_info[num].pmf = 1;
                }
                else if(!strcmp(o->e.name, "manage_template"))
                {
                    stinfo->wlan_st_info[num].manage_template = 1;
                }
                else if (strcmp(o->e.name, "manage_ip") == 0) {
                    struct in_addr ip;
                    inet_pton(AF_INET, o->v.string, &ip);
                    stinfo->wlan_st_info[num].manage_ip = ip.s_addr;
                }
                else if (strcmp(o->e.name, "manage_mask") == 0) {
                    stinfo->wlan_st_info[num].manage_mask = atoi(o->v.string);
                }
            }
        }
        num++;
    }
    stinfo->num = num;

    return 0;
}

int wlan_service_template_get_all(struct service_template *stcfg)
{
    return cfg_visit_package(WLAN_CFG_SERVICE_TEMPLATE_PACKAGE, wlan_service_template_list, stcfg);
}

int wlan_set_service_template_enable(int stid, int enable)
{
    return 0;
}


int wlan_set_auth(int stid, int auth)
{
    return 0;
}

int wlan_set_country(const char *country)
{
    cfg_set_option_value(WIFI_CFG_RADIO0_OPTION_COUNTRY_TUPLE, country);
    cfg_set_option_value(WIFI_CFG_RADIO1_OPTION_COUNTRY_TUPLE, country);
    return 0;
}

int wlan_undo_country(void)
{
    cfg_set_option_value(WIFI_CFG_RADIO0_OPTION_COUNTRY_TUPLE, WIFI_COUNTRY_DEFAULT);
    cfg_set_option_value(WIFI_CFG_RADIO1_OPTION_COUNTRY_TUPLE, WIFI_COUNTRY_DEFAULT);
    return 0;
}

int wlan_get_country(char *country)
{
    cfg_get_option_value(WIFI_CFG_RADIO0_OPTION_COUNTRY_TUPLE, country, 128);
    return 0;
}

int wlan_undo_bind(int radio, int stid)
{
    //wlan_radio.WLAN_Radio1.bind='0-1'
    char tuple[128];
    sprintf(tuple, "wlan_radio.@WLAN_Radio%d[0].bind='0-%d'", radio, stid);
    cfg_del_option_list_value(tuple);

    /*TODO*/

    return 0;
}

