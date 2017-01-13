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
                    else if (!strcmp(o->v.string, "na"))
                        info->radioinfo[num].radio.mode = DOT11_RADIO_MODE_A | DOT11_RADIO_MODE_N;
                    else if (!strcmp(o->v.string, "ng"))
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
                        int stid;
                        sscanf(e3->name, "ServiceTemplate%d", &stid);
                        info->radioinfo[num].service[count] = stid;
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
    //wlan_service_template.ServiceTemplate0=ServiceTemplate0
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d", stid);
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
    //wlan_service_template.ServiceTemplate1.service_template='enabled'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.service_template", stid);
    cfg_set_option_value(tuple, enable?"enabled":"disabled");
    return 0;
}

const static char *auth_str[] = {
    "open", "shared", "wpa-psk", "wpa2-psk", "wpa2-radius", 
    "wpa-auto-psk"
};

const static char *wlan_convert_auth(int auth)
{
    return auth_str[auth];
}

int wlan_set_auth(int stid, int auth)
{
    //wlan_service_template.ServiceTemplate1.authentication='open'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.authentication", stid);
    cfg_set_option_value(tuple, wlan_convert_auth(auth));
    return 0;
}

int wlan_set_country(const char *country)
{
    if (!strcmp(country, "CN")) {
        //wireless.wifi0.country
        cfg_set_option_value("wireless.wifi0.country", "156");
        cfg_set_option_value("wireless.wifi1.country", "156");
    } else if (!strcmp(country, "US")) {
        //wireless.wifi0.country
        cfg_set_option_value("wireless.wifi0.country", "840");
        cfg_set_option_value("wireless.wifi1.country", "840");
    }

    return 0;
}

int wlan_undo_country(void)
{
    //wlan_radio.country.country='CN'
    cfg_set_option_value("wireless.wifi0.country", "156");
    cfg_set_option_value("wireless.wifi1.country", "156");
    return 0;
}

int wlan_get_country(char *country)
{
    //wlan_radio.country.country='CN'
    char country_code[4];
    
    if (0 == cfg_get_option_value("wlan_radio.country.country", 
        country_code, sizeof(country_code))) {
        country_code[sizeof(country_code) - 1] = 0;
        strcpy(country, country_code);
    }
    else {
        strcpy(country, WLAN_DEFAULT_COUNTRY_CODE);
    }
 
    return 0;
}

int wlan_undo_bind(int radio, int stid)
{
    //wireless.ath02.ifname='ath02'
    char tuple[128];
    sprintf(tuple, "wireless.ath%d%d", radio, stid);
    /* del ssid conf on specified radio in openwrt wireless conf file */
    cfg_del_section(tuple);


    //wlan_radio.WLAN_Radio1.bind='ServiceTemplate1'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.bind=ServiceTemplate%d", radio, stid);
    cfg_del_option_list_value(tuple);

    return 0;
}

int wlan_undo_service_template_enable(int stid)
{
    char tuple[128];
    //wlan_service_template.ServiceTemplate0.service_template='enabled'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.service_template", stid);
    cfg_set_option_value(tuple, "disabled");
    return 0;
}

static int get_service_id(struct uci_package *p, void *arg) {
    struct uci_element *e1;
    struct uci_section *s;
    int id = 0;
    
    char *info = (char *)arg;

    uci_foreach_element(&p->sections, e1) {
        s = uci_to_section(e1);
        sscanf(s->e.name, "ServiceTemplate%d", &id);
        *(info + id) = 1;
    }

    return 0;
}

int wlan_get_valid_stid(void) 
{
    char service_arry[ST_MAX_COUNT];
    int i, id = -1;
    
    memset(service_arry, 0, sizeof(service_arry));
    cfg_visit_package(WLAN_CFG_SERVICE_TEMPLATE_PACKAGE, get_service_id, service_arry);
    for ( i = 0; i < ST_MAX_COUNT; i++ ) { 
        if ( 0 == service_arry[i] ) {
            id = i;
            break;
        }
    }

    return id;
}

int wlan_create_service_template(int stid)
{
    /*
    init default setting
    st->client_max = 127;
    st->beacon_ssid_hide = 0;
    st->auth = WLAN_AUTH_OPEN;
    st->cipher = WLAN_CIPHER_NONE;
    st->wep_key_slot = 1;
    st->ptk_lifetime = 3600;
    st->gtk_lifetime = 86400;
    st->gtk_enabled = 0;
    st->ptk_enabled = 0;
    st->m2u_enabled = 0;
    st->opmode = WLAN_OPMODE_AP; 
    st->wpa_key.key_type = WLAN_KEY_TYPE_ASCII;
    st->wpa_key.key_crypt = WLAN_KEY_CRYPT_PLAIN;
    for (i = 0; i < 4; ++i) {
        st->wep40_key[i].key_type = WLAN_KEY_TYPE_ASCII;
        st->wep40_key[i].key_crypt = WLAN_KEY_CRYPT_PLAIN;
        st->wep40_key[i].key[0] = 0;
        st->wep40_key[i].key_len = 0;

        st->wep108_key[i].key_type = WLAN_KEY_TYPE_ASCII;
        st->wep108_key[i].key_crypt = WLAN_KEY_CRYPT_PLAIN;
        st->wep108_key[i].key[0] = 0;
        st->wep108_key[i].key_len = 0;
    }
    */

    int i = 0;

    //wlan_service_template.ServiceTemplate1=ServiceTemplate1
    char tuple[128];
    sprintf(tuple, "ServiceTemplate%d", stid);
    cfg_add_section(WLAN_CFG_SERVICE_TEMPLATE_PACKAGE, tuple);

    /* init default values */
    //wlan_service_template.ServiceTemplate0.service_template='enabled'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.service_template", stid);
    cfg_set_option_value(tuple, "disabled");

    //wlan_service_template.ServiceTemplate0.cipher='ccmp'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.cipher", stid);
    cfg_set_option_value(tuple, "none");

    //wlan_service_template.ServiceTemplate0.beacon_ssid_hide='disabled'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.beacon_ssid_hide", stid);
    cfg_set_option_value(tuple, "disabled");

    //wlan_service_template.ServiceTemplate0.client_max='127'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.client_max", stid);
    cfg_set_option_value(tuple, "127");

    //wlan_service_template.ServiceTemplate0.authentication='open'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.authentication", stid);
    cfg_set_option_value(tuple, "open");


    //wlan_service_template.ServiceTemplate0.ptk_lifttime='3600'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ptk_lifttime", stid);
    cfg_set_option_value(tuple, "3600");

    //wlan_service_template.ServiceTemplate0.gtk_lifttime='86400'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.gtk_lifttime", stid);
    cfg_set_option_value(tuple, "86400");


    //wlan_service_template.ServiceTemplate1.ptk_enabled='enabled'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ptk_enabled", stid);
    cfg_set_option_value(tuple, "disabled");

    //wlan_service_template.ServiceTemplate1.gtk_enabled='enabled'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ptk_enabled", stid);
    cfg_set_option_value(tuple, "disabled");

    //wlan_service_template.ServiceTemplate1.wep_key_slot='1'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep_key_slot", stid);
    cfg_set_option_value(tuple, "1");

    //wlan_service_template.ServiceTemplate1.psk_key='string'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.psk_key", stid);
    cfg_set_option_value(tuple,""); 

    //wlan_service_template.ServiceTemplate1.psk_key_type='passphrase'
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.psk_key_type", stid);
    cfg_set_option_value(tuple, "passphrase");

    //wlan_service_template.ServiceTemplate1.psk_key_crypt='plain'
    sprintf(tuple, "wlan_service_template.ServiceTemplate1.psk_key_crypt", stid);
    cfg_set_option_value(tuple, "plain");

    for (i = 0; i < 4; ++i) {
        //wlan_service_template.ServiceTemplate1.wep40_key_type_1='passphrase'
        sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep40_key_type_%d", stid, i + 1);
        cfg_set_option_value(tuple, "passphrase");

        //wlan_service_template.ServiceTemplate1.wep40_key_crypt_1=' '
        sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep40_key_crypt_%d", stid, i + 1);
        cfg_set_option_value(tuple, "plain");

        //wlan_service_template.ServiceTemplate1.wep40_key_1='string'
        sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep40_key_%d", stid, i + 1);
        cfg_set_option_value(tuple, "");

        //wlan_service_template.ServiceTemplate1.wep108_key_type_1=' '
        sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep108_key_type_%d", stid, i + 1);
        cfg_set_option_value(tuple, "passphrase");

        //wlan_service_template.ServiceTemplate1.wep108_key_crypt_1=' '
        sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep108_key_crypt_%d", stid, i + 1);
        cfg_set_option_value(tuple, "plain");

        //wlan_service_template.ServiceTemplate1.wep108_key_1='string'
        sprintf(tuple, "wlan_service_template.ServiceTemplate%d.wep108_key_%d", stid, i + 1);
        cfg_set_option_value(tuple, "");
    }

    return 0;
}

int wlan_set_ssid(int stid, const char *ssid)
{
    //wlan_service_template.ServiceTemplate1.ssid='name'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ssid", stid);
    cfg_set_option_value(tuple, ssid);
    return 0;
}

int wlan_set_beacon_ssid_hide(int stid, int value)
{
    //wlan_service_template.ServiceTemplate1.beacon_ssid_hide='disabled'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.beacon_ssid_hide", stid);
    if (value) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }

    return 0;
}

int wlan_set_client_max(int stid, int value)
{
    //wlan_service_template.ServiceTemplate1.client_max='127'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.client_max", stid);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

const static char * cipher_str[] = {
    "none", "wep40", "wep108", "tkip", "ccmp", "ccmp-tkip"
};

const char * wlan_convert_cipher(int cipher)
{
    return cipher_str[cipher];
}

int wlan_set_cipher(int stid, int cipher)
{
    //wlan_service_template.ServiceTemplate1.cipher='ccmp'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.cipher", stid);
    cfg_set_option_value(tuple, wlan_convert_cipher(cipher));
    return 0;
}

const static char * type_str[] = {
    "passphrase", "hex"
};

const char * wlan_convert_key_type(int type)
{
    return type_str[type];
}



int wlan_set_wep40_key(int stid, int slot, int type, int crypt, const char * key)
{
    return 0;
}


int wlan_set_wep108_key(int stid, int slot, int type, int crypt, const char * key)
{
    return 0;
}


int wlan_set_psk(int stid, 
        const char * password, int crypt, int type)
{
    return 0;
}

int wlan_set_ptk_lifetime(int stid, int value)
{
    //wlan_service_template.ServiceTemplate1.ptk_lifttime='3600'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ptk_lifttime", stid);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

int wlan_set_ptk_lifetime_enable(int stid, int value)
{
    //wlan_service_template.ServiceTemplate1.ptk_enabled='enabled'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ptk_enabled", stid);
    if (value){
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }

    return 0;
}

int wlan_set_gtk_lifetime(int stid, int value)
{
    //wlan_service_template.ServiceTemplate1.gtk_lifttime='86400
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.gtk_lifttime", stid);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

int wlan_set_gtk_lifetime_enable(int stid, int value)
{
    //wlan_service_template.ServiceTemplate0.gtk_enabled='enabled'
    char tuple[128];
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.gtk_enabled", stid);
    if (value) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }
    return 0;
}






int wlan_set_radio_enable(int radio_id, int enable)
{
    char tuple[128];
    //wireless.wifi1.disabled='1'
    sprintf(tuple, "wireless.wifi%d.disabled", radio_id);
    cfg_set_option_value_int(tuple, enable?0:1);

    //wlan_radio.WLAN_Radio1.enabled='enabled'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.enabled", radio_id);
    if (enable) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }

    return 0;
}

char * wlan_mode_to_str(int mode)
{
    static char mode_str[8];
    int i = 0;

    if (mode & DOT11_RADIO_MODE_AC) {
        strcpy(mode_str, "11ac");
        return mode_str;
    }

    if (mode & DOT11_RADIO_MODE_N) {
        mode_str[i] = 'n';
        ++i;
    }
    if (mode & DOT11_RADIO_MODE_A) {
        mode_str[i] = 'a';
        ++i;
    }
    if (mode & DOT11_RADIO_MODE_B) {
        mode_str[i] = 'b';
        ++i;
    }
    if (mode & DOT11_RADIO_MODE_G) {
        mode_str[i] = 'g';
        ++i;
    }
    mode_str[i] = 0;

    return mode_str;
}

int wlan_set_mode(int radio_id, int mode)
{
    char tuple[128];
    //wireless.wifi0.hwmode
    sprintf(tuple, "wireless.wifi%d.hwmode", radio_id);
    cfg_set_option_value(tuple, wlan_mode_to_str(mode));

    //wlan_radio.WLAN_Radio1.mode='ng'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.mode", radio_id);
    cfg_set_option_value(tuple, wlan_mode_to_str(mode));

    /* reset parameters */
    if ((mode & DOT11_RADIO_MODE_AC) != 0) {
        /*
        radio->config.short_gi = 1;
        radio->config.bandwidth = 20;
        radio->config.dot11nonly = 0;
        radio->config.dot11aconly = 0;
        radio->config.ampdu = 1;
        */

        //wireless.wifi0.AMDPU
        sprintf(tuple, "wireless.wifi%d.AMPDU", radio_id);
        cfg_set_option_value_int(tuple, 1);
        //wlan_radio.WLAN_Radio1.a_mpdu='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.a_mpdu", radio_id);
        cfg_set_option_value(tuple, "enabled");

        //wireless.ath01.shortgi
        //wlan_radio.WLAN_Radio1.short_gi='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.short_gi", radio_id);
        cfg_set_option_value(tuple, "enabled");

        //wireless.wifi0.htmode
        sprintf(tuple, "wireless.wifi%d.htmode", radio_id);
        cfg_set_option_value(tuple, "HT20");
        //wlan_radio.WLAN_Radio1.bandwidth='20'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.bandwidth", radio_id);
        cfg_set_option_value(tuple, "20");

        //wlan_radio.WLAN_Radio1.dot11only='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11only", radio_id);
        cfg_set_option_value(tuple, "disabled");

        //wlan_radio.WLAN_Radio1.dot11aconly='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11aconly", radio_id);
        cfg_set_option_value(tuple, "disabled");

    }
    else if ((mode & DOT11_RADIO_MODE_N) == 0) {
        /*
        radio->config.short_gi = 0;
        radio->config.bandwidth = 20;
        radio->config.dot11nonly = 0;
        radio->config.dot11aconly = 0;
        radio->config.ampdu = 0;
        */

        //wireless.wifi0.AMDPU
        sprintf(tuple, "wireless.wifi%d.AMPDU", radio_id);
        cfg_set_option_value_int(tuple, 0);
        //wlan_radio.WLAN_Radio1.a_mpdu='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.a_mpdu", radio_id);
        cfg_set_option_value(tuple, "disabled");

        //wlan_radio.WLAN_Radio1.short_gi='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.short_gi", radio_id);
        cfg_set_option_value(tuple, "disabled");

        //wireless.wifi0.htmode
        sprintf(tuple, "wireless.wifi%d.htmode", radio_id);
        cfg_set_option_value(tuple, "HT20");
        //wlan_radio.WLAN_Radio1.bandwidth='20'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.bandwidth", radio_id);
        cfg_set_option_value(tuple, "20");

        //wlan_radio.WLAN_Radio1.dot11only='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11only", radio_id);
        cfg_set_option_value(tuple, "disabled");

        //wlan_radio.WLAN_Radio1.dot11aconly='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11aconly", radio_id);
        cfg_set_option_value(tuple, "disabled");

    }
    else if ((mode & DOT11_RADIO_MODE_N) != 0) {
        /*
        radio->config.short_gi = 1;
        radio->config.bandwidth = 20;
        radio->config.dot11nonly = 0;
        radio->config.dot11aconly = 0;
        radio->config.ampdu = 1;
        */
        
        //wireless.wifi0.AMDPU
        sprintf(tuple, "wireless.wifi%d.AMPDU", radio_id);
        cfg_set_option_value_int(tuple, 1);
        //wlan_radio.WLAN_Radio1.a_mpdu='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.a_mpdu", radio_id);
        cfg_set_option_value(tuple, "enabled");

        //wlan_radio.WLAN_Radio1.short_gi='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.short_gi", radio_id);
        cfg_set_option_value(tuple, "enabled");

        //wireless.wifi0.htmode
        sprintf(tuple, "wireless.wifi%d.htmode", radio_id);
        cfg_set_option_value(tuple, "HT20");
        //wlan_radio.WLAN_Radio1.bandwidth='20'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.bandwidth", radio_id);
        cfg_set_option_value(tuple, "20");

        //wlan_radio.WLAN_Radio1.dot11only='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11only", radio_id);
        cfg_set_option_value(tuple, "disabled");

        //wlan_radio.WLAN_Radio1.dot11aconly='enabled'
        sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11aconly", radio_id);
        cfg_set_option_value(tuple, "disabled");

    }
    else {
        syslog(LOG_DEBUG, "Add code to support default setting under mode 0x%x\n", mode);
    }

    syslog(LOG_INFO, "Set radio %d with mode %s\n", radio_id, wlan_mode_to_str(mode));
    return 0;
}

int wlan_set_channel(int radio_id, int value)
{
    char tuple[128];
    //wireless.wifi0.channel
    sprintf(tuple, "wireless.wifi%d.channel", radio_id);
    cfg_set_option_value_int(tuple, value);

    //wlan_radio.WLAN_Radio1.channel='20'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.channel", radio_id);
    char value_str[33] = "auto";
    if (value) {
        sprintf(value_str, "%d", value);
    }
    cfg_set_option_value(tuple,value_str);
    return 0;
}


int wlan_set_max_power(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio1.max_power='20'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.max_power", radio_id);
    if (value) {
        cfg_set_option_value_int(tuple, value);
    } else {
        cfg_set_option_value(tuple, "auto");
    }

    return 0;
}

int wlan_set_dtim(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio1.dtim='20'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.dtim", radio_id);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

int wlan_set_frag_threshold(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio1.fragment_threshold='20'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.fragment_threshold", radio_id);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

int wlan_set_rts_threshold(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio1.rts_threshold='20'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.rts_threshold", radio_id);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

int wlan_set_short_gi(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio0.short_gi='enabled'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.short_gi", radio_id);
    if (value) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }
    return 0;
}

int wlan_set_ampdu(int radio_id, int enable)
{
    char tuple[128];
    //wireless.wifi0.AMPDU
    sprintf(tuple, "wireless.wifi%d.AMPDU", radio_id);
    cfg_set_option_value_int(tuple, enable);

    //wlan_radio.WLAN_Radio0.a_mpdu='enabled'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.a_mpdu", radio_id);
    if (enable) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }
    return 0;
}

int wlan_set_dot11nonly(int radio_id, int dot11nonly)
{
    //wlan_radio.WLAN_Radio1.dot11nonly='disabled'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11only", radio_id);
    if (dot11nonly) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }

    return 0;
}

int wlan_set_dot11aconly(int radio_id, int dot11aconly)
{
    //wlan_radio.WLAN_Radio1.dot11aconly='disabled'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.dot11aconly", radio_id);
    if (dot11aconly) {
        cfg_set_option_value(tuple, "enabled");
    } else {
        cfg_set_option_value(tuple, "disabled");
    }
    return 0;
}

int wlan_set_bandwidth(int radio_id, int bandwidth)
{
    char tuple[128];
    char buf[33];
    //wireless.wifi0.htmode='HT20'
    sprintf(tuple, "wireless.wifi%d.htmode", radio_id);
    sprintf(buf, "HT%d", bandwidth);
    cfg_set_option_value(tuple, buf);

    //wlan_radio.WLAN_Radio0.bandwidth='20'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.bandwidth", radio_id);
    cfg_set_option_value_int(tuple, bandwidth);

    return 0;
}

int wlan_set_distance(int radio_id, int value)
{
    char tuple[128];
    //wireless.wifi0.distance
    sprintf(tuple, "wireless.wifi%d.distance", radio_id);
    cfg_set_option_value_int(tuple, value);

    //wlan_radio.WLAN_Radio0.distance='20'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.distance", radio_id);
    cfg_set_option_value_int(tuple, value);
    return 0;
}

const char * wlan_convert_preamble(int value)
{
    const static char * preamble_str[] = {
        "short", "long"
    };

    return preamble_str[value];
}


int wlan_set_preamble(int radio_id, int preamble)
{
    //wlan_radio.WLAN_Radio0.preamble='short'
    char tuple[128];
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.preamble", radio_id);
    cfg_set_option_value(tuple, wlan_convert_preamble(preamble));
    return 0;
}

int wlan_set_protection_mode(int radio_id, int mode)
{
    //wlan_radio.WLAN_Radio0.protection_mode='none'
    return 0;
}

int wlan_set_beacon_interval(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio0.beacon_interval='20'
    return 0;
}

int wlan_set_rssi_threshold(int radio_id, int value)
{
    //wlan_radio.WLAN_Radio0.rssi_access_threshold='20'
    return 0;
}

int wlan_set_rssi(int radio_id, int enable)
{
    //wlan_radio.WLAN_Radio0.rssi_access='enable'
    return 0;
}

int wlan_set_bcast_ratelimit_enable(int radio_id, int value)
{
    return 0;
}

int wlan_set_bcast_ratelimit_param(int radio_id, int cir, int cbs)
{
    return 0;
}

int wlan_set_atf(int radio_id, int enable)
{
    return 0;
}

int wlan_set_bind(int radio_id, int stid)
{
    char tuple[128];
    char buf[33];
    //wireless.ath15=wifi-iface
    sprintf(buf, "ath%d%d", radio_id, stid);
    cfg_add_section_with_name_type("wireless", buf, "wifi-iface");

    //wireless.ath15.network='lan'
    sprintf(tuple, "wireless.ath%d%d.network", radio_id, stid);
    cfg_set_option_value(tuple, "lan1");

    //wireless.ath15.device='wifi1'
    sprintf(tuple, "wireless.ath%d%d.device", radio_id, stid);
    sprintf(buf, "wifi%d", radio_id);
    cfg_set_option_value(tuple, buf);

    //wireless.ath15.ifname='ath15'
    sprintf(tuple, "wireless.ath%d%d.ifname", radio_id, stid);
    sprintf(buf, "ath%d%d", radio_id, stid);
    cfg_set_option_value(tuple, buf);

    //wireless.ath15.mode='ap'
    sprintf(tuple, "wireless.ath%d%d.mode", radio_id, stid);
    cfg_set_option_value(tuple, "ap");

    //wireless.ath15.ssid='oakridg-def1' <-> wlan_service_template.ServiceTemplate1.ssid="ssid"
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.ssid", stid);
    cfg_get_option_value(tuple, buf, 33);
    sprintf(tuple, "wireless.ath%d%d.ssid", radio_id, stid);
    cfg_set_option_value(tuple, buf);

    //wireless.ath15.disabled='0' <-> wlan_serivce_template.ServiceTemplate1.service_template="enabled"
    sprintf(tuple, "wlan_service_template.ServiceTemplate%d.service_template", stid);
    cfg_get_option_value(tuple, buf, 33);
    if (!strcmp(buf, "enabled")) {
        sprintf(tuple, "wireless.ath%d%d.disabled", radio_id, stid);
        cfg_set_option_value(tuple, "0");
    } else {
        cfg_set_option_value(tuple, "1");
    }

    //wlan_radio.WLAN_Radio1.bind='ServiceTemplate1'
    sprintf(tuple, "wlan_radio.WLAN_Radio%d.bind", radio_id);
    sprintf (buf, "ServiceTemplate%d", stid);
    cfg_add_option_list_value(tuple, buf);

    return 0;
}

static int wlan_fetch_stid(struct uci_package *p, void *arg)
{
    struct uci_element *e1, *e2;
    struct uci_section *s;
    struct uci_option *o;
    struct wlan_ssid_stid {
        char ssid[33];
        int stid;
    };
    struct wlan_ssid_stid *ssid_stid = (struct wlan_ssid_stid *)arg;

    uci_foreach_element(&p->sections, e1) {
        s = uci_to_section(e1);
        sscanf(s->e.name, "ServiceTemplate%d", &(ssid_stid->stid));
        uci_foreach_element(&s->options, e2) {
            o = uci_to_option(e2);
            if (!strcmp(o->e.name, "ssid")) {
                if(!strcmp(o->v.string, ssid_stid->ssid)) {
                    break;
                }
            }
        }
    }

    return 0;
}

int wlan_get_stid_by_ssid(char *ssid, int *stid)
{
    struct wlan_ssid_stid {
        char ssid[33];
        int stid;
    };
    struct wlan_ssid_stid ssid_stid;
    strcpy(ssid_stid.ssid, ssid);
    cfg_visit_package(WLAN_CFG_SERVICE_TEMPLATE_PACKAGE, wlan_fetch_stid, &ssid_stid);
    *stid = ssid_stid.stid;

    return 0;
}

int wlan_get_ifname_by_stid(int radioid, int stid, char *ifname)
{
    sprintf(ifname, "ath%d%d", radioid, stid);
    return 0;
}
