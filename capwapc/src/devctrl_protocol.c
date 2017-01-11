#include <sys/sysinfo.h>

#include "CWWTP.h"
#include "devctrl_protocol.h"
#include "nmsc/nmsc.h"

#include "services/cfg_services.h"

static const int gMaxDTLSHeaderSize = 25; // see http://crypto.stanford.edu/~nagendra/papers/dtls.pdf
static const int gMaxCAPWAPHeaderSize = 8; // note: this include optional Wireless field

/* Max cache 3 fragment type that with different fragment id */
#define MAX_CACHE_MSGNUM    3   
static devctrl_fraglist_s g_devctrl_fraglist[MAX_CACHE_MSGNUM] = 
{
    {-1, -1, NULL},
    {-1, -1, NULL},
    {-1, -1, NULL},
};

static struct device_update_info g_dev_updateinfo;

static void delete_fraglist(CWList *list)
{
    int i;
    
    for (i = 0; i < MAX_CACHE_MSGNUM; i++) {
        if (list == &(g_devctrl_fraglist[i].list)) {
            g_devctrl_fraglist[i].id = -1;
        }
    }

    CWDeleteList(list, CWProtocolDestroyFragment);
}

static CWList* search_fraglist_byid(int id) 
{
    static int order = 0, cache = 0;
    int i = cache, oldest, oldest_order;

    /* compare with the latest cached list */
    if (id == g_devctrl_fraglist[i].id) {
        goto SEARCHED;
    }

    /* try to find recorded list */
    for (i = 0; i < MAX_CACHE_MSGNUM; i++) {
        if (id == g_devctrl_fraglist[i].id) {
            goto SEARCHED;;
        }
    }

    /* it means new msg */
    
    /* try to find free posion */
    for (i = 0; i < MAX_CACHE_MSGNUM; i++) {
        if (g_devctrl_fraglist[i].id == -1) {
            g_devctrl_fraglist[i].id = id;
            g_devctrl_fraglist[i].order = (order++ % MAX_CACHE_MSGNUM);
            goto SEARCHED;
        }
    }
    
    /* discard the oldest msg with different frag id */
    oldest = 0;
    oldest_order = g_devctrl_fraglist[oldest].order;
    for (i = 1; i < MAX_CACHE_MSGNUM; i++) {
        if (g_devctrl_fraglist[i].order < oldest_order) {
            oldest = i;
            oldest_order = g_devctrl_fraglist[oldest].order;
        }
    }
    CWDeleteList(&(g_devctrl_fraglist[oldest].list), CWProtocolDestroyFragment);
    
    g_devctrl_fraglist[oldest].id = id;
    i = oldest;

SEARCHED:    
    cache = i;
//    CWDebugLog_F("Serarched the index %d for the fragment id %d", i, id);
    return &(g_devctrl_fraglist[i].list);
}

static int parser_msg_seq(CWProtocolMessage *msg)
{
    CWProtocolTransportHeaderValues transp_header;
    CWControlHeaderValues ctrl_header;
    CWBool dataFlag = CW_FALSE;
    int offset = msg->offset;
    
    msg->offset = 0;
    CWParseTransportHeader(msg, &transp_header, &dataFlag);
    CWParseControlHeader(msg, &ctrl_header);
    msg->offset = offset;

    if (dataFlag) {
        CW_FREE_OBJECT(transp_header.bindingValuesPtr);
    }

    return ctrl_header.seqNum;
}

static void init_dev_updateinfo(device_info_s *info)
{
    g_dev_updateinfo.iptype  = info->iptype;
    g_dev_updateinfo.ip      = info->ip;
    g_dev_updateinfo.netmask = info->netmask;
    g_dev_updateinfo.gateway = info->gateway;

    gethostname(g_dev_updateinfo.hostname, sizeof(g_dev_updateinfo.hostname));
    g_dev_updateinfo.len = strlen(g_dev_updateinfo.hostname);
}

struct device_update_info* chk_dev_updateinfo(void)
{
    struct device_update_info info = {0};
    int ret, sk;
    struct ifreq ifr;
    struct sockaddr_in *paddr;

    sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "br-lan1", sizeof(ifr.ifr_name));
	if (ioctl(sk, SIOCGIFADDR, &ifr) < 0) {
        syslog(LOG_ERR, "no such interface: br-lan1");
		close(sk);
		return -1;
	}

    paddr = (struct sockaddr_in *) &ifr.ifr_addr;
    info.ip = paddr->sin_addr.s_addr;

    if (ioctl(sk, SIOCGIFNETMASK, &ifr) < 0) {
		close(sk);
		return -1;
	}

    paddr = (struct sockaddr_in *) &ifr.ifr_netmask;
    info.netmask = paddr->sin_addr.s_addr;
    gethostname(info.hostname, HOST_NAME_MAX);
    info.len = strlen(info.hostname);
	close(sk);

    if (g_dev_updateinfo.iptype != info.iptype
            || g_dev_updateinfo.ip != info.ip
            || g_dev_updateinfo.netmask != info.netmask
            || strcmp(g_dev_updateinfo.hostname, info.hostname)
            || g_dev_updateinfo.wds_mode != info.wds_mode) {
        g_dev_updateinfo.iptype  = info.iptype;
        g_dev_updateinfo.ip      = info.ip;
        g_dev_updateinfo.netmask = info.netmask;
        g_dev_updateinfo.gateway = info.gateway;

        strcpy(g_dev_updateinfo.hostname, info.hostname);
        g_dev_updateinfo.len = strlen(g_dev_updateinfo.hostname);
        g_dev_updateinfo.wds_mode = info.wds_mode;

        return &g_dev_updateinfo;
    }
    return NULL;
}

CWBool assemble_dev_updateinfo(char **info, int *len)
{
    struct device_update_info* update = NULL;
    CWProtocolMessage msg;
    int size = UPDATEINFO_FIX_LEN;

    if (info == NULL || len == NULL) {
        return CW_FALSE;
    }

    update = chk_dev_updateinfo();
    if (update == NULL) {
        return CW_FALSE;
    }
    size += update->len;

    memset(&msg, 0, sizeof(msg));
	CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    CWProtocolStore8(&msg, update->iptype);
    CWProtocolStore32(&msg, update->ip);
    CWProtocolStore32(&msg, update->netmask);
    CWProtocolStore32(&msg, update->gateway);
    CWProtocolStore8(&msg, update->len);
    CWProtocolStoreRawBytes(&msg, update->hostname, update->len);
    CWProtocolStore8(&msg, update->wds_mode);
    
    *info = msg.msg;
    *len = size;
    
    return CW_TRUE;
}

static int get_device_info(device_info_s *devinfo)
{
    struct product_info info;
    struct sysinfo sys;
    char nms_version[16] = "1.7.0";     
    char *s, *e;
    int i;

    if (cfg_get_product_info(&info)) {
        return -1;
    }

    /* mac address */
    s = info.mac;
    for (i = 0; i < 6; i++) {
        devinfo->mac[i] = s ? strtoul(s, &e, 16) : 0;
        if (s) {
            s = (*e) ? e + 1 : e;
        }
    }

    int ret, sk;
    struct ifreq ifr;
    struct sockaddr_in *paddr;

    sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "br-lan1", sizeof(ifr.ifr_name));
	if (ioctl(sk, SIOCGIFADDR, &ifr) < 0) {
        syslog(LOG_ERR, "no interface: br-lan1");
		close(sk);
		return -1;
	}

    paddr = (struct sockaddr_in *) &ifr.ifr_addr;
    devinfo->ip = paddr->sin_addr.s_addr;

    if (ioctl(sk, SIOCGIFNETMASK, &ifr) < 0) {
		close(sk);
		return -1;
	}

    paddr = (struct sockaddr_in *) &ifr.ifr_netmask;
    devinfo->netmask = paddr->sin_addr.s_addr;
	close(sk);

    /* uptime in second unit */
    sysinfo(&sys);
    devinfo->uptime = sys.uptime;

    /* serial number */
    devinfo->snlen = strlen(info.serial);
    CW_CREATE_OBJECT_SIZE_ERR(devinfo->sn, devinfo->snlen, CWDebugLog_E("malloc sn failed"););
    if (devinfo->sn == NULL) {
        return -1;
    }
    else {
        strncpy(devinfo->sn, info.serial, devinfo->snlen);
    }

    /* product name */
    devinfo->namelen = strlen(info.model);
    CW_CREATE_OBJECT_SIZE_ERR(devinfo->name, devinfo->namelen, CWDebugLog_E("malloc name failed"););
    if (devinfo->name == NULL) {
        CW_FREE_OBJECT(devinfo->sn);
        return -1;
    }
    else {
        strncpy(devinfo->name, info.model, devinfo->namelen);
    }
    devinfo->mtu = g_capwapc_config.mtu;

    devinfo->verlen = strlen(nms_version);
    CW_CREATE_OBJECT_SIZE_ERR(devinfo->version, devinfo->verlen, CWDebugLog_E("malloc version failed"););
    if (devinfo->version == NULL) {
        CW_FREE_OBJECT(devinfo->sn);
        CW_FREE_OBJECT(devinfo->name);
        return -1;
    }
    else {
        strncpy(devinfo->version, nms_version, devinfo->verlen);
    }

    devinfo->cfg_version = cfg_get_version();
    devinfo->cfg_code = dc_get_handcode();

    init_dev_updateinfo(devinfo);


    return 0;
}

CWBool assemble_vendor_devinfo(char **info, int *len)
{
    CWProtocolMessage msg;
    device_info_s devinfo;
    int size, i;

    if (info == NULL || len == NULL) {
        return CW_FALSE;
    }

    memset(&msg, 0, sizeof(msg));
    memset(&devinfo, 0, sizeof(devinfo));
#if !AH_PATCH
    if (get_device_info(&devinfo)) {
        return CW_FALSE;
    }
#else
    get_device_info(&devinfo);
#endif
    size = DEVINFO_FIX_LEN + NAT_VLAN_FIX_LEN * devinfo.natlist.num;
    size += devinfo.snlen + devinfo.namelen + devinfo.verlen + devinfo.cn_len;

	CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    CWProtocolStoreRawBytes(&msg, devinfo.mac, sizeof(devinfo.mac));
    CWProtocolStore8(&msg, devinfo.iptype);
    CWProtocolStore32(&msg, devinfo.ip);
    CWProtocolStore32(&msg, devinfo.netmask);
    CWProtocolStore32(&msg, devinfo.gateway);
    CWProtocolStore32(&msg, devinfo.uptime);
    CWProtocolStore8(&msg, devinfo.snlen);
    CWProtocolStoreRawBytes(&msg, devinfo.sn, devinfo.snlen);
    CWProtocolStore8(&msg, devinfo.namelen);
    CWProtocolStoreRawBytes(&msg, devinfo.name, devinfo.namelen);
    CWProtocolStore16(&msg, devinfo.mtu);
    CWProtocolStore8(&msg, devinfo.verlen);
    CWProtocolStoreRawBytes(&msg, devinfo.version, devinfo.verlen);
    CWProtocolStore32(&msg, devinfo.cfg_version);
    CWProtocolStore32(&msg, devinfo.cfg_code);
    CWProtocolStore8(&msg, devinfo.mode);
    CWProtocolStore8(&msg, devinfo.natlist.num);
    for (i = 0; i < devinfo.natlist.num; i++) {
        CWProtocolStore16(&msg, devinfo.natlist.info[i].len);
        CWProtocolStore32(&msg, devinfo.natlist.info[i].id);
        CWProtocolStore8(&msg, devinfo.natlist.info[i].type);
        CWProtocolStore32(&msg, devinfo.natlist.info[i].ip);
        CWProtocolStore32(&msg, devinfo.natlist.info[i].mask);
        CWProtocolStore32(&msg, devinfo.natlist.info[i].gw);
    }
    CWProtocolStore8(&msg, devinfo.wds_mode);
    CWProtocolStore8(&msg, devinfo.cn_len);
    CWProtocolStoreRawBytes(&msg, devinfo.country, devinfo.cn_len);
    
    if (devinfo.natlist.info) {
        CW_FREE_OBJECT(devinfo.natlist.info);
    }
    
    CW_FREE_OBJECT(devinfo.sn);
    CW_FREE_OBJECT(devinfo.name);
    CW_FREE_OBJECT(devinfo.version);

    if (msg.offset != size) {
        CWLog("Assmeble interface info failed for message offset match failed %d:%d", msg.offset ,size);
        CW_FREE_PROTOCOL_MESSAGE(msg);
        return CW_FALSE;
    }
    
    
    *info = msg.msg;
    *len = size;
    
    return CW_TRUE;
}

CWBool assemble_interface_info_elem(char **payload, int *len,
    struct device_interface_info *stas, int count)
{
    int i, size = 0, number = 0;
    CWProtocolMessage msg;

    size = 1; 
    for (i = 0; i < count; i++) {
        size += WLAN_INTERFACE_INFO_FIXLEN;
        size += (stas[i].interface_len + stas[i].ssid_len);
    }
    number = count;

    memset(&msg, 0, sizeof(msg));
    CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    /* interface info number */
    CWProtocolStore8(&msg, number);

    for (i = 0; i < count; i++) {
        struct device_interface_info *info = &(stas[i]);
        
        info->len = WLAN_INTERFACE_INFO_FIXLEN + info->interface_len + info->ssid_len;
        
        CWProtocolStore16(&msg, info->len);
        CWProtocolStore8(&msg, info->interface_len);
        CWProtocolStoreRawBytes(&msg, info->interface_name, info->interface_len);
        CWProtocolStore8(&msg, info->state);
        CWProtocolStoreRawBytes(&msg, (char *)(info->mac), 6);
        CWProtocolStore32(&msg, info->pvid);
        CWProtocolStore8(&msg, info->ssid_len);
        CWProtocolStoreRawBytes(&msg, info->ssid, info->ssid_len);
        CWProtocolStore32(&msg, info->ip_address);
        CWProtocolStore32(&msg, info->mask_address);
        CWProtocolStore32(&msg, info->channel);
        CWProtocolStore32(&msg, info->txpower);
    }
    
    if (msg.offset != size) {
        CWLog("Assmeble interface info failed for message offset match failed %d:%d", msg.offset ,size);
        CW_FREE_PROTOCOL_MESSAGE(msg);
        return CW_FALSE;
    }
    
    *payload = msg.msg;
    *len = size;

    return CW_TRUE;
}

CWBool assemble_wds_info_elem(char **payload, int *len,
    struct wds_tunnel_info *stas, int count)
{
    int i, size = 0, number = 0;
    CWProtocolMessage msg;

    size = 1; 
    for (i = 0; i < count; i++) {
        size += WDS_TUNNEL_INFO_FIXLEN;
    }
    number = count;

    memset(&msg, 0, sizeof(msg));
    CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    /* wds tunnel info number */
    CWProtocolStore8(&msg, number);

    for (i = 0; i < count; i++) {
        
        CWProtocolStore16(&msg, WDS_TUNNEL_INFO_FIXLEN);
        CWProtocolStoreRawBytes(&msg, (char *)(stas[i].mac), 6);
        CWProtocolStore8(&msg, stas[i].mode);
        CWProtocolStore8(&msg, stas[i].err_code);
        CWProtocolStore8(&msg, stas[i].status);
        CWProtocolStore8(&msg, stas[i].level);
        CWProtocolStoreRawBytes(&msg, (char *)(stas[i].uplink), 6);
    }
    
    if (msg.offset != size) {
        CWLog("Assmeble wds info failed for message offset match failed %d:%d", msg.offset ,size);
        CW_FREE_PROTOCOL_MESSAGE(msg);
        return CW_FALSE;
    }
    
    *payload = msg.msg;
    *len = size;

    return CW_TRUE;
}

CWBool assemble_wlan_sta_status_elem(char **payload, int *len,
    struct wlan_sta_stat *stas, int count, int type)
{
    int i, size = 0, number = 0;
    CWProtocolMessage msg;

    switch (type) {
        case WLAN_STA_TYPE_QUERY:
            /* sta number seciont */
            size = 1; 
            for (i = 0; i < count; i++) {
                /* does not includ stat section */
                size += WLAN_STA_QUERY_FIXLEN;
                size += (stas[i].ssid_len + stas[i].name_len + stas[i].ps_len);
            }
            number = count;
            break;

        case WLAN_STA_TYPE_STAUS:
            for (i = 0; i < count; i++) {
                if (!stas[i].updated) {
                    number++;
                    size += WLAN_STA_STATUS_FIXLEN;
                    size += (stas[i].ssid_len + stas[i].name_len + stas[i].ps_len);
                }
            }
            if (number > 0) {
                /* add sta number seciont */
                size += 1;
            }
            break;

        case WLAN_STA_TYPE_UPDATE:
            for (i = 0; i < count; i++) {
                if (stas[i].updated) {
                    number++;
                    size += WLAN_STA_UPDATE_FIXLEN;
                    size += stas[i].name_len;
                }
            }
            if (number > 0) {
                /* add sta number seciont */
                size += 1;
            }
            break;
    }

    if (number == 0 && type != WLAN_STA_TYPE_QUERY) {
        /* nothing to do */
        return CW_TRUE;
    }
    
    memset(&msg, 0, sizeof(msg));

    CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    /* wlan sta number */
    CWProtocolStore8(&msg, number);
    if (type == WLAN_STA_TYPE_UPDATE) {
        for (i = 0; i < count; i++) {
            struct wlan_sta_stat *sta = &(stas[i]);

            if (!sta->updated) {
                continue;
            }
            
            sta->len = WLAN_STA_UPDATE_FIXLEN + sta->name_len;
            
            CWProtocolStore16(&msg, sta->len);
            CWProtocolStoreRawBytes(&msg, (char *)(sta->mac), 6);
            CWProtocolStore32(&msg, sta->ip);
            CWProtocolStore32(&msg, sta->portal_mode);
            CWProtocolStore8(&msg, sta->name_len);
            CWProtocolStoreRawBytes(&msg, sta->user, sta->name_len);
            CWProtocolStore32(&msg, sta->rssi);
        }
    }
    else {
        for (i = 0; i < count; i++) {
            struct wlan_sta_stat *sta = &(stas[i]);
            
            if (type == WLAN_STA_TYPE_QUERY) {
                sta->len = WLAN_STA_QUERY_FIXLEN + sta->ssid_len + sta->name_len + sta->ps_len;
                CWProtocolStore16(&msg, sta->len);
            }
            else {
                if (sta->updated) {
                    continue;
                }
                sta->len = WLAN_STA_STATUS_FIXLEN + sta->ssid_len + sta->name_len + sta->ps_len;
                CWProtocolStore16(&msg, sta->len);
                CWProtocolStore8(&msg, sta->state);
            }
            
            CWProtocolStoreRawBytes(&msg, (char *)(sta->mac), 6);
            CWProtocolStore64(&msg, sta->time_ms);
            CWProtocolStore32(&msg, sta->uptime);
            CWProtocolStore8(&msg, sta->radioid);
            CWProtocolStore8(&msg, sta->ssid_len);
            CWProtocolStoreRawBytes(&msg, sta->ssid, sta->ssid_len);
            CWProtocolStore8(&msg, sta->auth);
            CWProtocolStore8(&msg, sta->cipher);
            CWProtocolStore8(&msg, sta->portal);
            CWProtocolStore32(&msg, sta->ip);
            CWProtocolStore32(&msg, sta->portal_mode);
            CWProtocolStore8(&msg, sta->name_len);
            CWProtocolStoreRawBytes(&msg, sta->user, sta->name_len);
            CWProtocolStore8(&msg, sta->ps_len);
            CWProtocolStoreRawBytes(&msg, sta->ps_name, sta->ps_len);
            CWProtocolStoreRawBytes(&msg, sta->bssid, sizeof(sta->bssid));
            CWProtocolStore32(&msg, sta->rssi);
            CWProtocolStore32(&msg, sta->channel);
            CWProtocolStore32(&msg, sta->vlan);
            
        }
    }
    if (msg.offset != size) {
        CWLog("Assmeble wlan sta stats(%d) failed for message offset match failed %d:%d", 
            type, msg.offset ,size);
        CW_FREE_PROTOCOL_MESSAGE(msg);
        return CW_FALSE;
    }
    
    *payload = msg.msg;
    *len = size;

    return CW_TRUE;
}

CWBool assemble_cli_result_elem(char **payload, int *len, struct cli_exec_result *result)
{
    int size = sizeof(result->code) + sizeof(result->len) + result->len;
    CWProtocolMessage msg;
    
    memset(&msg, 0, sizeof(msg));
    CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    CWProtocolStore32(&msg, result->code);
    CWProtocolStore32(&msg, result->len);
    CWProtocolStoreRawBytes(&msg, (char *)(result->result), result->len);
    
    if (msg.offset != size) {
        CWLog("Assmeble cli exec result failed for message offset match failed %d:%d", msg.offset ,size);
        CW_FREE_PROTOCOL_MESSAGE(msg);
        return CW_FALSE;
    }
    
    *payload = msg.msg;
    *len = size;

    return CW_TRUE;
}

CWBool assemble_rate_sta_elem(char **payload, int *len, struct if_rate_stas *result)
{
    int size, i;
    CWProtocolMessage msg;

    size = 1;
    for (i = 0; i < result->num; i++) {
        size += 2;
        size += RATE_STA_FIX_LEN + strlen(result->stas[i].name);
    }

    memset(&msg, 0, sizeof(msg));
    CW_CREATE_PROTOCOL_MESSAGE(msg, size, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    CWProtocolStore8(&msg, result->num);
    for (i = 0; i < result->num; i++) {
        struct if_flow_stat *stas = &(result->stas[i]);
        CWProtocolStore16(&msg, 2 + RATE_STA_FIX_LEN + strlen(stas->name)); /* include slef 2 bytes */
        CWProtocolStore8(&msg, strlen(stas->name));
        CWProtocolStoreRawBytes(&msg, stas->name, strlen(stas->name));
#if !OK_PATCH
        CWProtocolStore64(&msg, stas->sta.stat.tx_bytes);
        CWProtocolStore64(&msg, stas->sta.stat.rx_bytes);
        CWProtocolStore32(&msg, stas->sta.tx_bps);
        CWProtocolStore32(&msg, stas->sta.rx_bps);
#endif
    }
    
    if (msg.offset != size) {
        CWLog("Assmeble flow sta result failed for message offset match failed %d:%d", msg.offset ,size);
        CW_FREE_PROTOCOL_MESSAGE(msg);
        return CW_FALSE;
    }
    
    *payload = msg.msg;
    *len = size;

    return CW_TRUE;
}

static CWBool parse_devctrlreq_elem(CWProtocolMessage *msgPtr, int len, 
    devctrl_block_s *valPtr) 
{
    CWParseMessageElementStart();

    valPtr->version = CWProtocolRetrieve8(msgPtr);
    memcpy(valPtr->cookie, (msgPtr->msg + msgPtr->offset), COOKIE_LENGTH);
    msgPtr->offset += COOKIE_LENGTH;
    valPtr->type = CWProtocolRetrieve16(msgPtr);
    valPtr->compressed = CWProtocolRetrieve8(msgPtr);
    valPtr->orig_len = CWProtocolRetrieve32(msgPtr);
    valPtr->len = CWProtocolRetrieve32(msgPtr);

    CW_CREATE_OBJECT_SIZE_ERR(valPtr->data, valPtr->len, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
    memcpy(valPtr->data, &((msgPtr->msg)[(msgPtr->offset)]), valPtr->len);
    msgPtr->offset += valPtr->len;    
    
	CWParseMessageElementEnd();  
}

CWBool parse_devctrlreq_msg(CWProtocolMessage *msg, devctrl_block_s *controlinfo) 
{
    CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
    unsigned short int elemType = 0, elemLen = 0;
    int len, total_elemlen;
	
	if(msg == NULL || controlinfo == NULL) {
        return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
    }

    msg->offset = 0;
	
	/* will be handled by the caller */
	if(!(CWParseControlHeader(msg, &controlVal))) {
		return CW_FALSE;	
    }

    if (controlVal.flags == 0) {
    	len = controlVal.msgElemsLen - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
    }
    else {
        /* The msg lenth bigger than 64k */
        len = (((controlVal.flags) & 0xff) << 16) + controlVal.msgElemsLen - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
    }

	completeMsg.msg = msg->msg + msg->offset;
	completeMsg.offset = 0;
    /* devctrlreq only one element */
	while (completeMsg.offset < len) { 
		CWParseFormatMsgElem(&completeMsg, &elemType, &elemLen);
        /* if the element lenth bigger than 64k */
        total_elemlen = elemLen + (((controlVal.flags) & 0xff) << 16);
        
		switch(elemType) { 
			case CW_MSG_ELEMENT_WTP_DEVICE_CONTROLINFO_CW_TYPE:
				if (!parse_devctrlreq_elem(&completeMsg,  total_elemlen, controlinfo)) {
					CWLog("Parse message element %d failed.", elemType);
					return CW_FALSE;
                }
				break;
                
			default:
                CWLog("Unrecognized Message Element:%d", elemType);
                CWDebugLog_E("Unrecognized Message Element:%d", elemType);
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}

	if(completeMsg.offset != len) {
        return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
    }
    
	return CW_TRUE;
}

CWBool assemble_devctrlresp_elem(CWProtocolMessage *msgPtr, devctrl_block_s *Controlblock) 
{
	if(msgPtr == NULL || Controlblock == NULL) {
        return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
    }
    
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, Controlblock->len + DEVCTRL_BLOCK_HEADER_LEN, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, Controlblock->version); /* 1 byte */
    CWProtocolStoreRawBytes(msgPtr, Controlblock->cookie, COOKIE_LENGTH); /* 8 bytes */
    CWProtocolStore16(msgPtr, Controlblock->type); /* 2 bytes */
    CWProtocolStore8(msgPtr, Controlblock->compressed); /* 1 bytes */
    CWProtocolStore32(msgPtr, Controlblock->orig_len); /* 4 bytes */
    CWProtocolStore32(msgPtr, Controlblock->len); /* 4 bytes */
    CWProtocolStoreRawBytes(msgPtr, Controlblock->data, Controlblock->len);

    CWDebugLog("Assembled dev_ctrl result msg element, data len:%d...", Controlblock->len);
    
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE);
}


CWBool assemble_devctrlresp_msg(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, 
    int PMTU, int seqNum, CWProtocolResultCode resultCode) 
{
	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) {
        return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
    }

    CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
    
    if (!(CWAssembleMsgElemResultCode(msgElems, CW_PROTOCOL_SUCCESS))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}
    
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_DEVICE_CONTROL_RESPONSE,
			       msgElems,
			       msgElemCount,
			       NULL,
			       0,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       )))  {
		return CW_FALSE;
    }
	CWDebugLog("Assembled dev_ctrl info response.");
    
	return CW_TRUE;
}

CWBool assemble_devctrlresp_frag(CWProtocolMessage **completeMsgPtr, 
    int *fragmentsNumPtr, int PMTU, int seqNum, int msgTypeValue, 
    CWProtocolMessage *msgElems, int is_crypted) 
{
	CWProtocolMessage header, msg;
	int msgElemsLen = 0, msgElemDatalen;
	CWProtocolTransportHeaderValues transportVal;
	CWControlHeaderValues controlVal;

    CWDebugLog("Assemble message with the dev_ctrl_result element.");
    
	if(completeMsgPtr == NULL || fragmentsNumPtr == NULL || (msgElems == NULL)) { 
        return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
    }
	
	/* dev_ctrl_result only one msg element	*/
	msgElemsLen = msgElems[0].offset;

	/* Assemble Control Header */
	controlVal.messageTypeValue = msgTypeValue;
    /* !!! if msgElemslen bigger than 64k, following saved wrong value
     * but it must need to be fragmented, it will handle correctly
     */
	controlVal.msgElemsLen = msgElemsLen;
	controlVal.seqNum = seqNum;

	if(!(CWAssembleControlHeader(&header, &controlVal))) {
		CW_FREE_PROTOCOL_MESSAGE(header);
		CW_FREE_PROTOCOL_MESSAGE(msgElems[0]);
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE; 
	}
	
	/* Assemble the message putting all the data consecutively */
	CW_CREATE_PROTOCOL_MESSAGE(msg, header.offset + msgElemsLen, 
	    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CWProtocolStoreMessage(&msg, &header);
	CWProtocolStoreMessage(&msg, &(msgElems[0]));

	/* Free memory not needed anymore */
	CW_FREE_PROTOCOL_MESSAGE(header);
	CW_FREE_PROTOCOL_MESSAGE(msgElems[0]);
	CW_FREE_OBJECT(msgElems);

    /* For the dev_ctrl_result, only the element data need to be fragmented */
	PMTU = PMTU - gMaxDTLSHeaderSize - gMaxCAPWAPHeaderSize;
    /* skip element header (2 bytes type + 2 bytes len) */
	msgElemDatalen = msgElemsLen - CW_MSGELEM_HEADER_LENGTH;
    /* 8 bytes msg control header + 4 bytes element header */
    PMTU -= (CW_CONTROL_HEADER_LENGTH + CW_MSGELEM_HEADER_LENGTH);
	if(PMTU > 0) {
		PMTU = (PMTU / 8) * 8; // CAPWAP fragments are made of groups of 8 bytes
		if(PMTU == 0) {
            goto cw_dont_fragment;
        }
		
		*fragmentsNumPtr = msgElemDatalen / PMTU;
		if((msgElemDatalen % PMTU) != 0) (*fragmentsNumPtr)++;
	} 
    else {
cw_dont_fragment:
		*fragmentsNumPtr = 1;
	}
	
	transportVal.bindingValuesPtr = NULL;
		
	if(*fragmentsNumPtr == 1) {
		CW_CREATE_OBJECT_ERR(*completeMsgPtr, CWProtocolMessage, 
            return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		
		transportVal.isFragment = transportVal.last = transportVal.fragmentOffset = transportVal.fragmentID = 0;
		transportVal.payloadType = is_crypted;

		/* Assemble transporthader */
		if	(!(CWAssembleTransportHeader(&header, &transportVal))) {
			CW_FREE_PROTOCOL_MESSAGE(msg);
			CW_FREE_PROTOCOL_MESSAGE(header);
			CW_FREE_OBJECT(completeMsgPtr);
			return CW_FALSE; 
		} 
	
		// assemble the message putting all the data consecutively
		CW_CREATE_PROTOCOL_MESSAGE(((*completeMsgPtr)[0]), header.offset + msg.offset, 
		    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		
		CWProtocolStoreMessage(&((*completeMsgPtr)[0]), &header);
		CWProtocolStoreMessage(&((*completeMsgPtr)[0]), &msg);
		
		CW_FREE_PROTOCOL_MESSAGE(header);
		CW_FREE_PROTOCOL_MESSAGE(msg);
	} 
    else {
        int i;
		int fragID = CWGetFragmentID();
        CWControlHeaderValues Ctrl_header;

        msg.offset = 0;
        if (!(CWParseControlHeader(&msg, &Ctrl_header))) {
            CW_FREE_PROTOCOL_MESSAGE(msg);
            return CW_FALSE;
        }
        
        CWDebugLog_D("Fragment dev_ctrl_result msgelement, fragnum:%d, totallen:%d, msg:%d:%d:%d.", 
            *fragmentsNumPtr, msgElemDatalen, Ctrl_header.messageTypeValue, Ctrl_header.msgElemsLen, Ctrl_header.seqNum);
        
		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(*completeMsgPtr, *fragmentsNumPtr, 
            return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

        /* Only msgelement data will be fragmented, so skip 8 bytes msg control header + 4 bytes element header */
        msg.offset = (CW_CONTROL_HEADER_LENGTH + CW_MSGELEM_HEADER_LENGTH);

        /* loop for each fragment to assemble */
		for(i = 0; i < *fragmentsNumPtr; i++) { 
			int fragSize;
			
			transportVal.isFragment = 1;
			transportVal.fragmentOffset = i; /* fragment offset increased one by one */
			transportVal.fragmentID = fragID;
			transportVal.payloadType = is_crypted;

            /* excepet the last fragment all same with PMTU */
			if(i < ((*fragmentsNumPtr)-1)) { 
				fragSize = PMTU;
				transportVal.last = 0;
			} 
            else {
				fragSize = msgElemDatalen - (((*fragmentsNumPtr)-1) * PMTU);
				transportVal.last = 1;
			}
            
			if(!(CWAssembleTransportHeader(&header, &transportVal))) {
				CW_FREE_PROTOCOL_MESSAGE(msg);
				CW_FREE_PROTOCOL_MESSAGE(header);
				CW_FREE_OBJECT(completeMsgPtr);
				return CW_FALSE;
			}
            /* each fragment include transporthdr, controlhdr, msgelemhdr and fragsize of elem data */
            CW_CREATE_PROTOCOL_MESSAGE(((*completeMsgPtr)[i]), 
                header.offset + (CW_CONTROL_HEADER_LENGTH + CW_MSGELEM_HEADER_LENGTH) + fragSize, 
                return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

            /* First: Assemble Transport Header for this fragment */
            CWProtocolStoreMessage(&((*completeMsgPtr)[i]), &header);
            CW_FREE_PROTOCOL_MESSAGE(header);
            
            /* Second: Assemble Control Header for this fragment */
            /* msgelemlen include 4 bytes element header */
            Ctrl_header.msgElemsLen = fragSize + CW_MSGELEM_HEADER_LENGTH;
            if (i > 0) {
                Ctrl_header.seqNum = CWGetSeqNum();
            }
            if(!(CWAssembleControlHeader(&header, &Ctrl_header))) {
				CW_FREE_PROTOCOL_MESSAGE(msg);
				CW_FREE_PROTOCOL_MESSAGE(header);
				CW_FREE_OBJECT(completeMsgPtr);
				return CW_FALSE; 
			}
            CWProtocolStoreMessage(&((*completeMsgPtr)[i]), &header);
            CW_FREE_PROTOCOL_MESSAGE(header);
            
            /* Third: Assemble Msgelement Header for this fragment */
            CWProtocolStore16(&((*completeMsgPtr)[i]), CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE);
            CWProtocolStore16(&((*completeMsgPtr)[i]), fragSize);

            /* Last: Assemble Control data for this fragment */
            CWProtocolStoreRawBytes(&((*completeMsgPtr)[i]), &((msg.msg)[msg.offset]), fragSize);
            msg.offset += fragSize;
		}
		CW_FREE_PROTOCOL_MESSAGE(msg);
	}

	return CW_TRUE;
}

CWBool parse_devctrlreq_frag(char *buf, int readBytes,  CWProtocolMessage *reassembledMsg, 
    CWBool *dataFlagPtr) 
{
    CWList *fragmentsListPtr;
	CWProtocolTransportHeaderValues values;
	CWProtocolMessage msg;
    CWControlHeaderValues ctrl_header;
    int offset;
    
	msg.msg = buf;
	msg.offset = 0;

	*dataFlagPtr = CW_FALSE;
	
	if(!CWParseTransportHeader(&msg, &values, dataFlagPtr)) return CW_FALSE;

    offset = msg.offset;
    if (!CWParseControlHeader(&msg, &ctrl_header)) {
        return CW_FALSE;
    }
    msg.offset = offset;
    
	if(values.isFragment == 0) { // single fragment
		CW_CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (readBytes-msg.offset), 
            return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
        
		CWProtocolStoreRawBytes(reassembledMsg, &(buf[msg.offset]), (readBytes-msg.offset));
		reassembledMsg->data_msgType=msg.data_msgType;    
		CWErrorRaise(CW_ERROR_SUCCESS, NULL);
		return CW_TRUE;
	} 
    else {
		CWListElement *el;
		CWProtocolFragment *fragPtr;
        int totalSize = 0, last_offset, frag_offset;

		CW_CREATE_OBJECT_ERR(fragPtr, CWProtocolFragment, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

		fragPtr->transportVal.fragmentID = values.fragmentID;
		fragPtr->transportVal.fragmentOffset = values.fragmentOffset;
		fragPtr->transportVal.last = values.last;

		CWDebugLog_D("Received Fragment ID:%d, offset:%d, notLast:%d", fragPtr->transportVal.fragmentID,fragPtr->transportVal.fragmentOffset, fragPtr->transportVal.last);
	
		fragPtr->dataLen = (readBytes-msg.offset);

        /* Empty list of this fragment is in the set of fragments we are receiving */
        fragmentsListPtr = search_fraglist_byid(fragPtr->transportVal.fragmentID);
        if (fragmentsListPtr != NULL) {
            CWListElement *aux = NULL;
			aux = CWSearchInList(*fragmentsListPtr, fragPtr, CWCompareFragment);
			if(aux == NULL) 
			{
				CW_CREATE_OBJECT_SIZE_ERR(fragPtr->data, fragPtr->dataLen, 
                    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                
				CW_COPY_MEMORY(fragPtr->data, &(buf[msg.offset]), fragPtr->dataLen);
				if(!CWAddElementToList(fragmentsListPtr, fragPtr)) {
					delete_fraglist(fragmentsListPtr);
					CW_FREE_OBJECT(fragPtr);
					return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
				}
			}
			else{
				CWDebugLog("Received a copy of a fragment already in List");
                CWDebugLog_E("Received a copy of a fragment already in List");
				CW_FREE_OBJECT(fragPtr);
				return CWErrorRaise(CW_ERROR_NEED_RESOURCE, NULL);
			}	
        }
        else {
            /* should not come here !!! */
            return CW_FALSE;
        }

        /* First: check if received the last fragment */
        last_offset = -1;
        for(el = *fragmentsListPtr; el != NULL; el = el->next) {
    		if((((CWProtocolFragment*)(el->data))->transportVal.last) == 1) {
    			last_offset = ((CWProtocolFragment*)(el->data))->transportVal.fragmentOffset;
                break;
    		}
    	}
        if (last_offset <= 0) {
            goto NEED_RESOURCE; 
        }

        /* Second: check if received all the fragmentes */
        for (frag_offset = 0; frag_offset < last_offset; frag_offset++) {
            for(el = *fragmentsListPtr; el != NULL; el = el->next) {
        		if((((CWProtocolFragment*)(el->data))->transportVal.fragmentOffset) == frag_offset) { 
                		break;
            	}
            }
            /* at least one frag_offset does not exist, it means at least one more fragment */
            if (el == NULL) {
                break;
            }
        }

        if (frag_offset < last_offset) {
            goto NEED_RESOURCE;
        }

        /* Now we received all fragmentes, calculate the total length */
        for(el = *fragmentsListPtr; el != NULL; el = el->next) {
            if((((CWProtocolFragment*)(el->data))->transportVal.fragmentOffset) == 0) {
    			totalSize += (((CWProtocolFragment*)(el->data))->dataLen);
    		}
    		else {
                /* skip msg header(8 bytes) + msgElement header(4 bytes) */
                totalSize += (((CWProtocolFragment*)(el->data))->dataLen) - (CW_CONTROL_HEADER_LENGTH + CW_MSGELEM_HEADER_LENGTH);
            }
    	}
		
		if(1){
			int currentOffset = 0;

            /* msg data bigger than 0xffff */
            if (totalSize - CW_CONTROL_HEADER_LENGTH + CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS > 0xffff) {
                /* if the reserved flags nothing to do, we save it, else we do nothing, but return false */
                if (ctrl_header.flags == 0) {
                    ctrl_header.msgElemsLen = (totalSize - CW_CONTROL_HEADER_LENGTH) & 0xffff;
                    ctrl_header.flags = ((totalSize - CW_CONTROL_HEADER_LENGTH) & 0xff0000) >> 16;
                    if (ctrl_header.msgElemsLen > 0xffff - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS) {                
                        ctrl_header.msgElemsLen = (unsigned int)ctrl_header.msgElemsLen 
                            + CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS - (1 << 16);
                        ctrl_header.flags ++;
                    }
                }
                else {
                    delete_fraglist(fragmentsListPtr);
                    CW_FREE_PROTOCOL_MESSAGE(*reassembledMsg);
                    return CW_FALSE;  
                }
            }
            else {
                /* skip the msg header (8 bytes) */
                ctrl_header.msgElemsLen = totalSize - CW_CONTROL_HEADER_LENGTH;
            }
		
			CWDebugLog_D("Message Reassembled, reassembledMsg:%p:%d, head:%d:%d:%d:%d",  reassembledMsg, totalSize,
                            ctrl_header.messageTypeValue, ctrl_header.msgElemsLen, ctrl_header.seqNum, ctrl_header.flags);
 
			
			CW_CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (totalSize), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

			CW_REPEAT_FOREVER {
				CWBool found = CW_FALSE;

				/* find the fragment in the list with the currend offset */
				for(el = *fragmentsListPtr; el != NULL; el = el->next) {
					if( (((CWProtocolFragment*)(el->data))->transportVal.fragmentOffset) == currentOffset) {
						found = CW_TRUE;
						break;
					}
				}
			
				if(!found) { /* mmm... we should have all the fragment, but we haven't a fragment for the current offset */
					delete_fraglist(fragmentsListPtr);
					CW_FREE_PROTOCOL_MESSAGE(*reassembledMsg);
					return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Bad Fragmented Messsage");
				}

                /* First fragment copy all data */
                if (currentOffset == 0) { 
    				CWProtocolStoreRawBytes(reassembledMsg, (((CWProtocolFragment*)(el->data))->data), 
                        (((CWProtocolFragment*)(el->data))->dataLen)); 
                } 
                else {
                    /* Other fragmentes skip msg header and element header */
                    CWProtocolStoreRawBytes(reassembledMsg, 
                        (((CWProtocolFragment*)(el->data))->data + (CW_CONTROL_HEADER_LENGTH + CW_MSGELEM_HEADER_LENGTH)), 
                        (((CWProtocolFragment*)(el->data))->dataLen - (CW_CONTROL_HEADER_LENGTH + CW_MSGELEM_HEADER_LENGTH)));
                }

				if((((CWProtocolFragment*)(el->data))->transportVal.last) == 1) { // last fragment
                    CWProtocolMessage controlHdr;

                    reassembledMsg->offset = 0;
                    if(!(CWAssembleControlHeader(&controlHdr, &ctrl_header)))  {
                        delete_fraglist(fragmentsListPtr);
                        CW_FREE_PROTOCOL_MESSAGE(*reassembledMsg);
                        return CW_FALSE;                         
                    }
                    else {
                        /* Store msg header */
                        CWProtocolStoreMessage(reassembledMsg, &controlHdr);
                        /* skip msg element type (2 bytes) */
                        reassembledMsg->offset += 2;
                        /* Reset total msg element length */
                        CWProtocolStore16(reassembledMsg, ctrl_header.msgElemsLen -4);
                            
                    	CW_FREE_PROTOCOL_MESSAGE(controlHdr);
                    }
                    
					delete_fraglist(fragmentsListPtr);
                    CWErrorRaise(CW_ERROR_SUCCESS, NULL);
					return CW_TRUE;
				}
                /* Fragment offset was increased one by one */
                currentOffset ++;
			}
		}
	}

NEED_RESOURCE:
    CW_CREATE_PROTOCOL_MESSAGE(*reassembledMsg, (readBytes-msg.offset), 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	CWProtocolStoreRawBytes(reassembledMsg, &(buf[msg.offset]), (readBytes-msg.offset));
	reassembledMsg->data_msgType = msg.data_msgType;
    return CWErrorRaise(CW_ERROR_DEVCONTROL_REQ_FRAGMENT, NULL);
}

CWBool WTPEventRequest_devctrlresp(int type, int value)
{
    CWList msgElemList = NULL;
    CWProtocolMessage *messages = NULL;
    CWProtocolMessage *fragmsg;
    int fragmentsNum = 0;
    int seqNum;
    int *pendingReqIndex;
    int i, k, timeout, trytime = 0;

    CWDebugLog("WTP Event Request Message with dev_ctrl_result element(Run).");

    CW_CREATE_OBJECT_ERR(msgElemList, CWListElement, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
    CW_CREATE_OBJECT_ERR(msgElemList->data, CWMsgElemData, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););	
    msgElemList->next= NULL;
	//Change type and value to change the msg elem to send
	((CWMsgElemData*)(msgElemList->data))->type = type; //CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE;
	((CWMsgElemData*)(msgElemList->data))->value = value;

    seqNum = CWGetSeqNum();
    if(!CWAssembleWTPEventRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList)){
        if(messages) {
            for(i = 0; i < fragmentsNum; i++) {
                CW_FREE_PROTOCOL_MESSAGE(messages[i]);
            }	
            CW_FREE_OBJECT(messages);
        }
        return CW_FALSE;
    }

    for (i = 0; i < fragmentsNum; i++) {
        CW_CREATE_OBJECT_ERR(pendingReqIndex, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
        /* following alloc new msgptr to save mssage[i], because it will free protocol msg and msg object
         * (see fun: CWResetPendingMsgBox), but messagesptr is alloced by CW_CREATE_ARRAY_ERR
         */
        CW_CREATE_OBJECT_ERR(fragmsg, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
        fragmsg->msg = messages[i].msg;
        fragmsg->offset = messages[i].offset;
        fragmsg->data_msgType = messages[i].data_msgType;
        
TRY_AGAINTIME:
        lock_pendingbox();
        *pendingReqIndex = CWSendPendingRequestMessage(gPendingRequestMsgs, fragmsg, 1);        
        if (*pendingReqIndex < 0) {           
            unlock_pendingbox();
            if (trytime < 5) {
                timeout = (1 << trytime) * 100000;
                usleep(timeout);
                trytime++;
                goto TRY_AGAINTIME;                
            }           
            
            CWDebugLog_E("Failed to send WTP Event Request, free all messages.");
            for(k = i; k < fragmentsNum; k++) {
                CW_FREE_PROTOCOL_MESSAGE(messages[k]);
            }
            CW_FREE_OBJECT(messages);
            CW_FREE_OBJECT(fragmsg);
            CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);
            return CW_FALSE;
    	} 

        seqNum = parser_msg_seq(fragmsg);
        CWUpdatePendingMsgBox(&(gPendingRequestMsgs[*pendingReqIndex]),
            CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE, seqNum, g_capwapc_config.retran_intv,
            pendingReqIndex, CWWTPRetransmitTimerExpiredHandler, 0, fragmsg, 1);
        unlock_pendingbox(); 
        trytime = 0;
    }
    CW_FREE_OBJECT(messages);
    CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);
	return CW_TRUE;
}

