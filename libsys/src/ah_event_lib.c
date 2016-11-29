/*********************************************************
 AEROHIVE CONFIDENTIAL

 Copyright 2006-2016 Aerohive Networks, Inc.
 All Rights Reserved.

 NOTICE: All information herein is and remains the property
 of Aerohive Networks, Inc. and its suppliers, if any.

 The intellectual and technical concepts contained herein
 are proprietary to Aerohive Networks, Inc. and its
 suppliers and may be covered by U.S. and foreign patents
 and/or pending patent applications, and are protected by
 trade secret and copyright law.

 Disclosure, dissemination or reproduction of this
 information or the intellectual or technical concepts
 expressed by this information is prohibited unless prior
 written permission is obtained from Aerohive Networks, Inc.
 **********************************************************/
/********************************************************************
 * Copyright (C) 2006 Aerohive Networks
 *
 * ah_event_lib.c
 *
 * The file implements Aerohive Event Library.
 *
 *
 *******************************************************************/
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include "ah_event_internal.h"
#include "ah_device.h"
#include "ah_trap.h"


/* Event lib control data */
static ah_event_ctrl_t ah_event_ctrl;

/* Event lib debug */
int ah_event_debug = 0;
/* Event lib timer */
boolean event_start_timer = TRUE;


/*
 * return 1 if ah event lib has been inited, 0 if not yet
 */
int has_ah_event_init (void)
{
	return ah_event_ctrl.initialized;
}
char *ah_eventid_to_name (ah_event_t eid)
{
	return ( ((eid) == AH_EVENT_DCD_ADD_HIVEID) ? "add hiveID" : \
			 ((eid) == AH_EVENT_DCD_DEL_HIVEID) ? "rm hiveID" : \
			 ((eid) == AH_EVENT_DCD_IF_CHANGE) ? "ifp chg" : \
			 ((eid) == AH_EVENT_DCD_BIND_HIVEID) ? "bind hiveID" : \
			 ((eid) == AH_EVENT_IP_CHANGE) ? "mgt0 IP chg" : \
			 ((eid) == AH_EVENT_TUNNEL_IP_CHANGE) ? "tunnelx IP chg" : \
			 ((eid) == AH_EVENT_ETHX_IP_CHANGE) ? "ethx IP chg" : \
			 ((eid) == AH_EVENT_PPPX_IP_CHANGE) ? "pppx IP chg" :  \
			 ((eid) == AH_EVENT_USBX_IP_CHANGE) ? "usbx IP chg" :    \
			 ((eid) == AH_EVENT_VAP_IP_CHANGE) ? "wifix.y IP chg" : \
			 ((eid) == AH_EVENT_VMGT_IP_CHANGE) ? "mgtx.y IP chg" : \
			 ((eid) == AH_EVENT_BGD_IP_CHANGE) ? "bgd0.x IP chg" : \
			 ((eid) == AH_EVENT_VMGT_SUBNET_CHANGE) ? "mgtx.y subnet chg" : \
			 ((eid) == AH_EVENT_IPV6_CHANGE) ? "mgt0 IPV6 chg" : \
			 ((eid) == AH_EVENT_ETHX_IPV6_CHANGE) ? "ethx IPV6 chg" : \
			 ((eid) == AH_EVENT_TUNNEL_IPV6_CHANGE) ? "tunnelx IPV6 chg" : \
			 ((eid) == AH_EVENT_PPPX_IPV6_CHANGE) ? "pppx IPV6 chg" :  \
			 ((eid) == AH_EVENT_USBX_IPV6_CHANGE) ? "usbx IPV6 chg" :    \
			 ((eid) == AH_EVENT_VAP_IPV6_CHANGE) ? "wifix.y IPV6 chg" : \
			 ((eid) == AH_EVENT_VMGT_IPV6_CHANGE) ? "mgtx.y IPV6 chg" : \
			 ((eid) == AH_EVENT_BGD_IPV6_CHANGE) ? "bgd0.x IPV6 chg" : \
			 ((eid) == AH_EVENT_VMGT_IPV6_SUBNET_CHANGE) ? "mgtx.y IPV6 subnet chg" : \
			 ((eid) == AH_EVENT_DHCPV6C_REQUEST) ? "dhcpv6 request" : \
			 ((eid) == AH_EVENT_IP_VERSION_PREFERENCE) ? "ip version preference chg" : \
			 ((eid) == AH_EVENT_VMGT_IF_REMOVAL) ? "mgtx.y interface removal" : \
			 ((eid) == AH_EVENT_VAP_SSID_CHANGE) ? "ssid map to vap changed" : \
			 ((eid) == AH_EVENT_SSID_CHANGE) ? "ssid create/destory" : \
			 ((eid) == AH_EVENT_NMSSVR_CHG) ? "HM server chg" : \
			 ((eid) == AH_EVENT_NMSSVR_CHG_MANUAL) ? "HM server chg manual" : \
			 ((eid) == AH_EVENT_GW_CHANGE) ? "mgt0 GW chg" : \
			 ((eid) == AH_EVENT_AUTH_SYNC) ? "sync STAs" : \
			 ((eid) == AH_EVENT_AUTH_JOIN) ? "STA join" : \
			 ((eid) == AH_EVENT_AUTH_LEAVE) ? "STA leave" : \
			 ((eid) == AH_EVENT_CWP_USER_JOIN) ? "cwp user join" : \
			 ((eid) == AH_EVENT_CWP_AUTH_FAIL) ? "cwp auth failed" : \
			 ((eid) == AH_EVENT_CWP_LOGOFF) ? "cwp log off" : \
			 ((eid) == AH_EVENT_RESP_CWP_LOGOFF) ? "auth respond log off" : \
			 ((eid) == AH_EVENT_RESP_CWP_USER_JOIN) ? "cwp user join response" : \
			 ((eid) == AH_EVENT_AUTH_QUERY_SESSION_INFO) ? "query session info from auth" : \
			 ((eid) == AH_EVENT_AUTH_QUERY_STATION_INFO) ? "query station info from auth" : \
			 ((eid) == AH_EVENT_AUTH_RESP_SESSION_INFO) ? "auth respond session info" : \
			 ((eid) == AH_EVENT_AUTH_RESP_STATION_INFO) ? "auth respond session info" : \
			 ((eid) == AH_EVENT_AUTHDCD_REQUEST) ? "auth request dcd" : \
			 ((eid) == AH_EVENT_DCDAUTH_RESPONSE) ? "dcd respond auth" : \
			 ((eid) == AH_EVENT_AUTHDCD_ADD_MAC_OBJECT_ELEMENT) ? "notify dcd that have added a new element to mac-object" : \
			 ((eid) == AH_EVENT_AUTHDCD_REMOVE_MAC_OBJECT_ELEMENT) ? "notify dcd that mac-object's element be removed" : \
			 ((eid) == AH_EVENT_RM_CACHE) ? "need add cache" : \
			 ((eid) == AH_EVENT_HIVE_RECEIVE_UPDATE_CACHE) ? "new format message to add cache" : \
			 ((eid) == AH_EVENT_XMT_RM_CACHE) ? "xmt rm cache" : \
			 ((eid) == AH_EVENT_RM_NB_JOIN) ? "rm nbr join" : \
			 ((eid) == AH_EVENT_USER_PROFILE_VLAN_CHG) ? "user profile VLAN or VLAN group changed" : \
			 ((eid) == AH_EVENT_VLAN_GROUP_RANGE_CHG) ? "VLAN group range changed" : \
			 ((eid) == AH_EVENT_REPLY_NODE_FOR_STA) ? "reply node for station from AMRP" : \
			 ((eid) == AH_EVENT_RADIUS_VLAN_CHG) ? "VLAN changed from RADIUS" : \
			 ((eid) == AH_EVENT_DCD_LOCK_RADIOS) ? "lock radio" : \
			 ((eid) == AH_EVENT_DCD_UNLOCK_RADIOS) ? "unlock radio" : \
			 ((eid) == AH_EVENT_SYS_REBOOT) ? "sys reboot" : \
			 ((eid) == AH_EVENT_CTL_PKT_CRYPT_REQUEST) ? "ctrl-pkt-encrypt Q" : \
			 ((eid) == AH_EVENT_CTL_PKT_CRYPT_RESPONSE) ? "ctrl-pkt-encrypt P" : \
			 ((eid) == AH_EVENT_DHCPS_CFG_CHG) ? "dhcp srv cfg" : \
			 ((eid) == AH_EVENT_RADIUSD_NOTIFY) ? "radiusd event" : \
			 ((eid) == AH_EVENT_RADIUS_USER_NOTIFY) ? "RADIUS user notify" : \
			 ((eid) == AH_EVENT_DNS_CFG_CHG) ? "dns srv cfg" : \
			 ((eid) == AH_EVENT_DHCPC_REQUEST) ? "request dhcpc action" : \
			 ((eid) == AH_EVENT_RM_NBR_UPDATE) ? "acsp nbr update" : \
			 ((eid) == AH_EVENT_RM_PORT_CHG) ? "rm port cfg" : \
			 ((eid) == AH_EVENT_SYS_READY) ? "system ready" : \
			 ((eid) == AH_EVENT_L3_CONFIG) ? "L3 configuration" : \
			 ((eid) == AH_EVENT_CLEAR_TUN) ? "clear gre-tunnel" : \
			 ((eid) == AH_EVENT_AMRP_DEL_STA) ? "amrp-del-sta" : \
			 ((eid) == AH_EVENT_AMRP_ADD_STA) ? "amrp-add-sta" : \
			 ((eid) == AH_EVENT_AMRP_VPN_TIMEOUT) ? "amrp-vpn-timeout" : \
			 ((eid) == AH_EVENT_AMRP_PORTAL_CHG) ? "amrp-portal-chg" : \
			 ((eid) == AH_EVENT_RADIUS_DOS_CFG) ? "RADIUS DOS" : \
			 ((eid) == AH_EVENT_CAPWAP_IDP_PUSH) ? "capwap_idp_push" : \
			 ((eid) == AH_EVENT_CAPWAP_IDP_PULL) ? "capwap_idp_pull" : \
			 ((eid) == AH_EVENT_CAPWAP_IDP_PUSH_ALL) ? "capwap_idp_pull_all" : \
			 ((eid) == AH_EVENT_CAPWAP_CONNECT) ? "capwap connect" : \
			 ((eid) == AH_EVENT_CAPWAP_DISCONNECT) ? "capwap disconnect" : \
			 ((eid) == AH_EVENT_AMRP_METRIC_UPDATE) ? "amrp metric update" : \
			 ((eid) == AH_EVENT_STATISTICAL_SEND_DCD) ? "statistics send event to dcd" : \
			 ((eid) == AH_EVENT_STATISTICAL_RECV_DCD) ? "statistics recv event to dcd" : \
			 ((eid) == AH_EVENT_STATISTICAL_SEND_AUTH) ? "statistics send event to auth" : \
			 ((eid) == AH_EVENT_STATISTICAL_RECV_AUTH) ? "statistics recv event to auth" : \
			 ((eid) == AH_EVENT_STATISTICAL_SEND_AMRP) ? "statistics send event to amrp" : \
			 ((eid) == AH_EVENT_STATISTICAL_RECV_AMRP) ? "statistics recv event to amrp" : \
			 ((eid) == AH_EVENT_BRIDGE_STATUS_CHANGE) ? "interface eth0 bridge status changed" : \
			 ((eid) == AH_EVENT_UDPDATE_ALG_INFO) ? "update alg info" : \
			 ((eid) == AH_EVENT_CAPWAP_TRAP) ? "send trap to CAPWAP" : \
			 ((eid) == AH_EVENT_REBOOT_FAILED) ? "scd reboot failed event" : \
			 ((eid) == AH_EVENT_DELTA_CONFIG_FINISH) ? "HM delta configure finished" : \
			 ((eid) == AH_EVENT_HOSTNAME_CHG) ? "hostname changed" : \
			 ((eid) == AH_EVENT_CAPWAP_CLIENT_CHG) ? "Capwap client status changed" : \
			 ((eid) == AH_EVENT_WEBUI_INFORM_CAPWAP_SRV) ? "WebUI inform capwap server status change" : \
			 ((eid) == AH_EVENT_MONITOR_DEBUG_CHANGE) ? "monitor debug changed" : \
			 ((eid) == AH_EVENT_TRACK_IP_ACTIONS) ? "track ip action trigger" : \
			 ((eid) == AH_EVENT_TRACK_IP_STAT_QUERY) ? "track ip actions stat query" : \
			 ((eid) == AH_EVENT_WAN_IF_TEST_CFG_CHANGE) ? "track group cfg used for wan test change" : \
			 ((eid) == AH_EVENT_CAPTURE_START) ? "packet capture start" : \
			 ((eid) == AH_EVENT_CAPTURE_DONE) ? "packet capture done" : \
			 ((eid) == AH_EVENT_MESHFO_CHANGE) ? "mesh failover change" : \
			 ((eid) == AH_EVENT_POWER_CONFIG_CHANGED) ? "power changed" : \
			 ((eid) == AH_EVENT_DYNAMIC_AUTH_CHG) ? "dynamic auth chg" : \
			 ((eid) == AH_EVENT_MGT0_VLAN_CHG) ? "mgt0 vlan chg" : \
			 ((eid) == AH_EVENT_CFG_VER_CHANGED) ? "config version changed" : \
			 ((eid) == AH_EVENT_WEBUI_CLNT_PORTAL_CHGED) ? "webui client portal changed" : \
			 ((eid) == AH_EVENT_QUERY_ACTIVE_WEB_DIR) ? "query active web directory" : \
			 ((eid) == AH_EVENT_RESP_ACTIVE_WEB_DIR) ? "reply active web directory" : \
			 ((eid) == AH_EVENT_WEBUI_CLNT_HOSTNAME_CHGED) ? "webui client host changed" : \
			 ((eid) == AH_EVENT_SYSLOGD_CONF_UPDATE) ? "update syslogd conf" : \
			 ((eid) == AH_EVENT_TRAPD_CONF_UPDATE) ? "update trapd conf" : \
			 ((eid) == AH_EVENT_WEB_SRV_RESTART) ? "web server restart" : \
			 ((eid) == AH_EVENT_CLI_SRV_RESTART) ? "cli server restart" : \
			 ((eid) == AH_EVENT_ASM_BEHAVIOR_REPORT) ? "asm problematic behavior report" : \
			 ((eid) == AH_EVENT_ASM_BEHAVIOR_SUBSCRIBE) ? "asm behavior subscribe" : \
			 ((eid) == AH_EVENT_ASM_PROCESS_RESULT) ? "asm behavior process report" : \
			 ((eid) == AH_EVENT_ASM_ACTION_DEAUTH) ? "asm deauth action" : \
			 ((eid) == AH_EVENT_ASM_ACTION_LOCALBAN) ? "asm local-ban action" : \
			 ((eid) == AH_EVENT_ASM_BEHAVIOR_RECONNECTING) ? "asm behavior reconnect" : \
			 ((eid) == AH_EVENT_STA_OWNER_QUERY_REQ) ? "station owner query req" : \
			 ((eid) == AH_EVENT_STA_OWNER_QUERY_RESP) ? "station owner query resp" : \
			 ((eid) == AH_EVENT_LOCATION_TRACK_IN) ? "capwap query location track request" : \
			 ((eid) == AH_EVENT_LOCATION_TRACK_OUT) ? "capwap query location track response" : \
			 ((eid) == AH_AUTH_REGEN_AUTO_PPSK) ? "re-gen auto ppsk for user-group" : \
			 ((eid) == AH_AUTH_REGEN_ALL_AUTO_PPSK) ? "re-gen all auto ppsk" : \
			 ((eid) == AH_EVENT_PKT_CPT_STAT_QUERY) ? "capwap query packet caputre request" : \
			 ((eid) == AH_EVENT_PKT_CPT_STAT_RESP) ? "capwap query packet caputre response" : \
			 ((eid) == AH_EVENT_CAPWAP_EXEC_CLI) ? "capwap server execute cli" : \
			 ((eid) == AH_EVENT_ITK_NOTIFY) ? "it-tool-kit notify event to capwap-client" : \
			 ((eid) == AH_EVENT_SCHD_SUB_REF) ? "sub one schedule ref count" : \
			 ((eid) == AH_EVENT_CAPWAP_REQUEST_DCD) ? "CAPWAP send request to DCD" : \
			 ((eid) == AH_EVENT_DCD_RESPONE_CAPWAP) ? "DCD send response to CAPWAP" : \
			 ((eid) == AH_EVENT_STA_STATS) ? "station statistics record" : \
			 ((eid) == AH_EVENT_INTERFACE_MAP_IN) ? "capwap query interface map info request" : \
			 ((eid) == AH_EVENT_INTERFACE_MAP_OUT) ? "capwap query interface map info response" : \
			 ((eid) == AH_EVENT_TUNNEL_SI_CHANGE) ? "vpn tunnel route event" : \
			 ((eid) == AH_EVENT_AMRP_ETH_INFO) ? "amrp interface ethx info" : \
			 ((eid) == AH_EVENT_TUNNEL_HB_CHANGE) ? "vpn tunnel heartbeat change" : \
			 ((eid) == AH_EVENT_ETH_ALLOW_VLAN_CHG) ? "eth allowed vlan change" : \
			 ((eid) == AH_EVENT_DCD_MGT0_HIVE_CHG) ? "mgt0 bind hive changed" : \
			 ((eid) == AH_EVENT_CURR_CFG_VALID_CHG) ? "current config valid status changed" : \
			 ((eid) == AH_EVENT_USR_IP_VALID_CHG) ? "mgt0 user IP valid status changed" : \
			 ((eid) == AH_EVENT_CAPWAP_REQ_VPN) ? "capwap request vpn" : \
			 ((eid) == AH_EVENT_VPN_RESP_CAPWAP) ? "vpn respone capwap" : \
			 ((eid) == AH_EVENT_RADIO_LOAD_QUERY) ? "nbr-radio-load-query" : \
			 ((eid) == AH_EVENT_HDD_NBR_INFO) ? "hdd-nbr-info" : \
			 ((eid) == AH_EVENT_RADIUS_TEST_REQUEST) ? "RADIUS/LDAP test request" : \
			 ((eid) == AH_EVENT_RADIUS_TEST_RESPONSE) ? "RADIUS/LDAP test response" : \
			 ((eid) == AH_EVENT_REMOTE_SNIF_DATA_PORT_CHG) ? "Remote sniffer data port changed" : \
			 ((eid) == AH_EVENT_TV_WEBUI_REQ_CAPWAP) ? "WebUI tv no found to HM" : \
			 ((eid) == AH_EVENT_TV_CAPWAP_REQ_WEBUI) ? "HM tv found to WebUI" : \
			 ((eid) == AH_EVENT_STA_OS_INFO) ? "sta os info" : \
			 ((eid) == AH_EVENT_MB_ALLOC_REQUEST) ? "mb alloc request" : \
			 ((eid) == AH_EVENT_MB_ALLOC_RESPONSE) ? "mb alloc response" : \
			 ((eid) == AH_EVENT_RT_STA_UPDATE) ? "rt_sta update" : \
			 ((eid) == AH_EVENT_FE_ALG_CFG_CHG) ? "FE ALG configuration changed" : \
			 ((eid) == AH_EVENT_RADIUS_LDAP_TREE_REQ) ? "LDAP tree query request" : \
			 ((eid) == AH_EVENT_RADIUS_LDAP_TREE_RESP) ? "LDAP tree query response" : \
			 ((eid) == AH_EVENT_RADIUS_AD_RETRIVE_REQ) ? "AD retrieve info request" : \
			 ((eid) == AH_EVENT_RADIUS_AD_RETRIVE_RESP) ? "AD retrieve info response" : \
			 ((eid) == AH_EVENT_RADIUS_QUERY_AD_INFO_REQ) ? "query ad info request" : \
			 ((eid) == AH_EVENT_RADIUS_QUERY_AD_INFO_RESP) ? "query ad info response" : \
			 ((eid) == AH_EVENT_DCM_ENABLE) ? "dcm enable" : \
			 ((eid) == AH_EVENT_DCM_DISABLE) ? "dcm disable" : \
			 ((eid) == AH_EVENT_DCM_SND_PKT) ? "dcm send packet to CAPWAP" : \
			 ((eid) == AH_EVENT_AMRP_DA_CHG) ? "DA change" : \
			 ((eid) == AH_EVENT_IDP_DA_PULL) ? "pull from DA" : \
			 ((eid) == AH_EVENT_INFORM_PM_MONITOR) ? "Inform pm monitor module dynamic" : \
			 ((eid) == AH_EVENT_VPN_TUNNEL_CHANGE) ? "VPN tunnel status change" : \
			 ((eid) == AH_EVENT_DEFAULT_ROUTE_CHANGE) ? "default gateway route change" : \
			 ((eid) == AH_EVENT_INTF_DEFAULT_ROUTE_CHANGE) ? "interface default gateway route change" : \
			 ((eid) == AH_EVENT_TUN_EXCEPTION_CHANGE) ? "tunnel exception list change" : \
			 ((eid) == AH_EVENT_TUN_EXCEPTION_ACTION_CHANGE) ? "user profile tunnel exception change" : \
			 ((eid) == AH_EVENT_TUN_EXCEPTION_PBR_HOSTNAME_IP_LIST_CHANGE) ? "hostname ip list exception change" : \
			 ((eid) == AH_EVENT_TUN_EXCEPTION_PBR_HOSTNAME_CHANGE) ? "tun excep pbr hostname change" : \
			 ((eid) == AH_EVENT_DNS_PROXY_ADD_DEL_RT) ? "DNS proxy require add-del route" : \
			 ((eid) == AH_EVENT_NAAS_REQUEST) ? "Get NAAS request from CAPWAP" : \
			 ((eid) == AH_EVENT_NAAS_RESPONSE) ? "Send NAAS resonse to CAPWAP" : \
			 ((eid) == AH_EVENT_VPN_REPORT_SND_FILE) ? "vpn report export file request" : \
			 ((eid) == AH_EVENT_VPN_REPORT_RESPONCE_CAPWAP) ? "vpn report responce capwap" : \
			 ((eid) == AH_EVENT_VPN_REPORT_REQUEST_CAPWAP) ? "vpn report send to capwap" : \
			 ((eid) == AH_EVENT_VPN_REPORT_SAVE_DATA_2FLASH) ? "vpn report save data to flash" : \
			 ((eid) == AH_EVENT_L7D_APP_REPORT_READY_CAPWAP) ? "application report notification capwap" : \
			 ((eid) == AH_EVENT_L7D_APP_REPROT_UPLOADED) ? "application report upload ok" : \
			 ((eid) == AH_EVENT_L7D_APP_REPROT_UPLOADED_FAILED) ? "application report upload failed" : \
			 ((eid) == AH_EVENT_L7D_APPID) ? "L7D internal events" : \
			 ((eid) == AH_EVENT_L7D_APP_SIG_IMAGE_READY) ? "cli report sned to l7D signal file is download finished" : \
			 ((eid) == AH_EVENT_BRD_WEBSEC_OPENDNS_CFG_CHANGE) ? "web security opendns config change notify" : \
			 ((eid) == AH_EVENT_CAPWAP_REQUEST_L7D) ? "HM request to L7D" : \
			 ((eid) == AH_EVENT_L7D_RESPONSE_CAPWAP) ? "L7D reponse to HM request" : \
			 ((eid) == AH_EVENT_L7D_SIGNATURE_VERSION_NOTIFY) ? "L7D notifies signature version to HM" : \
			 ((eid) == AH_EVENT_VOIP_QOS_STATUS_UPDATE) ? "voip qos policing status update" : \
			 ((eid) == AH_EVENT_DCD_LOCK_LAN) ? "NAAS LOCK LAN PORT" : \
			 ((eid) == AH_EVENT_DCD_UNLOCK_LAN) ? "NAAS UNLOCK LAN PORT" : \
			 ((eid) == AH_EVENT_RMC_QUERY_USER) ? "query rmc user" : \
			 ((eid) == AH_EVENT_RMC_REPONSE_USER) ? "response rmc user" : \
			 ((eid) == AH_EVENT_VPN_DAEMON_RESTART) ? "VPN module restart" : \
			 ((eid) == AH_EVENT_BRD_RESTART) ? "BRD module restart" : \
			 ((eid) == AH_EVENT_BRD_PPPOE_REQUEST) ? "pppoe request" : \
			 ((eid) == AH_EVENT_PPSK_RAD_SRV_CHG_DHCP) ? "DHCP options for ppsk/radius server changed" : \
			 ((eid) == AH_EVENT_IDP_AP_CLF_HM_SEND) ? "HM Send AP classify info to AP" : \
			 ((eid) == AH_EVENT_IDP_AP_CLF_DA_SEND) ? "DA Send msg to HM" : \
			 ((eid) == AH_EVENT_PSE_INFO_REPORT_REQUEST) ? "CAPWAP Request to send normal PSE info to HM" : \
			 ((eid) == AH_EVENT_PSE_INFO_REPORT_RESPOND) ? "Respond CAPWAP to send normal PSE info to HM" : \
			 ((eid) == AH_EVENT_BGD_ENABLE_CHANGE) ? "BGD enable change" : \
			 ((eid) == AH_EVENT_BGD_NOTIFY) ? "BGD notify event" : \
			 ((eid) == AH_EVENT_VLAN_SCAN_NOTIFY) ? "VLAN scan notify" : \
			 ((eid) == AH_EVENT_PM_RESTART_ROUTING_DAEMON) ? "PM restart routing daemon" : \
			 ((eid) == AH_EVENT_FIRMWARE_UPDATE) ? "firmware update notify" : \
			 ((eid) == AH_EVENT_DHCPC_DEFAULT_ROUTE_NOTIFY) ? "DHCP client default route notify" : \
			 ((eid) == AH_EVENT_DHCPC_DNS_UPDATE) ? "DHCP client DNS update" : \
			 ((eid) == AH_EVENT_MGTXY_CHANGE) ? "add or delete mgt0.x" : \
			 ((eid) == AH_EVENT_AMRP_REALM_ID_CHANGE) ? "AMRP realm id change" : \
			 ((eid) == AH_EVENT_AMRP_BDD) ? "AMRP_KNOWN_BDD" : \
			 ((eid) == AH_EVENT_AMRP_MYBDD_CHG) ? "AMRP mybdd change" : \
			 ((eid) == AH_EVENT_OTP_RESPONCE_CAPWAP) ? "deviec responce capwap to HM for OTP" : \
			 ((eid) == AH_EVENT_OTP_REQUEST_CAPWAP) ? "HM send capwap device for OTP" : \
			 ((eid) == AH_EVENT_OTP_CWP) ? "CWP send password to OTP" : \
			 ((eid) == AH_EVENT_IPFW_CLEAR_NETWORKS_SESSION) ? "IPFW clear sessions for specified networks" : \
			 ((eid) == AH_EVENT_IPFW_CLEAR_MARKED_SESSION) ? "IPFW clear sessions for specified mark" : \
			 ((eid) == AH_EVENT_DCDAUTH_PPSK_RESPONSE) ? "dcd send PPSK config" : \
			 ((eid) == AH_EVENT_MDM_PASSED_REQ) ? "set MDM passed" : \
			 ((eid) == AH_EVENT_MDM_PASSED_RESP) ? "set MDM passed done" : \
			 ((eid) == AH_EVENT_RADSEC_CERT_CREATION_REQ) ? "RadSec cert creation request" : \
			 ((eid) == AH_EVENT_RADSEC_CERT_CREATION_RESP) ? "RadSec cert creation response" : \
			 ((eid) == AH_EVENT_RADSEC_NOTIFY) ? "RadSec event" : \
			 ((eid) == AH_EVENT_RADSEC_CERT_STATUS) ? "RadSec cert status notification event" : \
			 ((eid) == AH_EVENT_RADSEC_CERT_RENEW_RES) ? "RadSec cert renew result event" : \
			 ((eid) == AH_EVENT_CAPWAP_REQ_BGD) ? "CAPWAP query BGD" : \
			 ((eid) == AH_EVENT_BGD_RESP_CAPWAP) ? "BGD respond to CAPWAP" : \
			 ((eid) == AH_EVENT_DNS_ALG_UPDATE_WG) ? "Update walled garden by DNS alg" : \
			 ((eid) == AH_EVENT_AMRP_REMOTE_STA_SET) ? "AMRP_R_STA_SET" : \
			 ((eid) == AH_EVENT_CONFROLBCK_ACSPSTATE_QUERY) ? "Config rollback query ACSP state" : \
			 ((eid) == AH_EVENT_BR_MODE_ENABLE_CHANGE) ? "BR mode enable change" : \
			 ((eid) == AH_EVENT_AUTH_STA_INFO) ? "AUTH notify sta info" : \
			 ((eid) == AH_EVENT_BGD_SERVICE_INFO) ? "BGD service info" : \
			 ((eid) == AH_EVENT_SWD_PORT_LINK_CHANGED) ? "switch port link status changed" : \
			 ((eid) == AH_EVENT_SWD_PORT_AN_DONE) ? "switch port auto-negotiation done" : \
			 ((eid) == AH_EVENT_SWD_FDB_ADDR_LEARNED) ? "switch FDB new address learned" : \
			 ((eid) == AH_EVENT_SWD_FDB_ADDR_AGED) ? "switch FDB entry aged" : \
			 ((eid) == AH_EVENT_SWD_FDB_ADDR_NOTIFY) ? "FDB entry learned or aged" : \
			 ((eid) == AH_EVENT_SWD_LOCK_VLAN) ? "SWD lock vlan except mgt0's" : \
			 ((eid) == AH_EVENT_SWD_UNLOCK_VLAN) ? "SWD unlock vlan" : \
			 ((eid) == AH_EVENT_SWD_PORT_CHANNEL_CHANGE) ? "switch Port channel change" : \
			 ((eid) == AH_EVENT_SWD_PORT_CHANNEL_ACTIVE_PORT_CHANGE) ? "switch Port channel active port change" : \
			 ((eid) == AH_EVENT_BLOCK_CALL) ? "Blocking call event" : \
			 ((eid) == AH_EVENT_BLOCK_CALL_REPLY) ? "Blocking call reply" : \
			 ((eid) == AH_EVENT_REG_SERVICE) ? "config dynamic server" : \
			 ((eid) == AH_EVENT_INFO_SERVICE) ? "receive dynamic server infomation" : \
			 ((eid) == AH_EVENT_REQ_SERVICE) ? "request dynamic server infomation" : \
			 ((eid) == AH_EVENT_QUERY_SERVICE) ? "query dynamic server infomation" : \
			 ((eid) == AH_EVENT_RADSEC_RADIUS_STARTUP) ? "local RADIUS startup notification event" : \
			 ((eid) == AH_EVENT_SWD_CAPWAP_REQUEST) ? "CAPWAP send request to SWD" : \
			 ((eid) == AH_EVENT_SWD_CAPWAP_RESPONE) ? "SWD send response to CAPWAP" : \
			 ((eid) == AH_EVENT_SWD_IF_TYPE_CHANGE) ? "SWD send port mode change event" : \
			 ((eid) == AH_EVENT_SWD_VLAN_CHANGE_NOTIFY) ? "SWD send VLAN change event" : \
			 ((eid) == AH_EVENT_SWD_VLAN_LIST_CHANGE_NOTIFY) ? "SWD send VLAN list change event" : \
			 ((eid) == AH_EVENT_SWD_VLAN_PORT_CHANGE_NOTIFY) ? "SWD send port change vlan event" : \
			 ((eid) == AH_EVENT_SWD_VLAN_LIST_PORT_CHANGE_NOTIFY) ? "SWD send port change vlan list event" : \
			 ((eid) == AH_EVENT_SWD_VLAN_IF_RECOVER) ? "SWD send interface vlan recover event" : \
			 ((eid) == AH_EVENT_VPN_TUNNEL_NAT_POLICY_CFG) ? "tunnel nat policy cfg event" : \
			 ((eid) == AH_EVENT_STP_PORT_STATE) ? "STP port state change" : \
			 ((eid) == AH_EVENT_AUTH_SCHED_STAT_CHG) ? "change the schedule status disable/enable" : \
			 ((eid) == AH_EVENT_BRD_AUTH) ? "BRD get tunnel routes installed" : \
			 ((eid) == AH_EVENT_CAPWAP_REQUEST_USBNET_STATUS) ? "usbnet connection status request from HM" : \
			 ((eid) == AH_EVENT_CAPWAP_RESPONSE_USBNET_STATUS) ? "usbnet connection status response to HM" : \
			 ((eid) == AH_EVENT_BRD_USBMODEM_PRIMARY_WAN_NOTIFY) ? "usbmodem primary wan config" : \
			 ((eid) == AH_EVENT_UP_TUNNEL_POLICY_CHG) ? "user profile bind or unbind tunnel policy" : \
			 ((eid) == AH_EVENT_MDM_AW_PROC_COMPLIANT) ? "Process Compliant status for Airwatch" : \
			 ((eid) == AH_EVENT_VPN_TUNNEL_RENEW) ? "ipsec tunnel phase1 rekey" : \
			 ((eid) == AH_EVENT_AMRP_ONEWAY_TIMEOUT) ? "AMRP one-way neighbor timeout" : \
			 ((eid) == AH_EVENT_CHAN_SLT_ENABLE) ? "acsd channel selection enable" : \
			 ((eid) == AH_EVENT_BGSCAN_CFG) ? "bgscan config set" : \
			 ((eid) == AH_EVENT_ACSD_RESTART) ? "acsd restart" : \
			 ((eid) == AH_EVENT_ACSD_IF_CFG) ? "acsd if cfg" :  \
			 ((eid) == AH_EVENT_ACSD_SCAN_REQ) ? "acsd scan req" : \
			 ((eid) == AH_EVENT_ACSD_SCAN_DONE) ? "acsd scan done" :    \
			 ((eid) == AH_EVENT_ACSD_CCA_STATS_UPD) ? "acsd cca stats update" : \
			 ((eid) == AH_EVENT_HIVE_BROADCAST) ? "hive broadcast" : \
			 ((eid) == AH_EVENT_HIVE_BROADCAST_L2) ? "hive broadcast in L2" : \
			 ((eid) == AH_EVENT_HIVE_RECEIVE_CLEAR_CACHE) ? "hive broadcast receiver clear cache" : \
			 ((eid) == AH_EVENT_RDS_RESTART) ? "Restart radius server" : \
			 ((eid) == AH_EVENT_AUTH_ETH_IF_RESTART) ? "Restart ETH interface" : \
			 ((eid) == AH_EVENT_ACPP_QUERY_URL_INFO) ? "ACPP redirect url query" : \
			 ((eid) == AH_EVENT_ACPP_RESP_URL_INFO) ? "ACPP redirect url response" : \
			 ((eid) == AH_EVENT_ACPP_GRD_CHG) ? "Update walled garden for ACPP" : \
			 ((eid) == AH_EVENT_STATIC_ROUTE_CHANGE) ? "Static route change" : \
			 ((eid) == AH_EVENT_HAPD_UPDATE_UPP_CFG) ? "User Profile Policy changed" : \
			 ((eid) == AH_EVENT_RADSEC_PROXY_INFO_REQ) ? "RedSec get proxy info request" : \
			 ((eid) == AH_EVENT_RADSEC_PROXY_INFO_RESP) ? "RedSec get proxy info response" : \
			 ((eid) == AH_EVENT_TRAP) ? "Sent trap event" : \
			 ((eid) == AH_EVENT_RADSEC_IDM_CONNECT_LOST) ? "Lost the connection with ID Manager" : \
			 ((eid) == AH_EVENT_RADSEC_ELCT_GET_CDDT_INFO) ? "Arbiter get the candidate's election info" : \
			 ((eid) == AH_EVENT_CM_INFO) ? "Client Monitor info" : \
			 ((eid) == AH_EVENT_QUERY_IDM_PROXY) ? "notify auth to find dynamic server infomation" : \
			 ((eid) == AH_EVENT_CM_SHOW_INFO) ? "CLI show CM2.0 information" : \
			 ((eid) == AH_EVENT_CAVC_AP_CHANGE) ? "CAVC AP update" : \
			 ((eid) == AH_EVENT_CAVC_AP_TUNNEL_CREATE) ? "CAVC AP tunnel created" : \
			 ((eid) == AH_EVENT_CAVC_CLIENT_JOIN) ? "CAVC client join" : \
			 ((eid) == AH_EVENT_CAVC_CLIENT_LEAVE) ? "CAVC client leave" : \
			 ((eid) == AH_EVENT_CAVC_SW_MAC) ? "CAVC Switch MAC Addr" : \
			 ((eid) == AH_EVENT_ACL_USER_PROFILE_DEL) ? "ACL user-profile del" : \
			 ((eid) == AH_EVENT_AMRP_AEROHIVE_DEV) ? "Detect Aerohive Device" : \
			 ((eid) == AH_EVENT_DCD_IBEACON_CFG_CHANGE) ? "iBeacon config change" : \
			 ((eid) == AH_EVENT_DCD_IBEACON_USB_ATTACH_CHANGE) ? "iBeacon USB device attach/detach" : \
			 ((eid) == AH_EVENT_WPS_CMD_INFO) ? "notify wpa supplicant to execute cmd" : \
			 ((eid) == AH_EVENT_VRRP_MASTER_RENEW) ? "VRRP master route renew" : \
			 ((eid) == AH_EVENT_BRD_WAN_SM_NO_WAN) ? "TRACK WAN state" : \
			 ((eid) == AH_EVENT_NBRCOM_IP_UPDATE) ? "nbrcom update self IP address" : \
			 ((eid) == AH_EVENT_ADD_RMNBR_BRIDGE_BY_STA) ? "add roaming neighbour by station" : \
			 "n/a" );
}

//extern uint16_t ah_event_sub_mod_id;

//int ah_event_sendonly_init(uint16_t module_id, uint16_t sub_mod_id, pthread_t *event_tid)
//{
//	ah_event_sub_mod_id = sub_mod_id;
//	return ah_event_init(module_id, event_tid);
//}

void ah_event_end_ptimer(void)
{
	event_start_timer = FALSE;
	return;
}

static int ah_event_prio_init(uint16_t module_id, int creat_flag,
							  pthread_t *event_tid, pthread_t *hi_event_id,
							  pthread_t *lowest_event_id)
{
	pthread_t p_id;
	int rc;
	uint32_t mpi_port;

	ah_assert(creat_flag & (AH_LOW_EVT | AH_HIGH_EVT | AH_LOWEST_EVT));
	ah_assert(!ah_event_ctrl.initialized);
	ah_assert(   (AH_MOD_ID_MIN <= module_id)
				 && (module_id < AH_MOD_ID_MAX)
				 && (module_id < AH_EVENT_MAX_RCVRS));

	/* Initialize event control data */
	ah_event_ctrl.semid = ah_sem_create(AH_EVENT_SEM_ID, 1);
	if (ah_event_ctrl.semid == AH_INVALID_SEM_ID) {
		ah_err_old("failed to create semaphore for event lib\n");
		return -1;
	}

	ah_event_ctrl.event_shm = ah_shm_create(NULL, AH_EVENT_SHM_ID,
											sizeof(ah_event_shm_t));

	ah_event_ctrl.event[AH_LOWEST_EVENT_IDX].mpi_fd = -1;
	ah_event_ctrl.event[AH_LO_EVENT_IDX].mpi_fd = -1;
	ah_event_ctrl.event[AH_HI_EVENT_IDX].mpi_fd = -1;
	ah_event_ctrl.event[AH_BLOCK_EVENT_IDX].mpi_fd = -1;
	ah_event_ctrl.module_id = module_id;

	if (creat_flag & AH_LOWEST_EVT) {
		/* create event sub-thread */
		mpi_port = MPI_MOD2PID(module_id, AH_SUB_MOD_ID_LOWEST_EVENT);
		ah_event_ctrl.event[AH_LOWEST_EVENT_IDX].mpi_fd = ah_mpi_open(mpi_port);
		if (ah_event_ctrl.event[AH_LOWEST_EVENT_IDX].mpi_fd < 0) {
			ah_err_old("event lib: mpi open failed");
			goto clean_code;
		}
		rc = ah_event_start_subthread(&ah_event_ctrl, AH_LOWEST_EVENT_IDX, &p_id);
		if (rc < 0) {
			ah_err_old("ah_event_start_subthread failed, rc = %d, flag = %d",
					   rc, AH_LOWEST_EVT);
			goto clean_code;
		}

		if (lowest_event_id != NULL) {
			*lowest_event_id = p_id;
		}

	}

	if (creat_flag & AH_LOW_EVT) {
		/* create event sub-thread */
		mpi_port = MPI_MOD2PID(module_id, AH_SUB_MOD_ID_EVENT);
		ah_event_ctrl.event[AH_LO_EVENT_IDX].mpi_fd = ah_mpi_open(mpi_port);
		if (ah_event_ctrl.event[AH_LO_EVENT_IDX].mpi_fd < 0) {
			ah_err_old("event lib: mpi open failed");
			goto clean_code;
		}
		rc = ah_event_start_subthread(&ah_event_ctrl, AH_LO_EVENT_IDX, &p_id);
		if (rc < 0) {
			ah_err_old("ah_event_start_subthread failed, rc = %d, flag = %d",
					   rc, AH_LOW_EVT);
			goto clean_code;
		}

		if (event_tid != NULL) {
			*event_tid = p_id;
		}

	}

	if (creat_flag & AH_HIGH_EVT) {
		/* create event sub-thread */
		mpi_port = MPI_MOD2PID(module_id, AH_SUB_MOD_ID_HI_EVENT);
		ah_event_ctrl.event[AH_HI_EVENT_IDX].mpi_fd = ah_mpi_open(mpi_port);
		if (ah_event_ctrl.event[AH_HI_EVENT_IDX].mpi_fd < 0) {
			ah_err_old("event lib: mpi open failed");
			goto clean_code;
		}
		rc = ah_event_start_subthread(&ah_event_ctrl, AH_HI_EVENT_IDX, &p_id);
		if (rc < 0) {
			ah_err_old("ah_event_start_subthread failed, rc = %d, flag = %d",
					   rc, AH_HIGH_EVT);
			goto clean_code;
		}

		if (hi_event_id != NULL) {
			*hi_event_id = p_id;
		}

	}

	/* create blocking event channel */
	{
		mpi_port = MPI_MOD2PID(module_id, AH_SUB_MOD_ID_BLOCK_EVENT);
		ah_event_ctrl.event[AH_BLOCK_EVENT_IDX].mpi_fd = ah_mpi_open(mpi_port);
		if (ah_event_ctrl.event[AH_BLOCK_EVENT_IDX].mpi_fd < 0) {
			ah_err_old("event lib: block event mpi open failed");
			goto clean_code;
		}

		mpi_port = MPI_MOD2PID(module_id, AH_SUB_MOD_ID_BLOCK_REPLY);
		ah_event_ctrl.event[AH_BLOCK_REPLY_IDX].mpi_fd = ah_mpi_open(mpi_port);
		if (ah_event_ctrl.event[AH_BLOCK_REPLY_IDX].mpi_fd < 0) {
			ah_err_old("event lib: block reply mpi open failed");
			goto clean_code;
		}

	}

	ah_event_ctrl.initialized = TRUE;
	return 0;

clean_code:
	ah_event_ctrl.initialized = TRUE;
	ah_event_cleanup();
	return -1;
}

/************************************************************************
 * Initalize event lib
 *
 * Description:
 *      This function initialize event library.
 *
 * INPUT:
 *      Module_id - MPI module ID
 * OUTPUT:
 *      event_tid - the event sub thread tid is returned in event_tid if
 *                  event_tid is not NULL.
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_init(uint16_t module_id, pthread_t *event_tid)
{
	return ah_event_prio_init(module_id, AH_ALL_EVTS, event_tid, NULL, NULL);
}

/************************************************************************
 * Clean up event lib
 *
 * Description:
 *      This function clean up the event library. when call this function,
 *      we must not call any other event API.
 *
 * INPUT:
 *      None
 * OUTPUT:
 *      None
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_cleanup(void)
{
	int i;
	if (!ah_event_ctrl.initialized) {
		return 0;
	}

	ah_event_ctrl.initialized = FALSE;

	for (i = AH_LO_EVENT_IDX; i < AH_EVENT_IDX_MAX; ++i) {
		if (ah_event_ctrl.event[i].mpi_fd >= 0) {
			/* BLOCK REPLY only has channel, no thread */
			if (AH_BLOCK_REPLY_IDX != i) {
				ah_event_cleanup_subthread(i);
			}
			ah_mpi_close(ah_event_ctrl.event[i].mpi_fd);
			ah_event_ctrl.event[i].mpi_fd = -1;
		}
	}

	if (shmdt(ah_event_ctrl.event_shm) < 0) {
		ah_err_old("failed to detach event shm\n");
		return -1;
	}
	return 0;
}
/*
 * subscribe to kernel event
 */
int ah_kevent_subscribe(ah_kevent_t kevent_id, ah_kevent_proc_vector_t vector)
{
	int rc;
	ah_event_msg_t msg;
	int kevt_fd;

	ah_assert(NULL != vector);
	ah_assert(is_kevent_valid(kevent_id));

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	kevt_fd = ah_open(AH_MPI_DEV_NAME, O_RDWR);
	if (kevt_fd < 0) {
		ah_err_old("open device %s failed", AH_MPI_DEV_NAME);
		return -1;
	}

	msg.em_eid = kevent_id;
	msg.em_len = ah_event_ctrl.module_id; /* borrow this field for mid */

	rc = ioctl(kevt_fd, AH_KEVT_SUBSCRIBE, &msg);
	if (rc < 0) {
		ah_err_old("kevent ioctl faild: %s", strerror(errno));
		close(kevt_fd);
		return -1;
	}
	ah_close(kevt_fd);
	ah_event_ctrl.kevent_vector[kevent_id] = vector;
	return 0;
}

/*
 * unsubscribe kernel event
 */
int ah_kevent_unsubscribe(ah_kevent_t kevent_id)
{
	int rc;
	ah_event_msg_t msg;
	int kevt_fd;

	ah_assert(is_kevent_valid(kevent_id));
	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	kevt_fd = ah_open(AH_MPI_DEV_NAME, O_RDWR);
	if (kevt_fd < 0) {
		ah_err_old("open device %s failed\n", AH_MPI_DEV_NAME);
		return -1;
	}

	msg.em_eid = kevent_id;
	msg.em_len = ah_event_ctrl.module_id; /* borrow this field for mid */

	ah_event_ctrl.kevent_vector[kevent_id] = NULL;

	rc = ioctl(kevt_fd, AH_KEVT_UNSUBSCRIBE, &msg);
	if (rc < 0) {
		ah_err_old("kevent ioctl faild: %s\n", strerror(errno));
		close(kevt_fd);
		return -1;
	}
	ah_close(kevt_fd);
	return 0;
}

/************************************************************************
 * Subscribe to an event
 *
 * Description:
 * This function subscribes to an event.
 *
 * INPUT:
 *      event_id - event id to subscribe
 *      vector   - event processing function
 * OUTPUT:
 *      None
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_subscribe(ah_event_t event_id, ah_event_proc_vector_t vector)
{
	int event_debug;
	uint64_t event_map = 1;

	ah_assert(NULL != vector);
	ah_assert((event_id >= 0) && (event_id < AH_EVENT_MAX_NUM));

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	/* lock between processes */
	ah_sem_wait(ah_event_ctrl.semid);

	/* modify event receiver map */
	ah_event_ctrl.event_shm->rcvr_maps[event_id][(ah_event_ctrl.module_id) / AH_TOTAL_BITS_IN_WORD] |=
		(event_map << ah_event_ctrl.module_id % AH_TOTAL_BITS_IN_WORD);

	ah_sem_signal(ah_event_ctrl.semid);

	event_debug = ah_event_debug ||
				  (ah_event_ctrl.event_shm->rcvr_maps[event_id][(ah_event_ctrl.module_id) / AH_TOTAL_BITS_IN_WORD]
				   & AH_EVENT_DEBUG_MASK);
	ah_dbg_old(event_debug, "%s subscribed to event(%s)\n",
			   mid2name(ah_event_ctrl.module_id), ah_eventid_to_name(event_id));

	/* insert vector */
	ah_event_ctrl.event_vectors[event_id] = vector;

	return 0;
}

/************************************************************************
 * Unsubscribe to an event
 *
 * Description:
 * This function unsubscribes from an event. This API should only be called
 * when module exits.
 *
 * INPUT:
 *      event_id - event id to subscribe
 * OUTPUT:
 *      None
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_unsubscribe(ah_event_t event_id)
{
	int event_debug;

	ah_assert((event_id >= 0) && (event_id < AH_EVENT_MAX_NUM));

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	/* lock between processes */
	ah_sem_wait(ah_event_ctrl.semid);

	/* modify event receiver map */
	ah_event_ctrl.event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD] &=
		~(((ah_event_rcvr_map_t)1) << ah_event_ctrl.module_id % AH_TOTAL_BITS_IN_WORD);

	ah_sem_signal(ah_event_ctrl.semid);

	/* clear vector */
	ah_event_ctrl.event_vectors[event_id] = NULL;

	event_debug = ah_event_debug ||
				  (ah_event_ctrl.event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD]
				   & AH_EVENT_DEBUG_MASK);
	ah_dbg_old(event_debug, "%s un-subscribed to event(%s)\n",
			   mid2name(ah_event_ctrl.module_id), ah_eventid_to_name(event_id));

	return 0;
}

/************************************************************************
 * Verify that an event is subscribed
 *
 * Description:
 * This function verify that an event is subscribed.
 *
 * INPUT:
 *      event_id - event id to verify
 * OUTPUT:
 *      None
 * RETURN:
 *      1 - yes.
 *      0 - no.
 *************************************************************************/
int ah_event_verify(ah_event_t event_id)
{
	ah_assert((event_id >= 0) && (event_id < AH_EVENT_MAX_NUM));

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return 0;
	}

	/* check event receiver map */
	if (!(
			ah_event_ctrl.event_shm->rcvr_maps[event_id][(ah_event_ctrl.module_id) / AH_TOTAL_BITS_IN_WORD]
			& (((ah_event_rcvr_map_t)1) << ah_event_ctrl.module_id % AH_TOTAL_BITS_IN_WORD))) {
		ah_err_old("Module %s: event %s is not subscribed\n",
				   mid2name(ah_event_ctrl.module_id), ah_eventid_to_name(event_id));
		return 0;
	}

	return 1;
}

/************************************************************************
 * Send an event
 *
 * Description:
 * This function sends out an event.
 *
 * INPUT:
 *      event_id - event id to send
 *      size     - number of bytes of the event data
 *      data     - pointer to event data       -
 * OUTPUT:
 *      None
 * RETURN:
 *      0 - success.
 *      <0 - fail: return code is set to AH_EVENT_RC_SEND_INCOMPLETE for
 *                 partial send
 *************************************************************************/
int ah_event_send(ah_event_t event_id, uint32_t size, void *data)
{
	char *mpi_msg;
	ah_event_msg_t *event_msg;
	int rc = 0;
	int mod;
	int total_rc = 0;
	int event_debug;
	uint32_t mpi_port;
	int mpi_fd;
	uint32_t sub_mod_id;
	const char *mod_name = NULL;

	ah_assert((event_id >= 0) && (event_id < AH_EVENT_MAX_NUM));
	//ah_assert(size <= AH_EVENT_MAX_LEN);
	ah_assert(AH_MOD_ID_MAX <= AH_EVENT_MAX_RCVRS);

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	if ((size + sizeof(*event_msg)) >= AH_EVENT_MAX_LEN) {
		ah_err_old("send event \"%s\"(%d) with size %d, exceed the threshold %d, ohhhhhh!\n",
				   ah_eventid_to_name(event_id), event_id, size, AH_EVENT_MAX_LEN);
		return -1;
	}

	/* event debug control is in shm */
	event_debug = ah_event_debug ||
				  (ah_event_ctrl.event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD]
				   & AH_EVENT_DEBUG_MASK);

	/* Allocate MPI buffer */
	mpi_msg = ah_mpi_malloc(size + sizeof(*event_msg));
	if (NULL == mpi_msg) {
		ah_err_old("failed allocated mpi buffer\n");
		return -1;
	}

	ah_dbg_old(event_debug, "send event \"%s\", size=%u\n",
			   ah_eventid_to_name(event_id), size);

	/* Contruct event message */
	event_msg = (ah_event_msg_t *)mpi_msg;
	event_msg->em_eid = event_id;
	event_msg->em_len = size;
	event_msg->em_flag &= ~AH_EVT_FLAG_FROM_KERNEL;
	memcpy(event_msg->em_data, data, size);

	ah_dbg_old(event_debug, "event recv map: word %d:%x\n",
			   (ah_event_ctrl.module_id) / AH_TOTAL_BITS_IN_WORD,
			   ah_event_ctrl.event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD]);

	if (event_id < AH_EVENT_HIGH_PRIO_MIN) {
		sub_mod_id = AH_SUB_MOD_ID_EVENT;
		mpi_fd = ah_event_ctrl.event[AH_LO_EVENT_IDX].mpi_fd;
		if (mpi_fd < 0) {
			mpi_fd = ah_event_ctrl.event[AH_HI_EVENT_IDX].mpi_fd;
		}
	} else {
		sub_mod_id = AH_SUB_MOD_ID_HI_EVENT;
		mpi_fd = ah_event_ctrl.event[AH_HI_EVENT_IDX].mpi_fd;
		if (mpi_fd < 0) {
			mpi_fd = ah_event_ctrl.event[AH_LO_EVENT_IDX].mpi_fd;
		}
	}
	ah_assert(mpi_fd >= 0);

	/* mod 0 is reserved for event debug */
	for (mod = AH_MOD_ID_MIN; mod < AH_MOD_ID_MAX; ++mod) {
		if (  ah_event_ctrl.event_shm->rcvr_maps[event_id][mod / AH_TOTAL_BITS_IN_WORD]
			  & (((ah_event_rcvr_map_t)1) << (mod % AH_TOTAL_BITS_IN_WORD))) {
			/* Send to destination */
			ah_dbg_old(event_debug,
					   "Send event \"%s\" to module %s\n",
					   ah_eventid_to_name(event_id), mid2name(mod));

			mpi_port = MPI_MOD2PID(mod, sub_mod_id);
			rc = ah_mpi_sendto(mpi_fd,
							   mpi_msg,
							   size + sizeof(*event_msg),
							   mpi_port);
			if (rc <= 0) {
				mod_name = mid2name(mod);
				if (event_id < AH_EVENT_LOW_PRIO_MAX) {
					/* failed to send low priority event, warn log */
					ah_log_old(AH_LOG_WARNING,
							   "failed to send event \"%s\", dst module(%s), rc = %d\n",
							   ah_eventid_to_name(event_id), mod_name, rc);
				} else {
					/* failed to send high priority event, err log */
					ah_err_old("failed to send event \"%s\", dst module(%s), rc = %d\n",
							   ah_eventid_to_name(event_id), mod_name, rc);
				}
				total_rc = AH_EVENT_RC_SEND_INCOMPLETE;
			}
		}
	}

	ah_mpi_free(mpi_msg);

	return total_rc;
}

/************************************************************************
 * Set event debug
 *
 * Description:
 * This function set debug control for event
 *
 * INPUT:
 *      event_id - event id to debug
 *      enable   - enable/disable debug for the event
 * OUTPUT:
 *      None
 * RETURN:
 *      0 - success.
 *      <0 - fail.
 *************************************************************************/
int ah_event_set_debug(ah_event_t event_id, boolean enable)
{
	ah_event_shm_t *event_shm;

	ah_assert((event_id >= 0) && (event_id < AH_EVENT_MAX_NUM));

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	event_shm = ah_event_ctrl.event_shm;

	if (enable) {
		event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD] |= AH_EVENT_DEBUG_MASK;
	} else {
		event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD] &= ~AH_EVENT_DEBUG_MASK;
	}

	return 0;
}

int ah_event_dump_rcvr_map(void)
{
	int i = 0;

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	/* modify event receiver map */
	for (i = 0; i < AH_EVENT_MAX_NUM; i++) {
		ah_dbg_old(1, "event: %s, recv map: word %d:%x\n", ah_eventid_to_name(i),
				   ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD,
				   ah_event_ctrl.event_shm->rcvr_maps[i][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD]);
	}

	return 0;
}

/************************************************************************
 * Send a unicast message to the destination from block reply channel
 *
 * Description:
 * This function sends out an event.
 *
 * INPUT:
 *      event_id - event id to send
 *      size     - number of bytes of the event data
 *      data     - pointer to event data       -
 *     mpi_port  - destination
 * OUTPUT:
 *      None
 * RETURN:
 *      0 - success.
 *      <0 - fail: return code is set to AH_EVENT_RC_SEND_INCOMPLETE for
 *                 partial send
 *************************************************************************/
int ah_event_sendto(ah_event_t event_id, uint32_t size, void *data, uint32_t mpi_port, uint16_t seq)
{
	char *mpi_msg;
	ah_event_msg_t *event_msg;
	int rc = 0;
	int total_rc = 0;
	int event_debug;
	int mpi_fd;

	ah_assert((event_id >= 0) && (event_id < AH_EVENT_MAX_NUM));
	ah_assert(size <= AH_EVENT_MAX_LEN);
	ah_assert(AH_MOD_ID_MAX <= AH_EVENT_MAX_RCVRS);

	if (!ah_event_ctrl.initialized) {
		ah_err_old("Event lib not initialized");
		return -1;
	}

	/* event debug control is in shm */
	event_debug = ah_event_debug ||
				  (ah_event_ctrl.event_shm->rcvr_maps[event_id][ah_event_ctrl.module_id / AH_TOTAL_BITS_IN_WORD]
				   & AH_EVENT_DEBUG_MASK);

	/* Allocate MPI buffer */
	mpi_msg = ah_mpi_malloc(size + sizeof(*event_msg));
	if (NULL == mpi_msg) {
		ah_err_old("failed allocated mpi buffer\n");
		return -1;
	}

	ah_dbg_old(event_debug, "send event \"%s\", size=%u\n",
			   ah_eventid_to_name(event_id), size);

	/* Contruct event message */
	event_msg = (ah_event_msg_t *)mpi_msg;
	event_msg->em_eid = event_id;
	event_msg->em_len = size;
	event_msg->em_seq = seq;
	event_msg->em_flag &= ~AH_EVT_FLAG_FROM_KERNEL;
	memcpy(event_msg->em_data, data, size);

	/* use reply channel fd to send, so the receiver can send back reply to the right channel */
	mpi_fd = ah_event_ctrl.event[AH_BLOCK_REPLY_IDX].mpi_fd;
	ah_assert(mpi_fd >= 0);

	/* Send to destination */
	ah_dbg_old(event_debug,
			   "Send event \"%s\" to module %x\n",
			   ah_eventid_to_name(event_id), mpi_port);

	rc = ah_mpi_sendto(mpi_fd,
					   mpi_msg,
					   size + sizeof(*event_msg),
					   mpi_port);
	if (rc <= 0) {
		/* failed to send high priority event, err log */
		ah_err_old("failed to send event \"%s\", dst module(%x), rc = %d\n",
				   ah_eventid_to_name(event_id), mpi_port, rc);
		total_rc = AH_EVENT_RC_SEND_INCOMPLETE;
	}

	ah_mpi_free(mpi_msg);

	return total_rc;
}

/************************************************************************
 * Block receive a unicast message through block reply channel
 *
 * Description:
 * This function block receive an event.
 *
 * INPUT:
 *      len     - size of the buf
 *
 * OUTPUT:
 *      *buf -- event param for event id. NULL if not care
 *     *mpi_port - address of src
 *
 * RETURN:
 *      >0 - event id.
 *      <=0 - fail: return code is set to AH_EVENT_RC_SEND_INCOMPLETE for
 *                 partial send
 *************************************************************************/
#define AH_EVENT_RECVFROM_TIMEOUT 10    //seconds
int ah_event_recvfrom (char *buf, size_t len, uint32_t *mpi_port, uint16_t *seq)
{
	uint16_t   eid;
	int num = 0, rc = 0, readlen;
	ah_event_msg_t *event_msg;
	char *mpi_buf = NULL;

	/* initialize MPI buffer */
	mpi_buf = ah_mpi_malloc(AH_EVENT_MAX_LEN);
	if (NULL == mpi_buf) {
		ah_err_old("failed to malloc buffer for event lib");
		return 0;
	}

	do {
		rc = ah_mpi_recvfrom(ah_event_ctrl.event[AH_BLOCK_REPLY_IDX].mpi_fd, mpi_buf, AH_EVENT_MAX_LEN, mpi_port);
		if (rc < 0) {
			ah_err_old("failed to receive reply. rc = %d\n", rc);
			ah_mpi_free(mpi_buf);
			return rc;
		}
	} while (rc == 0 && ++num < AH_EVENT_RECVFROM_TIMEOUT);

	if (num >= AH_EVENT_RECVFROM_TIMEOUT) {
		ah_err_old("Receive reply timeout.");
		ah_mpi_free(mpi_buf);
		return 0;
	}

	readlen = rc;
	event_msg = (ah_event_msg_t *)mpi_buf;
	/* mpi msg is 4-byte aligned */
	ah_assert(event_msg->em_len + sizeof(*event_msg) <= readlen);

	eid = event_msg->em_eid;
	ah_assert( eid < AH_EVENT_MAX_NUM );
	*seq = event_msg->em_seq;

	if (buf && len >= event_msg->em_len) {
		memcpy(buf, event_msg->em_data, event_msg->em_len);
	}

	ah_mpi_free(mpi_buf);
	return eid;
}

int ah_event_block_send(ah_event_t event_id, uint32_t size, void *data, uint32_t dest_mod)
{
	uint32_t recv_mpi_port, mpi_port = MPI_MOD2PID(dest_mod, AH_SUB_MOD_ID_BLOCK_EVENT);
	ah_event_reply_t reply;
	int rc;
	static uint16_t seq = 0;
	uint16_t reply_seq;

	if (ah_event_sendto(event_id, size, data, mpi_port, ++seq) < 0) {
		ah_err_old("ah_event_sendto() failed to send to mod %s.\n", mid2name(dest_mod));
		return -1;
	}

	do {
		if ((rc = ah_event_recvfrom((char *)&reply, sizeof(reply), &recv_mpi_port, &reply_seq)) <= 0) {
			ah_err_old("ah_event_recvfrom failed to recv from mod %s.", mid2name(dest_mod));
			return rc;
		}
		if (seq != reply_seq) {
			ah_err_old("reply seq(%d) is different from the send seq(%d)\n", reply_seq, seq);
		}
	} while (seq != reply_seq);

	switch (rc) {
	case AH_EVENT_BLOCK_CALL_REPLY:
		if (reply.rc)
			ah_err_old("receive AH_EVENT_BLOCK_CALL_REPLY from %s, errno is %d",
					   mid2name(MPI_PID2MID(recv_mpi_port)), reply.rc);
		return reply.rc;
	default:
		ah_err_old("Unknown event(%s) received from %s", ah_eventid_to_name(rc),
				   mid2name(MPI_PID2MID(recv_mpi_port)));
		return -1;
	}
}


int ah_block_event_start_subthread(ah_block_event_proc_vector_t vector)
{
	pthread_t pid;
	ah_event_ctrl.block_event_vector = vector;
	if (ah_event_start_subthread(&ah_event_ctrl, AH_BLOCK_EVENT_IDX, &pid) < 0) {
		ah_err_old("Failed to start block event thread.");
		return -1;
	}
	return 0;
}

int ah_trap_send(uint trap_level, ah_trap_info_t *trap_info, const char *fmt, ...)
{
	va_list args;

	trap_info->level = trap_level;
	va_start(args, fmt);
	ah_vsnprintf(trap_info->desc, sizeof(trap_info->desc), fmt, args);
	va_end(args);

	return ah_event_send(AH_EVENT_TRAP, sizeof(ah_trap_info_t), trap_info);
}
