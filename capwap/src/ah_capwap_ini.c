/*********************************************************
AEROHIVE CONFIDENTIAL
Copyright [2006] - [2011] Aerohive Networks, Inc.
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
/*
   this file include all the global variable used for capwap
   zhanglei
   the copyrigh is for aerohive
 */
#include "ah_types.h"

#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_dtls.h"

ah_capwap_wtp_owninfo_t ah_capwap_info = {0};       /*capwap wtp info*/
ah_ipaddr46_t capwap_mgt0_ipv6;

pthread_t capwap_main_tid = 0;
/*capwap wtp parameter*/
ah_capwap_wtp_parameter_t ah_capwap_para = {
	{
		AH_CAPWAP_TIMER_DISCOVERY_DFT,
		AH_CAPWAP_TIMER_ECHO_DFT,
		AH_CAPWAP_TIMER_MAXDISCOVERY_DFT,
		AH_CAPWAP_TIMER_NEIGHBORDEAD_DFT,
		AH_CAPWAP_TIMER_SILENT_DFT,
		AH_CAPWAP_TIMER_WAITJOIN_DFT,
		AH_CAPWAP_TIMER_EVENT_DFT,
		AH_CAPWAP_TIMER_DTLS_CUT_DFT,
		AH_CAPWAP_TIMER_DTLS_CONN_DFT
	},
	{
		AH_CAPWAP_MAXDISCOVERY_COUNT_DFT,
		AH_CAPWAP_MAXRETRY_COUNT_DFT,
		AH_CAPWAP_DTLS_MAX_RETRY_DFT
	},
	{
		AH_CAPWAP_DTLS_ENABLE,
		AH_CAPWAP_DTLS_ENABLE,
		AH_DTLS_TOWN,
		AH_CAPWAP_DTLS_ACCEPT_BOOTSTRAP_ENABLE,
		{AH_CAPWAP_DTLS_SOCKET_UNAVLIB, AH_CAPWAP_DTLS_SOCKET_UNAVLIB}
	},
	AH_CAPWAP_ENABLE,
	AH_CAPWAP_DTLS_NEGOTIATION_ENABLE,
	AH_CAPWAP_CHOOSE_AC_INIT
}; /*capwap wtp parameter*/

/*the array for capwap client timer call back*/
ah_capwap_timerinfo_t ah_capwap_timer[] = {
	{AH_CAPWAP_TIMER_DISCOVERY,   AH_CAPWAP_TIMER_DISCOVERY_DFT,   ah_capwap_discovey_timer},
	{AH_CAPWAP_TIMER_ECHO,        AH_CAPWAP_TIMER_ECHO_DFT,        ah_capwap_echo_timer},
	{AH_CAPWAP_TIMER_MAXDISCOVERY, AH_CAPWAP_TIMER_MAXDISCOVERY_DFT, ah_capwap_maxdisco_timer},
	{AH_CAPWAP_TIMER_NEIGHBORDEAD, AH_CAPWAP_TIMER_NEIGHBORDEAD_DFT, ah_capwap_neigbor_timer},
	{AH_CAPWAP_TIMER_RESPONSE,    AH_CAPWAP_TIMER_RESPONSE_DFT,    ah_capwap_response_timer},
	{AH_CAPWAP_TIMER_RETRANSMIT,  AH_CAPWAP_TIMER_RESTRANSMIT_DFT, ah_capwap_retransmit_timer},
	{AH_CAPWAP_TIMER_SILENT,      AH_CAPWAP_TIMER_SILENT_DFT,      ah_capwap_silent_timer},
	{AH_CAPWAP_TIMER_WAITJOIN,    AH_CAPWAP_TIMER_WAITJOIN_DFT,    ah_capwap_waitjoin_timer},
	{AH_CAPWAP_TIMER_IDLE,        AH_CAPWAP_TIMER_IDLE_DFT,        ah_capwap_idle_timer},
	{AH_CAPWAP_TIMER_EVENT,       AH_CAPWAP_TIMER_EVENT_DFT,       ah_capwap_event_timer},
	{AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NONE_DFT,        ah_cpawpa_none_timer},
	{AH_CAPWAP_TIMER_DTLS_CONN,   AH_CAPWAP_TIMER_DTLS_CONN_DFT,   ah_capwap_dtls_conn_timer},
	{AH_CAPWAP_TIMER_DTLS_CUT,    AH_CAPWAP_TIMER_DTLS_CUT_DFT,    ah_capwap_dtls_disconn_timer}
};

/*the array for capwap client state change to do something*/
ah_capwap_state_client_chg_t ah_capwap_fsm[] = {
	{AH_CAPWAP_START,      AH_CAPWAP_WAIT_CLI,         AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NONE,        ah_capwap_start},
	{AH_CAPWAP_GET_HOST_IP, AH_CAPWAP_EVENT_NONE,       AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NONE,        ah_capwap_get_host_ip},
	{AH_CAPWAP_GET_NMS_IP, AH_CAPWAP_EVENT_NONE,       AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NONE,        ah_capwap_get_nms_ip},
	{AH_CAPWAP_IDLE,       AH_CAPWAP_EVENT_NONE,       AH_CAPWAP_TIMER_IDLE,        AH_CAPWAP_TIMER_NONE,        ah_capwap_idle},
	{AH_CAPWAP_DISCOVERY,  AH_CAPWAP_WAIT_SND_PKT,     AH_CAPWAP_TIMER_MAXDISCOVERY, AH_CAPWAP_TIMER_DISCOVERY,   ah_capwap_waitsnd},
	{AH_CAPWAP_DISCOVERY,  AH_CAPWAP_SND_PKT,          AH_CAPWAP_TIMER_DISCOVERY,   AH_CAPWAP_TIMER_MAXDISCOVERY, ah_capwap_dscav_snd},
	{AH_CAPWAP_DISCOVERY,  AH_CAPWAP_RCV_PKT,          AH_CAPWAP_TIMER_DISCOVERY,   AH_CAPWAP_TIMER_DISCOVERY,   ah_capwap_dscav_rcv},
	{AH_CAPWAP_DTLS_SETUP, AH_CAPWAP_DTLS_HANDSHAKE,   AH_CAPWAP_TIMER_DTLS_CONN,   AH_CAPWAP_TIMER_DISCOVERY,   ah_capwap_dtls_connect},
	{AH_CAPWAP_DTLS_TDWN,  AH_CAPWAP_DTLS_DISCONN,     AH_CAPWAP_TIMER_DTLS_CUT,    AH_CAPWAP_TIMER_NONE,        ah_capwap_dtls_disconnect},
	{AH_CAPWAP_SULKING,    AH_CAPWAP_EVENT_NONE,       AH_CAPWAP_TIMER_SILENT,      AH_CAPWAP_TIMER_NONE,        ah_capwap_sulking},
	{AH_CAPWAP_JOIN,       AH_CAPWAP_SND_PKT,          AH_CAPWAP_TIMER_WAITJOIN,    AH_CAPWAP_TIMER_NONE,        ah_capwap_join_snd},
	{AH_CAPWAP_JOIN,       AH_CAPWAP_RCV_PKT,          AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_WAITJOIN,    ah_capwap_join_rcv},
	{AH_CAPWAP_RUN,        AH_CAPWAP_CHG_EVENT_SND_PKT, AH_CAPWAP_TIMER_NEIGHBORDEAD, AH_CAPWAP_TIMER_NONE,        ah_capwap_chgfsm_snd},
	{AH_CAPWAP_RUN,        AH_CAPWAP_CHG_EVENT_RCV_PKT, AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NEIGHBORDEAD, ah_capwap_chgfsm_rcv},
	{AH_CAPWAP_RUN,        AH_CAPWAP_WAIT_SND_PKT,     AH_CAPWAP_TIMER_ECHO,        AH_CAPWAP_TIMER_ECHO,        ah_capwap_waitsnd},
	{AH_CAPWAP_RUN,        AH_CAPWAP_SND_PKT,          AH_CAPWAP_TIMER_NEIGHBORDEAD, AH_CAPWAP_TIMER_ECHO,        ah_capwap_run_snd},
	{AH_CAPWAP_RUN,        AH_CAPWAP_RCV_PKT,          AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NEIGHBORDEAD, ah_capwap_run_rcv},
	{AH_CAPWAP_RUN,        AH_CAPWAP_SND_EVENT,        AH_CAPWAP_TIMER_EVENT,       AH_CAPWAP_TIMER_NONE,        ah_capwap_event_snd},
	{AH_CAPWAP_RUN,        AH_CAPWAP_RCV_EVENT,        AH_CAPWAP_TIMER_EVENT,       AH_CAPWAP_TIMER_EVENT,       ah_capwap_event_rcv},
	{AH_CAPWAP_END,        AH_CAPWAP_EVENT_NONE,       AH_CAPWAP_TIMER_NONE,        AH_CAPWAP_TIMER_NONE,        ah_capwap_end}
};

void ah_capwap_get_member_num()
{
	/*get all capwap state number*/
	ah_capwap_para.capwap_number.fsm_chg_num = sizeof(ah_capwap_fsm) / sizeof(ah_capwap_fsm[0]);
	/*the totle number for timer */
	ah_capwap_para.capwap_number.timer_num = sizeof(ah_capwap_timer) / sizeof(ah_capwap_timer[0]);

	return;
}

/***************************************/
/*some debug function to check OpenSSL hung*/
char ah_capwap_dtls_connect_failed_number = 0;
char ah_capwap_dtls_read_status = 0;
/***************************************/


