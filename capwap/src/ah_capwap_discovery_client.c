#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_dbg_agent.h"
#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_capwap_tcp.h"

#include "htc/htc.h"

/***************************************************************************
 *
 * Function:  ah_capwap_waitsnd
 *
 * Purpose:   the callback function for capwap in waitsend state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:  need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_waitsnd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "Enter the wait send phase state: %s event: %s timer: %s\n",
			   ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent),
			   ah_capwap_get_timer_string(clienttimer));

	if (clientevent != AH_CAPWAP_WAIT_SND_PKT) {
		ah_err_old("CAPWAP waitting for send packet:event is error(event id:%d)!\n", clientevent);
		return -1;
	}

	if (ah_capwap_settimer(clienttimer, 0) == -1) {
		ah_err_old("CAPWAP waitting for send packet:set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
		return -1;
	}
	ah_dbg_old(capwap_info, "Leave the wait send phase state\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_sndpkt
 *
 * Purpose:   the capwap send packet function
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:  need handle the packet's buff
 *            buflen: the length for buff
 *            wtpstate: current wtp state
 *            pkttype:  send capwap packet type
 *
 * Output:     void
 *
 * Returns:    0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_sndpkt(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen,
					 uint32_t    wtpstate, uint32_t sdnpkttype)
{
#define AH_CAPWAP_HOST_IP_LEN 20
	uint32_t    packlen = 0;
	uint32_t    i = 0;
	char      hostip[AH_CAPWAP_HOST_IP_LEN];
	char      capwaptxpkt[AH_CAPWAP_BUF_LEN] = {'0'};/*the array to save the tx pkt*/

	if (clientstate != wtpstate || (clientevent != AH_CAPWAP_SND_PKT && clientevent != AH_CAPWAP_CHG_EVENT_SND_PKT)) {
		ah_log_old(AH_LOG_INFO, "CAPWAP send packet failed: state is %s or event is %s\n", ah_capwap_get_state_string(clientstate),
				   ah_capwap_get_event_string(clientevent));
		return -1;
	}
	/*unset the last timer*/
	for (i = 0; i < ah_capwap_para.capwap_number.fsm_chg_num; i++) {
		if ((clientstate == ah_capwap_fsm[i].state) && (clientevent == ah_capwap_fsm[i].event)) {
			ah_capwap_unsettimer(ah_capwap_fsm[i].lasttimer);
			break;
		}
	}

	/*fill the request packet buf*/
	if (ah_capwap_packet_client(capwaptxpkt, &packlen, sdnpkttype, clientstate, AH_CAPWAP_PKT_RQST_SEQ) == -1) {
		ah_err_old("CAPWAP assemble the packet failed!\n");
		return -1;
	}
	if (packlen == 0) {
		ah_err_old("CAPWAP assemble packet length is 0!\n");
		return -1;
	}
	/*choose send packet  module*/
	if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE && clientstate != AH_CAPWAP_DISCOVERY) {
		ah_dbg_old(capwap_ssl, "Encrypt and send the DTLS packet (state:%s len:%d)\n", ah_capwap_get_state_string(clientstate), packlen);
		if (ah_capwap_dtls_encrypt(capwaptxpkt, packlen) == -1) {
			ah_log_old(AH_LOG_WARNING, "CAPWAP send dtls packet error!");
		}
	} else {
		for (i = 0; i < ah_capwap_para.capwap_counter.max_retransmit; i++) {
			/*send to the packet*/
			if (ah_capwap_client_send(capwaptxpkt, packlen) == -1) {
				ah_sprintf(hostip, "%i", htonl(ah_capwap_info.wtpip));
				ah_log_old(AH_LOG_INFO, "CAPWAP send packet failed!packlen:%d/dst_ip:%s/src_ip:%s/udp_port:%d, reason:(%s)\n",
						   packlen, inet_ntoa(ah_capwap_para.capwapaddr.sin_addr), hostip, ntohs(ah_capwap_para.capwapaddr.sin_port), strerror(errno));
			} else {
				break;
			}
		}
	}
	ah_dbg_old(capwap_info, "SENDPKT->Send capwap packet\n");

	/*set CAPWAP timer*/
	if (ah_capwap_settimer(clienttimer, 0) == -1) {
		ah_err_old("CAPWAP set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
		return -1;
	}

	/*change the CAPWAP state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_rcvpkt
 *
 * Purpose:   the capwap receive packet function
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:   need handle the packet's buff
 *            buflen: the length for buff
 *            curwtpstate:  current wtp state
 *            nextwtpstate: next wtp state
 *            nextwtpevent: next wtp event
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_rcvpkt(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen,
					 uint32_t    curwtpstate, uint32_t nextwtpstate, uint32_t nextwtpevent)
{
	uint32_t    i = 0;

	if (buflen == 0) {
		ah_log_old(AH_LOG_INFO, "CAPWAP receive the packet length is 0.\n");
		return -1;
	}

	if (clientstate != curwtpstate || (clientevent != AH_CAPWAP_RCV_PKT && clientevent != AH_CAPWAP_CHG_EVENT_RCV_PKT)) {
		ah_err_old("CAPWAP receive packet error! state (%s) or event (%s)\n", ah_capwap_get_state_string(clientstate),
				   ah_capwap_get_event_string(clientevent));
		return -1;
	}

	/*unset the last timer*/
	for (i = 0; i < ah_capwap_para.capwap_number.fsm_chg_num; i++) {
		if ((clientstate == ah_capwap_fsm[i].state) && (clientevent == ah_capwap_fsm[i].event)) {
			ah_capwap_unsettimer(ah_capwap_fsm[i].lasttimer);
			break;
		}
	}
	if (i == ah_capwap_para.capwap_number.fsm_chg_num) {
		ah_err_old("CAPWAP can not find the timer,unset timer error!state: %s, event: %s\n", ah_capwap_get_state_string(clientstate),
				   ah_capwap_get_event_string(clientevent));
		return -1;
	}

	/*set CAPWAP timer*/
	if (ah_capwap_settimer(clienttimer, 0) == -1) {
		ah_err_old("CAPWAP set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
		return -1;
	}
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_rand
 *
 * Purpose:   generate a random number
 *
 * Inputs:    width: the random number width
 *
 * Output:    void
 *
 * Returns:   random number
 *
 **************************************************************************/
static int32_t  ah_capwap_get_rand(int width)
{
	int random_num = 0;
	struct timeval tv;

	if (width < 0) {
		return 100;
	}

	gettimeofday(&tv, NULL);
	srand((int)tv.tv_usec);

	random_num = (1 + (int)((float)width * rand() / (RAND_MAX + 1.0)));

	return random_num;
}

/***************************************************************************
 *
 * Function:  ah_capwap_start
 *
 * Purpose:   the callback function for capwap in start state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:  need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_start(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf, uint32_t buflen)
{
#define AH_CAPWAP_RANDOM_START_TIME (30*100)
	ah_dbg_old(capwap_info, "START->Enter the Start State.\n");
	if (clientstate != AH_CAPWAP_START) {
		ah_err_old("CAPWAP has the error status in start phrase!(status:%s)\n", ah_capwap_get_state_string(clientstate));
		return -1;
	}
	/*wait for cli configure end*/
#if 0
	while (ah_sys_ready() == AH_SYSTEM_NOT_READY) {
		sleep(1);
	}
#else
    sleep(50);
#endif

	/*CAPWAP simultaneous connection random back-off, unit is 10ms*/

	ah_usleep(0, ah_capwap_get_rand(AH_CAPWAP_RANDOM_START_TIME) * 10000);
	/*maybe the system boot up, client waitting for system ok
	 * .if  the configure file is no capwap client enable. then
	 * client enable change to enable if call ah_capwap_init*/
	if (ah_capwap_para.enable == AH_CAPWAP_ENABLE) {
		ah_capwap_unregister_mgt_port();
		ah_capwap_init();
	}
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "START->Leave the Start State.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_host_ip
 *
 * Purpose:   the callback function for capwap in get host ip state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:   need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_get_host_ip(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf,
						  uint32_t    buflen)
{
	uint32_t    hostip = 0;

	ah_dbg_old(capwap_info, "START->Enter the Get Host IP State.\n");
	if (clientstate != AH_CAPWAP_GET_HOST_IP) {
		ah_err_old("CAPWAP has the error status in get host ip phrase!(status:%s)\n", ah_capwap_get_state_string(clientstate));
		return -1;
	}
	/*the host ip is host order*/
	hostip = ah_capwap_getip();
	while (hostip == 0) {
		usleep(500000);/*sleep 500 millisecond*/
		if (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
			break;
		}
		/*set dog interval avoid be killed*/
		if (read_interface(AH_CAPWAP_MGT, NULL, &hostip, NULL, NULL) < 0) {
			ah_log_old(AH_LOG_WARNING, "%s: Got host IP failed.", __func__);
			continue;
		}
		capwap_mgt0_ip = hostip;
		ah_log_old(AH_LOG_WARNING, "CAPWAP mgt0 ip address is 0, update mgt0 ip to %i from kernel", hostip);
	}
	/*if waitting for host ip then the user use no capwap client*/
	if (ah_capwap_para.enable != AH_CAPWAP_DISABLE) {
		ah_dbg_old(capwap_info, "device ip is %i\n", hostip);
		/*if the ip is the same ip , then skip create socket*/
		if (ah_capwap_info.wtpip != hostip) {
			ah_capwap_info.wtpip = hostip;

			/*create socket*/
			if (ah_capwap_para.sock != 0) {
				/*unregister destnation port to FE*/
				ah_capwap_unregister_mgt_port();
				close(ah_capwap_para.sock);
			}
			if (ah_capwap_createsock() == -1) {
				ah_err_old("CAPWAP create sock error!\n");
				return -1;
			}
		}
	}
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "START->Leave the Get Host IP State.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_nms_ip
 *
 * Purpose:   the callback function for capwap in get nms ip state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_get_nms_ip(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf, uint32_t buflen)
{
	ah_dbg_old(capwap_info, "START->Enter the Get HM IP State.\n");
	if (clientstate != AH_CAPWAP_GET_NMS_IP) {
		ah_err_old("CAPWAP has the error status in get HM ip phrase!(status:%s)\n", ah_capwap_get_state_string(clientstate));
		return -1;
	}

	/*get hivemanager ip address*/
	ah_dbg_old(capwap_ha, "Choose HM IP or name for connecting....");
	ah_log_old(AH_LOG_INFO, "CAPWAP_HM:Choose HM IP or name for connecting....");
	while (1) {
		ah_capwap_nmsip();
		if (ah_capwap_get_tcp_status() != AH_CAPWAP_TCP_DISABLE
			&& ah_capwap_info.acip == 0) {
			/*tcp must need ip address to setup connection*/
			ah_dbg_old(capwap_htc_basic, "can not get HM's IP address when using TCP transfer mode.");
			/*set dog interval avoid be killed*/
			ah_sleep(1);
		} else {
			if (ah_capwap_info.acip == 0) {
				/* acip is 0 and choose ac predefine, dont make sense , get acip again */
				if (ah_capwap_get_choose_ac() == AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP) {
					sleep(5);
					continue;
				}
				ah_capwap_info.acip = AH_CAPWAP_BROADCAST;
				ah_capwap_info.acpri = AH_CAPWAP_GET_AC_BROADCAST;
			}
			break;
		}
	}
	ah_dbg_old(capwap_ha, "Ready connecting to HM %i", ntohl(ah_capwap_info.acip));
	ah_log_old(AH_LOG_INFO, "CAPWAP_HM:Ready connecting to HM %i", ntohl(ah_capwap_info.acip));
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "START->Leave the Get HM IP State.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_idle
 *
 * Purpose:   the callback function for capwap in idle state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:      need handle the packet's buff
 *            buflen:   the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_idle(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf, uint32_t buflen)
{
#define AH_CAPWAP_MAX_FAILED_TIMES 3
	uint32_t    timer_value = 0;

	ah_dbg_old(capwap_info, "IDLE->Enter the Idle State.\n");
	if (clientstate != AH_CAPWAP_IDLE) {
		ah_err_old("CAPWAP has the error status in idle phrase!(status:%s)\n", ah_capwap_get_state_string(clientstate));
		return -1;
	}
	/*Reset ah_capwap_para.capwap_counter.discovery_count*/
	ah_capwap_para.capwap_counter.discovery_count = 0;
	ah_capwap_para.state_duration = 0;
	ah_capwap_para.capwap_counter.retransmit_count = 0;
	ah_capwap_para.capwap_counter.dtls_retry_num = 0;
	ah_capwap_para.capwap_counter.discovery_failed_times ++;

	/*if user config the hivemanager ip(name), always unicast*/
	if (ah_capwap_info.acip == AH_CAPWAP_BROADCAST || ah_capwap_info.acip == 0) {
		ah_capwap_sendmode(AH_CAPWAP_SND_BROADCAST);/*send broadcast*/
	} else {
		ah_capwap_sendmode(AH_CAPWAP_SND_UNICAST);
	}

	/*clean frag buffer. if capwap reconnect with HM, capwap will clean the fragment buffer*/
	ah_capwap_clean_frag_buff();
	/*if capwap reconnect with HM,clear event buffer*/
	ah_capwap_event_buff_clean();

	/*set dtls reconnect status*/
	ah_capwap_dtls_set_enable_status(ah_capwap_dtls_get_next_enable_status());

	/*set tcp connetion*/
	if (ah_capwap_get_tcp_status() != AH_CAPWAP_TCP_DISABLE) {
		ah_capwap_set_last_socket_port(ah_capwap_para.capwap_port, -1);
		ah_capwap_finish();
		ah_capwap_register_mgt_port();
		Htc_para arg;

		ah_capwap_http_tunnel_init_para(&arg);
		if (ah_capwap_tcp_setup_connect(&arg) != 0) {
			return -1;
		}

		/*keep more time for HTTP get response from HTS when IN TCP connection*/
		timer_value = 5;
	} else {
		timer_value = 0;
	}

	if (ah_capwap_settimer(clienttimer, timer_value) != 0) {
		ah_err_old("%s: Capwap set timer failed, timer value is %d.", __func__, timer_value);
	}
	ah_dbg_old(capwap_info, "IDLE->Leave the Idle State.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dscav_snd
 *
 * Purpose:   the callback function for capwap in send discovery packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_dscav_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "DISCOVERY->Enter the send packet phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	if (ah_capwap_sndpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_REQUEST) < 0) {
		ah_err_old("CAPWAP DISCOVERY->send packet error!\n");
		return -1;
	}

	ah_capwap_para.capwap_counter.discovery_count ++;

	ah_dbg_old(capwap_info, "DISCOVERY->Leave the send packet phase state\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dscav_rcv
 *
 * Purpose:   the callback function for capwap in receive discovery packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_dscav_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{


	ah_dbg_old(capwap_info, "DISCOVERY->Enter the receive packet phase state: %s event: %s timer: %s\n",
			   ah_capwap_get_state_string(clientstate), ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	ah_capwap_para.capwap_counter.discovery_count = 0;
	if (ah_capwap_rcvpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY,
						 AH_CAPWAP_WAIT_SND_PKT) == -1) {
		ah_log_old(AH_LOG_INFO, "DISCOVERY->receive packet error!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "DISCOVERY->Leave the receive packet phase state.\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_sulking
 *
 * Purpose:   the callback function for capwap in sulking state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_sulking(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "SULKING->Enter the sulking phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	if (clientstate != AH_CAPWAP_SULKING || clientevent != AH_CAPWAP_EVENT_NONE) {
		ah_err_old("CAPWAP has error state %s or event %s in sulking phrase!\n", ah_capwap_get_state_string(clientstate),
				   ah_capwap_get_event_string(clientevent));
		return -1;
	}

	if (ah_capwap_settimer(clienttimer, 0) == -1) {
		ah_err_old("CAPWAP set timer error!(timer id:%d)", clienttimer);
		return -1;
	}

	ah_dbg_old(capwap_info, "SULKING->Leave the sulking phase state\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_join_snd
 *
 * Purpose:   the callback function for capwap in send join packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:   need handle the packet's buff
 *            buflen:the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_join_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "JOIN->Enter the send packet phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));
	/*if dtls enable, the change send mode will be done in dtls setup state*/
	if (ah_capwap_dtls_get_enable_status() != AH_CAPWAP_DTLS_ENABLE) {
		ah_capwap_sendmode(AH_CAPWAP_SND_UNICAST);/*send unicast*/
	}
	AH_CAPWAP_CLR_DTLS_CONNECT_FAILED_NUM;

	if (ah_capwap_sndpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST) == -1) {
		ah_err_old("CAPWAP JOIN->send packet error!\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "JOIN->Leave the send packet phase state\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_join_rcv
 *
 * Purpose:   the callback function for capwap in receive join packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:  need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_join_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "JOIN->Enter the receive packet phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	if (ah_capwap_rcvpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_JOIN, AH_CAPWAP_DISCOVERY,
						 AH_CAPWAP_WAIT_SND_PKT) == -1) {
		ah_err_old("CAPWAP JOIN->receive packet error!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "JOIN->Leave the receive packet phase state.\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_chgfsm_snd
 *
 * Purpose:   the callback function for capwap in send change state event packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:     need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_chgfsm_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						 uint32_t    buflen)
{
	ah_dbg_old(capwap_info, "CHANGE STATE EVENT->Enter the send packet phase state: %s event: %s timer: %s\n",
			   ah_capwap_get_state_string(clientstate), ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	if (ah_capwap_sndpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_RUN, AH_CAPWAP_CHGSTATE_EVENT_REQUEST) == -1) {
		ah_err_old("CAPWAP RUN CHANGE STATE EVENT->send packet error!\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "RUN CHANGE STATE EVENT->Leave the send packet phase state\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_chgfsm_rcv
 *
 * Purpose:   the callback function for capwap in receive change state event packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_chgfsm_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						 uint32_t    buflen)
{
	ah_dbg_old(capwap_info, "RUN CHANGE STATE EVENT->Enter the receive packet phase state: %s event: %s timer: %s\n",
			   ah_capwap_get_state_string(clientstate), ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	if (ah_capwap_rcvpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_RUN, AH_CAPWAP_DISCOVERY,
						 AH_CAPWAP_WAIT_SND_PKT) == -1) {
		ah_err_old("CAPWAP RUN CHANGE STATE EVENT->receive packet error!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "RUN CHANGE STATE EVENT->Leave the receive packet phase state");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_run_snd
 *
 * Purpose:   the callback function for capwap in send run echo packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_run_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "RUN ECHO->Enter the send packet phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));
	if (ah_capwap_sndpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_RUN, AH_CAPWAP_ECHO_REQUEST) == -1) {
		ah_err_old("CAPWAP RUN ECHO->send packet error!\n");
		return -1;
	}
	/*increase send packet counter*/
	ah_capwap_increase_packet_send_counter();
	ah_dbg_old(capwap_all_event_packet, "CAPWAP client send keep alive packet.\n");

	ah_capwap_para.echo_snd = AH_CAPWAP_ECHO_HAS_SND;
	ah_dbg_old(capwap_info, "RUN ECHO->Leave the send packet phase state\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_run_rcv
 *
 * Purpose:   the callback function for capwap in receive run echo packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_run_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	ah_dbg_old(capwap_info, "RUN ECHO->Enter the receive packet phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));
	ah_capwap_para.capwap_counter.discovery_failed_times = 0; /*the counter clear if the state is run*/

	if (ah_capwap_rcvpkt(clientstate, clientevent, clienttimer, buf, buflen, AH_CAPWAP_RUN, AH_CAPWAP_RUN, AH_CAPWAP_WAIT_SND_PKT) == -1) {
		ah_err_old("CAPWAP RUN ECHO->receive packet error!\n");
		return -1;
	}
	ah_capwap_para.capwap_counter.retransmit_count = 0;/*reset the counter for rcv echo pkt*/
	ah_capwap_para.echo_snd = AH_CAPWAP_ECHO_HAS_RCV;
	ah_capwap_increase_packet_recv_counter();
	ah_dbg_old(capwap_all_event_packet, "CAPWAP client receive keep alive packet.\n");

	ah_dbg_old(capwap_info, "RUN ECHO->Leave the receive packet phase state.\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_snd
 *
 * Purpose:   the callback function for capwap send event packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:     need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_event_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
#define AH_CAPWAP_MAX_HANDLE_SSL_PACKET_NUM  40
	uint32_t    snd_index = 0;
	uint32_t    msg_type = 0;
	char      capwaptxpkt[AH_CAPWAP_BUF_LEN] = {0};
	uint32_t    packlen = 0;
	uchar      snd_flag = 0;

	ah_dbg_old(capwap_info, "RUN EVENT->Enter the send packet phase state: %s event: %s timer: %s\n", ah_capwap_get_state_string(clientstate),
			   ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));
	/*
	sleep 500ms to avoid this case:
	if there have more than one event recevice(multi-fragment), the frag_id should be the same,
	if we send the first fragment before we receive the next fragment, the frag_id should be different.
	so HM will think this fragment as different packet.
	*/
	ah_usleep(0, 500 * 1000);
	/*check all the buff need send*/
	for (snd_index = 0; snd_index < AH_CAPWAP_EVENT_MAX_PKT; snd_index++) {
		/*set dog interval avoid be killed, seebug 11614*/
		/*fix bug#10344*/
		if (snd_flag >= AH_CAPWAP_MAX_HANDLE_SSL_PACKET_NUM) {
			/*because openSSL buffer has limitation, we need send 40 packets
			  and read from openSSL to empty the openSSL buffer*/
			break;
		}
		/*get the buff will be sent*/
		if (ah_capwap_event_get_snd_buff(snd_index, &msg_type) < 0) {
			continue;
		}
		snd_flag += 1;
		ah_dbg_old(capwap_info, "Send the event message,index:%d, msg_type %d\n", snd_index, msg_type);
		/*fill the request packet buf*/
		if (ah_capwap_packet_client(capwaptxpkt, &packlen, AH_CAPWAP_EVENT_REQUEST, clientstate, AH_CAPWAP_PKT_RQST_SEQ) == -1) {
			ah_err_old("CAPWAP assemble the packet failed!\n");
			return -1;
		}

		/*increase send packet counter*/
		ah_capwap_increase_packet_send_counter();
		ah_capwap_evtpkt_print_filter(capwaptxpkt, packlen, msg_type, AH_CAPWAP_DBGPKT_TX);

		/*choose send packet  module*/
		if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE && clientstate != AH_CAPWAP_DISCOVERY) {
			ah_dbg_old(capwap_ssl, "Send the DTLS packet (state:%s len:%d)\n", ah_capwap_get_state_string(clientstate), packlen);
			if (ah_capwap_dtls_encrypt(capwaptxpkt, packlen) == -1) {
				ah_log_old(AH_LOG_WARNING, "CAPWAP send event dtls packet error!");
			}
		} else {
			if (ah_capwap_client_send(capwaptxpkt, packlen) == -1) {
				ah_log_old(AH_LOG_INFO, "CAPWAP send packet failed!reason:%s\n", strerror(errno));
			}
		}
	}

	/*if there has no event need send, then change status to wait send echo*/
	if (snd_flag == 0) {
		ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
		ah_capwap_set_go_next_status(AH_CAPWAP_GOTO_NEXT_STATUS);
		ah_dbg_old(capwap_info, "RUN EVENT->Leave the send packet phase state. (there have no event to send)\n");
		return 0;
	} else {
		/* send event equal to send echo, so we mark the echo send flag */
		ah_capwap_para.echo_snd = AH_CAPWAP_ECHO_HAS_SND;
	}

	/*set AH_CAPWAP_TIMER_EVENT timer*/
	if (ah_capwap_settimer(clienttimer, 0) == -1) {
		ah_err_old("CAPWAP set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
		return -1;
	}

	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}

	ah_dbg_old(capwap_info, "RUN EVENT->Leave the send packet phase state\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_rcv
 *
 * Purpose:   the callback function for capwap receive event packet state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:    need handle the packet's buff
 *            buflen: the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_event_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen)
{
	int      rvs_time = 0;
	int      i = 0;

	ah_dbg_old(capwap_info, "RUN EVENT->Enter the receive packet phase state: %s event: %s timer: %s\n",
			   ah_capwap_get_state_string(clientstate), ah_capwap_get_event_string(clientevent), ah_capwap_get_timer_string(clienttimer));

	ah_capwap_para.capwap_counter.discovery_failed_times = 0; /*the counter clear if the state is run*/
	/* receive event equal to receive echo, mark flag here */
	ah_capwap_para.echo_snd = AH_CAPWAP_ECHO_HAS_RCV;
	/*get the left time of current timer and stop it*/
	rvs_time = ah_capwap_get_time2fire();
	if (rvs_time < 0) {
		rvs_time = 0;
	}
	for (i = 0; i < ah_capwap_para.capwap_number.fsm_chg_num; i++) {
		if ((clientstate == ah_capwap_fsm[i].state) && (clientevent == ah_capwap_fsm[i].event)) {
			ah_capwap_unsettimer(ah_capwap_fsm[i].lasttimer);
			break;
		}
	}

	/*if need event packet go on rcving the event confirm packet*/
	if (ah_capwap_event_need_rcv() == 0) {
		ah_dbg_old(capwap_info, "There have other event request packt need confirm! next time out:%d\n", rvs_time);
		/*go on the laster timer*/
		ah_capwap_fsm[i].curtimer = ah_capwap_fsm[i].lasttimer;
		if (ah_capwap_settimer(ah_capwap_fsm[i].curtimer, rvs_time) == -1) {
			ah_err_old("CAPWAP set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
			return -1;
		}
	} else {
		/*Don't need timer receive packet*/
		ah_capwap_fsm[i].curtimer = AH_CAPWAP_TIMER_NONE;
		ah_capwap_para.capwap_counter.retransmit_count = 0;/*reset the counter for rcv event pkt*/
		/*change the state*/
		if (ah_capwap_chgfsm_parmeter() == -1) {
			ah_err_old("CAPWAP change status failed!\n");
			return -1;
		}
	}
	ah_capwap_increase_packet_recv_counter();

	ah_dbg_old(capwap_info, "RUN EVENT->Leave the receive packet phase state.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_end
 *
 * Purpose:   the callback function for capwap in end state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:     need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_end(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf, uint32_t buflen)
{
#define AH_CAPWAP_DISABLE_DOG_VALUE 20
	ah_dbg_old(capwap_info, "END->Enter the End State.\n");
	if (clientstate != AH_CAPWAP_END) {
		ah_err_old("CAPWAP has the error status in end phrase!(status:%s)\n", ah_capwap_get_state_string(clientstate));
		return -1;
	}

	/*wait for cli configure start capwap*/
	while (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
		sleep(5);/*sleep 5 seconds*/
	}

	/*re-init*/
	ah_capwap_init();
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_err_old("CAPWAP change status failed!\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "END->Leave the End State.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_connect
 *
 * Purpose:   the callback function for capwap in ready connect dtls state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:     need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_dtls_connect(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						   uint32_t    buflen)
{
	/*
	   1. call dtls connect function
	   2. set the dtls connect timer (capwap client will hung in select)
	 */
	int      i = 0;

	ah_dbg_old(capwap_info, "DTLS SETUP->Enter the DTLS setup State.\n");
	ah_dbg_old(capwap_ssl, "DTLS SETUP->Enter the DTLS setup State.\n");
	/*connect to SSL server*/
	ah_capwap_dtls_set_conn_status(AH_DTLS_SETUP);
	/*change send mode*/
	ah_capwap_sendmode(AH_CAPWAP_SND_UNICAST);/*send unicast*/

	/*unset last timer*/
	for (i = 0; i < ah_capwap_para.capwap_number.fsm_chg_num; i++) {
		if ((clientstate == ah_capwap_fsm[i].state) && (clientevent == ah_capwap_fsm[i].event)) {
			ah_capwap_unsettimer(ah_capwap_fsm[i].lasttimer);
			break;
		}
	}

	/*set current timer*/
	if (ah_capwap_settimer(clienttimer, 0) < 0) {
		ah_err_old("CAPWAP set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
		return -1;
	}

	ah_dbg_old(capwap_info, "DTLS SETUP->Leave the DTLS setup State.\n");
	ah_dbg_old(capwap_ssl, "DTLS SETUP->Leave the DTLS setup State.\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_disconnect
 *
 * Purpose:   the callback function for capwap in ready disconnect dtls state
 *
 * Inputs:    clientstate: current capwap state
 *        clientevent:current capwap event
 *            clienttimer: current capwap timer
 *            buf:     need handle the packet's buff
 *            buflen:  the length for buff
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_dtls_disconnect(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
							  uint32_t    buflen)
{
	/*
	   1.call dtls clear function
	   2.set the dtls cut timer (capwap client will hung in select)
	 */

	ah_dbg_old(capwap_info, "DTLS ABORT->Enter the DTLS abort State.\n");
	ah_dbg_old(capwap_ssl, "DTLS ABORT->Enter the DTLS abort State.\n");

	/*clean DTLS resource*/
	/*will do in the dtls thread*/

	/*set current timer*/
	if (ah_capwap_settimer(clienttimer, 0) < 0) {
		ah_err_old("CAPWAP set timer error!(timer:%s)\n", ah_capwap_get_timer_string(clienttimer));
		return -1;
	}

	ah_dbg_old(capwap_info, "DTLS ABORT->Leave the DTLS abort State.\n");
	ah_dbg_old(capwap_ssl, "DTLS ABORT->Leave the DTLS abort State.\n");

	return 0;
}

