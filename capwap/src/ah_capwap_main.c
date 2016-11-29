#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_dbg_agent.h"
#include "ah_capwap_tcp.h"


/***************************************************************************
 *
 * Function:  ah_capwap_init
 *
 * Purpose:   initial the capwap parameters
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_init()
{
	struct in6_addr ipv6_address;
	/*get capwap timer/state/event/..number*/
	ah_capwap_get_member_num();
	/*set the init state and event*/
	ah_capwap_info.wtpip = 0;
	ah_capwap_info.acip = 0;
	ah_capwap_info.acport = AH_CAPWAP_PORT_INVALID;
	if (ah_capwap_para.enable == AH_CAPWAP_ENABLE) {
		ah_capwap_info.state = AH_CAPWAP_START;
		ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
	} else {
		ah_capwap_info.state = AH_CAPWAP_END;
		ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;
	}
	ah_capwap_info.acpri = AH_CAPWAP_GET_AC_INIT;
	capwap_mgt0_ip = ah_tpa_get_current_mgt_ip();
	capwap_mgt0_ipv6.af = AF_INET6;
	ah_tpa_get_mgt0_global_ipv6_addr(&ipv6_address);
	ah_memcpy(&capwap_mgt0_ipv6.u_ipv6_addr, &ipv6_address, sizeof(struct in6_addr));

	/*set the init parameter of capwap*/
	ah_capwap_para.event = AH_CAPWAP_EVENT_WAIT;
	ah_capwap_para.event_flag = AH_CAPWAP_EVENT_SND_ON;
	ah_capwap_para.capwap_counter.discovery_failed_times = 0;
	ah_capwap_para.state_duration = 0;
	ah_capwap_para.capwap_counter.retransmit_count = 0;
	ah_capwap_para.capwap_counter.max_retransmit = (ah_capwap_para.capwap_timer.neighbordead_interval /
			ah_capwap_para.capwap_timer.echo_interval) - 1;
	/*Don't config port*/
	if (ah_capwap_para.capwap_port  == 0) {
		ah_capwap_para.capwap_port = AH_CAPWAP_PORT;
	}

	/*set durate timer*/
	ah_capwap_set_durate_timer();

	/*clear event buffer*/
	ah_capwap_event_buff_clean();

	/*capwap init reset the reconnect flag*/
	ah_capwap_reset_reconnect_schedule();
	/*get capwap predefine server name*/
	ah_capwap_get_predefine_server_name(ah_capwap_para.predefine_name);

	/*initial capwap TCP*/
	ah_capwap_tcp_init();

	return;
}

static int ah_capwap_last_dst_port = AH_CAPWAP_PORT;
static int ah_capwap_last_proxy_port = 0;
/***************************************************************************
 *
 * Function:  ah_capwap_set_last_socket_port
 *
 * Purpose:   set CAPWAP destination port
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_set_last_socket_port(int capwap_port, int proxy_port)
{
	if (capwap_port != -1) {
		ah_capwap_last_dst_port = capwap_port;
	}
	if (proxy_port != -1) {
		ah_capwap_last_proxy_port = proxy_port;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_last_socket_port
 *
 * Purpose:   get CAPWAP destination port
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   last socket destination port
 *
 **************************************************************************/
int ah_capwap_get_last_socket_port(int *capwap_port, int *proxy_port)
{
	*capwap_port = ah_capwap_last_dst_port;
	*proxy_port = ah_capwap_last_proxy_port;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_unregister_mgt_port
 *
 * Purpose:   unregister managment port
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   last socket destination port
 *
 **************************************************************************/
int ah_capwap_unregister_mgt_port()
{
	int      capwap_port = 0;
	int      proxy_port = 0;

#if 0
	/*unregister destnation port to FE*/
	ah_capwap_get_last_socket_port(&capwap_port, &proxy_port);
	ah_dbg_old(capwap_info, "unregister port:%d, proxy port:%d\n", capwap_port, proxy_port);
	if (capwap_port == AH_CAPWAP_HTTP_DEFAULT_PORT) {
		ah_tpa_fe_unregister_to_self_pkt_port(IPPROTO_TCP, capwap_port, AH_TO_SELF_SRC_CHECK);
	} else if (capwap_port > 0) {
		ah_tpa_fe_unregister_to_self_pkt_port(IPPROTO_UDP, capwap_port, AH_TO_SELF_SRC_CHECK);
	}
	if (proxy_port > 0) {
		ah_tpa_fe_unregister_to_self_pkt_port(IPPROTO_TCP, proxy_port, AH_TO_SELF_SRC_CHECK);
	}
#endif

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_register_mgt_port
 *
 * Purpose:   register managment port
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 successfully, others failed
 *
 **************************************************************************/
int ah_capwap_register_mgt_port(void)
{
	ah_dbg_old(capwap_info, "register port :%d\n", ah_capwap_para.capwap_port);
#if 0
	if (ah_capwap_para.capwap_port == AH_CAPWAP_HTTP_DEFAULT_PORT) {
		ah_tpa_fe_register_to_self_pkt_port(IPPROTO_TCP, ah_capwap_para.capwap_port, AH_TO_SELF_SRC_CHECK, "CAPWAP destination port");
	} else {
		ah_tpa_fe_register_to_self_pkt_port(IPPROTO_UDP, ah_capwap_para.capwap_port, AH_TO_SELF_SRC_CHECK, "CAPWAP destination port");
	}
#endif
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_finish
 *
 * Purpose:   clean some resource when capwap disabled
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_finish()
{
	if (ah_capwap_para.sock != 0) {
		ah_capwap_unregister_mgt_port();
		close(ah_capwap_para.sock);
	}

	sleep(1);/*if error then sleep and try again*/
	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_dog_flag
 *
 * Purpose:   set dog flag to PM
 *
 * Inputs:    timer:  dog flag time
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_set_dog_flag(uint32_t timer)
{
#define AH_CAPWAP_DOG_INCRE 120 /*see bug #8666*/
#define AH_CAPWAP_DOG_DFT 60
	int      j = 0;
	uint      dog_timer = AH_CAPWAP_DOG_DFT;

	/*call PM api to tell him capwap is running normally*/
	if (ah_capwap_fsm[timer].curtimer != 0) {
		for (j = 0; j < ah_capwap_para.capwap_number.timer_num; j++) {
			if (ah_capwap_timer[j].timertype == ah_capwap_fsm[timer].curtimer) {
				dog_timer = ah_capwap_timer[j].timervalue + AH_CAPWAP_DOG_INCRE;
				break;
			}
		}
		if (j == ah_capwap_para.capwap_number.timer_num) {
			ah_err_old("CAPWAP can not find state: %s event: %s \n",
					   ah_capwap_get_state_string(ah_capwap_info.state),
					   ah_capwap_get_event_string(ah_capwap_info.event));
		}
	}
	ah_dbg_old(capwap_basic, "capwap set watch dog:%d priority:%d modid:%d\n", dog_timer, AH_PRIORITY_MGT, AH_MOD_ID_CAPWAP);
	if (capwap_basic) {
		ah_log_old(AH_LOG_INFO, "capwaptimer: set watch dog:%d priority:%d modid:%d\n", dog_timer, AH_PRIORITY_MGT, AH_MOD_ID_CAPWAP);
	}
	ah_pm_toggle_watchdog(AH_MOD_ID_CAPWAP, dog_timer, AH_PRIORITY_MGT);
	ah_capwap_para.wd.flag = AH_CAPWAP_WD_CLIENT;
	ah_capwap_para.wd.set_time = ah_sys_up_sec();
	ah_capwap_para.wd.offset = dog_timer;

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_handle_signal
 *
 * Purpose:   capwap handle signal callback
 *
 * Inputs:    signal: signal number
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
static void ah_capwap_handle_signal(int signal)
{
	switch (signal) {
	case SIGUSR1:
		/* DTLS decrypte complete, do nothing */
		break;
	case SIGPIPE:
		/**/
		ah_dbg_old(capwap_htc_basic, "Receive a signal pipe");
		break;
	default:
		break;
	}
}

/***************************************************************************
 * Function:  ah_capwap_client
 *
 * Purpose:   the main loop for CAPWAP
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_client()
{
#define AH_CAPWAP_FIND_RIGHT_STATE 0
#define AH_CAPWAP_FIND_ERROR_STATE 1
#define AH_CAPWAP_INHERIT_PRIORITY 1
	uint      i = 0;
	uint      find_state = AH_CAPWAP_FIND_RIGHT_STATE;
	uint32_t    pktlen = 0;
	char      capwaprxpkt[AH_CAPWAP_BUF_LEN] = {'0'};/*the array to save the rx pkt*/
	pthread_t HandshakeThread;
	int      rc = 0;

	ah_capwap_init();
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	ah_capwap_init_http_proxy_conf_file();
	ah_capwap_monitor_bonjour_service();
#endif

	/*reset capwap packet counter when process bootup*/
	ah_capwap_reset_packet_counter();
	rc = ah_pthread_create(&HandshakeThread, ah_capwap_dtls_thread, NULL, SCHED_RR, AH_PRIORITY_MGT, 0);
	if (rc < 0) {
		/*capwap will disable*/
		ah_capwap_disable();
		ah_err_old("CAPWAP create thread for DTLS error (rc:%d)", rc);
	}
	ah_dbg_old(capwap_ssl, "Create a DTLS thread.(threadid:%d)", (uint32_t)HandshakeThread);

	rc = ah_pthread_create(&HandshakeThread, ah_capwap_get_trap, NULL, SCHED_RR, AH_PRIORITY_MGT, 0);
	if (rc < 0) {
		ah_err_old("CAPWAP create thread for get trap error (rc:%d)", rc);
	}
	capwap_main_tid = pthread_self();
	signal(SIGUSR1, ah_capwap_handle_signal);
	signal(SIGPIPE, ah_capwap_handle_signal);

	while (1) {
		/*reset need start flag*/
		find_state = AH_CAPWAP_FIND_ERROR_STATE;
		/*do something in term of capwap state and capwap event*/
		for (i = 0; i < ah_capwap_para.capwap_number.fsm_chg_num; i++) {
			if ((ah_capwap_info.state == ah_capwap_fsm[i].state) && (ah_capwap_info.event == ah_capwap_fsm[i].event)) {
				ah_dbg_old(capwap_basic, "current parameters:%s  %s  %s\n",
						   ah_capwap_get_state_string(ah_capwap_fsm[i].state),
						   ah_capwap_get_event_string(ah_capwap_fsm[i].event),
						   ah_capwap_get_timer_string(ah_capwap_fsm[i].curtimer));
				/*set find flag*/
				find_state = AH_CAPWAP_FIND_RIGHT_STATE;
				if (ah_capwap_fsm[i].ah_client_fsmchg_callback(ah_capwap_fsm[i].state, ah_capwap_fsm[i].event, ah_capwap_fsm[i].curtimer, capwaprxpkt,
						pktlen) == -1) {
					ah_log_old(AH_LOG_INFO, "CAPWAP call the function error! state:%s event:%s  timer:%s\n",
							   ah_capwap_get_state_string(ah_capwap_fsm[i].state),
							   ah_capwap_get_event_string(ah_capwap_fsm[i].event),
							   ah_capwap_get_timer_string(ah_capwap_fsm[i].curtimer));
					/*reset capwap state to init and then start again*/
					find_state = AH_CAPWAP_FIND_ERROR_STATE;
				}
				break;
			}
		}
		/*state is error need go from start*/
		if (find_state == AH_CAPWAP_FIND_ERROR_STATE) {
			/*reset capwap state to init and then start again*/
			ah_capwap_finish();
			ah_capwap_init();
			ah_capwap_set_dog_flag(0);
			continue;
		}

		/*set dog flag to pm*/
		ah_capwap_set_dog_flag(i);

		/*check need change status directly*/
		if (ah_capwap_get_go_next_status() == AH_CAPWAP_GOTO_NEXT_STATUS) {
			ah_dbg_old(capwap_basic, "change the status to status:%s, event:%s directly.\n",
					   ah_capwap_get_state_string(ah_capwap_info.state),
					   ah_capwap_get_event_string(ah_capwap_info.event));
			ah_capwap_set_go_next_status(AH_CAPWAP_KEEP_CURR_STATUS);
			continue;
		}

		/*timer only for receive packet*/
		if (ah_capwap_fsm[i].curtimer != AH_CAPWAP_TIMER_NONE) {
			/*listen the udp port to rcv the packet and analyse the packet*/
			if (ah_capwap_client_listen(capwaprxpkt, &pktlen) == -1) {
				ah_log_old(AH_LOG_INFO, "CAPWAP listen the port error or receive an interrupt signal when hung in select!\n");
				/*reset capwap state to init and then start again*/
				ah_capwap_finish();
				ah_capwap_init();
				continue;
			}
		}

		/*check receive event from scd(nms_ip changed or host_ip changed)*/
		ah_capwap_deal_event();
	}

	return;
}
