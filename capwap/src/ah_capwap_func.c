#include <stdio.h>
#include <stdarg.h>
#include <netdb.h>
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
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pthread.h>
#include <resolv.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_assert.h"
#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_event.h"
#include "ah_capwap_tcp.h"
#include "ah_capwap_api.h"
#include "ah_dbg_agent.h"
#include "ah_alarm.h"

#define AH_CAPWAP_DURATE_TIME  1
#define AH_CAPWAP_LISTEN_STOP  0
#define AH_CAPWAP_LISTEN_KEEP  1

/*capwap record how long durate timer*/
static ah_ptimer_t *ah_capwap_durate_timer = NULL;
/*capwap state timer*/
static ah_ptimer_t *ah_capwap_timervar = NULL;
/*capwap current timer time to fire*/

static int ah_capwap_timer_fire = 0;
static int ah_capwap_chk_img = 0;

/*capwap packet counter*/
static ah_capwap_pkt_counter ah_capwap_pkt_counter_info;
static ah_capwap_event_pkt_counter_t ah_capwap_event_pkt_counter;

/*capwap change ac flag*/
static int ah_capwap_chg_ac_flag = 0;

/*capwap go to next status flag*/
static int ah_capwap_go_next_status_flag = AH_CAPWAP_KEEP_CURR_STATUS;
uint32_t capwap_mgt0_ip = 0;

/***************************************************************************
 *
 * Function:  ah_capwap_set_chg_ac_flag
 *
 * Purpose:   set change current AC flag
 *
 * Inputs:    chg_flag
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_set_chg_ac_flag(uint32_t chg_flag)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_chg_ac_flag = chg_flag;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_chg_ac_flag
 *
 * Purpose:   get change current AC flag
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   capwap choose ac level
 *
 **************************************************************************/
int ah_capwap_get_chg_ac_flag()
{
	uint32_t    chg_flag = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	chg_flag = ah_capwap_chg_ac_flag;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return chg_flag;
}

/***************************************************************************
 *
 * Function:   ah_capwap_reset_packet_counter
 *
 * Purpose:    reset the CPAWAP packet counter
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
int ah_capwap_reset_packet_counter()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_memset(&ah_capwap_pkt_counter_info, 0x00, sizeof(ah_capwap_pkt_counter_info));
	ah_memset(&ah_capwap_event_pkt_counter, 0x00, sizeof(ah_capwap_event_pkt_counter));
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_increase_packet_lost_counter
 *
 * Purpose:    increase the CPAWAP lost packet counter
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_increase_packet_lost_counter()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_pkt_counter_info.lost_pkt ++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_increase_packet_send_counter
 *
 * Purpose:    increase the CPAWAP send packet counter
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_increase_packet_send_counter()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_pkt_counter_info.snd_pkt++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_increase_packet_recv_counter
 *
 * Purpose:    increase the CPAWAP receive packet counter
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_increase_packet_recv_counter()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_pkt_counter_info.rcv_pkt++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_increase_packet_drop_buffer_counter
 *
 * Purpose:    increase the CPAWAP discard packet counter because of capwap buff is full
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_increase_packet_drop_buffer_counter()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_pkt_counter_info.drop_buff++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_increase_packet_drop_conn_counter
 *
 * Purpose:    increase the CPAWAP discard packet counter because of capwap lost connect
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_increase_packet_drop_conn_counter()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_pkt_counter_info.drop_conn++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_get_packet_counter
 *
 * Purpose:    get the CPAWAP packet counter
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
int ah_capwap_get_packet_counter(ah_capwap_pkt_counter *pkt_counter)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_memcpy(pkt_counter, &ah_capwap_pkt_counter_info, sizeof(ah_capwap_pkt_counter_info));
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_increase_event_counter
 *
 * Purpose:    increase  event packet
 *
 * Inputs:     op_type: operation type
 *                  index: event_type index id
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
int ah_capwap_increase_event_counter(uint32_t op_type, uint32_t index)
{

	if (index >= AH_CAPWAP_MAX_EVENT_COUNTER_TYPE) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: the current event counter index(%d) larger than the max index(%d)\n",
				   (index + 1), AH_CAPWAP_MAX_EVENT_COUNTER_TYPE);
		return 0;
	}

	switch (op_type) {
	case AH_CAPWAP_INCREASE_EVENT_SEND_PKT_COUNTER:
		ah_capwap_event_pkt_counter.event_send[index] ++;
		break;
	case AH_CAPWAP_INCREASE_EVENT_LOST_PKT_COUNTER:
		ah_capwap_event_pkt_counter.event_lost[index] ++;
		break;
	case AH_CAPWAP_INCREASE_EVENT_DROP_CONN_COUNTER:
		ah_capwap_event_pkt_counter.event_drop_conn[index] ++;
		break;
	case AH_CAPWAP_INCREASE_EVENT_DROP_BUFF_COUNTER:
		ah_capwap_event_pkt_counter.event_drop_buff[index] ++;
		break;
	case AH_CAPWAP_INCREASE_EVENT_DROP_DSAB_COUNTER:
		ah_capwap_event_pkt_counter.event_drop_dsab[index] ++;
		break;
	}

	return 0;
}

/*the array for increase event packet counter*/
static uint32_t ah_capwap_event_packet_counter[] = {
	AH_CAPWAP_EVENT_IDP,
	AH_CAPWAP_EVENT_PORT,
	AH_CAPWAP_EVENT_CLI,
	AH_CAPWAP_EVENT_DOWNLOAD,
	AH_CAPWAP_EVENT_STATISTICAL,
	AH_CAPWAP_EVENT_REBOOT_FAILED,
	AH_CAPWAP_EVENT_CFG_VER_CHGED,
	AH_CAPWAP_EVENT_CWP_DIR,
	AH_CAPWAP_EVENT_SSH_KEY,
	AH_CAPWAP_EVENT_HOSTNAME_CHG,
	AH_CAPWAP_EVENT_SEND_TRAP,
	AH_CAPWAP_EVENT_MGT0_HIVE_CHG,
};
static int event_counter_array = sizeof(ah_capwap_event_packet_counter) / sizeof(ah_capwap_event_packet_counter[0]);


/***************************************************************************
 *
 * Function:   ah_capwap_increase_event_packet_counter
 *
 * Purpose:    increase  event packet base on event type
 *
 * Inputs:     op_type: operation type
 *                  event_type: event_type id
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_increase_event_packet_counter(uint32_t op_type, uint32_t event_type)
{
	int i = 0;

	for (i = 0; i < event_counter_array; i++) {
		if (event_type == ah_capwap_event_packet_counter[i]) {
			break;
		}
	}

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_increase_event_counter(op_type, i);
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:   ah_capwap_get_event_packet_counter
 *
 * Purpose:    get  event packet base on event type
 *
 * Inputs:     op_type: operation type
 *                  event_type: event_type id
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
inline int ah_capwap_get_event_packet_counter(ah_capwap_event_pkt_counter_t *event_pkt_counter)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_memcpy(event_pkt_counter, &ah_capwap_event_pkt_counter, sizeof(ah_capwap_event_pkt_counter));
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_choose_ac
 *
 * Purpose:   set choose current AC flag
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_set_choose_ac(uint32_t ac_level)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.choose_ac = ac_level;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_choose_ac
 *
 * Purpose:   get the capwap next need choose AC flag
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   capwap choose ac level
 *
 **************************************************************************/
int ah_capwap_get_choose_ac()
{
	uint32_t    ac_level = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ac_level = ah_capwap_para.choose_ac;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return ac_level;
}

/***************************************************************************
 *
 * Function:   ah_capwap_reset_timer
 *
 * Purpose:    reset the CPAWAP current timer
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
void ah_capwap_reset_timer()
{
	if (ah_capwap_timervar != NULL) {
		ah_pmpt_timer_start(ah_capwap_timervar, 0); /*let the timer time out at once*/
	}
	if (ah_capwap_durate_timer != NULL) {
		ah_pmpt_timer_start(ah_capwap_durate_timer, 0);
	}

	return;
}

/***************************************************************************
 *
 * Function:   ah_capwap_printf
 *
 * Purpose:    CAPWAP print function
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    void
 *
 **************************************************************************/
void ah_capwap_printf(const char *format, ...)
{

#if AH_CAPWAP_DBG
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
#endif
	return;
}

/***************************************************************************
 *
 * Function:   ah_capwap_getip
 *
 * Purpose:    get capwap current host ip
 *
 * Inputs:     void
 *
 * Output:     void
 *
 * Returns:    != 0 success, otherwise failed
 *
 **************************************************************************/
uint32_t ah_capwap_getip()
{
	/* use ioctl to get ip may block capwap process
	 * because kernel some big lock to wait ??? */
#if 0
	uint32_t ipaddr = 0;
	uint32_t mask = 0;

	if (ah_dcd_get_addr_byname(AH_CAPWAP_MGT, &ipaddr, &mask) < 0) {
		return 0;
	}

	return ipaddr;
#else
	if (capwap_mgt0_ip == 0) {
		capwap_mgt0_ip = ah_tpa_get_current_mgt_ip();
	}
	return capwap_mgt0_ip;
#endif
}


/***************************************************************************
 *
 * Function:  ah_capwap_deal_durate_timer
 *
 * Purpose:   handle duration timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_deal_durate_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_capwap_para.state_duration ++;
	ah_capwap_chk_img_download();

	ah_capwap_stat_process_timer();

	if (ah_capwap_durate_timer != NULL) {
		ah_pmpt_timer_continue(ah_capwap_durate_timer, AH_CAPWAP_DURATE_TIME);
	}

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_durate_timer
 *
 * Purpose:   set duration timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_set_durate_timer()
{
	if (ah_capwap_durate_timer != NULL) {
		ah_pmpt_timer_delete(ah_capwap_durate_timer);
		ah_capwap_durate_timer = NULL;
	}
	ah_capwap_durate_timer = ah_pmpt_timer_create(ah_capwap_deal_durate_timer, NULL);
	if (ah_capwap_durate_timer == NULL) {
		ah_err_old("CAPWAP create durate timer failed!\n");
		return -1;
	}
	ah_pmpt_timer_start(ah_capwap_durate_timer, AH_CAPWAP_DURATE_TIME);
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_unset_durate_timer
 *
 * Purpose:   unset duration timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_unset_durate_timer()
{
	if (ah_capwap_timervar != NULL) {
		ah_pmpt_timer_stop(ah_capwap_durate_timer);
	}
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_run_state_timer
 *
 * Purpose:   set run state timer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
void ah_capwap_set_run_state_timer(int timer_type, uint32_t *timer_value)
{
#define AH_CAPWAP_MIN_TIMER_FOR_EVENT 3
	/*capwap in status AH_CAPWAP_SND_EVENT*/
	if (ah_capwap_timer_fire > 0) {
		*timer_value = (ah_capwap_timer_fire < AH_CAPWAP_MIN_TIMER_FOR_EVENT) ? AH_CAPWAP_MIN_TIMER_FOR_EVENT : ah_capwap_timer_fire;
		ah_capwap_timer_fire = 0;
		return;
	}
	/*Neighbor Dead don't time out, use Echo interval*/
	if (ah_capwap_para.capwap_counter.retransmit_count < ah_capwap_para.capwap_counter.max_retransmit) {
		*timer_value = ah_capwap_para.capwap_timer.echo_interval;
		return;
	}

	if (ah_capwap_para.echo_snd != AH_CAPWAP_ECHO_HAS_SND && ah_capwap_info.event == AH_CAPWAP_SND_EVENT) {
		/*only retransmit max times. so need wait more than one Echo interval*/
		*timer_value = ah_capwap_para.capwap_timer.neighbordead_interval - (ah_capwap_para.capwap_counter.max_retransmit) *
					   (ah_capwap_para.capwap_timer.echo_interval);
	} else {
		/*the leave time can not support one Echo interval*/
		*timer_value = ah_capwap_para.capwap_timer.neighbordead_interval - (ah_capwap_para.capwap_counter.max_retransmit + 1) *
					   (ah_capwap_para.capwap_timer.echo_interval);
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_settimer
 *
 * Purpose:   set capwap state timer
 *
 * Inputs:    timertype: timer type
 *            timer_value: timer value
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_settimer(uint32_t timertype, uint32_t timer_value)
{
	int      i = 0;

	if (timertype == AH_CAPWAP_TIMER_NONE) {
		return 0;
	}
	/*release the timer memory*/
	if (ah_capwap_timervar != NULL) {
		ah_pmpt_timer_delete(ah_capwap_timervar);
		ah_capwap_timervar = NULL;
	}

	for (i = 0; i < ah_capwap_para.capwap_number.timer_num; i++) {
		if (timertype == ah_capwap_timer[i].timertype) {
			if (ah_capwap_info.state == AH_CAPWAP_RUN && (ah_capwap_info.event == AH_CAPWAP_SND_PKT || ah_capwap_info.event == AH_CAPWAP_SND_EVENT)) {
				ah_capwap_set_run_state_timer(timertype, &ah_capwap_timer[i].timervalue);
			}
			ah_capwap_timervar = ah_pmpt_timer_create(ah_capwap_timer[i].ah_timer_callback, NULL);
			if (ah_capwap_timervar == NULL) {
				ah_err_old("CAPWAP create preemptive timer failed!timer type is %s interval is %d\n", ah_capwap_get_timer_string(timertype),
						   ah_capwap_timer[i].timervalue);
				return -1;
			}
			/*set ready listen flag*/
			ah_capwap_keep_listen();
			if (timer_value > 0) {
				ah_pmpt_timer_start(ah_capwap_timervar, timer_value);
				ah_dbg_old(capwap_info, "set timer type is %s interval is %d\n", ah_capwap_get_timer_string(timertype), timer_value);
			} else {
				ah_pmpt_timer_start(ah_capwap_timervar, ah_capwap_timer[i].timervalue);
				ah_dbg_old(capwap_info, "set timer type is %s interval is %d\n", ah_capwap_get_timer_string(timertype), ah_capwap_timer[i].timervalue);
			}

			return 0;
		}
	}
	ah_err_old("CAPWAP can not found any corresponding timer!%s/%d\n", ah_capwap_get_timer_string(timertype), ah_capwap_timer[i].timervalue);

	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_unsettimer
 *
 * Purpose:   unset capwap state timer
 *
 * Inputs:    timertype: timer type
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_unsettimer(uint32_t timertype)
{
	int      i = 0;

	if (timertype == AH_CAPWAP_TIMER_NONE && ah_capwap_timervar != NULL) {
		ah_pmpt_timer_stop(ah_capwap_timervar); /*timer type is dynamic*/
		return 0;
	}

	for (i = 0; i < ah_capwap_para.capwap_number.timer_num; i++) {
		if (timertype == ah_capwap_timer[i].timertype && ah_capwap_timervar != NULL) {
			ah_pmpt_timer_stop(ah_capwap_timervar);
			ah_dbg_old(capwap_info, "unset timer type is %s interval is %d\n", ah_capwap_get_timer_string(timertype), 0);
			return 0;
		}
	}
	ah_dbg_old(capwap_info, "not found any corresponding timer!%s/%d\n", ah_capwap_get_timer_string(timertype), 0);
	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_discovey_timer
 *
 * Purpose:   handle discovery timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_discovey_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_info.state != AH_CAPWAP_JOIN
		&& ah_capwap_info.state != AH_CAPWAP_DTLS_SETUP) { /*discovery->join must wait for discovery interval*/
		ah_capwap_info.state = AH_CAPWAP_DISCOVERY;
		ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
	}
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_discovey_timer timed out\n");
	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_echo_timer
 *
 * Purpose:   handle echo timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_echo_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_info.state != AH_CAPWAP_RUN) {
		goto OUT;
	}
	ah_capwap_info.state = AH_CAPWAP_RUN;
	ah_capwap_info.event = AH_CAPWAP_SND_PKT;
	ah_capwap_interrupt_listen();

	ah_dbg_old(capwap_info, "ah_capwap_echo_timer timed out\n");
OUT:
	ah_capwap_interrupt_listen();
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_retransmit_timer
 *
 * Purpose:   handle retransmit timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_retransmit_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_dbg_old(capwap_info, "ah_capwap_retransmit_timer timed out\n");
	ah_capwap_interrupt_listen();
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_response_timer
 *
 * Purpose:   handle response timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_response_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_dbg_old(capwap_info, "ah_capwap_response_timer timed out\n");
	ah_capwap_interrupt_listen();
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_maxdisco_timer
 *
 * Purpose:   handle max discovery timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_maxdisco_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_info.state != AH_CAPWAP_DISCOVERY) {
		goto OUT;
	}
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP change status failed in discovery phase!\n");
		goto OUT;
	}
OUT:
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_maxdisco_timer timed out\n");
	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_silent_timer
 *
 * Purpose:   handle silent timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_silent_timer(ah_ptimer_t *timername, void *timerparameter)
{
	/*change the state*/
	if (ah_capwap_chgfsm_parmeter() == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP change status failed in silent phase!\n");
		goto OUT;
	}

OUT:
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_silent_timer timed out\n");
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_idle_timer
 *
 * Purpose:   handle idle timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_idle_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_capwap_info.state = AH_CAPWAP_DISCOVERY;
	ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
	ah_capwap_para.state_duration = 0;
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_idle_timer timed out\n");
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_waitjoin_timer
 *
 * Purpose:   handle wait join timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_waitjoin_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_info.state != AH_CAPWAP_JOIN) {
		goto OUT;
	}
	if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_DTLS_TDWN;
		ah_capwap_info.event = AH_CAPWAP_DTLS_DISCONN;
	} else {
		ah_capwap_info.state = AH_CAPWAP_START;
		ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
	}
OUT:
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_AH_CAPWAP_TIMER_WAITJOIN_timer timed out\n");
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_neigbor_timer
 *
 * Purpose:   handle neighbor dead timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_neigbor_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_info.state != AH_CAPWAP_RUN) {
		goto OUT;
	}
	ah_dbg_old(capwap_info, "echo no recevie %d %d\n", ah_capwap_para.capwap_counter.retransmit_count,
			   ah_capwap_para.capwap_counter.max_retransmit);
	//ah_log_old(AH_LOG_INFO, "capwaptimer: echo timer timed out");
	if ((AH_CAPWAP_RUN == ah_capwap_info.state) && (AH_CAPWAP_CHG_EVENT_RCV_PKT == ah_capwap_info.event)) {
		if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
			ah_capwap_para.state_duration = 0;
			ah_capwap_info.state = AH_CAPWAP_DTLS_TDWN;
			ah_capwap_info.event = AH_CAPWAP_DTLS_DISCONN;
		} else {
			ah_capwap_info.state = AH_CAPWAP_START;
			ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		}
	}

	if ((AH_CAPWAP_RUN == ah_capwap_info.state) && (AH_CAPWAP_RCV_PKT == ah_capwap_info.event)) {
		/*increase the lost packet counter*/
		ah_capwap_increase_packet_lost_counter();
		if (ah_capwap_para.capwap_counter.retransmit_count >= ah_capwap_para.capwap_counter.max_retransmit) {
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
			ah_capwap_set_reconnect_reason(AH_CAPWAP_RECONNECT_TIMEOUT);
			ah_log_old(AH_LOG_WARNING, "CAPWAP: capwap client doesn't receive echo packet %d times, CAPWAP client reconnect",
					   ah_capwap_para.capwap_counter.retransmit_count);
			ah_capwap_increase_disconnect_number();
			if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
				ah_capwap_para.state_duration = 0;
				ah_capwap_info.state = AH_CAPWAP_DTLS_TDWN;
				ah_capwap_info.event = AH_CAPWAP_DTLS_DISCONN;
			} else {
				ah_capwap_info.state = AH_CAPWAP_START;
				ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
			}
		} else {
			ah_capwap_para.capwap_counter.retransmit_count ++;
			ah_dbg_old(capwap_info, "no recv echo pkt %d times\n", ah_capwap_para.capwap_counter.retransmit_count);
			ah_log_old(AH_LOG_WARNING, "CAPWAP: capwap client doesn't receive echo packet %d times", ah_capwap_para.capwap_counter.retransmit_count);
			/*need to send again*/
			ah_capwap_info.state = AH_CAPWAP_RUN;
			ah_capwap_info.event = AH_CAPWAP_SND_PKT;
		}
	}
OUT:
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_neigbor_timer timed out\n");
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_timer
 *
 * Purpose:   handle event timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_event_timer(ah_ptimer_t *timername, void *timerparameter)
{
	if (ah_capwap_info.state != AH_CAPWAP_RUN || AH_CAPWAP_RCV_EVENT != ah_capwap_info.event) {
		goto OUT;
	}
	ah_dbg_old(capwap_info, "event no recevie %d %d\n", ah_capwap_para.capwap_counter.retransmit_count,
			   ah_capwap_para.capwap_counter.max_retransmit);
	/*increase the lost packet counter*/
	ah_capwap_increase_packet_lost_counter();
	if (ah_capwap_para.capwap_counter.retransmit_count >= ah_capwap_para.capwap_counter.max_retransmit) {
		ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
		ah_capwap_set_reconnect_reason(AH_CAPWAP_RECONNECT_TIMEOUT);
		ah_log_old(AH_LOG_WARNING, "CAPWAP: capwap client doesn't receive event packet %d times, CAPWAP client reconnect",
				   ah_capwap_para.capwap_counter.retransmit_count);
		ah_capwap_increase_disconnect_number();
		if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
			ah_capwap_info.state = AH_CAPWAP_DTLS_TDWN;
			ah_capwap_info.event = AH_CAPWAP_DTLS_DISCONN;
		} else {
			ah_capwap_info.state = AH_CAPWAP_START;
			ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		}
	} else {
		ah_capwap_para.capwap_counter.retransmit_count ++;
		ah_dbg_old(capwap_info, "no recv event pkt %d times\n", ah_capwap_para.capwap_counter.retransmit_count);
		ah_log_old(AH_LOG_WARNING, "CAPWAP: capwap client doesn't receive event packet %d times", ah_capwap_para.capwap_counter.retransmit_count);
		/*need to send again*/
		ah_capwap_info.state = AH_CAPWAP_RUN;
		ah_capwap_info.event = AH_CAPWAP_SND_EVENT;
	}
OUT:
	ah_capwap_interrupt_listen();
	ah_dbg_old(capwap_info, "ah_capwap_event_timer timed out\n");

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_none_timer
 *
 * Purpose:   handle none timer time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_cpawpa_none_timer(ah_ptimer_t *timername, void *timerparameter)
{
	ah_dbg_old(capwap_info, "timer none time out!\n");
	ah_capwap_interrupt_listen();
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_conn_timer
 *
 * Purpose:   handle dtls connectr time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_dtls_conn_timer(ah_ptimer_t *timername, void *timerparameter)
{
#define AH_CAPWAP_MAX_DTLS_CONTINUE_CONNECT_FAILED_THRESHOLD (2)
	/*1.change state to AH_CAPWAP_DTLS_TDWN
	  2.interrup select
	 */
	/*if connect time > this timer? do we need release resource?*/
	ah_dbg_old(capwap_ssl, "timer ah_capwap_dtls_connect_timer timed out!\n");
	ah_dbg_old(capwap_info, "timer ah_capwap_dtls_connect_timer timed out!\n");

	if (ah_capwap_para.capwap_counter.dtls_retry_num >= ah_capwap_para.capwap_counter.max_dtls_retry) {
		ah_capwap_info.state = AH_CAPWAP_START;
		ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		AH_CAPWAP_ADD_DTLS_CONNECT_FAILED_NUM;
	} else {
		ah_capwap_info.state = AH_CAPWAP_DTLS_SETUP;
		ah_capwap_info.event = AH_CAPWAP_DTLS_HANDSHAKE;
		ah_capwap_para.capwap_counter.dtls_retry_num ++;
	}
	if (AH_CAPWAP_GET_DTLS_CONNECT_FAILED_NUM >= AH_CAPWAP_MAX_DTLS_CONTINUE_CONNECT_FAILED_THRESHOLD) {
		ah_log_old(AH_LOG_ERR, "CAPWAP detect OpenSSL hung, need restart CAPWAP");
		/* reset capwap watchdog check */
		ah_top_reset_dog_shm("capwap");
		ah_system("killall -9 capwap");
	}
	ah_capwap_dtls_conn_abort();
	ah_capwap_interrupt_listen();
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_disconn_timer
 *
 * Purpose:   handle dtls disconnect time out
 *
 * Inputs:    timername: timer name
 *            timerparameter: timer parameter
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_dtls_disconn_timer(ah_ptimer_t *timername, void *timerparameter)
{
	/*
	   1.change state to AH_CAPWAP_IDLE
	   2.interrup select
	 */
	ah_dbg_old(capwap_ssl, "timer ah_capwap_dtls_disconn_timer timed out\n");
	ah_dbg_old(capwap_info, "timer ah_capwap_dtls_disconn_timer timed out\n");

	ah_capwap_info.state = AH_CAPWAP_START;
	ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;

	ah_capwap_interrupt_listen();

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_sendmode
 *
 * Purpose:   set send packet mode
 *
 * Inputs:    pktmode: send packet mode
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_sendmode(uint32_t pktmode)
{
	ah_capwap_para.capwapaddr.sin_family = AF_INET;
	ah_capwap_para.capwapaddr.sin_port = htons(ah_capwap_para.capwap_port);

	if (pktmode == AH_CAPWAP_SND_UNICAST) {
		ah_capwap_para.capwapaddr.sin_addr.s_addr = htonl(ah_capwap_info.acip);
		ah_dbg_old(capwap_basic, "UNICAST: IP = %s,Port = %d\n", inet_ntoa(ah_capwap_para.capwapaddr.sin_addr),
				   ntohs(ah_capwap_para.capwapaddr.sin_port));
		return ;
	}

	ah_capwap_para.capwapaddr.sin_addr.s_addr = htonl(AH_CAPWAP_BROADCAST);
	ah_dbg_old(capwap_basic, "BROADCAST: IP = %s,Port = %d\n", inet_ntoa(ah_capwap_para.capwapaddr.sin_addr),
			   ntohs(ah_capwap_para.capwapaddr.sin_port));
	ah_capwap_info.acpri = AH_CAPWAP_GET_AC_BROADCAST; /*set the priority of acip*/
	ah_capwap_info.acip = 0;

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_createsock
 *
 * Purpose:   create a capwap socket
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_createsock()
{

	int      rnt = 0;
	int      n = 1;

#if 0  /* fix capwap packet can't go through ipsec tunnel, 
           change from bind mgt0 ip to bind INADDR_ANY */
	uint      hostip = 0;

	hostip = ah_capwap_getip();
	if (hostip == 0) {
		ah_log_old(AH_LOG_INFO, "CAPWAP can not get box ip!\n");
		return -1;
	}
#endif
	bzero(&ah_capwap_para.capwapaddr, sizeof(ah_capwap_para.capwapaddr));
	ah_capwap_para.capwapaddr.sin_family = AF_INET;

	/* ah_capwap_para.capwapaddr.sin_addr.s_addr = htonl(hostip);
	   fix bug9848 capwap packet can't go through ipsec tunnel,
	   change from bind mgt0 ip to bind INADDR_ANY */
	ah_capwap_para.capwapaddr.sin_addr.s_addr = INADDR_ANY;

	/*set up a socket for UDP*/
	if ((ah_capwap_para.sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ah_err_old("CAPWAP socket call error:(rc:%d)", ah_capwap_para.sock);
		perror(" ");
		return -1;
	}

	/*let the socket support BROADCAST*/
	rnt = setsockopt(ah_capwap_para.sock, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n));
	if (rnt == -1) {
		ah_err_old("CAPWAP setsockopt error!\n");
		return -1;
	}
	n = 1;
	if (setsockopt(ah_capwap_para.sock, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) == -1) {
		ah_err_old("CAPWAP setsockopt reuseed error!\n");
		return -1;
	}

	if ((bind(ah_capwap_para.sock, (struct sockaddr *)&ah_capwap_para.capwapaddr, sizeof(struct sockaddr))) == -1) {
		ah_err_old("CAPWAP bind sock error!");
		perror(" ");
		return -1;
	}

	ah_dbg_old(capwap_info, "IP = %s,Port = %d\n", inet_ntoa(ah_capwap_para.capwapaddr.sin_addr), ntohs(ah_capwap_para.capwapaddr.sin_port));

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_printpacket
 *
 * Purpose:   print the CAPWAP packet
 *
 * Inputs:    packetbuf: capwap buff
 *            packetlen: capwap packet len
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_printpacket(char *packetbuf, short packetlen)
{
	short      curlen = 0;

	for (curlen = 0; curlen < packetlen; curlen ++) {
		ah_dbg_old(capwap_packet, " %02X", *(uchar *)(packetbuf + curlen));
		if (((curlen + 1) % 6) == 0) {
			ah_dbg_old(capwap_packet, "\n");
		}
	}
	ah_dbg_old(capwap_packet, "\n");
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_chgfsm_parmeter
 *
 * Purpose:   change CAPWAP sate machine
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_chgfsm_parmeter()
{
	uint32_t    oldstate = 0;
	uint32_t    oldevent = 0;
	uint32_t    send_hm_ip = 0;

	if (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
		ah_capwap_info.state = AH_CAPWAP_END;
		ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;
	}

	oldstate = ah_capwap_info.state;
	oldevent = ah_capwap_info.event;

	switch (ah_capwap_info.state) {
	case AH_CAPWAP_START:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_GET_HOST_IP;
		ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;
		break;
	case AH_CAPWAP_GET_HOST_IP:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_GET_NMS_IP;
		ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;
		break;
	case AH_CAPWAP_GET_NMS_IP:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_IDLE;
		ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;
		break;
	case AH_CAPWAP_IDLE:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_DISCOVERY;
		ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
		break;
	case AH_CAPWAP_DISCOVERY:
		ah_tpa_set_capwap_status(AH_CAPWAP_NOT_RUN);
#if AH_SUPPORT_UPGRADE_SAFELY
		ah_tpa_set_capwap_conn_info(((ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_DISABLE) ? 0 : 1),
									ah_capwap_para.capwap_port, ((ah_capwap_info.state == AH_CAPWAP_RUN) ? 1 : 0), ah_capwap_info.acip);
#endif
		ah_event_send(AH_EVENT_CAPWAP_DISCONNECT, 0, NULL);
#if (AH_PLATFORM_HAS_SINGLE_LED)|| ((AH_BOARD == AH_BOARD_ID_CHESAPEAKE) && defined (AH_SUPPORT_CHESAPEAKE_512M_DRAM_1G_NAND))  || ((AH_PLATFORM == AH_PLATFORM_BRCM1) && defined(CONFIG_AP1130))
		if (ah_dcd_led_unset_flag_capwap_ready() != 0) {
			ah_log_old(AH_LOG_ERR, "CAPWAP: unset AP120 LED color failed.");
		}
#endif
		if (ah_capwap_para.capwap_counter.discovery_count >=
			ah_capwap_para.capwap_counter.max_discoveries) { /*the discovery is to the max, entry sulking*/
			ah_capwap_info.state = AH_CAPWAP_SULKING;
			ah_capwap_para.state_duration = 0;
			ah_capwap_info.event = 0;
			ah_dbg_old(capwap_info, "current discovery count is %d,max discovery count is%d\n", ah_capwap_para.capwap_counter.discovery_count,
					   ah_capwap_para.capwap_counter.max_discoveries);
			break;
		}
		if (ah_capwap_info.event == AH_CAPWAP_WAIT_SND_PKT) {
			ah_capwap_info.event = AH_CAPWAP_SND_PKT;
		} else if (ah_capwap_info.event == AH_CAPWAP_SND_PKT) {
			ah_capwap_info.event = AH_CAPWAP_RCV_PKT;
		} else if (ah_capwap_info.event == AH_CAPWAP_RCV_PKT) {
			ah_capwap_para.state_duration = 0;
			/*checke CAPWAP DTLS status*/
			if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
				ah_capwap_info.state = AH_CAPWAP_DTLS_SETUP;
				ah_capwap_info.event = AH_CAPWAP_DTLS_HANDSHAKE;
			} else {
				ah_capwap_info.state = AH_CAPWAP_JOIN;
				ah_capwap_info.event = AH_CAPWAP_SND_PKT;
			}
		} else {
			goto ERROR;
		}
		break;
	case AH_CAPWAP_SULKING:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_START;
		ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		break;
	case AH_CAPWAP_JOIN:
		ah_capwap_para.state_duration = 0;
		if (ah_capwap_info.event == AH_CAPWAP_SND_PKT) {
			ah_capwap_info.event = AH_CAPWAP_RCV_PKT;
		} else if (ah_capwap_info.event == AH_CAPWAP_RCV_PKT) {
			ah_capwap_info.state = AH_CAPWAP_RUN;
			ah_capwap_info.event = AH_CAPWAP_CHG_EVENT_SND_PKT;
		} else {
			goto ERROR;
		}
		break;
	case AH_CAPWAP_RUN:
		if (ah_capwap_info.event == AH_CAPWAP_CHG_EVENT_SND_PKT) {
			ah_capwap_para.state_duration = 0;
			ah_capwap_info.event = AH_CAPWAP_CHG_EVENT_RCV_PKT;
		} else if (ah_capwap_info.event == AH_CAPWAP_CHG_EVENT_RCV_PKT) {
			ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
			ah_tpa_set_capwap_status(AH_CAPWAP_HAS_RUN);/*fix bug#10532*/
#if AH_SUPPORT_UPGRADE_SAFELY
			ah_tpa_set_capwap_conn_info(((ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_DISABLE) ? 0 : 1),
										ah_capwap_para.capwap_port, ((ah_capwap_info.state == AH_CAPWAP_RUN) ? 1 : 0), ah_capwap_info.acip);
#endif
			ah_capwap_info.connected_flag = 1;
			send_hm_ip = htonl(ah_capwap_info.acip);
			ah_event_send(AH_EVENT_CAPWAP_CONNECT, sizeof(uint32_t), (void *)(&send_hm_ip));
			ah_dbg_old(capwap_ha, "Connected with HM %i", send_hm_ip);
			ah_log_old(AH_LOG_INFO, "CAPWAP_HM: Connected with HM %i", send_hm_ip);
			ah_capwap_para.primary_times = 0;
			ah_capwap_para.backup_times = 0;
#if (AH_PLATFORM_HAS_SINGLE_LED) || ((AH_BOARD == AH_BOARD_ID_CHESAPEAKE) && defined (AH_SUPPORT_CHESAPEAKE_512M_DRAM_1G_NAND)) || ((AH_PLATFORM == AH_PLATFORM_BRCM1) && defined(CONFIG_AP1130))
			if (ah_dcd_led_set_flag_capwap_ready() != 0) {
				ah_log_old(AH_LOG_ERR, "CAPWAP: set AP LED color failed.");
			}
#endif
		} else if (ah_capwap_info.event == AH_CAPWAP_WAIT_SND_PKT) {
			ah_capwap_info.event = AH_CAPWAP_SND_PKT;
		} else if (ah_capwap_info.event == AH_CAPWAP_SND_PKT) {
			ah_capwap_info.event = AH_CAPWAP_RCV_PKT;
		} else if (ah_capwap_info.event == AH_CAPWAP_RCV_PKT) {
			if (ah_capwap_event_need_snd() == 0) { /*the event buffer has msg to send*/
				ah_dbg_old(capwap_info, "The event buffer has event message to send, chang to send event!\n");
				ah_capwap_info.event = AH_CAPWAP_SND_EVENT;
			} else {
				ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
			}
		} else if (ah_capwap_info.event == AH_CAPWAP_SND_EVENT) {
			ah_capwap_info.event = AH_CAPWAP_RCV_EVENT;
		} else if (ah_capwap_info.event == AH_CAPWAP_RCV_EVENT) {
			ah_capwap_info.event = AH_CAPWAP_WAIT_SND_PKT;
		} else {
			goto ERROR;
		}
		break;
	case AH_CAPWAP_END:
		ah_capwap_para.state_duration = 0;
		if (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
			ah_capwap_info.state = AH_CAPWAP_END;
			ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;
		} else {
			ah_capwap_info.state = AH_CAPWAP_START;
			ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		}
		break;
	case AH_CAPWAP_DTLS_SETUP:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_JOIN;
		ah_capwap_info.event = AH_CAPWAP_SND_PKT;
		break;
	case AH_CAPWAP_DTLS_TDWN:
		ah_capwap_para.state_duration = 0;
		ah_capwap_info.state = AH_CAPWAP_START;
		ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		break;
	default :
		goto ERROR;
	}

	ah_dbg_old(capwap_basic, "state: %s--->%s, event: %s--->%s\n", ah_capwap_get_state_string(oldstate),
			   ah_capwap_get_state_string(ah_capwap_info.state),
			   ah_capwap_get_event_string(oldevent),
			   ah_capwap_get_event_string(ah_capwap_info.event));
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	if (oldstate != ah_capwap_info.state) {
		ah_capwap_handle_bonjour_service(FALSE);
	}
#endif
	return 0;
ERROR:
	ah_log_old(AH_LOG_INFO, "CAPWAP state change failed! state: %s,event %s", ah_capwap_get_state_string(ah_capwap_info.state),
			   ah_capwap_get_event_string(ah_capwap_info.event));
	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_check_client_server_subnet
 *
 * Purpose:   check hm's ip is the same subnet with hiveap ip address
 *
 * Inputs:    hm_ip: hm's ip address (network order)
 *
 * Output:    void
 *
 * Returns:   0 is the same subnet, -1 is not the same subnet
 *
 **************************************************************************/
int ah_capwap_check_client_server_subnet(uint32_t hm_ip)
{
	uint32_t    ipaddr = 0;
	uint32_t    mask = 0;

	if (ah_dcd_get_addr_byname(AH_CAPWAP_MGT, &ipaddr, &mask) < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: get box ip address and mask failed.\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "the value (ip & mask) from server is:%x, the value (ip & mask) from AP is:%x (mask:%i)\n", (hm_ip & mask),
			   (ipaddr & mask), mask);

	return ((hm_ip & mask) == (ipaddr & mask)) ? (0) : (-1);
}

/***************************************************************************
 *
 * Function:  ah_capwap_client_udp_listen
 *
 * Purpose:   listen to the socket and receive the packet for udp mode
 *
 * Inputs:    void
 *
 * Output:    capwaprxpkt: capwap receive packet
 *            pktlen: capwap receive packet len
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static int ah_capwap_client_udp_listen(char *capwaprxpkt, uint32_t *pktlen)
{
#define AH_CAPWAP_SELECT_TIMER 20000
	int      len = 0;
	uint      clear_len = 0;
	uint      dtls_len = 0;
	fd_set fdR;
	uint      max_socket = 0;
	int      rc = 0;
	struct sockaddr_in clear_pkt;
	struct sockaddr_in dtls_pkt;
	struct timeval capwapsel = {0, AH_CAPWAP_SELECT_TIMER};
	uint32_t    rcv_ip = 0;

	clear_len = sizeof(clear_pkt);
	dtls_len = sizeof(dtls_pkt);
	/*waiting for response packet, if have event, handle it at once*/
	if (ah_capwap_para.event != AH_CAPWAP_EVENT_WAIT) {
		ah_capwap_interrupt_listen();
	}
	ah_dbg_old(capwap_basic, "CAPWAP: cur_status:%s, cur_event:%s, timer to fire:%d", ah_capwap_get_state_string(ah_capwap_info.state),
			   ah_capwap_get_event_string(ah_capwap_info.event), ah_capwap_get_time2fire());
	if (capwap_basic) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: cur_status:%s, cur_event:%s, timer to fire:%d", ah_capwap_get_state_string(ah_capwap_info.state),
				   ah_capwap_get_event_string(ah_capwap_info.event), ah_capwap_get_time2fire());
	}
	while (ah_capwap_get_listen_state() == AH_CAPWAP_LISTEN_KEEP && ah_capwap_para.enable == AH_CAPWAP_ENABLE) {
		capwapsel.tv_usec = AH_CAPWAP_SELECT_TIMER;
		FD_ZERO(&fdR);
		FD_SET(ah_capwap_para.sock, &fdR);
		if (ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ] != AH_CAPWAP_DTLS_SOCKET_UNAVLIB
			&& ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE] != AH_CAPWAP_DTLS_SOCKET_UNAVLIB) {
			FD_SET(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], &fdR);
		}
		/*set the max select socket number*/
		if (ah_capwap_para.sock > ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ]) {
			max_socket = ah_capwap_para.sock + 1;
		} else {
			max_socket = ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ] + 1;
		}
		switch (select(max_socket, &fdR, NULL, NULL, &capwapsel)) {
		case -1:
			if (errno == EINTR) {
				//ah_log_old(AH_LOG_INFO, "CAPWAP receive an interrupt when select!(reason:%s)\n", strerror(errno));
				continue;
			}
			ah_dbg_old(capwap_info, "CAPWAP call select function errno:%d reason:%s!\n", errno, strerror(errno));
			continue;
		case 0:
			/*select time out*/
			continue;
		default:
			if (FD_ISSET(ah_capwap_para.sock, &fdR)) {
				if ((len = recvfrom(ah_capwap_para.sock, (char *)capwaprxpkt, AH_CAPWAP_BUF_LEN, 0, (struct sockaddr *)&clear_pkt, &clear_len)) <= 0) {
					ah_log_old(AH_LOG_INFO, "CAPWAP receive packet error! (socket id is:%d)\n", ah_capwap_para.sock);
					continue;
				}
				ah_capwap_increase_receive_bytes_counter((uint32_t)len);
				*pktlen = len;
				ah_dbg_old(capwap_info, "recv %d bytes from %i port:%d, exp:%i, port:%d\n", len, clear_pkt.sin_addr.s_addr,
						   ntohs(clear_pkt.sin_port), ntohl(ah_capwap_info.acip), ah_capwap_info.acport);
#if 0
				/*check the source ip is the same as host ip*/
				if (ah_capwap_info.wtpip == ntohl(clear_pkt.sin_addr.s_addr)) {
					ah_log_old(AH_LOG_INFO, "CAPWAP receive the packet which source ip (%i) is the same with box ip!\n", ntohl(clear_pkt.sin_addr.s_addr));
					continue;
				}
#endif
				/*Support BR send broadcast packet from WAN interface*/
				if (!ah_dcd_is_in_br_mode()) {
					/*if discovery by broadcast, need check responser ip is the same subnet with HiveAP or not*/
					rcv_ip = (uint32_t)(clear_pkt.sin_addr.s_addr); /*see bug#11627*/
					if (ah_capwap_info.acip == 0 && ah_capwap_check_client_server_subnet(rcv_ip) != 0) {
						ah_log_old(AH_LOG_WARNING,
								   "CAPWAP: receive a discovery response from wrong subnet when sending broadcast discovery request, the response ip is:%i\n",
								   clear_pkt.sin_addr.s_addr);
						continue;
					}
				}
				/*check the source ip and save the ac ip*/
				if ((ah_capwap_info.acip != 0 && ah_capwap_info.acip != ntohl(clear_pkt.sin_addr.s_addr))
					|| (ah_capwap_info.acport !=  AH_CAPWAP_PORT_INVALID && ah_capwap_info.acport != ntohs(clear_pkt.sin_port))) {
					ah_log_old(AH_LOG_INFO, "CAPWAP receive an unknown ip packet ip(%i) port(%d)! expect ip(%i), expect port(%d)\n",
							   clear_pkt.sin_addr.s_addr, ntohs(clear_pkt.sin_port), ntohl(ah_capwap_info.acip), ah_capwap_info.acport);
					continue;
				}
				/*check packet is SSL packet or not*/
				rc = ah_capwap_dtls_pkt_type(capwaprxpkt, len);
				if (rc == AH_CAPWAP_DTLS_PKT) {
					/*will read from SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], send DTLS packet in function
					  ah_capwap_dtls_pkt_type()*/
					continue ;
				} else if (rc == AH_CAPWAP_ERROR_PKT) {
					/*drop it*/
					continue;
				}
				/*analyse the packet*/
				if (ah_capwap_analysepacket(capwaprxpkt, len) == -1) {
					ah_dbg_old(capwap_info, "receive an error format pakcet!\n");
					continue;
				}
				if (capwap_packet) {
					ah_dbg_old(capwap_packet, "CAPWAP client receive packet len %d.\n", len);
					ah_hexdump((uchar *)capwaprxpkt, len);
				}
				ah_capwap_info.acip = ntohl(clear_pkt.sin_addr.s_addr);/*Store the AC ip*/
				ah_capwap_info.acport = ntohs(clear_pkt.sin_port);/*Store the AC port*/
				ah_dbg_old(capwap_info, "receive the response packet from: %s port: %d\n", inet_ntoa(clear_pkt.sin_addr), ntohs(clear_pkt.sin_port));
				return 0;
			}
			/*capwap and ssl socket, local socket*/
			if ((ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ] != AH_CAPWAP_DTLS_SOCKET_UNAVLIB)
				&& FD_ISSET(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], &fdR)) {
				if ((len = recvfrom(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ],
									(char *)capwaprxpkt, AH_CAPWAP_BUF_LEN, 0, (struct sockaddr *)&dtls_pkt, &dtls_len)) <= 0) {
					ah_dbg_old(capwap_ssl, "SSL socket receive from failed. reason:%s\n", strerror(errno));
					continue;
				}
				ah_dbg_old(capwap_ssl, "SSL socket receive from %i, pkt len:%d\n", ntohl(dtls_pkt.sin_addr.s_addr), len);
				if (capwap_packet) {
					ah_hexdump((uchar *)capwaprxpkt, len);
				}
				/*add the capwap header and send the SSL packet, go on waitting for*/
				ah_capwap_dtls_snd_pkt(capwaprxpkt, len);

				continue;
			}
		}
	}
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_client_listen
 *
 * Purpose:   listen to the socket and receive the packet
 *
 * Inputs:    void
 *
 * Output:    capwaprxpkt: capwap receive packet
 *            pktlen: capwap receive packet len
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_client_listen(char *capwaprxpkt, uint32_t *pktlen)
{
	int rc = 0;

	if (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_DISABLE) {
		rc = ah_capwap_client_udp_listen(capwaprxpkt, pktlen);
	} else {
		rc = ah_capwap_client_tcp_listen(capwaprxpkt, pktlen);
	}

	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_ver
 *
 * Purpose:   get box version
 *
 * Inputs:    ver: version in uint32
 *
 * Output:    verstr:  version in string
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_ver(uint32_t ver, uchar *verstr)
{
	union verunion {
		uint32_t     vernum;
		uchar      verchar[4];
	} verunion_un;

	verunion_un.vernum = ver;
#if __BYTE_ORDER == __BIG_ENDIAN
	sprintf((char *)verstr, "%d.%d.%d.%d", verunion_un.verchar[0], verunion_un.verchar[1], verunion_un.verchar[2], verunion_un.verchar[3]);
#else
	sprintf((char *)verstr, "%d.%d.%d.%d", verunion_un.verchar[3], verunion_un.verchar[2], verunion_un.verchar[1], verunion_un.verchar[0]);
#endif

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_hm_name2ip
 *
 * Purpose:   get hm ip from hm name
 *
 * Inputs:    hm_name: hm name string
 *
 * Output:    void
 *
 * Returns:   >0 ip address, otherwise failed
 *
 **************************************************************************/
static uint32_t ah_capwap_hm_name2ip(char *hm_name)
{
	struct hostent *serhost = NULL;
	struct sockaddr_in seraddr;
	uint32_t    ser_ip = 0;

	/*force to init the gethostbyname. so the system can get the dns change in resov.conf*/
	res_init();
	serhost = gethostbyname(hm_name);
	if (serhost == NULL) {
		/*can not resolve it*/
		ah_log_old(AH_LOG_INFO, "CAPWAP_HM:can not find the ip address of hostname  (%s),reason:%s\n",
				   hm_name, hstrerror(h_errno));
		ah_dbg_old(capwap_ha, "can not get ip from HM's name:(%s)", hm_name);
		return 0;
	}
	/*can resolve it*/
	bcopy(serhost->h_addr, (char *)&seraddr.sin_addr, serhost->h_length);
	ser_ip = ntohl(seraddr.sin_addr.s_addr);
	ah_dbg_old(capwap_ha, "get capwap server ip (%i) for name (%s)", ntohl(ser_ip), hm_name);
	ah_log_old(AH_LOG_INFO, "CAPWAP_HM:get capwap server ip (%i) for name (%s)", ntohl(ser_ip), hm_name);

	return ser_ip;
}

/***************************************************************************
 *
 * Function:  ah_capwap_switch_udp2tcp
 *
 * Purpose:   change send udp mode to tcp mode
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static uint32_t ah_capwap_switch_udp2tcp()
{
	if (ah_capwap_get_tcp_status() != AH_CAPWAP_TCP_ENABLE) {
		ah_capwap_set_tcp_status(AH_CAPWAP_TCP_ENABLE_PREDEF_MODE);
	}
	ah_capwap_para.capwap_port = AH_CAPWAP_HTTP_DEFAULT_PORT;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_switch_tcp2udp
 *
 * Purpose:   change send tcp mode to udp mode
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static uint32_t ah_capwap_switch_tcp2udp()
{
	if (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_ENABLE_PREDEF_MODE) {
		ah_capwap_set_tcp_status(AH_CAPWAP_TCP_DISABLE);
	}

	return 0;
}

#define AH_CAPWAP_IS_DFT_PORT (ah_capwap_para.capwap_port == AH_CAPWAP_PORT || \
							   ah_capwap_para.capwap_port == AH_CAPWAP_HTTP_DEFAULT_PORT)
#define AH_CAPWAP_NOT_DEF_HTTP_MODE (ah_capwap_get_tcp_status() != AH_CAPWAP_TCP_ENABLE)
#define AH_CAPWAP_HAS_DEF_HTTP_MODE (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_ENABLE)
/***************************************************************************
 *
 * Function:  ah_capwap_try_broadcast
 *
 * Purpose:   change to send broadcast mode
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static uint32_t ah_capwap_try_broadcast(ah_capwap_choose_ac_level ac_level)
{
	ah_capwap_switch_tcp2udp();
	ah_capwap_set_choose_ac(ac_level);
	ah_capwap_info.acip = 0;

	return 0;
}


#define AH_CAPWAP_CHK_SWITCH_UDP2TCP(srv_ip) ((srv_ip) > 0 && \
		(AH_CAPWAP_IS_DFT_PORT || AH_CAPWAP_HAS_DEF_HTTP_MODE))
#define AH_CAPWAP_CHK_SWITCH_TCP2UDP(srv_ip) ((srv_ip) > 0 && \
		(AH_CAPWAP_NOT_DEF_HTTP_MODE))
#define AH_CAPWAP_NMS_NAME_DFT AH_OEM_DFT_SRV
/***************************************************************************
 *
 * Function:  ah_capwap_get_not_def_hm_info
 *
 * Purpose:   set hm's information if user doesn't config any hm's name
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_get_not_def_hm_info()
{
	uint32_t    fix_ip = 0;
	uint32_t    pre_ip = 0;
	int      ac_mode = 0;

	/*1. use fix name udp to try
	 *2. use fix name tcp to try
	 *3. use broadcast to try
	 *4. use predefine server name udp to try
	 *5. use predefine server name tcp to try
	 *6. failed, goto 1)
	 */
	ah_dbg_old(capwap_ha, "user doesn't config primary and backup HM's name," \
			   "use fixed server name and pre-defined server name to try");
	ah_log_old(AH_LOG_INFO, "CAPWAP_HM:user doesn't config primary and backup HM's name," \
			   "use fixed server name and pre-defined server name to try");
	fix_ip = ah_capwap_hm_name2ip(AH_CAPWAP_NMS_NAME_DFT);
	pre_ip = ah_capwap_hm_name2ip(ah_capwap_para.predefine_name);
	/*can not get fixed name and predefine name, use broadcast*/
	if (fix_ip == 0 && pre_ip == 0 && AH_CAPWAP_NOT_DEF_HTTP_MODE) {
		ah_capwap_try_broadcast(AH_CAPWAP_CHOOSE_AC_BROADCAST_PREDEFINE);
		ah_dbg_old(capwap_ha, "can not resolve fixed/predefine name, use broadcast, ip=%i, port=%d",
				   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
		ah_log_old(AH_LOG_INFO, "CAPWAP_HM:can not resolve fixed/predefine name, use broadcast, ip=%i, port=%d",
				   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
		return 0;
	}

	while (1) {
		/*get last status*/
		ac_mode = ah_capwap_get_choose_ac();
		/*Get configed port number to avoid the port changed in
		 *between HTTP and UDP mode for default server.*/
		ah_capwap_get_port((int *)&ah_capwap_para.capwap_port);
		switch (ac_mode) {
		case AH_CAPWAP_CHOOSE_AC_INIT:
		case AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP:
		case AH_CAPWAP_CHOOSE_AC_BROADCAST_PREDEFINE:
			/*use fixed server name to try upd*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_FIXED);
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(fix_ip)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = fix_ip;
				ah_dbg_old(capwap_ha, "use fixed server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use fixed server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_FIXED:
			/*use fixed server name to try tcp*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_FIXED_TCP);
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(fix_ip)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = fix_ip;
				ah_dbg_old(capwap_ha, "use fixed server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use fixed server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_FIXED_TCP:
			/*use broadcast to try*/
			ah_capwap_try_broadcast(AH_CAPWAP_CHOOSE_AC_BROADCAST);
			if (AH_CAPWAP_NOT_DEF_HTTP_MODE) {
				ah_dbg_old(capwap_ha, "use broadcast, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use broadcast, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
			} else {
				ah_dbg_old(capwap_ha, "Don't use broadcast because define HTTP mode, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:Don't use broadcast because define HTTP mode, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
			}

			break;
		case AH_CAPWAP_CHOOSE_AC_BROADCAST:
			/*use predefine server try udp*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PREDEFINE_UDP);
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(pre_ip)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = pre_ip;
				ah_dbg_old(capwap_ha, "use predefine server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM: use predefine server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_PREDEFINE_UDP:
			/*use predefin server try tcp*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP);
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(pre_ip)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = pre_ip;
				ah_dbg_old(capwap_ha, "use predefine server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use predefine server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		default:
			ah_dbg_old(capwap_ha, "find wrong last HM record:%d, set to initial\n", ac_mode);
			ah_log_old(AH_LOG_INFO, "CAPWAP_HM:find wrong last HM record:%d, set to initial\n", ac_mode);
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
			continue;
		}
		ah_capwap_info.acpri = AH_CAPWAP_GET_AC_BROADCAST;

		return 0;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_has_def_hm_info
 *
 * Purpose:   set hm's information if user has config any hm's name
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_get_has_def_hm_info(ah_nms_names_t *hm_names)
{
#define AH_CAPWAP_GET_HM_CLI_TIMES_MAX 3
	int      ac_mode = 0;
	uint32_t    pri_ip = 0;
	uint32_t    bak_ip = 0;
	ah_nms_names_t dhcp_nms;
	uint32_t    dhcp_pri = 0;
	uint32_t    dhcp_bak = 0;
	uint32_t    fix_ip = 0;
	uint32_t    pre_ip = 0;

	/* 1. use primary name (udp mode, tcp mode)
	   2. use backup name (udp mode, tcp mode)
	   3. failed,loop 1) - 2) up to 3 times
	   lauch auto discover process:
	   4. use DHCP if it is not same with CLI configure (udp mode, tcp mode)
	   5. use DNS(fix name) if it is not same with CLI configure (udp mode, tcp mode)
	   6. use broadcasting to try(if enable)
	   7. use predefine server name (udp mode, tcp mode)
	   8. failed, goto 1)
	   */
	ah_dbg_old(capwap_ha, "user has configured primary or backup HM's name");
	ah_log_old(AH_LOG_INFO, "CAPWAP_HM:user has configured primary or backup HM's name");
	if (hm_names->first[0]) {
		pri_ip = ah_capwap_hm_name2ip(hm_names->first);
	}
	if (hm_names->second[0]) {
		bak_ip = ah_capwap_hm_name2ip(hm_names->second);
	}

	ah_tpa_get_val_nmsname(&dhcp_nms);
	if (dhcp_nms.first[0]) {
		dhcp_pri = ah_capwap_hm_name2ip(dhcp_nms.first);
	}
	if (dhcp_nms.second[0]) {
		dhcp_bak = ah_capwap_hm_name2ip(dhcp_nms.second);
	}

	if (pri_ip == 0 && bak_ip == 0) {
		/*primary name and backup name are all can not be resolved*/
		switch (ah_capwap_get_choose_ac()) {
		case AH_CAPWAP_CHOOSE_AC_INIT:
		case AH_CAPWAP_CHOOSE_AC_PRIMARY:
		case AH_CAPWAP_CHOOSE_AC_PRIMARY_TCP:
		case AH_CAPWAP_CHOOSE_AC_BACKUP:
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_BACKUP_TCP);
			ah_capwap_para.primary_times = AH_CAPWAP_GET_HM_CLI_TIMES_MAX;
			ah_capwap_para.backup_times = AH_CAPWAP_GET_HM_CLI_TIMES_MAX;
			ah_dbg_old(capwap_ha, "Can not resolve primary and backup server name, try DHCP/DNS/broadcast/redirector");
			ah_log_old(AH_LOG_INFO, "CAPWAP_HM:Can not resolve primary and backup server name, try DHCP/DNS/broadcast/redirector");
			break;
		default:
			break;
		}
	}

	while (1) {
		/*get last status*/
		ac_mode = ah_capwap_get_choose_ac();
		/*Get configed port number to avoid the port changed in
		 *between HTTP and UDP mode for default server.*/
		ah_capwap_get_port((int *)&ah_capwap_para.capwap_port);
		switch (ac_mode) {
		case AH_CAPWAP_CHOOSE_AC_INIT:
			ah_capwap_para.primary_times = 0;
			ah_capwap_para.backup_times = 0;
		/* fallthrough */
		case AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP:
			/*use primary server name to try upd*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PRIMARY);
			ah_capwap_para.primary_times++;
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(pri_ip) &&
				(ah_capwap_para.primary_times <= AH_CAPWAP_GET_HM_CLI_TIMES_MAX)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = pri_ip;
				ah_dbg_old(capwap_ha, "use primary %d times",
						   ah_capwap_para.primary_times);
				ah_dbg_old(capwap_ha, "use primary server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);

				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use primary server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_PRIMARY:
			/*use primary server name to try tcp*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PRIMARY_TCP);
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(pri_ip)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = pri_ip;
				ah_dbg_old(capwap_ha, "use primary server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use primary server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_PRIMARY_TCP:
			/*use backup server name to try upd*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_BACKUP);
			ah_capwap_para.backup_times++;
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(bak_ip) &&
				(ah_capwap_para.backup_times <= AH_CAPWAP_GET_HM_CLI_TIMES_MAX)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = bak_ip;
				ah_dbg_old(capwap_ha, "use backup %d times",
						   ah_capwap_para.backup_times);
				ah_dbg_old(capwap_ha, "use backup server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use backup server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_BACKUP:
			/*use backup server name to try tcp*/
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_BACKUP_TCP);
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(bak_ip)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = bak_ip;
				ah_dbg_old(capwap_ha, "use backup server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use backup server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_BACKUP_TCP:
			if ((ah_capwap_para.primary_times < AH_CAPWAP_GET_HM_CLI_TIMES_MAX) &&
				(ah_capwap_para.backup_times < AH_CAPWAP_GET_HM_CLI_TIMES_MAX)) {
				ah_dbg_old(capwap_ha, "use %d times primary server, %d times backup server, continue to try CLI configuration",
						   ah_capwap_para.primary_times, ah_capwap_para.backup_times);
				ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP);
				continue;
			}
			ah_capwap_para.primary_times = 0;
			ah_capwap_para.backup_times = 0;
			ah_dbg_old(capwap_ha, "Can not connect to primary and backup server, try DHCP/DNS/broadcast/redirector");
			ah_log_old(AH_LOG_INFO, "CAPWAP_HM:Can not connect to primary and backup server, try DHCP/DNS/broadcast/redirector");
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_DHCP);
			if ((dhcp_pri == pri_ip) || (dhcp_pri == bak_ip)) {
				ah_dbg_old(capwap_ha, "DHCP primary server is same with CLI configuration, skip");
				continue;
			}
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(dhcp_pri)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = dhcp_pri;
				ah_dbg_old(capwap_ha, "use DHCP primary server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use DHCP primary server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_DHCP:
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_DHCP_TCP);
			if ((dhcp_pri == pri_ip) || (dhcp_pri == bak_ip)) {
				ah_dbg_old(capwap_ha, "DHCP primary server is same with CLI configuration, skip");
				continue;
			}
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(dhcp_pri)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = dhcp_pri;
				ah_dbg_old(capwap_ha, "use DHCP primary server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use DHCP primary server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_DHCP_TCP:
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_DHCP_BACKUP);
			if ((dhcp_bak == pri_ip) || (dhcp_bak == bak_ip)) {
				ah_dbg_old(capwap_ha, "DHCP backup server is same with CLI configuration, skip");
				continue;
			}
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(dhcp_bak)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = dhcp_bak;
				ah_dbg_old(capwap_ha, "use DHCP backup server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use DHCP backup server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_DHCP_BACKUP:
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_DHCP_BACKUP_TCP);
			if ((dhcp_bak == pri_ip) || (dhcp_bak == bak_ip)) {
				ah_dbg_old(capwap_ha, "DHCP backup server is same with CLI configuration, skip");
				continue;
			}
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(dhcp_bak)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = dhcp_bak;
				ah_dbg_old(capwap_ha, "use DHCP backup server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use DHCP backup server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_DHCP_BACKUP_TCP:
			/*use fixed server name to try upd*/
			fix_ip = ah_capwap_hm_name2ip(AH_CAPWAP_NMS_NAME_DFT);
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_FIXED);
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(fix_ip)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = fix_ip;
				ah_dbg_old(capwap_ha, "use fixed server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use fixed server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_FIXED:
			/*use fixed server name to try tcp*/
			fix_ip = ah_capwap_hm_name2ip(AH_CAPWAP_NMS_NAME_DFT);
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_FIXED_TCP);
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(fix_ip)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = fix_ip;
				ah_dbg_old(capwap_ha, "use fixed server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use fixed server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_FIXED_TCP:
			/*use broadcast to try*/
			ah_capwap_try_broadcast(AH_CAPWAP_CHOOSE_AC_BROADCAST);
			if (ah_capwap_para.enable_discovery_bcast == AH_CAPWAP_DISCOVERY_BROADCAST_DISABLE) {
				ah_dbg_old(capwap_ha, "capwap server discovery method broadcast disable, skip");
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:capwap server discovery method broadcast disable, skip");
				continue;
			}
			if (AH_CAPWAP_NOT_DEF_HTTP_MODE) {
				ah_dbg_old(capwap_ha, "use broadcast, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use broadcast, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
			} else {
				ah_dbg_old(capwap_ha, "Don't use broadcast because define HTTP mode, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:Don't use broadcast because define HTTP mode, ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
			}
			break;
		case AH_CAPWAP_CHOOSE_AC_BROADCAST:
			/*use predefine server try udp*/
			pre_ip = ah_capwap_hm_name2ip(ah_capwap_para.predefine_name);
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PREDEFINE_UDP);
			if (AH_CAPWAP_CHK_SWITCH_TCP2UDP(pre_ip)) {
				ah_capwap_switch_tcp2udp();
				ah_capwap_info.acip = pre_ip;
				ah_dbg_old(capwap_ha, "use predefine server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM: use predefine server(UDP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			continue;
		case AH_CAPWAP_CHOOSE_AC_PREDEFINE_UDP:
			/*use predefin server try tcp*/
			pre_ip = ah_capwap_hm_name2ip(ah_capwap_para.predefine_name);
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_PREDEFINE_TCP);
			if (AH_CAPWAP_CHK_SWITCH_UDP2TCP(pre_ip)) {
				ah_capwap_switch_udp2tcp();
				ah_capwap_info.acip = pre_ip;
				ah_dbg_old(capwap_ha, "use predefine server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				ah_log_old(AH_LOG_INFO, "CAPWAP_HM:use predefine server(TCP), ip=%i, port=%d",
						   ntohl(ah_capwap_info.acip), ah_capwap_para.capwap_port);
				break;
			}
			/* can't find availiable capwap server ip, break the loop and wait next round */
			ah_dbg_old(capwap_ha, "try DHCP/DNS/broadcast/redirector, can not get HM's IP, wait next round");
			break;
		default:
			ah_dbg_old(capwap_ha, "find wrong last HM record:%d, set to initial\n", ac_mode);
			ah_capwap_set_choose_ac(AH_CAPWAP_CHOOSE_AC_INIT);
			continue;
		}
		ah_capwap_set_chg_ac_flag(AH_CAPWAP_NEED_CHG_AC);

		return 0;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_nmsip
 *
 * Purpose:   get nms ip
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
uint32_t ah_capwap_nmsip()
{
	ah_nms_names_t nms_names;
	ah_memset(&nms_names, 0, sizeof(ah_nms_names_t));

	/*get nms ip from scd*/
	ah_tpa_get_nmsname(&nms_names);
	ah_dbg_old(capwap_ha, "get hivemanager name from scd (first:%s, second:%s).\n",
			   nms_names.first, nms_names.second);
	ah_log_old(AH_LOG_INFO , "CAPWAP_HM:get hivemanager name from scd (first:%s, second:%s).\n",
			   nms_names.first, nms_names.second);
	if (strlen(nms_names.first) == 0 && strlen(nms_names.second) == 0) {
		/*user doen't define any hm name*/
		ah_capwap_get_not_def_hm_info();
	} else {
		/*user has define hm name*/
		ah_capwap_get_has_def_hm_info(&nms_names);
	}

	/*register destnation port to FE*/
	ah_capwap_register_mgt_port();

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_disable
 *
 * Purpose:   disable capwpa client
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void  ah_capwap_disable()
{
	/*need set dog flag and stop timer*/
	if (ah_capwap_durate_timer != NULL) {
		ah_pmpt_timer_stop(ah_capwap_durate_timer);
	}
	if (ah_capwap_timervar != NULL) {
		ah_pmpt_timer_stop(ah_capwap_timervar);
	}

	ah_capwap_info.state = AH_CAPWAP_END;
	ah_capwap_info.event = AH_CAPWAP_EVENT_NONE;

	ah_capwap_para.enable = AH_CAPWAP_DISABLE;

	/*reset durate time*/
	ah_capwap_para.state_duration = 0;

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_enable
 *
 * Purpose:   enable capwpa client
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_enable()
{
	ah_capwap_para.enable = AH_CAPWAP_ENABLE;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_time2fire
 *
 * Purpose:   get the how many sec until the time fire
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   >=0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_get_time2fire()
{
	return ah_pmpt_timer_time2fire(ah_capwap_timervar);
}

static uint32_t ah_capwap_reconnect_schedule = AH_CAPWAP_RECONNECT_NEXT;
/***************************************************************************
 *
 * Function:  ah_capwap_reset_reconnect_schedule
 *
 * Purpose:   reset reconnect schedul flag
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
inline void ah_capwap_reset_reconnect_schedule()
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_reconnect_schedule = AH_CAPWAP_RECONNECT_NEXT;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_reconnect_schedule
 *
 * Purpose:   set reconnect schedul flag
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
inline void ah_capwap_set_reconnect_schedule(uint32_t reconnect_schedule)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	ah_capwap_reconnect_schedule = reconnect_schedule;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_reconnect_schedule
 *
 * Purpose:   get reconnect schedul flag
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   reconnect schedul flag
 *
 **************************************************************************/
inline uint32_t ah_capwap_get_reconnect_schedule()
{
	uint32_t    reconnect_schedule = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	reconnect_schedule = ah_capwap_reconnect_schedule;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return reconnect_schedule;
}

/***************************************************************************
 *
 * Function:  ah_capwap_deal_event
 *
 * Purpose:   handle the capwap event
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_deal_event()
{
	int      leave_time = 0;

	if (ah_capwap_get_reconnect_schedule() == AH_CAPWAP_RECONNECT_NOW) {
		ah_capwap_info.state = AH_CAPWAP_START;
		ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		ah_capwap_set_reconnect_schedule(AH_CAPWAP_RECONNECT_NEXT);
		return;
	}

	if (ah_capwap_para.event != AH_CAPWAP_EVENT_WAIT && ah_capwap_para.enable == AH_CAPWAP_ENABLE) {
		/*unset timer*/
		leave_time = ah_pmpt_timer_time2fire(ah_capwap_timervar);
		if (leave_time < 0) {
			leave_time = 0;
		}
		if (ah_capwap_timervar != NULL) {
			ah_pmpt_timer_stop(ah_capwap_timervar);
		}

		/*if event need send by capwap,change state to send event. otherwise restart capwap*/
		if (ah_capwap_para.event > AH_CAPWAP_EVENT_SND_START && ah_capwap_para.event < AH_CAPWAP_EVENT_SND_END) {
			ah_capwap_info.state = AH_CAPWAP_RUN;
			ah_capwap_info.event = AH_CAPWAP_SND_EVENT;
			ah_capwap_timer_fire = leave_time;
		} else {
			ah_capwap_info.state = AH_CAPWAP_START;
			ah_capwap_info.event = AH_CAPWAP_WAIT_CLI;
		}

		/*reset event flag*/
		ah_capwap_para.event = AH_CAPWAP_EVENT_WAIT;
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_state_string
 *
 * Purpose:   get the capwap state string
 *
 * Inputs:    state: capwap state
 *
 * Output:    void
 *
 * Returns:   capwpa state string
 *
 **************************************************************************/
const char *ah_capwap_get_state_string(uint32_t state)
{
	/*string for capwap client state*/
	const static char *ah_capwap_state_str[] = {"Start", "Waitting for "AH_OEM_AP_NAME" IP", "Waitting for "AH_OEM_HM_NAME" IP",
												"Idle", "Discovery", "DTLS setup", "DTLS cut", "Sulking", "Join", "Run", "End"
											   };

	return ah_capwap_state_str[state];
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_event_string
 *
 * Purpose:   get the capwap event string
 *
 * Inputs:    event: capwap event
 *
 * Output:    void
 *
 * Returns:   capwpa event string
 *
 **************************************************************************/
const char *ah_capwap_get_event_string(uint32_t event)
{
	/*string for capwap event*/
	const static char *ah_capwap_event_str[] = {"none", "waitting for cli", "waitting sndpkt", "sndpkt", "rcvpkt",
												"sndchgevntpkt", "rckchgevntpkt", "sndeventpkt", "rcveventpkt", "DTLS connect", "DTLS abort"
											   };

	return ah_capwap_event_str[event];
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_timer_string
 *
 * Purpose:   get the capwap timer string
 *
 * Inputs:    timer: capwap timer
 *
 * Output:    void
 *
 * Returns:   capwpa timer string
 *
 **************************************************************************/
const char *ah_capwap_get_timer_string(uint32_t timer)
{
	/*string for capwap timer*/
	const static char *ah_capwap_timer_str[] = {"none", "discovery_timer", "echo_timer", "maxdis_timer", "neibo_timer", "respo_timer",
												"retran_timer", "silent_timer", "wait_timer", "idle_timer", "getnms_timer", "event_timer", "DTLS_delete_timer", "DTLS_handshake_timer"
											   };

	return ah_capwap_timer_str[timer];
}

/***************************************************************************
 *
 * Function:   ah_capwap_interrupt_listen
 *
 * Purpose:   interrupt from capwap listen
 *
 * Inputs:     void
 *
 *
 * Output:    void
 *
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_interrupt_listen()
{
	ah_capwap_para.listen = AH_CAPWAP_LISTEN_STOP;
}

/***************************************************************************
 *
 * Function:  ah_capwap_keep_listen
 *
 * Purpose:   keep capwap listen
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_keep_listen()
{
	ah_capwap_para.listen = AH_CAPWAP_LISTEN_KEEP;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_listen_state
 *
 * Purpose:   get the capwap listen state
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   capwap listen state
 *
 **************************************************************************/
int ah_capwap_get_listen_state()
{
	return ah_capwap_para.listen;
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_go_next_status
 *
 * Purpose:   set the capwap flag and go next status directly
 *
 * Inputs:    status_flag: go next status flag
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
inline int ah_capwap_set_go_next_status(int status_flag)
{
	ah_capwap_go_next_status_flag = status_flag;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_go_next_status
 *
 * Purpose:   get the capwap flag and go next status directly
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 is keep current status, 1 is go to next status
 *
 **************************************************************************/
inline int ah_capwap_get_go_next_status()
{
	return (ah_capwap_go_next_status_flag);
}

/*
 * for filter debug capwap packet
 */
void ah_capwap_evtpkt_print_filter(char *packet,
								   uint32_t    length,
								   uint32_t    msg_type,
								   uint32_t    direction)
{
	char      direct[32] = { 0 };

	ah_assert(NULL != packet);
	ah_sprintf(direct, "%s", ((direction == AH_CAPWAP_DBGPKT_TX) ? "send" : "receive"));

	if (capwap_packet) {
		; /* will print in ah_capwap_packet_client */
	} else {
		if (capwap_all_event_packet
			/* && (msg_type > AH_CAPWAP_EVENT_SND_START) */
			/* && (msg_type < AH_CAPWAP_EVENT_SND_END) */) {
			ah_dbg_old(capwap_all_event_packet,
					   "CAPWAP client %s %s type %d message len %d.\n",
					   direct, (((msg_type > AH_CAPWAP_EVENT_SND_START) && \
								 (msg_type < AH_CAPWAP_EVENT_SND_END)) ? "event" : "message"),
					   msg_type, length);
			ah_hexdump((uchar *)packet, (uint)length);
			return;
		}

		if (capwap_idp_packet && (msg_type == AH_CAPWAP_EVENT_IDP)) {
			ah_dbg_old(capwap_idp_packet,
					   "CAPWAP client %s IDP event, message len %d.\n",
					   direct, length);
			ah_hexdump((uchar *)packet, (uint)length);
			return;
		}

		if (capwap_cli_packet && (msg_type == AH_CAPWAP_EVENT_CLI)) {
			ah_dbg_old(capwap_cli_packet,
					   "CAPWAP client %s CLI response event, message len %d.\n",
					   direct, length);
			ah_hexdump((uchar *)packet, (uint)length);
			return;
		}

		if (capwap_trap_packet && (msg_type == AH_CAPWAP_EVENT_SEND_TRAP)) {
			ah_dbg_old(capwap_trap_packet,
					   "CAPWAP client %s trap event, message len %d.\n",
					   direct, length);
			ah_hexdump((uchar *)packet, (uint)length);
			return;
		}

		if (capwap_stat_packet && (msg_type == AH_CAPWAP_EVENT_STATISTICAL)) {
			ah_dbg_old(capwap_trap_packet,
					   "CAPWAP client %s packet statistical event, message len %d.\n",
					   direct, length);
			ah_hexdump((uchar *)packet, (uint)length);
			return;
		}

	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_upd_send
 *
 * Purpose:   capwap client send packet udp mode
 *
 * Inputs:    capwaprxpkt: capwap receive packet
 *                pktlen: capwap receive packet len
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
static int ah_capwap_udp_send(char *capwaptxpkt, uint32_t packlen)
{
	int      rc = 0;

	rc = sendto(ah_capwap_para.sock, capwaptxpkt, packlen, MSG_DONTWAIT, (struct sockaddr *)&ah_capwap_para.capwapaddr,
				sizeof(ah_capwap_para.capwapaddr));
	if (rc == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP send packet failed!packlen:%d/dst_ip:%s/src_ip:%i/udp_port:%d, reason:(%s)\n",
				   packlen, inet_ntoa(ah_capwap_para.capwapaddr.sin_addr), htonl(ah_capwap_info.wtpip), ntohs(ah_capwap_para.capwapaddr.sin_port),
				   strerror(errno));
	}
	ah_capwap_increase_send_bytes_counter(packlen);
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_client_send
 *
 * Purpose:   capwap client send packet
 *
 * Inputs:    capwaprxpkt: capwap receive packet
 *                pktlen: capwap receive packet len
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_client_send(char *capwaptxpkt, uint32_t packlen)
{
	if (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_DISABLE) {
		return (ah_capwap_udp_send(capwaptxpkt, packlen));
	} else {
		int32_t    snd_len = 0;
		snd_len = ah_capwap_tcp_send(capwaptxpkt, packlen);
		if (snd_len > 0) {
			ah_capwap_increase_send_bytes_counter(snd_len);
		}
		if (snd_len != packlen) {
			ah_log_old(AH_LOG_INFO, "CAPWAP: use TCP connection send %d bytes, actually send :%d bytes\n", snd_len, packlen);
			return -1;
		}
		return 0;
	}
}

static pthread_mutex_t ah_capwap_delay_lm;
inline void ah_capwap_delay_lm_init(void)
{
	pthread_mutex_init(&ah_capwap_delay_lm, NULL);
	return;
}

inline void ah_capwap_delay_lm_lock(void)
{
	pthread_mutex_lock(&ah_capwap_delay_lm);
	return;
}

inline void ah_capwap_delay_lm_unlock(void)
{
	pthread_mutex_unlock(&ah_capwap_delay_lm);
	return;
}

char *ah_capwap_64bit_num2str(int64_t value)
{
	static char str64_print[AH_CAPWAP_UINT64_STR_LEN];

	sprintf(str64_print, "%lld", value);

	return str64_print;
}

#define AH_CAPWAP_MINOR_THRESHOLD (60*1000)
#define AH_CAPWAP_MAJOR_THRESHOLD (123*1000)
#define AH_CAPWAP_DELAY_MAX_WAIT_TIMES (3)
static ah_capwap_delay_para_t ah_capwap_delay = {0, 0, AH_CAPWAP_DELAY_ALARM_NONE, 0, 0, 0,
												 AH_CAPWAP_MINOR_THRESHOLD, AH_CAPWAP_MAJOR_THRESHOLD,
												 AH_CAPWAP_DELAY_ALARM_NONE, TRUE
												};

inline int ah_capwap_set_alarm_init_status(boolean init_status)
{
	ah_capwap_delay.init_status = init_status;

	return 0;
}

inline boolean ah_capwap_get_alarm_init_status(void)
{
	return ah_capwap_delay.init_status;
}

inline int ah_capwap_set_last_alarm(ah_capwap_delay_alarm_t alarm)
{
	ah_capwap_delay.last_alarm = alarm;

	return 0;
}

inline ah_capwap_delay_alarm_t ah_capwap_get_last_alarm(void)
{
	return ah_capwap_delay.last_alarm;
}

static int ah_capwap_get_next_alarm(void)
{
	if ((ah_capwap_delay.min_alarm + ah_capwap_delay.maj_alarm) >= AH_CAPWAP_DELAY_MAX_WAIT_TIMES) {
		if (ah_capwap_delay.min_alarm == 0) {
			return AH_CAPWAP_DELAY_ALARM_MAJOR;
		} else {
			return AH_CAPWAP_DELAY_ALARM_MINOR;
		}
	}

	return AH_CAPWAP_DELAY_ALARM_STANDBY;
}

static int ah_capwap_set_abnormal_average_time(uint64_t delay_time)
{
	if (ah_capwap_delay.abnormal_average == 0) {
		ah_capwap_delay.abnormal_average = delay_time;
	} else {
		ah_capwap_delay.abnormal_average = (ah_capwap_delay.abnormal_average + delay_time) / 2;
	}
	ah_dbg_old(capwap_delay, "Update abnormal delay average to:%s ",
			   ah_capwap_64bit_num2str(ah_capwap_delay.abnormal_average));
	return 0;
}

inline int64_t ah_capwap_get_abnormal_agerage_time(void)
{
	return ah_capwap_delay.abnormal_average;
}

inline int ah_capwap_increase_minor_number(void)
{
	ah_capwap_delay.min_alarm ++;

	return 0;
}

inline int ah_capwap_get_minor_number(void)
{
	return ah_capwap_delay.min_alarm;
}

inline int ah_capwap_increase_major_number(void)
{
	ah_capwap_delay.maj_alarm ++;

	return 0;
}

inline int ah_capwap_get_major_number(void)
{
	return ah_capwap_delay.maj_alarm;
}

inline uint64_t ah_capwap_get_major_threshold(void)
{
	return ah_capwap_delay.maj_threshold;
}

int ah_capwap_set_major_threshold(const uint64_t threshold)
{
	ah_capwap_delay.maj_threshold = threshold;
	ah_dbg_old(capwap_delay, "Update delay major threshold to:%s by CLI",
			   ah_capwap_64bit_num2str(ah_capwap_delay.maj_threshold));

	return 0;
}

inline uint64_t ah_capwap_get_minor_threshold(void)
{
	return ah_capwap_delay.min_threshold;
}

int ah_capwap_set_minor_threshold(const uint64_t threshold)
{
	ah_capwap_delay.min_threshold = threshold;
	ah_dbg_old(capwap_delay, "Update delay minor threshold to:%s by CLI",
			   ah_capwap_64bit_num2str(ah_capwap_delay.min_threshold));

	return 0;
}

static int ah_capwap_reset_delay_info(void)
{
	ah_capwap_delay.min_alarm = 0;
	ah_capwap_delay.maj_alarm = 0;
	ah_capwap_delay.abnormal_average = 0;

	return 0;
}

uint64_t ah_capwap_get_delay_average(boolean print_debug)
{
	if (print_debug) {
		ah_dbg_old(capwap_delay, "Current delay average is:%s", ah_capwap_64bit_num2str(ah_capwap_delay.average));
	}

	return ah_capwap_delay.average;
}

int ah_capwap_set_delay_average_cli(const uint64_t average)
{
	ah_capwap_delay.average = average;
	ah_dbg_old(capwap_delay, "Update delay average to:%s by CLI",
			   ah_capwap_64bit_num2str(ah_capwap_delay.average));

	return 0;
}

static int ah_capwap_set_delay_average(const uint64_t average)
{
	if (ah_capwap_delay.average == 0) {
		ah_capwap_delay.average = average;
	} else {
		ah_capwap_delay.average = (ah_capwap_delay.average + average) / 2;
	}
	ah_dbg_old(capwap_delay, "Update delay average to:%s", ah_capwap_64bit_num2str(ah_capwap_delay.average));

	return 0;
}

static int ah_capwap_get_delay_alarm(void)
{
	return ah_capwap_delay.alarm;
}

int ah_capwap_set_delay_alarm(ah_capwap_delay_alarm_t alarm_type)
{
	ah_capwap_delay.alarm = alarm_type;

	return 0;
}

static int64_t ah_capwap_get_delay_offset(void)
{
	return ah_capwap_delay.offset;
}

static int ah_capwap_set_delay_offset(int64_t offset)
{
	ah_capwap_delay.offset = offset;

	return 0;
}

static char *ah_capwap_delay_alarm_to_name(ah_capwap_delay_alarm_t alarm_type)
{
	char *retval = NULL;
	switch (alarm_type) {
	case    AH_CAPWAP_DELAY_ALARM_NONE:
		retval = "None";
		break;
	case    AH_CAPWAP_DELAY_ALARM_CLEAR:
		retval = "Clear";
		break;
	case    AH_CAPWAP_DELAY_ALARM_MAJOR:
		retval = "Major";
		break;
	case    AH_CAPWAP_DELAY_ALARM_STANDBY:
		retval = "Standby";
		break;
	default:
		retval = "n/a";
		break;
	}

	return retval;
}

static int ah_capwap_handle_delay_alarm(ah_capwap_delay_alarm_t alarm_type)
{
	int      trap_type = AH_CAPWAP_DELAY_ALARM_NONE;

	ah_dbg_old(capwap_delay, "Current alarm type is %s", ah_capwap_delay_alarm_to_name(ah_capwap_get_delay_alarm()));
	switch (ah_capwap_get_delay_alarm()) {
	case AH_CAPWAP_DELAY_ALARM_NONE:
		if (alarm_type == AH_CAPWAP_DELAY_ALARM_MINOR
			|| alarm_type == AH_CAPWAP_DELAY_ALARM_MAJOR) {
			/*send alarm trap*/
			trap_type = alarm_type;
		}
		break;
	case AH_CAPWAP_DELAY_ALARM_MINOR:
		if (alarm_type == AH_CAPWAP_DELAY_ALARM_NONE) {
			/*send clear trap*/
			trap_type = AH_CAPWAP_DELAY_ALARM_CLEAR;
		} else if (alarm_type == AH_CAPWAP_DELAY_ALARM_MAJOR) {
			/*send major alarm trap*/
			trap_type = AH_CAPWAP_DELAY_ALARM_MAJOR;
		}
		break;
	case AH_CAPWAP_DELAY_ALARM_MAJOR:
		if (alarm_type == AH_CAPWAP_DELAY_ALARM_NONE) {
			/*send clear trap*/
			trap_type = AH_CAPWAP_DELAY_ALARM_CLEAR;
		} else if (alarm_type == AH_CAPWAP_DELAY_ALARM_MINOR) {
			/*send minor alarm trap*/
			trap_type = AH_CAPWAP_DELAY_ALARM_MINOR;
		}
		break;
	default:
		return trap_type;
	}

	ah_capwap_set_delay_alarm(alarm_type);
	ah_dbg_old(capwap_delay, "Update alarm type to %s", ah_capwap_delay_alarm_to_name(trap_type));

	return trap_type;
}

#define AH_CAPWAP_DELAY_TIMES_FOR_MINOR (3)
#define AH_CAPWAP_DELAY_TIMES_FOR_MAJOE (10)
static int ah_capwap_send_delay_trap(const uint64_t delay_time, int trap_type)
{
#define AH_CAPWAP_MAX_DELAY_TRAP_BUFF (1000)
#define AH_CAPWAP_DELAY_TRAP_ALARM "It is currently taking longer to contact the capwap server than the threshold specified in settings"
#define AH_CAPWAP_DELAY_TRAP_CLEAR "It is currently taking lower to contact the capwap server than the threshold specified in settings"
	char      *trap_msg = NULL;
	int      trap_len = 0;
	long      trap_type_id;
	boolean clear;

	if (trap_type == AH_CAPWAP_DELAY_ALARM_NONE
		|| trap_type == AH_CAPWAP_DELAY_ALARM_STANDBY) {
		return 0;
	}

	trap_msg = malloc(AH_CAPWAP_MAX_DELAY_TRAP_BUFF);
	if (trap_msg == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: malloc %d bytes for send delay trap failed.", AH_CAPWAP_MAX_DELAY_TRAP_BUFF);
		return -1;
	}
	/*fill trap type*/
	*(char *)(trap_msg) = AH_CAPWAP_DELAY_TRAP;
	trap_type_id = AH_CAPWAP_DELAY_TRAP << 16;
	trap_len += sizeof(char);
	/*skip trap total len*/
	trap_len += sizeof(ushort);
	/*fill trap description*/
	if (trap_type == AH_CAPWAP_DELAY_ALARM_CLEAR) {
		clear = AH_MSG_TRAP_CLEAR;
		*(char *)(trap_msg + trap_len) = strlen(AH_CAPWAP_DELAY_TRAP_CLEAR);
		trap_len += sizeof(char);
		ah_memcpy(trap_msg + trap_len, AH_CAPWAP_DELAY_TRAP_CLEAR, strlen(AH_CAPWAP_DELAY_TRAP_CLEAR));
		trap_len += strlen(AH_CAPWAP_DELAY_TRAP_CLEAR);
	} else {
		clear = AH_MSG_TRAP_SET;
		*(char *)(trap_msg + trap_len) = strlen(AH_CAPWAP_DELAY_TRAP_ALARM);
		trap_len += sizeof(char);
		ah_memcpy(trap_msg + trap_len, AH_CAPWAP_DELAY_TRAP_ALARM, strlen(AH_CAPWAP_DELAY_TRAP_ALARM));
		trap_len += strlen(AH_CAPWAP_DELAY_TRAP_ALARM);
	}
	/*fill trap severity*/
	*(char *)(trap_msg + trap_len) = (char)trap_type;
	trap_len += sizeof(char);
	/*fill average delay*/
	*(uint64_t *)(trap_msg + trap_len) = htonll(ah_capwap_get_delay_average(FALSE));
	trap_len += sizeof(uint64_t);
	/*fill current delay*/
	*(uint64_t *)(trap_msg + trap_len) = htonll(delay_time);
	trap_len += sizeof(uint64_t);
	/*fill minor threshold*/
	*(uint64_t *)(trap_msg + trap_len) = htonll(ah_capwap_get_minor_threshold());
	trap_len += sizeof(uint64_t);
	/*fill major threshold*/
	*(uint64_t *)(trap_msg + trap_len) = htonll(ah_capwap_get_major_threshold());
	trap_len += sizeof(uint64_t);

	/*fill trap total len*/
	*(ushort *)(trap_msg + sizeof(char)) = htons(trap_len - sizeof(char) - sizeof(ushort));

	//ah_capwap_send_trap(trap_len, trap_msg, AH_MSG_TRAP_CAPWAP_DELAY);
	ah_capwap_send_trap_with_id(trap_len, trap_msg, AH_MSG_TRAP_CAPWAP_DELAY, trap_type_id, clear);
	free(trap_msg);
	ah_dbg_old(capwap_delay, "Send capwap delay alarm %s trap", ah_capwap_delay_alarm_to_name(trap_type));
	/*reset delay information*/
	ah_capwap_reset_delay_info();
	ah_capwap_set_last_alarm(AH_CAPWAP_DELAY_ALARM_NONE);

	return 0;
}

static ah_capwap_delay_alarm_t ah_capwap_prehandle_alarm(const int64_t delay_time,
		const int64_t min_threshold, const int64_t maj_threshold)
{
	/*normal delay time*/
	if (delay_time < min_threshold) {
		ah_capwap_set_delay_average(delay_time);
		ah_capwap_reset_delay_info();
		ah_capwap_set_last_alarm(AH_CAPWAP_DELAY_ALARM_NONE);
		ah_dbg_old(capwap_delay, "the delay time is normally, reset all delay information");
		return AH_CAPWAP_DELAY_ALARM_NONE;
	}

	/*minor delay time*/
	if (delay_time > min_threshold && delay_time < maj_threshold) {
		ah_capwap_increase_minor_number();
		ah_capwap_set_abnormal_average_time(delay_time);
		ah_capwap_set_last_alarm(AH_CAPWAP_DELAY_ALARM_MINOR);
		ah_dbg_old(capwap_delay, "the delay time is in minor threshold, minor threshold %d time, major threshold %d times",
				   ah_capwap_get_minor_number(), ah_capwap_get_major_number());
		return ah_capwap_get_next_alarm();
	}
	/*major delay time*/
	ah_capwap_increase_major_number();
	ah_capwap_set_abnormal_average_time(delay_time);
	ah_capwap_set_last_alarm(AH_CAPWAP_DELAY_ALARM_MAJOR);
	ah_dbg_old(capwap_delay, "the delay time is in major threshold, minor threshold %d time, major threshold %d times",
			   ah_capwap_get_minor_number(), ah_capwap_get_major_number());

	return ah_capwap_get_next_alarm();
}

#define AH_CAPWAP_SECOND2USECOND (1000*1000)
#define AH_CAPWAP_MAX_ROUND_TRIP_TIME (30*AH_CAPWAP_SECOND2USECOND)
#define AH_CAPWAP_DELAY_LOWER_PERCENT (0.9)
#define AH_CAPWAP_DELAY_HIGHER_PERCENT (1.1)
int ah_capwap_handle_alarm(int64_t delay_time)
{
	ah_capwap_delay_alarm_t alarm_type = 0;
	int64_t    min_threshold = 0;
	int64_t    maj_threshold = 0;

	if (delay_time <= 0 || delay_time >= AH_CAPWAP_MAX_ROUND_TRIP_TIME) {
		ah_dbg_old(capwap_delay, "the round trip time :%s unvalible", ah_capwap_64bit_num2str(delay_time));
		return 0;
	}

	ah_capwap_delay_lm_lock();
	if (ah_capwap_get_delay_average(TRUE) == 0) {
		ah_capwap_set_delay_average(delay_time);
		goto OUT;
	}
	switch (ah_capwap_get_last_alarm()) {
	case AH_CAPWAP_DELAY_ALARM_NONE:
		min_threshold = (int64_t)(ah_capwap_get_minor_threshold() * AH_CAPWAP_DELAY_HIGHER_PERCENT);
		maj_threshold = (int64_t)(ah_capwap_get_major_threshold() * AH_CAPWAP_DELAY_HIGHER_PERCENT);
		break;
	case AH_CAPWAP_DELAY_ALARM_MINOR:
		min_threshold = (int64_t)(ah_capwap_get_minor_threshold() * AH_CAPWAP_DELAY_LOWER_PERCENT);
		maj_threshold = (int64_t)(ah_capwap_get_major_threshold() * AH_CAPWAP_DELAY_HIGHER_PERCENT);
		break;
	case AH_CAPWAP_DELAY_ALARM_MAJOR:
		min_threshold = (int64_t)(ah_capwap_get_minor_threshold() * AH_CAPWAP_DELAY_LOWER_PERCENT);
		maj_threshold = (int64_t)(ah_capwap_get_major_threshold() * AH_CAPWAP_DELAY_LOWER_PERCENT);
		break;
	default:
		ah_dbg_old(capwap_delay, "Wrong last alarm type %s",
				   ah_capwap_delay_alarm_to_name(ah_capwap_get_last_alarm()));
		break;
	}
	ah_dbg_old(capwap_delay, "last not send alarm is %s, set current minor threshold to %s",
			   ah_capwap_delay_alarm_to_name(ah_capwap_get_last_alarm()),
			   ah_capwap_64bit_num2str(min_threshold));
	ah_dbg_old(capwap_delay, "last not send alarm is %s, set current major threshold to %s",
			   ah_capwap_delay_alarm_to_name(ah_capwap_get_last_alarm()),
			   ah_capwap_64bit_num2str(maj_threshold));

	alarm_type = ah_capwap_prehandle_alarm(delay_time, min_threshold, maj_threshold);
	if (alarm_type != ah_capwap_get_delay_alarm()
		&& alarm_type != AH_CAPWAP_DELAY_ALARM_STANDBY) {
		if (alarm_type == AH_CAPWAP_DELAY_ALARM_MINOR
			|| alarm_type == AH_CAPWAP_DELAY_ALARM_MAJOR) {
			delay_time = ah_capwap_get_abnormal_agerage_time();
			ah_dbg_old(capwap_delay, "The minor or major average delay time is %s", ah_capwap_64bit_num2str(delay_time));
		}
		ah_capwap_send_delay_trap(delay_time, ah_capwap_handle_delay_alarm(alarm_type));
		ah_capwap_set_alarm_init_status(FALSE);
	} else {
		if (alarm_type != AH_CAPWAP_DELAY_ALARM_STANDBY) {
			if (ah_capwap_get_alarm_init_status() == TRUE) {
				ah_dbg_old(capwap_delay, "Each reconnect, Send the initial alarm status %s to HM", ah_capwap_delay_alarm_to_name(alarm_type));
				ah_capwap_send_delay_trap(delay_time, alarm_type);
				ah_capwap_set_alarm_init_status(FALSE);
				goto OUT;
			}
			ah_capwap_reset_delay_info();
		}
		ah_dbg_old(capwap_delay, "Current alarm %s is the same as the last time, skip it.",
				   ah_capwap_delay_alarm_to_name(alarm_type));
	}

OUT:
	ah_capwap_delay_lm_unlock();
	return 0;
}

int64_t ah_capwap_get_rount_trip_time(ah_capwap_round_trip_time_t *para)
{
	int64_t    snd_req = 0;
	int64_t    rcv_req = 0;
	int64_t    trip_time = 0;

	snd_req = ((int64_t)para->snd_second * AH_CAPWAP_SECOND2USECOND) + (int64_t)(para->snd_usecond);
	ah_dbg_old(capwap_delay, "Round trip snd request time second:%d, usecond:%d, total usecond:%s",
			   para->snd_second, para->snd_usecond, ah_capwap_64bit_num2str(snd_req));

	rcv_req = ((int64_t)para->rcv_second * AH_CAPWAP_SECOND2USECOND) + (int64_t)(para->rcv_usecond);
	ah_dbg_old(capwap_delay, "Round trip rcv request time second:%d, usecond:%d, total usecond:%s",
			   para->rcv_second, para->rcv_usecond, ah_capwap_64bit_num2str(rcv_req));

	//trip_time = rcv_req - snd_req + ah_capwap_get_delay_offset();
	trip_time = (rcv_req - snd_req) / 2;
	ah_dbg_old(capwap_delay, "Round trip time is:%s", ah_capwap_64bit_num2str(trip_time));

	return trip_time;
}

int ah_capwap_handle_delay_offset(ah_capwap_delay_offset_t *para)
{
	int64_t    snd_req = 0;
	int64_t    rcv_req = 0;
	int64_t    snd_rsp = 0;
	int64_t    rcv_rsp = 0;

	snd_req = ((int64_t)para->snd_req_second * AH_CAPWAP_SECOND2USECOND) + (int64_t)(para->snd_req_usecond);
	ah_dbg_old(capwap_delay, "Snd requst time second:%d, usecond:%d, total usecond:%s",
			   para->snd_req_second, para->snd_req_usecond, ah_capwap_64bit_num2str(snd_req));

	rcv_req = ((int64_t)para->rcv_req_second * AH_CAPWAP_SECOND2USECOND) + (int64_t)(para->rcv_req_usecond);
	ah_dbg_old(capwap_delay, "Rcv requst time second:%d, usecond:%d, total usecond:%s",
			   para->rcv_req_second, para->rcv_req_usecond, ah_capwap_64bit_num2str(rcv_req));

	snd_rsp = ((int64_t)para->snd_rsp_second * AH_CAPWAP_SECOND2USECOND) + (int64_t)(para->snd_rsp_usecond);
	ah_dbg_old(capwap_delay, "Snd response time second:%d, usecond:%d, total usecond:%s",
			   para->snd_rsp_second, para->snd_rsp_usecond, ah_capwap_64bit_num2str(snd_rsp));

	rcv_rsp = ((int64_t)para->rcv_rsp_second * AH_CAPWAP_SECOND2USECOND) + (int64_t)(para->rcv_rsp_usecond);
	ah_dbg_old(capwap_delay, "Rcv response time second:%d, usecond:%d, total usecond:%s",
			   para->rcv_rsp_second, para->rcv_rsp_usecond, ah_capwap_64bit_num2str(rcv_rsp));

	if (rcv_rsp <= snd_req || (rcv_rsp - snd_req) >= AH_CAPWAP_MAX_ROUND_TRIP_TIME) {
		ah_dbg_old(capwap_delay, "Rcv response time abnormal, skip it");
		return -1;
	}

	ah_capwap_set_delay_offset(((rcv_req - snd_req) + (snd_rsp - rcv_rsp)) / 2);
	ah_dbg_old(capwap_delay, "Total offset is:%s", ah_capwap_64bit_num2str(ah_capwap_get_delay_offset()));

	return 0;
}

static uint64_t capwap_snd_bytes = 0;
static uint64_t capwap_rcv_bytes = 0;

int ah_capwap_increase_send_bytes_counter(uint32_t snd_bytes)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_snd_bytes += (uint64_t)snd_bytes;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

int ah_capwap_increase_receive_bytes_counter(uint32_t rcv_bytes)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_rcv_bytes += (uint64_t)rcv_bytes;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

int ah_capwap_clear_snd_rcv_bytes_counter(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_snd_bytes = 0;
	capwap_rcv_bytes = 0;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

int ah_capwap_get_snd_rcv_bytes_counter(uint64_t *snd_bytes, uint64_t *rcv_bytes)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	*snd_bytes = capwap_snd_bytes;
	*rcv_bytes = capwap_rcv_bytes;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

static uint statis_start_time = 0;
int ah_capwap_set_statistic_bytes_time(void)
{
	uint      up_sec = 0;
	uint      up_usec = 0;
	(void)ah_get_system_uptime(&up_sec, &up_usec);

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	statis_start_time = up_sec;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

int ah_capwap_get_statistic_bytes_time(uint *start_time)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	*start_time = statis_start_time;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

static uint capwap_disconn_times = 0;
int ah_capwap_increase_disconnect_number(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_disconn_times++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

uint ah_capwap_get_disconnect_number(void)
{
	uint      number = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	number = capwap_disconn_times;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return number;
}

int ah_capwap_reset_disconnect_number(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_disconn_times = 0;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

static uint capwap_detection_counter = 0;
int ah_capwap_increase_detection_number(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_detection_counter++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

uint ah_capwap_get_detection_number(void)
{
	uint      number = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	number = capwap_detection_counter;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return number;
}

int ah_capwap_reset_detection_number(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_detection_counter = 0;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

static uint capwap_detection_failed_counter = 0;
int ah_capwap_increase_detection_failed_number(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_detection_failed_counter++;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

uint ah_capwap_get_detection_failed_number(void)
{
	uint      number = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	number = capwap_detection_failed_counter;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return number;
}

int ah_capwap_reset_detection_failed_number(void)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_counter_lm);
	capwap_detection_failed_counter = 0;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_counter_lm);

	return 0;
}

/**
 * @brief check the mgt0's address if equal to portal ip, AMRP always sends
 *        AH_EVENT_AMRP_PORTAL_CHG ipv46 addresses based on ip version-preference.
 *        Even if an AP doesn't get global IPv4/IPv6 addresses, it still gets link local addresses.
 *        So the IPV6 link local address should be compared.
 * @param[in] portal portal address info
 * @param[out]
 * @return
 * @note
 */
boolean ah_capwap_is_portal(ah_ipaddr46_t *portal)
{
	ah_ipaddr46_t  host_ip;
	struct in6_addr local_ipv6_addr;

	/* get IPV4 address or IPV6 global address according portal af */
	if (ah_capwap_get_wtpip(portal->af, &host_ip) != 0) {
		ah_dbg_old(capwap_info, "CAPWAP get device IP error");
		return FALSE;
	}

	/* cmp IPV4 address or IPV6 global address */
	if (ah_cmp_ipaddr46(portal, &host_ip) == 0) {
		return TRUE;
	} else {
		/* if af is AF_INET6, cmp the link local address */
		if (portal->af == AF_INET6) {
			if (ah_tpa_get_mgt0_link_local(&local_ipv6_addr) != 0) {
				ah_dbg_old(capwap_trap, "CAPWAP: get device local IPV6 address from SCD failed.\n");
			} else {
				/* portal equal to mgt0 link local address */
				if (ipv6_addr_cmp(&local_ipv6_addr, &portal->u_ipv6_addr) == 0) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

