#ifndef AH_CAPWAP_FUNC_H
#define AH_CAPWAP_FUNC_H
#include "ah_event.h"

#include "ah_capwap_types.h"

#define AH_CAPWAP_DBGPKT_RX 0
#define AH_CAPWAP_DBGPKT_TX 1

uint32_t ah_capwap_getip();
uint32_t ah_capwap_nmsip();
int ah_capwap_end(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf, uint32_t buflen);
int ah_capwap_start(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf, uint32_t buflen);
int ah_capwap_get_host_ip(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf,
						  uint32_t    buflen);
int ah_capwap_get_nms_ip(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf,
						 uint32_t    buflen);
int ah_capwap_idle(uint32_t clientstae, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_settimer(uint32_t timertype, uint32_t timer_value);
int ah_capwap_unsettimer(uint32_t timertype);
int  ah_capwap_packet_client(char *packbuf, uint32_t *packlen, uint32_t packettype, uint32_t capwapstate,
							 uint      seq_num);
int ah_capwap_analysepacket(char *buf, uint32_t len);
int ah_capwap_sulking(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_waitsnd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_dscav_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						uint32_t    buflen);
int ah_capwap_dscav_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						uint32_t    buflen);
int ah_capwap_join_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_join_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_chgfsm_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						 uint32_t    buflen);
int ah_capwap_chgfsm_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						 uint32_t    buflen);
int ah_capwap_run_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_run_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf , uint32_t buflen);
int ah_capwap_event_snd(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						uint32_t    buflen);
int ah_capwap_event_rcv(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						uint32_t    buflen);
int ah_capwap_run_event();
int ah_capwap_run_echo();
int ah_capwap_createsock();
int ah_capwap_printpacket(char *packetbuf, short packetlen);
int ah_capwap_client_listen(char *rcvbuf, uint32_t *pktlen);
int ah_capwap_chgfsm_parmeter();
int ah_capwap_ver(uint32_t ver, uchar *verstr);
int ah_capwap_event_save_msg(int msg_type, uint msg_len, char *msg, uint frag_id);
int ah_capwap_event_get_snd_buff(uint32_t snd_index, uint32_t *msg_type);
int ah_capwap_event_need_snd();
int ah_capwap_event_need_rcv();
int ah_capwap_snd_confirm(uint32_t capwap_state, uint32_t pkt_type, uint seq_num);
void ah_capwap_printf(const char *format, ...);
void ah_capwap_init();
void ah_capwap_sendmode(uint32_t pktmode);
void ah_capwap_client();
void ah_capwap_event_get_index(uint32_t *snd_index, uint32_t *sav_index);
void ah_capwap_event_get_buff(uint32_t buff_index, ah_capwap_event_pkt_t *buff);
void ah_capwap_get_frag_info(int frag_index, ah_capwap_pkt_frag_buff *frag_buff);
void ah_capwap_send_event2buf(uint32_t event_type, uint32_t event_len, char *event, uint frag_id);

/*define for callback function*/
void ah_capwap_discovey_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_echo_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_maxdisco_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_neigbor_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_response_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_retransmit_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_waitjoin_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_silent_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_idle_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_event_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_cpawpa_none_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_wait_broadcast(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_discoveryopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_joinopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_chgeventopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_runopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_configopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_idpopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_eventopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_chg_event_opt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_staopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_abort_save_image(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_cliopt(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_rcv_ssh_key(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_cwp_directory(char *optbuf, uint32_t totlelen, uint seq_num);
void ah_capwap_event_info_request(char *optbuf, uint32_t totlelen, uint seq_num);
int ah_capwap_fillopt_discoverytype(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpdescr(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpframmod(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpmactype(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_locationdata(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_sessionid(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpfallback(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpipv4addr(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpipv6addr(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtp_ipv6gateway(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpname(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpmac(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpmask(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtp_prefix(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_radioadminstate(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpgateway(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_iptype(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_ip6type(char *fillbuf, uint *filllen);
int ah_capwap_fillopt_result_code(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_abort_image_result(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_region_code(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_country_code(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_statistical(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_mgt0_hive(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_hiveap_info(char *fillbuf, uint32_t *filllen);
boolean ah_capwap_is_portal(ah_ipaddr46_t *portal);
int ah_capwap_fillopt_port_info(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_wtpvhm(char *fillbuf, uint32_t *filllen);
uint ah_capwap_get_wtpip(int af, ah_ipaddr46_t *host_ip);

/*************************/
int ah_capwap_ini_eventlist();
int ah_capwap_set_durate_timer();
int ah_capwap_unset_durate_timer();
void ah_capwap_delete_eventlist();
int ah_capwap_get_time2fire();
void ah_capwap_reset_para();
void ah_capwap_get_member_num() ;
void ah_capwap_enable();
void ah_capwap_disable();
void ah_capwap_deal_event();
void ah_capwap_event_buff_clean();
void ah_capwap_send_event_itself(uint32_t event_len, const char *event_msg, uint32_t event_id);
void ah_capwap_interrupt_listen();
void ah_capwap_keep_listen();
void ah_capwap_clean_frag_buff();
int ah_capwap_get_listen_state();
const char *ah_capwap_get_state_string(uint32_t state);
const char *ah_capwap_get_event_string(uint32_t event);
const char *ah_capwap_get_timer_string(uint32_t timer);
void *ah_capwap_get_trap();
int ah_capwap_resend_active_alarm(void);
void ah_capwap_set_reconnect_reason(uint32_t reason);
void ah_capwap_get_reconnect_reason(uint32_t *reason);
void ah_capwap_set_choose_ac(uint32_t ac_level);
int ah_capwap_get_choose_ac();
void ah_capwap_set_chg_ac_flag(uint32_t chg_flag);
int ah_capwap_get_chg_ac_flag();
int ah_capwap_idp_get_allsta(ushort type, uint32_t seq_num, char **data, int *data_len);
int ah_capwap_handle_idp_mitigation_request(uint32_t buf_len, char *rqt_buff);
int ah_capwap_handle_location_track_request(uint32_t buf_len, char *rqt_buff);
int ah_capwap_handle_pkt_cpt_stat_request(uint32_t buf_len, char *rqt_buff);
int ah_capwap_handle_delete_cookie_confirm(char *rqst_buff, char *rst_buf, uint32_t *rst_len);
int ah_capwap_handle_get_system_topology_info(char *rqst_buff, char *rst_buf, uint32_t *rst_len);
int ah_capwap_handle_remote_event_request(uint32_t buf_len, char *rqt_buff);
int ah_capwap_handle_interface_map(uint32_t buf_len, char *rqt_buff);
int ah_capwap_fillopt_info_query_result(char *fillbuf, uint32_t *filllen);
void ah_capwap_info_query_request(char *optbuf, uint32_t totlelen, uint seq_num);
int ah_capwap_handle_enable_clnt_trace_confirm(char *rqst_buff, char *rst_buf, uint32_t *rst_len);
int ah_capwap_fillopt_event_query_result(char *fillbuf, uint32_t *filllen);
int ah_capwap_fillopt_snd_echo_time(char *fillbuf, uint32_t *filllen);
int ah_capwap_get_free_buffer_count(int all);
int ah_capwap_reset_packet_counter();
inline int ah_capwap_increase_packet_lost_counter();
inline int ah_capwap_increase_packet_send_counter();
inline int ah_capwap_increase_packet_recv_counter();
inline int ah_capwap_increase_packet_drop_buffer_counter();
inline int ah_capwap_increase_packet_drop_conn_counter();
inline int ah_capwap_increase_event_packet_counter(uint32_t op_type, uint32_t event_type);
inline int ah_capwap_get_event_packet_counter(ah_capwap_event_pkt_counter_t *event_pkt_counter);
int ah_capwap_get_packet_counter(ah_capwap_pkt_counter *pkt_counter);
inline int ah_capwap_set_go_next_status(int status_flag);
inline int ah_capwap_get_go_next_status();
void ah_capwap_evtpkt_print_filter(char *packet, uint32_t length, uint32_t msg_type, uint32_t direction);
inline void ah_capwap_set_reconnect_schedule(uint32_t reconnect_schedul);
inline void ah_capwap_reset_reconnect_schedule();
int ah_capwap_set_reconn_timer(time_t reconn_time);
int32_t ah_capwap_get_reconn_time();
int ah_capwap_get_predefine_server_name(char *pre_name);
void ah_capwap_finish();
int ah_capwap_client_send(char *capwaptxpkt, uint32_t packlen);
int ah_capwap_get_port(int *value);
int ah_capwap_get_last_socket_port(int *capwap_port, int *proxy_port);
int ah_capwap_set_last_socket_port(int capwap_port, int proxy_port);
int ah_capwap_unregister_mgt_port();
int ah_capwap_register_mgt_port(void);
#ifdef AH_SUPPORT_TV
int ah_capwap_event_tv_found_studs(uint32_t len, char *data);
#endif
#if defined(AH_SUPPORT_IDP)
int ah_capwap_handle_idp_ap_clf_hm(uint32_t len, char *data);
#endif

typedef enum _ah_capwap_delay_alarm_t {
	AH_CAPWAP_DELAY_ALARM_NONE = 0,
	AH_CAPWAP_DELAY_ALARM_CLEAR,
	AH_CAPWAP_DELAY_ALARM_STANDBY,
	AH_CAPWAP_DELAY_ALARM_MINOR = AH_CAPWAP_DELAY_ALARM_CLEAR,
	AH_CAPWAP_DELAY_ALARM_MAJOR = 4,
} ah_capwap_delay_alarm_t;

typedef struct _ah_capwap_delay_para_t {
	int64_t    offset;              /*offset between AP and HM*/
	uint64_t    average;            /*averate round trip cost (usecond)*/
	ah_capwap_delay_alarm_t alarm;  /*send alram record*/
	uint      min_alarm;           /*minor alarm times*/
	uint      maj_alarm;           /*major alarm times*/
	uint64_t    abnormal_average;   /*average for abnormal delay (usecond)*/
	uint64_t    min_threshold;      /*minor threshold delay time (usecond)*/
	uint64_t    maj_threshold;      /*major threshold delay time (usecond)*/
	ah_capwap_delay_alarm_t last_alarm; /*last alarm flag, not send to HM*/
	boolean init_status;  /*init status should send to HM*/
} ah_capwap_delay_para_t;

typedef struct _ah_capwap_delay_offset_t {
	uint32_t    snd_req_second;
	uint32_t    snd_req_usecond;
	uint32_t    rcv_req_second;
	uint32_t    rcv_req_usecond;
	uint32_t    snd_rsp_second;
	uint32_t    snd_rsp_usecond;
	uint32_t    rcv_rsp_second;
	uint32_t    rcv_rsp_usecond;
} ah_capwap_delay_offset_t;

typedef struct _ah_capwap_round_trip_time_t {
	uint32_t    snd_second;
	uint32_t    snd_usecond;
	uint32_t    rcv_second;
	uint32_t    rcv_usecond;
} ah_capwap_round_trip_time_t;

extern uint32_t capwap_mgt0_ip;

int ah_capwap_handle_delay_offset(ah_capwap_delay_offset_t *para);
int64_t ah_capwap_get_rount_trip_time(ah_capwap_round_trip_time_t *para);
int ah_capwap_handle_alarm(int64_t delay_time);
uint64_t ah_capwap_get_delay_average(boolean print_debug);
int ah_capwap_set_delay_average_cli(const uint64_t average);
int ah_capwap_set_delay_alarm(ah_capwap_delay_alarm_t alarm_type);
inline void ah_capwap_delay_lm_init(void);
inline void ah_capwap_delay_lm_lock(void);
inline void ah_capwap_delay_lm_unlock(void);
int ah_capwap_set_minor_threshold(const uint64_t threshold);
int ah_capwap_set_major_threshold(const uint64_t threshold);
inline int ah_capwap_set_alarm_init_status(boolean init_status);
int ah_capwap_increase_send_bytes_counter(uint32_t snd_bytes);
int ah_capwap_increase_receive_bytes_counter(uint32_t rcv_bytes);
int ah_capwap_clear_snd_rcv_bytes_counter(void);
char *ah_capwap_64bit_num2str(int64_t value);
int ah_capwap_get_snd_rcv_bytes_counter(uint64_t *snd_bytes, uint64_t *rcv_bytes);
int ah_capwap_set_statistic_bytes_time(void);
int ah_capwap_get_statistic_bytes_time(uint *start_time);
int ah_capwap_increase_disconnect_number(void);
uint ah_capwap_get_disconnect_number(void);
int ah_capwap_reset_disconnect_number(void);

int ah_capwap_increase_detection_number(void);
uint ah_capwap_get_detection_number(void);
int ah_capwap_reset_detection_number(void);
int ah_capwap_increase_detection_failed_number(void);
uint ah_capwap_get_detection_failed_number(void);
int ah_capwap_reset_detection_failed_number(void);
int ah_capwap_set_detection_timer(time_t detect_time);
int ah_capwap_cancel_detection_timer(time_t detect_time);
void ah_capwap_set_stat_update_timer();
void ah_capwap_cancel_stat_update_timer();
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
void ah_capwap_handle_bonjour_service(boolean overwrite);
void ah_capwap_monitor_bonjour_service(void);
void ah_capwap_handle_bonjour_notify(void *data);
int ah_capwap_get_http_proxy_auth_data(uint32_t seq_num, uint32_t ip);
void ah_capwap_handle_hive_chg_4_bonjour(void);
void ah_capwap_init_http_proxy_conf_file(void);
#endif


#endif
