#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>


#include "ah_smpi.h"
#include "ah_lib.h"
#include "ah_pthread.h"
#include "ah_capwap_api.h"
#include "ah_capwap_def.h"
#include "ah_capwap_types.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_func.h"
#include "ah_capwap_dtls.h"
#include "ah_syscall.h"
#include "ah_capwap_recovery.h"
#include "ah_capwap_hvcom.h"
#include "ah_capwap_tcp.h"

#define AH_CAPWAP_SND_EVENT_CMD_SAVED     0
#define AH_CAPWAP_SND_EVENT_CMD_NOSAVED   1
extern int ah_start_cli_agent(uint mod_id, uint sub_mod_id, pthread_t *it);
static int ah_capwap_event_snd_flag = AH_CAPWAP_SND_EVENT_CMD_NOSAVED;

static void *ah_capwapagent_main(void *argv)
{
	ah_capwap_client();/*start capwap by default*/

	return NULL;
}

int ah_capwap_get_predefine_server_name(char *pre_name)
{
	FILE *fp = NULL;
	char      linebuf[AH_MAX_STR_64_LEN + 1];
	int      linesize = AH_MAX_STR_64_LEN + 1;
	int      rc = 0;
	char      low_str[AH_MAX_STR_64_LEN + 1];

	ah_str2lowcase(AH_CAPWAP_DFT_PREDEFINE_NAME, low_str, AH_MAX_STR_64_LEN);
	ah_str_del_blank(low_str);
	fp = fopen(AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH, "r");
	if (fp == NULL) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: capwap predefine server name file isn't exist.");
		ah_strncpy(pre_name, low_str, AH_MAX_STR_64_LEN);
		pre_name[AH_MAX_STR_64_LEN] = '\0';
		goto OUT;
	}
	if (fgets(linebuf, linesize, fp) == NULL) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: read capwap predefine server name from file (%s) failed. reason:%s\n",
				   AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH, strerror(errno));
		ah_strncpy(pre_name, low_str, AH_MAX_STR_64_LEN);
		pre_name[AH_MAX_STR_64_LEN] = '\0';
		rc = -1;
		goto OUT;
	}
	ah_strncpy(pre_name, linebuf, AH_MAX_STR_64_LEN);
	pre_name[AH_MAX_STR_64_LEN] = '\0';

OUT:
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}

	return rc;
}

static int ah_capwap_set_predefine_server_name(char *pre_name)
{
	FILE *fp = NULL;
	int      rc = -1;

	if (strlen(pre_name) > AH_MAX_STR_64_LEN) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: capwap predefine server name (%s) length (%d) exceed max length (%d)\n",
				   pre_name, strlen(pre_name), AH_MAX_STR_64_LEN);
		goto OUT;
	}
	/*no command*/
	if (strlen(pre_name) == 0) {
		unlink(AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH);
		rc = 0;
		goto OUT;
	}
	fp = fopen(AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH, "w+");
	if (fp == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: create capwap predefine server name file (%s) failed, reason:%s\n.",
				   AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH, strerror(errno));
		goto OUT;
	}
	if (fputs(pre_name, fp) < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: write capwap predefine server name (%s) to file (%s) failed. reason:%s\n",
				   pre_name, AH_CAPWAP_PREDEFINE_SERVER_NAME_PATH, strerror(errno));
		goto OUT;
	}
	rc = 0;
	sync();

OUT:
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
	return rc;
}

int main(int argc, char **argv)
{
	int rc;
	pthread_t main_tid;
	pthread_t   cli_tid;

	if (ah_pmpt_timer_init(NULL) < 0) {
		exit(1);
	}

	/*init the event list*/
	if (ah_capwap_ini_eventlist() == -1) {
		ah_err_old("CAPWAP init the capwap event list error!\n");
		return 0;
	}


	if (0 != ah_capwap_stat_init()) {
		ah_err_old("CAPWAP init statistic feature failed!");
	}

	/*init the capwap lock*/
	pthread_mutex_init(&ah_capwap_para.ah_capwap_lm, NULL);
	pthread_mutex_init(&ah_capwap_para.ah_capwap_counter_lm, NULL);
	ah_capwap_delay_lm_init();

	/* init virtual hive manager name */
	ah_memset(ah_capwap_para.vhm_name, 0, AH_CAPWAP_MAX_VHM_NAME_LEN + 1);

	/*recovery CLI configuration*/
	if (ah_capwap_init_recovery() == -1) {
		ah_err_old("CAPWAP init recovery capwap CLI error!\n");
		return 0;
	}
	/* start stat update timer */
	ah_capwap_set_stat_update_timer();

	/* init CAPWAP HiveComm */
	if (ah_capwap_hvcom_init() < 0) {
		ah_err_old("CAPWAP init HiveComm error!\n");
		return 0;
	}


	/* Create the main thread */
	rc = ah_pthread_create(&main_tid, ah_capwapagent_main, NULL, SCHED_RR, AH_PRIORITY_MGT, 0);

	/* Wait for child thread */
	pthread_join(main_tid, NULL);

	ah_capwap_delete_eventlist();
	/* deinit client monitor lib */

	syslog_dbg("Leave ah_CAPWAP_main\n");

	return 0;
}
#if 0

int ah_capwap_cfg_gen(ah_cmd_handle_t *h, void *data)
{

	ah_capwap_disinterval_cmd_data_t cmd1data;
	ah_capwap_dismaxinterval_cmd_data_t cmd2data;
	ah_capwap_heartbeatinterval_cmd_data_t cmd3data;
	ah_capwap_deadinterval_cmd_data_t cmd4data;
	ah_capwap_jointimeout_cmd_data_t cmd6data;
	ah_capwap_maxdiscounter_cmd_data_t cmd7data;
	ah_capwap_maxretrycounter_cmd_data_t cmd8data;
	ah_capwap_silentinterval_cmd_data_t cmd9data;
	ah_capwap_clientenable_cmd_data_t cmd10data;
	ah_capwap_event_enable_cmd_data_t cmd11data;
	ah_capwap_cli_port_cmd_data_t cmd12data;
	ah_capwap_cli_name_cmd_data_t cmd13data;
	ah_capwap_cli_dtls_enable_cmd_data_t cmd14data;
	ah_capwap_cli_dtls_hm_define_pasphrase_cmd_data_t cmd15data;
	ah_capwap_cli_dtls_bootstrap_pasphrase_cmd_data_t cmd16data;
	ah_capwap_cli_dtls_set_psk_cmd_data_t cmd17data;
	ah_capwap_cli_dtls_session_del_timer_cmd_data_t cmd18data;
	ah_capwap_cli_dtls_accept_boot_pasphrase_cmd_data_t cmd19data;
	ah_capwap_cli_dtls_max_retry_cmd_data_t cmd20data;
	ah_capwap_cli_dtls_handshake_wait_timer_cmd_data_t cmd21data;
	ah_capwap_cli_dtls_negotiation_cmd_data_t cmd22data;
	ah_capwap_cli_vhm_cmd_data_t cmd23data;
	ah_capwap_pci_alert_cmd_data_t cmd24data;
	ah_capwap_transfer_mode_cmd_data_t cmd25data;
	ah_capwap_http_proxy_info_cmd_data_t cmd26data;
	ah_capwap_http_proxy_auth_cmd_data_t cmd27data;
	ah_capwap_http_proxy_content_length_cmd_data_t cmd28data;
	ah_capwap_cli_discovery_method_cmd_data_t cmd29data;
	ah_capwap_stat_update_interval_cmd_data_t cmd30data;

	memset(&cmd1data, 0, sizeof(ah_capwap_disinterval_cmd_data_t));
	memset(&cmd2data, 0, sizeof(ah_capwap_dismaxinterval_cmd_data_t));
	memset(&cmd3data, 0, sizeof(ah_capwap_heartbeatinterval_cmd_data_t));
	memset(&cmd4data, 0, sizeof(ah_capwap_deadinterval_cmd_data_t));
	memset(&cmd6data, 0, sizeof(ah_capwap_jointimeout_cmd_data_t));
	memset(&cmd7data, 0, sizeof(ah_capwap_maxdiscounter_cmd_data_t));
	memset(&cmd8data, 0, sizeof(ah_capwap_maxretrycounter_cmd_data_t));
	memset(&cmd9data, 0, sizeof(ah_capwap_silentinterval_cmd_data_t));
	memset(&cmd10data, 0, sizeof(ah_capwap_clientenable_cmd_data_t));
	memset(&cmd11data, 0, sizeof(ah_capwap_event_enable_cmd_data_t));
	memset(&cmd12data, 0, sizeof(ah_capwap_cli_port_cmd_data_t));
	memset(&cmd13data, 0, sizeof(ah_capwap_cli_name_cmd_data_t));
	memset(&cmd14data, 0, sizeof(ah_capwap_cli_dtls_enable_cmd_data_t));
	memset(&cmd15data, 0, sizeof(ah_capwap_cli_dtls_hm_define_pasphrase_cmd_data_t));
	memset(&cmd16data, 0, sizeof(ah_capwap_cli_dtls_bootstrap_pasphrase_cmd_data_t));
	memset(&cmd17data, 0, sizeof(ah_capwap_cli_dtls_set_psk_cmd_data_t));
	memset(&cmd18data, 0, sizeof(ah_capwap_cli_dtls_session_del_timer_cmd_data_t));
	memset(&cmd19data, 0, sizeof(ah_capwap_cli_dtls_accept_boot_pasphrase_cmd_data_t));
	memset(&cmd20data, 0, sizeof(ah_capwap_cli_dtls_max_retry_cmd_data_t));
	memset(&cmd21data, 0, sizeof(ah_capwap_cli_dtls_handshake_wait_timer_cmd_data_t));
	memset(&cmd22data, 0, sizeof(ah_capwap_cli_dtls_negotiation_cmd_data_t));
	memset(&cmd23data, 0, sizeof(ah_capwap_cli_vhm_cmd_data_t));
	memset(&cmd24data, 0, sizeof(ah_capwap_pci_alert_cmd_data_t));
	memset(&cmd25data, 0, sizeof(ah_capwap_transfer_mode_cmd_data_t));
	memset(&cmd26data, 0, sizeof(ah_capwap_http_proxy_info_cmd_data_t));
	memset(&cmd27data, 0, sizeof(ah_capwap_http_proxy_auth_cmd_data_t));
	memset(&cmd28data, 0, sizeof(ah_capwap_http_proxy_content_length_cmd_data_t));
	memset(&cmd29data, 0, sizeof(ah_capwap_cli_discovery_method_cmd_data_t));
	memset(&cmd30data, 0, sizeof(ah_capwap_stat_update_interval_cmd_data_t));

	AH_CLI_BE_DECL_IPC_BUF(h);
	/*no capwap client enable*/
	if (ah_capwap_para.enable == AH_CAPWAP_DISABLE) {
		cmd10data.valid.__no_flag = 1;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_CLIENT_ENABLE, &cmd10data);
	}

	/*capwap client discovery interval <number>*/
	if (ah_capwap_para.capwap_timer.discovery_interval != AH_CAPWAP_TIMER_DISCOVERY_DFT) {
		cmd1data.valid.intervalval = 1;
		cmd1data.intervalval = ah_capwap_para.capwap_timer.discovery_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DISCOVERY_INTERVAL, &cmd1data);
	}

	/*capwap client statistic-info update-interval <number>*/
	if (ah_capwap_stat_update_timer_interval != AH_CAPWAP_TIMER_STAT_UPDATE_DFT) {
		cmd30data.valid.intervalval = 1;
		cmd30data.intervalval = ah_capwap_stat_update_timer_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_STAT_UPDATE_INTERVAL, &cmd30data);
	}

	/*capwap client discovery maximum interval <number>*/
	if (ah_capwap_para.capwap_timer.max_discovery_interval != AH_CAPWAP_TIMER_MAXDISCOVERY_DFT) {
		cmd2data.valid.intervalval = 1;
		cmd2data.intervalval = ah_capwap_para.capwap_timer.max_discovery_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DISCOVERY_MAXINTERVAL, &cmd2data);
	}
	/*capwap neighbor dead interval <number>*/
	if (ah_capwap_para.capwap_timer.neighbordead_interval != AH_CAPWAP_TIMER_NEIGHBORDEAD_DFT) {
		cmd4data.valid.intervalval = 1;
		cmd4data.intervalval = ah_capwap_para.capwap_timer.neighbordead_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_NEIGHBORDEAD, &cmd4data);
	}

	/*Capwap client neighbor heartbeat <interval>
	 Note: this CLI must follow CLI: capwap neighbor dead interval <number>*/
	if (ah_capwap_para.capwap_timer.echo_interval != AH_CAPWAP_TIMER_ECHO_DFT) {
		cmd3data.valid.intervalval = 1;
		cmd3data.intervalval = ah_capwap_para.capwap_timer.echo_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_HEARTBEAT, &cmd3data);
	}

	/*capwap join timeout <interval>*/
	if (ah_capwap_para.capwap_timer.waitjoin_interval != AH_CAPWAP_TIMER_WAITJOIN_DFT) {
		cmd6data.valid.intervalval = 1;
		cmd6data.intervalval = ah_capwap_para.capwap_timer.waitjoin_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_JOINTIMEOUT, &cmd6data);
	}

	/*capwap max-discoveries counter <number>*/
	if (ah_capwap_para.capwap_counter.max_discoveries != AH_CAPWAP_MAXDISCOVERY_COUNT_DFT) {
		cmd7data.valid.intervalval = 1;
		cmd7data.intervalval = ah_capwap_para.capwap_counter.max_discoveries;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DISCOUNTE, &cmd7data);
	}

	/*capwap max-retransmit counter <number>*/
	if (ah_capwap_para.capwap_counter.max_retransmit != AH_CAPWAP_MAXRETRY_COUNT_DFT) {
		cmd8data.valid.intervalval = 1;
		cmd8data.intervalval = ah_capwap_para.capwap_counter.max_retransmit;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_MAXTRYCOUNT, &cmd8data);
	}

	/*capwap silent interval <number>*/
	if (ah_capwap_para.capwap_timer.silent_interval != AH_CAPWAP_TIMER_SILENT_DFT) {
		cmd9data.valid.intervalval = 1;
		cmd9data.intervalval = ah_capwap_para.capwap_timer.silent_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_SILENTINTERVAL, &cmd9data);
	}

#if 0
	/*capwap client event enable*/
	if (ah_capwap_event_snd_flag == AH_CAPWAP_SND_EVENT_CMD_SAVED
		&& ah_capwap_para.event_flag == AH_CAPWAP_EVENT_SND_ON) {
		cmd11data.valid.__no_flag = 0;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_EVENT_ENABLE, &cmd11data);
	}
#endif

	/*capwap server port [numbers]*/
	if ((ah_capwap_para.capwap_port == AH_CAPWAP_HTTP_DEFAULT_PORT
		 && ah_capwap_get_tcp_status() != AH_CAPWAP_TCP_ENABLE_PREDEF_MODE)
		|| (ah_capwap_para.capwap_port != AH_CAPWAP_HTTP_DEFAULT_PORT
			&& ah_capwap_para.capwap_port != AH_CAPWAP_PORT)) {
		cmd12data.valid.port_num = 1;
		cmd12data.port_num = ah_capwap_para.capwap_port;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_SRV_PORT, &cmd12data);
	}

	/*capwap client discovery method broadcast */
	if (ah_capwap_para.enable_discovery_bcast == AH_CAPWAP_DISCOVERY_BROADCAST_DISABLE) {
		cmd29data.valid.__no_flag = 1;
		cmd29data.valid.method = 1;
		strcpy(cmd29data.method, "broadcast");
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DISCOVERY_METHOD, &cmd29data);
	}

	/*capwap server name <string>*/
	ah_nms_names_t nms_names;
#ifdef AH_VPN_ENABLE
	boolean tunnel;
#endif
	ah_tpa_get_cli_nmsname(&nms_names);
	if (strlen(nms_names.first) != 0) {
		cmd13data.valid.srv_name = 1;
		cmd13data.valid.sn = 1;
		cmd13data.valid.sn_new = 1;
		strcpy(cmd13data.sn, "");
		strcpy(cmd13data.sn_new, "");
		strcpy(cmd13data.srv_name, nms_names.first);
#ifdef AH_VPN_ENABLE
		ah_tpa_get_cli_nms_tunnel(0, &tunnel);
		if (tunnel) {
			cmd13data._opt_via_vpn_tunnel = 1;
		}
#endif
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_SRV_NAME, &cmd13data);
	}
	if (strlen(nms_names.second) != 0) {
		memset(&cmd13data, 0, sizeof(ah_capwap_cli_name_cmd_data_t));
		cmd13data.valid.srv_name = 1;
		cmd13data.valid.sn = 1;
		cmd13data.valid.sn_new = 1;
		strcpy(cmd13data.sn, "");
		strcpy(cmd13data.sn_new, "backup");
		strcpy(cmd13data.srv_name, nms_names.second);
#ifdef AH_VPN_ENABLE
		ah_tpa_get_cli_nms_tunnel(1, &tunnel);
		if (tunnel) {
			cmd13data._opt_via_vpn_tunnel = 1;
		}
#endif

		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_SRV_NAME, &cmd13data);
	}
	/*capwap dtls enable*/
	if (ah_capwap_dtls_get_next_enable_status() == AH_CAPWAP_DTLS_DISABLE) {
		cmd14data.valid.__no_flag = 1;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_ENABLE, &cmd14data);
	}

	/*capwap client dtls hm-defined-passphrase <string> key-id [numbers]*/
	if (ah_capwap_para.capwap_dtls.cur_keyid != 0) {
		cmd15data.valid.dtls_keyid = 1;
		cmd15data.valid.dtls_pass = 1;
		cmd15data.dtls_keyid = ah_capwap_para.capwap_dtls.cur_keyid;
		strcpy(cmd15data.dtls_pass, ah_capwap_para.capwap_dtls.dtls_cur_phrase);
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_HM_DEFINE_PASPHRASE, &cmd15data);
	}

	/*capwap client dtls bootstrap-passphrase <string>*/
	if (strcmp(ah_capwap_para.capwap_dtls.dtls_dft_phrase, AH_CAPWAP_DTLS_PASS_DFT) != 0) {
		cmd16data.valid.dtls_pass = 1 ;
		strcpy(cmd16data.dtls_pass, ah_capwap_para.capwap_dtls.dtls_dft_phrase);
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_BOOTSTRAP_PASPHRASE, &cmd16data);
	}

	/*capwap client dtls psk <hex>*/
	if (strlen(ah_capwap_para.capwap_dtls.dtls_psk) != 0) {
		cmd17data.valid.dtls_psk = 1;
		strcpy(cmd17data.dtls_psk, ah_capwap_para.capwap_dtls.dtls_psk);
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_SET_PSK, &cmd17data);
	}

	/*capwap client dtls session-delete-wait-time [numbers]*/
	if (ah_capwap_para.capwap_timer.dtls_cut_interval != AH_CAPWAP_TIMER_DTLS_CUT_DFT) {
		cmd18data.valid.dtls_timer = 1;
		cmd18data.dtls_timer = ah_capwap_para.capwap_timer.dtls_cut_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_SESSION_DEL_TIMER, &cmd18data);
	}

	/*capwap client dtls always-accept-bootstrap-passphrase*/
	if (ah_capwap_para.capwap_dtls.dtls_bootstrap != AH_CAPWAP_DTLS_ACCEPT_BOOTSTRAP_ENABLE) {
		cmd19data.valid.__no_flag = 1;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_ACEPT_BOOT_PASPHRASE, &cmd19data);
	}

	/*capwap client dtls max-retries [numbers]*/
	if (ah_capwap_para.capwap_counter.max_dtls_retry != AH_CAPWAP_DTLS_MAX_RETRY_DFT) {
		cmd20data.valid.dtls_retry = 1;
		cmd20data.dtls_retry = ah_capwap_para.capwap_counter.max_dtls_retry;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_MAX_RETYR, &cmd20data);
	}

	/*capwap client dtls handshake-wait-time [numbers]*/
	if (ah_capwap_para.capwap_timer.dtls_conn_interval != AH_CAPWAP_TIMER_DTLS_CONN_DFT) {
		cmd21data.valid.dtls_timer = 1;
		cmd21data.dtls_timer = ah_capwap_para.capwap_timer.dtls_conn_interval;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_HANDSHAKE_TIMER, &cmd21data);
	}

	/* capwap client virtual manager */
	if (ah_strlen(ah_capwap_para.vhm_name) != 0) {
		cmd23data.valid.vhm_name = 1;
		ah_strcpy(cmd23data.vhm_name, ah_capwap_para.vhm_name);
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_VHM_NAME, &cmd23data);
	}

	/*capwap dtls negotation*/
	if (ah_capwap_dtls_get_negotiation_status() == AH_CAPWAP_DTLS_NEGOTIATION_DISABLE) {
		cmd22data.valid.__no_flag = 1;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_DTLS_NEGOTIATION, &cmd22data);
	}

	/*capwap client pci-alert enable*/
	if (ah_pci_alert_enable()) {
		cmd24data.valid.__no_flag = 0;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_PCI_ALERT, &cmd24data);
	}

	/*capwap client http proxy name <string> port [number]*/
	if (ah_strlen(ah_capwap_para.proxy_name) != 0) {
		cmd26data.valid.name = 1;
		ah_strcpy(cmd26data.name, ah_capwap_para.proxy_name);
		cmd26data.valid.port = 1;
		cmd26data.port = ah_capwap_para.proxy_port;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_PROXY_INFO, &cmd26data);
	}

	/*capwap client http proxy user <string> password <password>*/
	if (ah_strlen(ah_capwap_para.proxy_auth_name) != 0) {
		cmd27data.valid.name = 1;
		ah_strcpy(cmd27data.name, ah_capwap_para.proxy_auth_name);
		cmd27data.valid.pswd = 1;
		ah_strcpy(cmd27data.pswd, ah_capwap_para.proxy_auth_pswd);
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_PROXY_AUTH, &cmd27data);
	}

	/*capwap client http proxy content length [numbers]*/
	if (ah_capwap_para.proxy_content_len != AH_CAPWAP_HTTP_TUNNEL_MAX_CONTENT_LEN
		&& ah_capwap_para.proxy_content_len != 0) {
		cmd28data.valid.len = 1;
		cmd28data.len = (ah_capwap_para.proxy_content_len / 1024);
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_PROXY_CONTENT_LENGTH, &cmd28data);
	}

	/*capwap client transfer mode tcp*/
	if (ah_capwap_get_tcp_status() == AH_CAPWAP_TCP_ENABLE
		|| ah_capwap_get_tcp_next_status() == AH_CAPWAP_TCP_ENABLE) {
		cmd25data.valid.__no_flag = 0;
		AH_CLI_BE_ADD_CMD_DATA(h, AH_CMD_CAPWAP_TRANSFER_MODE, &cmd25data);
	}

	return 0;
}

static void *ah_capwap_test_event_loop(void *argv)
{
	uint      ver = 1;
	while (1) {
		ah_event_send(AH_EVENT_CFG_VER_CHANGED, sizeof(uint), &ver);
		/*sleep 10 msecond to send another event*/
		ah_usleep(0, 10 * 1000);
	}

	return NULL;
}

static void ah_capwap_test_event()
{
	pthread_t main_tid;

	if (ah_pthread_create(&main_tid, ah_capwap_test_event_loop, NULL, SCHED_RR, AH_PRIORITY_MGT, 0) != 0) {
		ah_err_old("%s: Create pthread failed.", __func__);
	}
	return ;
}

int ah_capwap_show_shm(ah_cmd_handle_t *cmd, ah_capwap_cli_show_shm_cmd_data_t *ptr)
{
	ah_capwap_recovery_t show_shm;

	ah_capwap_get_shm_value(&show_shm);

	ah_cli_printf(cmd, "CAPWAP share memory information(inited:%s):\n", show_shm.init ? "yes" : "no");
	ah_cli_printf(cmd, "CAPWAP enable status:%s\n", show_shm.enable ? "enabled" : "disabled");
	ah_cli_printf(cmd, "CAPWAP transport mode:%s\n", (show_shm.transfer_mode == AH_CAPWAP_TCP_ENABLE) ? "HTTP" : "UDP");
	ah_cli_printf(cmd, "CAPWAP HTTP proxy name:%s\n", show_shm.proxy_name);
	ah_cli_printf(cmd, "CAPWAP HTTP proxy port:%d\n", show_shm.proxy_port);
	ah_cli_printf(cmd, "CAPWAP HTTP proxy auth name:%s\n", show_shm.proxy_auth_name);
	ah_cli_printf(cmd, "CAPWAP HTTP proxy auth pswd:%s\n", show_shm.proxy_auth_pswd);
	ah_cli_printf(cmd, "CAPWAP HTTP proxy content length:%d\n", show_shm.proxy_content_len);
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	int      method;
	ah_get_nms_cfg_method(&method);
	ah_cli_printf(cmd, "CAPWAP HM IP configure method:%d\n", method);
	ah_cli_printf(cmd, "CAPWAP HTTP proxy configure method:%d\n", show_shm.proxy_cfg_method);
	ah_cli_printf(cmd, "CAPWAP publish service type:%d\n", show_shm.bonjour_service_type);
#endif
	ah_cli_printf(cmd, "CAPWAP protocol port:%d\n", show_shm.capwap_port);
	ah_cli_printf(cmd, "CAPWAP send event :%s\n", show_shm.event_flag ? "enabled" : "disabled");
	ah_cli_printf(cmd, "CAPWAP reconnect reason:%d\n", show_shm.reconnect_reason);
	ah_cli_printf(cmd, "CAPWAP client virtual manager:%s\n", show_shm.vhm_name);
	ah_cli_printf(cmd, "CAPWAP discovery broadcast:%s\n",
				  (show_shm.enable_discovery_bcast == AH_CAPWAP_DISCOVERY_BROADCAST_ENABLE) ?
				  "Enabled" : "Disabled");
	ah_cli_printf(cmd, "------------Timer CLI----------------\n");
	ah_cli_printf(cmd, "Discovery interval:%d\n", show_shm.timer_cli.discovery_interval);
	ah_cli_printf(cmd, "Echo interval:%d\n", show_shm.timer_cli.echo_interval);
	ah_cli_printf(cmd, "Max discovery interval:%d\n", show_shm.timer_cli.max_discovery_interval);
	ah_cli_printf(cmd, "NeighborDead interval:%d\n", show_shm.timer_cli.neighbordead_interval);
	ah_cli_printf(cmd, "Slience interval:%d\n", show_shm.timer_cli.silent_interval);
	ah_cli_printf(cmd, "WaitJoin interval:%d\n", show_shm.timer_cli.waitjoin_interval);
	ah_cli_printf(cmd, "Event interval:%d\n", show_shm.timer_cli.event_interval);
	ah_cli_printf(cmd, "DTLS cut interval:%d\n", show_shm.timer_cli.dtls_cut_interval);
	ah_cli_printf(cmd, "DTLS connect interval:%d\n", show_shm.timer_cli.dtls_conn_interval);
	ah_cli_printf(cmd, "Statistic info update interval:%d\n", show_shm.timer_cli.stat_update_interval);
	ah_cli_printf(cmd, "------------Counter CLI----------------\n");
	ah_cli_printf(cmd, "Max discovery count:%d\n", show_shm.counter_cli.max_discoveries);
	ah_cli_printf(cmd, "Max retransmit count:%d\n", show_shm.counter_cli.max_retransmit);
	ah_cli_printf(cmd, "Max DTLS retry count:%d\n", show_shm.counter_cli.max_dtls_retry);
	ah_cli_printf(cmd, "------------DTLS CLI----------------\n");
	ah_cli_printf(cmd, "DTLS enable:%s\n", show_shm.dtls_cli.dtls_enable ? "enabled" : "disabled");
	ah_cli_printf(cmd, "DTLS next enable:%s\n", show_shm.dtls_cli.dtls_next_enable ? "enabled" : "disabled");
	ah_cli_printf(cmd, "DTLS always accept bootstrap:%s\n", show_shm.dtls_cli.dtls_bootstrap ? "yes" : "no");
	ah_cli_printf(cmd, "DTLS key type:%s\n", show_shm.dtls_cli.dtls_key_type ? "manual" : "passphrase");
	ah_cli_printf(cmd, "DTLS current key id:%d\n", show_shm.dtls_cli.cur_keyid);
	ah_cli_printf(cmd, "DTLS current passphrase:%s\n", show_shm.dtls_cli.dtls_cur_phrase);
	ah_cli_printf(cmd, "DTLS current passphrase footprint:%s\n", show_shm.dtls_cli.dtls_cur_footprint);
	ah_cli_printf(cmd, "DTLS backup key id:%d\n", show_shm.dtls_cli.bak_keyid);
	ah_cli_printf(cmd, "DTLS backup passphrase:%s\n", show_shm.dtls_cli.dtls_bak_phrase);
	ah_cli_printf(cmd, "DTLS bakcup passphrase footprint:%s\n", show_shm.dtls_cli.dtls_bak_footprint);
	ah_cli_printf(cmd, "DTLS default passphrase:%s\n", show_shm.dtls_cli.dtls_dft_phrase);
	ah_cli_printf(cmd, "DTLS default passphrase footprint:%s\n", show_shm.dtls_cli.dtls_dft_footprint);
	ah_cli_printf(cmd, "DTLS manual PSK:%s\n", show_shm.dtls_cli.dtls_psk);
	ah_cli_printf(cmd, "DTLS negotiation:%s\n", show_shm.dtls_negotiation ? "enabled" : "disabled");
	ah_cli_printf(cmd, "DTLS connect failed:%d, DTLS read status:%s", AH_CAPWAP_GET_DTLS_CONNECT_FAILED_NUM,
				  (AH_CAPWAP_GET_DTLS_READ_STATUS == 1) ? "start" : "end");
	ah_cli_printf(cmd, "\n--------capwap parameters----------\n");
	ah_cli_printf(cmd, "capwap mgt0 ip: %i\n", capwap_mgt0_ip);
	ah_cli_printf(cmd, "capwap socket fd: %d\n", ah_capwap_para.sock);
	ah_cli_printf(cmd, "capwap watchdog flag: %d\n", ah_capwap_para.wd.flag);
	ah_cli_printf(cmd, "capwap watchdog setting time: %d, current time: %d\n",
				  ah_capwap_para.wd.set_time, ah_sys_up_sec());
	ah_cli_printf(cmd, "capwap watchdog setting offset: %d\n", ah_capwap_para.wd.offset);

	return 0;
}
#endif
