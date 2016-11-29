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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ah_types.h"
#include "ah_shm.h"
#include "ah_syscall.h"
#include "ah_scd_api.h"

#include "ah_capwap_def.h"
#include "ah_capwap_types.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_capwap_func.h"
#include "ah_capwap_recovery.h"
#include "ah_capwap_tcp.h"
#include "ah_capwap_statistic_main.h"
#include "ah_top.h"

#include "htc/htc.h"

/* engine management global data, will be put in shared memory */
static ah_capwap_recovery_t *capwap_shm = NULL;
static ah_shm_t shm_id = -1;

/***************************************************************************
 *
 * Function:  ah_capwap_get_reconnect_reason_str
 *
 * Purpose:   get capwap client reconnect reason
 *
 * Inputs:    reason: the reconnect reason
 *
 * Output:    void
 *
 * Returns:   char *
 *
 **************************************************************************/
char *ah_capwap_get_reconnect_reason_str(uint32_t reason_id)
{
	return (((reason_id) == AH_CAPWAP_RECONNECT_ENABLE_CHANGED) ? "CAPWAP was disabled/enabled on the client" : \
			((reason_id) == AH_CAPWAP_RECONNECT_DTLS_CHANGED) ? "DTLS was enabled or disabled" : \
			((reason_id) == AH_CAPWAP_RECONNECT_PORT_CHANGED) ? "its port changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_HOST_IP_CHANGED) ? "its IP address changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_HM_IP_CHANGED) ? "the CAPWAP server IP address changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_BOX_REBOOT) ? "the AP rebooted" : \
			((reason_id) == AH_CAPWAP_RECONNECT_TIMEOUT) ? "the neighbor dead interval elapsed during the previous CAPWAP session" : \
			((reason_id) == AH_CAPWAP_RECONNECT_UPGRADE_IMG) ? "the AP upgrade image rebooted" : \
			((reason_id) == AH_CAPWAP_RECONNECT_CONF_ROLBCK) ? "the AP configuration rollback rebooted" : \
			((reason_id) == AH_CAPWAP_RECONNECT_TRANSFER_MODE_CHANGED) ? "the AP transfer mode changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_PROXY_NAME_CHANGED) ? "the AP HTTP proxy name changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_PROXY_AUTH_CHANGED) ? "the AP HTTP proxy authentication changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_PROXY_CONTENT_LEN_CHANGED) ? "the AP HTTP proxy content length changed" : \
			((reason_id) == AH_CAPWAP_RECONNECT_IMG_ROLBCK) ? "the AP image rollback happened" : \
			"of an unknown error");
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_reconnect_reason
 *
 * Purpose:   set capwap client reconnect reason
 *
 * Inputs:    reason: the reconnect reason
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_set_reconnect_reason(uint32_t reason)
{
	if (ah_capwap_info.state == AH_CAPWAP_RUN) {
		capwap_shm->reconnect_reason = reason;
		ah_log_old(AH_LOG_INFO, "CAPWAP:capwap client reconnect because %s (reason id: %d)",
				   ah_capwap_get_reconnect_reason_str(reason), reason);
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_reconnect_reason_from_flash
 *
 * Purpose:   get capwap client reconnect reason from flash record
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   success:reason type, fail:-1
 *
 **************************************************************************/
static int ah_capwap_get_reconnect_reason_from_flash(void)
{
	FILE *fp = NULL;
	int      reason = 0;

	if (access(AH_CAPWAP_RECONNECT_REASON_PATH, F_OK) < 0) {
		return -1;
	}

	fp = fopen(AH_CAPWAP_RECONNECT_REASON_PATH, "r");
	if (fp != NULL) {
		if (fread(&reason, sizeof(int), 1, fp) != 1) {
			reason = -1;
		}
		fclose(fp);
		unlink(AH_CAPWAP_RECONNECT_REASON_PATH);
	} else {
		reason = -1;
	}

	return reason;
}

#if AH_IS_DUAL_IMAGE_SUPPORTED
/***************************************************************************
 *
 * Function:  ah_capwap_is_img_rollback
 *
 * Purpose:   Get weather the image roll back or not.
 *
 * Inputs:    N/A
 *
 * Output:    img_rollback
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static int ah_capwap_is_img_rollback(char *img_rollback)
{
	int      rc = 0;
	static int call_once = 0;
	static char rollback = 0;

	if (call_once == 0) {
		if (access(AH_PM_IMAGE_ROLLBACK, F_OK) == 0) {
			rollback = (char)1;
			call_once = 1;
		} else {
			if (errno == ENOENT) {
				rollback = (char)0;
				call_once = 1;
			} else {
				ah_err_old("failed when try to access %s", AH_PM_IMAGE_ROLLBACK);
				rc = -1;
				goto out;
			}
		}
	}
	*img_rollback = rollback;

out:
	return rc;
}
#endif

/***************************************************************************
 *
 * Function:  ah_capwap_get_reconnect_reason
 *
 * Purpose:   get capwap client reconnect reason
 *
 * Inputs:    void
 *
 * Output:    reason: the reconnect reason
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_get_reconnect_reason(uint32_t *reason)
{
	int      flash_reason = 0;
#if AH_IS_DUAL_IMAGE_SUPPORTED
	char      img_rolbck = 0; // work around compiler warning...
	ah_capwap_is_img_rollback(&img_rolbck);
#endif

	flash_reason = ah_capwap_get_reconnect_reason_from_flash();
	if ((flash_reason >= AH_CAPWAP_RECONNECT_ENABLE_CHANGED)
		&& (flash_reason < AH_CAPWAP_RECONNECT_REASON_MAX)
		&& (capwap_shm->reconnect_reason == AH_CAPWAP_RECONNECT_BOX_REBOOT)) {
		*reason = flash_reason;
	} else {
		*reason = capwap_shm->reconnect_reason;
	}
#if AH_IS_DUAL_IMAGE_SUPPORTED
	if (img_rolbck == 1) { //image roll back happened
		if (*reason == AH_CAPWAP_RECONNECT_BOX_REBOOT) {
			// the last reason is reboot
			*reason = AH_CAPWAP_RECONNECT_IMG_ROLBCK;
		} else if (*reason == AH_CAPWAP_RECONNECT_UPGRADE_IMG) {
			// the last reason is img upgrade
			*reason = AH_CAPWAP_RECONNECT_IMG_ROLBCK;
		} else if (*reason == AH_CAPWAP_RECONNECT_CONF_ROLBCK) {
			/* the configuration roll back and image
			 * roll back happened at the same time,
			 * keep the reason configuration roll back higher
			 * priority.
			 * */
			//*reason = AH_CAPWAP_RECONNECT_IMG_ROLBCK;
		}
	}
#endif

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_init_parameter
 *
 * Purpose:   init capwap parameter to share memory
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_init_parameter()
{
	char      foot_print[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1];

	capwap_shm->enable = AH_CAPWAP_ENABLE;
	capwap_shm->capwap_port = AH_CAPWAP_PORT;
	capwap_shm->event_flag = AH_CAPWAP_EVENT_SND_ON;

	/*init CAPWAP timer default value*/
	capwap_shm->timer_cli.discovery_interval = AH_CAPWAP_TIMER_DISCOVERY_DFT;
	capwap_shm->timer_cli.echo_interval = AH_CAPWAP_TIMER_ECHO_DFT;
	capwap_shm->timer_cli.max_discovery_interval = AH_CAPWAP_TIMER_MAXDISCOVERY_DFT;
	capwap_shm->timer_cli.neighbordead_interval = AH_CAPWAP_TIMER_NEIGHBORDEAD_DFT;
	capwap_shm->timer_cli.silent_interval = AH_CAPWAP_TIMER_SILENT_DFT;
	capwap_shm->timer_cli.waitjoin_interval = AH_CAPWAP_TIMER_WAITJOIN_DFT;
	capwap_shm->timer_cli.event_interval = AH_CAPWAP_TIMER_EVENT_DFT;
	capwap_shm->timer_cli.dtls_cut_interval = AH_CAPWAP_TIMER_DTLS_CUT_DFT;
	capwap_shm->timer_cli.dtls_conn_interval = AH_CAPWAP_TIMER_DTLS_CONN_DFT;
	capwap_shm->timer_cli.stat_update_interval = AH_CAPWAP_TIMER_STAT_UPDATE_DFT;

	/*init CAPWAP counter default value*/
	capwap_shm->counter_cli.max_discoveries = AH_CAPWAP_MAXDISCOVERY_COUNT_DFT;
	capwap_shm->counter_cli.max_retransmit = AH_CAPWAP_MAXRETRY_COUNT_DFT;
	capwap_shm->counter_cli.max_dtls_retry = AH_CAPWAP_DTLS_MAX_RETRY_DFT;

	/*init CAPWAP DTLS default value*/
	capwap_shm->dtls_cli.dtls_enable = AH_CAPWAP_DTLS_ENABLE;
	capwap_shm->dtls_cli.dtls_next_enable = AH_CAPWAP_DTLS_ENABLE;
	capwap_shm->dtls_cli.dtls_bootstrap = AH_CAPWAP_DTLS_ACCEPT_BOOTSTRAP_ENABLE;
	strcpy(capwap_shm->dtls_cli.dtls_dft_phrase, AH_CAPWAP_DTLS_PASS_DFT);
	ah_capwap_dtls_gen_footprint(foot_print, AH_CAPWAP_DTLS_PASS_DFT);
	strcpy(capwap_shm->dtls_cli.dtls_dft_footprint, foot_print);
	capwap_shm->dtls_negotiation = AH_CAPWAP_DTLS_NEGOTIATION_ENABLE;
	capwap_shm->reconnect_reason = AH_CAPWAP_RECONNECT_BOX_REBOOT;
	/* init capwap virtual hive manager*/
	ah_memset(capwap_shm->vhm_name, 0, AH_CAPWAP_MAX_VHM_NAME_LEN + 1);
	capwap_shm->transfer_mode = AH_CAPWAP_TCP_INIT;

	ah_strcpy(capwap_shm->proxy_name, "");
	capwap_shm->proxy_port = 0;
	ah_strcpy(capwap_shm->proxy_auth_name, "");
	ah_strcpy(capwap_shm->proxy_auth_pswd, "");
	capwap_shm->proxy_content_len = AH_CAPWAP_HTTP_TUNNEL_MAX_CONTENT_LEN;
	capwap_shm->enable_discovery_bcast = AH_CAPWAP_DISCOVERY_BROADCAST_ENABLE; /* default enable capwap local discover */

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_recovery_parameter
 *
 * Purpose:   recovery capwap parameter from share memory
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_recovery_parameter()
{
	int      i = 0;

	ah_capwap_para.enable = capwap_shm->enable;
	ah_capwap_para.capwap_port = capwap_shm->capwap_port;
	ah_capwap_para.event_flag = capwap_shm->event_flag;
	ah_capwap_para.dtls_negotiation = capwap_shm->dtls_negotiation;
	ah_capwap_para.enable_discovery_bcast = capwap_shm->enable_discovery_bcast;
	/*recovery CAPWAP timer value*/
	ah_capwap_para.capwap_timer.discovery_interval = capwap_shm->timer_cli.discovery_interval;
	ah_capwap_para.capwap_timer.echo_interval = capwap_shm->timer_cli.echo_interval;
	ah_capwap_para.capwap_timer.max_discovery_interval = capwap_shm->timer_cli.max_discovery_interval;
	ah_capwap_para.capwap_timer.neighbordead_interval = capwap_shm->timer_cli.neighbordead_interval;
	ah_capwap_para.capwap_timer.silent_interval = capwap_shm->timer_cli.silent_interval;
	ah_capwap_para.capwap_timer.waitjoin_interval = capwap_shm->timer_cli.waitjoin_interval;
	ah_capwap_para.capwap_timer.event_interval = capwap_shm->timer_cli.event_interval;
	ah_capwap_para.capwap_timer.dtls_cut_interval = capwap_shm->timer_cli.dtls_cut_interval;
	ah_capwap_para.capwap_timer.dtls_conn_interval = capwap_shm->timer_cli.dtls_conn_interval;
	ah_capwap_stat_update_timer_interval = capwap_shm->timer_cli.stat_update_interval;

	ah_capwap_get_member_num();
	for (i = 0; i < ah_capwap_para.capwap_number.timer_num; i++) {
		if (ah_capwap_timer[i].timertype == AH_CAPWAP_TIMER_DISCOVERY) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.discovery_interval;
		}
		if (ah_capwap_timer[i].timertype == AH_CAPWAP_TIMER_ECHO) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.echo_interval;
		}
		if (ah_capwap_timer[i].timertype == AH_CAPWAP_TIMER_MAXDISCOVERY) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.max_discovery_interval;
		}
		if (ah_capwap_timer[i].timertype ==  AH_CAPWAP_TIMER_NEIGHBORDEAD) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.neighbordead_interval;
		}
		if (ah_capwap_timer[i].timertype ==  AH_CAPWAP_TIMER_SILENT) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.silent_interval;
		}
		if (ah_capwap_timer[i].timertype ==  AH_CAPWAP_TIMER_WAITJOIN) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.waitjoin_interval;
		}
		if (ah_capwap_timer[i].timertype ==  AH_CAPWAP_TIMER_EVENT) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.event_interval;
		}
		if (ah_capwap_timer[i].timertype ==  AH_CAPWAP_TIMER_DTLS_CUT) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.dtls_cut_interval;
		}
		if (ah_capwap_timer[i].timertype ==  AH_CAPWAP_TIMER_DTLS_CONN) {
			ah_capwap_timer[i].timervalue = ah_capwap_para.capwap_timer.dtls_conn_interval;
		}
	}

	/*recovery CAPWAP counter value*/
	ah_capwap_para.capwap_counter.max_discoveries = capwap_shm->counter_cli.max_discoveries;
	ah_capwap_para.capwap_counter.max_retransmit = capwap_shm->counter_cli.max_retransmit;
	ah_capwap_para.capwap_counter.max_dtls_retry = capwap_shm->counter_cli.max_dtls_retry;

	/*recovery CAPWAP dtls value*/
	ah_capwap_para.capwap_dtls.dtls_enable = capwap_shm->dtls_cli.dtls_enable;
	ah_capwap_para.capwap_dtls.dtls_next_enable = capwap_shm->dtls_cli.dtls_next_enable;
	ah_capwap_para.capwap_dtls.dtls_bootstrap = capwap_shm->dtls_cli.dtls_bootstrap;
	ah_capwap_para.capwap_dtls.dtls_key_type = capwap_shm->dtls_cli.dtls_key_type;
	ah_capwap_para.capwap_dtls.cur_keyid = capwap_shm->dtls_cli.cur_keyid;
	ah_capwap_para.capwap_dtls.bak_keyid = capwap_shm->dtls_cli.bak_keyid;
	strcpy(ah_capwap_para.capwap_dtls.dtls_psk, capwap_shm->dtls_cli.dtls_psk);
	strcpy(ah_capwap_para.capwap_dtls.dtls_cur_phrase, capwap_shm->dtls_cli.dtls_cur_phrase);
	strcpy(ah_capwap_para.capwap_dtls.dtls_cur_footprint, capwap_shm->dtls_cli.dtls_cur_footprint);
	strcpy(ah_capwap_para.capwap_dtls.dtls_bak_phrase, capwap_shm->dtls_cli.dtls_bak_phrase);
	strcpy(ah_capwap_para.capwap_dtls.dtls_bak_footprint, capwap_shm->dtls_cli.dtls_bak_footprint);
	strcpy(ah_capwap_para.capwap_dtls.dtls_dft_phrase, capwap_shm->dtls_cli.dtls_dft_phrase);
	strcpy(ah_capwap_para.capwap_dtls.dtls_dft_footprint, capwap_shm->dtls_cli.dtls_dft_footprint);
	strcpy(ah_capwap_para.vhm_name, capwap_shm->vhm_name);
	ah_capwap_set_tcp_status(capwap_shm->transfer_mode);
	ah_capwap_set_tcp_http_proxy_info(capwap_shm->proxy_name, capwap_shm->proxy_port);
	ah_capwap_set_tcp_http_proxy_auth(capwap_shm->proxy_auth_name, capwap_shm->proxy_auth_pswd);
	ah_capwap_set_tcp_http_proxy_content_length(capwap_shm->proxy_content_len);
	capwap_mgt0_ip = ah_tpa_get_current_mgt_ip();
	capwap_shm->reconnect_reason = AH_CAPWAP_RECONNECT_UNKNOWN;

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_init_recovery
 *
 * Purpose:   init capwap share memory and thread lock
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_init_recovery(void)
{
#define AH_CAPWAP_SHM_INITED 1
	/*init share memory for recovery CLI*/
	capwap_shm = ah_shm_create(&shm_id, AH_CAPWAP_SHM_ID, sizeof(ah_capwap_recovery_t));

	if (capwap_shm->init != AH_CAPWAP_SHM_INITED) { /* module first time up */
		capwap_shm->init = AH_CAPWAP_SHM_INITED;
		/*init the default value for CAPWAP*/
		ah_capwap_init_parameter();
	} else {
		/* module restart, need recovery CLI*/
		ah_capwap_recovery_parameter();
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_discovery
 *
 * Purpose:   save discovery timer value to share memory
 *
 * Inputs:    value: discovery interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_discovery(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:discovery)\n");
		return -1;
	}

	capwap_shm->timer_cli.discovery_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_stat_update
 *
 * Purpose:   save stat-info update timer value to share memory and global var
 *
 * Inputs:    value: stat-info update interval value
 *
 * Output:    void
 **************************************************************************/
void ah_capwap_save_timer_stat_update(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:stat update)\n");
		return;
	}

	capwap_shm->timer_cli.stat_update_interval = value;
	ah_capwap_stat_update_timer_interval = value;
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_echo
 *
 * Purpose:   save echo timer value to share memory
 *
 * Inputs:    value: echo interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_echo(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:echo)\n");
		return -1;
	}

	capwap_shm->timer_cli.echo_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_maxdiscovery
 *
 * Purpose:   save maxdiscovery timer value to share memory
 *
 * Inputs:    value: maxdiscovery interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_maxdiscovery(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:maxdiscovery)\n");
		return -1;
	}

	capwap_shm->timer_cli.max_discovery_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_neighbordead
 *
 * Purpose:   save neighbordead timer value to share memory
 *
 * Inputs:    value: neighbordead interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_neighbordead(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:neighbordead)\n");
		return -1;
	}

	capwap_shm->timer_cli.neighbordead_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_silent
 *
 * Purpose:   save silent timer value to share memory
 *
 * Inputs:    value: silent interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_silent(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:silent)\n");
		return -1;
	}

	capwap_shm->timer_cli.silent_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_waitjoin
 *
 * Purpose:   save waitjoin timer value to share memory
 *
 * Inputs:    value: waitjoin interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_waitjoin(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:waitjoin)\n");
		return -1;
	}

	capwap_shm->timer_cli.waitjoin_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_event
 *
 * Purpose:   save event timer value to share memory
 *
 * Inputs:    value: event interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_event(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:event)\n");
		return -1;
	}

	capwap_shm->timer_cli.event_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_dtls_cut
 *
 * Purpose:   save dtls cut timer value to share memory
 *
 * Inputs:    value: dtls cut interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_dtls_cut(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_cut)\n");
		return -1;
	}

	capwap_shm->timer_cli.dtls_cut_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_timer_dtls_conn
 *
 * Purpose:   save dtls connect timer value to share memory
 *
 * Inputs:    value: dtls connect interval value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_timer_dtls_conn(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_conn)\n");
		return -1;
	}

	capwap_shm->timer_cli.dtls_conn_interval = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_counter_max_discoveries
 *
 * Purpose:   save max discoveries counter value to share memory
 *
 * Inputs:    value: max discoveries counter value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_counter_max_discoveries(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(TYPE:counter_max_discoverie)\n");
		return -1;
	}

	capwap_shm->counter_cli.max_discoveries = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_counter_max_retransmit
 *
 * Purpose:   save max retransmit counter value to share memory
 *
 * Inputs:    value: max retransmit counter value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_counter_max_retransmit(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:max_retransmit)\n");
		return -1;
	}

	capwap_shm->counter_cli.max_retransmit = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_counter_max_dtls_retry
 *
 * Purpose:   save max dtls retry counter value to share memory
 *
 * Inputs:    value: max dtls retry counter value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_counter_max_dtls_retry(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:max_dtls_retry)\n");
		return -1;
	}

	capwap_shm->counter_cli.max_dtls_retry = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_status
 *
 * Purpose:   save dtls status value to share memory
 *
 * Inputs:    value: capwap dtls status value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_status(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_status)\n");
		return -1;
	}

	capwap_shm->dtls_cli.dtls_enable = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_next_status
 *
 * Purpose:   save dtls next status value to share memory
 *
 * Inputs:    value: capwap dtls next status value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_next_status(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_next_status)\n");
		return -1;
	}

	capwap_shm->dtls_cli.dtls_next_enable = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_bootstrap
 *
 * Purpose:   save always accept bootstrap passphrase value to share memory
 *
 * Inputs:    value: always accept bootstrap passphrase value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_bootstrap(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_bootstrap)\n");
		return -1;
	}

	capwap_shm->dtls_cli.dtls_bootstrap = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_key_type
 *
 * Purpose:   save dtls key type (manual or passphrase)value to share memory
 *
 * Inputs:    value: dtls key type value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_key_type(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_key_type)\n");
		return -1;
	}

	capwap_shm->dtls_cli.dtls_key_type = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_cur_keyid
 *
 * Purpose:   save dtls current key id value to share memory
 *
 * Inputs:    value: dtls current key id value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_cur_keyid(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_cur_keyid)\n");
		return -1;
	}

	capwap_shm->dtls_cli.cur_keyid = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_bak_keyid
 *
 * Purpose:   save dtls backup key id value to share memory
 *
 * Inputs:    value: dtls backup key id value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_bak_keyid(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_bak_keyid)\n");
		return -1;
	}

	capwap_shm->dtls_cli.bak_keyid = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_psk
 *
 * Purpose:   save dtls manual psk value to share memory
 *
 * Inputs:    value: dtls manual psk value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_psk(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_psk)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_psk, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_cur_passphrase
 *
 * Purpose:   save dtls current passphrase value to share memory
 *
 * Inputs:    value: dtls current passphrase value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_cur_passphrase(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_cur_passphrase)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_cur_phrase, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_cur_footprint
 *
 * Purpose:   save dtls current passphrase footprint value to share memory
 *
 * Inputs:    value: dtls current passphrase footprint value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_cur_footprint(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_cur_footprint)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_cur_footprint, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_bak_passphrase
 *
 * Purpose:   save dtls backup passphrase value to share memory
 *
 * Inputs:    value: dtls backup passphrase value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_bak_passphrase(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_bak_passphrase)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_bak_phrase, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_bak_footprint
 *
 * Purpose:   save dtls backup passphrase footprint value to share memory
 *
 * Inputs:    value: dtls backup passphrase footprint value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_bak_footprint(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_bak_footprint)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_bak_footprint, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_dft_passphrase
 *
 * Purpose:   save dtls default passphrase value to share memory
 *
 * Inputs:    value: dtls default passphrase value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_dft_passphrase(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_dft_passphrase)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_dft_phrase, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_dft_footprint
 *
 * Purpose:   save dtls default passphrase footprint value to share memory
 *
 * Inputs:    value: dtls default passphrase footprint value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_dft_footprint(char *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_dft_footprint)\n");
		return -1;
	}

	strcpy(capwap_shm->dtls_cli.dtls_dft_footprint, value);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_enable_status
 *
 * Purpose:   save capwap enable status value to share memory
 *
 * Inputs:    value: capwap enable status value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_enable_status(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:enable_status)\n");
		return -1;
	}

	capwap_shm->enable = value;

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_save_discovery_method
 *
 * Purpose:   save capwap discovery method value to share memory
 *
 * Inputs:    value: capwap discovery method value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_discovery_method(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:enable_status)\n");
		return -1;
	}

	capwap_shm->enable_discovery_bcast = value;

	return 0;
}
/***************************************************************************
 *
 * Function:  ah_capwap_save_port
 *
 * Purpose:   save capwap protocol port value to share memory
 *
 * Inputs:    value: capwap protocol port value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_port(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:port)\n");
		return -1;
	}

	capwap_shm->capwap_port = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_port
 *
 * Purpose:   get capwap protocol port value from share memory
 *
 * Inputs:     void
 *
 * Output:    value: capwap protocol port value
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_get_port(int *value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:get port)\n");
		return -1;
	}

	*value = capwap_shm->capwap_port;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_event_enable_status
 *
 * Purpose:   save capwap event enable status value to share memory
 *
 * Inputs:    value: capwap event enable status value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_event_enable_status(int value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:event_enable_status)\n");
		return -1;
	}

	capwap_shm->event_flag = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_dtls_negotiation_status
 *
 * Purpose:   save capwap event enable status value to share memory
 *
 * Inputs:    value: capwap event enable status value
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_dtls_negotiatio_status(uchar value)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:dtls_negotiatio_status)\n");
		return -1;
	}

	capwap_shm->dtls_negotiation = value;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_vhm_name
 *
 * Purpose:   save capwap capwap client vhm to share memory
 *
 * Inputs:    value: vhm string, NULL is unset
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_vhm_name(char *name)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_vhm_name)\n");
		return -1;
	}

	if (name == NULL) { /* unset */
		if (ah_strlen(capwap_shm->vhm_name) != 0) {
			ah_memset(capwap_shm->vhm_name, 0, AH_CAPWAP_MAX_VHM_NAME_LEN + 1);
		}
	} else {
		ah_strcpy(capwap_shm->vhm_name, name);
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_transfer_mode
 *
 * Purpose:   save capwap client transfer mode
 *
 * Inputs:    mode: transfer mode
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_transfer_mode(uchar mode)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_transfer_mode)\n");
		return -1;
	}

	capwap_shm->transfer_mode = mode;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_proxy_info
 *
 * Purpose:   save capwap client proxy information
 *
 * Inputs:    name: proxy name
 *                 port: proxy port
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_proxy_info(char *name, int port)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_proxy_info)\n");
		return -1;
	}

	capwap_shm->proxy_port = port;
	ah_strcpy(capwap_shm->proxy_name, name);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_proxy_auth
 *
 * Purpose:   save capwap client proxy auth information
 *
 * Inputs:    name: proxy name
 *                 pswd: proxy password
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_proxy_auth(char *name, char *pswd)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_proxy_auth)\n");
		return -1;
	}

	ah_strcpy(capwap_shm->proxy_auth_name, name);
	ah_strcpy(capwap_shm->proxy_auth_pswd, pswd);

	return 0;
}

#ifdef AH_BONJOUR_GATEWAY_SUPPORT
/***************************************************************************
 *
 * Function:  ah_capwap_save_proxy_cfg_method
 *
 * Purpose:   save capwap client proxy cfg method
 *
 * Inputs:    method
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_proxy_cfg_method(int method)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_proxy_info)\n");
		return -1;
	}

	capwap_shm->proxy_cfg_method = method;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_bonjour_service_type
 *
 * Purpose:   save capwap bonjour service type
 *
 * Inputs:    method
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_bonjour_service_type(int type)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_proxy_info)\n");
		return -1;
	}

	capwap_shm->bonjour_service_type = type;
	return 0;
}

#endif

/***************************************************************************
 *
 * Function:  ah_capwap_save_proxy_content_length
 *
 * Purpose:   save capwap client proxy content length
 *
 * Inputs:    length: content length
 *
 * Output:    void
 *
 * Returns:   0 success. otherwise -1
 *
 **************************************************************************/
int ah_capwap_save_proxy_content_length(uint32_t length)
{
	if (capwap_shm == NULL) {
		ah_err_old("CAPWAP:Share memory pointer is NULL(type:ah_capwap_save_proxy_content_length)\n");
		return -1;
	}

	capwap_shm->proxy_content_len = length;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_shm_value
 *
 * Purpose:   get share memory value
 *
 * Inputs:    void
 *
 * Output:    share memory value
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_get_shm_value(ah_capwap_recovery_t *shm_value)
{
	shm_value->init = capwap_shm->init;
	shm_value->enable = capwap_shm->enable;
	shm_value->capwap_port = capwap_shm->capwap_port;
	shm_value->event_flag = capwap_shm->event_flag;

	/*recovery CAPWAP timer value*/
	shm_value->timer_cli.discovery_interval = capwap_shm->timer_cli.discovery_interval;
	shm_value->timer_cli.echo_interval = capwap_shm->timer_cli.echo_interval;
	shm_value->timer_cli.max_discovery_interval = capwap_shm->timer_cli.max_discovery_interval;
	shm_value->timer_cli.neighbordead_interval = capwap_shm->timer_cli.neighbordead_interval;
	shm_value->timer_cli.silent_interval = capwap_shm->timer_cli.silent_interval;
	shm_value->timer_cli.waitjoin_interval = capwap_shm->timer_cli.waitjoin_interval;
	shm_value->timer_cli.event_interval = capwap_shm->timer_cli.event_interval;
	shm_value->timer_cli.dtls_cut_interval = capwap_shm->timer_cli.dtls_cut_interval;
	shm_value->timer_cli.dtls_conn_interval = capwap_shm->timer_cli.dtls_conn_interval;
	shm_value->timer_cli.stat_update_interval = capwap_shm->timer_cli.stat_update_interval;

	/*recovery CAPWAP counter value*/
	shm_value->counter_cli.max_discoveries = capwap_shm->counter_cli.max_discoveries;
	shm_value->counter_cli.max_retransmit = capwap_shm->counter_cli.max_retransmit;
	shm_value->counter_cli.max_dtls_retry = capwap_shm->counter_cli.max_dtls_retry;

	/*recovery CAPWAP dtls value*/
	shm_value->dtls_cli.dtls_enable = capwap_shm->dtls_cli.dtls_enable;
	shm_value->dtls_cli.dtls_next_enable = capwap_shm->dtls_cli.dtls_next_enable;
	shm_value->dtls_cli.dtls_bootstrap = capwap_shm->dtls_cli.dtls_bootstrap;
	shm_value->dtls_cli.dtls_key_type = capwap_shm->dtls_cli.dtls_key_type;
	shm_value->dtls_cli.cur_keyid = capwap_shm->dtls_cli.cur_keyid;
	shm_value->dtls_cli.bak_keyid = capwap_shm->dtls_cli.bak_keyid;
	strcpy(shm_value->dtls_cli.dtls_psk, capwap_shm->dtls_cli.dtls_psk);
	strcpy(shm_value->dtls_cli.dtls_cur_phrase, capwap_shm->dtls_cli.dtls_cur_phrase);
	strcpy(shm_value->dtls_cli.dtls_bak_phrase, capwap_shm->dtls_cli.dtls_bak_phrase);
	strcpy(shm_value->dtls_cli.dtls_dft_phrase, capwap_shm->dtls_cli.dtls_dft_phrase);
	strcpy(shm_value->dtls_cli.dtls_cur_footprint, capwap_shm->dtls_cli.dtls_cur_footprint);
	strcpy(shm_value->dtls_cli.dtls_bak_footprint, capwap_shm->dtls_cli.dtls_bak_footprint);
	strcpy(shm_value->dtls_cli.dtls_dft_footprint, capwap_shm->dtls_cli.dtls_dft_footprint);
	strcpy(shm_value->vhm_name, capwap_shm->vhm_name);
	shm_value->dtls_negotiation = capwap_shm->dtls_negotiation;
	shm_value->reconnect_reason = capwap_shm->reconnect_reason;
	shm_value->transfer_mode = capwap_shm->transfer_mode;
	strcpy(shm_value->proxy_name, capwap_shm->proxy_name);
	shm_value->proxy_port = capwap_shm->proxy_port;
	strcpy(shm_value->proxy_auth_name, capwap_shm->proxy_auth_name);
	strcpy(shm_value->proxy_auth_pswd, capwap_shm->proxy_auth_pswd);
	shm_value->proxy_content_len = capwap_shm->proxy_content_len;
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	shm_value->bonjour_service_type = capwap_shm->bonjour_service_type;
	shm_value->proxy_cfg_method = capwap_shm->proxy_cfg_method;
#endif
	shm_value->enable_discovery_bcast = capwap_shm->enable_discovery_bcast;

	return;
}


