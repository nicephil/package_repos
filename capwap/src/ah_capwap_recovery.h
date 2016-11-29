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
#ifndef AH_CAPWAP_RECOVERY_H
#define AH_CAPWAP_RECOVERY_H

int ah_capwap_init_recovery(void);
int ah_capwap_save_timer_discovery(int value);
void ah_capwap_save_timer_stat_update(int value);
int ah_capwap_save_timer_echo(int value);
int ah_capwap_save_timer_maxdiscovery(int value);
int ah_capwap_save_timer_neighbordead(int value);
int ah_capwap_save_timer_silent(int value);
int ah_capwap_save_timer_waitjoin(int value);
int ah_capwap_save_timer_event(int value);
int ah_capwap_save_timer_dtls_cut(int value);
int ah_capwap_save_timer_dtls_conn(int value);
int ah_capwap_save_counter_max_discoveries(int value);
int ah_capwap_save_counter_max_retransmit(int value);
int ah_capwap_save_counter_max_dtls_retry(int value);
int ah_capwap_save_dtls_status(int value);
int ah_capwap_save_dtls_next_status(int value);
int ah_capwap_save_dtls_bootstrap(int value);
int ah_capwap_save_dtls_key_type(int value);
int ah_capwap_save_dtls_cur_keyid(int value);
int ah_capwap_save_dtls_bak_keyid(int value);
int ah_capwap_save_dtls_cur_passphrase(char *value);
int ah_capwap_save_dtls_cur_footprint(char *value);
int ah_capwap_save_dtls_bak_passphrase(char *value);
int ah_capwap_save_dtls_bak_footprint(char *value);
int ah_capwap_save_dtls_dft_passphrase(char *value);
int ah_capwap_save_dtls_dft_footprint(char *value);
int ah_capwap_save_port(int value);
int ah_capwap_save_event_enable_status(int value);
int ah_capwap_save_dtls_psk(char *value);
int ah_capwap_save_enable_status(int value);
int ah_capwap_save_discovery_method(int value);
int ah_capwap_save_dtls_negotiatio_status(uchar value);
void ah_capwap_get_shm_value(ah_capwap_recovery_t *shm_value);
int ah_capwap_save_vhm_name(char *name);
int ah_capwap_save_transfer_mode(uchar mode) ;
int ah_capwap_save_proxy_info(char *name, int port) ;
int ah_capwap_save_proxy_auth(char *name, char *pswd) ;
int ah_capwap_save_proxy_content_length(uint32_t length) ;
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
int ah_capwap_save_proxy_cfg_method(int method);
int ah_capwap_save_bonjour_service_type(int type);
#endif

#endif
