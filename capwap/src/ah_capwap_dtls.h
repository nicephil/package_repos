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
#ifndef AH_CAPWAP_DTLS_H
#define AH_CAPWAP_DTLS_H

#include "openssl/lhash.h"
#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "openssl/dh.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/dtls1.h"
#include "openssl/sha.h"
#include "openssl/md5.h"

#include "ah_capwap_types.h"

#define AH_CAPWAP_DTLS_SOCKET_WRITE 0
#define AH_CAPWAP_DTLS_SOCKET_READ   1
#define AH_CAPWAP_DTLS_SOCKET_UNAVLIB -1

int ah_capwap_dtls_init();
int ah_capwap_dtls_clean(void);
int ah_capwap_dtls_conn_abort();
int ah_capwap_dtls_get_conn_status();
int ah_capwap_dtls_get_enable_status();
int ah_capwap_dtls_get_next_enable_status();
int ah_capwap_dtls_encrypt(char *pkt_buf, uint32_t pkt_len);
int ah_capwap_dtls_decrypt(char *pkt_buf, uint32_t pkt_len);
int ah_capwap_dtls_set_enable_status(int enable_flag);
int ah_capwap_dtls_snd_pkt(char *pkt_buff, uint32_t pkt_len);
int ah_capwap_dtls_pkt_type(char *pkt_buf, uint32_t pkt_len);
int ah_capwap_dtls_set_next_enable_status(int enable_flag);
int ah_capwap_dtls_set_conn_status(ah_capwap_dtls_status_t dtls_status);
int ah_capwap_dtls_gen_footprint(char *boot_foot, char *passphrase);
int ah_capwap_dtls_connect(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
						   uint32_t    buflen);
int ah_capwap_dtls_disconnect(uint32_t clientstate, uint32_t clientevent, uint32_t clienttimer, char *buf ,
							  uint32_t    buflen);

void *ah_capwap_dtls_thread();
void ah_capwap_dtls_conn_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_dtls_disconn_timer(ah_ptimer_t *timername, void *timerparameter);
void ah_capwap_dtls_set_conn_timeout(struct timeval *rcv_tmot, struct timeval  *snd_tmot);

const char *ah_capwap_dtls_conn_state_str(ah_capwap_dtls_status_t dtls_status);
int ah_capwap_dtls_set_negotiation_status(int enable_flag);
int ah_capwap_dtls_get_negotiation_status();

#endif
