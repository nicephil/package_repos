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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <error.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_dbg_agent.h"
#include "ah_scd_api.h"
#include "ah_dcd_api.h"
#include "ah_hwlib_api.h"

#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_mem_chk_api.h"

#define AH_CAPWAP_DTLS_HDR                 1
#define AH_CAPWAP_DTLS_VER_OFFSET          28
#define AH_CAPWAP_DTLS_TYPE_OFFSET         24
#define AH_CAPWAP_DTLS_HANDSHAKE_FAILED    0
#define AH_CAPWAP_DTLS_HANDSHAKE_SUCCESS   1
#define AH_CAPWAP_DTLS_SHA1_LEN            20

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_negotiation_status
 *
 * Purpose:   set dtls negotiation status
 *
 * Inputs:    dtls negotiation flag
 *
 * Output:    void
 *
 * Returns:   0
 *
 **************************************************************************/
int ah_capwap_dtls_set_negotiation_status(int enable_flag)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.dtls_negotiation = enable_flag;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_negotiation_status
 *
 * Purpose:   get dtls negotiation status
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   dtls negotiation status
 *
 **************************************************************************/
int ah_capwap_dtls_get_negotiation_status()
{
	int      dtls_negotiation = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	dtls_negotiation = ah_capwap_para.dtls_negotiation;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return dtls_negotiation;
}


/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_enable_status
 *
 * Purpose:   set dtls enable or disable status
 *
 * Inputs:    dtls enable or disable
 *
 * Output:    void
 *
 * Returns:   0
 *
 **************************************************************************/
int ah_capwap_dtls_set_enable_status(int enable_flag)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.capwap_dtls.dtls_enable = enable_flag;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_enable_status
 *
 * Purpose:   get dtls enable or disable status
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   dtls enable or disable status
 *
 **************************************************************************/
int ah_capwap_dtls_get_enable_status()
{
	int      dtls_enable = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	dtls_enable = ah_capwap_para.capwap_dtls.dtls_enable;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return dtls_enable;

}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_next_enable_status
 *
 * Purpose:   set next connect dtls enable status
 *
 * Inputs:    dtls_status: dtls enable flag
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 **************************************************************************/
int ah_capwap_dtls_set_next_enable_status(int enable_flag)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.capwap_dtls.dtls_next_enable = enable_flag;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_next_enable_status
 *
 * Purpose:   get dtls next connect enable or disable status
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   dtls enable or disable status
 *
 **************************************************************************/
int ah_capwap_dtls_get_next_enable_status()
{
	int      dtls_enable = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	dtls_enable = ah_capwap_para.capwap_dtls.dtls_next_enable;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return dtls_enable;

}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_conn_status
 *
 * Purpose:   set dtls connect status
 *
 * Inputs:    dtls connect status
 *
 * Output:    void
 *
 * Returns:   0
 *
 **************************************************************************/
int ah_capwap_dtls_set_conn_status(ah_capwap_dtls_status_t dtls_status)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	ah_capwap_para.capwap_dtls.dtls_status = dtls_status;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_conn_status
 *
 * Purpose:   get dtls connect status
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   dtls connect status
 *
 **************************************************************************/
int ah_capwap_dtls_get_conn_status()
{
	int      dtls_status = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	dtls_status = ah_capwap_para.capwap_dtls.dtls_status;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return dtls_status;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_init
 *
 * Purpose:   initial dtls
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 is success, otherwise is failed
 *
 **************************************************************************/
int ah_capwap_dtls_init()
{
#define AH_CAPWAP_DTLS_RANDOM_FILE "/dev/urandom"
	/*do some initial part*/
	FILE    *fp = NULL;
#define AH_CAPWAP_DTLS_RANDOM_SIZE 8
	char       seed[AH_CAPWAP_DTLS_RANDOM_SIZE];
	char       footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1];
	/*
	 * ssl initialization
	 */
	/*get some randomness*/
	ah_log_old(AH_LOG_INFO, "CAPWAP: Ready to generate random number");
	fp = fopen(AH_CAPWAP_DTLS_RANDOM_FILE, "r");
	if (fp == NULL) {
		ah_err_old("CAPWAP_DTLS:can't open /dev/random\n");
	} else {
		(void) fread(seed, sizeof(char), AH_CAPWAP_DTLS_RANDOM_SIZE, fp);
		(void) fclose(fp);
	}
	ah_log_old(AH_LOG_INFO, "CAPWAP: Generate random number successfully");

	/*seed the random pool*/
	RAND_seed(seed, AH_CAPWAP_DTLS_RANDOM_SIZE);
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "SSL random:\n");
		ah_hexdump((uchar *)seed, AH_CAPWAP_DTLS_RANDOM_SIZE);
	}

	SSL_library_init();

	/*load error strings*/
	(void) SSL_load_error_strings();

	/*should only add supported algs...*/
	OpenSSL_add_all_algorithms() ;

	/*Init bootstrap passphrase and footprint*/
	if (strlen(ah_capwap_para.capwap_dtls.dtls_dft_phrase) == 0) {
		ah_strcpy(ah_capwap_para.capwap_dtls.dtls_dft_phrase, AH_CAPWAP_DTLS_PASS_DFT);
		ah_capwap_dtls_gen_footprint(footprint, AH_CAPWAP_DTLS_PASS_DFT);
		ah_strcpy(ah_capwap_para.capwap_dtls.dtls_dft_footprint, footprint);
	}

	ah_dbg_old(capwap_ssl, "CAPWAP initial success!\n");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_clean
 *
 * Purpose:   clean dtls resource
 *
 * Output:    void
 *
 * Returns:   0
 *
 **************************************************************************/
int ah_capwap_dtls_clean(void)
{

	// free the ssl connection
	ah_dbg_old(capwap_ssl, "clean DTLS resource\n");

	if (ah_capwap_para.capwap_dtls.SslConnectionPtr != NULL) {
		SSL_free(ah_capwap_para.capwap_dtls.SslConnectionPtr);
		ah_capwap_para.capwap_dtls.SslConnectionPtr = NULL;
	}

	// free the ssl context
	if (ah_capwap_para.capwap_dtls.SslCtxPtr != NULL) {
		SSL_CTX_free(ah_capwap_para.capwap_dtls.SslCtxPtr);
		ah_capwap_para.capwap_dtls.SslCtxPtr = NULL;
	}

	// close the socketpair
	if (ah_capwap_para.capwap_dtls.SocketPair[0] > 0) {
		(void) close(ah_capwap_para.capwap_dtls.SocketPair[0]);
		ah_capwap_para.capwap_dtls.SocketPair[0] = AH_CAPWAP_DTLS_SOCKET_UNAVLIB;
	}
	if (ah_capwap_para.capwap_dtls.SocketPair[1] > 0) {
		(void) close(ah_capwap_para.capwap_dtls.SocketPair[1]);
		ah_capwap_para.capwap_dtls.SocketPair[1] = AH_CAPWAP_DTLS_SOCKET_UNAVLIB;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_psk_key2bn
 *
 * Purpose:   convert the PSK key in ascii to binary
 *
 * Inputs:    psk_key: ascii
 *            max_psk_len: max psk length
 *
 * Output:    psk: binary PSK
 *
 * Returns:   psk length, if error then return 0
 *
 **************************************************************************/
int ah_capwap_dtls_psk_key2bn(const char *psk_key, uchar *psk, uint max_psk_len)
{
	int      psk_len = 0;
	int      ret = 0;
	BIGNUM *bn = NULL;

	ret = BN_hex2bn(&bn, psk_key);
	if (!ret) {
		ah_err_old("CAPWAP could not convert PSK key '%s' to BIGNUM\n", psk_key);
		goto OUT;
	}
	if (BN_num_bytes(bn) > max_psk_len) {
		ah_err_old("CAPWAP PSK buffer of callback is too small (%d) for key (%d)\n", max_psk_len, BN_num_bytes(bn));
		goto OUT;
	}
	psk_len = BN_bn2bin(bn, psk);
	BN_free(bn);
	bn = NULL;
	if (psk_len < 0) {
		ah_err_old("CAPWAP DTLS convert length is error!(len:%d)", psk_len);
		psk_len = 0;
		goto OUT;
	}

	ah_dbg_old(capwap_packet, "DTLS PSK:");
	if (capwap_packet) {
		ah_hexdump((uchar *)psk, psk_len);
	}

OUT:
	if (bn != NULL) {
		BN_free(bn);
	}
	return psk_len;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_hint_from_pkt
 *
 * Purpose:   get the hint from ServerKeyExchange packet
 *
 * Inputs:    dtls_hint:dtls_hint string
 *
 * Output:    dtls_foot: dtls footprint
 *
 * Returns:   return the integer hint, -1 is failed
 *
 **************************************************************************/
int  ah_capwap_dtls_get_hint_from_pkt(const char *dtls_hint, char *dtls_foot)
{
#define AH_CAPWAP_DTLS_HINT_LEN   16 /*mac:12 hint:2 footprint:2*/
#define AH_CAPWAP_DTLS_HINT_MAC_LEN 12
#define AH_CAPWAP_DTLS_HINT_KEYID_LEN 2
	char      hm_keyid[AH_CAPWAP_DTLS_HINT_KEYID_LEN + 1];
	int      hint = -1;

	/*check the hint is aerohive format*/
	if (strlen(dtls_hint) != AH_CAPWAP_DTLS_HINT_LEN) {
		ah_dbg_old(capwap_ssl, "The hint is not correct hint:%s, the hint len isn't correct\n", dtls_hint);
		goto OUT;
	}
	/*the dtls_hint fromat is <mac><hint><footprint>*/
	ah_memcpy(hm_keyid, (dtls_hint + AH_CAPWAP_DTLS_HINT_MAC_LEN), AH_CAPWAP_DTLS_HINT_KEYID_LEN);
	hm_keyid[AH_CAPWAP_DTLS_HINT_KEYID_LEN] = '\0';
	/*change hex string to an int*/
	sscanf(hm_keyid, "%2x", &hint);

	/*get footprint*/
	ah_memcpy(dtls_foot, (dtls_hint + AH_CAPWAP_DTLS_HINT_MAC_LEN + AH_CAPWAP_DTLS_HINT_KEYID_LEN), AH_CAPWAP_DTLS_FOOTPRINT_LEN);
	dtls_foot[AH_CAPWAP_DTLS_FOOTPRINT_LEN] = '\0';

	ah_dbg_old(capwap_ssl, "Get the SSL hint:%d footprint:%s\n", hint, dtls_foot);

OUT:
	return hint;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_gen_footprint
 *
 * Purpose:   generate the footprint
 *
 * Inputs:    passphrase:the correspond passphrase
 *
 * Output:    boot_foot:two byte footprint
 *
 * Returns:   0 is success, otherwise is failed
 *
 **************************************************************************/
int ah_capwap_dtls_gen_footprint(char *boot_foot, char *passphrase)
{
	char      pass_sha1[AH_CAPWAP_DTLS_SHA1_LEN] = {0};

	SHA1((uchar *)passphrase, strlen(passphrase), (uchar *)pass_sha1);

	/*change one byte to two bytes string(0 is 00, 255 is ff)*/
	sprintf(boot_foot, "%02x", (uchar)pass_sha1[0]);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_passphrase
 *
 * Purpose:   get the psk identity in term of hint
 *
 * Inputs:    hint: psk hint
 *        max_len: max length for dtls_iden
 *
 * Output:    dtls_id: hint id
 *            dtls_pass: dtls passphrase
 *            footprint: dtls passphrase footprint
 *
 * Returns:   0 is success, otherwise is failed
 *
 **************************************************************************/
int ah_capwap_dtls_get_passphrase(const char *dtls_hint, char *dtls_pass, uint max_len, int *dtls_id,
								  char      *footprint)
{
	uint      iden_len = 0;
	char      *kid_type = "NULL";
	char      dtls_foot[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1] = {0};
	int      key_id = 0;

	iden_len = (max_len > AH_CAPWAP_DTLS_MAX_PHRASE_LEN) ? AH_CAPWAP_DTLS_MAX_PHRASE_LEN : max_len;
	ah_dbg_old(capwap_ssl, "the max dtls identity length is %d\n", iden_len);

	key_id = ah_capwap_dtls_get_hint_from_pkt(dtls_hint, dtls_foot);
	if (key_id == -1) {
		/*hint format is error*/
		return -1;
	}
	/*1. check key_id_proposed == cur_key_id. Yes, use cur_key_id. No, goto 2.
	  2. check key_id_proposed == bak_key_id. Yes, use bak_key_id. No, goto 3.
	  3. check key_id_proposed == 0. No, fall back to key_id 0. Yes, goto 4.
	  4. check alwayway_accept_bootstrap_key == TRUE. Yes, use key_id 0.
	  No, reject the proposal, and terminate handshake.
	 */

	/*get the current identity*/
	if (key_id == ah_capwap_para.capwap_dtls.cur_keyid
		&& ah_capwap_para.capwap_dtls.cur_keyid != 0
		&& (strcmp(dtls_foot, ah_capwap_para.capwap_dtls.dtls_cur_footprint) == 0)) {
		memcpy(dtls_pass, ah_capwap_para.capwap_dtls.dtls_cur_phrase, iden_len);
		strncpy(footprint, ah_capwap_para.capwap_dtls.dtls_cur_footprint, AH_CAPWAP_DTLS_FOOTPRINT_LEN);
		footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN] = '\0';
		kid_type = "current identity";
		ah_capwap_para.capwap_dtls.using_keyid = ah_capwap_para.capwap_dtls.cur_keyid;
		*dtls_id = key_id;
		goto OUT;
	}

	/*get the backup identity*/
	if (key_id == ah_capwap_para.capwap_dtls.bak_keyid
		&& ah_capwap_para.capwap_dtls.bak_keyid != 0
		&& (strcmp(dtls_foot, ah_capwap_para.capwap_dtls.dtls_bak_footprint) == 0)) {
		memcpy(dtls_pass, ah_capwap_para.capwap_dtls.dtls_bak_phrase, strlen(ah_capwap_para.capwap_dtls.dtls_bak_phrase));
		strncpy(footprint, ah_capwap_para.capwap_dtls.dtls_bak_footprint, AH_CAPWAP_DTLS_FOOTPRINT_LEN);
		footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN] = '\0';
		kid_type = "backup identity";
		*dtls_id = ah_capwap_para.capwap_dtls.bak_keyid;
		ah_capwap_para.capwap_dtls.using_keyid = ah_capwap_para.capwap_dtls.bak_keyid;
		goto OUT;
	}

	/*get the default identity*/
	if (key_id != ah_capwap_para.capwap_dtls.dft_keyid) {
		memcpy(dtls_pass, ah_capwap_para.capwap_dtls.dtls_dft_phrase, iden_len);
		strncpy(footprint, ah_capwap_para.capwap_dtls.dtls_dft_footprint, AH_CAPWAP_DTLS_FOOTPRINT_LEN);
		footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN] = '\0';
		kid_type = "default identity";
		*dtls_id = ah_capwap_para.capwap_dtls.dft_keyid;
		ah_capwap_para.capwap_dtls.using_keyid = ah_capwap_para.capwap_dtls.dft_keyid;
		goto OUT;
	}

	/*check the accept*/
	if (ah_capwap_para.capwap_dtls.dtls_bootstrap == AH_CAPWAP_DTLS_ACCEPT_BOOTSTRAP_ENABLE
		&& (strcmp(dtls_foot, ah_capwap_para.capwap_dtls.dtls_dft_footprint)) == 0) {
		memcpy(dtls_pass, ah_capwap_para.capwap_dtls.dtls_dft_phrase, iden_len);
		strncpy(footprint, ah_capwap_para.capwap_dtls.dtls_dft_footprint, AH_CAPWAP_DTLS_FOOTPRINT_LEN);
		footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN] = '\0';
		kid_type = "default identity";
		*dtls_id = ah_capwap_para.capwap_dtls.dft_keyid;
		ah_capwap_para.capwap_dtls.using_keyid = ah_capwap_para.capwap_dtls.dft_keyid;
		goto OUT;
	}

	/*reject the proposal, and terminate handshake.*/
	ah_dbg_old(capwap_ssl, "Can not get the passphrase(hint:%d accept bootstrap falg:%d)\n", key_id, ah_capwap_para.capwap_dtls.dtls_bootstrap);
	return -1;

OUT:
	ah_dbg_old(capwap_ssl, "Get the dtls identity (%s) is: %d passphrase:%s\n", kid_type, *dtls_id, dtls_pass);;
	if (capwap_packet) {
		ah_hexdump((uchar *)dtls_pass, iden_len);
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_gen_psk
 *
 * Purpose:   generate the dtls psk
 *
 * Inputs:    passphrase: passphrase string
 *
 * Output:    psk_str:the PSK string
 *
 * Returns:   the length of PSK
 *
 **************************************************************************/
int ah_capwap_dtls_gen_psk(uchar *psk_str, char *passphrase)
{
#define AH_CPAWPA_DTLS_MD5_LEN 16
#define AH_CAPWAP_DTLS_MAX_STR_LEN  100
#define AH_CAPWAP_DTLS_FIX_STR1  "AeRoHiVe AP CAPWAP psk"
#define AH_CAPWAP_DTLS_FIX_STR2  "aErOhIvE HiveManager CAPWAP psk"
	char      dtls_salt1[AH_CAPWAP_DTLS_MAX_STR_LEN] = {0};
	char      dtls_salt2[AH_CAPWAP_DTLS_MAX_STR_LEN] = {0};
	char      secret1[AH_CAPWAP_DTLS_MAX_STR_LEN] = {0};
	char      secret2[AH_CAPWAP_DTLS_MAX_STR_LEN] = {0};
	char      psk1[AH_CAPWAP_DTLS_SHA1_LEN] = {0};
	char      psk2[AH_CPAWPA_DTLS_MD5_LEN] = {0};
	char      tmp = 0;
	int      salt1_len = 0;
	int      salt2_len = 0;
	int      sec1_len = 0;
	int      sec2_len = 0;
	int      i = 0;

	/*1.generate dtls salt1*/
	ah_memcpy(dtls_salt1, ah_capwap_info.wtpmac, AH_CAPWAP_MAC_LEN);
	salt1_len += AH_CAPWAP_MAC_LEN;
	ah_memcpy(dtls_salt1 + salt1_len, ah_capwap_info.wtpsn, (AH_CAPWAP_WTP_SN_LEN - 1));
	salt1_len += AH_CAPWAP_WTP_SN_LEN - 1;
	ah_memcpy(dtls_salt1 + salt1_len, AH_CAPWAP_DTLS_FIX_STR1, strlen(AH_CAPWAP_DTLS_FIX_STR1));
	salt1_len += strlen(AH_CAPWAP_DTLS_FIX_STR1);
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS salt1:\n");
		ah_hexdump((uchar *)dtls_salt1, salt1_len);
	}
#endif

	/*2.inv_HM_MAC = ~(HM_MAC) */
	for (i = 0; i < AH_CAPWAP_MAC_LEN; i++) {
		tmp = ~ah_capwap_info.acmac[i];
		dtls_salt2[i] = tmp;
	}
	salt2_len += AH_CAPWAP_MAC_LEN;

	/*3.generate dtls salt2*/
	ah_memcpy(dtls_salt2 + salt2_len, AH_CAPWAP_DTLS_FIX_STR2, strlen(AH_CAPWAP_DTLS_FIX_STR2));
	salt2_len += strlen(AH_CAPWAP_DTLS_FIX_STR2);
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS salt2:\n");
		ah_hexdump((uchar *)dtls_salt2, salt2_len);
	}
#endif

	/*4.generate secret1*/
	ah_memcpy(secret1, passphrase, strlen(passphrase));
	sec1_len += strlen(passphrase);
	ah_memcpy(secret1 + sec1_len, dtls_salt1, salt1_len);
	sec1_len += salt1_len;
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS secret1:\n");
		ah_hexdump((uchar *)secret1, sec1_len);
	}
#endif

	/*5.generate secret2*/
	ah_memcpy(secret2, passphrase, strlen(passphrase));
	sec2_len += strlen(passphrase);
	ah_memcpy(secret2 + sec2_len, dtls_salt2, salt2_len);
	sec2_len += salt2_len;
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS secret2:\n");
		ah_hexdump((uchar *)secret2, sec2_len);
	}
#endif

	/*6.generate PSK1*/
	SHA1((uchar *)secret1, sec1_len, (uchar *)psk1);
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS SHA1:\n");
		ah_hexdump((uchar *)psk1, AH_CAPWAP_DTLS_SHA1_LEN);
	}
#endif

	/*7.generate PSK2*/
	MD5((uchar *)secret2, sec2_len, (uchar *)psk2);
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS MD5:\n");
		ah_hexdump((uchar *)psk2, AH_CPAWPA_DTLS_MD5_LEN);
	}
#endif

	/*8.generate PSK*/
	ah_memcpy(psk_str, psk1, AH_CAPWAP_DTLS_SHA1_LEN);
	ah_memcpy(psk_str + AH_CAPWAP_DTLS_SHA1_LEN, psk2, AH_CPAWPA_DTLS_MD5_LEN);
#ifndef AH_BUILD_RELEASE
	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "DTLS PSK:\n");
		ah_hexdump((uchar *)psk_str, AH_CAPWAP_DTLS_SHA1_LEN + AH_CPAWPA_DTLS_MD5_LEN);
	}
#endif

	return AH_CAPWAP_DTLS_SHA1_LEN + AH_CPAWPA_DTLS_MD5_LEN;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_get_psk
 *
 * Purpose:   get the dtls psk
 *
 * Inputs:    dtls_pass: client dtls passphrase
 *            dtls_psk: the dtls psk
 *        max_len: the max length for PSK
 *
 * Output:    dtls_psk:the final psk
 *
 * Returns:   the length for PSK
 *
 **************************************************************************/
int ah_capwap_dtls_get_psk(char *dtls_pass, uchar *dtls_psk, uint max_len)
{
	int      psk_len = 0;
	int      rc = 0;
	char      *psk_type = NULL;

	psk_len = (max_len > AH_CAPWAP_DTLS_MAX_PSK_LEN) ? AH_CAPWAP_DTLS_MAX_PSK_LEN : max_len;
	ah_dbg_old(capwap_ssl, "DTLS max PSK length is %d\n", psk_len);

	/*manual dtls psk only for third party*/
	if (ah_capwap_para.capwap_dtls.dtls_key_type == AH_DTLS_MANUL_PSK) {
		psk_type = "manual PSK";
		rc = ah_capwap_dtls_psk_key2bn(ah_capwap_para.capwap_dtls.dtls_psk, dtls_psk,  psk_len);
		goto OUT;

	}

	psk_type = "passphrase PSK";
	/*get the psk from a aerohive cipher*/
	rc = ah_capwap_dtls_gen_psk(dtls_psk, dtls_pass);

OUT:
	ah_dbg_old(capwap_ssl, "DTLS PSK (%s) is:\n", psk_type);
	if (capwap_packet) {
		ah_hexdump((uchar *)dtls_psk, rc);
	}
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_psk_handle
 *
 * Purpose:   callback function is to select the PSK identity and the
 *                pre-shared key to use during the connection setup phase
 *
 * Inputs:    SSL *ssl, const char *hint, char *identity,uint max_identity_len,uchar *psk,uint max_psk_len
 *
 * Output:    void
 *
 * Returns:   psk length, if error then return 0
 *
 **************************************************************************/
uint ah_capwap_dtls_psk_handle(SSL *ssl, const char *hint, char *identity,
							   uint      max_identity_len, uchar *psk, uint max_psk_len)
{
	int      rc = 0;
	int      cln_hint = 0;
	char      dtls_pass[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1] = {0};
	char      footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1] = {0};

	if (identity == NULL) {
		ah_err_old("CAPWAP DTLS identity is NULL");
		goto OUT;
	}
	if (hint == NULL) {
		ah_err_old("CAPWAP DTLS PSK hint is null\n");
		goto OUT;
	} else {
		ah_dbg_old(capwap_ssl, "DTLS PSK hint is %s\n", hint);
	}

	/*find the identity in term of hint*/
	rc = ah_capwap_dtls_get_passphrase(hint, dtls_pass, max_identity_len, &cln_hint, footprint);
	/*if hint format error, use manul PSK*/
	if (rc == -1 && ah_capwap_para.capwap_dtls.dtls_key_type != AH_DTLS_MANUL_PSK) {
		goto OUT;
	} else if (rc != -1) {
		/*send ip addr to HM (mac+key_id+footprint+ip_address+sn)*/
		ah_dcd_get_mac_byname(AH_CAPWAP_MGT, (char *)ah_capwap_info.wtpmac);
		ah_hw_get_board_serial_number(ah_capwap_info.wtpsn, AH_CAPWAP_WTP_SN_LEN);
		ah_sprintf(identity, "%02x%02x%02x%02x%02x%02x%02x%s %i %s",
				   ah_capwap_info.wtpmac[0], ah_capwap_info.wtpmac[1], ah_capwap_info.wtpmac[2],
				   ah_capwap_info.wtpmac[3], ah_capwap_info.wtpmac[4], ah_capwap_info.wtpmac[5],
				   cln_hint, footprint, ah_capwap_info.wtpip, ah_capwap_info.wtpsn);
		ah_dbg_old(capwap_ssl, "DTLS Identity:%s\n", identity);
	}

	/*generate the PSK*/
	rc = ah_capwap_dtls_get_psk(dtls_pass, psk, max_psk_len);

OUT:
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_read
 *
 * Purpose:   if connect success, then read the ssl encrypt packet from OpenSSL lib
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_dtls_read()
{
	/*
	   receive the encrypt packet from SSL, in there, will decrypt the packet
	 */
	int      rc = 0;
	int      err_code;
	uint      max_socket = 0;
	char      dtls_buff[AH_CAPWAP_BUF_LEN];
	fd_set fdR;
	struct timeval capwapsel = {0, 5000};

	max_socket = ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE] + 1;
	while (ah_capwap_para.enable == AH_CAPWAP_ENABLE  /*only for check no capwap client enable*/
		   && ah_capwap_info.state != AH_CAPWAP_DISCOVERY/*only for check timeout to reconnect*/
		   && ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE  /*only for check no capwap client dtls enable*/
		   && ah_capwap_dtls_get_conn_status() == AH_DTLS_CONN /*only for receive alert to abort*/) {
		/*the timer only for check the CAPWAP status change*/
		capwapsel.tv_sec = 1;
		FD_ZERO(&fdR);
		FD_SET(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE], &fdR);
		switch (select(max_socket, &fdR, NULL, NULL, &capwapsel)) {
		case -1:
			if (errno == EINTR) {
				ah_dbg_old(capwap_info, "DTLS select have an interrupt signal!\n");
				continue;
			}
			ah_dbg_old(capwap_info, "CAPWAP DTLS select error!(reason:%s)!\n", strerror(errno));
			continue;
		case 0:
			/*select time out*/
			continue;
		default:
			/*capwap client and capwap server socket*/
			if (FD_ISSET(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE], &fdR)) {
				AH_CAPWAP_SET_DTLS_READ_STATUS;
				rc = SSL_read(ah_capwap_para.capwap_dtls.SslConnectionPtr, dtls_buff, AH_CAPWAP_BUF_LEN);
				AH_CAPWAP_CLR_DTLS_READ_STATUS;
				err_code = SSL_get_error(ah_capwap_para.capwap_dtls.SslConnectionPtr, rc);
				switch (err_code) {
				case SSL_ERROR_NONE:
					if (capwap_packet) {
						ah_dbg_old(capwap_packet, "ssl read clear packet length:%d\n", rc);
						ah_hexdump((uchar *)dtls_buff, rc);
					}
					/*handle the clear packet*/
					ah_capwap_analysepacket(dtls_buff, rc);
					ah_capwap_interrupt_listen();
					/*
					  because after decrypt the packet, the main thread hung in select, it need 10ms to recovery,
					  if box is busy at all time, it will difficult to get CPU to kick watch dog flag to PM in 50ms,
					  so send a signal to interrupt select after analyse decrypt packet
					 */
					if (pthread_kill(capwap_main_tid, SIGUSR1) != 0) {
						ah_log_old(AH_LOG_ERR, "CAPWAP send signal failed! error:%s", strerror(errno));
					}
					continue;
				case SSL_ERROR_ZERO_RETURN:
					ah_dbg_old(capwap_ssl, "SSL read return packet length is 0\n");
					continue;
				case SSL_ERROR_SYSCALL:
					ah_dbg_old(capwap_ssl, "SSL read interrupt by syscall");
					continue;
				default:
					/*Resource temporarily unavailable
					  This error is returned from operations on nonblocking sockets that cannot be completed immediately,
					  for example recv when no data is queued to be read from the socket. It is a nonfatal error, and the
					  operation should be retried later.  the timer for timed out is longger, so i need select to shortter the timer */
					//ah_err_old("SSL read problem,error code:%d",err_code);
					continue;
				}
			}
		}
	}

	return ;
}

/***************************************************************************
 *
 * Function:   capwapDtlsInfoCallbackFn
 *
 * Purpose:    dtls session debug
 *
 * Inputs:     BundleId - the bundle id
 *
 * Output:     Adds dtls session context; if client, starts dtls handshake
 *
 * Returns:    0 if everything okay
 *
 **************************************************************************/
void ah_capwap_dtls_info_handle(const SSL *SslPtr, int State, int rc)
{
	const char *StrPtr;
	const char *StatePtr;
	int      MaskedState = State & ~SSL_ST_MASK;

	ah_dbg_old(capwap_ssl, "DTLS info handle:action:%d, state:%d, rc:%d\n", State, SslPtr->state, rc);
	if (MaskedState & SSL_ST_ACCEPT) {
		StrPtr = "DTLS accept";
	} else if (MaskedState & SSL_ST_CONNECT) {
		StrPtr = "DTLS connect";
	} else {
		StrPtr = "(role unknown)";
	}

	if ((StatePtr = SSL_state_string_long(SslPtr)) == NULL) {
		StatePtr = "unknown state";
	}

	if (State & SSL_CB_LOOP) {
		ah_dbg_old(capwap_ssl, "DTLS info:%s:%s\n", StrPtr, SSL_state_string_long(SslPtr));
	} else if (State & SSL_CB_ALERT) {
		if (State & SSL_CB_READ) {
			StrPtr = "read";
		} else {
			StrPtr = "write";
		}
		ah_dbg_old(capwap_ssl, "DTLS ALERT: (%s) %s:%s\n", StrPtr, SSL_alert_type_string_long(rc), SSL_alert_desc_string_long(rc));
	} else if ((State & SSL_CB_HANDSHAKE_START) || (State & SSL_CB_HANDSHAKE_DONE)) {
		ah_dbg_old(capwap_ssl, "DTLS info:%s/%s(%d)\n", StrPtr, StatePtr, State);
	} else if (State & SSL_CB_EXIT) {
		if (rc < 0) {
			ah_dbg_old(capwap_ssl, "CAPWAP DTLS error; %s:%s\n", StrPtr, StatePtr);
		} else if (rc == 0) {
			ah_dbg_old(capwap_ssl, "receive/send timeout %s:%s\n", StrPtr, StatePtr);
		} else {
			ah_dbg_old(capwap_ssl, "no clue on good/bad; %s:%s\n", StrPtr, StatePtr);
		}
	} else {
		ah_dbg_old(capwap_ssl, "DTLS info:%s:%s\n", StrPtr, StatePtr);
	}

	return;
}

/***************************************************************************
 *
 * Function:  capwapDtlsMsgCallbackFn
 *
 * Purpose:   dtls session debug
 *
 * Inputs:    void
 *
 * Output:    debug information
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_dtls_msg_handle(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl,
							   void      *arg)
{
	const char *str_write_p, *str_version, *str_content_type = "", *str_details1 = "", *str_details2 = "";
	boolean save_log = FALSE;
	str_write_p = write_p ? "[outgoing] " : "[incoming] ";

	switch (version) {
	case SSL2_VERSION:
		str_version = "SSL 2.0";
		break;
	case SSL3_VERSION:
		str_version = "SSL 3.0 ";
		break;
	case TLS1_VERSION:
		str_version = "TLS 1.0 ";
		break;
	case DTLS1_VERSION:
		str_version = "DTLS 1.0 ";
		break;
	default:
		str_version = "??? ";
		ah_log_old(AH_LOG_INFO, "SSL:unknown version (%d)\n", version);
		break;
	}

	if (version == SSL3_VERSION || version == TLS1_VERSION || version == DTLS1_VERSION) {
		switch (content_type) {
		case 20:
			str_content_type = "ChangeCipherSpec";
			break;
		case 21:
			str_content_type = "Alert";
			break;
		case 22:
			str_content_type = "Handshake";
			break;
		}

		if (content_type == 21) { /* Alert */
			str_details1 = ", ???";

			if (len == 2) {
				switch (((const unsigned char *)buf)[0]) {
				case 1:
					str_details1 = ", warning";
					break;
				case 2:
					str_details1 = ", fatal";
					break;
				}

				str_details2 = " ???";
				switch (((const unsigned char *)buf)[1]) {
				case 0:
					str_details2 = " close_notify";
					break;
				case 10:
					str_details2 = " unexpected_message";
					break;
				case 20:
					str_details2 = " bad_record_mac";
					break;
				case 21:
					str_details2 = " decryption_failed";
					break;
				case 22:
					str_details2 = " record_overflow";
					break;
				case 30:
					str_details2 = " decompression_failure";
					break;
				case 40:
					str_details2 = " handshake_failure";
					save_log = TRUE;
					break;
				case 42:
					str_details2 = " bad_certificate";
					break;
				case 43:
					str_details2 = " unsupported_certificate";
					break;
				case 44:
					str_details2 = " certificate_revoked";
					break;
				case 45:
					str_details2 = " certificate_expired";
					break;
				case 46:
					str_details2 = " certificate_unknown";
					break;
				case 47:
					str_details2 = " illegal_parameter";
					break;
				case 48:
					str_details2 = " unknown_ca";
					break;
				case 49:
					str_details2 = " access_denied";
					break;
				case 50:
					str_details2 = " decode_error";
					break;
				case 51:
					str_details2 = " decrypt_error";
					break;
				case 60:
					str_details2 = " export_restriction";
					break;
				case 70:
					str_details2 = " protocol_version";
					break;
				case 71:
					str_details2 = " insufficient_security";
					break;
				case 80:
					str_details2 = " internal_error";
					break;
				case 90:
					str_details2 = " user_canceled";
					break;
				case 100:
					str_details2 = " no_renegotiation";
					break;
				}
			}
		}

		if (content_type == 22) { /* Handshake */
			str_details1 = "???";

			if (len > 0) {
				switch (((const unsigned char *)buf)[0]) {
				case 0:
					str_details1 = ", HelloRequest";
					break;
				case 1:
					str_details1 = ", ClientHello";
					break;
				case 2:
					str_details1 = ", ServerHello";
					break;
				case 11:
					str_details1 = ", Certificate";
					break;
				case 12:
					str_details1 = ", ServerKeyExchange";
					break;
				case 13:
					str_details1 = ", CertificateRequest";
					break;
				case 14:
					str_details1 = ", ServerHelloDone";
					break;
				case 15:
					str_details1 = ", CertificateVerify";
					break;
				case 16:
					str_details1 = ", ClientKeyExchange";
					break;
				case 20:
					str_details1 = ", Finished";
					break;
				}
			}
		}
	}

	ah_dbg_old(capwap_ssl, "DTLS msg:%s %s%s [length %d] %s%s\n", str_write_p, str_version, str_content_type, (unsigned long)len, str_details1,
			   str_details2);
	if (save_log) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: DTLS handshake failed, Please confirm the DTLS passphrase!");
	}
	if (len > 0 && capwap_packet) {
		ah_hexdump(buf, len);
	}

	return;

}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_pkt_hdr
 *
 * Purpose:   add capwap dtls packet header
 *
 * Inputs:    buf: old buf (no capwap dtls header)
 *        buf_len : old buf len
 *            out_pkt: new buf (include capwap dtls header)
 *            out_len:  new buf len
 *
 * Output:    the new buffer add capwap dtls header and new buff len
 *
 * Returns:   0 is success. otherwise is fialed
 *
 **************************************************************************/
int ah_capwap_dtls_pkt_hdr(char *buf, uint32_t buf_len, char *out_pkt, uint32_t *out_len)
{
	/*
	   <Preamble>
	   0 1 2 3 4 5 6 7
	   +-+-+-+-+-+-+
	   |Version| Type  |
	   +-+-+-+-+-+-+

	   <CAPWAP DTLS header>
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	   | Preamble    |                    Reserved                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	 */
	int32_t    dtls_hdr = 0;
	int32_t    version = AH_CAPWAP_VERSION;
	int32_t    type = AH_CAPWAP_DTLS_HDR;

	/*add cawpap dtls header*/
	version = version << AH_CAPWAP_DTLS_VER_OFFSET;
	type = type << AH_CAPWAP_DTLS_TYPE_OFFSET;

	dtls_hdr = dtls_hdr | version | type;

	/*generate a new capwap dtls packet*/
	*(uint32_t *)out_pkt = htonl(dtls_hdr);
	memcpy(out_pkt + sizeof(uint32_t), buf, buf_len);

	/*redirect the new buffer and packet length*/
	*out_len = buf_len + sizeof(uint32_t);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_snd_pkt
 *
 * Purpose:   send out the capwap dtls packet include dtls handshake packets
 *
 * Inputs:    pkt_buff: dtls packet
 *            pkt_len : packet length  (bytes)
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_dtls_snd_pkt(char *pkt_buff, uint32_t pkt_len)
{
#define AH_CAPWAP_HOST_IP_LEN 20
	uint32_t    dtls_len = 0;
	char      dtls_pkt[AH_CAPWAP_BUF_LEN];
	char      hostip[AH_CAPWAP_HOST_IP_LEN];

	/*Add CAPWAP DTLS hdr*/
	ah_capwap_dtls_pkt_hdr(pkt_buff, pkt_len, dtls_pkt, &dtls_len);
	if (dtls_len == 0) {
		ah_err_old("CAPWAP add DTLS packet header error!(packet_len:%d)", dtls_len);
		return -1;
	}

	ah_sprintf(hostip, "%i", htonl(ah_capwap_info.wtpip));
	ah_dbg_old(capwap_ssl, "send DTLS packet!packlen:%d/dst_ip:%s/src_ip:%s/udp_port:%d\n", pkt_len,
			   inet_ntoa(ah_capwap_para.capwapaddr.sin_addr), hostip, ntohs(ah_capwap_para.capwapaddr.sin_port));
	/*send encrypt packet*/
	if (ah_capwap_client_send(dtls_pkt, dtls_len) == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP send packet error!packlen:%d/dst_ip:%s/src_ip:%s/udp_port:%d, reason:%s\n", pkt_len,
				   inet_ntoa(ah_capwap_para.capwapaddr.sin_addr), hostip, ntohs(ah_capwap_para.capwapaddr.sin_port), strerror(errno));
	}
	ah_dbg_old(capwap_ssl, "Send SSL packet length:%d\n", dtls_len);
	if (capwap_packet) {
		ah_hexdump((uchar *)dtls_pkt, dtls_len);
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_conn_timeout
 *
 * Purpose:   set dtls connect timeout value
 *
 * Inputs:    rcv_timeout:  receive timeout
 *            snd_timeout:  send timeout
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_dtls_set_conn_timeout(struct timeval *rcv_tmot, struct timeval  *snd_tmot)
{
	/*set ssl_connect receive timeout*/
	BIO_ctrl(ah_capwap_para.capwap_dtls.SslBioPtr, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, rcv_tmot);
	/*set ssl_connect send timeout*/
	BIO_ctrl(ah_capwap_para.capwap_dtls.SslBioPtr, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, snd_tmot);

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_para
 *
 * Purpose:   configurate all dtls parameters
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_dtls_set_para()
{
#define AH_CAPWAP_DTLS_RCV_TIMEOUT 25
#define AH_CAPWAP_DTLS_SND_TIMEOUT 25
	int        rc;
	int        SockAddrSize;
	struct timeval rcv_time = {AH_CAPWAP_DTLS_RCV_TIMEOUT, 0};
	struct timeval snd_time = {AH_CAPWAP_DTLS_SND_TIMEOUT, 0};
	struct sockaddr SockAddr;

	if ((ah_capwap_para.capwap_dtls.SslCtxPtr = SSL_CTX_new(DTLSv1_client_method())) == NULL) {
		ah_err_old("CAPWAP ssl context allocation failed\n");
		return -1;
	}

	/*dtls needs read ahead to avoid data loss*/
	/*
	 * Tell SSL to read always read as much into its buffer as possible to
	 * avoid unnecessary system calls.
	 */
	SSL_CTX_set_read_ahead(ah_capwap_para.capwap_dtls.SslCtxPtr, 1);

	/* we'll do MTU query within capwap, so tell dtls nevermind.*/
	SSL_CTX_set_options(ah_capwap_para.capwap_dtls.SslCtxPtr, SSL_OP_NO_QUERY_MTU);

	if (SSL_CTX_set_cipher_list(ah_capwap_para.capwap_dtls.SslCtxPtr, "AES+PSK") == 0) {
		ah_err_old("CAPWAP set cipher error: (reason:%s)\n", ERR_reason_error_string(ERR_get_error()));
		rc = -1;
		goto ERROR;
	}

	/*allocate a connection for this context*/
	if ((ah_capwap_para.capwap_dtls.SslConnectionPtr = SSL_new(ah_capwap_para.capwap_dtls.SslCtxPtr)) == NULL) {
		ah_err_old("CAPWAP ssl connection allocation failed!\n");
		rc = -1;
		goto ERROR;
	}

	/*dtls needs read ahead to avoid data loss*/
	SSL_set_read_ahead(ah_capwap_para.capwap_dtls.SslConnectionPtr, 1);

	/*set debug callbacks...*/
	SSL_set_info_callback(ah_capwap_para.capwap_dtls.SslConnectionPtr, ah_capwap_dtls_info_handle);
	SSL_set_msg_callback(ah_capwap_para.capwap_dtls.SslConnectionPtr, ah_capwap_dtls_msg_handle);

	// get a unix socketpair
	errno = 0;
	rc = socketpair(AF_LOCAL, SOCK_DGRAM, 0, ah_capwap_para.capwap_dtls.SocketPair);
	if (rc != 0) {
		ah_err_old("CAPWAP DTLS set socketpair failed (rc:%d reason:%s)", rc, strerror(errno));
		goto ERROR;
	}

	SSL_set_psk_client_callback(ah_capwap_para.capwap_dtls.SslConnectionPtr, ah_capwap_dtls_psk_handle);
	SSL_CTX_set_psk_client_callback(ah_capwap_para.capwap_dtls.SslCtxPtr, ah_capwap_dtls_psk_handle);

	SockAddrSize = sizeof(SockAddr);
	if ((rc = getsockname(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], &SockAddr, (void *)&SockAddrSize)) < 0) {
		ah_err_old("CAPWAP getsockname failed (reason: %s)\n", strerror(errno));
		goto ERROR;
	}

	ah_capwap_para.capwap_dtls.SslBioPtr = BIO_new_dgram(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE],
										   BIO_NOCLOSE);
	if (ah_capwap_para.capwap_dtls.SslBioPtr == NULL) {
		ah_err_old("CAPWAP BIO_new_dgram() failed!\n");
		rc = -1;
		goto ERROR;
	}

	(void) BIO_ctrl_set_connected(ah_capwap_para.capwap_dtls.SslBioPtr, 1, &SockAddr);

	/*set SSL timeout, in ssl_read, we use select to time out*/
	ah_capwap_dtls_set_conn_timeout(&rcv_time, &snd_time);

	SSL_set_options(ah_capwap_para.capwap_dtls.SslConnectionPtr, SSL_OP_NO_QUERY_MTU);

#define AH_CAPWAP_DTLS_DFT_MTU 1480
	SSL_set_mtu(ah_capwap_para.capwap_dtls.SslConnectionPtr, AH_CAPWAP_DTLS_DFT_MTU);

	/* tell ssl to read/write same bio...*/
	SSL_set_bio(ah_capwap_para.capwap_dtls.SslConnectionPtr, ah_capwap_para.capwap_dtls.SslBioPtr, ah_capwap_para.capwap_dtls.SslBioPtr);

	/* tell ssl we are the client*/
	SSL_set_connect_state(ah_capwap_para.capwap_dtls.SslConnectionPtr);

	return 0;

ERROR:
	if (ah_capwap_para.capwap_dtls.SslCtxPtr != NULL) {
		(void) SSL_CTX_free(ah_capwap_para.capwap_dtls.SslCtxPtr);
	}

	if (ah_capwap_para.capwap_dtls.SslBioPtr != NULL) {
		(void) BIO_free(ah_capwap_para.capwap_dtls.SslBioPtr);
	}

	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_set_timeout
 *
 * Purpose:   set timeout and none block for capwap socket to avoid dead loop
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   NULL
 *
 **************************************************************************/
void ah_capwap_dtls_set_timeout()
{
	int      nflag = 0;
	struct timeval rcv_time = {0, 100000};
	struct timeval snd_time = {0, 100000};

	nflag = fcntl(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], F_GETFL, 0);
	nflag = nflag | O_NONBLOCK;
	if (fcntl(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], F_SETFL, nflag) < 0) {
		ah_err_old("%s: fcntl set O_NONBLOCK for read fail.", __func__);
	}

	nflag = fcntl(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE], F_GETFL, 0);
	nflag = nflag | O_NONBLOCK;
	if (fcntl(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_WRITE], F_SETFL, nflag) < 0) {
		ah_err_old("%s: fcntl set O_NONBLOCK for write fail.", __func__);
	}

	ah_capwap_dtls_set_conn_timeout(&rcv_time, &snd_time);
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_thread
 *
 * Purpose:   the main thread for dtls
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   NULL
 *
 **************************************************************************/
void *ah_capwap_dtls_thread()
{
	/*
	        Perform DTLS handshake
	        if success, change the capwap client state to AH_CAPWAP_JOIN. interrupt the capwap select
	        and in loop to read the encrypt packet.
	        ohterwise, change the capwap client state to AH_CAPWAP_DTLS_TDWN
	 */
	int      rc = 0;

	/*init the DTLS, because capwap init will do if capwap status change from start. dtls init only do once*/
	ah_dbg_old(capwap_ssl, "Init DTLS\n");
	ah_capwap_dtls_init();

	while (1) {
		if (ah_capwap_para.enable == AH_CAPWAP_ENABLE
			&& ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
			if (ah_capwap_info.state == AH_CAPWAP_DTLS_SETUP
				&& ah_capwap_dtls_get_conn_status() == AH_DTLS_SETUP) {
				/*1.do some parameter for ssl client*/
				ah_dbg_old(capwap_ssl, "Ready set DTLS parameters");
				rc = ah_capwap_dtls_set_para();
				if (rc != 0) {
					ah_err_old("CAPWAP Set DTLS enviorment parameter error!(rc:%d)", rc);
					return NULL;
				}

				/*2. connect to ssl server*/
				/*SSL_connect is a blocking call with the SSL BIO timeout set up in ah_capwap_dtls_set_para.*/
				ah_dbg_old(capwap_ssl, "Ready to do DTLS  connection");
				ah_log_old(AH_LOG_INFO, "CAPWAP:Ready to do DTLS  connection");
				rc = SSL_connect(ah_capwap_para.capwap_dtls.SslConnectionPtr);
				if (rc <= 0) {
					ah_dbg_old(capwap_ssl, "Handshake error: %s\n", ERR_reason_error_string(ERR_get_error()));
					ah_capwap_dtls_conn_abort();
					ah_capwap_dtls_clean();
					ah_capwap_dtls_set_conn_status(AH_DTLS_TOWN);
					continue;
				}
				ah_capwap_dtls_set_conn_status(AH_DTLS_CONN);
				ah_dbg_old(capwap_ssl, "Handshake with SSL server successfully!\n");
				ah_log_old(AH_LOG_INFO, "CAPWAP:Handshake with SSL server successfully!\n");

				/*3. chang state to AH_CAPWAP_JOIN and interrupt the capwap select*/
				ah_capwap_chgfsm_parmeter();
				/*capwap select hung in watting for dtls handshake successfully*/
				ah_capwap_interrupt_listen();
				/*set it avoid dead loop in read, see bug #8428*/
				ah_capwap_dtls_set_timeout();
				/*4. do a dead loop for read from SSL server*/
				ah_capwap_dtls_read();
				ah_dbg_old(capwap_ssl, "Exit current DTLS connect!\n");
				ah_log_old(AH_LOG_INFO, "CAPWAP:Exit current DTLS connect!\n");
				/*5.ready clean dtls*/
				ah_capwap_dtls_conn_abort();
				ah_capwap_dtls_clean();
			} else {
				/*waitting for next dtls connect
				  waitting for capwap in DLTS SETUP status*/
				sleep(1);
				ah_dbg_old(capwap_ssl, "do nothing because capwap status is %d, dtls connect status is %d",
						   ah_capwap_info.state, ah_capwap_dtls_get_conn_status());
			}
		} else {
			/*only waitting for do DTLS CLI enable CAPWAP DTLS ENABLE*/
			sleep(1);
			ah_dbg_old(capwap_ssl, "do nothing because capwap enable is %d, dtls enable is %d",
					   ah_capwap_para.enable, ah_capwap_dtls_get_enable_status());
		}
	}

	return NULL;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_conn_state_str
 *
 * Purpose:   convert int to dtls connect status string
 *
 * Inputs:    dtls status
 *
 * Output:    void
 *
 * Returns:   dtls connect status string
 *
 **************************************************************************/
const char *ah_capwap_dtls_conn_state_str(ah_capwap_dtls_status_t dtls_status)
{
	const static char *ah_capwap_dtls_state_str[] = {"NULL", "Connecting", "Authorize", "Connected", "Disconnect"};

	return ah_capwap_dtls_state_str[dtls_status];
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_conn_abort
 *
 * Purpose:   abort dtls connect
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 success, ohterwise -1
 *
 **************************************************************************/
int ah_capwap_dtls_conn_abort()
{
	int      rc = 0;

	if (ah_capwap_para.capwap_dtls.SslConnectionPtr == NULL) {
		return 0;
	}
	ah_dbg_old(capwap_ssl, "DTLS connect abort\n");

	rc = SSL_shutdown(ah_capwap_para.capwap_dtls.SslConnectionPtr);
	if (rc < 0) {
		ah_err_old("CAPWAP DTLS connect abort error!(reason:%s)", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	SSL_set_connect_state(ah_capwap_para.capwap_dtls.SslConnectionPtr);
	rc = SSL_get_fd(ah_capwap_para.capwap_dtls.SslConnectionPtr);
	if (rc >= 0) {
		close(rc);
		ah_capwap_dtls_set_conn_status(AH_DTLS_TOWN);
		rc = 0;
	}

	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_encrypt
 *
 * Purpose:   encrypt the capwap packet using dtls
 *
 * Inputs:    pkt_buf:  in packet
 *            pkt_len:  packet len
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1;
 *
 **************************************************************************/
int ah_capwap_dtls_encrypt(char *pkt_buf, uint32_t pkt_len)
{
	int      rc = 0;
	/*
	   Send cleared packet to dtls thread for encryption.
	 */
	rc = SSL_write(ah_capwap_para.capwap_dtls.SslConnectionPtr, pkt_buf, pkt_len);

	if (rc < 0) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: send dtls packet to SSL error!(reason:%s, packet len:%d, rc:%d)",
				   ERR_reason_error_string(ERR_get_error()), pkt_len, rc);
		return -1;
	}

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_dtls_decrypt
 *
 * Purpose:   send the dtls packet to SSL decrypt
 *
 * Inputs:    pkt_buf:  in packet
 *            pkt_len:  packet len
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1;
 *
 **************************************************************************/
int ah_capwap_dtls_decrypt(char *pkt_buf, uint32_t pkt_len)
{
	int      rc = 0;
	/*
	   Send encrypted packet to dtls thread for decryption.
	 */
	rc = write(ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], pkt_buf, pkt_len);

	if (rc < 0) {
		ah_log_old(AH_LOG_INFO, "CAPWAP send dtls packet to SSL error!(rc:%d, reason:%s, fd:%d, packet len:%d)",
				   rc, strerror(errno), ah_capwap_para.capwap_dtls.SocketPair[AH_CAPWAP_DTLS_SOCKET_READ], pkt_len);
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_dtls_pkt_type
 *
 * Purpose:   check the in packet is DTLS packet or not
 *
 * Inputs:    pkt_buf:  in packet
 *            pkt_len:  packet len
 *
 * Output:    void
 *
 * Returns:   AH_CAPWAP_DTLS_PKT: is a dtls packet
 *            AH_CAPWAP_CLEAR_PKT: is a clear packet
 *            AH_CAPWAP_ERROR_PKT: is a error packet
 *
 **************************************************************************/
int ah_capwap_dtls_pkt_type(char *pkt_buf, uint32_t pkt_len)
{
#define AH_CAPWAP_PREAMBLE_LEN 4
	int32_t    capwap_dtls;

	if (capwap_packet) {
		ah_dbg_old(capwap_packet, "CAPWAP packet preamble:\n");
		ah_hexdump((uchar *)pkt_buf, AH_CAPWAP_PREAMBLE_LEN);
	}
	/*get capwap dtls header*/
	capwap_dtls = ntohl(*(int32_t *)(pkt_buf));

	/*get capwap preamble*/
	capwap_dtls = capwap_dtls >> AH_CAPWAP_DTLS_TYPE_OFFSET;

	/*get type value*/
	capwap_dtls = 0x0f & capwap_dtls;

	if (capwap_dtls == AH_CAPWAP_DTLS_HDR) {
		if (ah_capwap_para.capwap_dtls.dtls_enable == AH_CAPWAP_DTLS_ENABLE) {
			ah_dbg_old(capwap_ssl, "Is a DTLS packet\n");
			/*need write to SSL decrypt packet*/
			ah_capwap_dtls_decrypt((pkt_buf + AH_CAPWAP_PREAMBLE_LEN), (pkt_len - AH_CAPWAP_PREAMBLE_LEN));
			return AH_CAPWAP_DTLS_PKT;
		}
		ah_dbg_old(capwap_ssl, "Is a error packet (packet type is DTLS packet ,but CAPWAP DTLS is disabled)\n");
		return AH_CAPWAP_ERROR_PKT;
	}

	/*CAPWAP discovery packet is always a clear packet*/
	if (ah_capwap_para.capwap_dtls.dtls_enable == AH_CAPWAP_DTLS_ENABLE &&
		ah_capwap_info.state != AH_CAPWAP_DISCOVERY) {
		ah_dbg_old(capwap_ssl, "Is an error packet (packet type is CLEAR packet ,but CAPWAP DTLS is enabled)\n");
		return AH_CAPWAP_ERROR_PKT;
	}

	ah_dbg_old(capwap_ssl, "Is a CLEAR packet\n");
	return AH_CAPWAP_CLEAR_PKT;
}

