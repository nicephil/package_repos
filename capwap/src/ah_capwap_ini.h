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
   this file include all the global variable reference for capwap
   zhanglei
   the copyrigh is for aerohive
*/

#ifndef AH_CAPWAP_INI_H
#define AH_CAPWAP_INI_H

extern ah_capwap_wtp_owninfo_t ah_capwap_info;
extern ah_ipaddr46_t capwap_mgt0_ipv6;
extern ah_capwap_wtp_parameter_t ah_capwap_para ;

extern ah_capwap_timerinfo_t ah_capwap_timer[];
extern ah_capwap_state_client_chg_t ah_capwap_fsm[];
extern pthread_t capwap_main_tid ;

/***************************************/
/*some debug function to check OpenSSL hung*/
extern char ah_capwap_dtls_connect_failed_number;
extern char ah_capwap_dtls_read_status;
/***************************************/


#endif
