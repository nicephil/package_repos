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
#ifndef _AH_CAPWAP_IDP_H
#define _AH_CAPWAP_IDP_H


#define AH_HM_TYPE_IDP_MITIGATE           1
/* IDP mitigate type */
#define AH_HM_IDP_MITIGATE_UPDATE         0
#define AH_HM_IDP_MITIGATE_STOP_NOTROGUE  1
#define AH_HM_IDP_MITIGATE_STOP_QUIET     2
#define AH_HM_IDP_MITIGATE_STOP_TIMEOUT   3
#define AH_HM_IDP_MITIGATE_STOP_MANUAL    4
#define AH_HM_IDP_REPORT_STATION          5
#define AH_HM_IDP_MITIGATE_START          6
#define AH_HM_IDP_REPORT_START            7

/* station data */
#define AH_HM_IDP_SDATA_OPEN_POLOCY        1
#define AH_HM_IDP_SDATA_WEP_POLOCY         2
#define AH_HM_IDP_SDATA_WPA_POLOCY         4
#define AH_HM_IDP_SDATA_WMM_POLOCY         8
#define AH_HM_IDP_SDATA_S_PREAMBLE_POLOCY  64
#define AH_HM_IDP_SDATA_S_BEACON_POLOCY    128
#define AH_HM_IDP_SDATA_AD_HOC_POLOCY      256

/* IDP sta message format to hive manager
    0                   1                  2                    3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |      result type              |            cookie
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |      cookie                   |data length                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |                               |data¡­.
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

 */
/* idp msg to sent to hive manager (non-byte member should be in net order, don't change member order) */
typedef struct ah_capwap_idpsta_msg_s {
	ushort      msg_type;
	uint32_t    cookie;    /* cookie from HM (to identify the request), otherwise set to 0 (unsolicated message) */
	uint      data_len;
	uint8_t     data[0];
} __attribute__((__packed__)) ah_capwap_idpsta_msg_t;

/*
       Data format:
    0                   1                  2                    3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |single IDP mitigation length|         flag|     BSSID
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
                 |ssid length  |            ssid¡­
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |     ifindex   |     channel  |In network flag|Station data
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
                    |compliance                   |  number of
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
       Client       |  sta item len |             client mac
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
                                                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |  remove flag  |   discover  time                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |               |    update    time                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |               |    other clients¡­
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |                   other IDP mitigations¡­
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

*/
/* idp sta item to sent to hive manager (non-byte member should be in net order, don't change member order) */
typedef struct ah_capwap_idp_item_s {
	ushort      item_len;                   /* the whole item length*/
	uint8_t    flag;
	uint8_t    remote_id[MACADDR_LEN];
	uint8_t    if_index;                    /* ifindex */
	uint8_t    idp_channel;
	uint8_t    in_net;
	ushort      station_data;
	ushort      compliance;
	uint8_t    ssid_len;                    /* ssid length, tail '\0' not included */
	char      ssid[AH_MAX_SSID_LEN];        /* ssid, include tail '\0' */
	ushort      sta_num;
} __attribute__((__packed__)) ah_capwap_idp_item_t;

typedef struct ah_capwap_idpsta_item_s {
	uint8_t    item_len;
	uint8_t                           macaddr[MACADDR_LEN];
	uint8_t                           flag;
	uint32_t                          discover_age; /* age from first rcv */
	uint32_t                          update_age;   /* age from last rcv */
	int8_t                          rssi;
} __attribute__((__packed__)) ah_capwap_idpsta_item_t;


#endif /*_AH_CAPWAP_IDP_H */

