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
#ifndef AH_CLI_CAPWAP_PING_TYPES_H
#define AH_CLI_CAPWAP_PING_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define AH_MAX_STR_64_LEN 64
#define AH_MAX_STR_PARM_LEN 32
#define __packed __attribute__((__packed__))

/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  ver  | type  |  HLEN   |   RID   | WBID   |T|F|L|W|M|K|Flags |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Fragment ID          |     Frag Offset         |Rsvd |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Message Type                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Seq Num    |        Msg Element Length     |     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Time Stamp                             +
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         TLV TYPE                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          TLV LEN              |            Payload ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
   */

typedef struct {
	union {
		uint32_t    header1;
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint32_t    version: 4;
			uint32_t    type: 4;
			uint32_t    hlen: 5;
			uint32_t    rid: 5;
			uint32_t    wbid: 5;
			uint32_t    t: 1;
			uint32_t    f: 1;
			uint32_t    l: 1;
			uint32_t    w: 1;
			uint32_t    m: 1;
			uint32_t    k: 1;
			uint32_t    flags: 3;
#else
			uint32_t    flags: 3;
			uint32_t    k: 1;
			uint32_t    m: 1;
			uint32_t    w: 1;
			uint32_t    l: 1;
			uint32_t    f: 1;
			uint32_t    t: 1;
			uint32_t    wbid: 5;
			uint32_t    rid: 5;
			uint32_t    hlen: 5;
			uint32_t    type: 4;
			uint32_t    version: 4;
#endif
		} header1_field;
	};
	union {
		uint32_t    header2;
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint32_t    frag_id: 16;
			uint32_t    frag_offset: 13;
			uint32_t    reserved: 3;
#else
			uint32_t    reserved: 3;
			uint32_t    frag_offset: 13;
			uint32_t    frag_id: 16;
#endif
		} header2_field;
	};
	uint32_t    msg_type;
	uint8_t    seq_num;
	uint16_t    msg_len;
	uint8_t    flags;
	uint32_t    timestamp;
	uint32_t    tlv_type;
	uint16_t    tlv_len;
} __packed ah_capwap_ping_header_t;

typedef struct {
	char      dst_name[AH_MAX_STR_64_LEN + 1];
	char      dst_ip[AH_MAX_STR_PARM_LEN + 1];
	uint32_t    dst_port;
	uint32_t    count;
	uint32_t    size;
	uint32_t    timeout;
} ah_capwap_ping_para_t;

typedef enum {
	AH_CAPWAP_PING_TIME_SEC = 0,
	AH_CAPWAP_PING_TIME_USEC,
	AH_CAPWAP_PING_TIME_MAX,
} ah_capwap_ping_time_array_index_t;

typedef struct {
	long      start_time[AH_CAPWAP_PING_TIME_MAX];
	long      end_time[AH_CAPWAP_PING_TIME_MAX];
	uint64_t    rtt_min;
	uint64_t    rtt_max;
	uint64_t    rtt_total;
	uint      snd_pkt;
	uint      rcv_pkt;
} ah_capwap_ping_info_t;

typedef enum {
	AH_CAPWAP_PING_MODE_NORMAL = 0,
	AH_CAPWAP_PING_MODE_BROADCAST,
	AH_CAPWAP_PING_MODE_FLOODING,
} ah_capwap_ping_mode_t;

#endif
