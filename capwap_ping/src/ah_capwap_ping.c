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
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>

#include "ah_capwap_ping_types.h"

typedef enum {
	AH_CAPWAP_PING_REQUEST = 300,
	AH_CAPWAP_PING_RESPONSE,
} ah_capwap_ping_type;

static ah_capwap_ping_para_t ah_capwap_ping_para;
static struct sockaddr_in ping_addr;
ah_capwap_ping_info_t ah_capwap_ping_info;
static int ah_capwap_ping_mode = AH_CAPWAP_PING_MODE_NORMAL;

#define AH_ISDIGIT(x) ((x >= '0') && (x <= '9'))

static int ah_get_system_uptime(uint *psec, uint *pmsec)
{
	int fd;
	char buf[64] = {0};
	char *p = buf;
	int sec = 0;
	uint msec = 0;

	assert(NULL != psec);

	fd = open("/proc/uptime", O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	if (read(fd, buf, sizeof(buf)) <= 0) {
		close(fd);
		return -1;
	}

	while (AH_ISDIGIT(*p)) {
		sec = 10 * sec + (*p - '0');
		++p;
	}

	if ('.' != *p) {
		close(fd);
		return -1;
	}
	++p;

	if (AH_ISDIGIT(*p)) {
		msec = 100 * (*p - '0');
		++p;
		if (AH_ISDIGIT(*p)) {
			msec += 10 * (*p - '0');
			++p;
			if (AH_ISDIGIT(*p)) {
				msec += *p - '0';
			}
		}
	}

	*psec = sec;
	if (pmsec != NULL) {
		*pmsec = msec;
	}

	close(fd);
	return 0;
}

static int ah_capwap_ping_decode(char *buff, uint8_t seq)
{
	ah_capwap_ping_header_t *ping_header = NULL;

	ping_header = (ah_capwap_ping_header_t *)(buff);
	if (ntohl(ping_header->msg_type) != AH_CAPWAP_PING_RESPONSE) {
		syslog(LOG_INFO, "CAPWAP ping: receive wrong CAPWAP ping packet message type!correct :%d, current:%d\n",
				   AH_CAPWAP_PING_RESPONSE, ping_header->msg_type);
		return -1;
	}
	if (ping_header->seq_num != seq) {
		syslog(LOG_INFO, "CAPWAP ping: receive wrong CAPWAP ping packet seqence number!correct :%d, current:%d\n",
				   seq, ping_header->seq_num);
		return -1;
	}

	return 0;
}

static int ah_capwap_ping_encode(char *buff, uint32_t payload_size, uint8_t seq_num)
{
#define AH_CAPWAP_PING_TLV_TYPE 8000
#define AH_CAPWAP_PING_VERSION 7
	uint32_t    msg_len = 0;
	uint      timestamp_sec = 0;
	uint      timestamp_usec = 0;
	ah_capwap_ping_header_t capwap_ping;

	capwap_ping.header1_field.version = AH_CAPWAP_PING_VERSION;
	capwap_ping.header1_field.type = 0;
	capwap_ping.header1_field.hlen = sizeof(capwap_ping.header1) + sizeof(capwap_ping.header2);
	capwap_ping.header1_field.rid = 2;
	capwap_ping.header1_field.wbid = 0;
	capwap_ping.header1_field.t = 0;
	capwap_ping.header1_field.f = 0;
	capwap_ping.header1_field.l = 0;
	capwap_ping.header1_field.w = 0;
	capwap_ping.header1_field.m = 0;
	capwap_ping.header1_field.k = 0;
	capwap_ping.header1_field.flags = 0;

	capwap_ping.header2_field.frag_id = 0;
	capwap_ping.header2_field.frag_offset = 0;
	capwap_ping.header2_field.reserved = 0;

	capwap_ping.msg_type = htonl(AH_CAPWAP_PING_REQUEST);
	capwap_ping.seq_num = seq_num;
	msg_len = payload_size + sizeof(capwap_ping.msg_len) + sizeof(capwap_ping.flags)
			  + sizeof(capwap_ping.tlv_type) + sizeof(capwap_ping.tlv_len) + sizeof(capwap_ping.timestamp);
	capwap_ping.msg_len = htons(msg_len);
	capwap_ping.flags = 0;
	(void)ah_get_system_uptime(&timestamp_sec, &timestamp_usec);
	capwap_ping.timestamp = htonl(timestamp_sec);
	capwap_ping.tlv_type = htonl(AH_CAPWAP_PING_TLV_TYPE);
	capwap_ping.tlv_len = htons(payload_size);

	capwap_ping.header1 = htonl(capwap_ping.header1);
	capwap_ping.header2 = htonl(capwap_ping.header2);

	memcpy(buff, &capwap_ping, sizeof(capwap_ping));

	return 0;
}

static void ah_capwap_ping_init_para(ah_capwap_ping_para_t *para)
{
#define AH_CAPWAP_PING_COUNT_DFT 5
#define AH_CAPWAP_PING_DST_PORT_DFT 12222
#define AH_CAPWAP_PING_PKT_SIZE_DFT 56
#define AH_CAPWAP_PING_TMOUT_DFT 5

	memset(para, 0x00, sizeof(ah_capwap_ping_para_t));

	para->count = AH_CAPWAP_PING_COUNT_DFT;
	para->dst_port = AH_CAPWAP_PING_DST_PORT_DFT;
	para->size = AH_CAPWAP_PING_PKT_SIZE_DFT;
	para->timeout = AH_CAPWAP_PING_TMOUT_DFT;

	return ;
}

#define AH_CAPWAP_PING_DST_IP (ah_capwap_ping_para.dst_ip)
#define AH_CAPWAP_PING_DST_NAME (ah_capwap_ping_para.dst_name)
#define AH_CAPWAP_PING_DST_PORT (ah_capwap_ping_para.dst_port)
#define AH_CAPWAP_PING_COUNT (ah_capwap_ping_para.count)
#define AH_CAPWAP_PING_SIZE (ah_capwap_ping_para.size)
#define AH_CAPWAP_PING_TMOT_VALUE (ah_capwap_ping_para.timeout)
static int ah_capwap_ping_get_dst_ip(char *dst_name, uint32_t *dst_ip)
{
	struct hostent *serhost = NULL;
	struct sockaddr_in seraddr;

	res_init();/*force to init the gethostbyname. so the system can get the dns change in resov.conf*/
	serhost = gethostbyname(dst_name);
	if (serhost == NULL) {
		printf("CAPWAP ping: unknown host %s\n", dst_name);
		return -1;
	}

	bcopy(serhost->h_addr, (char *)&seraddr.sin_addr, serhost->h_length);
	/*network order*/
	*dst_ip = seraddr.sin_addr.s_addr;
	sprintf(AH_CAPWAP_PING_DST_IP, "%i", *dst_ip);

	return 0;
}

static int ah_capwap_ping_create_socket(uint32_t port, uint32_t ip, int *ping_socket)
{
	int      n = 1;
	uint32_t    rcv_buff = 0;

	bzero(&ping_addr, sizeof(ping_addr));
	ping_addr.sin_family = AF_INET;
	ping_addr.sin_addr.s_addr = INADDR_ANY;

	/*create a socket for UDP*/
	if ((*ping_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("CAPWAP ping: Create CAPWAP ping socket failed, reason:%s\n", strerror(errno));
		syslog(LOG_ERR,"CAPWAP ping: Create CAPWAP ping socket failed, reason:%s\n", strerror(errno));
		return -1;
	}
	n = 1;
	if (setsockopt(*ping_socket, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n)) == -1) {
		printf("CAPWAP ping: setsockopt support broadcast failed, reason:%s\n", strerror(errno));
		syslog(LOG_ERR,"CAPWAP ping: setsockopt support broadcast failed, reason:%s\n", strerror(errno));
		return -1;
	}
	n = 1;
	if (setsockopt(*ping_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) == -1) {
		printf("CAPWAP ping: setsockopt reuseed failed, reason:%s\n", strerror(errno));
		syslog(LOG_ERR,"CAPWAP ping: setsockopt reuseed failed, reason:%s\n", strerror(errno));
		return -1;
	}
	if (ah_capwap_ping_mode == AH_CAPWAP_PING_MODE_FLOODING) {
		rcv_buff = 1024 * 1024;
		if (setsockopt(*ping_socket, SOL_SOCKET, SO_RCVBUF, (char *)&rcv_buff, sizeof(rcv_buff)) == -1) {
			printf("CAPWAP ping: setsockopt receive buffer failed, reason:%s\n", strerror(errno));
			syslog(LOG_ERR,"CAPWAP ping: setsockopt receive buffer failed, reason:%s\n", strerror(errno));
			return -1;
		}
		rcv_buff = 1024 * 1024;
		if (setsockopt(*ping_socket, SOL_SOCKET, SO_SNDBUF, (char *)&rcv_buff, sizeof(rcv_buff)) == -1) {
			printf("CAPWAP ping: setsockopt receive buffer failed, reason:%s\n", strerror(errno));
			syslog(LOG_ERR,"CAPWAP ping: setsockopt receive buffer failed, reason:%s\n", strerror(errno));
			return -1;
		}
	}
	if ((bind(*ping_socket, (struct sockaddr *)&ping_addr, sizeof(struct sockaddr))) == -1) {
		printf("CAPWAP ping: bind sock failed, reason:%s\n", strerror(errno));
		syslog(LOG_ERR,"CAPWAP ping: bind sock failed, reason:%s\n", strerror(errno));
		return -1;
	}

	ping_addr.sin_port = htons(port);
	ping_addr.sin_addr.s_addr = ip; /*IP is network order*/

	return 0;
}

static int ah_capwap_ping_send(int socket, char *pkt, uint32_t pkt_len)
{
	int      rc = 0;

	rc = sendto(socket, pkt, pkt_len, 0, (struct sockaddr *)&ping_addr, sizeof(ping_addr));
	if (rc == -1) {
		syslog(LOG_WARNING, "CAPWAP ping: send packet failed!reason:(%s)\n", strerror(errno));
	}

	return rc;
}

#define AH_CAPWAP_PING_RTT_MIN (ah_capwap_ping_info.rtt_min)
#define AH_CAPWAP_PING_RTT_MAX (ah_capwap_ping_info.rtt_max)
#define AH_CAPWAP_PING_RTT_TOTAL (ah_capwap_ping_info.rtt_total)
#define AH_CAPWAP_PING_FLOOD_COUNT 100
static int ah_capwap_ping_print_result(int rcv_len, ulong *snd_time, ulong *rcv_time, int32_t seq, char *peer)
{
	uint64_t    snd_usec = 0;
	uint64_t    rcv_usec = 0;
	uint64_t    rtt_usec = 0;
	uint32_t    rtt_int = 0;
	uint32_t    rtt_dec = 0;

	if (rcv_time[AH_CAPWAP_PING_TIME_SEC] == 0 && rcv_time[AH_CAPWAP_PING_TIME_USEC] == 0) {
		printf("    Request timed out.\n");
		return 0;
	}

	snd_usec = (uint64_t)snd_time[AH_CAPWAP_PING_TIME_SEC] * 1000 * 1000 + snd_time[AH_CAPWAP_PING_TIME_USEC];
	rcv_usec = (uint64_t)rcv_time[AH_CAPWAP_PING_TIME_SEC] * 1000 * 1000 + rcv_time[AH_CAPWAP_PING_TIME_USEC];

	rtt_usec = rcv_usec - snd_usec;
	rtt_int = rtt_usec / 1000;
	rtt_dec = rtt_usec % 1000;

	if (rtt_usec < AH_CAPWAP_PING_RTT_MIN || AH_CAPWAP_PING_RTT_MIN == 0) {
		AH_CAPWAP_PING_RTT_MIN = rtt_usec;
	}

	if (rtt_usec >= AH_CAPWAP_PING_RTT_MAX) {
		AH_CAPWAP_PING_RTT_MAX = rtt_usec;
	}

	AH_CAPWAP_PING_RTT_TOTAL += rtt_usec;

	if (ah_capwap_ping_mode != AH_CAPWAP_PING_MODE_FLOODING) {
		printf("    %d bytes from %s udp port %d: seq=%d time=%d.%d ms\n",
			   rcv_len, peer, AH_CAPWAP_PING_DST_PORT, seq, rtt_int, rtt_dec);
	} else {
		printf("    %d packets transmitted, %d received from %s udp port %d: seq=%d time=%d.%d ms, \n",
			   AH_CAPWAP_PING_FLOOD_COUNT, rcv_len, peer, AH_CAPWAP_PING_DST_PORT, seq, rtt_int, rtt_dec);
	}

	return 0;
}

static int ah_capwap_ping_get_time(long *sec, long *usec)
{
	struct timeval tv ;

	gettimeofday(&tv, NULL);
	*sec = tv.tv_sec;
	*usec = tv.tv_usec;

	return 0;
}

#define AH_CAPWAP_PING_SND_PKT (ah_capwap_ping_info.snd_pkt)
#define AH_CAPWAP_PING_RCV_PKT (ah_capwap_ping_info.rcv_pkt)
#define AH_CAPWAP_PING_START_TIME_SEC (ah_capwap_ping_info.start_time[AH_CAPWAP_PING_TIME_SEC])
#define AH_CAPWAP_PING_START_TIME_USEC (ah_capwap_ping_info.start_time[AH_CAPWAP_PING_TIME_USEC])
#define AH_CAPWAP_PING_END_TIME_SEC (ah_capwap_ping_info.end_time[AH_CAPWAP_PING_TIME_SEC])
#define AH_CAPWAP_PING_END_TIME_USEC (ah_capwap_ping_info.end_time[AH_CAPWAP_PING_TIME_USEC])

#define AH_CAPWAP_PING_MALLOC_LEN 1500
static int ah_capwap_ping_flood_recv(int socket, uint8_t seq, char *rcv_buff, long *rcv_sec, long *rcv_usec)
{
	fd_set fdR;
	struct timeval timeout = {AH_CAPWAP_PING_TMOT_VALUE, 0};
	int      rcv_len = 0;
	int      rcv_pkt = 0;

	*rcv_sec = 0;
	*rcv_usec = 0;
	while (1) {
		FD_ZERO(&fdR);
		FD_SET(socket, &fdR);
		switch (select(socket + 1, &fdR, NULL, NULL, &timeout)) {
		case -1:
			continue;
		case 0:
			/*select time out*/
			return rcv_pkt;
		default:
			if (FD_ISSET(socket, &fdR)) {
				if ((rcv_len = recvfrom(socket, rcv_buff, AH_CAPWAP_PING_MALLOC_LEN, 0, NULL, NULL)) <= 0) {
					syslog(LOG_INFO, "CAPWAP ping: receive CAPWAP ping packet failed!reason:%s\n", strerror(errno));
					continue;
				}
				if (ah_capwap_ping_decode(rcv_buff, seq) == -1) {
					continue;
				}
				rcv_pkt ++;
				ah_capwap_ping_get_time(rcv_sec, rcv_usec);
				if (rcv_pkt == AH_CAPWAP_PING_FLOOD_COUNT) {
					return rcv_pkt;
				}
				continue;
			}
		}
	}

	return rcv_pkt;
}

static int ah_capwap_ping_broadcast_recv(int socket, uint32_t seq, char *rcv_buff, long *snd_time)
{
	fd_set fdR;
	struct timeval timeout = {AH_CAPWAP_PING_TMOT_VALUE, 0};
	int      rcv_len = 0;
	int      rcv_pkt = 0;
	struct sockaddr_in pkt_src;
	uint      addr_len = 0;
	long      rcv_time[AH_CAPWAP_PING_TIME_MAX] = {0, 0};
	char      peer_str[AH_MAX_STR_PARM_LEN];

	addr_len = sizeof(pkt_src);
	while (1) {
		FD_ZERO(&fdR);
		FD_SET(socket, &fdR);
		switch (select(socket + 1, &fdR, NULL, NULL, &timeout)) {
		case -1:
			continue;
		case 0:
			/*select time out*/
			return rcv_pkt;
		default:
			if (FD_ISSET(socket, &fdR)) {
				if ((rcv_len = recvfrom(socket, rcv_buff, AH_CAPWAP_PING_MALLOC_LEN, 0, (struct sockaddr *)&pkt_src, &addr_len)) <= 0) {
					syslog(LOG_INFO, "CAPWAP ping: receive CAPWAP ping packet failed!reason:%s\n", strerror(errno));
					continue;
				}
				if (ah_capwap_ping_decode(rcv_buff, seq) == -1) {
					continue;
				}
				ah_capwap_ping_get_time(&rcv_time[AH_CAPWAP_PING_TIME_SEC], &rcv_time[AH_CAPWAP_PING_TIME_USEC]);
				snprintf(peer_str, AH_MAX_STR_PARM_LEN, "%i", ntohl(pkt_src.sin_addr.s_addr));
				ah_capwap_ping_print_result(rcv_len, (ulong *)snd_time, (ulong *)rcv_time, (seq + 1), peer_str);
				rcv_pkt ++;
				continue;
			}
		}
	}

	return rcv_pkt;
}

static int ah_capwap_ping_recv(int socket, uint8_t seq, char *rcv_buff)
{
	fd_set fdR;
	struct timeval timeout = {AH_CAPWAP_PING_TMOT_VALUE, 0};
	int      rcv_len = 0;

	while (1) {
		FD_ZERO(&fdR);
		FD_SET(socket, &fdR);
		switch (select(socket + 1, &fdR, NULL, NULL, &timeout)) {
		case -1:
			continue;
		case 0:
			/*select time out*/
			return -1;
		default:
			if (FD_ISSET(socket, &fdR)) {
				if ((rcv_len = recvfrom(socket, rcv_buff, AH_CAPWAP_PING_MALLOC_LEN, 0, NULL, NULL)) <= 0) {
					syslog(LOG_INFO, "CAPWAP ping: receive CAPWAP ping packet failed!reason:%s\n", strerror(errno));
					continue;
				}
				if (ah_capwap_ping_decode(rcv_buff, seq) == -1) {
					continue;
				}
				return rcv_len;
			}
		}
	}

	return 0;
}

#define AH_CAPWAP_PING_HDR_SIZE (sizeof(ah_capwap_ping_header_t))
#define AH_CAPWAP_PING_DATA_SIZE (ah_capwap_ping_para.size)
static int ah_capwap_printf_ping_header()
{
	printf("CAPWAP ping parameters: \n");
	printf("    Destination server: %s (%s)\n", AH_CAPWAP_PING_DST_NAME, AH_CAPWAP_PING_DST_IP);
	printf("    Destination port: %d\n", AH_CAPWAP_PING_DST_PORT);
	printf("    Count: %d\n", AH_CAPWAP_PING_COUNT);
	printf("    Size: %d(%d) bytes\n", AH_CAPWAP_PING_SIZE, (AH_CAPWAP_PING_DATA_SIZE + AH_CAPWAP_PING_HDR_SIZE));
	printf("    Timeout: %d seconds\n", AH_CAPWAP_PING_TMOT_VALUE);
	printf("--------------------------------------------------\n");
	printf("CAPWAP ping result: \n");

	return 0;
}

static int ah_capwap_ping_print_statistic()
{
	double lost_pkt = 0;
	uint64_t    start_time = 0;
	uint64_t    end_time = 0;
	int      rtt_int = 0;
	int      rtt_dec = 0;

	lost_pkt = ((AH_CAPWAP_PING_SND_PKT - AH_CAPWAP_PING_RCV_PKT) * 1.0 * 100) / (AH_CAPWAP_PING_SND_PKT);

	ah_capwap_ping_get_time(&AH_CAPWAP_PING_END_TIME_SEC, &AH_CAPWAP_PING_END_TIME_USEC);
	start_time = (uint64_t)AH_CAPWAP_PING_START_TIME_SEC * 1000 * 1000 + AH_CAPWAP_PING_START_TIME_USEC;
	end_time = (uint64_t)AH_CAPWAP_PING_END_TIME_SEC * 1000 * 1000 + AH_CAPWAP_PING_END_TIME_USEC;
	rtt_int = (end_time - start_time) / 1000;
	rtt_dec = (end_time - start_time) % 1000;

	printf("    ------- %s CAPWAP ping statistics -------\n", AH_CAPWAP_PING_DST_NAME);
	switch (ah_capwap_ping_mode) {
	case AH_CAPWAP_PING_MODE_BROADCAST:
		printf("    %d packets transmitted, %d received, time %d.%dms\n",
			   AH_CAPWAP_PING_SND_PKT, AH_CAPWAP_PING_RCV_PKT, rtt_int, rtt_dec);
		break;
	case AH_CAPWAP_PING_MODE_FLOODING:
	default:
		printf("    %d packets transmitted, %d received, %.02f%% packet loss, time %d.%dms\n",
			   AH_CAPWAP_PING_SND_PKT, AH_CAPWAP_PING_RCV_PKT, lost_pkt, rtt_int, rtt_dec);
		break;
	}

	if (AH_CAPWAP_PING_RCV_PKT != 0) {
		rtt_int = AH_CAPWAP_PING_RTT_MIN / 1000;
		rtt_dec = AH_CAPWAP_PING_RTT_MIN % 1000;
		printf("    rtt min/avg/max = %d.%d/", rtt_int, rtt_dec);
		if (ah_capwap_ping_mode != AH_CAPWAP_PING_MODE_FLOODING) {
			AH_CAPWAP_PING_RTT_TOTAL = AH_CAPWAP_PING_RTT_TOTAL / AH_CAPWAP_PING_RCV_PKT;
		} else {
			AH_CAPWAP_PING_RTT_TOTAL = AH_CAPWAP_PING_RTT_TOTAL / AH_CAPWAP_PING_COUNT;
		}
		rtt_int = AH_CAPWAP_PING_RTT_TOTAL / 1000;
		rtt_dec = AH_CAPWAP_PING_RTT_TOTAL % 1000;
		printf("%d.%d/", rtt_int, rtt_dec);

		rtt_int = AH_CAPWAP_PING_RTT_MAX / 1000;
		rtt_dec = AH_CAPWAP_PING_RTT_MAX % 1000;
		printf("%d.%d ms\n", rtt_int, rtt_dec);
	}
	return 0;
}

static int ah_capwap_ping_flood_main_loop(int ping_socket)
{
	char      *ping_pkt = NULL;
	int      rc = -1;
	int      pkt_size = AH_CAPWAP_PING_HDR_SIZE + AH_CAPWAP_PING_DATA_SIZE;
	uint32_t    seq = 0;
	long      snd_time[AH_CAPWAP_PING_TIME_MAX] = {0, 0};
	long      rcv_time[AH_CAPWAP_PING_TIME_MAX] = {0, 0};
	int      rcv_pkt = 0;
	int      flood_count = 0;

	ping_pkt = malloc(AH_CAPWAP_PING_MALLOC_LEN);
	if (ping_pkt == NULL) {
		printf("CAPWAP ping: malloc buffer for CAPWAP ping failed. malloc len:%d\n", AH_CAPWAP_PING_MALLOC_LEN);
		syslog(LOG_ERR,"CAPWAP ping: malloc buffer for CAPWAP ping failed. malloc len:%d\n", AH_CAPWAP_PING_MALLOC_LEN);
		goto OUT;
	}
	do {
		for (flood_count = 0; flood_count < AH_CAPWAP_PING_FLOOD_COUNT; flood_count ++) {
			ah_capwap_ping_encode(ping_pkt, AH_CAPWAP_PING_DATA_SIZE, seq);
			ah_capwap_ping_send(ping_socket, ping_pkt, pkt_size);
			if (flood_count == 20) {
				usleep(100);
			}
		}
		AH_CAPWAP_PING_SND_PKT += AH_CAPWAP_PING_FLOOD_COUNT;
		ah_capwap_ping_get_time(&snd_time[AH_CAPWAP_PING_TIME_SEC], &snd_time[AH_CAPWAP_PING_TIME_USEC]);
		rcv_pkt = ah_capwap_ping_flood_recv(ping_socket, seq, ping_pkt, &rcv_time[AH_CAPWAP_PING_TIME_SEC], &rcv_time[AH_CAPWAP_PING_TIME_USEC]);
		AH_CAPWAP_PING_RCV_PKT += rcv_pkt;
		seq ++;
		ah_capwap_ping_print_result(rcv_pkt, (ulong *)snd_time, (ulong *)rcv_time, seq, AH_CAPWAP_PING_DST_IP);
	} while (seq < AH_CAPWAP_PING_COUNT);

	rc = 0;
OUT:
	if (ping_pkt != NULL) {
		free(ping_pkt);
	}

	return rc;
}

static int ah_capwap_ping_broadcast_main_loop(int ping_socket)
{
	char      *ping_pkt = NULL;
	int      rc = -1;
	int      pkt_size = AH_CAPWAP_PING_HDR_SIZE + AH_CAPWAP_PING_DATA_SIZE;
	uint32_t    seq = 0;
	long      snd_time[AH_CAPWAP_PING_TIME_MAX] = {0, 0};
	int      rcv_pkt = 0;

	ping_pkt = malloc(AH_CAPWAP_PING_MALLOC_LEN);
	if (ping_pkt == NULL) {
		printf("CAPWAP ping: malloc buffer for CAPWAP ping failed. malloc len:%d\n", AH_CAPWAP_PING_MALLOC_LEN);
		syslog(LOG_ERR,"CAPWAP ping: malloc buffer for CAPWAP ping failed. malloc len:%d\n", AH_CAPWAP_PING_MALLOC_LEN);
		goto OUT;
	}
	do {
		ah_capwap_ping_encode(ping_pkt, AH_CAPWAP_PING_DATA_SIZE, seq);
		ah_capwap_ping_get_time(&snd_time[AH_CAPWAP_PING_TIME_SEC], &snd_time[AH_CAPWAP_PING_TIME_USEC]);
		ah_capwap_ping_send(ping_socket, ping_pkt, pkt_size);
		AH_CAPWAP_PING_SND_PKT ++;
		rcv_pkt = ah_capwap_ping_broadcast_recv(ping_socket, seq, ping_pkt, snd_time);
		if (rcv_pkt == 0) {
			/*timeout*/
			printf("    Request timed out.\n");
		} else {
			AH_CAPWAP_PING_RCV_PKT += rcv_pkt;
		}
		seq ++;
	} while (seq < AH_CAPWAP_PING_COUNT);

	rc = 0;
OUT:
	if (ping_pkt != NULL) {
		free(ping_pkt);
	}

	return rc;
}

static int ah_capwap_ping_main_loop(int ping_socket)
{
	char      *ping_pkt = NULL;
	int      rc = -1;
	int      pkt_size = AH_CAPWAP_PING_HDR_SIZE + AH_CAPWAP_PING_DATA_SIZE;
	uint32_t    seq = 0;
	long      snd_time[AH_CAPWAP_PING_TIME_MAX] = {0, 0};
	long      rcv_time[AH_CAPWAP_PING_TIME_MAX] = {0, 0};
	int      rcv_len = 0;

	ping_pkt = malloc(AH_CAPWAP_PING_MALLOC_LEN);
	if (ping_pkt == NULL) {
		printf("CAPWAP ping: malloc buffer for CAPWAP ping failed. malloc len:%d\n", AH_CAPWAP_PING_MALLOC_LEN);
		syslog(LOG_ERR,"CAPWAP ping: malloc buffer for CAPWAP ping failed. malloc len:%d\n", AH_CAPWAP_PING_MALLOC_LEN);
		goto OUT;
	}
	do {
		ah_capwap_ping_encode(ping_pkt, AH_CAPWAP_PING_DATA_SIZE, seq);
		ah_capwap_ping_get_time(&snd_time[AH_CAPWAP_PING_TIME_SEC], &snd_time[AH_CAPWAP_PING_TIME_USEC]);
		ah_capwap_ping_send(ping_socket, ping_pkt, pkt_size);
		AH_CAPWAP_PING_SND_PKT ++;
		rcv_len = ah_capwap_ping_recv(ping_socket, seq, ping_pkt);
		if (rcv_len == -1) {
			/*timeout*/
			rcv_time[AH_CAPWAP_PING_TIME_SEC] = 0;
			rcv_time[AH_CAPWAP_PING_TIME_USEC] = 0;
		} else {
			ah_capwap_ping_get_time(&rcv_time[AH_CAPWAP_PING_TIME_SEC], &rcv_time[AH_CAPWAP_PING_TIME_USEC]);
			AH_CAPWAP_PING_RCV_PKT ++;
			sleep(1);
		}
		seq ++;
		ah_capwap_ping_print_result(rcv_len, (ulong *)snd_time, (ulong *)rcv_time, seq, AH_CAPWAP_PING_DST_IP);
	} while (seq < AH_CAPWAP_PING_COUNT);

	rc = 0;
OUT:
	if (ping_pkt != NULL) {
		free(ping_pkt);
	}

	return rc;
}

static int ah_capwap_ping_socket = 0;
#define AH_CAPWAP_PING_SOCKET (ah_capwap_ping_socket)
static void ah_capwap_ping_exit(int signal)
{
	if (AH_CAPWAP_PING_SOCKET != 0) {
		close(AH_CAPWAP_PING_SOCKET);
	}
	exit(0) ;
}

static void ah_capwap_ping_init()
{
	signal(SIGINT, ah_capwap_ping_exit);
	memset(&ah_capwap_ping_info, 0x00, sizeof(ah_capwap_ping_info));
	/*save the start time*/
	ah_capwap_ping_get_time(&AH_CAPWAP_PING_START_TIME_SEC, &AH_CAPWAP_PING_START_TIME_USEC);
	/*init the ping parameter*/
	ah_capwap_ping_init_para(&ah_capwap_ping_para);
}

int main(int argc, char **argv)
{
#define AH_CAPWAP_PING_BROADCAST_IP_STR "255.255.255.255"
	int8_t    ch;
	uint32_t    dst_ip = 0;

	ah_capwap_ping_init();
	/*get the user parameter from CLI*/
	while ((ch = getopt(argc, argv, "d:p:c:s:t:f:")) != EOF) {
		switch (ch) {
		case 'd':
			strncpy(ah_capwap_ping_para.dst_name, optarg, AH_MAX_STR_64_LEN);
			break;
		case 'p':
			ah_capwap_ping_para.dst_port = atoi(optarg);
			break;
		case 'c':
			ah_capwap_ping_para.count = atoi(optarg);
			break;
		case 's':
			ah_capwap_ping_para.size = atoi(optarg);
			break;
		case 't':
			ah_capwap_ping_para.timeout = atoi(optarg);
			break;
		case 'f':
			ah_capwap_ping_mode = AH_CAPWAP_PING_MODE_FLOODING;
			ah_capwap_ping_para.count = atoi(optarg);
			break;
		default:
			printf("Usage: capwap_ping -d <server name> -p <destination port> -s <payload size> -t <timeout value> [-c |-f] <counter>\n");
			syslog(LOG_ERR,"CAPWAP Ping: invalid parameter %c\n", ch);
			return -1;
		}
	}

	/*resolve the destination server name*/
	if (ah_capwap_ping_get_dst_ip(ah_capwap_ping_para.dst_name, &dst_ip) == -1) {
		return -1;
	}

	/*print ping header*/
	ah_capwap_printf_ping_header();

	/*create a socket*/
	if (ah_capwap_ping_create_socket(ah_capwap_ping_para.dst_port, dst_ip, &AH_CAPWAP_PING_SOCKET) == -1) {
		return -1;
	}
	/*while in receive and sending*/
	if (strcmp(AH_CAPWAP_PING_BROADCAST_IP_STR, AH_CAPWAP_PING_DST_IP) == 0) {
		ah_capwap_ping_mode = AH_CAPWAP_PING_MODE_BROADCAST;
	}
	switch (ah_capwap_ping_mode) {
	case AH_CAPWAP_PING_MODE_BROADCAST:
		if (ah_capwap_ping_broadcast_main_loop(AH_CAPWAP_PING_SOCKET) == -1) {
			return -1;
		}
		break;
	case AH_CAPWAP_PING_MODE_FLOODING:
		if (ah_capwap_ping_flood_main_loop(AH_CAPWAP_PING_SOCKET) == -1) {
			return -1;
		}
		break;
	default:
		if (ah_capwap_ping_main_loop(AH_CAPWAP_PING_SOCKET) == -1) {
			return -1;
		}
		break;
	}
	/*calculate the statistic information*/
	ah_capwap_ping_print_statistic(&ah_capwap_ping_info);
	if (AH_CAPWAP_PING_SOCKET != 0) {
		close(AH_CAPWAP_PING_SOCKET);
	}

	return (AH_CAPWAP_PING_RCV_PKT ? 0 : -1);
}

