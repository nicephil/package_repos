#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <zlib.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_assert.h"
#include "ah_capwap_types.h"
#include "ah_capwap_def.h"
#include "ah_capwap_func.h"
#include "ah_capwap_ini.h"
#include "ah_capwap_dtls.h"
#include "ah_dbg_agent.h"
#include "ah_capwap_api.h"
#include "ah_capwap_hvcom.h"
#include "ah_capwap_tcp.h"
#include "ah_ipv6_shared.h"


/*CAPWAP EVENT BUFFER FLAG*/
#define AH_CAPWAP_EVENT_PKT_AVLB    1
#define AH_CAPWAP_EVENT_PKT_UNAVLB  0

/*CAPWAP PACKET OPTION TYPE*/
#define DISCOVERY_TYPE             20
#define LOCATION_DATA              27
#define SESSION_ID                 32
#define RESULT_CODE              35
#define WTP_DESCRIPTOR             36
#define WTP_FALLBACK               37
#define WTP_FRAME_TUNNEL_MOD       38
#define WTP_IPV4_IPADDRESS         39
#define WTP_MAC_TYPE               40
#define WTP_NAME                   41
#define WTP_IPV6_IPADDRESS         50
#define AH_CAPWAP_WTP_MAC          5000
#define AH_CAPWAP_WTP_MASK         5001
#define AH_CAPWAP_WTP_GATEWAY      5002
#define AH_CAPWAP_WTP_REGION_CODE  5003
#define AH_CAPWAP_WTP_COUNTRY_CODE 5004
#define AH_CAPWAP_WTP_IP_TYPE      5005
#define AH_CAPWAP_WTP_PORT_INFO    5006

#define AH_CAPWAP_WTP_VHM_NAME     5008
#define AH_CAPWAP_WTP_IPV6_PREFIX  5013
#define AH_CAPWAP_WTP_IPV6_GATEWAY 5014
#define AH_CAPWAP_WTP_IPV6_TYPE    5015

/*CAPWAP PACKET FIXED LEN*/
#define AH_CAPWAP_TRANS_HEAD_LEN   8
#define AH_CAPWAP_TLV_TYPE_LEN     4
#define AH_CAPWAP_TLV_LENGTH_LEN   2

/*CAPWAP PACKET FRAG info*/
#define AH_CAPWAP_IS_FRAG_PKT        0x01
#define AH_CAPWAP_LAST_FRAG_PKT      0x01
#define AH_CAPWAP_FRAG_BUFF_INVALID  0
#define AH_CAPWAP_FRAG_BUFF_VALID    1
#define AH_CAPWAP_FRAG_ONLY_SAVE     0
#define AH_CAPWAP_FRAG_NEED_ASSEMBLY 1

#define AH_CAPWAP_SKIP_THIS_ATTRIBUTE -2
/*the array for capwap fill opt callback*/
static ah_capwap_fill_discoveryopt_t capwapopt[] = {
	{AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_REQUEST, ah_capwap_fillopt_discoverytype},
	{AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_REQUEST, ah_capwap_fillopt_wtpdescr},
	{AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_REQUEST, ah_capwap_fillopt_wtpframmod},
	{AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_REQUEST, ah_capwap_fillopt_wtpmactype},
	{AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_REQUEST, ah_capwap_fillopt_wtpmac},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_locationdata},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_sessionid},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpfallback},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpipv4addr},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpipv6addr},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpname},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpmac},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpdescr},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpmask},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtp_prefix},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpgateway},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtp_ipv6gateway},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_region_code},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_port_info},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_country_code},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_iptype},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_ip6type},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_result_code},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_REQUEST, ah_capwap_fillopt_wtpvhm},
	{AH_CAPWAP_RUN, AH_CAPWAP_ABORT_IMAGE_RESPONSE, ah_capwap_fillopt_abort_image_result},
	{AH_CAPWAP_RUN, AH_CAPWAP_INFORMATION_RESPONSE, ah_capwap_fillopt_info_query_result},
	{AH_CAPWAP_RUN, AH_CAPWAP_EVENT_INFO_RESPONSE, ah_capwap_fillopt_event_query_result},
	{AH_CAPWAP_RUN, AH_CAPWAP_ECHO_REQUEST, ah_capwap_fillopt_snd_echo_time},
};

/*the array for capwap fill event opt callback*/
static ah_capwap_fill_eventopt_t capwapeventopt[] = {
	{AH_CAPWAP_RUN, AH_CAPWAP_CHGSTATE_EVENT_REQUEST, ah_capwap_fillopt_radioadminstate},
	{AH_CAPWAP_RUN, AH_CAPWAP_CHGSTATE_EVENT_REQUEST, ah_capwap_fillopt_mgt0_hive},
	{AH_CAPWAP_RUN, AH_CAPWAP_CHGSTATE_EVENT_REQUEST, ah_capwap_fillopt_hiveap_info},
};

/*the array for capwao fill event request option callback*/
static ah_capwap_fill_event_request_t capwap_event_request[] = {
	{AH_CAPWAP_RUN, AH_CAPWAP_EVENT_REQUEST, ah_capwap_fillopt_statistical},
};

/*the array for capwap client to analyse the packet*/
static ah_capwap_state_msgtyep_t capwapstatemsg[] = {
	{AH_CAPWAP_DISCOVERY, AH_CAPWAP_DISCOVERY_RESPONSE, ah_capwap_discoveryopt},
	{AH_CAPWAP_JOIN, AH_CAPWAP_JOIN_RESPONSE, ah_capwap_joinopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_CHGSTATE_EVENT_RESPONSE, ah_capwap_chgeventopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_ECHO_RESPONSE, ah_capwap_runopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_CONFIG_REQUEST, ah_capwap_configopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_EVENT_RESPONSE, ah_capwap_eventopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_CHG_EVENT_REQUEST, ah_capwap_chg_event_opt},
	{AH_CAPWAP_RUN, AH_CAPWAP_CLI_REQUEST, ah_capwap_cliopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_STA_REQUEST, ah_capwap_staopt},
	{AH_CAPWAP_RUN, AH_CAPWAP_GET_CWP_DIR_REQUEST, ah_capwap_cwp_directory},
	{AH_CAPWAP_RUN, AH_CAPWAP_ABORT_IMAGE_REQUEST, ah_capwap_abort_save_image},
	{AH_CAPWAP_RUN, AH_CAPWAP_SSH_KEY_REQUEST, ah_capwap_rcv_ssh_key},
	{AH_CAPWAP_RUN, AH_CAPWAP_EVENT_INFO_REQUEST, ah_capwap_event_info_request},
	{AH_CAPWAP_RUN, AH_CAPWAP_INFORMATION_REQUEST, ah_capwap_info_query_request},
};

/*the array for capwap handle event request*/
static ah_capweap_handle_event_t capwap_event_handle_request[] = {
	{AH_CAPWAP_EVENT_SHOW_CAPTURE_INTERFACE, ah_capwap_handle_pkt_cpt_stat_request, NULL},
	{AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING, NULL, ah_capwap_handle_enable_clnt_trace_confirm},
	{AH_CAPWAP_EVENT_DHCP_PROBE, NULL, ah_capwap_handle_enable_clnt_trace_confirm},
	{AH_CAPWAP_EVENT_PCI_ALERT, NULL, ah_capwap_handle_enable_clnt_trace_confirm},
	{AH_CAPWAP_EVENT_INTERFACE_MAP, ah_capwap_handle_interface_map, NULL},
	{AH_CAPWAP_EVENT_POE, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_LCDP_NEIGHBORS, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_VPN_STATUS, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_HVCOM, ah_capwap_hvcom_msg_handle, NULL},
	{AH_CAPWAP_EVENT_STATS_REPORT, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_RADIUS_TEST, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_RETRIVE_AD_INFO, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_LDAP_TREE_INFO, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_DOMAIN_JOINED, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_WAN_VPN_AVAILABLE, ah_capwap_handle_remote_event_request, NULL},
	{AH_CAPWAP_EVENT_BRD_OTP, ah_capwap_handle_remote_event_request, NULL},
};

typedef struct _ah_capwap_pkttype2eventid_t_s {
	uint16_t    packet_type;              /*CAPWAP protocol TLV type*/
	uint16_t    event_id;                 /*aerohive event id*/
} ah_capwap_pkttype2eventid_t;

/*the mapping between CAPWAP event request to Aerohive event id*/
static ah_capwap_pkttype2eventid_t ah_capwap_type2eventid[] = {
	{AH_CAPWAP_EVENT_POE, AH_EVENT_CAPWAP_REQUEST_DCD},
	{AH_CAPWAP_EVENT_LCDP_NEIGHBORS, AH_EVENT_CAPWAP_REQUEST_DCD},
	{AH_CAPWAP_EVENT_VPN_STATUS, AH_EVENT_CAPWAP_REQ_VPN},
	{AH_CAPWAP_EVENT_STATS_REPORT, AH_EVENT_CAPWAP_REQUEST_DCD},
	{AH_CAPWAP_EVENT_RADIUS_TEST, AH_EVENT_RADIUS_TEST_REQUEST},
	{AH_CAPWAP_EVENT_RETRIVE_AD_INFO, AH_EVENT_RADIUS_AD_RETRIVE_REQ},
	{AH_CAPWAP_EVENT_LDAP_TREE_INFO, AH_EVENT_RADIUS_LDAP_TREE_REQ},
	{AH_CAPWAP_EVENT_DOMAIN_JOINED, AH_EVENT_RADIUS_QUERY_AD_INFO_REQ},
};

static uint ah_capwap_type2eventid_num = sizeof(ah_capwap_type2eventid) / sizeof(ah_capwap_type2eventid[0]);

/*the array for capwap handle information query request*/
static ah_capwap_handle_information_query_t capwap_info_query_handle_request[] = {
	{AH_CAPWAP_INFO_DELETE_COOKIE, NULL, ah_capwap_handle_delete_cookie_confirm},
	{AH_CAPWAP_INFO_SYSTEM_TOPOLOGY, NULL, ah_capwap_handle_get_system_topology_info},
};

/*the struct for capwap event pkt buffer*/
static ah_capwap_save_pkt ah_capwap_pkt_buff = {0};
static ah_capwap_pkt_frag_buff ah_capwap_frag_buff[AH_CAPWAP_FRAG_MAX_NUM];

static uint32_t abort_save_type = 0;
static char *confirm_pkt_info = NULL;

/***************************************************************************
 *
 * Function:  ah_capwap_set_event_frag_id
 *
 * Purpose:   set event buffer frag id for event buffer matching the
 *                given event buffer sequence number.
 *
 * Inputs:    seq_num: event buffer seqence number
 *            frag_id:  new frag id
 *
 * Output:    void
 *
 * Returns:   0 is success
 *
 **************************************************************************/
int ah_capwap_set_event_frag_id(int seq_num, int frag_id)
{
	int      i = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	for (i = 0; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
		if (ah_capwap_pkt_buff.event_pkt[i].sub_seq == seq_num) {
			ah_capwap_pkt_buff.event_pkt[i].frag_id = frag_id;
		}
	}

	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_event_frag_id
 *
 * Purpose:   get event buffer frag id for event buffer specified by the given
 *                event buffer sequnence number.
 *
 * Inputs:    voidr
 *
 * Output:    void
 *
 * Returns:   the frag id in term of seq_num
 *
 **************************************************************************/
int ah_capwap_get_event_frag_id()
{
	int      frag_id = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	frag_id = ah_capwap_para.frag_id;
	if (ah_capwap_para.frag_id >= AH_CAPWAP_MAX_FRAG_ID) {
		ah_capwap_para.frag_id = 0;
	} else {
		ah_capwap_para.frag_id ++;
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return frag_id;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_free_buffer_count
 *
 * Purpose:   get the total empty buffer can be set event
 *
 * Inputs:    all, get all available buffer
 *
 * Output:    void
 *
 * Returns:   the total number of empty room
 *
 **************************************************************************/
int ah_capwap_get_free_buffer_count(int all)
{
	int      i = 0;
	int      buff_unalb = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	for (i = 0; i < AH_CAPWAP_NORMAL_EVENT_MAX_PKT; i++) {
		if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_UNAVLB) {
			buff_unalb ++;
		}
	}

	/* reserve the last part buffer for special event usage */
	if (all == 1) {
		for (i = AH_CAPWAP_NORMAL_EVENT_MAX_PKT; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
			if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_UNAVLB) {
				buff_unalb ++;
			}
		}
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return buff_unalb;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_error_cli_info
 *
 * Purpose:   save the error CLI information to a temp file
 *
 * Inputs:    zip_flag: zip or not zip
 *                orign_len: unzip cli information length
 *                cli_info: error cli information
 *                info_len: error cli information length
 *
 * Output:    void
 *
 * Returns:   0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_save_error_cli_info(char zip_flag, uint32_t orign_len, uchar *cli_info, uint32_t info_len)
{
	FILE *fp = NULL;
	int      rc = -1;
	uint32_t    unzip_len = htonl(orign_len);

	fp = fopen(AH_CAPWAP_ERROR_CLI_FILE, "w+");
	if (fp == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: open file %s failed\n", AH_CAPWAP_ERROR_CLI_FILE);
		goto OUT;
	}

	/*save the zip flag*/
	fwrite(&zip_flag, sizeof(char), sizeof(char), fp);

	/*save the orign length*/
	fwrite(&unzip_len, sizeof(char), sizeof(uint32_t), fp);

	/*save the cli information*/
	fwrite(cli_info, sizeof(char), info_len, fp);

	rc = 0;
OUT:
	if (fp != NULL) {
		fsync(fileno(fp));
		fclose(fp);
	}

	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fragment_and_send
 *
 * Purpose:   send the cli result information to event buffer and fragment it
 *
 * Inputs:    pkt_len: packet len
 *            start_pkt: frag index for start (0 is the initial value)
 *            total_pkt: total index for all buffer
 *            buffer: need send buffer
 *
 * Output:    frag_id: all pkt frag id (it will be revalue in the first packet)
 *
 * Returns:   last index for current fragment
 *
 **************************************************************************/
int ah_capwap_fragment_and_send(char *buffer, uint pkt_len, uint start_pkt, uint total_pkt, uint *frag_id)
{
#define AH_CAPWAP_FRAG_FIRST_PKT       1
#define AH_CAPWAP_FRAG_CUR_FRAG_OFFSET 1
#define AH_CAPWAP_FRAG_MAX_NUMBER_FRAG 1000
	char      msg[AH_CAPWAP_EVENT_MAX_LEN + 100] = {0};
	int      pkt_int;
	int      pkt_del;
	int      i = 0;
	int      snd_len = 0;
	int      first_pkt = 0;
	int      cpy_pkt_len = 0;
	uint32_t    sub_seq = 0;
	uint32_t    event_id = 0;
	struct timeval tv;
	struct timezone tz;

	ah_dbg_old(capwap_info, "Receive capwap event cli: length(%d) start_index(%d) total_index(%d) frag_id(%d)\n",
			   pkt_len, start_pkt, total_pkt, *frag_id);
	if (total_pkt > AH_CAPWAP_FRAG_MAX_NUMBER_FRAG) {
		ah_err_old("CAPWAP:The Max fragment is %d. the current total fragment is :%d", AH_CAPWAP_FRAG_MAX_NUMBER_FRAG, total_pkt);
		return -1;
	}
	if (start_pkt == 0) {
		first_pkt = AH_CAPWAP_FRAG_FIRST_PKT;
	}

	/*generate a random sub_seq*/
	gettimeofday(&tv, &tz);
	srand(tv.tv_sec + tv.tv_usec);
	sub_seq = 1 + (int)(AH_CAPWAP_EVENT_MAX_RAND * rand() / (RAND_MAX + 1.0));

	/*fragment the message as needed*/
	pkt_int = pkt_len / AH_CAPWAP_EVENT_MAX_LEN;
	pkt_del = pkt_len % AH_CAPWAP_EVENT_MAX_LEN;

	/*calculate total number of packets to send*/
	if (pkt_del != 0) {
		pkt_int ++;
	}
	/*no event message, only need add cur_msg/total_msg*/
	if (pkt_del == 0 && pkt_int == 0) {
		/*may be some module only send a event to HM, not any conent*/
		pkt_int = 1;
	}

	/*the format of the message
	  <total fragment>(1 bytes)<current fragment>(1 bytes)<fragement seqence number>(4 bytes)<payload>
	 */
	/*add total_msg/cur_msg*/
	*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_TOL_FRAG_OFFSET) = htons((uint16_t)(total_pkt));

	/*add sub_seq*/
	*(uint32_t *)(msg + AH_CAPWAP_EVENT_MSG_SEQ_FRAG_OFFSET) = htonl(sub_seq);

	/*send event*/
	event_id = AH_CAPWAP_EVENT_CLI;
	/*get the frag id*/
	if (first_pkt == AH_CAPWAP_FRAG_FIRST_PKT) {
		*frag_id = ah_capwap_get_event_frag_id();
	}

	cpy_pkt_len = AH_CAPWAP_EVENT_MAX_LEN;
	for (i = 0; i < pkt_int; i++) {
		*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET) = htons((uint16_t)(start_pkt + AH_CAPWAP_FRAG_CUR_FRAG_OFFSET));
		start_pkt ++;
		/*copy message*/
		if (i == (pkt_int - 1)) { /*the last part*/
			cpy_pkt_len = pkt_del ? pkt_del : AH_CAPWAP_EVENT_MAX_LEN;
			memcpy((msg + AH_CAPWAP_EVENT_MSG_START), (buffer + (i * AH_CAPWAP_EVENT_MAX_LEN)), cpy_pkt_len);
			snd_len = cpy_pkt_len + AH_CAPWAP_EVENT_MSG_START;
		} else { /*not the last part*/
			memcpy((msg + AH_CAPWAP_EVENT_MSG_START), (buffer + (i * AH_CAPWAP_EVENT_MAX_LEN)), cpy_pkt_len);
			snd_len = cpy_pkt_len + AH_CAPWAP_EVENT_MSG_START;
		}

		ah_capwap_send_event2buf(event_id, snd_len, msg, *frag_id);
		ah_dbg_old(capwap_info, "Send capwap event itself send to buff: total:%d current:%d seq_num:%d frag id :%d length:%d\n",
				   ntohs(*(uint16_t *)(msg)), ntohs(*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET)), sub_seq, *frag_id, snd_len);
	}

	/*interrupt the capwap loop to deal with event*/
	ah_capwap_interrupt_listen();

	return start_pkt;
}

/***************************************************************************
 *
 * Function:  ah_capwap_read_data_file
 *
 * Purpose:   read the data from  file
 *
 * Inputs:    fp: FILE fp
 *            len: max len for read
 *
 * Output:    buffer: the filled buffer
 *
 * Returns:   the total len filled
 *
 **************************************************************************/
int ah_capwap_read_data_file(char *buffer, FILE *fp, int max_len)
{
	return fread(buffer, sizeof(char), max_len, fp);
}

/***************************************************************************
 *
 * Function:  ah_capwap_set_hdr
 *
 * Purpose:   fill the return information hdr
 *
 * Inputs:    seq_num: the sequence number of response
 *            file_size:   the total file size of cli information
 *
 * Output:    info_buffer: the buffer has been filled the cli hdr
 *
 * Returns:   0 is success, otherwise is failed
 *
 **************************************************************************/
int ah_capwap_set_hdr(char *info_buffer, char zip_flag, uint32_t file_size)
{
	if (info_buffer == NULL) {
		ah_err_old("CAPWAP:the buffer is NULL\n");
		return -1;
	}

	/*encapsulate the event hdr <seq_num><cli_result><result_len>*/
	*(char *)info_buffer = zip_flag;
	*(uint32_t *)(info_buffer + sizeof(char)) = htonl(file_size);

	return 0;
}

#define AH_CAPWAP_FRAG_EVENT_HDR_LEN  9
/***************************************************************************
 *
 * Function:  ah_capwap_compress_cli_result
 *
 * Purpose:   fill the cli result header and compress the buffer
 *
 * Inputs:    seq_num : seqence number
 *            result:        the result of cli execute
 *            file_path:   the path for save the result
 *            origin_size: the uncompress buffer size
 *            zip_flag: compress or not flag
 *
 * Output:    void
 *
 * Returns:   0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_compress_cli_result(uint seq_num, char result, char *file_path, uint32_t *origin_size,
								  char      *zip_flag)
{
	int      rc = 0;
#if 0
	struct stat file_buf ;
	uint16_t    header_len = 0;
	uchar      *uncompress_buffer = NULL;
	uchar      *compress_buffer = NULL;
	FILE *fp = NULL;
	ulong      compress_len = 0;
	uint32_t    uncompress_len = 0;
	int      cp_rst = 0;

	if (stat(file_path, &file_buf) < 0) {
		ah_err_old("%s: Fetch file's info failed.", __func__);
		goto OUT;
	}
	*origin_size = file_buf.st_size + AH_CAPWAP_FRAG_EVENT_HDR_LEN;
	uncompress_buffer = ah_malloc(*origin_size);
	if (uncompress_buffer == NULL) {
		ah_err_old("CAPWAP, malloc buffer for compress cli result failed, malloc len:%d\n", *origin_size);
		goto OUT;
	}
	/*fill seq-number/result flag/result len*/
	*(uint32_t *)(uncompress_buffer) = htonl(seq_num);
	*(uncompress_buffer + sizeof(uint32_t)) = result;
	*(uint32_t *)(uncompress_buffer + sizeof(uint32_t) + sizeof(char)) = htonl(file_buf.st_size);
	ah_dbg_old(capwap_info, "the cli result: seq_num is:%d, result:%d, result len:%d\n", seq_num, result, file_buf.st_size);

	/*read file*/
	fp = fopen(file_path, "r+");
	if (fp == NULL) {
		ah_err_old("CAPWAP: open cli result file:%s failed!\n", file_path);
		goto OUT;
	}
	if (fread((uncompress_buffer + AH_CAPWAP_FRAG_EVENT_HDR_LEN), sizeof(char), file_buf.st_size, fp) !=  file_buf.st_size) {
		ah_err_old("%s: Read file failed.", __func__);
		goto OUT;
	}
	/*clear file*/
	if (ftruncate(fileno(fp), 0) != 0) {
		ah_err_old("CAPWAP: clear file:%s failed!reason:%s\n", file_path, strerror(errno));
		goto OUT;
	}
	rewind(fp);
	/*check need compress or not*/
	header_len = AH_CAPWAP_COMPRESS_FLAG_LEN + AH_CAPWAP_UNCOMPRESS_SIZE_LEN + AH_CAPWAP_FRAG_EVENT_HDR_LEN;
	uncompress_len = *origin_size;
	compress_len = *origin_size;
	if ((file_buf.st_size + header_len) >  AH_CAPWAP_EVENT_MAX_LEN) {
		/*need compress the buffer*/
		*zip_flag = AH_CAPWAP_CLI_COMPRESS_PACKET;
		compress_buffer = ah_malloc(*origin_size);
		if (compress_buffer == NULL) {
			ah_err_old("CAPWAP, malloc buffer for compress cli result failed, malloc len:%d\n", *origin_size);
			goto OUT;
		}
		cp_rst = compress2(compress_buffer, &compress_len, uncompress_buffer, uncompress_len, Z_BEST_COMPRESSION);
		ah_dbg_old(capwap_info, "compress buffer, now buffer len is:%d, return code:%d\n", compress_len, cp_rst);
		/*write to file*/
		fwrite(compress_buffer, sizeof(char), compress_len, fp);
	} else {
		/*write to file*/
		fwrite(uncompress_buffer, sizeof(char), uncompress_len, fp);
	}

	/*save the error cli information*/
	if (result == AH_RUN_CMD_FAILED) {
		if (*zip_flag == AH_CAPWAP_CLI_COMPRESS_PACKET) {
			if (compress_buffer == NULL) {
				ah_err_old("%s: error happens.", __func__);
				goto OUT;
			}
			ah_capwap_save_error_cli_info(*zip_flag, *origin_size, compress_buffer, compress_len);
		} else {
			ah_capwap_save_error_cli_info(*zip_flag, *origin_size, uncompress_buffer, uncompress_len);
		}
	}

	rc = 0;
OUT:
	if (uncompress_buffer != NULL) {
		ah_free(uncompress_buffer);
	}
	if (compress_buffer != NULL) {
		ah_free(compress_buffer);
	}
	if (fp != NULL) {
		fclose(fp);
	}

#endif
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_info_from_file
 *
 * Purpose:   read the file and send the file content to event buffer
 *
 * Inputs:    seq_num : seqence number
 *            result:        the result of cli execute
 *            file_path:   the path for save the result
 *
 * Output:    void
 *
 * Returns:   0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_get_info_from_file(uint seq_num, char result, char *file_path)
{
#define AH_CAPWAP_FRAG_NEED_HEAD      0
#define AH_CAPWAP_FRAG_NOT_NEED_HEAD  1
	int      rc = -1;
	uint      buff_num = 0;
	int       total_len = 0;
	uint      last_pkt = 0;
	uint      total_pkt  = 0;
	uint      frag_id = AH_CAPWAP_FRAG_NUM_INVALID;
	uint32_t    file_size = 0;
	uint32_t    malloc_size = 0;
	int      hdr_len = 0;
	int      rst_hdr = AH_CAPWAP_FRAG_NEED_HEAD;
	char      *result_buff = NULL;
	struct stat file_buf ;
	FILE *fp = NULL;
	char      zip_flag = 0;
	uint32_t    uncompress_size = 0;
	uint32_t    wait_cnt = 0;

	if (file_path == NULL) {
		ah_err_old("CAPWAP get information from file error, file path is NULL\n");
		goto OUT;
	}
	/*compress the cli result*/
	if (ah_capwap_compress_cli_result(seq_num, result, file_path, &uncompress_size, &zip_flag) == -1) {
		goto OUT;
	}
	/*get the file size*/
	if (stat(file_path, &file_buf) < 0) {
		ah_err_old("%s: Get the file size failed.", __func__);
		goto OUT;
	}
	/*total length = file_size + fixed header*/
	hdr_len = AH_CAPWAP_COMPRESS_FLAG_LEN + AH_CAPWAP_UNCOMPRESS_SIZE_LEN;
	file_size = file_buf.st_size + hdr_len;
	/*get the total packet capwap need send*/
	total_pkt = ((file_size + AH_CAPWAP_EVENT_MAX_LEN - 1) / AH_CAPWAP_EVENT_MAX_LEN);
	ah_dbg_old(capwap_info, "Get information from file: seq_num:%d rc:%d file path:%s file size:%d total packet:%d\n", seq_num, result,
			   file_path, file_size, total_pkt);
	/*1. check number of free buffers available
	  2.  check for need to encapuslate payload header
	  3.  read data from file
	  4.  goto 1*/
	fp = fopen(file_path, "r");
	if (fp == NULL) {
		ah_err_old("CAPWAP read cli file error!(file:%s)\n", file_path);
		goto OUT;
	}
	while (1) {
		/*get number of free buffers availabler*/
		buff_num = ah_capwap_get_free_buffer_count(1);
		if (buff_num == 0) {
			/*wait up to 120 seconds for buffers to be freed up.*/
			if (wait_cnt >= 120) {
				ah_log_flash(AH_LOG_NOTICE, "waiting 120 seconds, no capwap event buffer can be used to send CLI result to HM.\n");
				goto OUT;
			}
			ah_log_old(AH_LOG_WARNING, "no capwap event buffer can be used to send CLI result to HM, waiting...\n");
			sleep(1);
			wait_cnt++;
		} else {
			wait_cnt = 0;
			ah_dbg_old(capwap_info, "there have %d buffer can be used\n", buff_num);
			/*check the file size and buffer size*/
			if (file_size >= (buff_num * AH_CAPWAP_EVENT_MAX_LEN)) {
				malloc_size = buff_num * AH_CAPWAP_EVENT_MAX_LEN ;
			} else {
				malloc_size = file_size;
			}
			/*malloc buffer*/
			ah_dbg_old(capwap_info, "need malloc %d bytes len\n", malloc_size);
			if (malloc_size == 0) {
				ah_dbg_old(capwap_info, "there is no information need send\n");
				rc = 0;
				goto OUT;
			}
			result_buff = ah_malloc(malloc_size);
			if (result_buff == NULL) {
				ah_err_old("CAPWAP malloc for CLI event error!(size:%d)\n", malloc_size);
				goto OUT;
			}
			if (rst_hdr == AH_CAPWAP_FRAG_NEED_HEAD) {
				/*set the hdr*/
				if (ah_capwap_set_hdr(result_buff, zip_flag, uncompress_size) == -1) {
					goto OUT;
				}
				ah_dbg_old(capwap_info, "CLI response header: compress flag:%d uncompress size:%d, compress size:%d\n", zip_flag, uncompress_size,
						   file_size);
				total_len = hdr_len;
				/*fill cli information*/
				ah_dbg_old(capwap_info, "read %d byte to event buffer", malloc_size - hdr_len);
				total_len += ah_capwap_read_data_file(result_buff + hdr_len, fp, malloc_size - hdr_len);
			} else {
				/*fill cli information*/
				total_len = ah_capwap_read_data_file(result_buff, fp, malloc_size);
			}

			/*check total length is error*/
			if (total_len < 0) {
				ah_err_old("CAPWAP Read CLI information error!(total_len:%d)", total_len);
				goto OUT;
			}
			ah_dbg_old(capwap_info, "there have %d bytes cli information need send\n", total_len);

			/*send to event buffer*/
			if (total_len > 0 ) {
				uint      length_to_send = (uint)total_len;
				last_pkt = ah_capwap_fragment_and_send(result_buff, length_to_send, last_pkt, total_pkt, &frag_id);
				/*save the left file size*/
				file_size -= length_to_send;
				ah_dbg_old(capwap_info, "The last pkt index is :%d\n", last_pkt);
				ah_free(result_buff);
				result_buff = NULL;
				/*if total fragment exceed the Max fragement support*/
				if (last_pkt == -1) {
					goto OUT;
				}
			}

			/*file read over*/
			if (feof(fp) || total_len == 0) {
				ah_dbg_old(capwap_info, "The cli file reach end\n");
				if (result_buff != NULL) {
					ah_free(result_buff);
					result_buff = NULL;
				}
				rc = 0;
				goto OUT;
			}
			rst_hdr = AH_CAPWAP_FRAG_NOT_NEED_HEAD;
		}
	}
OUT:
	if (fp != NULL) {
		fclose(fp);
	}
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_buff_clean
 *
 * Purpose:   the function for clean event packet buff
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_event_buff_clean()
{
	int      i = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	for (i = 0; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
		ah_capwap_pkt_buff.event_pkt[i].msg_avlb = AH_CAPWAP_EVENT_PKT_UNAVLB;
		if (ah_capwap_pkt_buff.event_pkt[i].msg != NULL) {
			free(ah_capwap_pkt_buff.event_pkt[i].msg);
			ah_capwap_pkt_buff.event_pkt[i].msg = NULL;
		}
	}
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_need_snd
 *
 * Purpose:   the function for check event buff need send event packet or not
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 need send, otherwise need not send
 *
 **************************************************************************/
int ah_capwap_event_need_snd()
{
	int      i = 0;
	int      rc = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	for (i = 0; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
		if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_AVLB
			&& ah_capwap_pkt_buff.event_pkt[i].snd_times <= ah_capwap_para.capwap_counter.max_retransmit) {
			goto OUT;
		}
	}
	rc = -1;
OUT:
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_need_rcv
 *
 * Purpose:   the function for check event buff need receive event packet or not
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   0 need receive, otherwise need not receive
 *
 **************************************************************************/
int ah_capwap_event_need_rcv()
{
	int      i = 0;
	int      rc = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	for (i = 0; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
		if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_AVLB
			&& ah_capwap_pkt_buff.event_pkt[i].snd_times > 0
			&& ah_capwap_pkt_buff.event_pkt[i].snd_times <= ah_capwap_para.capwap_counter.max_retransmit) {
			ah_dbg_old(capwap_info, "Need receive the packet type:%d, cur_index:%d, max_index:%d, snd_times:%d\n",
					   ah_capwap_pkt_buff.event_pkt[i].msg_type,
					   ah_capwap_pkt_buff.event_pkt[i].cur_index, ah_capwap_pkt_buff.event_pkt[i].max_index, ah_capwap_pkt_buff.event_pkt[i].snd_times);
			goto OUT;
		}
	}
	rc = -1;
OUT:
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_get_index
 *
 * Purpose:   the function for get next send index and next save index
 *
 * Inputs:    void
 *
 * Output:    snd_index: next send index
 *            sav_index: next save index
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_event_get_index(uint32_t *snd_index, uint32_t *sav_index)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	*snd_index = ah_capwap_pkt_buff.send_index;
	*sav_index = ah_capwap_pkt_buff.save_index;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_get_buff
 *
 * Purpose:   get the event buff information in term of buff index
 *
 * Inputs:    buff_index: buff index
 *
 * Output:    buff: the buff infromation
 *
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_event_get_buff(uint32_t buff_index, ah_capwap_event_pkt_t *buff)
{
	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	buff->msg_type = ah_capwap_pkt_buff.event_pkt[buff_index].msg_type;
	buff->msg_len = ah_capwap_pkt_buff.event_pkt[buff_index].msg_len;
	buff->msg_id = ah_capwap_pkt_buff.event_pkt[buff_index].msg_id;
	buff->msg_avlb = ah_capwap_pkt_buff.event_pkt[buff_index].msg_avlb;
	buff->sav_time = ah_capwap_pkt_buff.event_pkt[buff_index].sav_time;
	buff->snd_times = ah_capwap_pkt_buff.event_pkt[buff_index].snd_times;
	buff->cur_index = ah_capwap_pkt_buff.event_pkt[buff_index].cur_index;
	buff->max_index = ah_capwap_pkt_buff.event_pkt[buff_index].max_index;
	buff->sub_seq = ah_capwap_pkt_buff.event_pkt[buff_index].sub_seq;
	buff->msg = ah_capwap_pkt_buff.event_pkt[buff_index].msg;
	buff->frag_id = ah_capwap_pkt_buff.event_pkt[buff_index].frag_id;
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_get_snd_buff
 *
 * Purpose:   check the buff need send
 *
 * Inputs:    buff_index: buff index
 *
 * Output:    void
 *
 *
 * Returns:   0 buffer has packet need send, otherwise not
 *
 **************************************************************************/
int ah_capwap_event_get_snd_buff(uint32_t snd_index, uint32_t *msg_type)
{
#define AH_CAPWAP_EVENT_RETRAN_TIME 10
	uint      now_time = 0;
	int      rc = 0;

	/*get current time*/
	get_system_start_interval(&now_time);

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	if (ah_capwap_pkt_buff.event_pkt[snd_index].msg_avlb == AH_CAPWAP_EVENT_PKT_AVLB) {
		/*two conditions need send.
		  1.new packet
		  2.snd_times <= AH_CAPWAP_EVENT_MAX_SND and save_time + AH_CAPWAP_EVENT_RETRAN_TIME < now_time
		  */
		if (ah_capwap_pkt_buff.event_pkt[snd_index].snd_times == 0) {
			ah_capwap_pkt_buff.send_index = snd_index;
			*msg_type = ah_capwap_pkt_buff.event_pkt[snd_index].msg_type;
			ah_capwap_increase_event_packet_counter(AH_CAPWAP_INCREASE_EVENT_SEND_PKT_COUNTER, ah_capwap_pkt_buff.event_pkt[snd_index].msg_type);
			goto OUT;
		}
		if (ah_capwap_pkt_buff.event_pkt[snd_index].snd_times <= ah_capwap_para.capwap_counter.max_retransmit) {
			if (now_time - ah_capwap_pkt_buff.event_pkt[snd_index].sav_time > AH_CAPWAP_EVENT_RETRAN_TIME) {
				ah_capwap_pkt_buff.event_pkt[snd_index].sav_time = now_time;
				ah_capwap_pkt_buff.send_index = snd_index;
				*msg_type = ah_capwap_pkt_buff.event_pkt[snd_index].msg_type;
				ah_capwap_increase_event_packet_counter(AH_CAPWAP_INCREASE_EVENT_SEND_PKT_COUNTER, ah_capwap_pkt_buff.event_pkt[snd_index].msg_type);
				goto OUT;
			}
		} else { /*delete the retransmit times overflow the max times*/
			/*see bug #8399 to avoid capwap loop in send event status*/
			/*delete the retransmit times overflow the max times and exist time exceed 2 minutes*/
			/* only delete the times overflow packet when we receive any echo packet or confirm event */
			if ((ah_capwap_para.echo_snd == AH_CAPWAP_ECHO_HAS_RCV) &&
				((now_time - ah_capwap_pkt_buff.event_pkt[snd_index].sav_time) > (AH_CAPWAP_EVENT_RETRAN_TIME * 12))) {
				if (ah_capwap_pkt_buff.event_pkt[snd_index].msg != NULL) {
					free(ah_capwap_pkt_buff.event_pkt[snd_index].msg);
					ah_capwap_pkt_buff.event_pkt[snd_index].msg = NULL;
				}
				ah_capwap_pkt_buff.event_pkt[snd_index].msg_avlb = AH_CAPWAP_EVENT_PKT_UNAVLB;
				/*increase lost counter*/
				ah_log_old(AH_LOG_WARNING, "Event packet doesn't receive the response for %d times, discard it. (event:%d)\n",
						   ah_capwap_para.capwap_counter.max_retransmit, ah_capwap_para.capwap_counter.max_retransmit);
				ah_capwap_increase_packet_lost_counter();
				ah_capwap_increase_event_packet_counter(AH_CAPWAP_INCREASE_EVENT_LOST_PKT_COUNTER, ah_capwap_pkt_buff.event_pkt[snd_index].msg_type);
			}
		}
	}
	rc = -1;
OUT:
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_get_save_index
 *
 * Purpose:   get the next saved index
 *
 * Inputs:    now_time: current time from boot
 *
 * Output:    save_index: the index for next save
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_event_get_save_index(int msg_type, uint32_t *save_index, uint32_t now_time)
{
	//ah_uint_t max_times = 0;
	int      i = 0;

	for (i = 0; i < AH_CAPWAP_NORMAL_EVENT_MAX_PKT; i++) {
		/*there have a empty buffer*/
		if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_UNAVLB) {
			*save_index = i;
			return 0;
		}
#if 0  /*see bug #8399 to avoid capwap loop in send event status*/
		/*save the oldest buffer*/
		if ((now_time - ah_capwap_pkt_buff.event_pkt[i].sav_time) > max_times) {
			max_times = (now_time - ah_capwap_pkt_buff.event_pkt[i].sav_time);
			*save_index = i;
		}
#endif
	}
	/* current only CLI event use the last special buffer */
	if (msg_type == AH_CAPWAP_EVENT_CLI) {
		for (i = AH_CAPWAP_NORMAL_EVENT_MAX_PKT; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
			/*there have a empty buffer*/
			if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_UNAVLB) {
				*save_index = i;
				return 0;
			}
		}
	}

	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_get_msg_frag_info
 *
 * Purpose:   check the event packe is frag packe or not
 *
 * Inputs:    event_msg: the event packet in buff
 *            msg:           the event info get from dcd idp event
 *            frag_id:       the fixed frag id
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_event_get_msg_frag_info(ah_capwap_event_pkt_t *event_msg, char *msg, uint frag_id)
{
	int      i = 0;

	if (event_msg == NULL) {
		ah_err_old("CAPWAP event message is NULL\n");
		return -1;
	}
	/*get frag information*/
	event_msg->cur_index = ntohs(*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_SUB_FRAG_OFFSET));
	event_msg->max_index = ntohs(*(uint16_t *)(msg + AH_CAPWAP_EVENT_MSG_TOL_FRAG_OFFSET));
	event_msg->sub_seq = ntohl(*(uint32_t *)(msg + AH_CAPWAP_EVENT_MSG_SEQ_FRAG_OFFSET));

	/*event message is a single packet*/
	if (event_msg->cur_index == 1 && event_msg->max_index == 1) {
		event_msg->frag_id = 0;
		event_msg->msg_frag = 0;
		event_msg->msg_last = 0;
		event_msg->frag_offset = 0;

		return 0;
	}

	/*event message is a multiple packet*/
	event_msg->msg_frag = 1;                                       /*Is a fragment flag*/
	event_msg->frag_offset = event_msg->cur_index - 1;             /*fragment offset(start is zero)*/
	if (event_msg->cur_index == event_msg->max_index) {            /*Is the last packet*/
		event_msg->msg_last = 1;
	} else {
		event_msg->msg_last = 0;
	}

	/*find the same seb_seq event message to get the same frag_id*/
	for (i = 0; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
		/*find the same event message*/
		if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_AVLB && ah_capwap_pkt_buff.event_pkt[i].sub_seq == event_msg->sub_seq) {
			event_msg->frag_id = ah_capwap_pkt_buff.event_pkt[i].frag_id;

			return 0;
		}
	}
	/*can not find the same event message*/
	if (frag_id != AH_CAPWAP_FRAG_NUM_INVALID) {
		/*use the fixed frag id*/
		event_msg->frag_id = frag_id;
		return 0;
	} else {
		/*system alloc a frag id*/
		event_msg->frag_id = ah_capwap_get_event_frag_id();
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_save_msg
 *
 * Purpose:   save the message get from idp to event buff
 *
 * Inputs:    msg_type:  message type
 *            msg_len:    message len
 *            msg:          the event info get from dcd idp event
 *            frag_id:      the fixed frag id
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_event_save_msg(int msg_type, uint msg_len, char *msg, uint frag_id)
{
	uint32_t    save_index;
	uint      now_time = 0;
	int      rc = -1;

	/*get current time*/
	get_system_start_interval(&now_time);

	/*init the save packet buffer param*/
	if (ah_capwap_event_get_save_index(msg_type, &save_index, now_time) == -1) {
		ah_log_old(AH_LOG_WARNING, "CAPWAP:event buffer is full, discard new event message (type:%d).\n", msg_type);
		ah_capwap_increase_packet_drop_buffer_counter();
		ah_capwap_increase_event_packet_counter(AH_CAPWAP_INCREASE_EVENT_DROP_BUFF_COUNTER, msg_type);
		goto OUT;
	}
	ah_capwap_pkt_buff.save_index = save_index;
	ah_dbg_old(capwap_info, "Current save index is %d\n", save_index);
	ah_capwap_pkt_buff.event_pkt[save_index].msg_type = msg_type;
	ah_capwap_pkt_buff.event_pkt[save_index].msg_len = msg_len - AH_CAPWAP_EVENT_MSG_START;

	/*set this packet parameter*/
	ah_capwap_pkt_buff.event_pkt[save_index].snd_times = 0;
	ah_capwap_pkt_buff.event_pkt[save_index].sav_time = now_time;

	/*set the packet frag info*/
	ah_capwap_event_get_msg_frag_info(&ah_capwap_pkt_buff.event_pkt[save_index], msg, frag_id);
	ah_dbg_old(capwap_info, "Frag_id:%d;Frag_flag:%d;Frag_last:%d;Frag_offset:%d\n", ah_capwap_pkt_buff.event_pkt[save_index].frag_id,
			   ah_capwap_pkt_buff.event_pkt[save_index].msg_frag, ah_capwap_pkt_buff.event_pkt[save_index].msg_last,
			   ah_capwap_pkt_buff.event_pkt[save_index].frag_offset);

	/*malloc buffer saved*/
	if (ah_capwap_pkt_buff.event_pkt[save_index].msg_len > 0) {
		ah_capwap_pkt_buff.event_pkt[save_index].msg = malloc(msg_len);/*free in function:ah_capwap_del_event_msg*/
		if ((ah_capwap_pkt_buff.event_pkt[save_index].msg) == NULL) {
			ah_err_old("CAPWAP Event packet buffer malloc error!\n(msg_type:%d)\n", msg_type);
			goto OUT;
		}
		/*get rid of the event message head(cur_index,max_index,sub_seq)*/
		memcpy(ah_capwap_pkt_buff.event_pkt[save_index].msg, (msg + AH_CAPWAP_EVENT_MSG_START), msg_len);
	}
	/*All done, set packet valid*/
	ah_capwap_pkt_buff.event_pkt[save_index].msg_avlb = AH_CAPWAP_EVENT_PKT_AVLB;
	rc = 0;
OUT:
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_event_del_msg
 *
 * Purpose:   after HM receive the event packet, delete this from event butt
 *
 * Inputs:    msg_id:  message id
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_event_del_msg(int msg_id)
{
	int      i = 0;
	int      rc = 0;

	pthread_mutex_lock(&ah_capwap_para.ah_capwap_lm);
	/*check the event msg id*/
	for (i = 0; i < AH_CAPWAP_EVENT_MAX_PKT; i++) {
		if (msg_id == ah_capwap_pkt_buff.event_pkt[i].msg_id && ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_AVLB) {
			if (ah_capwap_pkt_buff.event_pkt[i].msg != NULL) {
				free(ah_capwap_pkt_buff.event_pkt[i].msg);/*malloc in function:ah_capwap_save_event_msg*/
				ah_capwap_pkt_buff.event_pkt[i].msg = NULL;
			}
			ah_capwap_pkt_buff.event_pkt[i].msg_avlb = AH_CAPWAP_EVENT_PKT_UNAVLB;
			ah_dbg_old(capwap_info, "Event message(msg_id:%d, index:%d) received the response packet, free it!\n", msg_id, i);
			goto OUT;
		}
	}
	/*may be covered by other event message if buffer is full*/
	ah_dbg_old(capwap_info, "Can not found the Event seqence number:%d in event buffer!\n", msg_id);
	rc = -1;
OUT:
	pthread_mutex_unlock(&ah_capwap_para.ah_capwap_lm);
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_move_special_char
 *
 * Purpose:   get rid of the special char from input packet
 *
 * Inputs:    input:  input packet
 *            sep_char: sepcial char
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_move_special_char(char *input, char spe_char)
{
	char      check_string[AH_MAX_STR_256_LEN];
	int      i = 0;

	if (input == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP input string is NULL\n");
		return -1;
	}

	strcpy(check_string, input);

	if (strchr(check_string, spe_char) != check_string) { /*the string has no special char*/
		return 0;
	}

	for (i = 1; i < strlen(check_string); i++) {
		if (check_string[i] == spe_char) {
			strncpy(input, (check_string + 1), i); /*skip the first special char*/
			input[i - 1] = '\0';
			return 0;
		}
	}
	ah_log_old(AH_LOG_ERR, "CAPWAP can not found correspond char:%s\n", check_string);
	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_filltlv_head
 *
 * Purpose:   fill the TLV head
 *
 * Inputs:    fillbuf: the packet buff
 *            tlvtype: T for tlv
 *            tlvlen:   L for tlv
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_filltlv_head(char *fillbuf, uint32_t tlvtype, short tlven)
{
	short      curlen = 0;

	if (fillbuf == NULL) {
		ah_err_old("CAPWAP malloc for request %d is NULL\n", tlvtype);
		return -1;
	}

	/*fill the type*/
	*(uint32_t *) fillbuf = htonl(tlvtype);
	curlen = curlen + sizeof(uint32_t);

	/*fill the length*/
	*(short *)(fillbuf + curlen) = htons(tlven);
	curlen = curlen + sizeof(short);

	return 0;

}

/***************************************************************************
 *
 * Function:  ah_capwap_fillstramac
 *
 * Purpose:   fill the MAC
 *
 * Inputs:    stramac: the packet for fill mac
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillstramac(ah_capwap_radiomac_t *stramac)
{
	/*
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |    Length     |                  MAC Address
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	int8_t    maclen = AH_CAPWAP_MAC_LEN ;
	char      macadd[AH_CAPWAP_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	int      macaddlen = 0;

	if (stramac == NULL) {
		ah_err_old("CAPWAP fill stramac buffer is null\n");
		return -1;
	}

	stramac->len = maclen;

	/*use the setting value instead of memcpy*/
	while (macaddlen < AH_CAPWAP_MAC_LEN) {
		*(((char *)&stramac->mac) + macaddlen) = (char)macadd[macaddlen];
		macaddlen ++;
	}
	return 0;

}

/***************************************************************************
 *
 * Function:  ah_capwap_fillstaeroinfo
 *
 * Purpose:   fill the radio info
 *
 * Inputs:    staeroinfo: the packet for fill radio infor
 *
 * Output:    len: the information's len
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillstaeroinfo(ah_capwap_wireless_info_t *staeroinfo, short *len)
{
	/*
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  Wireless ID  |    Length     |             Data
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	int8_t    wirelessid = 1;
	char      wirelessdata[] = {'2', '2'};
	char      datalen = 0;

	if (staeroinfo == NULL) {
		ah_err_old("CAPWAP fill staeroinfo buf is null\n");
		return -1;
	}

	staeroinfo->wbid = wirelessid;
	staeroinfo->len = ah_strlen(wirelessdata);
	ah_memcpy(&staeroinfo->data, wirelessdata, ah_strlen(wirelessdata));
	/*
	   while (datalen < ah_strlen(wirelessdata)){
	 *(((char *)&staeroinfo->data)+datalen) = wirelessdata[datalen];
	 datalen ++;
	 }*/
	*len = datalen;
	return 0;

}

/***************************************************************************
 *
 * Function:  ah_capwap_filleventopt
 *
 * Purpose:   fill the event packt optional TLV
 *
 * Inputs:    option: the packet for fill optional
 *            capwapstate: current capwap state
 *
 * Output:    optlen: the optional's len
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_filleventopt(char *option, uint32_t *optlen, uint32_t capwapstate)
{
	uint32_t    curopt = 0;
	uint32_t    curlen = 0;
	uint32_t    totlelen = 0;

	if (option == NULL) {
		ah_err_old("CAPWAP:the fillopt options is null!\n");
		ah_assert(0);
		return -1;
	}

	/*the totle number for capwap event packet option*/
	ah_capwap_para.capwap_number.event_opt_num = sizeof(capwapeventopt) / sizeof(capwapeventopt[0]);

	for (curopt = 0; curopt < ah_capwap_para.capwap_number.event_opt_num; curopt++) {
		if (capwapeventopt[curopt].state != capwapstate) {
			continue;
		}

		if (capwapeventopt[curopt].ah_filleventopt_callback(option + totlelen, &curlen) == -1) {
			ah_err_old("CAPWAP:fill option in discovery failed!\n");
			return -1;
		}
		if (curlen <= 0) {
			ah_err_old("CAPWAP:fill len in discovery failed!%d\n", curlen);
			return -1;
		}

		totlelen = totlelen + curlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;/*6 is Tyep and Len, curlen is Value*/
	}

	*optlen = totlelen;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fill_event
 *
 * Purpose:   fill the event packet
 *
 * Inputs:    optbuff: the packet for fill optional
 *
 * Output:    optlen: the optional's len
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fill_event(char *optbuf, uint32_t *optlen)
{
	int      i = 0;
	int      event_req_num = 0;
	uint32_t    curlen = 0;
	uint32_t    totlelen = 0;

	if (optbuf == NULL) {
		ah_err_old("CAPWAP:event packet buffer is NULL!\n");
		return -1;
	}

	/*read the buff will be send*/
	i = ah_capwap_pkt_buff.send_index;

	/*only first fragment need add the standart options*/
	if (ah_capwap_pkt_buff.event_pkt[i].frag_offset == 0) {
		event_req_num =  sizeof(capwap_event_request) / sizeof(capwap_event_request[0]);
		/*fill the pre-requisite option*/
		for (i = 0; i < event_req_num; i++) {
			if (capwap_event_request[i].ah_fill_event_reuqest_callback(optbuf + totlelen, &curlen) == -1) {
				ah_err_old("CAPWAP:fill option in event request failed!\n");
				return -1;
			}

			if (curlen <= 0) {
				ah_err_old("CAPWAP: fill len in event request failed!%d\n", curlen);
				return -1;
			}

			totlelen = totlelen + curlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
		}
	}

	i = ah_capwap_pkt_buff.send_index;
	/*if is a unavlb packet, ignor it*/
	if (ah_capwap_pkt_buff.event_pkt[i].msg_avlb == AH_CAPWAP_EVENT_PKT_UNAVLB) {
		return 0;
	}

	/*fill the event buffer option*/
	if (ah_capwap_filltlv_head(optbuf + totlelen, ah_capwap_pkt_buff.event_pkt[i].msg_type, ah_capwap_pkt_buff.event_pkt[i].msg_len) == -1) {
		ah_err_old("CAPWAP:fill event head(msg_type:%d,msg_len:%d) failed!\n", ah_capwap_pkt_buff.event_pkt[i].msg_type,
				   ah_capwap_pkt_buff.event_pkt[i].msg_len);
		return -1;
	}
	totlelen =  totlelen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	if ((totlelen + ah_capwap_pkt_buff.event_pkt[i].msg_len) > AH_CAPWAP_BUF_LEN) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: the messge len exceed the max len:%d, current len is:%d\n", AH_CAPWAP_BUF_LEN,
				   totlelen + ah_capwap_pkt_buff.event_pkt[i].msg_len);
		return -1;
	}
	memcpy((optbuf + totlelen), ah_capwap_pkt_buff.event_pkt[i].msg, ah_capwap_pkt_buff.event_pkt[i].msg_len);
	/*save the send_times*/
	ah_capwap_pkt_buff.event_pkt[i].snd_times++ ;

	/*calculator the total length*/
	*optlen = totlelen + ah_capwap_pkt_buff.event_pkt[i].msg_len;

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_fillopt
 *
 * Purpose:   fill the packt optional TLV
 *
 * Inputs:    option: the packet for fill optional
 *            capwapstate: current capwap state
 *
 * Output:    optlen: the optional's len
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt(char *option, uint32_t *optlen, uint32_t capwapstate, uint32_t packettype)
{
	uint32_t    curopt = 0;
	uint32_t    curlen = 0;
	uint32_t    totlelen = 0;
	int         res = 0;

	if (option == NULL) {
		ah_err_old("CAPWAP the options buffer is null!\n");
		ah_assert(0);
		return -1;
	}
	/*the totle number for capwap packet options*/
	ah_capwap_para.capwap_number.option_num = sizeof(capwapopt) / sizeof(capwapopt[0]);

	/*the event packet is special, so need deal with it alone*/
	if (capwapstate == AH_CAPWAP_RUN && ah_capwap_info.event == AH_CAPWAP_SND_EVENT && packettype == AH_CAPWAP_EVENT_REQUEST) {
		ah_dbg_old(capwap_info, "Event message need be filled!\n");
		if (ah_capwap_fill_event(option, optlen) == -1) {
			ah_err_old("CAPWAP: fill event packet failed!\n");
			return -1;
		}
		return 0;
	}

	for (curopt = 0; curopt < ah_capwap_para.capwap_number.option_num; curopt++) {
		curlen = 0;
		if (capwapopt[curopt].wtpstate != capwapstate
			|| capwapopt[curopt].opttype != packettype) {
			continue;
		}
		res = capwapopt[curopt].ah_fillopt_callback(option + totlelen, &curlen);
		if (res == -1) {
			ah_err_old("CAPWAP: fill option in discovery failed!\n");
			return -1;
		} else if (res == AH_CAPWAP_SKIP_THIS_ATTRIBUTE) {
			totlelen = totlelen + curlen;/* skip this attribute, not include the length of the TYPE and LENGTH  */
		} else {
			/*curlen equaling to zero is permitted*/
			totlelen = totlelen + curlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;/*6 is Tyep and Len, curlen is Value*/
		}
	}

	*optlen = totlelen;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_pkt_need_fragment
 *
 * Purpose:   check the packet need fragment or not
 *
 * Inputs:    void
 *
 * Output:    lst_pkt:  is last pkt or not
 *            frag_id:  frag id
 *            frag_offset: frag offset
 *
 * Returns:    0 success, otherwise -1
 *
 **************************************************************************/
int32_t ah_capwap_pkt_need_fragment(int *lst_pkt, short *frag_id, short *frag_offset)
{
	if (ah_capwap_info.event == AH_CAPWAP_SND_EVENT) {
		if (ah_capwap_pkt_buff.event_pkt[ah_capwap_pkt_buff.send_index].msg_frag == 1) {
			if (ah_capwap_pkt_buff.event_pkt[ah_capwap_pkt_buff.send_index].msg_last == 1) {
				*lst_pkt = 1 ;
			}
			*frag_id = ah_capwap_pkt_buff.event_pkt[ah_capwap_pkt_buff.send_index].frag_id;
			*frag_offset = ah_capwap_pkt_buff.event_pkt[ah_capwap_pkt_buff.send_index].frag_offset;

			return 0;
		}
	}

	return -1;

}

/***************************************************************************
 *
 * Function:  ah_capwap_get_tz_info
 *
 * Purpose:   get current box time zone information
 *
 * Inputs:    void
 *
 * Output:    tz_info: time zone information
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static inline int ah_capwap_get_tz_info(char *tz_info)
{
	/*fill flags*/
	/* 1 bytes (2 bite is daylight save tie, the last 6 bite is timezone)
	   0 1 2 3 4 5 6 7 8
	   +---------------+
	   +dst|    tz     +
	   +---------------+
	 */
#define AH_CAPWAP_TIMEZONE_OFFSET 13
	int      tmzn = 0;
	char      daylight = 0;
	char      fill_flag = 0;
	time_t tm = time(NULL);

	if (ah_tpa_ntp_get_timezone(&tmzn, NULL) != 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP:get current time zone value failed.");
	}

	/*use this flag to indicate current time zone (1 - 25)*/
	fill_flag = (char)(tmzn + AH_CAPWAP_TIMEZONE_OFFSET);
	/*get daylight save time flag*/
	tzset();
	daylight = (char)(localtime(&tm)->tm_isdst);
	fill_flag = (daylight << 6) | (fill_flag);
	*tz_info = fill_flag;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillpacket
 *
 * Purpose:   fill the capwap packet
 *
 * Inputs:    buff: capwap buff
 *            packettype:  capwpa packet type
 *            capwapstate: current capwap state
 *
 * Output:    packetlen: the capwap packet len
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillpacket(char *buf, uint32_t *packetlen, uint32_t packettype, uint32_t capwapstate, uint seq_num)
{
	/*
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Preamble     |  HLEN   |  RID    |   WBID  |T|F|L|W|M|K|Flags|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |          Fragment ID                Frag Offset         |Rsvd |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                          (optional) Radio MAC Address         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                       (optional) Wireless Specific Information|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                                               Payload ....    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
#define AH_CAPWAP_CTRL_MSG_HEAD_LEN 12
#define AH_CAPWAP_HDR_PREAM_TYPE 0  /*in capwap hdr, this field is always 0*/
#define AH_CAPWAP_HLEN_OFFSET 19
#define AH_CAPWAP_RID_OFFSET  14
#define AH_CAPWAP_VER_OFFSET  28
#define AH_CAPWAP_TYPE_OFFSET 24
#define AH_CAPWAP_WBID_OFFSET 9
#define AH_CAPWAP_FRAG_OFFSET 7
#define AH_CAPWAP_LAST_OFFSET 6
#define AH_CAPWAP_RSVD_OFFSET 3
#define AH_CAPWAP_MAX_SEQ_NUM 255
	int32_t    verin = AH_CAPWAP_VERSION << AH_CAPWAP_VER_OFFSET;
	int32_t    rid = 200;
	int32_t    flagt = 0;
	int32_t    flagf = 0;
	int32_t    flagl = 0;
	int32_t    flagw = 0;
	int32_t    flagm = 0;
	int32_t    flags = 0;
	int32_t    flagk = 0;
	int32_t    baseinfo = 0;
	int16_t    fragid = 0;
	int16_t    offset_rsvd = 0;
	uint32_t    type = 0;
	uint32_t    wbid = 200;
	uint32_t    headlen = 0;
	uint32_t    optlen = 0;
	uint32_t    colmsgtype = 0;
	uint32_t    timestamp = 0;
	uint32_t    curlen = 0;
	uint32_t    msglenstart = 0;
	//ah_short_t dismsgheadlen = 0;
	short      msgheadlen = 0;
	char      msgheadflag = 0;
	struct timeval tv ;
	struct timezone tz ;

	if (buf == NULL) {
		ah_err_old("CAPWAP: packet buf is null \n");
		return -1;
	}
	/*add capwap hdr type*/
	type = AH_CAPWAP_HDR_PREAM_TYPE << AH_CAPWAP_TYPE_OFFSET;

	/*get RID & WBID from dcd*/
	if (ah_dcd_lib_init() < 0) {
		ah_err_old("%s: dcd lib init failed.", __func__);
	}
	rid = ah_dcd_get_radio_id();
	wbid = ah_dcd_get_wbid();
	rid = rid << AH_CAPWAP_RID_OFFSET;
	wbid = wbid << AH_CAPWAP_WBID_OFFSET;

	if (ah_capwap_pkt_need_fragment(&flagl, &fragid, &offset_rsvd) == 0) {
		flagf = 1 << AH_CAPWAP_FRAG_OFFSET;
		if (flagl == 1) { /*the last packet fragment*/
			flagl = 1 << AH_CAPWAP_LAST_OFFSET;
		}
		offset_rsvd = offset_rsvd << AH_CAPWAP_RSVD_OFFSET;
	}

	/*fill |Version|type|RID|WBID|T|F|L|W|M|K| Flags */
	baseinfo = verin | type | rid | wbid | flagt | flagf | flagl | flagw | flagm | flagk | flags ;
	curlen = sizeof(uint32_t);/*save the baseinfo address*/

	/*set the fragment id*/
	*(short *)(buf + curlen) = htons(fragid);
	curlen = curlen + sizeof(short);

	/*set the fragmet offset and rsvd*/
	*(short *)(buf + curlen) = htons(offset_rsvd);
	curlen = curlen + sizeof(short);

	/*fill Control Message Infor include Option*/
	//colmsgtype = (AH_CAPWAP_IANA_AEROHIVE * 256) + packettype;
	colmsgtype = packettype;
	*(uint32_t *)(buf + curlen) = htonl(colmsgtype);
	curlen = curlen + sizeof(uint32_t);

	/*if seq_num != AH_CAPWAP_PKT_RQST_SEQ, that is the response packet to HM.*/
	if (seq_num == AH_CAPWAP_PKT_RQST_SEQ) {
		if (ah_capwap_para.seq_num >= AH_CAPWAP_MAX_SEQ_NUM) {
			ah_capwap_para.seq_num = 0;
		} else {
			ah_capwap_para.seq_num ++;
		}
		*(int8_t *)(buf + curlen) = ah_capwap_para.seq_num;
	} else {
		*(int8_t *)(buf + curlen) = (int8_t)(seq_num);
	}

	/*save the seq_num to event packet*/
	if (packettype == AH_CAPWAP_EVENT_REQUEST) {
		ah_capwap_pkt_buff.event_pkt[ah_capwap_pkt_buff.send_index].msg_id = ah_capwap_para.seq_num;
		ah_dbg_old(capwap_info, "Event message index %d msg_id is %d\n", ah_capwap_pkt_buff.send_index, ah_capwap_para.seq_num);
	}
	curlen = curlen + sizeof(int8_t);

	msglenstart = curlen;/*save the start place to set msg element lenght*/
	/*fill flags*/
	curlen = curlen + sizeof(short);/*the len of Msg element lenght*/

	ah_capwap_get_tz_info(&msgheadflag);
	*(int8_t *)(buf + curlen) = msgheadflag;
	curlen = curlen + sizeof(uint8_t);

	/*fill time stamp*/
	gettimeofday(&tv, &tz);
	timestamp = tv.tv_sec;
	*(uint32_t *)(buf + curlen) = htonl(timestamp);
	curlen = curlen + sizeof(uint32_t);
	/*fill options*/
	if (packettype == AH_CAPWAP_CHGSTATE_EVENT_RESPONSE || packettype == AH_CAPWAP_CHGSTATE_EVENT_REQUEST) {
		if (ah_capwap_filleventopt((char *)(buf + curlen), &optlen, capwapstate) == -1) {
			ah_err_old("CAPWAP:fill event option failed!\n");
			return -1;
		}
	} else if (ah_capwap_fillopt((char *)(buf + curlen), &optlen, capwapstate, packettype) == -1) {
		ah_err_old("CAPWAP:fill option failed!\n");
		return -1;
	}

	/*fill the msg element length*/
	msgheadlen = (short)optlen + AH_CAPWAP_CTRL_MSG_HEAD_LEN - sizeof(uint32_t) - sizeof(int8_t);
	*(short *)(buf + msglenstart) = htons(msgheadlen);

	headlen = AH_CAPWAP_TRANS_HEAD_LEN; /*transport head this must be chang (is 4 bytes words)*/

	/*transport head this must be chang (is 4 bytes words)*/
	//headlen = headlen / 4;

	/*set the hlen for 9 - 13 bites*/
	baseinfo = ((( headlen << AH_CAPWAP_HLEN_OFFSET ) & 0x007c0000) | baseinfo);

	/*set the 0 -31 fixed part*/
	*(int32_t *)buf = htonl(baseinfo);

	*packetlen = headlen + ( optlen + AH_CAPWAP_CTRL_MSG_HEAD_LEN);/* 12 is Control Message Head Len*/
	ah_dbg_old(capwap_info, "the totle len is %d, col msg head len is %d, options len is %d\n", *packetlen, headlen, optlen);

	if (capwap_packet) {
		ah_hexdump((uchar *)buf, *packetlen);
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_packet_client
 *
 * Purpose:   read fill the capwap packet
 *
 * Inputs:    capwapbuf: capwap buff
 *            packettype:  capwpa packet type
 *            capwapstate: current capwap state
 *
 * Output:    packetlen: the capwap packet len
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int  ah_capwap_packet_client(char *capwapbuf, uint32_t *packlen, uint32_t packettype, uint32_t capwapstate,
							 uint      seq_num)
{
	uint32_t    bufheadlen = 0;
	int      rtn = 0;

	if (capwapbuf == NULL) {
		ah_err_old("CAPWAP: capwap buffer is null!\n");
		return -1;
	}

	rtn = ah_capwap_fillpacket(capwapbuf, &bufheadlen, packettype, capwapstate, seq_num);
	if (rtn < 0 ) {
		ah_err_old("CAPWAP: fill packet failed!(header len:%d)\n", bufheadlen);
		return -1;
	}

	if (bufheadlen <= 0) {
		ah_err_old("CAPWAP:packet len is 0 !%d\n", bufheadlen);
		return -1;
	}
	*packlen = bufheadlen;
	return 0 ;
}

/*DEFINE SOME MACRO FOR FILL OPTIONS*/
#define AH_CAPWAP_TLV_LEN 2
#define WTP_MEMORY_DUMP 2

/*********************************************fill options*******************************************************/
/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_discoverytype
 *
 * Purpose:   fill Discovery Type 4.4.18
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_discoverytype(char *fillbuf, uint32_t *filllen)
{
#define AC_UNKNOW 0

	short      len = 0;
	char      discotype = (char)AC_UNKNOW;
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(char);
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, DISCOVERY_TYPE, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed!(type:DISCOVERY_TYPE)\n");
		return -1;
	}

	/*fill the value*/
	*(char *)(fillbuf + curlen) = discotype;

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_is_cli_failed
 *
 * Purpose:   Get weather the CLI failed or not.
 *
 * Inputs:    N/A
 *
 * Output:    cli_failed
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static int ah_capwap_is_cli_failed(char *cli_failed)
{
	int      rc = 0;
#if 0
	static char failed = 0;
	static int call_once = 0;

	if (call_once == 0) {
		if (access(AH_CONF_FAILED_CLI_FILE, F_OK)) {
			if (errno == ENOENT) {
				failed = (char)0;
				call_once = 1;
			} else {
				ah_err_old("failed when try to access %s", AH_CONF_FAILED_CLI_FILE);
				rc = -1;
				goto out;
			}
		} else {
			failed = (char)1;
			call_once = 1;
		}
	}

	*cli_failed = failed;

out:
#endif
	return rc;
}

#define AH_CAPWAP_MAX_VER_STR_LEN (256)
/***************************************************************************
 *
 * Function:  ah_capwap_get_sw_string
 *
 * Purpose:   get hiveAP software string
 *
 * Inputs:    void
 *
 * Output:    sw_ver: the software version string
 *
 * Returns:   0 success, otherwise -1
 *
**************************************************************************/
#define AH_CAPWAP_FORMAT_PRINT_(n)  "%" #n "s"
#define AH_CAPWAP_FORMAT_PRINT(n)   AH_CAPWAP_FORMAT_PRINT_(n)
int ah_capwap_get_sw_string(char *sw_ver)
{
#ifndef AH_VERSION_FILE
#define AH_VERSION_FILE "/opt/ah/etc/version"
#endif
	FILE *fp = NULL;
	char      line[AH_CAPWAP_MAX_VER_STR_LEN] = {0};
	char      ver_type[AH_MAX_STR_PARM_LEN] = {0};
	char      os_info[AH_MAX_STR_PARM_LEN] = {0};
	int      rc = -1;
	char      *pos = NULL;

	fp = fopen(AH_VERSION_FILE, "r");
	if (fp == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: can not open OS version file:%s\n", AH_VERSION_FILE);
		goto FINISH;
	}

	while (fgets (line, (AH_CAPWAP_MAX_VER_STR_LEN - 1), fp)) {
		sscanf(line, AH_CAPWAP_FORMAT_PRINT(AH_MAX_STR_PARM_LEN) " " AH_CAPWAP_FORMAT_PRINT(AH_MAX_STR_PARM_LEN), ver_type, os_info);
		ver_type[AH_MAX_STR_PARM_LEN - 1] = 0;
		os_info[AH_MAX_STR_PARM_LEN - 1] = 0;
		if (strcasecmp(ver_type, "version:") == 0 && ah_strlen(os_info) > 0) {
			/*strstr return no-null pointer because "os_info" get from "line"*/
			pos = strstr(line, os_info);
			if (pos == NULL) {
				ah_log_old(AH_LOG_INFO, "CAPWAP:get device software version string failed\n");
				break;
			} else {
				ah_snprintf(sw_ver, (AH_CAPWAP_MAX_VER_STR_LEN - 1), pos);
				strtok(sw_ver, "\n"); /*remove unused '\n'*/
				ah_log_old(AH_LOG_INFO, "CAPWAP:get device software version string:(%s)\n", sw_ver);
				rc = 0;
				break;
			}
		}
	}

FINISH:
	if (fp != NULL) {
		fclose(fp);
	}

	return rc;

}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpdescr
 *
 * Purpose:   WTP Descriptor 4.4.33
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpdescr(char *fillbuf, uint *filllen)
{
	/*
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |   Max Radios  | Radios in use |    Encryption Capabilities    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                       Vendor Identifier                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |         Type=0                |            Length             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                          Value...                             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
#define AH_CAPWAP_IANA_AEROHIVE AH_OEM_VENDOR_ID
#define AH_CAPWAP_VER_LEN 20
#define AH_CAPWAP_HW_MOD_LEN 13
	char maxradio = 200;
	char radioinuse = (char)2;
	short encryenable = 0;
	uint vendorid = AH_CAPWAP_IANA_AEROHIVE;
	short vendortype = 0;
	char *vendorvalue = AH_OEM_NAME;
	short vendorlen = ah_strlen(vendorvalue);
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	short len = 0;
	uint8_t swver[AH_CAPWAP_VER_LEN] = "1.0.0.1";
	uint8_t hwver[AH_CAPWAP_VER_LEN] = "1.0.0.1";
	char wtpsn[AH_CAPWAP_WTP_SN_LEN] = "11111111111111";
	char hw_mod[AH_CAPWAP_HW_MOD_LEN] = {0};
	uint cfg_ver = 0;
	uint up_second = 0;
	uint up_usecond = 0;
	char sw_ver_str[AH_CAPWAP_MAX_VER_STR_LEN];
#if (AH_IS_HAS_HWINFO)
	ah_hwinfo_t hw_info;
#endif

	/*get swver & hwver from scd*/
	uint ver = 0;
	uint l7_ver = 0;/*used for l7d*/

	ah_scd_get_sw_ver((int *)(&ver));
	ah_capwap_ver(ver, swver);

	ah_scd_get_hw_ver((int *)(&ver));
	ah_capwap_ver(ver, hwver);
	(void)ah_hw_get_board_serial_number(wtpsn, AH_CAPWAP_WTP_SN_LEN);
	if ((strlen(wtpsn) == 0) || (wtpsn[0] == ' ')) {
		ah_log_old(AH_LOG_ERR, "CAPWAP get box SN error!\n");
	}
	ah_dbg_old(capwap_info, "CAPWAP get box SN from SCD is %s\n", wtpsn);

	/*get the Max Radios & Radios in use & Encryption Capabilities*/
	maxradio = ah_dcd_get_max_radios();
	radioinuse = ah_dcd_get_radio_in_use();
	encryenable = ah_dcd_get_encrypt_cap();

	/*get HiveAP software version string*/
	if (ah_capwap_get_sw_string(sw_ver_str) == -1) {
		strcpy(sw_ver_str, "Unknown");
	}

#if (AH_IS_HAS_HWINFO)
	memset(&hw_info, 0, sizeof(hw_info));
	ah_hw_read_hw_info((uint8_t *)&hw_info, sizeof(hw_info));
	/* hw_info.product_name may be not include '\0' */
	ah_assert(sizeof(hw_info.product_name) < sizeof(hw_mod));
	memcpy(hw_mod, hw_info.product_name, sizeof(hw_info.product_name));
	ah_dbg_old(capwap_info, "CAPWAP GET WTP HW module from SCD is %s\n", hw_mod);
#endif
	len = sizeof(short) * 7 + sizeof(char) * 2 + sizeof(uint) * 3 + strlen(vendorvalue) + strlen((char *)swver) + strlen((char *)hw_mod);
	len = len + sizeof(short) * 2 + sizeof(uint) + AH_CAPWAP_WTP_SN_LEN - 1 + sizeof(short) * 2 + sizeof(uint) * 2 + sizeof(short) * 2 + sizeof(
			  uint) * 2 ;
	len = len + sizeof(short) * 2 + sizeof(uint) * 2;
	len = len + sizeof(short) * 2 + sizeof(uint) + strlen(sw_ver_str);
	len = len + sizeof(short) * 2 + sizeof(uint) * 2;

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_DESCRIPTOR, len) == -1) {
		ah_err_old("CAPWAP: fill tlv head failed! ,(type:WTP_DESCRIPTOR)\n");
		return -1;
	}

	/*fill the value*/
	*(char *)(fillbuf + curlen) = maxradio;
	curlen = curlen + sizeof(char);
	*(char *)(fillbuf + curlen) = radioinuse;
	curlen = curlen + sizeof(char);
	*(short *)(fillbuf + curlen) = htons(encryenable);
	curlen = curlen + sizeof(short);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	memcpy(fillbuf + curlen, vendorvalue, strlen(vendorvalue) );
	curlen = curlen + strlen(vendorvalue);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 4;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = strlen((char *)hw_mod);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	memcpy(fillbuf + curlen, hw_mod, strlen((char *)hw_mod) );
	curlen = curlen + strlen((char *)hw_mod);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 5;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = strlen((char *)swver);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	memcpy(fillbuf + curlen, swver, strlen((char *)swver) );
	curlen = curlen + strlen((char *)swver);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 1;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = AH_CAPWAP_WTP_SN_LEN - 1;
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	memcpy(fillbuf + curlen, wtpsn, AH_CAPWAP_WTP_SN_LEN - 1);
	curlen = curlen + AH_CAPWAP_WTP_SN_LEN - 1;
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 20;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = sizeof(uint);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	ah_scd_get_config_version(&cfg_ver);
	ah_dbg_old(capwap_info, "Get CLI configuration version:%d\n", cfg_ver);
	*(uint *)(fillbuf + curlen) = htonl(cfg_ver);
	curlen = curlen + sizeof(uint);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 21;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = sizeof(uint);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	*(uint *)(fillbuf + curlen) = htonl(ah_capwap_info.acip);
	curlen = curlen + sizeof(uint);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 22;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = sizeof(uint);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	(void)ah_get_system_uptime(&up_second, &up_usecond);
	*(uint *)(fillbuf + curlen) = htonl(up_second);
	curlen = curlen + sizeof(uint);
	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);

	vendortype = 23;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = strlen(sw_ver_str);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);
	memcpy(fillbuf + curlen, sw_ver_str, strlen(sw_ver_str));
	curlen = curlen + strlen(sw_ver_str);

	*(uint *)(fillbuf + curlen) = htonl(vendorid);
	curlen = curlen + sizeof(uint);
	vendortype = 24;
	*(short *)(fillbuf + curlen) = htons(vendortype);
	curlen = curlen + sizeof(short);
	vendorlen = sizeof(int);
	*(short *)(fillbuf + curlen) = htons(vendorlen);
	curlen = curlen + sizeof(short);

#ifdef AH_L7_SUPPORT
	l7_ver = (uint)ah_l7d_get_signature_version();
#endif
	*(uint *)(fillbuf + curlen) = htonl(l7_ver);
	curlen = curlen + sizeof(uint);

	/*if need add other item, we need add vendorid*/
	/*
	 *(uint32_t *)(fillbuf + curlen) = htonl(vendorid);
	 curlen = curlen + sizeof(uint32_t);
	 */

	*filllen = len;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpframmod
 *
 * Purpose:   fill WTP Frame Tunnel Mode 4.4.35
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpframmod(char *fillbuf, uint32_t *filllen)
{
#define WTP_FRAME_TUNNEL_ALL 7

	char      frametunmod = (char)WTP_FRAME_TUNNEL_ALL;
	short      len = 0;
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(char);
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_FRAME_TUNNEL_MOD, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_FRAME_TUNNEL_MOD)\n");
		return -1;
	}

	/*fill value*/
	*(char *)(fillbuf + curlen) = frametunmod;

	*filllen = len;
	return 0;
}

uint ah_capwap_get_wtpip(int af, ah_ipaddr46_t *host_ip)
{
	ah_set_ipaddr46_all_zero(host_ip);
	if (af == AF_INET) {
		host_ip->af = AF_INET;
		if (capwap_mgt0_ip == 0) {
			host_ip->u_ipv4 = ah_tpa_get_current_mgt_ip();
			capwap_mgt0_ip = host_ip->u_ipv4;
		} else {
			host_ip->u_ipv4 = capwap_mgt0_ip;
		}
		return 0;
	} else if (af == AF_INET6) {
		host_ip->af = AF_INET6;
		if (ah_is_ipaddr46_all_zero(&capwap_mgt0_ipv6)) {
			struct in6_addr ipv6_address;
			if (ah_tpa_get_mgt0_global_ipv6_addr(&ipv6_address) != 0) {
				ah_err_old("CAPWAP: get mgt0 ipv6 address from SCD failed.");
				return -1;
			}
			memcpy(&host_ip->u_ipv6_addr, &ipv6_address, sizeof(struct in6_addr));
			memcpy(&capwap_mgt0_ipv6.u_ipv6_addr, &ipv6_address, sizeof(struct in6_addr));
		} else {
			memcpy(&host_ip->u_ipv6_addr, &capwap_mgt0_ipv6.u_ipv6_addr, sizeof(struct in6_addr));
		}
		return 0;
	} else {
		return -1;
	}
}
/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpipv4addr
 *
 * Purpose:   fill WTP IPV4 IP ADDRESS 4.4.36
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpipv4addr(char *fillbuf, uint *filllen)
{
	ah_ipaddr46_t wtpip;
	short len = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(uint);
	/*get ipv4 form scd*/
	if (ah_capwap_get_wtpip(AF_INET, &wtpip) != 0) {
		ah_err_old("CAPWAP:Get AP IP address error!\n");
		return -1;
	}
	if (wtpip.u_ipv4 == 0) {
		ah_err_old("CAPWAP:Get wtpipv4 IP error!\n");
		return -1;
	}

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_IPV4_IPADDRESS, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_IPV4_IPADDRESS)\n");
		return -1;
	}

	/*fill value, wtpipv4add is network order*/
	*(uint *)(fillbuf + curlen) = wtpip.u_ipv4;
	*filllen = len;
	return 0;
}
int ah_capwap_fillopt_wtpipv6addr(char *fillbuf, uint *filllen)
{
	ah_ipaddr46_t wtpip;
	short len = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	len = sizeof(struct in6_addr);
	if (ah_capwap_get_wtpip(AF_INET6, &wtpip) != 0) {
		ah_err_old("CAPWAP:Get AP IP address error!\n");
		return -1;
	}
	if (ipv6_addr_is_all_zero(&wtpip.u_ipv6_addr) ) {
		ah_dbg_old(capwap_info, "CAPWAP:Get wtpipv6 IP zero!\n");
	}
	ah_dbg_old(capwap_info, "CAPWAP GET WTP IPV6 address is %pI46c\n", &wtpip);
	if (ah_capwap_filltlv_head(fillbuf, WTP_IPV6_IPADDRESS, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_IPV6_IPADDRESS)\n");
		return -1;
	}
	memcpy(fillbuf + curlen, &wtpip.u_ipv6_addr, len);

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpmactype
 *
 * Purpose:   fill WTP MAC Type 4.4.37
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpmactype(char *fillbuf, uint32_t *filllen)
{
#define WTP_MAC_BOTH 2

	char      wtpmactype = (char)WTP_MAC_BOTH;
	short      len = 0;
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(char);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_MAC_TYPE, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_MAC_TYPE)\n");
		return -1;
	}

	/*fill value*/
	*(char *)(fillbuf + curlen) = wtpmactype;

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpname
 *
 * Purpose:   fill WTP Name 4.4.41
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpname(char *fillbuf, uint32_t *filllen)
{
	char      wtpname[MAX_WTP_NAME_LEN] = {"wtp"};
	short      len = 0;
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get WTP_NAME from scd*/
	ah_tpa_get_hostname(wtpname);

	len = ah_strlen(wtpname) ;
	if (len == 0) {
		ah_strcpy(wtpname, "wtp");
		len = ah_strlen(wtpname);
	}
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_NAME, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_NAME)\n");
		return -1;
	}

	/*fill value*/
	ah_memcpy(fillbuf + curlen, wtpname, ah_strlen(wtpname));

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpmac
 *
 * Purpose:   fill WTP MAC 5000
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpmac(char *fillbuf, uint32_t *filllen)
{
#define AH_CAPWAP_MACADDR_LEN 6
	char      wtpmac[AH_CAPWAP_MACADDR_LEN] = { 0 };
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get WTP MAC from dcd*/
	ah_dcd_get_mac_byname(AH_CAPWAP_MGT, wtpmac);
	ah_dbg_old(capwap_info, "CAPWAP GET WTP MAC FROM DCD IS %m\n", wtpmac);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_MAC, AH_CAPWAP_MACADDR_LEN) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_MAC)\n");
		return -1;
	}

	/*fill value*/
	ah_memcpy(fillbuf + curlen, wtpmac, AH_CAPWAP_MACADDR_LEN);

	*filllen = AH_CAPWAP_MACADDR_LEN ;
	ah_memcpy(ah_capwap_info.wtpmac, wtpmac, AH_CAPWAP_MACADDR_LEN);
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpmask
 *
 * Purpose:   fill WTP MASK 5001
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpmask(char *fillbuf, uint *filllen)
{
	uint wtp_mask = 0;
	uint wtp_ip = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get WTP MASK from dcd*/
	if (ah_dcd_get_addr_byname(AH_CAPWAP_MGT, (uint *)&wtp_ip, (uint *)&wtp_mask) < 0) {
		ah_err_old("CAPWAP:Get mask from DCD error!\n");
		return -1;
	}
	ah_dbg_old(capwap_info, "CAPWAP GET WTP MASK FROM DCD IS %i\n", wtp_mask);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_MASK, sizeof(uint)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_MASK)\n");
		return -1;
	}

	/*fill value*/
	/*wtp_mask is network order*/
	*(uint *)(fillbuf + curlen) = wtp_mask;

	*filllen = sizeof(uint);
	return 0;
}

int ah_capwap_fillopt_wtp_prefix(char *fillbuf, uint *filllen)
{
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	ah_if_ipv6_addr_t global_if_ipv6_addr;
	memset(&global_if_ipv6_addr, 0, sizeof(ah_if_ipv6_addr_t));
	if (ah_get_if_ipv6_global_addrs_by_name(default_hvi_name(), &global_if_ipv6_addr) != 0) {
		ah_dbg_old(capwap_info, "CAPWAP: get box ipv6 address and mask from kernal failed.\n");
	}
	ah_dbg_old(capwap_info, "CAPWAP GET WTP IPV6 prefix FROM kernal is %d\n", global_if_ipv6_addr.pfxlen);
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_IPV6_PREFIX, sizeof(int)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:AH_CAPWAP_WTP_IPV6_PREFIX)\n");
		return -1;
	}
	*(int *)(fillbuf + curlen) = htonl(global_if_ipv6_addr.pfxlen);
	*filllen = sizeof(int);
	return 0;
}
/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpgateway
 *
 * Purpose:   fill WTP GATEWAY 5002
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpgateway(char *fillbuf, uint *filllen)
{
	uint wtp_gateway = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get WTP GATEWAY from dcd*/
	ah_dcd_get_default_gw_byname(AH_CAPWAP_MGT, (uint *)&wtp_gateway);

	ah_dbg_old(capwap_info, "CAPWAP GET WTP GATEWAY FROM DCD IS %i\n", wtp_gateway);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_GATEWAY, sizeof(uint)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:WTP_GATEWAY)\n");
		return -1;
	}

	/*fill value*/
	/*wtp_gateway is network order*/
	*(uint *)(fillbuf + curlen) = wtp_gateway;

	*filllen = sizeof(uint);
	return 0;
}

int ah_capwap_fillopt_wtp_ipv6gateway(char *fillbuf, uint *filllen)
{
	struct in6_addr wtp_gw_ipv6;
	short len = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	memset(&wtp_gw_ipv6, 0, sizeof(struct in6_addr));
	if (ah_dcd_get_default_gw_byname_ipv6(AH_CAPWAP_MGT, &wtp_gw_ipv6) != 0) {
		ah_dbg_old(capwap_info, "CAPWAP:get IPV6 default gateway failed! ,(type:AH_CAPWAP_WTP_IPV6_GATEWAY)\n");
	}
	ah_dbg_old(capwap_info, "CAPWAP GET WTP GATEWAY FROM DCD IS %pI6c\n", &wtp_gw_ipv6);
	len = sizeof(struct in6_addr);
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_IPV6_GATEWAY, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:AH_CAPWAP_WTP_IPV6_GATEWAY)\n");
		return -1;
	}
	memcpy(fillbuf + curlen, &wtp_gw_ipv6, len);
	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_region_code
 *
 * Purpose:   fill WTP REGION CODE 5003
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_region_code(char *fillbuf, uint32_t *filllen)
{
	uint      region_code = 0;
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
#if AH_BOARD != AH_BOARD_ID_VHIVEOS && AH_BOARD != AH_BOARD_ID_AH_APPLIANCE_1
	/*get REGION CODE from dcd*/
	ah_boot_get_reg_code(&region_code);
#endif
	ah_dbg_old(capwap_info, "CAPWAP GET WTP REGION CODE FROM DCD IS %d\n", region_code);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_REGION_CODE, sizeof(uint32_t)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! ,(type:REGION CODE)\n");
		return -1;
	}

	/*fill value*/
	/*wtp_gateway is network order*/
	*(uint32_t *)(fillbuf + curlen) = htonl(region_code);

	*filllen = sizeof(uint32_t);
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_country_code
 *
 * Purpose:   fill COUNTRY CODE 5004
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_country_code(char *fillbuf, uint32_t *filllen)
{
	uint      country_code = 0;
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
#if AH_BOARD != AH_BOARD_ID_VHIVEOS && AH_BOARD != AH_BOARD_ID_AH_APPLIANCE_1
	/*get COUNTRY CODE from dcd*/
	(void)ah_boot_get_ctry_code(&country_code);
#endif
	ah_dbg_old(capwap_info, "CAPWAP GET COUNTRY CODE FROM DCD IS %d\n", country_code);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_COUNTRY_CODE, sizeof(uint32_t)) == -1) {
		ah_err_old("CAPWAP: fill tlv head failed! ,(type:COUNTRY CODE)\n");
		return -1;
	}

	/*fill value*/
	/*wtp_gateway is network order*/
	*(uint32_t *)(fillbuf + curlen) = htonl(country_code);

	*filllen = sizeof(uint32_t);
	return 0;
}

/**
 * @brief fill portal info, when update images, HM will prior to update mesh AP.
 * @param[in] fillbuf buffer to be filled
 * @param[out] filllen the len for this option
 * @return 0 success, otherwise -1
 * @note
 */
int ah_capwap_fillopt_port_info(char *fillbuf, uint *filllen)
{
	ah_ipaddr46_t port_ip;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
#if 0

	ah_set_ipaddr46_all_zero(&port_ip);
	/*get portal ip*/
	port_ip = ah_amrp_lib_who_is_my_portal();
	ah_log_old(AH_LOG_INFO, "CAPWAP: device portal ip is %pI46c\n", &port_ip);

	/* set portal info */
	if (ah_capwap_is_portal(&port_ip)) {
		ah_capwap_para.portal_info = AH_CAPWAP_IS_PORT;
	} else {
		ah_capwap_para.portal_info = AH_CAPWAP_NOT_PORT;
	}

	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_PORT_INFO, sizeof(char)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:PORTAL INFO)\n");
		return -1;
	}

	*(fillbuf + curlen) = (char)(ah_capwap_para.portal_info);

	*filllen = sizeof(char);

#endif
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_iptype
 *
 * Purpose:   fill WTP IP TYPE 5005
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_iptype(char *fillbuf, uint *filllen)
{
#define AH_CAPWAP_WTP_IP_STATIC  1
#define AH_CAPWAP_WTP_IP_DYNAMIC 2
	char ip_type = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get WTP IP TYPE from scd*/
	ip_type = ah_tpa_get_mgt_ip_status();
	ah_dbg_old(capwap_info, "CAPWAP GET MGT0 IP TYPE FROM SCD IS %d\n", ip_type);

	if (ip_type <= 0) {
		ah_err_old("CAPWAP WTP ip type is wrong:%d", ip_type);
		return 0;
	}

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_IP_TYPE, sizeof(uint8_t)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:WTP_IPTYPE)\n");
		return -1;
	}

	/*fill value*/
	if (ip_type != AH_CAPWAP_WTP_IP_DYNAMIC) {
		*(uint8_t *)(fillbuf + curlen) = AH_CAPWAP_WTP_IP_STATIC;
	} else {
#define AH_CAPWAP_PROTOCOL_IP_DYNAMIC 0  /*protocol said the dynamic is 0, but api dynamic is 2. so change it*/
		*(uint8_t *)(fillbuf + curlen) = AH_CAPWAP_PROTOCOL_IP_DYNAMIC;
	}

	*filllen = sizeof(uint8_t);
	return 0;
}
#define AH_CAPWAP_WTP_IP6_DHCP    0
#define AH_CAPWAP_WTP_IP6_AUTO    1
#define AH_CAPWAP_WTP_IP6_MANUAL  2
int ah_capwap_fillopt_ip6type(char *fillbuf, uint *filllen)
{
#if 0
	uint8_t ip_type = 0;
	uint curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	int ipv6_addr_type;
	int rc;
	rc = ah_tpa_get_ipv6_addr_type(default_hvi_name(), &ipv6_addr_type);
	if ((rc != 0) && (ipv6_addr_type != AH_IPV6_IF_NOT_EXIST)) {
		ah_err_old("get ipv6 addr type error in function %s", __func__);
		return -1;
	}
	ah_dbg_old(capwap_info, "CAPWAP GET MGT0 IPv6 TYPE FROM SCD is %d\n", ipv6_addr_type);
	if (ipv6_addr_type == AH_IPV6_ADDR_MANUAL) {
		ip_type = AH_CAPWAP_WTP_IP6_MANUAL;
	} else if (ipv6_addr_type == AH_IPV6_ADDR_AUTO) {
		ip_type = AH_CAPWAP_WTP_IP6_AUTO;
	} else if (ipv6_addr_type == AH_IPV6_ADDR_DHCP) {
		ip_type = AH_CAPWAP_WTP_IP6_DHCP;
	}
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_IPV6_TYPE, sizeof(uint8_t)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:AH_CAPWAP_WTP_IPV6_TYPE)\n");
		return -1;
	}
	*(uint8_t *)(fillbuf + curlen) = ip_type;
	*filllen = sizeof(uint8_t);
#endif
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_result_code
 *
 * Purpose:   fill result code
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_result_code(char *fillbuf, uint32_t *filllen)
{
	uint32_t    reason = 0;
	uint32_t    curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get cawpap client reconnect reason*/
	ah_capwap_get_reconnect_reason(&reason);
	ah_dbg_old(capwap_basic, "get capwap reconnect reason:%d\n", reason);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, RESULT_CODE, sizeof(uint32_t)) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:RESULT_CODE)\n");
		return -1;
	}

	*(uint32_t *)(fillbuf + curlen) = htonl(reason);

	*filllen = sizeof(uint32_t);

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_locationdata
 *
 * Purpose:   fill Location Data 4.4.25
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_locationdata(char *fillbuf, uint32_t *filllen)
{
	char      locationdata[AH_MAX_STR_256_LEN];
	short      len = 0;
	char       curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	int      rc = 0;

	/*get the location from scd*/
	ah_scd_get_locdata( AH_MAX_STR_256_LEN, locationdata);

	len = ah_strlen(locationdata) ;
	if (len == 0) {
		ah_strcpy(locationdata, "change_me");
		len = ah_strlen(locationdata);
	}
	rc = ah_capwap_move_special_char(locationdata, '"');
	if (rc == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP analyse location failed! (location:%s)\n", locationdata);
		return -1;
	}
	len = ah_strlen(locationdata);/*get the new length of location*/
	ah_dbg_old(capwap_info, "location:(%s),len:%d\n", locationdata, len);
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, LOCATION_DATA, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:LOCATION_DATA)\n");
		return -1;
	}

	/*fill value*/
	ah_memcpy(fillbuf + curlen, locationdata, len);
	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_sessionid
 *
 * Purpose:   fill Session id 4.4.29
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_sessionid(char *fillbuf, uint32_t *filllen)
{
	uint32_t    sessionid = 112;
	short      len = 0;
	char       curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(uint32_t);
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, SESSION_ID, len) == -1) {
		ah_err_old("CAPWAP: fill tlv head failed! (type:SESSION_ID)\n");
		return -1;
	}

	/*fill value*/
	*(uint32_t *)(fillbuf + curlen) = htonl(sessionid);/*this may be generated by a function*/

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpfallback
 *
 * Purpose:   fill WTP Fallback 4.4.34
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpfallback(char *fillbuf, uint32_t *filllen)
{
	char      wtpfallback = (char)0;
	short      len = 0;
	char       curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(char);
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_FALLBACK, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:WTP_FALLBACK)\n");
		return -1;
	}

	/*fill value*/
	*(char *)(fillbuf + curlen) = wtpfallback;

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_radioadminstate
 *
 * Purpose:   fill Radio Administrative State 4.4.27
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_radioadminstate(char *fillbuf, uint32_t *filllen)
{
#define RADIO_ADMIN_STATE 29
#define AH_CAPWAP_ENABLE 1

	char      radioid = 2;
	char      adminstate = AH_CAPWAP_ENABLE;
	short      len = 0;
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(char) * 3  ;

	/*get RID from dcd*/
	radioid = ah_dcd_get_radio_id();

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, RADIO_ADMIN_STATE, len) == -1) {
		ah_err_old("CAPWAP: fill tlv head failed! (type:RADIO_ADMIN_STATE)\n");
		return -1;
	}

	/*fill value*/

	*(char *)(fillbuf + curlen) = radioid;
	curlen = curlen + sizeof(char);
	*(char *)(fillbuf + curlen) = adminstate;
	curlen = curlen + sizeof(char);
	*(char *)(fillbuf + curlen) = adminstate;

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_statistical
 *
 * Purpose:   fill WTP Operational Statistics 4.6.46
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_statistical(char *fillbuf, uint32_t *filllen)
{
#define WTP_OPT_STATI 46
	char      radio_id = 0;
	char      tx_queue = 0;
	short      link = 0;
	short      len = 0;
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = sizeof(uint32_t);

	/*fill tyep and lenght*/
	if (ah_capwap_filltlv_head(fillbuf, WTP_OPT_STATI, len) == -1) {
		ah_err_old("CAPWAP:file tlv head failed!(type: WTP_OPT_STATI)\n");
		return -1;
	}

	/*fill value*/
	*(char *)(fillbuf + curlen) = radio_id;
	curlen = curlen + sizeof(char);
	*(char *)(fillbuf + curlen) = tx_queue;
	curlen = curlen + sizeof(char);
	*(short *)(fillbuf + curlen) = htons(link);

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_mgt0_hive
 *
 * Purpose:   fill current box mgt0 hive information
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_mgt0_hive(char *fillbuf, uint32_t *filllen)
{
#define AH_CAPWAP_MGT0_HIVE 5009
	char      mgt0_hive[AH_MAX_HIVEID_LEN + 1] = {0};
	short      len = 0;
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	if (ah_dcd_get_mgt0_hive(mgt0_hive) != 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: get mgt0 hive information failed.\n");
		return -1;
	}
	ah_log_old(AH_LOG_INFO, "CAPWAP: get mgt0 bind hive:%s\n", mgt0_hive);
	len = ah_strlen(mgt0_hive);

	/*fill tyep and lenght*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_MGT0_HIVE, len) == -1) {
		ah_err_old("CAPWAP:file tlv head failed!(type: WTP_OPT_STATI)\n");
		return -1;
	}

	/*fill value*/
	ah_memcpy(fillbuf + curlen, mgt0_hive, len);

	*filllen = len;
	return 0;
}

/************Start define structurefor hiveAP information to HM ********************/
typedef struct {
	uint32_t    type;
	uint16_t    len;
} __packed ah_capwap_hiveap_info_header_t;

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	uchar      transfer_mode;                          /*transfer mode for udp or tcp*/
	uint32_t    transfer_port;                         /*destination port for udp or tcp*/
	char      proxy_name[AH_MAX_STR_64_LEN + 1];     /*proxy name*/
	uint32_t    proxy_port;                            /*proxy port*/
	char      proxy_user[AH_MAX_STR_PARM_LEN + 1];     /*proxy user name*/
	char      proxy_pswd[AH_MAX_STR_PARM_LEN + 1];     /*proxy user password*/
} __packed ah_capwap_transfer_info_t;

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	uchar      indoor;
} __packed ah_capwap_ap_indoor_info_t;

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	uchar      enable;
} __packed ah_capwap_ap_pppoe_info_t;

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	uchar      br_mode;
} __packed ah_capwap_ap_br_mode_info_t;

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	uint32_t    chip_version;
} __packed ah_capwap_switch_info_t;

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	uint32_t    system_value;
} __packed ah_capwap_system_info_t;

#if (AH_SUPPORT_NETDUMP)
typedef struct {
	ah_capwap_hiveap_info_header_t header;
	int8_t    reboot_type;
	int      timestamp;
} __packed ah_capwap_reboot_info_t;
#endif

typedef struct {
	ah_capwap_hiveap_info_header_t header;
	char      hw_rev[AH_IMG_HW_REVISION_LEN + 1];
} __packed ah_capwap_hw_rev_info_t;

typedef struct {
	ah_capwap_transfer_info_t transfer_info;  /*transfer mode information*/
	ah_capwap_ap_indoor_info_t indoor_info;  /*indoor or outdoor ap*/
	ah_capwap_ap_pppoe_info_t pppoe_info;  /*pppoe info*/
	ah_capwap_ap_br_mode_info_t br_mode_info;  /*br mode info*/
	ah_capwap_switch_info_t switch_info;  /* switch chip info */
	ah_capwap_system_info_t system_info; /* system info */
#if (AH_SUPPORT_NETDUMP)
	ah_capwap_reboot_info_t reboot_info;    /*reboot info*/
#endif
	ah_capwap_hw_rev_info_t hw_rev_info;
} __packed ah_capwap_hiveap_info_t;

typedef enum {
	AH_CAPWAP_HIVEAP_TRANSFER_INFO = 1,
	AH_CAPWAP_HIVEAP_INDOOR_INFO,
	AH_CAPWAP_HIVEAP_PPPOE_INFO,
	AH_CAPWAP_HIVEAP_BR_MODE_INFO,
	AH_CAPWAP_HIVEAP_SWITCH_INFO,
	AH_CAPWAP_HIVEAP_SYSTEM_INFO,
#if (AH_SUPPORT_NETDUMP)
	AH_CAPWAP_HIVEAP_REBOOT_INFO,
#endif
	AH_CAPWAP_HIVEAP_HW_REV_INFO = 8,
} ah_capwap_hiveap_info_type_t;
/************End define structure for hiveAP information to HM********************/

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_transfer_info
 *
 * Purpose:   fill current box transfer mode information
 *
 * Inputs:    N/A
 *
 * Output:    transfer_info: current transfer information
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static int ah_capwap_fillopt_hiveap_transfer_info(ah_capwap_transfer_info_t *transfer_info)
{
	transfer_info->header.type = htonl(AH_CAPWAP_HIVEAP_TRANSFER_INFO);
	transfer_info->header.len = htons(sizeof(ah_capwap_transfer_info_t) - sizeof(ah_capwap_hiveap_info_header_t));
	/*get transfer mode and destination port*/
	transfer_info->transfer_mode = ah_capwap_get_tcp_status();
	transfer_info->transfer_port = htonl(ah_capwap_para.capwap_port);
	/*get http proxy name and port*/
	ah_capwap_get_tcp_http_proxy_info(transfer_info->proxy_name, (int *)&transfer_info->proxy_port);
	transfer_info->proxy_port = htonl(transfer_info->proxy_port);
	/*get http proxy user name and passwprd, if DTLS disabled, don't pass this information*/
	if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE) {
		ah_capwap_get_tcp_http_proxy_auth_name_pswd(transfer_info->proxy_user, transfer_info->proxy_pswd);
	} else {
		ah_strcpy(transfer_info->proxy_user, "");
		ah_strcpy(transfer_info->proxy_pswd, "");
	}
	ah_dbg_old(capwap_info, "fill hiveap info: transfer mode:%s, destinatin port:%d, proxy name:%s, proxy port:%d\n",
			   (transfer_info->transfer_mode) ? "TCP" : "UDP", transfer_info->transfer_port,
			   transfer_info->proxy_name, transfer_info->proxy_port);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_indoor_info
 *
 * Purpose:   fill current box indoor or outdoor information
 *
 * Inputs:    N/A
 *
 * Output:    indoor_info: current indoor/outdoor information (0 is indoor, 1 is outdoor)
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static int ah_capwap_fillopt_hiveap_indoor_info(ah_capwap_ap_indoor_info_t *indoor_info)
{
	indoor_info->header.type = htonl(AH_CAPWAP_HIVEAP_INDOOR_INFO);
	indoor_info->header.len = htons(sizeof(ah_capwap_ap_indoor_info_t) - sizeof(ah_capwap_hiveap_info_header_t));
	/*get ap indoor or outdoor*/
	indoor_info->indoor = ah_hw_is_outdoor();

	ah_dbg_old(capwap_info, "current AP is %s\n", indoor_info->indoor ? "outdoor" : "indoor");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_pppoe_info
 *
 * Purpose:   fill current box pppoe enable information
 *
 * Inputs:    N/A
 *
 * Output:    pppoe_info: current enable/disable information (0 is disable, 1 is enable)
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static int ah_capwap_fillopt_hiveap_pppoe_info(ah_capwap_ap_pppoe_info_t *pppoe_info)
{
	pppoe_info->header.type = htonl(AH_CAPWAP_HIVEAP_PPPOE_INFO);
	pppoe_info->header.len = htons(sizeof(ah_capwap_ap_pppoe_info_t) - sizeof(ah_capwap_hiveap_info_header_t));

	pppoe_info->enable = 0;

	ah_dbg_old(capwap_info, "current PPPoE is %s\n", pppoe_info->enable ? "enable" : "disable");

	return 0;

}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_br_mode_info
 *
 * Purpose:   fill current box BR/AP mode information
 *
 * Inputs:    N/A
 *
 * Output:    br_mode_info: current box is disposed as AP/BR information (0 is AP, 1 is BR)
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
static int ah_capwap_fillopt_hiveap_br_mode_info(ah_capwap_ap_br_mode_info_t *br_mode_info)
{
	int      mode = 0;
	br_mode_info->header.type = htonl(AH_CAPWAP_HIVEAP_BR_MODE_INFO);
	br_mode_info->header.len = htons(sizeof(ah_capwap_ap_br_mode_info_t) - sizeof(ah_capwap_hiveap_info_header_t));

	mode = ah_dcd_is_in_br_mode();
	br_mode_info->br_mode = mode ? 1 : 0;

	ah_dbg_old(capwap_info, "current box is %s\n", (br_mode_info->br_mode) ? "BR" : "AP");

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_switch_info
 *
 * Purpose:   fill current box switch chip information
 *
 * Inputs:    N/A
 *
 * Output:    switch_info: current box's switch chip info, e.g. chip HW version
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/

static int ah_capwap_fillopt_hiveap_switch_info(ah_capwap_switch_info_t *switch_info)
{
	uint32_t    chip_version = 0;
	switch_info->header.type = htonl(AH_CAPWAP_HIVEAP_SWITCH_INFO);
	switch_info->header.len = htons(sizeof(ah_capwap_switch_info_t) - sizeof(ah_capwap_hiveap_info_header_t));

	switch_info->chip_version = 0;

	ah_dbg_old(capwap_info, "current box switch chip version: %08x\n", chip_version);

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_system_info
 *
 * Purpose:   fill current box system information
 *
 * Inputs:    N/A
 *
 * Output:    switch_info: current box's system info, e.g. cli failed
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
#if (AH_SUPPORT_BBOX)
static int ah_get_bbox_status()
{
	int bbox_enable = 0;
	FILE *fp;

	if (NULL == (fp = fopen(AH_BBOX_SW_R, "r"))) {
		ah_log_old(AH_LOG_ERR, "open proc file failed\n");
		return bbox_enable;
	}
	(void)fscanf(fp, "%d", &bbox_enable);
	fclose(fp);

	return bbox_enable;
}
#endif

static int ah_capwap_fillopt_hiveap_system_info(ah_capwap_system_info_t *system_info)
{
	char      cli_failed = 0;
	int      rc = 0;
	uint      system_value = 0;
	int entries_count = 0;
	struct dirent **entries = NULL;
#if defined(AH_BEAN_SUPPORT_PD)
	unsigned char power_source = 0;
	int fd = -1;
#endif

#define SETBIT(x,y) (x |= (1<<(y)))

	system_info->header.type = htonl(AH_CAPWAP_HIVEAP_SYSTEM_INFO);
	system_info->header.len = htons(sizeof(ah_capwap_system_info_t) - sizeof(ah_capwap_hiveap_info_header_t));
	rc = ah_capwap_is_cli_failed(&cli_failed);
	if (rc == -1) {
		ah_err_old("failed to get the cli failed status");
		cli_failed = 0;
	}

#define CLI_FAILED       0x0
#define HOS_CRASH         0x1
#if defined(AH_BEAN_SUPPORT_PD)
#define PS_OFFSET        0x2
#endif
	if (cli_failed) {
		SETBIT(system_value, CLI_FAILED);
	}

#if (AH_SUPPORT_BBOX)
	entries_count = scandir(
						AH_BBOX_DIR,
						&entries,
						&ah_bbox_scandir_strict_selector,
						&ah_kdump_scandir_comparator
					);
	if (ah_get_bbox_status() && entries_count > 0) {
		SETBIT(system_value, HOS_CRASH);
	}
#endif

#if defined(AH_BEAN_SUPPORT_PD)
#define SETVAL(x,y) (x = ((x) & ~(0x7<<PS_OFFSET)) | (((y) & 0x7)<<PS_OFFSET))
	/*
	 * Use 3 bits to represent 5 power source status:
	 * bit[4:2] =  001(0x1)  --  port9 AT
	 *             010(0x2)  --  port10 AT
	 *             011(0x3)  --  2xAT
	 *             100(0x4)  --  UPOE
	 *             101(0x5)  --  PSU
	 */
	if (ah_hw_is_product_sr2010p()) {
		rc = ah_dcd_read_power_source(&power_source);
		if (rc == -1) {
			ah_err_old("failed to get the power source");
		} else {
			SETVAL(system_value, power_source);
		}
	}
#endif

	system_info->system_value = htonl(system_value);

	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_reboot_info
 *
 * Purpose:   fill current box some information
 *
 * Inputs:    N/A
 *
 * Output:    reboot_info: reboot cause, timestamp
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
#if (AH_SUPPORT_NETDUMP)
int ah_capwap_fillopt_hiveap_reboot_info(ah_capwap_reboot_info_t *reboot_info)
{
	int      fd = -1;
	ah_reboot_info_t rbi;
	int rc = 0;
	struct timeval tv;

	reboot_info->header.type = htonl(AH_CAPWAP_HIVEAP_REBOOT_INFO);
	reboot_info->header.len = htons(sizeof(ah_capwap_reboot_info_t) - sizeof(ah_capwap_hiveap_info_header_t));

	/*only send reboot cause when capwap reconnect for the first time*/

	if (ah_capwap_info.connected_flag) {
		reboot_info->reboot_type = -1;
		reboot_info->timestamp = 0;
	} else {
		reboot_info->reboot_type =  AH_REBOOT_CAUSE_UNKNOWN; /*default reboot cause is unknown*/
		reboot_info->timestamp = 0;

		fd = open(AH_REBOOT_INFO_FILE, O_RDONLY);

		if (fd < 0) {
			rc = -1;
		} else {
			if (read(fd, &rbi, sizeof(rbi)) != sizeof(rbi)) {
				rc = -1;
			}
			if (strncmp(rbi.reboot_info_magic, AH_REBOOT_INFO_MAGIC, sizeof(AH_REBOOT_INFO_MAGIC)) != 0) {
				rc = -1;
			}
		}

		if (rc != 0) {
			ah_err_old("failed to get reboot info");
		} else {
			reboot_info->reboot_type = rbi.reboot_cause;
			if (reboot_info->reboot_type == AH_REBOOT_POWER_CYCLE) {
				gettimeofday(&tv, NULL);
			} else {
				rbi_get_tv(&rbi, &tv);
			}
			reboot_info->timestamp = htonl((int)tv.tv_sec);
		}

		if (fd >= 0) {
			close(fd);
		}
	}

	return rc;
}
#endif

int ah_capwap_fillopt_hiveap_hw_rev_info(ah_capwap_hw_rev_info_t *hw_rev_info)
{
	int rc = 0;
	char hw_rev_str[AH_IMG_HW_REVISION_LEN + 1] = {0};

	memset(hw_rev_info, 0, sizeof(*hw_rev_info));

	hw_rev_info->header.type = htonl(AH_CAPWAP_HIVEAP_HW_REV_INFO);
	hw_rev_info->header.len = htons(sizeof(ah_capwap_hw_rev_info_t) - sizeof(ah_capwap_hiveap_info_header_t));

	memset(hw_rev_str, 0, (AH_IMG_HW_REVISION_LEN + 1));

	if (ah_hw_get_hw_rev_str(hw_rev_str) != 0) {
		ah_err_old("%s: failed to get hw rev\n", __FUNCTION__);

		strcpy(hw_rev_str, "00");
	} else {
		strncpy(hw_rev_info->hw_rev, hw_rev_str, AH_IMG_HW_REVISION_LEN);
	}

	ah_log_old(AH_LOG_INFO, "fill in hw_rev_info(%s) to HM\n", hw_rev_str);

	/* always OK. */
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_hiveap_info
 *
 * Purpose:   fill current box some information
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_hiveap_info(char *fillbuf, uint32_t *filllen)
{
#define AH_CAPWAP_HIVEAP_INFO 5010
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	ah_capwap_hiveap_info_t hiveap_info;
	short      len = sizeof(hiveap_info);

	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_HIVEAP_INFO, len) == -1) {
		ah_err_old("CAPWAP:file tlv head failed!(type: AH_CAPWAP_HIVEAP_INFO)\n");
		return -1;
	}

	/*fill transfer info*/
	ah_capwap_fillopt_hiveap_transfer_info(&hiveap_info.transfer_info);
	/*indoor or outdoor*/
	ah_capwap_fillopt_hiveap_indoor_info(&hiveap_info.indoor_info);
	/*fill pppoe info or*/
	ah_capwap_fillopt_hiveap_pppoe_info(&hiveap_info.pppoe_info);
	/*fill br mode info or*/
	ah_capwap_fillopt_hiveap_br_mode_info(&hiveap_info.br_mode_info);
	/* switch info */
	ah_capwap_fillopt_hiveap_switch_info(&hiveap_info.switch_info);
	/* system info */
	ah_capwap_fillopt_hiveap_system_info(&hiveap_info.system_info);
#if (AH_SUPPORT_NETDUMP)
	/*reboot info */
	ah_capwap_fillopt_hiveap_reboot_info(&hiveap_info.reboot_info);
#endif
	ah_capwap_fillopt_hiveap_hw_rev_info(&hiveap_info.hw_rev_info);

	ah_memcpy(fillbuf + curlen, &hiveap_info, len);

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_wtpvhm
 *
 * Purpose:   fill WTP virtual hive manager name
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_wtpvhm(char *fillbuf, uint32_t *filllen)
{
	short      len = 0;
	char       curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	len = ah_strlen(ah_capwap_para.vhm_name);
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_WTP_VHM_NAME, len) == -1) {
		ah_err_old("CAPWAP: fill tlv head failed! (type:AH_CAPWAP_WTP_VHM_NAME)\n");
		return -1;
	}

	if (len > 0) {
		ah_memcpy(fillbuf + curlen, ah_capwap_para.vhm_name, len);
	}

	*filllen = len;
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_abort_image_result
 *
 * Purpose:   fill save image abort result
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_abort_image_result(char *fillbuf, uint32_t *filllen)
{
#define AH_CAPWAP_ABORT_RESULT  6011
	int32_t    abort_rst = -1;
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	uint32_t    len = 0;

	len = sizeof(int32_t);
	/*call Jerry's APIs to get abort save image result*/
	abort_rst = ah_system_stop_transfer_data(abort_save_type);
	ah_log_old(AH_LOG_INFO, "CAPWAP abort save image result:%d, abort type:%d\n", abort_rst, abort_save_type);
	abort_save_type = 0;
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_ABORT_RESULT, len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:AH_CAPWAP_ABORT_RESULT)\n");
		return -1;
	}

	/*fill value*/
	*(int32_t *)(fillbuf + curlen) = htonl(abort_rst);

	*filllen = len;

	return 0;
}
typedef struct {
	uint16_t    info_type;
	uint32_t    data_len;
	uint8_t    data[0];
} __packed ah_capwap_info_query_header;

typedef struct {
	uint16_t    event_type;
	uint32_t    cookie;
} __packed ah_capwap_info_query_data;

int ah_capwap_dp_stop()
{
	int      rc = 0;
#if 0
	ah_dhcp_probe_t dp;
	ah_memset(&dp, 0, sizeof(dp));
	dp.dhcp_probe = FALSE;
	rc = ah_tpa_dhcp_exec_probe(&dp);
#endif
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_handle_delete_cookie_confirm
 *
 * Purpose:   fill information query delete cookie confirm result
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_handle_delete_cookie_confirm(char *rqst_buff, char *rst_buf, uint32_t *rst_len)
{
#if 0
Information query:
	0                   1                  2                    3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + -
	|      information type         |            data length
	+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + -
	|     data��.
	+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + -

Data format:
	0                   1                  2                    3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + -
	|      event type                  | cookie
	+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + -
	|
	+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - +
#endif
	uint32_t    fill_len = 0;
	uint16_t    event_type = 0;
	int32_t    rc;
#ifdef AH_SUPPORT_CPM
	ah_capwap_in_msg_hdr_t data;
#endif
	ah_dbg_old(capwap_info, "fill delete cookie confirm result");
	ah_capwap_info_query_header *info_query =
		(ah_capwap_info_query_header * )rqst_buff;
	ah_capwap_info_query_data *query_data =
		(ah_capwap_info_query_data * )(info_query + 1);
	ah_dbg_old(capwap_itk, "info_query:event_type=%d, cookie=%d\n",
			   ntohs(query_data->event_type), ntohl(query_data->cookie));
	event_type = ntohs(query_data->event_type);
	switch (event_type) {
	case AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING:
		/*call API to delete cookie*/
		rc = ah_itk_ct_del(NULL, ntohl(query_data->cookie));
#ifdef AH_SUPPORT_CPM
		data.msg_type = htons(AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING);
		data.cookie = query_data->cookie;
		data.flag = 0;
		data.data_len = 0;
		rc = ah_event_send(AH_EVENT_CAPWAP_REQUEST_DCD, sizeof(data), &data);
		if (rc < 0) {
			ah_log_old(AH_LOG_ERR, "CAPWAP:Send client perf monitor cookie to DCD failed.\n");
		}
#endif
		break;
	case AH_CAPWAP_EVENT_DHCP_PROBE:
#if 0
		/*call API to delete cookie*/
		rc = ah_dp_del(ntohl(query_data->cookie));
		if (0 == rc) {
			dhcp_probe_entry_t dp;
			ah_dp_get(&dp);
			if (0 == dp.dp_cnt) {
				ah_capwap_dp_stop();
			}
		}
#endif
		break;
	default:
		ah_log_old(AH_LOG_ERR, "CAPWAP:Can not find delete cookie event type (%d)", event_type);
		break;
	}
	/*fill result*/
#if 0
	*(uint16_t *)(rst_buf) = htons((uint16_t)(AH_CAPWAP_INFO_DELETE_COOKIE));
	fill_len += sizeof(uint16_t);
	*(uint32_t *)(rst_buf + fill_len) = htonl(rc);
	fill_len += sizeof(uint32_t);
#else
	*(uint16_t *)(rst_buf) = info_query->info_type;
	fill_len += sizeof(uint16_t);
	*(uint32_t *)(rst_buf + fill_len) = htonl(0);
	fill_len += sizeof(uint32_t);
#endif
	*rst_len = fill_len;

	return 0;
}

typedef struct {
	uint32_t    cpu_int;
	uint32_t    cpu_dec;
	uint32_t    mem_total;
	uint32_t    mem_free;
	uint32_t    mem_usage;
} __packed ah_capwap_info_system;

typedef struct {
	char      my_da[AH_CAPWAP_MAC_LEN];
	char      my_bda[AH_CAPWAP_MAC_LEN];
	char      my_portal[AH_CAPWAP_MAC_LEN];
} __packed ah_capwap_info_topology;

typedef struct {
	ah_capwap_info_system system_info;
	ah_capwap_info_topology topology_info;
} __packed ah_capwap_info_system_topology;


/***************************************************************************
 *
 * Function:  ah_capwap_handle_get_cpu_mem_info
 *
 * Purpose:   fill information query system memory and cpu confirm result
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_handle_get_system_topology_info(char *rqst_buff, char *rst_buf, uint32_t *rst_len)
{
#if 0
	uint32_t    fill_len = 0;
	ulong      cpu_int = 0;
	ulong      cpu_dec = 0;
	ah_mem_sys_info_t mem_info;
	ah_capwap_info_system_topology sys_topo;
	ah_ipaddr46_t topo_ipv46;
	ah_mac_t topo_mac;

	/*fill type*/
	*(uint16_t *)(rst_buf) = htons(AH_CAPWAP_INFO_SYSTEM_TOPOLOGY);
	fill_len += sizeof(uint16_t);
	/*fill len*/
	*(uint32_t *)(rst_buf + fill_len) = htonl(sizeof(sys_topo));
	fill_len += sizeof(uint32_t);

	/*fill cpu utilize*/
	ah_sys_get_cpu_total_utilize(&cpu_int, &cpu_dec);

	/*fill memory utilize*/
	if (ah_mem_get_system_memory(&mem_info) < 0) {
		ah_err_old("CAPWAP: get sytem memory information failed!");
		return -1;
	}
	ah_dbg_old(capwap_info, "cpu utilize int:%d dec:%d, mem_total:%d, total_free:%d", cpu_int, cpu_dec, mem_info.mem_total,
			   mem_info.total_free);
	sys_topo.system_info.cpu_int = htonl((uint32_t)(cpu_int));
	sys_topo.system_info.cpu_dec = htonl((uint32_t)(cpu_dec));
	sys_topo.system_info.mem_total = htonl((uint32_t)(mem_info.mem_total));
	sys_topo.system_info.mem_free = htonl((uint32_t)(mem_info.total_free));
	sys_topo.system_info.mem_usage = htonl((uint32_t)(mem_info.mem_total - mem_info.total_free));


	ah_amrp_lib_get_my_da(&topo_mac, &topo_ipv46);
	ah_dbg_old(capwap_info, "Get my DA mac is :%m", &topo_mac);
	ah_memcpy(sys_topo.topology_info.my_da, &topo_mac, AH_CAPWAP_MAC_LEN);
	ah_amrp_lib_get_my_bda(&topo_mac, &topo_ipv46);
	ah_dbg_old(capwap_info, "Get my BDA mac is :%m", &topo_mac);
	ah_memcpy(sys_topo.topology_info.my_bda, &topo_mac, AH_CAPWAP_MAC_LEN);
	ah_amrp_lib_get_my_portal(&topo_mac, &topo_ipv46);
	ah_dbg_old(capwap_info, "Get my portal mac is :%m", &topo_mac);
	ah_memcpy(sys_topo.topology_info.my_portal, &topo_mac, AH_CAPWAP_MAC_LEN);

	/*copy info*/
	ah_memcpy(rst_buf + fill_len, &sys_topo, sizeof(sys_topo));
	fill_len += sizeof(sys_topo);


	*rst_len = fill_len;
#endif

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_handle_remote_event_request
 *
 * Purpose:   fill information query remote event request
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_handle_remote_event_request(uint32_t buf_len, char *rqt_buff)
{
	uint      i = 0;
	uint      packet_type = ah_capwap_get_request_type(rqt_buff);
	int      rc = -1;

	ah_dbg_old(capwap_info, "Get HM's event request, event id:%d\n", packet_type);
	for (i = 0; i < ah_capwap_type2eventid_num; i++) {
		if (packet_type == ah_capwap_type2eventid[i].packet_type) {
			ah_dbg_old(capwap_info, "Send event (%s) to destination module\n", ah_eventid_to_name(ah_capwap_type2eventid[i].event_id));
			if (ah_event_send(ah_capwap_type2eventid[i].event_id, buf_len, rqt_buff) < 0) {
				ah_log_old(AH_LOG_ERR, "CAPWAP: send request to event (%s) failed!", ah_eventid_to_name(ah_capwap_type2eventid[i].event_id));
				goto OUT;
			} else {
				rc = 0;
				goto OUT;
			}
		}
	}

	ah_log_old(AH_LOG_ERR, "CAPWAP: can not get the AP event mapping from CAPWAP event type:%d\n", packet_type);
OUT:
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_handle_interface_map
 *
 * Purpose:   fill information query system interface map info
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_handle_interface_map(uint32_t buf_len, char *rqt_buff)
{

	ah_dbg_old(capwap_info, "CAPWAP:send handle get interface map info request to DCD");
	if (ah_event_send(AH_EVENT_INTERFACE_MAP_IN, buf_len, rqt_buff) < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: send handle get interface map info request to DCD failed!");
	}
	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_info_query_result
 *
 * Purpose:   fill information query confirm result
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_info_query_result(char *fillbuf, uint32_t *filllen)
{
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	int      event_num = 0;
	int      i = 0;
	uint16_t    info_id = 0;
	uint32_t    rst_len = 0;

	if (confirm_pkt_info == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: confirm packet inforamtion data is null.");
		return 0;
	}
	info_id = ntohs(*(uint16_t *)confirm_pkt_info);

	/*find the correspond callback function to handle it*/
	event_num = sizeof(capwap_info_query_handle_request) / sizeof(capwap_info_query_handle_request[0]);
	for (i = 0; i < event_num; i++) {
		if (capwap_info_query_handle_request[i].info_id == info_id) {
			if (capwap_info_query_handle_request[i].ah_capwap_info_confirm_callback != NULL) {
				capwap_info_query_handle_request[i].ah_capwap_info_confirm_callback(confirm_pkt_info, fillbuf + curlen, &rst_len);
			}
			break;
		}
	}
	if (i == event_num) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: can not find the confirm information type request id (%d).", info_id);
	}
	/*avoid the confirm TLV len not 0, 0 is success*/
	if (rst_len == 0) {
		*(uint16_t *)(fillbuf + curlen) = htons(info_id);
		rst_len += sizeof(uint16_t);
		*(uint32_t *)(fillbuf + curlen + sizeof(uint16_t)) = htonl(0);
		rst_len += sizeof(uint32_t);
	}
	if (confirm_pkt_info != NULL) {
		ah_free(confirm_pkt_info);/*malloc in function ah_capwap_info_query_request*/
		confirm_pkt_info = NULL;
	}
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_INFO_QUERY_RESPONSE, rst_len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:AH_CAPWAP_INFO_QUERY_RESPONSE)\n");
		return -1;
	}

	*filllen = rst_len;

	return 0;
}

typedef struct {
	uint16_t    event_type;
	uint32_t    cookie;
	uint8_t    flag;
	uint32_t    data_len;
	uint8_t    data[0];
} __packed ah_capwap_event_query_data_t;

typedef struct {
	uint16_t    min_vlanid;
	uint16_t    max_vlanid;
	uint16_t    retry;
	uint16_t    timeout;
} __packed ah_capwap_event_query_dp_t;

typedef struct {
	uint16_t    pci_status;
} __packed ah_capwap_event_query_pci_t;

int ah_capwap_dp_config(ah_capwap_event_query_dp_t *dp_config)
{
	int      rc = 0;
#if 0
	ah_dhcp_probe_t dp;
	ah_memset(&dp, 0, sizeof(dp));
	dp.dhcp_probe = TRUE;
	dp.start_vlan = ntohs(dp_config->min_vlanid);
	dp.end_vlan = ntohs(dp_config->max_vlanid);
	dp.retry_times = ntohs(dp_config->retry);
	dp.timeout = ntohs(dp_config->timeout);
	rc = ah_tpa_dhcp_exec_probe(&dp);
#endif
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_handle_enable_clnt_trace_confirm
 *
 * Purpose:   fill information query client tracing confirm result
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_handle_enable_clnt_trace_confirm(char *rqst_buff, char *rst_buf, uint32_t *rst_len)
{
	uint32_t    fill_len = 0;
	uint16_t    event_type = 0;
	uint32_t    rst = 0;
	ah_dbg_old(capwap_info, "fill handle enable client tracing confirm result");
	ah_capwap_event_query_data_t *data = (ah_capwap_event_query_data_t * )rqst_buff;
	ah_capwap_event_query_dp_t *dp_config = NULL;
	ah_capwap_event_query_pci_t *pci_config = NULL;
	ah_dbg_old(capwap_itk, "event_query:event_type=%d, cookie=%d, flag=%d, len=%d\n",
			   ntohs(data->event_type), ntohl(data->cookie),
			   data->flag, ntohl(data->data_len));
	event_type = ntohs(data->event_type);
	switch (event_type) {
	case AH_CAPWAP_EVENT_CLIENT_ACCESS_TRACING:
		/*call API to enable client tracing*/
		rst = ah_itk_ct_add((ah_mac_t *)data->data,
							ntohl(data->cookie));
		break;
	case AH_CAPWAP_EVENT_DHCP_PROBE:
#if 0
		dp_config = (ah_capwap_event_query_dp_t * )(data + 1);
		rst = ah_capwap_dp_config(dp_config);
		if (0 == rst) {
			rst = ah_dp_add(ntohl(data->cookie), ntohs(dp_config->min_vlanid),
							ntohs(dp_config->max_vlanid));
		} else {
			rst = AH_ITK_ERRCODE_DHCP_PROBE_START;
		}
#endif
		break;
	case AH_CAPWAP_EVENT_PCI_ALERT:
		pci_config = (ah_capwap_event_query_pci_t *)(data + 1);
		ah_dbg_old(capwap_itk, "event_query: set pci alert enable(%s)\n", (pci_config->pci_status) ? "On" : "Off");
		rst = ah_itk_pci_set_status(pci_config->pci_status);
		break;
	default:
		ah_log_old(AH_LOG_ERR, "CAPWAP:Can not find delete cookie event type (%d)", event_type);
		break;
	}
	/*fill result*/
	*(uint16_t *)(rst_buf) = htons((uint16_t)(event_type));
	fill_len += sizeof(uint16_t);
	*(uint32_t *)(rst_buf + fill_len) = htonl(rst);
	fill_len += sizeof(uint32_t);

	*rst_len = fill_len;

	return 0;
}


/***************************************************************************
 *
 * Function:  ah_capwap_fillopt_event_query_result
 *
 * Purpose:   fill eventn query confirm result
 *
 * Inputs:    fillbuf: fill buf
 *
 * Output:    fillen: the len for this option
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_fillopt_event_query_result(char *fillbuf, uint32_t *filllen)
{
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	int      event_num = 0;
	int      i = 0;
	uint16_t    event_id = 0;
	uint32_t    rst_len = 0;

	if (confirm_pkt_info == NULL) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: event query confirm packet inforamtion data is null.");
		return 0;
	}
	event_id = ntohs(*(uint16_t *)confirm_pkt_info);

	/*find the correspond callback function to handle it*/
	event_num = sizeof(capwap_event_handle_request) / sizeof(capwap_event_handle_request[0]);
	for (i = 0; i < event_num; i++) {
		if (capwap_event_handle_request[i].event_id == event_id) {
			if (capwap_event_handle_request[i].ah_capwap_event_confirm_callback != NULL) {
				capwap_event_handle_request[i].ah_capwap_event_confirm_callback(confirm_pkt_info, fillbuf + curlen, &rst_len);
			}
			break;
		}
	}
	if (i == event_num) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: can not find the event query confirm information type request id (%d).", event_id);
	}
	/*avoid the confirm TLV len not 0, 0 is success*/
	if (rst_len == 0) {
		*(uint16_t *)(fillbuf + curlen) = htons(event_id);
		rst_len += sizeof(uint16_t);
		*(uint32_t *)(fillbuf + curlen + sizeof(uint16_t)) = htonl(0);
		rst_len += sizeof(uint32_t);
	}
	if (confirm_pkt_info != NULL) {
		ah_free(confirm_pkt_info);/*malloc in function ah_capwap_event_info_request*/
		confirm_pkt_info = NULL;
	}
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_EVENT_QUERY_RESULT, rst_len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:AH_CAPWAP_EVENT_QUERY_RESULT)\n");
		return -1;
	}

	*filllen = rst_len;

	return 0;
}

int ah_capwap_fillopt_snd_echo_time(char *fillbuf, uint32_t *filllen)
{
#define AH_CAPWAP_ECHO_SND_TIME (5011)
	short      curlen = AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	uint32_t    rst_len = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	*(uint32_t *)(fillbuf + curlen) = htonl(tv.tv_sec);
	rst_len += sizeof(uint32_t);
	curlen += sizeof(uint32_t);
	*(uint32_t *)(fillbuf + curlen) = htonl(tv.tv_usec);
	rst_len += sizeof(uint32_t);
	curlen += sizeof(uint32_t);
	/*fill type and length*/
	if (ah_capwap_filltlv_head(fillbuf, AH_CAPWAP_ECHO_SND_TIME, rst_len) == -1) {
		ah_err_old("CAPWAP:fill tlv head failed! (type:AH_CAPWAP_ECHO_SND_TIME)\n");
		return -1;
	}

	*filllen = rst_len;

	return 0;
}

/*********************************************end fill*******************************************************/

/***************************************************************************
 *
 * Function:  ah_capwap_clear_frag_buff
 *
 * Purpose:   clean frag buffer
 *
 * Inputs:    void
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_clean_frag_buff()
{
	int      i = 0;

	ah_dbg_old(capwap_info, "Clean frag buffer..\n");

	for (i = 0; i < AH_CAPWAP_FRAG_MAX_NUM; i ++) {
		ah_capwap_frag_buff[i].buff_valid = AH_CAPWAP_FRAG_BUFF_INVALID;
		if (ah_capwap_frag_buff[i].frag_msg != NULL) {
			ah_free(ah_capwap_frag_buff[i].frag_msg); /*malloc in ah_capwap_frag_to_buff*/
			ah_capwap_frag_buff[i].frag_msg = NULL;
		}
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_frag_info
 *
 * Purpose:   get the frag buffer information in term of index
 *
 * Inputs:    frag_index:  frag buffer index
 *
 * Output:    frag_buff: buffer information
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_get_frag_info(int frag_index, ah_capwap_pkt_frag_buff *frag_buff)
{
	frag_buff->buff_valid = ah_capwap_frag_buff[frag_index].buff_valid;
	frag_buff->frag_info.frag_id = ah_capwap_frag_buff[frag_index].frag_info.frag_id;
	frag_buff->frag_info.frag_last = ah_capwap_frag_buff[frag_index].frag_info.frag_last;
	frag_buff->frag_info.frag_ofst = ah_capwap_frag_buff[frag_index].frag_info.frag_ofst;
	frag_buff->frag_info.frag_flag = ah_capwap_frag_buff[frag_index].frag_info.frag_flag;
	frag_buff->frag_len = ah_capwap_frag_buff[frag_index].frag_len;
	frag_buff->frag_num = ah_capwap_frag_buff[frag_index].frag_num;
	frag_buff->frag_time = ah_capwap_frag_buff[frag_index].frag_time;
	frag_buff->frag_msg = ah_capwap_frag_buff[frag_index].frag_msg;

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_insert_frag_to_buff
 *
 * Purpose:   send the frag packet to buff
 *
 * Inputs:    pkt_buff:  capwap receive packet
 *            frag_len:  capwap frag len
 *            frag_info: packet fragment information
 *            frag_index: buff index for new frag
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_insert_frag_to_buff(char *pkt_buff, uint32_t frag_len, ah_capwap_pkt_frag_info frag_info, uint32_t index)
{
	uint      current_timestamp = 0;

	/*get current time*/
	get_system_start_interval(&current_timestamp);

	ah_capwap_frag_buff[index].buff_valid = AH_CAPWAP_FRAG_BUFF_VALID;
	ah_capwap_frag_buff[index].frag_info.frag_id = frag_info.frag_id;
	ah_capwap_frag_buff[index].frag_info.frag_ofst = frag_info.frag_ofst;
	ah_capwap_frag_buff[index].frag_info.frag_last = frag_info.frag_last;
	ah_capwap_frag_buff[index].frag_info.frag_flag = frag_info.frag_flag;
	ah_capwap_frag_buff[index].frag_len = frag_len;
	ah_capwap_frag_buff[index].frag_time = current_timestamp;
	ah_capwap_frag_buff[index].frag_num = 1ULL << frag_info.frag_ofst;
	ah_capwap_frag_buff[index].frag_msg = ah_malloc(frag_len); /*free in ah_capwap_frag_from_buff() or ah_capwap_clean_frag_buff()*/
	if (ah_capwap_frag_buff[index].frag_msg == NULL) {
		ah_err_old("CAPWAP:Malloc buffer for frag packet error!(len:%d)", frag_len);
	} else {
		memcpy(ah_capwap_frag_buff[index].frag_msg, pkt_buff, frag_len);
	}

	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_delete_frag_from_buff
 *
 * Purpose:   clean the frag packet from buff
 *
 * Inputs:    frag_id: the delete frag id
 *
 * Output:    empty_index: the empty_index
 *
 * Returns:   0 found the right frag id, otherwise not found the right frag id
 *
 **************************************************************************/
int ah_capwap_delete_frag_from_buff(uint32_t frag_id, uint *empty_index)
{
#define AH_CAPWAP_NOT_FOUND_FRAG 0
#define AH_CAPWAP_FOUND_FRAG     1
	int      i = 0;
	int      found_flag =  AH_CAPWAP_NOT_FOUND_FRAG;

	ah_dbg_old(capwap_info, "Remove the frag (id:%d) from frag buffer\n", frag_id);
	for (i = 0; i < AH_CAPWAP_FRAG_MAX_NUM; i++) {
		if (ah_capwap_frag_buff[i].frag_info.frag_id == frag_id) {
			/*delete the oldest frag_id*/
			ah_free(ah_capwap_frag_buff[i].frag_msg); /*malloc in ah_capwap_frag_to_buff()*/
			ah_capwap_frag_buff[i].frag_msg = NULL;
			ah_capwap_frag_buff[i].buff_valid = AH_CAPWAP_FRAG_BUFF_INVALID;
			*empty_index = i;
			found_flag = AH_CAPWAP_FOUND_FRAG;
		}
	}

	if (found_flag == AH_CAPWAP_NOT_FOUND_FRAG) {
		ah_log_old(AH_LOG_INFO, "CAPWAP:Can not found the right flag id:%d to delete\n", frag_id);
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_get_pkt_frag_info
 *
 * Purpose:   get the received capwap packet frag information
 *
 * Inputs:    pkt_buff:  capwap receive packet
 *
 * Output:    frag_info: packet fragment information
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_get_pkt_frag_info(char *pkt, ah_capwap_pkt_frag_info *frag_info)
{
#define AH_CAPWAP_FRAG_ID_BITS       16
#define AH_CAPWPA_FRAG_OFST_BITS     3
#define AH_CAPWAP_PKT_ONLY_FRAG      0x0080
#define AH_CAPWAP_PKT_FRAG_LAST      0x00c0
#define AH_CAPWAP_GET_FRAG_OFFSET    0xfff8
	uint32_t    hdr_info = 0;
	uint32_t    tmp = AH_CAPWAP_PKT_FRAG_LAST;

	/*get the first 4 bytes information*/
	hdr_info = ntohl(*(uint32_t *)(pkt));

	/*calculate the frag information*/
	tmp = tmp & hdr_info;
	ah_dbg_old(capwap_info, "the fragment information number is:%02x hdr is:%02x\n", tmp , hdr_info);
	switch (tmp) {
	case 0:
		/*Is not a frag pkt*/
		frag_info->frag_flag = 0;
		frag_info->frag_last = 0;
		ah_dbg_old(capwap_info, "This packet is not a fragment packet\n");
		return 0;
	case AH_CAPWAP_PKT_ONLY_FRAG:
		/*is frag pkt but not last one*/
		frag_info->frag_flag = (char)AH_CAPWAP_IS_FRAG_PKT;
		frag_info->frag_last = 0;
		ah_dbg_old(capwap_info, "this packet is a fragment packet, not last fragment\n");
		break;
	case AH_CAPWAP_PKT_FRAG_LAST:
		/*is a last frag pkt*/
		frag_info->frag_flag = (char)AH_CAPWAP_IS_FRAG_PKT;
		frag_info->frag_last = (char)AH_CAPWAP_LAST_FRAG_PKT;
		ah_dbg_old(capwap_info, "this packet is a fragment packet, is last fragment \n");
		break;
	default:
		if (capwap_info) {
			ah_dbg_old(capwap_info, "the packet header format is error:\n");
			ah_hexdump((uchar *)pkt, sizeof(uint32_t));
		}
		return -1;
	}

	/*get the frag_id and frag_offset*/
	hdr_info = ntohl(*(uint32_t *)(pkt + sizeof(uint32_t)));
	frag_info->frag_id = (uint16_t)(hdr_info >> AH_CAPWAP_FRAG_ID_BITS) ;
	frag_info->frag_ofst = (uint16_t)(hdr_info & AH_CAPWAP_GET_FRAG_OFFSET) >> AH_CAPWPA_FRAG_OFST_BITS;
	if (frag_info->frag_ofst > AH_CAPWAP_FRAG_MAX_NUM) {
		ah_dbg_old(capwap_info, "Current we only support max %d fragment, current offset is %d frag id is %d\n",
				   AH_CAPWAP_FRAG_MAX_NUM, frag_info->frag_ofst, frag_info->frag_id);
		ah_capwap_delete_frag_from_buff(frag_info->frag_id, &tmp);
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_save_fragment
 *
 * Purpose:   save the frag packet
 *
 * Inputs:    pkt_buff:  capwap receive packet
 *            frag_len:  capwap frag len
 *            frag_info: packet fragment information
 *
 * Output:    total_len:  all frag information total length
 *            last_index: the last packet index
 *
 * Returns:   AH_CAPWAP_FRAG_ONLY_SAVE saved ok
 *            AH_CAPWAP_FRAG_NEED_ASSEMBLY saved ok and need assembled
 *                -1 is errored
 *
 **************************************************************************/
int ah_capwap_save_fragment(char *pkt_buff, uint32_t frag_len, ah_capwap_pkt_frag_info frag_info, uint32_t *total_len,
							uint      *last_index)
{
#define AH_CAPWAP_FRAG_LAST_NOT_ARIV   -1
#define AH_CAPWAP_FRAG_NOT_SAVED    0
#define AH_CAPWAP_FRAG_IS_SAVED   1
	uint      frag_index = 0;
	uint32_t    frag_time = 0xffffffff;
	uint64_t    frag_num = 0;
	uint64_t    new_num = 0;
	uint64_t    i = 0;
	uint64_t    base_num = 1;/*add this various, see bug #8674*/
	int      oldest_id = 0;
	int      frag_save = AH_CAPWAP_FRAG_NOT_SAVED;
	int      frag_last = AH_CAPWAP_FRAG_LAST_NOT_ARIV;
	char      longlong_str[AH_CAPWAP_UINT64_STR_LEN];

	/*calculate frag num, if one fragment arrived, the corresponed bit will be set 1*/
	/*only 64 fragments for receive, so we use ah_uint64_t */
	frag_num = (uint64_t)(base_num << frag_info.frag_ofst);
	new_num = frag_num;

	/*find a empty room to save it and change the same frag_id information*/
	for (i = 0; i < AH_CAPWAP_FRAG_MAX_NUM; i++) {
		/*find empty room*/
		if (ah_capwap_frag_buff[i].buff_valid == AH_CAPWAP_FRAG_BUFF_INVALID
			&& frag_save == AH_CAPWAP_FRAG_NOT_SAVED) {
			/*find a empty room*/
			ah_dbg_old(capwap_info, "find the empty room (%d) for new frag\n", i);
			ah_capwap_insert_frag_to_buff(pkt_buff, frag_len, frag_info, i);
			frag_index = i;
			frag_save = AH_CAPWAP_FRAG_IS_SAVED;
			/*save the same frag id and is the last pkt index*/
			if (ah_capwap_frag_buff[i].frag_info.frag_last == AH_CAPWAP_LAST_FRAG_PKT) {
				frag_last = i;
			}
			*total_len += frag_len;
			continue;
		}

		/*save the oldest frag_time and update the frag num*/
		if (ah_capwap_frag_buff[i].buff_valid != AH_CAPWAP_FRAG_BUFF_INVALID) {
			if (ah_capwap_frag_buff[i].frag_time < frag_time) {
				frag_time = ah_capwap_frag_buff[i].frag_time;
				oldest_id = ah_capwap_frag_buff[i].frag_info.frag_id;
			}
			if (ah_capwap_frag_buff[i].frag_info.frag_id == frag_info.frag_id) {
				ah_capwap_frag_buff[i].frag_num = frag_num | ah_capwap_frag_buff[i].frag_num;
				new_num = ah_capwap_frag_buff[i].frag_num;
				/*save the same frag id and is the last pkt index*/
				if (ah_capwap_frag_buff[i].frag_info.frag_last == AH_CAPWAP_LAST_FRAG_PKT) {
					frag_last = i;
				}
				*total_len += ah_capwap_frag_buff[i].frag_len;
			}
		}

	}

	/*no empty romm, then delete the oldest frag*/
	if (frag_save == AH_CAPWAP_FRAG_NOT_SAVED) {
		if (ah_capwap_delete_frag_from_buff(oldest_id, &frag_index) == -1) {
			ah_err_old("CAPWAP:Find room to save new frag failed!");
			return -1;
		}
		/*set the new frag to buff*/
		ah_dbg_old(capwap_info, "find the empty room (%d) for new frag\n", frag_index);
		ah_capwap_insert_frag_to_buff(pkt_buff, frag_len, frag_info, frag_index);
	}

	/*update the frag_num for new frag*/
	ah_capwap_frag_buff[frag_index].frag_num = new_num;
	sprintf(longlong_str, "%llu", new_num);

	if (frag_last == AH_CAPWAP_FRAG_LAST_NOT_ARIV) {
		ah_dbg_old(capwap_info, "Only frag packet arrived(Last frag doesn't arrive).(frag_id:%d, offset:%d, total_len:%d, all frag is:%s)",
				   frag_info.frag_id, frag_info.frag_ofst, *total_len, longlong_str);
		return AH_CAPWAP_FRAG_ONLY_SAVE;
	}

	*last_index = frag_last;
	/*check the last frag and check all frags arrive*/
	i = (uint64_t)(base_num << (ah_capwap_frag_buff[*last_index].frag_info.frag_ofst + 1));
	if (new_num == (i - 1)) {
		/*all frag packet arrived*/
		ah_dbg_old(capwap_info, "All frag packet arrived.(frag_id:%d, total_len:%d, all frag is:%s)",
				   frag_info.frag_id, *total_len, longlong_str);
		return AH_CAPWAP_FRAG_NEED_ASSEMBLY;
	}

	ah_dbg_old(capwap_info, "Only frag packet arrived.(frag_id:%d, offset:%d, total_len:%d, all frag is:%s)",
			   frag_info.frag_id, frag_info.frag_ofst, *total_len, longlong_str);
	return AH_CAPWAP_FRAG_ONLY_SAVE;
}

/***************************************************************************
 *
 * Function:  ah_capwap_assemble_fragment
 *
 * Purpose:   assemble the frag packet
 *
 * Inputs:    frag_id:   frag id for assembly
 *            total_len: total length of all fragments
 *            last_index:last frag index
 *       tlv_len:   the payload len
 *
 * Output:    assembly_buff:  buffer to store the assembled packet
 *
 * Returns:   0 success, otherwise failed
 *
 **************************************************************************/
int ah_capwap_assemble_fragment(uint32_t frag_id, uint32_t total_len, uint last_index, char *assembly_buff,
								uint16_t    *tlv_len)
{
	uint32_t    total_frag = 0;
	uint32_t    frag_len = 0;
	uint16_t    payload_len = 0;
	char      *asmb_pkt = NULL;
	int      i = 0;
	int      j = 0;

	/*get total number of fragments*/
	total_frag = ah_capwap_frag_buff[last_index].frag_info.frag_ofst + 1;

	/*assemble the buffer*/
	asmb_pkt = assembly_buff;
	for (j = 0; j < total_frag; j++) {
		ah_dbg_old(capwap_info, "Total frag is:%d total_len:%d ready to find offset: %d\n", total_frag, total_len, j);
		for (i = 0; i < AH_CAPWAP_FRAG_MAX_NUM; i++) {
			if (ah_capwap_frag_buff[i].frag_info.frag_id == frag_id
				&& ah_capwap_frag_buff[i].frag_info.frag_ofst == j) {
				/*find the right offset*/
				payload_len = ntohs(*(uint16_t *)(ah_capwap_frag_buff[i].frag_msg + AH_CAPWAP_TLV_TYPE_LEN));
				ah_dbg_old(capwap_info, "found the offset %d frag, frag_id:%d, buffer index:%d buffer len:%d payload_len:%d\n",
						   j, frag_id, i, ah_capwap_frag_buff[i].frag_len, payload_len);
				if (ah_capwap_frag_buff[i].frag_info.frag_ofst == 0) {
					/*first frag need save TLV*/
					ah_memcpy(asmb_pkt, ah_capwap_frag_buff[i].frag_msg, ah_capwap_frag_buff[i].frag_len);
					asmb_pkt += AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN + payload_len;
					ah_dbg_old(capwap_info, "assemble %d bytes\n", payload_len + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN);
				} else {
					/*other frag only save V*/
					ah_memcpy(asmb_pkt, (ah_capwap_frag_buff[i].frag_msg + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN),
							  payload_len);
					asmb_pkt += payload_len;
					ah_dbg_old(capwap_info, "assemble %d bytes\n", payload_len);
				}
				frag_len += ah_capwap_frag_buff[i].frag_len;
				*tlv_len += payload_len;
				break;
			}
		}
		if (i == AH_CAPWAP_FRAG_MAX_NUM) {
			ah_err_old("CAPWAP:Can not found the right offset %d frag_id:%d", j, frag_id);
			return -1;
		}
	}

	if (frag_len != total_len) {
		ah_err_old("CAPWAP:Assemble frag len (%d) is not the same with the total len (%d)", frag_len, total_len);
		return -1;
	}
	/*update the L of TLV in first frag*/
	*(uint16_t *)(assembly_buff + AH_CAPWAP_TLV_TYPE_LEN) = htons(*tlv_len);
	*tlv_len += AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_chk_same_fragment
 *
 * Purpose:   check the buffer has the same frag in term of  frag_id and offset
 *                 check for retransmission
 *
 * Inputs:    frag_info: packet fragment information
 *
 * Output:    void
 *
 * Returns:   0 is the same fragment, otherwise is not the same fragment
 *
 **************************************************************************/
int ah_capwap_chk_same_fragment(ah_capwap_pkt_frag_info frag_info)
{
	int      i = 0;

	for (i = 0; i < AH_CAPWAP_FRAG_MAX_NUM; i++) {
		if (ah_capwap_frag_buff[i].frag_info.frag_id == frag_info.frag_id
			&& ah_capwap_frag_buff[i].frag_info.frag_ofst == frag_info.frag_ofst
			&& ah_capwap_frag_buff[i].buff_valid == AH_CAPWAP_FRAG_BUFF_VALID) {
			ah_dbg_old(capwap_info, "Found the same frag, id:%d offset:%d index:%d\n", frag_info.frag_id, frag_info.frag_ofst, i);
			return 0;
		}
	}
	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_handle_fragment
 *
 * Purpose:   handle the frag packet
 *
 * Inputs:    capwap_state: capwap current state
 *            pkt_buff:  capwap TLV packet
 *            msg_len:   capwap TLV len
 *            frag_info: packet fragment information
 *            handler:   the callback function,if all frag arrived, handle it
 *            msg_type:  capwap packet type
 *            seq_num:   sequence number
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_handle_fragment(uint32_t capwap_state, char *pkt_buff, uint32_t msg_len, ah_capwap_pkt_frag_info frag_info,
							   ah_capwap_analyopt_func handler, uint32_t msg_type, uint msg_seq)
{
	/*1. put the packet into buffer
	  2. check the pkt is the last one we need
	  3. if all the pkt arrive, assembled them and send the response
	  4. if all the pkt not arriev, only send the response
	 */
	int      rc = 0;
	uint32_t    total_len = 0;
	uint      last_index = 0;
	uint      emp_index = 0;
	char      *frag_all = NULL;
	uint16_t    payload_len = 0;

	/*check for retransmission*/
	if (ah_capwap_chk_same_fragment(frag_info) == 0) {
		goto OUT;
	}

	/*save the frag to buffer */
	rc = ah_capwap_save_fragment(pkt_buff, msg_len, frag_info, &total_len, &last_index);
	if (rc == AH_CAPWAP_FRAG_NEED_ASSEMBLY) {
		/*all the frag arrived*/
		frag_all = ah_malloc(total_len);
		if (frag_all == NULL) {
			ah_err_old("CAPWAP:Malloc for frag assemble failed!(len:%d)", total_len);
			goto OUT;
		}
		/*assembled all the frag*/
		if (ah_capwap_assemble_fragment(frag_info.frag_id, total_len, last_index, frag_all, &payload_len) == -1) {
			ah_capwap_delete_frag_from_buff(frag_info.frag_id, &emp_index);
			goto OUT;
		}
		/*handle the assemble packet*/
		ah_dbg_old(capwap_info, "Assemble packet(TLV, total len:%d) is :\n", payload_len);
		if (capwap_packet) {
			ah_hexdump((uchar *)frag_all, payload_len);
		}
		handler(frag_all, payload_len, (uint)msg_seq);
		/*delete all frag from buffer*/
		ah_dbg_old(capwap_info, "Handle the fragment end, remove (frag_id:%d)...\n", frag_info.frag_id);
		ah_capwap_delete_frag_from_buff(frag_info.frag_id, &emp_index);
	} else if (rc == AH_CAPWAP_FRAG_ONLY_SAVE) {
		/*only give HM a response, response msg type is receive msg type + 1*/
		ah_dbg_old(capwap_info, "Send the fragment response(msg_type:%d, seq_num:%d)\n", msg_type + 1, msg_seq);
		if (ah_capwap_snd_confirm(capwap_state, (msg_type + 1), msg_seq) < 0) {
			ah_err_old("%s: error happens when call ah_capwap_snd_confirm.", __func__);
		}
	}

OUT:
	if (frag_all != NULL) {
		ah_free(frag_all);
	}
	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_analysecolmsg
 *
 * Purpose:   analyse the cpawap control message part
 *
 * Inputs:    capwapcolmsg: capwap packet
 *               frag_info:  the packet fragment information
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_analysecolmsg(char *capwapcolmsg, ah_capwap_pkt_frag_info frag_info)
{
#define AH_CAPWAP_CTRL_LEN_PLACE 5
#define AH_CAPWAP_CTRL_TIMESTAMP 7

	uint32_t    msgtype = 0;
	uint32_t    coloffset = 12;
	short      colmsglen = 0;
	short      i = 0;
	uchar      seq_num = 0;

	/*the totle number for wtp can received packet type*/
	ah_capwap_para.capwap_number.msg_num = sizeof(capwapstatemsg) / sizeof(capwapstatemsg[0]);

	if (capwapcolmsg == NULL) {
		ah_err_old("CAPWAP:the control msg is null!\n");
		return -1;
	}

	/*get the message type*/
	msgtype = *(uint32_t *)capwapcolmsg;
	msgtype = ntohl(msgtype);
	ah_dbg_old(capwap_info, "Rcv msg type:%d, fragment info: is-frag-pkt=%d, is-last-frag=%d, frag-id=%d, frag-offset=%d\n",
			   msgtype, frag_info.frag_flag, frag_info.frag_last, frag_info.frag_id, frag_info.frag_ofst);
	if (msgtype <= 0 || msgtype >= AH_CAPWAP_MAX_MSG_NUM) {
		ah_log_old(AH_LOG_INFO, "CAPWAP: receive an unknown packet, message type is %d!\n", msgtype);
		return -1;
	}

	/*get the seq_num*/
	seq_num = *(uchar *)(capwapcolmsg + sizeof(uint32_t));

	for ( i = 0; i < ah_capwap_para.capwap_number.msg_num; i ++) {
		if ((capwapstatemsg[i].capwapstate == ah_capwap_info.state) && (msgtype == capwapstatemsg[i].revcmsgtype)) {
			colmsglen = *(short *)(capwapcolmsg + AH_CAPWAP_CTRL_LEN_PLACE);
			colmsglen = ntohs(colmsglen);
			if (colmsglen <= 0) {
				ah_log_old(AH_LOG_INFO, "CAPWAP control message length(len=%d) is error!\n", colmsglen);
				return -1;
			}
			colmsglen = colmsglen - AH_CAPWAP_CTRL_TIMESTAMP; /*Msg Element Length and Flags and   Time Stamp */
			/*do something you will get*/
			if (frag_info.frag_flag == AH_CAPWAP_IS_FRAG_PKT) {
				/*1. send the packet to frag buffer
				  2. send the response to HM
				  3. return*/
				ah_capwap_handle_fragment(ah_capwap_info.state, capwapcolmsg + coloffset, colmsglen,
										  frag_info, capwapstatemsg[i].ah_analyopt_callback, msgtype, seq_num);
				return 0;
			}

			/*callback function handle the TLV*/
			capwapstatemsg[i].ah_analyopt_callback(capwapcolmsg + coloffset, colmsglen, (uint)seq_num);
			return 0;
		}
	}

	ah_log_old(AH_LOG_INFO, "CAPWAP control message type(type=%d) is error!\n", msgtype);
	return -1;
}

/***************************************************************************
 *
 * Function:  ah_capwap_analysepacket
 *
 * Purpose:   analyse the cpawap all message part
 *
 * Inputs:    capwapbuf: capwap packet
 *            len:            capwap packet len
 *
 * Output:    void
 *
 * Returns:    0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_analysepacket(char *capwapbuf, uint32_t len)
{
	uint32_t    packlen = 0;
	uint32_t    headinfo = 0;
	uint32_t    cpyinfo = 0;
	//ah_int_t radiomac = 0;
	//ah_int_t wirelessinfo = 0;
	int      colmsglen = 0;
	//ah_int_t wirelesslen = 0;
	ah_capwap_pkt_frag_info frag_info = {0};

	if (capwapbuf == NULL) {
		ah_err_old("CAPWAP:analyse packet is NULL!\n");
		return -1;
	}

	headinfo = *(uint32_t *)capwapbuf;
	if (headinfo == 0) {
		ah_err_old("CAPWAP:the head info is error!\n");
		return -1;
	}

	cpyinfo = ntohl(headinfo);

	packlen = (( cpyinfo >> 18) & (0x1f));/*0x1f = 11111*/
	ah_dbg_old(capwap_info, "the CAPWAP transport header len is %d\n", packlen);

	colmsglen = AH_CAPWAP_TRANS_HEAD_LEN;/*fixed the len*/
#if 0
	radiomac = ((cpyinfo >> 8) & (0x01));
	wirelessinfo = ((cpyinfo >> 9) & (0x01));
	/*
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |    Length     |                  MAC Address
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	if (radiomac == 1) {
		colmsglen = colmsglen + AH_CAPWAP_MAC_LEN + 1;    /*1 is the len's field len*/
	}
	if (wirelessinfo == 1) {
		/*
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |  Wireless ID  |    Length     |             Data
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		wirelesslen = *(int8_t *)(capwapbuf + colmsglen + 1);/*1 is the Wireless ID 's field len*/
		colmsglen = colmsglen + wirelesslen + 2;/*not a fixed value*/

	}
#endif
	/*get the packet frag infomation*/
	if (ah_capwap_get_pkt_frag_info(capwapbuf, &frag_info) == -1) {
		return -1;
	}

	if (ah_capwap_analysecolmsg(capwapbuf + colmsglen, frag_info) == -1) {
		ah_dbg_old(capwap_info, "CAPWAP:analyse control msg error!(control message length:%d)", colmsglen);
		return -1;
	}
	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_analysetlvmsg
 *
 * Purpose:   analyse the cpawap TLV part
 *
 * Inputs:    capwaptlvmsg: capwap packet
 *            tlvtype:  T for tlv
 *            totlelen: all len for TLV
 *
 * Output:    tlvlen:   current L for tlv
 *            tlvvalue: current V for tlv
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_analysetlvmsg(char *capwaptlvmsg, uint32_t tlvtype, uint16_t *tlvlen, char *tlvvalue,
							uint32_t    totletlvlen)
{
	uint16_t    len = 0;
	uint32_t    type = 0;
	uint32_t    tlvoffset = 0;

	if (capwaptlvmsg == NULL) {
		ah_log_old(AH_LOG_INFO, "CAPWAP control message is null!\n");
		return -1;
	}

	while (tlvoffset < totletlvlen) {
		/*Get type*/
		type = ntohl(*(uint32_t *)(capwaptlvmsg + tlvoffset));
		tlvoffset = tlvoffset + sizeof(uint32_t);
		/*Get length*/
		len = ntohs(*(short *)(capwaptlvmsg + tlvoffset));
		if (len <= 0) {
			ah_log_old(AH_LOG_INFO, "CAPWAP can not find the proper request %d, Maybe HM doesn't support it.", tlvtype);
			return -1;
		}
		tlvoffset = tlvoffset + sizeof(short);

		/*Get value*/
		if (type == tlvtype) {
			ah_memcpy(tlvvalue, capwaptlvmsg + tlvoffset, len);
			ah_dbg_old(capwap_info, "the type is %d, the len is %d the value is :\n", type, len);
			if (capwap_packet) {
				ah_hexdump((uchar *)tlvvalue, len);
			}
			ah_capwap_evtpkt_print_filter(tlvvalue, (uint32_t)len, type, AH_CAPWAP_DBGPKT_RX);
			*tlvlen = len;
			return 0;
		}
		tlvoffset = tlvoffset + len;
	}
	if (tlvoffset == totletlvlen) {
		ah_dbg_old(capwap_info, "CAPWAP can not find the request which type is %d\n!", tlvtype);
		*tlvlen = 0;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_discoveryopt
 *
 * Purpose:   analyse the cpawap discovery response packet
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:  all len for TLV
 *            seq_num:   sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_discoveryopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AC_DESCRIBE    1
#define AC_NAME  4
#define WTP_MAN_COL_IPV4 10
#define WTP_MAN_COL_IPV6 11
#define AH_CAPWAP_AC_MAC 6005
#define AH_CAPWAP_DTLS_NEGOTIATION 6007

	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char       tlvvalue[AH_CAPWAP_BUF_LEN];

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		return ;
	}
#if 0 /*now our HM don't support these options.*/
	/*get the AC Descriptor*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AC_DESCRIBE, &tlvlen, tlvvalue, totlelen) == -1) {
		return ;
	}
	if (tlvlen <= 0) {
		return ;
	}
	curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get the AC Name*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AC_NAME, &tlvlen, tlvvalue, totlelen) == -1) {
		return ;
	}
	if (tlvlen <= 0) {
		return ;
	}
	curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*get the WTP Manager Control IPv4 Address*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, WTP_MAN_COL_IPV4, &tlvlen, tlvvalue, totlelen) == -1) {
		return ;
	}
	if (tlvlen <= 0) {
		return ;
	}
	curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	/*
	   need get ac ip then send to the real ac
	   ah_capwap_info.acip = ntohl(*(uint32_t*)(tlvvalue));
	 */


	/*get the WTP Manager Control IPv6 Address*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, WTP_MAN_COL_IPV6, &tlvlen, tlvvalue, totlelen) == -1) {
		return ;
	}
	if (tlvlen <= 0) {
		return ;
	}
	curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
#endif
	/*get the AC MAC*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_AC_MAC, &tlvlen, tlvvalue, totlelen) == 0 && tlvlen != 0) {
		ah_dbg_old(capwap_info, "Get CAPWAP AC mac is:\n");
		if (capwap_info) {
			ah_hexdump((uchar *)tlvvalue, AH_CAPWAP_MAC_LEN);
		}
		memcpy(ah_capwap_info.acmac, tlvvalue, AH_CAPWAP_MAC_LEN);
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}

	/*get the DTLS negotiation*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_DTLS_NEGOTIATION, &tlvlen, tlvvalue, totlelen) == 0 && tlvlen != 0) {
		ah_dbg_old(capwap_info, "Get CAPWAP DTLS negotiation is:\n");
		if (capwap_info) {
			ah_hexdump((uchar *)tlvvalue, tlvlen);
		}
		if (ah_capwap_dtls_get_negotiation_status() == AH_CAPWAP_DTLS_NEGOTIATION_ENABLE) {
			ah_dbg_old(capwap_info, "dtls negotiation set dtls status:%d\n", tlvvalue[0]);
			ah_capwap_dtls_set_enable_status(tlvvalue[0]);
		}
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}
	return ;
}

/***************************************************************************
 *
 * Function:  ah_capwap_chgeventopt
 *
 * Purpose:   analyse the cpawap change state event response packet
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_chgeventopt(char *optbuf, uint32_t totlelen, uint seq_num)
{

	/*Set first delay status to major to send clear trap to HM when AP reconnect*/
	ah_capwap_set_delay_alarm(AH_CAPWAP_DELAY_ALARM_MAJOR);
	ah_capwap_set_alarm_init_status(TRUE);
	ah_dbg_old(capwap_delay, "Reconnect to HM, set delay flag to major");

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_runopt
 *
 * Purpose:   analyse the cpawap run echo response packet
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_runopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_ECHO_RCV_TIME (5012)
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	ah_capwap_delay_offset_t offset;
	ah_capwap_round_trip_time_t trip;
	struct timeval tv;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		return ;
	}
	gettimeofday(&tv, NULL);
	/*get the echo receive time*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_ECHO_RCV_TIME, &tlvlen, (char *)&offset, totlelen) == 0
		&& tlvlen != 0) {
		ah_dbg_old(capwap_info, "Get CAPWAP ECHO receive time:\n");
		if (capwap_info) {
			ah_hexdump((uchar *)&offset, tlvlen);
		}
		/*handle offset*/
		offset.snd_req_second = ntohl(offset.snd_req_second);
		offset.snd_req_usecond = ntohl(offset.snd_req_usecond);
		offset.rcv_req_second = ntohl(offset.rcv_req_second);
		offset.rcv_req_usecond = ntohl(offset.rcv_req_usecond);
		offset.snd_rsp_second = ntohl(offset.snd_rsp_second);
		offset.snd_rsp_usecond = ntohl(offset.snd_rsp_usecond);
		offset.rcv_rsp_second = tv.tv_sec;
		offset.rcv_rsp_usecond = tv.tv_usec;
#if 0
		if (ah_capwap_handle_delay_offset(&offset) != 0) {
			return;
		}
#endif
		/*handle delay arlarm*/
		trip.snd_second = offset.snd_req_second;
		trip.snd_usecond = offset.snd_req_usecond;
		trip.rcv_second = offset.rcv_rsp_second;
		trip.rcv_usecond = offset.rcv_rsp_usecond;
		ah_capwap_handle_alarm(ah_capwap_get_rount_trip_time(&trip));

		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}

	return;
}

int ah_capwap_get_request_time(char *buff, uint32_t totlelen)
{
#define AH_CAPWAP_GET_REQUEST_SND_TIME (5011)
#define AH_CAPWAP_ROUND_TRIP_NUM_LEN (2)
	uint16_t    tlvlen = 0;
	ah_capwap_round_trip_time_t trip;
	struct timeval tv;

	if (ah_capwap_get_delay_average(TRUE) == 0) {
		ah_dbg_old(capwap_delay, "There haven't delay offset calibration, skip this data");

		return 0;
	}

	if (ah_capwap_analysetlvmsg(buff, AH_CAPWAP_GET_REQUEST_SND_TIME, &tlvlen, (char *)&trip, totlelen) == 0
		&& tlvlen != 0) {
		gettimeofday(&tv, NULL);
		trip.snd_second = htonl(trip.snd_second);
		trip.snd_usecond = htonl(trip.snd_usecond);
		trip.rcv_second = tv.tv_sec;
		trip.rcv_usecond = tv.tv_usec;

		ah_capwap_handle_alarm(ah_capwap_get_rount_trip_time(&trip));
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_snd_confirm
 *
 * Purpose:   send the confirm packet for HM's request
 *
 * Inputs:    capwap_state: capwap state
 *            pkt_type:  capwpa packet type
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_snd_confirm(uint32_t capwap_state, uint32_t pkt_type, uint seq_num)
{
	uint32_t    pkt_len = 0;
	char      *rsp_pkt = NULL;
	int      rc = -1;

	/*malloc memory*/
	rsp_pkt = ah_malloc(AH_CAPWAP_BUF_LEN);
	if (rsp_pkt == NULL) {
		ah_err_old("CAPWAP:malloc memory for confirm packet failed! (size:%d)\n", AH_CAPWAP_BUF_LEN);
		goto OUT;
	}
	/*fill the packet*/
	if (ah_capwap_packet_client(rsp_pkt, &pkt_len, pkt_type, capwap_state, seq_num) == -1) {
		ah_err_old("CAPWAP:generate the response packet failed!\n");
		goto OUT;
	}
	if (pkt_len <= 0) {
		ah_err_old("CAPWAP:the response packet len is error!(packet len:%d)\n", pkt_len);
		goto OUT;
	}
#if 0 /*commnet it, see bug 8309*/
	/*choose send packet  module*/
	if (ah_capwap_dtls_get_enable_status() == AH_CAPWAP_DTLS_ENABLE && capwap_state != AH_CAPWAP_DISCOVERY) {
		ah_dbg_old(capwap_ssl, "Send the DTLS confirm packet (state:%s len:%d)\n", ah_capwap_get_state_string(capwap_state), pkt_len);
		if (ah_capwap_dtls_encrypt(rsp_pkt, pkt_len) == -1) {
			ah_err_old("CAPWAP send dtls packet error (confirm packet)!");
			goto OUT;
		}
	} else {
		/*send the packet*/
		if (sendto(ah_capwap_para.sock, rsp_pkt, pkt_len, 0, (struct sockaddr *)&ah_capwap_para.capwapaddr,
				   sizeof(ah_capwap_para.capwapaddr)) == -1) {
			ah_log_old(AH_LOG_DEBUG, "CAPWAP send request confirm packet error!\n");
			goto OUT;
		}
	}
#endif
	/*send the packet*/
	if (ah_capwap_client_send(rsp_pkt, pkt_len) == -1) {
		ah_log_old(AH_LOG_INFO, "CAPWAP send request confirm packet(type:%d) error!, reason:%s\n", pkt_type, strerror(errno));
		goto OUT;
	}

	ah_dbg_old(capwap_info, "SENDPKT->Send the request confirm packet(type:%d)\n", pkt_type);
	ah_capwap_evtpkt_print_filter(rsp_pkt, pkt_len, pkt_type, AH_CAPWAP_DBGPKT_TX);

	rc = 0;
OUT:
	if (rsp_pkt != NULL) {
		ah_free(rsp_pkt);
	}
	return rc;
}

/***************************************************************************
 *
 * Function:  ah_capwap_deal_L3_config
 *
 * Purpose:   handle L3 config
 *
 * Inputs:    config_len: config len
 *            config:   config buff
 *
 * Output:    void
 *
 * Returns:   0 success, otherwise -1
 *
 **************************************************************************/
int ah_capwap_deal_L3_config(uint32_t config_len, char *config)
{
	if (capwap_info) {
		ah_dbg_old(capwap_info, "Rcv L3 Romain configuration....\n");
		ah_hexdump((uchar *)config, config_len);
	}

	/*the value's struct is:
	 * Roaming port/Neighbor interval/Number of queries/Cache interval/Number of queries/Numbers of type_ip_mask
	 * Type/IP/Mask.....*/
	/*send a event to other module*/
	if (ah_event_send(AH_EVENT_L3_CONFIG, config_len, config) < 0) {
		ah_err_old("CAPWAP:send event AH_EVENT_L3_CONFIG failed!\n");
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_staopt
 *
 * Purpose:   handle statistic request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_staopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_STA_TBL 6004
	short                           curlen = 0;
	uint16_t                         tlvlen = 0;
	char                            *tlvvalue = NULL;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get cli request pkt tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the sta table*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_STA_TBL, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		/*send configuration packet reponse*/
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_STA_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send statistical response packet error!\n");
			goto OUT;
		}
		ah_capwap_stat_parse_packet(tlvvalue, tlvlen);
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}

OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_abort_save_image
 *
 * Purpose:   handle abort save image command
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_abort_save_image(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_ABORT_IMAEG_DATA 6010
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the operation buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get abort save image pkt tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the abort save image parameters*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_ABORT_IMAEG_DATA, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		/*send back the result reponse*/
		abort_save_type = *(uint32_t *)(tlvvalue);
		ah_dbg_old(capwap_info, "receive abort save image request, save type:%d\n", abort_save_type);
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_ABORT_IMAGE_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send abort image response packet error!\n");
			goto OUT;
		}
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}

OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_cwp_directory
 *
 * Purpose:   handle get cwp directory request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_cwp_directory(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_GET_CWP_DIRECTORY 6009
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;
	uint32_t    req_num = 0;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the operation buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get CWP directory pkt tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the abort save image parameters*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_GET_CWP_DIRECTORY, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		/*send back the result reponse*/
		req_num = *(uint32_t *)(tlvvalue);
		ah_dbg_old(capwap_info, "receive get cwp request, sequence number:%d\n", req_num);
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_GET_CWP_DIR_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send abort image response packet error!\n");
			goto OUT;
		}
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
		/*send event to DCD*/
		if (ah_event_send(AH_EVENT_QUERY_ACTIVE_WEB_DIR, sizeof(req_num), &req_num) < 0) {
			ah_err_old("CAPWAP:send CWP directory request event error! (idp_seq:%d)\n", req_num);
		}
		ah_dbg_old(capwap_info, "Send CWP directory request event to DCD!(idp_seq:%d)\n", req_num);
	}

OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_uncompress_packet
 *
 * Purpose:   handle CLI request uncompress packet
 *
 * Inputs:    buff: uncompress packet buffer
 *                 buff_len: the max buffer len
 *                zip_buff: the compress buff
 *                zip len: the zip len
 *            compress_header: compress header len
 *
 * Output:    void
 *
 * Returns:   0 is success, -1 is failed
 *
 **************************************************************************/
int ah_capwap_uncompress_packet(char *buff, ulong *buff_len, char *zip_buff, uint16_t zip_len,
								uint16_t    header_len)
{
	ulong      expect_len = *buff_len;

	ah_dbg_old(capwap_info, "the compress len is:%d, header len:%d\n", zip_len, header_len);

	if (uncompress((uchar *)buff, buff_len, (uchar *)(zip_buff + header_len), (zip_len - header_len)) != Z_OK) {
		ah_err_old("%s: Uncompress packet failed.", __func__);
		return -1;
	}

	if (*buff_len != expect_len) {
		ah_err_old("CAPWAP: expcet uncompress packet len is:%d, acture len: %d\n", expect_len, buff_len);
		return -1;
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_cliopt
 *
 * Purpose:   handle CLI request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:  all len for TLV
 *            seq_num:   sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_cliopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_CLI_CONFG 6003
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;
	char      compress_flag = 0;
	ulong      uncompress_size = 0;
	char      *p = NULL;
	uint16_t    compress_header = AH_CAPWAP_COMPRESS_FLAG_LEN + AH_CAPWAP_UNCOMPRESS_SIZE_LEN;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get cli request pkt tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the config CLI*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_CLI_CONFG, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		ah_dbg_old(capwap_info, "Get the config CLI request...(length:%d)\n", tlvlen);
		if (capwap_info) {
			ah_hexdump((uchar *)tlvvalue, tlvlen);
		}
		/*check compress or not*/
		/*packet format is: <compress flag>/<uncompress len>/<packet>*/
		compress_flag = *(char *)(tlvvalue);
		ah_dbg_old(capwap_info, "the CLI request compress flag is:%d\n", compress_flag);
		if (compress_flag == AH_CAPWAP_CLI_COMPRESS_PACKET) {
			/*get uncompress size*/
			uncompress_size = ntohl(*(uint32_t *)(tlvvalue + AH_CAPWAP_COMPRESS_FLAG_LEN));
			ah_dbg_old(capwap_info, "the CLI request uncompress size is:%d\n", uncompress_size);
			p = ah_malloc(uncompress_size);
			if (p == NULL) {
				ah_err_old("CAPWAP: malloc for uncompress delta config failed! malloc len:%d", uncompress_size);
				goto OUT;
			}
			if (ah_capwap_uncompress_packet(p, &uncompress_size, tlvvalue, totlelen, compress_header) == -1) {
				goto OUT;
			}
			ah_capwap_cli_ui_rcv_data(p, uncompress_size);
		} else {
			ah_capwap_cli_ui_rcv_data(tlvvalue + compress_header, tlvlen - compress_header);
		}
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}

	/*send configuration packet reponse*/
	if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_CLI_RESPONSE, seq_num) < 0) {
		ah_err_old("CAPWAP:send configuration response packet error!\n");
	}

OUT:
	if (p != NULL) {
		ah_free(p);
	}
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;

}

/***************************************************************************
 *
 * Function:  ah_capwap_rcv_ssh_key
 *
 * Purpose:   handle change ssh key
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_rcv_ssh_key(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_RCV_SSH_KEY 6012
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;
	char      compress_flag = 0;
	ulong      orign_len = 0;
	char      *p = NULL;
	char      *buf = NULL;
	uint16_t    compress_header = AH_CAPWAP_COMPRESS_FLAG_LEN + AH_CAPWAP_UNCOMPRESS_SIZE_LEN;
	uint32_t    ssh_seq = 0;
	uint32_t    rst_flag = 0;
	char      rst_buf[8] = {0};
	uint32_t    key_len = 0;
	char      ip_str[33] = {0};

	extern int ah_save_ssh_key(char *buf, uint len, char *addr);
	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the operation buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get ssh key tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the abort save image parameters*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_RCV_SSH_KEY, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		compress_flag = *(char *)(tlvvalue);
		if (compress_flag == 1) {
			orign_len = ntohl(*(uint32_t *)(tlvvalue + AH_CAPWAP_COMPRESS_FLAG_LEN));
			ah_dbg_old(capwap_info, "This is a compress packet about ssh key, orign length is:%d\n", orign_len);
			buf = ah_malloc(orign_len );
			p = buf;
			if (p == NULL) {
				ah_err_old("CAPWAP: malloc for uncompress ssh key failed! malloc len:%d", orign_len);
				goto OUT;
			}
			if (ah_capwap_uncompress_packet(p, &orign_len , tlvvalue, totlelen, compress_header) == -1) {
				goto OUT;
			}
			ssh_seq = ntohl(*(uint32_t *)(p));
			/*we need get rid of sequence number len*/
			key_len = orign_len - sizeof(uint32_t);
			ah_dbg_old(capwap_info, "ssh key seq number is:%d, ssh key len:%d\n", ssh_seq, key_len);
		} else {
			ah_dbg_old(capwap_info, "This is not a compress packet about ssh key, orign length is:%d\n", tlvlen);
			ssh_seq = ntohl(*(uint32_t *)(tlvvalue + compress_header));
			p = tlvvalue + compress_header;
			/*we need get rid of compress flag/orign length/sequence number len*/
			key_len = tlvlen - sizeof(char) - sizeof(uint32_t) - sizeof(uint32_t);
			ah_dbg_old(capwap_info, "ssh key seq number is:%d, ssh key len:%d\n", ssh_seq, key_len);
		}
		/*send back the result reponse*/
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_SSH_KEY_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send ssh key response packet error!\n");
			goto OUT;
		}
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

		/*call jerry's api, the ac ip is host order*/
		ah_sprintf(ip_str, "%i", htonl(ah_capwap_info.acip));
		rst_flag = ah_save_ssh_key(p + sizeof(uint32_t), key_len, ip_str);
		if (rst_flag) {
			ah_log_old(AH_LOG_NOTICE, "CAPWAP:save ssh key file failed.");
		}

		/*send the result to HM*/
		*(uint32_t *)(rst_buf) = htonl(ssh_seq);
		*(uint32_t *)(rst_buf + sizeof(uint32_t)) = htonl(rst_flag);
		ah_dbg_old(capwap_info, "send ssh key result %d and seq number %d to HM\n", rst_flag, ssh_seq);
		ah_capwap_send_event_itself(sizeof(rst_buf), rst_buf, AH_CAPWAP_EVENT_SSH_KEY);
	}

OUT:
	if (buf != NULL) {
		ah_free(buf);
	}
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}


#if defined(AH_SUPPORT_IDP)
/***************************************************************************
 *
 * Function:  ah_capwap_handle_idp_mitigation_request
 *
 * Purpose:   handle event information mitigation request
 *
 * Inputs:    optbuf: capwap idp mitigation packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_handle_idp_mitigation_request(uint32_t buf_len, char *rqt_buff)
{
	/*get query type and cookie*/
	uint16_t    query_type = 0;
	uint32_t    cookie_id = 0;
	char      *data = NULL;
	int      data_len = 0;
	int      rc = 0;

	query_type = ntohs(*(uint16_t *)(rqt_buff));
	cookie_id = ntohl(*(uint32_t *)(rqt_buff + sizeof(uint16_t)));

	/* we need to return msg header to HM if no idp sta item */
	data = malloc(sizeof(ah_capwap_idpsta_msg_t));
	if (data == NULL) {
		ah_err_old("CAPWAP IDP: no memory\n");
		rc = -1;
		goto out;
	}
	memset(data, 0, sizeof(ah_capwap_idpsta_msg_t));

	ah_dbg_old(capwap_idp, "Get idp mitigation quer type:%d, cookie id:%d\n", query_type, cookie_id);

	rc = ah_capwap_idp_get_allsta(query_type, cookie_id, &data, &data_len);
	ah_dbg_old(capwap_idp, "Get idp mitigation data, rc =%d", rc);
	if (rc == -1) {
		ah_log_old(AH_LOG_ERR, "CAPWAP:Get idp mitigation data failed.");
		goto out;
	}
	if (data != NULL && data_len > 0) {
		ah_capwap_send_event_itself(data_len, (char *)data, AH_CAPWAP_EVENT_SEND_RESPONSE);
		ah_capwap_interrupt_listen();
	} else {
		ah_dbg_old(capwap_idp, "idp migigation data is null or data length is 0 (data_len:%d)", data_len);
	}

out:
	if (data != NULL) {
		free(data);
	}
	return rc;
}
#endif  //#if defined(AH_SUPPORT_IDP)


#if defined(AH_SUPPORT_LTR)
/***************************************************************************
 *
 * Function:  ah_capwap_handle_location_track_request
 *
 * Purpose:   handle event information location track request
 *
 * Inputs:    optbuf: capwap idp mitigation packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_handle_location_track_request(uint32_t buf_len, char *rqt_buff)
{
	ah_dbg_old(capwap_info, "CAPWAP:send handle location track request to DCD");
	if (ah_event_send(AH_EVENT_LOCATION_TRACK_IN, buf_len, rqt_buff) < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: send query location track  request failed!");
	}

	return 0;
}
#endif

/***************************************************************************
 *
 * Function:  ah_capwap_handle_pkt_cpt_stat_request
 *
 * Purpose:   handle event information packet caputre request
 *
 * Inputs:    optbuf: capwap idp mitigation packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
int ah_capwap_handle_pkt_cpt_stat_request(uint32_t buf_len, char *rqt_buff)
{
	ah_dbg_old(capwap_info, "CAPWAP:send handle packet capture statistic request to DCD");
	if (ah_event_send(AH_EVENT_PKT_CPT_STAT_QUERY, buf_len, rqt_buff) < 0) {
		ah_log_old(AH_LOG_ERR, "CAPWAP: send query packet capture statistic request failed!");
	}

	return 0;
}

/***************************************************************************
 *
 * Function:  ah_capwap_info_query_request
 *
 * Purpose:   handle event information query request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_info_query_request(char *optbuf, uint32_t totlelen, uint seq_num)
{
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;
	int16_t    event_num = 0;
	int      i = 0;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the operation buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get information query value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the information query parameters*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_INFO_QUERY_REQUEST, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		/*malloc packet for send confirm*/
		confirm_pkt_info = ah_malloc(tlvlen); /*free in function ah_capwap_fillopt_info_query_result*/
		if (confirm_pkt_info == NULL) {
			ah_err_old("CAPWAP:malloc for get information query confirm response value error!(size:%d)\n", tlvlen);
			goto OUT;
		}
		ah_memcpy(confirm_pkt_info, tlvvalue, tlvlen);
		/*send back the result reponse*/
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_INFORMATION_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send information query response packet error!\n");
			if (confirm_pkt_info != NULL) {
				ah_free(confirm_pkt_info);
				confirm_pkt_info = NULL;
			}
			goto OUT;
		}
		/*find the correspond callback function to handle it*/
		event_num = sizeof(capwap_info_query_handle_request) / sizeof(capwap_info_query_handle_request[0]);
		for (i = 0; i < event_num; i++) {
			if (capwap_info_query_handle_request[i].info_id == ntohs(*(uint16_t *)(tlvvalue))) {
				if (capwap_info_query_handle_request[i].ah_capwap_info_query_callback != NULL) {
					capwap_info_query_handle_request[i].ah_capwap_info_query_callback(tlvlen, tlvvalue);
				}
				curlen += tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
				break;
			}
		}
		if (i == event_num) {
			ah_log_old(AH_LOG_INFO, "CAPWAP: can not find the information type request id (%d).", ntohs(*(uint16_t *)(tlvvalue)));
		}
	}

OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}


/***************************************************************************
 *
 * Function:  ah_capwap_event_info_request
 *
 * Purpose:   handle event information request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen: all len for TLV
 *            seq_num:  sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_event_info_request(char *optbuf, uint32_t totlelen, uint seq_num)
{
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;
	int16_t    event_num = 0;
	int      i = 0;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the operation buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get event information value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the event information parameters*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_EVENT_GET_REQUEST, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	if (tlvlen > 0) {
		/*malloc packet for send confirm*/
		confirm_pkt_info = ah_malloc(tlvlen); /*free in function ah_capwap_fillopt_event_query_result*/
		if (confirm_pkt_info == NULL) {
			ah_err_old("CAPWAP:malloc for get information event confirm response value error!(size:%d)\n", tlvlen);
			goto OUT;
		}
		ah_memcpy(confirm_pkt_info, tlvvalue, tlvlen);
		/*send back the result reponse*/
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_EVENT_INFO_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send event information response packet error!\n");
			if (confirm_pkt_info != NULL) {
				ah_free(confirm_pkt_info);
				confirm_pkt_info = NULL;
			}
			goto OUT;
		}
		/*find the correspond callback function to handle it*/
		event_num = sizeof(capwap_event_handle_request) / sizeof(capwap_event_handle_request[0]);
		for (i = 0; i < event_num; i++) {
			if (capwap_event_handle_request[i].event_id == ntohs(*(uint16_t *)(tlvvalue))) {
				if (capwap_event_handle_request[i].ah_capwap_event_callback != NULL) {
					capwap_event_handle_request[i].ah_capwap_event_callback(tlvlen, tlvvalue);
				}
				curlen += tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
				break;
			}
		}
		if (i == event_num) {
			ah_log_old(AH_LOG_INFO, "CAPWAP: can not find the event request id (%d).", ntohs(*(uint16_t *)(tlvvalue)));
		}
	}

OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}


/***************************************************************************
 *
 * Function:  ah_capwap_configopt
 *
 * Purpose:   handle config request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:  all len for TLV
 *            seq_num:   sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_configopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_L3_CONFG 6000
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		return ;
	}

	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get configuration request pkt tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the L3 romaing configuration*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_L3_CONFG, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	/*if not found the type, tlvlen is 0*/
	if (tlvlen > 0) {
		ah_capwap_deal_L3_config(tlvlen, tlvvalue);
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}


	if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_CONFIG_RESPONSE, seq_num) < 0) {
		ah_err_old("CAPWAP:send configuration response packet error!\n");
	}

OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}

	return;
}


#if defined(AH_SUPPORT_IDP)
/***************************************************************************
 *
 * Function:  ah_capwap_idpopt
 *
 * Purpose:   handle IDP request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:    all len for TLV
 *            seq_num:     sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_idpopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_IDP_SEQ 6006
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      *tlvvalue = NULL;;
	uint32_t    idp_seq  = 0;

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		goto OUT;
	}
	tlvvalue = ah_malloc(totlelen);
	if (tlvvalue == NULL) {
		ah_err_old("CAPWAP:malloc for get configuration request pkt tlv value error!(size:%d)\n", totlelen);
		goto OUT;
	}

	/*get the idp sequence*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_IDP_SEQ, &tlvlen, tlvvalue, totlelen) == -1) {
		goto OUT;
	}
	/*if not found the type, tlvlen is 0*/
	if (tlvlen > 0) {
		/*send configuration packet reponse*/
		if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_IDP_RESPONSE, seq_num) < 0) {
			ah_err_old("CAPWAP:send configuration response packet error!\n");
			goto OUT;
		}

		idp_seq = ntohl(*(uint32_t *)tlvvalue);
		/*Don't need do anything, only send event to request all IDP information*/
		if (ah_event_send(AH_EVENT_CAPWAP_IDP_PULL, sizeof(idp_seq), &idp_seq) < 0) {
			ah_err_old("CAPWAP:send IDP request event error! (idp_seq:%d)\n", idp_seq);
		}
		ah_dbg_old(capwap_info, "Send IDP request event to DCD!(idp_seq:%d)\n", idp_seq);
		curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;
	}
	ah_dbg_old(capwap_info, "Send IDP response to HM!\n");
OUT:
	if (tlvvalue != NULL) {
		ah_free(tlvvalue);
	}
	return;
}
#endif

/***************************************************************************
 *
 * Function:  ah_capwap_joinopt
 *
 * Purpose:   handle join response
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:  all len for TLV
 *            seq_num:   sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_joinopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
	/*now we need not any options from HM*/

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_eventopt
 *
 * Purpose:   handle event packet response
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:   all len for TLV
 *            seq_num:    sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_eventopt(char *optbuf, uint32_t totlelen, uint seq_num)
{
	/*deleter the confirm packet in event buffer*/
	ah_capwap_event_del_msg(seq_num);

	return;
}

/***************************************************************************
 *
 * Function:  ah_capwap_chg_event_opt
 *
 * Purpose:   handle change event switch request
 *
 * Inputs:    optbuf: capwap packet
 *            totlelen:   all len for TLV
 *            seq_num:    sequenct numer for this packet
 *
 * Output:    void
 *
 * Returns:   void
 *
 **************************************************************************/
void ah_capwap_chg_event_opt(char *optbuf, uint32_t totlelen, uint seq_num)
{
#define AH_CAPWAP_CHG_EVENT_STAUS 6002
	short      curlen = 0;
	uint16_t    tlvlen = 0;
	char      tlvvalue[10];

	if (NULL == optbuf) {
		ah_err_old("CAPWAP:the OPT buf is null! \n");
		return ;
	}
	/*get change event status flag*/
	if (ah_capwap_analysetlvmsg(optbuf + curlen, AH_CAPWAP_CHG_EVENT_STAUS, &tlvlen, tlvvalue, totlelen) == -1) {
		ah_err_old("CAPWAP:Analyse change event status failed!\n");
		return;
	}
	if (tlvlen <= 0) {
		return;
	}

	curlen = curlen + tlvlen + AH_CAPWAP_TLV_TYPE_LEN + AH_CAPWAP_TLV_LENGTH_LEN;

	if (ah_capwap_snd_confirm(AH_CAPWAP_RUN, AH_CAPWAP_CHG_EVENT_PESPONSE, seq_num) < 0) {
		ah_err_old("CAPWAP:send change event status response packet failed!\n");
	}

	/*change event status
	comments:if the status(for example:MP_PORTAL) status changed between join and run status phase.
	then the HM only get the old status because the switch is off by default. so there maybe has a mistake in default is off*/
	if (tlvvalue[0] == AH_CAPWAP_EVENT_SND_OFF) {
		ah_log_old(AH_LOG_NOTICE, "HM try to disable the CAPWAP send event flag, ignore it\n");
		/* always enable it bug 29881 */
		ah_capwap_para.event_flag = AH_CAPWAP_EVENT_SND_ON;
	} else {
		ah_dbg_old(capwap_info, "Enable the CAPWAP send event!\n");
		ah_capwap_para.event_flag = AH_CAPWAP_EVENT_SND_ON;
	}

	return;
}

#ifdef AH_SUPPORT_TV
int ah_capwap_event_tv_found_studs(uint32_t len, char *data)
{
	if (ah_event_send(AH_EVENT_TV_CAPWAP_REQ_WEBUI, len, data) < 0) {
		ah_dbg_old(capwap_info, "CAPWAP: send tv found event failed.\n");
		return -1;
	}

	return 0;
}
#endif
#if defined(AH_SUPPORT_IDP)
#define AH_CAPWAP_IDP_CLF_MAX_NUM_PER_MSG ((AH_EVENT_MAX_LEN - sizeof(ah_event_msg_t) - sizeof(ah_idp_ap_clf_capwap_msg_t)) / \
		sizeof(ah_idp_ap_clf_info_t))

int ah_capwap_send_idp_ap_clf_event(ah_idp_ap_clf_capwap_unit_t *capwap_unit, char *info, uint32_t info_len,
									uint16_t    info_num, uint16_t clf_num)
{
	ah_idp_ap_clf_capwap_msg_t *clf_msg;
	uint32_t    msg_len = info_len + sizeof(ah_idp_ap_clf_capwap_msg_t);

	clf_msg = ah_malloc(msg_len);
	if (NULL == clf_msg) {
		ah_err_old("CAPWAP: failed allocated buffer\n");
		return -1;
	}

	memcpy(&clf_msg->idp_capwap_unit, capwap_unit, sizeof(ah_idp_ap_clf_capwap_unit_t));
	clf_msg->idp_capwap_unit.num = clf_num;
	clf_msg->total_clf_num = info_num;
	clf_msg->data_len = info_len + sizeof(ah_idp_ap_clf_capwap_unit_t);
	memcpy(clf_msg->idp_capwap_unit.info, info, info_len);

	ah_dbg_old(capwap_idp, "CAPWAP: send IDP AP CLF list: total_clf_num %d!\n", clf_msg->total_clf_num);
	ah_idp_capwap_msg_hton(clf_msg);

	if (ah_event_send(AH_EVENT_IDP_AP_CLF_HM_SEND, msg_len, clf_msg) < 0) {
		ah_dbg_old(capwap_info, "CAPWAP: send tv found event failed.\n");
		ah_free(clf_msg);
		return -1;
	}
	ah_free(clf_msg);
	return 0;
}

int ah_capwap_handle_idp_ap_clf_hm(uint32_t len, char *data)
{
	ah_idp_ap_clf_capwap_unit_t *capwap_unit;
	uint16_t    info_num;
	uint      i, clf_num = 0;
	int32_t    reply = -1;
	uint32_t    payload_len = 0;
	char      *payload = NULL;
	char      buff[AH_EVENT_MAX_LEN];
	uint32_t    buff_len = 0;
	int      ret = 0;

	ah_dbg_old(capwap_info, "Get HM's event request, event id:%d\n", ah_capwap_get_request_type(data));

	/*get capwap request payload data*/
	reply = ah_capwap_get_request_payload(data, &payload_len, &payload);
	/*send the result of receive:0:success, -1:failure to HM*/
	ah_capwap_send_event_payload(AH_EVENT_IDP_AP_CLF_DA_SEND,
								 &reply,
								 sizeof(int32_t),
								 data);

	if ((payload_len == 0) || (payload == NULL)) {
		ah_dbg_old(capwap_info, "CAPWAP: No IDP AP CLF data received from HM!\n");
		return -1;
	}


	capwap_unit = (ah_idp_ap_clf_capwap_unit_t *)payload;

	ah_idp_capwap_unit_ntoh(capwap_unit);

	info_num = capwap_unit->num;

	memset(buff, 0, AH_EVENT_MAX_LEN);

	for (i = 0; i < info_num; i++) {
		/* If adding the next classfiy ap, the capwap msg length cann't exceed the max event length */
		if (clf_num == AH_CAPWAP_IDP_CLF_MAX_NUM_PER_MSG) {
			ret = ah_capwap_send_idp_ap_clf_event(capwap_unit, buff, buff_len, info_num, clf_num);
			if (ret < 0) {
				ah_dbg_old(capwap_info, "CAPWAP: Send IDP AP CLF event failed!\n");
				return -1;
			}
			buff_len = 0;
			memset(buff, 0, AH_EVENT_MAX_LEN);
			clf_num = 0;
		}
		ah_dbg_old(capwap_info, "CAPWAP: IDP AP CLF: mac %m!\n", capwap_unit->info[i].mac);
		memcpy(buff + buff_len, &capwap_unit->info[i], sizeof(ah_idp_ap_clf_info_t));
		buff_len += sizeof(ah_idp_ap_clf_info_t);
		clf_num ++;
	}

	/* "info_num == 0"  ==> Clear the ap classify list */
	if (clf_num || (info_num == 0)) {
		ret = ah_capwap_send_idp_ap_clf_event(capwap_unit, buff, buff_len, info_num, clf_num);
		if (ret < 0) {
			ah_dbg_old(capwap_info, "CAPWAP: Send IDP AP CLF event failed!\n");
			return -1;
		}
	}
	return 0;
}
#endif
