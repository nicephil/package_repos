#ifndef _AH_CAPWAP_HVCOM_H
#define _AH_CAPWAP_HVCOM_H

#include "list.h"

#define AH_CAPWAP_HVCOM_CONCUR_REQ_NUM 12    /* hivecom support concurrent req number */
#define AH_CAPWAP_HVCOM_REQ_TIMEOUT 600      /* seconds */
#define AH_CAPWAP_HVCOM_RES_TIMEOUT 360      /* seconds */
#define AH_CAPWAP_HVCOM_CHKRES_INTERVAL 10   /* 10 seconds for check response result */
#define AH_CAPWAP_HVCOM_EVTMSG_HDR_LEN 11    /* 2(evttype)+4(cookie)+1(flag)+4(data len)*/

/* 4(msgtype)+2(size of ap list)+2(length of ap info)+6(mac)+4(ip)+1(flag)+4(timeout threshold) */
#define AH_CAPWAP_HVCOM_MIN_EVTMSG_DATA_LEN 23

/* define the capwap nbrcom packet header len */
#define AH_CAPWAP_HVCOM_NBRPKT_HDR_LEN  14    /* 2(optmsg)+4(msgtype)+4(seq_num)+4(playload length)*/
#define AH_CAPWAP_HVCOM_MAXSCP_CONCUR_NUM 5  /* hivecom support concurrent SCP client number */

#define AH_CAPWAP_HVCOM_PORTALAP_AGING_INTERVAL (30*60) /* seconds */

/* packet operation(request/response) type receive from nbrcom  */
typedef enum {
	AH_CAPWAP_HVCOM_OPTMSG_REQUEST = 1,
	AH_CAPWAP_HVCOM_OPTMSG_RESPONSE,
	AH_CAPWAP_HVCOM_OPTMSG_BUTT
} ah_capwap_hvcom_optmsg_type;

/* request/response message type */
typedef enum {
	AH_CAPWAP_HVCOM_MSG_DOWNIMG = 1,
	AH_CAPWAP_HVCOM_MSG_CLI,
	AH_CAPWAP_HVCOM_MSG_DOWNIMG_CANCEL,
	AH_CAPWAP_HVCOM_MSG_HTTP_PROXY_AUTH,
	AH_CAPWAP_HVCOM_MSG_BUTT
} ah_capwap_hvcom_msg_type;

/* send message status */
typedef enum {
	AH_CAPWAP_HVCOM_MSG_STATUS_READY = 1,       /* wait send */
	AH_CAPWAP_HVCOM_MSG_STATUS_PENDING,         /* send but not reply */
	AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_COMPLETE,  /* download image complete but not write in flash */
	AH_CAPWAP_HVCOM_MSG_STATUS_COMPLETE,        /* already receive response */
	AH_CAPWAP_HVCOM_MSG_STATUS_TIMEOUT,         /* time out */
	AH_CAPWAP_HVCOM_MSG_STATUS_SEND_FAIL,       /* send failed */
	AH_CAPWAP_HVCOM_MSG_STATUS_LAST_SEND,       /* use for portal HiveAP upgrade image */
	AH_CAPWAP_HVCOM_MSG_STATUS_RESPONSED,       /* use for single response, means already response hm */
	AH_CAPWAP_HVCOM_MSG_STATUS_DWIMG_CANCEL,    /* use for indicat cancel download image */
	AH_CAPWAP_HVCOM_MSG_STATUS_BUTT             /* max invalid */
} ah_capwap_hvcom_msg_status_type;

/* portal HiveAP response all HiveAP of hive execute result type */
typedef enum {
	AH_CAPWAP_HVCOM_RESHM_TYPE_SINGLE,     /* when portal receive one ap response will send response to HM */
	AH_CAPWAP_HVCOM_RESHN_TYPE_ALL,        /* when portal receive all ap response will send response to HM */
	AH_CAPWAP_HVCOM_RESHM_TYPE_BUTT
} ah_capwap_hvcom_reshm_type;

/* hive comm event message proess state */
typedef enum {
	AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_READY,
	AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_START,
	AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_END,
	AH_CAPWAP_HVCOM_REQ_ANALYSE_STATE_BUTT
} ah_capwap_hvcom_req_analyse_state;

typedef struct ah_capwap_hvcom_nbr {
	uchar       mac[MACADDR_LEN];              /* dest HiveAP mac address */
	uint32_t    ip;                            /* dest HiveAP IP address */
	ah_capwap_hvcom_msg_status_type status;    /* send msg status */
	ulong      snd_time;                       /* send time */
	int32_t    result;                         /* receive exec result */
	struct list_head node;
} ah_capwap_hvcom_nbr_t;

typedef struct ah_capwap_hvcom_nbr_queue {
	uint32_t    msg_type;                    /* event message type */
	uint32_t    seq_num;                     /* request seq_num */
	uint32_t    timeout;                     /* this request timeout threshold */
	uint32_t    state;                       /* request analyse state, use for check is it response and init this request queue */
	uint32_t    msg_len;                     /* receive capwap HiveComm message length */
	uint16_t    count;                       /* dest HiveAP total */
	char        res_type;                    /* reponse HM type */
	char        *msg;                        /* receive capwap HiveComm message content */
	pthread_mutex_t lock;                    /* mutex lock */
	struct list_head list;
} ah_capwap_hvcom_nbr_queue_t;

typedef struct ah_capwap_hvcom_portal_apinfo {
	uint32_t    ip;                           /* portal HiveAP IP address */
	uint32_t    seq_num[AH_CAPWAP_HVCOM_CONCUR_REQ_NUM];
	ulong       last_rcvreq_time;             /* last receive request time */
	pthread_mutex_t lock;
} ah_capwap_hvcom_portal_apinfo_t;


int ah_capwap_hvcom_init(void);
int ah_capwap_hvcom_msg_handle(uint32_t len, char *buff);
int ah_capwap_hvcom_snd_res(uint32_t seq_num, uint32_t msg_type, uint32_t result, uint16_t len, char *buff);
int ah_capwap_hvcom_snd_cmd_res(uint32_t seq_num, char *res_file_path);
boolean ah_capwap_hvcom_chkres_portal(uint32_t seq_num);
boolean ah_capwap_hvcom_chkres_portal_by_time(void);
#endif

