#ifndef AH_CAPWAP_TYPES_H
#define AH_CAPWAP_TYPES_H

#include <sys/socket.h>
#include <arpa/inet.h>

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
#include "ah_smpi.h"
#include "ah_capwap_def.h"
#include "ah_event.h"

/*this struct  for wtp save the current state parameters*/
typedef struct _ah_capwap_wtp_owninfo_t {
	uint32_t    state;                      /*WTP state*/
	uint32_t    event;                      /*WTP event*/
	uint32_t    wtpip;                      /*WTP ip-address*/
	uchar      wtpmac[AH_CAPWAP_MAC_LEN];    /*WTP MAC address*/
	char      wtpsn[AH_CAPWAP_WTP_SN_LEN];  /*WTP SN*/
	uint32_t    meshid;                     /*Mesh ID*/
	uint32_t    acip;                       /*AC ip-address*/
	ushort      acport;                      /*AC source port*/
	char      acmac[AH_CAPWAP_MAC_LEN];     /*AC MAC address*/
	uint32_t    acpri;                      /*the priority of ac ip*/
	uint32_t    connected_flag;        /*the capwap connected flag*/
} ah_capwap_wtp_owninfo_t;

/*this struct for save wtp parameters*/
/*All capwap timer*/
typedef struct _ah_capwap_wtp_timer_t {
	uint32_t    discovery_interval;    /*AH_CAPWAP_TIMER_DISCOVERY*/
	uint32_t    echo_interval;         /*AH_CAPWAP_TIMER_ECHO*/
	uint32_t    max_discovery_interval;/*AH_CAPWAP_TIMER_MAXDISCOVERY*/
	uint32_t    neighbordead_interval; /*AH_CAPWAP_TIMER_NEIGHBORDEAD*/
	uint32_t    silent_interval;       /*AH_CAPWAP_TIMER_SILENT*/
	uint32_t    waitjoin_interval;     /*AH_CAPWAP_TIMER_WAITJOIN*/
	uint32_t    event_interval;        /*AH_CAPWAP_TIMER_EVENT*/
	uint32_t    dtls_cut_interval;     /*AH_CAPWAP_TIMER_DTLS_CUT*/
	uint32_t    dtls_conn_interval;    /*AH_CAPWAP_TIMER_DTLS_CONN*/
} ah_capwap_wtp_timer_t;

/*All capwap counter*/
typedef struct _ah_capwap_wtp_counter_t {
	uint32_t    max_discoveries;       /*MaxDiscoveries times*/
	uint32_t    max_retransmit;        /*MaxRetransmit times*/
	uint32_t    max_dtls_retry;        /*Max dtls retry connect times*/
	uint32_t    discovery_count;       /*DiscoveryCount*/
	uint32_t    discovery_failed_times;/*Discovery Failed number*/
	uint32_t    retransmit_count;      /*Retransmit Counter*/
	uint32_t    dtls_auth_faild;       /*dtls authorize failed times*/
	uint32_t    dtls_retry_num;        /*dtls retry times*/
} ah_capwap_wtp_counter_t;

/*All capwap total number*/
typedef struct _ah_capwap_wtp_number_t {
	uint32_t    timer_num;             /*the totle number for timer */
	uint32_t    option_num;            /*the totle number for capwap packet options*/
	uint32_t    msg_num;               /*the totle number for wtp can received packet type*/
	uint32_t    event_opt_num ;        /*the totle number for capwap event packet option*/
	uint32_t    fsm_chg_num;           /*the totle number for client change state*/
} ah_capwap_wtp_number_t;

typedef enum _ah_capwap_dtls_status_t {
	AH_DTLS_SETUP = 1, /*DTLS setup*/
	AH_DTLS_AUTH,      /*DTLS authorize*/
	AH_DTLS_CONN,      /*DTLS connect*/
	AH_DTLS_TOWN       /*DTLS tear down*/
} ah_capwap_dtls_status_t;

/*All capwap dtls parameters*/
typedef struct _ah_capwap_dtls_t {
	uint32_t    dtls_enable;                                        /*the flag indicate dtls enable or disable*/
	uint32_t    dtls_next_enable;                                   /*the flag indicate dtls next connect enable or disable*/
	ah_capwap_dtls_status_t dtls_status;                            /*the dtls status*/
	char      dtls_bootstrap;                                       /*always accept bootstrap passphrase(Enabled|Disabled)*/
	int      SocketPair[2];                                         /*socket paire to connect SSL*/
	uchar      dft_keyid;                                            /*default dtls key id*/
	uchar      cur_keyid;                                            /*current dtls key id*/
	uchar      bak_keyid;                                            /*backup dtuls key id*/
	char      dtls_dft_phrase[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1];   /*passphrase for default index*/
	char      dtls_cur_phrase[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1];   /*passphrase for current index*/
	char      dtls_bak_phrase[AH_CAPWAP_DTLS_MAX_PHRASE_LEN + 1];   /*passphrase for backup index*/
	char      dtls_dft_footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1]; /*passphrase footprint for default index*/
	char      dtls_cur_footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1]; /*passphrase footprint for current index*/
	char      dtls_bak_footprint[AH_CAPWAP_DTLS_FOOTPRINT_LEN + 1]; /*passphrase footprint for backup index*/
	char      dtls_psk[AH_CAPWAP_DTLS_MAX_PSK_LEN + 1];             /*dtls PSK*/
	ah_capwap_dtls_key_type_t dtls_key_type;                        /*dtls key type*/
	struct ssl_ctx_st   *SslCtxPtr;                                 /*ssl contex*/
	SSL                 *SslConnectionPtr;                          /*ssl*/
	BIO   *SslBioPtr;
	uchar      using_keyid;                                          /*current using keyid*/
} ah_capwap_dtls_info_t;

#ifdef AH_BONJOUR_GATEWAY_SUPPORT
/* 1: proxy configuration is learned by bonjour
 * 2: proxy configuration is configed by CLI */
#define AH_CAPWAP_HTTP_PROXY_CONF_BY_BONJOUR 1
#define AH_CAPWAP_HTTP_PROXY_CONF_BY_CLI     2
#define AH_CAPWAP_HM_ADDR_CONF_BY_BONJOUR 1
#define AH_CAPWAP_HM_ADDR_CONF_BY_CLI     2
#define AH_CAPWAP_HVCOM_REQUEST_HTTP_PROXY_MSG_LEN 128

#define AH_CAPWAP_HTTP_PROXY_CONF_DIR         "/tmp/http_proxy/"
#define AH_CAPWAP_HTTP_PROXY_CONF_FLASH_DIR   "/f/http_proxy/"
#define AH_CAPWAP_HTTP_PROXY_CONF_DONE_FILE   "done_http_proxy.txt"
#define AH_CAPWAP_MAX_STR_LEN  512

struct ah_capwap_tlv_attr_ {
	/* Attribute Format, first bit is AF
	 * if AF equal 1, Attribute Length;
	 * if AF equal 0, Attribute Value */
	uint16_t type;
	uint32_t lorv;
	/* if AF equal 1, Attribute Value append here */
} __packed;
typedef struct ah_capwap_tlv_attr_ ah_capwap_tlv_attr_t;
#define AH_CAPWAP_GEN_TLV             (0x0000)
#define AH_CAPWAP_GEN_TV              (0x8000)
/* mask for type of attribute format */
#define AH_CAPWAP_GEN_MASK            (0x8000)
typedef enum {
	AH_CAPWAP_TLV_HTTP_PROXY_USERNAME = 1,
	AH_CAPWAP_TLV_HTTP_PROXY_PASSWORD,
} ah_capwap_tlv_attr_type_t;
#endif

typedef enum {
	AH_CAPWAP_WD_START = 1,
	AH_CAPWAP_WD_GET_HOSTIP,
	AH_CAPWAP_WD_GET_NMSIP,
	AH_CAPWAP_WD_EVENT_SEND,
	AH_CAPWAP_WD_END,
	AH_CAPWAP_WD_CLIENT
} ah_capwap_wd_flag_t;
typedef struct _ah_capwap_wd_t {
	uint      flag;      /* flag */
	uint      set_time;  /* system uptime when setting */
	uint      offset;    /* time offset */
} ah_capwap_wd_t;



/*the parameters of capwap is the same name of the capwap protocol!! it is very simple to mapping to protocol*/
typedef struct _ah_capwap_wtp_parameter_t {
	ah_capwap_wtp_timer_t capwap_timer;     /*capwap timer struct*/
	ah_capwap_wtp_counter_t capwap_counter; /*capwap counter struct*/
	ah_capwap_dtls_info_t  capwap_dtls;     /*capwap dtls struct*/
	int      enable;                        /*capwap enable flag*/
	uchar      dtls_negotiation;            /*dtls negotiation flag*/
	uint32_t    choose_ac;          /*ac choose level*/
	ah_capwap_wtp_number_t capwap_number;   /*capwap numner struct*/
	uint32_t    state_duration;             /*capwap durate time*/
	uint32_t    listen;                     /*the flag of timer out flag*/
	uint32_t    event;                      /*the flag of rcv event */
	uint32_t    portal_info;                /*the portal info*/
	uint32_t    capwap_port;                /*capwap_port*/
	int      sock;                          /*capwap send and recv pkt socket*/
	short      frag_id;                     /*packet frag id*/
	uchar      seq_num;                     /*packet seq_num*/
	uchar      echo_snd;                    /*the flag of echo snd*/
	uchar      event_flag;                  /*send event or not flag*/
	uchar      img_download;                /*start to download image*/
	pthread_mutex_t ah_capwap_lm;           /*capwap thread lock*/
	pthread_mutex_t ah_capwap_counter_lm; /*capwap counter locker*/
	struct sockaddr_in capwapaddr;          /*capwap send packet struct*/
	char      vhm_name[AH_CAPWAP_MAX_VHM_NAME_LEN + 1]; /*capwap virtual hive manager */
	char      predefine_name[AH_MAX_STR_64_LEN + 1]; /*capwap predefine server name*/
	char      proxy_name[AH_MAX_STR_64_LEN + 1]; /*proxy name*/
	int      proxy_port; /*proxy port*/
	char      proxy_auth_name[AH_MAX_STR_PARM_LEN + 1]; /*proxy authentication name*/
	char      proxy_auth_pswd[AH_MAX_STR_PARM_LEN + 1]; /*proxy authentication password*/
	uint32_t    proxy_content_len;        /*proxy content length*/
#ifdef AH_BONJOUR_GATEWAY_SUPPORT
	char       proxy_cfg_method;
	char       bonjour_service_type;
#endif
	int      enable_discovery_bcast;      /* disable CAPWAP client discovery method broadcast */
	uint      primary_times;       /* capwap try times with primary CLI configuration */
	uint      backup_times;       /* capwap try times with backup CLI configuration */
	ah_capwap_wd_t wd;            /* for debug watchdog issue */
} ah_capwap_wtp_parameter_t;

/*this struct and funccall is for timer to call back*/
typedef void (* ah_capwap_timer_func)(ah_ptimer_t *, void *);
typedef struct _ah_capwap_timerinfo_t {
	uint32_t    timertype;  /*timer type*/
	uint32_t    timervalue; /*timer value*/
	ah_capwap_timer_func ah_timer_callback;  /*call back function of timer*/
} ah_capwap_timerinfo_t;

/*this struct and funccall is for wtp fill options*/
typedef int (* ah_capwap_fillopt_func)(char *, uint32_t *);
typedef struct _ah_capwap_fill_discoveryopt_t {
	uint32_t    wtpstate;   /*wtp state*/
	uint32_t    opttype;    /*option type(string or ulong)*/
	ah_capwap_fillopt_func ah_fillopt_callback; /*call back function of fill discovery option*/
} ah_capwap_fill_discoveryopt_t;

/*this struct and funccall is for change state event to fill options*/
typedef int (* ah_capwap_filleventopt_func)(char *, uint32_t *);
typedef struct _ah_capwap_fill_eventopt_t {
	uint32_t    state;      /*wtp state*/
	uint32_t    opttype;    /*option type(string or ulong)*/
	ah_capwap_filleventopt_func ah_filleventopt_callback;    /*call back function of fill discovery option*/
} ah_capwap_fill_eventopt_t;

/*this struct and funccall is for the wtp event request to fill options*/
typedef int (* ah_capwap_fillevent_func)(char *, uint32_t *);
typedef struct _ah_cawpap_fill_event_t {
	uint32_t    state;
	uint32_t    opttype;
	ah_capwap_fillevent_func ah_fill_event_reuqest_callback;
} ah_capwap_fill_event_request_t;

/*the struct and funccall is for analyse capwap packet*/
typedef void (* ah_capwap_analyopt_func)(char *, uint32_t, uint);
typedef struct  _ah_capwap_state_msgtyep_t {
	uint32_t    capwapstate;
	uint32_t    revcmsgtype;
	ah_capwap_analyopt_func ah_analyopt_callback;
} ah_capwap_state_msgtyep_t;

/*the struct and funccall for client change state to do corresponding things*/
typedef int (* ah_capwap_client_fsmchgfunc)(uint32_t, uint32_t, uint32_t, char *, uint32_t);
typedef struct  _ah_capwap_state_client_chg_t {
	uint32_t    state;
	uint32_t    event;
	uint32_t    curtimer;
	uint32_t    lasttimer;
	ah_capwap_client_fsmchgfunc ah_client_fsmchg_callback;
} ah_capwap_state_client_chg_t;

/*the capwap event information request*/
typedef int (* ah_capwap_client_handl_event_request)(uint32_t, char *);
typedef int (* ah_capwap_client_handl_event_confirm)(char *, char *, uint32_t *);
typedef struct _ah_capwap_handle_event_t {
	uint16_t    event_id;
	ah_capwap_client_handl_event_request ah_capwap_event_callback;
	ah_capwap_client_handl_event_confirm ah_capwap_event_confirm_callback;
} ah_capweap_handle_event_t;

/*the capwap information query request*/
typedef int (* ah_capwap_client_handl_information_request)(uint32_t, char *);
typedef int (* ah_capwap_client_handl_information_confirm)(char *, char *, uint32_t *);
typedef struct _ah_capwap_handle_information_query_t {
	uint16_t    info_id;
	ah_capwap_client_handl_information_request ah_capwap_info_query_callback;
	ah_capwap_client_handl_information_confirm ah_capwap_info_confirm_callback;
} ah_capwap_handle_information_query_t;

/***********************************************************************************/
/*************capwap packet format***************************************************/
/*this struct is for capwap pkt Radio MAC Address part*/
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Length     |                  MAC Address
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
typedef struct _ah_capwap_radiomac_t {
	uint8_t    len;/*LENGTH*/
	char      mac[AH_CAPWAP_MAC_LEN];/*MAC Address*/
} ah_capwap_radiomac_t;

/*this struct is for capwap pkt Wireless Specific Information*/
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Wireless ID  |    Length     |             Data
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct _ah_capwap_wireless_info_t {
	uint8_t    wbid;/*Wireless binding ID*/
	uint8_t    len;/*Length*/
	char      data[0];/*Data*/
} ah_capwap_wireless_info_t;

/*this struct is for capwap pkt capwap control header*/
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Message Type                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Seq Num    |        Msg Element Length     |     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Time Stamp                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Msg Element [0..N] ...
   +-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct _ah_capwap_ctrl_header_t {
	uint32_t    msgtype;/*Message Type*/
	uint32_t    timestamp;/*Time Stamp*/
	uchar      seqnum;/*Seq Num*/
	uchar      flags;/*Flage*/
	short      len;/*Msg Element Length*/
	char      option[0];/*Msg Element[0..N]*/
} ah_capwap_ctrl_header_t;

/*this struct is for capwap pakcet*/
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|   RID   |  HLEN   |  WBID   |T|F|L|W|M|     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Fragment ID          |     Frag Offset         |Rsvd |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 (optional) Radio MAC Address                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            (optional) Wireless Specific Information           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Payload ....                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct _ah_capwap_pro_header_t {
	uint32_t    baseinfo;/*Version RID HLEN WBID TFLWM Flags*/
	short      fragid; /*Fragment ID*/
	short      offset_rsvd;/*Frag offset and Rsvd, the last 3 bites is Rsvd*/
	ah_capwap_radiomac_t stramac;/*Radio MAC Address*/
	ah_capwap_wireless_info_t staeroinfo;/*Wireless Specific Infomation*/
	ah_capwap_ctrl_header_t stcolmsg;/*payload -CAPWAP Control Message*/
} ah_capwap_pro_header_t;
/***********************************************************************************/
/**********************************************************************************/

/*the restransmit packet struct*/
typedef struct _ah_capwap_event_pkt_t {
	uint32_t    msg_type;    /*message type*/
	uint32_t    msg_len;     /*message length*/
	uint32_t    sav_time;    /*message saved time*/
	short      sub_seq;     /*frag sub sequeue*/
	short      frag_id;     /*message frag id*/
	short      frag_offset; /*message frag offset*/
	uint16_t    cur_index;    /*message current index*/
	uint16_t    max_index;    /*message max index*/
	uchar      msg_frag;     /*message is frag message*/
	uchar      msg_last;     /*message's last flag*/
	uchar      msg_id;       /*message id*/
	uchar      msg_avlb;     /*message avaliable*/
	uchar      snd_times;    /*retransmit times*/
	char      *msg;         /*message*/
} ah_capwap_event_pkt_t;

/*the save packet struct*/
typedef struct _ah_capwap_save_pkt_t {
	uint32_t    send_index;    /*the buff will be send*/
	uint32_t    save_index;   /*the next place save pkt*/
	ah_capwap_event_pkt_t event_pkt[AH_CAPWAP_EVENT_MAX_PKT];
} ah_capwap_save_pkt;


/*the capwap packet fragment struct*/
typedef struct _ah_capwap_pkt_frag_info_t {
	uint16_t    frag_id;      /*frag id*/
	uint16_t    frag_ofst;    /*frag offset*/
	uchar      frag_last;      /*is last frag*/
	uchar      frag_flag;      /*is a frag pkt*/
} ah_capwap_pkt_frag_info;

/*the capwap save fragment buffer struc*/
typedef struct _ah_capwap_pkt_frag_buff_t {
	uchar      buff_valid;                 /*is a valid buffer*/
	ah_capwap_pkt_frag_info  frag_info;  /*fragment information*/
	uint64_t    frag_num;                /*the number for all fragment*/
	uint32_t    frag_len;                /*current frag len (bytes)*/
	uint      frag_time;                 /*receive timestamp*/
	char      *frag_msg;                 /*current frag pkt*/
} ah_capwap_pkt_frag_buff;

/*the capwap trap packet counter*/
typedef struct ah_capwap_event_pkt_counter_t {
	uint32_t    event_send[AH_CAPWAP_MAX_EVENT_COUNTER_TYPE];       /*send packet counter*/
	uint32_t    event_lost[AH_CAPWAP_MAX_EVENT_COUNTER_TYPE];       /*lost packet counter*/
	uint32_t    event_drop_conn[AH_CAPWAP_MAX_EVENT_COUNTER_TYPE];  /*drop packet counter because connect lost*/
	uint32_t    event_drop_buff[AH_CAPWAP_MAX_EVENT_COUNTER_TYPE];  /*drop packet counter because buffer full*/
	uint32_t    event_drop_dsab[AH_CAPWAP_MAX_EVENT_COUNTER_TYPE];  /*drop packet counter because event disabled*/
} ah_capwap_event_pkt_counter_t;

/*the capwap packet counter*/
typedef struct ah_capwap_pkt_counter_t {
	uint32_t    snd_pkt;      /*keep alive send packet*/
	uint32_t    rcv_pkt;      /*receive alive packet*/
	uint32_t    lost_pkt;     /*lost keep alive packet*/
	uint32_t    drop_buff;    /*discard packet because of capwap buff full*/
	uint32_t    drop_conn;    /*discard packet because of capwap connection lost*/
} ah_capwap_pkt_counter;

#endif

