#ifndef __DEVCTRL_PAYLOAD_H__
#define __DEVCTRL_PAYLOAD_H__

enum {
    DC_PAYLOAD_JSON_CONFIG          = 1,
    DC_PAYLOAD_CONFIG_RESULT        = 2, 

    DC_PAYLOAD_STA_STAUS_NOTICE     = 101,
    DC_PAYLOAD_STA_INFO_NOTICE      = 102,
    DC_PAYLOAD_DEV_UPDATE_NOTICE    = 103,
    DC_PAYLOAD_RADIO_STATUS_NOTICE  = 104,
    
    DC_PAYLOAD_STA_KICKOFF_REQ      = 1001,
    DC_PAYLOAD_STA_KICKOFF_RESULT   = 1002,

    DC_PAYLOAD_STA_QUERY_REQ        = 1003,
    DC_PAYLOAD_STA_QUERY_RESULT     = 1004,

    DC_PAYLOAD_IMAGE_UPGRADE_REQ    = 1005,
    DC_PAYLOAD_IMAGE_UPGRADE_RESULT = 1006,

    DC_PAYLOAD_REBOOT_REQ           = 1007,
    DC_PAYLOAD_REBOOT_RESULT        = 1008,

    DC_PAYLOAD_PORTAL_OFFLINE_REQ   = 1009,
    DC_PAYLOAD_PORTAL_OFFLINE_RESULT = 1010,

    DC_PAYLOAD_PORTAL_AUTHENTICATION_REQ   = 1011,
    DC_PAYLOAD_PORTAL_AUTHENTICATION_RESULT = 1012,

    DC_PAYLOAD_UPLOAD_TECHSUPPORT_REQ = 1013,
    DC_PAYLOAD_UPLOAD_TECHSUPPORT_RESULT = 1014,

    DC_PAYLOAD_INTERFACE_INFO_REQ = 1015,
    DC_PAYLOAD_INTERFACE_INFO_RESULT = 1016,

    DC_PAYLOAD_SSH_TUNNEL_REQ = 1017,
    DC_PAYLOAD_SSH_TUNNEL_RESULT = 1018,

    DC_PAYLOAD_WDS_TUNNEL_REQ = 1019,
    DC_PAYLOAD_WDS_TUNNEL_RESULT = 1020,

    DC_PAYLOAD_CLI_REQ = 1021,
    DC_PAYLOAD_CLI_RESULT = 1022,

    DC_PAYLOAD_FLOWSTA_REQ = 1023,
    DC_PAYLOAD_FLOWSTA_RESULT = 1024,

#if OK_PATCH
    DC_PAYLOAD_ROUTER_CONFIG_REQ = 10001,
    DC_PAYLOAD_ROUTER_CONFIG_RESULT = 10002,
#endif
};

struct tlv {
    unsigned short t;
    unsigned int l;
    char *v;
};

struct dc_payloadfunc_table {
    int type;
    int (*handler)(struct tlv *, void **);
    int (*response)(devctrl_block_s *, void *);
    int (*finished)(void *);
};

static inline unsigned short get_payload_type(const char *payload) 
{
	unsigned short val;
	
	CW_COPY_MEMORY(&val, payload, 2);
	return ntohs(val);
}

static inline void save_payload_type(char *payload, unsigned short type) 
{
	type = htons(type);
	CW_COPY_MEMORY(payload, &(type), 2);
}

static inline unsigned int get_payload_length(const char *payload) 
{
	unsigned int val;
	
	CW_COPY_MEMORY(&val, payload, 4);
	return ntohl(val);
}

static inline void save_payload_length(char *payload, unsigned int length) 
{
	length = htonl(length);
	CW_COPY_MEMORY(payload, &(length), 4);
}

extern int dc_task_handler(devctrl_block_s *dc_block);

#endif
