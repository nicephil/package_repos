#include "CWWTP.h"
#include <sys/un.h>
#include <sys/socket.h>
//#include "nmsc/nmsc.h"
#include "dummy.h"

/* list used to pass device control request data from nms to the task handle thread */
CWSafeList g_devctrlreq_list;

/* used to synchronize access to the lists */
CWThreadCondition g_devctrlreq_wait;
CWThreadMutex g_devctrlreq_mutex;

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

static void task_freeblock(devctrl_block_s *devctrl_block)
{
    if (devctrl_block->data) {
        CW_FREE_OBJECT(devctrl_block->data);
    }

    CW_FREE_OBJECT(devctrl_block);
}

static void task_response(devctrl_block_s *dc_block)
{
    char *json_data = NULL;
    char *payload;
    int paylength = 0; 
    
    if (dc_block && dc_block->data) {
        CW_FREE_OBJECT(dc_block->data);
    }

    json_data = dc_get_handresult();
    if (json_data) {
        paylength = strlen(json_data);
    }

    /* 2bytes type + 4bytes length */
    CW_CREATE_OBJECT_SIZE_ERR(payload, paylength + 6, {free(json_data);return;});
        
    save_payload_type(payload, 2);/* config result with json format */
    save_payload_length(payload + 2, paylength);

    if (json_data) {
        CW_COPY_MEMORY(payload + 6, json_data, paylength);
        free(json_data);
    }
    
    dc_block->type = 1;       /* payload between nms and device */
    dc_block->compressed = 0; /* no compress */
    dc_block->orig_len = paylength + 6; /* 2bytes type + 4bytes length */
    dc_block->len = paylength + 6; /* 2bytes type + 4bytes length */
    dc_block->data = payload;
    
    if (!WTPEventRequest_devctrlresp(CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE, 
        (int)dc_block)) {
        CWDebugLog("Send WTPEventReq with device control resopnse element failed.");
    }

    task_freeblock(dc_block);
}

CWBool task_init(void) 
{
    if (!CWErr(CWCreateSafeList(&g_devctrlreq_list))) {
        CWDebugLog("Create dev ctrl req list failed");
		return CW_FALSE;
	}
    
    CWCreateThreadMutex(&g_devctrlreq_mutex);
	CWSetMutexSafeList(g_devctrlreq_list, &g_devctrlreq_mutex);
    
    CWCreateThreadCondition(&g_devctrlreq_wait);
	CWSetConditionSafeList(g_devctrlreq_list, &g_devctrlreq_wait);

    return CW_TRUE;
}

static CWBool task_done(devctrl_block_s *dc_block)
{
    struct tlv {
        unsigned short t;
        unsigned int l;
        char *v;
    } tlv;
    char *payload = dc_block->data;
    int totallen = 0, ret = 0;
    char reserved;

    while (totallen < dc_block->len) {
        tlv.t = get_payload_type(payload);
        payload += sizeof(tlv.t);
        /* type 1: json config  */
        if (tlv.t != 1) {
            /* bad type */
            CWDebugLog("Received config data from NMS with bad type: %d", tlv.t);
            ret = -1;
            break;
        }

        tlv.l = get_payload_length(payload);
        payload += sizeof(tlv.l);
        totallen += sizeof(tlv.t) + sizeof(tlv.l) + tlv.l;

        if (totallen > dc_block->len) {
            CWDebugLog("Received config data from NMS with bad length: %d:%d:%d", totallen, tlv.l ,dc_block->len);
            /* invalid data length */
            ret = -2;
            break;
        }
        tlv.v = payload;
        
        CWLog("Received config data from NMS with length: %d", tlv.l);

        reserved = tlv.v[tlv.l];
        ret = dc_json_machine(tlv.v);
        tlv.v[tlv.l] = reserved;
        if (ret) {
            break;
        }

        payload += tlv.l;
    }

    task_response(dc_block);

    return ret;
}

CW_THREAD_RETURN_TYPE task_handlereq(void *arg) 
{
    devctrl_block_s *devctrl_block = NULL;
    int size = 0;

    CW_REPEAT_FOREVER {
        CWLockSafeList(g_devctrlreq_list);
        pthread_cleanup_push(pthread_mutex_unlock, ((CWPrivateSafeList *)g_devctrlreq_list)->pThreadMutex);

        while (CWGetCountElementFromSafeList(g_devctrlreq_list) == 0) {
            CWWaitElementFromSafeList(g_devctrlreq_list);
        }
        devctrl_block = (devctrl_block_s*)CWRemoveHeadElementFromSafeList(g_devctrlreq_list, &size);
        pthread_cleanup_pop(0);

        CWUnlockSafeList(g_devctrlreq_list);

        if (size != sizeof(devctrl_block_s *)) {
            CWDebugLog("Get one dev ctrl block, but with invalid size:%d", size);
            task_freeblock(devctrl_block);
        }

        if (task_done(devctrl_block)) {
            CWDebugLog("Handle one dev ctrl req, but sent response with wtp event req failed.");
        }
        else {
            CWDebugLog("Handle one dev ctrl req, and sent response with wtp event req.");
        }
    }

    return NULL;
}

static int task_notify_status(void * data, int size)
{
    int s, ret;
    struct sockaddr_un un;

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s == -1) {
        return -1;
    }

    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, CAPWAPC_LISTEN_ADDRESS);

    ret = sendto(s, data, size, 0, (const struct sockaddr *)&un, sizeof(un));
    if (ret == -1) {
        CWDebugLog("Sendto status failed for:  %s(%d) \n", strerror(errno), errno);
    }
    close(s);
    return 0;
}

int task_update_status(CWStateTransition state, CWACInfoValues *server)
{
    char *char_serach;
    struct capwapc_status status;
    const struct state_match {
        CWStateTransition cwstate;
        capwapc_state_e   state;
    } state_trans[] = {
        {CW_ENTER_SULKING,    CAPWAPC_STATE_SULKING},
        {CW_ENTER_DISCOVERY,  CAPWAPC_STATE_DISCOVERY},
        {CW_ENTER_JOIN,       CAPWAPC_STATE_JOIN},
        {CW_ENTER_CONFIGURE,  CAPWAPC_STATE_CONFIGURE},
        {CW_ENTER_DATA_CHECK, CAPWAPC_STATE_DATA_CHECK},
        {CW_ENTER_RUN,        CAPWAPC_STATE_RUN},
        {CW_ENTER_RESET,      CAPWAPC_STATE_RESET}
    };

    int i, size = sizeof(state_trans)/sizeof(state_trans[0]);

    memset(&status, 0, sizeof(status));

    for (i = 0; i < size; i++) {
        if (state == state_trans[i].cwstate) {
            status.state = state_trans[i].state;
            break;
        }
    }

    if (i >= size) {
        CWDebugLog("Failed to translate the CW state to the capwap state\n");
        return -1;
    }

    if (server) {
        if (server->name) {
            strncpy(status.server_name, server->name, sizeof(status.server_name) - 1);
        }
        CWUseSockNtop(&(server->preferredAddress), 
            {strncpy(status.server_addr, str, sizeof(status.server_addr) - 1);});
        char_serach = strchr(status.server_addr, ':');
        if (char_serach) {
            *char_serach = 0;
        }
    }
    
    return task_notify_status(&status, sizeof(status));
}

