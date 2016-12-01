#include "CWWTP.h"
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#if !OK_PATCH
#include "nmsc/nmsc.h"
#endif
#include "devctrl_protocol.h"
#include "devctrl_payload.h"
#include "devctrl_notice.h"

/* list used to pass device control request data from nms to the task handle thread */
CWSafeList g_devctrlreq_list;

/* used to synchronize access to the lists */
CWThreadCondition g_devctrlreq_wait;
CWThreadMutex g_devctrlreq_mutex;

static int g_sigusr2_count = 0;
static void signal_void(int signo)
{
    /* do nothing */
    CWDebugLog("Receive signal %d, nothing need to do.", signo);
}

static int signal_init(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = signal_void;

    if(sigaction(SIGUSR2, &sa, 0) < 0){
		CWLog("Can't user SIGUSR2 signer");
        return -1;
    }

    return 0;
}

void sigusr2_notice(int signo)
{
    g_sigusr2_count++;
    
    simulate_AddElementToSafeListHead(g_devctrlreq_list);

    return;
}

static int signal_action(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sigusr2_notice;

    if(sigaction(SIGUSR2, &sa, 0) < 0){
		CWLog("Can't user SIGUSR2 signer");
        return -1;
    }

    return 0;
}

static int signal_action_doen(void)
{
    if (g_sigusr2_count > 0) {
        get_wds_sigusr(SIGUSR2);
        g_sigusr2_count--;

        return 1;
    }

    return 0;
}

static void task_freeblock(devctrl_block_s *devctrl_block)
{
    if (devctrl_block->data) {
        CW_FREE_OBJECT(devctrl_block->data);
    }

    CW_FREE_OBJECT(devctrl_block);
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

    signal_init();
    
    return CW_TRUE;
}

CW_THREAD_RETURN_TYPE task_handlereq(void *arg) 
{
    devctrl_block_s *devctrl_block = NULL;
    int size = 0;
    
    CWDebugLog("Device control task pid %d.", getpid());

    signal_action();
    
    CW_REPEAT_FOREVER {
        CWLockSafeList(g_devctrlreq_list);
        pthread_cleanup_push(CWUnlockSafeList, g_devctrlreq_list);

        while (CWGetCountElementFromSafeList(g_devctrlreq_list) == 0) {
            if (signal_action_doen() == 0) {
                CWWaitElementFromSafeList(g_devctrlreq_list);
            }
        }
        
        devctrl_block = (devctrl_block_s*)CWRemoveHeadElementFromSafeList(g_devctrlreq_list, &size);
        pthread_cleanup_pop(0);
        CWUnlockSafeList(g_devctrlreq_list);

        if (devctrl_block == NULL) {
            continue;
        }

        if (size != sizeof(devctrl_block_s *)) {
            CWDebugLog("Get one dev ctrl block, but with invalid size:%d", size);
            goto FREE_BLOCK;
        }

        if (dc_task_handler(devctrl_block)) {
            CWDebugLog("Handle one dev ctrl req, but sent response with wtp event req failed.");
        }
        else {
            CWDebugLog("Handle one dev ctrl req, and sent response with wtp event req.");
        }
        
FREE_BLOCK:
        task_freeblock(devctrl_block);
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
    struct capwapc_status status;
#if !OK_PATCH
    char *char_serach;
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
        {CW_ENTER_RESET,      CAPWAPC_STATE_RESET}, 
        {CW_RESTART_SILENTLY, CAPWAPC_STATE_RESTART_SILENTLY},
        {CW_STOP,             CAPWAPC_STATE_STOP_SILENTLY},
        {CW_QUIT,             CAPWAPC_STATE_QUIT}
    };
    struct sysinfo sys;
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

    if (server && state > CW_ENTER_DISCOVERY) {
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

    status.type = CAPWAP_STATUS_NOTICE;
    if (state == CW_ENTER_RUN) {
        sysinfo(&sys);
        status.uptime = sys.uptime;
    }
    else {
        status.uptime = -1;
    }
#endif
    return task_notify_status(&status, sizeof(status));
}

