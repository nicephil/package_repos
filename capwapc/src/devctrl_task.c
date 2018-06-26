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
    loglevel = LOG_DEBUG;
    setlogmask(LOG_UPTO(loglevel));
    CWLog("Receive signal %d, enable debug log.", signo);
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

static int signal_action_done(void)
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

    /*signal_action();*/
    
    CW_REPEAT_FOREVER {
        CWLockSafeList(g_devctrlreq_list);
        pthread_cleanup_push(CWUnlockSafeList, g_devctrlreq_list);

        /*while (CWGetCountElementFromSafeList(g_devctrlreq_list) == 0) {
            if (signal_action_done() == 0) {
                CWWaitElementFromSafeList(g_devctrlreq_list);
            }
        }*/
        
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

