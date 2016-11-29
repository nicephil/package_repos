#ifndef __TASK_H__
#define __TASK_H__

extern CWSafeList g_devctrlreq_list;

extern CWBool task_init(void);
extern CW_THREAD_RETURN_TYPE task_handlereq(void *arg);
extern int task_update_status(CWStateTransition state, CWACInfoValues *server);

#endif
