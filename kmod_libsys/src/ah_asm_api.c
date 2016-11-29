#ifdef __KERNEL__
#include "ah_asm_kernel.h"
#else
#include "ah_asm_user.h"
#endif

int      ah_asm_report_instance_proc_result(ah_asm_install_result_t *result)
{
	int      rc = 0;

	rc = AH_ASM_EVENT_SEND_ERR(sizeof(ah_asm_install_result_t), result);
	if (rc < 0) {
		AH_ASM_LOG_ERR("ASM: ah_event_send(AH_EVENT_ASM_PROCESS_RESULT) failed(rc=%d)\n", rc);
	}
	return rc;
}
#ifdef __KERNEL__
EXPORT_SYMBOL(ah_asm_report_instance_proc_result);
#endif

/* when detections on different APs, we need ap_mac. For now it can be null */
int      ah_asm_report_behavior(ah_asm_behavior_report_msg_t *event_msg)
{
	int      rc = 0;

#if 0
	ah_asm_behavior_report_msg_t *event;
	int      len;

	len = sizeof(ah_asm_behavior_report_msg_t);
	event = (ah_asm_behavior_report_msg_t *)AH_ASM_MALLOC(len);
	if (event == NULL) {
		AH_ASM_LOG_ERR("ASM: no enough memory for reporting behavior message!");
		return -1;
	}
	memset(event, 0, len);
	memcpy(event, event_msg, sizeof(ah_asm_behavior_report_msg_t));
#endif

#ifdef __KERNEL__
	event_msg->detect_time = jiffies / HZ;
#else
	event_msg->detect_time = time(NULL);
#endif

	rc = AH_ASM_EVENT_SEND_REPORT(sizeof(ah_asm_behavior_report_msg_t), event_msg);
	if (rc < 0) {
		AH_ASM_LOG_ERR("ASM: ah_event_send(AH_EVENT_ASM_BEHAVIOR_REPORT) failed(rc=%d)\n", rc);
	}
	//AH_ASM_FREE(event);
	return rc;
}
#ifdef __KERNEL__
EXPORT_SYMBOL(ah_asm_report_behavior);
#endif

