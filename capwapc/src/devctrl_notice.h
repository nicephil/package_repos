#ifndef __DEVCTRL_NOTICE_H__
#define __DEVCTRL_NOTICE_H__

extern int dc_start_sta_notice_timer(void);
extern int dc_stop_sta_notice_timer(void);
extern int dc_get_wlan_sta_stats(struct wlan_sta_stat **stas, int diff);
extern void dc_dev_update_notice(void);
extern void get_wds_sigusr(int signo);
#endif
