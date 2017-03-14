#ifndef __NTPCLIENT_SERVICES_H_
#define __NTPCLIENT_SERVICES_H_

#define MAX_NTP_SERVER  3   
#define DEFAULT_NTP_SERVER1 "time.nist.gov"
#define DEFAULT_NTP_SERVER2 "time.windows.com"

typedef struct ntpclient_info
{
    int num;
    int enabled;
    int period;
    char server[MAX_NTP_SERVER][128];
} ntpclient_info;

extern int ntpclient_enabled(void);

extern int ntpclient_disabled(void);

extern int ntpclient_add_server(const char * server);

extern int ntpclient_undo_all_server(void);

extern int ntpclient_set_update_period(unsigned int period);

extern int ntpclient_get_defcfg(struct ntpclient_info *defcfg);

#endif /* __NTPCLIENT_SERVICES_H_ */
