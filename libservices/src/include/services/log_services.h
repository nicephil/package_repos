#ifndef __LOG_SERVICES_H_
#define __LOG_SERVICES_H_

#include <syslog.h>


#define DEFAULT_HOST_IP           "0.0.0.0"
#define DEFAULT_HOST_LEVEL        LOG_INFO
#define DEFAULT_BUFFER_LEVEL      LOG_INFO
#define DEFAULT_TERMINAL_LEVEL    LOG_INFO
#define DEFAULT_INFOCENTER_ENABLE 1
#define DEFAULT_BUFFER_ENABLE     1
#define DEFAULT_TERMINAL_ENABLE   1


struct log_center {
    int enable;
};

struct log_hostinfo {
    int level;
    char ip[32];
}; 

struct log_bufferinfo {
   int enable;
   int level;
}; 

struct log_terminalinfo {
   int enable;
   int level;
}; 

typedef struct log_infocenter {
    struct log_center center;
    struct log_hostinfo host;
    struct log_bufferinfo buffer;
    struct log_terminalinfo terminal;
} log_infocenter;


extern int log_get_defcfg(log_infocenter *infocenter);
extern int log_enable_infocenter(void);
extern int log_undo_infocenter(void);
extern int log_set_hostip(const char *ip);
extern int log_undo_hostip(void);
extern int log_set_hostlevel(int level);
extern int log_undo_hostlevel(void);
extern int log_enable_buffer(void);
extern int log_undo_buffer(void);
extern int log_set_bufferlevel(int level);
extern int log_apply_all(int enabled);
#endif /* __LOG_SERVICES_H_ */
