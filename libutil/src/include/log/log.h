#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>

#ifndef CONFIG_LOG_CLIENT_MAX_NUM
#define CONFIG_LOG_CLIENT_MAX_NUM   (64)
#endif

#define LOG_IDENT_SYSTEM_RESERVED_NAME  "system"

#define LOG_IDENT_NAME_MAX_LENGTH       16  // include tailing '\0'
#define LOG_FILE_NAME_MAX_LENGTH        32  // include tailing '\0'

enum {
    LOG_DEST_SYSLOG = 0, 
    LOG_DEST_CONSOLE, 
    LOG_DEST_MONITOR, 
    LOG_DEST_FILE, 

    LOG_DEST_MAX
};

/* TODO: how to define the debug level clearly */
enum {
    DEBUG_ONLY = (LOG_DEBUG + 1),
    DEBUG_EXCEPT,                  /* Output except debug information */        
    DEBUG_FLOW,                   /* Output process flow information */        
    DEBUG_DETAIL,                 /* Output detail debug information (such as key packet) */
};

/*
 *  return value: 
 *      >=0         OK and return module id (passed to zlog)
 *      -1          failed
 */
extern int zlog_open(const char * ident);
extern void zlog_open_kernel_modules(void);
extern void zlog(int module, int priority, const char *format, ...) __attribute__ ((format (printf, 3, 4)));

extern int zlog_set_consoleparam(int enable, int level);
extern int zlog_enable_infocenter(int enable);
extern int zlog_read(int size, int reverse, int level, int caller);
extern int zdebug_read(int size, int reverse, int fd);
extern int zdebug_enable(int enable);
extern int zdebug_updateparam(int level, int console_enable, int file_enable);
extern int zdebug_getparam(int *level, int *console_enable, int *file_enable);
extern int zdebug_openmodule(const char *name);
extern int zdebug_openall(void);
extern int zdebug_closemodule(const char *name);
extern int zdebug_closeall(void);
extern int zlog_register_modules(char (*modules)[16], int *num, int opened);
extern char *zlog_module_indent(int module);
extern void zdebug_resetbuffer(void);

#ifdef ZLOG_COMPAT
#define zlog(priority, format, ...) zlog(-2, priority, format, ##__VA_ARGS__)
#endif

extern void zlog_close(int module);

#define BUG_ON(_cond)   \
    do {\
        if ((_cond) == 0) {\
            zlog(LOG_ERR,"BUG: %s %d\n", __func__, __LINE__);\
        }\
    } while(0)

#endif /* _LOG_H_ */
