#ifndef _SESSION_H_
#define _SESSION_H_

#define SESSION_SHARED_MEMORY_KEY   0x6c6f6757  
#define SESSION_MAX_COUNT   6   /* 1 serial + 5 telnet */
#define DEV_NAME_LENGTH     64

#define OPEN_LOGING        0x01
#define OPEN_DEBUGGING     0x02

#define MAX_LOGIN_USER_LEN  33
#define MAX_LOGIN_FROM_LEN  48

struct session_info{
    int type;           /* serial or telnet */
    time_t timestamp;
    char user[MAX_LOGIN_USER_LEN];
    char from[MAX_LOGIN_USER_LEN];
};

struct session_block{
    pid_t pid;
    int on_mask;               /* switch log&debug output */
    char dev[DEV_NAME_LENGTH]; /* pty or tty device name */
    struct session_info session;
};

struct session_shared_control {
    int session_num;
    struct session_block list[SESSION_MAX_COUNT];
};

extern int session_devlist(int bit, char **ppdev);
extern int session_openlog(int bit);
extern int session_closelog(int bit);
extern int session_closedelay(const char *dev);
extern int session_new(struct session_info session);
extern int session_getall(struct session_shared_control *sessions);

//add by puyg
//extern int show_telnet_session_info(int fd);
//end by puyg

#endif
