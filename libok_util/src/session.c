#include <stdio.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>



#include "util/util.h"
#include "session/session.h"

#define LOCK_NAME   "/tmp/session_lock"
#define DEBUG   printf

static int  session_shm_id = -1;
static void* session_shm_data = (void *) -1;

static inline int session_lock(void)
{
    int fd ;

    fd = open(LOCK_NAME, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        DEBUG("Failed to create %s\n", LOCK_NAME);
        return -1;
    }

    if (-1 == util_file_lock(fd)) {
        close(fd);
        return -1;
    }

    return fd;
}

static inline void session_unlock(int fd)
{
    util_file_unlock(fd);
    close(fd);
    unlink(LOCK_NAME);
}

static int session_init(void)
{
    key_t   key = SESSION_SHARED_MEMORY_KEY;
    size_t  size = sizeof(struct session_shared_control);
    int     flag = 0666 | IPC_CREAT | IPC_EXCL;
    int     id;
    void * data;
    struct session_shared_control * sessions;
    int lock;

    lock = session_lock();
    if (lock == -1) {
        return -1;
    }

    id = shmget(key, size, flag);
    if (id == -1) {
        if (errno == EEXIST) {
            session_unlock(lock);
            return 0;
        }
        else {
            DEBUG("Failed to open shared memory: %d %s!\n", errno, strerror(errno));
            session_unlock(lock);
            return -1;
        }
    }

    data = shmat(id, NULL, 0);
    if (data == (void *) -1) {
        DEBUG("Failed to attach: %d %s!\n", errno, strerror(errno));
        session_unlock(lock);
        return -1;
    }

    sessions = (struct session_shared_control *)data;
    memset(sessions, 0, sizeof(*sessions));
    shmdt(data);
    session_unlock(lock);

    return 0;
}

static int session_sharemem(void)
{
    key_t   key = SESSION_SHARED_MEMORY_KEY;
    size_t  size = sizeof(struct session_shared_control);
    int flag = O_RDWR;

    session_init();
    
    if (session_shm_id == -1 ) {
        session_shm_id = shmget(key, size, flag);
        if (session_shm_id == -1) {
            return -1;
        }
    }

    if (session_shm_data == (void *) -1) {
        session_shm_data = shmat(session_shm_id, NULL, 0);
        if (session_shm_data == (void *) -1) {
            return -1;
        }
    }
    
    return 0;
}

/* locked before calling this function */
static int session_tryclose(void)
{
    struct session_shared_control *sessions = (struct session_shared_control *)session_shm_data;
    int i;

retry:
    for (i=0; i<sessions->session_num; i++) {
		if (kill(sessions->list[i].pid, 0)) {
            if (i < SESSION_MAX_COUNT-1 && i < sessions->session_num-1) {
                memmove(&(sessions->list[i]), &(sessions->list[i+1]), 
                    (sessions->session_num-i-1)*sizeof(struct session_block));
            }
            sessions->session_num--;
            goto retry;
        }
    }
    
    return 0;
}

int session_closelog(int bit)
{
    struct session_shared_control *sessions; // = (struct session_shared_control *)session_shm_data;
    int i, lock;
    pid_t pid;

	if (session_sharemem()) {
        return 0;
    }
    
    sessions = (struct session_shared_control *)session_shm_data;
	
    pid = getpid();
    lock = session_lock();
    for (i=0; i<sessions->session_num; i++) {
        if (sessions->list[i].pid == pid) {
            sessions->list[i].on_mask &= ~bit;
            break;
        }
    }
    session_unlock(lock);

    return 0;
        
}

int session_closedelay(const char *dev)
{
    struct session_shared_control *sessions = (struct session_shared_control *)session_shm_data;
    int i, lock;

    lock = session_lock();
    for (i=0; i<sessions->session_num; i++) {
        if (!strcmp(sessions->list[i].dev, dev)) {
            if (i < SESSION_MAX_COUNT-1 && i < sessions->session_num-1) {
                memmove(&(sessions->list[i]), &(sessions->list[i+1]), 
                    (sessions->session_num-i-1)*sizeof(struct session_block));
            }
            sessions->session_num--;
            break;
        }
    }
    session_unlock(lock);
    
    return 0;
}

int session_openlog(int bit)
{
    struct session_shared_control *sessions;
    struct session_block *block;
    key_t   key = SESSION_SHARED_MEMORY_KEY;
    size_t  size = sizeof(struct session_shared_control);
    int flag = O_RDWR;
    int lock;
    int i;
    pid_t pid;
    
    session_init();
    
    if (session_shm_id == -1 ) {
        session_shm_id = shmget(key, size, flag);
        if (session_shm_id == -1) {
            return -1;
        }
    }

    if (session_shm_data == (void *) -1) {
        session_shm_data = shmat(session_shm_id, NULL, 0);
        if (session_shm_data == (void *) -1) {
            return -1;
        }
    }

    lock = session_lock();
    if (lock == -1) {
        return -1;
    }

    sessions = (struct session_shared_control *)session_shm_data;
    pid = getpid();
    for (i=0; i<sessions->session_num; i++) {
        block = &(sessions->list[i]);
        if (block->pid == pid) {
            block->on_mask |= bit;
            strncpy(block->dev, ttyname(1), sizeof(block->dev)-1);
            session_unlock(lock);
            return 0;
        }
    }

    if (sessions->session_num >= SESSION_MAX_COUNT) {
        session_tryclose();
    }
    
    if (sessions->session_num < SESSION_MAX_COUNT) {
        block = &(sessions->list[sessions->session_num]);
        block->pid = pid;
        block->on_mask |= bit;
        strncpy(block->dev, ttyname(1), sizeof(block->dev)-1);
        sessions->session_num++;
    }
   
    session_unlock(lock);

    return 0;
}

int session_devlist(int bit, char **ppdev)
{
    struct session_shared_control *sessions;
    struct session_block *block;
    int i, num, lock;

    if (session_sharemem()) {
        return 0;
    }
    
    sessions = (struct session_shared_control *)session_shm_data;
    num = 0;
    lock = session_lock();
    for (i=0; i<sessions->session_num; i++) {
        block = &(sessions->list[i]);
        if (block->on_mask & bit) {
            *(ppdev + num) = block->dev;
            num++;
        }
    }
    session_unlock(lock);

    return num;
}

int session_new(struct session_info session)
{
    struct session_shared_control *sessions;
    struct session_block *block;
    pid_t pid;
    int i, lock;

    if (session_sharemem()) {
        return 0;
    }
    sessions = (struct session_shared_control *)session_shm_data;
    pid = getpid();
    lock = session_lock();
    for (i=0; i<sessions->session_num; i++) {
        block = &(sessions->list[i]);
        if (block->pid == pid) {
            memcpy(&(block->session), &session, sizeof(struct session_info));
            session_unlock(lock);
            return 0;
        }
    }

    if (sessions->session_num >= SESSION_MAX_COUNT) {
        session_tryclose();
    }
    
    if (sessions->session_num < SESSION_MAX_COUNT) {
        block = &(sessions->list[sessions->session_num]);
        memset(block, 0, sizeof(struct session_block));
        block->pid = pid;
        memcpy(&(block->session), &session, sizeof(struct session_info));
        sessions->session_num++;
    }
    else {
        session_unlock(lock);
        return -1;
    }
    session_unlock(lock);

    return 0;
}

int session_getall(struct session_shared_control *sessions)
{
    int lock;
    
    if (session_sharemem()) {
        return 0;
    }

    lock = session_lock();
    session_tryclose();
    memcpy(sessions, (struct session_shared_control *)session_shm_data, 
        sizeof(struct session_shared_control));
    session_unlock(lock);

    return 0;
}

//add by puyg: for create tech_support for show_telnet_session_info
#if 0
enum login_type {
    LOGIN_TYPE_CONSOLE = 0,
    LOGIN_TYPE_TELNET,
    LOGIN_TYPE_SSH,
    LOGIN_TYPE_INVALID
};

int show_telnet_session_info(int fd){
    struct session_shared_control sessions;
    char time_str2[80];
    int i = 0, j = 0, len = 0;
    char cmd[128] = {};

    len = sprintf(cmd, "user          from            time\r\n");
    write(fd, cmd, len);
    memset(cmd, 0, sizeof(cmd));
    if (!session_getall(&sessions) && sessions.session_num > 0) {
        for (i = 0; i < sessions.session_num; i++) {
            if (sessions.list[i].session.type == LOGIN_TYPE_TELNET) {
                if (strlen(sessions.list[i].session.user) <= 12) {
                    len = sprintf(cmd, "%-12s  ", sessions.list[i].session.user);
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                }
                else {
                    len = sprintf(cmd, "%-.9s...  ", sessions.list[i].session.user);
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                }
                if (strlen(sessions.list[i].session.from) <= 15) {
                    len = sprintf(cmd, "%-15s ", sessions.list[i].session.from);
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                }
                else {
                    len = sprintf(cmd, "%-.12s... ", sessions.list[i].session.from);
                    write(fd, cmd, len);
                    memset(cmd, 0, sizeof(cmd));
                }
                ctime_r(&(sessions.list[i].session.timestamp), time_str2);
                len = sprintf(cmd, "%-.15s\r\n",  (time_str2 + 4));
                write(fd, cmd, len);
                memset(cmd, 0, sizeof(cmd));
            }
        }
    }

    return 0;
}
#endif
