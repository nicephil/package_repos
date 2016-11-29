#include "log/log.h"
#include "log/data.h"
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/klog.h>
#include "session/session.h"

#undef ZLOG_COMPAT

#if 0
#define DEBUG   printf
#else
#define DEBUG(...)
#endif

#define TRACE() DEBUG("%d %s\n", __LINE__, strerror(errno))
#define HERE() DEBUG("%s %d\n", __func__, __LINE__)
#define     SEM_NAME    "log_sem"
#define     LOCK_NAME   "/tmp/log_lock"

#if !(defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
/* Not C99; do we need to define va_copy? */
#ifndef va_copy
#ifdef __va_copy
#define va_copy(DST,SRC) __va_copy(DST,SRC)
#else
/* Now we are desperate; this should work on many typical platforms. 
 *    But this is slightly dangerous, because the standard does not require
 *       va_copy to be a macro. */
#define va_copy(DST,SRC) memcpy(&(DST), &(SRC), sizeof(va_list))
#warning "Not C99 and no va_copy macro available, falling back to memcpy"
#endif /* __va_copy */
#endif /* !va_copy */
#endif /* !C99 */


static int openlog_once = 0;
static int  g_shm_id = -1;
static void * g_shm_data = (void *) -1;
static int g_log_id = -1;

static struct shmem_control debug_shmem = 
{
    .keyid = DEBUG_KEY_ID,
    .shmid = -1,
    .s_semid = -1,
    .shm_size = (64 * 1024),      /* 64k is enough? */
    .SMwup = {{1, -1, IPC_NOWAIT}},
    .SMwdn = {{0, 0}, {1, 0}, {1, +1}},
};

static const struct sembuf init_sem[3] = {
	{0, -1, IPC_NOWAIT | SEM_UNDO},
	{1, 0}, {0, +1, SEM_UNDO}
};

static CODE prioritynames[] =
  {
    { "alert", LOG_ALERT },
    { "crit", LOG_CRIT },
    { "debug", LOG_DEBUG },
    { "emerg", LOG_EMERG },
    { "err", LOG_ERR },
    { "error", LOG_ERR },		/* DEPRECATED */
    { "info", LOG_INFO },
    { "none", 0x10 },		/* INTERNAL */
    { "notice", LOG_NOTICE },
    { "panic", LOG_EMERG },		/* DEPRECATED */
    { "warn", LOG_WARNING },		/* DEPRECATED */
    { "warning", LOG_WARNING },
    { NULL, -1 }
  };

void zlog_open_kernel_modules(void)
{
/* log module id add to priv_prk_clients synchronize in kernel */    
    static char* (g_kernel_models[]) = {
        "wlan",
        "VLAN",
        "UMAC",
        "LMAC",
        "VLAN",
        "band-steering",
        "wifi-bcast",
        "arp-optimize",
        NULL
    };
    
    int i = 0;

    while (g_kernel_models[i] != NULL) {
        zlog_open(g_kernel_models[i]);
        i++;
    }
}

static void zlog_unlock(int fd)
{
    struct flock    lock;
    int     ret;

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    ret = fcntl(fd, F_SETLKW, &lock);

    if (ret == -1) {
        DEBUG("Failed to unlock: %d %s\n", errno, strerror(errno));
    }

    close(fd);
    unlink(LOCK_NAME);
    return ;
}

static int zlog_lock()
{
    int     fd, ret;
    struct flock    lock;

    fd = open(LOCK_NAME, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        DEBUG("Failed to create %s\n", LOCK_NAME);
        return -1;
    }

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    ret = fcntl(fd, F_SETLKW, &lock);
    if (ret == -1) {
        DEBUG("Failed to set lock: %d %s\n", errno, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static inline int is_slot_used(struct debug_client * client)
{
    return ((client->flags & LOG_CLIENT_FLAG_USED) == LOG_CLIENT_FLAG_USED);

}
static int  log_get_idle_slot(const char * name)
{
    int i, ret;
    struct debug_config * config = &(((struct shared_config *)g_shm_data)->debug);
    struct debug_client * client;

    ret = -1;
    client = &config->clients[0];
    for (i = 0; i < ARRAY_SIZE((*config).clients); ++i, ++client) {
        if (is_slot_used(client)) {
            if (strcmp(client->ident, name) == 0) {
                ret = i;
                goto out;      // program crashed and restart, use this old slot
            }
        }
        else {
            if (ret == -1) {
                ret = i;
            }
        }
    }

    if (ret != -1) {            // occupy this slot
        struct debug_client * def = &config->clients[0];

        client = &config->clients[ret];
        memcpy(client, def, sizeof(*client));
        strncpy(client->ident, name, sizeof(client->ident) - 1);
        client->ident[sizeof(client->ident) - 1] = 0;
        client->flags |= LOG_CLIENT_FLAG_USED;
    }
out:

    return ret;
}

int zlog_register_modules(char (*modules)[16], int *num, int opened)
{
    int i, n = 0;
    struct debug_config * config;
    struct debug_client * client;

    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);
    client = &config->clients[1];
    for (i = 1; i < ARRAY_SIZE((*config).clients); ++i, ++client) {
        if (is_slot_used(client)) {
            if (opened && !bit_test(config->bitsets, i)) {
                continue;
            }
            if (*num > n) {
                strcpy(modules[n++], client->ident);
            }
        }
    }
    *num = n;
   
    return 0;
}

int zlog_open(const char * ident)
{
    key_t   key = LOG_SHARED_MEMORY_KEY;
    size_t  size = sizeof(struct  shared_config);
    int     flag = O_RDWR;
    int ret;
    int lock;
    char buf[64];

    ret = zlog_init();
    DEBUG("RET = %d\n", ret);

    ret = zdebug_shminit();
    DEBUG("RET = %d\n", ret);
     
    if (g_shm_id == -1 ) {
        g_shm_id = shmget(key, size, flag);
        if (g_shm_id == -1) {
            TRACE();
            return -1;
        }
        else {
            HERE();
        }
    }

    if (g_shm_data == (void *) -1) {
        g_shm_data = shmat(g_shm_id, NULL, 0);
        if (g_shm_data == (void *) -1) {
            TRACE();
            return -1;
        }
        else {
            HERE();
        }
    }

    lock = zlog_lock();
    if (lock == -1) {
        DEBUG("Failed to lock %s\n", LOCK_NAME);
        return -1;
    }
    ret = log_get_idle_slot(ident);
    if (ret != -1) {
        if (g_log_id == -1) {
            g_log_id = ret; // saved the first slot
        }
    }
    if (openlog_once == 0) {
        openlog(ident, LOG_PID, LOG_LOCAL3);
        openlog_once = 1;
    }
    zlog_unlock(lock);

    sprintf(buf, "%d_%s", ret, ident);
    klogctl(20, buf, sizeof(buf));
    
    return ret;
}

void zlog_close(int module)
{
    struct debug_config * config = &(((struct shared_config *)g_shm_data)->debug);
    int lock;

    lock = zlog_lock();
    if (lock == -1) {
        return ;
    }
    config->clients[module].flags &= (~LOG_CLIENT_FLAG_USED);
    if (module == g_log_id) {
        g_log_id = -1;
    }
    zlog_unlock(lock);
}
  
void zlog_output(int module, int priority, const char *format, va_list args)
{
    struct shared_config * config = ((struct shared_config *)g_shm_data);
    char *devlist[SESSION_MAX_COUNT];
    const CODE *c_pri;
    int devnum, i, len, new_line = 0;
    time_t now;
    
    /* do nothing if info center disabled */
    if (!config->infocenter_enable) {
        return;
    }

    va_list ac;
    va_copy(ac, args);
    vsyslog(priority, format, ac);
    va_end(ac);

    if ((unsigned int)module >= CONFIG_LOG_CLIENT_MAX_NUM) {
        return;
    }
    
    if (config->log.console_enable && config->log.console_level >= priority) {
        devnum = session_devlist(OPEN_LOGING, devlist);
        va_list ac;
        va_copy(ac, args);
        if (devnum > 0) {
            char buf[64];
            
            (void)time(&now);

            c_pri = prioritynames;
			while (c_pri->c_name) {
				if (c_pri->c_val == LOG_PRI(priority)) {
					break;
				}
                c_pri++;
			}
            
            sprintf(buf,"%.15s %-6s %s[%d]: ", ctime(&now) + 4, 
                c_pri->c_name?c_pri->c_name:"info", config->debug.clients[module].ident, getpid());
            len = strlen(format);
            if (format[len - 1] != '\r' && format[len - 1] != '\n') {
                new_line = 1;
            }
            for (i=0; i<devnum; i++) {
                FILE * fp = fopen(devlist[i], "a+");                    
                if (!fp) { 
                    session_closedelay(devlist[i]);
                    continue;
                }
                fputs(buf, fp);
                vfprintf(fp, format, ac);
                if (new_line) {
                    fputs("\n", fp);
                }
                fclose(fp);
            }
        }
        va_end(ac);
    }

    return ;
}

void zlog(int module, int priority, const char *format, ...)
{
    va_list args;
    
    va_start (args, format); 
    
    if (priority > DEBUG_ONLY) {
        zdebug_output(module, priority, format, args);
    }
    else {
        zlog_output(module, priority, format, args);
    }
    
    va_end (args);
}

static int zlog_sharemem(void) 
{
    key_t   key = LOG_SHARED_MEMORY_KEY;
    size_t  size = sizeof(struct shared_config);
    int     flag = O_RDWR;
    
    zlog_init();
    if (g_shm_id == -1) {
        g_shm_id = shmget(key, size, flag);
        if (g_shm_id == -1) {
            TRACE();
            return -1;
        }
    }

    if (g_shm_data == (void *) -1) {
        g_shm_data = shmat(g_shm_id, NULL, 0);
        if (g_shm_data == (void *) -1) {
            TRACE();
            return -1;
        }
    }

    return 0;
}

int zdebug_enable(int enable) 
{
    struct debug_config * config;

    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    config->enable = enable;

    return 0;
}

int zdebug_updateparam(int level, int console_enable, int file_enable) 
{
    struct debug_config * config;

    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    if (level <= DEBUG_DETAIL && level>= DEBUG_EXCEPT) {
        config->level = level;
    }
    
    if (console_enable >= 0) {
        config->console_enable = console_enable;
    }

    if (file_enable >= 0) {
        config->file_enable = file_enable;
    }
    
    return 0;
}

int zdebug_getparam(int *level, int *console_enable, int *file_enable)
{
    struct debug_config * config;

    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    *level = config->level;
    *console_enable = config->console_enable;
    *file_enable = config->file_enable;

    return 0;
}

static void zdebug_kernel_operate(const char *name, int op)
{
    char buf[64];

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "%d_%s", op, name);
    klogctl(25, buf, sizeof(buf));
}

int zdebug_openmodule(const char *name)
{
    struct debug_config * config;
    struct debug_client * client;
    int i;
    
    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    client = &config->clients[0];
    for (i = 0; i < ARRAY_SIZE((*config).clients); ++i, ++client) {
        if (is_slot_used(client)) {
            if (strcmp(client->ident, name) == 0) {
                zdebug_kernel_operate(client->ident, 1);
                bit_set(config->bitsets, i);
                return 0;
            }
        }
    }
    
    return -1;
}

int zdebug_openall(void)
{
    struct debug_config * config;
    struct debug_client * client;
    int i;
    
    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    client = &config->clients[0];
    for (i = 0; i < ARRAY_SIZE((*config).clients); ++i, ++client) {
        if (is_slot_used(client)) {
            zdebug_kernel_operate(client->ident, 1);
            bit_set(config->bitsets, i);
        }
    }
    
    return 0;
}

int zdebug_closemodule(const char *name)
{
    struct debug_config * config;
    struct debug_client * client;
    int i;
    
    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    client = &config->clients[0];
    for (i = 0; i < ARRAY_SIZE((*config).clients); ++i, ++client) {
        if (is_slot_used(client)) {
            if (strcmp(client->ident, name) == 0) {
                zdebug_kernel_operate(client->ident, 0);
                bit_clear(config->bitsets, i);
                return 0;
            }
        }
    }
    
    return -1;
}

int zdebug_closeall(void)
{
    struct debug_config * config;
    struct debug_client * client;
    int i;
    
    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
    }
    config = &(((struct shared_config *)g_shm_data)->debug);

    client = &config->clients[0];
    for (i = 0; i < ARRAY_SIZE((*config).clients); ++i, ++client) {
        if (is_slot_used(client)) {
            zdebug_kernel_operate(client->ident, 0);
            bit_clear(config->bitsets, i);
        }
    }
    
    return 0;
}

static int zlog_init(void)
{
    key_t   key = LOG_SHARED_MEMORY_KEY;
    size_t  size = sizeof(struct shared_config);
    int     flag = 0666 | IPC_CREAT | IPC_EXCL;
    int     id;
    void * data;
    struct shared_config * config;
    struct debug_client   def;
    int lock;

    lock = zlog_lock();
    if (lock == -1) {
        return -1;
    }
    id = shmget(key, size, flag);
    if (id == -1) {
        if (errno == EEXIST) {
            // init done
            zlog_unlock(lock);
            return 0;
        }
        else {
            DEBUG("Failed to open shared memory: %d %s!\n", errno, strerror(errno));
            zlog_unlock(lock);
            return -1;
        }
    }

    data = shmat(id, NULL, 0);
    if (data == (void *) -1) {
        /* TODO: delete shared memory */

        DEBUG("Failed to attach: %d %s!\n", errno, strerror(errno));
        zlog_unlock(lock);
        return -1;
    }

    config = (struct shared_config *)data;
    memset(config, 0, sizeof(*config));

    /* alloc a default slot */
    strcpy(def.ident, "default");
    def.flags = LOG_CLIENT_FLAG_USED;
    strcpy(def.filename, "/var/run/debug");
    memcpy(&config->debug.clients[0], &def, sizeof(def));
    /* default value: disable output and LOG_INFO level */
    config->infocenter_enable = 1;
    config->log.console_enable = 0;
    config->log.console_level = LOG_INFO;
    config->debug.enable = 1;
    config->debug.level = DEFAULT_DEBUG_LEVEL;
    config->debug.console_enable = DEFAULT_DEBUG_CONSOLEENABLE;
    config->debug.file_enable = DEFAULT_DEBUG_FILEENABLE;

    shmdt(data);

    zlog_unlock(lock);

    return 0;
}

int zlog_set_consoleparam(int enable, int level)
{
    struct shared_config * config = (struct shared_config *)g_shm_data;

    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
        config = (struct shared_config *)g_shm_data;
    }
    
    config->log.console_enable = enable;
    config->log.console_level = level;
    
    return 0;
}

int zlog_enable_infocenter(int enable)
{
    struct shared_config * config = (struct shared_config *)g_shm_data;

    if (g_shm_data == (void *) -1) {
        if (zlog_sharemem()) {
            return -1;
        }
        config = (struct shared_config *)g_shm_data;
    }
    
    config->infocenter_enable = enable;
    
    return 0;
}

char *zlog_module_indent(int module)
{
    struct shared_config * config = ((struct shared_config *)g_shm_data);

    if ((unsigned int)module >= CONFIG_LOG_CLIENT_MAX_NUM || config == (void *) -1) {
        return "unknow module";
    }
    
    return config->debug.clients[module].ident;
}

static int zdebug_shminit(void)
{
#define G debug_shmem     
#define INITED_FILE "/var/run/debug_shminit"
    struct flock fl;
    int fd, inited = 0, num;

	G.shmid = shmget(G.keyid, G.shm_size, IPC_CREAT | 0644);
	if (G.shmid == -1) {
        if (errno == EEXIST) {
            G.shmid = shmget(G.keyid, G.shm_size, 0);
            if (G.shmid == -1) {
            	DEBUG("shmget error. \n");
                return - 1;
            }
        }
	}

	G.shbuf = shmat(G.shmid, NULL, 0);
	if (G.shbuf == (void*) -1L) { /* shmat has bizarre error return */
		DEBUG("shmat error.\n");
        return -1;
	}

    fd = open(INITED_FILE, O_RDWR|O_CREAT, 0666);
    if (fd >= 0) {
        fl.l_whence = SEEK_SET;
    	fl.l_start = 0;
    	fl.l_len = 1;
    	fl.l_type = F_RDLCK;
    	fcntl(fd, F_SETLKW, &fl);
        do {
        	num = read(fd, &inited, sizeof(int));
        } while (num < sizeof(int) && errno == EINTR);
    }

    if (inited == 0) {
    	memset(G.shbuf, 0, G.shm_size);
    	G.shbuf->size = G.shm_size - offsetof(struct shbuf_ds, data) - 1;
    	/*G.shbuf->tail = 0;*/
    }
    inited = 1;
    if (fd >= 0) {
        write(fd, &inited, sizeof(int));
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
    }

	// we'll trust the OS to set initial semval to 0 (let's hope)
	G.s_semid = semget(G.keyid, 2, IPC_CREAT | IPC_EXCL | 1023);
	if (G.s_semid == -1) {
		if (errno == EEXIST) {
			G.s_semid = semget(G.keyid, 2, 0);
			if (G.s_semid != -1)
				return 0;
		}
		DEBUG("semget error. \n" );
        return -1;
	}
    
    return 0;
#undef G    
}

void zdebug_resetbuffer(void)
{
#define G debug_shmem  
    memset(G.shbuf, 0, G.shm_size);
    G.shbuf->size = G.shm_size - offsetof(struct shbuf_ds, data) - 1;
#undef G
}

/* Write message to shared mem buffer */
static void zdebug_to_shmem(const char *msg, int len)
{
#define G debug_shmem    
	int old_tail, new_tail;

	if (semop(G.s_semid, G.SMwdn, 3) == -1) {
		DEBUG("SMwdn error.\n");
	}

	/* Circular Buffer Algorithm:
	 * --------------------------
	 * tail == position where to store next syslog message.
	 * tail's max value is (shbuf->size - 1)
	 * Last byte of buffer is never used and remains NUL.
	 */
	len++; /* length with NUL included */
 again:
	old_tail = G.shbuf->tail;
	new_tail = old_tail + len;
	if (new_tail < G.shbuf->size) {
		/* store message, set new tail */
		memcpy(G.shbuf->data + old_tail, msg, len);
		G.shbuf->tail = new_tail;
	} else {
		/* k == available buffer space ahead of old tail */
		int k = G.shbuf->size - old_tail;
		/* copy what fits to the end of buffer, and repeat */
		memcpy(G.shbuf->data + old_tail, msg, k);
		msg += k;
		len -= k;
		G.shbuf->tail = 0;
		goto again;
	}
	if (semop(G.s_semid, G.SMwup, 1) == -1) {
		DEBUG("SMwup error.\n");
	}
#undef G		
}

static void zdebug_output(int module, int priority, const char *format, 
    va_list args)
{
    struct debug_config * config = &(((struct shared_config *)g_shm_data)->debug);
    char *devlist[SESSION_MAX_COUNT];
    static char *pri_name[3] = {"except", "flow", "detail"};
    time_t now;
    int devnum, i, len, new_line = 0;

    if ((unsigned int)module >= CONFIG_LOG_CLIENT_MAX_NUM) {
        return;
    }
    if ((config->clients[module].flags & LOG_CLIENT_FLAG_USED) == 0) {
        return;
    }

    if (!config->enable || config->level < priority) {
        return;
    }
    
    if (!bit_test(config->bitsets, module)) {
        return;
    }
   
    (void)time(&now);
    if (config->console_enable) {
        devnum = session_devlist(OPEN_DEBUGGING, devlist);
        if (devnum > 0) {
            char buf[64];
            va_list ac;
            va_copy(ac, args);

            sprintf(buf, "%.15s %-6s %s[%d]: ", ctime(&now) + 4, 
                pri_name[(priority - DEBUG_EXCEPT)%3], config->clients[module].ident, getpid());

            len = strlen(format);
            if (format[len - 1] != '\r' && format[len - 1] != '\n') {
                new_line = 1;
            }
            
            for (i=0; i<devnum; i++) {
                FILE * fp = fopen(devlist[i], "a+");                    
                if (!fp) { 
                    session_closedelay(devlist[i]);
                    continue;
                }
                fputs(buf, fp);
                vfprintf(fp, format, ac);
                if (new_line) {
                    fputs("\n", fp);
                }
                fclose(fp);
            }
            va_end(ac);
        }
    }

    if (config->file_enable) {
        char tbuf[1024];
        char *p, *end;

        memset(tbuf, 0, sizeof(tbuf));
        end = tbuf + sizeof(tbuf) - 1;
    	p = tbuf + sprintf(tbuf, "%.15s %-6s %s[%d]: ", ctime(&now) + 4, 
            pri_name[(priority - DEBUG_EXCEPT)%3], config->clients[module].ident, getpid());
        p += vsnprintf(p, end - p, format, args);
        if (tbuf[strlen(tbuf) - 1] != '\n') {
            if (strlen(tbuf) < sizeof(tbuf))
                tbuf[strlen(tbuf)] = '\n' ;
        }
        zdebug_to_shmem(tbuf, strlen(tbuf));
#if 0        
        FILE * fp = fopen(config->clients[module].filename, "a+");
        if (fp) {
            va_list ac;
            va_copy(ac, args);
            vfprintf(fp, format, ac);
            va_end(ac);
            fclose(fp);
        }
#endif
        
    }

    return ;
}

struct globals {
	struct sembuf SMrup[1]; // {0, -1, IPC_NOWAIT | SEM_UNDO},
	struct sembuf SMrdn[2]; // {1, 0}, {0, +1, SEM_UNDO}
	struct shbuf_ds *shbuf;
};
struct globals G;
#define SMrup (G.SMrup)
#define SMrdn (G.SMrdn)
#define shbuf (G.shbuf)
#define INIT_G() do { \
	memcpy(SMrup, init_sem, sizeof(init_sem)); \
} while (0)

static void interrupted(int sig)
{
    sig = sig;
	signal(SIGINT, SIG_IGN);
	shmdt(shbuf);
	exit(EXIT_SUCCESS);
}

static size_t strnlen(const char *s, size_t maxlen)
{
	size_t i;
	if (!maxlen) return 0;
	if (!s) return 0;
	for (i = 0; *s && i < maxlen; ++s) ++i;
	return i;
}

static inline int get_logpri(const char *message)
{
    const CODE *c_pri = prioritynames;
    char *priname = NULL;
    int pri = LOG_DEBUG;
    int len;
    
    priname = strchr(message, '.'); 
    if (priname) {
        priname++;
        len = 0;
        while (priname[len]) {
            if (priname[len] == ' ') {
                break;
            }
            len++;
        }        
        if (len > 0) {
            while (c_pri->c_name) {
				if (!strncmp(c_pri->c_name, priname, len)) {
                    pri = c_pri->c_val;
                    break;
				}
                c_pri++;
			}
        }
    }

    return pri;
}

/*
 * size: number of log message, -1 for all messages
 * reverse: 0 for sequential order, 1 for reverse order
 * level: output log with pri <= level, -1 for all log
 * caller: 0 for CLI (output to console), 1 for WEB (output to file)
 */
static int shmem_read(key_t keyid, int size, int reverse, int level, int caller);
int zlog_read(int size, int reverse, int level, int caller)
{
    return shmem_read(LOG_KEY_ID, size, reverse, level, caller);
}

int zdebug_read(int size, int reverse, int fd)
{
    return shmem_read(DEBUG_KEY_ID, size, reverse, 0, fd);
}

static int shmem_read(key_t keyid, int size, int reverse, int level, int caller)
{
	unsigned cur;
	int log_semid; /* ipc semaphore id */
	int log_shmid; /* ipc shared memory id */

	INIT_G();

	log_shmid = shmget(keyid, 0, 0);
	if (log_shmid == -1) {
		DEBUG("can't find share memory buffer\.n");
        return -1;
    }

	/* Attach shared memory to our char* */
	shbuf = shmat(log_shmid, NULL, SHM_RDONLY);
	if (shbuf == NULL) {
		DEBUG("can't access syslogd buffer");
        return -1;
    }

	log_semid = semget(keyid, 0, 0);
	if (log_semid == -1) {
		DEBUG("can't get access to semaphores for syslogd buffer");
        return -1;
    }

	signal(SIGINT, interrupted);

	/* Suppose atomic memory read */
	/* Max possible value for tail is shbuf->size - 1 */
	cur = shbuf->tail;

	/* Loop for logread -f, one pass if there was no -f */
	do {
		unsigned shbuf_size;
		unsigned shbuf_tail;
		const char *shbuf_data;
		int i, num;
		int len_first_part;
		int len_total = 0; /* for gcc */
		char *copy = NULL; /* for gcc */

		if (semop(log_semid, SMrdn, 2) == -1) {
			DEBUG("semop[SMrdn]");
            return -1;
        }

		/* Copy the info, helps gcc to realize that it doesn't change */
		shbuf_size = shbuf->size;
		shbuf_tail = shbuf->tail;
		shbuf_data = shbuf->data; /* pointer! */

		/* advance to oldest complete message */
		/* find NUL */
		cur += strlen(shbuf_data + cur);

		if (cur >= shbuf_size) { /* last byte in buffer? */
			cur = strnlen(shbuf_data, shbuf_tail);
			if (cur == shbuf_tail)
				goto unlock; /* no complete messages */
		}
		/* advance to first byte of the message */
		cur++;
		if (cur >= shbuf_size) /* last byte in buffer? */
			cur = 0;

		/* Read from cur to tail */
		len_first_part = len_total = shbuf_tail - cur;
		if (len_total < 0) {
			/* message wraps: */
			/* [SECOND PART.........FIRST PART] */
			/*  ^data      ^tail    ^cur      ^size */
			len_total += shbuf_size;
		}
        copy = NULL;
		copy = malloc(len_total + 1);
		
        if (len_first_part < 0) {
			/* message wraps (see above) */
			len_first_part = shbuf_size - cur;
			memcpy(copy + len_first_part, shbuf_data, shbuf_tail);
		}
		memcpy(copy, shbuf_data + cur, len_first_part);
		copy[len_total] = '\0';
		cur = shbuf_tail;
 unlock:
		/* release the lock on the log chain */
        if (semop(log_semid, SMrup, 1) == -1) {
            DEBUG("semop[SMrup]");
            return -1;
        }
        if (keyid == LOG_KEY_ID) {
            if (0 == caller) {
                num = 0;
                if (!reverse) {
            		for (i = 0; i<len_total && (size<0 || num<size); i += strlen(copy + i) + 1) {
                        if (strlen(copy + i) > 0) {
                            if (level < 0 || level >= get_logpri(copy+i)) {
                                fputs(copy + i, stdout);
                                num ++;
                            }
                        }
            		}  
                }
                else {
                    for (i=len_total-2; i>=0 && (size<0 || num<size); i--) {
                        if (!copy[i]) {
                            if (strlen(copy+i+1) > 0) {
                                if (level < 0 || level >= get_logpri(copy + i +1)) {
                                    fputs(copy + i +1, stdout);
                                    num ++;
                                }
                            }
                        }
                    }
                }
            }
            else {
                #define BUFFLER_LOGFILE  "/var/run/bufferlog"  
                int fd;

                unlink(BUFFLER_LOGFILE);
                fd = open(BUFFLER_LOGFILE, O_RDWR | O_CREAT, 0666);
                if (fd == -1) {
                    goto FREE;
                }
                num = 0;
                if (!reverse) {
            		for (i = 0; i<len_total && (size<0 || num<size); i += strlen(copy + i) + 1) {
                        if (strlen(copy + i) > 0) {
                            if (level < 0 || level >= get_logpri(copy+i)) {
                                write(fd, copy + i, strlen(copy + i));
                                num ++;
                            }
                        }
            		}  
                }
                else {
                    for (i=len_total-2; i>=0 && (size<0 || num<size); i--) {
                        if (!copy[i]) {
                            if (strlen(copy+i+1) > 0) {
                                if (level < 0 || level >= get_logpri(copy+i+1)) {
                                    write(fd, copy+i+1, strlen(copy+i+1));
                                    num ++;

                                }
                            }
                        }
                    }
                }
                
                close(fd);
            }
        }
        else if (keyid == DEBUG_KEY_ID) {
            num = 0;
            if (!reverse) {
        		for (i = 0; i<len_total && (size<0 || num<size); i += strlen(copy + i) + 1) {
                    if (strlen(copy + i) > 0) {
                        if (caller < 0) {
                            fputs(copy + i, stdout);
                        }
                        else {
                            write(caller, copy + i, strlen(copy + i));
                        }
                        num ++;
                    }
        		}  
            }
            else {
                for (i=len_total-2; i>=0 && (size<0 || num<size); i--) {
                    if (!copy[i]) {
                        if (strlen(copy+i+1) > 0) {
                            
                            if (caller < 0) {
                                fputs(copy + i +1, stdout);
                            }
                            else {
                                write(caller, copy + i +1, strlen(copy + i +1));
                            }
                            num ++;
                        }
                    }
                }
            }
        }
FREE:
        free(copy);
	} while (0);

	shmdt(shbuf);

	return 0;
}




