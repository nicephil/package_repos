#ifndef _DATA_H_
#define _DATA_H_

#include "log.h"
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdarg.h>

#define CHAR_BIT	     8
typedef unsigned long int bitset_word_t;
#define BITSET_WORD_BITS (sizeof(bitset_word_t) * CHAR_BIT)

#define bit_set(set,i) \
  (set[i / BITSET_WORD_BITS] |= (bitset_word_t) 1 << i % BITSET_WORD_BITS)
#define bit_clear(set,i) \
  (set[i / BITSET_WORD_BITS] &= ~((bitset_word_t) 1 << i % BITSET_WORD_BITS))
#define bit_test(set,i) \
  (set[i / BITSET_WORD_BITS] & ((bitset_word_t) 1 << i % BITSET_WORD_BITS))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif

struct debug_client {
    int flags;
    char ident[LOG_IDENT_NAME_MAX_LENGTH];
    char filename[LOG_FILE_NAME_MAX_LENGTH];
};

struct debug_config {
    int enable;
    int level;
    int console_enable;
    int file_enable;
    unsigned long bitsets[2];
    struct debug_client clients[CONFIG_LOG_CLIENT_MAX_NUM + 1];
};

struct log_config {
    int console_enable;
    int console_level;
};

struct shared_config {
    int infocenter_enable;
    struct log_config log;
    struct debug_config debug;
};

/* busybox logread.c */
enum { 
    LOG_KEY_ID = 0x414e4547, /* our shared key (must be in sync with syslogd.c) */
    DEBUG_KEY_ID = 0x313e4545,
}; 


struct shbuf_ds {
	int32_t size;           // size of data - 1
	int32_t tail;           // end of message list
	char data[1];           // messages
};

struct shmem_control {
    key_t keyid;
    int shmid;    /* shared memory id */   
	int shm_size; 
    struct shbuf_ds *shbuf;
	int s_semid;  /* semaphore id */         
	struct sembuf SMwup[1];                 
	struct sembuf SMwdn[3];      
};

typedef struct _code {
	const char      *c_name;
	int             c_val;
} CODE;
	
/* linked list handling */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif



#define LOG_CLIENT_FLAG_USED    1
#define LOG_SHARED_MEMORY_KEY   0x6c6f6701  //'log'

#define DEFAULT_DEBUG_CONSOLEENABLE     1
#define DEFAULT_DEBUG_FILEENABLE        0
#define DEFAULT_DEBUG_LEVEL             DEBUG_FLOW

static int zlog_init(void);
static void zdebug_output(int module, int priority, const char *format, va_list args);
static int zdebug_shminit(void);
static int zlog_sharemem(void);
#endif /* _DATA_H_ */
