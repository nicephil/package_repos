#ifndef _AH_TYPES_H_
#define _AH_TYPES_H_

#ifdef __KERNEL__

#include <linux/types.h>

#else

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#endif

#ifdef AH_ACSD
#include "typedefs.h"
#endif

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

#ifndef __KERNEL__

// These are OK abbreviations
typedef unsigned short     ushort;
typedef unsigned int       uint;
typedef unsigned long      ulong;

#endif /* __KERNEL__ */

#ifndef TYPEDEF_UCHAR
#define TYPEDEF_UCHAR
typedef unsigned char      uchar;
#endif
typedef unsigned long long ulonglong;

typedef uint32_t           ah_ipaddr_t;

typedef int  boolean;

// These are done this way to avoid conflict in defs.h for now.
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE  (1)
#endif


/* define some common used macros */
#ifndef min
#define min(x, y)   ((x) <= (y) ? (x) : (y))
#endif
#ifndef max
#define max(x, y)   ((x) >= (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y)   ((x) <= (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y)   ((x) >= (y) ? (x) : (y))
#endif

/*
 * Defined in seconds
 */
typedef uint32_t ah_ktime_t;

#ifndef NULL
#define NULL 0
#endif

/* These are also Deprecated - use stdint.h equivalents */
#define AH_CHAR_MIN      (-128)
#define AH_CHAR_MAX      127
#define AH_UCHAR_MAX     255

#define AH_SHORT_MIN     (-32768)
#define AH_SHORT_MAX     (32767)
#define AH_USHORT_MAX    65535


#define AH_INT_MIN       (-AH_INT_MAX - 1)
#define AH_INT_MAX       2147483647
#define AH_UINT_MAX      4294967295U


/* some common const*/
#define AH_MAX_NAME_LEN 32

/* For mac bypass*/
#define AH_MAX_BIND_MAC_OBJECT_NUM      8




/********************************/
/* some propority global def    */
/********************************/
/* pirmary key size */
#define PMK_LEN     32
#define PMKID_LEN   16
#define PMK_SIZE        (PMK_LEN+PMKID_LEN)

/* the macro is used to do aerohive code trace for debug mode*/
#ifdef AH_BUILD_AHCT

#ifndef ahctd
#define ahctd(x, n) int x[n];
#define ahcts(s) s
#define ahct(x) ((x)++);
#endif

#else

#ifndef ahctd
#define ahctd(x, n)
#define ahct(x)
#define ahcts(s)
#endif

#endif


#endif /* _AH_TYPES_H_ */
