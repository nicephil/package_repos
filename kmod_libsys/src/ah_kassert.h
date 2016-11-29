#ifndef __AH_KASSERT_H__
#define __AH_KASSERT_H__

#include <linux/kernel.h>

/* only take effect in dbg feature build */
#ifdef AH_DEBUG_FEATURE
#define ah_kassert(x) do { \
		if (unlikely(!(x))) { \
			kernel_trace_dump = 1; \
			printk(KERN_ERR "AH_KERNEL: assertion (%s) failed at %s (%d)\n", \
				   #x,  __func__ , __LINE__); \
			dump_stack(); \
			kernel_trace_dump = 0; \
		} \
	} while(0)
#else
#define ah_kassert(x)
#endif

#endif/*__AH_KASSERT_H__*/
