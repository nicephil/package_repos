#ifndef __AH_OVERRIDES_H__
#define __AH_OVERRIDES_H__

#include <string.h>
#include <stdlib.h>

/*
 * simple wrappers, just call the linux sys API,
 * leave up side for future optimization
 */
#define ah_malloc(size)                  malloc(size)
#define ah_calloc(n, size)               calloc(n,size)
#define ah_realloc(ptr,size)             realloc(ptr,size)
#define ah_free(ptr)                     free(ptr)

/** THese are deprecated  - there may be some use for the wrappers above, but
 *  not a whole lot of use for the wrappers below....
 */
#define ah_strcpy(dst, src)              strcpy(dst,src)
#define ah_strncpy(dst,src,n)            strncpy(dst,src,n)
#define ah_memcpy(dst,src,n)             memcpy(dst,src,n)
#define ah_memcmp(s1,s2,n)               memcmp(s1,s2,n)
#define ah_memset(dst,v,size)            memset(dst,v,size)
#define ah_strchr(s,c)                   strchr(s,c)
#define ah_strlen(s)                     strlen(s)
#define ah_strrchr(s,c)                  strrchr(s,c)
#define ah_strcmp(s1,s2)                 strcmp(s1,s2)
#define ah_strlcat(s1,s2,size)           strlcat(s1,s2,size)

#endif /*__AH_OVERRIDES_H__ */
