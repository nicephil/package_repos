#ifndef __AH_LOG_ID_H__
#define __AH_LOG_ID_H__

/* mod id start from 1 */
#include "ah_mod_id.h"

/*
 * log id is unsigned int(32 bits), format:
 * R-reserved;
 *   bit   bit   bit   bit   bit   bit   bit   bit
 * |--0--|--1--|--2--|--3--|--4--|--5--|--6--|--7--|
 * +++++++++++++++++++++++++++++++++++++++++++++++++
 * +  R  +         module ID                       +
 * +     +                                         +
 * +++++++++++++++++++++++++++++++++++++++++++++++++
 * +                 Group ID                      +
 * +                                               +
 * +++++++++++++++++++++++++++++++++++++++++++++++++
 * +                     ID                        +
 * +                                               +
 * +++++++++++++++++++++++++++++++++++++++++++++++++
 * +            ID               +    level        +
 * +      (continued)            +                 +
 * +++++++++++++++++++++++++++++++++++++++++++++++++
 */

#define AH_LOG_MODULE_MASK 0x7f000000u
#define AH_LOG_GROUP_MASK  0xff0000u
#define AH_LOG_ID_MASK     0xfff8u
#define AH_LOG_LEVEL_MASK  0x7u

#define GEN_LOG_ID(mid, gid, id) \
	(((((unsigned int)mid) << 24) & AH_LOG_MODULE_MASK) \
	 | ((((unsigned int)gid) << 16) & AH_LOG_GROUP_MASK) \
	 | ((((unsigned int)id) << 3) & AH_LOG_ID_MASK))

/* group id for auth */
#define AH_GRP_AUTH_CONNECT     0x0u

/* log id for AH_GRP_AUTH_CONNECT */
#define LOG_AUTH_CONNECT_FAILURE  GEN_LOG_ID(AH_MOD_ID_AUTH, AH_GRP_AUTH_CONNECT, 0x0u)
#define LOG_AUTH_CONNECT_DOWN     GEN_LOG_ID(AH_MOD_ID_AUTH, AH_GRP_AUTH_CONNECT, 0x1u)

#endif /*__AH_LOG_ID_H__*/

