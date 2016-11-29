/*************************************************************************
* @file ah_logging.h
*
* @brief Logging APIs and enums for the system. Currently user-space only.
*        We need to get this moved to "share" as soon as we can.
*
*************************************************************************/

#ifndef __AH_LOGGING_H__
#define __AH_LOGGING_H__

#include "ah_log_types.h"

#define AH_SPEC_LOG_HEAD   "::SPECIAL_LOG::T"
#define AH_SPEC_LOG_CLEAR_LOG           1
#define AH_SPEC_LOG_FLASH_LOG           2


extern int ah_log_old(ah_log_level_t level, const char *fmt, ...);
extern int __ah_dbg_old(const char *file, int line, const char *type, const char *fmt, ...);
extern int __ah_err_old(const char *file, int line, const char *fmt, ...);
extern int ah_log_flash(ah_log_level_t level, const char *fmt, ...);

/*
 * Error report utility
 */
#ifdef AH_BUILD_RELEASE
// TODO - pass NULL as first parm - make __ah_err understand it
#define AH_FILE     ""
#else
#define AH_FILE     __FILE__
#endif

#define ah_err_old(fmt, arg...)  __ah_err_old(AH_FILE, __LINE__, fmt, ##arg)

#define ah_fatal_if(doit, fmt, arg...) \
	do { \
		if (doit) { \
			__ah_dbg_old(AH_FILE, __LINE__, #doit, fmt, ##arg); \
			ah_assert_always(0); \
		} \
	} while (0)

#define ah_fatal(fmt, arg...) \
	do { \
		__ah_err_old(AH_FILE, __LINE__, fmt, ##arg); \
		ah_assert_always(0); \
	} while (0)

#if defined(AH_BUILD_RELEASE)
#define ah_fatal_debug(fmt, arg...)
#define ah_fatal_if_debug(doit, fmt, arg...)
#else
#define ah_fatal_debug(fmt, arg...)           ah_fatal(fmt, ##arg)
#define ah_fatal_if_debug(doit, fmt, arg...)  ah_fatal_if(doit, fmt, ##arg)
#endif

/*
 * TODO: Eventually, ah_dbg_if and ah_dbg go away if we're in a release build, and only
 * ah_qalog is related to AH_DEBUG_FEATURE
 */
#ifdef AH_DEBUG_FEATURE
#define ah_dbg_if(doit, fmt, arg...) \
	do { \
		if (doit) { \
			__ah_dbg_old(AH_FILE, __LINE__, #doit, fmt, ##arg); \
		} \
	} while(0)

#else
#define ah_dbg_if(doit, fmt, arg...)
#endif

// Deprecated - TODO: eventually maps to ah_qalog_if
#define ah_dbg_old(doit, fmt, arg...)   ah_dbg_if(doit, fmt, ##arg)

#endif /* __AH_LOGGING_H__ */

