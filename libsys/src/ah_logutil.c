/**
 * @file ah_logutil.c
 * @brief this file define the syslog apis 
 *
 */

/*******************************************************************************
 *                              HEADER INCLUDE                                *
*******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>

#include "ah_types.h"
#include "ah_logging.h"
/******************************************************************************/


/*******************************************************************************
 *                         LOCAL VARIABLE DEFINITION                          *
*******************************************************************************/
static int ah_log_level[AH_MAX_LOG_LEVELS] = {
	LOG_EMERG,
	LOG_ALERT,
	LOG_CRIT,
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG
};
/******************************************************************************/

/*******************************************************************************
 *                        GLOBAL FUNCTION DEFINITION                          *
*******************************************************************************/
/*
 * a super simple wrapper for debug print
 * TODO: need a procedure to define some var locally, then
 *       the option show up in cli automatically, to turn on/off the
 *       debug.
 * The "doit" variable must follow this format: debug_module_type
 * e.g:
 *   int debug_amrp_pkt=0;
 *   int debug_amrp_event=0;
 *   int debug_mesh_whatever=0;
 *
 * // change value of debug_pkt/debug_event/whatever to 1 by cli
 *   ah_dbg_old(debug_amrp_pkt, "this is my pkt\n");
 *   ah_dbg_old(debug_amrp_event, "this is my event\n");
 *   ah_dbg_old(debug_mesh_whatever, "this is whatever\n");
 */
int __ah_dbg_old(const char *file, int line, const char *type, const char *fmt, ...)
{
	char hdr[64];
	char buf[512];
	va_list args;

#ifdef AH_BUILD_RELEASE
	snprintf(hdr, sizeof(hdr), "[%s]: ", type);
#else
	snprintf(hdr, sizeof(hdr), "[%s, %s, %d]: ", type, file, line);
#endif

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	/* log it and print to the console for now */
	syslog(LOG_USER | LOG_DEBUG, "%s%s", hdr, buf);
	return 0;
}

/*
 * Log utility
 */
int ah_log_old(ah_log_level_t level, const char *fmt, ...)
{
	char buf[512];
	va_list args;

	if (level < 0 || level >= AH_MAX_LOG_LEVELS) {
		return -1;
	}

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	// log it
	syslog(LOG_USER | ah_log_level[level], "%s", buf);

	return 0;
}

/*
 * Error report utility
 * Caller doesn't need to do strerror in the string. This function
 * will add the error string to the end automatically.
 */
int __ah_err_old(const char *file, int line, const char *fmt, ...)
{
	ah_log_level_t level = AH_LOG_ERR;
	char buf[512];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	// Remove any "\n" or "\r" at the end
	while (strlen(buf) > 0) {
		if ((buf[strlen(buf) - 1] == '\n') || (buf[strlen(buf) - 1] == '\r')) {
			buf[strlen(buf) - 1] = '\0';
		} else {
			break;
		}
	}

	if (errno != 0) {
		// Add error string
		//Bug29953
		strncat(buf, ": ", 2);
		strncat(buf, strerror(errno), 512 - 2 - strlen(buf));

		/* if is the following error, log as warning */
		if (errno == ENODEV) {
			level = AH_LOG_WARNING;
		}
	}

	// log it and print to the console for now
#ifdef AH_BUILD_RELEASE
	ah_log_old(level, "%s", buf);
	return printf("%s\r\n", buf);
#else
	ah_log_old(level, "[%s,%d]: %s", file, line, buf);
	return printf("[%s,%d]: %s\r\n", file, line, buf);
#endif
}

int ah_log_flash(ah_log_level_t level, const char *fmt, ...)
{
	char buf[512];
	int ret;
	va_list args;

	if (level < 0 || level >= AH_MAX_LOG_LEVELS) {
		return -1;
	}

	ret = snprintf(buf, sizeof(buf), "%s%d:", AH_SPEC_LOG_HEAD, AH_SPEC_LOG_FLASH_LOG);
	va_start(args, fmt);
	vsnprintf(buf + ret, sizeof(buf) - ret, fmt, args);
	va_end(args);

	syslog(LOG_USER | ah_log_level[level], "%s", buf);

	return 0;
}
/******************************************************************************/
