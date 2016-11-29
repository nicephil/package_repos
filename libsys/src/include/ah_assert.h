#ifndef _AH_ASSERT_H_
#define _AH_ASSERT_H_

#include <syslog.h>

#include "ah_types.h"
#include "ah_log_id.h"
#include "ah_logging.h"

/*
 * ----------------------------------------------------------------------
 * FUNCTION DECLARATIONS
 * ----------------------------------------------------------------------
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ah_assert(expression)
 * TODO: This shouldn't be an inline......
 */
static inline void __ah_assert(const char *expr, const char *file, uint line)
{
	while (*file && (*file == '.' || *file == '/')) {
		++file;
	}

	syslog(LOG_USER | LOG_DEBUG, "Assertion (%s) failed at %s:%d\n", expr, file, line);
	__ah_err_old(file, line, "### Assertion (%s) failed at %s:%d\n", expr);

	/*
	 * Dump core
	 */
	*((int *)NULL) = 0;
}

#define ah_assert_always(expr) \
	((void) ((expr) ? 0 : (__ah_assert (#expr, __FILE__, __LINE__), 0)))

/*
 * ah_assert(expression) - DEPRECATED - be explicit, use ah_assert_always or ah_assert_debug
 */
#define ah_assert(expr) ah_assert_always(expr)

/*
 * ah_assert_debug(expression)
 *
 * Use this for code that should not ever happen, and should be caught in testing if it does.
 * You shouldn't use this for things that might happen in real life.
 * FOr instance, if an API should never take a NULL pointer parameter, you can use this API on it
 * to catch anyone during initial testing who might pass the pointer (although in this case, you'll probably
 * die dereferencing the pointer, and it will be just as easy to track down as the ah_assert).
 */
#ifndef AH_BUILD_RELEASE
#define ah_assert_debug(expr) ah_assert_always(expr)
#else
#define ah_assert_debug(expr) ((void) 0)
#endif

#ifdef __cplusplus
}
#endif


#endif /* _AH_ASSERT_H_ */
