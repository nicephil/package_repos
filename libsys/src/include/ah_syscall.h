#ifndef _AH_SYSCALL_H_
#define _AH_SYSCALL_H_

#include <stdio.h>
#include "ah_types.h"

int ah_system(const char *command);
int ah_curl_system(const char *command);
int ah_vsystem(const char *cmd_fmt, ...);
int ah_run_daemon(char **argv, int *pid);
FILE  *ah_popen(const char *command, const char *type);
int ah_str2lowcase(const char *raw_str, char *low_str, int max_len);
int ah_str_del_blank(char *raw_str);
int ah_system_timedwait(const char *cmd, uint timeout);
char  *ah_strlwr( char *orig, char *lwr);
#endif /* _AH_SYSCALL_H_ */

