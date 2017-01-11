#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>


#include "services/hostname_services.h"

static char g_hostname[128] = HOSTNAME_DEFAULT;
static int g_hostname_init = 0;

int hostname_undo(void)
{
    if (strcmp(g_hostname, HOSTNAME_DEFAULT)) {
        return hostname_set(HOSTNAME_DEFAULT);
    }
    return 0;
}

int hostname_get(char * hostname, int len)
{
    /* get from memory */
    if (g_hostname_init) {
        strcpy(hostname, g_hostname);
        return 0;
    }

    /* get from config file */
    cfg_get_option_value(SYSTEM_OPTION_HOSTNAME_TUPLE, g_hostname, sizeof(g_hostname));
    strncpy(hostname, g_hostname, len-1);
    hostname[len-1] = '\0';
}

int hostname_set(const char *hostname)
{
    /* same as global variable */
    if (!strcmp(hostname, g_hostname)) {
        return 0;
    }

    /* real operation */
    sethostname(g_hostname, strlen(g_hostname));

    /* update config */
    cfg_set_option_value(SYSTEM_OPTION_HOSTNAME_TUPLE, hostname);

    /* update global variable */
    strncpy(g_hostname, hostname, sizeof(g_hostname)-1);
    g_hostname[sizeof(g_hostname)-1] = '\0';

    syslog(LOG_NOTICE, "Set hostname:%s\n", g_hostname);
    return 0;
}
