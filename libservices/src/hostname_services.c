#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>


#include "services/hostname_services.h"

int hostname_undo(void)
{
    return 0;
    return hostname_set(HOSTNAME_DEFAULT);
}

int hostname_get(char * hostname, int len)
{
    /* get from system directly */
   return gethostname(hostname, len);
}

int hostname_set(const char *hostname)
{
    return 0;
    /* update config */
    cfg_set_option_value(SYSTEM_OPTION_HOSTNAME_TUPLE, hostname);

    /* real operation */
    sethostname(hostname, strlen(hostname));

    syslog(LOG_NOTICE, "Set hostname:%s\n", hostname);
    return 0;
}

int zone_undo(void)
{
    return zone_set(ZONE_DEFAULT);
}

int zone_set(const char *zone)
{
    /* update config */
    cfg_set_option_value(SYSTEM_OPTION_ZONE_TUPLE, zone);

    syslog(LOG_NOTICE, "Set timezone:%s\n", zone);
    return 0;
}
