#ifndef __HOSTNAME_SERVICES_H
#define __HOSTNAME_SERVICES_H
#include <unistd.h>

/* default value */
#define HOSTNAME_DEFAULT "oakridge" 

/* tuple */
#define CFG_SYSTEM_PACKAGE "system"
#define SYSTEM_OPTION_HOSTNAME_TUPLE "system.@system[0].hostname" 


/* default value for zone */
#define ZONE_DEFAULT "UTC"
#define SYSTEM_OPTION_ZONE_TUPLE "system.@system[0].timezone" 

/* tuple */



extern int hostname_undo(void);
extern int hostname_set(const char * hostname);
extern int hostname_get(char * hostname, int len);



extern int zone_undo(void);
extern int zone_set(const char * zone);
extern int zone_get(char * zone, int len);

#endif
