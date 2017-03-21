#ifndef __DNS_SERVICES_H_
#define __DNS_SERVICES_H_

#include <arpa/inet.h>

#define MAX_DNS_COUNT   3    

extern int dns_set_global(struct in_addr dns);
extern int dns_undo_global(struct in_addr dns);
extern int dns_undo_global_all(void);
extern int dns_get_global(struct in_addr * dns);

#endif /* __DNS_SERVICES_H_ */



