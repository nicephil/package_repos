#ifndef __DNS_SERVICES_H_
#define __DNS_SERVICES_H_

#include <arpa/inet.h>

extern int dns_set_global(struct in_addr dns);
extern int dns_undo_global(struct in_addr dns);
extern int dns_undo_global_all(void);
extern int dns_get_global(struct in_addr * dns);

#endif /* __DNS_SERVICES_H_ */



