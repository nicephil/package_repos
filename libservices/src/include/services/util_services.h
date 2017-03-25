#ifndef __UTIL_SERVICES_H_
#define __UTIL_SERVICES_H_
extern int if_ether_ntoa(const unsigned char *addr, char *txt);
extern int if_ether_aton(const char *txt, unsigned char *addr);
extern int util_str2ip(char *ipstr, unsigned int *ipaddr);
#endif /* __UTIL_SERVICES_H_ */
