#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "services/util_services.h"

int util_str2ip(char *ipstr, unsigned int *ipaddr)
{
        char *ptr = ipstr, *lastdot = NULL;
        int dotcnt = 0;
        unsigned int ip = 0;
        unsigned int oct = 0;
        int zerotag = 0;

        if (*ptr == '0')
            zerotag=1;
            
        while (1) {
                if (*ptr == '.' || *ptr == '\0') {
                        if (ptr == ipstr || ptr - lastdot == 1) {
                                return -1;
                        }
                        dotcnt++;
                        if (dotcnt > 3 && *ptr != '\0') {
                                return -1;
                        }
                        
                        if (oct > 255) {
                                return -1;
                        }
                        
                        if (zerotag > 0 && oct > 0){
                                return -1;
                        }
                        
                        if (*ptr != '\0' && *(ptr+1) == '0'){
                                zerotag = 1;
                        } else 
                                zerotag = 0;
                            
                        if (oct) {
                                ip |= (oct << ((4 - dotcnt) << 3));
                                oct = 0;
                        }
                        lastdot = ptr;
                        
                        if (*ptr == '\0')
                            break;
                } else if (*ptr < '0' || *ptr > '9') {
                        return -1;
                } else {
                        oct = (oct << 3) + (oct << 1) + (*ptr - '0');
                }
                ptr++;
        }

        if (dotcnt == 4) {
                *ipaddr = ip;
        }

        return (dotcnt == 4) ? 0 : -1;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int is_null_macaddr(unsigned char *mac)
{
    if ((mac[0]==0)&&(mac[1]==0)&&(mac[2]==0)&&(mac[3]==0)&&(mac[4]==0)&&(mac[5]==0))
        return 1;
    return 0;
}

int if_ether_ntoa(const unsigned char *addr, char *txt) 
{
    sprintf(txt, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    return 1;
}

int if_ether_aton(const char *txt, unsigned char *addr)
{
	int i;

	for (i = 0; i < 6; i++) {
		int a, b;

		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		
		if (('\0' != *txt) && (':' != *txt)){
            b = hex2num(*txt++);
            if (b < 0)
			    return -1;
		} else {
            b = a;
            a = 0;
		}
			
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}

	return 0;
}
