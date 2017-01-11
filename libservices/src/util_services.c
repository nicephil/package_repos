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
