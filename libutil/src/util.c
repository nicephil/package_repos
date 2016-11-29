#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include <syslog.h>


#include "util/util.h"

unsigned int util_APHash(const char * str)
{   
    unsigned int hash=0 ;   
    int i ;        
    for(i=0;*str;i++)   
    {   
        if((i&1)==0)   
        {   
            hash^=((hash<<7)^(*str++)^(hash>>3));   
        }   
        else    
        {   
            hash^=(~((hash<<11)^(*str++)^(hash>>5)));   
        }   
    }        
    return hash;//(hash % M);   
}   

int util_file_lock(int fd)
{
    struct flock    lock;
    int     ret;

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    ret = fcntl(fd, F_SETLKW, &lock);

    return ret;
}

int util_file_unlock(int fd)
{
    struct flock    lock;
    int     ret;

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    ret = fcntl(fd, F_SETLKW, &lock);

    return ret;
}

int util_output_pidfile(const char * file)
{
    int fd, len;
    char    buf[16];
    pid_t   pid;

    unlink(file);

    fd = open(file, O_RDWR | O_CREAT, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "Failed to open file [%s]\n", file);
        return -1;
    }
    fchmod(fd, 0644 | S_ISGID); // need for mandatory lock

    util_file_lock(fd);

    pid = getpid();
    len = sprintf(buf, "%d", pid);
    write(fd, buf, len);

    util_file_unlock(fd);

    close(fd);

    return 0;
}

pid_t util_try_pidfile(const char * file)
{
    int fd;
    int ret;
    char    buf[128];

    fd = open(file, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    util_file_lock(fd);
    ret = read(fd, buf, sizeof(buf) - 1);
    util_file_unlock(fd);
    close(fd);

    if (ret <= 0) {
        return -1;
    }

    buf[ret] = 0;
    ret = atoi(buf);
    if (ret == 0) {
        return -1;
    }

    return ret;
}

pid_t util_load_pidfile(const char * file)
{
    int fd, ret;
    char    buf[128];

    fd = open(file, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    util_file_lock(fd);
    ret = read(fd, buf, sizeof(buf) - 1);
    util_file_unlock(fd);
    close(fd);

    if (ret <= 0) {
        return -1;
    }

    buf[ret] = 0;
    ret = atoi(buf);
    if (ret == 0) {
        return -1;
    }

    return ret;
}

pid_t util_wait_pidfile(const char * file)
{
    int fd;
    int i, ret;
    char    buf[128];
    int timeout = 500000;

    for (i = 0; i < 10; ++i) {
        fd = open(file, O_RDONLY);
        if (fd == -1) {
            usleep(timeout);
            continue;
        }
        util_file_lock(fd);
        ret = read(fd, buf, sizeof(buf) - 1);
        util_file_unlock(fd);
        close(fd);

        if (ret <= 0) {
            /* added by chenxiaojie for bug 2103 */
            usleep(timeout);
            continue;
        }
        else {
            buf[ret] = 0;
            ret = atoi(buf);
            if (ret <= 0) {
                syslog(LOG_ERR, "Invalid data(%s) read in file [%s]\n", 
                        buf, file);
                        
                return -1;
            }
            return ret;
        }
    }

    return -1;
}

void kill_pid_safe(pid_t pid)
{
    int i, ret;
   
    if (pid <= 0) {
        syslog(LOG_ERR, "FATAL ERROR: Could not kill process %d\n", pid);
        return ;
    }

    for (i = 0; i < 5; ++i) {
        kill(pid, SIGTERM);
        ret = kill(pid, SIGINT);
        if (ret == -1) {
            return;  // process is already dead
        }
        usleep(200000);
    }

    for (i = 0; i < 2; ++i) {
        ret = kill(pid, SIGKILL);
        if (ret == -1) {
            return;  // process is already dead
        }
        usleep(200000);
    }

    syslog(LOG_ERR, "Failed to kill process %d\n", pid);
}

static int drv_set_flags(const char * linkname, int set_or_clear, int flags)
{
    int sock, ret;
    struct ifreq    ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        return -1;
    }
    strcpy(ifr.ifr_name, linkname);
    ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    if (ret == -1) {
        goto out;
    }

    strcpy(ifr.ifr_name, linkname);
    if (set_or_clear) {
        ifr.ifr_flags |= flags;
    }
    else {
        ifr.ifr_flags &= ~flags;
    }
    ret = ioctl(sock, SIOCSIFFLAGS, &ifr);

out:
    close(sock);
    return ret;
}

int drv_up(const char * linkname)
{
    return drv_set_flags(linkname, 1, (IFF_UP | IFF_RUNNING));
}
int drv_down(const char * linkname)
{
    return drv_set_flags(linkname, 0, IFF_UP);
}

struct vlan_ioctl_args {
    int cmd; /* Should be one of the vlan_ioctl_cmds enum above. */
    char device1[24];

    union {
        char device2[24];
        int VID;
        unsigned int skb_priority;
        unsigned int name_type;
        unsigned int bind_type;
        unsigned int flag; /* Matches vlan_dev_info flags */
    } u;

    short vlan_qos;
};
enum vlan_ioctl_cmds {
    ADD_VLAN_CMD,
    DEL_VLAN_CMD,
    SET_VLAN_INGRESS_PRIORITY_CMD,
    SET_VLAN_EGRESS_PRIORITY_CMD,
    GET_VLAN_INGRESS_PRIORITY_CMD,
    GET_VLAN_EGRESS_PRIORITY_CMD,
    SET_VLAN_NAME_TYPE_CMD,
    SET_VLAN_FLAG_CMD
};
#define VLAN_GROUP_ARRAY_LEN 4096
#define SIOCSIFVLAN 0x8983      /* Set 802.1Q VLAN options */

int vlan_add(const char * basename, int vlanid)
{
    struct vlan_ioctl_args ifr;
    int sock, ret;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ret == -1) {
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));

    ifr.cmd = ADD_VLAN_CMD;
    strcpy(ifr.device1, basename);
    ifr.u.VID = vlanid;

    ret = ioctl(sock, SIOCSIFVLAN, &ifr);
    close(sock);

    return ret;
}
int vlan_rem(const char * vlanname)
{
    struct vlan_ioctl_args ifr;
    int sock, ret;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ret == -1) {
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));

    ifr.cmd = DEL_VLAN_CMD;
    strcpy(ifr.device1, vlanname);

    ret = ioctl(sock, SIOCSIFVLAN, &ifr);
    close(sock);

    return ret;
}

unsigned long util_uptime()
{
    struct sysinfo  info;

    sysinfo(&info);

    return info.uptime;
}

static const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char base64decode[255] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

// generated by original key:
// CommSkyResearchDepartmentAPGroupAuthorChenxiaojie-Mixed1374#18384@&#&$&NM)_~@}{.a/dadfuqpti
#define MAX_KEY_LENGTH  256
static const unsigned char rc4_key[MAX_KEY_LENGTH] = {
0x34, 0x3D, 0x3F, 0x3C, 0x3F, 0x3E, 0x3E, 0x3D,
0x3E, 0x3B, 0x34, 0x3D, 0x34, 0x3B, 0x34, 0x3C,
0x3E, 0x3F, 0x3B, 0x3F, 0x34, 0x3F, 0x34, 0x3B,
0x3C, 0x3E, 0x3E, 0x3B, 0x34, 0x3D, 0x3F, 0x3C,
0x3F, 0x3E, 0x34, 0x3C, 0x3B, 0x3B, 0x3B, 0x3E,
0x3B, 0x3B, 0x3D, 0x34, 0x3B, 0x3C, 0x34, 0x3B,
0x34, 0x34, 0x3F, 0x3B, 0x34, 0x3C, 0x34, 0x3F,
0x3F, 0x3F, 0x3E, 0x3B, 0x3D, 0x3F, 0x3C, 0x34,
0x3B, 0x3F, 0x3C, 0x3D, 0x3B, 0x3F, 0x3E, 0x34,
0x3D, 0x34, 0x3D, 0x3C, 0x3C, 0x3E, 0x34, 0x3E,
0x3B, 0x3C, 0x3C, 0x3D, 0x3C, 0x3B, 0x3B, 0x3C,
0x3C, 0x3E, 0x3E, 0x3E, 0x3F, 0x3D, 0x3E, 0x3C,
0x34, 0x3C, 0x34, 0x3F, 0x3F, 0x34, 0x3B, 0x3D,
0x3C, 0x3D, 0x34, 0x3B, 0x3D, 0x3E, 0x3C, 0x3C,
0x3C, 0x34, 0x34, 0x3D, 0x3F, 0x3C, 0x3D, 0x3C,
0x3E, 0x3E, 0x3E, 0x3C, 0x3B, 0x3E, 0x3C, 0x3D,
0x3F, 0x3E, 0x34, 0x3E, 0x3E, 0x3E, 0x3F, 0x3D,
0x34, 0x3E, 0x3E, 0x34, 0x3C, 0x3F, 0x3F, 0x3E,
0x34, 0x3F, 0x3D, 0x34, 0x3B, 0x3B, 0x3D, 0x34,
0x3B, 0x3E, 0x34, 0x3F, 0x3B, 0x3E, 0x3D, 0x34,
0x3B, 0x3D, 0x3F, 0x3C, 0x3B, 0x3D, 0x3C, 0x3E,
0x34, 0x3C, 0x3D, 0x3D, 0x3C, 0x3B, 0x34, 0x3E,
0x3F, 0x3B, 0x34, 0x3D, 0x34, 0x3F, 0x3C, 0x34,
0x3D, 0x3B, 0x3F, 0x3F, 0x3E, 0x3E, 0x3E, 0x34,
0x3F, 0x3F, 0x3C, 0x3F, 0x3D, 0x3B, 0x3D, 0x3B,
0x34, 0x3D, 0x3E, 0x3D, 0x3B, 0x3F, 0x3D, 0x3C,
0x3E, 0x3B, 0x3F, 0x3E, 0x3C, 0x34, 0x3B, 0x3B,
0x3F, 0x3E, 0x3C, 0x3B, 0x34, 0x3E, 0x3F, 0x3D,
0x3E, 0x3C, 0x3C, 0x3D, 0x3B, 0x34, 0x34, 0x3E,
0x3D, 0x3E, 0x3F, 0x3B, 0x3B, 0x3D, 0x3D, 0x3E,
0x3E, 0x3B, 0x3F, 0x3E, 0x3D, 0x3B, 0x3D, 0x3C,
0x3B, 0x34, 0x3B, 0x3E, 0x34, 0x3D, 0x3F, 0x3E,
};

int util_base64_encode(const unsigned char * in, int in_length, unsigned char * out)
{
    int i, j;
    unsigned char current;

    for ( i = 0, j = 0 ; i < in_length ; i += 3 )
    {
        current = (in[i] >> 2) ;
        current &= (unsigned char)0x3F;
        out[j++] = base64char[(int)current];

        current = ( (unsigned char)(in[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= in_length )
        {
            out[j++] = base64char[(int)current];
            out[j++] = '=';
            out[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(in[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        out[j++] = base64char[(int)current];

        current = ( (unsigned char)(in[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= in_length )
        {
            out[j++] = base64char[(int)current];
            out[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(in[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        out[j++] = base64char[(int)current];

        current = ( (unsigned char)in[i+2] ) & ( (unsigned char)0x3F ) ;
        out[j++] = base64char[(int)current];
    }
    out[j] = '\0';

    return j;
}


int util_base64_decode(const unsigned char * base64, unsigned char * bindata )
{
    int i, j;
    unsigned char temp[4];
    int should_end = 0;

    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        if (should_end) {
            return -1;
        }

        temp[0] = base64decode[base64[i]];
        temp[1] = base64decode[base64[i + 1]];
        temp[2] = base64decode[base64[i + 2]];
        temp[3] = base64decode[base64[i + 3]];

        if (temp[0] == -1 || temp[1] == -1) {
            return -1;
        }
        if (temp[2] == -1) {
            if (base64[i + 2] != '=') {
                return -1;
            }
            else if (base64[i + 3] != '=') {
                return -1;
            }
            should_end = 1;
        }
        if (temp[3] == -1) {
            if (base64[i + 3] != '=') {
                return -1;
            }
            should_end = 1;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
            ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
            ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
            ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

int util_password_encrypt(const char * in, char * out)
{
    int i;
    unsigned char rc4_bin[MAX_KEY_LENGTH];
    unsigned char   ch;
    unsigned char * p;

    i = 0;
    p = rc4_bin;
    while (1) {
        ch = (unsigned char)*in;
        if  (ch == 0) {
            *p = 0;
            break;
        }
        *p = ch ^ rc4_key[i];
        ++p;
        ++in;
        ++i;
        if (i > MAX_KEY_LENGTH) {
            return -1;
        }
    }

    return util_base64_encode(rc4_bin, i, out);
}

int util_password_decrypt(const char * in, char * out)
{
    int len, i;
    unsigned char rc4_bin[MAX_KEY_LENGTH * 2];
    unsigned char ch;
    unsigned char * p;

    len = util_base64_decode(in, rc4_bin);
    if (len > MAX_KEY_LENGTH || len < 0) {
        return -1;
    }

    p = rc4_bin;
    for (i = 0; i < len; ++i) {
        ch = *p ^ rc4_key[i];
        *out = ch;
        ++out;
        ++p;
    }
    *out = 0;

    return len;
}

// begin: add by chenxiaojie for bug 1462
int util_set_sysname(const char * devname, const char * name)
{
    int s;
    struct ifreq ifr;
    char    sysname[24];

    s = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, devname);
    ifr.ifr_data = sysname;
    strncpy(sysname, name, sizeof(sysname) - 1);

    ioctl(s, 0x890F, &ifr);

    close(s);

    return 0;
}
// end: add by chenxiaojie for bug 1462

int util_convert_mtd_name(const char * in_name, char * out)
{
    FILE * fp;
    char    line[256];
    int num, ret;
    char    dev[32], name[32];

    fp = fopen("/proc/mtd", "r");
    if (fp == NULL) {
        return -1;
    }

    ret = -1;
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        /* Format: dev:    size   erasesize  name */
        num = sscanf(line, "%s %*s %*s %s", dev, name);
        if (num == 2) {
            dev[strlen(dev) - 1] = 0;
            name[strlen(name) - 1] = 0;

            if (strcmp(in_name, name + 1) == 0) {
                sprintf(out, "/dev/%s", dev);
                ret = 0;
                break;
            }
        }
        else {
            continue;
        }
    }

    fclose(fp);

    return ret;
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
//return 0 if success, -1 if fail
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
//return 0 if success, -1 if fail
int util_str2net(char *str, unsigned int *ip, unsigned int *cidr)
{
        char *ptr = str;
        unsigned int oct = 0;

        while((*ptr) && (*ptr)!='/')
            ptr++;

        if ((*ptr) == '\0')
            return -1;

        *ptr++ = '\0';

        if (util_str2ip(str, ip) < 0)
            return -1;

        if ((*ptr) == '\0')
            return -1;
            
        while((*ptr) >= '0' && (*ptr) <= '9'){
            oct = oct*10 + (*ptr - '0');
            ptr++;
        }
        
        if ((*ptr) || oct>32){ /*if not terminator or maskbit>32,*/
            return -1;
        }

        if((*ip & ((1<<(32-oct)) - 1))) /*need ?*/
            return -1;
            
        *cidr = oct;
        return 0;
}


/*******************************************************************************
 Function name : util_upper
 Input         : 
 Output        : 
 Return        : 
 Author        : sxqiao
 Data          : 2015-08-27
 Description   : upper alphabet
*******************************************************************************/
int util_upper(char *pcString) 
{
    if (NULL == pcString) {
        return -1;
    }

    while(*pcString) {
        if (('a' <= *pcString) &&
            ('z' >= *pcString)) {
            *pcString &= ~0x20;
        }
        pcString++;
    }

    return 0;
}

/*******************************************************************************
 Function name : util_lower
 Input         : 
 Output        : 
 Return        : 
 Author        : sxqiao
 Data          : 2015-08-27
 Description   : low alphabet
*******************************************************************************/
int util_lower(char *pcString) 
{
    if (NULL == pcString) {
        return -1;
    }

    while(*pcString) {
        if (('A' <= *pcString) &&
            ('Z' >= *pcString)) {
            *pcString |= 0x20;
        }
        pcString++;
    }

    return 0;
}

int netmask_str2len(char* mask)
{
    int netmask = 0;
    unsigned int mask_tmp;

    mask_tmp = ntohl((int)inet_addr(mask));
    while (mask_tmp & 0x80000000)
    {
        netmask++;
        mask_tmp = (mask_tmp << 1);
    }

    return netmask;    
}

static char utilHexToDec(char HexDigit)
{
    if (('0' <= HexDigit) && (HexDigit <= '9'))
        return (HexDigit - '0');

    if (('a' <= HexDigit) && (HexDigit <= 'f'))
        return (HexDigit - 'a' + 10);

    if (('A' <= HexDigit) && (HexDigit <= 'F'))
        return (HexDigit - 'A' + 10);

    /* illegal digit */
    return -1;
}

int StrToMacAddr(char *pString, void *pMacAddr)
{
    short   hiDigit;
    short   loDigit;
    short   tempDigit;
    int     index;
    char    MacAddr[6];

    if ((NULL == pString) || ('\0' == *pString))
        return -1;

    if( 17 != strlen( pString ))
        return -1;

    for (index = 0; index < 6; index++)
    {
        hiDigit = utilHexToDec(*(pString++));

        if (('\0' != *pString) && (':' != *pString))
            loDigit = utilHexToDec(*(pString++));
        else
        {
            loDigit = hiDigit;
            hiDigit = 0;
        }
        
        if ((0 > hiDigit) || (0 > loDigit))
            return -1;

        tempDigit = (hiDigit << 4) + loDigit;
        if ((0 > tempDigit) || (tempDigit > 255))
            return -1;

        if ((index < 5) && (':' != *pString))
            return -1;

        pString++;

        MacAddr[index] = (char) tempDigit;
    }

/* endian conversion may be necessary here */
    memcpy(pMacAddr, MacAddr, 6);
    return 0;
}

