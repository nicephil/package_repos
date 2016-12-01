#ifndef _UTIL_H_
#define _UTIL_H_

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

extern unsigned int util_APHash(const char * str);

extern int util_file_lock(int fd);
extern int util_file_unlock(int fd);
extern pid_t util_wait_pidfile(const char * file);
extern pid_t util_try_pidfile(const char * file);
extern int util_output_pidfile(const char * file);
extern void kill_pid_safe(pid_t pid);
extern pid_t util_load_pidfile(const char * file);

extern unsigned long util_uptime();

extern int drv_up(const char * linkname);
extern int drv_down(const char * linkname);

extern int vlan_add(const char * basename, int vlanid);
extern int vlan_rem(const char * vlanname);

extern int util_upper(char *pcString); 
extern int util_lower(char *pcString); 

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif

static inline int is_netmask_valid(unsigned int netmask)  // in host order
{
    if (netmask) {
        unsigned int    y = ~netmask;
        unsigned int    z = y + 1;

        return (z & y) == 0;

    }
    return 0;
}

// NOTICE: these function must pass a network-order param
static inline int ipv4_is_loopback(unsigned int addr)
{
    return (addr & htonl(0xff000000)) == htonl(0x7f000000);
}

static inline int ipv4_is_multicast(unsigned int addr)
{
    return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

static inline int ipv4_is_local_multicast(unsigned int addr)
{
    return (addr & htonl(0xffffff00)) == htonl(0xe0000000);
}

static inline int ipv4_is_lbcast(unsigned int addr)
{
    /* limited broadcast */
    return addr == htonl(INADDR_BROADCAST);
}

static inline int ipv4_is_zeronet(unsigned int addr)
{
    return (addr & htonl(0xff000000)) == htonl(0x00000000);
}

/* Special-Use IPv4 Addresses (RFC3330) */

static inline int ipv4_is_private_10(unsigned int addr)
{
    return (addr & htonl(0xff000000)) == htonl(0x0a000000);
}

static inline int ipv4_is_private_172(unsigned int addr)
{
    return (addr & htonl(0xfff00000)) == htonl(0xac100000);
}

static inline int ipv4_is_private_192(unsigned int addr)
{
    return (addr & htonl(0xffff0000)) == htonl(0xc0a80000);
}

static inline int ipv4_is_linklocal_169(unsigned int addr)
{
    return (addr & htonl(0xffff0000)) == htonl(0xa9fe0000);
}

static inline int ipv4_is_anycast_6to4(unsigned int addr)
{
    return (addr & htonl(0xffffff00)) == htonl(0xc0586300);
}

static inline int ipv4_is_test_192(unsigned int addr)
{
    return (addr & htonl(0xffffff00)) == htonl(0xc0000200);
}

static inline int ipv4_is_test_198(unsigned int addr)
{
    return (addr & htonl(0xfffe0000)) == htonl(0xc6120000);
}

#define SERVICE_PID_FILE_PATH   "/var/run/services"

static inline pid_t service_load_pidfile(const char * id)
{
    char    buf[128];

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    return util_load_pidfile(buf);
}
static inline pid_t service_wait_pidfile(const char * id)
{
    char    buf[128];

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    return util_wait_pidfile(buf);
}
static inline int service_output_pidfile(const char * id)
{
    char    buf[128];

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    return util_output_pidfile(buf);
}
static inline int service_try_pidfile(const char * id)
{
    char    buf[128];

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    return util_try_pidfile(buf);
}
static inline void service_unlink_pidfile(const char * id)
{
    char    buf[128];

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    unlink(buf);
}
static inline void service_once_complete(const char * id)
{
    char    buf[128];
    int     fd;

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    fd = open(buf, O_RDWR | O_CREAT | O_EXCL, 0666);
    close(fd);
}
static inline int service_once_check_completed(const char * id)
{
    char    buf[128];
    int     ret;

    sprintf(buf, "%s/%s.pid", SERVICE_PID_FILE_PATH, id);
    ret = access(buf, R_OK);
    return ret == 0;
}
static inline void util_set_bit(unsigned int * addr, int bit)
{
    (*addr) |= (1 << bit);
}
static inline void util_clear_bit(unsigned int * addr, int bit)
{
    (*addr) &= ~(1 << bit);
}
static inline int util_is_bit_set(unsigned int * addr, int bit)
{
    return (*addr) & (1 << bit);
}

/* 
 * return value:
 *  < 0: error, may be @in is too long
 */
extern int util_password_encrypt(const char * in, char * out);

/*
 * return value:
 * < 0 : error
 * > 0 : OK, and return strlen(out)
 */
extern int util_password_decrypt(const char * in, char * out);

/*
 * return value: 
 *  strlen(@out)
 */
extern int util_base64_encode(const unsigned char * in, int in_length, unsigned char * out);

/*
 * return value:
 * < 0 : error
 * > 0 : OK, and return strlen(out)
 */
extern int util_base64_decode(const unsigned char * base64, unsigned char * bindata);

extern int util_set_sysname(const char * devname, const char * name);

extern int util_str2ip(char *ipstr, unsigned int *ipaddr);

extern int util_str2net(char *str, unsigned int *ip, unsigned int *cidr);
/*
 * return value:
 *  0: convert OK
 *  convert a given @in_name(such as "config") to 
 *  actually dev name (such as /dev/mtdXXX) stored in @out
 */
extern int util_convert_mtd_name(const char * in_name, char * out);

extern int if_ether_ntoa(const unsigned char *addr, char *txt); 
extern int if_ether_aton(const char *txt, unsigned char *addr);
extern int is_null_macaddr(unsigned char *mac);

extern int netmask_str2len(char* mask);
extern int StrToMacAddr(char *pString, void *pMacAddr);

#endif /* _UTIL_H_ */
