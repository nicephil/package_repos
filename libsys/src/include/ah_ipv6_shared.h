#ifndef _AH_IPV6_SHARED_H_
#define _AH_IPV6_SHARED_H_

#ifdef __KERNEL__
#include "linux/in.h"
#include "linux/in6.h"
#else
#include "netinet/in.h"
#endif
#include "ah_types.h"


/* The following are already defined in:
   kernel/linux-2.6.32/include/net/ipv6.h, but not available in
   user space toolchain */

#if !defined(__KERNEL__)
#define IPV6_ADDR_ANY       0x0000U

#define IPV6_ADDR_UNICAST       0x0001U
#define IPV6_ADDR_MULTICAST     0x0002U

#define IPV6_ADDR_LOOPBACK  0x0010U
#define IPV6_ADDR_LINKLOCAL 0x0020U
#define IPV6_ADDR_SITELOCAL 0x0040U

#define IPV6_ADDR_COMPATv4  0x0080U

#define IPV6_ADDR_SCOPE_MASK    0x00f0U

#define IPV6_ADDR_MAPPED    0x1000U
#define IPV6_ADDR_RESERVED  0x2000U /* reserved address space */

#endif  /* #if !defined(__KERNEL__) */



#define IPV6_ADDR_NO_GLOBAL_ADDR 1
#define IPV6_ADDR_NO_LINK_LOCAL_ADDR 2

#define MAX_IPV6_SCOPE_STR_LEN   10

#define IPV6_MIN_MTU    1280
#define IPV6_LINK_LOCAL_ADDR_PREFIX_LEN  64


/* ifa_flags */     /* copied from kernel */
#define IFA_F_SECONDARY     0x01
#define IFA_F_TEMPORARY     IFA_F_SECONDARY

#define IFA_F_NODAD     0x02
#define IFA_F_OPTIMISTIC    0x04
#define IFA_F_DADFAILED     0x08
#define IFA_F_HOMEADDRESS   0x10
#define IFA_F_DEPRECATED    0x20
#define IFA_F_TENTATIVE     0x40
#define IFA_F_PERMANENT     0x80


#define AH_IFINET6_PATH "/proc/net/if_inet6"
#define MAX_NUM_IF_ADDRS6           10

#define AH_MAX_NUM_STA_ADDRS6       5
#define AH_MGT0_GLOBAL_ADDR6_NUM_MAX 1
#define AH_MGT0_LOCAL_ADDR6_NUM_MAX  1
#define AH_MGT0_ADDR6_NUM_MAX  (AH_MGT0_GLOBAL_ADDR6_NUM_MAX + AH_MGT0_LOCAL_ADDR6_NUM_MAX)
/***************************
 *
 * !!! Note that, the internal IPv4 or IPv6 address is stored in network order.
 *
 ***************************/
typedef struct ah_ipaddr46_ {
	int af; /* AF_INET / AF_INET6 */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
		uint8_t bytes[16];
	} u;

#define u_ipv4        u.v4.s_addr
#define u_ipv4_addr   u.v4
#define u_ipv6_addr   u.v6

} ah_ipaddr46_t;

typedef struct ah_ipaddr_mask46_ {
	ah_ipaddr46_t ipaddr46;
	uint32_t      mask_len;
} ah_ipaddr_mask46_t;

typedef struct ah_if_ipv6_addr_ {
	struct in6_addr ipv6_addr;
	int idx;
	/* TODO: use macro IF_NAMESIZE, which file to include? */
	char ifname[16];
	int pfxlen;
	int scope;
	int flags;
} ah_if_ipv6_addr_t;

typedef struct ah_if_all_ipv6_addrs_ {
	int num_addrs;
	ah_if_ipv6_addr_t addrs[MAX_NUM_IF_ADDRS6];
} ah_if_all_ipv6_addrs_t;


/*********************************************************
 *
 * APIs manipulating "ah_ipaddr46_t", "ah_ipaddr_mask46_t"
 *
 * Note that, confirm to OOP flavor, all APIs are named with "XXX_ipaddr46_XXX", and all future APIs should be named so.
 *
 *********************************************************/

/*************************
 *
 *  init "ah_ipaddr46_t" from existing address or string.
 *
 *************************/
void ah_set_ipaddr46_ipv4_all_zero(ah_ipaddr46_t *ip46);
void ah_set_ipaddr46_ipv4(ah_ipaddr46_t *ip46, int addr4);  //addr4 should be network order
void ah_set_ipaddr46_ipv4_in_addr(ah_ipaddr46_t *ip46, struct in_addr *addr4);
int ah_set_ipaddr46_addr_ipv4_str(ah_ipaddr46_t *ip46, const char *addr4_str);

void ah_set_ipaddr46_ipv6_all_zero(ah_ipaddr46_t *ip46);
void ah_set_ipaddr46_ipv6(ah_ipaddr46_t *ip46, struct in6_addr *addr6);
int ah_set_ipaddr46_ipv6_str(ah_ipaddr46_t *ip46, const char *addr6_str);


void ah_set_ipaddr46_invalid(ah_ipaddr46_t *ip46);  /* back to uninitialized INVALID state. */

void ah_set_ipaddr46_all_zero(ah_ipaddr46_t *ip46); /* I don't like this API, but have to, because other people like it
                                                    * Maybe because the name "all_zero" is more familiar and friendly.
                                                    *
                                                    * Note that, ah_set_ipaddr46_all_zero() would be return TRUE after this API call.
                                                    */


/*************************
 *  address family check
 *************************/
int ah_is_ipaddr46_ipv4(ah_ipaddr46_t *ip46);
int ah_is_ipaddr46_ipv6(ah_ipaddr46_t *ip46);

int ah_is_ipaddr46_invalid(ah_ipaddr46_t
						   *ip46);    /* # check if "ah_ipaddr46_t" not initialized at all ( haven't call those set APIs above yet). */
int ah_is_ipaddr46_unspec(ah_ipaddr46_t *ip46);     /* same as is_invalid */


/*************************
 *  string conversion & check
 *************************/
int ah_is_valid_ipaddr46_str(const char *addr_str);
int ah_str_to_ipaddr46(ah_ipaddr46_t *ip46, const char *addr_str);


/*************************
 * get address in "ah_ipaddr46_t"
 *
 * if address family not match, then return error code.
 *
 *************************/
int ah_get_ipaddr46_ipv4(ah_ipaddr46_t *ip46, int *addr4);
int ah_get_ipaddr46_ipv4_in_addr(ah_ipaddr46_t *ip46, struct in_addr *addr4);
int ah_get_ipaddr46_ipv6(ah_ipaddr46_t *ip46, struct in6_addr *addr6);


/*************************
 * misc check
 *************************/
int ah_is_ipaddr46_all_zero(ah_ipaddr46_t *ip46);   /* # if IPv4, 0.0.0.0, if IPv6, :: */
int ah_is_ipaddr46_multicast(ah_ipaddr46_t *ip46);  /* # internally check either IPv4 either IPv6 multicast. */

/*************************
 * copy
 *************************/
void ah_copy_ipaddr46(ah_ipaddr46_t *dst, ah_ipaddr46_t *src);


/*************************
 * comparison
 *************************/

int ah_cmp_ipaddr46(ah_ipaddr46_t *addr1, ah_ipaddr46_t *addr2);
int ah_is_ipaddr46_equal(ah_ipaddr46_t *addr1, ah_ipaddr46_t *addr2);
/*
 * compare with address family check
 *
 * if address family not same, then consider as not equal and a error, and "err_af" output argument is set to TRUE, so caller must also check "err_af".
 */
int ah_is_ipaddr46_equal_with_af(ah_ipaddr46_t *addr1, ah_ipaddr46_t *addr2, int *err_af);
int ah_cmp_ipaddr46_with_af(ah_ipaddr46_t *addr1, ah_ipaddr46_t *addr2, int *err_af);


/*************************
 * host <-> network order transform.
 *
 *  Note that,
 *
 *      the HiveOS convention is that, we store any IPv4 (IPv6) address in network order.
 *
 *      by default the internal IPv4 or IPv6 address of "ah_ipaddr46_t" is stored in network order, by those set_XXX() APIs.
 *
 *
 * These 2 API is not to transform internal address network order, but you still need to use them,
 * because "ah_ipaddr46_t->af" need to transform for network tranversal.
 *
 *************************/
void hton_ipaddr46(ah_ipaddr46_t *addr46);
void ntoh_ipaddr46(ah_ipaddr46_t *addr46);


/*********************************************************
 *
 * APIs manipulating "ah_ipaddr46_t", "ah_ipaddr_mask46_t" --- end
 *
 *********************************************************/



/*
 * Since rtnetlink is more prefered in ipv6, there are not as many IOCTL in ipv6 as in ipv4.
 *
 * In current HOS code, IOCTL dominate, and most of us are still used to IOCTL instead of rtnetlink.
 *
 * So we try to port some functionaliy from rtnetlink to IOCTL, to ease HOS user-level delopement.
 *
 * @@update - 2014.04.18
 *
 *      This go beyond simply porting rtnetlink function to IOCTL, but would contain many other functions
 *      exported to user-level to reference.
 *
 *
 * IOCTL comand:
 *
 *      SIOCGIFADDR = reuse it as AH_IN6_IFREQ      # native ipv6 IOCTL not use it
 *
 *
 * "sub_cmd"
 *
 */
struct ah_in6_ifreq {
	int ifindex;

	int sub_cmd;

	union {
		/* AH_IN6_IFREQ_SUB_CMD_GETIFADDR - ifname is not used inside, user-level must specify a buffer */
		ah_if_all_ipv6_addrs_t *__addrs;

		/* AH_IN6_IFREQ_SUB_CMD_GLOBAL_AUTCONF  - not extra cmd */
	} u;
};

#define AH_IN6_IFREQ    SIOCGIFADDR     /* see "ah_in6_ifreq" for reason */

#define AH_IN6_IFREQ_SUB_CMD_GETIFADDR  1 /* get address (global unicast & link local ) configured on a interface */
#define AH_IN6_IFREQ_SUB_CMD_GLOBAL_AUTCONF  2 /* (re)kick global unicast autoconf on a interface, if permitted */
#define AH_IN6_IFREQ_SUB_CMD_FLUSH_ROUTE_AUTO   3   /* flush any "autoconf route" on a interface, previously configured with RTF_ADDRCONF */

static inline int ah_is_ipv6_linklocal(const struct in6_addr *addr)
{
	return ((addr->s6_addr32[0] & htonl(0xFFC00000)) == htonl(0xFE800000));
}

extern char *
ah_ipv6_scope_str(char *scope_buf, int scope);

/**
 * @brief compute a hash value in the range [0, 15) for a given IPv6 address. duplicated from kernel native ipv6_addr_hash()
 * @param[in] addr IPv6 address
 * @return the hash value in the range [0, 15)
 * @@note !! the hash value returned is in the range [0, 15), so it is ONLY suitable for small hash table -- see the usage of kernel native ipv6_addr_hash().
 *          If you have a big hash table, you should NOT directly use this hash value, Otherwise, would cause much hash collision. 
 *          But instead, you should take this hash value as one factor of computing more appropriate hashvalue suitable 
 *          for your big hash table.
 */
static inline uint8_t ah_ipv6_addr_hash(const struct in6_addr *addr)
{
	uint32_t word;

	/*
	 * We perform the hash function over the last 64 bits of the address
	 * This will include the IEEE address token on links that support it.
	 */

	word = (uint32_t)(addr->s6_addr32[2] ^ addr->s6_addr32[3]);
	word ^= (word >> 16);
	word ^= (word >> 8);

	return ((word ^ (word >> 4)) & 0x0f);
}

static inline ah_ipaddr46_t ipv46_zero(void)
{
	ah_ipaddr46_t ret;

	ret.af = AF_INET;
	ret.u_ipv4 = 0;

	return ret;
}

#define IPV6_PREFIX_LEN_MIN 0
#define IPV6_PREFIX_LEN_MAX 128

static inline int ah_ipv6_is_valid_prefix_len(int prefix_len)
{
	/* I assume nobody would use 0 as prefix */
	return (prefix_len >= IPV6_PREFIX_LEN_MIN) && (prefix_len <= IPV6_PREFIX_LEN_MAX);
}

#endif /* _AH_IPV6_SHARED_H_ */

