#ifndef _IF_PUB_H_
#define _IF_PUB_H_

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#if 0
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#endif

/* some version may has no macro */
#ifndef ARPHRD_VOID
#define ARPHRD_VOID 0xFFFF
#endif

/*
 *  global configuration secion
 */
#ifndef CONFIG_ADDRESS_MAX_COUNT    // for each interface, not global
#define CONFIG_ADDRESS_MAX_COUNT    10
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ                    16
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif

#define SYS_INTF_NAME_SIZE          24
#define SYS_SERVICE_NAME_SIZE       32
#define SYS_INTF_DESC_SIZE          16

#define NETIFD_SERVICE_NAME         "$.intf.netifd"

#define NETIFD_EVENT_ADDRESS        "$.interface"
#define NETIFD_EVENT_ACK_ADDRESS    "$.interface.ack"

/*
 *  ifindex section
 */
typedef int     ifindex_t;
#define IF_INVALID_IFINDEX      (-2U)
#define IF_ALL_IFINDEX          (-1U)


#define WLANDRV_VERSION(a,b,c,d)    (((a) << 24) + ((b) << 16) + ((c) << 8) + (d))
/*
 *  interface attributes secion
 */

#define     MAJOR_SLOT(slot)        (((slot) >> 8) & 0xFF)
#define     MINOR_SLOT(slot)        ((slot) & 0xFF)

#define     MAKE_SLOT(major, minor) (((major) << 8) | minor)

enum if_phytype {
    IF_PHYTYPE_ETH = 1 << 0,     //  10/100MBits
    IF_PHYTYPE_GIGA_ETH = 1 << 1,    //  1000MBits
    IF_PHYTYPE_VLAN = 1 << 2,
    IF_PHYTYPE_WLAN = 1 << 3,
    IF_PHYTYPE_WLAN_BSS = 1 << 4,
#if 0
    IF_PHYTYPE_WLAN_REPEATER = 1 << 5,
    IF_PHYTYPE_WLAN_STATION = 1 << 6,
    IF_PHYTYPE_WLAN_IBSS = 1 << 7,
#endif
    IF_PHYTYPE_LOOPBACK = 1 << 5,
    IF_PHYTYPE_SERIAL = 1 << 6,
};
#define IF_PHYTYPE_MAX      7
#define IF_PHYTYPE_ALL      (-1UL)

#define WLAN_BSS_NAME_PREFIX        "WLAN-BSS"
#define WLAN_RADIO_NAME_PREFIX      "WLAN-Radio"
#define VLAN_INTERFACE_PREFIX       "Vlan-interface"
#define ETHERNET_NAME_PREFIX        "Ethernet"
#define GIGAETHERNET_NAME_PREFIX    "GigabitEthernet"

enum if_status {
    IF_STATUS_PRESENT = 1 << 0,
    IF_STATUS_ENABLED = 1 << 1,
    IF_STATUS_UP = 1 << 2,

    IF_STATUS_RUNON_LAYER_1 = 1 << 3,
    IF_STATUS_RUNON_LAYER_2 = 1 << 4,
    IF_STATUS_RUNON_LAYER_3 = 1 << 5,
};

/*
 *  IF_FEATURE_PHYSICAL: a physical interface, its status is got by driver
 *  IF_FEATURE_FOLLOW_BASED: for UP or DOWN status, followed its based
 */
enum if_features {
    IF_FEATURE_PHYSICAL = 1 << 0,
    IF_FEATURE_ALWAYS_UP = 1 << 1,
    IF_FEATURE_FOLLOW_BASED = 1 << 2,
    IF_FEATURE_ALWAYS_PRESENT = 1 << 3,
    IF_FEATURE_CONNECTE_TO_SWITCH = 1 << 4,

    IF_FEATURES_WORK_LAYER_1 = 1 << 5,
    IF_FEATURES_WORK_LAYER_2 = 1 << 6,
    IF_FEATURES_WORK_LAYER_3 = 1 << 7,
};

/*
 *  NOTICE:
 *      IF_EVENT_ADDR_ADD & IF_EVENT_ADDR_DEL
 *      is post by DIALER
 */

#define IF_EVENT_ALL    ((unsigned int)(-1))
enum if_event {
    IF_EVENT_PRESENT = 1 << 0,
    IF_EVENT_REMOVED = 1 << 1,
    IF_EVENT_ENABLED = 1 << 2,
    IF_EVENT_DISABLED = 1 << 3,
    IF_EVENT_UP = 1 << 4,
    IF_EVENT_DOWN = 1 << 5,

    IF_EVENT_ADDR_BEFORE_ADD = 1 << 6,
    IF_EVENT_ADDR_AFTER_ADD = 1 << 7,
    IF_EVENT_ADDR_BEFORE_DEL = 1 << 8,
    IF_EVENT_ADDR_AFTER_DEL = 1 << 9,

    IF_EVENT_CREATED = 1 << 10,
    IF_EVENT_DELETED = 1 << 11
};

#define if_dev_addr_equal(addr, addr2) \
    (((addr)->sa_family == (addr2)->sa_family) \
     && (memcmp((addr)->sa_data, (addr2)->sa_data, ETH_ALEN) == 0))

#define IF_DEV_MAC(addr)    ((addr)->sa_data)

/*
 *  Used by high-layer application
 */
struct if_attrs {
    unsigned char   slot;       // slot number
    unsigned char   interface;  // interface number
    unsigned char   addr_count;         // address count

    unsigned int    type;       // see enum if_phytype
    short int       mtu;
    short int       metric;
    ifindex_t       ifindex;
    ifindex_t       based;
    unsigned int    status;     // see enum if_status
    unsigned int    features;   // see enum if_features
    struct sockaddr dev_addr;
    char            name[SYS_INTF_NAME_SIZE];     // such as ETH0, longest format is SERIAL255/255/255
    char            linkname[IFNAMSIZ];
    char            netname[IFNAMSIZ];
    char            description[SYS_INTF_DESC_SIZE];
};

#ifndef uint64
#define uint64  unsigned long long
#endif
struct if_stats {
    uint64  tx_packets;
    uint64  rx_packets;
    uint64  tx_bytes;
    uint64  rx_bytes;
    uint64  tx_err_packets;
    uint64  rx_err_packets;
};
/*
 *  address attribute section
 */


#define IF_ADDRESS_GET_V4_IP(addr)  ((addr)->u.v4.ip)
#define IF_ADDRESS_GET_V4_NETMASK(addr)  ((addr)->u.v4.netmask)
#define IF_ADDRESS_SET_V4_IP(addr, _ip)  ((addr)->u.v4.ip = (_ip))
#define IF_ADDRESS_SET_V4_NETMASK(addr, _netmask)  ((addr)->u.v4.netmask = (_netmask))

#define IF_ADDRESS_GET_V6_IP(addr)  ((addr)->u.v6.ipv6_address)
#define IF_ADDRESS_GET_V6_NETMASK(addr)  ((addr)->u.v6.ipv6_prefix)
#define IF_ADDRESS_SET_V6_IP(addr, _ip)  memcpy((addr)->u.v6.ipv6_address, _ip, sizeof(addr->u.v6.ipv6_address)
#define IF_ADDRESS_SET_V6_NETMASK(addr, _netmask)  ((addr)->u.v6.ipv6_prefix = (_netmask))

struct if_address {
    unsigned int    version;
    union {
        struct {
            unsigned int    ip;         // in network bytes order
            unsigned int    netmask;
        }v4;

        struct {
            unsigned char   ipv6_address[16];
            unsigned int    ipv6_prefix;
        }v6;
    }u;
};

static inline int if_address_equal(struct if_address const * addr, struct if_address const * addr2)
{
    if (addr->version != addr2->version) {
        return 0;
    }
    if (addr->version == 4) {
        return (IF_ADDRESS_GET_V4_IP(addr) == IF_ADDRESS_GET_V4_IP(addr2))
            && (IF_ADDRESS_GET_V4_NETMASK(addr) == IF_ADDRESS_GET_V4_NETMASK(addr2));
    }
    else {
        return (IF_ADDRESS_GET_V6_NETMASK(addr) == IF_ADDRESS_GET_V6_NETMASK(addr2))
            && (memcmp(IF_ADDRESS_GET_V6_IP(addr), IF_ADDRESS_GET_V6_IP(addr2), sizeof(addr->u.v6.ipv6_address) == 0));
    }
}
#define IF_ADDRESS_EQUAL(_addr1, _addr2) if_address_equal(_addr1, _addr2)
/*
 *  helper function
 */
static inline int   if_is_present(unsigned int status)
{
    return (status & IF_STATUS_PRESENT) == IF_STATUS_PRESENT;
}
static inline int   if_is_enabled(unsigned int status)
{
    return (status & IF_STATUS_ENABLED) == IF_STATUS_ENABLED;
}
static inline int   if_is_up(unsigned int status)
{
    return (status & IF_STATUS_UP) == IF_STATUS_UP;
}
static inline int   if_is_runon_layer_2(unsigned int status)
{
    return (status & IF_STATUS_RUNON_LAYER_2) == IF_STATUS_RUNON_LAYER_2;
}
static inline int   if_is_runon_layer_3(unsigned int status)
{
    return (status & IF_STATUS_RUNON_LAYER_3) == IF_STATUS_RUNON_LAYER_3;
}

static inline int   if_is_work_on_layer_1(unsigned int features)
{
    return (features & IF_FEATURES_WORK_LAYER_1) == IF_FEATURES_WORK_LAYER_1;
}
static inline int   if_is_work_on_layer_2(unsigned int features)
{
    return (features & IF_FEATURES_WORK_LAYER_2) == IF_FEATURES_WORK_LAYER_2;
}
static inline int   if_is_work_on_layer_3(unsigned int features)
{
    return (features & IF_FEATURES_WORK_LAYER_3) == IF_FEATURES_WORK_LAYER_3;
}

static inline int   if_has_feature_physical(unsigned int features)
{
    return (features & IF_FEATURE_PHYSICAL) == IF_FEATURE_PHYSICAL;
}
static inline int   if_has_feature_always_up(unsigned int features)
{
    return (features & IF_FEATURE_ALWAYS_UP) == IF_FEATURE_ALWAYS_UP;
}
static inline int   if_has_feature_follow_based(unsigned int features)
{
    return (features & IF_FEATURE_FOLLOW_BASED) == IF_FEATURE_FOLLOW_BASED;
}
static inline int   if_has_feature_always_present(unsigned int features)
{
    return (features & IF_FEATURE_ALWAYS_PRESENT) == IF_FEATURE_ALWAYS_PRESENT;
}
static inline int   if_has_feature_connect_to_switch(unsigned int features)
{
    return (features & IF_FEATURE_CONNECTE_TO_SWITCH) == IF_FEATURE_CONNECTE_TO_SWITCH;
}
static inline int   if_is_addr_event(unsigned int event)
{
    return event & (IF_EVENT_ADDR_BEFORE_ADD | IF_EVENT_ADDR_AFTER_ADD | IF_EVENT_ADDR_BEFORE_DEL | IF_EVENT_ADDR_AFTER_DEL);
}
/*
 *  API function
 */

/*
 * EVENT_SEQ_AFTER (a, b) returns TRUE if the seq a is after seq b
 */
#define EVENT_SEQ_AFTER(a, b)\
    ((int)(b) - (int)(a) < 0)
#define EVENT_SEQ_BEFORE(a, b)  EVENT_SEQ_AFTER(b, a)

#define EVENT_SEQ_AFTER_EQ(a, b)\
    ((int)(a) - (int)(b) >= 0)
#define EVENT_SEQ_BEFORE_EQ(a, b)   EVENT_SEQ_AFTER_EQ(b, a)

extern int if_get_attrs(ifindex_t ifindex, struct if_attrs * attrs, struct if_address ** addrs);
extern int if_get_attrs_by_name(const char * name, struct if_attrs * attrs, struct if_address ** addrs);
extern int if_get_attrs_by_netname(const char * netname, struct if_attrs * attrs, struct if_address ** addrs);
extern int if_get_attrs_by_linkname(const char * linkname, struct if_attrs * attrs, struct if_address ** addrs);

/*
 * return value:
 *  1   exited
 *  0   not exited
 */
static inline int if_is_name_exist(const char * name)
{
    int     ret;
    struct if_attrs attrs;

    ret = if_get_attrs_by_name(name, &attrs, NULL);
    if (ret == 0) {
        return 1;
    }
    return 0;
}

extern int if_dev_addr_build_from_mac(struct sockaddr * addr, const char * mac);

extern int if_form_name(unsigned int slot, unsigned int interface,
        unsigned int type, char * name);
extern unsigned int if_parse_type_by_name(const char * name);

static inline int if_is_layer2(unsigned int type)
{
    if (type == IF_PHYTYPE_ETH || type == IF_PHYTYPE_GIGA_ETH ||
            type == IF_PHYTYPE_WLAN_BSS) {
        return 1;
    }
    return 0;
}

static inline int if_is_layer3(unsigned int type)
{
    if (type == IF_PHYTYPE_VLAN) {
        return 1;
    }
    return 0;
}

/*
 *  if @based is not NULL, it's a sub-interface of @based and has following features:
 *  1.when @based received DELETED,REMOVED,DISABLED event, all of its sub-interfaces will auto received one copy
 *  2.when @based received ENABLED event, all of sub's will auto received one copy ONLY IF they are enabled by admin
 *  3.when @based is DISABLED, all of sub's CAN NOT BE ENABLED
 *  4.when @based is PRESENT, NOW nothing happen(more if_features may be add to support)
 */
extern int if_create_interface(unsigned short slot, unsigned short interface,
        unsigned int type, unsigned int features,
        const char * based, const char * linkname,
        struct if_attrs * attrs);
extern int if_destroy(ifindex_t ifindex);

/*
 *  DEMO
 *  int count = 0, addr_count = 0;
 *  unsigned int seq = 0;
 *  struct if_attrs * attrs = NULL;
 *  struct if_address * addrs = NULL;
 *  int i, j;   // loop counter
 *  int ret;
 *
 *  ret = if_get_interfaces(mask_you_want, &count, &attrs, &addrs, &seq);
 *  if (ret) {
 *      // error handle code here
 *  }
 *  if (count == 0) {
 *      // no any result
 *  }
 *  // Now, process the expected result here
 *  for (i = 0; i < count; ++i) {
 *      // access all attributes except address
 *      for (j = 0; j < attrs[i].addr_count; ++j) {
 *          // access addrs[addr_count].address
 *          ++addr_count;
 *      }
 *  }
 *
 *  if (addrs) {
 *      free(addrs);
 *  }
 *  if (attrs) {
 *      free(attrs);
 *  }
 */
extern int if_get_interfaces(unsigned int phytype_mask, int *count,
        struct if_attrs ** attrs, struct if_address **addrs, unsigned int * seq);
/*
 * @acker is combine of bit mask same as event
 */
extern int if_register_event(unsigned int event_mask,
        unsigned int phytype_mask,
        const char * id, int event_acker, int phytype_acker);
extern int if_open_listener(void);
extern int if_deligate_process_event(int fd,
        int (*handler)(ifindex_t, unsigned int, struct if_attrs*,
            struct if_address *, void * arg));
extern int if_deligate_process_event_ex(int fd,
        int (*handler)(ifindex_t, unsigned int, struct if_attrs*,
            struct if_address *, void * arg),
        int (*notifier)(int, int, void *));

extern int if_enable(ifindex_t ifindex);
extern int if_disable(ifindex_t ifindex);
extern int if_add_addr(ifindex_t ifindex, struct if_address * addr, struct if_address * peer_addr);
extern int if_del_addr(ifindex_t ifindex, struct if_address * addr, int ack);
extern int if_set_netname(ifindex_t ifindex, char * name);
extern const char * if_event_name(unsigned int event);
extern int if_up(ifindex_t ifindex);
extern int if_down(ifindex_t ifindex);
extern int if_present(ifindex_t ifindex, const char * linkname);
extern int if_remove(ifindex_t ifindex, int clear);
/*
 *  @ifindex is depends on @depend
 */
extern int if_depend(ifindex_t ifindex, ifindex_t depend);

extern const char * if_dump_attrs(struct if_attrs const * attrs);
extern const char * if_dump_address(int count, struct if_address const * address);

static inline void if_output_address(struct if_address const * address, char * ip, char * netmask, socklen_t size)
{
    if (address->version == 4) {
        struct in_addr in;

        in.s_addr = IF_ADDRESS_GET_V4_IP(address);
        inet_ntop(AF_INET, &in, ip, size);

        in.s_addr = IF_ADDRESS_GET_V4_NETMASK(address);
        inet_ntop(AF_INET, &in, netmask, size);
    }
    else {
        struct in6_addr in6;

        memcpy(in6.s6_addr, IF_ADDRESS_GET_V6_IP(address), sizeof(in6.s6_addr));
        inet_ntop(AF_INET6, &in6, ip, size);
        sprintf(netmask, "%d", IF_ADDRESS_GET_V6_NETMASK(address));
    }
}

enum if_message_type {
    IF_MESSAGE_TYPE_GETATTRS = 0,   // get all attr
    IF_MESSAGE_TYPE_REGISTER,       // register hook
    IF_MESSAGE_TYPE_UNREGISTER,
    IF_MESSAGE_TYPE_CREATE,
    IF_MESSAGE_TYPE_DELETE,
    IF_MESSAGE_TYPE_ENABLE,
    IF_MESSAGE_TYPE_DISABLE,

    IF_MESSAGE_TYPE_ACK,

    IF_MESSAGE_ADD_ADDR,
    IF_MESSAGE_DEL_ADDR,
    IF_MESSAGE_SET_NETNAME,
    IF_MESSAGE_PRESENT,
    IF_MESSAGE_REMOVED,

    IF_MESSAGE_GET_INTERFACES,
    IF_MESSAGE_UP,
    IF_MESSAGE_DOWN,

    IF_MESSAGE_DEPEND,

    IF_MESSAGE_TYPE_MAX
};

enum if_response_status {
    IF_RESPONSE_STATUS_OK = 0,
    IF_RESPONSE_STATUS_INVALID_REQUEST_TYPE,
    IF_RESPONSE_STATUS_INVALID_PARAMTER_ERROR,
    IF_RESPONSE_STATUS_NO_SUCH_IFINDEX,
    IF_RESPONSE_STATUS_REQUEST_FORBIDDEN,
    IF_RESPONSE_STATUS_GENERAL_ERROR,

    IF_RESPONSE_STATUS_MAX
};
struct if_message_header {
    int     type;
    pid_t   pid;
    char    id[SYS_SERVICE_NAME_SIZE];
};

struct if_response_header {
    int status;
    unsigned int    seq;
};

struct if_request_general {
    struct if_message_header    header;
    ifindex_t                   ifindex;
};

struct if_request_addr {
    struct if_message_header    header;
    ifindex_t                   ifindex;
    int                         ack;
    struct if_address           address;
	struct if_address           peer_address;
};

struct if_request_get_attr {
    struct if_message_header    header;
    int bytype;
    union {
        ifindex_t   ifindex;
        char    name[SYS_INTF_NAME_SIZE];
    } u;
};

struct if_response_get_attr {
    struct if_response_header   header;
    struct if_attrs             attrs;
    struct if_address           addrs[0];
};

struct if_request_register {
    struct if_message_header    header;
    ifindex_t       ifindex;
    unsigned int    event;
    unsigned int    phytype;
    int     priority;
    int     event_acker;
    int     phytype_acker;
    char    service_name[SYS_SERVICE_NAME_SIZE];
};
#if 0
struct if_response_register {
    struct if_response_header   header;
    ifindex_t                   ifindex;
};
#endif

struct if_request_unregister {
    struct if_message_header    header;
    ifindex_t       ifindex;
    char    service_name[SYS_SERVICE_NAME_SIZE];
};

struct if_request_set_netname {
    struct if_message_header    header;
    ifindex_t ifindex;
    char    netname[IFNAMSIZ];
};

struct if_request_create {
    struct if_message_header    header;
    unsigned short  slot;
    unsigned short  interface;
    unsigned int    type;
    unsigned int    features;
    char            based[SYS_INTF_NAME_SIZE];
    char            linkname[IFNAMSIZ];
};

struct if_response_create {
    struct if_response_header   header;
//    ifindex_t   ifindex;
    //char        name[SYS_INTF_NAME_SIZE];
    struct if_attrs attrs;
};

enum if_notify_message {
    IF_NOTIFY_EVENT_CHANGED = 0,
    IF_NOTIFY_MTU_CHANGED,
    IF_NOTIFY_METRIC_CHANGED,
    IF_NOTIFY_DEVADDR_CHANGED,
    IF_NOTIFY_LINKMODE_CHANGED,

    IF_NOTIFY_MAX
};

/*
 * NOTICE:
 *  ALL notify struct MUST have first three member same order
 */
struct if_mtu_notify {
    int             message;    // must be first
    unsigned int    seq;
    ifindex_t       ifindex;

    short int       mtu;
};
struct if_metric_notify {
    int             message;    // must be first
    unsigned int    seq;
    ifindex_t       ifindex;

    short int       metric;
};
struct if_devaddr_notify {
    int             message;    // must be first
    unsigned int    seq;
    ifindex_t       ifindex;

    struct sockaddr devaddr;
};

enum IF_LINKMODE {
    IF_LINKMODE_BRIDGE = 0,
    IF_LINKMODE_ROUTE,

    IF_LINKMODE_MAX
};

struct if_linkmode_notify {
    int             message;    // must be first
    unsigned int    seq;
    ifindex_t       ifindex;

    struct if_attrs attrs;
    unsigned int    linkmode;       // refer to @enum IF_LINKMODE
};

/*
 *  for all IF_EVENT_*,
 */
struct if_event_notify {
    int             message;    // must be first
    unsigned int    seq;
    ifindex_t       ifindex;

    unsigned int    event;
    char            id[SYS_SERVICE_NAME_SIZE];
    struct if_attrs attrs;
    struct if_address address[0];   //
    /*
     *  for IF_EVENT_ADDR* family, extra_arg is point to the changing address, otherwise, extra_arg is NULL
     *  char    extra_arg[0];
     */
};

struct if_ack_event_notify {
    struct if_message_header    header;
    unsigned int    seq;
    int             result;     // ignore now,  < 0 means error
};

struct if_request_present {
    struct if_message_header    header;
    ifindex_t       ifindex;
    int             set;        // 1 for set linkname
    char            linkname[IFNAMSIZ];
};

struct if_request_removed {
    struct if_message_header    header;
    ifindex_t       ifindex;
    int             clear;      // 1 for clear linkname
};

struct if_request_depend {
    struct if_message_header    header;
    ifindex_t       ifindex;
    ifindex_t       depend;
};

struct if_request_get_interfaces {
    struct if_message_header    header;
    unsigned int    phytype_mask;
    int             get_addr;
};

struct if_response_get_interfaces {
    struct if_response_header   header;
    int     count;
    char    data[0];
};

#ifndef __u64
#define __u64   uint64_t
#endif
struct netifd_link_stats {
    __u64   rx_packets;     /* total packets received   */
    __u64   tx_packets;     /* total packets transmitted    */
    __u64   rx_bytes;       /* total bytes received     */
    __u64   tx_bytes;       /* total bytes transmitted  */
    __u64   rx_errors;      /* bad packets received     */
    __u64   tx_errors;      /* packet transmit problems */
    __u64   rx_dropped;     /* no space in linux buffers    */
    __u64   tx_dropped;     /* no space available in linux  */
    __u64 rx_multicast_packets;       /* multicast packets received   */
    __u64 tx_multicast_packets;       /* multicast packets received   */
    __u64 rx_broadcast_packets;       /* broadcast packets received   */
    __u64 tx_broadcast_packets;       /* broadcast packets received   */

    __u64 rx_multicast_bytes;     /* multicast bytes received */
    __u64 tx_multicast_bytes;     /* multicast bytes received */
    __u64 rx_broadcast_bytes;     /* broadcast bytes received */
    __u64 tx_broadcast_bytes;     /* broadcast bytes received */

    __u64   collisions;

    /* detailed rx_errors: */
    __u64   rx_length_errors;
    __u64   rx_over_errors;     /* receiver ring buff overflow  */
    __u64   rx_crc_errors;      /* recved pkt with crc error    */
    __u64   rx_frame_errors;    /* recv'd frame alignment error */
    __u64   rx_fifo_errors;     /* recv'r fifo overrun      */
    __u64   rx_missed_errors;   /* receiver missed packet   */

    __u64 l3_rx_unicast;      /* unicast packets received */
    __u64 l3_tx_unicast;      /* unicast packets received */
    __u64 l3_rx_multicast;        /* multicast packets received   */
    __u64 l3_tx_multicast;        /* multicast packets received   */
    __u64 l3_rx_broadcast;        /* broadcast packets received   */
    __u64 l3_tx_broadcast;        /* broadcast packets received   */
    __u64 l3_rx_unicast_bytes;        /* unicast bytes received   */
    __u64 l3_tx_unicast_bytes;        /* unicast bytes received   */
    __u64 l3_rx_multicast_bytes;      /* multicast bytes received */
    __u64 l3_tx_multicast_bytes;      /* multicast bytes received */
    __u64 l3_rx_broadcast_bytes;      /* broadcast bytes received */
    __u64 l3_tx_broadcast_bytes;      /* broadcast bytes received */

    /* detailed tx_errors */
    __u64   tx_aborted_errors;
    __u64   tx_carrier_errors;
    __u64   tx_fifo_errors;
    __u64   tx_heartbeat_errors;
    __u64   tx_window_errors;

    /* for cslip etc */
    __u64   rx_compressed;
    __u64   tx_compressed;
};

struct netifd_abbr_link_stats {
    __u64   rx_packets;     /* total packets received   */
    __u64   tx_packets;     /* total packets transmitted    */
    __u64   rx_bytes;       /* total bytes received     */
    __u64   tx_bytes;       /* total bytes transmitted  */
};

#endif /* _IF_PUB_H_ */
