#include "log/log.h"
#include "if/if_pub.h"
#include "kbus/kbus.h"
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>

#undef zlog
//#define zlog(...)
#define zlog    syslog

static char g_id[SYS_SERVICE_NAME_SIZE];

static int if_request(void * req, int req_len, kbus_message_t  **rsp)
{
    kbus_ksock_t    fd;
    int ret;
    int retry;
    kbus_message_t * msg;
    kbus_msg_id_t   id;
    fd_set      readset;
    struct timeval  tv = {2, 0};
    struct if_message_header * header = (struct if_message_header *)req;

    header->pid = getpid();

    fd = kbus_ksock_open(0, O_RDWR);
    if (fd < 0) {
        zlog(LOG_DEBUG, "Open kbus failed: %s\n", strerror(errno));
        return -1;
    }

    strcpy(((struct if_message_header *)req)->id, g_id);

    ret = kbus_msg_create_request(&msg, NETIFD_SERVICE_NAME, sizeof(NETIFD_SERVICE_NAME) - 1, req, req_len, 0);
    if (ret < 0) {
        zlog(LOG_DEBUG, "Create kbus message failed: %s\n", strerror(errno));
        kbus_ksock_close(fd);
        return -1;
    }

    ret = kbus_ksock_send_msg(fd, msg, &id);
    if (ret < 0) {
        zlog(LOG_DEBUG, "Send kbus message failed: %s\n", strerror(errno));
        kbus_msg_delete(&msg);
        kbus_ksock_close(fd);
        return -1;
    }
    retry = 3;

    kbus_msg_delete(&msg);

again:
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    ret = select(fd + 1, &readset, NULL, NULL, &tv);
    if (ret == -1) {
        if (errno == EINTR) {
            --retry;
            if (retry) {
                goto again;
            }
            else {  // too much signal, aborted
                zlog(LOG_DEBUG, "Request got too much signal!\n");
                kbus_ksock_close(fd);
                return -1;
            }
        }
    }
    else if (ret == 0) {
        zlog(LOG_DEBUG, "Wait response timeout!\n");
        kbus_ksock_close(fd);
        return -1;
    }

    ret = kbus_ksock_read_next_msg(fd, rsp);
    kbus_ksock_close(fd);
    if (ret == 0) {
        //        zlog(LOG_DEBUG, "Read response OK!\n");
        return 0;
    }

    zlog(LOG_DEBUG, "Read response failed: %s\n", strerror(errno));
    return -1;
}

static int process_get_attrs(struct if_request_get_attr * req,
        struct if_attrs * attrs, struct if_address ** addrs)
{
    kbus_message_t * msg;
    int     ret, size;
    struct if_response_get_attr * rsp;

    ret = if_request(req, sizeof(*req), &msg);
    if (ret) {
        return -1;
    }

    /* Check minimum size */
    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);

    /* Check response status */
    if (rsp->header.status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        if (IF_RESPONSE_STATUS_NO_SUCH_IFINDEX != rsp->header.status) {
            zlog(LOG_DEBUG, "Get response with error status: %d\n",
                    rsp->header.status);
        }
        return -1;
    }

    /* Check total size */
    size = sizeof(*rsp) + sizeof(struct if_address) * rsp->attrs.addr_count;
    if (msg->data_len < size) {
//        zlog(LOG_DEBUG, "Want %d bytes but got %d\n", size,
//                msg->data_len);
        kbus_msg_delete(&msg);
        return -1;
    }
    memcpy(attrs, &rsp->attrs, sizeof(*attrs));

    if (addrs != NULL && rsp->attrs.addr_count != 0) {
        size -= sizeof(*rsp);
        *addrs = (typeof(*addrs))malloc(size);
        if (*addrs == NULL) {
            zlog(LOG_DEBUG, "Failed to alloc %d bytes\n", size);
            kbus_msg_delete(&msg);
            return -1;
        }
        memcpy(*addrs, &rsp->addrs[0], size);
    }
    kbus_msg_delete(&msg);

//    zlog(LOG_DEBUG, "Get attrs OK!\n");
    return 0;
}

int if_get_attrs(ifindex_t ifindex, struct if_attrs * attrs, struct if_address** addrs)
{
    struct if_request_get_attr  req;

//    zlog(LOG_DEBUG, "Begin to get attrs %d\n", ifindex);
    req.header.type = IF_MESSAGE_TYPE_GETATTRS;
    req.bytype = 0;
    req.u.ifindex = ifindex;

    return process_get_attrs(&req, attrs, addrs);
}

int if_get_attrs_by_name(const char * name, struct if_attrs * attrs, struct if_address ** addrs)
{
    struct if_request_get_attr  req;

//    zlog(LOG_DEBUG, "Begin to get attrs by name: %s\n", name);
    req.header.type = IF_MESSAGE_TYPE_GETATTRS;
    req.bytype = 1;
    strncpy(req.u.name, name, sizeof(req.u.name) - 1);
    req.u.name[sizeof(req.u.name) - 1] = 0;

    return process_get_attrs(&req, attrs, addrs);
}

int if_create_interface(unsigned short slot, unsigned short interface,
        unsigned int type, unsigned int features,
        const char * based, const char * linkname,
        struct if_attrs * attrs)
{
    struct if_request_create    req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_create * rsp;

    zlog(LOG_DEBUG, "Begin to create interface\n");
    req.header.type = IF_MESSAGE_TYPE_CREATE;
    req.slot = slot;
    req.interface = interface;
    req.type = type;
    req.features = features;
    if (based) {
        strncpy(req.based, based, sizeof(req.based) - 1);
    }
    else {
        req.based[0] = 0;
    }
    if (linkname) {
        strncpy(req.linkname, linkname, sizeof(req.linkname) - 1);
    }
    else {
        req.linkname[0] = 0;
    }

    ret = if_request(&req, sizeof(req), &msg);

    //kbus_msg_dump(msg , 1);
    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->header.status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response create interface with error status: %d\n",
                rsp->header.status);
        return -1;
    }
//    *ifindex = rsp->ifindex;
    memcpy(attrs, &rsp->attrs, sizeof(rsp->attrs));
//    strcpy(name, rsp->name);
    kbus_msg_delete(&msg);

    zlog(LOG_DEBUG, "Create interface %s(ifindex %d) OK!\n",
            rsp->attrs.name, rsp->attrs.ifindex);
    return 0;
}

int if_destroy(ifindex_t ifindex)
{
    struct if_request_general   req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to destroy interface\n");
    req.header.type = IF_MESSAGE_TYPE_DELETE;
    req.ifindex = ifindex;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response delete interface with error status: %d\n",
                rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Delete interface OK!\n");
    return 0;
}

struct event_handler {
    unsigned int    event;
    unsigned int    phytype;
    const char *    id;
    int     event_acker;
    int     phytype_acker;
};

static struct event_handler * evt_handler;
int if_register_event(unsigned int event_mask, unsigned int phytype_mask,
        const char * id, int event_acker, int phytype_acker)
{
    struct if_request_register  req;
    int len, ret;
    kbus_message_t * msg;
    struct if_response_header * rsp;

    if (strlen(id) >= SYS_SERVICE_NAME_SIZE) {
        zlog(LOG_DEBUG, "ID is too large\n");
        return -1;
    }
    strcpy(g_id, id);
    zlog(LOG_DEBUG, "Begin to register event\n");
    if (evt_handler != NULL) {
        zlog(LOG_DEBUG, "Not support register multiple times yet, please concat YOUR LEADER~\n");
        return -1;
    }

    len = strlen(id);
    if (len >= SYS_SERVICE_NAME_SIZE) {
        zlog(LOG_DEBUG, "ID is too long: %d (%d limit)\n", len, SYS_SERVICE_NAME_SIZE);
        return -1;
    }
    evt_handler = (typeof(evt_handler))malloc(sizeof(*evt_handler));
    if (evt_handler == NULL) {
        return -1;
    }

    req.header.type = IF_MESSAGE_TYPE_REGISTER;
    req.ifindex = IF_ALL_IFINDEX;
    req.event = event_mask;
    req.phytype = phytype_mask;
    req.priority = 0;
    req.event_acker = event_acker;
    req.phytype_acker = phytype_acker;
    strcpy(req.service_name, id);

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        free(evt_handler);
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        free(evt_handler);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Register id %s with error status: %d\n", id,
                rsp->status);
        free(evt_handler);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Register id %s OK!\n", id);

    evt_handler->event = event_mask;
    evt_handler->phytype = phytype_mask;
    evt_handler->id = id;
    evt_handler->event_acker = event_acker;
    evt_handler->phytype_acker = phytype_acker;

    return 0;
}

int if_open_listener(void)
{
    int fd, ret;

    fd = kbus_ksock_open(0, O_RDWR);
    if (fd < 0) {
        zlog(LOG_DEBUG, "Open kbus failed: %s\n", strerror(errno));
        return -1;
    }

    ret = kbus_ksock_bind(fd, NETIFD_EVENT_ADDRESS, 0);
    if (ret < 0) {
        zlog(LOG_DEBUG, "Bind interface listen address failed: %s\n",
                strerror(errno));
        kbus_ksock_close(fd);
        return -1;
    }

    return fd;
}

int if_deligate_process_event_ex(int fd,
        int (*handler)(ifindex_t, unsigned int, struct if_attrs*,
            struct if_address *, void * arg),
        int (*notifier)(int, int, void *))
{
    /*
     * TODO:
     *  To support multiple register,
     *  Get list of struct event_handler by lookup event
     */
    struct event_handler * event_handler = evt_handler;
    int ret;
    kbus_message_t  * msg;
    struct if_event_notify * notify;
    void * arg;
    int acker = 0;
    int addr_count, arg_len;
    struct if_attrs * attrs;
    struct if_address * address;
    int * message;

    ret = kbus_ksock_read_next_msg(fd, &msg);
    if (ret < 0) {
        zlog(LOG_DEBUG, "Read next message failed!\n");
        return -1;
    }

    if (msg->data_len < sizeof(*message)) {
        zlog(LOG_DEBUG, "Message is too short: %d\n", msg->data_len);
        ret = -1;
        goto out;
    }
    message = (typeof(message))kbus_msg_data_ptr(msg);
    if (*message != IF_NOTIFY_EVENT_CHANGED) {
        if (*message >= IF_NOTIFY_MAX) {
            goto out;
        }
        if (notifier) {
            notifier(*message, msg->data_len, kbus_msg_data_ptr(msg));
        }
//        zlog(LOG_DEBUG, "Not interface event: %d, ignore...\n", *message);
        goto out;
    }
    if (msg->data_len < sizeof(*notify)) {
        zlog(LOG_DEBUG, "Message is too short: %d\n", msg->data_len);
        ret = -1;
        goto out;
    }
    notify = (typeof(notify))kbus_msg_data_ptr(msg);
    attrs = &notify->attrs;
    addr_count = attrs->addr_count;

    if (strcmp(notify->id, g_id) == 0) {
        zlog(LOG_DEBUG, "Discard interface %s event %s(0x%x) sent by self: %s\n", attrs->name, if_event_name(notify->event), notify->event, g_id);
        goto out;
    }
    /* filter out un-attention message */
    if (event_handler) {
        if ((notify->event & event_handler->event) == 0) {
            goto out;
        }
        if ((notify->attrs.type & event_handler->phytype) == 0) {
            goto out;
        }
    }

    arg_len = msg->data_len - sizeof(*notify) - addr_count * sizeof(struct if_address);
    if (arg_len < 0) {
        zlog(LOG_DEBUG, "Message is too short: %d\n", msg->data_len);
        ret = -1;
        goto out;
    }
    address = (typeof(address))(notify + 1);
    if (arg_len == 0) {
        arg = NULL;
    }
    else {
        arg = (notify + 1) + addr_count * sizeof(struct if_address);
    }

    ret = handler(notify->ifindex, notify->event,
            attrs, address, arg);

    if (event_handler) {
        acker = (event_handler->event_acker & notify->event)
            && (event_handler->phytype_acker & notify->attrs.type);
    }

    if (acker) {
        struct if_ack_event_notify  ack;
        kbus_msg_id_t   id;
        kbus_message_t  * rsp;

        ack.header.type = IF_MESSAGE_TYPE_ACK;
        ack.header.pid = getpid();
        strcpy(ack.header.id, g_id);
        ack.seq = notify->seq;
        ack.result = ret;
#if 1
        ret = kbus_msg_create(&rsp, NETIFD_EVENT_ACK_ADDRESS, sizeof(NETIFD_EVENT_ACK_ADDRESS) - 1, &ack, sizeof(ack), 0);
#else
        ret = kbus_msg_create(&rsp, "$.abc", sizeof("$.abc") - 1, &ack, sizeof(ack), 0);
#endif
        if (ret == 0) {
            ret = kbus_ksock_send_msg(fd, rsp, &id);
            if (ret) {
                zlog(LOG_DEBUG, "Failed to send ack message!\n");
            }
            else {
                zlog(LOG_DEBUG, "OK to send ack message!\n");
            }
            kbus_msg_delete(&rsp);
        }
        else {
            zlog(LOG_DEBUG, "Failed to create ack message!\n");
        }
    }
out:
    kbus_msg_delete(&msg);
    return ret;
}

int if_deligate_process_event(int fd,
        int (*handler)(ifindex_t, unsigned int, struct if_attrs*,
            struct if_address *, void * arg))
{
    return if_deligate_process_event_ex(fd, handler, NULL);
}

int if_enable(ifindex_t ifindex)
{
    struct if_request_general   req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to enable interface\n");
    req.header.type = IF_MESSAGE_TYPE_ENABLE;
    req.ifindex = ifindex;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response enable interface %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Enable interface %d OK!\n", ifindex);
    return 0;

}

int if_disable(ifindex_t ifindex)
{
    struct if_request_general   req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to disable interface\n");
    req.header.type = IF_MESSAGE_TYPE_DISABLE;
    req.ifindex = ifindex;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response disable interface %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Disable interface %d OK!\n", ifindex);
    return 0;
}

int if_add_addr(ifindex_t ifindex, struct if_address * addr, struct if_address * peer_addr)
{
    struct if_request_addr  req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to add address\n");
    req.header.type = IF_MESSAGE_ADD_ADDR;
    req.ifindex = ifindex;
    req.ack = 0;
    memcpy(&req.address, addr, sizeof(*addr));

    if (peer_addr) {
        memcpy(&req.peer_address, peer_addr, sizeof(*peer_addr));
    }
    else {
        memset(&req.peer_address, 0, sizeof(*peer_addr));
    }
    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response add address with error status: %d\n",
                rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Add address OK!\n");
    return 0;
}
int if_del_addr(ifindex_t ifindex, struct if_address * addr, int ack)
{
    struct if_request_addr  req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to del addr");
    req.header.type = IF_MESSAGE_DEL_ADDR;
    req.ifindex = ifindex;
    req.ack = ack;
    memcpy(&req.address, addr, sizeof(*addr));

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response del address with error status: %d\n",
                rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Del address OK!\n");
    return 0;
}

int if_set_netname(ifindex_t ifindex, char * name)
{
    struct if_request_set_netname  req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to set netname\n");
    req.header.type = IF_MESSAGE_SET_NETNAME;
    req.ifindex = ifindex;
    strncpy(req.netname, name, sizeof(req.netname) - 1);
    req.netname[sizeof(req.netname) - 1] = 0;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response set %d netname %s with error status: %d\n",
                ifindex, name, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Set %d netname %s OK!\n", ifindex, name);
    return 0;
}

static int find_lsb(unsigned int value)
{
    int lsb = 0;

again:
    value >>= 1;
    if (value) {
        ++lsb;
        goto again;
    }

    return lsb;
}

const char * event_names[] = {
    "PRESENT",
    "REMOVED",
    "ENABLED",
    "DISABLED",
    "PHY UP",
    "PHY DOWN",
    "ADDRESS BEFORE ADD",
    "ADDRESS AFTER ADD",
    "ADDRESS BEFORE DEL",
    "ADDRESS AFTER DEL",
    "CREATED",
    "DELETED"
};
const char * if_event_name(unsigned int event)
{
    event = find_lsb(event);
    if (event >= ARRAY_SIZE(event_names)) {
        return "UNKNOWN";
    }

    return event_names[event];
}
int if_present(ifindex_t ifindex, const char * linkname)
{
    struct if_request_present   req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to send present \n");
    req.header.type = IF_MESSAGE_PRESENT;
    req.ifindex = ifindex;
    if (linkname) {
        req.set = 1;
        strncpy(req.linkname, linkname, sizeof(req.linkname) - 1);
        req.linkname[sizeof(req.linkname) - 1] = 0;
    }
    else {
        req.set = 0;
    }

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response present %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Present %d with linkname: %s OK!\n", ifindex, linkname ? linkname : "NOT SET");
    return 0;
}

int if_remove(ifindex_t ifindex, int clear)
{
    struct if_request_removed req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to send removed \n");
    req.header.type = IF_MESSAGE_REMOVED;
    req.ifindex = ifindex;
    req.clear = clear;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response present %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Remove %d with linkname: %s OK!\n", ifindex, clear ? "cleared" : "not cleared");
    return 0;
}
int if_up(ifindex_t ifindex)
{
    struct if_request_general   req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to up interface\n");
    req.header.type = IF_MESSAGE_UP;
    req.ifindex = ifindex;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response up interface %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Phyup interface %d OK!\n", ifindex);
    return 0;
}
int if_down(ifindex_t ifindex)
{
    struct if_request_general   req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to down interface\n");
    req.header.type = IF_MESSAGE_DOWN;
    req.ifindex = ifindex;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response down interface %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Phydown interface %d OK!\n", ifindex);
    return 0;
}

int if_get_interfaces(unsigned int phytype_mask, int *count,
        struct if_attrs ** attrs, struct if_address **addrs, unsigned int * seq)
{
    struct if_request_get_interfaces req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_get_interfaces * rsp;
    int     addr_count, i, j;
    struct if_attrs *   attr;
    struct if_address * addr, *to;
    char *  p;

//   zlog(LOG_DEBUG, "Begin to get interface\n");
    if (count == NULL || attrs == NULL) {
        return -1;
    }
    req.header.type = IF_MESSAGE_GET_INTERFACES;
    req.phytype_mask = phytype_mask;
    if (addrs == NULL) {
        req.get_addr = 0;
    }
    else {
        req.get_addr = 1;
    }

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->header.status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response get interface with error status: %d\n",
                rsp->header.status);
        return -1;
    }
    *count = rsp->count;
    if (rsp->count == 0) {
        *attrs = NULL;
        if (addrs) {
            *addrs = NULL;
        }
        goto out;
    }
    if (msg->data_len < rsp->count * sizeof(struct if_attrs) + sizeof(*rsp)) {
        zlog(LOG_DEBUG, "Want at least %d bytes but got %d\n",
                sizeof(*rsp) + rsp->count * sizeof(struct if_attrs), msg->data_len);
        kbus_msg_delete(&msg);
        return -1;
    }

    *attrs = (struct if_attrs *)malloc(sizeof(struct if_attrs) * rsp->count);
    if (*attrs == NULL) {
        zlog(LOG_DEBUG, "get interface alloc %d bytes failed!\n",
                sizeof(**attrs) * rsp->count);
        kbus_msg_delete(&msg);
        return -1;
    }
    if (addrs) {
        // now addr_count is total size of address(in bytes, not counter)
        addr_count = (msg->data_len - sizeof(*rsp) -
                sizeof(struct if_attrs) * rsp->count);
        if (addr_count) {
            *addrs = (struct if_address *)malloc(addr_count);
            if (*addrs == NULL) {
                free(*attrs);
                zlog(LOG_DEBUG, "get interface alloc %d bytes failed!\n",
                        addr_count);
                kbus_msg_delete(&msg);
                return -1;
            }
            to = *addrs;
            addr_count /= sizeof(struct if_address);
        }
        else {
            *addrs = NULL;
        }
    }
    p = rsp->data;
    for (i = 0; i < rsp->count; ++i) {
        attr = (struct if_attrs *)p;
        memcpy(&((*attrs)[i]), attr, sizeof(*attr));
        p += sizeof(*attr);
        if (addrs && attr->addr_count) {
            addr = (struct if_address *)p;
            for (j = 0; j < attr->addr_count; ++j) {
                --addr_count;
                if (addr_count < 0) {
                    zlog(LOG_DEBUG, "Error response data\n");
                    free(*addrs);
                    free(*attrs);
                    kbus_msg_delete(&msg);
                    return -1;
                }
                memcpy(to, addr, sizeof(*addr));
                ++addr;
                ++to;
            }
            p = (char *)addr;
        }
    }

out:
    if (seq) {
        *seq = rsp->header.seq;
    }
    kbus_msg_delete(&msg);
//    zlog(LOG_DEBUG, "get interface OK!\n");
    return 0;
}

int if_depend(ifindex_t ifindex, ifindex_t depend)
{
    struct if_request_depend req;
    kbus_message_t * msg;
    int     ret;
    struct if_response_header * rsp;

    zlog(LOG_DEBUG, "Begin to depend interface\n");
    req.header.type = IF_MESSAGE_DEPEND;
    req.ifindex = ifindex;
    req.depend = depend;

    ret = if_request(&req, sizeof(req), &msg);

    if (ret) {
        return -1;
    }

    if (msg->data_len < sizeof(*rsp)) {
        kbus_msg_delete(&msg);
        return -1;
    }
    rsp = (typeof(rsp))kbus_msg_data_ptr(msg);
    if (rsp->status != IF_RESPONSE_STATUS_OK) {
        kbus_msg_delete(&msg);
        zlog(LOG_DEBUG, "Response up interface %d with error status: %d\n",
                ifindex, rsp->status);
        return -1;
    }
    kbus_msg_delete(&msg);
    zlog(LOG_DEBUG, "Depend interface %d OK!\n", ifindex);
    return 0;
}
static char g_dump_buffer[1024];
const char * if_dump_attrs(struct if_attrs const * attrs)
{
    char * p = g_dump_buffer;

    *p = 0;
    p += sprintf(p, "Interface %s\n", attrs->name);
    p += sprintf(p, "Attributes\n");
    p += sprintf(p, "slot: %u \tinterface: %u\n", attrs->slot, attrs->interface);
    p += sprintf(p, "mtu: %hd \tmetric: %hd\n", attrs->mtu, attrs->metric);
    p += sprintf(p, "mac: %02X:%02X:%02X:%02X:%02X:%02X ", attrs->dev_addr.sa_data[0], attrs->dev_addr.sa_data[1], attrs->dev_addr.sa_data[2],
            attrs->dev_addr.sa_data[3], attrs->dev_addr.sa_data[4], attrs->dev_addr.sa_data[5]);
    p += sprintf(p, "linkname: %s \tnetname: %s ", attrs->linkname, attrs->netname);
    p += sprintf(p, "type: %u \tfeatures: %u(", attrs->type, attrs->features);
    if (attrs->features & IF_FEATURE_PHYSICAL) {
        p += sprintf(p, " %s", "physical");
    }
    if (attrs->features & IF_FEATURE_ALWAYS_UP) {
        p += sprintf(p, " %s", "always up");
    }
    if (attrs->features & IF_FEATURE_FOLLOW_BASED) {
        p += sprintf(p, " %s", "follow based");
    }
    if (attrs->features & IF_FEATURE_CONNECTE_TO_SWITCH) {
        p += sprintf(p, " %s", "switch port");
    }
    p += sprintf(p, " )\n");
    p += sprintf(p, "ifindex: %d \tbased: %d\n", attrs->ifindex,
            attrs->based);
    p += sprintf(p, "linkname: %s \tnetname: %s\n", attrs->linkname, attrs->netname);
    p += sprintf(p, "status: %u %s %s %s\n", attrs->status,
            attrs->status & IF_STATUS_PRESENT ? "PRESENT" : "REMOVED",
            attrs->status & IF_STATUS_ENABLED ? "ENABLED" : "DISABLED",
            attrs->status & IF_STATUS_UP ? "UP" : "DOWN");
    p += sprintf(p, "address count: %u\n", attrs->addr_count);

    return g_dump_buffer;
}
const char * if_dump_address(int count, struct if_address const * address)
{
    int i;
    char * p = g_dump_buffer;
    char    ip[INET6_ADDRSTRLEN + 1], netmask[INET6_ADDRSTRLEN + 1];

    *p = 0;
    for (i = 0; i < count; ++i) {
        if_output_address(address, ip, netmask, sizeof(ip));
        p += sprintf(p, "IP: %s/%s", ip, netmask);
    }

    return g_dump_buffer;
}

int if_dev_addr_build_from_mac(struct sockaddr * addr, const char * mac)
{
    char * ptr = &addr->sa_data[0];
    int i, j;
    unsigned char val, c;

    i = 0;
    do {
        j = val = 0;
        if (i && (*mac == ':')) {
            mac++;
        }

        do {
            c = *mac;
            if (((unsigned char)(c - '0')) <= 9) {
                c -= '0';
            }
            else if (((unsigned char)((c|0x20) - 'a')) <= 5) {
                c = (c|0x20) - ('a'-10);
            }
            else if (j && (c == ':' || c == 0)) {
                break;
            }
            else {
                return -1;
            }
            ++mac;
            val <<= 4;
            val += c;
        } while (++j < 2);
        *ptr++ = val;
    } while (++i < ETH_ALEN);

    addr->sa_family = ARPHRD_ETHER;
    return 0;
}

struct name_prefix {
    const char * name;
    unsigned short length;
    unsigned short physical;
};

#define NAME_PREFIX_ITEM(_name, phy) {_name, sizeof(_name) - 1, phy}
static struct name_prefix name_prefixs[IF_PHYTYPE_MAX] = {
    NAME_PREFIX_ITEM(ETHERNET_NAME_PREFIX, 1),
    NAME_PREFIX_ITEM(GIGAETHERNET_NAME_PREFIX, 1),
    NAME_PREFIX_ITEM(VLAN_INTERFACE_PREFIX, 0),
    NAME_PREFIX_ITEM(WLAN_RADIO_NAME_PREFIX, 1),
    NAME_PREFIX_ITEM(WLAN_BSS_NAME_PREFIX, 0),
#if 0
    NAME_PREFIX_ITEM("WLAN_REP", 0),
    NAME_PREFIX_ITEM("WLAN_STA", 0),
    NAME_PREFIX_ITEM("WLAN_IBSS", 0),
#endif
    NAME_PREFIX_ITEM("Loopback", 0),
    NAME_PREFIX_ITEM("Serial", 1),
};
unsigned int if_parse_type_by_name(const char * name)
{
    int i, len = -1, ret = -1;
    for (i = 0; i < ARRAY_SIZE(name_prefixs); ++i) {
        if (strncmp(name, name_prefixs[i].name, name_prefixs[i].length) == 0) {
            if (name_prefixs[i].length > len) {
                len = name_prefixs[i].length;
                ret = (1 << i);
            }
        }
    }
    return ret;
}

int if_form_name(unsigned int slot, unsigned int interface,
        unsigned int type, char * name)
{
    unsigned int lsb = find_lsb(type);
    if (name == NULL || lsb >= IF_PHYTYPE_MAX) {
        return -1;
    }
    if (!name_prefixs[lsb].physical) {
        sprintf(name, "%s%u", name_prefixs[lsb].name, interface);
        return 0;
    }
    sprintf(name, "%s%u/%u", name_prefixs[lsb].name, slot, interface);
    return 0;
}
int if_get_attrs_by_netname(const char * netname, struct if_attrs * attrs, struct if_address ** addrs)
{
    struct if_request_get_attr  req;

//    zlog(LOG_DEBUG, "Begin to get attrs by netname: %s\n", netname);
    req.header.type = IF_MESSAGE_TYPE_GETATTRS;
    req.bytype = 2;
    strncpy(req.u.name, netname, sizeof(req.u.name) - 1);
    req.u.name[sizeof(req.u.name) - 1] = 0;

    return process_get_attrs(&req, attrs, addrs);
}
int if_get_attrs_by_linkname(const char * linkname, struct if_attrs * attrs, struct if_address ** addrs)
{
    struct if_request_get_attr  req;

//    zlog(LOG_DEBUG, "Begin to get attrs by linkname: %s\n", linkname);
    req.header.type = IF_MESSAGE_TYPE_GETATTRS;
    req.bytype = 3;
    strncpy(req.u.name, linkname, sizeof(req.u.name) - 1);
    req.u.name[sizeof(req.u.name) - 1] = 0;

    return process_get_attrs(&req, attrs, addrs);
}
