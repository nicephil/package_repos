#ifndef _CAPWAPC_SERVICES_H_
#define _CAPWAPC_SERVICES_H_
#if !OK_PATCH
#include "services/dialer_services.h"
#endif
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define CAPWAPC_LISTEN_ADDRESS    "/var/run/wtp"

typedef enum {
    CAPWAPC_STATE_DISABLE = 0,
    CAPWAPC_STATE_INIT,
    CAPWAPC_STATE_SULKING,
    CAPWAPC_STATE_DISCOVERY,
    CAPWAPC_STATE_JOIN,
    CAPWAPC_STATE_CONFIGURE,
    CAPWAPC_STATE_DATA_CHECK,
    CAPWAPC_STATE_RUN,
    CAPWAPC_STATE_RESET,
    CAPWAPC_STATE_RESTART_SILENTLY,
    CAPWAPC_STATE_STOP_SILENTLY,
    CAPWAPC_STATE_QUIT,
    CAPWAPC_STATE_MAX,
} capwapc_state_e;

#define CAPWAP_STATUS_NOTICE    (DHCP_OPTION43_RELEASE + 10)

/* following for the selection of the highest prioriy capwapc server */
/* low 4 bites for the master or slave server */
#define SET_STANDBY_PRI(pri, sp)  (pri |= (sp & 0x0F))
/* higher 4 bites for the priority of different discovery type */
#define SET_ABSOLUTE_PRI(pri, ap) (pri |= ((ap & 0x0F) << 4))
/* then higher 8 bites for the relative priority */
#define SET_RELATIVE_PRI(pri, rp) (pri |= ((rp & 0xFF) << 8))
/* zero relative priority mean it is the highest prioriy in current config  */
#define IS_HIGHEST_RELATIVEPRI(pri) (((pri >> 8) & 0xFF) == 0)
/* low value mean higher priority */
#define IS_HIGHER_PRI(pri, oldpri) ((pri & 0xFF) < (oldpri & 0xFF))

typedef enum {
    STATIC_NMS = 0,
    DHCP_NMS,
    BORADCAST_NMS,
    DEFAULT_NMS,
} capwapc_address_pri;

typedef enum {
    MASTER_ADDRESS = 0,
    SLAVE_ADDRESS,
} capwapc_static_address;
struct capwapc_status {
    char type;
    capwapc_state_e state;
    char server_name[32];
    char server_addr[16];
    long uptime;
};

typedef struct capwapc_config {
    /* globale cfg */
    int enable;
    char location[33];
    char domain[33];

    /* server cfg */
    char mas_server[65];    /* master server address: maybe ip or host name */
    char sla_server[65];    /* slaver server address: maybe ip or host name */
    char def_server[65];
    int ctrl_port;
    
    /* WTP cfg */
    int mtu;
    int disc_intv;
    int maxdisc_intv;
    int echo_intv;
    int retran_intv;
    int silent_intv;
    int join_timeout;
    int max_disces;
    int max_retran;
} capwapc_config;


extern int capwapc_enable(void);
extern int capwapc_disable(void);
extern int capwapc_set_location(const char *location);
extern int capwapc_undo_location(void);
extern int capwapc_set_domain(const char *domain);
extern int capwapc_undo_domain(void);
extern int capwapc_get_domain(char *domain, int len);
extern int capwapc_set_masterserver(const char *server);
extern int capwapc_undo_masterserver(void);
extern int capwapc_set_slaveserver(const char *server);
extern int capwapc_undo_slaveserver(void);
extern int capwapc_set_defaultserver(const char *server);
extern int capwapc_undo_defaultserver(void);
extern int capwapc_set_ctrlport(int ctrlport);
extern int capwapc_undo_ctrlport(void);
extern int capwapc_set_mtu(int mtu);
extern int capwapc_undo_mtu(void);
extern int capwapc_set_discintv(int discintv);
extern int capwapc_undo_discintv(void);
extern int capwapc_set_maxdiscintv(int max_discintv);
extern int capwapc_undo_maxdiscintv(void);
extern int capwapc_set_echointv(int echointv);
extern int capwapc_undo_echointv(void);
extern int capwapc_set_retranintv(int retranintv);
extern int capwapc_undo_retranintv(void);
extern int capwapc_set_silentintv(int silentintv);
extern int capwapc_undo_silentintv(void);
extern int capwapc_set_jointimeout(int jointimeout);
extern int capwapc_undo_jointimeout(void);
extern int capwapc_set_maxdisces(int maxdisces);
extern int capwapc_undo_maxdisces(void);
extern int capwapc_set_maxretran(int maxretran);
extern int capwapc_undo_maxretran(void);
extern int capwapc_set_forceexec(int force);
extern int capwapc_restart(void);
extern int capwapc_get_status(struct capwapc_status *status);

extern int capwapc_get_defcfg(capwapc_config *defcfg);
extern int capwapc_get_curcfg(capwapc_config *curcfg);

//add by puyg
extern int capwapc_decompile(int fd);
//extern int show_capwap_info(int fd);
extern int capwapc_get_server_pri(char *server, int *pri);
//end by puyg
#endif    
