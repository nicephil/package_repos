#ifndef _CAPWAPC_SERVICES_H_
#define _CAPWAPC_SERVICES_H_



#define CAPWAPC_CFG_PACKAGE             "capwapc"

#define CAPWAPC_CFG_SECTION_GLOBAL         "global"
#define CAPWAPC_CFG_SECTION_SERVER         "server"
#define CAPWAPC_CFG_SECTION_WTP            "wtp"

#define CAPWAPC_CFG_OPTION_ENABLE     "enable"
#define CAPWAPC_CFG_OPTION_LOCATION    "location"
#define CAPWAPC_CFG_OPTION_LOCATION_TUPLE "capwapc.wtp.location"
#define CAPWAPC_CFG_OPTION_DOMAIN      "domain"
#define CAPWAPC_CFG_OPTION_DOMAIN_TUPLE "capwapc.wtp.domain"

#define CAPWAPC_CFG_OPTION_MASSER      "mas_server"
#define CAPWAPC_CFG_OPTION_MASSER_TUPLE "capwapc.server.mas_server"
#define CAPWAPC_CFG_OPTION_SLASER      "sla_server"
#define CAPWAPC_CFG_OPTION_SLASER_TUPLE "capwapc.server.sla_server"
#define CAPWAPC_CFG_OPTION_DEFSER      "def_server"
#define CAPWAPC_CFG_OPTION_CTRLPORT    "ctrl_port"
#define CAPWAPC_CFG_OPTION_CTRLPORT_TUPLE  "capwapc.wtp.ctrl_port"

#define CAPWAPC_CFG_OPTION_MTU	      "mtu"
#define CAPWAPC_CFG_OPTION_MTU_TUPLE "capwapc.wtp.mtu"
#define CAPWAPC_CFG_OPTION_DISCINTV    "disc_intv"
#define CAPWAPC_CFG_OPTION_MAXDISCINTV "maxdisc_intv"
#define CAPWAPC_CFG_OPTION_ECHOINTV    "echo_intv"
#define CAPWAPC_CFG_OPTION_ECHOINTV_TUPLE "capwapc.wtp.echo_intv"
#define CAPWAPC_CFG_OPTION_RETRANINTV  "retran_intv"
#define CAPWAPC_CFG_OPTION_SILENTINTV  "silent_intv"
#define CAPWAPC_CFG_OPTION_JOINTIMEOUT "join_timeout"
#define CAPWAPC_CFG_OPTION_MAXDISCES   "max_disces"
#define CAPWAPC_CFG_OPTION_MAXRETRANS  "max_retran"

#define CAPWAPC_DEFAULT_ENABLE        1
#define CAPWAPC_DEFAULT_SERVER        "redirector.oakridge.io"
#define CAPWAPC_DEFAULT_CTRLPORT      5246
#define CAPWAPC_DEFAULT_MTU           1300
#define CAPWAPC_DEFAULT_DISCINTV      5
#define CAPWAPC_DEFAULT_MAXDISCINTV   20
#define CAPWAPC_DEFAULT_ECHOINTV      30
#define CAPWAPC_DEFAULT_RETRANINTV    3
#define CAPWAPC_DEFAULT_SILENTINTV    30
#define CAPWAPC_DEFAULT_JIONTIMEOUT   60
#define CAPWAPC_DEFAULT_MAXDISCES     10
#define CAPWAPC_DEFAULT_MAXRETRAN     5

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



typedef struct capwapc_config {
    /* globale cfg */
    int enable;
    char domain[33];

    /* server cfg */
    char mas_server[65];    /* master server address: maybe ip or host name */
    char sla_server[65];    /* slaver server address: maybe ip or host name */
    char def_server[65];
    
    /* WTP cfg */
    int ctrl_port;
    int mtu;
    int disc_intv;
    int maxdisc_intv;
    int echo_intv;
    int retran_intv;
    int silent_intv;
    int join_timeout;
    int max_disces;
    int max_retran;
    char location[33];
} capwapc_config;




extern int capwapc_get_server_pri(char *server, int *server_pri);


extern int capwapc_get_defcfg(capwapc_config *defcfg);
extern int capwapc_get_curcfg(capwapc_config *curcfg);
extern int capwapc_set_echointv(int echointv);
extern int capwapc_set_mtu(int mtu);
extern int capwapc_set_slaveserver(const char *server);
extern int capwapc_undo_slaveserver(void);
extern int capwapc_set_masterserver(const char *server);
extern int capwapc_undo_masterserver(void);
extern int capwapc_set_ctrlport(int ctrlport);
extern int capwapc_set_location(const char *location);
extern int capwapc_undo_location(void);
extern int capwapc_set_domain(const char *domain);
extern int capwapc_set_domain(const char *domain);
extern int capwapc_undo_domain(void);
#endif    
