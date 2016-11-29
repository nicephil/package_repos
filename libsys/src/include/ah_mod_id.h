#ifndef __AH_MODULE_ID_H__
#define __AH_MODULE_ID_H__

/*
 * user process module ID table
 * pls update the mid2name(...) as well when add new mid
 */
#define AH_MOD_ID_ALL  0xff /* only used by cli, should be remove from here */
typedef enum {
	AH_MOD_ID_MIN  = 1,   /* eventlib take mid=0 as for dbg, should apply that to all lib */
	AH_MOD_ID_AMRP = AH_MOD_ID_MIN,
	AH_MOD_ID_FED,        /* FE daemon mpi mode id */
	AH_MOD_ID_DCD,        /* DCD daemon mpi module id */
	AH_MOD_ID_CAPWAP,     /* CAPWAP daemon mpi module id */
	AH_MOD_ID_CLI,        /* CLI mpi module id */
	/* 5 */
	AH_MOD_ID_SCD,        /* SCD */
	AH_MOD_ID_AUTH,       /* AUTH */
	AH_MOD_ID_PM,         /* Process Monitor */
	AH_MOD_ID_DHCPC,       /* dhcpc */
	AH_MOD_ID_CW,          /*CLI WIZARD*/
	/* 10 */
	AH_MOD_ID_CGI,         /* Web cgi */
	AH_MOD_ID_DNS,         /* DNS */
	AH_MOD_ID_DNS_MGT0_0,  /* per-interface DNS proxy on mgt0.0*/
	AH_MOD_ID_DNS_MGT0_1,  /* per-interface DNS proxy on mgt0.1*/
	AH_MOD_ID_DNS_MGT0_2,  /* per-interface DNS proxy on mgt0.2*/
	/* 15 */
	AH_MOD_ID_DNS_MGT0_3,  /* per-interface DNS proxy on mgt0.3*/
	AH_MOD_ID_DNS_MGT0_4,  /* per-interface DNS proxy on mgt0.4*/
	AH_MOD_ID_DNS_MGT0_5,  /* per-interface DNS proxy on mgt0.5*/
	AH_MOD_ID_DNS_MGT0_6,  /* per-interface DNS proxy on mgt0.6*/
	AH_MOD_ID_DNS_MGT0_7,  /* per-interface DNS proxy on mgt0.7*/
	/* 20 */
	AH_MOD_ID_DNS_MGT0_8,  /* per-interface DNS proxy on mgt0.8*/
	AH_MOD_ID_DNS_MGT0_9,  /* per-interface DNS proxy on mgt0.9*/
	AH_MOD_ID_DNS_MGT0_10, /* per-interface DNS proxy on mgt0.10 */
	AH_MOD_ID_DNS_MGT0_11, /* per-interface DNS proxy on mgt0.11 */
	AH_MOD_ID_DNS_MGT0_12, /* per-interface DNS proxy on mgt0.12 */
	/* 25 */
	AH_MOD_ID_DNS_MGT0_13, /* per-interface DNS proxy on mgt0.13 */
	AH_MOD_ID_DNS_MGT0_14, /* per-interface DNS proxy on mgt0.14 */
	AH_MOD_ID_DNS_MGT0_15, /* per-interface DNS proxy on mgt0.15 */
	AH_MOD_ID_DNS_MGT0_16, /* per-interface DNS proxy on mgt0.16 */
	AH_MOD_ID_DHCPS,       /* dhcpd */
	/* 30 */
	AH_MOD_ID_WIFITOOL,    /* wifi tool */
	AH_MOD_ID_CLI_UI_0,    /* cli ui 0 */
	AH_MOD_ID_CLI_UI_1,    /* cli ui 1 */
	AH_MOD_ID_CLI_UI_2,    /* cli ui 2 */
	AH_MOD_ID_CLI_UI_3,    /* cli ui 3 */
	/* 35 */
	AH_MOD_ID_CLI_UI_4,    /* cli ui 4 */
	AH_MOD_ID_CLI_UI_5,    /* cli ui 5 */
	AH_MOD_ID_CLI_UI_6,    /* cli ui 6 */
	AH_MOD_ID_CLI_UI_7,    /* cli ui 7 */
	AH_MOD_ID_CLI_UI_8,    /* cli ui 8 */
	/* 40 */
	AH_MOD_ID_CLI_UI_9,    /* cli ui 9 */
	AH_MOD_ID_RADIUS,      /* freeradius */
	AH_MOD_ID_WINBIND,     /* winbindd */
	AH_MOD_ID_LCS,         /* location service */
	AH_MOD_ID_WEB_SRV,     /* web server, hiawatha */
	/* 45 */
	AH_MOD_ID_PHP_0,       /* php */
	AH_MOD_ID_WEBUI,       /* webui */
	AH_MOD_ID_CAPWAP_SRV,  /* capwap server */
	AH_MOD_ID_MONITOR,     /* track ip */
	AH_MOD_ID_WLANDUMP,    /* wlandump */
	/* 50 */
	AH_MOD_ID_VPN,         /* vpn */
	AH_MOD_ID_LTR,         /* location tracking */
	AH_MOD_ID_ASD,         /* AirScreen */
	AH_MOD_ID_NBRCOM,      /* nbr */
	AH_MOD_ID_NTPC,        /* ntp client */
	/* 55 */
	AH_MOD_ID_UPGRADE_IMG, /* upgrade image */
	AH_MOD_ID_REMOTE_SNIFFER,  /*Remote sniffer*/
	AH_MOD_ID_DCM,         /*Data Collection Manager*/
	AH_MOD_ID_BRD,         /* bridge router daemon */
	AH_MOD_ID_IPFW,        /* iptables config daemon */
	/* 60 */
	AH_MOD_ID_WEB_PROXY_BARRACUDA, /* tinyproxy */
	AH_MOD_ID_WEB_PROXY_WEBSENSE,  /* tinyproxy */
	AH_MOD_ID_PPPOE,         /* PPPoE daemon */
	AH_MOD_ID_PPPOUSB,       /* PPPoUSB daemon */
	AH_MOD_ID_MDNSD,       /*MultiDNS deamon for bonjour AP*/
	/* 65 */
	AH_MOD_ID_BGD,         /*Bonjour gateway daemon */
	AH_MOD_ID_RADSEC,      /* radsecproxy */
	AH_MOD_ID_WPC,           /*wpa_supplicant*/
	AH_MOD_ID_SWD,         /* Switch daemon for Chesapeake */
	AH_MOD_ID_STPD,        /* stp daemon for Chesapeake */
	/* 70 */
	AH_MOD_ID_DNS_MGT0_17,
	AH_MOD_ID_DNS_MGT0_18,
	AH_MOD_ID_DNS_MGT0_19,
	AH_MOD_ID_DNS_MGT0_20,
	AH_MOD_ID_DNS_MGT0_21,
	/* 75 */
	AH_MOD_ID_DNS_MGT0_22,
	AH_MOD_ID_DNS_MGT0_23,
	AH_MOD_ID_DNS_MGT0_24,
	AH_MOD_ID_DNS_MGT0_25,
	AH_MOD_ID_DNS_MGT0_26,
	/* 80 */
	AH_MOD_ID_DNS_MGT0_27,
	AH_MOD_ID_DNS_MGT0_28,
	AH_MOD_ID_DNS_MGT0_29,
	AH_MOD_ID_DNS_MGT0_30,
	AH_MOD_ID_DNS_MGT0_31,
	/* 85 */
	AH_MOD_ID_DNS_MGT0_32,
	AH_MOD_ID_DNS_MGT0_33,
	AH_MOD_ID_DNS_MGT0_34,
	AH_MOD_ID_DNS_MGT0_35,
	AH_MOD_ID_DNS_MGT0_36,
	/* 90 */
	AH_MOD_ID_DNS_MGT0_37,
	AH_MOD_ID_DNS_MGT0_38,
	AH_MOD_ID_DNS_MGT0_39,
	AH_MOD_ID_DNS_MGT0_40,
	AH_MOD_ID_DNS_MGT0_41,
	/* 95 */
	AH_MOD_ID_DNS_MGT0_42,
	AH_MOD_ID_DNS_MGT0_43,
	AH_MOD_ID_DNS_MGT0_44,
	AH_MOD_ID_DNS_MGT0_45,
	AH_MOD_ID_DNS_MGT0_46,
	/* 100 */
	AH_MOD_ID_DNS_MGT0_47,
	AH_MOD_ID_DNS_MGT0_48,
	AH_MOD_ID_DNS_MGT0_49,
	AH_MOD_ID_DNS_MGT0_50,
	AH_MOD_ID_DNS_MGT0_51,
	/* 105 */
	AH_MOD_ID_DNS_MGT0_52,
	AH_MOD_ID_DNS_MGT0_53,
	AH_MOD_ID_DNS_MGT0_54,
	AH_MOD_ID_DNS_MGT0_55,
	AH_MOD_ID_DNS_MGT0_56,
	/* 110 */
	AH_MOD_ID_DNS_MGT0_57,
	AH_MOD_ID_DNS_MGT0_58,
	AH_MOD_ID_DNS_MGT0_59,
	AH_MOD_ID_DNS_MGT0_60,
	AH_MOD_ID_DNS_MGT0_61,
	/* 115 */
	AH_MOD_ID_DNS_MGT0_62,
	AH_MOD_ID_DNS_MGT0_63,
	AH_MOD_ID_DNS_MGT0_64,
	AH_MOD_ID_L7D,         /* l7 */
	AH_MOD_ID_ACSD, /* acsd */
	/* 120 */
	AH_MOD_ID_SFLOW,
	AH_MOD_ID_IBEACON,
	AH_MOD_ID_DHCLIENT,
	AH_MOD_ID_VRRPD,
	AH_MOD_ID_TRAP,
	/* 125 */
	AH_MOD_ID_MAX,
	AH_MOD_ID_INVALID = AH_MOD_ID_MAX
} ah_mod_id_t;

#define AH_TOTAL_BITS_IN_WORD               32
#define AH_MODULE_ID_BITMAP_SIZE            (AH_MOD_ID_MAX / AH_TOTAL_BITS_IN_WORD + 1)

#define mid2name(mid) ( ((mid)==AH_MOD_ID_AMRP)? "amrp2": \
						((mid)==AH_MOD_ID_FED)? "fed": \
						((mid)==AH_MOD_ID_DCD)? "ah_dcd": \
						((mid)==AH_MOD_ID_CAPWAP)? "capwap": \
						((mid)==AH_MOD_ID_CLI)? "ah_cli": \
						((mid)==AH_MOD_ID_SCD)? "ah_scd": \
						((mid)==AH_MOD_ID_AUTH)? "ah_auth": \
						((mid)==AH_MOD_ID_PM)? "ah_top": \
						((mid)==AH_MOD_ID_DNS)? "sheerdns": \
						((mid)==AH_MOD_ID_DNS_MGT0_0)? "dns_proxy_mgt0_0": \
						((mid)==AH_MOD_ID_DNS_MGT0_1)? "dns_proxy_mgt0_1": \
						((mid)==AH_MOD_ID_DNS_MGT0_2)? "dns_proxy_mgt0_2": \
						((mid)==AH_MOD_ID_DNS_MGT0_3)? "dns_proxy_mgt0_3": \
						((mid)==AH_MOD_ID_DNS_MGT0_4)? "dns_proxy_mgt0_4": \
						((mid)==AH_MOD_ID_DNS_MGT0_5)? "dns_proxy_mgt0_5": \
						((mid)==AH_MOD_ID_DNS_MGT0_6)? "dns_proxy_mgt0_6": \
						((mid)==AH_MOD_ID_DNS_MGT0_7)? "dns_proxy_mgt0_7": \
						((mid)==AH_MOD_ID_DNS_MGT0_8)? "dns_proxy_mgt0_8": \
						((mid)==AH_MOD_ID_DNS_MGT0_9)? "dns_proxy_mgt0_9": \
						((mid)==AH_MOD_ID_DNS_MGT0_10)? "dns_proxy_mgt0_10": \
						((mid)==AH_MOD_ID_DNS_MGT0_11)? "dns_proxy_mgt0_11": \
						((mid)==AH_MOD_ID_DNS_MGT0_12)? "dns_proxy_mgt0_12": \
						((mid)==AH_MOD_ID_DNS_MGT0_13)? "dns_proxy_mgt0_13": \
						((mid)==AH_MOD_ID_DNS_MGT0_14)? "dns_proxy_mgt0_14": \
						((mid)==AH_MOD_ID_DNS_MGT0_15)? "dns_proxy_mgt0_15": \
						((mid)==AH_MOD_ID_DNS_MGT0_16)? "dns_proxy_mgt0_16": \
						((mid)==AH_MOD_ID_DHCPS)? "dhcpd": \
						((mid)==AH_MOD_ID_DHCPC)? "dhcpc": \
						((mid)==AH_MOD_ID_CW)? "ah_cw": \
						((mid)==AH_MOD_ID_CGI)? "ah_capture": \
						((mid)==AH_MOD_ID_RADIUS)? "radiusd": \
						((mid)==AH_MOD_ID_WINBIND)? "winbindd": \
						((mid)==AH_MOD_ID_LCS)? "ah_lcs": \
						((mid)==AH_MOD_ID_WEB_SRV)? "hiawatha": \
						((mid)==AH_MOD_ID_CAPWAP_SRV)? "capwap_srv": \
						((mid)==AH_MOD_ID_WEBUI)? "ah_webui": \
						((mid)==AH_MOD_ID_MONITOR)? "ah_monitor": \
						((mid)==AH_MOD_ID_WLANDUMP)? "ah_wlandump": \
						((mid)==AH_MOD_ID_VPN)?"ah_vpn": \
						((mid)==AH_MOD_ID_LTR)? "ah_ltr": \
						((mid)==AH_MOD_ID_ASD)? "ah_asd": \
						((mid)==AH_MOD_ID_NBRCOM)? "ah_nbr": \
						((mid)==AH_MOD_ID_UPGRADE_IMG)? "ah_image": \
						((mid)==AH_MOD_ID_REMOTE_SNIFFER)? "rpcapd": \
						((mid)==AH_MOD_ID_DCM)? "ah_dcm": \
						((mid)==AH_MOD_ID_BRD)? "ah_brd": \
						((mid)==AH_MOD_ID_IPFW)?"ah_ipfw": \
						((mid)==AH_MOD_ID_WEB_PROXY_WEBSENSE)?"tinyproxy-websense": \
						((mid)==AH_MOD_ID_WEB_PROXY_BARRACUDA)?"tinyproxy-barracuda": \
						((mid)==AH_MOD_ID_PPPOE)?"pppd": \
						((mid)==AH_MOD_ID_PPPOUSB)?"pppd": \
						((mid)==AH_MOD_ID_MDNSD)? "mdnsd": \
						((mid)==AH_MOD_ID_BGD)? "ah_bgd": \
						((mid)==AH_MOD_ID_RADSEC)? "radsecproxy": \
						((mid)==AH_MOD_ID_WPC)? "wpa_supplicant": \
						((mid)==AH_MOD_ID_SWD)? "ah_swd": \
						((mid)==AH_MOD_ID_STPD)? "ah_stpd": \
						((mid)==AH_MOD_ID_DNS_MGT0_0)? "dns_proxy_mgt0_17": \
						((mid)==AH_MOD_ID_DNS_MGT0_1)? "dns_proxy_mgt0_18": \
						((mid)==AH_MOD_ID_DNS_MGT0_2)? "dns_proxy_mgt0_19": \
						((mid)==AH_MOD_ID_DNS_MGT0_3)? "dns_proxy_mgt0_20": \
						((mid)==AH_MOD_ID_DNS_MGT0_4)? "dns_proxy_mgt0_21": \
						((mid)==AH_MOD_ID_DNS_MGT0_5)? "dns_proxy_mgt0_22": \
						((mid)==AH_MOD_ID_DNS_MGT0_6)? "dns_proxy_mgt0_23": \
						((mid)==AH_MOD_ID_DNS_MGT0_7)? "dns_proxy_mgt0_24": \
						((mid)==AH_MOD_ID_DNS_MGT0_8)? "dns_proxy_mgt0_25": \
						((mid)==AH_MOD_ID_DNS_MGT0_9)? "dns_proxy_mgt0_26": \
						((mid)==AH_MOD_ID_DNS_MGT0_10)? "dns_proxy_mgt0_27": \
						((mid)==AH_MOD_ID_DNS_MGT0_11)? "dns_proxy_mgt0_28": \
						((mid)==AH_MOD_ID_DNS_MGT0_12)? "dns_proxy_mgt0_29": \
						((mid)==AH_MOD_ID_DNS_MGT0_13)? "dns_proxy_mgt0_30": \
						((mid)==AH_MOD_ID_DNS_MGT0_14)? "dns_proxy_mgt0_31": \
						((mid)==AH_MOD_ID_DNS_MGT0_15)? "dns_proxy_mgt0_32": \
						((mid)==AH_MOD_ID_DNS_MGT0_16)? "dns_proxy_mgt0_33": \
						((mid)==AH_MOD_ID_DNS_MGT0_0)? "dns_proxy_mgt0_34": \
						((mid)==AH_MOD_ID_DNS_MGT0_1)? "dns_proxy_mgt0_35": \
						((mid)==AH_MOD_ID_DNS_MGT0_2)? "dns_proxy_mgt0_36": \
						((mid)==AH_MOD_ID_DNS_MGT0_3)? "dns_proxy_mgt0_37": \
						((mid)==AH_MOD_ID_DNS_MGT0_4)? "dns_proxy_mgt0_38": \
						((mid)==AH_MOD_ID_DNS_MGT0_5)? "dns_proxy_mgt0_39": \
						((mid)==AH_MOD_ID_DNS_MGT0_6)? "dns_proxy_mgt0_40": \
						((mid)==AH_MOD_ID_DNS_MGT0_7)? "dns_proxy_mgt0_41": \
						((mid)==AH_MOD_ID_DNS_MGT0_8)? "dns_proxy_mgt0_42": \
						((mid)==AH_MOD_ID_DNS_MGT0_9)? "dns_proxy_mgt0_43": \
						((mid)==AH_MOD_ID_DNS_MGT0_10)? "dns_proxy_mgt0_44": \
						((mid)==AH_MOD_ID_DNS_MGT0_11)? "dns_proxy_mgt0_45": \
						((mid)==AH_MOD_ID_DNS_MGT0_12)? "dns_proxy_mgt0_46": \
						((mid)==AH_MOD_ID_DNS_MGT0_13)? "dns_proxy_mgt0_47": \
						((mid)==AH_MOD_ID_DNS_MGT0_14)? "dns_proxy_mgt0_48": \
						((mid)==AH_MOD_ID_DNS_MGT0_15)? "dns_proxy_mgt0_49": \
						((mid)==AH_MOD_ID_DNS_MGT0_16)? "dns_proxy_mgt0_50": \
						((mid)==AH_MOD_ID_DNS_MGT0_0)? "dns_proxy_mgt0_51": \
						((mid)==AH_MOD_ID_DNS_MGT0_2)? "dns_proxy_mgt0_52": \
						((mid)==AH_MOD_ID_DNS_MGT0_3)? "dns_proxy_mgt0_53": \
						((mid)==AH_MOD_ID_DNS_MGT0_4)? "dns_proxy_mgt0_54": \
						((mid)==AH_MOD_ID_DNS_MGT0_5)? "dns_proxy_mgt0_55": \
						((mid)==AH_MOD_ID_DNS_MGT0_6)? "dns_proxy_mgt0_56": \
						((mid)==AH_MOD_ID_DNS_MGT0_7)? "dns_proxy_mgt0_57": \
						((mid)==AH_MOD_ID_DNS_MGT0_8)? "dns_proxy_mgt0_58": \
						((mid)==AH_MOD_ID_DNS_MGT0_9)? "dns_proxy_mgt0_59": \
						((mid)==AH_MOD_ID_DNS_MGT0_10)? "dns_proxy_mgt0_60": \
						((mid)==AH_MOD_ID_DNS_MGT0_11)? "dns_proxy_mgt0_61": \
						((mid)==AH_MOD_ID_DNS_MGT0_12)? "dns_proxy_mgt0_62": \
						((mid)==AH_MOD_ID_DNS_MGT0_13)? "dns_proxy_mgt0_63": \
						((mid)==AH_MOD_ID_DNS_MGT0_14)? "dns_proxy_mgt0_64": \
						((mid)==AH_MOD_ID_L7D)? "l7d": \
						((mid)==AH_MOD_ID_ACSD)? "ah_acsd": \
						((mid)==AH_MOD_ID_SFLOW)? "sflow": \
						((mid)==AH_MOD_ID_IBEACON)? "ah_ibeacon": \
						((mid)==AH_MOD_ID_DHCLIENT)?"dhclient": \
						((mid)==AH_MOD_ID_VRRPD)? "vrrpd": \
						"n/a" )
/*Note: should use process name not use process destription string*/
#endif /* __AH_MODULE_ID_H__ */

