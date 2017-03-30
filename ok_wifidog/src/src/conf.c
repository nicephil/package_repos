/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/* $Id$ */
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire, Technologies Coeus inc.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>

#include <sqlite3.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"
#include "config.h"

#include "util.h"
#include "client_list.h"



#if OK_PATCH

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h> 

#include "pstring.h"

#include "services/wlan_services.h"
#include "services/portal_services.h"
#include "services/dnsset_services.h"
#include "services/cfg_services.h"

#include "okos_auth_param.h"
#include "gateway.h"
#endif

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
    oBadOption,
    oDaemon,
    oDebugLevel,
    oExternalInterface,
    oGatewayID,
    oGatewayInterface,
    oGatewayAddress,
    oGatewayPort,
    oDeltaTraffic,
    oAuthServer,
    oAuthServHostname,
    oAuthServSSLAvailable,
    oAuthServSSLPort,
    oAuthServHTTPPort,
    oAuthServPath,
    oAuthServLoginScriptPathFragment,
    oAuthServPortalScriptPathFragment,
    oAuthServMsgScriptPathFragment,
    oAuthServPingScriptPathFragment,
    oAuthServAuthScriptPathFragment,
    oHTTPDMaxConn,
    oHTTPDName,
    oHTTPDRealm,
    oHTTPDUsername,
    oHTTPDPassword,
    oClientTimeout,
    oCheckInterval,
    oWdctlSocket,
    oSyslogFacility,
    oFirewallRule,
    oFirewallRuleSet,
    oTrustedMACList,
    oPopularServers,
    oHtmlMessageFile,
    oProxyPort,
    oSSLPeerVerification,
    oSSLCertPath,
    oSSLAllowedCipherList,
    oSSLUseSNI,
#if OK_PATCH
    oCheckLimitRate,
    oCheckLimitBurst,
#endif
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
    const char *name;
    OpCodes opcode;
} keywords[] = {
    {
    "deltatraffic", oDeltaTraffic}, {
    "daemon", oDaemon}, {
    "debuglevel", oDebugLevel}, {
    "externalinterface", oExternalInterface}, {
    "gatewayid", oGatewayID}, {
    "gatewayinterface", oGatewayInterface}, {
    "gatewayaddress", oGatewayAddress}, {
    "gatewayport", oGatewayPort}, {
    "authserver", oAuthServer}, {
    "httpdmaxconn", oHTTPDMaxConn}, {
    "httpdname", oHTTPDName}, {
    "httpdrealm", oHTTPDRealm}, {
    "httpdusername", oHTTPDUsername}, {
    "httpdpassword", oHTTPDPassword}, {
    "clienttimeout", oClientTimeout}, {
    "checkinterval", oCheckInterval}, {
    "syslogfacility", oSyslogFacility}, {
    "wdctlsocket", oWdctlSocket}, {
    "hostname", oAuthServHostname}, {
    "sslavailable", oAuthServSSLAvailable}, {
    "sslport", oAuthServSSLPort}, {
    "httpport", oAuthServHTTPPort}, {
    "path", oAuthServPath}, {
    "loginscriptpathfragment", oAuthServLoginScriptPathFragment}, {
    "portalscriptpathfragment", oAuthServPortalScriptPathFragment}, {
    "msgscriptpathfragment", oAuthServMsgScriptPathFragment}, {
    "pingscriptpathfragment", oAuthServPingScriptPathFragment}, {
    "authscriptpathfragment", oAuthServAuthScriptPathFragment}, {
    "firewallruleset", oFirewallRuleSet}, {
    "firewallrule", oFirewallRule}, {
    "trustedmaclist", oTrustedMACList}, {
    "popularservers", oPopularServers}, {
    "htmlmessagefile", oHtmlMessageFile}, {
    "proxyport", oProxyPort}, {
    "sslpeerverification", oSSLPeerVerification}, {
    "sslcertpath", oSSLCertPath}, {
    "sslallowedcipherlist", oSSLAllowedCipherList}, {
    "sslusesni", oSSLUseSNI}, {
#if OK_PATCH
    "limitrate", oCheckLimitRate}, {
    "limitburst", oCheckLimitBurst}, {
#endif
NULL, oBadOption},};

static void config_notnull(const void *, const char *);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static int _parse_firewall_rule(const char *, char *);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);
static void parse_trusted_mac_list(const char *);
static void parse_popular_servers(const char *);
static void validate_popular_servers(void);
static void add_popular_server(const char *);

static OpCodes config_parse_token(const char *, const char *, int);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
    debug(LOG_DEBUG, "Setting default config parameters");
    config.configfile = safe_strdup(DEFAULT_CONFIGFILE);
    config.htmlmsgfile = safe_strdup(DEFAULT_HTMLMSGFILE);
    config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
    config.external_interface = NULL;
    config.gw_id = DEFAULT_GATEWAYID;
    config.gw_interface = NULL;
    config.gw_address = NULL;
    config.gw_port = DEFAULT_GATEWAYPORT;
    //config.auth_servers = NULL;
    config.httpdname = NULL;
    config.httpdrealm = DEFAULT_HTTPDNAME;
    config.httpdusername = NULL;
    config.httpdpassword = NULL;
    config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
    config.checkinterval = DEFAULT_CHECKINTERVAL;
    config.daemon = -1;
    config.pidfile = NULL;
    config.wdctl_sock = safe_strdup(DEFAULT_WDCTL_SOCK);
    config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
    config.rulesets = NULL;
    config.trustedmaclist = NULL;
    config.popular_servers = NULL;
    config.proxy_port = 0;
    config.ssl_certs = safe_strdup(DEFAULT_AUTHSERVSSLCERTPATH);
    config.ssl_verify = DEFAULT_AUTHSERVSSLPEERVER;
    config.deltatraffic = DEFAULT_DELTATRAFFIC;
    config.ssl_cipher_list = NULL;
    config.arp_table_path = safe_strdup(DEFAULT_ARPTABLE);
    config.ssl_use_sni = DEFAULT_AUTHSERVSSLSNI;

    debugconf.log_stderr = 1;
    debugconf.debuglevel = DEFAULT_DEBUGLEVEL;
    debugconf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
    debugconf.log_syslog = DEFAULT_LOG_SYSLOG;

#if OK_PATCH
    config.limit_rate = DEFAULT_LIMIT_RATE;
    config.limit_burst = DEFAULT_LIMIT_BURST;
#endif
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) {
        config.daemon = DEFAULT_DAEMON;
        if (config.daemon > 0) {
            debugconf.log_stderr = 0;
        }
    }
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
    int i;

    for (i = 0; keywords[i].name; i++)
        if (strcasecmp(cp, keywords[i].name) == 0)
            return keywords[i].opcode;

    debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
    return oBadOption;
}

/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE * file, const char *filename, int *linenum)
{
#if OK_PATCH
#else
    char *host = NULL,
        *path = NULL,
        *loginscriptpathfragment = NULL,
        *portalscriptpathfragment = NULL,
        *msgscriptpathfragment = NULL,
        *pingscriptpathfragment = NULL, *authscriptpathfragment = NULL, line[MAX_BUF], *p1, *p2;
    int http_port, ssl_port, ssl_available, opcode;
    t_auth_serv *new, *tmp;

    /* Defaults */
    path = safe_strdup(DEFAULT_AUTHSERVPATH);
    loginscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
    portalscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
    msgscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
    pingscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
    authscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
    http_port = DEFAULT_AUTHSERVPORT;
    ssl_port = DEFAULT_AUTHSERVSSLPORT;
    ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* trim all blanks at the end of the line */
        for (p2 = (p2 != NULL ? p2 - 1 : &line[MAX_BUF - 2]); isblank(*p2) && p2 > p1; p2--) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            switch (opcode) {
            case oAuthServHostname:
                /* Coverity rightfully pointed out we could have duplicates here. */
                if (NULL != host)
                    free(host);
                host = safe_strdup(p2);
                break;
            case oAuthServPath:
                free(path);
                path = safe_strdup(p2);
                break;
            case oAuthServLoginScriptPathFragment:
                free(loginscriptpathfragment);
                loginscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServPortalScriptPathFragment:
                free(portalscriptpathfragment);
                portalscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServMsgScriptPathFragment:
                free(msgscriptpathfragment);
                msgscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServPingScriptPathFragment:
                free(pingscriptpathfragment);
                pingscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServAuthScriptPathFragment:
                free(authscriptpathfragment);
                authscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServSSLPort:
                ssl_port = atoi(p2);
                break;
            case oAuthServHTTPPort:
                http_port = atoi(p2);
                break;
            case oAuthServSSLAvailable:
                ssl_available = parse_boolean_value(p2);
                if (ssl_available < 0) {
                    debug(LOG_WARNING, "Bad syntax for Parameter: SSLAvailable on line %d " "in %s."
                        "The syntax is yes or no." , *linenum, filename);
                    exit(-1);
                }
                break;
            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                exit(-1);
                break;
            }
        }
    }

    /* only proceed if we have an host and a path */
    if (host == NULL) {
        free(path);
        free(authscriptpathfragment);
        free(pingscriptpathfragment);
        free(msgscriptpathfragment);
        free(portalscriptpathfragment);
        free(loginscriptpathfragment);
        return;
    }

    debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the auth server list", host, http_port, ssl_port, path);

    /* Allocate memory */
    new = safe_malloc(sizeof(t_auth_serv));

    /* Fill in struct */
    new->authserv_hostname = host;
    new->authserv_use_ssl = ssl_available;
    new->authserv_path = path;
    new->authserv_login_script_path_fragment = loginscriptpathfragment;
    new->authserv_portal_script_path_fragment = portalscriptpathfragment;
    new->authserv_msg_script_path_fragment = msgscriptpathfragment;
    new->authserv_ping_script_path_fragment = pingscriptpathfragment;
    new->authserv_auth_script_path_fragment = authscriptpathfragment;
    new->authserv_http_port = http_port;
    new->authserv_ssl_port = ssl_port;
#if OK_PATCH
    /* Hacking a little too much, since we can't support domain name any more. */
    new->last_ip = safe_strdup(host);
#endif
    

    /* If it's the first, add to config, else append to last server */
    if (config.auth_servers == NULL) {
        config.auth_servers = new;
    } else {
        for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next) ;
        tmp->next = new;
    }

    debug(LOG_DEBUG, "Auth server added");
#endif /* OK_PATCH */
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *ruleset, FILE * file, const char *filename, int *linenum)
{
    char line[MAX_BUF], *p1, *p2;
    int opcode;

    debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

            switch (opcode) {
            case oFirewallRule:
                _parse_firewall_rule(ruleset, p2);
                break;

            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                exit(-1);
                break;
            }
        }
    }

    debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(const char *ruleset, char *leftover)
{
    int i;
    t_firewall_target target = TARGET_REJECT;     /**< firewall target */
    int all_nums = 1;     /**< If 0, port contained non-numerics */
    int finished = 0;     /**< reached end of line */
    char *token = NULL;     /**< First word */
    char *port = NULL;     /**< port to open/block */
    char *protocol = NULL;     /**< protocol to block, tcp/udp/icmp */
    char *mask = NULL;     /**< Netmask */
    char *other_kw = NULL;     /**< other key word */
    int mask_is_ipset = 0;
    t_firewall_ruleset *tmpr;
    t_firewall_ruleset *tmpr2;
    t_firewall_rule *tmp;
    t_firewall_rule *tmp2;

    debug(LOG_DEBUG, "leftover: %s", leftover);

    /* lower case */
    for (i = 0; *(leftover + i) != '\0' && (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++) ;

    token = leftover;
    TO_NEXT_WORD(leftover, finished);

    /* Parse token */
    if (!strcasecmp(token, "block") || finished) {
        target = TARGET_REJECT;
    } else if (!strcasecmp(token, "drop")) {
        target = TARGET_DROP;
    } else if (!strcasecmp(token, "allow")) {
        target = TARGET_ACCEPT;
    } else if (!strcasecmp(token, "log")) {
        target = TARGET_LOG;
    } else if (!strcasecmp(token, "ulog")) {
        target = TARGET_ULOG;
    } else {
        debug(LOG_ERR, "Invalid rule type %s, expecting " "\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
        return -1;
    }

    /* Parse the remainder */
    /* Get the protocol */
    if (strncmp(leftover, "tcp", 3) == 0 || strncmp(leftover, "udp", 3) == 0 || strncmp(leftover, "icmp", 4) == 0) {
        protocol = leftover;
        TO_NEXT_WORD(leftover, finished);
    }

    /* Get the optional port or port range */
    if (strncmp(leftover, "port", 4) == 0) {
        TO_NEXT_WORD(leftover, finished);
        /* Get port now */
        port = leftover;
        TO_NEXT_WORD(leftover, finished);
        for (i = 0; *(port + i) != '\0'; i++)
            if (!isdigit((unsigned char)*(port + i)) && ((unsigned char)*(port + i) != ':'))
                all_nums = 0;   /*< No longer only digits */
        if (!all_nums) {
            debug(LOG_ERR, "ERROR: wifidog config file, section FirewallRuleset %s. " "Invalid port %s", ruleset, port);
            return -3;          /*< Fail */
        }
    }

    /* Now, further stuff is optional */
    if (!finished) {
        /* should be exactly "to" or "to-ipset" */
        other_kw = leftover;
        TO_NEXT_WORD(leftover, finished);
        if (!finished) {
            /* Get arg now and check validity in next section */
            mask = leftover;
        }
        if (strncmp(other_kw, "to-ipset", 8) == 0 && !finished) {
            mask_is_ipset = 1;
        }
        TO_NEXT_WORD(leftover, finished);
        if (!finished) {
            debug(LOG_WARNING, "Ignoring trailining string after successfully parsing rule: %s", leftover);
        }
    }
    /* Generate rule record */
    tmp = safe_malloc(sizeof(t_firewall_rule));
    tmp->target = target;
    tmp->mask_is_ipset = mask_is_ipset;
    if (protocol != NULL)
        tmp->protocol = safe_strdup(protocol);
    if (port != NULL)
        tmp->port = safe_strdup(port);
    if (mask == NULL)
        tmp->mask = safe_strdup("0.0.0.0/0");
    else
        tmp->mask = safe_strdup(mask);

    debug(LOG_DEBUG, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);

    /* Append the rule record */
    if (config.rulesets == NULL) {
        config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
        config.rulesets->name = safe_strdup(ruleset);
        tmpr = config.rulesets;
    } else {
        tmpr2 = tmpr = config.rulesets;
        while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
            tmpr2 = tmpr;
            tmpr = tmpr->next;
        }
        if (tmpr == NULL) {
            /* Rule did not exist */
            tmpr = safe_malloc(sizeof(t_firewall_ruleset));
            tmpr->name = safe_strdup(ruleset);
            tmpr2->next = tmpr;
        }
    }

    /* At this point, tmpr == current ruleset */
    if (tmpr->rules == NULL) {
        /* No rules... */
        tmpr->rules = tmp;
    } else {
        tmp2 = tmpr->rules;
        while (tmp2->next != NULL)
            tmp2 = tmp2->next;
        tmp2->next = tmp;
    }

    return 1;
}

t_firewall_rule *
get_ruleset(const char *ruleset)
{
    t_firewall_ruleset *tmp;

    for (tmp = config.rulesets; tmp != NULL && strcmp(tmp->name, ruleset) != 0; tmp = tmp->next) ;

    if (tmp == NULL)
        return NULL;

    return (tmp->rules);
}

/**
@param filename Full path of the configuration file to be read 
*/
void
config_read(const char *filename)
{
    FILE *fd;
    char line[MAX_BUF], *s, *p1, *p2, *rawarg = NULL;
    int linenum = 0, opcode, value;
    size_t len;

    debug(LOG_INFO, "Reading configuration file '%s'", filename);

    if (!(fd = fopen(filename, "r"))) {
        debug(LOG_ERR, "Could not open configuration file '%s', " "exiting...", filename);
        exit(1);
    }

    while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
        linenum++;
        s = line;

        if (s[strlen(s) - 1] == '\n')
            s[strlen(s) - 1] = '\0';

        if ((p1 = strchr(s, ' '))) {
            p1[0] = '\0';
        } else if ((p1 = strchr(s, '\t'))) {
            p1[0] = '\0';
        }

        if (p1) {
            p1++;

            // Trim leading spaces
            len = strlen(p1);
            while (*p1 && len) {
                if (*p1 == ' ')
                    p1++;
                else
                    break;
                len = strlen(p1);
            }
            rawarg = safe_strdup(p1);
            if ((p2 = strchr(p1, ' '))) {
                p2[0] = '\0';
            } else if ((p2 = strstr(p1, "\r\n"))) {
                p2[0] = '\0';
            } else if ((p2 = strchr(p1, '\n'))) {
                p2[0] = '\0';
            }
        }

        if (p1 && p1[0] != '\0') {
            /* Strip trailing spaces */

            if ((strncmp(s, "#", 1)) != 0) {
                debug(LOG_DEBUG, "Parsing token: %s, " "value: %s", s, p1);
                opcode = config_parse_token(s, filename, linenum);

                switch (opcode) {
                case oDeltaTraffic:
                    config.deltatraffic = parse_boolean_value(p1);
                    break;
                case oDaemon:
                    if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
                        config.daemon = value;
                        if (config.daemon > 0) {
                            debugconf.log_stderr = 0;
                        } else {
                            debugconf.log_stderr = 1;
                        }
                    }
                    break;
                case oExternalInterface:
                    config.external_interface = safe_strdup(p1);
                    break;
                case oGatewayID:
                    config.gw_id = safe_strdup(p1);
                    break;
                case oGatewayInterface:
                    config.gw_interface = safe_strdup(p1);
                    break;
                case oGatewayAddress:
                    config.gw_address = safe_strdup(p1);
                    break;
                case oGatewayPort:
                    sscanf(p1, "%d", &config.gw_port);
                    break;
                case oAuthServer:
                    parse_auth_server(fd, filename, &linenum);
                    break;
                case oFirewallRuleSet:
                    parse_firewall_ruleset(p1, fd, filename, &linenum);
                    break;
                case oTrustedMACList:
                    parse_trusted_mac_list(p1);
                    break;
                case oPopularServers:
                    parse_popular_servers(rawarg);
                    break;
                case oHTTPDName:
                    config.httpdname = safe_strdup(p1);
                    break;
                case oHTTPDMaxConn:
                    sscanf(p1, "%d", &config.httpdmaxconn);
                    break;
                case oHTTPDRealm:
                    config.httpdrealm = safe_strdup(p1);
                    break;
                case oHTTPDUsername:
                    config.httpdusername = safe_strdup(p1);
                    break;
                case oHTTPDPassword:
                    config.httpdpassword = safe_strdup(p1);
                    break;
                case oCheckInterval:
                    sscanf(p1, "%d", &config.checkinterval);
                    break;
#if OK_PATCH
                case oCheckLimitRate:
                    sscanf(p1, "%d", &config.limit_rate);
                    break;
                case oCheckLimitBurst:
                    sscanf(p1, "%d", &config.limit_burst);
                    break;
#endif
                case oWdctlSocket:
                    free(config.wdctl_sock);
                    config.wdctl_sock = safe_strdup(p1);
                    break;
                case oClientTimeout:
                    sscanf(p1, "%d", &config.clienttimeout);
                    break;
                case oSyslogFacility:
                    sscanf(p1, "%d", &debugconf.syslog_facility);
                    break;
                case oHtmlMessageFile:
                    config.htmlmsgfile = safe_strdup(p1);
                    break;
                case oProxyPort:
                    sscanf(p1, "%d", &config.proxy_port);
                    break;
                case oSSLCertPath:
                    config.ssl_certs = safe_strdup(p1);
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLCertPath is set but not SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLPeerVerification:
                    config.ssl_verify = parse_boolean_value(p1);
                    if (config.ssl_verify < 0) {
                        debug(LOG_WARNING, "Bad syntax for Parameter: SSLPeerVerification on line %d " "in %s."
                            "The syntax is yes or no." , linenum, filename);
                        exit(-1);
                    }
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLPeerVerification is set but no SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLAllowedCipherList:
                    config.ssl_cipher_list = safe_strdup(p1);
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLAllowedCipherList is set but no SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLUseSNI:
                    config.ssl_use_sni = parse_boolean_value(p1);
                    if (config.ssl_use_sni < 0) {
                        debug(LOG_WARNING, "Bad syntax for Parameter: SSLUseSNI on line %d " "in %s."
                            "The syntax is yes or no." , linenum, filename);
                        exit(-1);
                    }
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLUseSNI is set but no SSL compiled in. Ignoring!");
#else
#ifndef HAVE_SNI
                    debug(LOG_WARNING, "SSLUseSNI is set but no CyaSSL SNI enabled. Ignoring!");
#endif
#endif
                    break;
                case oBadOption:
                    /* FALL THROUGH */
                default:
                    debug(LOG_ERR, "Bad option on line %d " "in %s.", linenum, filename);
                    debug(LOG_ERR, "Exiting...");
                    exit(-1);
                    break;
                }
            }
        }
        if (rawarg) {
            free(rawarg);
            rawarg = NULL;
        }
    }

    if (config.httpdusername && !config.httpdpassword) {
        debug(LOG_ERR, "HTTPDUserName requires a HTTPDPassword to be set.");
        exit(-1);
    }

    fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
    if (strcasecmp(line, "yes") == 0) {
        return 1;
    }
    if (strcasecmp(line, "no") == 0) {
        return 0;
    }
    if (strcmp(line, "1") == 0) {
        return 1;
    }
    if (strcmp(line, "0") == 0) {
        return 0;
    }

    return -1;
}

/**
 * Parse possiblemac to see if it is valid MAC address format */
int
check_mac_format(char *possiblemac)
{
    char hex2[3];
    return
        sscanf(possiblemac,
               "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
               hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}

/** @internal
 * Parse the trusted mac list.
 */
static void
parse_trusted_mac_list(const char *ptr)
{
    char *ptrcopy = NULL;
    char *possiblemac = NULL;
    char *mac = NULL;
    t_trusted_mac *p = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

    mac = safe_malloc(18);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

    while ((possiblemac = strsep(&ptrcopy, ","))) {
        /* check for valid format */
        if (!check_mac_format(possiblemac)) {
            debug(LOG_ERR,
                  "[%s] not a valid MAC address to trust. See option TrustedMACList in wifidog.conf for correct this mistake.",
                  possiblemac);
            free(ptrcopy);
            free(mac);
            return;
        } else {
            if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
                /* Copy mac to the list */

                debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

                if (config.trustedmaclist == NULL) {
                    config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
                    config.trustedmaclist->mac = safe_strdup(mac);
                    config.trustedmaclist->next = NULL;
                } else {
                    int skipmac;
                    /* Advance to the last entry */
                    p = config.trustedmaclist;
                    skipmac = 0;
                    /* Check before loop to handle case were mac is a duplicate
                     * of the first and only item in the list so far.
                     */
                    if (0 == strcmp(p->mac, mac)) {
                        skipmac = 1;
                    }
                    while (p->next != NULL) {
                        if (0 == strcmp(p->mac, mac)) {
                            skipmac = 1;
                        }
                        p = p->next;
                    }
                    if (!skipmac) {
                        p->next = safe_malloc(sizeof(t_trusted_mac));
                        p = p->next;
                        p->mac = safe_strdup(mac);
                        p->next = NULL;
                    } else {
                        debug(LOG_ERR,
                              "MAC address [%s] already on trusted list. See option TrustedMACList in wifidog.conf file ",
                              mac);
                    }
                }
            }
        }
    }

    free(ptrcopy);

    free(mac);

}

/** @internal
 * Add a popular server to the list. It prepends for simplicity.
 * @param server The hostname to add.
 */
static void
add_popular_server(const char *server)
{
    t_popular_server *p = NULL;

    p = (t_popular_server *)safe_malloc(sizeof(t_popular_server));
    p->hostname = safe_strdup(server);

    if (config.popular_servers == NULL) {
        p->next = NULL;
        config.popular_servers = p;
    } else {
        p->next = config.popular_servers;
        config.popular_servers = p;
    }
}

static void
parse_popular_servers(const char *ptr)
{
    char *ptrcopy = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for popular servers", ptr);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

    while ((hostname = strsep(&ptrcopy, ","))) {  /* hostname does *not* need allocation. strsep
                                                     provides a pointer in ptrcopy. */
        /* Skip leading spaces. */
        while (*hostname != '\0' && isblank(*hostname)) { 
            hostname++;
        }
        if (*hostname == '\0') {  /* Equivalent to strcmp(hostname, "") == 0 */
            continue;
        }
        /* Remove any trailing blanks. */
        tmp = hostname;
        while (*tmp != '\0' && !isblank(*tmp)) {
            tmp++;
        }
        if (*tmp != '\0' && isblank(*tmp)) {
            *tmp = '\0';
        }
        debug(LOG_DEBUG, "Adding Popular Server [%s] to list", hostname);
        add_popular_server(hostname);
    }

    free(ptrcopy);
}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
#if OK_PATCH
void
config_validate(void)
{
    if (NULL == config.device_id) {
        config.device_id = safe_strdup("00:4F:4B:4F:53:21");
    }
    config_notnull(config.device_id, "Device ID");

    if (NULL == config.domain_name) {
        config.domain_name = safe_strdup("");
    }

    validate_popular_servers();
}

#else /* OK_PATCH */
void
config_validate(void)
{
    config_notnull(config.gw_interface, "GatewayInterface");
    config_notnull(config.auth_servers, "AuthServer");
    validate_popular_servers();

    if (missing_parms) {
        debug(LOG_ERR, "Configuration is not complete, exiting...");
        exit(-1);
    }
}
#endif /* OK_PATCH */

/** @internal
 * Validate that popular servers are populated or log a warning and set a default.
 */
static void
validate_popular_servers(void)
{
    if (config.popular_servers == NULL) {
        debug(LOG_WARNING, "PopularServers not set in config file, this will become fatal in a future version.");
#if OK_PATCH
        add_popular_server("www.baidu.com");
#else
        add_popular_server("www.google.com");
        add_popular_server("www.yahoo.com");
#endif
    }
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
    if (parm == NULL) {
        debug(LOG_ERR, "%s is not set", parmname);
        missing_parms = 1;
    }
}

/**
 * This function returns the current (first auth_server)
 */
#if OK_PATCH
t_auth_serv *
get_auth_server(
        const t_client *client
        )
{
    if (NULL == client)
        return NULL;

    if (NULL == client->ssid_conf)
        return NULL;

    return client->ssid_conf->auth_servers;
}

#else /* OK_PATCH */
t_auth_serv *
get_auth_server(void)
{

    /* This is as good as atomic */
    return config.auth_servers;
}

#endif /* OK_PATCH */

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv * bad_server)
{
#if OK_PATCH
#else
    t_auth_serv *tmp;

    if (config.auth_servers == bad_server && bad_server->next != NULL) {
        /* Go to the last */
        for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next) ;
        /* Set bad server as last */
        tmp->next = bad_server;
        /* Remove bad server from start of list */
        config.auth_servers = bad_server->next;
        /* Set the next pointe to NULL in the last element */
        bad_server->next = NULL;
    }
#endif
}


#if OK_PATCH

#if 0
t_client * okos_fill_client_info_by_fdb(t_client *client)
{
    debug(LOG_INFO, "Fill the client info from config by checking fdb.");

    t_client *whatIfound = NULL;
    debug(LOG_DEBUG, "Obtain data structure of bridge in configuration.");
    t_bridge_conf *br = NULL;
    okos_list_for_each(br, config.br_conf) {
        if (0 == strcmp(br->br_name, client->brX)) {
            debug(LOG_DEBUG, "Got bridge (%s) for client(%s)[%s]", client->brX, client->ip, client->mac);
            break;
        }
    }
    if (NULL == br) {
        debug(LOG_ERR, "can not find out the bridge (%s) for client(%s)[%s]", client->brX, client->ip, client->mac);
        return whatIfound;
    }

    debug(LOG_DEBUG, "Query iface info throug brctl");

    char line[256];
    int port;
    char mac[18];
    char *command = NULL;
    safe_asprintf(&command, "brctl showmacs %s", client->brX);
    FILE *arp = popen(command, "r");
    if (arp) {
        while (!feof(arp) && '\n' != fgetc(arp)) ;

        while (fgets(line, sizeof(line), arp)) {
            debug(LOG_DEBUG, "%s", line);
            if (2 == sscanf(line, "%d %17[A-Fa-f0-9:] %*s %*s", &port, mac)) {
                debug(LOG_DEBUG, "{port = %d; mac = %s}", port, mac);
                if (0 == strcasecmp(mac, client->mac)) {
                    if (port <= 0 || port > OKOS_MAX_BRIDGE_IF_NUM) {
                        continue;
                    }
                    client->ifx = br->ifx[--port];
                    client->ssid_conf = client->ifx->ssid;
                    client->if_name = safe_strdup(client->ifx->if_name);
                    client->ssid = safe_strdup(client->ssid_conf->ssid);
                    client->scheme = safe_strdup(client->ssid_conf->scheme_name);
                    client->token = safe_strdup(OKOS_AUTH_FAKE_TOKEN);
                    whatIfound = client;

                    debug(LOG_DEBUG, "client {%s, %s} reported from iface (%s) on ssid (%s) with scheme:%s", client->ip, client->mac, client->if_name, client->ssid, client->scheme);
                    break;
                }
            }
        }
        if (NULL == whatIfound) {
            debug(LOG_ERR, "can not find out the basic information for client(%s)[%s] in bridge{%s}", client->ip, client->mac, client->brX);
        }

        pclose(arp);
    } else {
        debug(LOG_ERR, "Call `brctl showmacs %s` failed.", client->brX);
    }
    free(command);
    return whatIfound;
}


#define okos_cleanup_record_buf(element) \
    if (element) {\
        free(element); \
        element = NULL; \
    }
static t_client * okos_get_client_ifname_by_stainfo(t_client *client)
{
    char *filename = "/tmp/stationinfo/stationinfo";
    debug(LOG_DEBUG, "Fill the client info by checking %s.", filename);

    system("/lib/getstainfo.sh");

    t_client *whatIfound = NULL;
    FILE *stainfo = fopen(filename, "r");
    if (NULL == stainfo) {
        debug(LOG_ERR, "Couldn't open %s", filename);
        return whatIfound;
    }

    //while(!feof(stainfo) && '\n' != fgetc(proc));

#define MAX_LINE 256
#define OPTION_NUM 12
#define findStartLineOfRecord(line, config, client) ((2 == sscanf(line, "%s %s", config, client))\
        && (0 == strcmp(config, "config")) && (0 == strcmp(client, "client")))
#define getAnOption(line, option, key, value) ((2 <= sscanf(line, " %s %s %s", option, key, value)) \
        && (0 == strcmp(option, "option")) )
    char line[MAX_LINE];
    int line_num;
    char config[8];
    char object[8];
    char option[8];
    char key[128];
    char value[128];
    char *options[OPTION_NUM] = { NULL };
    while (!feof(stainfo) && fgets(line, sizeof(line), stainfo)) {
        if (! findStartLineOfRecord(line, config, object) ) {
            debug(LOG_DEBUG, "It (%s) supposed to be a start line of a record. keep searching.", line);
            continue;
        }
        debug(LOG_DEBUG, "Found a Record. {%s, %s}", config, object);
        for (line_num = 0; !feof(stainfo) && line_num < OPTION_NUM && fgets(line, MAX_LINE, stainfo);
            line_num++) {
            if (!getAnOption(line, option, key, value)) {
                debug(LOG_DEBUG, "it (%s) supposed to be an option.", line);
                break;
            }
            debug(LOG_DEBUG, "{key = %s, value = %s}", key, value);
            options[line_num] = safe_strdup(value);
        }
        if (OPTION_NUM != line_num) {
            debug(LOG_DEBUG, "Record is uncompleted. ");
        } else {
            if (0 == strcmp(client->ip, options[5]) && 0 == strcmp(client->mac, options[1])) {
                okos_client_set_str(client->if_name, options[0]);
                whatIfound = client;
                break;
            } else {
                debug(LOG_DEBUG, "Record unmatched.");
            }
        }
        for (line_num = 0; line_num < OPTION_NUM; line_num++) {
            okos_cleanup_record_buf(options[line_num]);
        }
    }
    fclose(stainfo);
    for (line_num = 0; line_num < OPTION_NUM; line_num++) {
        okos_cleanup_record_buf(options[line_num]);
    }

    return whatIfound;
}
#endif


static char * okos_conf_get_option_value(const char *p_path, const char *p_key);
//#define okos_conf_get_option_value_from_config(key) okos_conf_get_option_value("/etc/config", key)
static char *
okos_conf_get_option_value_from_config(
        const char *key_fmt,
        ...
        )
{
    char key[OKOS_WFD_MAX_STR_LEN];
    va_list ap;

    va_start(ap, key_fmt);
    vsprintf(key, key_fmt, ap);
    va_end(ap);
    
    //debug(LOG_DEBUG, "[CFG]\t\t\t Query '%s' from UCI.", key);
    return okos_conf_get_option_value("/etc/config", key);
}
/*
static t_client * okos_get_client_ifname(t_client *client)
{
    system("/lib/getstainfo.sh");

    char mac[18];
    char *p_src = client->mac;
    char *p_dst = mac;
    for (p_src = client->mac; 0 != *p_src; p_src++) {
        if (':' != *p_src) {
            *p_dst = *p_src;
            if ('A' <= *p_dst && *p_dst <= 'Z') {
                *p_dst = *p_dst - 'A' + 'a';
            }
            p_dst++;
        }
    }
    *p_dst = 0;

    char tuple[OKOS_WFD_MAX_STR_LEN];
    sprintf(tuple, "stationinfo.%s.ifname", mac);
    debug(LOG_DEBUG, ".... %s ....", tuple);
    char *p_ifname = okos_conf_get_option_value("/tmp/stationinfo", tuple);
    if (NULL == p_ifname) {
        return NULL;
    }
    okos_client_set_str(client->if_name, p_ifname);
    return client;
}
*/

static int
okos_show_station_info(
        void *data,
        int col_n,
        char **col_v,
        char **col_name
        )
{
    t_client *client = (t_client *)data;
    int i = 0;
    for (i = 0; i < col_n; i++) {
        debug(LOG_DEBUG, "<sqlite>\t\t key:%s, value:%s.", col_name[i], col_v[i] ? col_v[i] : "Nil");
        if (0 == strcasecmp(col_name[i], "IFNAME") && NULL != col_v[i]) {
            okos_client_set_strdup(client->if_name, col_v[i]);
        } else if (0 == strcasecmp(col_name[i], "MAC") && NULL != col_v[i]) {
            okos_client_set_strdup(client->mac, col_v[i]);
        } else {
            debug(LOG_DEBUG, "<sqlite>!! Got value[%s] UNREQUIRED.", col_name[i]);
        }
    }
    return 0;
}


static t_client *
okos_get_client_iface(
        t_client *client
        )
{
    char *sql = NULL;
    if (NULL == client->ip) { /* ip => mac */
        return NULL;
    }
    client->mac = arp_get(client->ip);
    debug(LOG_DEBUG, "<sqlite>\t Query ARP table for (%s) => [%s]",
            client->ip, client->mac ? client->mac : "NULL");
    if (NULL != client->mac) { /* mac => if_name */
        safe_asprintf(&sql, "SELECT IFNAME from STAINFO " \
                "WHERE MAC = '%s';" \
                ,
                client->mac
                );
    } else { /* ip => mac, ifname */
        safe_asprintf(&sql, "SELECT MAC, IFNAME from STAINFO " \
                "WHERE IPADDR = '%s';" \
                ,
                client->ip
                );
    }
    debug(LOG_DEBUG, "<sqlite>\t '%s'", sql);

    sqlite3 *sta_info_db = NULL;
    int db_result = sqlite3_open(station_info_db_file, &sta_info_db);
    if (0 != db_result) {
        debug(LOG_ERR, "<sqlite>!! Fail to open database %s:%s.",
                station_info_db_file, sqlite3_errmsg(sta_info_db));
        free(sql);
        return NULL;
    }
    debug(LOG_DEBUG, "<sqlite>\t Open database %s successfully.", station_info_db_file);
    
    char *err_msg = NULL;
    int rc = sqlite3_exec(sta_info_db, sql, okos_show_station_info, client, &err_msg);
    if (SQLITE_OK != rc) {
        debug(LOG_WARNING, "<sqlite>!! Query ( %s ) Failed for %s.",
                sql, err_msg);
        sqlite3_free(err_msg);
        client = NULL;
    } else {
        if (NULL == client->if_name) {
            debug(LOG_DEBUG, "<sqlite>!! Return without error but if_name is NULL)");
        } else if (NULL == client->mac) {
            debug(LOG_DEBUG, "<sqlite>!! Return without error but mac is NULL)");
        } else {
            debug(LOG_DEBUG, "<sqlite>\t Query ( %s ) successfully.", sql);
        }
    }

    sqlite3_close(sta_info_db);
    free(sql);
    debug(LOG_DEBUG, "<sqlite>\t Close database.");
    
    return client;
}

t_client *
okos_fill_client_info_by_stainfo(
        t_client *client
        )
{
#if 0
    if (NULL != okos_get_client_ifname_by_stainfo(client)) {
#endif
#if 0
    if (NULL != okos_get_client_ifname(client)) {
#endif
    if (NULL != okos_get_client_iface(client)) {
        client->ifx = okos_conf_get_ifx_by_name(client->if_name);
        if (NULL != client->ifx) {
            client->ssid_conf = client->ifx->ssid;
            if (NULL != client->ssid_conf) {

                okos_client_set_strdup(client->scheme, client->ssid_conf->scheme_name);
                okos_client_set_strdup(client->ssid, client->ssid_conf->ssid);
                okos_client_set_strdup(client->token, OKOS_AUTH_FAKE_TOKEN);

                debug(LOG_DEBUG, ".... found record of client {ip:%s, mac=%s, ifname:%s, ssid:%s, scheme:%s}", client->ip, client->mac, client->if_name, client->ssid, client->scheme);

                return client;
            }
        }
    }

    client_free_node(client);
    debug(LOG_DEBUG, "..!! Configuration imcompleted. Can't find out ifx or ssid_conf.");

    return NULL;
}

#if 0
t_client *
okos_fill_client_info(
        t_client *client
        )
{
    debug(LOG_INFO, "Fill the client info from config by hand.");
    
    t_ssid_config *ssid;
    okos_list_for_each(ssid, config.ssid_conf) {
        if (0 == strcmp(client->brX, ssid->br_name)) {
            client->ssid_conf = ssid;
            client->ifx = ssid->if_list;
            client->if_name = safe_strdup(client->ifx->if_name);
            client->ssid = safe_strdup(client->ssid_conf->ssid);
            client->scheme = safe_strdup(client->ssid_conf->scheme_name);
            
            // Fake the token to cheat wifidog
            client->token = safe_strdup(OKOS_AUTH_FAKE_TOKEN);

            debug(LOG_DEBUG, "client (%s)[%s] located in bridge {%s}, ssid:%s, scheme:%s, if name is:%s, bssid=%s", client->ip, client->mac, client->brX, client->ssid, client->scheme, client->if_name, client->ifx->bssid);
            return client;
        }
    }
    debug(LOG_ERR, "can not find out the basic information for client(%s)[%s] in bridge{%s}", client->ip, client->mac, client->brX);
    return NULL;
}
#endif



static int
okos_get_bssid(
        char *p_ifname,
        char **pp_bssid
        )
{
    char line[256];
    char mac[18];
    char *p_command = NULL;
    safe_asprintf(&p_command, "ifconfig %s", p_ifname);
    FILE *pf_ifconfig = popen(p_command, "r");
    free(p_command);
    char *p_head = "HWaddr ";
    int head_len = strlen(p_head);

    if (pf_ifconfig) {
        while (fgets(line, sizeof(line), pf_ifconfig)) {
            //debug(LOG_DEBUG, "%s", line);
            char *p_mac = strstr(line, p_head);
            if (p_mac && head_len + sizeof(mac) - 1 <= strlen(p_mac)) {
                p_mac += head_len;
                *pp_bssid = safe_malloc(sizeof(mac));
                strncpy(*pp_bssid, p_mac, sizeof(mac) - 1);
                (*pp_bssid)[sizeof(mac) - 1] = '\0';
                pclose(pf_ifconfig);
                debug(LOG_DEBUG, "[CFG]\t\t\t iface(%s)'s bssid is:%s", p_ifname, *pp_bssid);
                return 0;
            }
        }
    }

    pclose(pf_ifconfig);
    return 1;
}


void
okos_config_init_default_auth_server(
        t_auth_serv *svr
        )
{
    svr->authserv_use_ssl = DEFAULT_AUTHSERVSSLAVAILABLE;

    okos_conf_set_str(svr->authserv_login_script_path_fragment, DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
    okos_conf_set_str(svr->authserv_portal_script_path_fragment, DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
    okos_conf_set_str(svr->authserv_msg_script_path_fragment, DEFAULT_AUTHSERVMSGPATHFRAGMENT);
    okos_conf_set_str(svr->authserv_ping_script_path_fragment, DEFAULT_AUTHSERVPINGPATHFRAGMENT);
    okos_conf_set_str(svr->authserv_auth_script_path_fragment, DEFAULT_AUTHSERVAUTHPATHFRAGMENT);

    svr->authserv_http_port = DEFAULT_AUTHSERVPORT;
    svr->authserv_ssl_port = DEFAULT_AUTHSERVSSLPORT;
}

#define okos_cfg_is_empty(str) ('\0' == str[0])

static char *
okos_conf_get_option_value(
        const char *p_path,
        const char *p_key
        )
{
    char cfg[OKOS_WFD_MAX_STR_LEN];
    cfg[0] = 0;
    int res = cfg_get_option_value_with_path(p_path, p_key, cfg, sizeof(cfg));
    if (0 == res) {
        return safe_strdup(cfg);
    }
    return NULL;
}

static int
okos_attach_vap_to_ssid(
        int radio,
        int vap,
        t_ssid_config *p_ssid
        )
{
    t_ath_if_list *p_iface = NULL;
    p_iface = okos_conf_ins_list_member(p_ssid->if_list);
    safe_asprintf(&p_iface->if_name, "ath%d%d", radio, vap);
    int getBssidFailed = okos_get_bssid(p_iface->if_name, &p_iface->bssid);
    if (getBssidFailed) {
        p_iface->bssid = safe_strdup(config.device_id);
    }
    p_iface->ssid = p_ssid;

    debug(LOG_DEBUG, "[CFG]\t\t\t Attach iface %s to ssid %s",
            p_iface->if_name, p_ssid->ssid);
    return getBssidFailed;
}

static int
okos_load_authsvr_to_ssid(
        struct portal_scheme_cfg *p_schm_cfg,
        t_ssid_config *p_ssid
        )
{
    t_auth_serv *p_auth_svr;
    char cfg[OKOS_WFD_MAX_STR_LEN];
    char host_name[OKOS_WFD_MAX_STR_LEN];
    char host_path[OKOS_WFD_MAX_STR_LEN];
    host_path[0] = '/';
    int host_port = DEFAULT_AUTHSERVPORT;
    if (1 == sscanf(p_schm_cfg->uri_path, "http://%s", cfg)) {
        if ((3 == sscanf(cfg, "%[a-zA-Z0-9.]:%d/%s", host_name, &host_port, &host_path[1]))
                || (2 == sscanf(cfg, "%[a-zA-Z0-9.]/%s", host_name, &host_path[1]))) {
            p_auth_svr = okos_conf_ins_list_member(p_ssid->auth_servers);
            okos_config_init_default_auth_server(p_auth_svr);
            okos_conf_set_str(p_auth_svr->authserv_hostname, host_name);
            okos_conf_set_str(p_auth_svr->authserv_path, host_path);
            p_auth_svr->authserv_http_port = host_port;
            debug(LOG_DEBUG, "[CFG]\t\t\t add auth server(%s) with path(%s) into ssid(%s)",
                    p_auth_svr->authserv_hostname, p_auth_svr->authserv_path, p_ssid->ssid);
            return 0;
        }
    }
    debug(LOG_WARNING, "[CFG]!! Bad auth server path configuration<%s>", p_schm_cfg->uri_path);
    return 1;
}

static int
okos_load_ip_whitelist_to_ssid(
        struct portal_scheme_cfg *p_schm_cfg,
        t_ssid_config *p_ssid
        )
{
    t_firewall_ruleset *p_ip_wlist;
    t_firewall_rule *p_ipx;
    p_ip_wlist = okos_conf_ins_list_member(p_ssid->ip_white_list);
    p_ip_wlist->name = safe_strdup("ip white list");
    debug(LOG_DEBUG, "[CFG]\t\t load ip white list into ssid(%s)", p_ssid->ssid);
    int i_ip;
    for (i_ip = 0; i_ip < p_schm_cfg->ip_num; i_ip++) {
        p_ipx = okos_conf_ins_list_member(p_ip_wlist->rules);
        struct in_addr ipaddr;
        ipaddr.s_addr = p_schm_cfg->ip_list[i_ip].ip;
        p_ipx->mask = safe_strdup(inet_ntoa(ipaddr));
        p_ipx->target = TARGET_ACCEPT;
        debug(LOG_DEBUG, "[CFG]\t\t\t load rule for %s", p_ipx->mask);
    }
    return 0;
}

static int
okos_load_dn_whitelist_to_ssid(
        struct portal_scheme_cfg *p_schm_cfg,
        t_ssid_config *p_ssid
        )
{
    struct dns_set_t *p_tmp, *p_dns = NULL;
    t_firewall_ruleset *p_dn_wlist;
    t_firewall_rule *p_dn_white;

    struct dns_set_t *p_dns_list = dnsset_cfg_getall();

    p_dn_wlist = okos_conf_ins_list_member(p_ssid->dn_white_list);
    p_dn_wlist->name = safe_strdup("dn white list");
    debug(LOG_DEBUG, "[CFG]\t\t load domain name white list into ssid(%s)", p_ssid->ssid);
    okos_list_for_each(p_tmp, p_dns_list) {
        if (p_tmp->enable && 0 == strcmp(p_tmp->name, p_schm_cfg->dns_set)) {
            p_dns = p_tmp;
            break;
        }
    }

    if (NULL != p_dns) {
        debug(LOG_DEBUG, "[CFG]\t\t found domain name set configuration [%s].",
                p_schm_cfg->dns_set);
        int i_key;
        struct key_list *p_key;
        okos_list_for_each_loop(p_key, p_dns->keylist,
                i_key = 0, i_key < p_dns->keycount, i_key++) {
            p_dn_white = okos_conf_ins_list_member(p_dn_wlist->rules);
            p_dn_white->target = TARGET_ACCEPT;
            p_dn_white->mask = safe_strdup(p_key->key);
            debug(LOG_DEBUG, "[CFG]\t\t\t load rule for %s", p_dn_white->mask);
        }
    }

    dnsset_cfg_free(p_dns_list);
    return 0;
}

static int
okos_load_mac_white_list_to_ssid(
        char *acl_name,
        t_ssid_config *p_ssid
        )
{
    /* Get ALL the ACLs */
    struct wlan_acl_stats *acls;
    int isEmpty = wlan_get_acl_all(&acls); // it will malloc all memory
    if (isEmpty) {
        debug(LOG_DEBUG, "[CFG]!! MAC white list is empty.");
        return 1;
    }

    /* Polling in ACLs to match ACL name in scheme */
    struct wlan_acl_status *acl = NULL;
    int i_acl;
    for (i_acl = 0; i_acl < acls->acl_count; i_acl++) {
        if (0 == strcmp(acls->acl[i_acl].name, acl_name)) {
            acl = acls->acl + i_acl;
            break;
        }
    }

    if (NULL != acl) {
        debug(LOG_DEBUG, "[CFG]\t\t Load ACL(%s) on SSID(%s).",
                acl_name, p_ssid->ssid);
        t_trusted_mac *p_mac_wlist;
        int i_mac;
        unsigned char *mac;
        for (i_mac = 0; i_mac < acl->count; i_mac++) {
            mac = acl->maclist[i_mac].mac;
            p_mac_wlist = okos_conf_ins_list_member(p_ssid->mac_white_list);
            safe_asprintf(&p_mac_wlist->mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
            debug(LOG_DEBUG, "[CFG]\t\t\t Insert MAC[%s]", p_mac_wlist->mac);
        }
    }

    wlan_free_acl_all(acls);
    return 0;
}

static t_ssid_config *
okos_load_ssid(
        int svc_tmp_id
        )
{
    /*-----------------------------------------------------------------
     * STEP1: After getting the service template SN.,
     *        Checking whether this SSID was configured as Portal Mode
     *        by querying 'portal_scheme' variable.
     *----------------------------------------------------------------*/
    char *scheme_name = okos_conf_get_option_value_from_config(
            "wlan_service_template.ServiceTemplate%d.portal_scheme", svc_tmp_id);
    if (NULL == scheme_name) {
        debug(LOG_DEBUG, "[CFG]\t\t Template[%d] works out of Portal mode.", svc_tmp_id);
        return NULL;
    }

    /*-----------------------------------------------------------------
     * STEP2: Got a service template enabled portal.
     *        So, should do
     *        1) Polling portal schemes by scheme name.
     *        2) Create ssid element;
     *        2.1) Copy AuthSvr Cfg.
     *        2.2) Copy Domain name & IP white list.
     *        3) Attach this VAP.
     *----------------------------------------------------------------*/
    struct portal_schemes *p_schemes = safe_malloc(sizeof(struct portal_schemes));
    portal_scheme_get_all(p_schemes);
    struct portal_scheme_cfg *p_schm_cfg = NULL;
    struct portal_scheme_cfg *p_tmp = p_schemes->config;
    int i_schm;
    for (i_schm = 0; i_schm < p_schemes->num && p_tmp->enable; i_schm++, p_tmp++) {
        if (0 == strncmp(p_tmp->scheme_name, scheme_name, strlen(scheme_name))) {
            p_schm_cfg = p_tmp;
            break;
        }
    }

    t_ssid_config *p_ssid = NULL;
    if (NULL != p_schm_cfg) {
        p_ssid = okos_conf_ins_list_member(config.ssid_conf);
        p_ssid->scheme_name = scheme_name;
        p_ssid->sn = svc_tmp_id;
        p_ssid->ssid = okos_conf_get_option_value_from_config(
                "wlan_service_template.ServiceTemplate%d.ssid", svc_tmp_id);
        p_ssid->ssid = p_ssid->ssid ? p_ssid->ssid : "OkOS";
        debug(LOG_DEBUG, "[CFG]\t\t Created ssid(%s) scheme(%s) sn(%d).",
                p_ssid->ssid, p_ssid->scheme_name, p_ssid->sn);

        okos_load_authsvr_to_ssid(p_schm_cfg, p_ssid);
        okos_load_ip_whitelist_to_ssid(p_schm_cfg, p_ssid);
        okos_load_dn_whitelist_to_ssid(p_schm_cfg, p_ssid);

        char *acl_name = okos_conf_get_option_value_from_config(
                "wlan_service_template.ServiceTemplate%d.acl", svc_tmp_id);
        if (NULL != acl_name) {
            okos_load_mac_white_list_to_ssid(acl_name, p_ssid);
        }
        free(acl_name);
    } else {
        debug(LOG_DEBUG, "[CFG]!! Can't find out Portal Scheme(%s) set in template(%d)",
                scheme_name, svc_tmp_id);
        free(scheme_name);
    }

    portal_scheme_free_all(p_schemes);

    return p_ssid;
}

static void
okos_config_read(void)
{
    struct wlan_radio_info *p_rdcfg = safe_malloc(sizeof(struct wlan_radio_info));
    wlan_radio_get_all(p_rdcfg);
    //struct service_template *p_stcfg = safe_malloc(sizeof(struct service_template));
    //wlan_service_template_get_all(p_stcfg);

    t_ssid_config *p_ssid = NULL;

    debug(LOG_INFO, "[CFG] Reading configuration from uci.\n"); 

    config.device_id = okos_conf_get_option_value_from_config("productinfo.@productinfo[0].mac");
    if (config.device_id) {
        debug(LOG_DEBUG, "[CFG]\t Parsing {device_id: %s}", config.device_id);
    } else {
        int r = rand() % 0x10000;
        safe_asprintf(&config.device_id, "00:4f:61:6b:%02x:%02x", (r>>8)&0xff, r&0xff);
        debug(LOG_DEBUG, "[CFG]!! Parsing device_id UNCOMPLETED. Filled by [%s]", config.device_id);
    }
    config.domain_name = okos_conf_get_option_value_from_config("system.domain.domain");
    if (config.domain_name) {
        debug(LOG_DEBUG, "[CFG]\t Parsing {domain_name: %s}", config.domain_name);
    } else {
        debug(LOG_DEBUG, "[CFG]!! Parsing domain_name UNCOMPLETED.");
        config.domain_name = safe_strdup("");
    }

    /*-------------------------------------------------------------
     * Purpose of this block:
     * Install SSID configuration from 'wlan_service_template'
     * Since SSID, Portal Configuration are all restored in it.
     *------------------------------------------------------------*/
    int i_rd, i_vap, i_svc_tmp_id, ssid_is_loaded;
    debug(LOG_DEBUG, "[CFG]\t Checking configuration of total %d Radioes.", p_rdcfg->num);
    for (i_rd = 0; i_rd < p_rdcfg->num && p_rdcfg->radioinfo[i_rd].enable; i_rd++) {
        debug(LOG_DEBUG, "[CFG]\t\t Checking configuration of total %d VAP, on Radio.%d.",
                p_rdcfg->radioinfo[i_rd].count, i_rd);

        for (i_vap = 0; i_vap < p_rdcfg->radioinfo[i_rd].count; i_vap++) {

            /*-----------------------------------------------------------------
             * STEP1: Get template SN.
             *        If The template associated to this VAP has been installed,
             *        1) Attach it.
             *        2) Skip it.
             *----------------------------------------------------------------*/
            i_svc_tmp_id = p_rdcfg->radioinfo[i_rd].service[i_vap];
            ssid_is_loaded = 0;
            okos_list_for_each(p_ssid, config.ssid_conf) {
                if (i_svc_tmp_id == (int)p_ssid->sn) {
                    debug(LOG_DEBUG, "[CFG]]\t\t {radio.%d vap.%d} is attached to template [%d].",
                            i_rd, i_vap, i_svc_tmp_id);
                    okos_attach_vap_to_ssid(i_rd, i_vap, p_ssid);
                    ssid_is_loaded = 1;
                    break;
                }
            }
            if (ssid_is_loaded) {
                continue;
            }

            /*-----------------------------------------------------------------
             * STEP2: Try to Load SSID configuration and attch ath i/f.
             *        If The template does not work in Portal mode,
             *        Skip it.
             *----------------------------------------------------------------*/
            p_ssid = okos_load_ssid(i_svc_tmp_id);
            if (NULL == p_ssid) {
                debug(LOG_DEBUG, "[CFG]!! {radio.%d, vap.%d} load service templete %d failed!",
                        i_rd, i_vap, i_svc_tmp_id);
            } else {
                debug(LOG_DEBUG, "[CFG]\t\t {radio.%d, vap.%d} load template [%d] successfully.",
                        i_rd, i_vap, i_svc_tmp_id);
                okos_attach_vap_to_ssid(i_rd, i_vap, p_ssid);
            }
        }
    }

    free(p_rdcfg);
    //free(p_stcfg);

    debug(LOG_INFO, "[CFG] Reading configuration from uci finished.\n");
}


void
config_simulate(void)
{
    okos_config_read();
}


#if 0
static void
okos_simulate_3ssid(void)
{

    s_config *my_config = &config;

    okos_conf_set_str(my_config->device_id, "00:55:AA:E7:38:29");
    okos_conf_set_str(my_config->domain_name, "76e0d05f7a6a4ae9a7d2b582c6ec74be");
    okos_conf_set_str(my_config->gw_id, my_config->device_id);

    t_ssid_config *ssid;
    t_auth_serv *authsvrs;
    t_trusted_mac *trusted_mac;
    t_firewall_ruleset *dn_white_list;
    t_firewall_rule *dns;
    t_firewall_ruleset *ip_set;
    t_firewall_rule * ipx;
    t_ath_if_list *ifs;
    t_bridge_conf *brX;

    brX = okos_conf_append_list_member(my_config->br_conf);
    okos_conf_set_str(brX->br_name, "br-lan1");

    // 1st ssid 
    ssid = okos_conf_append_list_member(my_config->ssid_conf);
    ssid->brx = brX;
    ifs = okos_conf_append_list_member(ssid->if_list);
    ifs->ssid = ssid;
    ifs->brx = brX;
    brX->ifx[0] = ifs;
    okos_conf_set_str(ifs->if_name, "ath00");
    okos_conf_set_str(ifs->bssid, "00:55:AA:E7:38:29");
    ifs = okos_conf_append_list_member(ifs);
    ifs->ssid = ssid;
    ifs->brx = brX;
    brX->ifx[2] = ifs;
    okos_conf_set_str(ifs->if_name, "ath10");
    okos_conf_set_str(ifs->bssid, "00:55:AA:E7:38:29");


    okos_conf_set_int(ssid, sn, 1);
    okos_conf_set_str(ssid->ssid, "oakridge_test_1");
    okos_conf_set_str(ssid->br_name, "br-lan1");
    okos_conf_set_str(ssid->scheme_name, "1");

    authsvrs = okos_conf_append_list_member(ssid->auth_servers);
    okos_config_init_default_auth_server(authsvrs);
    okos_conf_set_str(authsvrs->authserv_hostname, "139.196.188.253");
    okos_conf_set_str(authsvrs->authserv_path, "/auth/device/");

    trusted_mac = okos_conf_append_list_member(ssid->mac_white_list);
    okos_conf_set_str(trusted_mac->mac, "00:61:71:83:25:7B"); 
    trusted_mac = okos_conf_append_list_member(trusted_mac);
    okos_conf_set_str(trusted_mac->mac, "f4:0f:24:26:b1:59"); 

    dn_white_list = okos_conf_append_list_member(ssid->dn_white_list);
    okos_conf_set_str(dn_white_list->name, "dn white list");
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "dangdang.com");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "a1.oakridge.io");
    okos_conf_set_str(dns->port, "39901");
    okos_conf_set_str(dns->protocol, "tcp");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);

    ip_set = okos_conf_append_list_member(ssid->ip_white_list);
    okos_conf_set_str(ip_set->name, "ip white list");
    ipx = okos_conf_append_list_member(ip_set->rules);
    okos_conf_set_str(ipx->mask, "192.168.0.1");
    okos_conf_set_int(ipx, target, TARGET_ACCEPT);
    ipx = okos_conf_append_list_member(ip_set->rules);
    okos_conf_set_str(ipx->mask, "192.168.100.1");
    okos_conf_set_int(ipx, target, TARGET_ACCEPT);


    // second ssid 
    ssid = okos_conf_append_list_member(my_config->ssid_conf);
    ssid->brx = brX;
    ifs = okos_conf_append_list_member(ssid->if_list);
    ifs->ssid = ssid;
    ifs->brx = brX;
    brX->ifx[1] = ifs;
    okos_conf_set_str(ifs->if_name, "ath01");
    okos_conf_set_str(ifs->bssid, "00:55:AA:E7:38:29");
    ifs = okos_conf_append_list_member(ifs);
    ifs->ssid = ssid;
    ifs->brx = brX;
    brX->ifx[3] = ifs;
    okos_conf_set_str(ifs->if_name, "ath11");
    okos_conf_set_str(ifs->bssid, "00:55:AA:E7:38:29");

    okos_conf_set_int(ssid, sn, 2);
    okos_conf_set_str(ssid->ssid, "oakridge_test_2");
    okos_conf_set_str(ssid->br_name, "br-lan1");
    okos_conf_set_str(ssid->scheme_name, "1");

    authsvrs = okos_conf_append_list_member(ssid->auth_servers);
    okos_config_init_default_auth_server(authsvrs);
    okos_conf_set_str(authsvrs->authserv_hostname, "139.196.188.253");
    okos_conf_set_str(authsvrs->authserv_path, "/auth/device/");

    trusted_mac = okos_conf_append_list_member(ssid->mac_white_list);
    okos_conf_set_str(trusted_mac->mac, "00:61:71:83:25:7B"); 
    trusted_mac = okos_conf_append_list_member(trusted_mac);
    okos_conf_set_str(trusted_mac->mac, "f4:0f:24:26:b1:59"); 

    dn_white_list = okos_conf_append_list_member(ssid->dn_white_list);
    okos_conf_set_str(dn_white_list->name, "dn white list");
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "oakridge.io");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "apple.com.cn");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "apple.com");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);

    ip_set = okos_conf_append_list_member(ssid->ip_white_list);
    okos_conf_set_str(ip_set->name, "ip white list");
    ipx = okos_conf_append_list_member(ip_set->rules);
    okos_conf_set_str(ipx->mask, "192.168.0.1");
    okos_conf_set_int(ipx, target, TARGET_ACCEPT);
    ipx = okos_conf_append_list_member(ip_set->rules);
    okos_conf_set_str(ipx->mask, "192.168.100.1");
    okos_conf_set_int(ipx, target, TARGET_ACCEPT);

    
    // Third ssid 
    ssid = okos_conf_append_list_member(my_config->ssid_conf);
    ssid->brx = brX;
    ifs = okos_conf_append_list_member(ssid->if_list);
    ifs->ssid = ssid;
    ifs->brx = brX;
    brX->ifx[4] = ifs;
    okos_conf_set_str(ifs->if_name, "ath12");
    okos_conf_set_str(ifs->bssid, "00:55:AA:E7:38:29");

    okos_conf_set_int(ssid, sn, 3);
    okos_conf_set_str(ssid->ssid, "oakridge_test_3");
    okos_conf_set_str(ssid->br_name, "br-lan1");
    okos_conf_set_str(ssid->scheme_name, "1");

    authsvrs = okos_conf_append_list_member(ssid->auth_servers);
    okos_config_init_default_auth_server(authsvrs);
    okos_conf_set_str(authsvrs->authserv_hostname, "139.196.188.253");
    okos_conf_set_str(authsvrs->authserv_path, "/auth/device/");

    trusted_mac = okos_conf_append_list_member(ssid->mac_white_list);
    okos_conf_set_str(trusted_mac->mac, "f4:0f:24:26:b1:59"); 

    dn_white_list = okos_conf_append_list_member(ssid->dn_white_list);
    okos_conf_set_str(dn_white_list->name, "dn white list");
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "ctrip.com");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);
    dns = okos_conf_append_list_member(dn_white_list->rules);
    okos_conf_set_str(dns->mask, "dianping.com");
    okos_conf_set_int(dns, target, TARGET_ACCEPT);

    ip_set = okos_conf_append_list_member(ssid->ip_white_list);
    okos_conf_set_str(ip_set->name, "ip white list");
    ipx = okos_conf_append_list_member(ip_set->rules);
    okos_conf_set_str(ipx->mask, "192.168.0.1");
    okos_conf_set_int(ipx, target, TARGET_ACCEPT);

}
#endif



t_ssid_config *
okos_conf_get_ssid_by_name(
        const char *name
        )
{
    if (NULL == name)
        return NULL;

    t_ssid_config *ssid;
    okos_list_for_each(ssid, config.ssid_conf) {
        if (0 == strcmp(ssid->ssid, name)) {
            return ssid;
        }
    }
    return NULL;
}

t_ath_if_list *
okos_conf_get_ifx_by_name(
        const char *name
        )
{
    if (NULL == name)
        return NULL;

    t_ssid_config *ssid;
    okos_list_for_each(ssid, config.ssid_conf) {
        t_ath_if_list *ifx;
        okos_list_for_each(ifx, ssid->if_list) {
            if (0 == strcmp(ifx->if_name, name)) {
                return ifx;
            }
        }
    }
    return NULL;
}

#define OKOS_CONF_GET_STR(element) (element ? element : "NULL")
#define OKOS_CONF_APP_INT(msg, num) pstr_append_sprintf(p_str, "%s: %d\n", msg, num)
#define OKOS_CONF_APP_STR(msg, str) pstr_append_sprintf(p_str, "%s: %s\n", msg, OKOS_CONF_GET_STR(str))

static char *
okos_conf_parse_target(
        int target
        )
{
    switch(target) {
        case TARGET_DROP:
            return "DROP";
        case TARGET_REJECT:
            return "REJECT";
        case TARGET_ACCEPT:
            return "ACCEPT";
        case TARGET_LOG:
            return "LOG";
        case TARGET_ULOG:
            return "ULOG";
        default:
            return "UNKNOWN";
    }
}

static void
okos_conf_get_firewall(
        pstr_t * p_str,
        t_firewall_rule *p_head
        )
{
    t_firewall_rule *p_rule;
    okos_list_for_each(p_rule, p_head) {
#if 0
        OKOS_CONF_APP_STR("  Mask", p_rule->mask);
        OKOS_CONF_APP_STR("  Port", p_rule->port);
        OKOS_CONF_APP_STR("  Protocol", p_rule->protocol);
        OKOS_CONF_APP_STR("  Target", okos_conf_parse_target(p_rule->target));
#endif
        pstr_append_sprintf(p_str, "  {Mask = %s, Port = %s, Protocol = %s, Target = %s}\n",
                OKOS_CONF_GET_STR(p_rule->mask), OKOS_CONF_GET_STR(p_rule->port),
                OKOS_CONF_GET_STR(p_rule->protocol), OKOS_CONF_GET_STR(okos_conf_parse_target(p_rule->target)));

        pstr_append_sprintf(p_str, "  --Mask %s IP Set.\n", p_rule->mask_is_ipset ? "is" : "isn't");
    }
}

char *
okos_conf_get_all(void)
{
    pstr_t *p_str = pstr_new();
    pstr_cat(p_str, "\n+---------------------------+");
    pstr_cat(p_str, "\n| OKOS Portal Configuration |");
    pstr_cat(p_str, "\n+---------------------------+\n");

    LOCK_CONFIG();

    pstr_cat(p_str, ">>>>Internal file section<<<<\n");
    OKOS_CONF_APP_STR("Configuation file", config.configfile);
    OKOS_CONF_APP_STR("Html message file", config.htmlmsgfile);
    OKOS_CONF_APP_STR("WDCTL socket file", config.wdctl_sock);
    OKOS_CONF_APP_STR("Internal socket file", config.internal_sock);
    OKOS_CONF_APP_STR("PID file", config.pidfile);
    
    pstr_cat(p_str, ">>>>Gateway section<<<<\n");
    OKOS_CONF_APP_INT("Delta traffic", config.deltatraffic);
    pstr_append_sprintf(p_str, "The program is %s a daemon\n", config.daemon ? "" : "not");
    OKOS_CONF_APP_STR("External interface", config.external_interface);
    OKOS_CONF_APP_STR("Gateway ID", config.gw_id);
    OKOS_CONF_APP_STR("Gateway Interface", config.gw_interface);
    OKOS_CONF_APP_STR("Gateway address", config.gw_address);
    OKOS_CONF_APP_INT("Gateway port", config.gw_port);

    pstr_cat(p_str, ">>>>Httpd section<<<<\n");
    OKOS_CONF_APP_STR("Httpd Name", config.httpdname);
    OKOS_CONF_APP_INT("Httpd Max Connections", config.httpdmaxconn);
    OKOS_CONF_APP_STR("Httpd realm", config.httpdrealm);
    OKOS_CONF_APP_STR("Httpd user name", config.httpdusername);
    OKOS_CONF_APP_STR("Httpd password", config.httpdpassword);

    pstr_cat(p_str, ">>>>Client Control Section<<<<\n");
    OKOS_CONF_APP_INT("Client timeout", config.clienttimeout);
    OKOS_CONF_APP_INT("Check Interval", config.checkinterval);
    OKOS_CONF_APP_INT("Limit Rate", config.limit_rate);
    OKOS_CONF_APP_INT("Limit Burst", config.limit_burst);

    OKOS_CONF_APP_INT("Proxy Port", config.proxy_port);
    OKOS_CONF_APP_STR("ARP table path", config.arp_table_path);
    
    pstr_cat(p_str, ">>>>SSL section<<<<\n");
    OKOS_CONF_APP_INT("SSL verify", config.ssl_verify);
    OKOS_CONF_APP_INT("SSL use sni", config.ssl_use_sni);
    OKOS_CONF_APP_STR("SSL certs", config.ssl_certs);
    OKOS_CONF_APP_STR("SSL cipher list", config.ssl_cipher_list);

    pstr_cat(p_str, ">>>>Firewall Rules Section<<<<\n");
    t_firewall_ruleset *p_fw;
    okos_list_for_each(p_fw, config.rulesets) {
        OKOS_CONF_APP_STR("@@@@", p_fw->name);
        okos_conf_get_firewall(p_str, p_fw->rules);
    }

    pstr_cat(p_str, ">>>>Trusted MAC list Section<<<<\n");
    t_trusted_mac *p_trusted_mac;
    okos_list_for_each(p_trusted_mac, config.trustedmaclist) {
        OKOS_CONF_APP_STR("  MAC", p_trusted_mac->mac);
    }


    pstr_cat(p_str, ">>>>Popular Servers Section<<<<\n");
    t_popular_server *p_ps;
    okos_list_for_each(p_ps, config.popular_servers) {
        OKOS_CONF_APP_STR("  Host Name", p_ps->hostname);
    }

    pstr_cat(p_str, "\n\n>>>> Configuration section <<<<\n");
    OKOS_CONF_APP_STR("Device ID", config.device_id);
    OKOS_CONF_APP_STR("Domain Name", config.domain_name);
    pstr_cat(p_str, ">>>> SSID Configuration <<<<\n");
    t_ssid_config *p_ssid;
    okos_list_for_each(p_ssid, config.ssid_conf) {
        pstr_cat(p_str, "----------------------------\n");
        OKOS_CONF_APP_INT("  sn", p_ssid->sn);
        OKOS_CONF_APP_STR("  SSID", p_ssid->ssid);
        OKOS_CONF_APP_STR("  Scheme", p_ssid->scheme_name);
        pstr_cat(p_str, ">>Interfaces attched to this SSID<<\n");
        t_ath_if_list *p_if;
        okos_list_for_each(p_if, p_ssid->if_list) {
            OKOS_CONF_APP_STR("  Interface Name", p_if->if_name);
            OKOS_CONF_APP_STR("  BSSID", p_if->bssid);
        }
        pstr_cat(p_str, ">>Authentication Server<<\n");
        t_auth_serv *p_svr;
        okos_list_for_each(p_svr, p_ssid->auth_servers) {
            OKOS_CONF_APP_STR("  Host Name", p_svr->authserv_hostname);
            OKOS_CONF_APP_STR("  Path", p_svr->authserv_path);
            OKOS_CONF_APP_STR("  Login script path", p_svr->authserv_login_script_path_fragment);
            OKOS_CONF_APP_STR("  Portal script path", p_svr->authserv_portal_script_path_fragment);
            OKOS_CONF_APP_STR("  Msg script path", p_svr->authserv_msg_script_path_fragment);
            OKOS_CONF_APP_STR("  Ping script path", p_svr->authserv_ping_script_path_fragment);
            OKOS_CONF_APP_STR("  Auth script path", p_svr->authserv_auth_script_path_fragment);
            OKOS_CONF_APP_INT("  Http port", p_svr->authserv_http_port);
            OKOS_CONF_APP_INT("  SSL port", p_svr->authserv_ssl_port);
            pstr_append_sprintf(p_str, "  SSL %s\n", p_svr->authserv_use_ssl ? "Enabled" : "Disabled");
        }
        OKOS_CONF_APP_STR("@", p_ssid->dn_white_list->name);
        okos_conf_get_firewall(p_str, p_ssid->dn_white_list->rules);
        OKOS_CONF_APP_STR("@", p_ssid->ip_white_list->name);
        okos_conf_get_firewall(p_str, p_ssid->ip_white_list->rules);
        pstr_cat(p_str, ">>MAC address white list<<\n");
        t_trusted_mac *p_mac;
        okos_list_for_each(p_mac, p_ssid->mac_white_list) {
            OKOS_CONF_APP_STR("  MAC", p_mac->mac);
        }
    }

    pstr_cat(p_str, "\n\n>>>>Debug Section<<<<\n");
    pstr_cat(p_str, ">>>>System<<<<\n");
    OKOS_CONF_APP_INT("  System Start Time", started_time);
    OKOS_CONF_APP_INT("  System Current Time", time(NULL));

    pstr_cat(p_str, ">>>>Web Server<<<<\n");
    if (NULL == webserver) {
        pstr_cat(p_str, "Fatal Error, No Web Server here right now.\n");
    } else {
        OKOS_CONF_APP_STR("  Host", webserver->host);
        OKOS_CONF_APP_INT("  Port", webserver->port);
        OKOS_CONF_APP_INT("  Server Socket", webserver->serverSock);
        OKOS_CONF_APP_INT("  Start Time", webserver->startTime);
        OKOS_CONF_APP_INT("  Last Error", webserver->lastError);
    }

    pstr_cat(p_str, "========================\n");

    UNLOCK_CONFIG();

    pstr_cat(p_str, "That's all.\n");

    return pstr_to_string(p_str);
}


#endif /* OK_PATCH */
