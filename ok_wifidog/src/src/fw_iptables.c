/* vim: set et ts=4 sts=4 sw=4 : */
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
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

static int iptables_do_command(const char *format, ...);
static char *iptables_compile(const char *, const char *, const t_firewall_rule *);
static void iptables_load_ruleset(const char *, const char *, const char *);

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;




#if OK_PATCH
/* Please don't forget to release the returned buffer. */
static inline char * okos_get_chain_name(const char * prefix, const unsigned int id)
{
    char * chain = NULL;
    safe_asprintf(&chain, prefix, id);
    return chain;
}
#else /* OK_PATCH */
#endif /* OK_PATCH */



/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
static void
iptables_insert_gateway_id(char **input)
{
    char *token;
    const s_config *config;
    char *buffer;
    char *tmp_intf;

    if (strstr(*input, "$ID$") == NULL)
        return;

    while ((token = strstr(*input, "$ID$")) != NULL)
        /* This string may look odd but it's standard POSIX and ISO C */
        memcpy(token, "%1$s", 4);

    config = config_get_config();
    tmp_intf = safe_strdup(config->gw_interface);
    if (strlen(tmp_intf) > CHAIN_NAME_MAX_LEN) {
        *(tmp_intf + CHAIN_NAME_MAX_LEN) = '\0';
    }
    safe_asprintf(&buffer, *input, tmp_intf);

    free(tmp_intf);
    free(*input);  /* Not an error, input from safe_asprintf */
    *input = buffer;
}

/** @internal 
 * */
static int
iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

    debug(LOG_DEBUG, "__Executing command: %s", cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "__!! iptables command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "__!! iptables command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
iptables_compile(const char *table, const char *chain, const t_firewall_rule * rule)
{
    char command[MAX_BUF], *mode;

    memset(command, 0, MAX_BUF);
    mode = NULL;

    switch (rule->target) {
    case TARGET_DROP:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("DROP");
        break;
    case TARGET_REJECT:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("REJECT");
        break;
    case TARGET_ACCEPT:
        mode = safe_strdup("ACCEPT");
        break;
    case TARGET_LOG:
        mode = safe_strdup("LOG");
        break;
    case TARGET_ULOG:
        mode = safe_strdup("ULOG");
        break;
    }

    snprintf(command, sizeof(command), "-t %s -A %s ", table, chain);
    if (rule->mask != NULL) {
        if (rule->mask_is_ipset) {
            snprintf((command + strlen(command)), (sizeof(command) -
                                                   strlen(command)), "-m set --match-set %s dst ", rule->mask);
        } else {
            snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-d %s ", rule->mask);
        }
    }
    if (rule->protocol != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-p %s ", rule->protocol);
    }
    if (rule->port != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "--dport %s ", rule->port);
    }
    snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-j %s", mode);

    free(mode);

    /* XXX The buffer command, an automatic variable, will get cleaned
     * off of the stack when we return, so we strdup() it. */
    return (safe_strdup(command));
}

#if OK_PATCH

static void
iptables_push_ruleset(const char * table, const t_firewall_ruleset * ruleset, const char * format, ...)
{
    va_list vlist;
    char * chain;

    va_start(vlist, format);
    safe_vasprintf(&chain, format, vlist);
    va_end(vlist);


    debug(LOG_DEBUG, "Push ruleset %s into table %s, chain %s", ruleset->name, table, chain);

    char * cmd;
    t_firewall_rule * rule;
    okos_list_for_each(rule, ruleset->rules) {
        cmd = iptables_compile(table, chain, rule);
        if (cmd != NULL) {
            debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
            iptables_do_command(cmd);
        }
        free(cmd);
    }

    debug(LOG_DEBUG, "Ruleset %s pushed into table %s, chain %s", ruleset->name, table, chain);

    free(chain);
}

#endif /* OK_PATCH */

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
static void
iptables_load_ruleset(const char *table, const char *ruleset, const char *chain)
{
    t_firewall_rule *rule;
    char *cmd;

    debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);

    for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
        cmd = iptables_compile(table, chain, rule);
        if (cmd != NULL) {
            debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
            iptables_do_command(cmd);
        }
        free(cmd);
    }

    debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

/* OK_PATCH
 * MUTEX of config Must be holded outside.
 * This pair of functions of authserver only be called when connect_auth_server().
 * the config has been locked. Feel free to use config->xxx
 */
#if OK_PATCH

void
iptables_fw_clear_authservers(const t_ssid_config * ssid)
{
    //char * chain = okos_get_chain_name(CHAIN_AUTHSERVERS_i, ssid->sn);

    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS_i, ssid->sn);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS_i, ssid->sn);

    //free(chain);
}

void
iptables_fw_set_authservers(const t_ssid_config * ssid)
{
    //char * chain = okos_get_chain_name(CHAIN_AUTHSERVERS_i, ssid->sn);

    t_auth_serv *auth_server;
    okos_list_for_each(auth_server, ssid->auth_servers){
        if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
            iptables_do_command("-t filter -A " CHAIN_AUTHSERVERS_i " -d %s -j ACCEPT", ssid->sn, auth_server->last_ip);
#if 0
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS_i " -d %s -m limit --limit %d --limit-burst %d -j ACCEPT", ssid->sn, auth_server->last_ip, p_cfg->limit_rate, p_cfg->limit_burst);
#endif 
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS_i " -d %s -j ACCEPT", ssid->sn, auth_server->last_ip);
        }
    }

    //free(chain);
}
#else
void
iptables_fw_clear_authservers(void)
{
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
    const s_config *config;
    t_auth_serv *auth_server;

    config = config_get_config();

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
        if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
            iptables_do_command("-t filter -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
        }
    }

}
#endif

/** Initialize the firewall rules
*/
#if OK_PATCH
int
iptables_fw_init(void)
{
    const s_config *config;
    fw_quiet = 0;
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;

    LOCK_CONFIG();
    config = config_get_config();
    int proxy_port = config->proxy_port;
    int sn;

    iptables_do_command("-t nat -N " CHAIN_GLOBAL);

    iptables_do_command("-t filter -N " CHAIN_LOCKED);
    iptables_do_command("-t filter -N " CHAIN_GLOBAL);
    iptables_do_command("-t filter -N " CHAIN_VALIDATE);
    iptables_do_command("-t filter -N " CHAIN_KNOWN);
    iptables_do_command("-t filter -N " CHAIN_UNKNOWN);

    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -N " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t filter -N " CHAIN_AUTH_IS_DOWN);

        iptables_do_command("-t nat -A " CHAIN_AUTH_IS_DOWN " -m mark --mark 0x%u -j ACCEPT", FW_MARK_AUTH_IS_DOWN);
        iptables_load_ruleset("filter", FWRULESET_AUTH_IS_DOWN, CHAIN_AUTH_IS_DOWN);
    }

    t_ssid_config * ssid;
    okos_list_for_each(ssid, config->ssid) {
        sn = ssid->sn;

        /* Create new chains */
        /* For mangle table */
        iptables_do_command("-t mangle -N " CHAIN_TRUSTED_i, sn);
        iptables_do_command("-t mangle -N " CHAIN_OUTGOING_i, sn);
        //iptables_do_command("-t mangle -N " CHAIN_INCOMING_i, sn); 
        if (got_authdown_ruleset) {
            iptables_do_command("-t mangle -N " CHAIN_AUTH_IS_DOWN_i, sn);
        }

        /* For nat table */
        iptables_do_command("-t nat -N " CHAIN_OUTGOING_i, sn);
        iptables_do_command("-t nat -N " CHAIN_TO_ROUTER_i, sn);
        iptables_do_command("-t nat -N " CHAIN_TO_INTERNET_i, sn);
        iptables_do_command("-t nat -N " CHAIN_DN_ALLOWED_i, sn);
        iptables_do_command("-t nat -N " CHAIN_IP_ALLOWED_i, sn);
        iptables_do_command("-t nat -N " CHAIN_UNKNOWN_i, sn);
        iptables_do_command("-t nat -N " CHAIN_AUTHSERVERS_i, sn);

        /* For filter table */
        iptables_do_command("-t filter -N " CHAIN_TO_INTERNET_i, sn);
        iptables_do_command("-t filter -N " CHAIN_AUTHSERVERS_i, sn);
        iptables_do_command("-t filter -N " CHAIN_DN_ALLOWED_i, sn);
        iptables_do_command("-t filter -N " CHAIN_IP_ALLOWED_i, sn);

        /* Assign links and rules to these new chains */
        t_ath_if_list * ath_if;
        okos_list_for_each(ath_if, ssid->if_list) {
            char * if_name = ath_if->if_name;

            /* For mangle table.
             * Be careful!!!: The rules below are NOT appented after prior one,
             * but inserted into the head of chain.
             */
            iptables_do_command("-t mangle -I PREROUTING 1 -m physdev --physdev-in %s -j " CHAIN_OUTGOING_i, if_name, sn);
            iptables_do_command("-t mangle -I PREROUTING 1 -m physdev --physdev-in %s -j " CHAIN_TRUSTED_i, if_name, sn);
            if (got_authdown_ruleset) {   //this rule must be last in the chain
                iptables_do_command("-t mangle -I PREROUTING 1 -m physdev --physdev-in %s -j " CHAIN_AUTH_IS_DOWN_i, if_name, sn);
            }
            //iptables_do_command("-t mangle -I POSTROUTING 1 -m physdev --physdev-out %s -j " CHAIN_INCOMING_i, if_name, sn);

            /* For nat table */
            iptables_do_command("-t nat -A PREROUTING -m physdev --physdev-in %s -j " CHAIN_OUTGOING_i, if_name, sn);

            /* For filter table */
            iptables_do_command("-t filter -I FORWARD -m physdev --physdev-in %s -j " CHAIN_TO_INTERNET_i, if_name, sn);
        }

        /* For mangle table */
        t_trusted_mac * trusted_mac;
        okos_list_for_each(trusted_mac, ssid->mac_white_list) {
            iptables_do_command("-t mangle -A " CHAIN_TRUSTED_i " -m mac --mac-source %s -j MARK --set-mark %d", sn, trusted_mac->mac, FW_MARK_KNOWN);
        }

        /* For nat table */
        /* FIXME : should use ip of brX to replace gw_address here. */
        iptables_do_command("-t nat -A " CHAIN_OUTGOING_i " -j " CHAIN_TO_ROUTER_i, sn, sn);
        //ptables_do_command("-t nat -A " CHAIN_TO_ROUTER_i " -d %s -j ACCEPT", sn, );
        iptables_do_command("-t nat -A " CHAIN_OUTGOING_i " -j " CHAIN_TO_INTERNET_i, sn, sn);
        if (proxy_port != 0) {
            debug(LOG_DEBUG, "Proxy port set, setting proxy rule");
            iptables_do_command("-t nat -A " CHAIN_TO_INTERNET_i " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", sn, FW_MARK_KNOWN, proxy_port);
            iptables_do_command("-t nat -A " CHAIN_TO_INTERNET_i " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", sn, FW_MARK_PROBATION, proxy_port);
        }
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET_i " -d 10.10.111.111 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports %d", sn, config->gw_port);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET_i " -m mark --mark 0x%u -j ACCEPT", sn, FW_MARK_KNOWN);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET_i " -m mark --mark 0x%u -j ACCEPT", sn, FW_MARK_PROBATION);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET_i " -j " CHAIN_UNKNOWN_i, sn, sn);

        iptables_do_command("-t nat -A " CHAIN_UNKNOWN_i " -j " CHAIN_AUTHSERVERS_i, sn, sn);
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN_i " -j " CHAIN_GLOBAL, sn);
        if (got_authdown_ruleset) {
            iptables_do_command("-t nat -A " CHAIN_UNKNOWN_i " -j " CHAIN_AUTH_IS_DOWN, sn);
        }

        iptables_do_command("-t nat -A " CHAIN_UNKNOWN_i " -j " CHAIN_DN_ALLOWED_i, sn, sn);
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN_i " -j " CHAIN_IP_ALLOWED_i, sn, sn);
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN_i " -p tcp --dport 80 -j REDIRECT --to-ports %d", sn, config->gw_port);

        /* For filter table */
        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -m state --state INVALID -j DROP", sn);

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -j " CHAIN_AUTHSERVERS_i, sn, sn);
        /* FIXME
        iptables_fw_set_authservers();
        */
        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -m mark --mark 0x%u -j " CHAIN_LOCKED, sn, FW_MARK_LOCKED);

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -j " CHAIN_GLOBAL, sn);

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -m mark --mark 0x%u -j " CHAIN_VALIDATE, sn, FW_MARK_PROBATION);

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -m mark --mark 0x%u -j " CHAIN_KNOWN, sn, FW_MARK_KNOWN);

        if (got_authdown_ruleset) {
            iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -m mark --mark 0x%u -j " CHAIN_AUTH_IS_DOWN,
                    sn, FW_MARK_AUTH_IS_DOWN);
        }

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -j " CHAIN_DN_ALLOWED_i, sn, sn);
        iptables_push_ruleset("filter", ssid->dn_white_list, CHAIN_DN_ALLOWED_i, sn);
        iptables_push_ruleset("nat", ssid->dn_white_list, CHAIN_DN_ALLOWED_i, sn);

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -j " CHAIN_IP_ALLOWED_i, sn, sn);
        iptables_push_ruleset("filter", ssid->ip_white_list, CHAIN_IP_ALLOWED_i, sn);
        iptables_push_ruleset("nat", ssid->ip_white_list, CHAIN_IP_ALLOWED_i, sn);

        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET_i " -j " CHAIN_UNKNOWN, sn);

    }

    iptables_load_ruleset("nat", FWRULESET_GLOBAL, CHAIN_GLOBAL);
    iptables_load_ruleset("filter", FWRULESET_GLOBAL, CHAIN_GLOBAL);

    iptables_load_ruleset("filter", FWRULESET_LOCKED_USERS, CHAIN_LOCKED);
    iptables_load_ruleset("filter", FWRULESET_VALIDATING_USERS, CHAIN_VALIDATE);
    iptables_load_ruleset("filter", FWRULESET_KNOWN_USERS, CHAIN_KNOWN);
    iptables_load_ruleset("filter", FWRULESET_UNKNOWN_USERS, CHAIN_UNKNOWN);
    iptables_do_command("-t filter -A " CHAIN_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

    UNLOCK_CONFIG();

    return 1;
}
#else /* OK_PATCH */
int
iptables_fw_init(void)
{
    const s_config *config;
    char *ext_interface = NULL;
    int gw_port = 0;
    t_trusted_mac *p;
    int proxy_port;
    fw_quiet = 0;
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;

    LOCK_CONFIG();
    config = config_get_config();
    gw_port = config->gw_port;
    if (config->external_interface) {
        ext_interface = safe_strdup(config->external_interface);
    } else {
        ext_interface = get_ext_iface();
    }

    if (ext_interface == NULL) {
        UNLOCK_CONFIG();
        debug(LOG_ERR, "FATAL: no external interface");
        return 0;
    }
    /*
     *
     * Everything in the MANGLE table
     *
     */

    /* Create new chains */
    iptables_do_command("-t mangle -N " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -N " CHAIN_OUTGOING);
    iptables_do_command("-t mangle -N " CHAIN_INCOMING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_OUTGOING, config->gw_interface);
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_TRUSTED, config->gw_interface);     //this rule will be inserted before the prior one
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_AUTH_IS_DOWN, config->gw_interface);    //this rule must be last in the chain
    iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " CHAIN_INCOMING, config->gw_interface);

    for (p = config->trustedmaclist; p != NULL; p = p->next)
        iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->mac,
                            FW_MARK_KNOWN);

    /*
     *
     * Everything in the NAT table
     *
     */

    /* Create new chains */
    iptables_do_command("-t nat -N " CHAIN_OUTGOING);
    iptables_do_command("-t nat -N " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -N " CHAIN_GLOBAL);
    iptables_do_command("-t nat -N " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -N " CHAIN_AUTHSERVERS);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
    iptables_do_command("-t nat -A PREROUTING -i %s -j " CHAIN_OUTGOING, config->gw_interface);

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -d %s -j " CHAIN_TO_ROUTER, config->gw_address);
    iptables_do_command("-t nat -A " CHAIN_TO_ROUTER " -j ACCEPT");

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_TO_INTERNET);

    if ((proxy_port = config_get_config()->proxy_port) != 0) {
        debug(LOG_DEBUG, "Proxy port set, setting proxy rule");
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_KNOWN,
                            proxy_port);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_PROBATION,
                            proxy_port);
    }

    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_KNOWN);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_PROBATION);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);

    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_GLOBAL);
    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t nat -A " CHAIN_AUTH_IS_DOWN " -m mark --mark 0x%u -j ACCEPT", FW_MARK_AUTH_IS_DOWN);
    }
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);

    /*
     *
     * Everything in the FILTER table
     *
     */

    /* Create new chains */
    iptables_do_command("-t filter -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -N " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -N " CHAIN_LOCKED);
    iptables_do_command("-t filter -N " CHAIN_GLOBAL);
    iptables_do_command("-t filter -N " CHAIN_VALIDATE);
    iptables_do_command("-t filter -N " CHAIN_KNOWN);
    iptables_do_command("-t filter -N " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */

    /* Insert at the beginning */
    iptables_do_command("-t filter -I FORWARD -i %s -j " CHAIN_TO_INTERNET, config->gw_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state INVALID -j DROP");

    /* XXX: Why this? it means that connections setup after authentication
       stay open even after the connection is done... 
       iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT"); */

    //Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
    //iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);

    /* TCPMSS rule for PPPoE */
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET
                        " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_AUTHSERVERS);
    iptables_fw_set_authservers();

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_LOCKED, FW_MARK_LOCKED);
    iptables_load_ruleset("filter", FWRULESET_LOCKED_USERS, CHAIN_LOCKED);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_GLOBAL);
    iptables_load_ruleset("filter", FWRULESET_GLOBAL, CHAIN_GLOBAL);
    iptables_load_ruleset("nat", FWRULESET_GLOBAL, CHAIN_GLOBAL);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_VALIDATE, FW_MARK_PROBATION);
    iptables_load_ruleset("filter", FWRULESET_VALIDATING_USERS, CHAIN_VALIDATE);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_KNOWN, FW_MARK_KNOWN);
    iptables_load_ruleset("filter", FWRULESET_KNOWN_USERS, CHAIN_KNOWN);

    if (got_authdown_ruleset) {
        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_AUTH_IS_DOWN,
                            FW_MARK_AUTH_IS_DOWN);
        iptables_load_ruleset("filter", FWRULESET_AUTH_IS_DOWN, CHAIN_AUTH_IS_DOWN);
    }

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);
    iptables_load_ruleset("filter", FWRULESET_UNKNOWN_USERS, CHAIN_UNKNOWN);
    iptables_do_command("-t filter -A " CHAIN_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

    UNLOCK_CONFIG();

    free(ext_interface);
    return 1;
}
#endif /* OK_PATCH */

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
#if OK_PATCH
int
iptables_fw_destroy(void)
{
    const s_config *config;
    config = config_get_config();
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    fw_quiet = 1;

    debug(LOG_DEBUG, "Destroying our iptables entries");

    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_AUTH_IS_DOWN);
    iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);

    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);

    iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET);
    

    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -F " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t filter -F " CHAIN_AUTH_IS_DOWN);
    }
    iptables_do_command("-t nat -F " CHAIN_GLOBAL);
    
    iptables_do_command("-t filter -F " CHAIN_LOCKED);
    iptables_do_command("-t filter -F " CHAIN_GLOBAL);
    iptables_do_command("-t filter -F " CHAIN_VALIDATE);
    iptables_do_command("-t filter -F " CHAIN_KNOWN);
    iptables_do_command("-t filter -F " CHAIN_UNKNOWN);

    LOCK_CONFIG();

    int sn;
    t_ssid_config * ssid;
    okos_list_for_each(ssid, config->ssid) {
        sn = ssid->sn;

        /*
         *
         * Everything in the MANGLE table
         *
         */
        debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
        iptables_do_command("-t mangle -F " CHAIN_TRUSTED_i, sn);
        iptables_do_command("-t mangle -F " CHAIN_OUTGOING_i, sn);
        if (got_authdown_ruleset)
            iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN_i, sn);
        //iptables_do_command("-t mangle -F " CHAIN_INCOMING_i, sn);
        iptables_do_command("-t mangle -X " CHAIN_TRUSTED_i, sn);
        iptables_do_command("-t mangle -X " CHAIN_OUTGOING_i, sn);
        if (got_authdown_ruleset)
            iptables_do_command("-t mangle -X " CHAIN_AUTH_IS_DOWN_i, sn);
        //iptables_do_command("-t mangle -X " CHAIN_INCOMING_i, sn);

        /*
         *
         * Everything in the NAT table
         *
         */
        debug(LOG_DEBUG, "Destroying chains in the NAT table");
        iptables_do_command("-t nat -F " CHAIN_DN_ALLOWED_i, sn);
        iptables_do_command("-t nat -F " CHAIN_IP_ALLOWED_i, sn);
        iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS_i, sn);
        iptables_do_command("-t nat -F " CHAIN_OUTGOING_i, sn);
        iptables_do_command("-t nat -F " CHAIN_TO_ROUTER_i, sn);
        iptables_do_command("-t nat -F " CHAIN_TO_INTERNET_i, sn);
        iptables_do_command("-t nat -F " CHAIN_UNKNOWN_i, sn);
        iptables_do_command("-t nat -X " CHAIN_DN_ALLOWED_i, sn);
        iptables_do_command("-t nat -X " CHAIN_IP_ALLOWED_i, sn);
        iptables_do_command("-t nat -X " CHAIN_AUTHSERVERS_i, sn);
        iptables_do_command("-t nat -X " CHAIN_OUTGOING_i, sn);
        iptables_do_command("-t nat -X " CHAIN_TO_ROUTER_i, sn);
        iptables_do_command("-t nat -X " CHAIN_TO_INTERNET_i, sn);
        iptables_do_command("-t nat -X " CHAIN_UNKNOWN_i, sn);

        /*
         *
         * Everything in the FILTER table
         *
         */
        debug(LOG_DEBUG, "Destroying chains in the FILTER table");
        iptables_do_command("-t filter -F " CHAIN_TO_INTERNET_i, sn);
        iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS_i, sn);
        iptables_do_command("-t filter -F " CHAIN_DN_ALLOWED_i, sn);
        iptables_do_command("-t filter -F " CHAIN_IP_ALLOWED_i, sn);
        iptables_do_command("-t filter -X " CHAIN_TO_INTERNET_i, sn);
        iptables_do_command("-t filter -X " CHAIN_AUTHSERVERS_i, sn);
        iptables_do_command("-t filter -X " CHAIN_DN_ALLOWED_i, sn);
        iptables_do_command("-t filter -X " CHAIN_IP_ALLOWED_i, sn);

    }

    UNLOCK_CONFIG();

    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -X " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t filter -X " CHAIN_AUTH_IS_DOWN);
    }
    iptables_do_command("-t nat -X " CHAIN_GLOBAL);

    iptables_do_command("-t filter -X " CHAIN_LOCKED);
    iptables_do_command("-t filter -X " CHAIN_GLOBAL);
    iptables_do_command("-t filter -X " CHAIN_VALIDATE);
    iptables_do_command("-t filter -X " CHAIN_KNOWN);
    iptables_do_command("-t filter -X " CHAIN_UNKNOWN);

    return 1;
}

#else /* OK_PATCH */

int
iptables_fw_destroy(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    fw_quiet = 1;

    debug(LOG_DEBUG, "Destroying our iptables entries");

    /*
     *
     * Everything in the MANGLE table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_AUTH_IS_DOWN);
    iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);
    iptables_do_command("-t mangle -F " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -F " CHAIN_INCOMING);
    iptables_do_command("-t mangle -X " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -X " CHAIN_INCOMING);

    /*
     *
     * Everything in the NAT table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the NAT table");
    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -F " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -F " CHAIN_GLOBAL);
    iptables_do_command("-t nat -F " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -X " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -X " CHAIN_GLOBAL);
    iptables_do_command("-t nat -X " CHAIN_UNKNOWN);

    /*
     *
     * Everything in the FILTER table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the FILTER table");
    iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -F " CHAIN_LOCKED);
    iptables_do_command("-t filter -F " CHAIN_GLOBAL);
    iptables_do_command("-t filter -F " CHAIN_VALIDATE);
    iptables_do_command("-t filter -F " CHAIN_KNOWN);
    iptables_do_command("-t filter -F " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t filter -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -X " CHAIN_LOCKED);
    iptables_do_command("-t filter -X " CHAIN_GLOBAL);
    iptables_do_command("-t filter -X " CHAIN_VALIDATE);
    iptables_do_command("-t filter -X " CHAIN_KNOWN);
    iptables_do_command("-t filter -X " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -X " CHAIN_AUTH_IS_DOWN);

    return 1;
}
#endif /* OK_PATCH */


/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention)
{
    FILE *p = NULL;
    char *command = NULL;
    char *command2 = NULL;
    char line[MAX_BUF];
    char rulenum[10];
    char *victim = safe_strdup(mention);
    int deleted = 0;

    iptables_insert_gateway_id(&victim);

    debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

    safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
    iptables_insert_gateway_id(&command);

    if ((p = popen(command, "r"))) {
        /* Skip first 2 lines */
        while (!feof(p) && fgetc(p) != '\n') ;
        while (!feof(p) && fgetc(p) != '\n') ;
        /* Loop over entries */
        while (fgets(line, sizeof(line), p)) {
            /* Look for victim */
            if (strstr(line, victim)) {
                /* Found victim - Get the rule number into rulenum */
                if (sscanf(line, "%9[0-9]", rulenum) == 1) {
                    /* Delete the rule: */
                    debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain,
                          victim);
                    safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
                    iptables_do_command(command2);
                    free(command2);
                    deleted = 1;
                    /* Do not keep looping - the captured rulenums will no longer be accurate */
                    break;
                }
            }
        }
        pclose(p);
    }

    free(command);
    free(victim);

    if (deleted) {
        /* Recurse just in case there are more in the same table+chain */
        iptables_fw_destroy_mention(table, chain, mention);
    }

    return (deleted);
}

/** Set if a specific client has access through the firewall */
#if OK_PATCH
int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag, const t_ssid_config * ssid)
{
    int rc;

    fw_quiet = 0;

    //char * chain_outgoing = okos_get_chain_name(CHAIN_OUTGOING_i, ssid->sn);

    switch (type) {
    case FW_ACCESS_ALLOW:
        rc = iptables_do_command("-t mangle -A " CHAIN_OUTGOING_i " -m mac --mac-source %s -j MARK --set-mark %d",
                ssid->sn, mac, tag);
        break;
    case FW_ACCESS_DENY:
        /* XXX Add looping to really clear? */
        rc = iptables_do_command("-t mangle -D " CHAIN_OUTGOING_i " -m mac --mac-source %s -j MARK --set-mark %d",
                ssid->sn, mac, tag);
        break;
    default:
        rc = -1;
        break;
    }
    //free(chain_outgoing);

    return rc;
}
#else /* OK_PATCH */
int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
        break;
    case FW_ACCESS_DENY:
        /* XXX Add looping to really clear? */
        iptables_do_command("-t mangle -D " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}
#endif /* OK_PATCH */



#if OK_PATCH
int
iptables_fw_access_host(fw_access_t type, const char *host, const t_ssid_config * ssid)
{
    int rc;

    fw_quiet = 0;

    if (NULL == ssid) {
        switch (type) {
            case FW_ACCESS_ALLOW:
                iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
                rc = iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
                break;
            case FW_ACCESS_DENY:
                iptables_do_command("-t nat -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
                rc = iptables_do_command("-t filter -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
                break;
            default:
                rc = -1;
                break;
        }
    } else {
        switch (type) {
            case FW_ACCESS_ALLOW:
                iptables_do_command("-t nat -A " CHAIN_DN_ALLOWED_i " -d %s -j ACCEPT", ssid->sn, host);
                rc = iptables_do_command("-t filter -A " CHAIN_DN_ALLOWED_i " -d %s -j ACCEPT", ssid->sn, host);
                break;
            case FW_ACCESS_DENY:
                iptables_do_command("-t nat -D " CHAIN_DN_ALLOWED_i " -d %s -j ACCEPT", ssid->sn, host);
                rc = iptables_do_command("-t filter -D " CHAIN_DN_ALLOWED_i " -d %s -j ACCEPT", ssid->sn, host);
                break;
            default:
                rc = -1;
                break;
        }
    }

    return rc;
}
#else /* OK_PATCH */
int
iptables_fw_access_host(fw_access_t type, const char *host)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    case FW_ACCESS_DENY:
        iptables_do_command("-t nat -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}
#endif /* OK_PATCH */

/** Set a mark when auth server is not reachable */
/* FIXME
 * We need multiple chains in mangle table for each ssid. 
 */
int
iptables_fw_auth_unreachable(int tag)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -A " CHAIN_AUTH_IS_DOWN " -j MARK --set-mark 0x%u", tag);
    else
        return 1;
}

/** Remove mark when auth server is reachable again */
int
iptables_fw_auth_reachable(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    else
        return 1;
}

/** Update the counters of all the clients in the client list */
int
iptables_fw_counters_update(void)
{
#if OK_PATCH
#else
    FILE *output;
    char *script, ip[16], rc;
    unsigned long long int counter;
    t_client *p1;
    struct in_addr tempaddr;

    /* Look for outgoing traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_OUTGOING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s %*s", &counter, ip);
        //rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
                    p1->counters.outgoing_delta = p1->counters.outgoing_history + counter - p1->counters.outgoing;
                    p1->counters.outgoing = p1->counters.outgoing_history + counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Outgoing traffic %llu bytes, updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip,
                          counter, p1->counters.outgoing, p1->counters.last_updated);
                }
            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    /* Look for incoming traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_INCOMING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
                    p1->counters.incoming_delta = p1->counters.incoming_history + counter - p1->counters.incoming;
                    p1->counters.incoming = p1->counters.incoming_history + counter;
                    debug(LOG_DEBUG, "%s - Incoming traffic %llu bytes, Updated counter.incoming to %llu bytes", ip, counter, p1->counters.incoming);
                }
            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);
#endif
    return 1;
}
