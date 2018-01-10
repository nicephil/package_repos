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

/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  2006 Benoit Grégoire, Technologies Coeus inc. <bock@step.polymtl.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <netdb.h>
#include <sys/time.h>

#include "httpd.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
#include "commandline.h"

#if OK_PATCH
static int _fw_deny_raw(const char *, const char *, const int, const t_ssid_config *);

int
fw_allow(t_client * client, int new_fw_connection_state)
{
    int result;
    int old_state = client->fw_connection_state;
    t_ssid_config * ssid = client->ssid;
    if (NULL == ssid) {
        debug(LOG_ERR, "  &&!! Can't set iptables allow rule for state %d on ssid unknown for client {ip = %s, mac = %s}", new_fw_connection_state, client->ip, client->mac);
        return -1;
    }

    debug(LOG_DEBUG, "  && Allowing %s %s with fw_connection_state %d on ssid[%s]", client->ip, client->mac, new_fw_connection_state, ssid->ssid);
    client->fw_connection_state = new_fw_connection_state;

    /* Grant first */
    result = iptables_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state, ssid);

    /* Deny after if needed. */
    if (old_state != FW_MARK_NONE) {
        debug(LOG_DEBUG, "  && Clearing previous fw_connection_state %d", old_state);
        _fw_deny_raw(client->ip, client->mac, old_state, ssid);
    }

    return result;
}

int
fw_allow_host(const char *host, const t_ssid_config * ssid)
{
    if (NULL == ssid) {
        debug(LOG_DEBUG, "  && Allowing %s on global whitelist", host);
    } else {
        debug(LOG_DEBUG, "  && Allowing %s on whitelist of  ssid[%s]", host, ssid->ssid);
    }

    return iptables_fw_access_host(FW_ACCESS_ALLOW, host, ssid);
}

int
fw_deny(t_client * client)
{
    int fw_connection_state = client->fw_connection_state;
    t_ssid_config * ssid = client->ssid;
    if (NULL == ssid) {
        debug(LOG_ERR, "  &&!! Can't set iptables deny rule on ssid unknown for client {ip = %s, mac = %s}", client->ip, client->mac);
        return -1;
    }

    debug(LOG_DEBUG, "  && Denying %s %s with fw_connection_state %d on ssid[%s]", client->ip, client->mac, client->fw_connection_state, ssid->ssid);

    client->fw_connection_state = FW_MARK_NONE; /* Clear */
    return _fw_deny_raw(client->ip, client->mac, fw_connection_state, ssid);
}

static int
_fw_deny_raw(const char *ip, const char *mac, const int mark, const t_ssid_config * ssid)
{
    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, mark, ssid);
}

#else /* OK_PATCH */
static int _fw_deny_raw(const char *, const char *, const int);

/**
 * Allow a client access through the firewall by adding a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_allow(t_client * client, int new_fw_connection_state)
{
    int result;
    int old_state = client->fw_connection_state;

    debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", client->ip, client->mac, new_fw_connection_state);
    client->fw_connection_state = new_fw_connection_state;

    /* Grant first */
    result = iptables_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);

    /* Deny after if needed. */
    if (old_state != FW_MARK_NONE) {
        debug(LOG_DEBUG, "Clearing previous fw_connection_state %d", old_state);
        _fw_deny_raw(client->ip, client->mac, old_state);
    }

    return result;
}

/**
 * Allow a host through the firewall by adding a rule in the firewall
 * @param host IP address, domain or hostname to allow
 * @return Return code of the command
 */
int
fw_allow_host(const char *host)
{
    debug(LOG_DEBUG, "Allowing %s", host);

    return iptables_fw_access_host(FW_ACCESS_ALLOW, host);
}

/**
 * @brief Deny a client access through the firewall by removing the rule in the firewall that was fw_connection_stateging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_deny(t_client * client)
{
    int fw_connection_state = client->fw_connection_state;
    debug(LOG_DEBUG, "Denying %s %s with fw_connection_state %d", client->ip, client->mac, client->fw_connection_state);

    client->fw_connection_state = FW_MARK_NONE; /* Clear */
    return _fw_deny_raw(client->ip, client->mac, fw_connection_state);
}

/** @internal
 * Actually does the clearing, so fw_allow can call it to clear previous mark.
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param mark fw_connection_state Tag
 * @return Return code of the command
 */
static int
_fw_deny_raw(const char *ip, const char *mac, const int mark)
{
    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, mark);
}

#endif /* OK_PATCH */


/** Passthrough for clients when auth server is down */
int
fw_set_authdown(void)
{
    debug(LOG_DEBUG, "Marking auth server down");

    return iptables_fw_auth_unreachable(FW_MARK_AUTH_IS_DOWN);
}

/** Remove passthrough for clients when auth server is up */
int
fw_set_authup(void)
{
    debug(LOG_DEBUG, "Marking auth server up again");

    return iptables_fw_auth_reachable();
}


/* XXX DCY */
/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in config->arp_table_path until we find the
 * requested IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char *
arp_get(const char *req_ip)
{
    FILE *proc;
    char ip[16];
    char mac[18];
    char *reply;
    s_config *config = config_get_config();

    if (!(proc = fopen(config->arp_table_path, "r"))) {
        debug(LOG_DEBUG, "<ARP>!! Open ARP table failed for %s", req_ip);
        return NULL;
    }

    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n') ;

    /* Find ip, copy mac in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
        if (strcmp(ip, req_ip) == 0) {
            reply = safe_strdup(mac);
            break;
        }
    }

    fclose(proc);

    debug(LOG_DEBUG, "<ARP>\t Query for (%s) => [%s]", req_ip, reply?reply:"NULL");
    return reply;
}

#if OK_PATCH
int arp_get_all(const char * req_ip, char ** mac, char ** br_dev)
{
    debug(LOG_DEBUG, "I got ip(%s), I want mac and bridge name.", req_ip);

    s_config *config = config_get_config();
    FILE * proc;
    if (!(proc = fopen(config->arp_table_path, "r"))) {
        debug(LOG_ERR, "I can't open ARP file %s", config->arp_table_path);
        return -1;
    }
    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n') ;

    char ip[16];
    char mac_addr[18];
    char brX[256];

    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %s",
                    ip, mac_addr, brX) == 3)) {
        if (strcmp(ip, req_ip) == 0) {
            if (*mac == NULL) {
                *mac = safe_strdup(mac_addr);
            } else if (strcasecmp(*mac, mac_addr)) {
                continue;
            }

            *br_dev = safe_strdup(brX);

            debug(LOG_DEBUG, "Got client [%s] from %s for ip %s", mac_addr, brX, ip);

            fclose(proc);
            return 0;
        }
    }

    fclose(proc);

    debug(LOG_WARNING, "Cant' find information for client (%s) in ARP file.", req_ip);

    return -1;
}

#endif

/** Initialize the firewall rules
 */
int
fw_init(void)
{
    int result = 0;
    int new_fw_state;
    t_client *client = NULL;

    if (!init_icmp_socket()) {
        return 0;
    }

    debug(LOG_INFO, "&& Initializing Firewall");
    result = iptables_fw_init();

    if (restart_orig_pid) {
        debug(LOG_INFO, "&& Restoring firewall rules for clients inherited from parent");
        LOCK_CLIENT_LIST();
        client = client_get_first_client();
        while (client) {
            new_fw_state = client->fw_connection_state;
            client->fw_connection_state = FW_MARK_NONE;
            fw_allow(client, new_fw_state);
            client = client->next;
        }
        UNLOCK_CLIENT_LIST();
    }

    return result;
}

#if OK_PATCH
void
fw_clear_authservers(const t_ssid_config * ssid)
{
    debug(LOG_INFO, "&& Clearing the authservers list on ssid: %s", ssid->ssid);
    iptables_fw_clear_authservers(ssid);
}

void
fw_set_authservers(const t_ssid_config * ssid)
{
    debug(LOG_INFO, "&& Setting the authservers list on ssid: %s", ssid->ssid);
    iptables_fw_set_authservers(ssid);
}
#else /* OK_PATCH */
/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
    debug(LOG_INFO, "&& Clearing the authservers list");
    iptables_fw_clear_authservers();
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
    debug(LOG_INFO, "&& Setting the authservers list");
    iptables_fw_set_authservers();
}
#endif /* OK_PATCH */

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    close_icmp_socket();
    debug(LOG_INFO, "Removing Firewall rules");
    return iptables_fw_destroy();
}

#if 0
time_t
fw_sync_with_authserver(void)
{
    static time_t expired_time = 0;

    time_t current_time = time(NULL) + 1;
    debug(LOG_DEBUG, "<ClientTimeout>: "
            "Start to check client status periodly (%ld). ", current_time);

#if 0
    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
    }
#endif

    s_config *config = config_get_config();
    time_t low_threshold = current_time + config->checkinterval; 
    if (!okos_client_list_should_be_checked() && current_time < expired_time) {
        debug(LOG_DEBUG, "<ClientTimeout>: "
                "No new client and it's too early to expried time.");
        return low_threshold;
    }

    if (okos_client_list_is_empty(NULL)) {
        debug(LOG_DEBUG, "<ClientTimeout>: "
                "The client list is empty. Check it over.");
        return low_threshold; 
    }

    LOCK_CLIENT_LIST();

    /* XXX Ideally, from a thread safety PoV, this function
     * should build a list of client pointers,
     * iterate over the list and have an explicit "client
     * still valid" check while list is locked.
     * That way clients can disappear during the cycle with
     * no risk of trashing the heap or getting
     * a SIGSEGV.
     */
    debug(LOG_DEBUG, "<ClientTimeout>: " 
            "Duplicate the whole client list from a thread safety PoV.");
    t_client *worklist;
    client_list_dup(&worklist);
    UNLOCK_CLIENT_LIST();

    time_t next_timer = current_time + config->checkinterval * config->clienttimeout; 
    time_t this_timer;
    t_client *p1, *p2, *original;
    for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
        p2 = p1->next;
        if (! client_list_polling_flag(p1)) {
            continue;
        }

        debug(LOG_DEBUG, "<ClientTimeout>: "
                "Start to check client {%s, %s}.", p1->mac, p1->ip);

        /* Update the counters on the remote server only if we have an auth server */
        int updateFailed = 1;

#define  OKOS_AUTH_CONFIRM_PERIOD
#ifdef OKOS_AUTH_CONFIRM_PERIOD
        t_authresponse authresponse;
        updateFailed = auth_server_request(&authresponse, p1);
#endif

        this_timer = p1->remain_time + p1->last_flushed;
        
        debug(LOG_DEBUG, "<ClientTimeout>: "
                "Checking client {%s,%s,%s}:  Last flushed %ld (%ld seconds ago),"
                "remain time %ld seconds, current time %ld, %ld seconds left.",
                p1->ip, p1->mac, p1->if_name, p1->last_flushed, current_time - p1->last_flushed,
                p1->remain_time, current_time, this_timer - current_time);

        if (p1->remain_time == 0 || this_timer <= current_time) { //Client is timeout.
            debug(LOG_INFO, "<ClientTimeout>: "
                    "Client {%s, %s, %s} - Inactive, removing client and denying in firewall",
                    p1->ip, p1->mac, p1->if_name);
            
            LOCK_CLIENT_LIST();
            original = client_list_find_by_client(p1);
            if (NULL != original) {
                logout_client(original);
            } else { //client is gone already.
                debug(LOG_DEBUG, "<ClientTimeout>: "
                        "Client {%s, %s, %s} was already removed. Not logging out.",
                        p1->ip, p1->mac, p1->if_name);
            }
            UNLOCK_CLIENT_LIST();

        } else { //Client should be updated.
            debug(LOG_DEBUG, "<ClientTimeout>: "
                    "Client {%s, %s, %s} is still active.",
                    p1->ip, p1->mac, p1->if_name);
            if (this_timer < next_timer) {
                next_timer = this_timer;
            }
            if (!updateFailed) {
                debug(LOG_DEBUG, "<ClientTimeout>: "
                        "Flush Client {%s, %s, %s} remain time:%ld.",
                        p1->ip, p1->mac, p1->if_name, p1->remain_time);

                LOCK_CLIENT_LIST();
                original = client_list_find_by_client(p1);
                if (NULL != original) {
                    okos_client_list_flush(original, p1->remain_time);
                } else { //client is gone already.
                    debug(LOG_DEBUG, "<ClientTimeout>: "
                            "Client{%s, %s, %s} was already removed. Not logging out.",
                            p1->ip, p1->mac, p1->if_name);
                }
                UNLOCK_CLIENT_LIST();
            }
        }
    }
    debug(LOG_DEBUG, "<ClientTimeout>: Destroy the duplicated client list.");
    client_list_destroy(worklist);
    okos_client_list_checked();

    expired_time = next_timer;
    if (next_timer > low_threshold) { // We should come in early to check new client.
        next_timer = low_threshold;
    }

    return next_timer;
}
#endif

time_t
fw_sync_with_authserver(void)
{
    time_t current_time = time(NULL) + 1;
    debug(LOG_DEBUG, "<ClientTimeout>: "
            "Start to check client status periodly (%ld). ", current_time);

#if 0
    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
    }
#endif

    s_config *config = config_get_config();

    time_t next_timer = current_time + config->checkinterval * config->clienttimeout; 
    time_t low_threshold = current_time + config->checkinterval;

    if (okos_client_list_is_empty(NULL)) {
        debug(LOG_DEBUG, "<ClientTimeout>: "
                "The client list is empty. Check it over.");
        return next_timer; 
    }

    LOCK_CLIENT_LIST();

    /* XXX Ideally, from a thread safety PoV, this function
     * should build a list of client pointers,
     * iterate over the list and have an explicit "client
     * still valid" check while list is locked.
     * That way clients can disappear during the cycle with
     * no risk of trashing the heap or getting
     * a SIGSEGV.
     */
    debug(LOG_DEBUG, "<ClientTimeout>: " 
            "Duplicate the whole client list from a thread safety PoV.");
    t_client *worklist;
    client_list_dup(&worklist);
    UNLOCK_CLIENT_LIST();

    time_t this_timer;
    t_client *p1, *p2, *original;
    for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
        p2 = p1->next;
        if (! client_list_polling_flag(p1)) {
            continue;
        }

        debug(LOG_DEBUG, "<ClientTimeout>: "
                "Start to check client {%s, %s}.", p1->mac, p1->ip);

        /* Update the counters on the remote server only if we have an auth server */
        int updateFailed = 1;

//#define  OKOS_AUTH_CONFIRM_PERIOD
#ifdef OKOS_AUTH_CONFIRM_PERIOD
        t_authresponse authresponse;
        updateFailed = auth_server_request(&authresponse, p1);
#endif

        this_timer = p1->remain_time + p1->last_flushed;
        
        debug(LOG_DEBUG, "<ClientTimeout>: "
                "Checking client {%s,%s,%s}:  Last flushed %ld (%ld seconds ago),"
                "remain time %ld seconds, current time %ld, %ld seconds left.",
                p1->ip, p1->mac, p1->if_name, p1->last_flushed, current_time - p1->last_flushed,
                p1->remain_time, current_time, this_timer - current_time);

        if (p1->remain_time == 0 || this_timer <= current_time) { //Client is timeout.
            debug(LOG_INFO, "<ClientTimeout>: "
                    "Client {%s, %s, %s} - Inactive, removing client and denying in firewall",
                    p1->ip, p1->mac, p1->if_name);
            
            LOCK_CLIENT_LIST();
            original = client_list_find_by_client(p1);
            if (NULL != original) {
                logout_client(original);
            } else { //client is gone already.
                debug(LOG_DEBUG, "<ClientTimeout>: "
                        "Client {%s, %s, %s} was already removed. Not logging out.",
                        p1->ip, p1->mac, p1->if_name);
            }
            UNLOCK_CLIENT_LIST();

        } else { //Client should be updated.
            debug(LOG_DEBUG, "<ClientTimeout>: "
                    "Client {%s, %s, %s} is still active.",
                    p1->ip, p1->mac, p1->if_name);
            if (this_timer < next_timer) {
                next_timer = this_timer;
            }
            if (!updateFailed) {
                debug(LOG_DEBUG, "<ClientTimeout>: "
                        "Flush Client {%s, %s, %s} remain time:%ld.",
                        p1->ip, p1->mac, p1->if_name, p1->remain_time);

                LOCK_CLIENT_LIST();
                original = client_list_find_by_client(p1);
                if (NULL != original) {
                    okos_client_list_flush(original, p1->remain_time);
                } else { //client is gone already.
                    debug(LOG_DEBUG, "<ClientTimeout>: "
                            "Client{%s, %s, %s} was already removed. Not logging out.",
                            p1->ip, p1->mac, p1->if_name);
                }
                UNLOCK_CLIENT_LIST();
            }
        }
    }
    debug(LOG_DEBUG, "<ClientTimeout>: Destroy the duplicated client list.");
    client_list_destroy(worklist);

    if (next_timer < low_threshold){
        next_timer = low_threshold;
    }

    return next_timer;
}
#if 0
/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_sync_with_authserver(void)
{
    t_authresponse authresponse;
    t_client *p1, *p2, *worklist, *tmp;
    s_config *config = config_get_config();

    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }

    LOCK_CLIENT_LIST();

    /* XXX Ideally, from a thread safety PoV, this function should build a list of client pointers,
     * iterate over the list and have an explicit "client still valid" check while list is locked.
     * That way clients can disappear during the cycle with no risk of trashing the heap or getting
     * a SIGSEGV.
     */
    client_list_dup(&worklist);
    UNLOCK_CLIENT_LIST();

    for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
        p2 = p1->next;

        /* Ping the client, if he responds it'll keep activity on the link.
         * However, if the firewall blocks it, it will not help.  The suggested
         * way to deal witht his is to keep the DHCP lease time extremely
         * short:  Shorter than config->checkinterval * config->clienttimeout */
        icmp_ping(p1->ip);

        /* Update the counters on the remote server only if we have an auth server */
        if (config->auth_servers != NULL) {
            auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, p1->ip, p1->mac, p1->token, p1->counters.incoming,
                                p1->counters.outgoing, p1->counters.incoming_delta, p1->counters.outgoing_delta);
        }

        time_t current_time = time(NULL);
        debug(LOG_INFO,
              "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
              p1->ip, p1->counters.last_updated, current_time - p1->counters.last_updated,
              config->checkinterval * config->clienttimeout, current_time);
        if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
            /* Timing out user */
            debug(LOG_INFO, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
                  p1->ip, config->checkinterval * config->clienttimeout);
            LOCK_CLIENT_LIST();
            tmp = client_list_find_by_client(p1);
            if (NULL != tmp) {
                logout_client(tmp);
            } else {
                debug(LOG_NOTICE, "Client was already removed. Not logging out.");
            }
            UNLOCK_CLIENT_LIST();
        } else
        {
            /*
             * This handles any change in
             * the status this allows us
             * to change the status of a
             * user while he's connected
             *
             * Only run if we have an auth server
             * configured!
             */
            LOCK_CLIENT_LIST();
            tmp = client_list_find_by_client(p1);
            if (NULL == tmp) {
                UNLOCK_CLIENT_LIST();
                debug(LOG_NOTICE, "Client was already removed. Skipping auth processing");
                continue;       /* Next client please */
            }

            if (config->auth_servers != NULL) {
                switch (authresponse.authcode) {
                case AUTH_DENIED:
                    debug(LOG_NOTICE, "%s - Denied. Removing client and firewall rules", tmp->ip);
                    fw_deny(tmp);
                    client_list_delete(tmp);
                    break;

                case AUTH_VALIDATION_FAILED:
                    debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules",
                          tmp->ip);
                    fw_deny(tmp);
                    client_list_delete(tmp);
                    break;

                case AUTH_ALLOWED:
                    if (tmp->fw_connection_state != FW_MARK_KNOWN) {
                        debug(LOG_INFO, "%s - Access has changed to allowed, refreshing firewall and clearing counters",
                              tmp->ip);
                        //WHY did we deny, then allow!?!? benoitg 2007-06-21
                        //fw_deny(tmp->ip, tmp->mac, tmp->fw_connection_state);
                        ///* XXX this was possibly to avoid dupes. */

                        if (tmp->fw_connection_state != FW_MARK_PROBATION) {
                            tmp->counters.incoming_delta =
                             tmp->counters.outgoing_delta =
                             tmp->counters.incoming =
                             tmp->counters.outgoing = 0;
                        } else {
                            //We don't want to clear counters if the user was in validation,
                            //it probably already transmitted data..
                            debug(LOG_INFO,
                                  "%s - Skipped clearing counters after all, the user was previously in validation",
                                  tmp->ip);
                        }
                        fw_allow(tmp, FW_MARK_KNOWN);
                    }
                    break;

                case AUTH_VALIDATION:
                    /*
                     * Do nothing, user
                     * is in validation
                     * period
                     */
                    debug(LOG_INFO, "%s - User in validation period", tmp->ip);
                    break;

                case AUTH_ERROR:
                    debug(LOG_WARNING, "Error communicating with auth server - leaving %s as-is for now", tmp->ip);
                    break;

                default:
                    debug(LOG_ERR, "I do not know about authentication code %d", authresponse.authcode);
                    break;
                }
            }
            UNLOCK_CLIENT_LIST();
        }
    }

    client_list_destroy(worklist);
}
#endif