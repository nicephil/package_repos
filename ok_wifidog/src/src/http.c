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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"

#include "../config.h"

#if OK_PATCH
#include "okos_auth_param.h"
#endif



#if OK_PATCH
static int okos_http_check_whitelist(request *r, char *url)
{
    // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
    // e.g. www.example.com  
    debug(LOG_DEBUG, "Check host %s is in global whitelist or not", r->request.host);
    t_firewall_rule *rule;
    //e.g. example.com is in whitelist
    // if request http://www.example.com/, it's not equal example.com.
    for (rule = get_ruleset("global"); NULL != rule; rule = rule->next) {
        debug(LOG_DEBUG, "rule mask %s", rule->mask);
        if (NULL == strstr(r->request.host, rule->mask)) {
            debug(LOG_DEBUG, "host %s is not in %s, continue", r->request.host, rule->mask);
            continue;
        }
        int host_length = strlen(r->request.host);
        int mask_length = strlen(rule->mask);
        if (host_length != mask_length) {
            char prefix[1024] = { 0 };
            // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
            strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
            strcat(prefix, ".");    // www.
            strcat(prefix, rule->mask);     // www.example.com
            if (strcasecmp(r->request.host, prefix) == 0) {
                debug(LOG_DEBUG, "allow subdomain");
                fw_allow_host(r->request.host, NULL);
                http_send_redirect(r, url, "allow subdomain");
                return 0;
            }
        } else {
            /* e.g. "example.com" is in conf, so it had been parse to IP and
             * added into "iptables allow" when wifidog start.
             * but then its' A record(IP) changed, it will go to here.*/
            debug(LOG_DEBUG, "allow domain again, because IP changed");
            fw_allow_host(r->request.host, NULL);
            http_send_redirect(r, url, "allow domain");
            return 0;
        }
    }
    return 1;
}
static int okos_http_check_whitelist_by_ssid(request *r, char *url, t_ssid_config *ssid)
{
    // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
    // e.g. www.example.com  
    debug(LOG_DEBUG, "Check host %s is in whitelist or not for ssid(%s).", r->request.host, ssid->ssid);
    t_firewall_rule *rule;
    //e.g. example.com is in whitelist
    // if request http://www.example.com/, it's not equal example.com.
    okos_list_for_each(rule, ssid->dn_white_list->rules) {
        debug(LOG_DEBUG, "rule mask %s", rule->mask);
        if (NULL == strstr(r->request.host, rule->mask)) {
            debug(LOG_DEBUG, "host %s is not in %s, continue", r->request.host, rule->mask);
            continue;
        }
        int host_length = strlen(r->request.host);
        int mask_length = strlen(rule->mask);
        if (host_length != mask_length) {
            char prefix[1024] = { 0 };
            // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
            strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
            strcat(prefix, ".");    // www.
            strcat(prefix, rule->mask);     // www.example.com
            if (strcasecmp(r->request.host, prefix) == 0) {
                debug(LOG_DEBUG, "allow subdomain");
                fw_allow_host(r->request.host, ssid);
                http_send_redirect(r, url, "allow subdomain");
                return 0;
            }
        } else {
            /* e.g. "example.com" is in conf, so it had been parse to IP and
             * added into "iptables allow" when wifidog start.
             * but then its' A record(IP) changed, it will go to here.*/
            debug(LOG_DEBUG, "allow domain again, because IP changed");
            fw_allow_host(r->request.host, ssid);
            http_send_redirect(r, url, "allow domain");
            return 0;
        }
    }
    return 1;
}

static void okos_try_to_add_client_into_list(t_client *p_client)
{
    debug(LOG_DEBUG, "Trying to add client {%s,%s,%s} into list.", p_client->ip, p_client->mac, p_client->ssid);

    LOCK_CLIENT_LIST();

    t_client *p_old = client_list_find_by_ssid(p_client->mac, p_client->ssid);
    if (NULL == p_old) {
        debug(LOG_DEBUG, "New client for {%s,%s,%s}", p_client->ip, p_client->mac, p_client->ssid);
        client_list_insert_client(p_client);
    } else {
        debug(LOG_WARNING, "Client{%s,%s,%s} is already in the list with remain time: %d", p_old->ip, p_old->mac, p_old->ssid, p_old->remain_time);
        okos_client_list_flush(p_old, p_client->remain_time);
        client_free_node(p_client);
        p_client = p_old;
    }

    /* Logged in successfully as a regular account */
    debug(LOG_DEBUG, "Got ALLOWED from auth server for client {%s,%s,%s} - "
            "adding to firewall and redirecting them to portal", p_client->ip, p_client->mac, p_client->ssid);
    fw_allow(p_client, FW_MARK_KNOWN);

    UNLOCK_CLIENT_LIST();
    served_this_session++;
}

static t_client * okos_query_auth_server(t_client *client)
{
    debug(LOG_DEBUG, "Querying auth server...");
    
    t_authresponse auth_code;
    int updateFailed = 1;
    updateFailed = auth_server_request(&auth_code, client);
    if (!updateFailed && AUTH_ALLOWED == auth_code.authcode) {

        okos_try_to_add_client_into_list(client);
        /*
        LOCK_CLIENT_LIST();
        
        t_client *old = client_list_find_by_ssid(client->mac, client->ssid);
        if (NULL == old) {
            debug(LOG_DEBUG, "New client for {%s,%s,%s}", client->ip, client->mac, client->ssid);
            client_list_insert_client(client);
        } else {
            debug(LOG_WARNING, "Client for {%s,%s,%s} is already in the client list with remain time: %d", old->ip, old->mac, old->ssid, old->remain_time);
            okos_client_list_flush(old, client->remain_time);
            client_free_node(client);
            client = old;
        }

        debug(LOG_DEBUG, "Got ALLOWED from auth server from %s at %s - "
              "adding to firewall and redirecting them to portal", client->ip, client->mac);
        fw_allow(client, FW_MARK_KNOWN);

        UNLOCK_CLIENT_LIST();
        served_this_session++;*/

        debug(LOG_DEBUG, "Auth Server recoganize {%s,%s,%s} Let it go.", client->ip, client->mac, client->ssid);
        return NULL;
    }
    debug(LOG_DEBUG, "Auth Server won't let {%s,%s,%s} go.", client->ip, client->mac, client->ssid);
    return client;
}

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd *webserver, request *r, int error_code)
{
    debug(LOG_DEBUG, "Calling 404() for %s", r->clientAddr);
    char tmp_url[MAX_BUF];
    memset(tmp_url, 0, sizeof(tmp_url));
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);

    /* This part is for roaming.
     * When a client is roaming to a new AP, it didn't register to this AP before.
     * So, iptables won't let it go. the http request will be redirected to 404.
     * We query auth server here to confirm his login status.
     * If we got confirm from Auth Sever and this client is allowed, set it into iptables.
     * Then, redirect him to the original web page.
     */
    debug(LOG_DEBUG, "build a new client data structure for 404.");
    t_client *client = okos_client_get_new_client(r->clientAddr);
    if (NULL == client) {
        debug(LOG_ERR, "Failed to retrieve info for client(%s), so not putting in login request.", r->clientAddr);
        /* FIXME: we may need to port some error handler here. */
        return;
    }
    
    debug(LOG_DEBUG, "Start to query for new client in 404.");
    if (NULL == okos_query_auth_server(client)) {
        http_send_redirect(r, tmp_url, "Allowed");

        debug(LOG_INFO, "Client{%s,%s,%s} login already. Let him go.", client->ip, client->mac, client->ssid);
        return;
    }

    debug(LOG_INFO, "Client{%s,%s,%s} hasn't been authenticated before, need to kickoff auth process from beginning.", client->ip, client->mac, client->ssid);
    /* For new client, check his target host in the white list.
     */
    //t_ssid_config * ssid = okos_conf_get_ssid_by_client(client);
    t_ssid_config * ssid = client->ssid_conf;
    debug(LOG_DEBUG, "Start to check target host in white list...");
    int canntMatchHostInWhiteList;
    canntMatchHostInWhiteList = okos_http_check_whitelist(r, tmp_url);
    if (0 == canntMatchHostInWhiteList) {
        debug(LOG_INFO, "Match target in global WhiteList, redirect client, exit 404 process..");
        return;
    }
    canntMatchHostInWhiteList = okos_http_check_whitelist_by_ssid(r, tmp_url, ssid);
    if (0 == canntMatchHostInWhiteList) {
        debug(LOG_INFO, "Match target in WhiteList on ssid(%s), redirect client, exit 404 process..", ssid->ssid);
        return;
    }

    /* Re-direct them to auth server */
    char *url = httpdUrlEncode(tmp_url);
    char *info = okos_http_insert_parameter(client);
    char *urlFragment;
    t_auth_serv *auth_server = get_auth_server(client);
    client_free_node(client);

    safe_asprintf(&urlFragment, "%sinfo=%s&originalurl=%s",
              auth_server->authserv_login_script_path_fragment, info, url);
    free(info);
    
    debug(LOG_INFO, "Captured {%s,%s,%s} requesting [%s] and re-directing them to login page",
                     client->ip, client->mac, client->ssid, url);
    free(url);

    http_send_redirect_to_auth(r, urlFragment, "Redirect to login page", auth_server);
    free(urlFragment);
    return;
}

#else /* OK_PATCH */

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
    char tmp_url[MAX_BUF], *url;
    t_auth_serv *auth_server = get_auth_server();
    char *mac;
    s_config *config = config_get_config();
    memset(tmp_url, 0, sizeof(tmp_url));
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
    url = httpdUrlEncode(tmp_url);

    if (!is_online()) {
        /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
                      "<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

        send_http_page(r, "Uh oh! Internet access unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server",
              r->clientAddr);
    } else if (!is_auth_online()) {
        /* The auth server is down at the moment - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>",
                      tmp_url);

        send_http_page(r, "Uh oh! Login screen unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server",
              r->clientAddr);
    } else {
        /* Re-direct them to auth server */
        char *urlFragment;

        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request",
                  r->clientAddr);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment, config->gw_address, config->gw_port,
                          config->gw_id, r->clientAddr, url);
        } else {
            debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&mac=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment,
                          config->gw_address, config->gw_port, config->gw_id, r->clientAddr, mac, url);
            free(mac);
        }

        // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
        debug(LOG_INFO, "Check host %s is in whitelist or not", r->request.host);       // e.g. www.example.com
        t_firewall_rule *rule;
        //e.g. example.com is in whitelist
        // if request http://www.example.com/, it's not equal example.com.
        for (rule = get_ruleset("global"); rule != NULL; rule = rule->next) {
            debug(LOG_INFO, "rule mask %s", rule->mask);
            if (strstr(r->request.host, rule->mask) == NULL) {
                debug(LOG_INFO, "host %s is not in %s, continue", r->request.host, rule->mask);
                continue;
            }
            int host_length = strlen(r->request.host);
            int mask_length = strlen(rule->mask);
            if (host_length != mask_length) {
                char prefix[1024] = { 0 };
                // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
                strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
                strcat(prefix, ".");    // www.
                strcat(prefix, rule->mask);     // www.example.com
                if (strcasecmp(r->request.host, prefix) == 0) {
                    debug(LOG_INFO, "allow subdomain");
                    fw_allow_host(r->request.host);
                    http_send_redirect(r, tmp_url, "allow subdomain");
                    free(url);
                    free(urlFragment);
                    return;
                }
            } else {
                // e.g. "example.com" is in conf, so it had been parse to IP and added into "iptables allow" when wifidog start. but then its' A record(IP) changed, it will go to here.
                debug(LOG_INFO, "allow domain again, because IP changed");
                fw_allow_host(r->request.host);
                http_send_redirect(r, tmp_url, "allow domain");
                free(url);
                free(urlFragment);
                return;
            }
        }

        debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
        free(urlFragment);
    }
    free(url);
}
#endif /* OK_PATCH */

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "OKOS", "Please use the menu to navigate the features of this OKOS installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About me", "This is my version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
#if OK_PATCH
void
http_send_redirect_to_auth(request *r, const char *urlFragment, const char *text, const t_auth_serv *auth_server)
#else /* OK_PATCH */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
#endif /* OK_PATCH */
{
    char *protocol = NULL;
    int port = 80;
#if OK_PATCH
#else /* OK_PATCH */
    t_auth_serv *auth_server = get_auth_server();
#endif /* OK_PATCH */

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    send_http_page(r, text ? text : "Redirection to message", message);
    free(message);
}

#if OK_PATCH

void http_callback_auth(httpd *webserver, request *r)
{
    debug(LOG_DEBUG, "Calling http_callback_auth...");
    httpVar *auth = httpdGetVariableByName(r, "auth");
	if (NULL == auth) {
        debug(LOG_WARNING, "Cant get parameter auth from server response for client(%s)", r->clientAddr);
        send_http_page(r, "Auth Server Error", "Invalid Auth Parameter");
        return;
    }

    debug(LOG_DEBUG, "build a new client data structure in auth confirm.");
    t_client *client = okos_client_get_new_client(r->clientAddr);
    if (NULL == client) {
        debug(LOG_WARNING, "Since we can't get local infor for client(%s),"
                "we need to apologize to our client.", r->clientAddr);
        /* FIXME: we may need to port some error handler here. */
        return;
    }

    debug(LOG_DEBUG, "Starting parse the return info from auth server.");
    int parseFailed = okos_http_parse_info(auth->value, client);
    if (parseFailed) {
        send_http_page(r, "Auth Server Error", "Invalid auth parameter");
        debug(LOG_WARNING, "We can't parse the auth parameter correctly."
                "code: %d", parseFailed);
        client_free_node(client);
        return;
    }
    
    debug(LOG_INFO, "Client{%s,%s,%s} got authoriated by server.", client->ip, client->mac, client->ssid);
    okos_try_to_add_client_into_list(client);
    /*
    LOCK_CLIENT_LIST();

    t_client *old = client_list_find_by_ssid(client->mac, client->ssid);
    if (NULL == old) {
        debug(LOG_DEBUG, "New client for {%s,%s} on ssid:%s", client->ip, client->mac, client->ssid);
        client_list_insert_client(client);
    } else {
        okos_client_list_flush(old, client->remain_time);
        debug(LOG_DEBUG, "Client {%s,%s} on ssid:%s is already in the list with remain time: %d",
                client->ip, client->mac, client->ssid, client->remain_time);
    }

    debug(LOG_DEBUG, "Got ALLOWED from central server for {%s, %s, %s} "
            "adding to firewall and redirecting them to portal",
            client->ip, client->mac, client->ssid);
    fw_allow(client, FW_MARK_KNOWN);

    UNLOCK_CLIENT_LIST();
    served_this_session++;
*/
    httpVar *flag = httpdGetVariableByName(r, "flag");
    int donot_redirect = 0;
    if (NULL != flag) {
        sscanf(flag->value, "%d", &donot_redirect);
    }
    httpVar *redirecturl = httpdGetVariableByName(r, "redirecturl");
    if (NULL == redirecturl)
        donot_redirect = 1;

    if (0 == donot_redirect) {
        debug(LOG_DEBUG, "We need to redirect client to the assigned web page.");
        char *url= NULL;
        safe_asprintf(&url, "%s", redirecturl->value);
        http_send_redirect(r, url, "Redirect to portal");
        free(url);
    } else {
        debug(LOG_DEBUG, "We just need to reply to client something.");
        send_http_page(r, "Life is short, play!", "my friend");
    }



    return;
}
#else /* OK_PATCH */
void
http_callback_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token"))) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();

            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client_list_add(r->clientAddr, mac, token->value);
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }

            UNLOCK_CLIENT_LIST();
            if (!logout) { /* applies for case 1 and 3 from above if */
                authenticate_client(r);
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "WiFiDog error", "Invalid token");
    }
}
#endif /* OK_PATCH */

void
http_callback_disconnect(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
        return;
    }

    return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}
