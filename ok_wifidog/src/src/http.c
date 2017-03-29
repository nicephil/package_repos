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
#include <sqlite3.h>

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
#include "pstring.h"
#include "okos_auth_param.h"
#include "gateway.h"
#endif


//#define OKOS_MAKE_JOKE_WITH_CLIENT
//#define OKOS_PORTAL_PRECHECK

#if OK_PATCH
static int okos_http_check_whitelist(request *r, char *url)
{
    // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
    // e.g. www.example.com  
    debug(LOG_DEBUG, "  $$ Check host %s is in global whitelist or not", r->request.host);
    t_firewall_rule *p_rule;
    //e.g. example.com is in whitelist
    // if request http://www.example.com/, it's not equal example.com.
    for (p_rule = get_ruleset("global"); NULL != p_rule; p_rule = p_rule->next) {
        debug(LOG_DEBUG, "    $$ rule mask %s", p_rule->mask);
        if (NULL == strstr(r->request.host, p_rule->mask)) {
            debug(LOG_DEBUG, "  $$ host %s is not in %s, continue",
                    r->request.host, p_rule->mask);
            continue;
        }
        int host_length = strlen(r->request.host);
        int mask_length = strlen(p_rule->mask);
        if (host_length != mask_length) {
            char prefix[1024] = { 0 };
            // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
            strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
            strcat(prefix, ".");    // www.
            strcat(prefix, p_rule->mask);     // www.example.com
            if (strcasecmp(r->request.host, prefix) == 0) {
                debug(LOG_DEBUG, "    $$ allow subdomain");
                fw_allow_host(r->request.host, NULL);
                http_send_redirect(r, url, "allow subdomain");
                return 0;
            }
        } else {
            /* e.g. "example.com" is in conf, so it had been parse to IP and
             * added into "iptables allow" when wifidog start.
             * but then its' A record(IP) changed, it will go to here.*/
            debug(LOG_DEBUG, "    $$ allow domain again, because IP changed");
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
    debug(LOG_DEBUG, "  $$ Check host %s is in whitelist or not for ssid(%s).",
            r->request.host, ssid->ssid);
    t_firewall_rule *p_rule;
    //e.g. example.com is in whitelist
    // if request http://www.example.com/, it's not equal example.com.
    okos_list_for_each(p_rule, ssid->dn_white_list->rules) {
        debug(LOG_DEBUG, "    $$ rule mask %s", p_rule->mask);
        if (NULL == strstr(r->request.host, p_rule->mask)) {
            debug(LOG_DEBUG, "  $$ host %s is not in %s, continue", r->request.host, p_rule->mask);
            continue;
        }
        int host_length = strlen(r->request.host);
        int mask_length = strlen(p_rule->mask);
        if (host_length != mask_length) {
            char prefix[1024] = { 0 };
            // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
            strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
            strcat(prefix, ".");    // www.
            strcat(prefix, p_rule->mask);     // www.example.com
            if (strcasecmp(r->request.host, prefix) == 0) {
                debug(LOG_DEBUG, "    $$ allow subdomain");
                fw_allow_host(r->request.host, ssid);
                http_send_redirect(r, url, "allow subdomain");
                return 0;
            }
        } else {
            /* e.g. "example.com" is in conf, so it had been parse to IP and
             * added into "iptables allow" when wifidog start.
             * but then its' A record(IP) changed, it will go to here.*/
            debug(LOG_DEBUG, "    $$ allow domain again, because IP changed");
            fw_allow_host(r->request.host, ssid);
            http_send_redirect(r, url, "allow domain");
            return 0;
        }
    }
    return 1;
}

static void okos_add_validation_client(t_client *client)
{
    debug(LOG_DEBUG, "  .. Trying to add VALIDATION client {%s, %s, %s} into list.",
            client->ip, client->mac, client->ssid);
    LOCK_CLIENT_LIST();
    t_client *old = client_list_find_by_ssid(client->mac, client->ssid);
    if (NULL == old) {
        client_list_insert_client(client);
        //fw_allow(client, FW_MARK_PROBATION);
        fw_allow(client, FW_MARK_KNOWN);
        debug(LOG_DEBUG, "  .. Insert a new VALIDATION client {%s, %s, %s, remain_time:%ld}.",
                client->ip, client->mac, client->ssid, client->remain_time);
    } else {
        debug(LOG_DEBUG, "  .. VALIDATION client {%s, %s, %s, remain_time:%ld} is already in.",
                client->ip, client->mac, client->ssid, client->remain_time);
    }
    UNLOCK_CLIENT_LIST();
    served_this_session++;
}


static void okos_try_to_add_client_into_list(t_client *p_client)
{
    debug(LOG_DEBUG, ".. Trying to add ALLOWED client {%s, %s, %s} into list.",
            p_client->ip, p_client->mac, p_client->ssid);

    LOCK_CLIENT_LIST();

    t_client *p_old = client_list_find_by_ssid(p_client->mac, p_client->ssid);
    if (NULL == p_old) {
        debug(LOG_DEBUG, "  .. Insert New ALLOWED client {%s, %s, %s}", p_client->ip, p_client->mac, p_client->ssid);
        client_list_insert_client(p_client);
        fw_allow(p_client, FW_MARK_KNOWN);
    } else {
        debug(LOG_INFO, "  .. ALLOWED Client {%s, %s, %s, remain_time:%ld} is already in.",
                p_old->ip, p_old->mac, p_old->ssid, p_old->remain_time);
        okos_client_list_flush(p_old, p_client->remain_time);
        client_free_node(p_client);
        p_client = p_old;
    }

    /* Logged in successfully as a regular account */
    debug(LOG_DEBUG, ".. Got ALLOWED from auth server for client {%s,%s,%s}",
            p_client->ip, p_client->mac, p_client->ssid);

    UNLOCK_CLIENT_LIST();
    served_this_session++;
}


#ifdef OKOS_PORTAL_PRECHECK
static t_client * okos_query_auth_server(t_client *p_client)
{
    debug(LOG_DEBUG, "~~ Querying auth server.");
    
    t_authresponse auth_code;
    int updateFailed = 1;
    updateFailed = auth_server_request(&auth_code, p_client);
    if (!updateFailed && AUTH_ALLOWED == auth_code.authcode) {

        okos_try_to_add_client_into_list(p_client);

        debug(LOG_DEBUG, "~~ Auth Server recoganize {%s,%s,%s} Let it go.", p_client->ip, p_client->mac, p_client->ssid);
        return NULL;
    }
    debug(LOG_DEBUG, "~~ Auth Server won't let {%s,%s,%s} go.", p_client->ip, p_client->mac, p_client->ssid);
    return p_client;
}
#endif


#define OKOS_HTTP_STR(s) (s ? s : "nil")

void okos_http_statistic_variables(request *r)
{
    debug(LOG_DEBUG, "HTTP_READ_BUF:[%s]", r->readBuf);

    pstr_t *p_str = pstr_new();
    pstr_append_sprintf(p_str, "Request:={Host=%s Path=%s Query=%s}",
           OKOS_HTTP_STR(r->request.host), OKOS_HTTP_STR(r->request.path), OKOS_HTTP_STR(r->request.query));

    pstr_cat(p_str, "httpVars:={");
    httpVar *p_var;
    for (p_var = r->variables; NULL != p_var; p_var = p_var->nextVariable) {
        pstr_append_sprintf(p_str, "{%s=%s} ", p_var->name, p_var->value);
    }
    pstr_cat(p_str, "}");

    char *p_header = pstr_to_string(p_str);
    debug(LOG_DEBUG, "%s", p_header);
    free(p_header);
}


/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd *webserver, request *r, int error_code)
{
    debug(LOG_DEBUG, "<HTTPD_404> Client {%s} request.", r->clientAddr);

    if (HTTP_GET != r->request.method) {
        debug(LOG_DEBUG, "<HTTPD_404> Drop HTTP request(%d) for Client {%s}, only GET method allowed.",
                r->request.method, r->clientAddr);
        goto cb_404_leave_for_bad_method;
    }

    char a_tmp_url[MAX_BUF];
    memset(a_tmp_url, 0, sizeof(a_tmp_url));
    snprintf(a_tmp_url, (sizeof(a_tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);

#if 0
    okos_http_statistic_variables(r);
#endif

    debug(LOG_DEBUG, "<HTTPD_404> build a new client {ip:%s}.", r->clientAddr);
    t_client *p_client = okos_client_get_new_client_v1(r->clientAddr);
    if (NULL == p_client) {
        debug(LOG_ERR, "<HTTPD_404> Failed to retrieve info for client(%s).", r->clientAddr);
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Login", "Do not support anonymous yet");
#endif
        goto cb_404_cannt_get_new_client;
    }
    debug(LOG_DEBUG, "<HTTPD_404> Client {%s, %s, %s, %s, scheme:%s}",
            p_client->ip, p_client->mac, p_client->ssid, p_client->if_name, p_client->scheme);

#ifdef OKOS_PORTAL_PRECHECK
    debug(LOG_DEBUG, "<HTTPD_404> Start to query for new client in 404.");
    if (NULL == okos_query_auth_server(p_client)) {
        http_send_redirect(r, a_tmp_url, "Allowed");

        debug(LOG_INFO, "<HTTPD_404> Client{%s, %s, %s} login already. Let him go.",
                p_client->ip, p_client->mac, p_client->ssid);
        goto cb_404_quick_check_failed;
    }
    debug(LOG_INFO, "<HTPPD_404> Client{%s, %s, %s} hasn't been authenticated before"
            "need to kickoff auth process from beginning.",
            p_client->ip, p_client->mac, p_client->ssid);
#endif

    debug(LOG_DEBUG, "<HTTPD_404> Start to check target host in white list.");
    int canntMatchHostInWhiteList;
    canntMatchHostInWhiteList = okos_http_check_whitelist(r, a_tmp_url);
    if (!canntMatchHostInWhiteList) {
        debug(LOG_INFO, "<HTTPD_404> Match target in global WhiteList, redirect client, exit 404 process..");
        goto cb_404_match_global_whitelist;
    }
    canntMatchHostInWhiteList = okos_http_check_whitelist_by_ssid(r, a_tmp_url, p_client->ssid_conf);
    if (!canntMatchHostInWhiteList) {
        debug(LOG_INFO, "<HTTPD_404> Match target in WhiteList on ssid(%s), redirect client, exit 404 process..",
                p_client->ssid_conf->ssid);
        goto cb_404_match_ssid_whitelist;
    }

    /* Re-direct them to auth server */
    char *s_url = httpdUrlEncode(a_tmp_url);
    char *s_info = okos_http_insert_parameter(p_client);
    char *s_urlFragment;

    t_auth_serv *auth_server = get_auth_server(p_client);
    if (NULL != auth_server) {
        safe_asprintf(&s_urlFragment, "%sinfo=%s&originalurl=%s",
                auth_server->authserv_login_script_path_fragment, s_info, s_url);

        debug(LOG_DEBUG, "<HTTPD_404> Captured {%s, %s, %s, %s}",
                p_client->ip, p_client->mac, p_client->ssid, p_client->if_name);
        debug(LOG_DEBUG, "<HTTPD_404> Build <info>=[%s]", s_info);
        debug(LOG_DEBUG, "<HTTPD_404> Build <originalurl>=[%s]", s_url);
        http_send_redirect_to_auth(r, s_urlFragment, "Redirect to login page", auth_server, "");
        free(s_urlFragment);
    } else {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Login", "Uh oh! Internet access unavailable! Take it easy.");
#endif
    }
    
    free(s_info);
    free(s_url);

cb_404_match_ssid_whitelist:
cb_404_match_global_whitelist:
    client_free_node(p_client);

#ifdef OKOS_PORTAL_PRECHECK
cb_404_quick_check_failed:
#endif
cb_404_cannt_get_new_client:
cb_404_leave_for_bad_method:
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

#if OK_PATCH

static void http_callback_wifidog_show(httpd *webserver, request *r)
{
    char *buf;
    safe_asprintf(&buf, "<h3><input class=\"qtext\" name=question type=\"text\" maxlength=\"256\" size=\"48\"></h3>");
    send_http_page(r, "Life is short, play hard!", buf);
    free(buf);
}

static t_http_callback *s_http_cb[64];

void okos_init_http_callback(void)
{
    debug(LOG_INFO, "<HTTPD_callback> Initialize http callback metric.");

    bzero(s_http_cb, sizeof(t_http_callback *) * 64);
}

int okos_http_callback_register(const char *name, okos_http_callback_func p_func, void *data)
{
    debug(LOG_DEBUG, "<HTTPD_callback> Register http callback for %s.", name);

    int i;
    for (i = 0; i < 64; i++) {
        if (NULL == s_http_cb[i]) {
            s_http_cb[i] = safe_malloc(sizeof(t_http_callback));
            s_http_cb[i]->name = name;
            s_http_cb[i]->p_func = p_func;
            s_http_cb[i]->data = data;
            return 0;
        }
    }

    return -1;
}

static void okos_http_callback_exec(httpd *webserver, request *r, char *key, char *value)
{
    char *buf, *msg;

    int i;
    for (i = 0; i < 64; i++) {
        if (NULL != s_http_cb[i]) {
            if (0 == strcasecmp(s_http_cb[i]->name, key)) {
                debug(LOG_DEBUG, "<HTTPD_callback> :%s called with %s.", key, value);

                buf = s_http_cb[i]->p_func(value, s_http_cb[i]->data);
                if (NULL != buf) {
                    safe_asprintf(&msg, "<h2><pre>%s</pre></h2>", buf);
                    send_http_page(r, "OKOS", msg);
                    free(buf);
                    free(msg);
                    return;
                }
                break;
            }
        }
    }
    debug(LOG_DEBUG, "HTTP callback %s unregisted.", key);

    http_callback_wifidog_show(webserver, r);
}

static int okos_http_analyze_key_value(const char *query, char **key, char **value)
{
    if ('@' != query[0]) {
        debug(LOG_DEBUG, "Query [%s] is not a command.");
        return -1;
    }

    char *p_key, *p_value;
    char buf[256];
    strncpy(buf, query, 255);
    buf[255] = 0;
    p_key = buf + 1;
    for (p_value = p_key; ':' != *p_value && 64 > p_value - p_key; p_value++) {
    }
    if (':' == *p_value) {
        *p_value++ = 0;
        while (' ' == *p_value) {
            p_value++;
        }
        *key = safe_strdup(p_key);
        *value = safe_strdup(p_value);
        debug(LOG_DEBUG, "Got query {key = [%s], value = [%s]}.", *key, *value);
        return 0;
    } else {
        debug(LOG_DEBUG, "Can't parse request [%s].", query);
        return -1;
    }
}

static void http_callback_wifidog_query(httpd *webserver, request *r, const char *query)
{
    char *key = NULL;
    char *value = NULL;
    int parseFailed = okos_http_analyze_key_value(query, &key, &value);
    if (parseFailed) {
        http_callback_wifidog_show(webserver, r);
        return;
    }

    okos_http_callback_exec(webserver, r, key, value);

    free(key);
    free(value);
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    httpVar *question = httpdGetVariableByName(r, "question");
    if (NULL == question || 0 == strcmp(question->value, "")) {
        http_callback_wifidog_show(webserver, r);
    } else {
        http_callback_wifidog_query(webserver, r, question->value);
    }
}

#if 0
static char * okos_http_callback_about(void *data)
{
    char *msg;
    safe_asprintf(&msg, "This is my version <strong>" VERSION "</strong>");
    return msg;
}

static char * okos_http_callback_status(void *data)
{
    char *status = get_status_text();

    return status;
}

static char * okos_http_callback_debug(void *data)
{
    char *eth_ip = get_iface_ip("br-lan1");
    char *buf;
    safe_asprintf(&buf, "Hi! My name is %s. Nice to meet you!", eth_ip);
    free(eth_ip);

    return buf;
}

static char * okos_http_callback_config(void *data)
{
    char *status = okos_conf_get_all();

    return status;
}

char * okos_http_cb_about(char *key, void *data)
{
    char *msg;
    if (0 == strcasecmp("status", key)) {
        msg = okos_http_callback_status(data);
    } else if (0 == strcasecmp("debug", key)) {
        msg = okos_http_callback_debug(data);
    } else if (0 == strcasecmp("config", key)) {
        msg = okos_http_callback_config(data);
    } else {
        msg = okos_http_callback_about(data);
    }

    return msg;
}
#endif

char * okos_http_cb_shell(char *key, void *data)
{
    debug(LOG_INFO, "Admin wanna run %s.", key);

    char line[256];
    int len = 0;
    char *msg = NULL;
    pstr_t *p_str = pstr_new();
    char *command = NULL;
    safe_asprintf(&command, "%s", key);
    FILE *shell = popen(command, "r");
    if (shell) {
        while (fgets(line, sizeof(line), shell)) {
            if (strlen(line) + len > 8 * 1024) {
                break;
            }
            pstr_cat(p_str, line);
            len += strlen(line);
        }
        pclose(shell);
        msg = pstr_to_string(p_str);
    } else {
        msg = "I'm sorry.\n";
    }

    debug(LOG_DEBUG, "Shell return: [%s].", msg);

    return msg;
}


#else /* OK_PATCH */
void http_callback_wifidog(httpd *webserver, request *r)
{
    char *buf;
    safe_asprintf(&buf, "  <input class=\"qtext\" name=question type=\"text\" maxlength=\"256\" size=\"48\">");
    send_http_page(r, "Life is short, play hard!", buf);
    free(buf);
}

#endif

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
    send_http_page(r, "OKOS Status", buf);
    free(buf);
    free(status);
}

#if OK_PATCH
void 
http_callback_auth_allow(httpd *webserver, request *r)
{
    /* They just got validated for X minutes to check their email */
    debug(LOG_DEBUG, "<HTTPD_allow> Got VALIDATION from central server from %s.",
            r->clientAddr);

    httpVar *time = httpdGetVariableByName(r, "time");
    if (NULL == time) {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Allowed", "I'd like to let you go, but I don't know how long.");
#endif
        debug(LOG_INFO, "<HTTPD_allow> Receive code 'allow' without 'time'.");
        return;
    }

    t_client *client = okos_client_get_new_client_v1(r->clientAddr);
    if (NULL == client) {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Allowed", "Don't give up! To be strong.");
#endif
        debug(LOG_INFO, "<HTTPD_allow> Cant create new client for allow code.");
        return;
    }
    client = client_get_new_validation(client, time->value);
    if (NULL == client) {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Allowed", "Can't let you go.");
#endif
        debug(LOG_WARNING, "<HTTPD_allow> We can't add a new validation correctly.");
        return;
    }

    debug(LOG_INFO, "<HTTPD_allow> Client {%s, %s, %s} VALIDATED!",
            client->ip, client->mac, client->ssid);
    okos_add_validation_client(client);

#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
    send_http_page(r, "Auth Allowed", "Move on!");
#endif
    return;
}

void
http_callback_auth_qrcode(httpd *webserver, request *r)
{
    debug(LOG_DEBUG, "<HTTPD_qrcode> Received request for auth qrcode from %s", r->clientAddr);

    debug(LOG_DEBUG, "<HTTPD_qrcode> build a new client {ip:%s} for 404.", r->clientAddr);
    t_client *p_client = okos_client_get_new_client_v1(r->clientAddr);
    if (NULL == p_client) {
        debug(LOG_ERR, "<HTTPD_qrcode> Failed to retrieve info for client(%s), so not putting in login request.", r->clientAddr);
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth qrcode", "Do not support anonymous yet");
#endif
        return;
    }
    debug(LOG_DEBUG, "<HTTPD_qrcode> Client {%s, %s, %s, %s, scheme:%s}",
            p_client->ip, p_client->mac, p_client->ssid, p_client->if_name, p_client->scheme);

    pstr_t *p_str = pstr_new();
    httpVar *p_var;
    for (p_var = r->variables; NULL != p_var; p_var = p_var->nextValue) {
        pstr_append_sprintf(p_str, "&%s=%s", p_var->name, p_var->value);
    }
    char *s_variables = pstr_to_string(p_str);
    debug(LOG_DEBUG, "<HTTPD_qrcode> Copy variables from original request. %s", s_variables);

    char *s_source = okos_http_insert_parameter(p_client);
    char *s_urlFragment;

    t_auth_serv *auth_server = get_auth_server(p_client);
    if (NULL != auth_server) {
        safe_asprintf(&s_urlFragment, "%ssource=%s%s",
                auth_server->authserv_login_script_path_fragment, s_source, s_variables);

        debug(LOG_DEBUG, "<HTTPD_qrcode> Authenticator {%s, %s, %s, %s} requesting [%s] and re-directed.",
                p_client->ip, p_client->mac, p_client->ssid, p_client->if_name, s_urlFragment);
        http_send_redirect_to_auth(r, s_urlFragment, "Redirect to qrcode page", auth_server, "/qrcode");

        free(s_urlFragment);
    }
    else {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth qrcode", "Uh oh! Internet access unavailable! Take it easy.");
#endif
    }
    free(s_source);
    free(s_variables);
    client_free_node(p_client);

    return;
}



void
http_callback_debug(httpd *webserver, request *r)
{
    const s_config *config = config_get_config();

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Debug page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    char *eth_ip = get_iface_ip("br-lan1");
    char *buf;
    safe_asprintf(&buf, "<pre>Hi! %s, I'm %s. Nice to meet you!</pre>", r->clientAddr, eth_ip);
    send_http_page(r, "OKOS Debug Information", buf);
    free(buf);
    free(eth_ip);
}

void
http_callback_config(httpd *webserver, request *r)
{
    const s_config *config = config_get_config();

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Config page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    char *status = okos_conf_get_all();
    char *buf;
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "OKOS Portal Configuration", buf);
    free(buf);
    free(status);
}

#endif

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
#if OK_PATCH
void
http_send_redirect_to_auth(request *r, const char *urlFragment, const char *text, const t_auth_serv *auth_server, const char *append)
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
    safe_asprintf(&url, "%s://%s:%d%s%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path,
                  NULL == append ? "" : append, urlFragment);
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
    debug(LOG_DEBUG, "-> Redirect:%s", url);
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
static int okos_update_callback(void *data, int col_n, char **_v, char **_k)
{
    int i;
    for (i = 0; i < col_n; i++) {
        debug(LOG_DEBUG, "++++ sqlite: %s", data ? data : "");
        debug(LOG_DEBUG, "  ++ key:%s; value:%s", _k[i], _v[i] ? _v[i]: "Nil");
    }
    return 0;
}

static void okos_update_station_info(t_client *client)
{
    sqlite3 *sta_info_db = NULL;
    int db_result = sqlite3_open(station_info_db_file, &sta_info_db);
    if (0 == db_result) {
        debug(LOG_DEBUG, "++ sqlite: Open database %s successfully.", station_info_db_file);
        /* Create merged SQL statement */
        char *sql = NULL;
        safe_asprintf(&sql, "UPDATE STAINFO set " \
                "PORTAL_SCHEME='%s', PORTAL_MODE='%d'," \
                "PORTAL_USER='%s', IPADDR='%s' " \
                "WHERE MAC='%s';" \
                /* "SELECT * from STAINFO where MAC='%s';" \ */
                ,
                client->scheme, client->auth_mode,
                client->user_name, client->ip,
                client->mac,
                client->mac
                );
        debug(LOG_DEBUG, "++ sqlite: '%s':", sql);

        /* Execute SQL statement */
        char *err_msg = NULL;
        int rc = sqlite3_exec(sta_info_db, sql, okos_update_callback, (void*)NULL, &err_msg);
        if (SQLITE_OK != rc) {
            debug(LOG_DEBUG, "++!! sqlite: Update '%s' failed with %s", sql, err_msg);
            sqlite3_free(err_msg);
        }else{
            debug(LOG_DEBUG, "++++ sqlite: Update '%s' successfully.", sql);
        }

        free(sql);
        sqlite3_close(sta_info_db);
        debug(LOG_DEBUG, "++ sqliet: Close database.");
    } else {
        debug(LOG_WARNING, "++!! Fail to open database %s:%s.",
                station_info_db_file, sqlite3_errmsg(sta_info_db));
    }
}


void http_callback_auth(httpd *webserver, request *r)
{
    debug(LOG_DEBUG, "<HTTPD_auth> Calling http_callback_auth.");
    httpVar *auth = httpdGetVariableByName(r, "auth");
	if (NULL == auth) {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Confirm", "Invalid Auth Parameter");
#endif
        debug(LOG_WARNING, "<HTTPD_auth> Cant get parameter auth from server for client(%s)", r->clientAddr);
        return;
    }

    t_client *client = client_get_new();
    debug(LOG_DEBUG, "<HTTPD_auth> Starting parse the return info from auth server.");
    int parseFailed = okos_http_parse_info(auth->value, client);
    if (parseFailed) {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Confirm", "Uncompleted auth parameter");
#endif
        client_free_node(client);
        debug(LOG_WARNING, "<HTTPD_auth> We can't parse the auth parameter correctly."
                "code: %d", parseFailed);
        return;
    }
    t_client *res = okos_client_append_info(client, r->clientAddr);
    if (NULL != res) {
        okos_update_station_info(client);
        debug(LOG_NOTICE, "<HTTPD_auth> Client{%s, %s, %s} PASSED!",
                client->ip, client->mac, client->ssid);
        okos_try_to_add_client_into_list(client);
    } else {
        client_free_node(client);
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Confirm", "Can't fill local information.");
        debug(LOG_WARNING, "<HTTPD_auth> Can't fill local info for client(%s)", r->clientAddr);
#endif
        return;
    }

    httpVar *flag = httpdGetVariableByName(r, "flag");
    int donot_redirect = 0;
    if (NULL != flag) {
        sscanf(flag->value, "%d", &donot_redirect);
    }
    httpVar *redirecturl = httpdGetVariableByName(r, "redirecturl");
    if (NULL == redirecturl)
        donot_redirect = 1;

    if (!donot_redirect) {
        debug(LOG_DEBUG, "<HTTPD_auth> Redirect client to the assigned web page.");
        char *url= NULL;
        safe_asprintf(&url, "%s", redirecturl->value);
        http_send_redirect(r, url, "Redirect to portal");
        free(url);
    } else {
#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
        send_http_page(r, "Auth Confirm", "Life is short, play! my friend");
#endif
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

    debug(LOG_INFO, "-> {title:%s, message:%s}", title, message);

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "-> Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "-> Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "-> Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
#if OK_PATCH
    httpdAddVariable(r, "nodeID", config->device_id);
#else
    httpdAddVariable(r, "nodeID", config->gw_id);
#endif
    httpdOutput(r, buffer);
    free(buffer);
}
