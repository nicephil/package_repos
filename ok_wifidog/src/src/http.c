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


#define OKOS_MAKE_JOKE_WITH_CLIENT

#ifdef OKOS_MAKE_JOKE_WITH_CLIENT
#define okos_send_http_page(r, title, msg)  okos_send_page_to_stranger(r, title, msg)
#else
#define okos_send_http_page(r, title, msg) ;
#endif


static void http_send_redirect_to_auth(request *, const char *, const char *, const struct _auth_serv_t *, const char *);
static void http_send_redirect(request * r, const char *url, const char *text);
static void okos_send_page_to_insider(request *r, const char *title, const char *msg);
static void okos_send_page_to_stranger(request *r, const char *title, const char *msg);
static void okos_send_simple_reply(request *r, const char *title, const char* msg);


/*-----------------------------------------------------------------------------
 * In this block, we implemented a mechanism to
 *      1) Register Hooks
 *      2) Implement a WEB Shell
 * --------------------------------------------------------------------------*/
static const char *okos_query_block = "<h3><input class=\"qtext\" name=question type=\"text\" maxlength=\"256\" size=\"48\"></h3>";
static void okos_http_cb_wifidog_show(httpd *webserver, request *r)
{
    okos_send_page_to_insider(r, "Life is short, play hard!", okos_query_block);
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
                    okos_send_page_to_insider(r, "OKOS", msg);
                    free(buf);
                    free(msg);
                    return;
                }
                break;
            }
        }
    }
    debug(LOG_DEBUG, "HTTP callback %s unregisted.", key);

    okos_http_cb_wifidog_show(webserver, r);
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

static void
okos_http_callback_wifidog_query(httpd *webserver, request *r, const char *query)
{
    char *key = NULL;
    char *value = NULL;
    int parseFailed = okos_http_analyze_key_value(query, &key, &value);
    if (parseFailed) {
        okos_http_cb_wifidog_show(webserver, r);
        return;
    }

    okos_http_callback_exec(webserver, r, key, value);

    free(key);
    free(value);
}

void
okos_http_cb_wifidog(httpd * webserver, request * r)
{
    httpVar *question = httpdGetVariableByName(r, "question");
    if (NULL == question || 0 == strcmp(question->value, "")) {
        okos_http_cb_wifidog_show(webserver, r);
    } else {
        okos_http_callback_wifidog_query(webserver, r, question->value);
    }
}

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


/*-----------------------------------------------------------------------------
 * Below this point, all the webserver content here:
 *  1) http_callback_404: handle all the redirected http request
 *  2) http_callback_auth_qrcode: handle http requets redirected from 10.10.111.111
 *  3) http_callback_auth: handle login confirm
 *  4) http_callback_auth_allow: handle 'let it go' temporarily.
 * --------------------------------------------------------------------------*/
static int okos_http_check_whitelist(request *r, char *url)
{
    // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
    // e.g. www.example.com  
    debug(LOG_DEBUG, "<WHITELIST> Check host %s is in global whitelist or not", r->request.host);
    t_firewall_rule *p_rule;
    //e.g. example.com is in whitelist
    // if request http://www.example.com/, it's not equal example.com.
    for (p_rule = get_ruleset("global"); NULL != p_rule; p_rule = p_rule->next) {
        debug(LOG_DEBUG, "<WHITELIST>\t rule mask %s", p_rule->mask);
        if (NULL == strstr(r->request.host, p_rule->mask)) {
            debug(LOG_DEBUG, "<WHITELIST>\t host %s is not in %s, continue",
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
                debug(LOG_DEBUG, "<WHITELIST>\t allow subdomain");
                fw_allow_host(r->request.host, NULL);
                http_send_redirect(r, url, "allow subdomain");
                return 0;
            }
        } else {
            /* e.g. "example.com" is in conf, so it had been parse to IP and
             * added into "iptables allow" when wifidog start.
             * but then its' A record(IP) changed, it will go to here.*/
            debug(LOG_DEBUG, "<WHITELIST>\t allow domain again, because IP changed");
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
    debug(LOG_DEBUG, "<WHTIELIST> Check host %s is in whitelist or not for ssid(%s).",
            r->request.host, ssid->ssid);
    t_firewall_rule *p_rule;
    //e.g. example.com is in whitelist
    // if request http://www.example.com/, it's not equal example.com.
    okos_list_for_each(p_rule, ssid->dn_white_list->rules) {
        debug(LOG_DEBUG, "<WHTIELIST>\t rule mask %s", p_rule->mask);
        if (NULL == strstr(r->request.host, p_rule->mask)) {
            debug(LOG_DEBUG, "<WHTIELIST>\t host %s is not in %s, continue", r->request.host, p_rule->mask);
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
                debug(LOG_DEBUG, "<WHTIELIST>\t allow subdomain");
                fw_allow_host(r->request.host, ssid);
                http_send_redirect(r, url, "allow subdomain");
                return 0;
            }
        } else {
            /* e.g. "example.com" is in conf, so it had been parse to IP and
             * added into "iptables allow" when wifidog start.
             * but then its' A record(IP) changed, it will go to here.*/
            debug(LOG_DEBUG, "<WHTIELIST>\t allow domain again, because IP changed");
            fw_allow_host(r->request.host, ssid);
            http_send_redirect(r, url, "allow domain");
            return 0;
        }
    }
    return 1;
}

void okos_add_validation_client(t_client **p_client)
{
    t_client *client = *p_client;
    if (NULL == client) {
        debug(LOG_DEBUG, "<client_info>!! Try to insert NULL VALIDATED Client.");
        return;
    }

    LOCK_CLIENT_LIST();
    t_client *old = client_list_find_by_ssid(client->mac, client->ssid->ssid);
    if (NULL == old) {
        client_list_set_polling_flag(client);
        client_list_insert_client(&client);
        if (client) {
            pthread_cond_signal(&client_polling_cond);
            fw_allow(client, FW_MARK_KNOWN);
            debug(LOG_DEBUG, "<client_info>\t Insert a new VALIDATION client"
                    "{%s, %s, %s, remain_time:%ld}.",
                    client->ip, client->mac, client->if_name, client->remain_time);
        }
    } else {
        debug(LOG_DEBUG, "<client_info>\t VALIDATION client"
                "{%s, %s, %s, remain_time:%ld} is already in.",
                client->ip, client->mac, client->if_name, client->remain_time);
        client_free_node(client);
    }
    UNLOCK_CLIENT_LIST();
    served_this_session++;
    *p_client = NULL;
}


static void okos_try_to_add_client_into_list(t_client **p_client)
{
    t_client *client = *p_client;
    if (NULL == client) {
        debug(LOG_DEBUG, "<client_info>!! Try to insert NULL client.");
        return;
    }
    LOCK_CLIENT_LIST();

    t_client *p_old = client_list_find_by_ssid(client->mac, client->ssid->ssid);
    if (NULL == p_old) {
        debug(LOG_DEBUG, "<client_info>\t Insert New ALLOWED client {%s, %s, %s}",
                client->ip, client->mac, client->if_name);
        client_list_unset_polling_flag(client);
        client_list_insert_client(&client);
        if (client) {
            /***********************************************************************
             * Trigger Timeout thread polling client list
             */
            pthread_cond_signal(&client_polling_cond);
            fw_allow(client, FW_MARK_KNOWN);
        }
    } else {
        debug(LOG_INFO, "<client_info>\t ALLOWED Client"
                "{%s, %s, %s, remain_time:%ld} is already in.",
                p_old->ip, p_old->mac, p_old->if_name, p_old->remain_time);
        client_list_unset_polling_flag(p_old);
        okos_client_list_flush_all(p_old, client);
    }

    UNLOCK_CLIENT_LIST();
    served_this_session++;
    *p_client = NULL;
}


#ifdef OKOS_PORTAL_PRECHECK
/*******************************************************************************
 * Caution! This function should NOT work well since the configuration of 
 * auth server had been moved from ssid to global.
 */
static t_client * okos_query_auth_server(t_client *p_client)
{
    debug(LOG_DEBUG, "~~ Querying auth server.");
    
    t_authresponse auth_code;
    int updateFailed = 1;
    updateFailed = auth_server_request(&auth_code, p_client);
    if (!updateFailed && AUTH_ALLOWED == auth_code.authcode) {
        debug(LOG_DEBUG, "~~ Auth Server recoganize {%s,%s,%s} Let it go.",
                p_client->ip, p_client->mac, p_client->if_name);
        okos_try_to_add_client_into_list(&p_client);

        return NULL;
    }
    debug(LOG_DEBUG, "~~ Auth Server won't let {%s,%s,%s} go.",
            p_client->ip, p_client->mac, p_client->if_name);
    return p_client;
}
#endif


/** The 404 handler is also responsible for redirecting to the auth server */
void
okos_http_cb_404(httpd *webserver, request *r, int error_code)
{
    debug(LOG_DEBUG, "<HTTPD_404> Client {%s} request.", r->clientAddr);

    /*---------------------------------------------------------------
     * STEP 1: ONLY accept GET request.
     * ------------------------------------------------------------*/
    if (HTTP_GET != r->request.method) {
        debug(LOG_DEBUG, "<HTTPD_404> Drop HTTP request(%d) for Client {%s}, only GET accepted.",
                r->request.method, r->clientAddr);
        goto cb_404_leave_for_bad_method;
    }

    /*---------------------------------------------------------------
     * STEP 2: Prepare client's original URL.
     * ------------------------------------------------------------*/
    char a_tmp_url[MAX_BUF];
    memset(a_tmp_url, 0, sizeof(a_tmp_url));
    snprintf(a_tmp_url, (sizeof(a_tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);

    /*---------------------------------------------------------------
     * STEP 3: Prepare Datebase.
     * ------------------------------------------------------------*/
    sqlite3 *stainfo_db = okos_open_stainfo_db();
    if (NULL == stainfo_db) {
        goto cb_404_open_db_failed;
    }
    
    /*---------------------------------------------------------------
     * STEP 3: Build a client based on IP address
     *         1) client->MAC <= arp table
     *         2) client->if_name <= database
     *         3) ssid, scheme <= configuration
     *         4) ifx, ssid.
     *
     *         If can't acquire local information, just say sorry.
     *         CLIENT will be released if we can't piese local info together.
     *
     *         After this, we got HALF client.
     * ------------------------------------------------------------*/
    debug(LOG_DEBUG, "<HTTPD_404> Try to build a new client for {ip:%s}.", r->clientAddr);
    t_client *p_client = okos_client_get_new(r->clientAddr);
    okos_fill_local_info_by_stainfo(&p_client, stainfo_db);
    if (NULL == p_client) {
        debug(LOG_ERR, "<HTTPD_404>!! Failed to piese info for client(%s).", r->clientAddr);
        okos_send_http_page(r, "Login", "Do not support anonymous yet");
        goto cb_404_cannt_get_new_client;
    }
    if (!okos_conf_ssid_is_portal(p_client->ssid)) {
        debug(LOG_DEBUG, "<HTTPD_404> Client {%s} request from invalid ssid", r->clientAddr);
        goto cb_404_ssid_not_support_portal;
    }
    debug(LOG_INFO, "<HTTPD_404> Client {%s, %s, %s} redirected portal.",
            p_client->ip, p_client->mac, p_client->if_name);

    /*---------------------------------------------------------------
     * STEP 5: Checking in the Domain Name White List.
     *         It is triggered by IP change of target domain name.
     *         Otherwise, normally the package should be bypassed
     *         in iptables.
     * ------------------------------------------------------------*/
    int canntMatchHostInWhiteList;
    canntMatchHostInWhiteList = okos_http_check_whitelist(r, a_tmp_url);
    if (!canntMatchHostInWhiteList) {
        debug(LOG_DEBUG, "<HTTPD_404> Match target in global WhiteList, redirect client, exit 404.");
        goto cb_404_match_global_whitelist;
    }
    canntMatchHostInWhiteList = okos_http_check_whitelist_by_ssid(r, a_tmp_url, p_client->ssid);
    if (!canntMatchHostInWhiteList) {
        debug(LOG_DEBUG, "<HTTPD_404> Match target in WhiteList on ssid(%s), redirect client, exit 404.",
                p_client->ssid->ssid);
        goto cb_404_match_ssid_whitelist;
    }

    /*---------------------------------------------------------------
     * STEP 4: Re-direct them to auth server.
     *         1) Encode original URL, and attach it as a parameter.
     *         2) Assemble `INFO` parameter from client local info.
     *         3) Create new url
     *         4) Send 302 redirect client to auth server.
     * ------------------------------------------------------------*/
    t_auth_serv *auth_server = get_auth_server();
    if (NULL == auth_server) {
        debug(LOG_WARNING, "<HTTPD_404>!! Without AuthSvr, Drop %s:%s's request.", p_client->ip, p_client->mac);
        okos_send_http_page(r, "Login", "Uh oh! Internet access unavailable! Take it easy.");
        goto cb_404_without_auth_server;
    }
    char *s_url = httpdUrlEncode(a_tmp_url);
    char *s_info = okos_http_assemble_INFO(p_client);
    char *s_urlFragment;
    debug(LOG_DEBUG, "<HTTPD_404> <%s's info>=[%s]", p_client->mac, s_info);
    debug(LOG_INFO, "<HTTPD_404> <%s's originalurl>=[%s]", p_client->mac, s_url);
    safe_asprintf(&s_urlFragment, "%sinfo=%s&originalurl=%s",
            auth_server->authserv_login_script_path_fragment, s_info, s_url);

    http_send_redirect_to_auth(r, s_urlFragment, "Redirect to login page", auth_server, "");
    okos_sta_log(LOG_INFO, "{'sta_mac':'%s','logmsg':'Client requests portal page on %s for [%s]'}", p_client->mac, p_client->ssid->ssid, a_tmp_url);

cb_404_final_clean_up:
    free(s_urlFragment);
    free(s_info);
    free(s_url);

cb_404_without_auth_server:
cb_404_match_ssid_whitelist:
cb_404_match_global_whitelist:
cb_404_ssid_not_support_portal:
    client_free_node(p_client);
cb_404_cannt_get_new_client:
    okos_close_stainfo_db(stainfo_db);
cb_404_open_db_failed:
cb_404_original_url_detect:
cb_404_leave_for_bad_method:
    return;
}

/*-------------------------------------------------------------------
 * This callback will be accessed through qrcode.
 * 1) Guest accessed portal will get a qrcode, they'd like to go for legal employee
 * 2) Autheticator(employee) will help to scan this qrcode.
 *      1) That leads to access 10.10.111.111/auth/client/qrcode
 *      2) Iptables could redirect all the attempt to 10.10.111.111.
 *
 * What we should do:
 * 1) Build up INFO for Authenticator, just like what we do in 404.
 * 2) Re-assemble all the variables in qrcode.
 * ----------------------------------------------------------------*/
void
okos_http_cb_qrcode(httpd *webserver, request *r)
{
    debug(LOG_DEBUG, "<HTTPD_qrcode> Received request for auth qrcode from %s", r->clientAddr);

    sqlite3 *stainfo_db = okos_open_stainfo_db();
    if (NULL == stainfo_db) {
        goto cb_qrcode_open_db_failed;
    }
    /*---------------------------------------------------------------
     * Try to build up INFO for Authenticator.
     * Just like what we do in 404.
     * ------------------------------------------------------------*/
    debug(LOG_DEBUG, "<HTTPD_qrcode> Try to build a new client for {%s}.", r->clientAddr);
    t_client *p_client = okos_client_get_new(r->clientAddr);
    okos_fill_local_info_by_stainfo(&p_client,stainfo_db);
    if (NULL == p_client) {
        debug(LOG_ERR, "<HTTPD_qrcode> Failed to retrieve info for client(%s),"
                "so not putting in login request.", r->clientAddr);
        okos_send_http_page(r, "Auth qrcode", "Do not support anonymous yet");
        goto cb_qrcode_cant_get_local_info;
    }
    debug(LOG_NOTICE, "<HTTPD_qrcode> Client {%s, %s, %s}",
            p_client->ip, p_client->mac, p_client->if_name);

    t_auth_serv *auth_server = get_auth_server();
    if (NULL == auth_server) {
        debug(LOG_WARNING, "<HTTP_qrcode>!! %s:%s's AuthSvr is invalid.", p_client->ip, p_client->mac);
        okos_send_http_page(r, "Auth qrcode", "Uh oh! Internet access unavailable! Take it easy.");
        goto cb_qrcode_not_auth_server;
    }

    /*---------------------------------------------------------------
     * Send INFO of Authenticator with original variables of guest.
     * 1) Re-assemble all the variables in qrcode.
     * 2) Insert Local INFO for Authenticator.
     * ------------------------------------------------------------*/
    pstr_t *p_str = pstr_new();
    httpVar *p_var;
    for (p_var = r->variables; NULL != p_var; p_var = p_var->nextValue) {
        pstr_append_sprintf(p_str, "&%s=%s", p_var->name, p_var->value);
    }
    char *s_variables = pstr_to_string(p_str);
    debug(LOG_DEBUG, "<HTTPD_qrcode> Copy variables from original request. %s", s_variables);

    char *s_source = okos_http_assemble_INFO(p_client);
    char *s_urlFragment;
    safe_asprintf(&s_urlFragment, "%ssource=%s%s",
            auth_server->authserv_login_script_path_fragment, s_source, s_variables);

    debug(LOG_NOTICE, "<HTTPD_qrcode> Authenticator {%s, %s, %s}"
            "requesting [%s] and re-directed.",
            p_client->ip, p_client->mac, p_client->if_name, s_urlFragment);
    http_send_redirect_to_auth(r, s_urlFragment, "Redirect to qrcode page", auth_server, "/qrcode");

    free(s_urlFragment);
    free(s_source);
    free(s_variables);

cb_qrcode_not_auth_server:
    client_free_node(p_client);
cb_qrcode_cant_get_local_info:
    okos_close_stainfo_db(stainfo_db);
cb_qrcode_open_db_failed:
    return;
}

/*-------------------------------------------------------------------
 * This is for 'Let it go, temporarily.
 * Normally, It's just about 5 ~ 10 seconds to
 * 1) bypass the backgroud session.
 * 2) Let WiFi portal show 'Completed'.
 *
 * Since using period thread to control the validation time of client,
 * It can not be accurate right now.
 * ----------------------------------------------------------------*/
void 
okos_http_cb_allow(httpd *webserver, request *r)
{
    debug(LOG_DEBUG, "<HTTPD_allow> Got VALIDATION for %s.", r->clientAddr);

    httpVar *time = httpdGetVariableByName(r, "time");
    if (NULL == time) {
        okos_send_http_page(r, "Auth Allowed",
                "I'd like to let you go, but I don't know how long.");
        debug(LOG_WARNING, "<HTTPD_allow>!! Receive code 'allow' for %s without 'time'.", r->clientAddr);
        return;
    }
    
    sqlite3 *stainfo_db = okos_open_stainfo_db();
    if (NULL == stainfo_db) {
        return;
    }
    
    t_client *client = okos_client_get_new(r->clientAddr);
    okos_fill_local_info_by_stainfo(&client, stainfo_db);
    okos_close_stainfo_db(stainfo_db);
    if (NULL == client) {
        okos_send_http_page(r, "Auth Allowed", "Don't give up! To be strong.");
        debug(LOG_WARNING, "<HTTPD_allow>!! Cant create new client %s for allow code.", r->clientAddr);
        return;
    }
    /*-----------------------------------------------------
     * Invalidate Client Field:
     * {auth_mode(int), user_name}
     * --------------------------------------------------*/
    okos_client_update_allow_time(&client, time->value);
    if (NULL == client) {
        okos_send_http_page(r, "Auth Allowed", "Can't let you go.");
        debug(LOG_WARNING, "<HTTPD_allow> We can't add a new validation correctly for %s:%s.", client->ip, client->mac);
        return;
    }

    debug(LOG_NOTICE, "<HTTPD_allow> Client {%s, %s, %s} VALIDATED!",
            client->ip, client->mac, client->if_name);
    okos_sta_log(LOG_INFO, "{'sta_mac':'%s','logmsg':'Network access allowed temporarily on %s.'}", client->mac, client->ssid->ssid);
    /*-----------------------------------------------------
     * pointer client is NULL after here.
     * --------------------------------------------------*/
    okos_add_validation_client(&client);

    okos_send_simple_reply(r, "Auth Allowed", "Move on!");
    return;
}



void okos_http_cb_auth(httpd *webserver, request *r)
{
    debug(LOG_DEBUG, "<HTTPD_auth> %s Calling http_callback_auth.", r->clientAddr);
    httpVar *auth = httpdGetVariableByName(r, "auth");
	if (NULL == auth) {
        okos_send_http_page(r, "Auth Confirm", "Invalid Auth Parameter");
        debug(LOG_WARNING, "<HTTPD_auth>!! Can't get AUTH from server for client(%s)",
                r->clientAddr);
        goto cb_auth_variable_inavailable;
    }

    t_client *client = okos_client_get_new(r->clientAddr);
    debug(LOG_DEBUG, "<HTTPD_auth> Start to parse %s's AUTH parameter.", r->clientAddr);
    int parseFailed = okos_http_parse_AUTH(auth->value, client);
    if (parseFailed) {
        okos_send_http_page(r, "Auth Confirm", "Uncompleted auth parameter");
        debug(LOG_WARNING, "<HTTPD_auth>!! Can't parse %s's AUTH correctly."
                "code: %d", r->clientAddr, parseFailed);
        goto cb_auth_parse_variable_failed;
    }
    sqlite3 *stainfo_db = okos_open_stainfo_db();
    if (NULL == stainfo_db) {
        goto cb_auth_open_db_failed;
    }
    okos_fill_local_info_by_stainfo(&client, stainfo_db);
    char mac[18] = '\0';
    strncpy(mac, client->mac, 18);
    if (client) {
        okos_update_station_info_v1(stainfo_db, client);
        okos_close_stainfo_db(stainfo_db);
        debug(LOG_NOTICE, "<HTTPD_auth> Client{%s, %s, %s} PASSED!",
                client->ip, client->mac, client->ssid->ssid);
        okos_sta_log(LOG_INFO, "{'sta_mac':'%s','logmsg':'Authentication passed on %s.'}", client->mac, client->ssid->ssid);
        /*-----------------------------------------------------
        * pointer client is NULL after here.
        * --------------------------------------------------*/
        okos_try_to_add_client_into_list(&client);
    } else {
        okos_close_stainfo_db(stainfo_db);
        okos_send_http_page(r, "Auth Confirm", "Can't fill local information.");
        debug(LOG_WARNING, "<HTTPD_auth>!! Can't fill local info for client(%s)", r->clientAddr);
        goto cb_auth_fill_local_info_failed;
    }
    /* Client is gone here, because
     * 1) either added into client list;
     * 2) or removed for lack of local information.
     * ------------------------------------------------------------*/

    httpVar *flag = httpdGetVariableByName(r, "flag");
    int donot_redirect = 0;
    if (NULL != flag) {
        sscanf(flag->value, "%d", &donot_redirect);
    }
    httpVar *redirecturl = httpdGetVariableByName(r, "redirecturl");
    if (NULL == redirecturl)
        donot_redirect = 1;

    if (!donot_redirect) {
        debug(LOG_DEBUG, "<HTTPD_auth> Redirect client %s to the assigned web page.", r->clientAddr);
        okos_sta_log(LOG_INFO, "{'sta_mac':'%s', 'logmsg':'Redirect %s to  %s.'}", mac, r->clientAddr, redirecturl->value);
        char *url= NULL;
        safe_asprintf(&url, "%s", redirecturl->value);
        http_send_redirect(r, url, "Redirect to portal");
        free(url);
    } else {
        okos_send_http_page(r, "Auth Confirm", "Life is short, play! my friend");
    }

cb_auth_fill_local_info_failed:
    return;

cb_auth_open_db_failed:
cb_auth_parse_variable_failed:
    client_free_node(client);
cb_auth_variable_inavailable:
    return;
}


#if 0
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
void http_callback_wifidog(httpd *webserver, request *r)
{
    char *buf;
    safe_asprintf(&buf, "  <input class=\"qtext\" name=question type=\"text\" maxlength=\"256\" size=\"48\">");
    send_http_page(r, "Life is short, play hard!", buf);
    free(buf);
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
    send_http_page(r, "OKOS Status", buf);
    free(buf);
    free(status);
}


/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

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
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}
#endif


static void
http_send_redirect_to_auth(request *r, const char *urlFragment, const char *text, const t_auth_serv *auth_server, const char *append)
{
    char *protocol = NULL;
    int port = 80;

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

static void
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
    okos_send_page_to_stranger(r, text ? text : "Redirection to message", message);

    free(message);
}

static void
okos_send_page(request * r, const char *title, const char *message, const char *subtitle)
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
    httpdAddVariable(r, "nodeID", subtitle);

    httpdOutput(r, buffer);
    free(buffer);
}

static void
okos_send_simple_reply(request *r, const char* title, const char* msg)
{
    httpdPrintf(r, "%s: %s", title, msg);
}


static void 
okos_send_page_to_insider(request *r, const char *title, const char *msg)
{
    s_config *config = config_get_config();
    okos_send_page(r, title, msg, config->device_id);
}

static void
okos_send_page_to_stranger(request *r, const char *title, const char *msg)
{
    okos_send_page(r, title, msg, "");
}
