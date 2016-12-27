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
static char * okos_http_insert_parameter(const request * r, const char * halfUrl);
#endif

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
    char tmp_url[MAX_BUF], *url;
#if OK_PATCH
#else
    char *mac;
    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
#endif
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
#if OK_PATCH
        char *urlFragment = okos_http_insert_parameter(r, url);
#else
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
#endif

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

#if OK_PATCH
#define OKOS_URLPARA_SSID_MLEN 32
#define OKOS_URLPARA_DOMAIN_MLEN 32
#define OKOS_URLPARA_SCHEME_MLEN 100
typedef struct s_http_auth_str {
    unsigned char len;
    char content[255];
}t_http_auth_str;

typedef struct s_http_auth_info_pri {
    /* Pravite Part: */
#define OKOS_BRIF_NAME_LEN 64
#define OKOS_UNKNOWN_BR "br-OKOS_UNKNOWN_BRIDGE_INTERFACE"
    char br_interface[OKOS_BRIF_NAME_LEN+1];
}t_http_auth_info_pri;

typedef struct s_http_auth_info {
    unsigned char version; //version == 3

    unsigned char device_mac[6];
    
    unsigned char client_mac[6];
    unsigned int  client_ip;

    unsigned char ssid_len;
    char ssid[OKOS_URLPARA_SSID_MLEN];
    unsigned char domain_len;
    char domain[OKOS_URLPARA_DOMAIN_MLEN];
    unsigned char scheme_len;
    char scheme[OKOS_URLPARA_SCHEME_MLEN];

    unsigned char bssid[6];
}t_http_auth_info;

static char * my_ssid = "ok_1st";
static char * my_domain = "D4E78543656449ABA9EC385D001BAB71";
static char * my_scheme = "1";

static inline void okos_http_simulate_string(unsigned char * buflen, char * str,
        const char * simulator, const unsigned char limit)
{
    char len = strlen(simulator);
    *buflen = len > limit ? limit : len;
    strncpy(str, simulator, *buflen);
}
static int okos_mac_str2bin(const char * macstr, unsigned char * mac)
{
    if (macstr == NULL || strlen(macstr) != 17)
        goto bad;
    unsigned int tmp[6];
    if (sscanf(macstr, "%2x:%2x:%2x:%2x:%2x:%2x", &tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]) != 6)
        goto bad;
    
    int i;
    for (i = 0; i < 6; i++)
        mac[i] = tmp[i] & 0xFF;

    return 0;

bad:
    memset(mac, 0, 6);
    return -1;
}
static inline void okos_get_br_from_client_ip(const char * ip, char * brX, unsigned char * mac)
{
    if (arp_get_all(ip, brX, mac) != 0) {
        memset(mac, 0, 6);
        brX = OKOS_UNKNOWN_BR ;
    }

    debug(LOG_INFO, "Got client [%2x:%2x:%2x:%2x:%2x:%2x] from %s for ip %s",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], brX, ip);
}
static int okos_http_simulate_client_info(const request * r, t_http_auth_info * info)
{
    info->version = 3;
    s_config *config = config_get_config();
    okos_mac_str2bin(config->gw_id, info->device_mac);
    memcpy(info->bssid, info->device_mac, 6);
    info->client_ip = inet_addr(r->clientAddr);

    t_http_auth_info_pri private;
    okos_get_br_from_client_ip(r->clientAddr, private.br_interface, info->client_mac);
    
    okos_http_simulate_string(&info->ssid_len, info->ssid, my_ssid, sizeof(info->ssid));
    okos_http_simulate_string(&info->domain_len, info->domain, my_domain, sizeof(info->domain));
    okos_http_simulate_string(&info->scheme_len, info->scheme, my_scheme, sizeof(info->scheme));

    return 0;
}

static unsigned char * okos_http_serial_auth_info(const request * r, int * len)
{
    t_http_auth_info info;
    okos_http_simulate_client_info(r, &info);

    unsigned char * urltmp = safe_malloc(sizeof(t_http_auth_info));
    unsigned char * pt = urltmp;

    *pt++ = info.version;
    memcpy(pt, info.device_mac, 6);
    pt += 6;
    memcpy(pt, info.client_mac, 6);
    pt += 6;
    memcpy(pt, (char *)(&(info.client_ip)), 4);
    pt += 4;
    
    *pt++ = info.ssid_len;
    memcpy(pt, info.ssid, info.ssid_len);
    pt += info.ssid_len;

    *pt++ = info.domain_len;
    memcpy(pt, info.domain, info.domain_len);
    pt += info.domain_len;
    
    *pt++ = info.scheme_len;
    memcpy(pt, info.scheme, info.scheme_len);
    pt += info.scheme_len;

    memcpy(pt, info.bssid, 6);
    pt += 6;

    *len = pt - urltmp;

    return urltmp;
}

static unsigned char * okos_http_hex2byte(const char * hex, int* len)
{
    int num = strlen(hex)/2;
    unsigned char * bytes = safe_malloc(num);

    int i;
    for (i = 0; i < num; i++) {
        int j;
        unsigned char tmp[2];
        for (j = 0; j < 2; j++) {
            if (hex[i*2+j] >= '0' && hex[i*2+j] <= '9'){
                tmp[j] = hex[i*2+j] - '0';
            }else if (hex[i*2+j] >= 'a' && hex[i*2+j] <= 'z'){
                tmp[j] = hex[i*2+j] - 'a';
            }else if (hex[i*2+j] >= 'A' && hex[i*2+j] <= 'Z'){
                tmp[j] = hex[i*2+j] - 'A';
            }else {
                free(bytes);
                return NULL;
            }
        }
        bytes[i] = ((tmp[0]&0xF) << 4) | (tmp[1]&0xF);
    }

    *len = num;
    return bytes;
}

static char * okos_http_byte2hex(const unsigned char * bytes, const int len)
{
    char * hex = safe_malloc(len*2+1);
    char alph[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    int i,j;
    for (j = 0, i = 0; i < len; i++){
        hex[j++] = alph[bytes[i] >> 4 & 0xF];
        hex[j++] = alph[bytes[i] & 0xF];
    }
    hex[j] = '\0';
    return hex;
}

static inline void okos_http_encrypt_auth_info(unsigned char * hex, const int len)
{
    int i;
    for (i = 0; i < len; i++) hex[i] ^= 0xDA;
}

static char * okos_http_insert_parameter(const request * r, const char * halfUrl)
{
    int len = 0;
    unsigned char * urlBytes = okos_http_serial_auth_info(r, &len);
    okos_http_encrypt_auth_info(urlBytes, len);
    char * info = okos_http_byte2hex(urlBytes, len);
    free(urlBytes);

    char * urlRet;
    t_auth_serv *auth_server = get_auth_server();
    safe_asprintf(&urlRet, "%sinfo=%s&originalurl=%s",
                  auth_server->authserv_login_script_path_fragment, info, halfUrl);

    free(info);
    return urlRet;
}

#endif

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
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
#define OKOS_URLPARA_USRNM_MLEN 64
typedef struct s_auth_confirm_info {
    unsigned char version;
    unsigned char mac_num;
    unsigned char mac1[6];
    unsigned char mac2[6];
    unsigned int auth_mode;
    unsigned int remain_time;
    unsigned char user_len;
    char user[OKOS_URLPARA_USRNM_MLEN+1];
}t_auth_confirm_info;

static int okos_http_parse_info(const unsigned char * info, t_auth_confirm_info * res)
{
    return 0;
}

void http_callback_auth(httpd * webserver, request * r)
{
    httpVar * auth = httpdGetVariableByName(r, "auth");
    httpVar * redirecturl = httpdGetVariableByName(r, "redirecturl");
    //httpVar * key =  httpdGetVariableByName(r, "key");
    //httpVar * flag = httpdGetVariableByName(r, "flag");

    if (auth == NULL || redirecturl == NULL)
        goto bad;
    int len = 0;
    unsigned char * info = okos_http_hex2byte(auth->value, &len);
    if (info == NULL)
        goto bad;

    okos_http_encrypt_auth_info(info, len);

    t_auth_confirm_info cli_info;
    if (okos_http_parse_info(info, &cli_info) != 0)
        goto bad;

    /* We get auth result from server. */
    char * mac;
    if (!(mac = arp_get(r->clientAddr))) {
        /* We could not get their MAC address */
        debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
        send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
    } else {
        /* We have their MAC address */
        LOCK_CLIENT_LIST();

        t_client *client;
        if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
            debug(LOG_DEBUG, "New client for %s", r->clientAddr);
            //client_list_add(r->clientAddr, mac, token->value);
        } else {
            debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
        }

        UNLOCK_CLIENT_LIST();


        free(mac);
    }

    return;

bad:
    /* We don't get enough information. */
    send_http_page(r, "okos error", "Invalid data");
    return;
}
#else
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
#endif

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
