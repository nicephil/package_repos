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
/** @file wdctl_thread.c
    @brief Monitoring and control of wifidog, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>
#include "common.h"
#include "httpd.h"
#include "util.h"
#include "wd_util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "commandline.h"
#include "gateway.h"
#include "safe.h"
#include "okos_auth_param.h"


static int create_unix_socket(const char *);
static int write_to_socket(int, char *, size_t);
static void *thread_wdctl_handler(void *);

static void okos_wdctl_status(int, const char*, const char*);
static void okos_wdctl_stop(int, const char*, const char*);
static void okos_wdctl_restart(int, const char*, const char*);
static void okos_wdctl_reset(int, const char *, const char *);
static void okos_wdctl_offline(int, const char *, const char *);
static void okos_wdctl_query_mac(int, const char *, const char *);
static void okos_wdctl_config(int, const char *, const char *);
static void okos_wdctl_insert(int, const char *, const char *);

static int wdctl_socket_server;

typedef void (*okos_wdctl_exec)(int, const char*, const char*);
static const struct {
    const char *name;
    unsigned int param1_len;
    unsigned int param2_len;
    okos_wdctl_exec action;
} cmds[] = {
    {"status", 0, 0, okos_wdctl_status},
    {"stop", 0, 0, okos_wdctl_stop},
    {"restart", 0, 0, okos_wdctl_restart},
    {"config", 0, 0, okos_wdctl_config},
    {"reset", okos_mac_len, 0, okos_wdctl_reset},
    {"offline", okos_mac_len, 0, okos_wdctl_offline},
    {"query", okos_mac_len, 0, okos_wdctl_query_mac},
    {"insert", okos_mac_len, 0, okos_wdctl_insert},
    {NULL, 0, 0, NULL},
};

static int
create_unix_socket(const char *sock_name)
{
    struct sockaddr_un sa_un;
    int sock;

    memset(&sa_un, 0, sizeof(sa_un));

    if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
        /* TODO: Die handler with logging.... */
        debug(LOG_ERR, "<WDCTL> socket name too long");
        return -1;
    }

    sock = socket(PF_UNIX, SOCK_STREAM, 0);

    if (sock < 0) {
        debug(LOG_DEBUG, "<WDCTL> Could not get unix socket: %s", strerror(errno));
        return -1;
    }
    debug(LOG_DEBUG, "<WDCTL> Got unix socket %d", sock);

    /* If it exists, delete... Not the cleanest way to deal. */
    unlink(sock_name);

    debug(LOG_DEBUG, "<WDCTL> Filling sockaddr_un");
    strcpy(sa_un.sun_path, sock_name);
    sa_un.sun_family = AF_UNIX;

    debug(LOG_DEBUG, "<WDCTL> Binding socket (%s) (%d)", sa_un.sun_path, strlen(sock_name));

    /* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
    if (bind(sock, (struct sockaddr *)&sa_un, sizeof(struct sockaddr_un))) {
        debug(LOG_ERR, "<WDCTL> Could not bind unix socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 5)) {
        debug(LOG_ERR, "<WDCTL> Could not listen on control socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_wdctl(void *arg)
{
    int *fd;
    char *sock_name;
    struct sockaddr_un sa_un;
    int result;
    pthread_t tid;
    socklen_t len;

    debug(LOG_DEBUG, "<WDCTL> Starting wdctl.");

    sock_name = (char *)arg;
    debug(LOG_DEBUG, "<WDCTL> Socket name: %s", sock_name);

    debug(LOG_DEBUG, "<WDCTL> Creating socket");
    wdctl_socket_server = create_unix_socket(sock_name);
    if (-1 == wdctl_socket_server) {
        termination_handler(0);
    }

    while (1) {
        len = sizeof(sa_un);
        memset(&sa_un, 0, len);
        fd = (int *)safe_malloc(sizeof(int));
        if ((*fd = accept(wdctl_socket_server, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "<WDCTL> Accept failed on control socket: %s", strerror(errno));
            free(fd);
        } else {
            debug(LOG_DEBUG, "<WDCTL> Accepted connection on wdctl socket %d (%s)",
                    fd, sa_un.sun_path);
            result = pthread_create(&tid, NULL, &thread_wdctl_handler, (void *)fd);
            if (result != 0) {
                debug(LOG_ERR, "<WDCTL> FATAL: Failed to create a new thread"
                        "(wdctl handler) - exiting");
                free(fd);
                termination_handler(0);
            }
            pthread_detach(tid);
        }
    }
}

static void *
thread_wdctl_handler(void *arg)
{
    int fd, done;
    char request[MAX_BUF];
    size_t read_bytes, i;
    ssize_t len;

    debug(LOG_DEBUG, "<WDCTL> Entering thread_wdctl_handler....");

    fd = *((int *)arg);
    free(arg);
    debug(LOG_DEBUG, "<WDCTL> Read bytes and stuff from fd[%d]", fd);

    /* Init variables */
    read_bytes = 0;
    done = 0;
    memset(request, 0, sizeof(request));

    /* Read.... */
    while (!done && read_bytes < (sizeof(request) - 1)) {
        len = read(fd, request + read_bytes, sizeof(request) - read_bytes);
        /* Have we gotten a command yet? */
        for (i = read_bytes; i < (read_bytes + (size_t) len); i++) {
            if (request[i] == '\r' || request[i] == '\n') {
                request[i] = '\0';
                done = 1;
            }
        }

        /* Increment position */
        read_bytes += (size_t) len;
    }
    if (!done) {
        debug(LOG_ERR, "<WDCTL> Invalid wdctl request.");
        shutdown(fd, 2);
        close(fd);
        pthread_exit(NULL);
    }

    debug(LOG_DEBUG, "<WDCTL> Request received: [%s]", request);
    int c;
    for (c = 0; NULL != cmds[c].name; c++) {
        int cmd_len = strlen(cmds[c].name);
        int param2_pos = cmd_len + cmds[c].param1_len + 1;
        if (0 == strncmp(request, cmds[c].name, cmd_len)) {
            request[param2_pos] = 0;
            if (cmds[c].action) {
                cmds[c].action(fd, request + cmd_len + 1, request + param2_pos + 1);
            }
            break;
        }
    }
    if (NULL == cmds[c].action) {
        debug(LOG_ERR, "<WDCTL> Request was not understood!");
    }

    shutdown(fd, 2);
    close(fd);
    debug(LOG_DEBUG, "<WDCTL> Exiting thread_wdctl_handler....");

    return NULL;
}

static int
write_to_socket(int fd, char *text, size_t len)
{
    ssize_t retval;
    size_t written;

    written = 0;
    while (written < len) {
        retval = write(fd, (text + written), len - written);
        if (retval == -1) {
            debug(LOG_CRIT, "<WDCTL> Failed to write client data to child: %s", strerror(errno));
            return 0;
        } else {
            written += retval;
        }
    }
    return 1;
}

static void
okos_wdctl_status(int fd, const char *_1, const char *_2)
{
    char *status = get_status_text();
    int len = strlen(status);

    write_to_socket(fd, status, len);

    free(status);
}

static void
okos_wdctl_stop(int fd, const char *_1, const char *_2)
{
    pid_t pid = getpid();
    kill(pid, SIGINT);
}

static void
okos_wdctl_restart(int afd, const char *_1, const char *_2)
{
    s_config *conf = config_get_config();

    debug(LOG_NOTICE, "<WDCTL> Will restart myself");

    /* First, prepare the internal socket */
    char *sock_name = conf->internal_sock;
    debug(LOG_DEBUG, "<WDCTL> Socket name: %s", sock_name);

    debug(LOG_DEBUG, "<WDCTL> Creating socket");
    int sock = create_unix_socket(sock_name);
    if (-1 == sock) {
        debug(LOG_ERR, "<WDCTL>!! Open socket between Father and Son failed!");
        return;
    }

    /*
     * The internal socket is ready, fork and exec ourselves
     */
    debug(LOG_DEBUG, "<WDCTL> Forking in preparation for exec()...");
    pid_t pid = safe_fork();
    if (pid > 0) { /* Parent */

        /*-----------------------------------------------------------
         * Wait for the child to connect to our socket :
         *      1) Father will be blocked by `accept`
         *      2) Until Son connect to.
         * --------------------------------------------------------*/
        debug(LOG_DEBUG, "<WDCTL> Waiting for child to connect on internal socket");
        struct sockaddr_un sa_un;
        socklen_t len = sizeof(sa_un);
        int fd = accept(sock, (struct sockaddr *)&sa_un, &len);
        if (-1 == fd) {
            debug(LOG_ERR, "<WDCTL> Accept failed on internal socket: %s", strerror(errno));
            close(sock);
            return;
        }
        close(sock);

        /*-----------------------------------------------------------
         * Son is born. As Father, should do:
         *      1) Package all the clients and hand them over to Son
         *      2) Kill myself.
         * --------------------------------------------------------*/
        debug(LOG_DEBUG, "<WDCTL> Received connection from child."
                "Sending them all existing clients");

        LOCK_CLIENT_LIST();
        t_client *client = client_get_first_client();
        char *tempstring = NULL;
        while (client) {
            safe_asprintf(&tempstring,
                          "CLIENT|ip=%s|mac=%s|fw_connection_state=%u"
                          "|fd=%d|auth_mode=%u|user_name=%s|flag=%d"
                          "|remain_time=%u|last_flushed=%lu|if_name=%s\n",
                          client->ip, client->mac, client->fw_connection_state,
                          client->fd, client->auth_mode, client->user_name, client->flag,
                          client->remain_time, client->last_flushed, client->if_name);

            debug(LOG_DEBUG, "<WDCTL> Sending to child client data: %s", tempstring);
            write_to_socket(fd, tempstring, strlen(tempstring));
            free(tempstring);
            client = client->next;
        }
        UNLOCK_CLIENT_LIST();

        close(fd);

        debug(LOG_INFO, "<WDCTL> Sent all existing clients to child.  Committing suicide!");

        shutdown(afd, 2);
        close(afd);

        /* Our job in life is done. Commit suicide! */
        okos_wdctl_stop(afd, _1, _2);
    } else { /* Child */
        close(wdctl_socket_server);
        close(sock);
        close_icmp_socket();
        shutdown(afd, 2);
        close(afd);
        debug(LOG_NOTICE, "<WDCTL> Re-executing myself (%s)", restartargv[0]);
        setsid();
        execvp(restartargv[0], restartargv);
        /* If we've reached here the exec() failed - die quickly and silently */
        debug(LOG_ERR, "<WDCTL> I failed to re-execute myself: %s", strerror(errno));
        debug(LOG_ERR, "<WDCTL> Exiting without cleanup");
        exit(9001);
    }
}

typedef char * (*okos_polling_action_by_mac)(const char *, const char *, int *);

static void
okos_wdctl_action_by_mac(
        int fd, 
        const char *mac,
        const char *content,
        const char *name,
        okos_polling_action_by_mac action)
{
    debug(LOG_DEBUG, "<WDCTL> Entering wdctl_%s.", name);
    debug(LOG_DEBUG, "<WDCTL> Argument: {mac = %s, [%s]}", mac, content);

	if (!okos_judge_mac(mac)) {
		debug(LOG_DEBUG, "<WDCTL> Can't %s client without MAC address.", name);
		write_to_socket(fd, "Bad", 3);
		return;
	}

	if (0 == strlen(content)) {
		content = NULL;
	}

    if (NULL == action) {
		debug(LOG_DEBUG, "<WDCTL> No action registered for %s.", name);
		write_to_socket(fd, "Sorry", 5);
        return;
    }

    int num = 0;
	char *clients_info = action(mac, content, &num);
    if (0 == num) {
        debug(LOG_DEBUG, "<WDCTL> No client found.");
        write_to_socket(fd, "No", 2);
    } else {
        debug(LOG_DEBUG, "<WDCTL> Output all the clients %sed.", name);
        write_to_socket(fd, clients_info, strlen(clients_info));
    }
    free(clients_info);
}

static void
okos_wdctl_offline(int fd, const char *mac, const char *scheme)
{
    okos_wdctl_action_by_mac(fd, mac, scheme, "offline", okos_delete_clients_by_scheme);
}


static void
okos_wdctl_reset(int fd, const char *mac, const char *ssid)
{
    okos_wdctl_action_by_mac(fd, mac, ssid, "reset", okos_delete_clients_by_ssid);
}


static void
okos_wdctl_query_mac(int fd, const char *mac, const char *ssid)
{
    okos_wdctl_action_by_mac(fd, mac, ssid, "query", okos_get_client_status_text);
}

static void okos_wdctl_config(int fd, const char *_1, const char *_2)
{
    char *s_config = NULL;
    size_t len = 0;

    debug(LOG_DEBUG, "<WDCTL> Entering wdctl_config.");
	s_config = okos_conf_get_all();
    len = strlen(s_config);

    debug(LOG_DEBUG, "<WDCTL> Output all the configuration.");
    write_to_socket(fd, s_config, len);

    free(s_config);
    debug(LOG_DEBUG, "<WDCTL> Existing wdctl_config.");
}

static int
okos_wdctl_insert_client(const char *mac, unsigned int remain_time)
{
    sqlite3 *stainfo_db = okos_open_stainfo_db();
    if (NULL == stainfo_db) {
        return;
    }
    t_client *client = okos_client_get_new("");
    client->mac = safe_strdup(mac);
    okos_fill_local_info_by_stainfo(&client, stainfo_db);
    okos_close_stainfo_db(stainfo_db);
    if (NULL == client) {
        debug(LOG_WARNING, "<WDCTL> can't file local info.");
        return -1;
    }
    client->remain_time = remain_time;
    client->last_flushed = time(NULL);

    debug(LOG_DEBUG, "<WDCTL> Created a client"
            "{%s, %s, %s, remain_time=%ld }",
            client->ip, client->mac, client->if_name, client->remain_time);
    okos_add_validation_client(&client);
    return 0;
}

static unsigned int str2int(const char *str)
{
    uintmax_t num = strtoumax(str, NULL, 10);
    if (num == UINTMAX_MAX && errno == ERANGE)
        return 0;
    else
        return num;
}

static void
okos_wdctl_insert(int fd, const char *mac, const char *remain)
{
    debug(LOG_DEBUG, "<WDCTL> Entering wdctl_insert.");
    debug(LOG_DEBUG, "<WDCTL> Argument: {mac = %s, remain time is %s}", mac, remain);

	if (!okos_judge_mac(mac)) {
		debug(LOG_DEBUG, "<WDCTL> Can't insert client without MAC address.");
		write_to_socket(fd, "Bad", 3);
		return;
	}

    unsigned int remain_time = str2int(remain);
    if (0 == remain_time) {
		debug(LOG_DEBUG, "<WDCTL> No action for unavaiable remain time.");
		write_to_socket(fd, "Sorry", 5);
        return;
    }

    if (NULL != client_list_find_by_mac(mac)) {
        debug(LOG_DEBUG, "<WDCTL> No action since client is already in.");
        write_to_socket(fd, "No", 2);
        return;
    }

    int rc = 0;
    rc = okos_wdctl_insert_client(mac, remain_time);
    if (0 != rc) {
		debug(LOG_DEBUG, "<WDCTL> insert client failed.");
		write_to_socket(fd, "Sorry", 5);
    } else {
        debug(LOG_DEBUG, "<WDCTL> insert client successfully.");
        write_to_socket(fd, "Yes", 3);
    }
}





