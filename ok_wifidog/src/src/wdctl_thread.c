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


static int create_unix_socket(const char *);
static int write_to_socket(int, char *, size_t);
static void *thread_wdctl_handler(void *);
static void wdctl_status(int);
static void wdctl_stop(int);
static void wdctl_restart(int);

#if OK_PATCH
static int okos_judge_mac(const char *);
static void okos_wdctl_reset(int, const char *, const char *);
static void okos_wdctl_offline(int, const char *, const char *);
static void okos_wdctl_query_mac(int, const char *, const char *);
static void okos_wdctl_config(int);
#endif


static int wdctl_socket_server;

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
            debug(LOG_DEBUG, "<WDCTL> Accepted connection on wdctl socket %d (%s)", fd, sa_un.sun_path);
            result = pthread_create(&tid, NULL, &thread_wdctl_handler, (void *)fd);
            if (result != 0) {
                debug(LOG_ERR, "<WDCTL> FATAL: Failed to create a new thread (wdctl handler) - exiting");
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
    debug(LOG_DEBUG, "<WDCTL> Read bytes and stuff from %d", fd);

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

    if (strncmp(request, "status", 6) == 0) {
        wdctl_status(fd);
    } else if (strncmp(request, "stop", 4) == 0) {
        wdctl_stop(fd);
#if OK_PATCH
    } else if (strncmp(request, "reset", 5) == 0) {
        request[23] = 0;
        okos_wdctl_reset(fd, (request + 6), (request + 24));
    } else if (strncmp(request, "offline", 7) == 0) {
        request[25] = 0;
        okos_wdctl_offline(fd, (request + 8), (request + 26));
#endif
    } else if (strncmp(request, "restart", 7) == 0) {
        wdctl_restart(fd);
#if OK_PATCH
	} else if (0 == strncmp(request, "query", 5)) {
		request[23] = 0;
		okos_wdctl_query_mac(fd, (request + 6), (request + 24));
	} else if (0 == strncmp(request, "config", 6)) {
		okos_wdctl_config(fd);
#endif
    } else {
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
wdctl_status(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_status_text();
    len = strlen(status);

    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

/** A bit of an hack, self kills.... */
/* coverity[+kill] */
static void
wdctl_stop(int fd)
{
    pid_t pid;

    pid = getpid();
    kill(pid, SIGINT);
}

static void
wdctl_restart(int afd)
{
    int sock, fd;
    char *sock_name;
    s_config *conf = NULL;
    struct sockaddr_un sa_un;
    t_client *client;
    char *tempstring = NULL;
    pid_t pid;
    socklen_t len;

    conf = config_get_config();

    debug(LOG_NOTICE, "<WDCTL> Will restart myself");

    /* First, prepare the internal socket */
    sock_name = conf->internal_sock;
    debug(LOG_DEBUG, "<WDCTL> Socket name: %s", sock_name);

    debug(LOG_DEBUG, "<WDCTL> Creating socket");
    sock = create_unix_socket(sock_name);
    if (-1 == sock) {
        return;
    }

    /*
     * The internal socket is ready, fork and exec ourselves
     */
    debug(LOG_DEBUG, "<WDCTL> Forking in preparation for exec()...");
    pid = safe_fork();
    if (pid > 0) {
        /* Parent */

        /* Wait for the child to connect to our socket : */
        debug(LOG_DEBUG, "<WDCTL> Waiting for child to connect on internal socket");
        len = sizeof(sa_un);
        if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "<WDCTL> Accept failed on internal socket: %s", strerror(errno));
            close(sock);
            return;
        }

        close(sock);

        debug(LOG_DEBUG, "<WDCTL> Received connection from child.  Sending them all existing clients");

        /* The child is connected. Send them over the socket the existing clients */
        LOCK_CLIENT_LIST();
        client = client_get_first_client();
        while (client) {
            /* Send this client */
#if OK_PATCH
            safe_asprintf(&tempstring,
                          "CLIENT|ip=%s|mac=%s|token=%s|fw_connection_state=%u|fd=%d|counters_incoming=%llu|counters_outgoing=%llu|counters_last_updated=%lu|auth_mode=%u|user_name=%s|remain_time=%u|last_flushed=%lu|if_name=%s|ssid=%s\n",
                          client->ip, client->mac, client->token, client->fw_connection_state, client->fd,
                          client->counters.incoming, client->counters.outgoing, client->counters.last_updated,
						  client->auth_mode, client->user_name, client->remain_time, client->last_flushed, client->if_name, client->ssid);
#else /* OK_PATCH */
            safe_asprintf(&tempstring,
                          "CLIENT|ip=%s|mac=%s|token=%s|fw_connection_state=%u|fd=%d|auth_mode=%u|user_name=%s|remain_time=%u|last_flushed=%lu|if_name=%s|ssid=%s\n",
                          client->ip, client->mac, client->token, client->fw_connection_state, client->fd,
						  client->auth_mode, client->user_name, client->remain_time, client->last_flushed, client->if_name, client->ssid);

#endif
            debug(LOG_DEBUG, "<WDCTL> Sending to child client data: %s", tempstring);
            write_to_socket(fd, tempstring, strlen(tempstring));        /* XXX Despicably not handling error. */
            free(tempstring);
            client = client->next;
        }
        UNLOCK_CLIENT_LIST();

        close(fd);

        debug(LOG_INFO, "<WDCTL> Sent all existing clients to child.  Committing suicide!");

        shutdown(afd, 2);
        close(afd);

        /* Our job in life is done. Commit suicide! */
        wdctl_stop(afd);
    } else {
        /* Child */
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
        exit(1);
    }
}

#if OK_PATCH
static void
okos_wdctl_offline(
        int fd,
        const char *mac,
        const char *scheme
        )
{
    debug(LOG_DEBUG, "<WDCTL> Entering wdctl_offline.");
    debug(LOG_DEBUG, "<WDCTL> Argument: {mac = %s, scheme:[%s]}", mac, scheme);

	if (!okos_judge_mac(mac)) {
		debug(LOG_DEBUG, "<WDCTL> Can't offline client without MAC address.");
		write_to_socket(fd, "Bad", 3);
		return;
	}

	if (0 == strlen(scheme)) {
		scheme = NULL;
	}

	char *clients_info = okos_delete_clients_by_scheme(mac, scheme);

    debug(LOG_DEBUG, "<WDCTL> Output all the clients offlined.");
	write_to_socket(fd, clients_info, strlen(clients_info));
	free(clients_info);
    debug(LOG_DEBUG, "<WDCTL> Existing wdctl_offline.");
}


static void
okos_wdctl_reset(int fd, const char *mac, const char *ssid)
{
    debug(LOG_DEBUG, "<WDCTL> Entering wdctl_reset.");
    debug(LOG_DEBUG, "<WDCTL> Argument: {mac = %s, ssid:[%s]}", mac, ssid);

	if (!okos_judge_mac(mac)) {
		debug(LOG_DEBUG, "<WDCTL> Can't reset client without MAC address.");
		write_to_socket(fd, "Bad", 3);
		return;
	}

	if (0 == strlen(ssid)) {
		ssid = NULL;
	}

	char *clients_info = okos_delete_clients_by_ssid(mac, ssid);

    debug(LOG_DEBUG, "<WDCTL> Output all the clients reset.");
	write_to_socket(fd, clients_info, strlen(clients_info));
	free(clients_info);
    debug(LOG_DEBUG, "<WDCTL> Existing wdctl_reset.");
}

#else /* OK_PATCH */
static void
wdctl_reset(int fd, const char *arg)
{
    t_client *node;

    debug(LOG_DEBUG, "<WDCTL> Entering wdctl_reset.");

    LOCK_CLIENT_LIST();
    debug(LOG_DEBUG, "<WDCTL> Argument: %s (@%x)", arg, arg);

    /* We get the node or return... */
    if ((node = client_list_find_by_ip(arg)) != NULL) ;
    else if ((node = client_list_find_by_mac(arg)) != NULL) ;
    else {
        debug(LOG_DEBUG, "<WDCTL> Client not found.");
        UNLOCK_CLIENT_LIST();
        write_to_socket(fd, "No", 2);   /* Error handling in fucntion sufficient. */

        return;
    }

    debug(LOG_DEBUG, "<WDCTL> Got node %x.", node);

    /* deny.... */
    logout_client(node);

    UNLOCK_CLIENT_LIST();

    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "<WDCTL> Exiting wdctl_reset.");
}
#endif

#if OK_PATCH

static int okos_judge_mac(const char *p_mac)
{
	int isMac = 0;
	unsigned int tmp[6];
	if (6 == sscanf(p_mac, "%02X:%02X:%02X:%02X:%02X:%02X", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5])) {
		isMac = 1;
	}
	return isMac;
}

static void okos_wdctl_query_mac(int fd, const char *p_mac, const char *p_ssid)
{
	debug(LOG_DEBUG, "<WDCTL> Entering wdctl_query_mac.");
	debug(LOG_DEBUG, "<WDCTL> Argument: {mac = %s; ssid = %s}", p_mac, p_ssid);

	if (!okos_judge_mac(p_mac)) {
		debug(LOG_DEBUG, "<WDCTL> Can't query client without MAC address.");
		write_to_socket(fd, "Bad", 3);
		return;
	}

	if (0 == strcmp(p_ssid, "")) {
		p_ssid = NULL;
	}

	char *p_client_info = okos_get_client_status_text(p_mac, p_ssid);

    debug(LOG_DEBUG, "<WDCTL> Output client information.");
	write_to_socket(fd, p_client_info, strlen(p_client_info));
	free(p_client_info);
    debug(LOG_DEBUG, "<WDCTL> Existing wdctl_query_mac.");
}

static void okos_wdctl_config(int fd)
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

#endif




