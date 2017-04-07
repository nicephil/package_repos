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
/** @file wdctl.c
    @brief Monitoring and control of wifidog, client part
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
#include <errno.h>

#include "wdctl.h"

static s_config config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(const char *);
static size_t send_request(int, const char *);
#if 0
static void wdctl_status(void);
static void wdctl_stop(void);
static void wdctl_reset(void);
static void wdctl_offline(void);
static void wdctl_restart(void);
#endif

static void wdctl_cmd_without_reply(const char *);
static void wdctl_cmd_parse_reply(const char *);


/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wdctl is run with -h or with an unknown option
 */
static void
usage(void)
{
    fprintf(stdout, "Usage: wdctl [options] command [arguments]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -s <path>         Path to the socket\n");
    fprintf(stdout, "  -h                Print usage\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "commands:\n");
    fprintf(stdout, "  reset mac [ssid]      Reset the specified mac or ip connection\n");
    fprintf(stdout, "  offline mac [scheme]  Offline the specified mac or ip connection\n");
    fprintf(stdout, "  status                Obtain the status of wifidog\n");
    fprintf(stdout, "  stop                  Stop the running wifidog\n");
    fprintf(stdout, "  restart               Re-start the running wifidog\n");
	fprintf(stdout, "  query mac [ssid]      Obtain the status of a client\n");
    fprintf(stdout, "\n");
}

/** @internal
 *
 * Init default values in config struct
 */
static void
init_config(void)
{

    config.socket = strdup(DEFAULT_SOCK);
    config.command = WDCTL_UNDEF;
}

typedef void (*ok_exec_cmd)(const char *);

static const struct {
    const char *name;
    int params_num;
    int cmd;
    ok_exec_cmd execute;
} cmds[] = {
    {"status", 0, WDCTL_STATUS, wdctl_cmd_without_reply},
    {"stop", 0, WDCTL_STOP, wdctl_cmd_without_reply},
    {"reset", 2, WDCTL_KILL, wdctl_cmd_parse_reply},
    {"restart", 0, WDCTL_RESTART, wdctl_cmd_without_reply},
    {"offline", 2, WDCTL_OFFLINE, wdctl_cmd_parse_reply},
    {"query", 2, WDCTL_QUERY, wdctl_cmd_parse_reply},
    {"config", 0, WDCTL_CONFIG, wdctl_cmd_without_reply},
    {NULL, 0, WDCTL_UNDEF, NULL},
};

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
    extern int optind;
    int c;

    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch (c) {
        case 'h':
            usage();
            exit(1);
            break;

        case 's':
            if (optarg) {
                free(config.socket);
                config.socket = strdup(optarg);
            }
            break;

        default:
            usage();
            exit(1);
            break;
        }
    }

    if ((argc - optind) <= 0) {
        usage();
        exit(1);
    }

    int i;
    for (i = 0; NULL != cmds[i].name; i++) {
        if (0 == strcmp(cmds[i].name, *(argv + optind))) {
            config.command = cmds[i].cmd;
            if (cmds[i].params_num >= 1) {
                if ((argc - (optind + 1)) <= 0) {
                    fprintf(stderr, "wdctl: Error: You must specify a MAC\n");
                    usage();
                    exit(1);
                }
                config.params[0] = strdup(*(argv + optind + 1));
                if (cmds[i].params_num >= 2) {
                    if ((argc - (optind + 1)) == 2) {
                        config.params[1] = strdup(*(argv + optind + 2));
                    }
                }
            }
            if (NULL != cmds[i].execute) {
                cmds[i].execute(cmds[i].name);
                exit(0);
            }
            break;
        }
    }

    fprintf(stderr, "wdctl: Error: Invalid command \"%s\"\n", *(argv + optind));
    usage();
    exit(1);

#if 0
    if (strcmp(*(argv + optind), "status") == 0) {
        config.command = WDCTL_STATUS;
    } else if (strcmp(*(argv + optind), "stop") == 0) {
        config.command = WDCTL_STOP;
    } else if (strcmp(*(argv + optind), "reset") == 0) {
        config.command = WDCTL_KILL;
        if ((argc - (optind + 1)) <= 0) {
            fprintf(stderr, "wdctl: Error: You must specify a Mac address to reset\n");
            usage();
            exit(1);
        }
        config.param = strdup(*(argv + optind + 1));
		if ((argc - (optind + 1)) == 2) {
			config.param1 = strdup(*(argv + optind + 2));
		}
    } else if (strcmp(*(argv + optind), "restart") == 0) {
        config.command = WDCTL_RESTART;
#if OK_PATCH
    } else if (strcmp(*(argv + optind), "offline") == 0) {
        config.command = WDCTL_OFFLINE;
        if ((argc - (optind + 1)) <= 0) {
            fprintf(stderr, "wdctl: Error: You must specify a Mac address to do offline\n");
            usage();
            exit(1);
        }
        config.param = strdup(*(argv + optind + 1));
		if ((argc - (optind + 1)) == 2) {
			config.param1 = strdup(*(argv + optind + 2));
		}
	} else if (strcmp(*(argv + optind), "query") == 0) {
		config.command = WDCTL_QUERY;
        if ((argc - (optind + 1)) <= 0) {
            fprintf(stderr, "wdctl: Error: You must specify a Mac address to query\n");
            usage();
            exit(1);
        }
        config.param = strdup(*(argv + optind + 1));
		if ((argc - (optind + 1)) == 2) {
			config.param1 = strdup(*(argv + optind + 2));
		}
	} else if (strcmp(*(argv + optind), "config") == 0) {
		config.command = WDCTL_CONFIG;
#endif
    } else {
        fprintf(stderr, "wdctl: Error: Invalid command \"%s\"\n", *(argv + optind));
        usage();
        exit(1);
    }
#endif
}

static int
connect_to_server(const char *sock_name)
{
    int sock;
    struct sockaddr_un sa_un;

    /* Connect to socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "wdctl: could not get socket (Error: %s)\n", strerror(errno));
        exit(1);
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

    if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        fprintf(stderr, "wdctl: wifidog probably not started (Error: %s)\n", strerror(errno));
        exit(1);
    }

    return sock;
}

static size_t
send_request(int sock, const char *request)
{
    size_t len;
    ssize_t written;

    len = 0;
    while (len != strlen(request)) {
        written = write(sock, (request + len), strlen(request) - len);
        if (written == -1) {
            fprintf(stderr, "Write to wifidog failed: %s\n", strerror(errno));
            exit(1);
        }
        len += (size_t) written;
    }

    return len;
}

static void
wdctl_cmd_without_reply(const char *cmd)
{
    int sock;
    char buffer[4096];
    char request[16];
    ssize_t len;

    sock = connect_to_server(config.socket);

    strncpy(request, cmd, 15);
    strncat(request, "\r\n\r\n", 15 - strlen(request));

    send_request(sock, request);

    // -1: need some space for \0!
    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void 
wdctl_cmd_parse_reply(const char *cmd)
{
    int sock;
    char buffer[4096];
    char request[256];
#define ok_cmd_buf_available(req) (sizeof(req) - strlen(req) - 1)

    size_t len;
    ssize_t rlen;

    sock = connect_to_server(config.socket);

    strncpy(request, cmd, sizeof(request));
    strncat(request, " ", ok_cmd_buf_available(request));
    strncat(request, config.params[0], ok_cmd_buf_available(request));
    if (config.params[1]) {
        strncat(request, " ", ok_cmd_buf_available(request));
        strncat(request, config.params[1], ok_cmd_buf_available(request));
    }
    strncat(request, "\r\n\r\n", ok_cmd_buf_available(request));

    send_request(sock, request);

    len = 0;
    memset(buffer, 0, sizeof(buffer));
    while ((len < sizeof(buffer)) &&
            ((rlen = read(sock, (buffer + len), (sizeof(buffer) - len))) > 0)) {
        len += (size_t) rlen;
    }

    if (strcmp(buffer, "Yes") == 0) {
        fprintf(stdout, "Connection [%s:%s] successfully.\n",
                config.params[0], config.params[1] ? config.params[1] : "*");
    } else if (strcmp(buffer, "No") == 0) {
        fprintf(stdout, "Connection [%s -  %s] was not active.\n",
                config.params[0], config.params[1] ? config.params[1] : "*");
    } else if (strcmp(buffer, "Bad") == 0) {
        fprintf(stdout, "MAC address [%s] couldn't be recoganized.\n",
                config.params[0]);
    } else if (strcmp(buffer, "Sorry") == 0) {
        fprintf(stdout, "No action registed for %s\n", request);
    } else {
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

#if 0
static void
wdctl_status(void)
{
    int sock;
    char buffer[4096];
    char request[16];
    ssize_t len;

    sock = connect_to_server(config.socket);

    strncpy(request, "status\r\n\r\n", 15);

    send_request(sock, request);

    // -1: need some space for \0!
    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void
wdctl_stop(void)
{
    int sock;
    char buffer[4096];
    char request[16];
    ssize_t len;

    sock = connect_to_server(config.socket);

    strncpy(request, "stop\r\n\r\n", 15);

    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}


void
wdctl_reset(void)
{
    int sock;
    char buffer[4096];
    char request[64];
    size_t len;
    ssize_t rlen;

    sock = connect_to_server(config.socket);

    strncpy(request, "reset ", 64);
    strncat(request, config.param, (64 - strlen(request) - 1));
    if (config.param1) {
        strncat(request, " ", (64 - strlen(request) - 1));
        strncat(request, config.param1, (64 - strlen(request) - 1));
    }
    strncat(request, "\r\n\r\n", (64 - strlen(request) - 1));

    send_request(sock, request);

    len = 0;
    memset(buffer, 0, sizeof(buffer));
    while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len), (sizeof(buffer) - len))) > 0)) {
        len += (size_t) rlen;
    }

    if (strcmp(buffer, "Yes") == 0) {
        fprintf(stdout, "Connection {%s:%s} successfully reset.\n", config.param, config.param1 ? config.param1 : "*");
    } else if (strcmp(buffer, "No") == 0) {
        fprintf(stdout, "Connection {%s:%s} was not active.\n", config.param, config.param1 ? config.param1 : "*");
    } else if (strcmp(buffer, "Bad") == 0) {
        fprintf(stdout, "MAC address {%s:%s} couldn't be recoganized.\n", config.param, config.param1 ? config.param1 : "*");
    } else {
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

#if OK_PATCH
static void
wdctl_offline(void)
{
    int sock;
    char buffer[4096];
    char request[256];
    size_t len;
    ssize_t rlen;

    sock = connect_to_server(config.socket);

    strncpy(request, "offline ", 256);
    strncat(request, config.param, (256 - strlen(request) - 1));
    if (config.param1) {
        strncat(request, " ", (256 - strlen(request) - 1));
        strncat(request, config.param1, (256 - strlen(request) - 1));
    }
    strncat(request, "\r\n\r\n", (256 - strlen(request) - 1));

    send_request(sock, request);

    len = 0;
    memset(buffer, 0, sizeof(buffer));
    while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len), (sizeof(buffer) - len))) > 0)) {
        len += (size_t) rlen;
    }

    if (strcmp(buffer, "Yes") == 0) {
        fprintf(stdout, "Connection {%s:%s} successfully reset.\n", config.param, config.param1 ? config.param1 : "*");
    } else if (strcmp(buffer, "No") == 0) {
        fprintf(stdout, "Connection {%s:%s} was not active.\n", config.param, config.param1 ? config.param1 : "*");
    } else if (strcmp(buffer, "Bad") == 0) {
        fprintf(stdout, "MAC address {%s:%s} couldn't be recoganized.\n", config.param, config.param1 ? config.param1 : "*");
    } else {
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}

static void wdctl_config(void)
{
    int sock;
    char buffer[4096];
    char request[16];
    ssize_t len;

    sock = connect_to_server(config.socket);

    strncpy(request, "config\r\n\r\n", 15);

    send_request(sock, request);

    // -1: need some space for \0!
    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}


static void wdctl_query(void)
{
    int sock;
    char buffer[4096];
    char request[64];
    size_t len;
    ssize_t rlen;

    sock = connect_to_server(config.socket);

    strncpy(request, "query ", 64);
    strncat(request, config.param, (64 - strlen(request) - 1));
	if (config.param1) {
		strncat(request, " ", (64 - strlen(request) -1));
		strncat(request, config.param1, (64 - strlen(request) - 1));
	}
    strncat(request, "\r\n\r\n", (64 - strlen(request) - 1));

    send_request(sock, request);

    len = 0;
    memset(buffer, 0, sizeof(buffer));
    while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len), (sizeof(buffer) - len))) > 0)) {
        len += (size_t) rlen;
    }

    if (strcmp(buffer, "No") == 0) {
        fprintf(stdout, "MAC address {%s:%s} was not valid.\n", config.param, config.param1 ? config.param1 : "*");
    } else {
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}
#endif

static void
wdctl_restart(void)
{
    int sock;
    char buffer[4096];
    char request[16];
    ssize_t len;

    sock = connect_to_server(config.socket);

    strncpy(request, "restart\r\n\r\n", 15);

    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);
}
#endif

int
main(int argc, char **argv)
{

    /* Init configuration */
    init_config();
    parse_commandline(argc, argv);

#if 0
    switch (config.command) {
    case WDCTL_STATUS:
        wdctl_status();
        break;

    case WDCTL_STOP:
        wdctl_stop();
        break;

    case WDCTL_KILL:
        wdctl_reset();
        break;

    case WDCTL_RESTART:
        wdctl_restart();
        break;
#if OK_PATCH
	case WDCTL_QUERY:
		wdctl_query();
		break;
	case WDCTL_CONFIG:
		wdctl_config();
		break;
    case WDCTL_OFFLINE:
        wdctl_offline();
        break;
#endif

    default:
        /* XXX NEVER REACHED */
        fprintf(stderr, "Oops\n");
        exit(1);
        break;
    }
#endif
    exit(0);

}
