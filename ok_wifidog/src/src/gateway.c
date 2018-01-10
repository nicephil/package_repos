/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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
  @file gateway.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include <fcntl.h>

#include "sqlite3.h"

#include "common.h"
#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "ping_thread.h"
#include "httpd_thread.h"
#include "util.h"


/** XXX Ugly hack 
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_fw_counter = 0;
static pthread_t tid_ping = 0;

time_t started_time = 0;

/* The internal web server */
httpd * webserver = NULL;

#if OK_PATCH
const char *station_info_db_file = "/tmp/stationinfo.db";
const char *station_info_table = "STAINFO";
#endif

/* Appends -x, the current PID, and NULL to restartargv
 * see parse_commandline in commandline.c for details
 *
 * Why is restartargv global? Shouldn't it be at most static to commandline.c
 * and this function static there? -Alex @ 8oct2006
 */
void
append_x_restartargv(void)
{
    int i;

    for (i = 0; restartargv[i]; i++) ;

    restartargv[i++] = safe_strdup("-x");
    safe_asprintf(&(restartargv[i++]), "%d", getpid());
}

#define OKOS_CLIENT_SHOW(element) (element ? element : "NULL")

/* @internal
 * @brief During gateway restart, connects to the parent process via the internal socket
 * Downloads from it the active client list
 */
void
get_clients_from_parent(void)
{
    int sock;
    struct sockaddr_un sa_un;
    s_config *config = NULL;
    char linebuffer[MAX_BUF];
    int len = 0;
    char *running1 = NULL;
    char *running2 = NULL;
    char *token1 = NULL;
    char *token2 = NULL;
    char onechar;
    char *command = NULL;
    char *key = NULL;
    char *value = NULL;
    t_client *client = NULL;

    config = config_get_config();

    debug(LOG_INFO, "Connecting to parent to download clients");

    /* Connect to socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    /* XXX An attempt to quieten coverity warning about the subsequent connect call:
     * Coverity says: "sock is apssed to parameter that cannot be negative"
     * Although connect expects a signed int, coverity probably tells us that it shouldn't
     * be negative */
    if (sock < 0) {
        debug(LOG_ERR, "Could not open socket (%s) - client list not downloaded", strerror(errno));
        return;
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, config->internal_sock, (sizeof(sa_un.sun_path) - 1));

    if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        debug(LOG_ERR, "Failed to connect to parent (%s) - client list not downloaded", strerror(errno));
        close(sock);
        return;
    }

    debug(LOG_INFO, "Connected to parent.  Downloading clients");

    LOCK_CLIENT_LIST();

    command = NULL;
    memset(linebuffer, 0, sizeof(linebuffer));
    len = 0;
    client = NULL;
    /* Get line by line */
    while (read(sock, &onechar, 1) == 1) {
        if (onechar == '\n') {
            /* End of line */
            onechar = '\0';
        }
        linebuffer[len++] = onechar;

        if (!onechar) {
            /* We have a complete entry in linebuffer - parse it */
            debug(LOG_DEBUG, "Received from parent: [%s]", linebuffer);
            running1 = linebuffer;
            while ((token1 = strsep(&running1, "|")) != NULL) {
                if (!command) {
                    /* The first token is the command */
                    command = token1;
                } else {
                    /* Token1 has something like "foo=bar" */
                    running2 = token1;
                    key = value = NULL;
                    while ((token2 = strsep(&running2, "=")) != NULL) {
                        if (!key) {
                            key = token2;
                        } else if (!value) {
                            value = token2;
                        }
                    }
                }

                if (strcmp(command, "CLIENT") == 0) {
                    /* This line has info about a client in the client list */
                    if (NULL == client) {
                        /* Create a new client struct */
                        client = client_get_new();
                    }
                }

                /* XXX client check to shut up clang... */
                if (key && value && client) {
                    if (strcmp(command, "CLIENT") == 0) {
                        /* Assign the key into the appropriate slot in the connection structure */
                        if (strcmp(key, "ip") == 0) {
                            client->ip = safe_strdup(value);
                        } else if (strcmp(key, "mac") == 0) {
                            client->mac = safe_strdup(value);
                        } else if (strcmp(key, "fw_connection_state") == 0) {
                            client->fw_connection_state = atoi(value);
                        } else if (strcmp(key, "fd") == 0) {
                            client->fd = atoi(value);
#if 0
                        } else if (strcmp(key, "counters_incoming") == 0) {
                            client->counters.incoming_history = (unsigned long long)atoll(value);
                            client->counters.incoming = client->counters.incoming_history;
                            client->counters.incoming_delta = 0;
                        } else if (strcmp(key, "counters_outgoing") == 0) {
                            client->counters.outgoing_history = (unsigned long long)atoll(value);
                            client->counters.outgoing = client->counters.outgoing_history;
                            client->counters.outgoing_delta = 0;
                        } else if (strcmp(key, "counters_last_updated") == 0) {
                            client->counters.last_updated = atol(value);
#endif
#if OK_PATCH /* Add more elements for client */
                        } else if (strcmp(key, "auth_mode") == 0) {
                            client->auth_mode = (unsigned int)atoi(value);
                        } else if (strcmp(key, "user_name") == 0) {
                            client->user_name = safe_strdup(value);
                        } else if (strcmp(key, "remain_time") == 0) {
                            client->remain_time = (unsigned int)atoi(value);
                        } else if (strcmp(key, "last_flushed") == 0) {
                            client->last_flushed = atol(value);
                        } else if (strcmp(key, "if_name") == 0) {
                            client->if_name = safe_strdup(value);
                        } else if (strcmp(key, "flag") == 0) {
                            client->flag = atoi(value);
#endif /* OK_PATCH */
                        } else {
                            debug(LOG_NOTICE, "I don't know how to inherit key [%s] value [%s] from parent", key,
                                  value);
                        }
                    }
                }
            }

#if OK_PATCH
            if (client) {
                debug(LOG_DEBUG, "Received a client {ip=%s, mac=%s, ifname=%s}",
                        OKOS_CLIENT_SHOW(client->ip), OKOS_CLIENT_SHOW(client->mac), OKOS_CLIENT_SHOW(client->if_name));
                debug(LOG_DEBUG, "Received a client {user_name=%s, auth_mode=%u}",
                        OKOS_CLIENT_SHOW(client->user_name), client->auth_mode);
                debug(LOG_DEBUG, "Received a client {remain_time=%u, last_flushed=%lu,fw_connection_state=%u, fd=%d}",
                        client->remain_time, client->last_flushed,
                        client->fw_connection_state, client->fd);

                if ((NULL == client->ip) || (NULL == client->mac)
                        || (NULL == client->user_name) || (0 == client->last_flushed)
                        || (NULL == client->if_name) || (0 == client->remain_time)) {
                    client_free_node(client);
                    debug(LOG_DEBUG, "Could not receive completed information from parent.");
                }
                client->ifx = okos_conf_get_ifx_by_name(client->if_name);
                if (NULL == client->ifx) {
                    debug(LOG_DEBUG, "Can't parse interface correctly.");
                    client_free_node(client);
                }
                client->ssid = client->ifx->ssid;
                
                debug(LOG_DEBUG, "Inheit a client {ip=%s, mac=%s, ifname=%s, user_name=%s, auth_mode=%u, remain_time=%u, last_flushed=%lu,fw_connection_state=%u, fd=%d}", client->ip, client->mac, client->if_name, client->user_name, client->auth_mode, client->remain_time, client->last_flushed, client->fw_connection_state, client->fd);

                client_list_insert_client(&client);
            }

#else /* OK_PATCH */
            /* End of parsing this command */
            if (client) {
                client_free_node(client);
            }
#endif

            /* Clean up */
            command = NULL;
            memset(linebuffer, 0, sizeof(linebuffer));
            len = 0;
            client = NULL;
        }
    }

    UNLOCK_CLIENT_LIST();
    debug(LOG_INFO, "Client list downloaded successfully from parent");

    close(sock);
}

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_DEBUG, "____Handler for SIGCHLD called. Trying to reap a child");

    rc = waitpid(-1, &status, WNOHANG);

    debug(LOG_DEBUG, "____Handler for SIGCHLD reaped child PID %d", rc);
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
void
termination_handler(int s)
{
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
#if OK_PATCH
#else
    pthread_t self = pthread_self();
#endif

    debug(LOG_INFO, "____Handler for termination caught signal %d", s);

    /* Makes sure we only call fw_destroy() once. */
    if (pthread_mutex_trylock(&sigterm_mutex)) {
        debug(LOG_INFO, "____Another thread already began global termination handler. I'm exiting");
        pthread_exit(NULL);
    } else {
        debug(LOG_INFO, "____Cleaning up and exiting");
    }

    debug(LOG_INFO, "____Flushing firewall rules...");
    fw_destroy();

    /* XXX Hack
     * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
     * termination handler) from happening so we need to explicitly kill the threads 
     * that use that
     */
#if OK_PATCH
#else
    if (tid_fw_counter && self != tid_fw_counter) {
        debug(LOG_INFO, "Explicitly killing the fw_counter thread");
        pthread_kill(tid_fw_counter, SIGKILL);
    }
    if (tid_ping && self != tid_ping) {
        debug(LOG_INFO, "Explicitly killing the ping thread");
        pthread_kill(tid_ping, SIGKILL);
    }
#endif

    debug(LOG_NOTICE, "____Exiting...");
    exit(s == 0 ? 1 : 0);
}

/** @internal 
 * Registers all the signal handlers
 */
static void
init_signals(void)
{
    struct sigaction sa;

    debug(LOG_DEBUG, "Initializing signal handlers");

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1001);
    }

    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1002);
    }

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1003);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1004);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1005);
    }
}

#if OK_PATCH
static void reserve_fd()
{
    s_config *config = config_get_config();
    if (!config->daemon) {
        return;
    }
    
    int fd;

    for (fd = 0; fd < 3; fd++) {
        int nfd;
        nfd = open("/dev/null", O_RDWR);

        if (nfd < 0) /* We're screwed. */
            continue;

        if (nfd == fd)
            continue;

        dup2(nfd, fd);
        if (nfd > 2)
            close(nfd);
    }
}
#endif


/**@internal
 * Main execution loop 
 */
static void
main_loop(void)
{
    int result;
    pthread_t tid;
    s_config *config = config_get_config();
    request *r;
    void **params;

    /* Set the time when wifidog started */
    if (!started_time) {
        debug(LOG_INFO, "<DAEMON> Setting started_time");
        started_time = time(NULL);
    } else if (started_time < MINIMUM_STARTED_TIME) {
        debug(LOG_WARNING, "<DAEMON> Detected possible clock skew - re-setting started_time");
        started_time = time(NULL);
    }

    /* OK_PATCH
     * Since the condition could never be filled, you won't see the file recorded the pid.
     */
	/* save the pid file if needed */
    if ((!config) && (!config->pidfile))
        save_pid_file(config->pidfile);

#if OK_PATCH
#else /* OK_PATCH */
    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (!config->gw_address) {
        debug(LOG_DEBUG, "Finding IP address of %s", config->gw_interface);
        if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
            exit(1);
        }
        debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_address);
    }

    /* If we don't have the Gateway ID, construct it from the internal MAC address.
     * "Can't fail" so exit() if the impossible happens. */
    if (!config->gw_id) {
        debug(LOG_DEBUG, "Finding MAC address of %s", config->gw_interface);
        if ((config->gw_id = get_iface_mac(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get MAC address information of %s, exiting...", config->gw_interface);
            exit(1);
        }
        debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_id);
    }
#endif /* OK_PATCH */

    /* Initializes the web server */
#if OK_PATCH
    reserve_fd();
    debug(LOG_NOTICE, "<DAEMON> Creating web server on %s:%d", "0.0.0.0", config->gw_port);
    if (NULL == (webserver = httpdCreate(HTTP_ANY_ADDR, config->gw_port))) {
#else
    debug(LOG_NOTICE, "Creating web server on %s:%d", config->gw_address, config->gw_port);
    if (NULL == (webserver = httpdCreate(config->gw_address, config->gw_port))) {
#endif
        debug(LOG_ERR, "<DAEMON> Could not create web server: %s", strerror(errno));
        exit(1006);
    }
    register_fd_cleanup_on_fork(webserver->serverSock);
    debug(LOG_DEBUG, "<DAEMON> Created web server {Host=%s, Port=%d, ServerSock=%d, StartTime=%d, LastError=%d}",
            webserver->host, webserver->port, webserver->serverSock,
            webserver->startTime, webserver->lastError);

    debug(LOG_DEBUG, "<DAEMON> Assigning callbacks to web server");
#if OK_PATCH
    /* FIXME
     * Why don't we add some funny things here?
     */
    okos_init_http_callback();
    okos_http_callback_register("about", okos_http_cb_shell, NULL);

    httpdAddCContent(webserver, "/", "auth", 0, NULL, okos_http_cb_wifidog);
    httpdAddCContent(webserver, "/auth", "", 0, NULL, okos_http_cb_wifidog);
    
    httpdAddCContent(webserver, "/auth", "client", 0, NULL, okos_http_cb_auth);
    httpdAddCContent(webserver, "/auth/client", "allow", 0, NULL, okos_http_cb_allow);
    httpdAddCContent(webserver, "/auth/client", "qrcode", 0, NULL, okos_http_cb_qrcode);

#else
    httpdAddCContent(webserver, "/", "wifidog", 0, NULL, http_callback_wifidog);
    httpdAddCContent(webserver, "/wifidog", "", 0, NULL, http_callback_wifidog);
    httpdAddCContent(webserver, "/wifidog", "about", 0, NULL, http_callback_about);
    httpdAddCContent(webserver, "/wifidog", "status", 0, NULL, http_callback_status);
    httpdAddCContent(webserver, "/wifidog", "auth", 0, NULL, http_callback_auth);
    httpdAddCContent(webserver, "/wifidog", "disconnect", 0, NULL, http_callback_disconnect);
#endif

    httpdSetErrorFunction(webserver, 404, okos_http_cb_404);

    /* Reset the firewall (if WiFiDog crashed) */
    fw_destroy();
    /* Then initialize it */
    if (!fw_init()) {
        debug(LOG_ERR, "FATAL: Failed to initialize firewall");
        exit(1007);
    }

    /* Start clean up thread */
    result = pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (fw_counter) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_fw_counter);

    /* Start control thread */
    result = pthread_create(&tid, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid);

    ping();
    /* Start heartbeat thread */    /*
    result = pthread_create(&tid_ping, NULL, (void *)thread_ping, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (ping) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_ping);
    */

    debug(LOG_NOTICE, "<DAEMON> Waiting for connections");
    while (1) {
        r = httpdGetConnection(webserver, NULL);
        /*
        httpdEndRequest(r);
        continue;
        /**/

        /* We can't convert this to a switch because there might be
         * values that are not -1, 0 or 1. */
        if (webserver->lastError == -1) {
            /* Interrupted system call */
            if (NULL != r) {
                httpdEndRequest(r);
            }
        } else if (webserver->lastError < -1) {
            /*
             * FIXME
             * An error occurred - should we abort?
             * reboot the device ?
             */
            debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.", webserver->lastError);
            termination_handler(0);
        } else if (r != NULL) {
            /*
             * We got a connection
             *
             * We should create another thread
             */
            debug(LOG_DEBUG, "Received connection from %s, spawning worker thread", r->clientAddr);
            /* The void**'s are a simulation of the normal C
             * function calling sequence. */
            params = safe_malloc(2 * sizeof(void *));
            *params = webserver;
            *(params + 1) = r;

            result = pthread_create(&tid, NULL, (void *)thread_httpd, (void *)params);
            if (result != 0) {
                debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
                termination_handler(0);
            }
            pthread_detach(tid);
        } else {
            /* webserver->lastError should be 2 */
            /* XXX We failed an ACL.... No handling because
             * we don't set any... */
        }
    }

    /* never reached */
}

/** Reads the configuration file and then starts the main loop */
int
gw_main(int argc, char **argv)
{

    s_config *config = config_get_config();
    config_init();

    parse_commandline(argc, argv);

    /* Initialize the config */
    config_read(config->configfile);
    config_simulate();
    config_validate();

    config_init_override();

    /* Initializes the linked list of connected clients */
    client_list_init();

    /* Init the signals to catch chld/quit/etc */
    init_signals();

    if (restart_orig_pid) {
        /*
         * We were restarted and our parent is waiting for us to talk to it over the socket
         */
        get_clients_from_parent();

        /*
         * At this point the parent will start destroying itself and the firewall. Let it finish it's job before we continue
         */
        while (kill(restart_orig_pid, 0) != -1) {
            debug(LOG_INFO, "Waiting for parent PID %d to die before continuing loading", restart_orig_pid);
            sleep(1);
        }

        debug(LOG_INFO, "Parent PID %d seems to be dead. Continuing loading.");
    }

    if (config->daemon) {

        debug(LOG_INFO, "Forking into background");

        switch (safe_fork()) {
        case 0:                /* child */
            setsid();
            append_x_restartargv();
            main_loop();
            break;

        default:               /* parent */
            exit(0);
            break;
        }
    } else {
        append_x_restartargv();
        main_loop();
    }

    return (0);                 /* never reached */
}

