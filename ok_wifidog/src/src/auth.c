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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
pthread_cond_t client_polling_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t client_polling_cond_mutex = PTHREAD_MUTEX_INITIALIZER;

void
thread_client_timeout_check(const void *arg)
{
    struct timespec timeout;
    timeout.tv_sec = time(NULL) + 5;
    timeout.tv_nsec = 0;

    while (1) {
        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&client_polling_cond_mutex);
        /* Thread safe "sleep" */
        pthread_cond_timedwait(&client_polling_cond, &client_polling_cond_mutex, &timeout);
        /* No longer needs to be locked */
        pthread_mutex_unlock(&client_polling_cond_mutex);
        debug(LOG_DEBUG, "<ClientTimeout>: Running client checking...");
        timeout.tv_sec = fw_sync_with_authserver() + 3;
        debug(LOG_DEBUG, "<ClientTimeout>: See you in %ld seconds", timeout.tv_sec);
    }
}

void
logout_client(t_client * client)
{
    if (NULL == client) {
        debug(LOG_DEBUG, "!!!!Who are trying to logout NULL client");
    }
    fw_deny(client);
    client_list_remove(client);
    client_free_node(client);
}

