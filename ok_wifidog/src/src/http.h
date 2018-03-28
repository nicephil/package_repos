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
/** @file http.h
    @brief HTTP IO functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"

void okos_http_cb_wifidog(httpd *, request *);
void okos_http_cb_404(httpd *, request *, int);
void okos_http_cb_auth(httpd *, request *);
void okos_http_cb_allow(httpd *, request *);
void okos_http_cb_qrcode(httpd *, request *);

struct _t_client;
void okos_add_validation_client(struct _t_client **);

struct _auth_serv_t;

typedef char * (*okos_http_callback_func)(char *, void *);
typedef struct _t_http_callback {
    const char *name;
    okos_http_callback_func p_func;
	void *data;
    struct _t_http_callback *next;
} t_http_callback;

void okos_init_http_callback(void);
int okos_http_callback_register(const char *, okos_http_callback_func, void *);

char * okos_http_cb_shell(char *, void *);

void okos_http_statistic_variables(request *);

#endif /* _HTTP_H_ */
