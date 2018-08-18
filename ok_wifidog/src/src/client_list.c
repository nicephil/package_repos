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

/** @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <string.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"

#if OK_PATCH
#include "auth.h"
#include "okos_auth_param.h"
#include "firewall.h"
#include "pstring.h"
#endif

/** @internal
 * Holds a pointer to the first element of the list 
 */
static t_client *firstclient = NULL;

/** @internal
 * Client ID
 */
static volatile unsigned long long client_id = 1;

/**
 * Mutex to protect client_id and guarantee uniqueness.
 */
static pthread_mutex_t client_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

#if OK_PATCH
typedef enum {
    ClientListNew,
    ClientListUpdated,
    ClientListChecked,
} OKOSClientListStatus;
static volatile OKOSClientListStatus client_list_status = ClientListNew;
static pthread_mutex_t client_list_status_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LOCK_LIST_STATUS(why) do { \
	debug(LOG_DEBUG, "____Locking list status for %s____", why); \
    pthread_mutex_lock(&client_list_status_mutex); \
	debug(LOG_DEBUG, "____List status locked for %s____", why); \
} while (0)

#define UNLOCK_LIST_STATUS(why) do { \
	debug(LOG_DEBUG, "____Unlocking list status for %s____", why); \
    pthread_mutex_unlock(&client_list_status_mutex); \
	debug(LOG_DEBUG, "____List status unlocked for %s____", why); \
} while (0)

void okos_client_list_created(void)
{/*
    LOCK_LIST_STATUS("New");
    client_list_status = ClientListNew;
    UNLOCK_LIST_STATUS("New");
    */
}

void okos_client_list_updated(void)
{/*
    LOCK_LIST_STATUS("update");
    client_list_status = ClientListUpdated;
    UNLOCK_LIST_STATUS("update");
    */
}

void okos_client_list_checked(void)
{/*
    LOCK_LIST_STATUS("check up");
    client_list_status = ClientListChecked;
    UNLOCK_LIST_STATUS("check up");
    */
}

int okos_client_list_should_be_checked(void)
{
    int result = 1;
    LOCK_LIST_STATUS("check in");
    if (ClientListChecked == client_list_status) {
        result = 0;
    }
    UNLOCK_LIST_STATUS("check in");
    return result;
}
    
#endif /* OK_PATCH */


/** Get a new client struct, not added to the list yet
 * @return Pointer to newly created client object not on the list yet.
 */
t_client *
client_get_new(void)
{
    t_client *client;
    client = safe_malloc(sizeof(t_client));
    return client;
}

/** Get the first element of the list of connected clients
 */
t_client *
client_get_first_client(void)
{
    return firstclient;
}

/**
 * Initializes the list of connected clients (client)
 */
void
client_list_init(void)
{
    firstclient = NULL;
    okos_client_list_created();
}

/** Insert client at head of list. Lock should be held when calling this!
 * @param Pointer to t_client object.
 */
static int okos_client_list_client_complete(t_client *client)
{
#define OK_STR(str) (str) ? (str) : "Nil"

    if (NULL == client->mac || \
        NULL == client->ifx || \
        NULL == client->ssid || \
        NULL == client->if_name \
        )
    {
        debug(LOG_ERR, "!!!! Corrupt Fruit {ip:%s, mac:%s, if_name:%s, ifx:0x%x, ssid:0x%x}",
                OK_STR(client->ip), OK_STR(client->mac), OK_STR(client->if_name),
                client->ifx, client->ssid);
        client_free_node(client);
        return -1;
    }
    if (NULL == client->ip) {
        client->ip = safe_strdup("");
    }
    if (NULL == client->user_name) {
        client->user_name = safe_strdup("");
    }
    return 0;
}

#define CLIENT_LIST_FLAG_POLLING 0x1
void
client_list_set_polling_flag(t_client *client)
{
    client->flag |= CLIENT_LIST_FLAG_POLLING;
}
void
client_list_unset_polling_flag(t_client *client)
{
    client->flag &= ~CLIENT_LIST_FLAG_POLLING;
}
int client_list_polling_flag(t_client *client)
{
    return client->flag & CLIENT_LIST_FLAG_POLLING;
}

void
client_list_insert_client(t_client **p_client)
{
    t_client *client = *p_client;
    int failed = okos_client_list_client_complete(client);
    if (failed) {
        *p_client = NULL;
        return;
    }

    t_client *prev_head;

    pthread_mutex_lock(&client_id_mutex);
    client->id = client_id++;
    pthread_mutex_unlock(&client_id_mutex);
    prev_head = firstclient;
    client->next = prev_head;
    firstclient = client;

    okos_client_list_updated();
}
#if OK_PATCH
int okos_client_list_is_empty(t_client * list)
{
    list = list ? list : firstclient;
    LOCK_CLIENT_LIST();
    int res = list ? 0 : 1;
    UNLOCK_CLIENT_LIST();

    return res;
}

static t_client * okos_client_query_mac(t_client *first, const char *mac)
{
    if (NULL == first || NULL == mac) {
        return NULL;
    }

    t_client *ptr = first;
    while (NULL != ptr) {
        if (0 == strcasecmp(ptr->mac, mac)) {
            return ptr;
        }
        ptr = ptr->next;
    }

    return NULL;
}




#if OK_PATCH
#else
/* FIXME: if you want to use this function, you have to handle all the string element
 *
 */
#if 0
t_client *
okos_client_list_add(const char *ip, const char *mac, const char *token, 
                const unsigned int remain_time, const unsigned int auth_mode,
                const char * username)
{
    t_client *curclient;

    curclient = client_get_new();

    curclient->ip = safe_strdup(ip);
    curclient->mac = safe_strdup(mac);
    curclient->token = safe_strdup(token);
    curclient->counters.incoming_delta = curclient->counters.outgoing_delta = 
        curclient->counters.incoming = curclient->counters.incoming_history =
        curclient->counters.outgoing = curclient->counters.outgoing_history = 0;
    curclient->counters.last_updated = time(NULL);

    curclient->auth_mode = auth_mode;
    curclient->user_name = safe_strdup(username);

    curclient->remain_time = remain_time;
    curclient->last_flushed = time(NULL);

    client_list_insert_client(curclient);

    debug(LOG_INFO, "Added a new client to linked list: IP: %s Token: %s Remain Time: %d", ip, token, remain_time);

    return curclient;
}
#endif 
#endif

void
okos_client_list_flush(t_client *client, const unsigned int remain_time)
{
    client->remain_time = remain_time;
    client->last_flushed = time(NULL);

    okos_client_list_updated();

    debug(LOG_DEBUG, "<client_info>\t\t Flushed an client{%s,%s,%s} Remain Time: %ld",
            client->ip, client->mac, client->if_name, remain_time);
}

void
okos_client_list_flush_all(t_client *old, t_client *cur)
{
    old->remain_time = cur->remain_time;
    old->last_flushed = cur->last_flushed;
    old->auth_mode = cur->auth_mode;
    okos_client_update_strdup_after_cmp(old->user_name, cur->user_name);
    client_free_node(cur);

    okos_client_list_updated();
    debug(LOG_DEBUG, "<client_info>\t Client{%s,%s,%s} got flushed with"
            "{remain_time:%ld, authmode:%d, user_name:%s}",
            old->ip, old->mac, old->if_name,
            old->remain_time, old->auth_mode, old->user_name);
}
#if 0
t_client *
okos_client_list_client_update(const t_auth_confirm_info *info, t_client *client)
{
    if (NULL == client->ip)
        return NULL;

    time_t curtime = time(NULL);
    if (NULL == client->mac) {
        if (0 != okos_mac_bin2str(info->mac1, &(client->mac))) {
            return NULL;
        }
        client->token = safe_strdup(OKOS_AUTH_FAKE_TOKEN);
        client->counters.incoming_delta = client->counters.outgoing_delta = 
            client->counters.incoming = client->counters.incoming_history =
            client->counters.outgoing = client->counters.outgoing_history = 0;
        client->counters.last_updated = curtime;

        client->auth_mode = info->auth_mode;
        client->user_name = safe_strdup(info->user);
        debug(LOG_DEBUG, "Set Mac [%s] to client: %s", client->mac, client->ip);
    }

    client->remain_time = info->remain_time;
    client->last_flushed = curtime;
    
    debug(LOG_DEBUG, "Update remain_time: %d.", client->remain_time);
    return client;
}
#endif

#if 0
t_client *
okos_client_list_update_mac(t_client *client, const char *mac, const t_auth_confirm_info *info)
{
    if (NULL == client->mac) {
        client->mac = safe_strdup(mac);
        client->token = safe_strdup(OKOS_AUTH_FAKE_TOKEN);
        client->counters.incoming_delta = client->counters.outgoing_delta = 
            client->counters.incoming = client->counters.incoming_history =
            client->counters.outgoing = client->counters.outgoing_history = 0;
        client->counters.last_updated = time(NULL);

        client->auth_mode = info->auth_mode;
        if (NULL != info->user)
            client->user_name = safe_strdup(info->user);

        client->remain_time = info->remain_time;
        client->last_flushed = time(NULL);
    
        debug(LOG_DEBUG, "Set Mac [%s] to client: %s", mac, client->ip);
    }
    return client;
}
#endif

#endif

#if 0
/** Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * Client is inserted at the head of the list.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @return Pointer to the client we just created
 */
t_client *
client_list_add(const char *ip, const char *mac, const char *token)
{
    t_client *curclient;

    curclient = client_get_new();

    curclient->ip = safe_strdup(ip);
    curclient->mac = safe_strdup(mac);
    curclient->token = safe_strdup(token);
    curclient->counters.incoming_delta = curclient->counters.outgoing_delta = 
            curclient->counters.incoming = curclient->counters.incoming_history = curclient->counters.outgoing =
        curclient->counters.outgoing_history = 0;
    curclient->counters.last_updated = time(NULL);

    client_list_insert_client(curclient);

    debug(LOG_INFO, "Added a new client to linked list: IP: %s Token: %s", ip, token);

    return curclient;
}
#endif

/** Duplicate the whole client list to process in a thread safe way
 * MUTEX MUST BE HELD.
 * @param dest pointer TO A POINTER to a t_client (i.e.: t_client **ptr)
 * @return int Number of clients copied
 */
int
client_list_dup(t_client ** dest)
{
    t_client *new, *cur, *top, *prev;
    int copied = 0;

    cur = firstclient;
    new = top = prev = NULL;

    if (NULL == cur) {
        *dest = new;            /* NULL */
        return copied;
    }

    while (NULL != cur) {
        new = client_dup(cur);
        if (NULL == top) {
            /* first item */
            top = new;
        } else {
            prev->next = new;
        }
        prev = new;
        copied++;
        cur = cur->next;
    }

    *dest = top;
    return copied;
}

/** Create a duplicate of a client.
 * @param src Original client
 * @return duplicate client object with next == NULL
 */
t_client *
client_dup(const t_client * src)
{
    t_client *new = NULL;
    
    if (NULL == src) {
        return NULL;
    }
    
    new = client_get_new();

    new->id = src->id;
    new->ip = safe_strdup(src->ip);
    new->mac = safe_strdup(src->mac);
#if OK_PATCH
#else
    new->token = safe_strdup(src->token);
#endif
#if 0
    new->counters.incoming = src->counters.incoming;
    new->counters.incoming_history = src->counters.incoming_history;
    new->counters.incoming_delta = src->counters.incoming_delta;
    new->counters.outgoing = src->counters.outgoing;
    new->counters.outgoing_history = src->counters.outgoing_history;
    new->counters.outgoing_delta = src->counters.outgoing_delta;
    new->counters.last_updated = src->counters.last_updated;
#endif
#if OK_PATCH
    new->auth_mode = src->auth_mode;
    new->user_name = safe_strdup(src->user_name);
    new->remain_time = src->remain_time;
    new->last_flushed = src->last_flushed;

    new->if_name = safe_strdup(src->if_name);
    new->ifx = src->ifx;
    new->ssid = src->ssid;

    new->flag = src->flag;
#endif /* OK_PATCH */

    new->next = NULL;

    return new;
}

/** Find a client in the list from a client struct, matching operates by id.
 * This is useful from a copy of client to find the original.
 * @param client Client to find
 * @return pointer to the client in the list.
 */
t_client *
client_list_find_by_client(t_client * client)
{
    t_client *c = firstclient;

    while (NULL != c) {
        if (c->id == client->id) {
            return c;
        }
        c = c->next;
    }
    return NULL;
}

/** Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find(const char *ip, const char *mac)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcasecmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

#if OK_PATCH

t_client *
client_list_find_by_scheme(const char *mac, const char *scheme)
{
    t_client *pclient;
    okos_list_for_each(pclient, firstclient) {
        if (0 == strcasecmp(pclient->mac, mac) && 0 == strcmp(pclient->ssid->scheme, scheme))
            return pclient;
    }

    return NULL;
}


t_client *
client_list_find_by_ssid(const char *mac, const char *ssid)
{
    t_client *pclient;
    okos_list_for_each(pclient, firstclient) {
        if (0 == strcasecmp(pclient->mac, mac) && 0 == strcmp(pclient->ssid->ssid, ssid))
            return pclient;
    }

    return NULL;
}

#endif

/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_ip(const char *ip)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * Finds a  client by its Mac, returns NULL if the client could not
 * be found
 * @param mac Mac we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_mac(const char *mac)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcasecmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

#if OK_PATCH
#else
/** Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_token(const char *token)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}
#endif

/** Destroy the client list. Including all free.
 * DOES NOT UPDATE firstclient or anything else.
 * @param list List to destroy (first item)
 */
void
client_list_destroy(t_client * list)
{
    t_client *next;

    while (NULL != list) {
        next = list->next;
        client_free_node(list);
        list = next;
    }
}

/** @internal
 * @brief Frees the memory used by a t_client structure
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void
client_free_node(t_client * client)
{
    if (NULL == client) {
        return;
    }

    if (client->mac)
        free(client->mac);
    if (client->ip)
        free(client->ip);
    if (client->user_name)
        free(client->user_name);
    if (client->if_name)
        free(client->if_name);

#if OK_PATCH
#else
    if (client->token != NULL)
        free(client->token);
#endif

    free(client);
}

/**
 * @brief Deletes a client from the connections list
 *
 * Removes the specified client from the connections list and then calls
 * the function to free the memory used by the client.
 * @param client Points to the client to be deleted
 */
void
client_list_delete(t_client * client)
{
    client_list_remove(client);
    client_free_node(client);
}

/**
 * @brief Removes a client from the connections list
 *
 * @param client Points to the client to be deleted
 */
void
client_list_remove(t_client * client)
{
    t_client *ptr;

    ptr = firstclient;

    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == client) {
        firstclient = ptr->next;
    } else {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != client) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        } else {
            ptr->next = client->next;
        }
    }
}


#if OK_PATCH

static void okos_get_client_status_format2(const t_client *p_node, pstr_t *p_str)
{
    pstr_append_sprintf(p_str, "%15s %17s %10d [%s] [%s]",
            p_node->ip, p_node->mac, p_node->auth_mode,
            p_node->ssid->ssid, p_node->user_name);
}

static void okos_get_client_status(const t_client *p_node, pstr_t *p_str)
{
    okos_get_client_status_format2(p_node, p_str);
}

typedef t_client * (*ok_client_search)(const char *, const char *);
typedef void (*ok_client_action)(t_client *);

static char *
okos_polling_list_by(const char *name, const char *mac,
        const char *cond, const char *cond_name,
        ok_client_search search, ok_client_action action, int *num)
{
    debug(LOG_DEBUG, "<WDCTL> Polling List to %s client by %s [%s - %s]",
            name, cond_name, mac, cond?cond:"?"); 

    *num = 0;
    pstr_t *p_str = pstr_new();
    pstr_append_sprintf(p_str, "%s client [%s]", name, mac);
    if (cond) {
        pstr_append_sprintf(p_str, " with %s[%s]:\n", cond_name, cond);
    } else {
        pstr_cat(p_str, " all:\n");
    }
    pstr_cat(p_str, "IP Address      MAC Address       AUTH MODE   SSID                  User Name\n");
	LOCK_CLIENT_LIST();
	t_client *node;
    if (cond) {
        node = search(mac, cond);
        if (node) {
            okos_get_client_status(node, p_str);
            (*num)++;
            if (action) {
                action(node);
            }
        }
    } else {
        node = client_get_first_client();
        t_client *tmp = NULL;
        while (NULL != (node = okos_client_query_mac(node, mac))) {
            okos_get_client_status(node, p_str);
            tmp = node;
            node = node->next;
            (*num)++;
            if (action) {
                action(tmp);
            }
        }
    }
	UNLOCK_CLIENT_LIST();
    pstr_cat(p_str, "\nSee you later.\n\n");
    return pstr_to_string(p_str);
}

char *
okos_delete_clients_by_scheme(const char *mac, const char *scheme, int *num)
{
    return okos_polling_list_by("OFFLINE", mac, scheme, "scheme",
            client_list_find_by_scheme, kickoff_client, num);
}

char *
okos_delete_clients_by_ssid(const char *mac, const char *ssid, int *num)
{
    return okos_polling_list_by("RESET", mac, ssid, "SSID",
            client_list_find_by_ssid, logout_client, num);
}

char *
okos_get_client_status_text(const char *mac, const char *ssid, int *num)
{
    return okos_polling_list_by("STATUS", mac, ssid, "SSID",
            client_list_find_by_ssid, NULL, num);
}

#endif
