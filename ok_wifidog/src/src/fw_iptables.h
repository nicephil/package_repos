/* vim: set et ts=4 sts=4 sw=4 : */
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
/** @file fw_iptables.h
    @brief Firewall iptables functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _FW_IPTABLES_H_
#define _FW_IPTABLES_H_

#include "firewall.h"

#define CHAIN_NAME_MAX_LEN 15  /* 28 (actual max) - 13 (AuthServers chain fixed part. */

#if OK_PATCH

#define CHAIN_OUTGOING_i  "OKOS_Outgoing_%d"
#define CHAIN_TO_INTERNET_i "OKOS_Internet_%d"
#define CHAIN_TO_ROUTER_i "OKOS_Router_%d"
#define CHAIN_INCOMING_i  "OKOS_Incoming_%d"
#define CHAIN_AUTHSERVERS_i "OKOS_AuthServs_%d"  /* Longest chain, 13 chars ecluding ID */
#define CHAIN_TRUSTED_i    "OKOS_Trusted_%d"
#define CHAIN_UNKNOWN_i   "OKOS_Unknown_%d"
#define CHAIN_DN_ALLOWED_i "OKOS_DN_Allowed_%d"
#define CHAIN_IP_ALLOWED_i "OKOS_IP_Allowed_%d"
#define CHAIN_AUTH_IS_DOWN_i "OKOS_AuthDown_%d"

#define CHAIN_OUTGOING  "OKOS_Outgoing"
#define CHAIN_TO_INTERNET "OKOS_Internet"
#define CHAIN_TO_ROUTER "OKOS_Router"
#define CHAIN_INCOMING  "OKOS_Incoming"
#define CHAIN_AUTHSERVERS "OKOS_AuthServs"  /* Longest chain, 13 chars ecluding ID */
#define CHAIN_TRUSTED    "OKOS_Trusted"
#define CHAIN_DN_ALLOWED "OKOS_DN_Allowed"
#define CHAIN_IP_ALLOWED "OKOS_IP_Allowed"
#define CHAIN_GLOBAL  "OKOS_Global"
#define CHAIN_VALIDATE  "OKOS_Validate"
#define CHAIN_KNOWN     "OKOS_Known"
#define CHAIN_UNKNOWN   "OKOS_Unknown"
#define CHAIN_LOCKED    "OKOS_Locked"
#define CHAIN_AUTH_IS_DOWN "OKOS_AuthDown"

#else /* OK_PATCH */
/*@{*/
/**Iptable chain names used by WifiDog */
#define CHAIN_OUTGOING  "WD_$ID$_Outgoing"
#define CHAIN_TO_INTERNET "WD_$ID$_Internet"
#define CHAIN_TO_ROUTER "WD_$ID$_Router"
#define CHAIN_INCOMING  "WD_$ID$_Incoming"
#define CHAIN_AUTHSERVERS "WD_$ID$_AuthServs"  /* Longest chain, 13 chars ecluding ID */
#define CHAIN_GLOBAL  "WD_$ID$_Global"
#define CHAIN_VALIDATE  "WD_$ID$_Validate"
#define CHAIN_KNOWN     "WD_$ID$_Known"
#define CHAIN_UNKNOWN   "WD_$ID$_Unknown"
#define CHAIN_LOCKED    "WD_$ID$_Locked"
#define CHAIN_TRUSTED    "WD_$ID$_Trusted"
#define CHAIN_AUTH_IS_DOWN "WD_$ID$_AuthDown"
/*@}*/
#endif /* OK_PATCH */

/** Used by iptables_fw_access to select if the client should be granted of denied access */
typedef enum fw_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY
} fw_access_t;

/** @brief Initialize the firewall */
int iptables_fw_init(void);

#if OK_PATCH

struct s_ssid_config;

/** @brief Initializes the authservers table */
void iptables_fw_set_authservers(void);
/** @brief Clears the authservers table */
void iptables_fw_clear_authservers(void);
int iptables_fw_access_host(fw_access_t , const char *, const struct _s_ssid_config *);
int iptables_fw_access(fw_access_t , const char *, const char *, int , const struct _s_ssid_config * );

#else /* OK_PATCH */

/** @brief Initializes the authservers table */
void iptables_fw_set_authservers(void);
/** @brief Clears the authservers table */
void iptables_fw_clear_authservers(void);
/** @brief Define the access of a specific client */
int iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);
/** @brief Define the access of a host */
int iptables_fw_access_host(fw_access_t type, const char *host);

#endif /* OK_PATCH */

/** @brief Destroy the firewall */
int iptables_fw_destroy(void);

/** @brief Helper function for iptables_fw_destroy */
int iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention);

/** @brief Set a mark when auth server is not reachable */
int iptables_fw_auth_unreachable(int tag);

/** @brief Remove mark when auth server is reachable again */
int iptables_fw_auth_reachable(void);

/** @brief All counters in the client list */
int iptables_fw_counters_update(void);


#endif                          /* _IPTABLES_H_ */
