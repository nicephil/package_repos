/*********************************************************
 AEROHIVE CONFIDENTIAL

 Copyright [2006] - [2011] Aerohive Networks, Inc.
 All Rights Reserved.

 NOTICE: All information herein is and remains the property
 of Aerohive Networks, Inc. and its suppliers, if any.

 The intellectual and technical concepts contained herein
 are proprietary to Aerohive Networks, Inc. and its
 suppliers and may be covered by U.S. and foreign patents
 and/or pending patent applications, and are protected by
 trade secret and copyright law.

 Disclosure, dissemination or reproduction of this
 information or the intellectual or technical concepts
 expressed by this information is prohibited unless prior
 written permission is obtained from Aerohive Networks, Inc.
 **********************************************************/
/*****************************************************************************
 *
 * Copyright (C) 2006 Aerohive Networks
 *
 * This file contains global typedefs and defines for kernel modules
 *
 * Author: Peter Wu
 *
 *****************************************************************************/

#ifndef _AH_KGLOBAL_H_
#define _AH_KGLOBAL_H_

#include "ah_net.h"

typedef struct ah_qos_module_dev_       ah_qos_module_dev_t;
typedef struct ah_sys_dev_qos_          ah_sys_dev_qos_t;
typedef struct ah_sys_dev_vlan_         ah_sys_dev_vlan_t;
typedef struct ah_sys_dev_              ah_sys_dev_t;
typedef struct ah_qos_vlan_             ah_qos_vlan_t;
typedef struct ah_qos_vlan_table_       ah_qos_vlan_table_t;
typedef struct ah_qos_user_profile_     ah_qos_user_profile_t;
typedef struct ah_qos_policy_           ah_qos_policy_t;
typedef struct ah_qos_user_             ah_qos_user_t;
typedef struct ah_qos_classifier_profile_  ah_qos_classifier_profile_t;
typedef struct ah_qos_policer_profile_  ah_qos_policer_profile_t;
typedef struct ah_qos_marker_profile_   ah_qos_marker_profile_t;
typedef struct ah_qos_scheduler_profile_ ah_qos_scheduler_profile_t;
typedef struct ah_mgt_if_               ah_mgt_if_t;
typedef struct ah_port_                 ah_port_t;
typedef struct ah_screen_method_        ah_screen_method_t;

/* firewall structures */
typedef struct ah_acl_grp_              ah_acl_grp_t;
typedef struct ah_mac_acl_grp_          ah_mac_acl_grp_t;

/* flow structures */
typedef struct ah_ip_sess_              ah_ip_sess_t;
typedef struct ah_ip_flow_              ah_ip_flow_t;
typedef struct ah_mac_sess_             ah_mac_sess_t;
typedef struct ah_mac_flow_             ah_mac_flow_t;
typedef struct ah_ip_gate_              ah_ip_gate_t;
typedef struct ah_tb_                   ah_tb_t;
typedef struct ah_dev_mac_list_         ah_dev_mac_list_t;

extern struct net_device               *g_mgt_if;
extern ah_mac_t                         ah_base_mac_addr;

#endif /* _AH_KGLOBAL_H_ */

