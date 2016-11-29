/*************************************************************************
* @file ah_shm.h
* @brief Shared memory APIs
*
*************************************************************************/

#ifndef AH_SHM_H
#define AH_SHM_H

#include <ah_types.h>
#include <ah_sem.h>

/* Add your shared memory and semaphore id below */
#define AH_DCD_SHM_ID            0x01000
#define AH_DCD_SEM_ID            0x01001
#define AH_DCD_PU_SEM_ID         0x01002 /* per user sem id */
#define AH_SCD_SEM_ID            0x02000
#define AH_SCD_SHM_ID            0x02001
#define AH_SCD_WR_SHADOW_SEM_ID  0x02002

#define AH_TOP_SEM_ID            0x03000
#define AH_TOP_SHM_ID            0x03001

#define AH_CONF_SEM_ID           0x04000
#define AH_CONF_SHM_ID           0x04001
#define AH_IMG_SEM_ID            0x05000
#define AH_IMG_SHM_ID            0x05001
#define AH_BOOT_SEM_ID           0x06001

#define AH_EVENT_SHM_ID          0x07000
#define AH_EVENT_SEM_ID          0x07001

#define AH_DHCP_SEM_ID           0x08000
#define AH_DHCP_SHM_ID           0x08001

#define AH_AMRP_LIB_SEM_ID       0x09000
#define AH_AMRP_LIB_SHM_ID       0x09001

#define AH_MPI_DEBUG_SEM_ID      0x0a000
#define AH_MPI_DEBUG_SHM_ID      0x0a001

#define AH_RADIUSD_SEM_ID        0x0c000
#define AH_RADIUSD_SHM_ID        0x0c001
#define AH_RADIUSD_SESS_SEM_ID   0x0c002

#define AH_LCS_SEM_ID            0x0d000
#define AH_LCS_SHM_ID            0x0d001

#define AH_CAPWAP_SEM_ID         0x0e000
#define AH_CAPWAP_SHM_ID         0x0e001
#define AH_CAPWAP_TRAP_DB_SEM_ID 0x0e002

#ifdef AH_SUPPORT_HIVEUI
#define AH_CS_SEM_ID             0x0ee00
#define AH_CS_SHM_ID             0x0ee01
#endif

#define AH_CGIC_SEM_ID           0x0f000

#ifdef AH_VPN_ENABLE
#define AH_VPN_SEM_ID            0x10000
#define AH_VPN_SHM_ID            0x10001
#endif

#define AH_NBRCOM_LIB_SEM_ID     0x10100
#define AH_NBRCOM_LIB_SHM_ID     0x10101

#define AH_RT_STA_LIB_SEM_ID     0x10102
#define AH_RT_STA_LIB_SHM_ID     0x10103

#ifdef AH_SUPPORT_LTR
#define AH_LTR_SEM_ID            0x10200
#define AH_LTR_SHM_ID            0x10201
#endif


#define AH_AUTH_USER_GROUP_SEM_ID   0x11000
#define AH_AUTH_USER_GROUP_SHM_ID   0x11001
#define AH_AUTH_USER_SEM_ID         0x11002
#define AH_AUTH_USER_SHM_ID         0x11003
#define AH_AUTH_USER_NUM_SHM_ID     0x11004

#define AH_AUTH_RAD_STAT_DB_SEM_ID  0x11005
#define AH_AUTH_RMC_DB_SEM_ID       0x11006
#define AH_AUTH_OS_DB_SEM_ID        0x11007
#define AH_AUTH_STA_DB_SEM_ID       0x11008
#define AH_BGD_SERVICE_DB_SEM_ID    0x11009
#define AH_RADC_CONF_DB_SEM_ID      0x1100a
#define AH_CLIENT_INFO_DB_SEM_ID    0x11010

#define AH_TPA_SEM_ID               0x12000
#define AH_TPA_SHM_ID               0x12001

#define AH_ITK_LIB_SEM_ID           0x13000
#define AH_ITK_LIB_SHM_ID           0x13001

#define AH_AUTH_ATTR_POLICY_SEM_ID  0x13010
#define AH_AUTH_ATTR_POLICY_SHM_ID  0x13011

#define AH_DCM_SEM_ID               0x14000
#define AH_DCM_SHM_ID               0x14001

#define AH_SCD_IFACE_DNS_SEM_ID     0x14010
#define AH_SCD_IFACE_DNS_SHM_ID     0x14011

#define AH_SCD_MONITOR_SEM_ID       0x14020
#define AH_SCD_MONITOR_SHM_ID       0x14021

#define AH_BRD_ROUTING_SEM_ID       0x15000
#define AH_BRD_ROUTING_SHM_ID       0x15001

#define AH_BRD_CPE_SEM_ID           0x15010
#define AH_BRD_CPE_SHM_ID           0x15011

#define AH_IPFW_SHM_ID              0x16000

#define AH_BRD_3G_USB_MODEM_SEM_ID  0x17000
#define AH_BRD_3G_USB_MODEM_SHM_ID  0x17001

/* Bonjour gateway share memroy */
#define AH_BGD_SEM_ID               0x18010
#define AH_BGD_SHM_ID               0x18011

#define AH_SWD_SEM_ID               0x19000
#define AH_SWD_SHM_ID               0x19001

#define AH_SWD_UPDATE_SEM_ID        0x19010

#define AH_L7D_SEM_ID               0x19100
#define AH_L7D_SHM_ID               0x19101

#define AH_STPD_SEM_ID              0x1A000
#define AH_STPD_SHM_ID              0x1A001

#define AH_ACSD_SEM_ID              0x1B000
#define AH_ACSD_SHM_ID              0x1B001
#ifdef AH_SUPPORT_IPV6
#define AH_DHCPV6_SEM_ID            0x1C000
#define AH_DHCPV6_SHM_ID            0x1C001
#endif

#define AH_CONFIG_SEM_ID            0x1D000
#define AH_CONFIG_SHM_ID            0x1D001
#define AH_VAR_SEM_ID               0x1D100
#define AH_VAR_SHM_ID               0x1D101
#define AH_VAR_SEM_PID_ID           0x1E00 // Use up to 1024 of these
#define AH_VAR_SEM_BLK_ID           0x1E400 // Use up to 1024 of these
#define AH_VAR_SEM_WT_ID            0x1E800 // Use up to 1024 of these

#define AH_SEM_MODE  0666

typedef int ah_shm_t;
typedef key_t ah_shm_key_t;

void *ah_shm_create(ah_shm_t *shmid, ah_shm_key_t key, size_t size);
void ah_shm_destroy(ah_shm_t shmid, void *addr);

#endif /* AH_SHM_H */
