#ifndef AH_DBG_H
#define AH_DBG_H
extern uint ah_lib_dbg;

#ifdef AH_AMRP_DBG

extern uint ah_amrp_dbg;

#define amrp_spf (ah_amrp_dbg & 0x100)
#define amrp_probe (ah_amrp_dbg & 0x200)
#define amrp_timer (ah_amrp_dbg & 0x400)
#define amrp_hive_bcast (ah_amrp_dbg & 0x800)
#define amrp_all (ah_amrp_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_RM_DBG

extern uint ah_rm_dbg;

#define rm_error (ah_rm_dbg & 0x01)
#define rm_basic (ah_rm_dbg & 0x02)
#define rm_info (ah_rm_dbg & 0x04)
#define rm_packet (ah_rm_dbg & 0x08)
#define rm_all (ah_rm_dbg & 0xffffffff)
 
#endif
#ifdef AH_AUTH_DBG

extern uint ah_auth_dbg;

#define auth_error (ah_auth_dbg & 0x01)
#define auth_basic (ah_auth_dbg & 0x02)
#define auth_info (ah_auth_dbg & 0x04)
#define auth_verbose (ah_auth_dbg & 0x08)
#define auth_dump (ah_auth_dbg & 0x10)
#define auth_excessive (ah_auth_dbg & 0x20)
#define auth_comm (ah_auth_dbg & 0x40)
#define auth_packet (ah_auth_dbg & 0x80)
#define auth_sync (ah_auth_dbg & 0x100)
#define auth_probe (ah_auth_dbg & 0x200)
#define auth_dhcp_fp (ah_auth_dbg & 0x400)
#define auth_fsm (ah_auth_dbg & 0x800)
#define auth_all (ah_auth_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define user_lib (ah_lib_dbg & 0x04)
#define workq_lib (ah_lib_dbg & 0x08)
#define httpsnooplib (ah_lib_dbg & 0x10)
#define httpsnoop_pktlib (ah_lib_dbg & 0x20)
#define mdm_lib (ah_lib_dbg & 0x80)
#define cmlib (ah_lib_dbg & 0x100)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_FED_DBG

extern uint ah_fed_dbg;

#define fed_cli (ah_fed_dbg & 0x01)
#define fed_basic (ah_fed_dbg & 0x02)
#define fed_alg_tftp_pkt (ah_fed_dbg & 0x08)
#define fed_alg_tftp_gate (ah_fed_dbg & 0x10)
#define fed_alg_tftp_fsm (ah_fed_dbg & 0x20)
#define fed_alg_tftp_error (ah_fed_dbg & 0x40)
#define fed_alg_ftp_pkt (ah_fed_dbg & 0x80)
#define fed_alg_ftp_gate (ah_fed_dbg & 0x100)
#define fed_alg_ftp_fsm (ah_fed_dbg & 0x200)
#define fed_alg_ftp_error (ah_fed_dbg & 0x400)
#define fed_alg_sip_pkt (ah_fed_dbg & 0x800)
#define fed_alg_sip_gate (ah_fed_dbg & 0x1000)
#define fed_alg_sip_fsm (ah_fed_dbg & 0x2000)
#define fed_alg_sip_error (ah_fed_dbg & 0x4000)
#define fed_alg_sip_parser (ah_fed_dbg & 0x8000)
#define fed_alg_dns_info (ah_fed_dbg & 0x10000)
#define fed_alg_dns_pkt (ah_fed_dbg & 0x20000)
#define fed_alg_dns_error (ah_fed_dbg & 0x40000)
#define fed_all (ah_fed_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_DCD_DBG

extern uint ah_dcd_dbg;

#define dcd_error (ah_dcd_dbg & 0x01)
#define dcd_basic (ah_dcd_dbg & 0x02)
#define dcd_info (ah_dcd_dbg & 0x04)
#define dcd_chnl (ah_dcd_dbg & 0x08)
#define dcd_power (ah_dcd_dbg & 0x10)
#define dcd_idp (ah_dcd_dbg & 0x20)
#define dcd_nbr (ah_dcd_dbg & 0x40)
#define dcd_packet (ah_dcd_dbg & 0x80)
#define dcd_mesh_fo (ah_dcd_dbg & 0x100)
#define dcd_stat (ah_dcd_dbg & 0x200)
#define dcd_lldp_packet (ah_dcd_dbg & 0x400)
#define dcd_lldp_adjacency (ah_dcd_dbg & 0x800)
#define dcd_lldp_error (ah_dcd_dbg & 0x1000)
#define dcd_cdp_packet (ah_dcd_dbg & 0x2000)
#define dcd_cdp_adjacency (ah_dcd_dbg & 0x4000)
#define dcd_cdp_error (ah_dcd_dbg & 0x8000)
#define dcd_ac_console (ah_dcd_dbg & 0x10000)
#define dcd_poe (ah_dcd_dbg & 0x20000)
#define dcd_dfs (ah_dcd_dbg & 0x40000)
#define dcd_ppsk (ah_dcd_dbg & 0x80000)
#define dcd_spectral (ah_dcd_dbg & 0x100000)
#define dcd_idp_detector (ah_dcd_dbg & 0x200000)
#define dcd_idp_da (ah_dcd_dbg & 0x400000)
#define dcd_hash (ah_dcd_dbg & 0x800000)
#define dcd_cpm (ah_dcd_dbg & 0x1000000)
#define dcd_ibeacon (ah_dcd_dbg & 0x2000000)
#define dcd_dos (ah_dcd_dbg & 0x4000000)
#define dcd_sas (ah_dcd_dbg & 0x8000000)
#define dcd_all (ah_dcd_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_SCD_DBG

extern uint ah_scd_dbg;

#define scd_error (ah_scd_dbg & 0x01)
#define scd_basic (ah_scd_dbg & 0x02)
#define scd_info (ah_scd_dbg & 0x04)
#define scd_naas_basic (ah_scd_dbg & 0x08)
#define scd_naas_info (ah_scd_dbg & 0x10)
#define scd_naas_detail (ah_scd_dbg & 0x20)
#define scd_naas_memory (ah_scd_dbg & 0x40)
#define ldap_lib (ah_lib_dbg & 0x80)
#define scd_radsec (ah_scd_dbg & 0x100)
#define scd_radsec_elct (ah_scd_dbg & 0x200)
#define scd_all (ah_scd_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define user_lib (ah_lib_dbg & 0x04)
#define scd_dns (ah_scd_dbg & 0x10)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#define AH_CAPWAP_DBG 1
#ifdef AH_CAPWAP_DBG

extern uint ah_capwap_dbg;

#define capwap_packet (ah_capwap_dbg & 0x01)
#define capwap_basic (ah_capwap_dbg & 0x02)
#define capwap_info (ah_capwap_dbg & 0x04)
#define capwap_ssl (ah_capwap_dbg & 0x08)
#define capwap_trap (ah_capwap_dbg & 0x10)
#define capwap_stat (ah_capwap_dbg & 0x20)
#define capwap_idp (ah_capwap_dbg & 0x40)
#define capwap_itk (ah_capwap_dbg & 0x80)
#define capwap_cli (ah_capwap_dbg & 0x100)
#define capwap_ha (ah_capwap_dbg & 0x200)
#define capwap_idp_packet (ah_capwap_dbg & 0x400)
#define capwap_trap_packet (ah_capwap_dbg & 0x800)
#define capwap_stat_packet (ah_capwap_dbg & 0x1000)
#define capwap_cli_packet (ah_capwap_dbg & 0x2000)
#define capwap_all_event_packet (ah_capwap_dbg & 0x4000)
#define capwap_hvcom (ah_capwap_dbg & 0x8000)
#define capwap_hvcom_packet (ah_capwap_dbg & 0x10000)
#define capwap_htc_basic (ah_capwap_dbg & 0x20000)
#define capwap_htc_detail (ah_capwap_dbg & 0x40000)
#define capwap_htc_info (ah_capwap_dbg & 0x80000)
#define capwap_delay (ah_capwap_dbg & 0x100000)
#define capwap_all (ah_capwap_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define l7dlib (ah_lib_dbg & 0x04)
#define cmlib (ah_lib_dbg & 0x100)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_PM_DBG

extern uint ah_pm_dbg;

#define pm_basic (ah_pm_dbg & 0x01)
#define pm_info (ah_pm_dbg & 0x02)
#define pm_corefile (ah_pm_dbg & 0x04)
#define pm_watchdog (ah_pm_dbg & 0x08)
#define pm_netlink (ah_pm_dbg & 0x10)
#define pm_cpu (ah_pm_dbg & 0x20)
#define pm_change (ah_pm_dbg & 0x40)
#define pm_all (ah_pm_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_LCS_DBG

extern uint ah_lcs_dbg;

#define lcs_error (ah_lcs_dbg & 0x01)
#define lcs_event (ah_lcs_dbg & 0x02)
#define lcs_info (ah_lcs_dbg & 0x04)
#define lcs_packet (ah_lcs_dbg & 0x08)
#define lcs_all (ah_lcs_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_LTR_DBG

extern uint ah_ltr_dbg;

#define ltr_error (ah_ltr_dbg & 0x01)
#define ltr_event (ah_ltr_dbg & 0x02)
#define ltr_info (ah_ltr_dbg & 0x04)
#define ltr_packet (ah_ltr_dbg & 0x08)
#define ltr_all (ah_ltr_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_VPN_DBG

extern uint ah_vpn_dbg;

#define vpn_error (ah_vpn_dbg & 0x01)
#define vpn_info (ah_vpn_dbg & 0x02)
#define vpn_debug (ah_vpn_dbg & 0x04)
#define vpn_packet (ah_vpn_dbg & 0x08)
#define vpn_all (ah_vpn_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_WEBUI_DBG

extern uint ah_webui_dbg;

#define webui_info (ah_webui_dbg & 0x01)
#define webui_basic (ah_webui_dbg & 0x02)
#define webui_packet (ah_webui_dbg & 0x04)
#define webui_usr (ah_webui_dbg & 0x08)
#define webui_retrieve (ah_webui_dbg & 0x10)
#define webui_message (ah_webui_dbg & 0x20)
#define webui_cli (ah_webui_dbg & 0x40)
#define webui_update (ah_webui_dbg & 0x80)
#define webui_radius (ah_webui_dbg & 0x100)
#define webui_tv (ah_webui_dbg & 0x200)
#define webui_tv_alg (ah_webui_dbg & 0x1000)
#define webui_tv_dump (ah_webui_dbg & 0x2000)
#define webui_all (ah_webui_dbg & 0xffffffff)
#define httpsnooplib (ah_lib_dbg & 0x10)
#define httpsnoop_pktlib (ah_lib_dbg & 0x20)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_ASD_DBG

extern uint ah_asd_dbg;

#define asd_basic (ah_asd_dbg & 0x01)
#define asd_info (ah_asd_dbg & 0x02)
#define asd_error (ah_asd_dbg & 0x04)
#define asd_verbose (ah_asd_dbg & 0x08)
#define asd_all (ah_asd_dbg & 0xffffffff)
 
#endif
#ifdef AH_NBR_DBG

extern uint ah_nbr_dbg;

#define nbr_error (ah_nbr_dbg & 0x01)
#define nbr_debug (ah_nbr_dbg & 0x02)
#define nbr_verbose (ah_nbr_dbg & 0x04)
#define nbr_all (ah_nbr_dbg & 0xffffffff)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_DCM_DBG

extern uint ah_dcm_dbg;

#define dcm_basic (ah_dcm_dbg & 0x01)
#define dcm_info (ah_dcm_dbg & 0x02)
#define dcm_memory (ah_dcm_dbg & 0x04)
#define dcm_detail (ah_dcm_dbg & 0x08)
#define dcm_all (ah_dcm_dbg & 0xffffffff)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_BRD_DBG

extern uint ah_brd_dbg;

#define brd_basic (ah_brd_dbg & 0x01)
#define brd_info (ah_brd_dbg & 0x02)
#define brd_verbose (ah_brd_dbg & 0x04)
#define brd_statistics (ah_brd_dbg & 0x08)
#define brd_hotplug (ah_brd_dbg & 0x10)
#define brd_wanmon (ah_brd_dbg & 0x20)
#define brd_ppp (ah_brd_dbg & 0x40)
#define brd_fosm (ah_brd_dbg & 0x80)
#define brd_pppoe (ah_brd_dbg & 0x100)
#define brd_pppdebug (ah_brd_dbg & 0x200)
#define brd_otp (ah_brd_dbg & 0x300)
#define brd_pbr (ah_brd_dbg & 0x400)
#define brd_ethnet (ah_brd_dbg & 0x800)
#define brd_usbnet (ah_brd_dbg & 0x1000)
#define brd_wanif (ah_brd_dbg & 0x2000)
#define brd_nat (ah_brd_dbg & 0x4000)
#define brd_report (ah_brd_dbg & 0x8000)
#define brd_hmdata (ah_brd_dbg & 0x10000)
#define brd_ddns (ah_brd_dbg & 0x20000)
#define brd_all (ah_brd_dbg & 0xffffffff)
 
#endif
#ifdef AH_IPFW_DBG

extern uint ah_ipfw_dbg;

#define ipfw_cli (ah_ipfw_dbg & 0x01)
#define ipfw_error (ah_ipfw_dbg & 0x02)
#define ipfw_info (ah_ipfw_dbg & 0x04)
#define ipfw_debug (ah_ipfw_dbg & 0x08)
#define ipfw_ulogd (ah_ipfw_dbg & 0x10)
#define ipfw_all (ah_ipfw_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
 
#endif
#ifdef AH_BGD_DBG

extern uint ah_bgd_dbg;

#define bgd_basic (ah_bgd_dbg & 0x01)
#define bgd_info (ah_bgd_dbg & 0x02)
#define bgd_detail (ah_bgd_dbg & 0x04)
#define bgd_packet (ah_bgd_dbg & 0x08)
#define bgd_distribution (ah_bgd_dbg & 0x10)
#define bgd_all (ah_bgd_dbg & 0xffffffff)
 
#endif
#ifdef AH_SWD_DBG

extern uint ah_swd_dbg;

#define swd_basic (ah_swd_dbg & 0x01)
#define swd_info (ah_swd_dbg & 0x02)
#define swd_error (ah_swd_dbg & 0x04)
#define swd_verbose (ah_swd_dbg & 0x08)
#define swd_brg (ah_swd_dbg & 0x10)
#define swd_fdb (ah_swd_dbg & 0x20)
#define swd_vlan (ah_swd_dbg & 0x40)
#define swd_event (ah_swd_dbg & 0x80)
#define swd_igmp (ah_swd_dbg & 0x100)
#define swd_qos (ah_swd_dbg & 0x200)
#define swd_span (ah_swd_dbg & 0x400)
#define swd_agg (ah_swd_dbg & 0x800)
#define swd_monitor_report (ah_swd_dbg & 0x1000)
#define swd_client (ah_swd_dbg & 0x2000)
#define swd_led (ah_swd_dbg & 0x4000)
#define swd_ldb (ah_swd_dbg & 0x8000)
#define swd_cavc (ah_swd_dbg & 0x10000)
#define swd_acl (ah_swd_dbg & 0x20000)
#define swd_all (ah_swd_dbg & 0xffffffff)
#define scdlib (ah_lib_dbg & 0x01)
#define dcdlib (ah_lib_dbg & 0x02)
#define alllib (ah_lib_dbg & 0xffffffff)
#define swd_basic (ah_swd_dbg & 0x01)
#define swd_info (ah_swd_dbg & 0x02)
#define swd_detail (ah_swd_dbg & 0x04)
#define swd_all (ah_swd_dbg & 0xffffffff)
 
#endif
#ifdef AH_STPD_DBG

extern uint ah_stpd_dbg;

#define stpd_rx (ah_stpd_dbg & 0x40)
#define stpd_tx (ah_stpd_dbg & 0x20)
#define stpd_proto (ah_stpd_dbg & 0x0c)
#define stpd_timer (ah_stpd_dbg & 0x03)
#define stpd_misc (ah_stpd_dbg & 0x10)
#define stpd_all (ah_stpd_dbg & 0x7f)
 
#endif
#ifdef AH_ACSD_DBG

extern uint ah_acsd_dbg;

#define acsd_error (ah_acsd_dbg & 0x01)
#define acsd_scan (ah_acsd_dbg & 0x02)
#define acsd_info (ah_acsd_dbg & 0x04)
#define acsd_all (ah_acsd_dbg & 0xffffffff)
#define dcdlib (ah_lib_dbg & 0x02)
 
#endif
#ifdef AH_SFLOW_DBG

extern uint ah_sflow_dbg;

#define sflow_basic (ah_sflow_dbg & 0x0001)
#define sflow_detail (ah_sflow_dbg & 0x0002)
#define sflow_verbose (ah_sflow_dbg & 0x0004)
#define sflow_kevent (ah_sflow_dbg & 0x0010)
#define sflow_poller (ah_sflow_dbg & 0x0020)
#define sflow_sender (ah_sflow_dbg & 0x0040)
#define sflow_misc1 (ah_sflow_dbg & 0x0100)
#define sflow_misc2 (ah_sflow_dbg & 0x0200)
#define sflow_misc3 (ah_sflow_dbg & 0x0400)
#define sflow_all (ah_sflow_dbg & 0xffffffff)
 
#endif
#ifdef AH_IBEACON_DBG

extern uint ah_ibeacon_dbg;

#define ibeacon_basic (ah_ibeacon_dbg & 0x0001)
#define ibeacon_detail (ah_ibeacon_dbg & 0x0002)
#define ibeacon_verbose (ah_ibeacon_dbg & 0x0004)
#define ibeacon_all (ah_ibeacon_dbg & 0xffffffff)
 
#endif
#ifdef AH_DHCLIENT_DBG

extern uint ah_dhclient_dbg;

#define dhclient_all (ah_dhclient_dbg & 0xffffffff)
 
#endif
#ifdef AH_VRRP_DBG

extern uint ah_vrrp_dbg;

#define vrrp_basic (ah_vrrp_dbg & 0x01)
#define vrrp_detail (ah_vrrp_dbg & 0x02)
#define vrrp_dump (ah_vrrp_dbg & 0x04)
#define vrrp_all (ah_vrrp_dbg & 0xffffffff)
 
#endif
#endif
