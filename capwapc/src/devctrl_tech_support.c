#include <stdio.h>
#include <stdlib.h>
#include "CWWTP.h"

#include <sys/types.h> 
#include <sys/stat.h> 

#define TECH_SUPPORT_PATH	"/tmp/tech_support"
#if 0
static int create_device_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/device", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open device file error.\n");
        return -1;
    }

    show_device_info(fd);
    
    close(fd);
    return 0;
}

static int create_version_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/version", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open version file error.\n");
        return -1;
    }

    show_version_info(fd);

    close(fd);
    return 0;
}

static int create_dual_image_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/dual_image", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open dual_image file error.\n");
        return -1;
    }

    show_dual_image_info(fd);

    close(fd);
    return 0;
}

static int create_capwap_file(void){
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/capwap", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open capwap file error.\n");
        return -1;
    }

    show_capwap_info(fd);
    
    close(fd);
    return 0;
}

static int create_dhcp_file(void){
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/dhcp", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open dhcp file error.\n");
        return -1;
    }
    
    show_dhcp_client_info(fd);

    close(fd);
    return 0;
}

static int create_interface_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/interface", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open interface file error.\n");
        return -1;
    }
    
    show_interface_info(fd);

    close(fd);
    return 0;
}

static int create_led_stats_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/led_status", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open led_status file error.\n");
        return -1;
    }

    show_led_status_info(fd);

    close(fd);
    return 0;
}

static int create_mac_address_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/mac_address", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open mac_address file error.\n");
        return -1;
    }

    show_mac_address_info(fd);

    close(fd);
    return 0;
}

static int create_ntp_status_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/ntp_status", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open ntp_status file error.\n");
        return -1;
    }

    ntp_status_info(fd);

    close(fd);
    return 0;
}

static int create_telnet_session_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/telnet_session", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open telent_session file error.\n");
        return -1;
    }

    show_telnet_session_info(fd);

    close(fd);
    return 0;
}

static int create_vlan_all_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/vlan_all", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open vlan_all file error.\n");
        return -1;
    }

    show_vlan_info(fd);
    
    close(fd);
    return 0;
}

static int create_portal_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/portal", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open portal file error.\n");
        return -1;
    }

    dump_portal_scheme_basic(fd, NULL);
    
    close(fd);
    return 0;
}

static int create_running_config_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/running_config", O_RDWR|O_CREAT|O_APPEND);

    if(fd < 0){
        CWDebugLog("Open file running_config error.\n");
        return -1;
    }

    dns_decompile(fd);
    log_decompile(fd);
    system_decompile(fd);
    telnetd_decompile(fd);
    time_decompile(fd);
    usrmanage_decompile(fd);
    vlan_decompile(fd);
    vlan_interface_decompile(fd);
    wlan_isolation_decompile(fd);
    vlan_port_decompile(fd);
    wlan_acl_decompile(fd);
    dns_set_decompile(fd);
    portal_decompile(fd);
    time_range_decompile(fd);
    radius_scheme_decompile(fd);
    wlan_service_template_decompile(fd);
    wrrm_decompile(fd);
    wlan_radio_decompile(fd);
    route_decompile(fd);
    capwapc_decompile(fd);
    wifisensor_decompile(fd);

    close(fd);
    return 0;
}

static int create_debug_file(void){
    
    int fd;
    
    fd = open(TECH_SUPPORT_PATH"/debug", O_RDWR|O_CREAT);

    if(fd < 0){
        CWDebugLog("Open debug file error.\n");
        return -1;
    }

    zdebug_read(-1, 0, fd);
    
    close(fd);
    return 0;
}

void create_tech_support_file() {

    #define TECH_SUPPORT_FILE	"/tmp/tech_support.tar"
    char cmdline[128] = {0};
    unsigned int i;
    struct wmac_init_param stWmacInitParam;
    DOT11_RADIO_CAP_S stCaps[DOT11_RADIO_NUM_MAX];

    DOT11_GetHardwareInfo(&stWmacInitParam, &stCaps[0]);
	int nNumRadios = stWmacInitParam.uRadioNums;

	system("mkdir -p /tmp/tech_support");
    system("chmod -R 777 /tmp/tech_support");

    sprintf(cmdline, "80211stats > %s/80211stats 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "athstats -i wifi0 > %s/athstats_wifi0 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "athstats -i wifi1 > %s/athstats_wifi1 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "cp /proc/meminfo %s 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "cp /proc/slabinfo %s 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "dmesg > %s/dmesg 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "ps > %s/ps 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "iwconfig > %s/iwconfig 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "ifconfig -a > %s/ifconfig 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "ip route show > %s/iproute 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);

    sprintf(cmdline, "cp /etc/config %s -fr", TECH_SUPPORT_PATH);
    system(cmdline);

    sprintf(cmdline, "cp /proc/net/arp %s ", TECH_SUPPORT_PATH);
    system(cmdline);
    //vosSnprintf(cmdline, 128, "iwlist scanning > %s/scanlist  2>&1", TECH_SUPPORT_PATH);
    //vosSystem(cmdline);

    sprintf(cmdline, "logread > %s/syslog 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);

    /* added more info */
    sprintf(cmdline, "cat /proc/commsky/ResetReason > %s/ResetReason 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "cat /proc/commsky/panicinfo > %s/panicinfo 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "top -n 1 > %s/top 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "cat /proc/interrupts > %s/interrupts 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "date > %s/date 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "uptime > %s/uptime 2>&1", TECH_SUPPORT_PATH);
    system(cmdline);
    sprintf(cmdline, "cp /etc/flash_cfg/panic.tar.gz %s 2>null", TECH_SUPPORT_PATH);
    system(cmdline);

    //char fileName[32] = {0};
	for ( i = 0; i < nNumRadios; i++ ) {
#if 0
        for ( j = 0; j < 8; j++ ) {
			vosSnprintf(fileName, 32, "%s/scanlist_ath%d", TECH_SUPPORT_PATH, i * 8 + j);
			vosSnprintf(cmdline, 128, "iwlist ath%d scanning 1>%s 2>/tmp/err", i * 8 + j, fileName );
			vosSystem(cmdline);
			struct stat buffer;
			int status;
			status = stat("/tmp/err", &buffer);
			if ( !status && buffer.st_size == 0 ) {
				break;
			} else {
			    vosSnprintf(cmdline, 128, "rm -rf %s", fileName);
				vosSystem(cmdline);
			}
		}
#endif
		sprintf(cmdline, "iwpriv wifi%d dis_radio > %s/wifi%d_dis_radio 2>&1", i, TECH_SUPPORT_PATH, i);
		system(cmdline);
		sprintf(cmdline, "iwpriv wifi%d dis_chanbusy > %s/wifi%d_dis_chanbusy 2>&1", i, TECH_SUPPORT_PATH, i);
		system(cmdline);
		sprintf(cmdline, "iwpriv wifi%d dis_queue > %s/wifi%d_dis_queue 2>&1", i, TECH_SUPPORT_PATH, i);
		system(cmdline);
	}
    
    for(i = 0; i < cfg_get_spec("wlan_bss"); i++){
        sprintf(cmdline, "wlanconfig ath%d list > %s/wlan_ath%d_client 2>/tmp/err", i, TECH_SUPPORT_PATH, i);
        system(cmdline);
        struct stat buffer;
		int status;
		status = stat("/tmp/err", &buffer);
		if ( !status && buffer.st_size == 0 ) {
		} else {
		    sprintf(cmdline, "rm -rf %s/wlan_ath%d_client", TECH_SUPPORT_PATH, i);
			system(cmdline);
		}
    }

    system("cst_cli -s");

    #if 0
	create_device_file();
	create_version_file();
	create_dual_image_file();

    create_capwap_file();
    create_dhcp_file();
    create_interface_file();
    create_led_stats_file();
    create_mac_address_file();
    create_ntp_status_file();
    create_telnet_session_file();
    create_vlan_all_file();
    create_portal_file();
    create_running_config_file();
    
    create_debug_file();
    #endif
	/* added more info, end */

    sprintf(cmdline, "cd /tmp && tar -cf %s tech_support >/dev/null 2>&1", TECH_SUPPORT_FILE);
    system(cmdline);
    sprintf(cmdline, "rm -rf %s", TECH_SUPPORT_PATH);
    system(cmdline);

}
#endif
void create_tech_support_file() {
#if !OK_PATCH

    #define TECH_SUPPORT_FILE	"/tmp/tech_support.tar"
    char cmdline[128] = {0};

	system("mkdir -p /tmp/tech_support");
    system("chmod -R 777 /tmp/tech_support");

    create_tech_support_file_wlan(TECH_SUPPORT_PATH);
    create_tech_support_file_cfg(TECH_SUPPORT_PATH);

    sprintf(cmdline, "cd /tmp && tar -cf %s tech_support >/dev/null 2>&1", TECH_SUPPORT_FILE);
    system(cmdline);
    sprintf(cmdline, "rm -rf %s", TECH_SUPPORT_PATH);
    system(cmdline);
#endif

}

