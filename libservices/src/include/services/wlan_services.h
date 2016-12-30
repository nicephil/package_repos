#ifndef __WLAN_SERVICES_H_
#define __WLAN_SERVICES_H_

#define WIFI_CFG_PACKAGE "wireless"
#define WIFI_CFG_SECTION_DEVICE "wifi-device"
#define WIFI_CFG_OPTION_COUNTRY "country"
extern int if_get_radio_count(int *count);

int wlan_get_country(char *country);
int wlan_set_country(const char *country);
int wlan_undo_country(void);




#endif /*__WLAN_SERVICES_H_ */
