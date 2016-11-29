/*********************************************************
AEROHIVE CONFIDENTIAL
Copyright 2006-2016 Aerohive Networks, Inc.
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
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>

#include "ah_types.h"
#include "ah_trap.h"
#include "ah_lib.h"
#include "ah_syscall.h"
#include "ah_dbg_agent.h"
#include "ah_capwap_api.h"

#include "ah_wifi.h"
#include "ah_capwap_idp.h"
#include "ah_dcd_api.h"


/**********************************************************************************
 * Name: ah_capwap_idp_convert                                                    *
 * Function: convert idp ap info to event format needed by hive manager           *
 * Parameters:                                                                    *
 *      item: the pointer to te memory to store the converted result              *
 *      inindex: interface index                                                  *
 *      idp: pointer to idp ap info                                               *
 * Return: void                                                                   *
 **********************************************************************************/
static void ah_capwap_idp_convert(ah_capwap_idp_item_t *item,
								  const int ifindex,
								  const ah_ieee80211_idp_ap_t *idp,
								  int event_type)
{
	memset(item, 0, sizeof(ah_capwap_idp_item_t));
	memcpy(item->remote_id, idp->macaddr, MACADDR_LEN);
	item->if_index = ifindex;
	item->item_len = htons(sizeof(ah_capwap_idp_item_t) - sizeof(ushort));
#ifdef AH_RADIO_BCM
	item->idp_channel = idp->ctrl_chan;
#else
	item->idp_channel = ah_dcd_mhz2ieee(idp->freq);
#endif /* AH_RADIO_BCM */

	if (event_type == AH_IEEE80211_IDP_KEVENT_MITIGATE_STOP_NOTROGUE) {
		item->flag = AH_HM_IDP_MITIGATE_STOP_NOTROGUE;
	} else if (event_type == AH_IEEE80211_IDP_KEVENT_MITIGATE_STOP_QUIET) {
		item->flag = AH_HM_IDP_MITIGATE_STOP_QUIET;
	} else if (event_type == AH_IEEE80211_IDP_KEVENT_MITIGATE_STOP_TIMEOUT) {
		item->flag = AH_HM_IDP_MITIGATE_STOP_TIMEOUT;
	} else if (event_type == AH_IEEE80211_IDP_KEVENT_MITIGATE_STOP_MANUAL) {
		item->flag = AH_HM_IDP_MITIGATE_STOP_MANUAL;
	} else if (event_type == AH_IEEE80211_IDP_KEVENT_MITIGATE_START) {
		item->flag = AH_HM_IDP_MITIGATE_START;
	} else if (event_type == AH_IEEE80211_IDP_KEVENT_REPORT_START) {
		item->flag = AH_HM_IDP_REPORT_START;
	} else if (idp->mitigate_flag && (!(idp->mitigate_flag & AH_IDP_REPORT_START_AUTO))) {
		item->flag = AH_HM_IDP_MITIGATE_UPDATE;
	} else {
		item->flag = AH_HM_IDP_REPORT_STATION;
	}
	ah_dbg_old(capwap_idp, "event_type %d mitigate_flag %d flag %d\n", event_type, idp->mitigate_flag, item->flag);
	item->in_net = idp->connection;

	if (idp->policy & AH_IEEE80211_POLICY_OPEN) {
		item->station_data |= AH_HM_IDP_SDATA_OPEN_POLOCY;
	}
	if (idp->policy & AH_IEEE80211_POLICY_WEP) {
		item->station_data |= AH_HM_IDP_SDATA_WEP_POLOCY;
	}
	if (idp->policy & AH_IEEE80211_POLICY_WMM) {
		item->station_data |= AH_HM_IDP_SDATA_WMM_POLOCY;
	}
	if (idp->policy & AH_IEEE80211_POLICY_SHORT_PREAMBLE) {
		item->station_data |= AH_HM_IDP_SDATA_S_PREAMBLE_POLOCY;
	}
	if (idp->policy & AH_IEEE80211_POLICY_BINTVL_SHORT) {
		item->station_data |= AH_HM_IDP_SDATA_S_BEACON_POLOCY;
	}
	if (idp->mode == AH_IEEE80211_IDP_MODE_IBSS) {
		item->station_data |= AH_HM_IDP_SDATA_AD_HOC_POLOCY;
	}
	item->station_data = htons(item->station_data);

	item->ssid_len = idp->ssid_len;
	memcpy(item->ssid, idp->ssid, idp->ssid_len);

	/* we need set sta_num to 0 */
	item->item_len = htons(sizeof(ah_capwap_idp_item_t) - sizeof(item->ssid) + item->ssid_len - sizeof(ushort));

}

/****************************************************************************
 * Name: ah_capwap_idp_sta_enc_one                                          *
 * Function: encapsule the idp ap and its clients msg                       *
 * Parameters:                                                              *
 *      ifindex: ifindex                                                    *
 *      event_type: idp sta event type                                      *
 *      ap: idp ap info                                                     *
 *      sta_tbl: sta table connect to idp ap                                *
 * output parameters:                                                       *
 *      data: the content need to send                                      *
 *      data_len: the length of the data                                    *
 * Return: 0 for success, -1 for failed.                                    *
 * NOTE: will realloc memory for data                                       *
 ***************************************************************************/
int ah_capwap_idp_sta_enc_one(int ifindex, int event_type,
							  ah_ieee80211_idp_ap_t *ap,
							  void *stas, char **data, int *data_len)
{
	ah_capwap_idpsta_msg_t *event_msg = (ah_capwap_idpsta_msg_t *) *data;
	ah_capwap_idp_item_t *idp_item = NULL;
	ah_capwap_idpsta_item_t *sta_item = NULL;
	ah_ieee80211_idp_sta_tbl_t *sta_tbl = (ah_ieee80211_idp_sta_tbl_t *)stas;
	int  i = 0;
	ushort       number = 0, temp_num;
	char *ptr = NULL;

	if (!event_msg) {
		return -1;
	}

	if (sta_tbl != NULL) {
		number = sta_tbl->num_stas;
	}
	event_msg = realloc(event_msg, sizeof(ah_capwap_idpsta_msg_t) + event_msg->data_len +
						sizeof(ah_capwap_idp_item_t) + number * sizeof(ah_capwap_idpsta_item_t));
	if (!event_msg) {
		ah_err_old("CAPWAP IDP: no memory\n");
		return -1;
	}

	/* fill idp AP info */
	idp_item = (ah_capwap_idp_item_t *)(event_msg->data + event_msg->data_len);
	ah_capwap_idp_convert(idp_item, ifindex, ap, event_type);
	/* delete all rogue clients connect to AP */
	if (sta_tbl == NULL) {
		goto out;
	}

	/* note: ah_capwap_idp_convert() already made it network order */
	/* sta number */
	ptr = ((char *)idp_item) + (ntohs(idp_item->item_len) + sizeof(ushort) - sizeof(ushort));

	temp_num = htons(number);
	memcpy(ptr, &temp_num, sizeof(ushort));

	/* fill idp STA info */
	sta_item = (ah_capwap_idpsta_item_t *)(ptr + sizeof(ushort));
	for (i = 0; i < number; i++) {
		sta_item->item_len = sizeof(ah_capwap_idpsta_item_t) - 1;
		memcpy(&sta_item->macaddr, &sta_tbl->sta_tbl[i].macaddr, MACADDR_LEN);
		if (sta_tbl->sta_tbl[i].flag == AH_IDP_STA_FLAG_DEL) {
			sta_item->flag = sta_tbl->sta_tbl[i].flag;
		} else {
			sta_item->flag = 0;
		}
		sta_item->discover_age = htonl(sta_tbl->sta_tbl[i].discover_age);
		sta_item->update_age = htonl(sta_tbl->sta_tbl[i].update_age);
		sta_item->rssi = sta_tbl->sta_tbl[i].rssi;

		ah_dbg_old(capwap_idp, "push one idp client %m info to HM\n", sta_item->macaddr);
		sta_item++;
	}
	ah_dbg_old(capwap_idp, "push %d idp clients on ap %m to HM\n", number, idp_item->remote_id);
	/* sta number and clients */
	idp_item->item_len = htons(ntohs(idp_item->item_len) + number * sizeof(ah_capwap_idpsta_item_t));

out:
	event_msg->data_len += ntohs(idp_item->item_len) + sizeof(ushort);
	*data = (char *)event_msg;
	if (data_len) {
		*data_len = event_msg->data_len + sizeof(ah_capwap_idpsta_msg_t);
	}
	return 0;
}

/****************************************************************************
 * Name: ah_capwap_idp_get_allsta                                           *
 * Function: get all rogue client info from driver                          *
 * Parameters:                                                              *
 *      type: msg type                                                      *
 *      seq_num: sequence number from HM                                    *
 * output parameters:                                                       *
 *      data: the content need to send                                      *
 *      data_len: the length of the data                                    *
 * Return: 0 for success, -1 for failed.                                    *
 * NOTE: will realloc memory for data                                       *
 ***************************************************************************/
int ah_capwap_idp_get_allsta(ushort type, uint32_t seq_num, char **data, int *data_len)
{
	ah_capwap_idpsta_msg_t *event_msg;
	ah_ieee80211_idp_ap_t *ap;
	ah_ieee80211_idp_ap_tbl_t *ap_tbl = NULL;
	ah_ieee80211_idp_sta_tbl_t *sta_tbl = NULL;
	char *chklist[] = {AH_DCD_RADIO_0, AH_DCD_RADIO_1};
	int ifindex;
	int i, j;
	int rc = 0;

	ap_tbl = (ah_ieee80211_idp_ap_tbl_t *)malloc(sizeof(ah_ieee80211_idp_ap_tbl_t));
	if (ap_tbl == NULL) {
		ah_err_old("CAPWAP IDP: No enough memory!\n");
		rc = -1;
		goto OUT;
	}
	sta_tbl = (ah_ieee80211_idp_sta_tbl_t *)malloc(sizeof(ah_ieee80211_idp_sta_tbl_t));
	if (sta_tbl == NULL) {
		ah_err_old("CAPWAP IDP: No enough memory!\n");
		rc = -1;
		goto OUT;
	}

	for (i = 0; i < sizeof(chklist) / sizeof(chklist[0]); i++) {
		ifindex = if_nametoindex(chklist[i]);
		if (ifindex == 0) {
			continue; /* AP110 no wifi1 radio */
		}

		/* Get IDP AP table from driver */
		if (ah_dcd_get_idp_ap_tbl(ifindex, sizeof(ah_ieee80211_idp_ap_tbl_t), ap_tbl) < 0) {
			ah_err_old("CAPWAP IDP: get IDP ap table of %s failed!\n", chklist[i]);
			rc = -1;
			goto OUT;
		}

		for (j = 0; j < ap_tbl->num_aps; j++) {
			ap = &ap_tbl->ap_tbl[j];

			if (!(ap->ap_type == AH_IEEE80211_ROGUE_AP)) {
				continue;
			}

			/* Get IDP station table from driver */
			if (ah_dcd_get_idp_rogue_sta_tbl(ifindex, ap->macaddr, sizeof(ah_ieee80211_idp_sta_tbl_t), sta_tbl) < 0) {
				ah_err_old("CAPWAP IDP: get IDP sta table of %m failed!\n", ap->macaddr);
				rc = -1;
				goto OUT;
			}

			if (sta_tbl->num_stas == 0 &&
				ap->mitigate_flag == 0) {
				/* HM requests HOS to send which rogue APs are in mitigating */
				continue;
			}

			rc = ah_capwap_idp_sta_enc_one(ifindex, AH_HM_IDP_MITIGATE_UPDATE, ap,
										   (sta_tbl->num_stas == 0) ? NULL : sta_tbl, data, NULL);
			if (rc < 0) {
				ah_err_old("CAPWAP IDP: encapsule AP %m sta table failed!\n", ap->macaddr);
				rc = -1;
				goto OUT;
			}
		}
	}

	event_msg = (ah_capwap_idpsta_msg_t *) *data;
	if (event_msg) {
		event_msg->msg_type = htons(AH_HM_TYPE_IDP_MITIGATE);
		event_msg->cookie = htonl(seq_num);
		*data_len = sizeof(ah_capwap_idpsta_msg_t) + event_msg->data_len;
		event_msg->data_len = htonl(event_msg->data_len);
		if (capwap_idp) {
			ah_hexdump((uchar *)(*data), *data_len);
		}
		ah_dbg_old(capwap_idp, "push all idp client info to HM. Cookie= %d\n", seq_num);
	}

OUT:
	if (ap_tbl) {
		free(ap_tbl);
	}
	if (sta_tbl) {
		free(sta_tbl);
	}
	return rc;
}

/****************************************************************************
 * Name: ah_capwap_idp_sta_send_trap                                        *
 * Function: send idp sta trap                                              *
 * Parameters:                                                              *
 *      ifindex: ifindex                                                    *
 *      event: idp sta event                                                *
 *                                                                          *
 * Return: 0 for success, -1 for failed.                                    *
 ***************************************************************************/
int ah_capwap_idp_sta_send_trap(int ifindex, ah_ieee80211_idp_sta_kevent_t *event)
{
	ah_trap_info_t trap_info;
	ah_trap_data_t *trap = &trap_info.data;
	ah_ieee80211_idp_sta_t *sta;
	ah_ieee80211_idp_sta_tbl_t *sta_tbl = (ah_ieee80211_idp_sta_tbl_t *)&event->num_stas;
	int  i = 0;
	ushort  number = 0;

	if (sta_tbl != NULL) {
		number = sta_tbl->num_stas;
	} else {
		ah_err_old("IDP_trap: wrong idp_sta_event");
		return -1;
	}

	trap->trap_type = AH_IDP_MITIGATE_TRAP_TYPE;
	strcpy(trap->idp_mitigate_trap.name, "idp mitigate");
	trap->idp_mitigate_trap.if_index = ifindex;
	memcpy(trap->idp_mitigate_trap.bssid, event->idp_ap.macaddr, MACADDR_LEN);

	/* fill idp STA info */
	for (i = 0; i < number; i++) {
		sta = &sta_tbl->sta_tbl[i];
		memcpy(trap->idp_mitigate_trap.remote_id, sta->macaddr, MACADDR_LEN);
		trap->idp_mitigate_trap.discover_age = sta->discover_age;
		trap->idp_mitigate_trap.update_age = sta->update_age;
		if (sta->flag == AH_IDP_STA_FLAG_DEL) {
			trap->idp_mitigate_trap.removed = AH_TRAP_IDP_REMOVED_TRUE;
		} else {
			trap->idp_mitigate_trap.removed = AH_TRAP_IDP_REMOVED_FALSE;
		}

		ah_dbg_old(capwap_idp, "A rogue client %m connected to rogue AP %m %s.\n",
				   sta->macaddr, event->idp_ap.macaddr, (sta->flag == AH_IDP_STA_FLAG_DEL) ? "is left" : "is detected");


		ah_trap_send(AH_LOG_WARNING, &trap_info, "A rogue client %m connected to rogue AP %m %s.\n",
					 sta->macaddr, event->idp_ap.macaddr, (sta->flag == AH_IDP_STA_FLAG_DEL) ? "is left" : "is detected");
	}

	return 0;
}

