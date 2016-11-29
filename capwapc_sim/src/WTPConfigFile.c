/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	       *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

 
#include "CWWTP.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

//const char *CW_CONFIG_FILE = "config.wtp";
char *CW_CONFIG_FILE = NULL;

CWBool CWConfigFileInitLib(void) 
{
    struct cfg_match {
        int index;
        int type;
        char* code;
        char* encode;
    } cfgarray[] = {
        {WTP_SERVER,      CW_STRING_ARRAY, CAPWAPC_SERVERADDR_CODE, CAPWAPC_SERVERADDR_ENCODE},
        {WTP_CTPORT,      CW_INTEGER,      NULL,                    CAPWAPC_CTRLPORT_ENCODE},
        {WTP_LOCATION,    CW_STRING,       NULL,                    CAPWAPC_LOCATION_ENCODE},
        {WTP_MTU,         CW_INTEGER,      NULL,                    CAPWAPC_MTU_ENCODE},
        {WTP_DISCINTV,    CW_INTEGER,      NULL,                    CAPWAPC_DISINTV_ENCODE}, 
        {WTP_MAXDISCINTV, CW_INTEGER,      NULL,                    CAPWAPC_MAXDISINTV_ENCODE},
        {WTP_ECHOINTV,    CW_INTEGER,      NULL,                    CAPWAPC_ECHOINTV_ENCODE},
        {WTP_RETRANINTV,  CW_INTEGER,      NULL,                    CAPWAPC_RETRANINTV_ENCODE},
        {WTP_SILENTINTV,  CW_INTEGER,      NULL,                    CAPWAPC_SILENTINTV_ENCODE},
        {WTP_JOINTIMEOUT, CW_INTEGER,      NULL,                    CAPWAPC_JOINTIMEOUT_ENCODE},
        {WTP_MAXDISCES,   CW_INTEGER,      NULL,                    CAPWAPC_MAXDISCES_ENCODE},              
        {WTP_MAXRETRANS,  CW_INTEGER,      NULL,                    CAPWAPC_MAXRETRANS_ENCODE},
    };
    int i;
	
	gConfigValuesCount = sizeof(cfgarray)/sizeof(cfgarray[0]);

	CW_CREATE_ARRAY_ERR(gConfigValues, gConfigValuesCount, CWConfigValue, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    for (i = 0; i < gConfigValuesCount; i++) {
        if (cfgarray[i].type == CW_STRING_ARRAY) {
            gConfigValues[i].type = cfgarray[i].type;
            gConfigValues[i].code = cfgarray[i].code;
            gConfigValues[i].endCode = cfgarray[i].encode;
            gConfigValues[i].value.str_array_value = NULL;
            gConfigValues[i].count = 0;
        }
        else if (cfgarray[i].type == CW_STRING) {
            gConfigValues[i].type = cfgarray[i].type;
            gConfigValues[i].code = cfgarray[i].encode;
            gConfigValues[i].value.str_value = NULL;
        }
        else {
            gConfigValues[i].type = cfgarray[i].type;
            gConfigValues[i].code = cfgarray[i].encode;
            gConfigValues[i].value.int_value = 0;
        }
    }
	
	return CW_TRUE;
}

CWBool CWConfigFileDestroyLib(void) 
{
    struct cfg_match {
        int index;
        int* value;
    } int_cfgarray[] = {
        {WTP_CTPORT,      &g_capwapc_config.ctrl_port},
        {WTP_MTU,         &g_capwapc_config.mtu},
        {WTP_DISCINTV,    &g_capwapc_config.disc_intv}, 
        {WTP_MAXDISCINTV, &g_capwapc_config.maxdisc_intv},
        {WTP_ECHOINTV,    &g_capwapc_config.echo_intv},
        {WTP_RETRANINTV,  &g_capwapc_config.retran_intv},
        {WTP_SILENTINTV,  &g_capwapc_config.silent_intv},
        {WTP_JOINTIMEOUT, &g_capwapc_config.join_timeout},
        {WTP_MAXDISCES,   &g_capwapc_config.max_disces},              
        {WTP_MAXRETRANS,  &g_capwapc_config.max_retran},
    };
    
	int  i, acnum = 0;

    /* first check vaild address */
    for(i = 0; i < gConfigValues[WTP_SERVER].count; i++) {
        if (inet_addr((gConfigValues[WTP_SERVER].value.str_array_value)[i])) {
            gCWACCount++;
        }
	}
    if (gCWACCount > 0) {
        /* creae array malloc */
    	CW_CREATE_ARRAY_ERR(gCWACAddresses, gCWACCount, char*, 
            return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

        /* last save the address list */
        for(i = 0; i < gConfigValues[WTP_SERVER].count; i++) {
            if (inet_addr((gConfigValues[WTP_SERVER].value.str_array_value)[i]) && acnum < gCWACCount) {
                CW_CREATE_STRING_FROM_STRING_ERR(gCWACAddresses[acnum], (gConfigValues[WTP_SERVER].value.str_array_value)[i], 
                    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                acnum++;
            }
    	}
    }
	
	#ifdef CW_DEBUGGING
		CW_PRINT_STRING_ARRAY(gCWACAddresses, gCWACCount);
	#endif

    if (gConfigValues[WTP_LOCATION].value.str_value != NULL) {
		strncpy(g_capwapc_config.location, gConfigValues[WTP_LOCATION].value.str_value,
            sizeof(g_capwapc_config.location) - 1);
	}
    else {
        g_capwapc_config.location[0] = 0;
    }
    
    for (i = 0; i < sizeof(int_cfgarray)/sizeof(int_cfgarray[0]); i++) {
        *(int_cfgarray[i].value) = gConfigValues[int_cfgarray[i].index].value.int_value;
    }
	
	for(i = 0; i < gConfigValuesCount; i++) {
		if(gConfigValues[i].type == CW_STRING) {
			CW_FREE_OBJECT(gConfigValues[i].value.str_value);
		} 
        else if(gConfigValues[i].type == CW_STRING_ARRAY) {
			CW_FREE_OBJECTS_ARRAY((gConfigValues[i].value.str_array_value), gConfigValues[i].count);
		}
	}
    
	CW_FREE_OBJECT(gConfigValues);
	
	return CW_TRUE;
}


