/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	   *
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
#if !OK_PATCH
#include "nmsc/nmsc.h" 
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "services/capwapc_services.h"
#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

/*________________________________________________________________*/
/*  *******************___CAPWAP VARIABLES___*******************  */

/*_________________________________________________________*/
/*  *******************___VARIABLES___*******************  */
int gCWDiscoveryCount;

/*_____________________________________________________*/
/*  *******************___MACRO___*******************  */
#define CWWTPFoundAnAC()	(gACInfoPtr != NULL /*&& gACInfoPtr->preferredAddress.ss_family != AF_UNSPEC*/)

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
CWBool CWReceiveDiscoveryResponse();
void CWWTPEvaluateAC(CWACInfoValues *ACInfoPtr);
CWBool CWReadResponses();
CWBool CWAssembleDiscoveryRequest(CWProtocolMessage **messagesPtr, int seqNum);
CWBool CWParseDiscoveryResponseMessage(char *msg,
				       int len,
				       int *seqNumPtr,
				       CWACInfoValues *ACInfoPtr);

/*_________________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

/* 
 * Manage Discovery State
 */
CWStateTransition CWWTPEnterDiscovery() {
	int i, sleeptime;
	CWBool j;	
	
	// CWLog("######### Discovery State #########");
	
	/* reset Discovery state */
	gCWDiscoveryCount = 0;
	CW_FREE_OBJECT(gACInfoPtr_temp);
	CW_FREE_OBJECT(gACInfoPtr);
	CWNetworkCloseSocket(gWTPSocket);
	if(!CWErr(CWNetworkInitSocketClient(&gWTPSocket, NULL))) {
        CWLog("CWNetworkInitSocketClient failed.");
		return CW_QUIT;
	}

	/* 
	 * note: gCWACList can be freed and reallocated (reading from config file)
	 * at each transition to the discovery state to save memory space
	 */
	for(i = 0; i < gCWACCount; i++) 
		gCWACList[i].received = CW_FALSE;

SLEEP_AGAIN:	
	/* wait a random time */
	if (g_capwapc_config.maxdisc_intv > g_capwapc_config.disc_intv) {
 		sleeptime = CWRandomIntInRange(g_capwapc_config.disc_intv, g_capwapc_config.maxdisc_intv);
	}
	else if (g_capwapc_config.maxdisc_intv < g_capwapc_config.disc_intv) {
		sleeptime = CWRandomIntInRange(g_capwapc_config.maxdisc_intv, g_capwapc_config.disc_intv);
	}
	else {
		sleeptime = g_capwapc_config.disc_intv;
	}
	sleep(sleeptime);

	if (dc_is_handle_doing()) {
		CWDebugLog("The system is processing the json config , wait a random time again!");
		goto SLEEP_AGAIN;
	}

	CW_REPEAT_FOREVER {
		CWBool sentSomething = CW_FALSE;
	
		/* we get no responses for a very long time */
		if(gCWDiscoveryCount == g_capwapc_config.max_disces) {
			if(gACInfoPtr_temp != NULL) {
				gACInfoPtr = gACInfoPtr_temp;
				gACInfoPtr_temp = NULL;
				break;
			} 
			else {
				return CW_ENTER_SULKING;
			}
		}

		/* send Requests to one or more ACs */
		for(i = 0; i < gCWACCount; i++) {

			/* if this AC hasn't responded to us... */
			/* bug2675: if it is the last time in this period we will send too */
			if(!(gCWACList[i].received) || (gCWDiscoveryCount + 1 == g_capwapc_config.max_disces)) {
				/* ...send a Discovery Request */

				CWProtocolMessage *msgPtr = NULL;
				
				/* get sequence number (and increase it) */
				gCWACList[i].seqNum = CWGetSeqNum();
				
				if(!CWErr(CWAssembleDiscoveryRequest(&msgPtr,
								     gCWACList[i].seqNum))) {
					exit(21);
				}
				
                                CW_CREATE_OBJECT_ERR(gACInfoPtr, 
						     CWACInfoValues,
						     return CW_QUIT;);
				
				if (CW_TRUE != CWNetworkGetAddressForHost(gCWACList[i].addrinfo->address, 
							   &(gACInfoPtr->preferredAddress))) {
					CWDebugLog("Can't resolve hostname %s", gCWACList[i].addrinfo->address);
					CWDebugLog_F("Can't resolve hostname %s", gCWACList[i].addrinfo->address);
				}		
				else {
					memcpy(&(gCWACList[i].addrinfo->preferredAddress), &(gACInfoPtr->preferredAddress), 
						sizeof(gCWACList[i].addrinfo->preferredAddress));
					CWUseSockNtop(&(gACInfoPtr->preferredAddress),
						CWDebugLog_F("Send discovery request to the server: %s", str););
				
					j = CWErr(CWNetworkSendUnsafeUnconnected(gWTPSocket,
									 &(gACInfoPtr->preferredAddress),
									 (*msgPtr).msg,
									 (*msgPtr).offset)); 
				}
				
				
				/* 
				 * log eventual error and continue
				 * CWUseSockNtop(&(gACInfoPtr->preferredAddress),
				 * 		 CWLog("WTP sends Discovery Request to: %s", str););
				 */
								
				CW_FREE_PROTOCOL_MESSAGE(*msgPtr);
				CW_FREE_OBJECT(msgPtr);
				CW_FREE_OBJECT(gACInfoPtr);
				
				/*
				 * we sent at least one Request in this loop
				 * (even if we got an error sending it) 
				 */
				sentSomething = CW_TRUE; 
			}
		}
		
		/* All AC sent the response (so we didn't send any request) */
		if(!sentSomething && CWWTPFoundAnAC()) break;
		
		gCWDiscoveryCount++;

		/* wait for Responses */
		if(CWErr(CWReadResponses()) && CWWTPFoundAnAC()) {
			/* we read at least one valid Discovery Response */
			break;
		}
		
		CWDebugLog("WTP Discovery-To-Discovery (%d)", gCWDiscoveryCount);
		CWDebugLog_F("WTP Discovery-To-Discovery (%d)", gCWDiscoveryCount);
	}
	
	CWLog("WTP Picks a server");
	 CWDebugLog_F("WTP Picks a server");
	
	/* crit error: we should have received at least one Discovery Response */
	if(!CWWTPFoundAnAC()) {
		CWDebugLog("No Discovery response Received");
		return CW_ENTER_DISCOVERY;
	}
	
	/* if the AC is multi homed, we select our favorite AC's interface */
	CWWTPPickACInterface();

	if (gACInfoPtr->name != NULL) {		
		CWUseSockNtop(&(gACInfoPtr->preferredAddress),
    			{CWLog("Preferred server: \"%s\", at address: %s", gACInfoPtr->name, str);
			CWDebugLog_F("Preferred server: \"%s\", at address: %s", gACInfoPtr->name, str);});
	}
	else {
		CWUseSockNtop(&(gACInfoPtr->preferredAddress),
			{CWLog("Preferred server address: %s", str); 
			CWDebugLog_F("Preferred server address: %s", str);});
	}
	
	return CW_ENTER_JOIN;
}

/* 
 * Wait DiscoveryInterval time while receiving Discovery Responses.
 */
CWBool CWReadResponses() {

	CWBool result = CW_FALSE;
	
	struct timeval timeout, before, after, delta, newTimeout;
	
	timeout.tv_sec = newTimeout.tv_sec = g_capwapc_config.disc_intv;
	timeout.tv_usec = newTimeout.tv_usec = 0;
	
	gettimeofday(&before, NULL);

	CW_REPEAT_FOREVER {
		/* check if something is available to read until newTimeout */
		if(CWNetworkTimedPollRead(gWTPSocket, &newTimeout)) { 
			/* success
			 * if there was no error, raise a "success error", so we can easily handle
			 * all the cases in the switch
			 */
			CWErrorRaise(CW_ERROR_SUCCESS, NULL);
		}

		switch(CWErrorGetLastErrorCode()) {
			case CW_ERROR_TIME_EXPIRED:
				goto cw_time_over;
				break;
				
			case CW_ERROR_SUCCESS:
				result = CWReceiveDiscoveryResponse();
			case CW_ERROR_INTERRUPTED: 
				/*
				 * something to read OR interrupted by the system
				 * wait for the remaining time (NetworkPoll will be recalled with the remaining time)
				 */
				gettimeofday(&after, NULL);

				CWTimevalSubtract(&delta, &after, &before);
				if(CWTimevalSubtract(&newTimeout, &timeout, &delta) == 1) { 
					/* negative delta: time is over */
					goto cw_time_over;
				}
				break;
			default:
				CWErrorHandleLast();
				goto cw_error;
				break;	
		}
	}
	cw_time_over:
		/* time is over */
		CWDebugLog("Timer expired during receive");	
	cw_error:
		return result;
}

/*
 * Gets a datagram from network that should be a Discovery Response.
 */
CWBool CWReceiveDiscoveryResponse() {
	char buf[CW_BUFFER_SIZE];
	int i;
	CWNetworkLev4Address addr;
	CWACInfoValues *ACInfoPtr;
	int seqNum;
	int readBytes;
	
	/* receive the datagram */
	if(!CWErr(CWNetworkReceiveUnsafe(gWTPSocket,
					 buf,
					 CW_BUFFER_SIZE-1,
					 0,
					 &addr,
					 &readBytes))) {
		return CW_FALSE;
	}
	
        CW_CREATE_OBJECT_ERR(ACInfoPtr,
			     CWACInfoValues,
			     return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    CWLog("WTP Receives Discovery Response");
    CWDebugLog_F("WTP Receives Discovery Response");
    
	/* check if it is a valid Discovery Response */
	if(!CWErr(CWParseDiscoveryResponseMessage(buf, readBytes, &seqNum, ACInfoPtr))) {

		CW_FREE_OBJECT(ACInfoPtr);
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Received something different from a\
				     Discovery Response while in Discovery State");
	}
	
	CW_COPY_NET_ADDR_PTR(&(ACInfoPtr->incomingAddress), &(addr));
	
	/* see if this AC is better than the one we have stored */
	CWWTPEvaluateAC(ACInfoPtr);
	
	

	/* check if the sequence number we got is correct */
	for(i = 0; i < gCWACCount; i++) {

		if(gCWACList[i].seqNum == seqNum) {
		
			CWUseSockNtop(&addr,
				      {CWDebugLog_F("Discovery Response from:%s", str);
                       CWLog("Discovery Response from:%s", str); });
			/* we received response from this address */
			gCWACList[i].received = CW_TRUE;
	
			return CW_TRUE;
		}
	}
	return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
			    "Sequence Number of Response doesn't macth Request");
}

void CWWTPEvaluateAC(CWACInfoValues *ACInfoPtr) 
{
    int i, pri = 0;
    struct sockaddr_in *addr;
    char *server = NULL;
    
    if(ACInfoPtr == NULL) {
        return;
    }
    else {
        addr = (struct sockaddr_in*)&(ACInfoPtr->incomingAddress);
    }

    /* step1: already pick the highest priority server, discard all others */
    if (gACInfoPtr != NULL) {
        CWDebugLog_F("Already picked the highest priority server, discard new comming server %s.", 
            inet_ntoa(addr->sin_addr));
        CW_FREE_OBJECT(ACInfoPtr);
        return;
    }

    /* step2: get the priority of the new comming server */
    for(i = 0; i < gCWACCount; i++) {
        if (((struct sockaddr_in *)&(gCWACList[i].addrinfo->preferredAddress))->sin_addr.s_addr == addr->sin_addr.s_addr) {
            server = gCWACList[i].addrinfo->address;
            break;
        }
    }
    if (server == NULL) {
        /* if can not find the server, it must be the boradcast address, it is the last one */
        server = gCWACList[gCWACCount - 1].addrinfo->address;
    }
    
    if (capwapc_get_server_pri(&g_capwapc_config, server, &pri) != 0) {
        CW_FREE_OBJECT(ACInfoPtr);
        return;
    }

    ACInfoPtr->priority = pri;
    CWDebugLog_F("Response from %s with the priority %d.", inet_ntoa(addr->sin_addr), pri);

    /* step3: check the new comming server's priority */
    if(IS_HIGHEST_RELATIVEPRI(pri)) {
        CWDebugLog_F("server %s is of the highest priority.", inet_ntoa(addr->sin_addr));
        if(gACInfoPtr_temp != NULL) {
            CW_FREE_OBJECT(gACInfoPtr_temp);
        }
        if(gACInfoPtr != NULL) {
            CW_FREE_OBJECT(gACInfoPtr);
        }
        
        gACInfoPtr = ACInfoPtr;
    }
    else {
        if(gACInfoPtr_temp == NULL) { 
            gACInfoPtr_temp = ACInfoPtr;
        }
        else {
            addr = (struct sockaddr_in*)&(gACInfoPtr_temp->incomingAddress);
            /* to update if higher priority, else release directly */
            if (IS_HIGHER_PRI(pri, gACInfoPtr_temp->priority)) {
                CWDebugLog_F("Compare with last time %s with the priority %d, replace it with new server.", 
                    inet_ntoa(addr->sin_addr), gACInfoPtr_temp->priority);
                CW_FREE_OBJECT(gACInfoPtr_temp);
                gACInfoPtr_temp = ACInfoPtr;
            }
            else{
                CWDebugLog_F("Compare with last time %s with the priority %d, keep the old server.", 
                    inet_ntoa(addr->sin_addr), gACInfoPtr_temp->priority);
    		    CW_FREE_OBJECT(ACInfoPtr);
            }
        }
    }
	/* 
	 * ... note: we can add our favourite algorithm to pick the best AC.
	 * We can also consider to remember all the Discovery Responses we 
	 * received and not just the best.
	 */
}

/*
 * Pick one interface of the AC (easy if there is just one interface). The 
 * current algorithm just pick the Ac with less WTP communicating with it. If
 * the addresses returned by the AC in the Discovery Response don't include the
 * address of the sender of the Discovery Response, we ignore the address in 
 * the Response and use the one of the sender (maybe the AC sees garbage 
 * address, i.e. it is behind a NAT).
 */
void CWWTPPickACInterface() {
	int i, min;
	CWBool foundIncoming = CW_FALSE;
	if(gACInfoPtr == NULL) return;
	
	gACInfoPtr->preferredAddress.ss_family = AF_UNSPEC;
	
	if(gNetworkPreferredFamily == CW_IPv6) {
		goto cw_pick_IPv6;
	}
	
cw_pick_IPv4:
	if(gACInfoPtr->IPv4Addresses == NULL || gACInfoPtr->IPv4AddressesCount <= 0) {
        /* 
		 * If there is no any addresses returned by the AC in the Discovery
		 * Response, we use the one of the sender (maybe the AC sees garbage
		 * address, i.e. it is behind a NAT).
		 */
        CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress),
				     &(gACInfoPtr->incomingAddress));
        return;
    }
		
	min = gACInfoPtr->IPv4Addresses[0].WTPCount;

	CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress),
			     &(gACInfoPtr->IPv4Addresses[0].addr));
		
	for(i = 1; i < gACInfoPtr->IPv4AddressesCount; i++) {

		if(!sock_cmp_addr((struct sockaddr*)&(gACInfoPtr->IPv4Addresses[i]),
				  (struct sockaddr*)&(gACInfoPtr->incomingAddress),
				  sizeof(struct sockaddr_in))) foundIncoming = CW_TRUE;

		if(gACInfoPtr->IPv4Addresses[i].WTPCount < min) {

			min = gACInfoPtr->IPv4Addresses[i].WTPCount;
			CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), 
					     &(gACInfoPtr->IPv4Addresses[i].addr));
		}
	}
		
	if(!foundIncoming) {
		/* 
		 * If the addresses returned by the AC in the Discovery
		 * Response don't include the address of the sender of the
		 * Discovery Response, we ignore the address in the Response
		 * and use the one of the sender (maybe the AC sees garbage
		 * address, i.e. it is behind a NAT).
		 */
		CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress),
				     &(gACInfoPtr->incomingAddress));
	}
	return;
		
cw_pick_IPv6:
	/* CWDebugLog("Pick IPv6"); */
	if(gACInfoPtr->IPv6Addresses == NULL ||\
	   gACInfoPtr->IPv6AddressesCount <= 0) goto cw_pick_IPv4;
		
	min = gACInfoPtr->IPv6Addresses[0].WTPCount;
	CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress),
			     &(gACInfoPtr->IPv6Addresses[0].addr));
		
	for(i = 1; i < gACInfoPtr->IPv6AddressesCount; i++) {

		/*
		 * if(!sock_cmp_addr(&(gACInfoPtr->IPv6Addresses[i]),
		 * 		     &(gACInfoPtr->incomingAddress),
		 * 		     sizeof(struct sockaddr_in6))) 
		 *
		 * 	foundIncoming = CW_TRUE;
		 */
			
		if(gACInfoPtr->IPv6Addresses[i].WTPCount < min) {
			min = gACInfoPtr->IPv6Addresses[i].WTPCount;
			CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress),
					     &(gACInfoPtr->IPv6Addresses[i].addr));
		}
	}
	/*
	if(!foundIncoming) {
		CW_COPY_NET_ADDR_PTR(&(gACInfoPtr->preferredAddress), 
				     &(gACInfoPtr->incomingAddress));
	}
	*/
	return;
}

CWBool CWAssembleDiscoveryRequest(CWProtocolMessage **messagesPtr, int seqNum) {

	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 5;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int k = -1;
	int fragmentsNum;

	if(messagesPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););	
	
	/* Assemble Message Elements */
	if((!(CWAssembleMsgElemDiscoveryType(&(msgElems[++k])))) ||
	   (!(CWAssembleMsgElemWTPBoardData(&(msgElems[++k]))))	 ||
	   (!(CWAssembleMsgElemWTPDescriptor(&(msgElems[++k])))) ||
	   (!(CWAssembleMsgElemWTPFrameTunnelMode(&(msgElems[++k])))) ||
	   (!(CWAssembleMsgElemWTPMACType(&(msgElems[++k]))))
	){
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}
	
	return CWAssembleMessage(messagesPtr, 
				 &fragmentsNum,
				 0,
				 seqNum,
				 CW_MSG_TYPE_VALUE_DISCOVERY_REQUEST,
				 msgElems,
				 msgElemCount,
				 msgElemsBinding,
				 msgElemBindingCount,
				 CW_PACKET_PLAIN);
}

/*
 *  Parse Discovery Response and return informations in *ACInfoPtr.
 */
CWBool CWParseDiscoveryResponseMessage(char *msg, 
				       int len,
				       int *seqNumPtr,
				       CWACInfoValues *ACInfoPtr) {

	CWControlHeaderValues controlVal;
	CWProtocolTransportHeaderValues transportVal;
	int offsetTillMessages, i, j;
	
	CWProtocolMessage completeMsg;
	
	if(msg == NULL || seqNumPtr == NULL || ACInfoPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parse Discovery Response");
	CWDebugLog_F("Parse Discovery Response");
    
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	CWBool dataFlag = CW_FALSE;
	/* will be handled by the caller */
	if(!(CWParseTransportHeader(&completeMsg, &transportVal, &dataFlag))) return CW_FALSE; 
	/* will be handled by the caller */
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE;
	
	/* different type */
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_DISCOVERY_RESPONSE) {
        char errinfo[128];

        sprintf(errinfo, "Message(%d) is not Discovery Response as Expected", 
            controlVal.messageTypeValue);
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, errinfo);
    }
	
	*seqNumPtr = controlVal.seqNum;
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	offsetTillMessages = completeMsg.offset;
	
	ACInfoPtr->IPv4AddressesCount = 0;
	ACInfoPtr->IPv6AddressesCount = 0;
	/* parse message elements */
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type=0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len=0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&type,&len);
		CWDebugLog_F("Parsing Message Element: %u, len: %u", type, len);
		
		switch(type) {
			case CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseACDescriptor(&completeMsg, len, ACInfoPtr))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseACName(&completeMsg, len, &(ACInfoPtr->name)))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
				/* 
				 * just count how many interfacess we have, 
				 * so we can allocate the array 
				 */
				ACInfoPtr->IPv4AddressesCount++;
				completeMsg.offset += len;
				break;
			case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
				/* 
				 * just count how many interfacess we have, 
				 * so we can allocate the array 
				 */
				ACInfoPtr->IPv6AddressesCount++;
				completeMsg.offset += len;
				break;
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
					"Unrecognized Message Element");
		}

		/* CWDebugLog("bytes: %d/%d",
		 * 	      (completeMsg.offset-offsetTillMessages),
		 * 	      controlVal.msgElemsLen); 
		 */
	}
	
	if (completeMsg.offset != len) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				    "Garbage at the End of the Message");
	
	/* actually read each interface info */
	CW_CREATE_ARRAY_ERR(ACInfoPtr->IPv4Addresses,
			    ACInfoPtr->IPv4AddressesCount,
			    CWProtocolIPv4NetworkInterface,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	if(ACInfoPtr->IPv6AddressesCount > 0) {

		CW_CREATE_ARRAY_ERR(ACInfoPtr->IPv6Addresses,
				    ACInfoPtr->IPv6AddressesCount,
				    CWProtocolIPv6NetworkInterface,
				    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}

	i = 0, j = 0;
	
	completeMsg.offset = offsetTillMessages;
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {

		unsigned short int type=0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len=0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&type,&len);		
		
		switch(type) {
			case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseCWControlIPv4Addresses(&completeMsg,
								   len,
								   &(ACInfoPtr->IPv4Addresses[i]))))
					return CW_FALSE; 
				i++;
				break;
			case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseCWControlIPv6Addresses(&completeMsg,
								   len,
								   &(ACInfoPtr->IPv6Addresses[j])))) 
					return CW_FALSE;				
				j++;
				break;
			default:
				completeMsg.offset += len;
				break;
		}
	}
	return CW_TRUE;
}

