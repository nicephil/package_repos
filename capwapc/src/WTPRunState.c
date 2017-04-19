/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica	*
 *                          Universita' Campus BioMedico - Italy								*
 *																								*
 * This program is free software; you can redistribute it and/or modify it under the terms		*
 * of the GNU General Public License as published by the Free Software Foundation; either		*
 * version 2 of the License, or (at your option) any later version.								*
 *																								*
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY				*
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A				*
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.						*
 *																								*
 * You should have received a copy of the GNU General Public License along with this			*
 * program; if not, write to the:																*
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,							*
 * MA  02111-1307, USA.																			*
 *																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap																				*
 *																								*
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)												*  
 *           Del Moro Andrea (andrea_delmoro@libero.it)											*
 *           Giovannini Federica (giovannini.federica@gmail.com)								*
 *           Massimo Vellucci (m.vellucci@unicampus.it)											*
 *           Mauro Bisson (mauro.bis@gmail.com)													*
 *	         Antonio Davoli (antonio.davoli@gmail.com)											*
 ************************************************************************************************/

#include "CWWTP.h"
#include "CWVendorPayloads.h"
#include "devctrl_protocol.h"
#include "devctrl_notice.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

#define ECHO_RATELIMIT_TIMES	30

static int g_echo_asmcount = 0;
static int g_echo_reqcount = 0;
static int g_echo_rspcount = 0;

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage *msgPtr);

CWBool CWWTPCheckForBindingFrame();

CWBool CWWTPCheckForWTPEventRequest();
CWBool CWParseWTPEventResponseMessage(char *msg,
				      int len,
				      int seqNum,
				      void *values);

CWBool CWSaveWTPEventResponseMessage(void *WTPEventResp);

CWBool CWAssembleEchoRequest(CWProtocolMessage **messagesPtr,
			     int *fragmentsNumPtr,
			     int PMTU,
			     int seqNum,
			     CWList msgElemList);

CWBool CWParseConfigurationUpdateRequest (char *msg,
										  int len,
										  CWProtocolConfigurationUpdateRequestValues *valuesPtr, 
										  int *updateRequestType);

CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues *valuesPtr,
										CWProtocolResultCode* resultCode,
										int *updateRequestType);

CWBool CWAssembleConfigurationUpdateResponse(CWProtocolMessage **messagesPtr,
					     int *fragmentsNumPtr,
					     int PMTU,
					     int seqNum,
					     CWProtocolResultCode resultCode,
						 CWProtocolConfigurationUpdateRequestValues values);

CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode* resultCode);

CWBool CWAssembleClearConfigurationResponse(CWProtocolMessage **messagesPtr,
					    int *fragmentsNumPtr,
					    int PMTU,
					    int seqNum,
					    CWProtocolResultCode resultCode);

CWBool CWAssembleStationConfigurationResponse(CWProtocolMessage **messagesPtr,
					      int *fragmentsNumPtr,
					      int PMTU,
					      int seqNum,
					      CWProtocolResultCode resultCode);

CWBool CWParseStationConfigurationRequest (char *msg, int len);

void CWConfirmRunStateToACWithEchoRequest();

CWTimerID gCWHeartBeatTimerID;
CWTimerID gCWNeighborDeadTimerID;
CWBool gNeighborDeadTimerSet=CW_FALSE;
	
/* 
 * Manage DTLS packets.
 */
CW_THREAD_RETURN_TYPE CWWTPReceiveDtlsPacket(void *arg) {

	int 			readBytes;
	char 			buf[CW_BUFFER_SIZE];
	CWSocket 		sockDTLS = (CWSocket)arg;
	CWNetworkLev4Address	addr;
	char* 			pData;

    CWDebugLog("Receiving packet task pid %d.", getpid());
    
	CW_REPEAT_FOREVER 
	{
		if(!CWErr(CWNetworkReceiveUnsafe(sockDTLS,
						 buf, 
						 CW_BUFFER_SIZE - 1,
						 0,
						 &addr,
						 &readBytes))) {

			if (CWErrorGetLastErrorCode() == CW_ERROR_INTERRUPTED)
				continue;
			
			break;
		}
		
		/* Clone data packet */
		CW_CREATE_OBJECT_SIZE_ERR(pData, readBytes, { CWDebugLog("Out Of Memory"); return NULL; });
		memcpy(pData, buf, readBytes);

        CWDebugLog_D("Received packet len: %d.", readBytes);
        
		CWLockSafeList(gPacketReceiveList);
		CWAddElementToSafeListTail(gPacketReceiveList, pData, readBytes);
		CWUnlockSafeList(gPacketReceiveList);		
	}

	return NULL;
}

/* 
 * Manage Run State.
 */
CWStateTransition CWWTPEnterRun() {

	int k;
    static CWThread devctrl_thread = -1;

	// CWLog("######### WTP enters in RUN State #########");

    g_echo_asmcount = 0;
    g_echo_reqcount = 0;
    g_echo_rspcount = 0;

    lock_pendingbox();
	for (k = 0; k < MAX_PENDING_REQUEST_MSGS; k++) {
        /* : else maybe delete the timer which id is 0 during CWResetPendingMsgBox */
        gPendingRequestMsgs[k].timer = -1;
		CWResetPendingMsgBox(gPendingRequestMsgs + k);
    }
    unlock_pendingbox();

    if (!CWErr(CWStartHeartbeatTimer()) || dc_start_sta_notice_timer() != 0) {
        CWLog("Start heartbeat timer or notice timer failed, will enter RESET State.");
        return CW_ENTER_RESET;
    }
    CWLog("Start heartbeat timer and wclient notice timer success.");

    if (devctrl_thread == -1) {
        if(!CWErr(CWCreateThread(&devctrl_thread, task_handlereq, NULL))) {
            CWLog("Create NMS task failed.");
            CWDebugLog_E("Create Task thread failed");
            return CW_ENTER_RESET;
        }
        CWLog("Create NMS task success.");
    }
    
	CW_REPEAT_FOREVER
	{
		struct timespec timenow;
		CWBool bReceivePacket = CW_FALSE;
		CWBool bReveiveBinding = CW_FALSE;
	
		/* Wait packet */
		timenow.tv_sec = time(0) + CW_NEIGHBORDEAD_RESTART_DISCOVERY_DELTA_DEFAULT;	 /* greater than NeighborDeadInterval */
		timenow.tv_nsec = 0;

		CWThreadMutexLock(&gInterfaceMutex);

		/*
		 * if there are no frames from stations
		 * and no packets from AC...
		 */
		if ((CWGetCountElementFromSafeList(gPacketReceiveList) == 0) && (CWGetCountElementFromSafeList(gFrameList) == 0)) {
			/*
			 * ...wait at most 4 mins for a frame or packet.
			 */
			if (!CWErr(CWWaitThreadConditionTimeout(&gInterfaceWait, &gInterfaceMutex, &timenow))) {

				CWThreadMutexUnlock(&gInterfaceMutex);
			
				if (CWErrorGetLastErrorCode() == CW_ERROR_TIME_EXPIRED)	{

					CWLog("No Message from NMS for a long time... restart Discovery State");
                    CWDebugLog_E("No Message from NMS for a long time... restart Discovery State");
					break;
				}
                CWDebugLog("Waiting on thread condition for receiving packet failed.");
				continue;
			}
		}

		bReceivePacket = ((CWGetCountElementFromSafeList(gPacketReceiveList) != 0) ? CW_TRUE : CW_FALSE);
		bReveiveBinding = ((CWGetCountElementFromSafeList(gFrameList) != 0) ? CW_TRUE : CW_FALSE);

		CWThreadMutexUnlock(&gInterfaceMutex);

        CWDebugLog_D("Received packet: %s, received binding information: %s.", 
            (bReceivePacket == CW_TRUE) ? "yes" : "no", 
            (bReveiveBinding == CW_TRUE) ? "yes" : "no");
        
		if (bReceivePacket) {

			CWProtocolMessage msg;

			msg.msg = NULL;
			msg.offset = 0;

			if (!(CWReceiveMessage(&msg))) {

				CW_FREE_PROTOCOL_MESSAGE(msg);
				CWLog("Failure Receiving Response, will enter RESET State");
                CWDebugLog_F("Failure Receiving Response");
				return CW_ENTER_RESET;
			}
			if (!CWErr(CWWTPManageGenericRunMessage(&msg))) {

				if(CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) {

					/* Log and ignore message */
					CWErrorHandleLast();
					CWLog("--> Received something different from a valid Run Message");
				} 
				else {
					CW_FREE_PROTOCOL_MESSAGE(msg);
					CWLog("--> Critical Error Managing Generic Run Message... will enter RESET State");
					return CW_ENTER_RESET;
				}
			}
		}
		if (bReveiveBinding)
			CWWTPCheckForBindingFrame();
	}

    CWLog("Quit from Run state and will enter RESET State.");
    
	return CW_ENTER_RESET;
}

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage *msgPtr) {

	CWControlHeaderValues controlVal;
	
	if(msgPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	msgPtr->offset = 0;
	
	/* will be handled by the caller */
	if(!(CWParseControlHeader(msgPtr, &controlVal))) 
		return CW_FALSE;	

    if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_ECHO_RESPONSE
        && controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE) {
        CWLog("Recevied a message(%d) from NMS with seq %d and len %d.", 
            controlVal.messageTypeValue, controlVal.seqNum, controlVal.msgElemsLen);
    }

	int len = controlVal.msgElemsLen - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	int pendingMsgIndex = 0;
    lock_pendingbox();
	pendingMsgIndex = CWFindPendingRequestMsgsBox(gPendingRequestMsgs,
						      MAX_PENDING_REQUEST_MSGS,
						      controlVal.messageTypeValue,
						      controlVal.seqNum);
    if (pendingMsgIndex >= 0) {
        CWResetPendingMsgBox(&(gPendingRequestMsgs[pendingMsgIndex]));
    }
    unlock_pendingbox();

	/* we have received a new Request or an Echo Response */
	if (pendingMsgIndex < 0) {

		CWProtocolMessage *messages = NULL;
		int fragmentsNum=0;
		CWBool toSend=CW_FALSE;
	
		switch(controlVal.messageTypeValue) {

			case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:
			{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;				
				CWProtocolConfigurationUpdateRequestValues values;
				int updateRequestType;

				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetTimers()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}

				CWDebugLog("Configuration Update Request received");
                CWDebugLog_F("Configuration Update Request received");
				
				/************************************************************************************************
				 * Update 2009:																					*
				 *				These two function need an additional parameter (Pointer to updateRequestType)	*
				 *				for distinguish between all types of message elements.							*
				 ************************************************************************************************/

				if(!CWParseConfigurationUpdateRequest((msgPtr->msg)+(msgPtr->offset), len, &values, &updateRequestType))
					return CW_FALSE;

				if(!CWSaveConfigurationUpdateRequest(&values, &resultCode, &updateRequestType))
					return CW_FALSE;

				/*
				if ( updateRequestType == BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL )
					break; 
				*/
				
				/*Update 2009:
				 Added values (to return stuff with a conf update response)*/
				if(!CWAssembleConfigurationUpdateResponse(&messages,
														  &fragmentsNum,
														  gWTPPathMTU,
														  controlVal.seqNum,
														  resultCode,
														  values)) 
					return CW_FALSE;
				
				toSend=CW_TRUE;				

				 /*
                                 * BUG-ML01- memory leak fix
                                 *
                                 * 16/10/2009 - Donato Capitella
                                 */
                                CWProtocolVendorSpecificValues* psValues = values.protocolValues;
                                if (psValues->vendorPayloadType == CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI)
					CW_FREE_OBJECT(((CWVendorUciValues *)psValues->payload)->response);
                                CW_FREE_OBJECT(psValues->payload);
                                CW_FREE_OBJECT(values.protocolValues);
                                break;

				
				break;
			}

			case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:
			{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetTimers()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				CWDebugLog("Clear Configuration Request received");
                CWDebugLog_F("Clear Configuration Request received");
				/*WTP RESET ITS CONFIGURAION TO MANUFACTURING DEFAULT}*/
				if(!CWSaveClearConfigurationRequest(&resultCode))
					return CW_FALSE;
				if(!CWAssembleClearConfigurationResponse(&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode)) 
					return CW_FALSE;

				toSend=CW_TRUE;
				break;
			}

			case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:
			{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;
				//CWProtocolStationConfigurationRequestValues values;  --> da implementare
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetTimers()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				CWDebugLog("Station Configuration Request received");
                CWDebugLog_F("Station Configuration Request received");
				
				if(!CWParseStationConfigurationRequest((msgPtr->msg)+(msgPtr->offset), len)) 
					return CW_FALSE;
				if(!CWAssembleStationConfigurationResponse(&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode)) 
					return CW_FALSE;

				toSend=CW_TRUE;
				break;
			}

			case CW_MSG_TYPE_VALUE_ECHO_RESPONSE:
			{
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetTimers()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				
//				CWLog("Echo Response received");
				if (g_echo_rspcount++ % ECHO_RATELIMIT_TIMES == 0) {
					if (g_echo_rspcount == 1) {
//						CWLog("Echo Response received");
                        CWDebugLog_F("Echo Response received");
                    }
					else {
//						CWLog("Echo Response received (compressed %d times)", ECHO_RATELIMIT_TIMES);
                        CWDebugLog_F("Echo Response received (compressed %d times)", ECHO_RATELIMIT_TIMES);
                    }
				}
				break;
			}

#if OK_PATCH
            /* reset from nms */
            case CW_MSG_TYPE_VALUE_RESET_REQUEST:
            {
				CWFreeMessageFragments(messages, fragmentsNum);
				CW_FREE_OBJECT(messages);
				CWDebugLog("Reset Request received");
                return CW_FALSE;
                break;
            }
#endif

            /* Custom MSG from nms */
            case CW_MSG_TYPE_VALUE_DEVICE_CONTROL_REQUEST:
            {
                CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;	

				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetTimers()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}

                if(!assemble_devctrlresp_msg(&messages, &fragmentsNum, 
                    gWTPPathMTU, controlVal.seqNum, resultCode))  {
                    CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE; 
                }
                toSend = CW_TRUE;
                
                if(CWErrorGetLastErrorCode() == CW_ERROR_DEVCONTROL_REQ_FRAGMENT) { 
                    /* Only need to send response, handle nothing, just reset the fragmented flag */
            		CWErrorRaise(CW_ERROR_SUCCESS, NULL);
                }
                else {
                    /* Received a complete device control request  */
                    devctrl_block_s *devctrl_req;

                    CW_CREATE_OBJECT_ERR(devctrl_req, devctrl_block_s, 
                        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                    
                    /* First: parse the reqest */
                    if(!parse_devctrlreq_msg(msgPtr, devctrl_req)) {
                        CWLog("Parse device control message failed.");
                        CW_FREE_OBJECT(devctrl_req);
                        CWFreeMessageFragments(messages, fragmentsNum);
    					CW_FREE_OBJECT(messages);
    					return CW_FALSE;
                    }

                    /* Then add into the task list */
                    CWLockSafeList(g_devctrlreq_list);
            		CWAddElementToSafeListTail(g_devctrlreq_list, devctrl_req, sizeof(devctrl_req));
            		CWUnlockSafeList(g_devctrlreq_list);	
                }
                break;
            }

			default:
				/* 
				 * We can't recognize the received Request so
				 * we have to send a corresponding response
				 * containing a failure result code
				 */
				CWLog("--> Not valid Request (%d) in Run State", controlVal.messageTypeValue);
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetTimers()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
                if ((controlVal.messageTypeValue%2) != 0) { /* only send response for receiving a request */
                    CWLog("--> we send a failure Response");
    				if(!(CWAssembleUnrecognizedMessageResponse(&messages,
    									   &fragmentsNum,
    									   gWTPPathMTU,
    									   controlVal.seqNum,
    									   controlVal.messageTypeValue+1))) 
    					return CW_FALSE;

    				toSend = CW_TRUE;
                }
				/* return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				 * 		       "Received Message not valid in Run State");
				 */
		}
		if(toSend) {

			int i;
			for(i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
				if(!CWNetworkSendUnsafeConnected(gWTPSocket,
								 messages[i].msg,
								 messages[i].offset)) 
#else
				if(!CWSecuritySend(gWTPSession,
						   messages[i].msg,
						   messages[i].offset))
#endif
				{
					CWDebugLog_E("Error sending message");
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
			}

			CWFreeMessageFragments(messages, fragmentsNum);
			CW_FREE_OBJECT(messages);

			/*
			 * Check if we have to exit due to an update commit request.
			 */
			if (WTPExitOnUpdateCommit) {
                CWLog("WTP exit on update commit.");
                exit(99);
			}
		}	
	} 
	else {/* we have received a Response */

		/*Update 2009:
		  		check to see if a time-out on session occur...
		 		 In case it happens it should go back to CW_ENTER_RESET*/
		if (!CWResetTimers())
			return CW_FALSE;

		switch(controlVal.messageTypeValue) 
		{
			case CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_RESPONSE:
				CWDebugLog("Change State Event Response received");
                CWDebugLog_F("Change State Event Response received");
				break;
		
			case CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE:
				CWDebugLog("WTP Event Response received");
                CWDebugLog_F("WTP Event Response received");
				break;
	
			case CW_MSG_TYPE_VALUE_DATA_TRANSFER_RESPONSE:
				CWDebugLog("Data Transfer Response received");
                CWDebugLog_F("Data Transfer Response received");
				break;

			default:
				/* 
				 * We can't recognize the received Response: we
				 * ignore the message and log the event.
				 */
				CWLog("can't recognize the received Response :%d", controlVal.messageTypeValue);
                CWDebugLog_E("can't recognize the received Response :%d", controlVal.messageTypeValue);
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
						    "Received Message not valid in Run State");
		}
//		CWResetPendingMsgBox(&(gPendingRequestMsgs[pendingMsgIndex]));
	}
	CW_FREE_PROTOCOL_MESSAGE(*msgPtr);
	return CW_TRUE;
}


/*______________________________________________________________*/
/*  *******************___TIMER HANDLERS___*******************  */
void CWWTPHeartBeatTimerExpiredHandler(void *arg) {

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;

    dc_dev_update_notice();

	if(!gNeighborDeadTimerSet) {

		if (!CWStartNeighborDeadTimer()) {
			CWStopHeartbeatTimer();
			CWStopNeighborDeadTimer();
			return;
		}
	}

	if (g_echo_reqcount++ % ECHO_RATELIMIT_TIMES == 0) {
		if (g_echo_reqcount == 1) {
//			CWLog("WTP HeartBeat Timer Expired... send an ECHO Request");
            CWDebugLog_F("WTP HeartBeat Timer Expired... send an ECHO Request");
		}
		else {
//			CWLog("WTP HeartBeat Timer Expired... send an ECHO Request (compressed %d times)", ECHO_RATELIMIT_TIMES);
            CWDebugLog_F("WTP HeartBeat Timer Expired... send an ECHO Request (compressed %d times)", ECHO_RATELIMIT_TIMES);
		}
		
		// CWDebugLog("#________ Echo Request Message (Run) ________#");
	}
	
	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if(!CWAssembleEchoRequest(&messages,
				  &fragmentsNum,
				  gWTPPathMTU,
				  seqNum,
				  msgElemList)){
		int i;

		CWDebugLog_E("Failure Assembling Echo Request");
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		return;
	}
	
	int i;
	for(i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
#else
		if(!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)){
#endif
			CWDebugLog_E("Failure sending Request");
			int k;
			for(k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}	
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);

	if(!CWStartHeartbeatTimer()) {
		return;
	}
}

void CWWTPNeighborDeadTimerExpired(void *arg) {

	CWDebugLog("WTP NeighborDead Timer Expired... we consider Peer Dead.");

#ifdef DMALLOC
	dmalloc_shutdown(); 
#endif

	return;
}


CWBool CWStartHeartbeatTimer() {
	
	gCWHeartBeatTimerID = timer_add(g_capwapc_config.echo_intv,
					0,
					&CWWTPHeartBeatTimerExpiredHandler,
					NULL);
	
	if (gCWHeartBeatTimerID == -1)	return CW_FALSE;

//	CWDebugLog("Heartbeat Timer Started");
	return CW_TRUE;
}


CWBool CWStopHeartbeatTimer()
{
    int ret = 0, i, times = 1;

    for (i = 0; i < 4; ++i) {
        ret = timer_rem(gCWHeartBeatTimerID, NULL);
        if (ret != 0) {
            times = (1 << i);
            CWDebugLog("Stop heartbeat timer %d failed, will try to stop again after %d seconds.", 
                gCWHeartBeatTimerID, times);
            sleep(times);
        }
        else {
            if (i > 0) {
                CWDebugLog("Stop heartbeat timer %d success now.", gCWHeartBeatTimerID);
            }
            break;
        }
    }
    
	
	CWDebugLog_D("Heartbeat Timer Stopped");
	return CW_TRUE;
}


CWBool CWStartNeighborDeadTimer() {

	gCWNeighborDeadTimerID = timer_add(gCWNeighborDeadInterval,
					   0,
					   &CWWTPNeighborDeadTimerExpired,
					   NULL);
	
	if (gCWNeighborDeadTimerID == -1)	return CW_FALSE;

	CWDebugLog_D("NeighborDead Timer Started");
	gNeighborDeadTimerSet = CW_TRUE;
	return CW_TRUE;
}


CWBool CWStopNeighborDeadTimer() {
	
	timer_rem(gCWNeighborDeadTimerID, NULL);
	CWDebugLog_D("NeighborDead Timer Stopped");
	gNeighborDeadTimerSet = CW_FALSE;
	return CW_TRUE;
}


CWBool CWResetTimers() {

	if(gNeighborDeadTimerSet) {
	
		if (!CWStopNeighborDeadTimer()) return CW_FALSE;
	}
	
	if(!CWStopHeartbeatTimer()) 
		return CW_FALSE;
	
	if(!CWStartHeartbeatTimer()) 
		return CW_FALSE;
	
	return CW_TRUE;
}

/*__________________________________________________________________*/
/*  *******************___ASSEMBLE FUNCTIONS___*******************  */
CWBool CWAssembleEchoRequest (CWProtocolMessage **messagesPtr,
			      int *fragmentsNumPtr,
			      int PMTU,
			      int seqNum,
			      CWList msgElemList) {

	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

//		CWLog("Assembling Echo Request...");
		
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_ECHO_REQUEST,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLSCWParseConfigurationUpdateRequest
			       CW_PACKET_PLAIN
#else			       
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;

	if (g_echo_asmcount++ % ECHO_RATELIMIT_TIMES == 0) {
		if (g_echo_asmcount == 1) {
			CWDebugLog("Echo Request Assembled");
            CWDebugLog_F("Echo Request Assembled");
        }
		else {
			CWDebugLog("Echo Request Assembled (compressed %d times)", ECHO_RATELIMIT_TIMES);
            CWDebugLog_F("Echo Request Assembled (compressed %d times)", ECHO_RATELIMIT_TIMES);
        }
	}
	
	return CW_TRUE;
}

CWBool CWAssembleWTPDataTransferRequest(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage *msgElems= NULL;
	int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int i;
	CWListElement *current;
	int k = -1;

	if(messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	msgElemCount = CWCountElementInList(msgElemList);

	if (msgElemCount > 0) {
		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	} 
	else msgElems = NULL;
		
	CWDebugLog("Assembling WTP Data Transfer Request...");
    CWDebugLog_F("Assembling WTP Data Transfer Request...");

	current=msgElemList;
	for (i=0; i<msgElemCount; i++)
	{
		switch (((CWMsgElemData *) current->data)->type)
		{
			case CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE:
				if (!(CWAssembleMsgElemDataTransferData(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;	
				break;
			/*case CW_MSG_ELEMENT_DATA_TRANSFER_MODE_CW_TYPE:
				if (!(CWAssembleMsgElemDataTansferMode(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;*/
		
			default:
				goto cw_assemble_error;
				break;	
		}

		current = current->next;	
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_DATA_TRANSFER_REQUEST,
				msgElems,
				msgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN
#else
				CW_PACKET_CRYPT
#endif
				)))
	 	return CW_FALSE;

	CWDebugLog("WTP Data Transfer Request Assembled");
	CWDebugLog_F("WTP Data Transfer Request Assembled");
    
	return CW_TRUE;

cw_assemble_error:
	{
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE; // error will be handled by the caller
	}
}

CWBool CWAssembleWTPEventRequest(CWProtocolMessage **messagesPtr,
				 int *fragmentsNumPtr,
				 int PMTU,
				 int seqNum,
				 CWList msgElemList) {

	CWProtocolMessage *msgElems= NULL;
	int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int i;
	CWListElement *current;
	int k = -1;

	if(messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	msgElemCount = CWCountElementInList(msgElemList);

	if (msgElemCount > 0) {

		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, 
						 msgElemCount,
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	} 
	else 
		msgElems = NULL;
		
	CWDebugLog("Assembling WTP Event Request...");
    CWDebugLog_F("Assembling WTP Event Request...");
    
	current=msgElemList;
	for (i=0; i<msgElemCount; i++) {

		switch (((CWMsgElemData *) current->data)->type) {

			case CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE:
				if (!(CWAssembleMsgElemDecryptErrorReport(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;	
				break;
			case CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE:
				if (!(CWAssembleMsgElemDuplicateIPv4Address(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE:
				if (!(CWAssembleMsgElemDuplicateIPv6Address(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE:
				if (!(CWAssembleMsgElemWTPOperationalStatistics(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE:
				if (!(CWAssembleMsgElemWTPRadioStatistics(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
				if (!(CWAssembleMsgElemWTPRebootStatistics(&(msgElems[++k]))))
					goto cw_assemble_error;	
				break;
                
            case CW_MSG_ELEMENT_WTP_DEVICE_CONTROLRESULT_CW_TYPE:
                if (!(assemble_devctrlresp_elem(&(msgElems[++k]), 
                    (devctrl_block_s *)(((CWMsgElemData *)current->data)->value))))
					goto cw_assemble_error;	
				break;
              
			default:
				goto cw_assemble_error;
				break;	
		}
		current = current->next;	
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_WTP_EVENT_REQUEST,
				msgElems,
				msgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN
#else
				CW_PACKET_CRYPT
#endif
				)))
	 	return CW_FALSE;

	CWDebugLog("WTP Event Request Assembled");
    CWDebugLog_F("WTP Event Request Assembled");
	
	return CW_TRUE;

cw_assemble_error:
	{
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE; // error will be handled by the caller
	}
}

/*Update 2009:
	Added values to args... values is used to determine if we have some 
	payload (in this case only vendor and only UCI) to send back with the
	configuration update response*/
CWBool CWAssembleConfigurationUpdateResponse(CWProtocolMessage **messagesPtr,
					     int *fragmentsNumPtr,
					     int PMTU,
					     int seqNum,
					     CWProtocolResultCode resultCode,
						 CWProtocolConfigurationUpdateRequestValues values) {

	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	CWProtocolVendorSpecificValues *protoValues = NULL;

	/*Get protocol data if we have it*/
	if (values.protocolValues) 
		protoValues = (CWProtocolVendorSpecificValues *) values.protocolValues;

	if(messagesPtr == NULL || fragmentsNumPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Assembling Configuration Update Response...");
    CWDebugLog_F("Assembling Configuration Update Response...");
	
	CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	if (protoValues)  {
		switch (protoValues->vendorPayloadType) {
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
					if (!(CWAssembleVendorMsgElemResultCodeWithPayload(msgElems,resultCode, protoValues))) {
						CW_FREE_OBJECT(msgElems);
						return CW_FALSE;
					}

			break;

			default:
				/*Result Code only*/
				if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
					CW_FREE_OBJECT(msgElems);
					return CW_FALSE;
				}
		}
	} else  {
		/*Result Code only*/
		if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
			CW_FREE_OBJECT(msgElems);
			return CW_FALSE;
		}
	}
		
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
	
	CWDebugLog("Configuration Update Response Assembled");
	CWDebugLog_F("Configuration Update Response Assembled");
    
	return CW_TRUE;
}

CWBool CWAssembleClearConfigurationResponse(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum, CWProtocolResultCode resultCode) 
{
	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Assembling Clear Configuration Response...");
    CWDebugLog_F("Assembling Clear Configuration Response...");
	
	CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_RESPONSE,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
	
	CWDebugLog("Clear Configuration Response Assembled");
	CWDebugLog_F("Clear Configuration Response Assembled");
    
	return CW_TRUE;
}

CWBool CWAssembleStationConfigurationResponse(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum, CWProtocolResultCode resultCode) 
{
	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Assembling Sattion Configuration Response...");
    CWDebugLog_F("Assembling Sattion Configuration Response...");
	
	CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_RESPONSE,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
	
	CWDebugLog("Station Configuration Response Assembled");
    CWDebugLog_F("Station Configuration Response Assembled");
	
	return CW_TRUE;
}

/*_______________________________________________________________*/
/*  *******************___PARSE FUNCTIONS___*******************  */
/*Update 2009:
	Function that parses vendor payload,
	filling in valuesPtr*/
CWBool CWParseVendorMessage(char *msg, int len, void **valuesPtr) {
	int i;
	CWProtocolMessage completeMsg;
	unsigned short int GlobalElemType=0;// = CWProtocolRetrieve32(&completeMsg);

	if(msg == NULL || valuesPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing Vendor Specific Message...");
	CWDebugLog_F("Parsing Vendor Specific Message...");
    
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	CWProtocolVendorSpecificValues *vendPtr;
  

	// parse message elements
	while(completeMsg.offset < len) {
	  unsigned short int elemType=0;// = CWProtocolRetrieve32(&completeMsg);
	  unsigned short int elemLen=0;// = CWProtocolRetrieve16(&completeMsg);
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		GlobalElemType = elemType;

		//CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);
		
		switch(elemType) {
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			  completeMsg.offset += elemLen;
			  break;
		default:
				if(elemType == CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE) 
				{
					CW_FREE_OBJECT(valuesPtr);
					return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
				}
				else 
				{
					completeMsg.offset += elemLen;
					break;
				}
		}
	}

	if(completeMsg.offset != len) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");


	switch(GlobalElemType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			CW_CREATE_OBJECT_ERR(vendPtr, CWProtocolVendorSpecificValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
			/*Allocate various other vendor specific fields*/
		break;
	}

	i=0;
	completeMsg.offset = 0;
	while(completeMsg.offset < len) {
		unsigned short int type=0;
		unsigned short int elemLen=0;
		
		CWParseFormatMsgElem(&completeMsg,&type,&elemLen);		

		switch(type) {
			/*Once we know it is a vendor specific payload...*/
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
				{
					if (!(CWParseVendorPayload(&completeMsg, elemLen, (CWProtocolVendorSpecificValues *) vendPtr)))
					{
						CW_FREE_OBJECT(vendPtr);
						return CW_FALSE; // will be handled by the caller
					}
				}
				break;
			default:
				completeMsg.offset += elemLen;
			break;
		}
	}
	
	*valuesPtr = (void *) vendPtr;
	CWDebugLog("Vendor Message Parsed");
    CWDebugLog_F("Vendor Message Parsed");
	
	return CW_TRUE;
}


CWBool CWParseConfigurationUpdateRequest (char *msg,
					  int len,
					  CWProtocolConfigurationUpdateRequestValues *valuesPtr, 
					  int *updateRequestType) {

	CWBool bindingMsgElemFound=CW_FALSE;
	CWBool vendorMsgElemFound=CW_FALSE;
	CWProtocolMessage completeMsg;
	unsigned short int GlobalElementType = 0;
	
	if(msg == NULL || valuesPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing Configuration Update Request...");
	CWDebugLog_F("Parsing Configuration Update Request...");
    
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	valuesPtr->bindingValues = NULL;
	/*Update 2009:
		added protocolValues (non-binding)*/
	valuesPtr->protocolValues = NULL;

	/* parse message elements */
	while(completeMsg.offset < len) {

		unsigned short int elemType=0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen=0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		GlobalElementType = elemType;

		/* CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen); */
		CWDebugLog_D("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		if(CWBindingCheckType(elemType)) {

			bindingMsgElemFound=CW_TRUE;
			completeMsg.offset += elemLen;
			continue;	
		}						
		switch(elemType) {
			/*Update 2009:
				Added case for vendor specific payload
				(Used mainly to parse UCI messages)...*/
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
				vendorMsgElemFound=CW_TRUE;
				completeMsg.offset += elemLen;
				break;
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
						    "Unrecognized Message Element");
		}
	}

	if (completeMsg.offset != len) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	/*Update 2009:
		deal with vendor specific messages*/
	if (vendorMsgElemFound) {
		/* For the knownledge of SaveConfiguration */
	  	*updateRequestType = GlobalElementType;

		if (!(CWParseVendorMessage(msg, len, &(valuesPtr->protocolValues)))) {

			return CW_FALSE;
		}
	}
	
	if (bindingMsgElemFound) {
	  /* For the knownledge of SaveConfiguration */
	  *updateRequestType = GlobalElementType;

		if (!(CWBindingParseConfigurationUpdateRequest(msg, len, &(valuesPtr->bindingValues)))) {


			return CW_FALSE;
		}
	}

	CWDebugLog("Configure Update Request Parsed");
	CWDebugLog_F("Configure Update Request Parsed");
    
	return CW_TRUE;
}

CWBool CWParseStationConfigurationRequest (char *msg, int len) 
{
	//CWBool bindingMsgElemFound=CW_FALSE;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing Station Configuration Request...");
	CWDebugLog_F("Parsing Station Configuration Request...");
    
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	//valuesPtr->bindingValues = NULL;

	// parse message elements
	while(completeMsg.offset < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		//CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		/*if(CWBindingCheckType(elemType))
		{
			bindingMsgElemFound=CW_TRUE;
			completeMsg.offset += elemLen;
			continue;	
		}*/
									
		switch(elemType) { 

			case CW_MSG_ELEMENT_ADD_STATION_CW_TYPE:
				if (!(CWParseAddStation(&completeMsg,  elemLen)))
					return CW_FALSE;
				break;
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}

	if(completeMsg.offset != len) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
	/*
	if(bindingMsgElemFound)
	{
		if(!(CWBindingParseConfigurationUpdateRequest (msg, len, &(valuesPtr->bindingValues))))
		{
			return CW_FALSE;
		}
	}*/

	CWDebugLog("Station Configuration Request Parsed");
	CWDebugLog_F("Station Configuration Request Parsed");
    
	return CW_TRUE;
}

CWBool CWParseWTPEventResponseMessage (char *msg, int len, int seqNum, void *values) {

	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing WTP Event Response...");
	CWDebugLog_F("Parsing WTP Event Response...");
    
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	/* error will be handled by the caller */
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE;
	
	/* different type */
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE) {
        char errinfo[128];

        sprintf(errinfo, "Message(%d) is not WTP Event Response as Expected", 
            controlVal.messageTypeValue);
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, errinfo);
    }
	
	if(controlVal.seqNum != seqNum) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Different Sequence Number");
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	
	if(controlVal.msgElemsLen != 0 ) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "WTP Event Response must carry no message element");

	CWDebugLog("WTP Event Response Parsed...");
    CWDebugLog_F("WTP Event Response Parsed...");
    
	return CW_TRUE;
}


/*______________________________________________________________*/
/*  *******************___SAVE FUNCTIONS___*******************  */
CWBool CWSaveWTPEventResponseMessage (void *WTPEventResp) {

	CWDebugLog("Saving WTP Event Response...");
    CWDebugLog_F("Saving WTP Event Response...");
	CWDebugLog("WTP Response Saved");
	CWDebugLog_F("WTP Response Saved");
	return CW_TRUE;
}

/*Update 2009:
	Save a vendor message (mainly UCI configuration messages)*/
CWBool CWSaveVendorMessage(void* protocolValuesPtr, CWProtocolResultCode* resultCode) {
	if(protocolValuesPtr==NULL) {return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);}
	*resultCode = CW_PROTOCOL_SUCCESS;

	CWProtocolVendorSpecificValues* vendorPtr=(CWProtocolVendorSpecificValues *)protocolValuesPtr; 

	/*Find out which custom vendor paylod really is...*/
	switch(vendorPtr->vendorPayloadType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
			if(!CWWTPSaveUCIValues((CWVendorUciValues *)(vendorPtr->payload), resultCode))
			{
				CW_FREE_OBJECT(((CWVendorUciValues *)vendorPtr->payload)->commandArgs);
				CW_FREE_OBJECT(vendorPtr->payload);
				CW_FREE_OBJECT(vendorPtr);
				return CW_FALSE;
			}
		break;

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
			if(!CWWTPSaveWUMValues((CWVendorWumValues *)(vendorPtr->payload), resultCode))
			{
				CW_FREE_OBJECT(vendorPtr->payload);
				CW_FREE_OBJECT(vendorPtr);
				return CW_FALSE;
			}
		break;
	}

	return CW_TRUE;
}

CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues *valuesPtr,
										CWProtocolResultCode* resultCode,
										int *updateRequestType) {

	*resultCode=CW_TRUE;

	if(valuesPtr==NULL) {return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);}

	if (valuesPtr->bindingValues!=NULL) {

	  if(!CWBindingSaveConfigurationUpdateRequest(valuesPtr->bindingValues, resultCode, updateRequestType)) 
			return CW_FALSE;
	} 
	if (valuesPtr->protocolValues!=NULL) {
		/*Update 2009:
			We have a msg which is not a 
			binding specific message... */
	  if(!CWSaveVendorMessage(valuesPtr->protocolValues, resultCode)) 
			return CW_FALSE;
	}
	return CW_TRUE;
}

CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode* resultCode)
{
	*resultCode=CW_TRUE;
	
	/*Back to manufacturing default configuration*/

	if ( !CWErr(CWWTPLoadConfiguration()) || !CWErr(CWWTPInitConfiguration()) ) 
	{
			CWDebugLog_E("Can't restore default configuration...");
			return CW_FALSE;
	}

	*resultCode=CW_TRUE;
	return CW_TRUE;
}

/*
CWBool CWWTPManageACRunRequest(char *msg, int len)
{
	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE; // error will be handled by the caller
	
	switch(controlVal.messageTypeValue) {
		case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:
			break;
		case CW_MSG_TYPE_VALUE_ECHO_REQUEST:
			break;
		case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:
			break;
		case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Change State Event Response as Expected");
	}

	
	
	//if(controlVal.seqNum != seqNum) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");
	
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS; // skip timestamp
	
	if(controlVal.msgElemsLen != 0 ) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Change State Event Response must carry no message elements");

	CWDebugLog("Change State Event Response Parsed");




	CWDebugLog("#########################");
	CWDebugLog("###### STO DENTRO #######");
	CWDebugLog("#########################");

	return CW_TRUE;
}
*/

void CWConfirmRunStateToACWithEchoRequest() {

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;

	CWLog("#________ Echo Request Message (Confirm Run) ________#");
	
	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if(!CWAssembleEchoRequest(&messages,
				  &fragmentsNum,
				  gWTPPathMTU,
				  seqNum,
				  msgElemList)){
		int i;

		CWDebugLog_E("Failure Assembling Echo Request");
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		return;
	}
	
	int i;
	for(i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
#else
		if(!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)){
#endif
			CWDebugLog_E("Failure sending Request");
			int k;
			for(k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}	
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);

}


