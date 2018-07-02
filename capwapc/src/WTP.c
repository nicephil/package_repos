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
#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif
#include <sys/wait.h>

CW_THREAD_RETURN_TYPE CWWTPReceiveFrame(void *arg);
CW_THREAD_RETURN_TYPE CWWTPReceiveStats(void *arg);
CW_THREAD_RETURN_TYPE CWWTPReceiveFreqStats(void *arg);


capwapc_config g_capwapc_config  = {
    .enable       = CAPWAPC_DEFAULT_ENABLE,
    .def_server   = CAPWAPC_DEFAULT_SERVER,
    .ctrl_port    = CAPWAPC_DEFAULT_CTRLPORT,
    .mtu          = CAPWAPC_DEFAULT_MTU,
    .disc_intv    = CAPWAPC_DEFAULT_DISCINTV,
    .maxdisc_intv = CAPWAPC_DEFAULT_MAXDISCINTV,
    .echo_intv    = CAPWAPC_DEFAULT_ECHOINTV,
    .retran_intv  = CAPWAPC_DEFAULT_RETRANINTV,
    .silent_intv  = CAPWAPC_DEFAULT_SILENTINTV,
    .join_timeout = CAPWAPC_DEFAULT_JIONTIMEOUT,
    .max_disces   = CAPWAPC_DEFAULT_MAXDISCES,
    .max_retran   = CAPWAPC_DEFAULT_MAXRETRAN,
};

int 	gEnabledLog = 1;
int 	gMaxLogFileSize = (1024 * 1024);
char 	gLogFileName[] = WTP_LOG_FILE_NAME;

/* addresses of ACs for Discovery */
char	**gCWACAddresses;
int	gCWACCount = 0;

int gIPv4StatusDuplicate = 0;
int gIPv6StatusDuplicate = 0;

/* if not NULL, jump Discovery and use this address for Joining */
char 		*gWTPForceACAddress = NULL;
CWAuthSecurity 	gWTPForceSecurity;

/* UDP network socket */
CWSocket 		gWTPSocket = -1;
/* DTLS session vars */
CWSecurityContext	gWTPSecurityContext;
CWSecuritySession 	gWTPSession;

/* list used to pass frames from wireless interface to main thread */
CWSafeList 		gFrameList;

/* list used to pass CAPWAP packets from AC to main thread */
CWSafeList 		gPacketReceiveList;

/* used to synchronize access to the lists */
CWThreadCondition    gInterfaceWait;
CWThreadMutex 		gInterfaceMutex;

/* infos about the ACs to discover */
CWACDescriptor *gCWACList = NULL;
/* infos on the better AC we discovered so far */
CWACInfoValues *gACInfoPtr = NULL;
CWACInfoValues *gACInfoPtr_temp = NULL;


/* WTP statistics timer */
int gWTPStatisticsTimer = CW_STATISTIC_TIMER_DEFAULT;

WTPRebootStatisticsInfo gWTPRebootStatistics;
CWWTPRadiosInfo gRadiosInfo;

/* path MTU of the current session */
int gWTPPathMTU = 0;

int gWTPRetransmissionCount;

CWPendingRequestMessage gPendingRequestMsgs[MAX_PENDING_REQUEST_MSGS];	

CWBool WTPExitOnUpdateCommit = CW_FALSE;

/* 
 * Receive a message, that can be fragmented. This is useful not only for the Join State
 */
CWBool CWReceiveMessage(CWProtocolMessage *msgPtr) {
	static CWList fragments = NULL;
	int readBytes;
	char buf[CW_BUFFER_SIZE];
	
	CW_REPEAT_FOREVER {
		CW_ZERO_MEMORY(buf, CW_BUFFER_SIZE);
#ifdef CW_NO_DTLS
		char *pkt_buffer = NULL;

		CWLockSafeList(gPacketReceiveList);

		while (CWGetCountElementFromSafeList(gPacketReceiveList) == 0)
			CWWaitElementFromSafeList(gPacketReceiveList);

		pkt_buffer = (char*)CWRemoveHeadElementFromSafeList(gPacketReceiveList, &readBytes);

		CWUnlockSafeList(gPacketReceiveList);

		CW_COPY_MEMORY(buf, pkt_buffer, readBytes);
		CW_FREE_OBJECT(pkt_buffer);
#else
		if(!CWSecurityReceive(gWTPSession, buf, CW_BUFFER_SIZE, &readBytes)) {return CW_FALSE;}
#endif
		CWBool dataFlag = CW_FALSE;
		if(!CWProtocolParseFragment(buf, readBytes, &fragments, msgPtr, &dataFlag)) {
            if(CWErrorGetLastErrorCode() == CW_ERROR_DEVCONTROL_REQ_FRAGMENT) { 
                /* Receive the fragment of device control request, we need send response */
                break;
            }
			else if(CWErrorGetLastErrorCode() == CW_ERROR_NEED_RESOURCE) { // we need at least one more fragment
				continue;
			} else { // error
				CWErrorCode error;
				error=CWErrorGetLastErrorCode();
				switch(error)
				{
					case CW_ERROR_SUCCESS: {CWDebugLog_F("ERROR: Success"); break;}
					case CW_ERROR_OUT_OF_MEMORY: {CWDebugLog_E("ERROR: Out of Memory"); break;}
					case CW_ERROR_WRONG_ARG: {CWDebugLog_E("ERROR: Wrong Argument"); break;}
					case CW_ERROR_INTERRUPTED: {CWDebugLog_E("ERROR: Interrupted"); break;}
					case CW_ERROR_NEED_RESOURCE: {CWDebugLog_E("ERROR: Need Resource"); break;}
					case CW_ERROR_COMUNICATING: {CWDebugLog_E("ERROR: Comunicating"); break;}
					case CW_ERROR_CREATING: {CWDebugLog_E("ERROR: Creating"); break;}
					case CW_ERROR_GENERAL: {CWDebugLog_E("ERROR: General"); break;}
					case CW_ERROR_OPERATION_ABORTED: {CWDebugLog_E("ERROR: Operation Aborted"); break;}
					case CW_ERROR_SENDING: {CWDebugLog_E("ERROR: Sending"); break;}
					case CW_ERROR_RECEIVING: {CWDebugLog_E("ERROR: Receiving"); break;}
					case CW_ERROR_INVALID_FORMAT: {CWDebugLog_E("ERROR: Invalid Format"); break;}
					case CW_ERROR_TIME_EXPIRED: {CWDebugLog_E("ERROR: Time Expired"); break;}
					case CW_ERROR_NONE: {CWDebugLog_E("ERROR: None"); break;}
                    case CW_ERROR_DEVCONTROL_REQ_FRAGMENT :{CWDebugLog_E("ERROR: Devctrl req frag"); break;}
				}
                CWLog("Parese message failed for %d.", error);
				return CW_FALSE;
			}
		} else break; // the message is fully reassembled
	}
	
	return CW_TRUE;
}

CWBool CWWTPSendAcknowledgedPacket(int seqNum, 
				   CWList msgElemlist,
				   CWBool (assembleFunc)(CWProtocolMessage **, int *, int, int, CWList),
				   CWBool (parseFunc)(char*, int, int, void*), 
				   CWBool (saveFunc)(void*),
				   void *valuesPtr) {

	CWProtocolMessage *messages = NULL;
	CWProtocolMessage msg;
	int fragmentsNum = 0, i;

	struct timespec timewait;
    
	int gTimeToSleep = g_capwapc_config.retran_intv;
	int gMaxTimeToSleep = g_capwapc_config.echo_intv/2;

	msg.msg = NULL;
	
	if(!(assembleFunc(&messages, 
			  &fragmentsNum, 
			  gWTPPathMTU, 
			  seqNum, 
			  msgElemlist))) {

		goto cw_failure;
	}
	
	gWTPRetransmissionCount= 0;
	
	while(gWTPRetransmissionCount < g_capwapc_config.max_retran) 
	{
		CWDebugLog_D("Transmission Num:%d", gWTPRetransmissionCount);
		for(i = 0; i < fragmentsNum; i++) 
		{
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
				CWDebugLog_F("Failure sending Request");
				goto cw_failure;
			}
		}
		
		timewait.tv_sec = time(0) + gTimeToSleep;
		timewait.tv_nsec = 0;

		CW_REPEAT_FOREVER 
		{
			CWThreadMutexLock(&gInterfaceMutex);

			if (CWGetCountElementFromSafeList(gPacketReceiveList) > 0)
				CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			else {
				if (CWErr(CWWaitThreadConditionTimeout(&gInterfaceWait, &gInterfaceMutex, &timewait)))
					CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			}

			CWThreadMutexUnlock(&gInterfaceMutex);

			switch(CWErrorGetLastErrorCode()) {

				case CW_ERROR_TIME_EXPIRED:
				{
					gWTPRetransmissionCount++;
					goto cw_continue_external_loop;
					break;
				}

				case CW_ERROR_SUCCESS:
				{
					/* there's something to read */
					if(!(CWReceiveMessage(&msg))) 
					{
						CW_FREE_PROTOCOL_MESSAGE(msg);
						CWDebugLog_E("Failure Receiving Response");
						goto cw_failure;
					}
					
					if(!(parseFunc(msg.msg, msg.offset, seqNum, valuesPtr))) 
					{
						if(CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {

							CW_FREE_PROTOCOL_MESSAGE(msg);
							CWDebugLog_E("Failure Parsing Response");
							goto cw_failure;
						}
						else {
							CWErrorHandleLast();
							{ 
								gWTPRetransmissionCount++;
								goto cw_continue_external_loop;
							}
							break;
						}
					}
					
					if((saveFunc(valuesPtr))) {

						goto cw_success;
					} 
					else {
						if(CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {
							CW_FREE_PROTOCOL_MESSAGE(msg);
							CWDebugLog_E("Failure Saving Response");
							goto cw_failure;
						} 
					}
					break;
				}

				case CW_ERROR_INTERRUPTED: 
				{
					gWTPRetransmissionCount++;
					goto cw_continue_external_loop;
					break;
				}	
				default:
				{
					CWErrorHandleLast();
					CWDebugLog_E("Failure");
					goto cw_failure;
					break;
				}
			}
		}
		
		cw_continue_external_loop:
			CWDebugLog_E("Retransmission time is over");
			
			gTimeToSleep<<=1;
			if ( gTimeToSleep > gMaxTimeToSleep ) gTimeToSleep = gMaxTimeToSleep;
	}

	/* too many retransmissions */
	return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "Peer Dead");
	
cw_success:	
	for(i = 0; i < fragmentsNum; i++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[i]);
	}
	
	CW_FREE_OBJECT(messages);
	CW_FREE_PROTOCOL_MESSAGE(msg);
	
	return CW_TRUE;
	
cw_failure:
	if(messages != NULL) {
		for(i = 0; i < fragmentsNum; i++) {
			CW_FREE_PROTOCOL_MESSAGE(messages[i]);
		}
		CW_FREE_OBJECT(messages);
	}
	CWDebugLog_E("Failure");
	return CW_FALSE;
}

int log_id = -1;

static char *(state_name[]) = 
{
	"sulking state",
	"discovery state",
	"join state",
	"configure state",
	"data check state",
	"run state",
	"reset state",
	"restart state",
	"Stop state",
	"quit state",
	""
};

int main (int argc, const char * argv[]) 
{
#define CAPWAPC_WORKING_DIR           "/tmp/wtp"

#if 0
    if (daemon(1,0) != 0) {
        CWLog("daemon failed: %s\n", strerror(errno));
        exit(1);
    }
#endif
    
	CWStateTransition nextState = CW_ENTER_DISCOVERY;

#ifdef LOG_FILE
	CWLogInitFile(gLogFileName);
#endif
    setlogmask(LOG_UPTO(loglevel));

#ifndef CW_SINGLE_THREAD
	CWDebugLog_F("Use Threads");
#else
	CWDebugLog_F("Don't Use Threads");
#endif
	CWErrorHandlingInitLib();
	
	if(!CWParseSettingsFile()){
		CWLog("Can't start WTP");
		exit(1);
	}

    /* Capwap task related */
	if (!CWErr(task_init()) || !create_pendingbox_mutex())
	{
		CWLog("Can't start WTP");
		exit(1);
	}

	/* Capwap receive packets list */
	if (!CWErr(CWCreateSafeList(&gPacketReceiveList)))
	{
		CWLog("Can't start WTP");
		exit(1);
	}

	/* Capwap receive frame list */
	if (!CWErr(CWCreateSafeList(&gFrameList)))
	{
		CWLog("Can't start WTP");
		exit(1);
	}

	CWCreateThreadMutex(&gInterfaceMutex);
	CWSetMutexSafeList(gPacketReceiveList, &gInterfaceMutex);
	CWSetMutexSafeList(gFrameList, &gInterfaceMutex);
	CWCreateThreadCondition(&gInterfaceWait);
	CWSetConditionSafeList(gPacketReceiveList, &gInterfaceWait);
	CWSetConditionSafeList(gFrameList, &gInterfaceWait);

	CWLog("Starting WTP...");
	
	CWRandomInitLib();

	CWThreadSetSignals(SIG_BLOCK, 2, SIGUSR1, SIGALRM);


	if (timer_init() == 0) {
		CWLog("Can't init timer module");
		exit(1);
	}

#ifdef CW_NO_DTLS
	if( !CWErr(CWWTPLoadConfiguration()) || capwapc_get_curcfg(&g_capwapc_config) ) {
#else
	if( !CWErr(CWSecurityInitLib())	|| !CWErr(CWWTPLoadConfiguration()) || capwapc_get_curcfg(&g_capwapc_config)) {
#endif
		CWLog("Can't start WTP");
		exit(1);
	}
	
	CWDebugLog_F("Init WTP Radio Info");
	if(!CWWTPInitConfiguration())
	{
		CWLog("Error Init Configuration");
		exit(1);
	}

#if 0 /* disabled by */
	CWThread thread_receiveFrame;
	if(!CWErr(CWCreateThread(&thread_receiveFrame, CWWTPReceiveFrame, NULL))) {
		CWLog("Error starting Thread that receive binding frame");
		exit(1);
	}

	CWThread thread_receiveStats;
	if(!CWErr(CWCreateThread(&thread_receiveStats, CWWTPReceiveStats, NULL))) {
		CWLog("Error starting Thread that receive stats on monitoring interface");
		exit(1);
	}

	/****************************************
	 * 2009 Update:							*
	 *				Spawn Frequency Stats	*
	 *				Receiver Thread			*
	 ****************************************/
		
	CWThread thread_receiveFreqStats;
	if(!CWErr(CWCreateThread(&thread_receiveFreqStats, CWWTPReceiveFreqStats, NULL))) {
		CWLog("Error starting Thread that receive frequency stats on monitoring interface");
		exit(1);
	}
#endif

	/* if AC address is given jump Discovery and use this address for Joining */
	if(gWTPForceACAddress != NULL)	nextState = CW_ENTER_JOIN;

	/* start CAPWAP state machine */	
	CW_REPEAT_FOREVER {
        CWDebugLog_F("Switch next state: %s.", state_name[(nextState - CW_ENTER_SULKING) % (CW_QUIT - CW_ENTER_SULKING + 1)]);
		switch(nextState) {
			case CW_ENTER_DISCOVERY:
				nextState = CWWTPEnterDiscovery();
				break;
			case CW_ENTER_SULKING:
				nextState = CWWTPEnterSulking();
				break;
			case CW_ENTER_JOIN:
				nextState = CWWTPEnterJoin();
				break;
			case CW_ENTER_CONFIGURE:
				nextState = CWWTPEnterConfigure();
				break;	
			case CW_ENTER_DATA_CHECK:
				nextState = CWWTPEnterDataCheck();
				break;	
            case CW_ENTER_RUN:
                nextState = CWWTPEnterRun();
                break;
            case CW_ENTER_RESET:
		        CWUseSockNtop(&(gACInfoPtr->preferredAddress),
			    {okos_system_log(LOG_INFO, "disconnected from oakmgr @%s, err:timeout", str);});
                CWStopHeartbeatTimer();
                CWStopNeighborDeadTimer();
                /*
                 * CWNetworkCloseSocket(gWTPSocket);
                 * CWSecurityDestroySession(gWTPSession);
                 * CWSecurityDestroyContext(gWTPSecurityContext);
                 * gWTPSecurityContext = NULL;
                 * gWTPSession = NULL;
                 */
                nextState = CW_ENTER_DISCOVERY;
                break;
			case CW_QUIT:
                CWLog("Try to destroy WTP");
				CWWTPDestroy();
				return 0;
            case CW_STOP:
            case CW_RESTART_SILENTLY:
                /* compile warning, do nothing */
                break;
		}
	}
}

__inline__ unsigned int CWGetSeqNum() {
	static unsigned int seqNum = 0;
	
	if (seqNum==CW_MAX_SEQ_NUM) seqNum=0;
	else seqNum++;
	return seqNum;
}

__inline__ int CWGetFragmentID() {
	static int fragID = 0;
	return fragID++;
}


/* 
 * Parses config file and inits WTP configuration.
 */
CWBool CWWTPLoadConfiguration() 
{
#define BROADCAST_DISCOVERY_ADDRESS   "255.255.255.255"
	int i;
	
	CWLog("WTP Loads Configuration");
	
	/* get saved preferences */
	if(!CWErr(CWParseConfigFile())) {
		CWLog("Can't Read Config File");
		exit(1);
	}

    /* one more for broadcast address */
    CW_CREATE_ARRAY_ERR(gCWACList, (gCWACCount + 1), CWACDescriptor, 
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    for(i = 0; i < gCWACCount; i++) {
        CWDebugLog_F("Init Configuration for server at %s", gCWACAddresses[i]);
        CW_CREATE_OBJECT_ERR(gCWACList[i].addrinfo, struct ac_addressinfo, 
            return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
        
        CW_CREATE_STRING_FROM_STRING_ERR(gCWACList[i].addrinfo->address, gCWACAddresses[i],
    						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
    }
    if (gCWACCount > 0) {
    	CW_FREE_OBJECTS_ARRAY(gCWACAddresses, gCWACCount);
     }

    /* add broadcast address to aclist automatically */
    CW_CREATE_OBJECT_ERR(gCWACList[gCWACCount].addrinfo, struct ac_addressinfo, 
         return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
        
    CW_CREATE_STRING_FROM_STRING_ERR(gCWACList[gCWACCount].addrinfo->address, BROADCAST_DISCOVERY_ADDRESS,
        return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

    gCWACCount += 1;

	return CW_TRUE;
}

void CWWTPDestroy() {
	int i;
	
	CWLog("Destroy WTP");
	
	for(i = 0; i < gCWACCount; i++) {
		CW_FREE_OBJECT(gCWACList[i].addrinfo->address);
        CW_FREE_OBJECT(gCWACList[i].addrinfo);
	}
	
	timer_destroy();

	CW_FREE_OBJECT(gCWACList);
    for(i = 0; i < gRadiosInfo.radioCount; i ++) {
        bindingValues *aux = gRadiosInfo.radiosInfo[i].bindingValuesPtr;
        if (aux) {
            CW_FREE_OBJECT(aux->qosValues);
	        CW_FREE_OBJECT(aux);
        }
    }
	CW_FREE_OBJECT(gRadiosInfo.radiosInfo);
}

CWBool CWWTPInitConfiguration() {
	int i;

	CWWTPResetRebootStatistics(&gWTPRebootStatistics);

	gRadiosInfo.radioCount = CWWTPGetMaxRadios();
	CW_CREATE_ARRAY_ERR(gRadiosInfo.radiosInfo, gRadiosInfo.radioCount, CWWTPRadioInfoValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
#if 0 /*  disabled  */
	gRadiosInfo.radiosInfo[0].radioID= 0;
	/* gRadiosInfo.radiosInfo[0].numEntries = 0; */
	gRadiosInfo.radiosInfo[0].decryptErrorMACAddressList = NULL;
	gRadiosInfo.radiosInfo[0].reportInterval= CW_REPORT_INTERVAL_DEFAULT;
	gRadiosInfo.radiosInfo[0].adminState= ENABLED;
	gRadiosInfo.radiosInfo[0].adminCause= AD_NORMAL;
	gRadiosInfo.radiosInfo[0].operationalState= ENABLED;
	gRadiosInfo.radiosInfo[0].operationalCause= OP_NORMAL;
	gRadiosInfo.radiosInfo[0].TxQueueLevel= 0;
	gRadiosInfo.radiosInfo[0].wirelessLinkFramesPerSec= 0;
	CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[0].statistics));
	if(!CWWTPInitBinding(0)) {
        return CW_FALSE;
    }
#endif	
	for (i=1; i<gRadiosInfo.radioCount; i++)
	{
		gRadiosInfo.radiosInfo[i].radioID= i;
		/* gRadiosInfo.radiosInfo[i].numEntries = 0; */
		gRadiosInfo.radiosInfo[i].decryptErrorMACAddressList = NULL;
		gRadiosInfo.radiosInfo[i].reportInterval= CW_REPORT_INTERVAL_DEFAULT;
		/* Default value for CAPWAP */
		gRadiosInfo.radiosInfo[i].adminState= ENABLED; 
		gRadiosInfo.radiosInfo[i].adminCause= AD_NORMAL;
		gRadiosInfo.radiosInfo[i].operationalState= DISABLED;
		gRadiosInfo.radiosInfo[i].operationalCause= OP_NORMAL;
		gRadiosInfo.radiosInfo[i].TxQueueLevel= 0;
		gRadiosInfo.radiosInfo[i].wirelessLinkFramesPerSec= 0;
		CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[i].statistics));
		if(!CWWTPInitBinding(i)) {
            return CW_FALSE;
        }
	}
	return CW_TRUE;
}
