#LDFLAGS = -lssl -lcrypto -lpthread -ldl -D_REENTRANT
#LDFLAGS = /usr/lib/libefence.a ./static/libssl.a ./static/libcrypto.a -lpthread -ldl -D_REENTRANT
LDFLAGS = ./static/uclibc/libssl.a ./static/uclibc/libcrypto.a -lpthread -ldl -D_REENTRANT 
#LDFLAGS = -lpthread -ldl -D_REENTRAN
CFLAGS = -Wall -g -O0 -D_REENTRANT -I./include/ -DCW_NO_DTLS
CFLAGS+=$(EXTRA_CFLAGS)
OPENSSL_INCLUDE = #-I/usr/local/ssl/include/ #Openssl include files
LDFLAGS+=$(EXTRA_LDFLAGS)
LDFLAGS+=-ljson -lok_util -lcfg -lnmsc -Wl

# Memory leak
#LDFLAGS += ../dmalloc-5.5.0/libdmallocth.a
#CFLAGS += -DDMALLOC

# Capwap Debugging
CFLAGS += -DCW_NO_DTLSCWParseConfigurationUpdateRequest  #-DCW_DEBUGGING
CFLAGS += -DOPENSSL_NO_KRB5

# list of generated object files for WTP. 
WTP_OBJS = WTP.o WTPFrameReceive.o WTPFreqStatsReceive.o WTPStatsReceive.o WTPConfigFile.o WTPProtocol.o WTPProtocol_User.o WTPDiscoveryState.o WTPJoinState.o WTPConfigureState.o WTPDataCheckState.o WTPRunState.o WTPRunStateCheck.o WTPRetransmission.o WTPSulkingState.o CWCommon.o CWConfigFile.o CWErrorHandling.o CWSafeList.o CWList.o CWLog.o CWNetwork.o CWProtocol.o CWRandom.o CWStevens.o CWThread.o CWBinding.o CWVendorPayloadsWTP.o WTPBinding.o WTPDriverInteraction.o WTPSettingsFile.o timerlib.o
#WTP_OBJS += CWSecurity.o CWOpenSSLBio.o
# for the device control
WTP_OBJS += devctrl_protocol.o devctrl_task.o devctrl_payload.o devctrl_notice.o devctrl_tech_support.o

OBJS = $(WTP_OBJS)


EXEC = ok_capwapc

include $(TOPDIR)/package_repos/build/okpost.mk

