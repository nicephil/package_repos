
DEPLIBS += -lsys -lpthread \
            -lssl \
            -lcrypto \
	    	-lz 

OBJS = ah_capwap_module.o \
       ah_capwap_func.o\
       ah_capwap_discovery_client.o\
       ah_capwap_ini.o\
       ah_capwap_main.o\
       ah_capwap_packet.o\
       ah_capwap_eventlist.o \
       ah_capwap_dtls.o \
       ah_capwap_recovery.o \
       ah_capwap_trap.o \
       ah_capwap_hvcom.o \
       ah_capwap_tcp.o 

EXEC = capwap


include $(TOPDIR)/package_repos/build/okpost.mk
