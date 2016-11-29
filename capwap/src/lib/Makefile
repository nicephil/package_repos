ifeq ($(AEROS_ROOT_SET),)
export AEROS_ROOT:=$(shell find_aeros_root.sh)
export AEROS_ROOT_SET=yes
endif

include $(AEROS_ROOT)/build/ahcommonpre.mk

DEPLIBS = -lah -lah_log -lah_sys -lpthread -lah_event -lah_mpi

LIBOBJS = ah_capwap_api.o 

DEPDIRS = $(AEROS_ROOT)/util/ahlib \
          $(AEROS_ROOT)/util/loglib \
          $(AEROS_ROOT)/system/syslib 

SHLIB = libah_capwap.so.1.0

include $(AEROS_ROOT)/build/ahuserpost.mk

