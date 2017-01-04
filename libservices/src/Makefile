LIBOBJS = util_services.o \
		  capwapc_services.o \
		  hostname_services.o \
		  cfg_services.o \
		  portal_services.o \
		  wlan_services.o \
		  ntpclient_services.o \
		  log_services.o \
		  dns_services.o \
		  vlan_services.o \
		  dnsset_services.o


SHLIB = libservices.so.1.0

EXTRA_CFLAGS +=
EXTRA_LDFLAGS += -luci

include $(TOPDIR)/package_repos/build/okpost.mk
