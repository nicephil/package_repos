LIBOBJS = blob.o cli.o delta.o \
		  file.o libcfg.o parse.o \
		  util.o cfg_version.o


SHLIB = libcfg.so.1.0

EXTRA_CFLAGS +=
EXTRA_LDFLAGS += -lubox

include $(TOPDIR)/package_repos/build/okpost.mk
