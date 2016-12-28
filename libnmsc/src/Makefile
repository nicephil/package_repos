
CFLAGS?=-O0 -Wall -g
LDFLAGS?=

CFLAGS+=-I./ -fPIC -std=gnu99
LDFLAGS+=-shared -fPIC  -lservices
CPPFLAGS+=-I./ -fPIC  

LIBOBJS=nmsc_json.o \
		nmsc_json_entry.o \
		nmsc_json_node.o \
		nmsc_util.o

SHLIB=libnmsc.so.1.0

include $(TOPDIR)/package_repos/build/okpost.mk
