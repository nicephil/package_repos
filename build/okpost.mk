EXTRA_CFLAGS += -DOK_PATCH=1 -DOK_BUILD_RELEASE=1 -g
EXTRA_LDFLAGS += -g

all: lib bin kmod

ifneq ($(KMOD),)
# It's kernel module
obj-m := $(KMOD).o
$(KMOD)-objs := $(OBJS)

else
# It's application

CFLAGS += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

BUILD_OBJS=$(OBJS)
BUILD_LIBOBJS=$(LIBOBJS)

CFLAGS += -I./include
SHLIBFLAGS += -shared -fPIC
STLIBFLAGS += rcs


$(BUILD_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_LIBOBJS): %.o: %.c
	$(CC) -fpic $(CFLAGS) -c -o $@ $<
endif

lib: $(BUILD_LIBOBJS)
ifneq ($(SHLIB),)
	$(CC) $(SHLIBFLAGS) $(LDFLAGS) -o $(SHLIB) $(BUILD_LIBOBJS) $(DEPLIBS)
endif
ifneq ($(STLIB),)
	$(AR) $(STLIBFLAGS) $(STLIB) $(BUILD_LIBOBJS)
endif

bin: $(BUILD_OBJS)
ifneq ($(EXEC),)
	$(CC) $(LDFLAGS) -o $(EXEC) $(BUILD_OBJS) $(DEPLIBS)
endif

kmod:
ifneq ($(KMOD),)
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="-I$(PKG_BUILD_DIR)/include $(EXTRA_CFLAGS)" \
		modules
endif

clean:
	rm -rf *.o *.so *.so.* *.a *.lo *.la
ifneq ($(SHLIB),)
	rm -rf $(SHLIB)
endif
ifneq ($(STLIB),)
	rm -rf $(STLIB)
endif
ifneq ($(EXE),)
	rm -rf $(EXE)
endif
ifneq ($(KMOD),)
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="-I./include -g $(BUILDFLAGS)" \
		clean
endif

doxygen:
	@$(Doxygen)

.PHONY: all lib bin clean distclean doxygen
