include $(TOPDIR)/rules.mk

include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=kmod_libsys
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define KernelPackage/kmod_libsys
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=Support Module for kmod_libsys
	AUTOLOAD:=$(call AutoLoad,81,kmod_libsys)
	FILES:=$(PKG_BUILD_DIR)/*.$(LINUX_KMOD_SUFFIX)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	export LINUX_DIR="$(LINUX_DIR)"; \
	export TARGET_CROSS="$(TARGET_CROSS)"; \
	export ARCH="$(ARCH)"; \
	export LINUX_KARCH="$(LINUX_KARCH)"; \
	export PKG_BUILD_DIR="$(PKG_BUILD_DIR)"; \
	export BUILDFLAGS="$(BUILDFLAGS)"; \
	export MAKE="$(MAKE)"; \
	$(MAKE) -C $(PKG_BUILD_DIR) kmod
endef

$(eval $(call KernelPackage,kmod_libsys))
