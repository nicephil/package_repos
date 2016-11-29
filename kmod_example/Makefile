include $(TOPDIR)/rules.mk

include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=kmod_example
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define KernelPackage/kmod_example
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=Support Module for kmod_example
	AUTOLOAD:=$(call AutoLoad,81,kmod_example)
	FILES:=$(PKG_BUILD_DIR)/*.$(LINUX_KMOD_SUFFIX)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	export LINUX_DIR="$(LINUX_DIR)"; \
	export LINUX_SRC_DIR="$(LINUX_SRC_DIR)"; \
	export TARGET_CROSS="$(TARGET_CROSS)"; \
	export LINUX_KARCH="$(LINUX_KARCH)"; \
	export ARCH="$(ARCH)"; \
	export PKG_BUILD_DIR="$(PKG_BUILD_DIR)"; \
	export EXTRA_CFLAGS="$(EXTRA_CFLAGS)"; \
	export MAKE="$(MAKE)"; \
	$(MAKE) -C $(PKG_BUILD_DIR) kmod
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
	-$(CP) $(PKG_BUILD_DIR)/include $(STAGING_DIR)/usr/include
endef

$(eval $(call KernelPackage,kmod_example))
