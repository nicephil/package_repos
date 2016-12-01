include $(TOPDIR)/rules.mk

PKG_NAME:=capwapc
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/capwapc
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=capwapc utilities
	DEPENDS:=+libpthread +libif +libservices +libok_util +libcfg +libjson +libnmsc +libubox
endef

define Package/capwapc/description
	capwapc to communicate to HM
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/capwapc/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ok_capwapc $(1)/bin/
endef

$(eval $(call BuildPackage,capwapc))
