include $(TOPDIR)/rules.mk

PKG_NAME:=capwap_ping
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/capwap_ping
	SECTION:=network
	CATEGORY:=Network
	TITLE:=capwap_ping utilities
endef

define Package/capwap_ping/description
	capwap_ping to communicate to HM
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/capwap_ping/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ok_capwap_ping $(1)/bin/
endef

$(eval $(call BuildPackage,capwap_ping))
