include $(TOPDIR)/rules.mk

PKG_NAME:=capwap
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/capwap
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=capwap utilities
	DEPENDS:=libpthread libsys
endef

define Package/capwap/description
	capwap to communicate to HM
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/capwap/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/capwap $(1)/bin/
endef

$(eval $(call BuildPackage,capwap))
