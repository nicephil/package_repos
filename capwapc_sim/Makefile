include $(TOPDIR)/rules.mk

PKG_NAME:=capwapc_sim
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/capwapc_sim
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=capwapc_sim utilities
	DEPENDS:=libpthread libutil libjson
endef

define Package/capwapc_sim/description
	capwapc_sim to communicate to HM
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/capwapc_sim/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ok_capwapc_sim $(1)/bin/
endef

$(eval $(call BuildPackage,capwapc_sim))
