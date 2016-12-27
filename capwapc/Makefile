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

define Package/capwapc/conffiles
/etc/capwapc/settings.wtp.txt
/etc/capwapc/config.wtp
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/capwapc/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/capwapc
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_CONF) ./files/etc/capwapc/settings.wtp.txt $(1)/etc/capwapc/
	$(INSTALL_CONF) ./files/etc/capwapc/config.wtp $(1)/etc/capwapc/
	$(INSTALL_CONF) ./files/etc/config/capwapc $(1)/etc/config/
	$(INSTALL_BIN) ./files/etc/init.d/capwapc $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ok_capwapc $(1)/usr/sbin/
endef


$(eval $(call BuildPackage,capwapc))
