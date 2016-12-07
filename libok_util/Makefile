include $(TOPDIR)/rules.mk

PKG_NAME:=libok_util
PKG_VERSION:=1.0
PKG_RELEASE:=0

include $(INCLUDE_DIR)/package.mk

define Package/libok_util
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=User Level System Library
	DEPENDS:=+kmod-qca-wifi-10.4-unified-perf
endef

define Package/libok_util/description
	The libok_util library provides a basic set of functions 
	for use by applications 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
	$(CP) $(PKG_BUILD_DIR)/include/* $(STAGING_DIR)/usr/include/
	$(INSTALL_DIR) $(STAGING)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libok_util.so.1.0 $(STAGING_DIR)/usr/lib/
	(cd $(STAGING_DIR)/usr/lib; $(LN) libok_util.so.1.0 libok_util.so.1;$(LN) libok_util.so.1.0 libok_util.so)
endef

define Package/libok_util/install
	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) ./files/qcawifi.sh $(1)/lib/wifi
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libok_util.so.1.0 $(1)/usr/lib/
	(cd $(1)/usr/lib;$(LN) libok_util.so.1.0 libok_util.so.1;$(LN) libok_util.so.1.0 libok_util.so)
endef

$(eval $(call BuildPackage,libok_util))
