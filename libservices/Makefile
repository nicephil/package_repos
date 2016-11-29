include $(TOPDIR)/rules.mk

PKG_NAME:=libservices
PKG_VERSION:=1.0
PKG_RELEASE:=0

include $(INCLUDE_DIR)/package.mk

define Package/libservices
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=User Level System Library
	DEPENDS:= libpthread
endef

define Package/libservices/description
	The libservices library provides a basic set of functions 
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
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libservices.so.1.0 $(STAGING_DIR)/usr/lib/
	(cd $(STAGING_DIR)/usr/lib; $(LN) libservices.so.1.0 libservices.so.1;$(LN) libservices.so.1.0 libservices.so)
endef

define Package/libservices/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libservices.so.1.0 $(1)/usr/lib/
	(cd $(1)/usr/lib;$(LN) libservices.so.1.0 libservices.so.1;$(LN) libservices.so.1.0 libservices.so)
endef

$(eval $(call BuildPackage,libservices))
