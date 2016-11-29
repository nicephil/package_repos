include $(TOPDIR)/rules.mk

PKG_NAME:=libif
PKG_VERSION:=1.0
PKG_RELEASE:=0

include $(INCLUDE_DIR)/package.mk

define Package/libif
	SECTION:=Oakridge
	CATEGORY:=Oakridge Software
	TITLE:=User Level System Library
	DEPENDS:= libpthread libutil
endef

define Package/libif/description
	The libif library provides a basic set of functions 
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
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libif.so.1.0 $(STAGING_DIR)/usr/lib/
	(cd $(STAGING_DIR)/usr/lib; $(LN) libif.so.1.0 libif.so.1;$(LN) libif.so.1.0 libif.so)
endef

define Package/libif/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libif.so.1.0 $(1)/usr/lib/
	(cd $(1)/usr/lib;$(LN) libif.so.1.0 libif.so.1;$(LN) libif.so.1.0 libif.so)
endef

$(eval $(call BuildPackage,libif))
