#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=Arpwatch-NG-VLAN
PKG_VERSION:=1.7
PKG_RELEASE:=3

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).zip
PKG_SOURCE_URL:=https://github.com/SgtMalicious/Arpwatch-NG-VLAN.git
PKG_MD5SUM:=4c7921f0a731a67a87e5ad6499dafda6

# use a subdirectory to prevent configure for finding libpcap build dir
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/Arpwatch-NG-VLAN
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap +libsqlite3
  TITLE:=Ethernet station activity monitor
  URL:=http://www-nrg.ee.lbl.gov/
endef

define Package/Arpwatch-NG-VLAN/description
	Ethernet monitor program for keeping track of ethernet/ip address
	pairings.
endef

define Package/Arpwatch-NG-VLAN/conffiles
/etc/arpwatch/arp.dat
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	chmod -R u+w $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		ARPDIR=/etc/arpwatch \
		CCOPT="$(TARGET_CFLAGS)" \
		INCLS="-I. $(TARGET_CPPFLAGS)" \
		LIBS="$(TARGET_LDFLAGS) -lpcap -lsqlite3"
endef

define Package/Arpwatch-NG-VLAN/install
	$(INSTALL_DIR) $(1)/etc/arpwatch
	$(CP) $(PKG_BUILD_DIR)/arp.dat $(1)/etc/arpwatch/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/arpwatch $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/arpwatch.init $(1)/etc/init.d/arpwatch
endef

$(eval $(call BuildPackage,Arpwatch-NG-VLAN))
