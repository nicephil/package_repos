#
# Copyright (C) 2015-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=speedtest-cli
PKG_VERSION:=2.0.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/sivel/speedtest-cli/tar.gz/v${PKG_VERSION}
PKG_MD5SUM:=0c2084abab6b4afc4743318f2786e0f8

PKG_BUILD_DEPENDS:=python python-setuptools

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE.rst
PKG_MAINTAINER:=Jeffery To <jeffery.to@gmail.com>

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/speedtest-cli
	SECTION:=lang
	CATEGORY:=Languages
	SUBMENU:=Python
	TITLE:=speedtest-cli
	URL:=https://github.com/sivel/speedtest-cli
	DEPENDS:=+python-light +python-setuptools
endef

define Package/speedtest-cli/description
Command line interface for testing internet bandwidth using speedtest.net
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix=/usr --root=$(PKG_INSTALL_DIR))
endef

$(eval $(call PyPackage,speedtest-cli))
$(eval $(call BuildPackage,speedtest-cli))
