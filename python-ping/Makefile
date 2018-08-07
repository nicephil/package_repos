#
# Copyright (C) 2015-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-ping
PKG_VERSION:=0.2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/03/ac/9a3f332f8d7d27cd8929922b2e225842c1623760364b37fc79dc0f65e77d/$(PKG_SOURCE)
PKG_MD5SUM:=623f6ed2ca6f0e0ad845c925c1cf464d

PKG_BUILD_DEPENDS:=python python-setuptools

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE.rst
PKG_MAINTAINER:=Jeffery To <jeffery.to@gmail.com>

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-ping
	SECTION:=lang
	CATEGORY:=Languages
	SUBMENU:=Python
	TITLE:=python-ping
	URL:=https://github.com/kjd/ping
	DEPENDS:=+python-light
endef

define Package/python-ping/description
A library to support the Internationalised Domain Names in Applications
(ping) protocol as specified in RFC 5891. This version of the protocol
is often referred to as "ping2008" and can produce different results
from the earlier standard from 2003.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix=/usr --root=$(PKG_INSTALL_DIR))
endef

$(eval $(call PyPackage,python-ping))
$(eval $(call BuildPackage,python-ping))
