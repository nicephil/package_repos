#
# Copyright (C) 2008-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-memoryprofiler
PKG_VERSION:=0.52.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/23/11/50a969d32a14cdec2cfd57bee2e67fd6f83715a04361ba230dbce562b9cb/memory_profiler-0.52.0.tar.gz
PKG_MD5SUM:=e9ef5e7badd9839ab9f06c9e70688678

PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-memoryprofiler
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Universal Encoding Detector
  URL:=http://memoryprofiler.feedparser.org/
  DEPENDS:=+python +python-memoryprofiler
endef

define Package/python-memoryprofiler/description
  Character encoding auto-detection in Python.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-memoryprofiler/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-memoryprofiler))
