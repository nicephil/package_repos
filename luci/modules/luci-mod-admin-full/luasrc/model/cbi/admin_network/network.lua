-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

local fs = require "nixio.fs"

m = Map("network", translate("Interfaces"))
m.pageaction = false
m:section(SimpleSection).template = "admin_network/iface_overview"

return m
