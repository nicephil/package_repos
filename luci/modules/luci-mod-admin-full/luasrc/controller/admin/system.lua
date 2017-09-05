-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008-2011 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.admin.system", package.seeall)

function index()

	entry({"admin", "system"}, alias("admin", "system", "admin"), _("System"), 30).index = true
	entry({"admin", "system", "admin"}, cbi("admin_system/admin"), _("Administration"), 2)

	entry({"admin", "system", "reboot"}, template("admin_system/reboot"), _("Reboot"), 90)
	entry({"admin", "system", "reboot", "call"}, post("action_reboot"))
end


local function supports_reset()
	return (os.execute([[grep -sqE '"rootfs_data"|"ubi"' /proc/mtd]]) == 0)
end

function action_reset()
	if supports_reset() then
		luci.template.render("admin_system/applyreboot", {
			title = luci.i18n.translate("Erasing..."),
			msg   = luci.i18n.translate("The system is erasing the configuration partition now and will reboot itself when finished."),
			addr  = "192.168.1.1"
		})

		fork_exec("sleep 1; killall dropbear uhttpd; sleep 1; jffs2reset -y && reboot")
		return
	end

	http.redirect(luci.dispatcher.build_url('admin/system/flashops'))
end

function action_passwd()
	local p1 = luci.http.formvalue("pwd1")
	local p2 = luci.http.formvalue("pwd2")
	local stat = nil

	if p1 or p2 then
		if p1 == p2 then
			stat = luci.sys.user.setpasswd("root", p1)
		else
			stat = 10
		end
	end

	luci.template.render("admin_system/passwd", {stat=stat})
end

function action_reboot()
	luci.sys.reboot()
end
