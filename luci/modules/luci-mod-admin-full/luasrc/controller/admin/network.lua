-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2011-2015 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.admin.network", package.seeall)

function index()
    local uci = require("luci.model.uci").cursor()
    local page

    page = node("admin", "network")
    page.target = firstchild()
    page.title  = _("Network")
    page.order  = 50
    page.index  = true

    page = entry({"admin", "network", "iface_add"}, cbi("admin_network/iface_add"), nil)
    page.leaf = true

    page = entry({"admin", "network", "iface_delete"}, post("iface_delete"), nil)
    page.leaf = true

    page = entry({"admin", "network", "iface_status"}, call("iface_status"), nil)
    page.leaf = true

    page = entry({"admin", "network", "iface_reconnect"}, post("iface_reconnect"), nil)
    page.leaf = true

    page = entry({"admin", "network", "iface_shutdown"}, post("iface_shutdown"), nil)
    page.leaf = true

    page = entry({"admin", "network", "network"}, arcombine(cbi("admin_network/network"), cbi("admin_network/ifaces")), _("Interfaces"), 10)
    page.leaf   = true
    page.subindex = true

    if page.inreq then
        uci:foreach("network", "interface",
        function (section)
            local ifc = section[".name"]
            if ifc ~= "loopback" then
                entry({"admin", "network", "network", ifc},
                true, ifc:upper())
            end
        end)
    end


    page = node("admin", "network", "diagnostics")
    page.target = template("admin_network/diagnostics")
    page.title  = _("Diagnostics")
    page.order  = 60

    page = entry({"admin", "network", "diag_ping"}, post("diag_ping"), nil)
    page.leaf = true

    page = entry({"admin", "network", "diag_nslookup"}, post("diag_nslookup"), nil)
    page.leaf = true

    page = entry({"admin", "network", "diag_traceroute"}, post("diag_traceroute"), nil)
    page.leaf = true

    page = entry({"admin", "network", "diag_ping6"}, post("diag_ping6"), nil)
    page.leaf = true

    page = entry({"admin", "network", "diag_traceroute6"}, post("diag_traceroute6"), nil)
    page.leaf = true
end

function iface_status(ifaces)
	local netm = require "luci.model.network".init()
	local rv   = { }

	local iface
	for iface in ifaces:gmatch("[%w%.%-_]+") do
		local net = netm:get_network(iface)
		local device = net and net:get_interface()
		if device then
			local data = {
				id         = iface,
				proto      = net:proto(),
				uptime     = net:uptime(),
				gwaddr     = net:gwaddr(),
				ipaddrs    = net:ipaddrs(),
				ip6addrs   = net:ip6addrs(),
				dnsaddrs   = net:dnsaddrs(),
				ip6prefix  = net:ip6prefix(),
				name       = device:shortname(),
				type       = device:type(),
				ifname     = device:name(),
				macaddr    = device:mac(),
				is_up      = device:is_up(),
				rx_bytes   = device:rx_bytes(),
				tx_bytes   = device:tx_bytes(),
				rx_packets = device:rx_packets(),
				tx_packets = device:tx_packets(),

				subdevices = { }
			}

			for _, device in ipairs(net:get_interfaces() or {}) do
				data.subdevices[#data.subdevices+1] = {
					name       = device:shortname(),
					type       = device:type(),
					ifname     = device:name(),
					macaddr    = device:mac(),
					macaddr    = device:mac(),
					is_up      = device:is_up(),
					rx_bytes   = device:rx_bytes(),
					tx_bytes   = device:tx_bytes(),
					rx_packets = device:rx_packets(),
					tx_packets = device:tx_packets(),
				}
			end

			rv[#rv+1] = data
		else
			rv[#rv+1] = {
				id   = iface,
				name = iface,
				type = "ethernet"
			}
		end
	end

	if #rv > 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json(rv)
		return
	end

	luci.http.status(404, "No such device")
end

function iface_reconnect(iface)
	local netmd = require "luci.model.network".init()
	local net = netmd:get_network(iface)
	if net then
		luci.sys.call("env -i /sbin/ifup %q >/dev/null 2>/dev/null" % iface)
		luci.http.status(200, "Reconnected")
		return
	end

	luci.http.status(404, "No such interface")
end

function iface_shutdown(iface)
	local netmd = require "luci.model.network".init()
	local net = netmd:get_network(iface)
	if net then
		luci.sys.call("env -i /sbin/ifdown %q >/dev/null 2>/dev/null" % iface)
		luci.http.status(200, "Shutdown")
		return
	end

	luci.http.status(404, "No such interface")
end

function iface_delete(iface)
	local netmd = require "luci.model.network".init()
	local net = netmd:del_network(iface)
	if net then
		luci.sys.call("env -i /sbin/ifdown %q >/dev/null 2>/dev/null" % iface)
		luci.http.redirect(luci.dispatcher.build_url("admin/network/network"))
		netmd:commit("network")
		netmd:commit("wireless")
		return
	end

	luci.http.status(404, "No such interface")
end

function diag_command(cmd, addr)
	if addr and addr:match("^[a-zA-Z0-9%-%.:_]+$") then
		luci.http.prepare_content("text/plain")

		local util = io.popen(cmd % addr)
		if util then
			while true do
				local ln = util:read("*l")
				if not ln then break end
				luci.http.write(ln)
				luci.http.write("\n")
			end

			util:close()
		end

		return
	end

	luci.http.status(500, "Bad address")
end

function diag_ping(addr)
	diag_command("ping -c 5 -W 1 %q 2>&1", addr)
end

function diag_traceroute(addr)
	diag_command("traceroute -q 1 -w 1 -n %q 2>&1", addr)
end

function diag_nslookup(addr)
	diag_command("nslookup %q 2>&1", addr)
end

function diag_ping6(addr)
	diag_command("ping6 -c 5 %q 2>&1", addr)
end

function diag_traceroute6(addr)
	diag_command("traceroute6 -q 1 -w 2 -n %q 2>&1", addr)
end
