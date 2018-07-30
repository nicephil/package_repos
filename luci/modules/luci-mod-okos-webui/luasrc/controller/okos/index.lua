-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

local http = require "luci.http"
local syslog = require "nixio".syslog
local sys = require "luci.sys"
local json = require "luci.json"
local nw = require "luci.model.network".init()
local string = require "string"
local uci = require "luci.model.uci".cursor()

module("luci.controller.okos.index", package.seeall)

function index()
    local root = node()
    if not root.lock then
        root.target = alias("okos")
    end
    local page = entry({"okos"}, alias("okos", "haspasscode"), _("OKOS"))
    --page.sysauth = "root"
    --page.sysauth_authenticator = "htmlauth"

    entry({"okos", "haspasscode"}, call("action_haspasscode"), _("CheckHasPasscode"))
    entry({"okos", "login"}, call("action_login"), _("Login)"))
    entry({"okos", "internetstatus"}, call("action_internetstatus"), _("InternetStatus"))
    entry({"okos", "queryifs"}, call("action_queryifs"), _("QueryInterfaces"))
    entry({"okos", "configwan"}, call("action_configwan"), _("ConfigWAN"))
    entry({"okos", "renewip"}, call("action_renewip"), _("RenewIP"))
    entry({"okos", "diag"}, call("action_diag"), _("Diag"))
    entry({"okos", "querydiag"}, call("action_querydiag"), _("QueryDiag"))
    entry({"okos", "devumac"}, call("action_devumac"), _("DeviceUniqueMAC"))
    entry({"okos", "regdev"}, call("action_regdev"), _("RegDev"))
    entry({"okos", "setgre"}, call("action_setgre"), _("SetGRE"))
end

function dumptable(t)
    if type(t) ~= "table" then
        syslog("err", "LUCI:-> " .. tostring(t))
        return
    end
    for k,v in pairs(t) do
        syslog("err", "LUCI:-> " .. tostring(k) .. "\t" .. tostring(v))
        if type(v) == "table" then
            dumptable(v)
        end
    end
end

function sanity_check_json()
    -- sanity check
    local hm = http.getenv("REQUEST_METHOD")
    local ct = http.getenv("CONTENT_TYPE")
    if hm == "OPTIONS" then
        http.header("access-control-allow-credentials", "true")
        http.header("access-control-allow-methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE")
        http.header("access-control-allow-origin", "*")
        http.header("access-control-allow-headers", "content-type")
        http.header("content-type", "application/json")
        http.status(200, "OK") 
        http.close()
        return false
    elseif hm ~= "POST" or not ct:match("^application/json") then
        http.status(400, "Bad Request")
        http.close()
        return false
    end
    return true
end

function sanity_check_get()
    -- sanity check
    local hm = http.getenv("REQUEST_METHOD")
    if hm == "OPTIONS" then
        http.header("access-control-allow-credentials", "true")
        http.header("access-control-allow-methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE")
        http.header("access-control-allow-origin", "*")
        http.header("access-control-allow-headers", "content-type")
        http.header("content-type", "application/json")
        http.status(200, "OK") 
        http.close()
        return false
    elseif hm ~= "GET" then
        http.status(400, "Bad Request")
        http.close()
        return false
    end
    return true
end

function response_json(response)
    http.header("Access-Control-Allow-Origin", "*")
    http.header("Access-Control-Allow-Credentials", "true")
    http.prepare_content("application/json")
    http.write_json(response)
    http.close()
end

-- check if needs passcoe to login
function action_haspasscode()
    -- sanity check --
    if not sanity_check_get() then
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
        errcode = 0
    }
    ]]--

    -- no passcode
    if sys.user.checkpasswd("root", "oakridge") then
        response = { 
            errcode = 1
        }
    else -- has passcode
        response = { 
            errcode = 0
        }
    end

    -- response --
    response_json(response)

end

-- check login
function action_login()
    -- sanity check --
    if not sanity_check_json() then
        return
    end

    -- parse json
    local hc = http.content()
    local input, rc, err = json.decode(hc)
    local user = input.username
    local pass = input.password
    
    -- process --
    local response = { }
    --[[
    response = {
        errcode = 0
    }
    ]]--
    response.errcode = 0
    if user == nil or pass == nil then
        http.status(400, "Bad Request");
        http.close()
        return
    end

    -- incorrect
    if not sys.user.checkpasswd(user, pass) then
        response.errcode = 1
    end

    -- response --
    response_json(response)
end

-- check current internet status
function action_internetstatus()
    -- sanity check --
    if not sanity_check_get() then
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
        errcode = 0
    }
    ]]--
    response.errcode = 0
    if sys.net.pingtest("8.8.8.8") ~= 0 and sys.net.pingtest("114.114.114.114") ~= 0 then
        response.errcode = 1
    end

    -- response --
    response_json(response)
end

local p2l_names = { }                                             
p2l_names['eth0'] = 'e0'                            
p2l_names['eth1'] = 'e1'
p2l_names['eth2'] = 'e2'
p2l_names['eth3'] = 'e3'
p2l_names['br-lan4000'] = 'switch'          

function swport_is_up(ifname)
    local port = ifname:sub(-1)
    local str = sys.exec("swconfig dev switch0 port " .. port .. " show 2>/dev/null")
    if str == nil or str:match("up") == nil then
        return false
    else
        return true
    end
end

-- get all interfaces information
function action_queryifs()
    -- sanity check --
    if not sanity_check_get() then
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
    e4: {
        ifname = "eth0.4054",
        mac = "F0:9F:C2:6D:24:7F",
        proto = "dhcp",
        ipaddr = "192.165.1.183",
        netmask = "255.255.255.0",
        gateway = "192.165.1.254",
        dns = ["114.114.114.114", "8.8.8.8"],
        username = "oakridge", 
        password = "oakridge",
        mtu = "1500",
        sid = "WAN",
        up = "1"
    }
    switch: {
        ifname = "eth0.4050",
        mac = "F0:9F:C2:6D:24:7F",
        proto = "dhcp",
        ipaddr = "192.165.1.183",
        netmask = "255.255.255.0",
        gateway = "192.165.1.254",
        dns = ["114.114.114.114", "8.8.8.8"],
        username = "oakridge", 
        password = "oakridge",
        mtu = "1500"
        sid = "WAN",
        up = "1"
    }
    }
    ]]--
                                                           
   for _,nt in pairs(nw:get_networks()) do
        if nt.sid ~= "loopback" and not (nt.sid):match("gre") then
            local tp = nw:get_protocol("static", nt.sid)
            local np = nw:get_protocol(tp:get("proto"), nt.sid)            
            if np ~= nil then
            local npdev = np:get_interface()
            local ifname = np:ifname()
            if np:proto() == "pppoe" then
                ifname = np:get("ifname")
            end
            local lifname = p2l_names[ifname]
            response[#response+1] = { }
            local res = response[#response]
            res.lname = lifname
            res.ifname = ifname
            res.mac = npdev:mac()
            res.up = npdev:is_up()
            res.sid = nt.sid
            res.mtu = npdev:_ubus("mtu")
            if res.mtu == nil then
                res.mtu = np:get("mtu")
            end
            res.proto = np:proto()
            if res.up then
                res.ipaddr = np:ipaddr()            
                res.netmask = np:netmask()        
                res.gateway = np:gwaddr()
                res.dns = np:dnsaddrs()                                
            else
                -- not up, should get static from config
                if res.proto == "static" then
                    res.ipaddr = np:get("ipaddr")
                    res.netmask = np:get("netmask")
                    res.gateway = np:get("gateway")
                    res.dns = np:get("dns")
                end
            end
            res.username = np:get("username")                                                    
            res.password = np:get("password")              
            end                   
        end
    end      

        -- response --
    response_json(response)
    
end

-- config wan 
function action_configwan()
    -- sanity check --
    if not sanity_check_json() then
        return
    end
    
    -- parse json
    local hc = http.content()
    local input, rc, err = json.decode(hc)
    --[[
    input = {
        proto = "dhcp",
        lname = "e4",
        ifname = "eth0.4050",
        ipaddr = "192.165.1.168",
        netmask = "255.255.255.0",
        gateway = "192.165.1.254",
        dns = [ "192.165.1.254", "114.114.114.114" ],
        username = "oakridge",
        password = "oakridge",
        mtu = "1500"
    }
    ]]--
    if input.proto == nil or input.ifname == nil or input.ifname == "br-lan4000" then
        http.status(400, "Bad Request");
        http.close()
        return
    end
    if input.proto == "static" and (input.ipaddr == nil or input.netmask == nil or input.gateway == nil or input.dns == nil) then
        http.status(400, "Bad Request");
        http.close()
        return
    end
    if input.proto == "pppoe" and (input.username == nil or input.password == nil or input.mtu == nil) then
        http.status(400, "Bad Request");
        http.close()
        return
    end
    
    -- process --
    local response = {}
    --[[
    response = {
        errcode = 0
    }
    ]]--
    response.errcode = 0

    -- del existing ifname network
    local ifn = nw:get_interface(input.ifname)
    if ifn == nil then
        -- no vlan interface
        response.errcode = 1
        response_json(response)
        return
    else
        local n = ifn:get_network() 
        nw:del_network(n.sid)
    end
    -- del existing wan network
    local np = nw:get_protocol("dhcp", "wan")            
    local wifname = np:ifname()
    nw:del_network("wan")
    -- set free lan interface
    --if (wifname == input.ifname) then
    --    nw:add_network("lan" .. wifname:sub(4,-1), {proto="none", ifname=wifname})
    --end
    -- setup new network
    local net =  { }
    if input.proto == "static" then
        net = nw:add_network("wan", {proto=input.proto, ipaddr=input.ipaddr, netmask=input.netmask, gateway=input.gateway, dns=input.dns})
    elseif input.proto == "dhcp" then
        net = nw:add_network("wan", {proto=input.proto})
    elseif input.proto == "pppoe" then
        net = nw:add_network("wan", {proto=input.proto, username=input.username, password=input.password, mtu=input.mtu})
    end
    if net then
        net:add_interface(input.ifname)
        nw:commit("network")
    else
        response.errcode = 1
    end
    
    -- response --
    response_json(response)
end


-- do renew ip
function action_renewip()
    -- sanity check --
    if not sanity_check_json() then
        return
    end
    
    -- parse json
    local hc = http.content()
    local input, rc, err = json.decode(hc)
    --[[
    input = {
        lname = 'e0',
        ifname = 'eth0.4050'
    }
    ]]--

    -- process --
    -- del existing ifname network
    local ifn = nw:get_interface(input.ifname)
    if ifn == nil then
        -- no vlan interface
        response.errcode = 1
        response_json(response)
        return
    else
        local n = ifn:get_network() 
        nw:del_network(n.sid)
    end
    -- del existing wan network
    nw:del_network("wan")
    -- setup new network
    local net =  { }
    net = nw:add_network("wan", {proto="dhcp"})

    local response = { }
    --[[
    response = {
        lname = "e0",
        ifname = "eth0.4050",
        ipaddr = "192.165.1.183",
        netmask = "255.255.255.0",
        gateway = "192.165.1.254",
        dns = {"114.114.114.114", "8.8.8.8"},
        errcode = 0
    }
    ]]--
    if net then
        net:add_interface(input.ifname)
        nw:save("network")
        response.errcode = sys.call("ifdown wan;sleep 1;ifup wan;sleep 7")
        if response.errcode == 0 then
            local wanp = nw:get_protocol("dhcp", "wan") 
            response.lname = input.lname
            response.ifname = wanp:ifname()
            response.ipaddr = wanp:ipaddr()
            response.netmask = wanp:netmask()
            response.gateway = wanp:gwaddr()
            response.dns = wanp:dnsaddrs()
            response.errcode = 0
            if response.ipaddr == nil then
                response.errcode = 1
            end
            nw:revert("network")
            sys.call("ifdown wan; sleep 1; ifup wan")
        end
    else
        response.errcode = 1
    end
   
    -- response --
    response_json(response)
 
end

-- do diag
function action_diag()
    -- sanity check --
    if not sanity_check_get() then
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
        proto = "dhcp",
        step = 2,
        errcode = 0
    }
    ]]--
    sys.call("uci del_list dhcp.@dnsmasq[0].address='/#/172.16.254.254';/etc/init.d/dnsmasq reload;")
    sys.call("/etc/init.d/log restart;sleep 1")
    response.errcode = sys.call("ifdown wan; sleep 1; ifup wan;sleep 3")
    tmp = nw:get_protocol("static", "wan")
    response.proto = tmp:get("proto")

    if response.proto == "static" then
        response.step = 4
    elseif response.proto == "dhcp" then
        response.step = 3
    elseif response.proto == "pppoe" then
        response.step = 1
    end

    -- response --
    response_json(response)
end

-- query result
function action_querydiag()
    -- sanity check --
    if not sanity_check_json() then
        return
    end

    -- parse json
    local hc = http.content()
    local input, rc, err = json.decode(hc)
    --[[
    input = {
        step = 1
    }
    ]]--

    -- process--
    local response = { }
    --[[
    response = {
        step = 1
        errcode = 0 
    }
    ]]--
    response.errcode = -1
    response.step = input.step
    sys.call("sleep 2")
    local log = sys.syslog()
    local np =nw:get_protocol("static","wan")
    if input.step == 1 then
        if log:match("ppp") == nil then
            response.errcode = 1
            response.step = 1
        else
            if log:match("Unable to complete PPPoE Discovery") ~= nil then
                response.errcode = 1
                response.step = 1
            else
                response.errcode = 0
                response.step = 2
            end
        end
    elseif input.step == 2 then
        if log:match("ppp") == nil then
            response.errcode = 1
            response.step = 2
        else
            if log:match("authentication succeeded") == nil then
                response.errcode = 1
                response.step = 2
            else
                response.errcode = 0
                response.step = 3
            end
        end
    elseif input.step == 3 then
        if np:ipaddr() == nil then
            response.errcode = 1
            response.step = 3
        else
            response.errcode = 0
            response.step = 4
        end
    elseif input.step == 4 then
        if sys.net.pingtest("www.baidu.com") ~= 0 then
            response.step = 4
            response.errcode = 1
        else
            response.errcode = 0
            response.step = 5
        end
    elseif input.step == 5 then
        if sys.net.pingtest("cloud2.oakridge.io") ~=0 and sys.net.pingtest("cloud.oakridge.io") ~=0 then
            response.errcode = 1
            response.step = 5
        else
            response.errcode = 0
            response.step = -1
        end
    end

    if response.errcode == 1 then
        sys.call("uci revert dhcp;/etc/init.d/dnsmasq reload;sleep 3")
    end

    if response.errocode == 0 and response.step == -1 then
        sys.call("uci del_list dhcp.@dnsmasq[0].address='/#/172.16.254.254';uci commit dhcp;/etc/init.d/dnsmasq reload;sleep 3")
    end

    -- response --
    response_json(response)
end

-- fetch device unique mac
function action_devumac()
    -- sanity check --
    if not sanity_check_get() then
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
        errocode = 0,
        mac = "00:11:22:33:44:55",
        is_sysloader = 0
    }
    ]]--
    response.errcode = 0
    response.is_sysloader = 0
    response.mac = uci:get("productinfo", "productinfo", "mac") 
    local var = uci:get("productinfo", "productinfo", "swversion") or ""

    if (var == "") then
        response.is_sysloader = 1
    end

    -- response --
    response_json(response)
end

-- register device response from cloud
function action_regdev()
    -- sanity check --
    if not sanity_check_json() then
        return
    end
    
    -- parse json
    local hc = http.content()
    local input, rc, err = json.decode(hc)
    --[[
    input = {
        oakmgr = "192.168.254.60",
        passcode = "oakridge"
    }
    ]]--
    if input.oakmgr == nil or input.passcode == nil then
        http.status(400, "Bad Request");
        http.close()
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
        errcode = 0
    }
    ]]--
    response.errcode = 0

    response.errcode = sys.call("/sbin/uci set capwapc.server.mas_server=" .. input.oakmgr .. " && /sbin/uci commit capwapc")

    if response.errcode == 0 then
        response.errcode = sys.user.setpasswd("root", input.passcode)
    end
    
    -- response --
    response_json(response)
end

-- set gre interface from ap
function action_setgre()
    -- sanity check --
    if not sanity_check_json() then
        return
    end
    
    -- parse json
    local hc = http.content()
    local input, rc, err = json.decode(hc)
    --[[
    input = {
        has_guestnet = true,
        macaddr = "00:11:22:33:44:55",
        ipaddr = "172.16.0.120",
        gateway = "172.16.0.1",
        timestamp = 1234
    }
    ]]--
    if input.has_guestnet == nil or input.macaddr == nil or input.ipaddr == nil or
        input.gateway == nil then
        http.status(400, "Bad Request");
        http.close()
        return
    end

    -- process --
    local response = { }
    --[[
    response = {
        errcode = 0,
        isolate_guest = 1
    }
    ]]--
    response.errcode = 0
    
    -- 1. get which lan
    local nt
    local gresid
    for _,nt in pairs(nw:get_networks()) do
        local sid = nt.sid
        if sid:match("lan") then
            local np = nw:get_protocol("static", sid)
            if np:get("ipaddr") == input.gateway then
                gresid = sid
                break
            end
        end
    end

    -- 2. which gre bridge lan
    -- lanxxxx - grexxxx gre bridge
    gresid = gresid:gsub("lan","gre")

    response.isolate_guest = false
    for _,nt in pairs(nw:get_networks()) do
        local sid = nt.sid
        if sid:match(gresid) then
            response.isolate_guest = true
        end
    end

    -- 3. which greinterface
    local grenetsid = (input.macaddr):gsub(":","")
    grenetsid = grenetsid:sub(4,-1)
    local grenet = nw:get_protocol("static", grenetsid)
    if grenet:get("proto") ~= "gretap" then
        grenet = nil
    end
    local change = false
    
    if input.has_guestnet and response.isolate_guest then
        -- setup new gre network if no existing gre interface
        if grenet == nil then
            grenet = nw:add_network(grenetsid, {proto="gretap", ipaddr=input.gateway, peeraddr=input.ipaddr, network=gresid})
            change = true
        else
            if grenet:get("ipaddr") ~= input.gateway then
                grenet:set("ipaddr", input.gateway)
                change = true
            end
            if grenet:get("peeraddr") ~= input.ipaddr then
                grenet:set("peeraddr", input.ipaddr)
                change = true
            end
            if grenet:get("network") ~= gresid then
                grenet:set("network", gresid)
                change = true
            end
        end
    else
        -- no guest network, delete protential virtual gre interface
        -- del existing virtual gre interface network
        if grenet ~= nil then
            nw:del_network(grenetsid)
            change = true
        end
    end

    if change then
        nw:commit("network")
        sys.call("/etc/init.d/network restart")
    end


    -- response --
    response_json(response)
end


