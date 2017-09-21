-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

local http = require "luci.http"
local syslog = require "nixio".syslog
local sys = require "luci.sys"
local json = require "luci.json"
local nw = require "luci.model.network".init()
local string = require "string"

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
    entry({"okos", "regdev"}, call("action_regdev"), _("RegDev"))
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
    if sys.net.pingtest("139.196.188.253") ~= 0 then
        response.errcode = 1
    end

    -- response --
    response_json(response)
end

local p2l_names = { }                                             
p2l_names['eth0.4090'] = 'e0'                            
p2l_names['eth0.4091'] = 'e1'
p2l_names['eth0.4092'] = 'e2'
p2l_names['eth0.4093'] = 'e3'
p2l_names['eth0.4094'] = 'e4'
p2l_names['br-lan'] = 'switch'          


local l2p_names = { }                                             
l2p_names['e0'] = 'eth0.4090'                            
l2p_names['e1'] = 'eth0.4091'
l2p_names['e2'] = 'eth0.4092'
l2p_names['e3'] = 'eth0.4093'
l2p_names['e4'] = 'eth0.4094'
l2p_names['switch'] = 'br-lan'          



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
        ifname = "eth0.4094",
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
        ifname = "eth0.4090",
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
        if nt.sid ~= "loopback" then
            local tp = nw:get_protocol("static", nt.sid)
            local np = nw:get_protocol(tp:get("proto"), nt.sid)            
            if np ~= nil then
            local npdev = np:get_interface()
            local ifname = np:ifname()
            ifname = p2l_names[ifname]
            response[ifname] = { }
            local res = response[ifname]
            res.ifname = np:ifname()
            res.mac = npdev:mac()
            res.up = npdev:is_up()
            res.sid = nt.sid
            res.mtu = npdev:_ubus("mtu")
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
        ifname = "eth0.4090",
        ipaddr = "192.165.1.168",
        netmask = "255.255.255.0",
        gateway = "192.165.1.254",
        dns = [ "192.165.1.254", "114.114.114.114" ],
        username = "oakridge",
        password = "oakridge",
        mtu = "1500"
    }
    ]]--
    if input.proto == nil or input.ifname == nil then
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
    input.ifname = l2p_names[input.ifname]
    local ifn = nw:get_interface(input.ifname)
    if ifn == nil then
        -- no vlan interface
        response.errcode = 1
        dumptable(response)
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
    if not sanity_check_get() then
        return
    end

    -- process --
    sys.call("killall -SIGUSR1 udhcpc; sleep 10")
    
    local response = { }
    --[[
    response = {
        ifname = "eth0.4090",
        ipaddr = "192.165.1.183",
        netmask = "255.255.255.0",
        gateway = "192.165.1.254",
        dns = {"114.114.114.114", "8.8.8.8"},
        errcode = 0
    }
    ]]--
    local wanp = nw:get_protocol("dhcp", "wan") 
    response.ifname = wanp:ifname()
    response.ipaddr = wanp:ipaddr()
    response.netmask = wanp:netmask()
    response.gateway = wanp:gwaddr()
    response.dns = wanp:dnsaddrs()
    response.errcode = 0

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
    response.errcode = sys.call("env -i /bin/ubus call network reload")
    sys.call("/etc/init.d/log restart")
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
    local log = sys.dmesg()
    if input.step == 1 then
        if log:match("ppp") == nil then
            response.errcode = -1
        else
            if log:match("Unable to complete PPPoE Discovery") ~= nil then
                response.errcode = 1
            else
                response.errcode = 0
            end
            response.step = 2
        end
    elseif input.step == 2 then
        if log:match("ppp") == nil then
            response.errcode = -1
        else
            if log:match("Unable to complete PPPoE Discovery") ~= nil then
                response.errcode = 1
            else
                response.errcode = 0
            end
            response.step = 3
        end
    elseif input.step == 3 then
        if log:match("netifd: wan .*: udhcpc: performing DHCP renew") == nil then
            response.errcode = 1
        else
            if log:match("netifd: wan .* : udhcpc: .* obtained") == nil then
                response.errcode = 1
            else
                response.errcode = 0
            end
            response.step = 4
        end
    elseif input.step == 4 then
        if sys.net.pingtest("www.baidu.com") ~= 0 then
            response.step = 5
            response.errcode = 1
        end
    elseif input.step == 5 then
        if sys.net.pingtest("cloud.oakridge.vip") ~=0 then
            response.errcode = 1
            response.step = -1
        end
    end

    -- response --
    response_json(response)
end

-- register device
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

    response.errcode = sys.call("/sbin/uci set capwapc.server.mas_server=" .. input.oakmgr .. " && /sbin/uci commit capwapc && /etc/init.d/capwapc restart")

    if response.errcode == 0 then
        response.errcode = sys.user.setpasswd("root", input.passcode)
    end
    
    -- response --
    response_json(response)
end
