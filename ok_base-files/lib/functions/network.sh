# 1: destination variable
# 2: interface
# 3: path
# 4: separator
# 5: limit
__network_ifstatus() {
	local __tmp

	[ -z "$__NETWORK_CACHE" ] && \
		export __NETWORK_CACHE="$(ubus call network.interface dump)"

	__tmp="$(jsonfilter ${4:+-F "$4"} ${5:+-l "$5"} -s "$__NETWORK_CACHE" -e "$1=@.interface${2:+[@.interface='$2']}$3")"

	[ -z "$__tmp" ] && \
		unset "$1" && \
		return 1

	eval "$__tmp"
}

# determine first IPv4 address of given logical interface
# 1: destination variable
# 2: interface
network_get_ipaddr() {
	__network_ifstatus "$1" "$2" "['ipv4-address'][0].address";
}

# determine first IPv6 address of given logical interface
# 1: destination variable
# 2: interface
network_get_ipaddr6() {
	__network_ifstatus "$1" "$2" "['ipv6-address'][0].address" || \
		__network_ifstatus "$1" "$2" "['ipv6-prefix-assignment'][0]['local-address'].address" || \
		return 1
}

# determine first IPv4 subnet of given logical interface
# 1: destination variable
# 2: interface
network_get_subnet() {
	__network_ifstatus "$1" "$2" "['ipv4-address'][0]['address','mask']" "/"
}

# determine first IPv6 subnet of given logical interface
# 1: destination variable
# 2: interface
network_get_subnet6() {
	local __nets __addr

	if network_get_subnets6 __nets "$2"; then
		# Attempt to return first non-fe80::/10, non-fc::/7 range
		for __addr in $__nets; do
			case "$__addr" in fe[8ab]?:*|f[cd]??:*)
				continue
			esac
			export "$1=$__addr"
			return 0
		done

		# Attempt to return first non-fe80::/10 range
		for __addr in $__nets; do
			case "$__addr" in fe[8ab]?:*)
				continue
			esac
			export "$1=$__addr"
			return 0
		done

		# Return first item
		for __addr in $__nets; do
			export "$1=$__addr"
			return 0
		done
	fi

	unset "$1"
	return 1
}

# determine first IPv6 prefix of given logical interface
# 1: destination variable
# 2: interface
network_get_prefix6() {
	__network_ifstatus "$1" "$2" "['ipv6-prefix'][0]['address','mask']" "/"
}

# determine all IPv4 addresses of given logical interface
# 1: destination variable
# 2: interface
network_get_ipaddrs() {
	__network_ifstatus "$1" "$2" "['ipv4-address'][*].address"
}

# determine all IPv6 addresses of given logical interface
# 1: destination variable
# 2: interface
network_get_ipaddrs6() {
	local __addr
	local __list=""

	if __network_ifstatus "__addr" "$2" "['ipv6-address'][*].address"; then
		for __addr in $__addr; do
			__list="${__list:+$__list }${__addr}"
		done
	fi

	if __network_ifstatus "__addr" "$2" "['ipv6-prefix-assignment'][*]['local-address'].address"; then
		for __addr in $__addr; do
			__list="${__list:+$__list }${__addr}"
		done
	fi

	if [ -n "$__list" ]; then
		export "$1=$__list"
		return 0
	fi

	unset "$1"
	return 1
}

# determine all IP addresses of given logical interface
# 1: destination variable
# 2: interface
network_get_ipaddrs_all() {
	local __addr __addr6

	network_get_ipaddrs __addr "$2"
	network_get_ipaddrs6 __addr6 "$2"

	if [ -n "$__addr" -o -n "$__addr6" ]; then
		export "$1=${__addr:+$__addr }$__addr6"
		return 0
	fi

	unset "$1"
	return 1
}

# determine all IPv4 subnets of given logical interface
# 1: destination variable
# 2: interface
network_get_subnets() {
	__network_ifstatus "$1" "$2" "['ipv4-address'][*]['address','mask']" "/ "
}

# determine all IPv6 subnets of given logical interface
# 1: destination variable
# 2: interface
network_get_subnets6() {
	local __addr __mask
	local __list=""

	if __network_ifstatus "__addr" "$2" "['ipv6-address'][*]['address','mask']" "/ "; then
		for __addr in $__addr; do
			__list="${__list:+$__list }${__addr}"
		done
	fi

	if __network_ifstatus "__addr" "$2" "['ipv6-prefix-assignment'][*]['local-address'].address" && \
	   __network_ifstatus "__mask" "$2" "['ipv6-prefix-assignment'][*].mask"; then
		for __addr in $__addr; do
			__list="${__list:+$__list }${__addr}/${__mask%% *}"
			__mask="${__mask#* }"
		done
	fi

	if [ -n "$__list" ]; then
		export "$1=$__list"
		return 0
	fi

	unset "$1"
	return 1
}

# determine all IPv6 prefixes of given logical interface
# 1: destination variable
# 2: interface
network_get_prefixes6() {
	__network_ifstatus "$1" "$2" "['ipv6-prefix'][*]['address','mask']" "/ "
}

# determine IPv4 gateway of given logical interface
# 1: destination variable
# 2: interface
# 3: consider inactive gateway if "true" (optional)
network_get_gateway() {
	__network_ifstatus "$1" "$2" ".route[@.target='0.0.0.0' && !@.table].nexthop" "" 1 && \
		return 0

	[ "$3" = 1 -o "$3" = "true" ] && \
		__network_ifstatus "$1" "$2" ".inactive.route[@.target='0.0.0.0' && !@.table].nexthop" "" 1
}

# determine IPv6 gateway of given logical interface
# 1: destination variable
# 2: interface
# 3: consider inactive gateway if "true" (optional)
network_get_gateway6() {
	__network_ifstatus "$1" "$2" ".route[@.target='::' && !@.table].nexthop" "" 1 && \
		return 0

	[ "$3" = 1 -o "$3" = "true" ] && \
		__network_ifstatus "$1" "$2" ".inactive.route[@.target='::' && !@.table].nexthop" "" 1
}

# determine the DNS servers of the given logical interface
# 1: destination variable
# 2: interface
# 3: consider inactive servers if "true" (optional)
network_get_dnsserver() {
	__network_ifstatus "$1" "$2" "['dns-server'][*]" && return 0

	[ "$3" = 1 -o "$3" = "true" ] && \
		__network_ifstatus "$1" "$2" ".inactive['dns-server'][*]"
}

# determine the domains of the given logical interface
# 1: destination variable
# 2: interface
# 3: consider inactive domains if "true" (optional)
network_get_dnssearch() {
	__network_ifstatus "$1" "$2" "['dns-search'][*]" && return 0

	[ "$3" = 1 -o "$3" = "true" ] && \
		__network_ifstatus "$1" "$2" ".inactive['dns-search'][*]"
}


# 1: destination variable
# 2: addr
# 3: inactive
__network_wan()
{
	__network_ifstatus "$1" "" \
		"[@.route[@.target='$2' && !@.table]].interface" "" 1 && \
			return 0

	[ "$3" = 1 -o "$3" = "true" ] && \
		__network_ifstatus "$1" "" \
			"[@.inactive.route[@.target='$2' && !@.table]].interface" "" 1
}

# find the logical interface which holds the current IPv4 default route
# 1: destination variable
# 2: consider inactive default routes if "true" (optional)
network_find_wan() { __network_wan "$1" "0.0.0.0" "$2"; }

# find the logical interface which holds the current IPv6 default route
# 1: destination variable
# 2: consider inactive dafault routes if "true" (optional)
network_find_wan6() { __network_wan "$1" "::" "$2"; }

# test whether the given logical interface is running
# 1: interface
network_is_up()
{
	local __up
	__network_ifstatus "__up" "$1" ".up" && [ "$__up" = 1 ]
}

# determine the protocol of the given logical interface
# 1: destination variable
# 2: interface
network_get_protocol() { __network_ifstatus "$1" "$2" ".proto"; }

# determine the layer 3 linux network device of the given logical interface
# 1: destination variable
# 2: interface
network_get_device() { __network_ifstatus "$1" "$2" ".l3_device"; }

# determine the layer 2 linux network device of the given logical interface
# 1: destination variable
# 2: interface
network_get_physdev() { __network_ifstatus "$1" "$2" ".device"; }

# defer netifd actions on the given linux network device
# 1: device name
network_defer_device()
{
	ubus call network.device set_state \
		"$(printf '{ "name": "%s", "defer": true }' "$1")" 2>/dev/null
}

# continue netifd actions on the given linux network device
# 1: device name
network_ready_device()
{
	ubus call network.device set_state \
		"$(printf '{ "name": "%s", "defer": false }' "$1")" 2>/dev/null
}

# OK_PATCH

# get netmask
# 1: variable for netmask
# 2: virtual network
network_get_netmask()
{
    local __nmask
    network_get_subnet __nmask "$2"
    __nmask=$(ipcalc.sh $__nmask | awk -F'=' '/NETMASK/{print $2}')
    [ -z $__nmask ] && return 1
    export "$1=${__nmask}"
    return 0
}

# get virtual network status
# 1: variable for phy status
# 2: virtual interface
network_get_status()
{
	__network_ifstatus "$1" "$2" ".up"
}

# 1: destination variable
# 2: device if
# 3: path
# 4: separator
# 5: limit
__network_devstatus() {
	local __tmp

	[ -z "$__DEVICE_CACHE" ] && \
		export __DEVICE_CACHE="$(ubus call network.device status)"

	__tmp="$(jsonfilter ${4:+-F "$4"} ${5:+-l "$5"} -s "$__DEVICE_CACHE" -e "$1=@['$2']$3")"

	[ -z "$__tmp" ] && \
		unset "$1" && \
		return 1

	eval "$__tmp"
}

# get macaddr
# 1: destination variable for macaddr
# 2: physical device
network_get_macaddr()
{
    __network_devstatus "$1" "$2" "['macaddr']"
}

# get all interfaces
# 1: destination variable
network_get_interfaces()
{
    ifs="`ubus list | awk -F '.' '/interface./{if(!match($3,"loopback")&&length($3)!=9)print $3}'`"
    export "$1=$ifs"
    return 0
}

# get logic name
# 1: destination variable
# 2: pname
network_get_lname()
{
    local var="$1"
    local lname=""
    local pname="$2"
    local gre=0
    if [ "${pname:0:6}" = "br-gre" ]
    then
        gre=1
        if [ "$pname" = "br-gre4000" ]
        then
            pname="br-lan${pname:6}"
        else
            pname="eth0.${pname:6}"
        fi
    fi

    case "$pname" in
        "br-lan4000")
            lname="switch"
            ;;
        "eth0")
            lname="e0"
            ;;
        "eth1")
            lname="e1"
            ;;
        "eth2")
            lname="e2"
            ;;
        "eth3")
            lname="e3"
            ;;
        *)
            echo "unknow interface"
            return 1
            ;;
    esac
    
    if [ "$gre" = "1" ]
    then
        lname="${lname}.guest"
    fi

    unset "$var"
    export "$var=$lname"
    return 0
}


# get uptime
# 1: destination variable
# 2: network
network_get_uptime()
{
    __network_ifstatus "$1" "$2" ".uptime";
}

# get link, speed and duplex
# 1: destination variable for link
# 2: destination variable for speed 
# 3: destination variable for duplex
# 4: phsical device
network_get_phy_status()
{
    local f_link=$1
    local f_speed=$2
    local f_duplex=$3
    local __ifname=$4
    unset $f_link
    unset $f_speed
    unset $f_duplex
    [ -z "$__ifname" ] && return 1
    
    local __tmp=$(ethtool $__ifname | awk -v OFS='|' -F'[: ]+' '/Speed/{speed=substr($2,0,length($2)-4)}/Duplex/{duplex=$2}/Link detected/{link=$3}END{print link,speed,duplex}')
    [ -z "$__tmp" ] && return 1
    OIFS=$IFS;IFS='|';set -- $__tmp;__link=$1;__speed=$2;__duplex=$3;IFS=$OIFS

    if [ "$__link" = "yes" ]
    then
        export "$f_link=1"
        export "$f_speed=${__speed}"
        if [ "$__duplex" = "Full" ]
        then
            export "$f_duplex=1"
        else
            export "$f_duplex=0"
        fi
    else
        export "$f_link=0"
        export "$f_speed=0"
        export "$f_duplex=0"
    fi

    return 0
}

# get bridge-members, reserve vlan4000 for bridge
# 1: destination variable for bridge-members
network_get_bmembers()
{
    local __tmp=$(swconfig dev switch0 vlan 4000 show | awk -F':' '/ports/{print $2}')
    [ -z "$__tmp" ] && return 1

    export "$1=${__tmp%6*}"
    return 0
}

# determine the metric of the given logical interface
# 1: destination variable
# 2: interface
network_get_metric() { __network_ifstatus "$1" "$2" ".metric"; }

# flush the internal value cache to force re-reading values from ubus
network_flush_cache() { unset __NETWORK_CACHE; unset __DEVICE_CACHE; }

#endo of OK_PATCH
