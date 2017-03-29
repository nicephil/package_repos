#!/bin/sh

. /lib/functions.sh


radios='wifi0 wifi1'
aths=''

for rd in $radios
do
    config_load wireless
    config_get _service_templates $rd bind
    
    rdidx=${rd:4} 
    #echo $rdidx $_service_templates
    
    config_load wlan_service_template
    for st in $_service_templates
    do
        config_get _static_uprate $st static_uplink_ratelimit
        config_get _static_downrate $st static_downlink_ratelimit
        
        config_get _dynamic_uprate $st dynamic_uplink_ratelimit
        config_get _dynamic_downrate $st dynamic_downlink_ratelimit
        
        stid=${st##*[^0-9]}
        #echo "==>"$stid $_static_uprate $_static_downrate 
        #echo "xxx=>"$_dynamic_uprate $_dynamic_downrate
        
        [ "$_static_uprate" != "0" -a "$_static_downrate" != "0" ] && {
            ath="ath$rdidx$stid"
            echo "Static==>$ath $_static_uprate $_static_downrate" 
            /lib/okos/ratelimit.sh -r $ath
            /lib/okos/ratelimit.sh -i $ath -b $_static_uprate $_static_downrate
        }
        
        [ "$_dynamic_uprate" != "0" -a "$_dynamic_downrate" != "0" ] && {
            ath="ath$rdidx$stid"
            echo "Dynamic==>$ath $_dynamic_uprate $_dynamic_downrate"
            /lib/okos/ratelimit.sh -r $ath
            /lib/okos/ratelimit.sh -i $ath -l $_dynamic_uprate $_dynamic_downrate
        }
        
    done
    
done


