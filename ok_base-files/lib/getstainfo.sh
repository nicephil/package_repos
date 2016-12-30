
#!/bin/sh
         
wlanconfig ath0 list sta  | awk -F' ' '{
                                        
if (NF > 1 && NR ==1) {                 
    print "config client"               
} else if (NR > 1) {     
    print "\toption ssid ath0"
    print "\toption addr "$1  
    print "\toption chan "$3  
    print "\toption rssi "$6
    print "\toption assoctime "$17
}                                 
}' > /tmp/stationinfo             
                            
wlanconfig ath1 list sta  | awk -F' ' '{
                                        
if (NF > 1 && NR ==1) {                 
    print "config client"               
} else if (NR > 1) {     
    print "\toption ssid ath0"
    print "\toption addr "$1  
    print "\toption chan "$3  
    print "\toption rssi "$6
    print "\toption assoctime "$17
}                                 
}' >> /tmp/stationinfo
