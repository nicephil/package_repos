(function () {
  'use strict'
  angular.module("oak.config")
    .component('configLanView', {
      templateUrl: 'apps/config/lanconfig/view.html',
      controller: function ($state, CommonService, ConfigService, MessageService) {
        var self = this;  
        self.wan_eths = [];
        self.lan_eths = [];
        self.data = {};
        self.eth_config = {};
        self.dhcp_monitor = {};   
        self.diag = {}; 

        self.$onInit = function () {
          self.diag = $state.params.data || {};
          ConfigService.getDeviceInterfaces().then(function(data){
            self.interfaces = data;
            var lanIndex = 1, wanIndex = 1;         
            angular.forEach(self.interfaces, function(intf){
              if(intf.sid.indexOf('wan') > -1){
                //WAN1 (e0, Linked up, 1Gbps, Full duplex)
                intf.display =  "WAN" + wanIndex + "( " + intf.lname + "," + " Linked " + ( intf.up ? " up" : " down" ) + " )"
                self.wan_eths.push(intf);                
              }else if(intf.sid.indexOf('lan') > -1){
                //LAN1 (e4, Linked up, 1Gbps, Full duplex)
                intf.display =  "LAN" + lanIndex + "( " + intf.lname + "," + " Linked " + ( intf.up ? " up" : " down" ) + " )"
                self.lan_eths.push(intf);
              }               
            })

            self.interfaces.sort(function(intf1, intf2){            
              return intf1.lname > intf2.lname ? 1 : -1;
            })

            if(self.lan_eths.length === 0) return;
            self.eth_config = self.lan_eths[0];
            self.data.netmask = netmask2CIDR(self.eth_config.netmask);
            var result = cidrToRange(self.eth_config.ipaddr, self.data.netmask, 0);             
            self.data.dhcp_start_ipaddr = long2ip( ip2long(result.start) + Number.parseInt(self.eth_config.dhcp_start) );    
            //Parse the dhcp end ipaddr
            self.data.dhcp_end_ipaddr = long2ip( ip2long(self.data.dhcp_start_ipaddr) + Number.parseInt(self.eth_config.dhcp_limit) );             
          }, function(error){          
            MessageService.showErrorMessage("WAN_CONFIG.MSG.INTERFACE_STATUS_FAIL");
          })

        }

        self.ethChagne = function(){
          if(self.eth_config.sid.indexOf('wan') > -1){
            CommonService.navPage("config.wan");
          }
        }

                    
        self.next = function(){
          self.configForm.$setSubmitted();
          if(self.configForm.$invalid) return;
          // delete self.eth_config.display;

          self.eth_config.netmask = cidr2Netmask(self.data.netmask);            
          self.eth_config.dhcp_limit = ip2long(self.data.dhcp_end_ipaddr) - ip2long(self.data.dhcp_start_ipaddr);
          self.eth_config.dhcp_start = getDHCPStart(self.eth_config.ipaddr, self.data.netmask, self.data.dhcp_start_ipaddr);
        
          self.loading = true;
          ConfigService.configlan(self.eth_config).then(function(res){          
            CommonService.navPage("config.diag");
          }, function(error){
            MessageService.showErrorMessage("WAN_CONFIG.MSG.INTERFACE_CONFIG_FAIL");
          }).finally(function(){
            self.loading = false;
          })

        }

        function getDHCPStart(ipaddr, netmask, dhcpStart){
          var result = cidrToRange(ipaddr, netmask, 0);
          return ip2long(dhcpStart) - ip2long(result.start);
        }

        function ip2long(ipAddress) {
          var ipLong=0;
          ipAddress.split('.').forEach(function( octet ) {
              ipLong<<=8;
              ipLong+=parseInt(octet);
          });
          return(ipLong >>>0);
        }

        function cidr2Netmask(cidr){
          var mask=[];
          for(let i=0;i<4;i++) {
            var n = Math.min(cidr, 8);
            mask.push(256 - Math.pow(2, 8-n));
            cidr -= n;
          }
          return mask.join('.');
        }

        function long2ip(ipLong) {
          return ( (ipLong>>>24) +'.' +
              (ipLong>>16 & 255) +'.' +
              (ipLong>>8 & 255) +'.' +
              (ipLong & 255) );
        }
      
        function netmask2CIDR(netmask){
          var ipString = netmask.split('.').map(Number).map(part => (part >>> 0).toString(2)).join('');
          return ipString.split('1').length - 1;  
        }

        function cidrToRange(ipaddr, netmask, exclude) {
          var result = { start: '', end: '', size: 0};  
          var size = Math.pow(2, (32 - netmask)) - 1;
          
          var startLong = (ip2long(ipaddr)) & ((-1 << (32 - netmask)));
          var endLong = startLong + size;
      
          // simple exclude 0, 255
          // e.g., 192.168.10.0/24 -> 192.168.10.0 ~ 192.168.10.255 -exclude-> 192.168.10.1 ~ 192.168.10.254
          var startOffset = exclude && size > 2 ? 1 : 0;
          var endOffset = exclude && size > 2 ? (size - 1) : size;
      
          result.start = long2ip(startLong + startOffset);
          result.end = long2ip(startLong + endOffset);
          result.size = size;
          return result;
        }

      }
    })
})()