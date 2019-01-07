(function () {
  'use strict'
  angular.module("oak.config")
    .component('configWanView', {
      templateUrl: 'apps/config/wanconfig/view.html',
      controller: function ($state, CommonService, ConfigService, MessageService) {
        var self = this;
        self.CONN_TYPE_SET = [
          { proto: "pppoe", name: "PPPOE"},
          { proto: "dhcp", name: "DHCP"},
          { proto: "static", name: "Static IP"},
        ];
        self.passwordType = 'password';
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
              intf.original_proto = intf.proto;
            })

            self.interfaces.sort(function(intf1, intf2){            
              return intf1.lname > intf2.lname ? 1 : -1;
            })

            if(self.wan_eths.length === 0) return;
            self.eth_config = self.wan_eths[0];          
            if(self.eth_config.dns){
              if(self.eth_config.dns.length > 1){
                self.data.dns1 = self.eth_config.dns[0];
                self.data.dns2 = self.eth_config.dns[1];
              }else if(self.eth_config.dns.length === 1){
                self.data.dns1 = self.eth_config.dns[0];
              }  
            }
            self.data.has_clone_mac = ( self.eth_config.mac != null && self.eth_config.mac !="" ) ? true : false;            
          }, function(error){          
            MessageService.showErrorMessage("WAN_CONFIG.MSG.INTERFACE_STATUS_FAIL");
          })

        }

        self.togglePasswordType = function(){
          self.passwordType = self.passwordType === 'password' ? 'text' : 'password';
        }

        self.updateMac = function() {
          // var duplicated = self.eth_config.mac && purgeMacAddress(self.eth_config.mac) === self.originalMac;
          // self.configForm.mac.$setValidity('duplicated', !duplicated);
          self.configForm.mac.$setValidity('invalidMac', true);
          if (self.configForm.mac.$valid) {
            var puregemac = purgeMacAddress(self.eth_config.mac);
            var firstBlock = puregemac.substr(0, 2);
            var num = parseInt(firstBlock, 16);
            if (puregemac == '000000000000' || puregemac == '111111111111' || num % 2 != 0) {
              self.configForm.mac.$setValidity('invalidMac', false);
            }
          }
        };

        self.ethChagne = function(){
          if(self.eth_config.sid.indexOf('lan') > -1){
            CommonService.navPage("config.lan");
          }
        }

        function purgeMacAddress(mac) {
          return (typeof mac === 'string' || mac instanceof String) ? mac.trim().replace(/-/g, "").replace(/:/g, "") : mac;
        }       
                    
        self.next = function(){
          self.configForm.$setSubmitted();
          if(self.configForm.$invalid) return;

          if(!self.data.has_clone_mac) self.eth_config.mac = "";
          // delete self.eth_config.display;
          // delete self.eth_config.original_proto;
          var dnss = [];
          if(self.data.dns1){
            dnss.push(self.data.dns1);  
          }
          if(self.data.dns2){
            dnss.push(self.data.dns2);
          }          
          self.eth_config.dns = dnss;
          self.loading = true;
          ConfigService.configwan(self.eth_config).then(function(res){
            // MessageService.showSuccessMessage("WAN_CONFIG.MSG.INTERFACE_CONFIG_SUCCESS");
            CommonService.navPage("config.diag");
          }, function(error){
            MessageService.showErrorMessage("WAN_CONFIG.MSG.INTERFACE_CONFIG_FAIL");
          }).finally(function(){
            self.loading = false;
          })

        }

      }
    })
})()