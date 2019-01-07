(function () {
  'use strict'
  angular.module("oak.config")
    .component('configStatusView', {
      templateUrl: 'apps/config/status/view.html',
      controller: function ( $state, ConfigService, MessageService, CommonService ) {
        var self = this;
        self.wan_eths = [];
        self.lan_eths = [];
    
        self.$onInit = function () {
          self.diag = $state.params.data || {};
          ConfigService.getDeviceInterfaces().then(function(data){
            self.interfaces = data;               
            angular.forEach(self.interfaces, function(intf){ 
              if(intf.sid.indexOf('wan') > -1){
                self.wan_eths.push(intf);                
              }else if(intf.sid.indexOf('lan') > -1){
                self.lan_eths.push(intf);
              }
            })              

            self.eth_config = self.wan_eths[0];   
          }, function(error){          
            MessageService.showErrorMessage("WAN_CONFIG.MSG.INTERFACE_STATUS_FAIL");
          })

        }


        self.pre = function(){
          CommonService.navPage("config.wan",{ data: self.diag });
        }

        self.next = function(){
          CommonService.navPage("config.done");
        }


      }
    })
    .component('configDoneView', {
      templateUrl: 'apps/config/status/done.html',
      controller: function ( ConfigService, MessageService, $location ) {
        var self = this;
        self.wan_eths = [];
        self.lan_eths = [];
        self.loading = false;
        self.passwordType = 'password';             
    
        self.$onInit = function () {
          self.loading = true;
          ConfigService.getDeviceMac().then(function (device) {
            self.device = device;
          }, function (error) {}).finally(function(){
            self.loading = false;
          })
        }


        self.pre = function(){

        }

        self.restart = function(){
          self.configForm.$setSubmitted();
          if(self.configForm.$invalid) return;

          if(self.passcode === 'oakridge'){
            MessageService.showWarningMessage("STATUS.MSG.CANNOT_DEFAULT_PWD");
            return;
          }

          self.loading = true;          
          ConfigService.regdev(self.passcode).then(function() {          
            ConfigService.reboot().then(function() {
              $location.path( "/" );
            }, function (error) {}).finally(function(){
              self.loading = false;
            })            
          }, function (error) {
            self.loading = false;
          });

        }

        self.togglePasswordType = function () {
          self.passwordType = self.passwordType === 'password' ? 'text' : 'password';
        }


        self.copy = function () {
          MessageService.showSuccessMessage("COMMON.COPIED");
        };

        self.onSuccssCopy = function (e) {
          e.clearSelection();
        };


      }
    })    
    ;
})()