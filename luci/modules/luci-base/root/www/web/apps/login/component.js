(function () {
  'use strict'
  angular.module("oak.login", ['oak.common', 'ngResource', 'pascalprecht.translate'])
    .component('loginView', {
      templateUrl: 'apps/login/view.html',
      controller: function ($translatePartialLoader, $location, LoginService, ConfigService, MessageService) {
        $translatePartialLoader.addPart('main');
        var self = this;
        self.passwordType = 'password';
        self.loading = false;
        self.device = {};
        self.data = {};

        self.$onInit = function () {
          self.loading = true;
          LoginService.haspasscode().then(function (initStatus) {
            if (initStatus === 1) {
              $location.path( "/configmgr" );
            }
            ConfigService.getDeviceMac().then(function (device) {
              self.device = device;
            }, function (error) {})
          }, function (error) {
            MessageService.showErrorMessage("LOGIN.MSG.INIT_FAIL")
          }).finally(function () {
            self.loading = false;
          })
        }

        self.doLogin = function () {          
          self.loginForm.$setSubmitted();
          if(self.loginForm.$invalid) return;
          self.loading = true;
          LoginService.login(self.data.password).then(function(){
            $location.path("/configmgr");
          }, function(error){
            MessageService.showErrorMessage("LOGIN.MSG.LOGIN_FAIL")
          }).finally(function(){
            self.loading = false;
          })          
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
})()