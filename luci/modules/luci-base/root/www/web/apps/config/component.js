(function () {
  'use strict'
  angular.module("oak.config")
    .component('configMgrView', {
      templateUrl: 'apps/config/mgr.html',
      controller: function (CommonService) {
        var self = this;

        self.$onInit = function () {
          CommonService.navPage("config.wan");        
        }

      }
    })
})()