(function () {
  'use strict'
  angular.module("oak.config")
    .service('ConfigService', function($state){
      var self = this;
      self.navPage = function(page, data){
        $state.go( page, data || {}, {
          reload: page
        }).then(function () { }, angular.noop);    
      }

    })
})()