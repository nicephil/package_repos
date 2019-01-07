(function () {
  'use strict';
  angular.module('oak.common')
    .config(function ($stateProvider) {
      $stateProvider
        .state('config', {
          views: {
            configContent: {
              template: '<div ui-view></div>'
            }
          }
        })
        .state('config.wan', {
          template: '<config-wan-view></config-wan-view>',
          params:{
            data: null
          }
        })       
        .state('config.lan', {
          template: '<config-lan-view></config-lan-view>',
          params:{
            data: null
          }
        })               
        .state('config.diag', {
          template: '<config-diag-view></config-diag-view>',
          params:{
            data: null
          }
        })       
        .state('config.status', {
          template: '<config-status-view></config-status-view>',
          params:{
            data: null
          }          
        })            
        .state('config.done', {
          template: '<config-done-view></config-done-view>',
          params:{
            data: null
          }          
        })                        
        ;      
    });
})()