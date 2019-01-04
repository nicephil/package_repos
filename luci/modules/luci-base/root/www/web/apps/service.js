(function () {
  'use strict'
  angular
    .module("oakApps", ['pascalprecht.translate', 'ngRoute', 'oak.common', 'oak.login', 'oak.config', 'ui.router'])
    .config(['$translateProvider', '$translatePartialLoaderProvider', '$routeProvider', '$locationProvider',
      function ($translateProvider, $translatePartialLoaderProvider, $routeProvider, $locationProvider) {

        $locationProvider.hashPrefix('!');

        //$routeProvider.otherwise({redirectTo: '/login'});
        // $routeProvider.otherwise({
        //   redirectTo: '/'
        // });

        $routeProvider
          .when('/', {
            template: '<login-view></login-view>',
          })
          .when('/wanconfig', {
            template: '<wan-config></wan-config>',
          })            

        $translatePartialLoaderProvider.addPart('main');

        $translateProvider
          .useLoader('$translatePartialLoader', {
              urlTemplate: 'assets/i18n/{part}/{lang}.json'
          })
          .preferredLanguage(Lang.normalize.getLanguageId("zh"))
          .fallbackLanguage(Lang.default)
          .useSanitizeValueStrategy('escape');        
      }
    ])
})()