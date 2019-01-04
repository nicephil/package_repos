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
          .when('/configmgr', {
            template: '<config-mgr-view></config-mgr-view>',
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
    .run(function ($rootScope, $translate) {
      $rootScope.$on('$translatePartialLoaderStructureChanged', function () {
        $translate.refresh();
      });
    });

})()