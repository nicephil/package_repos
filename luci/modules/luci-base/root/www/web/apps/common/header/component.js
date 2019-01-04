(function () {
  'use strict'
  angular
    .module("oak.common")
    .component('oakHeader', {
      templateUrl: 'apps/common/header/view.html',
      controller: function loginViewController( $cookies, $translate ){       
        var self = this;
        self.lang = "zh";  

        self.$onInit = function(){       
          self.lang = $cookies.get('lang') || Lang.get() || Lang.default;          
          $translate.use(self.lang);     
          // self.welcome = $translate.instant('COMMON.WELCOME', { device_type: "SDC-1000" });
        }

        self.changeLang = function(lang){
          self.lang = lang;
          $translate.use(lang);          
          $cookies.put('lang', lang);
        };
          
      }
    })    
})()