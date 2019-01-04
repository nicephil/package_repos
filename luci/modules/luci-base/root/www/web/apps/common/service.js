(function () {
  'use strict'
  angular.module("oak.common")
    .constant('Config', {
      SERVER_URL: 'http://router.oakridge.vip/cgi-bin/luci/okos/'
    })
    .service('DataResource', function ($resource, Config) {
      var self = this;
      var _gatewayRes = $resource('', {}, {
        haspasscode: {
          url: Config.SERVER_URL + 'haspasscode',
          method: 'GET'
        },
        login: {
          url: Config.SERVER_URL + 'login',
          method: 'POST'
        },
        devumac: {
          url: Config.SERVER_URL + 'devumac',
          method: 'GET'
        },
        queryifs: {
          url: Config.SERVER_URL + 'queryifs',
          method: 'GET',
          isArray: true
        },
        configwan: {
          url: Config.SERVER_URL + 'configwan',
          method: 'POST'
        },
        configlan: {
          url: Config.SERVER_URL + 'configlan',
          method: 'POST'
        },
        reboot: {
          url: Config.SERVER_URL + 'oakreboot',
          method: 'GET'
        },
        regdev: {
          url: Config.SERVER_URL + 'regdev',
          method: 'POST'
        },
        diag: {
          url: Config.SERVER_URL + 'diag',
          method: 'GET'
        },
        querydiag: {
          url: Config.SERVER_URL + 'querydiag',
          method: 'POST'
        }
      })

      self.getGatewayRes = function () {
        return _gatewayRes;
      }
    })
    .service('CommonService', function ($state) {
      var self = this;
      self.navPage = function (page, data) {
        $state.go(page, data || {}, {
          reload: page
        }).then(function () {}, angular.noop);
      }
    })
    .service('LoginService', function ($q, DataResource) {
      var self = this;

      self.haspasscode = function () {
        var defer = $q.defer();
        DataResource.getGatewayRes().haspasscode().$promise.then(function (res) {
          defer.resolve(res.errcode);
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.login = function (password) {
        var defer = $q.defer();
        DataResource.getGatewayRes().login({}, {
          username: 'root',
          password: password
        }).$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve();
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

    })
    .service('ConfigService', function ($q, DataResource) {
      var self = this;

      self.getDeviceMac = function () {
        var defer = $q.defer();
        DataResource.getGatewayRes().devumac().$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve(res);
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.getDeviceInterfaces = function () {
        var defer = $q.defer();
        DataResource.getGatewayRes().queryifs().$promise.then(function (res) {
          if (res.length === 0) {
            defer.reject();
          } else {
            var itfs = res.filter(function (item) {
              return item.proto != 'none' && item.ifname.indexOf(".") === -1;
            }) || [];
            if (itfs.length === 0) {
              defer.reject();
            } else {
              defer.resolve(itfs);
            }
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.configwan = function (wan) {
        var defer = $q.defer();
        DataResource.getGatewayRes().configwan({}, wan).$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve();
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.configlan = function (lan) {
        var defer = $q.defer();
        DataResource.getGatewayRes().configlan({}, lan).$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve();
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.reboot = function (lan) {
        var defer = $q.defer();
        DataResource.getGatewayRes().reboot().$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve();
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.regdev = function (passcode) {
        var defer = $q.defer();
        DataResource.getGatewayRes().regdev({}, {
          passcode: passcode
        }).$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve();
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.diag = function () {
        var defer = $q.defer();
        DataResource.getGatewayRes().diag().$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve(res);
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

      self.querydiag = function (step) {
        var defer = $q.defer();
        DataResource.getGatewayRes().querydiag({
          step: step
        }).$promise.then(function (res) {
          if (res.errcode === 0) {
            defer.resolve(res);
          } else {
            defer.reject();
          }
        }, function (error) {
          defer.reject(error);
        })
        return defer.promise;
      }

    })
    .service('MessageService', function (toaster, $translate) {
      var self = this;

      self.showSuccessMessage = function (message) {
        toaster.pop({
          type: 'success',
          body: $translate.instant(message),
          timeout: 3000
        });
      }

      self.showWarningMessage = function (message) {
        toaster.pop({
          type: 'warning',
          body: $translate.instant(message),
          timeout: 10000
        });
      }

      self.showInfoMessage = function (message) {
        toaster.pop({
          type: 'info',
          body: $translate.instant(message),
          timeout: 5000
        });
      }

      self.showErrorMessage = function (message) {
        toaster.pop({
          type: 'error',
          body: $translate.instant(message),
          timeout: 10000
        });
      }

    })
    .directive('loading', function () {
      return {
        restrict: 'A',
        scope: {
          loading: '=', // true - loading, false - finished
        },
        link: function (scope, element, attrs) {
          if (scope.loading) {
            element.addClass('whirl traditional');
          }
          scope.$watch('loading', function (newVal, oldVal) {
            if (newVal !== oldVal) {
              if (newVal) {
                element.addClass('whirl traditional');
              } else {
                element.removeClass('whirl traditional');
              }
            }
          });
        }
      };
    })
    .directive('equals', function () {
      return {
        restrict: 'A',
        require: '?ngModel',
        link: function (scope, element, attrs, ngModel) {
          if (!ngModel) return;
          scope.$watch(attrs.ngModel, function () {
            validate();
          });

          attrs.$observe('equals', function (val) {
            validate();
          });

          var validate = function () {
            var val1 = ngModel.$viewValue;
            var val2 = attrs.equals;
            ngModel.$setValidity('equals', !val1 || !val2 || val1 === val2);
          };
        }
      }
    })
    .directive('validNumber', function () {
      return {
        restrict: 'A',
        require: '?ngModel',
        link: function (scope, element, attrs, ngModel) {
          if (!ngModel) return;
          var allowEmpty = attrs.allowEmpty || false;
          var range = attrs.validNumber.split('-').map(Number);
          ngModel.$validators.validNumber = function (value) {
            if (allowEmpty && (value === null || value === undefined || value === '')) return true;
            return value >= range[0] && value <= range[1];
          };
        }
      }
    })
    .directive('macAddress', function ($timeout) {
      function setCaretPosition(elem, caretPos) {
        if (elem !== null) {
          if (elem.createTextRange) {
            var range = elem.createTextRange();
            range.move('character', caretPos);
            range.select();
          } else {
            if (elem.setSelectionRange) {
              elem.focus();
              elem.setSelectionRange(caretPos, caretPos);
            } else
              elem.focus();
          }
        }
      }
      return {
        restrict: 'A',
        require: "ngModel",
        link: function (scope, ele, attrs, ctrl) {
          if (!ctrl) return;

          var sperator = ':';
          var regex = /^([0-9a-f]{2}([:-]|$)){6}$/i;

          var macAddressParse = function (value) {
            var validVal = value.replace(/[^0-9a-f-:]/gi, "").toUpperCase();
            if (validVal !== value) {
              ctrl.$setViewValue(validVal);
              ctrl.$render();
            }
            return validVal;
          }

          var macAddressFormat = function (value) {
            if (!value) return undefined;
            var numbers = value.replace(/-/g, "").replace(/:/g, "");
            //if (value.length % 3 === 0) {
            if (numbers.length % 2 === 0) {
              return numbers.length < 12 ? numbers.replace(/([0-9A-Za-z]{2})/g, "$1" + sperator) :
                numbers.replace(/([0-9A-Za-z]{2})/g, "$1" + sperator).substr(0, 17);
            }
            if (numbers.length > 12) {
              // should not exceed the 00:00:00:00:00:00
              return numbers.substr(0, 12).replace(/([0-9A-Za-z]{2})/g, "$1" + sperator).substr(0, 17);
            }
          }

          ctrl.$parsers.push(macAddressParse);
          ctrl.$formatters.push(macAddressFormat);

          ele.on('input', function () {
            // clear validaty
            ctrl.$setValidity('macAddress', true);

            var value = macAddressFormat(ele.val());

            if (value !== undefined) {
              ctrl.$setViewValue(value);
              ctrl.$render();
            }
            scope.$apply();

            if (value) {
              $timeout(function () {
                // change the cursor position
                setCaretPosition(ele[0], value.length);
              }, 5);
            }
          });

          ele.bind('keydown keypress', function (e) {
            var code = e.which || e.keyCode;
            if (code === 8 || code === 46) {
              // backspace key or delete key
              var v = ele.val();
              if (v && (v.endsWith(':') || v.endsWith('-'))) {
                // delete two char
                var newVal = v.substr(0, v.length - 2);
                ctrl.$setViewValue(newVal);
                ctrl.$render();

                e.preventDefault();
              }
            }
          });

          ele.bind('blur', function () {
            //For the empty value, should use ng-required
            if (ele.val() && ele.val().length > 0) {
              ctrl.$setValidity('macAddress', regex.test(ele.val()));
            }
          });
        }
      };
    })
    .filter('macDisplayFilter', function () {
      return function (mac) {
        if (mac) {
          return mac.toUpperCase();
        } else {
          return "";
        }

      }
    })
    .filter('nullValueFilter', function () {
      return function (value) {
        if (value) {
          return value;
        } else {
          return "";
        }
      }
    })
    .filter('showDnsFilter', function () {
      return function (dns) {
        if (dns && dns.length > 0) {
          return dns.join();
        }

        return "";
      }
    })
    .filter('showConnTypeFilter', function ($translate) {
      return function (connType) {
        if (connType === 'static') {
          return $translate.instant("COMMON.CONN_TYPE.STATIC");
        } else if (connType === 'dhcp') {
          return $translate.instant("COMMON.CONN_TYPE.DHCP");
        } else if (connType === 'pppoe') {
          return $translate.instant("COMMON.CONN_TYPE.PPPOE");
        }
        return "";
      }
    })
})()