(function () {
'use strict'
angular.module("oak.common")
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
})()