webpackJsonp([2],{3:function(e,n,r){e.exports=r("uFMr")},KF6U:function(e,n){e.exports=function(e){"undefined"!=typeof execScript?execScript(e):eval.call(null,e)}},uFMr:function(e,n,r){r("KF6U")(r("vMDW"))},vMDW:function(e,n){e.exports="(function (window, document) {\r\n\r\n  let body = document.querySelector('body');\r\n  let preloader = document.querySelector('.preloader');\r\n\r\n  body.style.overflow = 'hidden';\r\n\r\n  function remove() {\r\n    preloader.addEventListener('transitionend', function () {\r\n      preloader.className = 'preloader-hidden';\r\n    });\r\n\r\n    preloader.className += ' preloader-hidden-add preloader-hidden-add-active';\r\n  }\r\n\r\n  window.appBootstrap = () => {\r\n    setTimeout(() => {\r\n      remove();\r\n      body.style.overflow = '';\r\n    }, 100);\r\n  }\r\n\r\n})(window, document);\r\n"}},[3]);