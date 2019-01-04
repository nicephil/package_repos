(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['jquery'], factory);
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    module.exports = factory(require('jquery'));
  } else {
    // Browser globals (root is window)
    root.Lang = factory(root.jQuery);
  }
}(typeof window !== 'undefined' ? window : this, function ($) {
  'use strict';

  /*
  Get the browser first language,
  [language designator]-[region designator] which is defined as,
  ISO 639-1 [+ ISO 3166-1], for example, 'en-US'

  see,
  https://en.wikipedia.org/wiki/ISO_639
  https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
  http://en.wikipedia.org/wiki/ISO_3166-1
  https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
  */
  function getBrowserLang() {
    var lang = navigator.languages && navigator.languages[0] ||
                 navigator.language ||
                 navigator.browserLanguage ||
                 navigator.systemLanguage ||
                 navigator.userLanguage;
    return lang;
  }

  /*
  Paser, 
  * 'en' -> 'en'
  * 'en-US' -> 'en'
  * 'en_US' -> 'en'
  * 'zh-TW' -> 'zh'
  * 'zh-MO' -> 'zh'
  */
  function normalizeLanguageId(langRegion) {
    var languageId = langRegion;
    if (langRegion.indexOf('-') !== -1) {
      languageId = langRegion.split('-')[0];
    }
    if (langRegion.indexOf('_') !== -1) {
      languageId = langRegion.split('_')[0];
    }
    return languageId;
  }

  /*
  Paser, 
  * 'en' -> ''
  * 'en-US' -> 'US'
  * 'en_US' -> 'US'
  * 'zh-TW' -> 'TW'
  * 'zh-MO' -> 'MO'
  */
  function normalizeRegionId(langRegion) {
    var regionId = '';
    if (langRegion.indexOf('-') >= 1) {
      regionId = langRegion.split('-')[1];
    }
    if (langRegion.indexOf('_') >= 1) {
      regionId = langRegion.split('_')[1];
    }
    return regionId;
  }

  var _default_language = 'zh';
  var _supported_languages = [
    'en', // English
    'zh', // Chinese
    ];

  // http://unicode.org/iso15924/iso15924-codes.html
  var _coresponding_script_codes_in_iso15924 = {
    'zh-TW': 'zh-Hant',
    'zh-HK': 'zh-Hant',
  };

  function isDefault(language) {
    return language === '' || language === _default_language;
  }
  /*
    'zh-TW' -> 'zh-Hant'
    'zh-HK' -> 'zh-Hant'
    'zh-Unknown' -> 'zh'
    'en-US' -> 'en'
    'en-UK' -> 'en'
  */
  function getRelatedLang(langRegion) {
    var scriptCode = _coresponding_script_codes_in_iso15924[langRegion];
    return scriptCode ? scriptCode : normalizeLanguageId(langRegion)
  }

  /*
  return,
  - ''
  - 'zh-Hant'
  - 'en'
  */
  function getLanguageByRegion() {
    var langRegion = getBrowserLang();
    var locale = ''; // default
    var language = normalizeLanguageId(langRegion);
    if($.inArray(language, _supported_languages) !== -1) {
      locale = getRelatedLang(langRegion);
    }
    return isDefault(locale) ? _default_language : locale;
  }

  return {
    browserLang: getBrowserLang,
    normalize: {
      getLanguageId: normalizeLanguageId,
      getRegionId: normalizeRegionId,
    },
    get: getLanguageByRegion,
    default: _default_language
  };
}));