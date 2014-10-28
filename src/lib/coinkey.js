'use strict';
var coinkey = require('coinkey');

angular.module('sacketty.coinkey',[])
.factory('Coinkey', function() {
  return coinkey
})