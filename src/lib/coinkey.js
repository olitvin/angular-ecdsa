'use strict';
var CoinKey = require('coinkey');

angular.module('sacketty.coinkey',[])
.factory('CoinKey', function() {
  return CoinKey;
});