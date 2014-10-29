'use strict';
var Coinkey = require('coinkey');

angular.module('sacketty.coinkey',[])
.factory('Coinkey', function() {
  return Coinkey
})