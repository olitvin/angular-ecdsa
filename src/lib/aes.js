'use strict';
var AES = require('aes');

angular.module('sacketty.aes',[])
.factory('AES', function() {
  return AES;
})