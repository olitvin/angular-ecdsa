'use strict';
var ecdsa = require('ecdsa');

angular.module('sacketty.ecdsa',[])
.factory('ecdsa', function() {
  return ecdsa
})