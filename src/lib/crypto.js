'use strict';
var crypto = require('crypto');

angular.module('sacketty.crypto',[])
.factory('crypto', function() {
  return crypto
})