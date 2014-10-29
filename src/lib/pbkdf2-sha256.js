'use strict';
var pbkdf2 = require('pbkdf2-sha256');

angular.module('sacketty.pbkdf2',[])
.factory('pbkdf2', function() {
  return pbkdf2;
})