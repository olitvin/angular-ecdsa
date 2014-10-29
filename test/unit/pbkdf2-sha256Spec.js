'use strict';


describe('Service: pbkdf2', function () {

  // load the service's module
  beforeEach(module('ng-pbkdf2'));

  // instantiate service
  var pbkdf2;

  beforeEach(inject(function (_pbkdf2_) {
    pbkdf2 = _pbkdf2_;
  }));

  it('should be instanciated', function () {
    expect(pbkdf2).not.toBe(null);
  });

  it('should verify known encryption', function () {
  	var key = 'passwd';
  	var salt = 'salt';
  	var res = pbkdf2(key, salt, 1, 64);
  	expect(res.toString('hex')).toEqual('55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783');
  });
  
});

