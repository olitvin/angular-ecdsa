'use strict';


describe('Service: crypto', function () {

  // load the service's module
  beforeEach(module('ng-ecdsa'));

  // instantiate service
  var crypto;

  beforeEach(inject(function (_ecdsa_, _crypto_) {
    crypto = _crypto_;
  }));

  it('should be instanciated', function () {
    expect(crypto).not.toBe(null);
  });

  it('should has createHash method', function () {
    expect(crypto.createHash).toBeDefined();
  });

});

