'use strict';


describe('Service: aes', function () {

  // load the service's module
  beforeEach(module('ng-aes'));

  // instantiate service
  var AES;

  beforeEach(inject(function (_AES_) {
    AES = _AES_;
  }));

  it('should verify known encryption', function () {
    var key = [0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xfffffff8];
    var pt = [0x00000000,0x00000000,0x00000000,0x00000000];
    var ct = [0xd241aab0,0x5a42d319,0xde81d874,0xf5c7b90d];

    var aes = new AES(key);
    expect(aes.encrypt(pt)).toEqual([0xd241aab0,0x5a42d319,0xde81d874,0xf5c7b90d]);
    expect(aes.decrypt(ct)).toEqual([0x00000000,0x00000000,0x00000000,0x00000000]);
  });

});

