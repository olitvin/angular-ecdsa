'use strict';


describe('Service: Coinkey', function () {

  // load the service's module
  beforeEach(module('ng-coinkey'));

  // instantiate service
  var Coinkey;

  beforeEach(inject(function (_Coinkey_) {
    Coinkey = _Coinkey_;
  }));

  it('should have known attributes', function () {
    var ck = Coinkey.fromWif('QVD3x1RPiWPvyxbTsfxVwaYLyeBZrQvjhZ2aZJUsbuRgsEAGpNQ2');
    expect(ck.privateKey.toString('hex')).toEqual('c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a');
    expect(ck.publicAddress).toEqual('DGG6AicS4Qg8Y3UFtcuwJqbuRZ3Q7WtYXv');
    expect(ck.compressed).toBe(true);
  });

});

