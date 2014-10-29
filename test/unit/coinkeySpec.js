'use strict';


describe('Service: Coinkey', function () {

  // load the service's module
  beforeEach(module('ng-coinkey'));

  // instantiate service
  var CoinKey;

  beforeEach(inject(function (_CoinKey_) {
    CoinKey = _CoinKey_;
  }));

  it('should have known attributes', function () {
    var ck = CoinKey.fromWif('QVD3x1RPiWPvyxbTsfxVwaYLyeBZrQvjhZ2aZJUsbuRgsEAGpNQ2');
    expect(ck.privateKey.toString('hex')).toEqual('c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a');
    expect(ck.publicAddress).toEqual('DGG6AicS4Qg8Y3UFtcuwJqbuRZ3Q7WtYXv');
    expect(ck.compressed).toBe(true);
    expect(ck.publicKey.toString('hex')).toEqual('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71');
  });
});

