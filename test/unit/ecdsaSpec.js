'use strict';

describe('Service: ecdsa', function () {

  // load the service's module
  beforeEach(module('ng-ecdsa'));

  // instantiate service
  var ecdsa;
  var CoinKey;
  var Buffer;
  var crypto;
  var ck;

  beforeEach(inject(function (_ecdsa_, _crypto_, _CoinKey_, _buffer_) {
    ecdsa = _ecdsa_;
    crypto = _crypto_;
    CoinKey = _CoinKey_;
    Buffer = _buffer_.Buffer;
    ck = CoinKey.createRandom();
  }));

  it('should be instanciated', function () {
    expect(ecdsa).not.toBe(null);
  });

  it('should verify signature', function(){
    var msg = new Buffer("hello world!", 'utf8')
    var shaMsg = crypto.createHash('sha256').update(msg).digest()
    var signature = ecdsa.sign(shaMsg, ck.privateKey)
    var isValid = ecdsa.verify(shaMsg, signature, ck.publicKey)
    expect(isValid).toBe(true);
  });
  it('should have the same privateKey from wif', function(){
    var privateWif = ck.privateWif;
    var ck2 = CoinKey.fromWif(privateWif);
    expect(ck2.privateKey.toString('hex')).toEqual(ck2.privateKey.toString('hex'));
  });
  it('verify from recreated Coinkey', function(){
    var msg = new Buffer("hello world!", 'utf8');
    var nonce = 'nonce';
    var shaMsg = crypto.createHash('sha256').update(msg).update(nonce).digest()
    var signature = ecdsa.sign(shaMsg, ck.privateKey)
    var privateWif = ck.privateWif;
    var ck2 = CoinKey.fromWif(privateWif);
    var isValid = ecdsa.verify(shaMsg, signature, ck2.publicKey)
    expect(isValid).toBe(true);
  });

  it('should generate a 32 bytes buffer', function(){
    var privateKey = ck.privateKey;
    expect(privateKey.length).toEqual(32);
    expect(Buffer.isBuffer(privateKey)).toBe(true);
  });

});

