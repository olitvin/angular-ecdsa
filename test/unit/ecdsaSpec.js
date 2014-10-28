'use strict';

describe('Service: ecdsa', function () {

  // load the service's module
  beforeEach(module('ng-ecdsa'));

  // instantiate service
  var ecdsa;
  var Coinkey;
  var Buffer;
  var crypto;

  beforeEach(inject(function (_ecdsa_,_crypto_,_Coinkey_, _buffer_) {
    ecdsa = _ecdsa_;
    crypto = _crypto_;
    Coinkey = _Coinkey_;
    Buffer = _buffer_.Buffer;
  }));

  it('should be instanciated', function () {
    expect(ecdsa).not.toBe(null);
  });

  it('should verify signature', function(){
    var ck = Coinkey.createRandom();
    var msg = new Buffer("hello world!", 'utf8')
    var shaMsg = crypto.createHash('sha256').update(msg).digest()
    var signature = ecdsa.sign(shaMsg, ck.privateKey)
    var isValid = ecdsa.verify(shaMsg, signature, ck.publicKey)
    expect(isValid).toBe(true);
  })
});

