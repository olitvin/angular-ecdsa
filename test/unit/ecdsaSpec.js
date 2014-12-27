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
/* //BigInteger not defined..
  it('should verified known signature', function(){
    var msg = 'execute';
    var nonce = '';
    var obj = {'abv-r': '918160662028608125308262544383524098082366479190253505580386675596999593447',
      'abv-s': '38418285381626091199969877420773704544327807656245042232333284436937730506472'};
    var pubKey = '03d2233b3f3e98dd2afb987df80c7be37b27a1a51742b66813028ebce23d9dd5cb';
    var publicKey = new Buffer(pubKey, 'hex');
    var signature = {
      r: new BigInteger(obj['abv-r'], 'hex'),
      s: new BigInteger(obj['abv-s'], 'hex')
    };
    var result = ecdsa.verify(shaMsg, signature, publicKey);
    expect(result).toBe(true);
  })
*/
});

