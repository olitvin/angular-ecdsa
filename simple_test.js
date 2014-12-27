var ecdsa = require('ecdsa')
  , BigInteger = require('bigi')
  , crypto = require('crypto')
  , assert = require('assert')
  , util = require ('util')
  , CoinKey = require('coinkey');

var ck = CoinKey.createRandom();
var msg = new Buffer("hello world!", 'utf8');
var shaMsg0 = crypto.createHash('sha256').update(msg).digest();
var signature = ecdsa.sign(shaMsg0, ck.privateKey);
o1 = {
	r: signature.r.toHex(16),
	s: signature.s.toHex(16)
}
var s2 = {
	r: BigInteger.fromHex(o1.r),
	s: BigInteger.fromHex(o1.s)
}
assert(ecdsa.verify(shaMsg0, s2, ck.publicKey), 'signature verif failed');

var obj = {
  'abv-r': '79cddc7574a98a6ab62ef359a7ddb9a3f03e6fa0eef2e6e32c9329d819aa93c8',
  'abv-s': '1d438540f7ef06d4bf43fb3dbe69b72f4e629163f3829c675d0116c1b0f0abba',
  'abv-msg': 'execute',
  'abv-nonce': ''
};
var pubKey = '0352bc357aee81e5400cbd1b33226979a970cef67794874f17420cb57aeddef2a2';
var publicKey = new Buffer(pubKey, 'hex');
var signature = {
  r: BigInteger.fromHex(obj['abv-r']),
  s: BigInteger.fromHex(obj['abv-s'])
};
//console.log('signature : ', signature);
var shaMsg = crypto.createHash('sha256').update(obj['abv-msg']).update(obj['abv-nonce']).digest();
var result = ecdsa.verify(shaMsg, signature, publicKey);
console.log("result = ", result);

var digest = crypto.createHash('sha256').
  update("Chuck").
  update("Norris").
  update("1950-10-10").
  update("karate").
  digest().toString('hex');
console.log("digest = ", digest);
