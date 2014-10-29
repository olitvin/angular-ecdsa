/*
  angular-ecdsa - v0.0.3 
  2014-10-29
*/
(function(window, angular, Math, undefined) {
    (function e(t, n, r) {
        function s(o, u) {
            if (!n[o]) {
                if (!t[o]) {
                    var a = typeof require == "function" && require;
                    if (!u && a) return a(o, !0);
                    if (i) return i(o, !0);
                    var f = new Error("Cannot find module '" + o + "'");
                    throw f.code = "MODULE_NOT_FOUND", f;
                }
                var l = n[o] = {
                    exports: {}
                };
                t[o][0].call(l.exports, function(e) {
                    var n = t[o][1][e];
                    return s(n ? n : e);
                }, l, l.exports, e, t, n, r);
            }
            return n[o].exports;
        }
        var i = typeof require == "function" && require;
        for (var o = 0; o < r.length; o++) s(r[o]);
        return s;
    })({
        1: [ function(require, module, exports) {
            module.exports = AES;
            function AES(key) {
                if (!this._tables[0][0][0]) this._precompute();
                var tmp, encKey, decKey;
                var sbox = this._tables[0][4];
                var decTable = this._tables[1];
                var keyLen = key.length;
                var rcon = 1;
                if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
                    throw new Error("invalid aes key size");
                }
                this._key = [ encKey = key.slice(0), decKey = [] ];
                for (var i = keyLen; i < 4 * keyLen + 28; i++) {
                    tmp = encKey[i - 1];
                    if (i % keyLen === 0 || keyLen === 8 && i % keyLen === 4) {
                        tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];
                        if (i % keyLen === 0) {
                            tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
                            rcon = rcon << 1 ^ (rcon >> 7) * 283;
                        }
                    }
                    encKey[i] = encKey[i - keyLen] ^ tmp;
                }
                for (var j = 0; i; j++, i--) {
                    tmp = encKey[j & 3 ? i : i - 4];
                    if (i <= 4 || j < 4) {
                        decKey[j] = tmp;
                    } else {
                        decKey[j] = decTable[0][sbox[tmp >>> 24]] ^ decTable[1][sbox[tmp >> 16 & 255]] ^ decTable[2][sbox[tmp >> 8 & 255]] ^ decTable[3][sbox[tmp & 255]];
                    }
                }
            }
            AES.prototype = {
                encrypt: function(data) {
                    return this._crypt(data, 0);
                },
                decrypt: function(data) {
                    return this._crypt(data, 1);
                },
                _tables: [ [ new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256) ], [ new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256) ] ],
                _precompute: function() {
                    var encTable = this._tables[0], decTable = this._tables[1], sbox = encTable[4], sboxInv = decTable[4], i, x, xInv, d = new Uint8Array(256), th = new Uint8Array(256), x2, x4, x8, s, tEnc, tDec;
                    for (i = 0; i < 256; i++) {
                        th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
                    }
                    for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
                        s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
                        s = s >> 8 ^ s & 255 ^ 99;
                        sbox[x] = s;
                        sboxInv[s] = x;
                        x8 = d[x4 = d[x2 = d[x]]];
                        tDec = x8 * 16843009 ^ x4 * 65537 ^ x2 * 257 ^ x * 16843008;
                        tEnc = d[s] * 257 ^ s * 16843008;
                        for (i = 0; i < 4; i++) {
                            encTable[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
                            decTable[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
                        }
                    }
                },
                _crypt: function(input, dir) {
                    if (input.length !== 4) {
                        throw new Error("invalid aes block size");
                    }
                    var key = this._key[dir], a = input[0] ^ key[0], b = input[dir ? 3 : 1] ^ key[1], c = input[2] ^ key[2], d = input[dir ? 1 : 3] ^ key[3], a2, b2, c2, nInnerRounds = key.length / 4 - 2, i, kIndex = 4, out = new Uint32Array(4), table = this._tables[dir], t0 = table[0], t1 = table[1], t2 = table[2], t3 = table[3], sbox = table[4];
                    for (i = 0; i < nInnerRounds; i++) {
                        a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[kIndex];
                        b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
                        c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
                        d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
                        kIndex += 4;
                        a = a2;
                        b = b2;
                        c = c2;
                    }
                    for (i = 0; i < 4; i++) {
                        out[dir ? 3 & -i : i] = sbox[a >>> 24] << 24 ^ sbox[b >> 16 & 255] << 16 ^ sbox[c >> 8 & 255] << 8 ^ sbox[d & 255] ^ key[kIndex++];
                        a2 = a;
                        a = b;
                        b = c;
                        c = d;
                        d = a2;
                    }
                    return out;
                }
            };
        }, {} ],
        2: [ function(require, module, exports) {
            (function(Buffer) {
                var util = require("util");
                var assert = require("assert");
                var ECKey = require("eckey");
                var cs = require("coinstring");
                var secureRandom = require("secure-random");
                var DEFAULT_VERSIONS = {
                    "public": 0,
                    "private": 128
                };
                function CoinKey(privateKey, versions) {
                    if (!(this instanceof CoinKey)) return new CoinKey(privateKey, versions);
                    if (!Array.isArray(privateKey) && !(privateKey instanceof Uint8Array) && !Buffer.isBuffer(privateKey)) throw new Error("Must pass a private key");
                    this._versions = versions || JSON.parse(JSON.stringify(DEFAULT_VERSIONS));
                    ECKey.call(this, privateKey, true);
                }
                util.inherits(CoinKey, ECKey);
                Object.defineProperty(CoinKey.prototype, "versions", {
                    enumerable: true,
                    configurable: true,
                    get: function() {
                        return this._versions;
                    },
                    set: function(versions) {
                        this._versions = versions;
                    }
                });
                Object.defineProperty(CoinKey.prototype, "privateWif", {
                    get: function() {
                        return cs.encode(this.privateExportKey, this.versions.private);
                    }
                });
                Object.defineProperty(CoinKey.prototype, "publicAddress", {
                    get: function() {
                        return cs.encode(this.pubKeyHash, this.versions.public);
                    }
                });
                CoinKey.prototype.toString = function() {
                    return this.privateWif + ": " + this.publicAddress;
                };
                CoinKey.fromWif = function(wif, versions) {
                    var res = cs.decode(wif);
                    var version = res.slice(0, 1);
                    var privateKey = res.slice(1);
                    var compressed = privateKey.length === 33;
                    if (compressed) privateKey = privateKey.slice(0, 32);
                    var v = versions || {};
                    v.private = v.private || version.readUInt8(0);
                    v.public = v.public || v.private - 128;
                    var ck = new CoinKey(privateKey, v);
                    ck.compressed = compressed;
                    return ck;
                };
                CoinKey.createRandom = function(versions) {
                    var privateKey = secureRandom.randomBuffer(32);
                    return new CoinKey(privateKey, versions);
                };
                module.exports = CoinKey;
            }).call(this, require("buffer").Buffer);
        }, {
            assert: 41,
            buffer: 43,
            coinstring: 3,
            eckey: 5,
            "secure-random": 15,
            util: 50
        } ],
        3: [ function(require, module, exports) {
            (function(Buffer) {
                var crypto = require("crypto");
                var assert = require("assert");
                var base58 = require("bs58");
                function encode(payload, version) {
                    if (Array.isArray(payload) || payload instanceof Uint8Array) payload = new Buffer(payload);
                    var buf;
                    if (version != null) {
                        if (typeof version == "number") version = new Buffer([ version ]);
                        buf = Buffer.concat([ version, payload ]);
                    } else {
                        buf = payload;
                    }
                    var checksum = sha256x2(buf).slice(0, 4);
                    var result = Buffer.concat([ buf, checksum ]);
                    return base58.encode(result);
                }
                function decode(base58str, version) {
                    var buf = base58.decode(base58str);
                    var versionLength;
                    if (version == null) versionLength = 0; else {
                        if (typeof version == "number") version = new Buffer([ version ]);
                        versionLength = version.length;
                        var versionCompare = buf.slice(0, versionLength);
                        if (versionCompare.toString("hex") !== version.toString("hex")) throw new Error("Invalid version");
                    }
                    var checksum = buf.slice(-4);
                    var endPos = buf.length - 4;
                    var bytes = buf.slice(0, endPos);
                    var newChecksum = sha256x2(bytes).slice(0, 4);
                    if (checksum.toString("hex") !== newChecksum.toString("hex")) throw new Error("Invalid checksum");
                    return bytes.slice(versionLength);
                }
                function isValid(base58str, version) {
                    try {
                        decode(base58str, version);
                    } catch (e) {
                        return false;
                    }
                    return true;
                }
                function createEncoder(version) {
                    return function(payload) {
                        return encode(payload, version);
                    };
                }
                function createDecoder(version) {
                    return function(base58str) {
                        return decode(base58str, version);
                    };
                }
                function createValidator(version) {
                    return function(base58str) {
                        return isValid(base58str, version);
                    };
                }
                function sha256x2(buffer) {
                    var sha = crypto.createHash("sha256").update(buffer).digest();
                    return crypto.createHash("sha256").update(sha).digest();
                }
                module.exports = {
                    encode: encode,
                    decode: decode,
                    isValid: isValid,
                    createEncoder: createEncoder,
                    createDecoder: createDecoder,
                    createValidator: createValidator
                };
            }).call(this, require("buffer").Buffer);
        }, {
            assert: 41,
            bs58: 4,
            buffer: 43,
            crypto: 19
        } ],
        4: [ function(require, module, exports) {
            (function(Buffer) {
                var assert = require("assert");
                var ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
                var ALPHABET_MAP = {};
                for (var i = 0; i < ALPHABET.length; i++) {
                    ALPHABET_MAP[ALPHABET.charAt(i)] = i;
                }
                var BASE = 58;
                function encode(buffer) {
                    if (buffer.length === 0) return "";
                    var i, j, digits = [ 0 ];
                    for (i = 0; i < buffer.length; i++) {
                        for (j = 0; j < digits.length; j++) digits[j] <<= 8;
                        digits[0] += buffer[i];
                        var carry = 0;
                        for (j = 0; j < digits.length; ++j) {
                            digits[j] += carry;
                            carry = digits[j] / BASE | 0;
                            digits[j] %= BASE;
                        }
                        while (carry) {
                            digits.push(carry % BASE);
                            carry = carry / BASE | 0;
                        }
                    }
                    for (i = 0; i < buffer.length - 1 && buffer[i] == 0; i++) digits.push(0);
                    return digits.reverse().map(function(digit) {
                        return ALPHABET[digit];
                    }).join("");
                }
                function decode(string) {
                    if (string.length === 0) return new Buffer(0);
                    var input = string.split("").map(function(c) {
                        assert(c in ALPHABET_MAP, "Non-base58 character");
                        return ALPHABET_MAP[c];
                    });
                    var i, j, bytes = [ 0 ];
                    for (i = 0; i < input.length; i++) {
                        for (j = 0; j < bytes.length; j++) bytes[j] *= BASE;
                        bytes[0] += input[i];
                        var carry = 0;
                        for (j = 0; j < bytes.length; ++j) {
                            bytes[j] += carry;
                            carry = bytes[j] >> 8;
                            bytes[j] &= 255;
                        }
                        while (carry) {
                            bytes.push(carry & 255);
                            carry >>= 8;
                        }
                    }
                    for (i = 0; i < input.length - 1 && input[i] == 0; i++) bytes.push(0);
                    return new Buffer(bytes.reverse());
                }
                module.exports = {
                    encode: encode,
                    decode: decode
                };
            }).call(this, require("buffer").Buffer);
        }, {
            assert: 41,
            buffer: 43
        } ],
        5: [ function(require, module, exports) {
            (function(Buffer) {
                var crypto = require("crypto");
                var ecurve = require("ecurve");
                var ecparams = ecurve.getCurveByName("secp256k1");
                var BigInteger = require("bigi");
                function ECKey(bytes, compressed) {
                    if (!(this instanceof ECKey)) return new ECKey(bytes, compressed);
                    if (typeof compressed == "boolean") this._compressed = compressed; else this._compressed = true;
                    if (bytes) this.privateKey = bytes;
                }
                Object.defineProperty(ECKey.prototype, "privateKey", {
                    enumerable: true,
                    configurable: true,
                    get: function() {
                        return this.key;
                    },
                    set: function(bytes) {
                        var byteArr;
                        if (Buffer.isBuffer(bytes)) {
                            this.key = bytes;
                            byteArr = [].slice.call(bytes);
                        } else if (bytes instanceof Uint8Array) {
                            byteArr = [].slice.call(bytes);
                            this.key = new Buffer(byteArr);
                        } else if (Array.isArray(bytes)) {
                            byteArr = bytes;
                            this.key = new Buffer(byteArr);
                        } else {
                            throw new Error("Invalid type. private key bytes must be either a Buffer, Array, or Uint8Array.");
                        }
                        if (bytes.length != 32) throw new Error("private key bytes must have a length of 32");
                        if (this._compressed) this._exportKey = Buffer.concat([ this.key, new Buffer([ 1 ]) ]); else this._exportKey = Buffer.concat([ this.key ]);
                        this.keyBigInteger = BigInteger.fromByteArrayUnsigned(byteArr);
                        this._publicPoint = null;
                        this._pubKeyHash = null;
                    }
                });
                Object.defineProperty(ECKey.prototype, "privateExportKey", {
                    get: function() {
                        return this._exportKey;
                    }
                });
                Object.defineProperty(ECKey.prototype, "publicHash", {
                    get: function() {
                        return this.pubKeyHash;
                    }
                });
                Object.defineProperty(ECKey.prototype, "pubKeyHash", {
                    get: function() {
                        if (this._pubKeyHash) return this._pubKeyHash;
                        var sha = crypto.createHash("sha256").update(this.publicKey).digest();
                        this._pubKeyHash = crypto.createHash("rmd160").update(sha).digest();
                        return this._pubKeyHash;
                    }
                });
                Object.defineProperty(ECKey.prototype, "publicKey", {
                    get: function() {
                        return new Buffer(this.publicPoint.getEncoded(this.compressed));
                    }
                });
                Object.defineProperty(ECKey.prototype, "publicPoint", {
                    get: function() {
                        if (!this._publicPoint) {
                            this._publicPoint = ecparams.G.multiply(this.keyBigInteger);
                        }
                        return this._publicPoint;
                    }
                });
                Object.defineProperty(ECKey.prototype, "compressed", {
                    get: function() {
                        return this._compressed;
                    },
                    set: function(val) {
                        var c = !!val;
                        if (c === this._compressed) return;
                        var pk = this.privateKey;
                        this._compressed = c;
                        this.privateKey = pk;
                    }
                });
                ECKey.prototype.toString = function(format) {
                    return this.privateKey.toString("hex");
                };
                module.exports = ECKey;
            }).call(this, require("buffer").Buffer);
        }, {
            bigi: 8,
            buffer: 43,
            crypto: 19,
            ecurve: 12
        } ],
        6: [ function(require, module, exports) {
            function BigInteger(a, b, c) {
                if (!(this instanceof BigInteger)) return new BigInteger(a, b, c);
                if (a != null) {
                    if ("number" == typeof a) this.fromNumber(a, b, c); else if (b == null && "string" != typeof a) this.fromString(a, 256); else this.fromString(a, b);
                }
            }
            var proto = BigInteger.prototype;
            proto.__bigi = require("../package.json").version;
            BigInteger.isBigInteger = function(obj, check_ver) {
                return obj && obj.__bigi && (!check_ver || obj.__bigi === proto.__bigi);
            };
            var dbits;
            function am1(i, x, w, j, c, n) {
                while (--n >= 0) {
                    var v = x * this[i++] + w[j] + c;
                    c = Math.floor(v / 67108864);
                    w[j++] = v & 67108863;
                }
                return c;
            }
            function am2(i, x, w, j, c, n) {
                var xl = x & 32767, xh = x >> 15;
                while (--n >= 0) {
                    var l = this[i] & 32767;
                    var h = this[i++] >> 15;
                    var m = xh * l + h * xl;
                    l = xl * l + ((m & 32767) << 15) + w[j] + (c & 1073741823);
                    c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
                    w[j++] = l & 1073741823;
                }
                return c;
            }
            function am3(i, x, w, j, c, n) {
                var xl = x & 16383, xh = x >> 14;
                while (--n >= 0) {
                    var l = this[i] & 16383;
                    var h = this[i++] >> 14;
                    var m = xh * l + h * xl;
                    l = xl * l + ((m & 16383) << 14) + w[j] + c;
                    c = (l >> 28) + (m >> 14) + xh * h;
                    w[j++] = l & 268435455;
                }
                return c;
            }
            BigInteger.prototype.am = am1;
            dbits = 26;
            BigInteger.prototype.DB = dbits;
            BigInteger.prototype.DM = (1 << dbits) - 1;
            var DV = BigInteger.prototype.DV = 1 << dbits;
            var BI_FP = 52;
            BigInteger.prototype.FV = Math.pow(2, BI_FP);
            BigInteger.prototype.F1 = BI_FP - dbits;
            BigInteger.prototype.F2 = 2 * dbits - BI_FP;
            var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
            var BI_RC = new Array();
            var rr, vv;
            rr = "0".charCodeAt(0);
            for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
            rr = "a".charCodeAt(0);
            for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
            rr = "A".charCodeAt(0);
            for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
            function int2char(n) {
                return BI_RM.charAt(n);
            }
            function intAt(s, i) {
                var c = BI_RC[s.charCodeAt(i)];
                return c == null ? -1 : c;
            }
            function bnpCopyTo(r) {
                for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
                r.t = this.t;
                r.s = this.s;
            }
            function bnpFromInt(x) {
                this.t = 1;
                this.s = x < 0 ? -1 : 0;
                if (x > 0) this[0] = x; else if (x < -1) this[0] = x + DV; else this.t = 0;
            }
            function nbv(i) {
                var r = new BigInteger();
                r.fromInt(i);
                return r;
            }
            function bnpFromString(s, b) {
                var self = this;
                var k;
                if (b == 16) k = 4; else if (b == 8) k = 3; else if (b == 256) k = 8; else if (b == 2) k = 1; else if (b == 32) k = 5; else if (b == 4) k = 2; else {
                    self.fromRadix(s, b);
                    return;
                }
                self.t = 0;
                self.s = 0;
                var i = s.length, mi = false, sh = 0;
                while (--i >= 0) {
                    var x = k == 8 ? s[i] & 255 : intAt(s, i);
                    if (x < 0) {
                        if (s.charAt(i) == "-") mi = true;
                        continue;
                    }
                    mi = false;
                    if (sh == 0) self[self.t++] = x; else if (sh + k > self.DB) {
                        self[self.t - 1] |= (x & (1 << self.DB - sh) - 1) << sh;
                        self[self.t++] = x >> self.DB - sh;
                    } else self[self.t - 1] |= x << sh;
                    sh += k;
                    if (sh >= self.DB) sh -= self.DB;
                }
                if (k == 8 && (s[0] & 128) != 0) {
                    self.s = -1;
                    if (sh > 0) self[self.t - 1] |= (1 << self.DB - sh) - 1 << sh;
                }
                self.clamp();
                if (mi) BigInteger.ZERO.subTo(self, self);
            }
            function bnpClamp() {
                var c = this.s & this.DM;
                while (this.t > 0 && this[this.t - 1] == c) --this.t;
            }
            function bnToString(b) {
                var self = this;
                if (self.s < 0) return "-" + self.negate().toString(b);
                var k;
                if (b == 16) k = 4; else if (b == 8) k = 3; else if (b == 2) k = 1; else if (b == 32) k = 5; else if (b == 4) k = 2; else return self.toRadix(b);
                var km = (1 << k) - 1, d, m = false, r = "", i = self.t;
                var p = self.DB - i * self.DB % k;
                if (i-- > 0) {
                    if (p < self.DB && (d = self[i] >> p) > 0) {
                        m = true;
                        r = int2char(d);
                    }
                    while (i >= 0) {
                        if (p < k) {
                            d = (self[i] & (1 << p) - 1) << k - p;
                            d |= self[--i] >> (p += self.DB - k);
                        } else {
                            d = self[i] >> (p -= k) & km;
                            if (p <= 0) {
                                p += self.DB;
                                --i;
                            }
                        }
                        if (d > 0) m = true;
                        if (m) r += int2char(d);
                    }
                }
                return m ? r : "0";
            }
            function bnNegate() {
                var r = new BigInteger();
                BigInteger.ZERO.subTo(this, r);
                return r;
            }
            function bnAbs() {
                return this.s < 0 ? this.negate() : this;
            }
            function bnCompareTo(a) {
                var r = this.s - a.s;
                if (r != 0) return r;
                var i = this.t;
                r = i - a.t;
                if (r != 0) return this.s < 0 ? -r : r;
                while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
                return 0;
            }
            function nbits(x) {
                var r = 1, t;
                if ((t = x >>> 16) != 0) {
                    x = t;
                    r += 16;
                }
                if ((t = x >> 8) != 0) {
                    x = t;
                    r += 8;
                }
                if ((t = x >> 4) != 0) {
                    x = t;
                    r += 4;
                }
                if ((t = x >> 2) != 0) {
                    x = t;
                    r += 2;
                }
                if ((t = x >> 1) != 0) {
                    x = t;
                    r += 1;
                }
                return r;
            }
            function bnBitLength() {
                if (this.t <= 0) return 0;
                return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM);
            }
            function bnByteLength() {
                return this.bitLength() >> 3;
            }
            function bnpDLShiftTo(n, r) {
                var i;
                for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
                for (i = n - 1; i >= 0; --i) r[i] = 0;
                r.t = this.t + n;
                r.s = this.s;
            }
            function bnpDRShiftTo(n, r) {
                for (var i = n; i < this.t; ++i) r[i - n] = this[i];
                r.t = Math.max(this.t - n, 0);
                r.s = this.s;
            }
            function bnpLShiftTo(n, r) {
                var self = this;
                var bs = n % self.DB;
                var cbs = self.DB - bs;
                var bm = (1 << cbs) - 1;
                var ds = Math.floor(n / self.DB), c = self.s << bs & self.DM, i;
                for (i = self.t - 1; i >= 0; --i) {
                    r[i + ds + 1] = self[i] >> cbs | c;
                    c = (self[i] & bm) << bs;
                }
                for (i = ds - 1; i >= 0; --i) r[i] = 0;
                r[ds] = c;
                r.t = self.t + ds + 1;
                r.s = self.s;
                r.clamp();
            }
            function bnpRShiftTo(n, r) {
                var self = this;
                r.s = self.s;
                var ds = Math.floor(n / self.DB);
                if (ds >= self.t) {
                    r.t = 0;
                    return;
                }
                var bs = n % self.DB;
                var cbs = self.DB - bs;
                var bm = (1 << bs) - 1;
                r[0] = self[ds] >> bs;
                for (var i = ds + 1; i < self.t; ++i) {
                    r[i - ds - 1] |= (self[i] & bm) << cbs;
                    r[i - ds] = self[i] >> bs;
                }
                if (bs > 0) r[self.t - ds - 1] |= (self.s & bm) << cbs;
                r.t = self.t - ds;
                r.clamp();
            }
            function bnpSubTo(a, r) {
                var self = this;
                var i = 0, c = 0, m = Math.min(a.t, self.t);
                while (i < m) {
                    c += self[i] - a[i];
                    r[i++] = c & self.DM;
                    c >>= self.DB;
                }
                if (a.t < self.t) {
                    c -= a.s;
                    while (i < self.t) {
                        c += self[i];
                        r[i++] = c & self.DM;
                        c >>= self.DB;
                    }
                    c += self.s;
                } else {
                    c += self.s;
                    while (i < a.t) {
                        c -= a[i];
                        r[i++] = c & self.DM;
                        c >>= self.DB;
                    }
                    c -= a.s;
                }
                r.s = c < 0 ? -1 : 0;
                if (c < -1) r[i++] = self.DV + c; else if (c > 0) r[i++] = c;
                r.t = i;
                r.clamp();
            }
            function bnpMultiplyTo(a, r) {
                var x = this.abs(), y = a.abs();
                var i = x.t;
                r.t = i + y.t;
                while (--i >= 0) r[i] = 0;
                for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
                r.s = 0;
                r.clamp();
                if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
            }
            function bnpSquareTo(r) {
                var x = this.abs();
                var i = r.t = 2 * x.t;
                while (--i >= 0) r[i] = 0;
                for (i = 0; i < x.t - 1; ++i) {
                    var c = x.am(i, x[i], r, 2 * i, 0, 1);
                    if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                        r[i + x.t] -= x.DV;
                        r[i + x.t + 1] = 1;
                    }
                }
                if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
                r.s = 0;
                r.clamp();
            }
            function bnpDivRemTo(m, q, r) {
                var self = this;
                var pm = m.abs();
                if (pm.t <= 0) return;
                var pt = self.abs();
                if (pt.t < pm.t) {
                    if (q != null) q.fromInt(0);
                    if (r != null) self.copyTo(r);
                    return;
                }
                if (r == null) r = new BigInteger();
                var y = new BigInteger(), ts = self.s, ms = m.s;
                var nsh = self.DB - nbits(pm[pm.t - 1]);
                if (nsh > 0) {
                    pm.lShiftTo(nsh, y);
                    pt.lShiftTo(nsh, r);
                } else {
                    pm.copyTo(y);
                    pt.copyTo(r);
                }
                var ys = y.t;
                var y0 = y[ys - 1];
                if (y0 == 0) return;
                var yt = y0 * (1 << self.F1) + (ys > 1 ? y[ys - 2] >> self.F2 : 0);
                var d1 = self.FV / yt, d2 = (1 << self.F1) / yt, e = 1 << self.F2;
                var i = r.t, j = i - ys, t = q == null ? new BigInteger() : q;
                y.dlShiftTo(j, t);
                if (r.compareTo(t) >= 0) {
                    r[r.t++] = 1;
                    r.subTo(t, r);
                }
                BigInteger.ONE.dlShiftTo(ys, t);
                t.subTo(y, y);
                while (y.t < ys) y[y.t++] = 0;
                while (--j >= 0) {
                    var qd = r[--i] == y0 ? self.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
                    if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
                        y.dlShiftTo(j, t);
                        r.subTo(t, r);
                        while (r[i] < --qd) r.subTo(t, r);
                    }
                }
                if (q != null) {
                    r.drShiftTo(ys, q);
                    if (ts != ms) BigInteger.ZERO.subTo(q, q);
                }
                r.t = ys;
                r.clamp();
                if (nsh > 0) r.rShiftTo(nsh, r);
                if (ts < 0) BigInteger.ZERO.subTo(r, r);
            }
            function bnMod(a) {
                var r = new BigInteger();
                this.abs().divRemTo(a, null, r);
                if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
                return r;
            }
            function Classic(m) {
                this.m = m;
            }
            function cConvert(x) {
                if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m); else return x;
            }
            function cRevert(x) {
                return x;
            }
            function cReduce(x) {
                x.divRemTo(this.m, null, x);
            }
            function cMulTo(x, y, r) {
                x.multiplyTo(y, r);
                this.reduce(r);
            }
            function cSqrTo(x, r) {
                x.squareTo(r);
                this.reduce(r);
            }
            Classic.prototype.convert = cConvert;
            Classic.prototype.revert = cRevert;
            Classic.prototype.reduce = cReduce;
            Classic.prototype.mulTo = cMulTo;
            Classic.prototype.sqrTo = cSqrTo;
            function bnpInvDigit() {
                if (this.t < 1) return 0;
                var x = this[0];
                if ((x & 1) == 0) return 0;
                var y = x & 3;
                y = y * (2 - (x & 15) * y) & 15;
                y = y * (2 - (x & 255) * y) & 255;
                y = y * (2 - ((x & 65535) * y & 65535)) & 65535;
                y = y * (2 - x * y % this.DV) % this.DV;
                return y > 0 ? this.DV - y : -y;
            }
            function Montgomery(m) {
                this.m = m;
                this.mp = m.invDigit();
                this.mpl = this.mp & 32767;
                this.mph = this.mp >> 15;
                this.um = (1 << m.DB - 15) - 1;
                this.mt2 = 2 * m.t;
            }
            function montConvert(x) {
                var r = new BigInteger();
                x.abs().dlShiftTo(this.m.t, r);
                r.divRemTo(this.m, null, r);
                if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
                return r;
            }
            function montRevert(x) {
                var r = new BigInteger();
                x.copyTo(r);
                this.reduce(r);
                return r;
            }
            function montReduce(x) {
                while (x.t <= this.mt2) x[x.t++] = 0;
                for (var i = 0; i < this.m.t; ++i) {
                    var j = x[i] & 32767;
                    var u0 = j * this.mpl + ((j * this.mph + (x[i] >> 15) * this.mpl & this.um) << 15) & x.DM;
                    j = i + this.m.t;
                    x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
                    while (x[j] >= x.DV) {
                        x[j] -= x.DV;
                        x[++j]++;
                    }
                }
                x.clamp();
                x.drShiftTo(this.m.t, x);
                if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
            }
            function montSqrTo(x, r) {
                x.squareTo(r);
                this.reduce(r);
            }
            function montMulTo(x, y, r) {
                x.multiplyTo(y, r);
                this.reduce(r);
            }
            Montgomery.prototype.convert = montConvert;
            Montgomery.prototype.revert = montRevert;
            Montgomery.prototype.reduce = montReduce;
            Montgomery.prototype.mulTo = montMulTo;
            Montgomery.prototype.sqrTo = montSqrTo;
            function bnpIsEven() {
                return (this.t > 0 ? this[0] & 1 : this.s) == 0;
            }
            function bnpExp(e, z) {
                if (e > 4294967295 || e < 1) return BigInteger.ONE;
                var r = new BigInteger(), r2 = new BigInteger(), g = z.convert(this), i = nbits(e) - 1;
                g.copyTo(r);
                while (--i >= 0) {
                    z.sqrTo(r, r2);
                    if ((e & 1 << i) > 0) z.mulTo(r2, g, r); else {
                        var t = r;
                        r = r2;
                        r2 = t;
                    }
                }
                return z.revert(r);
            }
            function bnModPowInt(e, m) {
                var z;
                if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
                return this.exp(e, z);
            }
            proto.copyTo = bnpCopyTo;
            proto.fromInt = bnpFromInt;
            proto.fromString = bnpFromString;
            proto.clamp = bnpClamp;
            proto.dlShiftTo = bnpDLShiftTo;
            proto.drShiftTo = bnpDRShiftTo;
            proto.lShiftTo = bnpLShiftTo;
            proto.rShiftTo = bnpRShiftTo;
            proto.subTo = bnpSubTo;
            proto.multiplyTo = bnpMultiplyTo;
            proto.squareTo = bnpSquareTo;
            proto.divRemTo = bnpDivRemTo;
            proto.invDigit = bnpInvDigit;
            proto.isEven = bnpIsEven;
            proto.exp = bnpExp;
            proto.toString = bnToString;
            proto.negate = bnNegate;
            proto.abs = bnAbs;
            proto.compareTo = bnCompareTo;
            proto.bitLength = bnBitLength;
            proto.byteLength = bnByteLength;
            proto.mod = bnMod;
            proto.modPowInt = bnModPowInt;
            function bnClone() {
                var r = new BigInteger();
                this.copyTo(r);
                return r;
            }
            function bnIntValue() {
                if (this.s < 0) {
                    if (this.t == 1) return this[0] - this.DV; else if (this.t == 0) return -1;
                } else if (this.t == 1) return this[0]; else if (this.t == 0) return 0;
                return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0];
            }
            function bnByteValue() {
                return this.t == 0 ? this.s : this[0] << 24 >> 24;
            }
            function bnShortValue() {
                return this.t == 0 ? this.s : this[0] << 16 >> 16;
            }
            function bnpChunkSize(r) {
                return Math.floor(Math.LN2 * this.DB / Math.log(r));
            }
            function bnSigNum() {
                if (this.s < 0) return -1; else if (this.t <= 0 || this.t == 1 && this[0] <= 0) return 0; else return 1;
            }
            function bnpToRadix(b) {
                if (b == null) b = 10;
                if (this.signum() == 0 || b < 2 || b > 36) return "0";
                var cs = this.chunkSize(b);
                var a = Math.pow(b, cs);
                var d = nbv(a), y = new BigInteger(), z = new BigInteger(), r = "";
                this.divRemTo(d, y, z);
                while (y.signum() > 0) {
                    r = (a + z.intValue()).toString(b).substr(1) + r;
                    y.divRemTo(d, y, z);
                }
                return z.intValue().toString(b) + r;
            }
            function bnpFromRadix(s, b) {
                var self = this;
                self.fromInt(0);
                if (b == null) b = 10;
                var cs = self.chunkSize(b);
                var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
                for (var i = 0; i < s.length; ++i) {
                    var x = intAt(s, i);
                    if (x < 0) {
                        if (s.charAt(i) == "-" && self.signum() == 0) mi = true;
                        continue;
                    }
                    w = b * w + x;
                    if (++j >= cs) {
                        self.dMultiply(d);
                        self.dAddOffset(w, 0);
                        j = 0;
                        w = 0;
                    }
                }
                if (j > 0) {
                    self.dMultiply(Math.pow(b, j));
                    self.dAddOffset(w, 0);
                }
                if (mi) BigInteger.ZERO.subTo(self, self);
            }
            function bnpFromNumber(a, b, c) {
                var self = this;
                if ("number" == typeof b) {
                    if (a < 2) self.fromInt(1); else {
                        self.fromNumber(a, c);
                        if (!self.testBit(a - 1)) self.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, self);
                        if (self.isEven()) self.dAddOffset(1, 0);
                        while (!self.isProbablePrime(b)) {
                            self.dAddOffset(2, 0);
                            if (self.bitLength() > a) self.subTo(BigInteger.ONE.shiftLeft(a - 1), self);
                        }
                    }
                } else {
                    var x = new Array(), t = a & 7;
                    x.length = (a >> 3) + 1;
                    b.nextBytes(x);
                    if (t > 0) x[0] &= (1 << t) - 1; else x[0] = 0;
                    self.fromString(x, 256);
                }
            }
            function bnToByteArray() {
                var self = this;
                var i = self.t, r = new Array();
                r[0] = self.s;
                var p = self.DB - i * self.DB % 8, d, k = 0;
                if (i-- > 0) {
                    if (p < self.DB && (d = self[i] >> p) != (self.s & self.DM) >> p) r[k++] = d | self.s << self.DB - p;
                    while (i >= 0) {
                        if (p < 8) {
                            d = (self[i] & (1 << p) - 1) << 8 - p;
                            d |= self[--i] >> (p += self.DB - 8);
                        } else {
                            d = self[i] >> (p -= 8) & 255;
                            if (p <= 0) {
                                p += self.DB;
                                --i;
                            }
                        }
                        if ((d & 128) != 0) d |= -256;
                        if (k === 0 && (self.s & 128) != (d & 128)) ++k;
                        if (k > 0 || d != self.s) r[k++] = d;
                    }
                }
                return r;
            }
            function bnEquals(a) {
                return this.compareTo(a) == 0;
            }
            function bnMin(a) {
                return this.compareTo(a) < 0 ? this : a;
            }
            function bnMax(a) {
                return this.compareTo(a) > 0 ? this : a;
            }
            function bnpBitwiseTo(a, op, r) {
                var self = this;
                var i, f, m = Math.min(a.t, self.t);
                for (i = 0; i < m; ++i) r[i] = op(self[i], a[i]);
                if (a.t < self.t) {
                    f = a.s & self.DM;
                    for (i = m; i < self.t; ++i) r[i] = op(self[i], f);
                    r.t = self.t;
                } else {
                    f = self.s & self.DM;
                    for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
                    r.t = a.t;
                }
                r.s = op(self.s, a.s);
                r.clamp();
            }
            function op_and(x, y) {
                return x & y;
            }
            function bnAnd(a) {
                var r = new BigInteger();
                this.bitwiseTo(a, op_and, r);
                return r;
            }
            function op_or(x, y) {
                return x | y;
            }
            function bnOr(a) {
                var r = new BigInteger();
                this.bitwiseTo(a, op_or, r);
                return r;
            }
            function op_xor(x, y) {
                return x ^ y;
            }
            function bnXor(a) {
                var r = new BigInteger();
                this.bitwiseTo(a, op_xor, r);
                return r;
            }
            function op_andnot(x, y) {
                return x & ~y;
            }
            function bnAndNot(a) {
                var r = new BigInteger();
                this.bitwiseTo(a, op_andnot, r);
                return r;
            }
            function bnNot() {
                var r = new BigInteger();
                for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
                r.t = this.t;
                r.s = ~this.s;
                return r;
            }
            function bnShiftLeft(n) {
                var r = new BigInteger();
                if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r);
                return r;
            }
            function bnShiftRight(n) {
                var r = new BigInteger();
                if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r);
                return r;
            }
            function lbit(x) {
                if (x == 0) return -1;
                var r = 0;
                if ((x & 65535) == 0) {
                    x >>= 16;
                    r += 16;
                }
                if ((x & 255) == 0) {
                    x >>= 8;
                    r += 8;
                }
                if ((x & 15) == 0) {
                    x >>= 4;
                    r += 4;
                }
                if ((x & 3) == 0) {
                    x >>= 2;
                    r += 2;
                }
                if ((x & 1) == 0) ++r;
                return r;
            }
            function bnGetLowestSetBit() {
                for (var i = 0; i < this.t; ++i) if (this[i] != 0) return i * this.DB + lbit(this[i]);
                if (this.s < 0) return this.t * this.DB;
                return -1;
            }
            function cbit(x) {
                var r = 0;
                while (x != 0) {
                    x &= x - 1;
                    ++r;
                }
                return r;
            }
            function bnBitCount() {
                var r = 0, x = this.s & this.DM;
                for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
                return r;
            }
            function bnTestBit(n) {
                var j = Math.floor(n / this.DB);
                if (j >= this.t) return this.s != 0;
                return (this[j] & 1 << n % this.DB) != 0;
            }
            function bnpChangeBit(n, op) {
                var r = BigInteger.ONE.shiftLeft(n);
                this.bitwiseTo(r, op, r);
                return r;
            }
            function bnSetBit(n) {
                return this.changeBit(n, op_or);
            }
            function bnClearBit(n) {
                return this.changeBit(n, op_andnot);
            }
            function bnFlipBit(n) {
                return this.changeBit(n, op_xor);
            }
            function bnpAddTo(a, r) {
                var self = this;
                var i = 0, c = 0, m = Math.min(a.t, self.t);
                while (i < m) {
                    c += self[i] + a[i];
                    r[i++] = c & self.DM;
                    c >>= self.DB;
                }
                if (a.t < self.t) {
                    c += a.s;
                    while (i < self.t) {
                        c += self[i];
                        r[i++] = c & self.DM;
                        c >>= self.DB;
                    }
                    c += self.s;
                } else {
                    c += self.s;
                    while (i < a.t) {
                        c += a[i];
                        r[i++] = c & self.DM;
                        c >>= self.DB;
                    }
                    c += a.s;
                }
                r.s = c < 0 ? -1 : 0;
                if (c > 0) r[i++] = c; else if (c < -1) r[i++] = self.DV + c;
                r.t = i;
                r.clamp();
            }
            function bnAdd(a) {
                var r = new BigInteger();
                this.addTo(a, r);
                return r;
            }
            function bnSubtract(a) {
                var r = new BigInteger();
                this.subTo(a, r);
                return r;
            }
            function bnMultiply(a) {
                var r = new BigInteger();
                this.multiplyTo(a, r);
                return r;
            }
            function bnSquare() {
                var r = new BigInteger();
                this.squareTo(r);
                return r;
            }
            function bnDivide(a) {
                var r = new BigInteger();
                this.divRemTo(a, r, null);
                return r;
            }
            function bnRemainder(a) {
                var r = new BigInteger();
                this.divRemTo(a, null, r);
                return r;
            }
            function bnDivideAndRemainder(a) {
                var q = new BigInteger(), r = new BigInteger();
                this.divRemTo(a, q, r);
                return new Array(q, r);
            }
            function bnpDMultiply(n) {
                this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
                ++this.t;
                this.clamp();
            }
            function bnpDAddOffset(n, w) {
                if (n == 0) return;
                while (this.t <= w) this[this.t++] = 0;
                this[w] += n;
                while (this[w] >= this.DV) {
                    this[w] -= this.DV;
                    if (++w >= this.t) this[this.t++] = 0;
                    ++this[w];
                }
            }
            function NullExp() {}
            function nNop(x) {
                return x;
            }
            function nMulTo(x, y, r) {
                x.multiplyTo(y, r);
            }
            function nSqrTo(x, r) {
                x.squareTo(r);
            }
            NullExp.prototype.convert = nNop;
            NullExp.prototype.revert = nNop;
            NullExp.prototype.mulTo = nMulTo;
            NullExp.prototype.sqrTo = nSqrTo;
            function bnPow(e) {
                return this.exp(e, new NullExp());
            }
            function bnpMultiplyLowerTo(a, n, r) {
                var i = Math.min(this.t + a.t, n);
                r.s = 0;
                r.t = i;
                while (i > 0) r[--i] = 0;
                var j;
                for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
                for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
                r.clamp();
            }
            function bnpMultiplyUpperTo(a, n, r) {
                --n;
                var i = r.t = this.t + a.t - n;
                r.s = 0;
                while (--i >= 0) r[i] = 0;
                for (i = Math.max(n - this.t, 0); i < a.t; ++i) r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
                r.clamp();
                r.drShiftTo(1, r);
            }
            function Barrett(m) {
                this.r2 = new BigInteger();
                this.q3 = new BigInteger();
                BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
                this.mu = this.r2.divide(m);
                this.m = m;
            }
            function barrettConvert(x) {
                if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m); else if (x.compareTo(this.m) < 0) return x; else {
                    var r = new BigInteger();
                    x.copyTo(r);
                    this.reduce(r);
                    return r;
                }
            }
            function barrettRevert(x) {
                return x;
            }
            function barrettReduce(x) {
                var self = this;
                x.drShiftTo(self.m.t - 1, self.r2);
                if (x.t > self.m.t + 1) {
                    x.t = self.m.t + 1;
                    x.clamp();
                }
                self.mu.multiplyUpperTo(self.r2, self.m.t + 1, self.q3);
                self.m.multiplyLowerTo(self.q3, self.m.t + 1, self.r2);
                while (x.compareTo(self.r2) < 0) x.dAddOffset(1, self.m.t + 1);
                x.subTo(self.r2, x);
                while (x.compareTo(self.m) >= 0) x.subTo(self.m, x);
            }
            function barrettSqrTo(x, r) {
                x.squareTo(r);
                this.reduce(r);
            }
            function barrettMulTo(x, y, r) {
                x.multiplyTo(y, r);
                this.reduce(r);
            }
            Barrett.prototype.convert = barrettConvert;
            Barrett.prototype.revert = barrettRevert;
            Barrett.prototype.reduce = barrettReduce;
            Barrett.prototype.mulTo = barrettMulTo;
            Barrett.prototype.sqrTo = barrettSqrTo;
            function bnModPow(e, m) {
                var i = e.bitLength(), k, r = nbv(1), z;
                if (i <= 0) return r; else if (i < 18) k = 1; else if (i < 48) k = 3; else if (i < 144) k = 4; else if (i < 768) k = 5; else k = 6;
                if (i < 8) z = new Classic(m); else if (m.isEven()) z = new Barrett(m); else z = new Montgomery(m);
                var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
                g[1] = z.convert(this);
                if (k > 1) {
                    var g2 = new BigInteger();
                    z.sqrTo(g[1], g2);
                    while (n <= km) {
                        g[n] = new BigInteger();
                        z.mulTo(g2, g[n - 2], g[n]);
                        n += 2;
                    }
                }
                var j = e.t - 1, w, is1 = true, r2 = new BigInteger(), t;
                i = nbits(e[j]) - 1;
                while (j >= 0) {
                    if (i >= k1) w = e[j] >> i - k1 & km; else {
                        w = (e[j] & (1 << i + 1) - 1) << k1 - i;
                        if (j > 0) w |= e[j - 1] >> this.DB + i - k1;
                    }
                    n = k;
                    while ((w & 1) == 0) {
                        w >>= 1;
                        --n;
                    }
                    if ((i -= n) < 0) {
                        i += this.DB;
                        --j;
                    }
                    if (is1) {
                        g[w].copyTo(r);
                        is1 = false;
                    } else {
                        while (n > 1) {
                            z.sqrTo(r, r2);
                            z.sqrTo(r2, r);
                            n -= 2;
                        }
                        if (n > 0) z.sqrTo(r, r2); else {
                            t = r;
                            r = r2;
                            r2 = t;
                        }
                        z.mulTo(r2, g[w], r);
                    }
                    while (j >= 0 && (e[j] & 1 << i) == 0) {
                        z.sqrTo(r, r2);
                        t = r;
                        r = r2;
                        r2 = t;
                        if (--i < 0) {
                            i = this.DB - 1;
                            --j;
                        }
                    }
                }
                return z.revert(r);
            }
            function bnGCD(a) {
                var x = this.s < 0 ? this.negate() : this.clone();
                var y = a.s < 0 ? a.negate() : a.clone();
                if (x.compareTo(y) < 0) {
                    var t = x;
                    x = y;
                    y = t;
                }
                var i = x.getLowestSetBit(), g = y.getLowestSetBit();
                if (g < 0) return x;
                if (i < g) g = i;
                if (g > 0) {
                    x.rShiftTo(g, x);
                    y.rShiftTo(g, y);
                }
                while (x.signum() > 0) {
                    if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
                    if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
                    if (x.compareTo(y) >= 0) {
                        x.subTo(y, x);
                        x.rShiftTo(1, x);
                    } else {
                        y.subTo(x, y);
                        y.rShiftTo(1, y);
                    }
                }
                if (g > 0) y.lShiftTo(g, y);
                return y;
            }
            function bnpModInt(n) {
                if (n <= 0) return 0;
                var d = this.DV % n, r = this.s < 0 ? n - 1 : 0;
                if (this.t > 0) if (d == 0) r = this[0] % n; else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
                return r;
            }
            function bnModInverse(m) {
                var ac = m.isEven();
                if (this.isEven() && ac || m.signum() == 0) return BigInteger.ZERO;
                var u = m.clone(), v = this.clone();
                var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
                while (u.signum() != 0) {
                    while (u.isEven()) {
                        u.rShiftTo(1, u);
                        if (ac) {
                            if (!a.isEven() || !b.isEven()) {
                                a.addTo(this, a);
                                b.subTo(m, b);
                            }
                            a.rShiftTo(1, a);
                        } else if (!b.isEven()) b.subTo(m, b);
                        b.rShiftTo(1, b);
                    }
                    while (v.isEven()) {
                        v.rShiftTo(1, v);
                        if (ac) {
                            if (!c.isEven() || !d.isEven()) {
                                c.addTo(this, c);
                                d.subTo(m, d);
                            }
                            c.rShiftTo(1, c);
                        } else if (!d.isEven()) d.subTo(m, d);
                        d.rShiftTo(1, d);
                    }
                    if (u.compareTo(v) >= 0) {
                        u.subTo(v, u);
                        if (ac) a.subTo(c, a);
                        b.subTo(d, b);
                    } else {
                        v.subTo(u, v);
                        if (ac) c.subTo(a, c);
                        d.subTo(b, d);
                    }
                }
                if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
                if (d.compareTo(m) >= 0) return d.subtract(m);
                if (d.signum() < 0) d.addTo(m, d); else return d;
                if (d.signum() < 0) return d.add(m); else return d;
            }
            proto.chunkSize = bnpChunkSize;
            proto.toRadix = bnpToRadix;
            proto.fromRadix = bnpFromRadix;
            proto.fromNumber = bnpFromNumber;
            proto.bitwiseTo = bnpBitwiseTo;
            proto.changeBit = bnpChangeBit;
            proto.addTo = bnpAddTo;
            proto.dMultiply = bnpDMultiply;
            proto.dAddOffset = bnpDAddOffset;
            proto.multiplyLowerTo = bnpMultiplyLowerTo;
            proto.multiplyUpperTo = bnpMultiplyUpperTo;
            proto.modInt = bnpModInt;
            proto.clone = bnClone;
            proto.intValue = bnIntValue;
            proto.byteValue = bnByteValue;
            proto.shortValue = bnShortValue;
            proto.signum = bnSigNum;
            proto.toByteArray = bnToByteArray;
            proto.equals = bnEquals;
            proto.min = bnMin;
            proto.max = bnMax;
            proto.and = bnAnd;
            proto.or = bnOr;
            proto.xor = bnXor;
            proto.andNot = bnAndNot;
            proto.not = bnNot;
            proto.shiftLeft = bnShiftLeft;
            proto.shiftRight = bnShiftRight;
            proto.getLowestSetBit = bnGetLowestSetBit;
            proto.bitCount = bnBitCount;
            proto.testBit = bnTestBit;
            proto.setBit = bnSetBit;
            proto.clearBit = bnClearBit;
            proto.flipBit = bnFlipBit;
            proto.add = bnAdd;
            proto.subtract = bnSubtract;
            proto.multiply = bnMultiply;
            proto.divide = bnDivide;
            proto.remainder = bnRemainder;
            proto.divideAndRemainder = bnDivideAndRemainder;
            proto.modPow = bnModPow;
            proto.modInverse = bnModInverse;
            proto.pow = bnPow;
            proto.gcd = bnGCD;
            proto.square = bnSquare;
            BigInteger.ZERO = nbv(0);
            BigInteger.ONE = nbv(1);
            BigInteger.valueOf = nbv;
            module.exports = BigInteger;
        }, {
            "../package.json": 9
        } ],
        7: [ function(require, module, exports) {
            (function(Buffer) {
                var assert = require("assert");
                var BigInteger = require("./bigi");
                BigInteger.fromByteArrayUnsigned = function(byteArray) {
                    if (byteArray[0] & 128) {
                        return new BigInteger([ 0 ].concat(byteArray));
                    }
                    return new BigInteger(byteArray);
                };
                BigInteger.prototype.toByteArrayUnsigned = function() {
                    var byteArray = this.toByteArray();
                    return byteArray[0] === 0 ? byteArray.slice(1) : byteArray;
                };
                BigInteger.fromDERInteger = function(byteArray) {
                    return new BigInteger(byteArray);
                };
                BigInteger.prototype.toDERInteger = BigInteger.prototype.toByteArray;
                BigInteger.fromBuffer = function(buffer) {
                    if (buffer[0] & 128) {
                        var byteArray = Array.prototype.slice.call(buffer);
                        return new BigInteger([ 0 ].concat(byteArray));
                    }
                    return new BigInteger(buffer);
                };
                BigInteger.fromHex = function(hex) {
                    if (hex === "") return BigInteger.ZERO;
                    assert.equal(hex, hex.match(/^[A-Fa-f0-9]+/), "Invalid hex string");
                    assert.equal(hex.length % 2, 0, "Incomplete hex");
                    return new BigInteger(hex, 16);
                };
                BigInteger.prototype.toBuffer = function(size) {
                    var byteArray = this.toByteArrayUnsigned();
                    var zeros = [];
                    var padding = size - byteArray.length;
                    while (zeros.length < padding) zeros.push(0);
                    return new Buffer(zeros.concat(byteArray));
                };
                BigInteger.prototype.toHex = function(size) {
                    return this.toBuffer(size).toString("hex");
                };
            }).call(this, require("buffer").Buffer);
        }, {
            "./bigi": 6,
            assert: 41,
            buffer: 43
        } ],
        8: [ function(require, module, exports) {
            var BigInteger = require("./bigi");
            require("./convert");
            module.exports = BigInteger;
        }, {
            "./bigi": 6,
            "./convert": 7
        } ],
        9: [ function(require, module, exports) {
            module.exports = {
                name: "bigi",
                version: "1.3.0",
                description: "Big integers.",
                keywords: [ "cryptography", "math", "bitcoin", "arbitrary", "precision", "arithmetic", "big", "integer", "int", "number", "biginteger", "bigint", "bignumber", "decimal", "float" ],
                devDependencies: {
                    mocha: "^1.20.1",
                    jshint: "^2.5.1",
                    coveralls: "^2.10.0",
                    istanbul: "^0.2.11"
                },
                repository: {
                    url: "https://github.com/cryptocoinjs/bigi",
                    type: "git"
                },
                main: "./lib/index.js",
                scripts: {
                    test: "_mocha -- test/*.js",
                    jshint: "jshint --config jshint.json lib/*.js ; true",
                    unit: "mocha",
                    coverage: "istanbul cover ./node_modules/.bin/_mocha -- --reporter list test/*.js",
                    coveralls: "npm run-script coverage && node ./node_modules/.bin/coveralls < coverage/lcov.info"
                },
                dependencies: {},
                testling: {
                    files: "test/*.js",
                    harness: "mocha",
                    browsers: [ "ie/9..latest", "firefox/latest", "chrome/latest", "safari/6.0..latest", "iphone/6.0..latest", "android-browser/4.2..latest" ]
                },
                readme: "bigi\n======\n\n[![build status](https://secure.travis-ci.org/cryptocoinjs/bigi.png)](http://travis-ci.org/cryptocoinjs/bigi)\n[![Coverage Status](https://img.shields.io/coveralls/cryptocoinjs/bigi.svg)](https://coveralls.io/r/cryptocoinjs/bigi)\n[![Version](http://img.shields.io/npm/v/bigi.svg)](https://www.npmjs.org/package/bigi)\n\n[![browser support](https://ci.testling.com/cryptocoinjs/bigi.png)](https://ci.testling.com/cryptocoinjs/bigi)\n\nJavaScript library to manipulate big integers. Based on `jsbn` made by [Tom Wu](http://www-cs-students.stanford.edu/~tjw/jsbn/)\n\nOfficial documentation: \n\nhttp://cryptocoinjs.com/modules/misc/bigi/",
                readmeFilename: "README.md",
                bugs: {
                    url: "https://github.com/cryptocoinjs/bigi/issues"
                },
                homepage: "https://github.com/cryptocoinjs/bigi",
                _id: "bigi@1.3.0",
                _from: "bigi@^1.1.0"
            };
        }, {} ],
        10: [ function(require, module, exports) {
            var assert = require("assert");
            var BigInteger = require("bigi");
            var Point = require("./point");
            function Curve(p, a, b, Gx, Gy, n, h) {
                this.p = p;
                this.a = a;
                this.b = b;
                this.G = Point.fromAffine(this, Gx, Gy);
                this.n = n;
                this.h = h;
                this.infinity = new Point(this, null, null, BigInteger.ZERO);
                this.pOverFour = p.add(BigInteger.ONE).shiftRight(2);
            }
            Curve.prototype.pointFromX = function(isOdd, x) {
                var alpha = x.pow(3).add(this.a.multiply(x)).add(this.b).mod(this.p);
                var beta = alpha.modPow(this.pOverFour, this.p);
                var y = beta;
                if (beta.isEven() ^ !isOdd) {
                    y = this.p.subtract(y);
                }
                return Point.fromAffine(this, x, y);
            };
            Curve.prototype.isInfinity = function(Q) {
                if (Q === this.infinity) return true;
                return Q.z.signum() === 0 && Q.y.signum() !== 0;
            };
            Curve.prototype.isOnCurve = function(Q) {
                if (this.isInfinity(Q)) return true;
                var x = Q.affineX;
                var y = Q.affineY;
                var a = this.a;
                var b = this.b;
                var p = this.p;
                if (x.signum() < 0 || x.compareTo(p) >= 0) return false;
                if (y.signum() < 0 || y.compareTo(p) >= 0) return false;
                var lhs = y.square().mod(p);
                var rhs = x.pow(3).add(a.multiply(x)).add(b).mod(p);
                return lhs.equals(rhs);
            };
            Curve.prototype.validate = function(Q) {
                assert(!this.isInfinity(Q), "Point is at infinity");
                assert(this.isOnCurve(Q), "Point is not on the curve");
                var nQ = Q.multiply(this.n);
                assert(this.isInfinity(nQ), "Point is not a scalar multiple of G");
                return true;
            };
            module.exports = Curve;
        }, {
            "./point": 14,
            assert: 41,
            bigi: 8
        } ],
        11: [ function(require, module, exports) {
            module.exports = {
                secp128r1: {
                    p: "fffffffdffffffffffffffffffffffff",
                    a: "fffffffdfffffffffffffffffffffffc",
                    b: "e87579c11079f43dd824993c2cee5ed3",
                    n: "fffffffe0000000075a30d1b9038a115",
                    h: "01",
                    Gx: "161ff7528b899b2d0c28607ca52c5b86",
                    Gy: "cf5ac8395bafeb13c02da292dded7a83"
                },
                secp160k1: {
                    p: "fffffffffffffffffffffffffffffffeffffac73",
                    a: "00",
                    b: "07",
                    n: "0100000000000000000001b8fa16dfab9aca16b6b3",
                    h: "01",
                    Gx: "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb",
                    Gy: "938cf935318fdced6bc28286531733c3f03c4fee"
                },
                secp160r1: {
                    p: "ffffffffffffffffffffffffffffffff7fffffff",
                    a: "ffffffffffffffffffffffffffffffff7ffffffc",
                    b: "1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
                    n: "0100000000000000000001f4c8f927aed3ca752257",
                    h: "01",
                    Gx: "4a96b5688ef573284664698968c38bb913cbfc82",
                    Gy: "23a628553168947d59dcc912042351377ac5fb32"
                },
                secp192k1: {
                    p: "fffffffffffffffffffffffffffffffffffffffeffffee37",
                    a: "00",
                    b: "03",
                    n: "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
                    h: "01",
                    Gx: "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
                    Gy: "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"
                },
                secp192r1: {
                    p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
                    a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
                    b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
                    n: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
                    h: "01",
                    Gx: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
                    Gy: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
                },
                secp256k1: {
                    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                    a: "00",
                    b: "07",
                    n: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                    h: "01",
                    Gx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    Gy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
                },
                secp256r1: {
                    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                    a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                    h: "01",
                    Gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    Gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                }
            };
        }, {} ],
        12: [ function(require, module, exports) {
            var Point = require("./point");
            var Curve = require("./curve");
            var getCurveByName = require("./names");
            module.exports = {
                Curve: Curve,
                Point: Point,
                getCurveByName: getCurveByName
            };
        }, {
            "./curve": 10,
            "./names": 13,
            "./point": 14
        } ],
        13: [ function(require, module, exports) {
            var BigInteger = require("bigi");
            var curves = require("./curves");
            var Curve = require("./curve");
            function getCurveByName(name) {
                var curve = curves[name];
                if (!curve) return null;
                var p = new BigInteger(curve.p, 16);
                var a = new BigInteger(curve.a, 16);
                var b = new BigInteger(curve.b, 16);
                var n = new BigInteger(curve.n, 16);
                var h = new BigInteger(curve.h, 16);
                var Gx = new BigInteger(curve.Gx, 16);
                var Gy = new BigInteger(curve.Gy, 16);
                return new Curve(p, a, b, Gx, Gy, n, h);
            }
            module.exports = getCurveByName;
        }, {
            "./curve": 10,
            "./curves": 11,
            bigi: 8
        } ],
        14: [ function(require, module, exports) {
            (function(Buffer) {
                var assert = require("assert");
                var BigInteger = require("bigi");
                var THREE = BigInteger.valueOf(3);
                function Point(curve, x, y, z) {
                    assert.notStrictEqual(z, undefined, "Missing Z coordinate");
                    this.curve = curve;
                    this.x = x;
                    this.y = y;
                    this.z = z;
                    this._zInv = null;
                    this.compressed = true;
                }
                Object.defineProperty(Point.prototype, "zInv", {
                    get: function() {
                        if (this._zInv === null) {
                            this._zInv = this.z.modInverse(this.curve.p);
                        }
                        return this._zInv;
                    }
                });
                Object.defineProperty(Point.prototype, "affineX", {
                    get: function() {
                        return this.x.multiply(this.zInv).mod(this.curve.p);
                    }
                });
                Object.defineProperty(Point.prototype, "affineY", {
                    get: function() {
                        return this.y.multiply(this.zInv).mod(this.curve.p);
                    }
                });
                Point.fromAffine = function(curve, x, y) {
                    return new Point(curve, x, y, BigInteger.ONE);
                };
                Point.prototype.equals = function(other) {
                    if (other === this) return true;
                    if (this.curve.isInfinity(this)) return this.curve.isInfinity(other);
                    if (this.curve.isInfinity(other)) return this.curve.isInfinity(this);
                    var u = other.y.multiply(this.z).subtract(this.y.multiply(other.z)).mod(this.curve.p);
                    if (u.signum() !== 0) return false;
                    var v = other.x.multiply(this.z).subtract(this.x.multiply(other.z)).mod(this.curve.p);
                    return v.signum() === 0;
                };
                Point.prototype.negate = function() {
                    var y = this.curve.p.subtract(this.y);
                    return new Point(this.curve, this.x, y, this.z);
                };
                Point.prototype.add = function(b) {
                    if (this.curve.isInfinity(this)) return b;
                    if (this.curve.isInfinity(b)) return this;
                    var x1 = this.x;
                    var y1 = this.y;
                    var x2 = b.x;
                    var y2 = b.y;
                    var u = y2.multiply(this.z).subtract(y1.multiply(b.z)).mod(this.curve.p);
                    var v = x2.multiply(this.z).subtract(x1.multiply(b.z)).mod(this.curve.p);
                    if (v.signum() === 0) {
                        if (u.signum() === 0) {
                            return this.twice();
                        }
                        return this.curve.infinity;
                    }
                    var v2 = v.square();
                    var v3 = v2.multiply(v);
                    var x1v2 = x1.multiply(v2);
                    var zu2 = u.square().multiply(this.z);
                    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.p);
                    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.p);
                    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.p);
                    return new Point(this.curve, x3, y3, z3);
                };
                Point.prototype.twice = function() {
                    if (this.curve.isInfinity(this)) return this;
                    if (this.y.signum() === 0) return this.curve.infinity;
                    var x1 = this.x;
                    var y1 = this.y;
                    var y1z1 = y1.multiply(this.z);
                    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.p);
                    var a = this.curve.a;
                    var w = x1.square().multiply(THREE);
                    if (a.signum() !== 0) {
                        w = w.add(this.z.square().multiply(a));
                    }
                    w = w.mod(this.curve.p);
                    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.p);
                    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.pow(3)).mod(this.curve.p);
                    var z3 = y1z1.pow(3).shiftLeft(3).mod(this.curve.p);
                    return new Point(this.curve, x3, y3, z3);
                };
                Point.prototype.multiply = function(k) {
                    if (this.curve.isInfinity(this)) return this;
                    if (k.signum() === 0) return this.curve.infinity;
                    var e = k;
                    var h = e.multiply(THREE);
                    var neg = this.negate();
                    var R = this;
                    for (var i = h.bitLength() - 2; i > 0; --i) {
                        R = R.twice();
                        var hBit = h.testBit(i);
                        var eBit = e.testBit(i);
                        if (hBit != eBit) {
                            R = R.add(hBit ? this : neg);
                        }
                    }
                    return R;
                };
                Point.prototype.multiplyTwo = function(j, x, k) {
                    var i;
                    if (j.bitLength() > k.bitLength()) i = j.bitLength() - 1; else i = k.bitLength() - 1;
                    var R = this.curve.infinity;
                    var both = this.add(x);
                    while (i >= 0) {
                        R = R.twice();
                        var jBit = j.testBit(i);
                        var kBit = k.testBit(i);
                        if (jBit) {
                            if (kBit) {
                                R = R.add(both);
                            } else {
                                R = R.add(this);
                            }
                        } else {
                            if (kBit) {
                                R = R.add(x);
                            }
                        }
                        --i;
                    }
                    return R;
                };
                Point.prototype.getEncoded = function(compressed) {
                    if (compressed == undefined) compressed = this.compressed;
                    if (this.curve.isInfinity(this)) return new Buffer("00", "hex");
                    var x = this.affineX;
                    var y = this.affineY;
                    var buffer;
                    var byteLength = Math.floor((this.curve.p.bitLength() + 7) / 8);
                    if (compressed) {
                        buffer = new Buffer(1 + byteLength);
                        buffer.writeUInt8(y.isEven() ? 2 : 3, 0);
                    } else {
                        buffer = new Buffer(1 + byteLength + byteLength);
                        buffer.writeUInt8(4, 0);
                        y.toBuffer(byteLength).copy(buffer, 1 + byteLength);
                    }
                    x.toBuffer(byteLength).copy(buffer, 1);
                    return buffer;
                };
                Point.decodeFrom = function(curve, buffer) {
                    var type = buffer.readUInt8(0);
                    var compressed = type !== 4;
                    var x = BigInteger.fromBuffer(buffer.slice(1, 33));
                    var byteLength = Math.floor((curve.p.bitLength() + 7) / 8);
                    var Q;
                    if (compressed) {
                        assert.equal(buffer.length, byteLength + 1, "Invalid sequence length");
                        assert(type === 2 || type === 3, "Invalid sequence tag");
                        var isOdd = type === 3;
                        Q = curve.pointFromX(isOdd, x);
                    } else {
                        assert.equal(buffer.length, 1 + byteLength + byteLength, "Invalid sequence length");
                        var y = BigInteger.fromBuffer(buffer.slice(1 + byteLength));
                        Q = Point.fromAffine(curve, x, y);
                    }
                    Q.compressed = compressed;
                    return Q;
                };
                Point.prototype.toString = function() {
                    if (this.curve.isInfinity(this)) return "(INFINITY)";
                    return "(" + this.affineX.toString() + "," + this.affineY.toString() + ")";
                };
                module.exports = Point;
            }).call(this, require("buffer").Buffer);
        }, {
            assert: 41,
            bigi: 8,
            buffer: 43
        } ],
        15: [ function(require, module, exports) {
            (function(process, Buffer) {
                !function(globals) {
                    "use strict";
                    if (typeof define !== "undefined" && define.amd) {
                        define([], function() {
                            return secureRandom;
                        });
                    } else if (typeof module !== "undefined" && module.exports) {
                        module.exports = secureRandom;
                    } else {
                        globals.secureRandom = secureRandom;
                    }
                    function secureRandom(count, options) {
                        options = options || {
                            type: "Array"
                        };
                        if (typeof process != "undefined" && typeof process.pid == "number") {
                            return nodeRandom(count, options);
                        } else {
                            var crypto = window.crypto || window.msCrypto;
                            if (!crypto) throw new Error("Your browser does not support window.crypto.");
                            return browserRandom(count, options);
                        }
                    }
                    function nodeRandom(count, options) {
                        var crypto = require("crypto");
                        var buf = crypto.randomBytes(count);
                        switch (options.type) {
                          case "Array":
                            return [].slice.call(buf);

                          case "Buffer":
                            return buf;

                          case "Uint8Array":
                            var arr = new Uint8Array(count);
                            for (var i = 0; i < count; ++i) {
                                arr[i] = buf.readUInt8(i);
                            }
                            return arr;

                          default:
                            throw new Error(options.type + " is unsupported.");
                        }
                    }
                    function browserRandom(count, options) {
                        var nativeArr = new Uint8Array(count);
                        var crypto = window.crypto || window.msCrypto;
                        crypto.getRandomValues(nativeArr);
                        switch (options.type) {
                          case "Array":
                            return [].slice.call(nativeArr);

                          case "Buffer":
                            try {
                                var b = new Buffer(1);
                            } catch (e) {
                                throw new Error("Buffer not supported in this environment. Use Node.js or Browserify for browser support.");
                            }
                            return new Buffer(nativeArr);

                          case "Uint8Array":
                            return nativeArr;

                          default:
                            throw new Error(options.type + " is unsupported.");
                        }
                    }
                    secureRandom.randomArray = function(byteCount) {
                        return secureRandom(byteCount, {
                            type: "Array"
                        });
                    };
                    secureRandom.randomUint8Array = function(byteCount) {
                        return secureRandom(byteCount, {
                            type: "Uint8Array"
                        });
                    };
                    secureRandom.randomBuffer = function(byteCount) {
                        return secureRandom(byteCount, {
                            type: "Buffer"
                        });
                    };
                }(this);
            }).call(this, require("_process"), require("buffer").Buffer);
        }, {
            _process: 48,
            buffer: 43,
            crypto: 42
        } ],
        16: [ function(require, module, exports) {
            (function(Buffer) {
                var createHash = require("sha.js");
                var md5 = toConstructor(require("./md5"));
                var rmd160 = toConstructor(require("ripemd160"));
                function toConstructor(fn) {
                    return function() {
                        var buffers = [];
                        var m = {
                            update: function(data, enc) {
                                if (!Buffer.isBuffer(data)) data = new Buffer(data, enc);
                                buffers.push(data);
                                return this;
                            },
                            digest: function(enc) {
                                var buf = Buffer.concat(buffers);
                                var r = fn(buf);
                                buffers = null;
                                return enc ? r.toString(enc) : r;
                            }
                        };
                        return m;
                    };
                }
                module.exports = function(alg) {
                    if ("md5" === alg) return new md5();
                    if ("rmd160" === alg) return new rmd160();
                    return createHash(alg);
                };
            }).call(this, require("buffer").Buffer);
        }, {
            "./md5": 20,
            buffer: 43,
            ripemd160: 22,
            "sha.js": 24
        } ],
        17: [ function(require, module, exports) {
            (function(Buffer) {
                var createHash = require("./create-hash");
                var zeroBuffer = new Buffer(128);
                zeroBuffer.fill(0);
                module.exports = Hmac;
                function Hmac(alg, key) {
                    if (!(this instanceof Hmac)) return new Hmac(alg, key);
                    this._opad = opad;
                    this._alg = alg;
                    var blocksize = alg === "sha512" ? 128 : 64;
                    key = this._key = !Buffer.isBuffer(key) ? new Buffer(key) : key;
                    if (key.length > blocksize) {
                        key = createHash(alg).update(key).digest();
                    } else if (key.length < blocksize) {
                        key = Buffer.concat([ key, zeroBuffer ], blocksize);
                    }
                    var ipad = this._ipad = new Buffer(blocksize);
                    var opad = this._opad = new Buffer(blocksize);
                    for (var i = 0; i < blocksize; i++) {
                        ipad[i] = key[i] ^ 54;
                        opad[i] = key[i] ^ 92;
                    }
                    this._hash = createHash(alg).update(ipad);
                }
                Hmac.prototype.update = function(data, enc) {
                    this._hash.update(data, enc);
                    return this;
                };
                Hmac.prototype.digest = function(enc) {
                    var h = this._hash.digest();
                    return createHash(this._alg).update(this._opad).update(h).digest(enc);
                };
            }).call(this, require("buffer").Buffer);
        }, {
            "./create-hash": 16,
            buffer: 43
        } ],
        18: [ function(require, module, exports) {
            (function(Buffer) {
                var intSize = 4;
                var zeroBuffer = new Buffer(intSize);
                zeroBuffer.fill(0);
                var chrsz = 8;
                function toArray(buf, bigEndian) {
                    if (buf.length % intSize !== 0) {
                        var len = buf.length + (intSize - buf.length % intSize);
                        buf = Buffer.concat([ buf, zeroBuffer ], len);
                    }
                    var arr = [];
                    var fn = bigEndian ? buf.readInt32BE : buf.readInt32LE;
                    for (var i = 0; i < buf.length; i += intSize) {
                        arr.push(fn.call(buf, i));
                    }
                    return arr;
                }
                function toBuffer(arr, size, bigEndian) {
                    var buf = new Buffer(size);
                    var fn = bigEndian ? buf.writeInt32BE : buf.writeInt32LE;
                    for (var i = 0; i < arr.length; i++) {
                        fn.call(buf, arr[i], i * 4, true);
                    }
                    return buf;
                }
                function hash(buf, fn, hashSize, bigEndian) {
                    if (!Buffer.isBuffer(buf)) buf = new Buffer(buf);
                    var arr = fn(toArray(buf, bigEndian), buf.length * chrsz);
                    return toBuffer(arr, hashSize, bigEndian);
                }
                module.exports = {
                    hash: hash
                };
            }).call(this, require("buffer").Buffer);
        }, {
            buffer: 43
        } ],
        19: [ function(require, module, exports) {
            (function(Buffer) {
                var rng = require("./rng");
                function error() {
                    var m = [].slice.call(arguments).join(" ");
                    throw new Error([ m, "we accept pull requests", "http://github.com/dominictarr/crypto-browserify" ].join("\n"));
                }
                exports.createHash = require("./create-hash");
                exports.createHmac = require("./create-hmac");
                exports.randomBytes = function(size, callback) {
                    if (callback && callback.call) {
                        try {
                            callback.call(this, undefined, new Buffer(rng(size)));
                        } catch (err) {
                            callback(err);
                        }
                    } else {
                        return new Buffer(rng(size));
                    }
                };
                function each(a, f) {
                    for (var i in a) f(a[i], i);
                }
                exports.getHashes = function() {
                    return [ "sha1", "sha256", "sha512", "md5", "rmd160" ];
                };
                var p = require("./pbkdf2")(exports);
                exports.pbkdf2 = p.pbkdf2;
                exports.pbkdf2Sync = p.pbkdf2Sync;
                each([ "createCredentials", "createCipher", "createCipheriv", "createDecipher", "createDecipheriv", "createSign", "createVerify", "createDiffieHellman" ], function(name) {
                    exports[name] = function() {
                        error("sorry,", name, "is not implemented yet");
                    };
                });
            }).call(this, require("buffer").Buffer);
        }, {
            "./create-hash": 16,
            "./create-hmac": 17,
            "./pbkdf2": 28,
            "./rng": 29,
            buffer: 43
        } ],
        20: [ function(require, module, exports) {
            var helpers = require("./helpers");
            function core_md5(x, len) {
                x[len >> 5] |= 128 << len % 32;
                x[(len + 64 >>> 9 << 4) + 14] = len;
                var a = 1732584193;
                var b = -271733879;
                var c = -1732584194;
                var d = 271733878;
                for (var i = 0; i < x.length; i += 16) {
                    var olda = a;
                    var oldb = b;
                    var oldc = c;
                    var oldd = d;
                    a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
                    d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
                    c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
                    b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
                    a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
                    d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
                    c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
                    b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
                    a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
                    d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
                    c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
                    b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
                    a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
                    d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
                    c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
                    b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);
                    a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
                    d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
                    c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
                    b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
                    a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
                    d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
                    c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
                    b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
                    a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
                    d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
                    c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
                    b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
                    a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
                    d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
                    c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
                    b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);
                    a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
                    d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
                    c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
                    b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
                    a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
                    d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
                    c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
                    b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
                    a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
                    d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
                    c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
                    b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
                    a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
                    d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
                    c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
                    b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);
                    a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
                    d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
                    c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
                    b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
                    a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
                    d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
                    c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
                    b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
                    a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
                    d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
                    c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
                    b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
                    a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
                    d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
                    c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
                    b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);
                    a = safe_add(a, olda);
                    b = safe_add(b, oldb);
                    c = safe_add(c, oldc);
                    d = safe_add(d, oldd);
                }
                return Array(a, b, c, d);
            }
            function md5_cmn(q, a, b, x, s, t) {
                return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
            }
            function md5_ff(a, b, c, d, x, s, t) {
                return md5_cmn(b & c | ~b & d, a, b, x, s, t);
            }
            function md5_gg(a, b, c, d, x, s, t) {
                return md5_cmn(b & d | c & ~d, a, b, x, s, t);
            }
            function md5_hh(a, b, c, d, x, s, t) {
                return md5_cmn(b ^ c ^ d, a, b, x, s, t);
            }
            function md5_ii(a, b, c, d, x, s, t) {
                return md5_cmn(c ^ (b | ~d), a, b, x, s, t);
            }
            function safe_add(x, y) {
                var lsw = (x & 65535) + (y & 65535);
                var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
                return msw << 16 | lsw & 65535;
            }
            function bit_rol(num, cnt) {
                return num << cnt | num >>> 32 - cnt;
            }
            module.exports = function md5(buf) {
                return helpers.hash(buf, core_md5, 16);
            };
        }, {
            "./helpers": 18
        } ],
        21: [ function(require, module, exports) {
            (function(Buffer) {
                module.exports = function(crypto) {
                    function pbkdf2(password, salt, iterations, keylen, digest, callback) {
                        if ("function" === typeof digest) {
                            callback = digest;
                            digest = undefined;
                        }
                        if ("function" !== typeof callback) throw new Error("No callback provided to pbkdf2");
                        setTimeout(function() {
                            var result;
                            try {
                                result = pbkdf2Sync(password, salt, iterations, keylen, digest);
                            } catch (e) {
                                return callback(e);
                            }
                            callback(undefined, result);
                        });
                    }
                    function pbkdf2Sync(password, salt, iterations, keylen, digest) {
                        if ("number" !== typeof iterations) throw new TypeError("Iterations not a number");
                        if (iterations < 0) throw new TypeError("Bad iterations");
                        if ("number" !== typeof keylen) throw new TypeError("Key length not a number");
                        if (keylen < 0) throw new TypeError("Bad key length");
                        digest = digest || "sha1";
                        if (!Buffer.isBuffer(password)) password = new Buffer(password);
                        if (!Buffer.isBuffer(salt)) salt = new Buffer(salt);
                        var hLen, l = 1, r, T;
                        var DK = new Buffer(keylen);
                        var block1 = new Buffer(salt.length + 4);
                        salt.copy(block1, 0, 0, salt.length);
                        for (var i = 1; i <= l; i++) {
                            block1.writeUInt32BE(i, salt.length);
                            var U = crypto.createHmac(digest, password).update(block1).digest();
                            if (!hLen) {
                                hLen = U.length;
                                T = new Buffer(hLen);
                                l = Math.ceil(keylen / hLen);
                                r = keylen - (l - 1) * hLen;
                                if (keylen > (Math.pow(2, 32) - 1) * hLen) throw new TypeError("keylen exceeds maximum length");
                            }
                            U.copy(T, 0, 0, hLen);
                            for (var j = 1; j < iterations; j++) {
                                U = crypto.createHmac(digest, password).update(U).digest();
                                for (var k = 0; k < hLen; k++) {
                                    T[k] ^= U[k];
                                }
                            }
                            var destPos = (i - 1) * hLen;
                            var len = i == l ? r : hLen;
                            T.copy(DK, destPos, 0, len);
                        }
                        return DK;
                    }
                    return {
                        pbkdf2: pbkdf2,
                        pbkdf2Sync: pbkdf2Sync
                    };
                };
            }).call(this, require("buffer").Buffer);
        }, {
            buffer: 43
        } ],
        22: [ function(require, module, exports) {
            (function(Buffer) {
                module.exports = ripemd160;
                var zl = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 ];
                var zr = [ 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 ];
                var sl = [ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 ];
                var sr = [ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 ];
                var hl = [ 0, 1518500249, 1859775393, 2400959708, 2840853838 ];
                var hr = [ 1352829926, 1548603684, 1836072691, 2053994217, 0 ];
                var bytesToWords = function(bytes) {
                    var words = [];
                    for (var i = 0, b = 0; i < bytes.length; i++, b += 8) {
                        words[b >>> 5] |= bytes[i] << 24 - b % 32;
                    }
                    return words;
                };
                var wordsToBytes = function(words) {
                    var bytes = [];
                    for (var b = 0; b < words.length * 32; b += 8) {
                        bytes.push(words[b >>> 5] >>> 24 - b % 32 & 255);
                    }
                    return bytes;
                };
                var processBlock = function(H, M, offset) {
                    for (var i = 0; i < 16; i++) {
                        var offset_i = offset + i;
                        var M_offset_i = M[offset_i];
                        M[offset_i] = (M_offset_i << 8 | M_offset_i >>> 24) & 16711935 | (M_offset_i << 24 | M_offset_i >>> 8) & 4278255360;
                    }
                    var al, bl, cl, dl, el;
                    var ar, br, cr, dr, er;
                    ar = al = H[0];
                    br = bl = H[1];
                    cr = cl = H[2];
                    dr = dl = H[3];
                    er = el = H[4];
                    var t;
                    for (var i = 0; i < 80; i += 1) {
                        t = al + M[offset + zl[i]] | 0;
                        if (i < 16) {
                            t += f1(bl, cl, dl) + hl[0];
                        } else if (i < 32) {
                            t += f2(bl, cl, dl) + hl[1];
                        } else if (i < 48) {
                            t += f3(bl, cl, dl) + hl[2];
                        } else if (i < 64) {
                            t += f4(bl, cl, dl) + hl[3];
                        } else {
                            t += f5(bl, cl, dl) + hl[4];
                        }
                        t = t | 0;
                        t = rotl(t, sl[i]);
                        t = t + el | 0;
                        al = el;
                        el = dl;
                        dl = rotl(cl, 10);
                        cl = bl;
                        bl = t;
                        t = ar + M[offset + zr[i]] | 0;
                        if (i < 16) {
                            t += f5(br, cr, dr) + hr[0];
                        } else if (i < 32) {
                            t += f4(br, cr, dr) + hr[1];
                        } else if (i < 48) {
                            t += f3(br, cr, dr) + hr[2];
                        } else if (i < 64) {
                            t += f2(br, cr, dr) + hr[3];
                        } else {
                            t += f1(br, cr, dr) + hr[4];
                        }
                        t = t | 0;
                        t = rotl(t, sr[i]);
                        t = t + er | 0;
                        ar = er;
                        er = dr;
                        dr = rotl(cr, 10);
                        cr = br;
                        br = t;
                    }
                    t = H[1] + cl + dr | 0;
                    H[1] = H[2] + dl + er | 0;
                    H[2] = H[3] + el + ar | 0;
                    H[3] = H[4] + al + br | 0;
                    H[4] = H[0] + bl + cr | 0;
                    H[0] = t;
                };
                function f1(x, y, z) {
                    return x ^ y ^ z;
                }
                function f2(x, y, z) {
                    return x & y | ~x & z;
                }
                function f3(x, y, z) {
                    return (x | ~y) ^ z;
                }
                function f4(x, y, z) {
                    return x & z | y & ~z;
                }
                function f5(x, y, z) {
                    return x ^ (y | ~z);
                }
                function rotl(x, n) {
                    return x << n | x >>> 32 - n;
                }
                function ripemd160(message) {
                    var H = [ 1732584193, 4023233417, 2562383102, 271733878, 3285377520 ];
                    if (typeof message == "string") message = new Buffer(message, "utf8");
                    var m = bytesToWords(message);
                    var nBitsLeft = message.length * 8;
                    var nBitsTotal = message.length * 8;
                    m[nBitsLeft >>> 5] |= 128 << 24 - nBitsLeft % 32;
                    m[(nBitsLeft + 64 >>> 9 << 4) + 14] = (nBitsTotal << 8 | nBitsTotal >>> 24) & 16711935 | (nBitsTotal << 24 | nBitsTotal >>> 8) & 4278255360;
                    for (var i = 0; i < m.length; i += 16) {
                        processBlock(H, m, i);
                    }
                    for (var i = 0; i < 5; i++) {
                        var H_i = H[i];
                        H[i] = (H_i << 8 | H_i >>> 24) & 16711935 | (H_i << 24 | H_i >>> 8) & 4278255360;
                    }
                    var digestbytes = wordsToBytes(H);
                    return new Buffer(digestbytes);
                }
            }).call(this, require("buffer").Buffer);
        }, {
            buffer: 43
        } ],
        23: [ function(require, module, exports) {
            module.exports = function(Buffer) {
                function Hash(blockSize, finalSize) {
                    this._block = new Buffer(blockSize);
                    this._finalSize = finalSize;
                    this._blockSize = blockSize;
                    this._len = 0;
                    this._s = 0;
                }
                Hash.prototype.init = function() {
                    this._s = 0;
                    this._len = 0;
                };
                Hash.prototype.update = function(data, enc) {
                    if ("string" === typeof data) {
                        enc = enc || "utf8";
                        data = new Buffer(data, enc);
                    }
                    var l = this._len += data.length;
                    var s = this._s = this._s || 0;
                    var f = 0;
                    var buffer = this._block;
                    while (s < l) {
                        var t = Math.min(data.length, f + this._blockSize - s % this._blockSize);
                        var ch = t - f;
                        for (var i = 0; i < ch; i++) {
                            buffer[s % this._blockSize + i] = data[i + f];
                        }
                        s += ch;
                        f += ch;
                        if (s % this._blockSize === 0) {
                            this._update(buffer);
                        }
                    }
                    this._s = s;
                    return this;
                };
                Hash.prototype.digest = function(enc) {
                    var l = this._len * 8;
                    this._block[this._len % this._blockSize] = 128;
                    this._block.fill(0, this._len % this._blockSize + 1);
                    if (l % (this._blockSize * 8) >= this._finalSize * 8) {
                        this._update(this._block);
                        this._block.fill(0);
                    }
                    this._block.writeInt32BE(l, this._blockSize - 4);
                    var hash = this._update(this._block) || this._hash();
                    return enc ? hash.toString(enc) : hash;
                };
                Hash.prototype._update = function() {
                    throw new Error("_update must be implemented by subclass");
                };
                return Hash;
            };
        }, {} ],
        24: [ function(require, module, exports) {
            var exports = module.exports = function(alg) {
                var Alg = exports[alg];
                if (!Alg) throw new Error(alg + " is not supported (we accept pull requests)");
                return new Alg();
            };
            var Buffer = require("buffer").Buffer;
            var Hash = require("./hash")(Buffer);
            exports.sha1 = require("./sha1")(Buffer, Hash);
            exports.sha256 = require("./sha256")(Buffer, Hash);
            exports.sha512 = require("./sha512")(Buffer, Hash);
        }, {
            "./hash": 23,
            "./sha1": 25,
            "./sha256": 26,
            "./sha512": 27,
            buffer: 43
        } ],
        25: [ function(require, module, exports) {
            var inherits = require("util").inherits;
            module.exports = function(Buffer, Hash) {
                var A = 0 | 0;
                var B = 4 | 0;
                var C = 8 | 0;
                var D = 12 | 0;
                var E = 16 | 0;
                var W = new (typeof Int32Array === "undefined" ? Array : Int32Array)(80);
                var POOL = [];
                function Sha1() {
                    if (POOL.length) return POOL.pop().init();
                    if (!(this instanceof Sha1)) return new Sha1();
                    this._w = W;
                    Hash.call(this, 16 * 4, 14 * 4);
                    this._h = null;
                    this.init();
                }
                inherits(Sha1, Hash);
                Sha1.prototype.init = function() {
                    this._a = 1732584193;
                    this._b = 4023233417;
                    this._c = 2562383102;
                    this._d = 271733878;
                    this._e = 3285377520;
                    Hash.prototype.init.call(this);
                    return this;
                };
                Sha1.prototype._POOL = POOL;
                Sha1.prototype._update = function(X) {
                    var a, b, c, d, e, _a, _b, _c, _d, _e;
                    a = _a = this._a;
                    b = _b = this._b;
                    c = _c = this._c;
                    d = _d = this._d;
                    e = _e = this._e;
                    var w = this._w;
                    for (var j = 0; j < 80; j++) {
                        var W = w[j] = j < 16 ? X.readInt32BE(j * 4) : rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                        var t = add(add(rol(a, 5), sha1_ft(j, b, c, d)), add(add(e, W), sha1_kt(j)));
                        e = d;
                        d = c;
                        c = rol(b, 30);
                        b = a;
                        a = t;
                    }
                    this._a = add(a, _a);
                    this._b = add(b, _b);
                    this._c = add(c, _c);
                    this._d = add(d, _d);
                    this._e = add(e, _e);
                };
                Sha1.prototype._hash = function() {
                    if (POOL.length < 100) POOL.push(this);
                    var H = new Buffer(20);
                    H.writeInt32BE(this._a | 0, A);
                    H.writeInt32BE(this._b | 0, B);
                    H.writeInt32BE(this._c | 0, C);
                    H.writeInt32BE(this._d | 0, D);
                    H.writeInt32BE(this._e | 0, E);
                    return H;
                };
                function sha1_ft(t, b, c, d) {
                    if (t < 20) return b & c | ~b & d;
                    if (t < 40) return b ^ c ^ d;
                    if (t < 60) return b & c | b & d | c & d;
                    return b ^ c ^ d;
                }
                function sha1_kt(t) {
                    return t < 20 ? 1518500249 : t < 40 ? 1859775393 : t < 60 ? -1894007588 : -899497514;
                }
                function add(x, y) {
                    return x + y | 0;
                }
                function rol(num, cnt) {
                    return num << cnt | num >>> 32 - cnt;
                }
                return Sha1;
            };
        }, {
            util: 50
        } ],
        26: [ function(require, module, exports) {
            var inherits = require("util").inherits;
            module.exports = function(Buffer, Hash) {
                var K = [ 1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298 ];
                var W = new Array(64);
                function Sha256() {
                    this.init();
                    this._w = W;
                    Hash.call(this, 16 * 4, 14 * 4);
                }
                inherits(Sha256, Hash);
                Sha256.prototype.init = function() {
                    this._a = 1779033703 | 0;
                    this._b = 3144134277 | 0;
                    this._c = 1013904242 | 0;
                    this._d = 2773480762 | 0;
                    this._e = 1359893119 | 0;
                    this._f = 2600822924 | 0;
                    this._g = 528734635 | 0;
                    this._h = 1541459225 | 0;
                    this._len = this._s = 0;
                    return this;
                };
                function S(X, n) {
                    return X >>> n | X << 32 - n;
                }
                function R(X, n) {
                    return X >>> n;
                }
                function Ch(x, y, z) {
                    return x & y ^ ~x & z;
                }
                function Maj(x, y, z) {
                    return x & y ^ x & z ^ y & z;
                }
                function Sigma0256(x) {
                    return S(x, 2) ^ S(x, 13) ^ S(x, 22);
                }
                function Sigma1256(x) {
                    return S(x, 6) ^ S(x, 11) ^ S(x, 25);
                }
                function Gamma0256(x) {
                    return S(x, 7) ^ S(x, 18) ^ R(x, 3);
                }
                function Gamma1256(x) {
                    return S(x, 17) ^ S(x, 19) ^ R(x, 10);
                }
                Sha256.prototype._update = function(M) {
                    var W = this._w;
                    var a, b, c, d, e, f, g, h;
                    var T1, T2;
                    a = this._a | 0;
                    b = this._b | 0;
                    c = this._c | 0;
                    d = this._d | 0;
                    e = this._e | 0;
                    f = this._f | 0;
                    g = this._g | 0;
                    h = this._h | 0;
                    for (var j = 0; j < 64; j++) {
                        var w = W[j] = j < 16 ? M.readInt32BE(j * 4) : Gamma1256(W[j - 2]) + W[j - 7] + Gamma0256(W[j - 15]) + W[j - 16];
                        T1 = h + Sigma1256(e) + Ch(e, f, g) + K[j] + w;
                        T2 = Sigma0256(a) + Maj(a, b, c);
                        h = g;
                        g = f;
                        f = e;
                        e = d + T1;
                        d = c;
                        c = b;
                        b = a;
                        a = T1 + T2;
                    }
                    this._a = a + this._a | 0;
                    this._b = b + this._b | 0;
                    this._c = c + this._c | 0;
                    this._d = d + this._d | 0;
                    this._e = e + this._e | 0;
                    this._f = f + this._f | 0;
                    this._g = g + this._g | 0;
                    this._h = h + this._h | 0;
                };
                Sha256.prototype._hash = function() {
                    var H = new Buffer(32);
                    H.writeInt32BE(this._a, 0);
                    H.writeInt32BE(this._b, 4);
                    H.writeInt32BE(this._c, 8);
                    H.writeInt32BE(this._d, 12);
                    H.writeInt32BE(this._e, 16);
                    H.writeInt32BE(this._f, 20);
                    H.writeInt32BE(this._g, 24);
                    H.writeInt32BE(this._h, 28);
                    return H;
                };
                return Sha256;
            };
        }, {
            util: 50
        } ],
        27: [ function(require, module, exports) {
            var inherits = require("util").inherits;
            module.exports = function(Buffer, Hash) {
                var K = [ 1116352408, 3609767458, 1899447441, 602891725, 3049323471, 3964484399, 3921009573, 2173295548, 961987163, 4081628472, 1508970993, 3053834265, 2453635748, 2937671579, 2870763221, 3664609560, 3624381080, 2734883394, 310598401, 1164996542, 607225278, 1323610764, 1426881987, 3590304994, 1925078388, 4068182383, 2162078206, 991336113, 2614888103, 633803317, 3248222580, 3479774868, 3835390401, 2666613458, 4022224774, 944711139, 264347078, 2341262773, 604807628, 2007800933, 770255983, 1495990901, 1249150122, 1856431235, 1555081692, 3175218132, 1996064986, 2198950837, 2554220882, 3999719339, 2821834349, 766784016, 2952996808, 2566594879, 3210313671, 3203337956, 3336571891, 1034457026, 3584528711, 2466948901, 113926993, 3758326383, 338241895, 168717936, 666307205, 1188179964, 773529912, 1546045734, 1294757372, 1522805485, 1396182291, 2643833823, 1695183700, 2343527390, 1986661051, 1014477480, 2177026350, 1206759142, 2456956037, 344077627, 2730485921, 1290863460, 2820302411, 3158454273, 3259730800, 3505952657, 3345764771, 106217008, 3516065817, 3606008344, 3600352804, 1432725776, 4094571909, 1467031594, 275423344, 851169720, 430227734, 3100823752, 506948616, 1363258195, 659060556, 3750685593, 883997877, 3785050280, 958139571, 3318307427, 1322822218, 3812723403, 1537002063, 2003034995, 1747873779, 3602036899, 1955562222, 1575990012, 2024104815, 1125592928, 2227730452, 2716904306, 2361852424, 442776044, 2428436474, 593698344, 2756734187, 3733110249, 3204031479, 2999351573, 3329325298, 3815920427, 3391569614, 3928383900, 3515267271, 566280711, 3940187606, 3454069534, 4118630271, 4000239992, 116418474, 1914138554, 174292421, 2731055270, 289380356, 3203993006, 460393269, 320620315, 685471733, 587496836, 852142971, 1086792851, 1017036298, 365543100, 1126000580, 2618297676, 1288033470, 3409855158, 1501505948, 4234509866, 1607167915, 987167468, 1816402316, 1246189591 ];
                var W = new Array(160);
                function Sha512() {
                    this.init();
                    this._w = W;
                    Hash.call(this, 128, 112);
                }
                inherits(Sha512, Hash);
                Sha512.prototype.init = function() {
                    this._a = 1779033703 | 0;
                    this._b = 3144134277 | 0;
                    this._c = 1013904242 | 0;
                    this._d = 2773480762 | 0;
                    this._e = 1359893119 | 0;
                    this._f = 2600822924 | 0;
                    this._g = 528734635 | 0;
                    this._h = 1541459225 | 0;
                    this._al = 4089235720 | 0;
                    this._bl = 2227873595 | 0;
                    this._cl = 4271175723 | 0;
                    this._dl = 1595750129 | 0;
                    this._el = 2917565137 | 0;
                    this._fl = 725511199 | 0;
                    this._gl = 4215389547 | 0;
                    this._hl = 327033209 | 0;
                    this._len = this._s = 0;
                    return this;
                };
                function S(X, Xl, n) {
                    return X >>> n | Xl << 32 - n;
                }
                function Ch(x, y, z) {
                    return x & y ^ ~x & z;
                }
                function Maj(x, y, z) {
                    return x & y ^ x & z ^ y & z;
                }
                Sha512.prototype._update = function(M) {
                    var W = this._w;
                    var a, b, c, d, e, f, g, h;
                    var al, bl, cl, dl, el, fl, gl, hl;
                    a = this._a | 0;
                    b = this._b | 0;
                    c = this._c | 0;
                    d = this._d | 0;
                    e = this._e | 0;
                    f = this._f | 0;
                    g = this._g | 0;
                    h = this._h | 0;
                    al = this._al | 0;
                    bl = this._bl | 0;
                    cl = this._cl | 0;
                    dl = this._dl | 0;
                    el = this._el | 0;
                    fl = this._fl | 0;
                    gl = this._gl | 0;
                    hl = this._hl | 0;
                    for (var i = 0; i < 80; i++) {
                        var j = i * 2;
                        var Wi, Wil;
                        if (i < 16) {
                            Wi = W[j] = M.readInt32BE(j * 4);
                            Wil = W[j + 1] = M.readInt32BE(j * 4 + 4);
                        } else {
                            var x = W[j - 15 * 2];
                            var xl = W[j - 15 * 2 + 1];
                            var gamma0 = S(x, xl, 1) ^ S(x, xl, 8) ^ x >>> 7;
                            var gamma0l = S(xl, x, 1) ^ S(xl, x, 8) ^ S(xl, x, 7);
                            x = W[j - 2 * 2];
                            xl = W[j - 2 * 2 + 1];
                            var gamma1 = S(x, xl, 19) ^ S(xl, x, 29) ^ x >>> 6;
                            var gamma1l = S(xl, x, 19) ^ S(x, xl, 29) ^ S(xl, x, 6);
                            var Wi7 = W[j - 7 * 2];
                            var Wi7l = W[j - 7 * 2 + 1];
                            var Wi16 = W[j - 16 * 2];
                            var Wi16l = W[j - 16 * 2 + 1];
                            Wil = gamma0l + Wi7l;
                            Wi = gamma0 + Wi7 + (Wil >>> 0 < gamma0l >>> 0 ? 1 : 0);
                            Wil = Wil + gamma1l;
                            Wi = Wi + gamma1 + (Wil >>> 0 < gamma1l >>> 0 ? 1 : 0);
                            Wil = Wil + Wi16l;
                            Wi = Wi + Wi16 + (Wil >>> 0 < Wi16l >>> 0 ? 1 : 0);
                            W[j] = Wi;
                            W[j + 1] = Wil;
                        }
                        var maj = Maj(a, b, c);
                        var majl = Maj(al, bl, cl);
                        var sigma0h = S(a, al, 28) ^ S(al, a, 2) ^ S(al, a, 7);
                        var sigma0l = S(al, a, 28) ^ S(a, al, 2) ^ S(a, al, 7);
                        var sigma1h = S(e, el, 14) ^ S(e, el, 18) ^ S(el, e, 9);
                        var sigma1l = S(el, e, 14) ^ S(el, e, 18) ^ S(e, el, 9);
                        var Ki = K[j];
                        var Kil = K[j + 1];
                        var ch = Ch(e, f, g);
                        var chl = Ch(el, fl, gl);
                        var t1l = hl + sigma1l;
                        var t1 = h + sigma1h + (t1l >>> 0 < hl >>> 0 ? 1 : 0);
                        t1l = t1l + chl;
                        t1 = t1 + ch + (t1l >>> 0 < chl >>> 0 ? 1 : 0);
                        t1l = t1l + Kil;
                        t1 = t1 + Ki + (t1l >>> 0 < Kil >>> 0 ? 1 : 0);
                        t1l = t1l + Wil;
                        t1 = t1 + Wi + (t1l >>> 0 < Wil >>> 0 ? 1 : 0);
                        var t2l = sigma0l + majl;
                        var t2 = sigma0h + maj + (t2l >>> 0 < sigma0l >>> 0 ? 1 : 0);
                        h = g;
                        hl = gl;
                        g = f;
                        gl = fl;
                        f = e;
                        fl = el;
                        el = dl + t1l | 0;
                        e = d + t1 + (el >>> 0 < dl >>> 0 ? 1 : 0) | 0;
                        d = c;
                        dl = cl;
                        c = b;
                        cl = bl;
                        b = a;
                        bl = al;
                        al = t1l + t2l | 0;
                        a = t1 + t2 + (al >>> 0 < t1l >>> 0 ? 1 : 0) | 0;
                    }
                    this._al = this._al + al | 0;
                    this._bl = this._bl + bl | 0;
                    this._cl = this._cl + cl | 0;
                    this._dl = this._dl + dl | 0;
                    this._el = this._el + el | 0;
                    this._fl = this._fl + fl | 0;
                    this._gl = this._gl + gl | 0;
                    this._hl = this._hl + hl | 0;
                    this._a = this._a + a + (this._al >>> 0 < al >>> 0 ? 1 : 0) | 0;
                    this._b = this._b + b + (this._bl >>> 0 < bl >>> 0 ? 1 : 0) | 0;
                    this._c = this._c + c + (this._cl >>> 0 < cl >>> 0 ? 1 : 0) | 0;
                    this._d = this._d + d + (this._dl >>> 0 < dl >>> 0 ? 1 : 0) | 0;
                    this._e = this._e + e + (this._el >>> 0 < el >>> 0 ? 1 : 0) | 0;
                    this._f = this._f + f + (this._fl >>> 0 < fl >>> 0 ? 1 : 0) | 0;
                    this._g = this._g + g + (this._gl >>> 0 < gl >>> 0 ? 1 : 0) | 0;
                    this._h = this._h + h + (this._hl >>> 0 < hl >>> 0 ? 1 : 0) | 0;
                };
                Sha512.prototype._hash = function() {
                    var H = new Buffer(64);
                    function writeInt64BE(h, l, offset) {
                        H.writeInt32BE(h, offset);
                        H.writeInt32BE(l, offset + 4);
                    }
                    writeInt64BE(this._a, this._al, 0);
                    writeInt64BE(this._b, this._bl, 8);
                    writeInt64BE(this._c, this._cl, 16);
                    writeInt64BE(this._d, this._dl, 24);
                    writeInt64BE(this._e, this._el, 32);
                    writeInt64BE(this._f, this._fl, 40);
                    writeInt64BE(this._g, this._gl, 48);
                    writeInt64BE(this._h, this._hl, 56);
                    return H;
                };
                return Sha512;
            };
        }, {
            util: 50
        } ],
        28: [ function(require, module, exports) {
            var pbkdf2Export = require("pbkdf2-compat/pbkdf2");
            module.exports = function(crypto, exports) {
                exports = exports || {};
                var exported = pbkdf2Export(crypto);
                exports.pbkdf2 = exported.pbkdf2;
                exports.pbkdf2Sync = exported.pbkdf2Sync;
                return exports;
            };
        }, {
            "pbkdf2-compat/pbkdf2": 21
        } ],
        29: [ function(require, module, exports) {
            (function(global, Buffer) {
                (function() {
                    var g = ("undefined" === typeof window ? global : window) || {};
                    _crypto = g.crypto || g.msCrypto || require("crypto");
                    module.exports = function(size) {
                        if (_crypto.getRandomValues) {
                            var bytes = new Buffer(size);
                            _crypto.getRandomValues(bytes);
                            return bytes;
                        } else if (_crypto.randomBytes) {
                            return _crypto.randomBytes(size);
                        } else throw new Error("secure random number generation not supported by this browser\n" + "use chrome, FireFox or Internet Explorer 11");
                    };
                })();
            }).call(this, typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {}, require("buffer").Buffer);
        }, {
            buffer: 43,
            crypto: 42
        } ],
        30: [ function(require, module, exports) {
            (function(Buffer) {
                var crypto = require("crypto");
                var assert = require("assert");
                var ecurve = require("ecurve");
                var Point = ecurve.Point;
                var BigInteger = require("bigi");
                var util = require("./util");
                var curve = ecurve.getCurveByName("secp256k1");
                function calcPubKeyRecoveryParam(e, signature, Q) {
                    for (var i = 0; i < 4; i++) {
                        var Qprime = recoverPubKey(e, signature, i);
                        if (Qprime.equals(Q)) {
                            return i;
                        }
                    }
                    throw new Error("Unable to find valid recovery factor");
                }
                function deterministicGenerateK(hash, D) {
                    assert(Buffer.isBuffer(hash), "Hash must be a Buffer, not " + hash);
                    assert.equal(hash.length, 32, "Hash must be 256 bit");
                    assert(BigInteger.isBigInteger(D, true), "Private key must be a BigInteger");
                    var x = D.toBuffer(32);
                    var k = new Buffer(32);
                    var v = new Buffer(32);
                    k.fill(0);
                    v.fill(1);
                    k = util.hmacSHA256(Buffer.concat([ v, new Buffer([ 0 ]), x, hash ]), k);
                    v = util.hmacSHA256(v, k);
                    k = util.hmacSHA256(Buffer.concat([ v, new Buffer([ 1 ]), x, hash ]), k);
                    v = util.hmacSHA256(v, k);
                    v = util.hmacSHA256(v, k);
                    var n = curve.n;
                    var kB = BigInteger.fromBuffer(v).mod(n);
                    assert(kB.compareTo(BigInteger.ONE) > 0, "Invalid k value");
                    assert(kB.compareTo(curve.n) < 0, "Invalid k value");
                    return kB;
                }
                function parseSig(buffer) {
                    assert.equal(buffer.readUInt8(0), 48, "Not a DER sequence");
                    assert.equal(buffer.readUInt8(1), buffer.length - 2, "Invalid sequence length");
                    assert.equal(buffer.readUInt8(2), 2, "Expected a DER integer");
                    var rLen = buffer.readUInt8(3);
                    var rB = buffer.slice(4, 4 + rLen);
                    var offset = 4 + rLen;
                    assert.equal(buffer.readUInt8(offset), 2, "Expected a DER integer (2)");
                    var sLen = buffer.readUInt8(1 + offset);
                    var sB = buffer.slice(2 + offset);
                    offset += 2 + sLen;
                    assert.equal(offset, buffer.length, "Invalid DER encoding");
                    return {
                        r: BigInteger.fromDERInteger(rB),
                        s: BigInteger.fromDERInteger(sB)
                    };
                }
                function parseSigCompact(buffer) {
                    assert.equal(buffer.length, 65, "Invalid signature length");
                    var i = buffer.readUInt8(0) - 27;
                    assert.equal(i, i & 7, "Invalid signature parameter");
                    var compressed = !!(i & 4);
                    i = i & 3;
                    var r = BigInteger.fromBuffer(buffer.slice(1, 33));
                    var s = BigInteger.fromBuffer(buffer.slice(33));
                    return {
                        signature: {
                            r: r,
                            s: s
                        },
                        i: i,
                        compressed: compressed
                    };
                }
                function recoverPubKey(e, signature, i) {
                    assert.strictEqual(i & 3, i, "Recovery param is more than two bits");
                    var n = curve.n;
                    var G = curve.G;
                    var r = signature.r;
                    var s = signature.s;
                    assert(r.signum() > 0 && r.compareTo(n) < 0, "Invalid r value");
                    assert(s.signum() > 0 && s.compareTo(n) < 0, "Invalid s value");
                    var isYOdd = i & 1;
                    var isSecondKey = i >> 1;
                    var x = isSecondKey ? r.add(n) : r;
                    var R = curve.pointFromX(isYOdd, x);
                    var nR = R.multiply(n);
                    assert(curve.isInfinity(nR), "nR is not a valid curve point");
                    var eNeg = e.negate().mod(n);
                    var rInv = r.modInverse(n);
                    var Q = R.multiplyTwo(s, G, eNeg).multiply(rInv);
                    curve.validate(Q);
                    return Q;
                }
                function serializeSig(signature) {
                    var rBa = signature.r.toDERInteger();
                    var sBa = signature.s.toDERInteger();
                    var sequence = [];
                    sequence.push(2);
                    sequence.push(rBa.length);
                    sequence = sequence.concat(rBa);
                    sequence.push(2);
                    sequence.push(sBa.length);
                    sequence = sequence.concat(sBa);
                    sequence.unshift(sequence.length);
                    sequence.unshift(48);
                    return sequence;
                }
                function serializeSigCompact(signature, i, compressed) {
                    if (compressed) {
                        i += 4;
                    }
                    i += 27;
                    var buffer = new Buffer(65);
                    buffer.writeUInt8(i, 0);
                    signature.r.toBuffer(32).copy(buffer, 1);
                    signature.s.toBuffer(32).copy(buffer, 33);
                    return buffer;
                }
                function sign(hash, privateKey) {
                    if (Buffer.isBuffer(privateKey)) var D = BigInteger.fromBuffer(privateKey); else var D = privateKey;
                    var k = deterministicGenerateK(hash, D);
                    var n = curve.n;
                    var G = curve.G;
                    var Q = G.multiply(k);
                    var e = BigInteger.fromBuffer(hash);
                    var r = Q.affineX.mod(n);
                    assert.notEqual(r.signum(), 0, "Invalid R value");
                    var s = k.modInverse(n).multiply(e.add(D.multiply(r))).mod(n);
                    assert.notEqual(s.signum(), 0, "Invalid S value");
                    var N_OVER_TWO = n.shiftRight(1);
                    if (s.compareTo(N_OVER_TWO) > 0) {
                        s = n.subtract(s);
                    }
                    return {
                        r: r,
                        s: s
                    };
                }
                function verify(hash, signature, pubkey) {
                    assert(signature.r && signature.s, "Invalid signature.");
                    var Q;
                    if (Buffer.isBuffer(pubkey)) {
                        Q = Point.decodeFrom(curve, pubkey);
                    } else {
                        throw new Error("Invalid format for pubkey value, must be Buffer");
                    }
                    var e = BigInteger.fromBuffer(hash);
                    return verifyRaw(e, {
                        r: signature.r,
                        s: signature.s
                    }, Q);
                }
                function verifyRaw(e, signature, Q) {
                    var n = curve.n;
                    var G = curve.G;
                    var r = signature.r;
                    var s = signature.s;
                    if (r.signum() <= 0 || r.compareTo(n) >= 0) return false;
                    if (s.signum() <= 0 || s.compareTo(n) >= 0) return false;
                    var c = s.modInverse(n);
                    var u1 = e.multiply(c).mod(n);
                    var u2 = r.multiply(c).mod(n);
                    var R = G.multiplyTwo(u1, Q, u2);
                    var v = R.affineX.mod(n);
                    if (curve.isInfinity(R)) return false;
                    return v.equals(r);
                }
                module.exports = {
                    curve: curve,
                    deterministicGenerateK: deterministicGenerateK,
                    parseSig: parseSig,
                    parseSigCompact: parseSigCompact,
                    recoverPubKey: recoverPubKey,
                    serializeSig: serializeSig,
                    serializeSigCompact: serializeSigCompact,
                    sign: sign,
                    verify: verify,
                    verifyRaw: verifyRaw
                };
            }).call(this, require("buffer").Buffer);
        }, {
            "./util": 31,
            assert: 41,
            bigi: 34,
            buffer: 43,
            crypto: 19,
            ecurve: 38
        } ],
        31: [ function(require, module, exports) {
            var crypto = require("crypto");
            module.exports = {
                hmacSHA256: hmacSHA256
            };
            function hmacSHA256(v, k) {
                return crypto.createHmac("sha256", k).update(v).digest();
            }
        }, {
            crypto: 19
        } ],
        32: [ function(require, module, exports) {
            arguments[4][6][0].apply(exports, arguments);
        }, {
            "../package.json": 35,
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/bigi/lib/bigi.js": 6
        } ],
        33: [ function(require, module, exports) {
            arguments[4][7][0].apply(exports, arguments);
        }, {
            "./bigi": 32,
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/bigi/lib/convert.js": 7,
            assert: 41,
            buffer: 43
        } ],
        34: [ function(require, module, exports) {
            arguments[4][8][0].apply(exports, arguments);
        }, {
            "./bigi": 32,
            "./convert": 33,
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/bigi/lib/index.js": 8
        } ],
        35: [ function(require, module, exports) {
            module.exports = {
                name: "bigi",
                version: "1.3.0",
                description: "Big integers.",
                keywords: [ "cryptography", "math", "bitcoin", "arbitrary", "precision", "arithmetic", "big", "integer", "int", "number", "biginteger", "bigint", "bignumber", "decimal", "float" ],
                devDependencies: {
                    mocha: "^1.20.1",
                    jshint: "^2.5.1",
                    coveralls: "^2.10.0",
                    istanbul: "^0.2.11"
                },
                repository: {
                    url: "https://github.com/cryptocoinjs/bigi",
                    type: "git"
                },
                main: "./lib/index.js",
                scripts: {
                    test: "_mocha -- test/*.js",
                    jshint: "jshint --config jshint.json lib/*.js ; true",
                    unit: "mocha",
                    coverage: "istanbul cover ./node_modules/.bin/_mocha -- --reporter list test/*.js",
                    coveralls: "npm run-script coverage && node ./node_modules/.bin/coveralls < coverage/lcov.info"
                },
                dependencies: {},
                testling: {
                    files: "test/*.js",
                    harness: "mocha",
                    browsers: [ "ie/9..latest", "firefox/latest", "chrome/latest", "safari/6.0..latest", "iphone/6.0..latest", "android-browser/4.2..latest" ]
                },
                readme: "bigi\n======\n\n[![build status](https://secure.travis-ci.org/cryptocoinjs/bigi.png)](http://travis-ci.org/cryptocoinjs/bigi)\n[![Coverage Status](https://img.shields.io/coveralls/cryptocoinjs/bigi.svg)](https://coveralls.io/r/cryptocoinjs/bigi)\n[![Version](http://img.shields.io/npm/v/bigi.svg)](https://www.npmjs.org/package/bigi)\n\n[![browser support](https://ci.testling.com/cryptocoinjs/bigi.png)](https://ci.testling.com/cryptocoinjs/bigi)\n\nJavaScript library to manipulate big integers. Based on `jsbn` made by [Tom Wu](http://www-cs-students.stanford.edu/~tjw/jsbn/)\n\nOfficial documentation: \n\nhttp://cryptocoinjs.com/modules/misc/bigi/",
                readmeFilename: "README.md",
                bugs: {
                    url: "https://github.com/cryptocoinjs/bigi/issues"
                },
                homepage: "https://github.com/cryptocoinjs/bigi",
                _id: "bigi@1.3.0",
                _from: "bigi@^1.2.1"
            };
        }, {} ],
        36: [ function(require, module, exports) {
            module.exports = require(10);
        }, {
            "./point": 40,
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/ecurve/lib/curve.js": 10,
            assert: 41,
            bigi: 34
        } ],
        37: [ function(require, module, exports) {
            module.exports = require(11);
        }, {
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/ecurve/lib/curves.json": 11
        } ],
        38: [ function(require, module, exports) {
            module.exports = require(12);
        }, {
            "./curve": 36,
            "./names": 39,
            "./point": 40,
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/ecurve/lib/index.js": 12
        } ],
        39: [ function(require, module, exports) {
            module.exports = require(13);
        }, {
            "./curve": 36,
            "./curves": 37,
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/ecurve/lib/names.js": 13,
            bigi: 34
        } ],
        40: [ function(require, module, exports) {
            module.exports = require(14);
        }, {
            "/Users/henrisack/workspace/NodeJS/angular-ecdsa/node_modules/coinkey/node_modules/eckey/node_modules/ecurve/lib/point.js": 14,
            assert: 41,
            bigi: 34,
            buffer: 43
        } ],
        41: [ function(require, module, exports) {
            var util = require("util/");
            var pSlice = Array.prototype.slice;
            var hasOwn = Object.prototype.hasOwnProperty;
            var assert = module.exports = ok;
            assert.AssertionError = function AssertionError(options) {
                this.name = "AssertionError";
                this.actual = options.actual;
                this.expected = options.expected;
                this.operator = options.operator;
                if (options.message) {
                    this.message = options.message;
                    this.generatedMessage = false;
                } else {
                    this.message = getMessage(this);
                    this.generatedMessage = true;
                }
                var stackStartFunction = options.stackStartFunction || fail;
                if (Error.captureStackTrace) {
                    Error.captureStackTrace(this, stackStartFunction);
                } else {
                    var err = new Error();
                    if (err.stack) {
                        var out = err.stack;
                        var fn_name = stackStartFunction.name;
                        var idx = out.indexOf("\n" + fn_name);
                        if (idx >= 0) {
                            var next_line = out.indexOf("\n", idx + 1);
                            out = out.substring(next_line + 1);
                        }
                        this.stack = out;
                    }
                }
            };
            util.inherits(assert.AssertionError, Error);
            function replacer(key, value) {
                if (util.isUndefined(value)) {
                    return "" + value;
                }
                if (util.isNumber(value) && (isNaN(value) || !isFinite(value))) {
                    return value.toString();
                }
                if (util.isFunction(value) || util.isRegExp(value)) {
                    return value.toString();
                }
                return value;
            }
            function truncate(s, n) {
                if (util.isString(s)) {
                    return s.length < n ? s : s.slice(0, n);
                } else {
                    return s;
                }
            }
            function getMessage(self) {
                return truncate(JSON.stringify(self.actual, replacer), 128) + " " + self.operator + " " + truncate(JSON.stringify(self.expected, replacer), 128);
            }
            function fail(actual, expected, message, operator, stackStartFunction) {
                throw new assert.AssertionError({
                    message: message,
                    actual: actual,
                    expected: expected,
                    operator: operator,
                    stackStartFunction: stackStartFunction
                });
            }
            assert.fail = fail;
            function ok(value, message) {
                if (!value) fail(value, true, message, "==", assert.ok);
            }
            assert.ok = ok;
            assert.equal = function equal(actual, expected, message) {
                if (actual != expected) fail(actual, expected, message, "==", assert.equal);
            };
            assert.notEqual = function notEqual(actual, expected, message) {
                if (actual == expected) {
                    fail(actual, expected, message, "!=", assert.notEqual);
                }
            };
            assert.deepEqual = function deepEqual(actual, expected, message) {
                if (!_deepEqual(actual, expected)) {
                    fail(actual, expected, message, "deepEqual", assert.deepEqual);
                }
            };
            function _deepEqual(actual, expected) {
                if (actual === expected) {
                    return true;
                } else if (util.isBuffer(actual) && util.isBuffer(expected)) {
                    if (actual.length != expected.length) return false;
                    for (var i = 0; i < actual.length; i++) {
                        if (actual[i] !== expected[i]) return false;
                    }
                    return true;
                } else if (util.isDate(actual) && util.isDate(expected)) {
                    return actual.getTime() === expected.getTime();
                } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
                    return actual.source === expected.source && actual.global === expected.global && actual.multiline === expected.multiline && actual.lastIndex === expected.lastIndex && actual.ignoreCase === expected.ignoreCase;
                } else if (!util.isObject(actual) && !util.isObject(expected)) {
                    return actual == expected;
                } else {
                    return objEquiv(actual, expected);
                }
            }
            function isArguments(object) {
                return Object.prototype.toString.call(object) == "[object Arguments]";
            }
            function objEquiv(a, b) {
                if (util.isNullOrUndefined(a) || util.isNullOrUndefined(b)) return false;
                if (a.prototype !== b.prototype) return false;
                if (isArguments(a)) {
                    if (!isArguments(b)) {
                        return false;
                    }
                    a = pSlice.call(a);
                    b = pSlice.call(b);
                    return _deepEqual(a, b);
                }
                try {
                    var ka = objectKeys(a), kb = objectKeys(b), key, i;
                } catch (e) {
                    return false;
                }
                if (ka.length != kb.length) return false;
                ka.sort();
                kb.sort();
                for (i = ka.length - 1; i >= 0; i--) {
                    if (ka[i] != kb[i]) return false;
                }
                for (i = ka.length - 1; i >= 0; i--) {
                    key = ka[i];
                    if (!_deepEqual(a[key], b[key])) return false;
                }
                return true;
            }
            assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
                if (_deepEqual(actual, expected)) {
                    fail(actual, expected, message, "notDeepEqual", assert.notDeepEqual);
                }
            };
            assert.strictEqual = function strictEqual(actual, expected, message) {
                if (actual !== expected) {
                    fail(actual, expected, message, "===", assert.strictEqual);
                }
            };
            assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
                if (actual === expected) {
                    fail(actual, expected, message, "!==", assert.notStrictEqual);
                }
            };
            function expectedException(actual, expected) {
                if (!actual || !expected) {
                    return false;
                }
                if (Object.prototype.toString.call(expected) == "[object RegExp]") {
                    return expected.test(actual);
                } else if (actual instanceof expected) {
                    return true;
                } else if (expected.call({}, actual) === true) {
                    return true;
                }
                return false;
            }
            function _throws(shouldThrow, block, expected, message) {
                var actual;
                if (util.isString(expected)) {
                    message = expected;
                    expected = null;
                }
                try {
                    block();
                } catch (e) {
                    actual = e;
                }
                message = (expected && expected.name ? " (" + expected.name + ")." : ".") + (message ? " " + message : ".");
                if (shouldThrow && !actual) {
                    fail(actual, expected, "Missing expected exception" + message);
                }
                if (!shouldThrow && expectedException(actual, expected)) {
                    fail(actual, expected, "Got unwanted exception" + message);
                }
                if (shouldThrow && actual && expected && !expectedException(actual, expected) || !shouldThrow && actual) {
                    throw actual;
                }
            }
            assert.throws = function(block, error, message) {
                _throws.apply(this, [ true ].concat(pSlice.call(arguments)));
            };
            assert.doesNotThrow = function(block, message) {
                _throws.apply(this, [ false ].concat(pSlice.call(arguments)));
            };
            assert.ifError = function(err) {
                if (err) {
                    throw err;
                }
            };
            var objectKeys = Object.keys || function(obj) {
                var keys = [];
                for (var key in obj) {
                    if (hasOwn.call(obj, key)) keys.push(key);
                }
                return keys;
            };
        }, {
            "util/": 50
        } ],
        42: [ function(require, module, exports) {}, {} ],
        43: [ function(require, module, exports) {
            var base64 = require("base64-js");
            var ieee754 = require("ieee754");
            var isArray = require("is-array");
            exports.Buffer = Buffer;
            exports.SlowBuffer = Buffer;
            exports.INSPECT_MAX_BYTES = 50;
            Buffer.poolSize = 8192;
            var kMaxLength = 1073741823;
            Buffer.TYPED_ARRAY_SUPPORT = function() {
                try {
                    var buf = new ArrayBuffer(0);
                    var arr = new Uint8Array(buf);
                    arr.foo = function() {
                        return 42;
                    };
                    return 42 === arr.foo() && typeof arr.subarray === "function" && new Uint8Array(1).subarray(1, 1).byteLength === 0;
                } catch (e) {
                    return false;
                }
            }();
            function Buffer(subject, encoding, noZero) {
                if (!(this instanceof Buffer)) return new Buffer(subject, encoding, noZero);
                var type = typeof subject;
                var length;
                if (type === "number") length = subject > 0 ? subject >>> 0 : 0; else if (type === "string") {
                    if (encoding === "base64") subject = base64clean(subject);
                    length = Buffer.byteLength(subject, encoding);
                } else if (type === "object" && subject !== null) {
                    if (subject.type === "Buffer" && isArray(subject.data)) subject = subject.data;
                    length = +subject.length > 0 ? Math.floor(+subject.length) : 0;
                } else throw new TypeError("must start with number, buffer, array or string");
                if (this.length > kMaxLength) throw new RangeError("Attempt to allocate Buffer larger than maximum " + "size: 0x" + kMaxLength.toString(16) + " bytes");
                var buf;
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    buf = Buffer._augment(new Uint8Array(length));
                } else {
                    buf = this;
                    buf.length = length;
                    buf._isBuffer = true;
                }
                var i;
                if (Buffer.TYPED_ARRAY_SUPPORT && typeof subject.byteLength === "number") {
                    buf._set(subject);
                } else if (isArrayish(subject)) {
                    if (Buffer.isBuffer(subject)) {
                        for (i = 0; i < length; i++) buf[i] = subject.readUInt8(i);
                    } else {
                        for (i = 0; i < length; i++) buf[i] = (subject[i] % 256 + 256) % 256;
                    }
                } else if (type === "string") {
                    buf.write(subject, 0, encoding);
                } else if (type === "number" && !Buffer.TYPED_ARRAY_SUPPORT && !noZero) {
                    for (i = 0; i < length; i++) {
                        buf[i] = 0;
                    }
                }
                return buf;
            }
            Buffer.isBuffer = function(b) {
                return !!(b != null && b._isBuffer);
            };
            Buffer.compare = function(a, b) {
                if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) throw new TypeError("Arguments must be Buffers");
                var x = a.length;
                var y = b.length;
                for (var i = 0, len = Math.min(x, y); i < len && a[i] === b[i]; i++) {}
                if (i !== len) {
                    x = a[i];
                    y = b[i];
                }
                if (x < y) return -1;
                if (y < x) return 1;
                return 0;
            };
            Buffer.isEncoding = function(encoding) {
                switch (String(encoding).toLowerCase()) {
                  case "hex":
                  case "utf8":
                  case "utf-8":
                  case "ascii":
                  case "binary":
                  case "base64":
                  case "raw":
                  case "ucs2":
                  case "ucs-2":
                  case "utf16le":
                  case "utf-16le":
                    return true;

                  default:
                    return false;
                }
            };
            Buffer.concat = function(list, totalLength) {
                if (!isArray(list)) throw new TypeError("Usage: Buffer.concat(list[, length])");
                if (list.length === 0) {
                    return new Buffer(0);
                } else if (list.length === 1) {
                    return list[0];
                }
                var i;
                if (totalLength === undefined) {
                    totalLength = 0;
                    for (i = 0; i < list.length; i++) {
                        totalLength += list[i].length;
                    }
                }
                var buf = new Buffer(totalLength);
                var pos = 0;
                for (i = 0; i < list.length; i++) {
                    var item = list[i];
                    item.copy(buf, pos);
                    pos += item.length;
                }
                return buf;
            };
            Buffer.byteLength = function(str, encoding) {
                var ret;
                str = str + "";
                switch (encoding || "utf8") {
                  case "ascii":
                  case "binary":
                  case "raw":
                    ret = str.length;
                    break;

                  case "ucs2":
                  case "ucs-2":
                  case "utf16le":
                  case "utf-16le":
                    ret = str.length * 2;
                    break;

                  case "hex":
                    ret = str.length >>> 1;
                    break;

                  case "utf8":
                  case "utf-8":
                    ret = utf8ToBytes(str).length;
                    break;

                  case "base64":
                    ret = base64ToBytes(str).length;
                    break;

                  default:
                    ret = str.length;
                }
                return ret;
            };
            Buffer.prototype.length = undefined;
            Buffer.prototype.parent = undefined;
            Buffer.prototype.toString = function(encoding, start, end) {
                var loweredCase = false;
                start = start >>> 0;
                end = end === undefined || end === Infinity ? this.length : end >>> 0;
                if (!encoding) encoding = "utf8";
                if (start < 0) start = 0;
                if (end > this.length) end = this.length;
                if (end <= start) return "";
                while (true) {
                    switch (encoding) {
                      case "hex":
                        return hexSlice(this, start, end);

                      case "utf8":
                      case "utf-8":
                        return utf8Slice(this, start, end);

                      case "ascii":
                        return asciiSlice(this, start, end);

                      case "binary":
                        return binarySlice(this, start, end);

                      case "base64":
                        return base64Slice(this, start, end);

                      case "ucs2":
                      case "ucs-2":
                      case "utf16le":
                      case "utf-16le":
                        return utf16leSlice(this, start, end);

                      default:
                        if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
                        encoding = (encoding + "").toLowerCase();
                        loweredCase = true;
                    }
                }
            };
            Buffer.prototype.equals = function(b) {
                if (!Buffer.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
                return Buffer.compare(this, b) === 0;
            };
            Buffer.prototype.inspect = function() {
                var str = "";
                var max = exports.INSPECT_MAX_BYTES;
                if (this.length > 0) {
                    str = this.toString("hex", 0, max).match(/.{2}/g).join(" ");
                    if (this.length > max) str += " ... ";
                }
                return "<Buffer " + str + ">";
            };
            Buffer.prototype.compare = function(b) {
                if (!Buffer.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
                return Buffer.compare(this, b);
            };
            Buffer.prototype.get = function(offset) {
                console.log(".get() is deprecated. Access using array indexes instead.");
                return this.readUInt8(offset);
            };
            Buffer.prototype.set = function(v, offset) {
                console.log(".set() is deprecated. Access using array indexes instead.");
                return this.writeUInt8(v, offset);
            };
            function hexWrite(buf, string, offset, length) {
                offset = Number(offset) || 0;
                var remaining = buf.length - offset;
                if (!length) {
                    length = remaining;
                } else {
                    length = Number(length);
                    if (length > remaining) {
                        length = remaining;
                    }
                }
                var strLen = string.length;
                if (strLen % 2 !== 0) throw new Error("Invalid hex string");
                if (length > strLen / 2) {
                    length = strLen / 2;
                }
                for (var i = 0; i < length; i++) {
                    var byte = parseInt(string.substr(i * 2, 2), 16);
                    if (isNaN(byte)) throw new Error("Invalid hex string");
                    buf[offset + i] = byte;
                }
                return i;
            }
            function utf8Write(buf, string, offset, length) {
                var charsWritten = blitBuffer(utf8ToBytes(string), buf, offset, length);
                return charsWritten;
            }
            function asciiWrite(buf, string, offset, length) {
                var charsWritten = blitBuffer(asciiToBytes(string), buf, offset, length);
                return charsWritten;
            }
            function binaryWrite(buf, string, offset, length) {
                return asciiWrite(buf, string, offset, length);
            }
            function base64Write(buf, string, offset, length) {
                var charsWritten = blitBuffer(base64ToBytes(string), buf, offset, length);
                return charsWritten;
            }
            function utf16leWrite(buf, string, offset, length) {
                var charsWritten = blitBuffer(utf16leToBytes(string), buf, offset, length);
                return charsWritten;
            }
            Buffer.prototype.write = function(string, offset, length, encoding) {
                if (isFinite(offset)) {
                    if (!isFinite(length)) {
                        encoding = length;
                        length = undefined;
                    }
                } else {
                    var swap = encoding;
                    encoding = offset;
                    offset = length;
                    length = swap;
                }
                offset = Number(offset) || 0;
                var remaining = this.length - offset;
                if (!length) {
                    length = remaining;
                } else {
                    length = Number(length);
                    if (length > remaining) {
                        length = remaining;
                    }
                }
                encoding = String(encoding || "utf8").toLowerCase();
                var ret;
                switch (encoding) {
                  case "hex":
                    ret = hexWrite(this, string, offset, length);
                    break;

                  case "utf8":
                  case "utf-8":
                    ret = utf8Write(this, string, offset, length);
                    break;

                  case "ascii":
                    ret = asciiWrite(this, string, offset, length);
                    break;

                  case "binary":
                    ret = binaryWrite(this, string, offset, length);
                    break;

                  case "base64":
                    ret = base64Write(this, string, offset, length);
                    break;

                  case "ucs2":
                  case "ucs-2":
                  case "utf16le":
                  case "utf-16le":
                    ret = utf16leWrite(this, string, offset, length);
                    break;

                  default:
                    throw new TypeError("Unknown encoding: " + encoding);
                }
                return ret;
            };
            Buffer.prototype.toJSON = function() {
                return {
                    type: "Buffer",
                    data: Array.prototype.slice.call(this._arr || this, 0)
                };
            };
            function base64Slice(buf, start, end) {
                if (start === 0 && end === buf.length) {
                    return base64.fromByteArray(buf);
                } else {
                    return base64.fromByteArray(buf.slice(start, end));
                }
            }
            function utf8Slice(buf, start, end) {
                var res = "";
                var tmp = "";
                end = Math.min(buf.length, end);
                for (var i = start; i < end; i++) {
                    if (buf[i] <= 127) {
                        res += decodeUtf8Char(tmp) + String.fromCharCode(buf[i]);
                        tmp = "";
                    } else {
                        tmp += "%" + buf[i].toString(16);
                    }
                }
                return res + decodeUtf8Char(tmp);
            }
            function asciiSlice(buf, start, end) {
                var ret = "";
                end = Math.min(buf.length, end);
                for (var i = start; i < end; i++) {
                    ret += String.fromCharCode(buf[i]);
                }
                return ret;
            }
            function binarySlice(buf, start, end) {
                return asciiSlice(buf, start, end);
            }
            function hexSlice(buf, start, end) {
                var len = buf.length;
                if (!start || start < 0) start = 0;
                if (!end || end < 0 || end > len) end = len;
                var out = "";
                for (var i = start; i < end; i++) {
                    out += toHex(buf[i]);
                }
                return out;
            }
            function utf16leSlice(buf, start, end) {
                var bytes = buf.slice(start, end);
                var res = "";
                for (var i = 0; i < bytes.length; i += 2) {
                    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256);
                }
                return res;
            }
            Buffer.prototype.slice = function(start, end) {
                var len = this.length;
                start = ~~start;
                end = end === undefined ? len : ~~end;
                if (start < 0) {
                    start += len;
                    if (start < 0) start = 0;
                } else if (start > len) {
                    start = len;
                }
                if (end < 0) {
                    end += len;
                    if (end < 0) end = 0;
                } else if (end > len) {
                    end = len;
                }
                if (end < start) end = start;
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    return Buffer._augment(this.subarray(start, end));
                } else {
                    var sliceLen = end - start;
                    var newBuf = new Buffer(sliceLen, undefined, true);
                    for (var i = 0; i < sliceLen; i++) {
                        newBuf[i] = this[i + start];
                    }
                    return newBuf;
                }
            };
            function checkOffset(offset, ext, length) {
                if (offset % 1 !== 0 || offset < 0) throw new RangeError("offset is not uint");
                if (offset + ext > length) throw new RangeError("Trying to access beyond buffer length");
            }
            Buffer.prototype.readUInt8 = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 1, this.length);
                return this[offset];
            };
            Buffer.prototype.readUInt16LE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                return this[offset] | this[offset + 1] << 8;
            };
            Buffer.prototype.readUInt16BE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                return this[offset] << 8 | this[offset + 1];
            };
            Buffer.prototype.readUInt32LE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 16777216;
            };
            Buffer.prototype.readUInt32BE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return this[offset] * 16777216 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
            };
            Buffer.prototype.readInt8 = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 1, this.length);
                if (!(this[offset] & 128)) return this[offset];
                return (255 - this[offset] + 1) * -1;
            };
            Buffer.prototype.readInt16LE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                var val = this[offset] | this[offset + 1] << 8;
                return val & 32768 ? val | 4294901760 : val;
            };
            Buffer.prototype.readInt16BE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                var val = this[offset + 1] | this[offset] << 8;
                return val & 32768 ? val | 4294901760 : val;
            };
            Buffer.prototype.readInt32LE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
            };
            Buffer.prototype.readInt32BE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
            };
            Buffer.prototype.readFloatLE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return ieee754.read(this, offset, true, 23, 4);
            };
            Buffer.prototype.readFloatBE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return ieee754.read(this, offset, false, 23, 4);
            };
            Buffer.prototype.readDoubleLE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 8, this.length);
                return ieee754.read(this, offset, true, 52, 8);
            };
            Buffer.prototype.readDoubleBE = function(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 8, this.length);
                return ieee754.read(this, offset, false, 52, 8);
            };
            function checkInt(buf, value, offset, ext, max, min) {
                if (!Buffer.isBuffer(buf)) throw new TypeError("buffer must be a Buffer instance");
                if (value > max || value < min) throw new TypeError("value is out of bounds");
                if (offset + ext > buf.length) throw new TypeError("index out of range");
            }
            Buffer.prototype.writeUInt8 = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 1, 255, 0);
                if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
                this[offset] = value;
                return offset + 1;
            };
            function objectWriteUInt16(buf, value, offset, littleEndian) {
                if (value < 0) value = 65535 + value + 1;
                for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; i++) {
                    buf[offset + i] = (value & 255 << 8 * (littleEndian ? i : 1 - i)) >>> (littleEndian ? i : 1 - i) * 8;
                }
            }
            Buffer.prototype.writeUInt16LE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value;
                    this[offset + 1] = value >>> 8;
                } else objectWriteUInt16(this, value, offset, true);
                return offset + 2;
            };
            Buffer.prototype.writeUInt16BE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 8;
                    this[offset + 1] = value;
                } else objectWriteUInt16(this, value, offset, false);
                return offset + 2;
            };
            function objectWriteUInt32(buf, value, offset, littleEndian) {
                if (value < 0) value = 4294967295 + value + 1;
                for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; i++) {
                    buf[offset + i] = value >>> (littleEndian ? i : 3 - i) * 8 & 255;
                }
            }
            Buffer.prototype.writeUInt32LE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset + 3] = value >>> 24;
                    this[offset + 2] = value >>> 16;
                    this[offset + 1] = value >>> 8;
                    this[offset] = value;
                } else objectWriteUInt32(this, value, offset, true);
                return offset + 4;
            };
            Buffer.prototype.writeUInt32BE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 24;
                    this[offset + 1] = value >>> 16;
                    this[offset + 2] = value >>> 8;
                    this[offset + 3] = value;
                } else objectWriteUInt32(this, value, offset, false);
                return offset + 4;
            };
            Buffer.prototype.writeInt8 = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 1, 127, -128);
                if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
                if (value < 0) value = 255 + value + 1;
                this[offset] = value;
                return offset + 1;
            };
            Buffer.prototype.writeInt16LE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value;
                    this[offset + 1] = value >>> 8;
                } else objectWriteUInt16(this, value, offset, true);
                return offset + 2;
            };
            Buffer.prototype.writeInt16BE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 8;
                    this[offset + 1] = value;
                } else objectWriteUInt16(this, value, offset, false);
                return offset + 2;
            };
            Buffer.prototype.writeInt32LE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value;
                    this[offset + 1] = value >>> 8;
                    this[offset + 2] = value >>> 16;
                    this[offset + 3] = value >>> 24;
                } else objectWriteUInt32(this, value, offset, true);
                return offset + 4;
            };
            Buffer.prototype.writeInt32BE = function(value, offset, noAssert) {
                value = +value;
                offset = offset >>> 0;
                if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
                if (value < 0) value = 4294967295 + value + 1;
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 24;
                    this[offset + 1] = value >>> 16;
                    this[offset + 2] = value >>> 8;
                    this[offset + 3] = value;
                } else objectWriteUInt32(this, value, offset, false);
                return offset + 4;
            };
            function checkIEEE754(buf, value, offset, ext, max, min) {
                if (value > max || value < min) throw new TypeError("value is out of bounds");
                if (offset + ext > buf.length) throw new TypeError("index out of range");
            }
            function writeFloat(buf, value, offset, littleEndian, noAssert) {
                if (!noAssert) checkIEEE754(buf, value, offset, 4, 3.4028234663852886e38, -3.4028234663852886e38);
                ieee754.write(buf, value, offset, littleEndian, 23, 4);
                return offset + 4;
            }
            Buffer.prototype.writeFloatLE = function(value, offset, noAssert) {
                return writeFloat(this, value, offset, true, noAssert);
            };
            Buffer.prototype.writeFloatBE = function(value, offset, noAssert) {
                return writeFloat(this, value, offset, false, noAssert);
            };
            function writeDouble(buf, value, offset, littleEndian, noAssert) {
                if (!noAssert) checkIEEE754(buf, value, offset, 8, 1.7976931348623157e308, -1.7976931348623157e308);
                ieee754.write(buf, value, offset, littleEndian, 52, 8);
                return offset + 8;
            }
            Buffer.prototype.writeDoubleLE = function(value, offset, noAssert) {
                return writeDouble(this, value, offset, true, noAssert);
            };
            Buffer.prototype.writeDoubleBE = function(value, offset, noAssert) {
                return writeDouble(this, value, offset, false, noAssert);
            };
            Buffer.prototype.copy = function(target, target_start, start, end) {
                var source = this;
                if (!start) start = 0;
                if (!end && end !== 0) end = this.length;
                if (!target_start) target_start = 0;
                if (end === start) return;
                if (target.length === 0 || source.length === 0) return;
                if (end < start) throw new TypeError("sourceEnd < sourceStart");
                if (target_start < 0 || target_start >= target.length) throw new TypeError("targetStart out of bounds");
                if (start < 0 || start >= source.length) throw new TypeError("sourceStart out of bounds");
                if (end < 0 || end > source.length) throw new TypeError("sourceEnd out of bounds");
                if (end > this.length) end = this.length;
                if (target.length - target_start < end - start) end = target.length - target_start + start;
                var len = end - start;
                if (len < 100 || !Buffer.TYPED_ARRAY_SUPPORT) {
                    for (var i = 0; i < len; i++) {
                        target[i + target_start] = this[i + start];
                    }
                } else {
                    target._set(this.subarray(start, start + len), target_start);
                }
            };
            Buffer.prototype.fill = function(value, start, end) {
                if (!value) value = 0;
                if (!start) start = 0;
                if (!end) end = this.length;
                if (end < start) throw new TypeError("end < start");
                if (end === start) return;
                if (this.length === 0) return;
                if (start < 0 || start >= this.length) throw new TypeError("start out of bounds");
                if (end < 0 || end > this.length) throw new TypeError("end out of bounds");
                var i;
                if (typeof value === "number") {
                    for (i = start; i < end; i++) {
                        this[i] = value;
                    }
                } else {
                    var bytes = utf8ToBytes(value.toString());
                    var len = bytes.length;
                    for (i = start; i < end; i++) {
                        this[i] = bytes[i % len];
                    }
                }
                return this;
            };
            Buffer.prototype.toArrayBuffer = function() {
                if (typeof Uint8Array !== "undefined") {
                    if (Buffer.TYPED_ARRAY_SUPPORT) {
                        return new Buffer(this).buffer;
                    } else {
                        var buf = new Uint8Array(this.length);
                        for (var i = 0, len = buf.length; i < len; i += 1) {
                            buf[i] = this[i];
                        }
                        return buf.buffer;
                    }
                } else {
                    throw new TypeError("Buffer.toArrayBuffer not supported in this browser");
                }
            };
            var BP = Buffer.prototype;
            Buffer._augment = function(arr) {
                arr._isBuffer = true;
                arr._get = arr.get;
                arr._set = arr.set;
                arr.get = BP.get;
                arr.set = BP.set;
                arr.write = BP.write;
                arr.toString = BP.toString;
                arr.toLocaleString = BP.toString;
                arr.toJSON = BP.toJSON;
                arr.equals = BP.equals;
                arr.compare = BP.compare;
                arr.copy = BP.copy;
                arr.slice = BP.slice;
                arr.readUInt8 = BP.readUInt8;
                arr.readUInt16LE = BP.readUInt16LE;
                arr.readUInt16BE = BP.readUInt16BE;
                arr.readUInt32LE = BP.readUInt32LE;
                arr.readUInt32BE = BP.readUInt32BE;
                arr.readInt8 = BP.readInt8;
                arr.readInt16LE = BP.readInt16LE;
                arr.readInt16BE = BP.readInt16BE;
                arr.readInt32LE = BP.readInt32LE;
                arr.readInt32BE = BP.readInt32BE;
                arr.readFloatLE = BP.readFloatLE;
                arr.readFloatBE = BP.readFloatBE;
                arr.readDoubleLE = BP.readDoubleLE;
                arr.readDoubleBE = BP.readDoubleBE;
                arr.writeUInt8 = BP.writeUInt8;
                arr.writeUInt16LE = BP.writeUInt16LE;
                arr.writeUInt16BE = BP.writeUInt16BE;
                arr.writeUInt32LE = BP.writeUInt32LE;
                arr.writeUInt32BE = BP.writeUInt32BE;
                arr.writeInt8 = BP.writeInt8;
                arr.writeInt16LE = BP.writeInt16LE;
                arr.writeInt16BE = BP.writeInt16BE;
                arr.writeInt32LE = BP.writeInt32LE;
                arr.writeInt32BE = BP.writeInt32BE;
                arr.writeFloatLE = BP.writeFloatLE;
                arr.writeFloatBE = BP.writeFloatBE;
                arr.writeDoubleLE = BP.writeDoubleLE;
                arr.writeDoubleBE = BP.writeDoubleBE;
                arr.fill = BP.fill;
                arr.inspect = BP.inspect;
                arr.toArrayBuffer = BP.toArrayBuffer;
                return arr;
            };
            var INVALID_BASE64_RE = /[^+\/0-9A-z]/g;
            function base64clean(str) {
                str = stringtrim(str).replace(INVALID_BASE64_RE, "");
                while (str.length % 4 !== 0) {
                    str = str + "=";
                }
                return str;
            }
            function stringtrim(str) {
                if (str.trim) return str.trim();
                return str.replace(/^\s+|\s+$/g, "");
            }
            function isArrayish(subject) {
                return isArray(subject) || Buffer.isBuffer(subject) || subject && typeof subject === "object" && typeof subject.length === "number";
            }
            function toHex(n) {
                if (n < 16) return "0" + n.toString(16);
                return n.toString(16);
            }
            function utf8ToBytes(str) {
                var byteArray = [];
                for (var i = 0; i < str.length; i++) {
                    var b = str.charCodeAt(i);
                    if (b <= 127) {
                        byteArray.push(b);
                    } else {
                        var start = i;
                        if (b >= 55296 && b <= 57343) i++;
                        var h = encodeURIComponent(str.slice(start, i + 1)).substr(1).split("%");
                        for (var j = 0; j < h.length; j++) {
                            byteArray.push(parseInt(h[j], 16));
                        }
                    }
                }
                return byteArray;
            }
            function asciiToBytes(str) {
                var byteArray = [];
                for (var i = 0; i < str.length; i++) {
                    byteArray.push(str.charCodeAt(i) & 255);
                }
                return byteArray;
            }
            function utf16leToBytes(str) {
                var c, hi, lo;
                var byteArray = [];
                for (var i = 0; i < str.length; i++) {
                    c = str.charCodeAt(i);
                    hi = c >> 8;
                    lo = c % 256;
                    byteArray.push(lo);
                    byteArray.push(hi);
                }
                return byteArray;
            }
            function base64ToBytes(str) {
                return base64.toByteArray(str);
            }
            function blitBuffer(src, dst, offset, length) {
                for (var i = 0; i < length; i++) {
                    if (i + offset >= dst.length || i >= src.length) break;
                    dst[i + offset] = src[i];
                }
                return i;
            }
            function decodeUtf8Char(str) {
                try {
                    return decodeURIComponent(str);
                } catch (err) {
                    return String.fromCharCode(65533);
                }
            }
        }, {
            "base64-js": 44,
            ieee754: 45,
            "is-array": 46
        } ],
        44: [ function(require, module, exports) {
            var lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            (function(exports) {
                "use strict";
                var Arr = typeof Uint8Array !== "undefined" ? Uint8Array : Array;
                var PLUS = "+".charCodeAt(0);
                var SLASH = "/".charCodeAt(0);
                var NUMBER = "0".charCodeAt(0);
                var LOWER = "a".charCodeAt(0);
                var UPPER = "A".charCodeAt(0);
                function decode(elt) {
                    var code = elt.charCodeAt(0);
                    if (code === PLUS) return 62;
                    if (code === SLASH) return 63;
                    if (code < NUMBER) return -1;
                    if (code < NUMBER + 10) return code - NUMBER + 26 + 26;
                    if (code < UPPER + 26) return code - UPPER;
                    if (code < LOWER + 26) return code - LOWER + 26;
                }
                function b64ToByteArray(b64) {
                    var i, j, l, tmp, placeHolders, arr;
                    if (b64.length % 4 > 0) {
                        throw new Error("Invalid string. Length must be a multiple of 4");
                    }
                    var len = b64.length;
                    placeHolders = "=" === b64.charAt(len - 2) ? 2 : "=" === b64.charAt(len - 1) ? 1 : 0;
                    arr = new Arr(b64.length * 3 / 4 - placeHolders);
                    l = placeHolders > 0 ? b64.length - 4 : b64.length;
                    var L = 0;
                    function push(v) {
                        arr[L++] = v;
                    }
                    for (i = 0, j = 0; i < l; i += 4, j += 3) {
                        tmp = decode(b64.charAt(i)) << 18 | decode(b64.charAt(i + 1)) << 12 | decode(b64.charAt(i + 2)) << 6 | decode(b64.charAt(i + 3));
                        push((tmp & 16711680) >> 16);
                        push((tmp & 65280) >> 8);
                        push(tmp & 255);
                    }
                    if (placeHolders === 2) {
                        tmp = decode(b64.charAt(i)) << 2 | decode(b64.charAt(i + 1)) >> 4;
                        push(tmp & 255);
                    } else if (placeHolders === 1) {
                        tmp = decode(b64.charAt(i)) << 10 | decode(b64.charAt(i + 1)) << 4 | decode(b64.charAt(i + 2)) >> 2;
                        push(tmp >> 8 & 255);
                        push(tmp & 255);
                    }
                    return arr;
                }
                function uint8ToBase64(uint8) {
                    var i, extraBytes = uint8.length % 3, output = "", temp, length;
                    function encode(num) {
                        return lookup.charAt(num);
                    }
                    function tripletToBase64(num) {
                        return encode(num >> 18 & 63) + encode(num >> 12 & 63) + encode(num >> 6 & 63) + encode(num & 63);
                    }
                    for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
                        temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + uint8[i + 2];
                        output += tripletToBase64(temp);
                    }
                    switch (extraBytes) {
                      case 1:
                        temp = uint8[uint8.length - 1];
                        output += encode(temp >> 2);
                        output += encode(temp << 4 & 63);
                        output += "==";
                        break;

                      case 2:
                        temp = (uint8[uint8.length - 2] << 8) + uint8[uint8.length - 1];
                        output += encode(temp >> 10);
                        output += encode(temp >> 4 & 63);
                        output += encode(temp << 2 & 63);
                        output += "=";
                        break;
                    }
                    return output;
                }
                exports.toByteArray = b64ToByteArray;
                exports.fromByteArray = uint8ToBase64;
            })(typeof exports === "undefined" ? this.base64js = {} : exports);
        }, {} ],
        45: [ function(require, module, exports) {
            exports.read = function(buffer, offset, isLE, mLen, nBytes) {
                var e, m, eLen = nBytes * 8 - mLen - 1, eMax = (1 << eLen) - 1, eBias = eMax >> 1, nBits = -7, i = isLE ? nBytes - 1 : 0, d = isLE ? -1 : 1, s = buffer[offset + i];
                i += d;
                e = s & (1 << -nBits) - 1;
                s >>= -nBits;
                nBits += eLen;
                for (;nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) ;
                m = e & (1 << -nBits) - 1;
                e >>= -nBits;
                nBits += mLen;
                for (;nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) ;
                if (e === 0) {
                    e = 1 - eBias;
                } else if (e === eMax) {
                    return m ? NaN : (s ? -1 : 1) * Infinity;
                } else {
                    m = m + Math.pow(2, mLen);
                    e = e - eBias;
                }
                return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
            };
            exports.write = function(buffer, value, offset, isLE, mLen, nBytes) {
                var e, m, c, eLen = nBytes * 8 - mLen - 1, eMax = (1 << eLen) - 1, eBias = eMax >> 1, rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0, i = isLE ? 0 : nBytes - 1, d = isLE ? 1 : -1, s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
                value = Math.abs(value);
                if (isNaN(value) || value === Infinity) {
                    m = isNaN(value) ? 1 : 0;
                    e = eMax;
                } else {
                    e = Math.floor(Math.log(value) / Math.LN2);
                    if (value * (c = Math.pow(2, -e)) < 1) {
                        e--;
                        c *= 2;
                    }
                    if (e + eBias >= 1) {
                        value += rt / c;
                    } else {
                        value += rt * Math.pow(2, 1 - eBias);
                    }
                    if (value * c >= 2) {
                        e++;
                        c /= 2;
                    }
                    if (e + eBias >= eMax) {
                        m = 0;
                        e = eMax;
                    } else if (e + eBias >= 1) {
                        m = (value * c - 1) * Math.pow(2, mLen);
                        e = e + eBias;
                    } else {
                        m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
                        e = 0;
                    }
                }
                for (;mLen >= 8; buffer[offset + i] = m & 255, i += d, m /= 256, mLen -= 8) ;
                e = e << mLen | m;
                eLen += mLen;
                for (;eLen > 0; buffer[offset + i] = e & 255, i += d, e /= 256, eLen -= 8) ;
                buffer[offset + i - d] |= s * 128;
            };
        }, {} ],
        46: [ function(require, module, exports) {
            var isArray = Array.isArray;
            var str = Object.prototype.toString;
            module.exports = isArray || function(val) {
                return !!val && "[object Array]" == str.call(val);
            };
        }, {} ],
        47: [ function(require, module, exports) {
            if (typeof Object.create === "function") {
                module.exports = function inherits(ctor, superCtor) {
                    ctor.super_ = superCtor;
                    ctor.prototype = Object.create(superCtor.prototype, {
                        constructor: {
                            value: ctor,
                            enumerable: false,
                            writable: true,
                            configurable: true
                        }
                    });
                };
            } else {
                module.exports = function inherits(ctor, superCtor) {
                    ctor.super_ = superCtor;
                    var TempCtor = function() {};
                    TempCtor.prototype = superCtor.prototype;
                    ctor.prototype = new TempCtor();
                    ctor.prototype.constructor = ctor;
                };
            }
        }, {} ],
        48: [ function(require, module, exports) {
            var process = module.exports = {};
            process.nextTick = function() {
                var canSetImmediate = typeof window !== "undefined" && window.setImmediate;
                var canMutationObserver = typeof window !== "undefined" && window.MutationObserver;
                var canPost = typeof window !== "undefined" && window.postMessage && window.addEventListener;
                if (canSetImmediate) {
                    return function(f) {
                        return window.setImmediate(f);
                    };
                }
                var queue = [];
                if (canMutationObserver) {
                    var hiddenDiv = document.createElement("div");
                    var observer = new MutationObserver(function() {
                        var queueList = queue.slice();
                        queue.length = 0;
                        queueList.forEach(function(fn) {
                            fn();
                        });
                    });
                    observer.observe(hiddenDiv, {
                        attributes: true
                    });
                    return function nextTick(fn) {
                        if (!queue.length) {
                            hiddenDiv.setAttribute("yes", "no");
                        }
                        queue.push(fn);
                    };
                }
                if (canPost) {
                    window.addEventListener("message", function(ev) {
                        var source = ev.source;
                        if ((source === window || source === null) && ev.data === "process-tick") {
                            ev.stopPropagation();
                            if (queue.length > 0) {
                                var fn = queue.shift();
                                fn();
                            }
                        }
                    }, true);
                    return function nextTick(fn) {
                        queue.push(fn);
                        window.postMessage("process-tick", "*");
                    };
                }
                return function nextTick(fn) {
                    setTimeout(fn, 0);
                };
            }();
            process.title = "browser";
            process.browser = true;
            process.env = {};
            process.argv = [];
            function noop() {}
            process.on = noop;
            process.addListener = noop;
            process.once = noop;
            process.off = noop;
            process.removeListener = noop;
            process.removeAllListeners = noop;
            process.emit = noop;
            process.binding = function(name) {
                throw new Error("process.binding is not supported");
            };
            process.cwd = function() {
                return "/";
            };
            process.chdir = function(dir) {
                throw new Error("process.chdir is not supported");
            };
        }, {} ],
        49: [ function(require, module, exports) {
            module.exports = function isBuffer(arg) {
                return arg && typeof arg === "object" && typeof arg.copy === "function" && typeof arg.fill === "function" && typeof arg.readUInt8 === "function";
            };
        }, {} ],
        50: [ function(require, module, exports) {
            (function(process, global) {
                var formatRegExp = /%[sdj%]/g;
                exports.format = function(f) {
                    if (!isString(f)) {
                        var objects = [];
                        for (var i = 0; i < arguments.length; i++) {
                            objects.push(inspect(arguments[i]));
                        }
                        return objects.join(" ");
                    }
                    var i = 1;
                    var args = arguments;
                    var len = args.length;
                    var str = String(f).replace(formatRegExp, function(x) {
                        if (x === "%%") return "%";
                        if (i >= len) return x;
                        switch (x) {
                          case "%s":
                            return String(args[i++]);

                          case "%d":
                            return Number(args[i++]);

                          case "%j":
                            try {
                                return JSON.stringify(args[i++]);
                            } catch (_) {
                                return "[Circular]";
                            }

                          default:
                            return x;
                        }
                    });
                    for (var x = args[i]; i < len; x = args[++i]) {
                        if (isNull(x) || !isObject(x)) {
                            str += " " + x;
                        } else {
                            str += " " + inspect(x);
                        }
                    }
                    return str;
                };
                exports.deprecate = function(fn, msg) {
                    if (isUndefined(global.process)) {
                        return function() {
                            return exports.deprecate(fn, msg).apply(this, arguments);
                        };
                    }
                    if (process.noDeprecation === true) {
                        return fn;
                    }
                    var warned = false;
                    function deprecated() {
                        if (!warned) {
                            if (process.throwDeprecation) {
                                throw new Error(msg);
                            } else if (process.traceDeprecation) {
                                console.trace(msg);
                            } else {
                                console.error(msg);
                            }
                            warned = true;
                        }
                        return fn.apply(this, arguments);
                    }
                    return deprecated;
                };
                var debugs = {};
                var debugEnviron;
                exports.debuglog = function(set) {
                    if (isUndefined(debugEnviron)) debugEnviron = process.env.NODE_DEBUG || "";
                    set = set.toUpperCase();
                    if (!debugs[set]) {
                        if (new RegExp("\\b" + set + "\\b", "i").test(debugEnviron)) {
                            var pid = process.pid;
                            debugs[set] = function() {
                                var msg = exports.format.apply(exports, arguments);
                                console.error("%s %d: %s", set, pid, msg);
                            };
                        } else {
                            debugs[set] = function() {};
                        }
                    }
                    return debugs[set];
                };
                function inspect(obj, opts) {
                    var ctx = {
                        seen: [],
                        stylize: stylizeNoColor
                    };
                    if (arguments.length >= 3) ctx.depth = arguments[2];
                    if (arguments.length >= 4) ctx.colors = arguments[3];
                    if (isBoolean(opts)) {
                        ctx.showHidden = opts;
                    } else if (opts) {
                        exports._extend(ctx, opts);
                    }
                    if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
                    if (isUndefined(ctx.depth)) ctx.depth = 2;
                    if (isUndefined(ctx.colors)) ctx.colors = false;
                    if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
                    if (ctx.colors) ctx.stylize = stylizeWithColor;
                    return formatValue(ctx, obj, ctx.depth);
                }
                exports.inspect = inspect;
                inspect.colors = {
                    bold: [ 1, 22 ],
                    italic: [ 3, 23 ],
                    underline: [ 4, 24 ],
                    inverse: [ 7, 27 ],
                    white: [ 37, 39 ],
                    grey: [ 90, 39 ],
                    black: [ 30, 39 ],
                    blue: [ 34, 39 ],
                    cyan: [ 36, 39 ],
                    green: [ 32, 39 ],
                    magenta: [ 35, 39 ],
                    red: [ 31, 39 ],
                    yellow: [ 33, 39 ]
                };
                inspect.styles = {
                    special: "cyan",
                    number: "yellow",
                    "boolean": "yellow",
                    undefined: "grey",
                    "null": "bold",
                    string: "green",
                    date: "magenta",
                    regexp: "red"
                };
                function stylizeWithColor(str, styleType) {
                    var style = inspect.styles[styleType];
                    if (style) {
                        return "[" + inspect.colors[style][0] + "m" + str + "[" + inspect.colors[style][1] + "m";
                    } else {
                        return str;
                    }
                }
                function stylizeNoColor(str, styleType) {
                    return str;
                }
                function arrayToHash(array) {
                    var hash = {};
                    array.forEach(function(val, idx) {
                        hash[val] = true;
                    });
                    return hash;
                }
                function formatValue(ctx, value, recurseTimes) {
                    if (ctx.customInspect && value && isFunction(value.inspect) && value.inspect !== exports.inspect && !(value.constructor && value.constructor.prototype === value)) {
                        var ret = value.inspect(recurseTimes, ctx);
                        if (!isString(ret)) {
                            ret = formatValue(ctx, ret, recurseTimes);
                        }
                        return ret;
                    }
                    var primitive = formatPrimitive(ctx, value);
                    if (primitive) {
                        return primitive;
                    }
                    var keys = Object.keys(value);
                    var visibleKeys = arrayToHash(keys);
                    if (ctx.showHidden) {
                        keys = Object.getOwnPropertyNames(value);
                    }
                    if (isError(value) && (keys.indexOf("message") >= 0 || keys.indexOf("description") >= 0)) {
                        return formatError(value);
                    }
                    if (keys.length === 0) {
                        if (isFunction(value)) {
                            var name = value.name ? ": " + value.name : "";
                            return ctx.stylize("[Function" + name + "]", "special");
                        }
                        if (isRegExp(value)) {
                            return ctx.stylize(RegExp.prototype.toString.call(value), "regexp");
                        }
                        if (isDate(value)) {
                            return ctx.stylize(Date.prototype.toString.call(value), "date");
                        }
                        if (isError(value)) {
                            return formatError(value);
                        }
                    }
                    var base = "", array = false, braces = [ "{", "}" ];
                    if (isArray(value)) {
                        array = true;
                        braces = [ "[", "]" ];
                    }
                    if (isFunction(value)) {
                        var n = value.name ? ": " + value.name : "";
                        base = " [Function" + n + "]";
                    }
                    if (isRegExp(value)) {
                        base = " " + RegExp.prototype.toString.call(value);
                    }
                    if (isDate(value)) {
                        base = " " + Date.prototype.toUTCString.call(value);
                    }
                    if (isError(value)) {
                        base = " " + formatError(value);
                    }
                    if (keys.length === 0 && (!array || value.length == 0)) {
                        return braces[0] + base + braces[1];
                    }
                    if (recurseTimes < 0) {
                        if (isRegExp(value)) {
                            return ctx.stylize(RegExp.prototype.toString.call(value), "regexp");
                        } else {
                            return ctx.stylize("[Object]", "special");
                        }
                    }
                    ctx.seen.push(value);
                    var output;
                    if (array) {
                        output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
                    } else {
                        output = keys.map(function(key) {
                            return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
                        });
                    }
                    ctx.seen.pop();
                    return reduceToSingleString(output, base, braces);
                }
                function formatPrimitive(ctx, value) {
                    if (isUndefined(value)) return ctx.stylize("undefined", "undefined");
                    if (isString(value)) {
                        var simple = "'" + JSON.stringify(value).replace(/^"|"$/g, "").replace(/'/g, "\\'").replace(/\\"/g, '"') + "'";
                        return ctx.stylize(simple, "string");
                    }
                    if (isNumber(value)) return ctx.stylize("" + value, "number");
                    if (isBoolean(value)) return ctx.stylize("" + value, "boolean");
                    if (isNull(value)) return ctx.stylize("null", "null");
                }
                function formatError(value) {
                    return "[" + Error.prototype.toString.call(value) + "]";
                }
                function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
                    var output = [];
                    for (var i = 0, l = value.length; i < l; ++i) {
                        if (hasOwnProperty(value, String(i))) {
                            output.push(formatProperty(ctx, value, recurseTimes, visibleKeys, String(i), true));
                        } else {
                            output.push("");
                        }
                    }
                    keys.forEach(function(key) {
                        if (!key.match(/^\d+$/)) {
                            output.push(formatProperty(ctx, value, recurseTimes, visibleKeys, key, true));
                        }
                    });
                    return output;
                }
                function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
                    var name, str, desc;
                    desc = Object.getOwnPropertyDescriptor(value, key) || {
                        value: value[key]
                    };
                    if (desc.get) {
                        if (desc.set) {
                            str = ctx.stylize("[Getter/Setter]", "special");
                        } else {
                            str = ctx.stylize("[Getter]", "special");
                        }
                    } else {
                        if (desc.set) {
                            str = ctx.stylize("[Setter]", "special");
                        }
                    }
                    if (!hasOwnProperty(visibleKeys, key)) {
                        name = "[" + key + "]";
                    }
                    if (!str) {
                        if (ctx.seen.indexOf(desc.value) < 0) {
                            if (isNull(recurseTimes)) {
                                str = formatValue(ctx, desc.value, null);
                            } else {
                                str = formatValue(ctx, desc.value, recurseTimes - 1);
                            }
                            if (str.indexOf("\n") > -1) {
                                if (array) {
                                    str = str.split("\n").map(function(line) {
                                        return "  " + line;
                                    }).join("\n").substr(2);
                                } else {
                                    str = "\n" + str.split("\n").map(function(line) {
                                        return "   " + line;
                                    }).join("\n");
                                }
                            }
                        } else {
                            str = ctx.stylize("[Circular]", "special");
                        }
                    }
                    if (isUndefined(name)) {
                        if (array && key.match(/^\d+$/)) {
                            return str;
                        }
                        name = JSON.stringify("" + key);
                        if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
                            name = name.substr(1, name.length - 2);
                            name = ctx.stylize(name, "name");
                        } else {
                            name = name.replace(/'/g, "\\'").replace(/\\"/g, '"').replace(/(^"|"$)/g, "'");
                            name = ctx.stylize(name, "string");
                        }
                    }
                    return name + ": " + str;
                }
                function reduceToSingleString(output, base, braces) {
                    var numLinesEst = 0;
                    var length = output.reduce(function(prev, cur) {
                        numLinesEst++;
                        if (cur.indexOf("\n") >= 0) numLinesEst++;
                        return prev + cur.replace(/\u001b\[\d\d?m/g, "").length + 1;
                    }, 0);
                    if (length > 60) {
                        return braces[0] + (base === "" ? "" : base + "\n ") + " " + output.join(",\n  ") + " " + braces[1];
                    }
                    return braces[0] + base + " " + output.join(", ") + " " + braces[1];
                }
                function isArray(ar) {
                    return Array.isArray(ar);
                }
                exports.isArray = isArray;
                function isBoolean(arg) {
                    return typeof arg === "boolean";
                }
                exports.isBoolean = isBoolean;
                function isNull(arg) {
                    return arg === null;
                }
                exports.isNull = isNull;
                function isNullOrUndefined(arg) {
                    return arg == null;
                }
                exports.isNullOrUndefined = isNullOrUndefined;
                function isNumber(arg) {
                    return typeof arg === "number";
                }
                exports.isNumber = isNumber;
                function isString(arg) {
                    return typeof arg === "string";
                }
                exports.isString = isString;
                function isSymbol(arg) {
                    return typeof arg === "symbol";
                }
                exports.isSymbol = isSymbol;
                function isUndefined(arg) {
                    return arg === void 0;
                }
                exports.isUndefined = isUndefined;
                function isRegExp(re) {
                    return isObject(re) && objectToString(re) === "[object RegExp]";
                }
                exports.isRegExp = isRegExp;
                function isObject(arg) {
                    return typeof arg === "object" && arg !== null;
                }
                exports.isObject = isObject;
                function isDate(d) {
                    return isObject(d) && objectToString(d) === "[object Date]";
                }
                exports.isDate = isDate;
                function isError(e) {
                    return isObject(e) && (objectToString(e) === "[object Error]" || e instanceof Error);
                }
                exports.isError = isError;
                function isFunction(arg) {
                    return typeof arg === "function";
                }
                exports.isFunction = isFunction;
                function isPrimitive(arg) {
                    return arg === null || typeof arg === "boolean" || typeof arg === "number" || typeof arg === "string" || typeof arg === "symbol" || typeof arg === "undefined";
                }
                exports.isPrimitive = isPrimitive;
                exports.isBuffer = require("./support/isBuffer");
                function objectToString(o) {
                    return Object.prototype.toString.call(o);
                }
                function pad(n) {
                    return n < 10 ? "0" + n.toString(10) : n.toString(10);
                }
                var months = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ];
                function timestamp() {
                    var d = new Date();
                    var time = [ pad(d.getHours()), pad(d.getMinutes()), pad(d.getSeconds()) ].join(":");
                    return [ d.getDate(), months[d.getMonth()], time ].join(" ");
                }
                exports.log = function() {
                    console.log("%s - %s", timestamp(), exports.format.apply(exports, arguments));
                };
                exports.inherits = require("inherits");
                exports._extend = function(origin, add) {
                    if (!add || !isObject(add)) return origin;
                    var keys = Object.keys(add);
                    var i = keys.length;
                    while (i--) {
                        origin[keys[i]] = add[keys[i]];
                    }
                    return origin;
                };
                function hasOwnProperty(obj, prop) {
                    return Object.prototype.hasOwnProperty.call(obj, prop);
                }
            }).call(this, require("_process"), typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
        }, {
            "./support/isBuffer": 49,
            _process: 48,
            inherits: 47
        } ],
        51: [ function(require, module, exports) {
            (function(Buffer) {
                var assert = require("assert");
                var crypto = require("crypto");
                function pbkdf2(key, salt, iterations, dkLen) {
                    var hLen = 32;
                    assert(dkLen <= (Math.pow(2, 32) - 1) * hLen, "requested key length too long");
                    assert(typeof key == "string" || Buffer.isBuffer(key), "key must be a string or buffer");
                    assert(typeof salt == "string" || Buffer.isBuffer(salt), "key must be a string or buffer");
                    if (typeof salt == "string") salt = new Buffer(salt);
                    var DK = new Buffer(dkLen);
                    var T = new Buffer(hLen);
                    var block1 = new Buffer(salt.length + 4);
                    var l = Math.ceil(dkLen / hLen);
                    var r = dkLen - (l - 1) * hLen;
                    salt.copy(block1, 0, 0, salt.length);
                    for (var i = 1; i <= l; i++) {
                        block1.writeUInt32BE(i, salt.length);
                        var U = crypto.createHmac("sha256", key).update(block1).digest();
                        U.copy(T, 0, 0, hLen);
                        for (var j = 1; j < iterations; j++) {
                            U = crypto.createHmac("sha256", key).update(U).digest();
                            for (var k = 0; k < hLen; k++) {
                                T[k] ^= U[k];
                            }
                        }
                        var destPos = (i - 1) * hLen;
                        var len = i == l ? r : hLen;
                        T.copy(DK, destPos, 0, len);
                    }
                    return DK;
                }
                module.exports = pbkdf2;
            }).call(this, require("buffer").Buffer);
        }, {
            assert: 41,
            buffer: 43,
            crypto: 19
        } ],
        52: [ function(require, module, exports) {
            angular.module("ng-ecdsa", [ "sacketty.ecdsa", "sacketty.crypto", "sacketty.coinkey", "sacketty.buffer" ]);
            angular.module("ng-crypto", [ "sacketty.crypto" ]);
            angular.module("ng-coinkey", [ "sacketty.coinkey" ]);
            angular.module("ng-aes", [ "sacketty.aes" ]);
            angular.module("ng-buffer", [ "sacketty.buffer" ]);
            angular.module("ng-pbkdf2", [ "sacketty.pbkdf2" ]);
        }, {} ],
        53: [ function(require, module, exports) {
            "use strict";
            var AES = require("aes");
            angular.module("sacketty.aes", []).factory("AES", function() {
                return AES;
            });
        }, {
            aes: 1
        } ],
        54: [ function(require, module, exports) {
            "use strict";
            var buffer = require("buffer");
            angular.module("sacketty.buffer", []).factory("buffer", function() {
                return buffer;
            });
        }, {
            buffer: 43
        } ],
        55: [ function(require, module, exports) {
            "use strict";
            var CoinKey = require("coinkey");
            angular.module("sacketty.coinkey", []).factory("CoinKey", function() {
                return CoinKey;
            });
        }, {
            coinkey: 2
        } ],
        56: [ function(require, module, exports) {
            "use strict";
            var crypto = require("crypto");
            angular.module("sacketty.crypto", []).factory("crypto", function() {
                return crypto;
            });
        }, {
            crypto: 19
        } ],
        57: [ function(require, module, exports) {
            "use strict";
            var ecdsa = require("ecdsa");
            angular.module("sacketty.ecdsa", []).factory("ecdsa", function() {
                return ecdsa;
            });
        }, {
            ecdsa: 30
        } ],
        58: [ function(require, module, exports) {
            "use strict";
            var pbkdf2 = require("pbkdf2-sha256");
            angular.module("sacketty.pbkdf2", []).factory("pbkdf2", function() {
                return pbkdf2;
            });
        }, {
            "pbkdf2-sha256": 51
        } ]
    }, {}, [ 52, 53, 54, 55, 56, 57, 58 ]);
})(this, this.angular, this.Math, void 0);