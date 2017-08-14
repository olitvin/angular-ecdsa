/*
  angular-ecdsa - v0.0.4 
  2017-08-14
*/

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
        var asn1 = exports;
        asn1.bignum = require("bn.js");
        asn1.define = require("./asn1/api").define;
        asn1.base = require("./asn1/base");
        asn1.constants = require("./asn1/constants");
        asn1.decoders = require("./asn1/decoders");
        asn1.encoders = require("./asn1/encoders");
    }, {
        "./asn1/api": 3,
        "./asn1/base": 5,
        "./asn1/constants": 9,
        "./asn1/decoders": 11,
        "./asn1/encoders": 14,
        "bn.js": 23
    } ],
    3: [ function(require, module, exports) {
        var asn1 = require("../asn1");
        var inherits = require("inherits");
        var api = exports;
        api.define = function define(name, body) {
            return new Entity(name, body);
        };
        function Entity(name, body) {
            this.name = name;
            this.body = body;
            this.decoders = {};
            this.encoders = {};
        }
        Entity.prototype._createNamed = function createNamed(base) {
            var named;
            try {
                named = require("vm").runInThisContext("(function " + this.name + "(entity) {\n" + "  this._initNamed(entity);\n" + "})");
            } catch (e) {
                named = function(entity) {
                    this._initNamed(entity);
                };
            }
            inherits(named, base);
            named.prototype._initNamed = function initnamed(entity) {
                base.call(this, entity);
            };
            return new named(this);
        };
        Entity.prototype._getDecoder = function _getDecoder(enc) {
            enc = enc || "der";
            if (!this.decoders.hasOwnProperty(enc)) this.decoders[enc] = this._createNamed(asn1.decoders[enc]);
            return this.decoders[enc];
        };
        Entity.prototype.decode = function decode(data, enc, options) {
            return this._getDecoder(enc).decode(data, options);
        };
        Entity.prototype._getEncoder = function _getEncoder(enc) {
            enc = enc || "der";
            if (!this.encoders.hasOwnProperty(enc)) this.encoders[enc] = this._createNamed(asn1.encoders[enc]);
            return this.encoders[enc];
        };
        Entity.prototype.encode = function encode(data, enc, reporter) {
            return this._getEncoder(enc).encode(data, reporter);
        };
    }, {
        "../asn1": 2,
        inherits: 122,
        vm: 188
    } ],
    4: [ function(require, module, exports) {
        var inherits = require("inherits");
        var Reporter = require("../base").Reporter;
        var Buffer = require("buffer").Buffer;
        function DecoderBuffer(base, options) {
            Reporter.call(this, options);
            if (!Buffer.isBuffer(base)) {
                this.error("Input not Buffer");
                return;
            }
            this.base = base;
            this.offset = 0;
            this.length = base.length;
        }
        inherits(DecoderBuffer, Reporter);
        exports.DecoderBuffer = DecoderBuffer;
        DecoderBuffer.prototype.save = function save() {
            return {
                offset: this.offset,
                reporter: Reporter.prototype.save.call(this)
            };
        };
        DecoderBuffer.prototype.restore = function restore(save) {
            var res = new DecoderBuffer(this.base);
            res.offset = save.offset;
            res.length = this.offset;
            this.offset = save.offset;
            Reporter.prototype.restore.call(this, save.reporter);
            return res;
        };
        DecoderBuffer.prototype.isEmpty = function isEmpty() {
            return this.offset === this.length;
        };
        DecoderBuffer.prototype.readUInt8 = function readUInt8(fail) {
            if (this.offset + 1 <= this.length) return this.base.readUInt8(this.offset++, true); else return this.error(fail || "DecoderBuffer overrun");
        };
        DecoderBuffer.prototype.skip = function skip(bytes, fail) {
            if (!(this.offset + bytes <= this.length)) return this.error(fail || "DecoderBuffer overrun");
            var res = new DecoderBuffer(this.base);
            res._reporterState = this._reporterState;
            res.offset = this.offset;
            res.length = this.offset + bytes;
            this.offset += bytes;
            return res;
        };
        DecoderBuffer.prototype.raw = function raw(save) {
            return this.base.slice(save ? save.offset : this.offset, this.length);
        };
        function EncoderBuffer(value, reporter) {
            if (Array.isArray(value)) {
                this.length = 0;
                this.value = value.map(function(item) {
                    if (!(item instanceof EncoderBuffer)) item = new EncoderBuffer(item, reporter);
                    this.length += item.length;
                    return item;
                }, this);
            } else if (typeof value === "number") {
                if (!(0 <= value && value <= 255)) return reporter.error("non-byte EncoderBuffer value");
                this.value = value;
                this.length = 1;
            } else if (typeof value === "string") {
                this.value = value;
                this.length = Buffer.byteLength(value);
            } else if (Buffer.isBuffer(value)) {
                this.value = value;
                this.length = value.length;
            } else {
                return reporter.error("Unsupported type: " + typeof value);
            }
        }
        exports.EncoderBuffer = EncoderBuffer;
        EncoderBuffer.prototype.join = function join(out, offset) {
            if (!out) out = new Buffer(this.length);
            if (!offset) offset = 0;
            if (this.length === 0) return out;
            if (Array.isArray(this.value)) {
                this.value.forEach(function(item) {
                    item.join(out, offset);
                    offset += item.length;
                });
            } else {
                if (typeof this.value === "number") out[offset] = this.value; else if (typeof this.value === "string") out.write(this.value, offset); else if (Buffer.isBuffer(this.value)) this.value.copy(out, offset);
                offset += this.length;
            }
            return out;
        };
    }, {
        "../base": 5,
        buffer: 54,
        inherits: 122
    } ],
    5: [ function(require, module, exports) {
        var base = exports;
        base.Reporter = require("./reporter").Reporter;
        base.DecoderBuffer = require("./buffer").DecoderBuffer;
        base.EncoderBuffer = require("./buffer").EncoderBuffer;
        base.Node = require("./node");
    }, {
        "./buffer": 4,
        "./node": 6,
        "./reporter": 7
    } ],
    6: [ function(require, module, exports) {
        var Reporter = require("../base").Reporter;
        var EncoderBuffer = require("../base").EncoderBuffer;
        var DecoderBuffer = require("../base").DecoderBuffer;
        var assert = require("minimalistic-assert");
        var tags = [ "seq", "seqof", "set", "setof", "objid", "bool", "gentime", "utctime", "null_", "enum", "int", "objDesc", "bitstr", "bmpstr", "charstr", "genstr", "graphstr", "ia5str", "iso646str", "numstr", "octstr", "printstr", "t61str", "unistr", "utf8str", "videostr" ];
        var methods = [ "key", "obj", "use", "optional", "explicit", "implicit", "def", "choice", "any", "contains" ].concat(tags);
        var overrided = [ "_peekTag", "_decodeTag", "_use", "_decodeStr", "_decodeObjid", "_decodeTime", "_decodeNull", "_decodeInt", "_decodeBool", "_decodeList", "_encodeComposite", "_encodeStr", "_encodeObjid", "_encodeTime", "_encodeNull", "_encodeInt", "_encodeBool" ];
        function Node(enc, parent) {
            var state = {};
            this._baseState = state;
            state.enc = enc;
            state.parent = parent || null;
            state.children = null;
            state.tag = null;
            state.args = null;
            state.reverseArgs = null;
            state.choice = null;
            state.optional = false;
            state.any = false;
            state.obj = false;
            state.use = null;
            state.useDecoder = null;
            state.key = null;
            state["default"] = null;
            state.explicit = null;
            state.implicit = null;
            state.contains = null;
            if (!state.parent) {
                state.children = [];
                this._wrap();
            }
        }
        module.exports = Node;
        var stateProps = [ "enc", "parent", "children", "tag", "args", "reverseArgs", "choice", "optional", "any", "obj", "use", "alteredUse", "key", "default", "explicit", "implicit", "contains" ];
        Node.prototype.clone = function clone() {
            var state = this._baseState;
            var cstate = {};
            stateProps.forEach(function(prop) {
                cstate[prop] = state[prop];
            });
            var res = new this.constructor(cstate.parent);
            res._baseState = cstate;
            return res;
        };
        Node.prototype._wrap = function wrap() {
            var state = this._baseState;
            methods.forEach(function(method) {
                this[method] = function _wrappedMethod() {
                    var clone = new this.constructor(this);
                    state.children.push(clone);
                    return clone[method].apply(clone, arguments);
                };
            }, this);
        };
        Node.prototype._init = function init(body) {
            var state = this._baseState;
            assert(state.parent === null);
            body.call(this);
            state.children = state.children.filter(function(child) {
                return child._baseState.parent === this;
            }, this);
            assert.equal(state.children.length, 1, "Root node can have only one child");
        };
        Node.prototype._useArgs = function useArgs(args) {
            var state = this._baseState;
            var children = args.filter(function(arg) {
                return arg instanceof this.constructor;
            }, this);
            args = args.filter(function(arg) {
                return !(arg instanceof this.constructor);
            }, this);
            if (children.length !== 0) {
                assert(state.children === null);
                state.children = children;
                children.forEach(function(child) {
                    child._baseState.parent = this;
                }, this);
            }
            if (args.length !== 0) {
                assert(state.args === null);
                state.args = args;
                state.reverseArgs = args.map(function(arg) {
                    if (typeof arg !== "object" || arg.constructor !== Object) return arg;
                    var res = {};
                    Object.keys(arg).forEach(function(key) {
                        if (key == (key | 0)) key |= 0;
                        var value = arg[key];
                        res[value] = key;
                    });
                    return res;
                });
            }
        };
        overrided.forEach(function(method) {
            Node.prototype[method] = function _overrided() {
                var state = this._baseState;
                throw new Error(method + " not implemented for encoding: " + state.enc);
            };
        });
        tags.forEach(function(tag) {
            Node.prototype[tag] = function _tagMethod() {
                var state = this._baseState;
                var args = Array.prototype.slice.call(arguments);
                assert(state.tag === null);
                state.tag = tag;
                this._useArgs(args);
                return this;
            };
        });
        Node.prototype.use = function use(item) {
            assert(item);
            var state = this._baseState;
            assert(state.use === null);
            state.use = item;
            return this;
        };
        Node.prototype.optional = function optional() {
            var state = this._baseState;
            state.optional = true;
            return this;
        };
        Node.prototype.def = function def(val) {
            var state = this._baseState;
            assert(state["default"] === null);
            state["default"] = val;
            state.optional = true;
            return this;
        };
        Node.prototype.explicit = function explicit(num) {
            var state = this._baseState;
            assert(state.explicit === null && state.implicit === null);
            state.explicit = num;
            return this;
        };
        Node.prototype.implicit = function implicit(num) {
            var state = this._baseState;
            assert(state.explicit === null && state.implicit === null);
            state.implicit = num;
            return this;
        };
        Node.prototype.obj = function obj() {
            var state = this._baseState;
            var args = Array.prototype.slice.call(arguments);
            state.obj = true;
            if (args.length !== 0) this._useArgs(args);
            return this;
        };
        Node.prototype.key = function key(newKey) {
            var state = this._baseState;
            assert(state.key === null);
            state.key = newKey;
            return this;
        };
        Node.prototype.any = function any() {
            var state = this._baseState;
            state.any = true;
            return this;
        };
        Node.prototype.choice = function choice(obj) {
            var state = this._baseState;
            assert(state.choice === null);
            state.choice = obj;
            this._useArgs(Object.keys(obj).map(function(key) {
                return obj[key];
            }));
            return this;
        };
        Node.prototype.contains = function contains(item) {
            var state = this._baseState;
            assert(state.use === null);
            state.contains = item;
            return this;
        };
        Node.prototype._decode = function decode(input, options) {
            var state = this._baseState;
            if (state.parent === null) return input.wrapResult(state.children[0]._decode(input, options));
            var result = state["default"];
            var present = true;
            var prevKey = null;
            if (state.key !== null) prevKey = input.enterKey(state.key);
            if (state.optional) {
                var tag = null;
                if (state.explicit !== null) tag = state.explicit; else if (state.implicit !== null) tag = state.implicit; else if (state.tag !== null) tag = state.tag;
                if (tag === null && !state.any) {
                    var save = input.save();
                    try {
                        if (state.choice === null) this._decodeGeneric(state.tag, input, options); else this._decodeChoice(input, options);
                        present = true;
                    } catch (e) {
                        present = false;
                    }
                    input.restore(save);
                } else {
                    present = this._peekTag(input, tag, state.any);
                    if (input.isError(present)) return present;
                }
            }
            var prevObj;
            if (state.obj && present) prevObj = input.enterObject();
            if (present) {
                if (state.explicit !== null) {
                    var explicit = this._decodeTag(input, state.explicit);
                    if (input.isError(explicit)) return explicit;
                    input = explicit;
                }
                var start = input.offset;
                if (state.use === null && state.choice === null) {
                    if (state.any) var save = input.save();
                    var body = this._decodeTag(input, state.implicit !== null ? state.implicit : state.tag, state.any);
                    if (input.isError(body)) return body;
                    if (state.any) result = input.raw(save); else input = body;
                }
                if (options && options.track && state.tag !== null) options.track(input.path(), start, input.length, "tagged");
                if (options && options.track && state.tag !== null) options.track(input.path(), input.offset, input.length, "content");
                if (state.any) result = result; else if (state.choice === null) result = this._decodeGeneric(state.tag, input, options); else result = this._decodeChoice(input, options);
                if (input.isError(result)) return result;
                if (!state.any && state.choice === null && state.children !== null) {
                    state.children.forEach(function decodeChildren(child) {
                        child._decode(input, options);
                    });
                }
                if (state.contains && (state.tag === "octstr" || state.tag === "bitstr")) {
                    var data = new DecoderBuffer(result);
                    result = this._getUse(state.contains, input._reporterState.obj)._decode(data, options);
                }
            }
            if (state.obj && present) result = input.leaveObject(prevObj);
            if (state.key !== null && (result !== null || present === true)) input.leaveKey(prevKey, state.key, result); else if (prevKey !== null) input.exitKey(prevKey);
            return result;
        };
        Node.prototype._decodeGeneric = function decodeGeneric(tag, input, options) {
            var state = this._baseState;
            if (tag === "seq" || tag === "set") return null;
            if (tag === "seqof" || tag === "setof") return this._decodeList(input, tag, state.args[0], options); else if (/str$/.test(tag)) return this._decodeStr(input, tag, options); else if (tag === "objid" && state.args) return this._decodeObjid(input, state.args[0], state.args[1], options); else if (tag === "objid") return this._decodeObjid(input, null, null, options); else if (tag === "gentime" || tag === "utctime") return this._decodeTime(input, tag, options); else if (tag === "null_") return this._decodeNull(input, options); else if (tag === "bool") return this._decodeBool(input, options); else if (tag === "objDesc") return this._decodeStr(input, tag, options); else if (tag === "int" || tag === "enum") return this._decodeInt(input, state.args && state.args[0], options);
            if (state.use !== null) {
                return this._getUse(state.use, input._reporterState.obj)._decode(input, options);
            } else {
                return input.error("unknown tag: " + tag);
            }
        };
        Node.prototype._getUse = function _getUse(entity, obj) {
            var state = this._baseState;
            state.useDecoder = this._use(entity, obj);
            assert(state.useDecoder._baseState.parent === null);
            state.useDecoder = state.useDecoder._baseState.children[0];
            if (state.implicit !== state.useDecoder._baseState.implicit) {
                state.useDecoder = state.useDecoder.clone();
                state.useDecoder._baseState.implicit = state.implicit;
            }
            return state.useDecoder;
        };
        Node.prototype._decodeChoice = function decodeChoice(input, options) {
            var state = this._baseState;
            var result = null;
            var match = false;
            Object.keys(state.choice).some(function(key) {
                var save = input.save();
                var node = state.choice[key];
                try {
                    var value = node._decode(input, options);
                    if (input.isError(value)) return false;
                    result = {
                        type: key,
                        value: value
                    };
                    match = true;
                } catch (e) {
                    input.restore(save);
                    return false;
                }
                return true;
            }, this);
            if (!match) return input.error("Choice not matched");
            return result;
        };
        Node.prototype._createEncoderBuffer = function createEncoderBuffer(data) {
            return new EncoderBuffer(data, this.reporter);
        };
        Node.prototype._encode = function encode(data, reporter, parent) {
            var state = this._baseState;
            if (state["default"] !== null && state["default"] === data) return;
            var result = this._encodeValue(data, reporter, parent);
            if (result === undefined) return;
            if (this._skipDefault(result, reporter, parent)) return;
            return result;
        };
        Node.prototype._encodeValue = function encode(data, reporter, parent) {
            var state = this._baseState;
            if (state.parent === null) return state.children[0]._encode(data, reporter || new Reporter());
            var result = null;
            this.reporter = reporter;
            if (state.optional && data === undefined) {
                if (state["default"] !== null) data = state["default"]; else return;
            }
            var content = null;
            var primitive = false;
            if (state.any) {
                result = this._createEncoderBuffer(data);
            } else if (state.choice) {
                result = this._encodeChoice(data, reporter);
            } else if (state.contains) {
                content = this._getUse(state.contains, parent)._encode(data, reporter);
                primitive = true;
            } else if (state.children) {
                content = state.children.map(function(child) {
                    if (child._baseState.tag === "null_") return child._encode(null, reporter, data);
                    if (child._baseState.key === null) return reporter.error("Child should have a key");
                    var prevKey = reporter.enterKey(child._baseState.key);
                    if (typeof data !== "object") return reporter.error("Child expected, but input is not object");
                    var res = child._encode(data[child._baseState.key], reporter, data);
                    reporter.leaveKey(prevKey);
                    return res;
                }, this).filter(function(child) {
                    return child;
                });
                content = this._createEncoderBuffer(content);
            } else {
                if (state.tag === "seqof" || state.tag === "setof") {
                    if (!(state.args && state.args.length === 1)) return reporter.error("Too many args for : " + state.tag);
                    if (!Array.isArray(data)) return reporter.error("seqof/setof, but data is not Array");
                    var child = this.clone();
                    child._baseState.implicit = null;
                    content = this._createEncoderBuffer(data.map(function(item) {
                        var state = this._baseState;
                        return this._getUse(state.args[0], data)._encode(item, reporter);
                    }, child));
                } else if (state.use !== null) {
                    result = this._getUse(state.use, parent)._encode(data, reporter);
                } else {
                    content = this._encodePrimitive(state.tag, data);
                    primitive = true;
                }
            }
            var result;
            if (!state.any && state.choice === null) {
                var tag = state.implicit !== null ? state.implicit : state.tag;
                var cls = state.implicit === null ? "universal" : "context";
                if (tag === null) {
                    if (state.use === null) reporter.error("Tag could be ommited only for .use()");
                } else {
                    if (state.use === null) result = this._encodeComposite(tag, primitive, cls, content);
                }
            }
            if (state.explicit !== null) result = this._encodeComposite(state.explicit, false, "context", result);
            return result;
        };
        Node.prototype._encodeChoice = function encodeChoice(data, reporter) {
            var state = this._baseState;
            var node = state.choice[data.type];
            if (!node) {
                assert(false, data.type + " not found in " + JSON.stringify(Object.keys(state.choice)));
            }
            return node._encode(data.value, reporter);
        };
        Node.prototype._encodePrimitive = function encodePrimitive(tag, data) {
            var state = this._baseState;
            if (/str$/.test(tag)) return this._encodeStr(data, tag); else if (tag === "objid" && state.args) return this._encodeObjid(data, state.reverseArgs[0], state.args[1]); else if (tag === "objid") return this._encodeObjid(data, null, null); else if (tag === "gentime" || tag === "utctime") return this._encodeTime(data, tag); else if (tag === "null_") return this._encodeNull(); else if (tag === "int" || tag === "enum") return this._encodeInt(data, state.args && state.reverseArgs[0]); else if (tag === "bool") return this._encodeBool(data); else if (tag === "objDesc") return this._encodeStr(data, tag); else throw new Error("Unsupported tag: " + tag);
        };
        Node.prototype._isNumstr = function isNumstr(str) {
            return /^[0-9 ]*$/.test(str);
        };
        Node.prototype._isPrintstr = function isPrintstr(str) {
            return /^[A-Za-z0-9 '\(\)\+,\-\.\/:=\?]*$/.test(str);
        };
    }, {
        "../base": 5,
        "minimalistic-assert": 126
    } ],
    7: [ function(require, module, exports) {
        var inherits = require("inherits");
        function Reporter(options) {
            this._reporterState = {
                obj: null,
                path: [],
                options: options || {},
                errors: []
            };
        }
        exports.Reporter = Reporter;
        Reporter.prototype.isError = function isError(obj) {
            return obj instanceof ReporterError;
        };
        Reporter.prototype.save = function save() {
            var state = this._reporterState;
            return {
                obj: state.obj,
                pathLen: state.path.length
            };
        };
        Reporter.prototype.restore = function restore(data) {
            var state = this._reporterState;
            state.obj = data.obj;
            state.path = state.path.slice(0, data.pathLen);
        };
        Reporter.prototype.enterKey = function enterKey(key) {
            return this._reporterState.path.push(key);
        };
        Reporter.prototype.exitKey = function exitKey(index) {
            var state = this._reporterState;
            state.path = state.path.slice(0, index - 1);
        };
        Reporter.prototype.leaveKey = function leaveKey(index, key, value) {
            var state = this._reporterState;
            this.exitKey(index);
            if (state.obj !== null) state.obj[key] = value;
        };
        Reporter.prototype.path = function path() {
            return this._reporterState.path.join("/");
        };
        Reporter.prototype.enterObject = function enterObject() {
            var state = this._reporterState;
            var prev = state.obj;
            state.obj = {};
            return prev;
        };
        Reporter.prototype.leaveObject = function leaveObject(prev) {
            var state = this._reporterState;
            var now = state.obj;
            state.obj = prev;
            return now;
        };
        Reporter.prototype.error = function error(msg) {
            var err;
            var state = this._reporterState;
            var inherited = msg instanceof ReporterError;
            if (inherited) {
                err = msg;
            } else {
                err = new ReporterError(state.path.map(function(elem) {
                    return "[" + JSON.stringify(elem) + "]";
                }).join(""), msg.message || msg, msg.stack);
            }
            if (!state.options.partial) throw err;
            if (!inherited) state.errors.push(err);
            return err;
        };
        Reporter.prototype.wrapResult = function wrapResult(result) {
            var state = this._reporterState;
            if (!state.options.partial) return result;
            return {
                result: this.isError(result) ? null : result,
                errors: state.errors
            };
        };
        function ReporterError(path, msg) {
            this.path = path;
            this.rethrow(msg);
        }
        inherits(ReporterError, Error);
        ReporterError.prototype.rethrow = function rethrow(msg) {
            this.message = msg + " at: " + (this.path || "(shallow)");
            if (Error.captureStackTrace) Error.captureStackTrace(this, ReporterError);
            if (!this.stack) {
                try {
                    throw new Error(this.message);
                } catch (e) {
                    this.stack = e.stack;
                }
            }
            return this;
        };
    }, {
        inherits: 122
    } ],
    8: [ function(require, module, exports) {
        var constants = require("../constants");
        exports.tagClass = {
            0: "universal",
            1: "application",
            2: "context",
            3: "private"
        };
        exports.tagClassByName = constants._reverse(exports.tagClass);
        exports.tag = {
            0: "end",
            1: "bool",
            2: "int",
            3: "bitstr",
            4: "octstr",
            5: "null_",
            6: "objid",
            7: "objDesc",
            8: "external",
            9: "real",
            10: "enum",
            11: "embed",
            12: "utf8str",
            13: "relativeOid",
            16: "seq",
            17: "set",
            18: "numstr",
            19: "printstr",
            20: "t61str",
            21: "videostr",
            22: "ia5str",
            23: "utctime",
            24: "gentime",
            25: "graphstr",
            26: "iso646str",
            27: "genstr",
            28: "unistr",
            29: "charstr",
            30: "bmpstr"
        };
        exports.tagByName = constants._reverse(exports.tag);
    }, {
        "../constants": 9
    } ],
    9: [ function(require, module, exports) {
        var constants = exports;
        constants._reverse = function reverse(map) {
            var res = {};
            Object.keys(map).forEach(function(key) {
                if ((key | 0) == key) key = key | 0;
                var value = map[key];
                res[value] = key;
            });
            return res;
        };
        constants.der = require("./der");
    }, {
        "./der": 8
    } ],
    10: [ function(require, module, exports) {
        var inherits = require("inherits");
        var asn1 = require("../../asn1");
        var base = asn1.base;
        var bignum = asn1.bignum;
        var der = asn1.constants.der;
        function DERDecoder(entity) {
            this.enc = "der";
            this.name = entity.name;
            this.entity = entity;
            this.tree = new DERNode();
            this.tree._init(entity.body);
        }
        module.exports = DERDecoder;
        DERDecoder.prototype.decode = function decode(data, options) {
            if (!(data instanceof base.DecoderBuffer)) data = new base.DecoderBuffer(data, options);
            return this.tree._decode(data, options);
        };
        function DERNode(parent) {
            base.Node.call(this, "der", parent);
        }
        inherits(DERNode, base.Node);
        DERNode.prototype._peekTag = function peekTag(buffer, tag, any) {
            if (buffer.isEmpty()) return false;
            var state = buffer.save();
            var decodedTag = derDecodeTag(buffer, 'Failed to peek tag: "' + tag + '"');
            if (buffer.isError(decodedTag)) return decodedTag;
            buffer.restore(state);
            return decodedTag.tag === tag || decodedTag.tagStr === tag || decodedTag.tagStr + "of" === tag || any;
        };
        DERNode.prototype._decodeTag = function decodeTag(buffer, tag, any) {
            var decodedTag = derDecodeTag(buffer, 'Failed to decode tag of "' + tag + '"');
            if (buffer.isError(decodedTag)) return decodedTag;
            var len = derDecodeLen(buffer, decodedTag.primitive, 'Failed to get length of "' + tag + '"');
            if (buffer.isError(len)) return len;
            if (!any && decodedTag.tag !== tag && decodedTag.tagStr !== tag && decodedTag.tagStr + "of" !== tag) {
                return buffer.error('Failed to match tag: "' + tag + '"');
            }
            if (decodedTag.primitive || len !== null) return buffer.skip(len, 'Failed to match body of: "' + tag + '"');
            var state = buffer.save();
            var res = this._skipUntilEnd(buffer, 'Failed to skip indefinite length body: "' + this.tag + '"');
            if (buffer.isError(res)) return res;
            len = buffer.offset - state.offset;
            buffer.restore(state);
            return buffer.skip(len, 'Failed to match body of: "' + tag + '"');
        };
        DERNode.prototype._skipUntilEnd = function skipUntilEnd(buffer, fail) {
            while (true) {
                var tag = derDecodeTag(buffer, fail);
                if (buffer.isError(tag)) return tag;
                var len = derDecodeLen(buffer, tag.primitive, fail);
                if (buffer.isError(len)) return len;
                var res;
                if (tag.primitive || len !== null) res = buffer.skip(len); else res = this._skipUntilEnd(buffer, fail);
                if (buffer.isError(res)) return res;
                if (tag.tagStr === "end") break;
            }
        };
        DERNode.prototype._decodeList = function decodeList(buffer, tag, decoder, options) {
            var result = [];
            while (!buffer.isEmpty()) {
                var possibleEnd = this._peekTag(buffer, "end");
                if (buffer.isError(possibleEnd)) return possibleEnd;
                var res = decoder.decode(buffer, "der", options);
                if (buffer.isError(res) && possibleEnd) break;
                result.push(res);
            }
            return result;
        };
        DERNode.prototype._decodeStr = function decodeStr(buffer, tag) {
            if (tag === "bitstr") {
                var unused = buffer.readUInt8();
                if (buffer.isError(unused)) return unused;
                return {
                    unused: unused,
                    data: buffer.raw()
                };
            } else if (tag === "bmpstr") {
                var raw = buffer.raw();
                if (raw.length % 2 === 1) return buffer.error("Decoding of string type: bmpstr length mismatch");
                var str = "";
                for (var i = 0; i < raw.length / 2; i++) {
                    str += String.fromCharCode(raw.readUInt16BE(i * 2));
                }
                return str;
            } else if (tag === "numstr") {
                var numstr = buffer.raw().toString("ascii");
                if (!this._isNumstr(numstr)) {
                    return buffer.error("Decoding of string type: " + "numstr unsupported characters");
                }
                return numstr;
            } else if (tag === "octstr") {
                return buffer.raw();
            } else if (tag === "objDesc") {
                return buffer.raw();
            } else if (tag === "printstr") {
                var printstr = buffer.raw().toString("ascii");
                if (!this._isPrintstr(printstr)) {
                    return buffer.error("Decoding of string type: " + "printstr unsupported characters");
                }
                return printstr;
            } else if (/str$/.test(tag)) {
                return buffer.raw().toString();
            } else {
                return buffer.error("Decoding of string type: " + tag + " unsupported");
            }
        };
        DERNode.prototype._decodeObjid = function decodeObjid(buffer, values, relative) {
            var result;
            var identifiers = [];
            var ident = 0;
            while (!buffer.isEmpty()) {
                var subident = buffer.readUInt8();
                ident <<= 7;
                ident |= subident & 127;
                if ((subident & 128) === 0) {
                    identifiers.push(ident);
                    ident = 0;
                }
            }
            if (subident & 128) identifiers.push(ident);
            var first = identifiers[0] / 40 | 0;
            var second = identifiers[0] % 40;
            if (relative) result = identifiers; else result = [ first, second ].concat(identifiers.slice(1));
            if (values) {
                var tmp = values[result.join(" ")];
                if (tmp === undefined) tmp = values[result.join(".")];
                if (tmp !== undefined) result = tmp;
            }
            return result;
        };
        DERNode.prototype._decodeTime = function decodeTime(buffer, tag) {
            var str = buffer.raw().toString();
            if (tag === "gentime") {
                var year = str.slice(0, 4) | 0;
                var mon = str.slice(4, 6) | 0;
                var day = str.slice(6, 8) | 0;
                var hour = str.slice(8, 10) | 0;
                var min = str.slice(10, 12) | 0;
                var sec = str.slice(12, 14) | 0;
            } else if (tag === "utctime") {
                var year = str.slice(0, 2) | 0;
                var mon = str.slice(2, 4) | 0;
                var day = str.slice(4, 6) | 0;
                var hour = str.slice(6, 8) | 0;
                var min = str.slice(8, 10) | 0;
                var sec = str.slice(10, 12) | 0;
                if (year < 70) year = 2e3 + year; else year = 1900 + year;
            } else {
                return buffer.error("Decoding " + tag + " time is not supported yet");
            }
            return Date.UTC(year, mon - 1, day, hour, min, sec, 0);
        };
        DERNode.prototype._decodeNull = function decodeNull(buffer) {
            return null;
        };
        DERNode.prototype._decodeBool = function decodeBool(buffer) {
            var res = buffer.readUInt8();
            if (buffer.isError(res)) return res; else return res !== 0;
        };
        DERNode.prototype._decodeInt = function decodeInt(buffer, values) {
            var raw = buffer.raw();
            var res = new bignum(raw);
            if (values) res = values[res.toString(10)] || res;
            return res;
        };
        DERNode.prototype._use = function use(entity, obj) {
            if (typeof entity === "function") entity = entity(obj);
            return entity._getDecoder("der").tree;
        };
        function derDecodeTag(buf, fail) {
            var tag = buf.readUInt8(fail);
            if (buf.isError(tag)) return tag;
            var cls = der.tagClass[tag >> 6];
            var primitive = (tag & 32) === 0;
            if ((tag & 31) === 31) {
                var oct = tag;
                tag = 0;
                while ((oct & 128) === 128) {
                    oct = buf.readUInt8(fail);
                    if (buf.isError(oct)) return oct;
                    tag <<= 7;
                    tag |= oct & 127;
                }
            } else {
                tag &= 31;
            }
            var tagStr = der.tag[tag];
            return {
                cls: cls,
                primitive: primitive,
                tag: tag,
                tagStr: tagStr
            };
        }
        function derDecodeLen(buf, primitive, fail) {
            var len = buf.readUInt8(fail);
            if (buf.isError(len)) return len;
            if (!primitive && len === 128) return null;
            if ((len & 128) === 0) {
                return len;
            }
            var num = len & 127;
            if (num > 4) return buf.error("length octect is too long");
            len = 0;
            for (var i = 0; i < num; i++) {
                len <<= 8;
                var j = buf.readUInt8(fail);
                if (buf.isError(j)) return j;
                len |= j;
            }
            return len;
        }
    }, {
        "../../asn1": 2,
        inherits: 122
    } ],
    11: [ function(require, module, exports) {
        var decoders = exports;
        decoders.der = require("./der");
        decoders.pem = require("./pem");
    }, {
        "./der": 10,
        "./pem": 12
    } ],
    12: [ function(require, module, exports) {
        var inherits = require("inherits");
        var Buffer = require("buffer").Buffer;
        var DERDecoder = require("./der");
        function PEMDecoder(entity) {
            DERDecoder.call(this, entity);
            this.enc = "pem";
        }
        inherits(PEMDecoder, DERDecoder);
        module.exports = PEMDecoder;
        PEMDecoder.prototype.decode = function decode(data, options) {
            var lines = data.toString().split(/[\r\n]+/g);
            var label = options.label.toUpperCase();
            var re = /^-----(BEGIN|END) ([^-]+)-----$/;
            var start = -1;
            var end = -1;
            for (var i = 0; i < lines.length; i++) {
                var match = lines[i].match(re);
                if (match === null) continue;
                if (match[2] !== label) continue;
                if (start === -1) {
                    if (match[1] !== "BEGIN") break;
                    start = i;
                } else {
                    if (match[1] !== "END") break;
                    end = i;
                    break;
                }
            }
            if (start === -1 || end === -1) throw new Error("PEM section not found for: " + label);
            var base64 = lines.slice(start + 1, end).join("");
            base64.replace(/[^a-z0-9\+\/=]+/gi, "");
            var input = new Buffer(base64, "base64");
            return DERDecoder.prototype.decode.call(this, input, options);
        };
    }, {
        "./der": 10,
        buffer: 54,
        inherits: 122
    } ],
    13: [ function(require, module, exports) {
        var inherits = require("inherits");
        var Buffer = require("buffer").Buffer;
        var asn1 = require("../../asn1");
        var base = asn1.base;
        var der = asn1.constants.der;
        function DEREncoder(entity) {
            this.enc = "der";
            this.name = entity.name;
            this.entity = entity;
            this.tree = new DERNode();
            this.tree._init(entity.body);
        }
        module.exports = DEREncoder;
        DEREncoder.prototype.encode = function encode(data, reporter) {
            return this.tree._encode(data, reporter).join();
        };
        function DERNode(parent) {
            base.Node.call(this, "der", parent);
        }
        inherits(DERNode, base.Node);
        DERNode.prototype._encodeComposite = function encodeComposite(tag, primitive, cls, content) {
            var encodedTag = encodeTag(tag, primitive, cls, this.reporter);
            if (content.length < 128) {
                var header = new Buffer(2);
                header[0] = encodedTag;
                header[1] = content.length;
                return this._createEncoderBuffer([ header, content ]);
            }
            var lenOctets = 1;
            for (var i = content.length; i >= 256; i >>= 8) lenOctets++;
            var header = new Buffer(1 + 1 + lenOctets);
            header[0] = encodedTag;
            header[1] = 128 | lenOctets;
            for (var i = 1 + lenOctets, j = content.length; j > 0; i--, j >>= 8) header[i] = j & 255;
            return this._createEncoderBuffer([ header, content ]);
        };
        DERNode.prototype._encodeStr = function encodeStr(str, tag) {
            if (tag === "bitstr") {
                return this._createEncoderBuffer([ str.unused | 0, str.data ]);
            } else if (tag === "bmpstr") {
                var buf = new Buffer(str.length * 2);
                for (var i = 0; i < str.length; i++) {
                    buf.writeUInt16BE(str.charCodeAt(i), i * 2);
                }
                return this._createEncoderBuffer(buf);
            } else if (tag === "numstr") {
                if (!this._isNumstr(str)) {
                    return this.reporter.error("Encoding of string type: numstr supports " + "only digits and space");
                }
                return this._createEncoderBuffer(str);
            } else if (tag === "printstr") {
                if (!this._isPrintstr(str)) {
                    return this.reporter.error("Encoding of string type: printstr supports " + "only latin upper and lower case letters, " + "digits, space, apostrophe, left and rigth " + "parenthesis, plus sign, comma, hyphen, " + "dot, slash, colon, equal sign, " + "question mark");
                }
                return this._createEncoderBuffer(str);
            } else if (/str$/.test(tag)) {
                return this._createEncoderBuffer(str);
            } else if (tag === "objDesc") {
                return this._createEncoderBuffer(str);
            } else {
                return this.reporter.error("Encoding of string type: " + tag + " unsupported");
            }
        };
        DERNode.prototype._encodeObjid = function encodeObjid(id, values, relative) {
            if (typeof id === "string") {
                if (!values) return this.reporter.error("string objid given, but no values map found");
                if (!values.hasOwnProperty(id)) return this.reporter.error("objid not found in values map");
                id = values[id].split(/[\s\.]+/g);
                for (var i = 0; i < id.length; i++) id[i] |= 0;
            } else if (Array.isArray(id)) {
                id = id.slice();
                for (var i = 0; i < id.length; i++) id[i] |= 0;
            }
            if (!Array.isArray(id)) {
                return this.reporter.error("objid() should be either array or string, " + "got: " + JSON.stringify(id));
            }
            if (!relative) {
                if (id[1] >= 40) return this.reporter.error("Second objid identifier OOB");
                id.splice(0, 2, id[0] * 40 + id[1]);
            }
            var size = 0;
            for (var i = 0; i < id.length; i++) {
                var ident = id[i];
                for (size++; ident >= 128; ident >>= 7) size++;
            }
            var objid = new Buffer(size);
            var offset = objid.length - 1;
            for (var i = id.length - 1; i >= 0; i--) {
                var ident = id[i];
                objid[offset--] = ident & 127;
                while ((ident >>= 7) > 0) objid[offset--] = 128 | ident & 127;
            }
            return this._createEncoderBuffer(objid);
        };
        function two(num) {
            if (num < 10) return "0" + num; else return num;
        }
        DERNode.prototype._encodeTime = function encodeTime(time, tag) {
            var str;
            var date = new Date(time);
            if (tag === "gentime") {
                str = [ two(date.getFullYear()), two(date.getUTCMonth() + 1), two(date.getUTCDate()), two(date.getUTCHours()), two(date.getUTCMinutes()), two(date.getUTCSeconds()), "Z" ].join("");
            } else if (tag === "utctime") {
                str = [ two(date.getFullYear() % 100), two(date.getUTCMonth() + 1), two(date.getUTCDate()), two(date.getUTCHours()), two(date.getUTCMinutes()), two(date.getUTCSeconds()), "Z" ].join("");
            } else {
                this.reporter.error("Encoding " + tag + " time is not supported yet");
            }
            return this._encodeStr(str, "octstr");
        };
        DERNode.prototype._encodeNull = function encodeNull() {
            return this._createEncoderBuffer("");
        };
        DERNode.prototype._encodeInt = function encodeInt(num, values) {
            if (typeof num === "string") {
                if (!values) return this.reporter.error("String int or enum given, but no values map");
                if (!values.hasOwnProperty(num)) {
                    return this.reporter.error("Values map doesn't contain: " + JSON.stringify(num));
                }
                num = values[num];
            }
            if (typeof num !== "number" && !Buffer.isBuffer(num)) {
                var numArray = num.toArray();
                if (!num.sign && numArray[0] & 128) {
                    numArray.unshift(0);
                }
                num = new Buffer(numArray);
            }
            if (Buffer.isBuffer(num)) {
                var size = num.length;
                if (num.length === 0) size++;
                var out = new Buffer(size);
                num.copy(out);
                if (num.length === 0) out[0] = 0;
                return this._createEncoderBuffer(out);
            }
            if (num < 128) return this._createEncoderBuffer(num);
            if (num < 256) return this._createEncoderBuffer([ 0, num ]);
            var size = 1;
            for (var i = num; i >= 256; i >>= 8) size++;
            var out = new Array(size);
            for (var i = out.length - 1; i >= 0; i--) {
                out[i] = num & 255;
                num >>= 8;
            }
            if (out[0] & 128) {
                out.unshift(0);
            }
            return this._createEncoderBuffer(new Buffer(out));
        };
        DERNode.prototype._encodeBool = function encodeBool(value) {
            return this._createEncoderBuffer(value ? 255 : 0);
        };
        DERNode.prototype._use = function use(entity, obj) {
            if (typeof entity === "function") entity = entity(obj);
            return entity._getEncoder("der").tree;
        };
        DERNode.prototype._skipDefault = function skipDefault(dataBuffer, reporter, parent) {
            var state = this._baseState;
            var i;
            if (state["default"] === null) return false;
            var data = dataBuffer.join();
            if (state.defaultBuffer === undefined) state.defaultBuffer = this._encodeValue(state["default"], reporter, parent).join();
            if (data.length !== state.defaultBuffer.length) return false;
            for (i = 0; i < data.length; i++) if (data[i] !== state.defaultBuffer[i]) return false;
            return true;
        };
        function encodeTag(tag, primitive, cls, reporter) {
            var res;
            if (tag === "seqof") tag = "seq"; else if (tag === "setof") tag = "set";
            if (der.tagByName.hasOwnProperty(tag)) res = der.tagByName[tag]; else if (typeof tag === "number" && (tag | 0) === tag) res = tag; else return reporter.error("Unknown tag: " + tag);
            if (res >= 31) return reporter.error("Multi-octet tag encoding unsupported");
            if (!primitive) res |= 32;
            res |= der.tagClassByName[cls || "universal"] << 6;
            return res;
        }
    }, {
        "../../asn1": 2,
        buffer: 54,
        inherits: 122
    } ],
    14: [ function(require, module, exports) {
        var encoders = exports;
        encoders.der = require("./der");
        encoders.pem = require("./pem");
    }, {
        "./der": 13,
        "./pem": 15
    } ],
    15: [ function(require, module, exports) {
        var inherits = require("inherits");
        var DEREncoder = require("./der");
        function PEMEncoder(entity) {
            DEREncoder.call(this, entity);
            this.enc = "pem";
        }
        inherits(PEMEncoder, DEREncoder);
        module.exports = PEMEncoder;
        PEMEncoder.prototype.encode = function encode(data, options) {
            var buf = DEREncoder.prototype.encode.call(this, data);
            var p = buf.toString("base64");
            var out = [ "-----BEGIN " + options.label + "-----" ];
            for (var i = 0; i < p.length; i += 64) out.push(p.slice(i, i + 64));
            out.push("-----END " + options.label + "-----");
            return out.join("\n");
        };
    }, {
        "./der": 13,
        inherits: 122
    } ],
    16: [ function(require, module, exports) {
        (function(global) {
            "use strict";
            function compare(a, b) {
                if (a === b) {
                    return 0;
                }
                var x = a.length;
                var y = b.length;
                for (var i = 0, len = Math.min(x, y); i < len; ++i) {
                    if (a[i] !== b[i]) {
                        x = a[i];
                        y = b[i];
                        break;
                    }
                }
                if (x < y) {
                    return -1;
                }
                if (y < x) {
                    return 1;
                }
                return 0;
            }
            function isBuffer(b) {
                if (global.Buffer && typeof global.Buffer.isBuffer === "function") {
                    return global.Buffer.isBuffer(b);
                }
                return !!(b != null && b._isBuffer);
            }
            var util = require("util/");
            var hasOwn = Object.prototype.hasOwnProperty;
            var pSlice = Array.prototype.slice;
            var functionsHaveNames = function() {
                return function foo() {}.name === "foo";
            }();
            function pToString(obj) {
                return Object.prototype.toString.call(obj);
            }
            function isView(arrbuf) {
                if (isBuffer(arrbuf)) {
                    return false;
                }
                if (typeof global.ArrayBuffer !== "function") {
                    return false;
                }
                if (typeof ArrayBuffer.isView === "function") {
                    return ArrayBuffer.isView(arrbuf);
                }
                if (!arrbuf) {
                    return false;
                }
                if (arrbuf instanceof DataView) {
                    return true;
                }
                if (arrbuf.buffer && arrbuf.buffer instanceof ArrayBuffer) {
                    return true;
                }
                return false;
            }
            var assert = module.exports = ok;
            var regex = /\s*function\s+([^\(\s]*)\s*/;
            function getName(func) {
                if (!util.isFunction(func)) {
                    return;
                }
                if (functionsHaveNames) {
                    return func.name;
                }
                var str = func.toString();
                var match = str.match(regex);
                return match && match[1];
            }
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
                        var fn_name = getName(stackStartFunction);
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
            function truncate(s, n) {
                if (typeof s === "string") {
                    return s.length < n ? s : s.slice(0, n);
                } else {
                    return s;
                }
            }
            function inspect(something) {
                if (functionsHaveNames || !util.isFunction(something)) {
                    return util.inspect(something);
                }
                var rawname = getName(something);
                var name = rawname ? ": " + rawname : "";
                return "[Function" + name + "]";
            }
            function getMessage(self) {
                return truncate(inspect(self.actual), 128) + " " + self.operator + " " + truncate(inspect(self.expected), 128);
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
                if (!_deepEqual(actual, expected, false)) {
                    fail(actual, expected, message, "deepEqual", assert.deepEqual);
                }
            };
            assert.deepStrictEqual = function deepStrictEqual(actual, expected, message) {
                if (!_deepEqual(actual, expected, true)) {
                    fail(actual, expected, message, "deepStrictEqual", assert.deepStrictEqual);
                }
            };
            function _deepEqual(actual, expected, strict, memos) {
                if (actual === expected) {
                    return true;
                } else if (isBuffer(actual) && isBuffer(expected)) {
                    return compare(actual, expected) === 0;
                } else if (util.isDate(actual) && util.isDate(expected)) {
                    return actual.getTime() === expected.getTime();
                } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
                    return actual.source === expected.source && actual.global === expected.global && actual.multiline === expected.multiline && actual.lastIndex === expected.lastIndex && actual.ignoreCase === expected.ignoreCase;
                } else if ((actual === null || typeof actual !== "object") && (expected === null || typeof expected !== "object")) {
                    return strict ? actual === expected : actual == expected;
                } else if (isView(actual) && isView(expected) && pToString(actual) === pToString(expected) && !(actual instanceof Float32Array || actual instanceof Float64Array)) {
                    return compare(new Uint8Array(actual.buffer), new Uint8Array(expected.buffer)) === 0;
                } else if (isBuffer(actual) !== isBuffer(expected)) {
                    return false;
                } else {
                    memos = memos || {
                        actual: [],
                        expected: []
                    };
                    var actualIndex = memos.actual.indexOf(actual);
                    if (actualIndex !== -1) {
                        if (actualIndex === memos.expected.indexOf(expected)) {
                            return true;
                        }
                    }
                    memos.actual.push(actual);
                    memos.expected.push(expected);
                    return objEquiv(actual, expected, strict, memos);
                }
            }
            function isArguments(object) {
                return Object.prototype.toString.call(object) == "[object Arguments]";
            }
            function objEquiv(a, b, strict, actualVisitedObjects) {
                if (a === null || a === undefined || b === null || b === undefined) return false;
                if (util.isPrimitive(a) || util.isPrimitive(b)) return a === b;
                if (strict && Object.getPrototypeOf(a) !== Object.getPrototypeOf(b)) return false;
                var aIsArgs = isArguments(a);
                var bIsArgs = isArguments(b);
                if (aIsArgs && !bIsArgs || !aIsArgs && bIsArgs) return false;
                if (aIsArgs) {
                    a = pSlice.call(a);
                    b = pSlice.call(b);
                    return _deepEqual(a, b, strict);
                }
                var ka = objectKeys(a);
                var kb = objectKeys(b);
                var key, i;
                if (ka.length !== kb.length) return false;
                ka.sort();
                kb.sort();
                for (i = ka.length - 1; i >= 0; i--) {
                    if (ka[i] !== kb[i]) return false;
                }
                for (i = ka.length - 1; i >= 0; i--) {
                    key = ka[i];
                    if (!_deepEqual(a[key], b[key], strict, actualVisitedObjects)) return false;
                }
                return true;
            }
            assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
                if (_deepEqual(actual, expected, false)) {
                    fail(actual, expected, message, "notDeepEqual", assert.notDeepEqual);
                }
            };
            assert.notDeepStrictEqual = notDeepStrictEqual;
            function notDeepStrictEqual(actual, expected, message) {
                if (_deepEqual(actual, expected, true)) {
                    fail(actual, expected, message, "notDeepStrictEqual", notDeepStrictEqual);
                }
            }
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
                }
                try {
                    if (actual instanceof expected) {
                        return true;
                    }
                } catch (e) {}
                if (Error.isPrototypeOf(expected)) {
                    return false;
                }
                return expected.call({}, actual) === true;
            }
            function _tryBlock(block) {
                var error;
                try {
                    block();
                } catch (e) {
                    error = e;
                }
                return error;
            }
            function _throws(shouldThrow, block, expected, message) {
                var actual;
                if (typeof block !== "function") {
                    throw new TypeError('"block" argument must be a function');
                }
                if (typeof expected === "string") {
                    message = expected;
                    expected = null;
                }
                actual = _tryBlock(block);
                message = (expected && expected.name ? " (" + expected.name + ")." : ".") + (message ? " " + message : ".");
                if (shouldThrow && !actual) {
                    fail(actual, expected, "Missing expected exception" + message);
                }
                var userProvidedMessage = typeof message === "string";
                var isUnwantedException = !shouldThrow && util.isError(actual);
                var isUnexpectedException = !shouldThrow && actual && !expected;
                if (isUnwantedException && userProvidedMessage && expectedException(actual, expected) || isUnexpectedException) {
                    fail(actual, expected, "Got unwanted exception" + message);
                }
                if (shouldThrow && actual && expected && !expectedException(actual, expected) || !shouldThrow && actual) {
                    throw actual;
                }
            }
            assert.throws = function(block, error, message) {
                _throws(true, block, error, message);
            };
            assert.doesNotThrow = function(block, error, message) {
                _throws(false, block, error, message);
            };
            assert.ifError = function(err) {
                if (err) throw err;
            };
            var objectKeys = Object.keys || function(obj) {
                var keys = [];
                for (var key in obj) {
                    if (hasOwn.call(obj, key)) keys.push(key);
                }
                return keys;
            };
        }).call(this, typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {
        "util/": 187
    } ],
    17: [ function(require, module, exports) {
        "use strict";
        exports.byteLength = byteLength;
        exports.toByteArray = toByteArray;
        exports.fromByteArray = fromByteArray;
        var lookup = [];
        var revLookup = [];
        var Arr = typeof Uint8Array !== "undefined" ? Uint8Array : Array;
        var code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (var i = 0, len = code.length; i < len; ++i) {
            lookup[i] = code[i];
            revLookup[code.charCodeAt(i)] = i;
        }
        revLookup["-".charCodeAt(0)] = 62;
        revLookup["_".charCodeAt(0)] = 63;
        function placeHoldersCount(b64) {
            var len = b64.length;
            if (len % 4 > 0) {
                throw new Error("Invalid string. Length must be a multiple of 4");
            }
            return b64[len - 2] === "=" ? 2 : b64[len - 1] === "=" ? 1 : 0;
        }
        function byteLength(b64) {
            return b64.length * 3 / 4 - placeHoldersCount(b64);
        }
        function toByteArray(b64) {
            var i, l, tmp, placeHolders, arr;
            var len = b64.length;
            placeHolders = placeHoldersCount(b64);
            arr = new Arr(len * 3 / 4 - placeHolders);
            l = placeHolders > 0 ? len - 4 : len;
            var L = 0;
            for (i = 0; i < l; i += 4) {
                tmp = revLookup[b64.charCodeAt(i)] << 18 | revLookup[b64.charCodeAt(i + 1)] << 12 | revLookup[b64.charCodeAt(i + 2)] << 6 | revLookup[b64.charCodeAt(i + 3)];
                arr[L++] = tmp >> 16 & 255;
                arr[L++] = tmp >> 8 & 255;
                arr[L++] = tmp & 255;
            }
            if (placeHolders === 2) {
                tmp = revLookup[b64.charCodeAt(i)] << 2 | revLookup[b64.charCodeAt(i + 1)] >> 4;
                arr[L++] = tmp & 255;
            } else if (placeHolders === 1) {
                tmp = revLookup[b64.charCodeAt(i)] << 10 | revLookup[b64.charCodeAt(i + 1)] << 4 | revLookup[b64.charCodeAt(i + 2)] >> 2;
                arr[L++] = tmp >> 8 & 255;
                arr[L++] = tmp & 255;
            }
            return arr;
        }
        function tripletToBase64(num) {
            return lookup[num >> 18 & 63] + lookup[num >> 12 & 63] + lookup[num >> 6 & 63] + lookup[num & 63];
        }
        function encodeChunk(uint8, start, end) {
            var tmp;
            var output = [];
            for (var i = start; i < end; i += 3) {
                tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + uint8[i + 2];
                output.push(tripletToBase64(tmp));
            }
            return output.join("");
        }
        function fromByteArray(uint8) {
            var tmp;
            var len = uint8.length;
            var extraBytes = len % 3;
            var output = "";
            var parts = [];
            var maxChunkLength = 16383;
            for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
                parts.push(encodeChunk(uint8, i, i + maxChunkLength > len2 ? len2 : i + maxChunkLength));
            }
            if (extraBytes === 1) {
                tmp = uint8[len - 1];
                output += lookup[tmp >> 2];
                output += lookup[tmp << 4 & 63];
                output += "==";
            } else if (extraBytes === 2) {
                tmp = (uint8[len - 2] << 8) + uint8[len - 1];
                output += lookup[tmp >> 10];
                output += lookup[tmp >> 4 & 63];
                output += lookup[tmp << 2 & 63];
                output += "=";
            }
            parts.push(output);
            return parts.join("");
        }
    }, {} ],
    18: [ function(require, module, exports) {
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
            if (this.signum() === 0) throw new Error("division by zero");
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
            while (d.compareTo(m) >= 0) d.subTo(m, d);
            while (d.signum() < 0) d.addTo(m, d);
            return d;
        }
        var lowprimes = [ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997 ];
        var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];
        function bnIsProbablePrime(t) {
            var i, x = this.abs();
            if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
                for (i = 0; i < lowprimes.length; ++i) if (x[0] == lowprimes[i]) return true;
                return false;
            }
            if (x.isEven()) return false;
            i = 1;
            while (i < lowprimes.length) {
                var m = lowprimes[i], j = i + 1;
                while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
                m = x.modInt(m);
                while (i < j) if (m % lowprimes[i++] == 0) return false;
            }
            return x.millerRabin(t);
        }
        function bnpMillerRabin(t) {
            var n1 = this.subtract(BigInteger.ONE);
            var k = n1.getLowestSetBit();
            if (k <= 0) return false;
            var r = n1.shiftRight(k);
            t = t + 1 >> 1;
            if (t > lowprimes.length) t = lowprimes.length;
            var a = new BigInteger(null);
            var j, bases = [];
            for (var i = 0; i < t; ++i) {
                for (;;) {
                    j = lowprimes[Math.floor(Math.random() * lowprimes.length)];
                    if (bases.indexOf(j) == -1) break;
                }
                bases.push(j);
                a.fromInt(j);
                var y = a.modPow(r, this);
                if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
                    var j = 1;
                    while (j++ < k && y.compareTo(n1) != 0) {
                        y = y.modPowInt(2, this);
                        if (y.compareTo(BigInteger.ONE) == 0) return false;
                    }
                    if (y.compareTo(n1) != 0) return false;
                }
            }
            return true;
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
        proto.millerRabin = bnpMillerRabin;
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
        proto.isProbablePrime = bnIsProbablePrime;
        proto.square = bnSquare;
        BigInteger.ZERO = nbv(0);
        BigInteger.ONE = nbv(1);
        BigInteger.valueOf = nbv;
        module.exports = BigInteger;
    }, {
        "../package.json": 21
    } ],
    19: [ function(require, module, exports) {
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
        "./bigi": 18,
        assert: 16,
        buffer: 54
    } ],
    20: [ function(require, module, exports) {
        var BigInteger = require("./bigi");
        require("./convert");
        module.exports = BigInteger;
    }, {
        "./bigi": 18,
        "./convert": 19
    } ],
    21: [ function(require, module, exports) {
        module.exports = {
            _args: [ [ {
                raw: "bigi@^1.3.0",
                scope: null,
                escapedName: "bigi",
                name: "bigi",
                rawSpec: "^1.3.0",
                spec: ">=1.3.0 <2.0.0",
                type: "range"
            }, "/home/olitvin/share-home/htdocs/angular-ecdsa" ] ],
            _from: "bigi@>=1.3.0 <2.0.0",
            _id: "bigi@1.4.2",
            _inCache: true,
            _location: "/bigi",
            _nodeVersion: "6.1.0",
            _npmOperationalInternal: {
                host: "packages-12-west.internal.npmjs.com",
                tmp: "tmp/bigi-1.4.2.tgz_1469584192413_0.6801238611806184"
            },
            _npmUser: {
                name: "jprichardson",
                email: "jprichardson@gmail.com"
            },
            _npmVersion: "3.8.6",
            _phantomChildren: {},
            _requested: {
                raw: "bigi@^1.3.0",
                scope: null,
                escapedName: "bigi",
                name: "bigi",
                rawSpec: "^1.3.0",
                spec: ">=1.3.0 <2.0.0",
                type: "range"
            },
            _requiredBy: [ "/", "/ecdsa", "/ecurve" ],
            _resolved: "https://registry.npmjs.org/bigi/-/bigi-1.4.2.tgz",
            _shasum: "9c665a95f88b8b08fc05cfd731f561859d725825",
            _shrinkwrap: null,
            _spec: "bigi@^1.3.0",
            _where: "/home/olitvin/share-home/htdocs/angular-ecdsa",
            bugs: {
                url: "https://github.com/cryptocoinjs/bigi/issues"
            },
            dependencies: {},
            description: "Big integers.",
            devDependencies: {
                coveralls: "^2.11.2",
                istanbul: "^0.3.5",
                jshint: "^2.5.1",
                mocha: "^2.1.0",
                mochify: "^2.1.0"
            },
            directories: {},
            dist: {
                shasum: "9c665a95f88b8b08fc05cfd731f561859d725825",
                tarball: "https://registry.npmjs.org/bigi/-/bigi-1.4.2.tgz"
            },
            gitHead: "c25308081c896ff84702303722bf5ecd8b3f78e3",
            homepage: "https://github.com/cryptocoinjs/bigi#readme",
            keywords: [ "cryptography", "math", "bitcoin", "arbitrary", "precision", "arithmetic", "big", "integer", "int", "number", "biginteger", "bigint", "bignumber", "decimal", "float" ],
            main: "./lib/index.js",
            maintainers: [ {
                name: "midnightlightning",
                email: "boydb@midnightdesign.ws"
            }, {
                name: "sidazhang",
                email: "sidazhang89@gmail.com"
            }, {
                name: "nadav",
                email: "npm@shesek.info"
            }, {
                name: "jprichardson",
                email: "jprichardson@gmail.com"
            } ],
            name: "bigi",
            optionalDependencies: {},
            readme: "ERROR: No README data found!",
            repository: {
                url: "git+https://github.com/cryptocoinjs/bigi.git",
                type: "git"
            },
            scripts: {
                "browser-test": "mochify --wd -R spec",
                coverage: "istanbul cover ./node_modules/.bin/_mocha -- --reporter list test/*.js",
                coveralls: "npm run-script coverage && node ./node_modules/.bin/coveralls < coverage/lcov.info",
                jshint: "jshint --config jshint.json lib/*.js ; true",
                test: "_mocha -- test/*.js",
                unit: "mocha"
            },
            testling: {
                files: "test/*.js",
                harness: "mocha",
                browsers: [ "ie/9..latest", "firefox/latest", "chrome/latest", "safari/6.0..latest", "iphone/6.0..latest", "android-browser/4.2..latest" ]
            },
            version: "1.4.2"
        };
    }, {} ],
    22: [ function(require, module, exports) {
        var Buffer = require("safe-buffer").Buffer;
        function check(buffer) {
            if (buffer.length < 8) return false;
            if (buffer.length > 72) return false;
            if (buffer[0] !== 48) return false;
            if (buffer[1] !== buffer.length - 2) return false;
            if (buffer[2] !== 2) return false;
            var lenR = buffer[3];
            if (lenR === 0) return false;
            if (5 + lenR >= buffer.length) return false;
            if (buffer[4 + lenR] !== 2) return false;
            var lenS = buffer[5 + lenR];
            if (lenS === 0) return false;
            if (6 + lenR + lenS !== buffer.length) return false;
            if (buffer[4] & 128) return false;
            if (lenR > 1 && buffer[4] === 0 && !(buffer[5] & 128)) return false;
            if (buffer[lenR + 6] & 128) return false;
            if (lenS > 1 && buffer[lenR + 6] === 0 && !(buffer[lenR + 7] & 128)) return false;
            return true;
        }
        function decode(buffer) {
            if (buffer.length < 8) throw new Error("DER sequence length is too short");
            if (buffer.length > 72) throw new Error("DER sequence length is too long");
            if (buffer[0] !== 48) throw new Error("Expected DER sequence");
            if (buffer[1] !== buffer.length - 2) throw new Error("DER sequence length is invalid");
            if (buffer[2] !== 2) throw new Error("Expected DER integer");
            var lenR = buffer[3];
            if (lenR === 0) throw new Error("R length is zero");
            if (5 + lenR >= buffer.length) throw new Error("R length is too long");
            if (buffer[4 + lenR] !== 2) throw new Error("Expected DER integer (2)");
            var lenS = buffer[5 + lenR];
            if (lenS === 0) throw new Error("S length is zero");
            if (6 + lenR + lenS !== buffer.length) throw new Error("S length is invalid");
            if (buffer[4] & 128) throw new Error("R value is negative");
            if (lenR > 1 && buffer[4] === 0 && !(buffer[5] & 128)) throw new Error("R value excessively padded");
            if (buffer[lenR + 6] & 128) throw new Error("S value is negative");
            if (lenS > 1 && buffer[lenR + 6] === 0 && !(buffer[lenR + 7] & 128)) throw new Error("S value excessively padded");
            return {
                r: buffer.slice(4, 4 + lenR),
                s: buffer.slice(6 + lenR)
            };
        }
        function encode(r, s) {
            var lenR = r.length;
            var lenS = s.length;
            if (lenR === 0) throw new Error("R length is zero");
            if (lenS === 0) throw new Error("S length is zero");
            if (lenR > 33) throw new Error("R length is too long");
            if (lenS > 33) throw new Error("S length is too long");
            if (r[0] & 128) throw new Error("R value is negative");
            if (s[0] & 128) throw new Error("S value is negative");
            if (lenR > 1 && r[0] === 0 && !(r[1] & 128)) throw new Error("R value excessively padded");
            if (lenS > 1 && s[0] === 0 && !(s[1] & 128)) throw new Error("S value excessively padded");
            var signature = Buffer.allocUnsafe(6 + lenR + lenS);
            signature[0] = 48;
            signature[1] = signature.length - 2;
            signature[2] = 2;
            signature[3] = r.length;
            r.copy(signature, 4);
            signature[4 + lenR] = 2;
            signature[5 + lenR] = s.length;
            s.copy(signature, 6 + lenR);
            return signature;
        }
        module.exports = {
            check: check,
            decode: decode,
            encode: encode
        };
    }, {
        "safe-buffer": 163
    } ],
    23: [ function(require, module, exports) {
        (function(module, exports) {
            "use strict";
            function assert(val, msg) {
                if (!val) throw new Error(msg || "Assertion failed");
            }
            function inherits(ctor, superCtor) {
                ctor.super_ = superCtor;
                var TempCtor = function() {};
                TempCtor.prototype = superCtor.prototype;
                ctor.prototype = new TempCtor();
                ctor.prototype.constructor = ctor;
            }
            function BN(number, base, endian) {
                if (BN.isBN(number)) {
                    return number;
                }
                this.negative = 0;
                this.words = null;
                this.length = 0;
                this.red = null;
                if (number !== null) {
                    if (base === "le" || base === "be") {
                        endian = base;
                        base = 10;
                    }
                    this._init(number || 0, base || 10, endian || "be");
                }
            }
            if (typeof module === "object") {
                module.exports = BN;
            } else {
                exports.BN = BN;
            }
            BN.BN = BN;
            BN.wordSize = 26;
            var Buffer;
            try {
                Buffer = require("buffer").Buffer;
            } catch (e) {}
            BN.isBN = function isBN(num) {
                if (num instanceof BN) {
                    return true;
                }
                return num !== null && typeof num === "object" && num.constructor.wordSize === BN.wordSize && Array.isArray(num.words);
            };
            BN.max = function max(left, right) {
                if (left.cmp(right) > 0) return left;
                return right;
            };
            BN.min = function min(left, right) {
                if (left.cmp(right) < 0) return left;
                return right;
            };
            BN.prototype._init = function init(number, base, endian) {
                if (typeof number === "number") {
                    return this._initNumber(number, base, endian);
                }
                if (typeof number === "object") {
                    return this._initArray(number, base, endian);
                }
                if (base === "hex") {
                    base = 16;
                }
                assert(base === (base | 0) && base >= 2 && base <= 36);
                number = number.toString().replace(/\s+/g, "");
                var start = 0;
                if (number[0] === "-") {
                    start++;
                }
                if (base === 16) {
                    this._parseHex(number, start);
                } else {
                    this._parseBase(number, base, start);
                }
                if (number[0] === "-") {
                    this.negative = 1;
                }
                this.strip();
                if (endian !== "le") return;
                this._initArray(this.toArray(), base, endian);
            };
            BN.prototype._initNumber = function _initNumber(number, base, endian) {
                if (number < 0) {
                    this.negative = 1;
                    number = -number;
                }
                if (number < 67108864) {
                    this.words = [ number & 67108863 ];
                    this.length = 1;
                } else if (number < 4503599627370496) {
                    this.words = [ number & 67108863, number / 67108864 & 67108863 ];
                    this.length = 2;
                } else {
                    assert(number < 9007199254740992);
                    this.words = [ number & 67108863, number / 67108864 & 67108863, 1 ];
                    this.length = 3;
                }
                if (endian !== "le") return;
                this._initArray(this.toArray(), base, endian);
            };
            BN.prototype._initArray = function _initArray(number, base, endian) {
                assert(typeof number.length === "number");
                if (number.length <= 0) {
                    this.words = [ 0 ];
                    this.length = 1;
                    return this;
                }
                this.length = Math.ceil(number.length / 3);
                this.words = new Array(this.length);
                for (var i = 0; i < this.length; i++) {
                    this.words[i] = 0;
                }
                var j, w;
                var off = 0;
                if (endian === "be") {
                    for (i = number.length - 1, j = 0; i >= 0; i -= 3) {
                        w = number[i] | number[i - 1] << 8 | number[i - 2] << 16;
                        this.words[j] |= w << off & 67108863;
                        this.words[j + 1] = w >>> 26 - off & 67108863;
                        off += 24;
                        if (off >= 26) {
                            off -= 26;
                            j++;
                        }
                    }
                } else if (endian === "le") {
                    for (i = 0, j = 0; i < number.length; i += 3) {
                        w = number[i] | number[i + 1] << 8 | number[i + 2] << 16;
                        this.words[j] |= w << off & 67108863;
                        this.words[j + 1] = w >>> 26 - off & 67108863;
                        off += 24;
                        if (off >= 26) {
                            off -= 26;
                            j++;
                        }
                    }
                }
                return this.strip();
            };
            function parseHex(str, start, end) {
                var r = 0;
                var len = Math.min(str.length, end);
                for (var i = start; i < len; i++) {
                    var c = str.charCodeAt(i) - 48;
                    r <<= 4;
                    if (c >= 49 && c <= 54) {
                        r |= c - 49 + 10;
                    } else if (c >= 17 && c <= 22) {
                        r |= c - 17 + 10;
                    } else {
                        r |= c & 15;
                    }
                }
                return r;
            }
            BN.prototype._parseHex = function _parseHex(number, start) {
                this.length = Math.ceil((number.length - start) / 6);
                this.words = new Array(this.length);
                for (var i = 0; i < this.length; i++) {
                    this.words[i] = 0;
                }
                var j, w;
                var off = 0;
                for (i = number.length - 6, j = 0; i >= start; i -= 6) {
                    w = parseHex(number, i, i + 6);
                    this.words[j] |= w << off & 67108863;
                    this.words[j + 1] |= w >>> 26 - off & 4194303;
                    off += 24;
                    if (off >= 26) {
                        off -= 26;
                        j++;
                    }
                }
                if (i + 6 !== start) {
                    w = parseHex(number, start, i + 6);
                    this.words[j] |= w << off & 67108863;
                    this.words[j + 1] |= w >>> 26 - off & 4194303;
                }
                this.strip();
            };
            function parseBase(str, start, end, mul) {
                var r = 0;
                var len = Math.min(str.length, end);
                for (var i = start; i < len; i++) {
                    var c = str.charCodeAt(i) - 48;
                    r *= mul;
                    if (c >= 49) {
                        r += c - 49 + 10;
                    } else if (c >= 17) {
                        r += c - 17 + 10;
                    } else {
                        r += c;
                    }
                }
                return r;
            }
            BN.prototype._parseBase = function _parseBase(number, base, start) {
                this.words = [ 0 ];
                this.length = 1;
                for (var limbLen = 0, limbPow = 1; limbPow <= 67108863; limbPow *= base) {
                    limbLen++;
                }
                limbLen--;
                limbPow = limbPow / base | 0;
                var total = number.length - start;
                var mod = total % limbLen;
                var end = Math.min(total, total - mod) + start;
                var word = 0;
                for (var i = start; i < end; i += limbLen) {
                    word = parseBase(number, i, i + limbLen, base);
                    this.imuln(limbPow);
                    if (this.words[0] + word < 67108864) {
                        this.words[0] += word;
                    } else {
                        this._iaddn(word);
                    }
                }
                if (mod !== 0) {
                    var pow = 1;
                    word = parseBase(number, i, number.length, base);
                    for (i = 0; i < mod; i++) {
                        pow *= base;
                    }
                    this.imuln(pow);
                    if (this.words[0] + word < 67108864) {
                        this.words[0] += word;
                    } else {
                        this._iaddn(word);
                    }
                }
            };
            BN.prototype.copy = function copy(dest) {
                dest.words = new Array(this.length);
                for (var i = 0; i < this.length; i++) {
                    dest.words[i] = this.words[i];
                }
                dest.length = this.length;
                dest.negative = this.negative;
                dest.red = this.red;
            };
            BN.prototype.clone = function clone() {
                var r = new BN(null);
                this.copy(r);
                return r;
            };
            BN.prototype._expand = function _expand(size) {
                while (this.length < size) {
                    this.words[this.length++] = 0;
                }
                return this;
            };
            BN.prototype.strip = function strip() {
                while (this.length > 1 && this.words[this.length - 1] === 0) {
                    this.length--;
                }
                return this._normSign();
            };
            BN.prototype._normSign = function _normSign() {
                if (this.length === 1 && this.words[0] === 0) {
                    this.negative = 0;
                }
                return this;
            };
            BN.prototype.inspect = function inspect() {
                return (this.red ? "<BN-R: " : "<BN: ") + this.toString(16) + ">";
            };
            var zeros = [ "", "0", "00", "000", "0000", "00000", "000000", "0000000", "00000000", "000000000", "0000000000", "00000000000", "000000000000", "0000000000000", "00000000000000", "000000000000000", "0000000000000000", "00000000000000000", "000000000000000000", "0000000000000000000", "00000000000000000000", "000000000000000000000", "0000000000000000000000", "00000000000000000000000", "000000000000000000000000", "0000000000000000000000000" ];
            var groupSizes = [ 0, 0, 25, 16, 12, 11, 10, 9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 ];
            var groupBases = [ 0, 0, 33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216, 43046721, 1e7, 19487171, 35831808, 62748517, 7529536, 11390625, 16777216, 24137569, 34012224, 47045881, 64e6, 4084101, 5153632, 6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149, 243e5, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176 ];
            BN.prototype.toString = function toString(base, padding) {
                base = base || 10;
                padding = padding | 0 || 1;
                var out;
                if (base === 16 || base === "hex") {
                    out = "";
                    var off = 0;
                    var carry = 0;
                    for (var i = 0; i < this.length; i++) {
                        var w = this.words[i];
                        var word = ((w << off | carry) & 16777215).toString(16);
                        carry = w >>> 24 - off & 16777215;
                        if (carry !== 0 || i !== this.length - 1) {
                            out = zeros[6 - word.length] + word + out;
                        } else {
                            out = word + out;
                        }
                        off += 2;
                        if (off >= 26) {
                            off -= 26;
                            i--;
                        }
                    }
                    if (carry !== 0) {
                        out = carry.toString(16) + out;
                    }
                    while (out.length % padding !== 0) {
                        out = "0" + out;
                    }
                    if (this.negative !== 0) {
                        out = "-" + out;
                    }
                    return out;
                }
                if (base === (base | 0) && base >= 2 && base <= 36) {
                    var groupSize = groupSizes[base];
                    var groupBase = groupBases[base];
                    out = "";
                    var c = this.clone();
                    c.negative = 0;
                    while (!c.isZero()) {
                        var r = c.modn(groupBase).toString(base);
                        c = c.idivn(groupBase);
                        if (!c.isZero()) {
                            out = zeros[groupSize - r.length] + r + out;
                        } else {
                            out = r + out;
                        }
                    }
                    if (this.isZero()) {
                        out = "0" + out;
                    }
                    while (out.length % padding !== 0) {
                        out = "0" + out;
                    }
                    if (this.negative !== 0) {
                        out = "-" + out;
                    }
                    return out;
                }
                assert(false, "Base should be between 2 and 36");
            };
            BN.prototype.toNumber = function toNumber() {
                var ret = this.words[0];
                if (this.length === 2) {
                    ret += this.words[1] * 67108864;
                } else if (this.length === 3 && this.words[2] === 1) {
                    ret += 4503599627370496 + this.words[1] * 67108864;
                } else if (this.length > 2) {
                    assert(false, "Number can only safely store up to 53 bits");
                }
                return this.negative !== 0 ? -ret : ret;
            };
            BN.prototype.toJSON = function toJSON() {
                return this.toString(16);
            };
            BN.prototype.toBuffer = function toBuffer(endian, length) {
                assert(typeof Buffer !== "undefined");
                return this.toArrayLike(Buffer, endian, length);
            };
            BN.prototype.toArray = function toArray(endian, length) {
                return this.toArrayLike(Array, endian, length);
            };
            BN.prototype.toArrayLike = function toArrayLike(ArrayType, endian, length) {
                var byteLength = this.byteLength();
                var reqLength = length || Math.max(1, byteLength);
                assert(byteLength <= reqLength, "byte array longer than desired length");
                assert(reqLength > 0, "Requested array length <= 0");
                this.strip();
                var littleEndian = endian === "le";
                var res = new ArrayType(reqLength);
                var b, i;
                var q = this.clone();
                if (!littleEndian) {
                    for (i = 0; i < reqLength - byteLength; i++) {
                        res[i] = 0;
                    }
                    for (i = 0; !q.isZero(); i++) {
                        b = q.andln(255);
                        q.iushrn(8);
                        res[reqLength - i - 1] = b;
                    }
                } else {
                    for (i = 0; !q.isZero(); i++) {
                        b = q.andln(255);
                        q.iushrn(8);
                        res[i] = b;
                    }
                    for (;i < reqLength; i++) {
                        res[i] = 0;
                    }
                }
                return res;
            };
            if (Math.clz32) {
                BN.prototype._countBits = function _countBits(w) {
                    return 32 - Math.clz32(w);
                };
            } else {
                BN.prototype._countBits = function _countBits(w) {
                    var t = w;
                    var r = 0;
                    if (t >= 4096) {
                        r += 13;
                        t >>>= 13;
                    }
                    if (t >= 64) {
                        r += 7;
                        t >>>= 7;
                    }
                    if (t >= 8) {
                        r += 4;
                        t >>>= 4;
                    }
                    if (t >= 2) {
                        r += 2;
                        t >>>= 2;
                    }
                    return r + t;
                };
            }
            BN.prototype._zeroBits = function _zeroBits(w) {
                if (w === 0) return 26;
                var t = w;
                var r = 0;
                if ((t & 8191) === 0) {
                    r += 13;
                    t >>>= 13;
                }
                if ((t & 127) === 0) {
                    r += 7;
                    t >>>= 7;
                }
                if ((t & 15) === 0) {
                    r += 4;
                    t >>>= 4;
                }
                if ((t & 3) === 0) {
                    r += 2;
                    t >>>= 2;
                }
                if ((t & 1) === 0) {
                    r++;
                }
                return r;
            };
            BN.prototype.bitLength = function bitLength() {
                var w = this.words[this.length - 1];
                var hi = this._countBits(w);
                return (this.length - 1) * 26 + hi;
            };
            function toBitArray(num) {
                var w = new Array(num.bitLength());
                for (var bit = 0; bit < w.length; bit++) {
                    var off = bit / 26 | 0;
                    var wbit = bit % 26;
                    w[bit] = (num.words[off] & 1 << wbit) >>> wbit;
                }
                return w;
            }
            BN.prototype.zeroBits = function zeroBits() {
                if (this.isZero()) return 0;
                var r = 0;
                for (var i = 0; i < this.length; i++) {
                    var b = this._zeroBits(this.words[i]);
                    r += b;
                    if (b !== 26) break;
                }
                return r;
            };
            BN.prototype.byteLength = function byteLength() {
                return Math.ceil(this.bitLength() / 8);
            };
            BN.prototype.toTwos = function toTwos(width) {
                if (this.negative !== 0) {
                    return this.abs().inotn(width).iaddn(1);
                }
                return this.clone();
            };
            BN.prototype.fromTwos = function fromTwos(width) {
                if (this.testn(width - 1)) {
                    return this.notn(width).iaddn(1).ineg();
                }
                return this.clone();
            };
            BN.prototype.isNeg = function isNeg() {
                return this.negative !== 0;
            };
            BN.prototype.neg = function neg() {
                return this.clone().ineg();
            };
            BN.prototype.ineg = function ineg() {
                if (!this.isZero()) {
                    this.negative ^= 1;
                }
                return this;
            };
            BN.prototype.iuor = function iuor(num) {
                while (this.length < num.length) {
                    this.words[this.length++] = 0;
                }
                for (var i = 0; i < num.length; i++) {
                    this.words[i] = this.words[i] | num.words[i];
                }
                return this.strip();
            };
            BN.prototype.ior = function ior(num) {
                assert((this.negative | num.negative) === 0);
                return this.iuor(num);
            };
            BN.prototype.or = function or(num) {
                if (this.length > num.length) return this.clone().ior(num);
                return num.clone().ior(this);
            };
            BN.prototype.uor = function uor(num) {
                if (this.length > num.length) return this.clone().iuor(num);
                return num.clone().iuor(this);
            };
            BN.prototype.iuand = function iuand(num) {
                var b;
                if (this.length > num.length) {
                    b = num;
                } else {
                    b = this;
                }
                for (var i = 0; i < b.length; i++) {
                    this.words[i] = this.words[i] & num.words[i];
                }
                this.length = b.length;
                return this.strip();
            };
            BN.prototype.iand = function iand(num) {
                assert((this.negative | num.negative) === 0);
                return this.iuand(num);
            };
            BN.prototype.and = function and(num) {
                if (this.length > num.length) return this.clone().iand(num);
                return num.clone().iand(this);
            };
            BN.prototype.uand = function uand(num) {
                if (this.length > num.length) return this.clone().iuand(num);
                return num.clone().iuand(this);
            };
            BN.prototype.iuxor = function iuxor(num) {
                var a;
                var b;
                if (this.length > num.length) {
                    a = this;
                    b = num;
                } else {
                    a = num;
                    b = this;
                }
                for (var i = 0; i < b.length; i++) {
                    this.words[i] = a.words[i] ^ b.words[i];
                }
                if (this !== a) {
                    for (;i < a.length; i++) {
                        this.words[i] = a.words[i];
                    }
                }
                this.length = a.length;
                return this.strip();
            };
            BN.prototype.ixor = function ixor(num) {
                assert((this.negative | num.negative) === 0);
                return this.iuxor(num);
            };
            BN.prototype.xor = function xor(num) {
                if (this.length > num.length) return this.clone().ixor(num);
                return num.clone().ixor(this);
            };
            BN.prototype.uxor = function uxor(num) {
                if (this.length > num.length) return this.clone().iuxor(num);
                return num.clone().iuxor(this);
            };
            BN.prototype.inotn = function inotn(width) {
                assert(typeof width === "number" && width >= 0);
                var bytesNeeded = Math.ceil(width / 26) | 0;
                var bitsLeft = width % 26;
                this._expand(bytesNeeded);
                if (bitsLeft > 0) {
                    bytesNeeded--;
                }
                for (var i = 0; i < bytesNeeded; i++) {
                    this.words[i] = ~this.words[i] & 67108863;
                }
                if (bitsLeft > 0) {
                    this.words[i] = ~this.words[i] & 67108863 >> 26 - bitsLeft;
                }
                return this.strip();
            };
            BN.prototype.notn = function notn(width) {
                return this.clone().inotn(width);
            };
            BN.prototype.setn = function setn(bit, val) {
                assert(typeof bit === "number" && bit >= 0);
                var off = bit / 26 | 0;
                var wbit = bit % 26;
                this._expand(off + 1);
                if (val) {
                    this.words[off] = this.words[off] | 1 << wbit;
                } else {
                    this.words[off] = this.words[off] & ~(1 << wbit);
                }
                return this.strip();
            };
            BN.prototype.iadd = function iadd(num) {
                var r;
                if (this.negative !== 0 && num.negative === 0) {
                    this.negative = 0;
                    r = this.isub(num);
                    this.negative ^= 1;
                    return this._normSign();
                } else if (this.negative === 0 && num.negative !== 0) {
                    num.negative = 0;
                    r = this.isub(num);
                    num.negative = 1;
                    return r._normSign();
                }
                var a, b;
                if (this.length > num.length) {
                    a = this;
                    b = num;
                } else {
                    a = num;
                    b = this;
                }
                var carry = 0;
                for (var i = 0; i < b.length; i++) {
                    r = (a.words[i] | 0) + (b.words[i] | 0) + carry;
                    this.words[i] = r & 67108863;
                    carry = r >>> 26;
                }
                for (;carry !== 0 && i < a.length; i++) {
                    r = (a.words[i] | 0) + carry;
                    this.words[i] = r & 67108863;
                    carry = r >>> 26;
                }
                this.length = a.length;
                if (carry !== 0) {
                    this.words[this.length] = carry;
                    this.length++;
                } else if (a !== this) {
                    for (;i < a.length; i++) {
                        this.words[i] = a.words[i];
                    }
                }
                return this;
            };
            BN.prototype.add = function add(num) {
                var res;
                if (num.negative !== 0 && this.negative === 0) {
                    num.negative = 0;
                    res = this.sub(num);
                    num.negative ^= 1;
                    return res;
                } else if (num.negative === 0 && this.negative !== 0) {
                    this.negative = 0;
                    res = num.sub(this);
                    this.negative = 1;
                    return res;
                }
                if (this.length > num.length) return this.clone().iadd(num);
                return num.clone().iadd(this);
            };
            BN.prototype.isub = function isub(num) {
                if (num.negative !== 0) {
                    num.negative = 0;
                    var r = this.iadd(num);
                    num.negative = 1;
                    return r._normSign();
                } else if (this.negative !== 0) {
                    this.negative = 0;
                    this.iadd(num);
                    this.negative = 1;
                    return this._normSign();
                }
                var cmp = this.cmp(num);
                if (cmp === 0) {
                    this.negative = 0;
                    this.length = 1;
                    this.words[0] = 0;
                    return this;
                }
                var a, b;
                if (cmp > 0) {
                    a = this;
                    b = num;
                } else {
                    a = num;
                    b = this;
                }
                var carry = 0;
                for (var i = 0; i < b.length; i++) {
                    r = (a.words[i] | 0) - (b.words[i] | 0) + carry;
                    carry = r >> 26;
                    this.words[i] = r & 67108863;
                }
                for (;carry !== 0 && i < a.length; i++) {
                    r = (a.words[i] | 0) + carry;
                    carry = r >> 26;
                    this.words[i] = r & 67108863;
                }
                if (carry === 0 && i < a.length && a !== this) {
                    for (;i < a.length; i++) {
                        this.words[i] = a.words[i];
                    }
                }
                this.length = Math.max(this.length, i);
                if (a !== this) {
                    this.negative = 1;
                }
                return this.strip();
            };
            BN.prototype.sub = function sub(num) {
                return this.clone().isub(num);
            };
            function smallMulTo(self, num, out) {
                out.negative = num.negative ^ self.negative;
                var len = self.length + num.length | 0;
                out.length = len;
                len = len - 1 | 0;
                var a = self.words[0] | 0;
                var b = num.words[0] | 0;
                var r = a * b;
                var lo = r & 67108863;
                var carry = r / 67108864 | 0;
                out.words[0] = lo;
                for (var k = 1; k < len; k++) {
                    var ncarry = carry >>> 26;
                    var rword = carry & 67108863;
                    var maxJ = Math.min(k, num.length - 1);
                    for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
                        var i = k - j | 0;
                        a = self.words[i] | 0;
                        b = num.words[j] | 0;
                        r = a * b + rword;
                        ncarry += r / 67108864 | 0;
                        rword = r & 67108863;
                    }
                    out.words[k] = rword | 0;
                    carry = ncarry | 0;
                }
                if (carry !== 0) {
                    out.words[k] = carry | 0;
                } else {
                    out.length--;
                }
                return out.strip();
            }
            var comb10MulTo = function comb10MulTo(self, num, out) {
                var a = self.words;
                var b = num.words;
                var o = out.words;
                var c = 0;
                var lo;
                var mid;
                var hi;
                var a0 = a[0] | 0;
                var al0 = a0 & 8191;
                var ah0 = a0 >>> 13;
                var a1 = a[1] | 0;
                var al1 = a1 & 8191;
                var ah1 = a1 >>> 13;
                var a2 = a[2] | 0;
                var al2 = a2 & 8191;
                var ah2 = a2 >>> 13;
                var a3 = a[3] | 0;
                var al3 = a3 & 8191;
                var ah3 = a3 >>> 13;
                var a4 = a[4] | 0;
                var al4 = a4 & 8191;
                var ah4 = a4 >>> 13;
                var a5 = a[5] | 0;
                var al5 = a5 & 8191;
                var ah5 = a5 >>> 13;
                var a6 = a[6] | 0;
                var al6 = a6 & 8191;
                var ah6 = a6 >>> 13;
                var a7 = a[7] | 0;
                var al7 = a7 & 8191;
                var ah7 = a7 >>> 13;
                var a8 = a[8] | 0;
                var al8 = a8 & 8191;
                var ah8 = a8 >>> 13;
                var a9 = a[9] | 0;
                var al9 = a9 & 8191;
                var ah9 = a9 >>> 13;
                var b0 = b[0] | 0;
                var bl0 = b0 & 8191;
                var bh0 = b0 >>> 13;
                var b1 = b[1] | 0;
                var bl1 = b1 & 8191;
                var bh1 = b1 >>> 13;
                var b2 = b[2] | 0;
                var bl2 = b2 & 8191;
                var bh2 = b2 >>> 13;
                var b3 = b[3] | 0;
                var bl3 = b3 & 8191;
                var bh3 = b3 >>> 13;
                var b4 = b[4] | 0;
                var bl4 = b4 & 8191;
                var bh4 = b4 >>> 13;
                var b5 = b[5] | 0;
                var bl5 = b5 & 8191;
                var bh5 = b5 >>> 13;
                var b6 = b[6] | 0;
                var bl6 = b6 & 8191;
                var bh6 = b6 >>> 13;
                var b7 = b[7] | 0;
                var bl7 = b7 & 8191;
                var bh7 = b7 >>> 13;
                var b8 = b[8] | 0;
                var bl8 = b8 & 8191;
                var bh8 = b8 >>> 13;
                var b9 = b[9] | 0;
                var bl9 = b9 & 8191;
                var bh9 = b9 >>> 13;
                out.negative = self.negative ^ num.negative;
                out.length = 19;
                lo = Math.imul(al0, bl0);
                mid = Math.imul(al0, bh0);
                mid = mid + Math.imul(ah0, bl0) | 0;
                hi = Math.imul(ah0, bh0);
                var w0 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w0 >>> 26) | 0;
                w0 &= 67108863;
                lo = Math.imul(al1, bl0);
                mid = Math.imul(al1, bh0);
                mid = mid + Math.imul(ah1, bl0) | 0;
                hi = Math.imul(ah1, bh0);
                lo = lo + Math.imul(al0, bl1) | 0;
                mid = mid + Math.imul(al0, bh1) | 0;
                mid = mid + Math.imul(ah0, bl1) | 0;
                hi = hi + Math.imul(ah0, bh1) | 0;
                var w1 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w1 >>> 26) | 0;
                w1 &= 67108863;
                lo = Math.imul(al2, bl0);
                mid = Math.imul(al2, bh0);
                mid = mid + Math.imul(ah2, bl0) | 0;
                hi = Math.imul(ah2, bh0);
                lo = lo + Math.imul(al1, bl1) | 0;
                mid = mid + Math.imul(al1, bh1) | 0;
                mid = mid + Math.imul(ah1, bl1) | 0;
                hi = hi + Math.imul(ah1, bh1) | 0;
                lo = lo + Math.imul(al0, bl2) | 0;
                mid = mid + Math.imul(al0, bh2) | 0;
                mid = mid + Math.imul(ah0, bl2) | 0;
                hi = hi + Math.imul(ah0, bh2) | 0;
                var w2 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w2 >>> 26) | 0;
                w2 &= 67108863;
                lo = Math.imul(al3, bl0);
                mid = Math.imul(al3, bh0);
                mid = mid + Math.imul(ah3, bl0) | 0;
                hi = Math.imul(ah3, bh0);
                lo = lo + Math.imul(al2, bl1) | 0;
                mid = mid + Math.imul(al2, bh1) | 0;
                mid = mid + Math.imul(ah2, bl1) | 0;
                hi = hi + Math.imul(ah2, bh1) | 0;
                lo = lo + Math.imul(al1, bl2) | 0;
                mid = mid + Math.imul(al1, bh2) | 0;
                mid = mid + Math.imul(ah1, bl2) | 0;
                hi = hi + Math.imul(ah1, bh2) | 0;
                lo = lo + Math.imul(al0, bl3) | 0;
                mid = mid + Math.imul(al0, bh3) | 0;
                mid = mid + Math.imul(ah0, bl3) | 0;
                hi = hi + Math.imul(ah0, bh3) | 0;
                var w3 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w3 >>> 26) | 0;
                w3 &= 67108863;
                lo = Math.imul(al4, bl0);
                mid = Math.imul(al4, bh0);
                mid = mid + Math.imul(ah4, bl0) | 0;
                hi = Math.imul(ah4, bh0);
                lo = lo + Math.imul(al3, bl1) | 0;
                mid = mid + Math.imul(al3, bh1) | 0;
                mid = mid + Math.imul(ah3, bl1) | 0;
                hi = hi + Math.imul(ah3, bh1) | 0;
                lo = lo + Math.imul(al2, bl2) | 0;
                mid = mid + Math.imul(al2, bh2) | 0;
                mid = mid + Math.imul(ah2, bl2) | 0;
                hi = hi + Math.imul(ah2, bh2) | 0;
                lo = lo + Math.imul(al1, bl3) | 0;
                mid = mid + Math.imul(al1, bh3) | 0;
                mid = mid + Math.imul(ah1, bl3) | 0;
                hi = hi + Math.imul(ah1, bh3) | 0;
                lo = lo + Math.imul(al0, bl4) | 0;
                mid = mid + Math.imul(al0, bh4) | 0;
                mid = mid + Math.imul(ah0, bl4) | 0;
                hi = hi + Math.imul(ah0, bh4) | 0;
                var w4 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w4 >>> 26) | 0;
                w4 &= 67108863;
                lo = Math.imul(al5, bl0);
                mid = Math.imul(al5, bh0);
                mid = mid + Math.imul(ah5, bl0) | 0;
                hi = Math.imul(ah5, bh0);
                lo = lo + Math.imul(al4, bl1) | 0;
                mid = mid + Math.imul(al4, bh1) | 0;
                mid = mid + Math.imul(ah4, bl1) | 0;
                hi = hi + Math.imul(ah4, bh1) | 0;
                lo = lo + Math.imul(al3, bl2) | 0;
                mid = mid + Math.imul(al3, bh2) | 0;
                mid = mid + Math.imul(ah3, bl2) | 0;
                hi = hi + Math.imul(ah3, bh2) | 0;
                lo = lo + Math.imul(al2, bl3) | 0;
                mid = mid + Math.imul(al2, bh3) | 0;
                mid = mid + Math.imul(ah2, bl3) | 0;
                hi = hi + Math.imul(ah2, bh3) | 0;
                lo = lo + Math.imul(al1, bl4) | 0;
                mid = mid + Math.imul(al1, bh4) | 0;
                mid = mid + Math.imul(ah1, bl4) | 0;
                hi = hi + Math.imul(ah1, bh4) | 0;
                lo = lo + Math.imul(al0, bl5) | 0;
                mid = mid + Math.imul(al0, bh5) | 0;
                mid = mid + Math.imul(ah0, bl5) | 0;
                hi = hi + Math.imul(ah0, bh5) | 0;
                var w5 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w5 >>> 26) | 0;
                w5 &= 67108863;
                lo = Math.imul(al6, bl0);
                mid = Math.imul(al6, bh0);
                mid = mid + Math.imul(ah6, bl0) | 0;
                hi = Math.imul(ah6, bh0);
                lo = lo + Math.imul(al5, bl1) | 0;
                mid = mid + Math.imul(al5, bh1) | 0;
                mid = mid + Math.imul(ah5, bl1) | 0;
                hi = hi + Math.imul(ah5, bh1) | 0;
                lo = lo + Math.imul(al4, bl2) | 0;
                mid = mid + Math.imul(al4, bh2) | 0;
                mid = mid + Math.imul(ah4, bl2) | 0;
                hi = hi + Math.imul(ah4, bh2) | 0;
                lo = lo + Math.imul(al3, bl3) | 0;
                mid = mid + Math.imul(al3, bh3) | 0;
                mid = mid + Math.imul(ah3, bl3) | 0;
                hi = hi + Math.imul(ah3, bh3) | 0;
                lo = lo + Math.imul(al2, bl4) | 0;
                mid = mid + Math.imul(al2, bh4) | 0;
                mid = mid + Math.imul(ah2, bl4) | 0;
                hi = hi + Math.imul(ah2, bh4) | 0;
                lo = lo + Math.imul(al1, bl5) | 0;
                mid = mid + Math.imul(al1, bh5) | 0;
                mid = mid + Math.imul(ah1, bl5) | 0;
                hi = hi + Math.imul(ah1, bh5) | 0;
                lo = lo + Math.imul(al0, bl6) | 0;
                mid = mid + Math.imul(al0, bh6) | 0;
                mid = mid + Math.imul(ah0, bl6) | 0;
                hi = hi + Math.imul(ah0, bh6) | 0;
                var w6 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w6 >>> 26) | 0;
                w6 &= 67108863;
                lo = Math.imul(al7, bl0);
                mid = Math.imul(al7, bh0);
                mid = mid + Math.imul(ah7, bl0) | 0;
                hi = Math.imul(ah7, bh0);
                lo = lo + Math.imul(al6, bl1) | 0;
                mid = mid + Math.imul(al6, bh1) | 0;
                mid = mid + Math.imul(ah6, bl1) | 0;
                hi = hi + Math.imul(ah6, bh1) | 0;
                lo = lo + Math.imul(al5, bl2) | 0;
                mid = mid + Math.imul(al5, bh2) | 0;
                mid = mid + Math.imul(ah5, bl2) | 0;
                hi = hi + Math.imul(ah5, bh2) | 0;
                lo = lo + Math.imul(al4, bl3) | 0;
                mid = mid + Math.imul(al4, bh3) | 0;
                mid = mid + Math.imul(ah4, bl3) | 0;
                hi = hi + Math.imul(ah4, bh3) | 0;
                lo = lo + Math.imul(al3, bl4) | 0;
                mid = mid + Math.imul(al3, bh4) | 0;
                mid = mid + Math.imul(ah3, bl4) | 0;
                hi = hi + Math.imul(ah3, bh4) | 0;
                lo = lo + Math.imul(al2, bl5) | 0;
                mid = mid + Math.imul(al2, bh5) | 0;
                mid = mid + Math.imul(ah2, bl5) | 0;
                hi = hi + Math.imul(ah2, bh5) | 0;
                lo = lo + Math.imul(al1, bl6) | 0;
                mid = mid + Math.imul(al1, bh6) | 0;
                mid = mid + Math.imul(ah1, bl6) | 0;
                hi = hi + Math.imul(ah1, bh6) | 0;
                lo = lo + Math.imul(al0, bl7) | 0;
                mid = mid + Math.imul(al0, bh7) | 0;
                mid = mid + Math.imul(ah0, bl7) | 0;
                hi = hi + Math.imul(ah0, bh7) | 0;
                var w7 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w7 >>> 26) | 0;
                w7 &= 67108863;
                lo = Math.imul(al8, bl0);
                mid = Math.imul(al8, bh0);
                mid = mid + Math.imul(ah8, bl0) | 0;
                hi = Math.imul(ah8, bh0);
                lo = lo + Math.imul(al7, bl1) | 0;
                mid = mid + Math.imul(al7, bh1) | 0;
                mid = mid + Math.imul(ah7, bl1) | 0;
                hi = hi + Math.imul(ah7, bh1) | 0;
                lo = lo + Math.imul(al6, bl2) | 0;
                mid = mid + Math.imul(al6, bh2) | 0;
                mid = mid + Math.imul(ah6, bl2) | 0;
                hi = hi + Math.imul(ah6, bh2) | 0;
                lo = lo + Math.imul(al5, bl3) | 0;
                mid = mid + Math.imul(al5, bh3) | 0;
                mid = mid + Math.imul(ah5, bl3) | 0;
                hi = hi + Math.imul(ah5, bh3) | 0;
                lo = lo + Math.imul(al4, bl4) | 0;
                mid = mid + Math.imul(al4, bh4) | 0;
                mid = mid + Math.imul(ah4, bl4) | 0;
                hi = hi + Math.imul(ah4, bh4) | 0;
                lo = lo + Math.imul(al3, bl5) | 0;
                mid = mid + Math.imul(al3, bh5) | 0;
                mid = mid + Math.imul(ah3, bl5) | 0;
                hi = hi + Math.imul(ah3, bh5) | 0;
                lo = lo + Math.imul(al2, bl6) | 0;
                mid = mid + Math.imul(al2, bh6) | 0;
                mid = mid + Math.imul(ah2, bl6) | 0;
                hi = hi + Math.imul(ah2, bh6) | 0;
                lo = lo + Math.imul(al1, bl7) | 0;
                mid = mid + Math.imul(al1, bh7) | 0;
                mid = mid + Math.imul(ah1, bl7) | 0;
                hi = hi + Math.imul(ah1, bh7) | 0;
                lo = lo + Math.imul(al0, bl8) | 0;
                mid = mid + Math.imul(al0, bh8) | 0;
                mid = mid + Math.imul(ah0, bl8) | 0;
                hi = hi + Math.imul(ah0, bh8) | 0;
                var w8 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w8 >>> 26) | 0;
                w8 &= 67108863;
                lo = Math.imul(al9, bl0);
                mid = Math.imul(al9, bh0);
                mid = mid + Math.imul(ah9, bl0) | 0;
                hi = Math.imul(ah9, bh0);
                lo = lo + Math.imul(al8, bl1) | 0;
                mid = mid + Math.imul(al8, bh1) | 0;
                mid = mid + Math.imul(ah8, bl1) | 0;
                hi = hi + Math.imul(ah8, bh1) | 0;
                lo = lo + Math.imul(al7, bl2) | 0;
                mid = mid + Math.imul(al7, bh2) | 0;
                mid = mid + Math.imul(ah7, bl2) | 0;
                hi = hi + Math.imul(ah7, bh2) | 0;
                lo = lo + Math.imul(al6, bl3) | 0;
                mid = mid + Math.imul(al6, bh3) | 0;
                mid = mid + Math.imul(ah6, bl3) | 0;
                hi = hi + Math.imul(ah6, bh3) | 0;
                lo = lo + Math.imul(al5, bl4) | 0;
                mid = mid + Math.imul(al5, bh4) | 0;
                mid = mid + Math.imul(ah5, bl4) | 0;
                hi = hi + Math.imul(ah5, bh4) | 0;
                lo = lo + Math.imul(al4, bl5) | 0;
                mid = mid + Math.imul(al4, bh5) | 0;
                mid = mid + Math.imul(ah4, bl5) | 0;
                hi = hi + Math.imul(ah4, bh5) | 0;
                lo = lo + Math.imul(al3, bl6) | 0;
                mid = mid + Math.imul(al3, bh6) | 0;
                mid = mid + Math.imul(ah3, bl6) | 0;
                hi = hi + Math.imul(ah3, bh6) | 0;
                lo = lo + Math.imul(al2, bl7) | 0;
                mid = mid + Math.imul(al2, bh7) | 0;
                mid = mid + Math.imul(ah2, bl7) | 0;
                hi = hi + Math.imul(ah2, bh7) | 0;
                lo = lo + Math.imul(al1, bl8) | 0;
                mid = mid + Math.imul(al1, bh8) | 0;
                mid = mid + Math.imul(ah1, bl8) | 0;
                hi = hi + Math.imul(ah1, bh8) | 0;
                lo = lo + Math.imul(al0, bl9) | 0;
                mid = mid + Math.imul(al0, bh9) | 0;
                mid = mid + Math.imul(ah0, bl9) | 0;
                hi = hi + Math.imul(ah0, bh9) | 0;
                var w9 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w9 >>> 26) | 0;
                w9 &= 67108863;
                lo = Math.imul(al9, bl1);
                mid = Math.imul(al9, bh1);
                mid = mid + Math.imul(ah9, bl1) | 0;
                hi = Math.imul(ah9, bh1);
                lo = lo + Math.imul(al8, bl2) | 0;
                mid = mid + Math.imul(al8, bh2) | 0;
                mid = mid + Math.imul(ah8, bl2) | 0;
                hi = hi + Math.imul(ah8, bh2) | 0;
                lo = lo + Math.imul(al7, bl3) | 0;
                mid = mid + Math.imul(al7, bh3) | 0;
                mid = mid + Math.imul(ah7, bl3) | 0;
                hi = hi + Math.imul(ah7, bh3) | 0;
                lo = lo + Math.imul(al6, bl4) | 0;
                mid = mid + Math.imul(al6, bh4) | 0;
                mid = mid + Math.imul(ah6, bl4) | 0;
                hi = hi + Math.imul(ah6, bh4) | 0;
                lo = lo + Math.imul(al5, bl5) | 0;
                mid = mid + Math.imul(al5, bh5) | 0;
                mid = mid + Math.imul(ah5, bl5) | 0;
                hi = hi + Math.imul(ah5, bh5) | 0;
                lo = lo + Math.imul(al4, bl6) | 0;
                mid = mid + Math.imul(al4, bh6) | 0;
                mid = mid + Math.imul(ah4, bl6) | 0;
                hi = hi + Math.imul(ah4, bh6) | 0;
                lo = lo + Math.imul(al3, bl7) | 0;
                mid = mid + Math.imul(al3, bh7) | 0;
                mid = mid + Math.imul(ah3, bl7) | 0;
                hi = hi + Math.imul(ah3, bh7) | 0;
                lo = lo + Math.imul(al2, bl8) | 0;
                mid = mid + Math.imul(al2, bh8) | 0;
                mid = mid + Math.imul(ah2, bl8) | 0;
                hi = hi + Math.imul(ah2, bh8) | 0;
                lo = lo + Math.imul(al1, bl9) | 0;
                mid = mid + Math.imul(al1, bh9) | 0;
                mid = mid + Math.imul(ah1, bl9) | 0;
                hi = hi + Math.imul(ah1, bh9) | 0;
                var w10 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w10 >>> 26) | 0;
                w10 &= 67108863;
                lo = Math.imul(al9, bl2);
                mid = Math.imul(al9, bh2);
                mid = mid + Math.imul(ah9, bl2) | 0;
                hi = Math.imul(ah9, bh2);
                lo = lo + Math.imul(al8, bl3) | 0;
                mid = mid + Math.imul(al8, bh3) | 0;
                mid = mid + Math.imul(ah8, bl3) | 0;
                hi = hi + Math.imul(ah8, bh3) | 0;
                lo = lo + Math.imul(al7, bl4) | 0;
                mid = mid + Math.imul(al7, bh4) | 0;
                mid = mid + Math.imul(ah7, bl4) | 0;
                hi = hi + Math.imul(ah7, bh4) | 0;
                lo = lo + Math.imul(al6, bl5) | 0;
                mid = mid + Math.imul(al6, bh5) | 0;
                mid = mid + Math.imul(ah6, bl5) | 0;
                hi = hi + Math.imul(ah6, bh5) | 0;
                lo = lo + Math.imul(al5, bl6) | 0;
                mid = mid + Math.imul(al5, bh6) | 0;
                mid = mid + Math.imul(ah5, bl6) | 0;
                hi = hi + Math.imul(ah5, bh6) | 0;
                lo = lo + Math.imul(al4, bl7) | 0;
                mid = mid + Math.imul(al4, bh7) | 0;
                mid = mid + Math.imul(ah4, bl7) | 0;
                hi = hi + Math.imul(ah4, bh7) | 0;
                lo = lo + Math.imul(al3, bl8) | 0;
                mid = mid + Math.imul(al3, bh8) | 0;
                mid = mid + Math.imul(ah3, bl8) | 0;
                hi = hi + Math.imul(ah3, bh8) | 0;
                lo = lo + Math.imul(al2, bl9) | 0;
                mid = mid + Math.imul(al2, bh9) | 0;
                mid = mid + Math.imul(ah2, bl9) | 0;
                hi = hi + Math.imul(ah2, bh9) | 0;
                var w11 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w11 >>> 26) | 0;
                w11 &= 67108863;
                lo = Math.imul(al9, bl3);
                mid = Math.imul(al9, bh3);
                mid = mid + Math.imul(ah9, bl3) | 0;
                hi = Math.imul(ah9, bh3);
                lo = lo + Math.imul(al8, bl4) | 0;
                mid = mid + Math.imul(al8, bh4) | 0;
                mid = mid + Math.imul(ah8, bl4) | 0;
                hi = hi + Math.imul(ah8, bh4) | 0;
                lo = lo + Math.imul(al7, bl5) | 0;
                mid = mid + Math.imul(al7, bh5) | 0;
                mid = mid + Math.imul(ah7, bl5) | 0;
                hi = hi + Math.imul(ah7, bh5) | 0;
                lo = lo + Math.imul(al6, bl6) | 0;
                mid = mid + Math.imul(al6, bh6) | 0;
                mid = mid + Math.imul(ah6, bl6) | 0;
                hi = hi + Math.imul(ah6, bh6) | 0;
                lo = lo + Math.imul(al5, bl7) | 0;
                mid = mid + Math.imul(al5, bh7) | 0;
                mid = mid + Math.imul(ah5, bl7) | 0;
                hi = hi + Math.imul(ah5, bh7) | 0;
                lo = lo + Math.imul(al4, bl8) | 0;
                mid = mid + Math.imul(al4, bh8) | 0;
                mid = mid + Math.imul(ah4, bl8) | 0;
                hi = hi + Math.imul(ah4, bh8) | 0;
                lo = lo + Math.imul(al3, bl9) | 0;
                mid = mid + Math.imul(al3, bh9) | 0;
                mid = mid + Math.imul(ah3, bl9) | 0;
                hi = hi + Math.imul(ah3, bh9) | 0;
                var w12 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w12 >>> 26) | 0;
                w12 &= 67108863;
                lo = Math.imul(al9, bl4);
                mid = Math.imul(al9, bh4);
                mid = mid + Math.imul(ah9, bl4) | 0;
                hi = Math.imul(ah9, bh4);
                lo = lo + Math.imul(al8, bl5) | 0;
                mid = mid + Math.imul(al8, bh5) | 0;
                mid = mid + Math.imul(ah8, bl5) | 0;
                hi = hi + Math.imul(ah8, bh5) | 0;
                lo = lo + Math.imul(al7, bl6) | 0;
                mid = mid + Math.imul(al7, bh6) | 0;
                mid = mid + Math.imul(ah7, bl6) | 0;
                hi = hi + Math.imul(ah7, bh6) | 0;
                lo = lo + Math.imul(al6, bl7) | 0;
                mid = mid + Math.imul(al6, bh7) | 0;
                mid = mid + Math.imul(ah6, bl7) | 0;
                hi = hi + Math.imul(ah6, bh7) | 0;
                lo = lo + Math.imul(al5, bl8) | 0;
                mid = mid + Math.imul(al5, bh8) | 0;
                mid = mid + Math.imul(ah5, bl8) | 0;
                hi = hi + Math.imul(ah5, bh8) | 0;
                lo = lo + Math.imul(al4, bl9) | 0;
                mid = mid + Math.imul(al4, bh9) | 0;
                mid = mid + Math.imul(ah4, bl9) | 0;
                hi = hi + Math.imul(ah4, bh9) | 0;
                var w13 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w13 >>> 26) | 0;
                w13 &= 67108863;
                lo = Math.imul(al9, bl5);
                mid = Math.imul(al9, bh5);
                mid = mid + Math.imul(ah9, bl5) | 0;
                hi = Math.imul(ah9, bh5);
                lo = lo + Math.imul(al8, bl6) | 0;
                mid = mid + Math.imul(al8, bh6) | 0;
                mid = mid + Math.imul(ah8, bl6) | 0;
                hi = hi + Math.imul(ah8, bh6) | 0;
                lo = lo + Math.imul(al7, bl7) | 0;
                mid = mid + Math.imul(al7, bh7) | 0;
                mid = mid + Math.imul(ah7, bl7) | 0;
                hi = hi + Math.imul(ah7, bh7) | 0;
                lo = lo + Math.imul(al6, bl8) | 0;
                mid = mid + Math.imul(al6, bh8) | 0;
                mid = mid + Math.imul(ah6, bl8) | 0;
                hi = hi + Math.imul(ah6, bh8) | 0;
                lo = lo + Math.imul(al5, bl9) | 0;
                mid = mid + Math.imul(al5, bh9) | 0;
                mid = mid + Math.imul(ah5, bl9) | 0;
                hi = hi + Math.imul(ah5, bh9) | 0;
                var w14 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w14 >>> 26) | 0;
                w14 &= 67108863;
                lo = Math.imul(al9, bl6);
                mid = Math.imul(al9, bh6);
                mid = mid + Math.imul(ah9, bl6) | 0;
                hi = Math.imul(ah9, bh6);
                lo = lo + Math.imul(al8, bl7) | 0;
                mid = mid + Math.imul(al8, bh7) | 0;
                mid = mid + Math.imul(ah8, bl7) | 0;
                hi = hi + Math.imul(ah8, bh7) | 0;
                lo = lo + Math.imul(al7, bl8) | 0;
                mid = mid + Math.imul(al7, bh8) | 0;
                mid = mid + Math.imul(ah7, bl8) | 0;
                hi = hi + Math.imul(ah7, bh8) | 0;
                lo = lo + Math.imul(al6, bl9) | 0;
                mid = mid + Math.imul(al6, bh9) | 0;
                mid = mid + Math.imul(ah6, bl9) | 0;
                hi = hi + Math.imul(ah6, bh9) | 0;
                var w15 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w15 >>> 26) | 0;
                w15 &= 67108863;
                lo = Math.imul(al9, bl7);
                mid = Math.imul(al9, bh7);
                mid = mid + Math.imul(ah9, bl7) | 0;
                hi = Math.imul(ah9, bh7);
                lo = lo + Math.imul(al8, bl8) | 0;
                mid = mid + Math.imul(al8, bh8) | 0;
                mid = mid + Math.imul(ah8, bl8) | 0;
                hi = hi + Math.imul(ah8, bh8) | 0;
                lo = lo + Math.imul(al7, bl9) | 0;
                mid = mid + Math.imul(al7, bh9) | 0;
                mid = mid + Math.imul(ah7, bl9) | 0;
                hi = hi + Math.imul(ah7, bh9) | 0;
                var w16 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w16 >>> 26) | 0;
                w16 &= 67108863;
                lo = Math.imul(al9, bl8);
                mid = Math.imul(al9, bh8);
                mid = mid + Math.imul(ah9, bl8) | 0;
                hi = Math.imul(ah9, bh8);
                lo = lo + Math.imul(al8, bl9) | 0;
                mid = mid + Math.imul(al8, bh9) | 0;
                mid = mid + Math.imul(ah8, bl9) | 0;
                hi = hi + Math.imul(ah8, bh9) | 0;
                var w17 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w17 >>> 26) | 0;
                w17 &= 67108863;
                lo = Math.imul(al9, bl9);
                mid = Math.imul(al9, bh9);
                mid = mid + Math.imul(ah9, bl9) | 0;
                hi = Math.imul(ah9, bh9);
                var w18 = (c + lo | 0) + ((mid & 8191) << 13) | 0;
                c = (hi + (mid >>> 13) | 0) + (w18 >>> 26) | 0;
                w18 &= 67108863;
                o[0] = w0;
                o[1] = w1;
                o[2] = w2;
                o[3] = w3;
                o[4] = w4;
                o[5] = w5;
                o[6] = w6;
                o[7] = w7;
                o[8] = w8;
                o[9] = w9;
                o[10] = w10;
                o[11] = w11;
                o[12] = w12;
                o[13] = w13;
                o[14] = w14;
                o[15] = w15;
                o[16] = w16;
                o[17] = w17;
                o[18] = w18;
                if (c !== 0) {
                    o[19] = c;
                    out.length++;
                }
                return out;
            };
            if (!Math.imul) {
                comb10MulTo = smallMulTo;
            }
            function bigMulTo(self, num, out) {
                out.negative = num.negative ^ self.negative;
                out.length = self.length + num.length;
                var carry = 0;
                var hncarry = 0;
                for (var k = 0; k < out.length - 1; k++) {
                    var ncarry = hncarry;
                    hncarry = 0;
                    var rword = carry & 67108863;
                    var maxJ = Math.min(k, num.length - 1);
                    for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
                        var i = k - j;
                        var a = self.words[i] | 0;
                        var b = num.words[j] | 0;
                        var r = a * b;
                        var lo = r & 67108863;
                        ncarry = ncarry + (r / 67108864 | 0) | 0;
                        lo = lo + rword | 0;
                        rword = lo & 67108863;
                        ncarry = ncarry + (lo >>> 26) | 0;
                        hncarry += ncarry >>> 26;
                        ncarry &= 67108863;
                    }
                    out.words[k] = rword;
                    carry = ncarry;
                    ncarry = hncarry;
                }
                if (carry !== 0) {
                    out.words[k] = carry;
                } else {
                    out.length--;
                }
                return out.strip();
            }
            function jumboMulTo(self, num, out) {
                var fftm = new FFTM();
                return fftm.mulp(self, num, out);
            }
            BN.prototype.mulTo = function mulTo(num, out) {
                var res;
                var len = this.length + num.length;
                if (this.length === 10 && num.length === 10) {
                    res = comb10MulTo(this, num, out);
                } else if (len < 63) {
                    res = smallMulTo(this, num, out);
                } else if (len < 1024) {
                    res = bigMulTo(this, num, out);
                } else {
                    res = jumboMulTo(this, num, out);
                }
                return res;
            };
            function FFTM(x, y) {
                this.x = x;
                this.y = y;
            }
            FFTM.prototype.makeRBT = function makeRBT(N) {
                var t = new Array(N);
                var l = BN.prototype._countBits(N) - 1;
                for (var i = 0; i < N; i++) {
                    t[i] = this.revBin(i, l, N);
                }
                return t;
            };
            FFTM.prototype.revBin = function revBin(x, l, N) {
                if (x === 0 || x === N - 1) return x;
                var rb = 0;
                for (var i = 0; i < l; i++) {
                    rb |= (x & 1) << l - i - 1;
                    x >>= 1;
                }
                return rb;
            };
            FFTM.prototype.permute = function permute(rbt, rws, iws, rtws, itws, N) {
                for (var i = 0; i < N; i++) {
                    rtws[i] = rws[rbt[i]];
                    itws[i] = iws[rbt[i]];
                }
            };
            FFTM.prototype.transform = function transform(rws, iws, rtws, itws, N, rbt) {
                this.permute(rbt, rws, iws, rtws, itws, N);
                for (var s = 1; s < N; s <<= 1) {
                    var l = s << 1;
                    var rtwdf = Math.cos(2 * Math.PI / l);
                    var itwdf = Math.sin(2 * Math.PI / l);
                    for (var p = 0; p < N; p += l) {
                        var rtwdf_ = rtwdf;
                        var itwdf_ = itwdf;
                        for (var j = 0; j < s; j++) {
                            var re = rtws[p + j];
                            var ie = itws[p + j];
                            var ro = rtws[p + j + s];
                            var io = itws[p + j + s];
                            var rx = rtwdf_ * ro - itwdf_ * io;
                            io = rtwdf_ * io + itwdf_ * ro;
                            ro = rx;
                            rtws[p + j] = re + ro;
                            itws[p + j] = ie + io;
                            rtws[p + j + s] = re - ro;
                            itws[p + j + s] = ie - io;
                            if (j !== l) {
                                rx = rtwdf * rtwdf_ - itwdf * itwdf_;
                                itwdf_ = rtwdf * itwdf_ + itwdf * rtwdf_;
                                rtwdf_ = rx;
                            }
                        }
                    }
                }
            };
            FFTM.prototype.guessLen13b = function guessLen13b(n, m) {
                var N = Math.max(m, n) | 1;
                var odd = N & 1;
                var i = 0;
                for (N = N / 2 | 0; N; N = N >>> 1) {
                    i++;
                }
                return 1 << i + 1 + odd;
            };
            FFTM.prototype.conjugate = function conjugate(rws, iws, N) {
                if (N <= 1) return;
                for (var i = 0; i < N / 2; i++) {
                    var t = rws[i];
                    rws[i] = rws[N - i - 1];
                    rws[N - i - 1] = t;
                    t = iws[i];
                    iws[i] = -iws[N - i - 1];
                    iws[N - i - 1] = -t;
                }
            };
            FFTM.prototype.normalize13b = function normalize13b(ws, N) {
                var carry = 0;
                for (var i = 0; i < N / 2; i++) {
                    var w = Math.round(ws[2 * i + 1] / N) * 8192 + Math.round(ws[2 * i] / N) + carry;
                    ws[i] = w & 67108863;
                    if (w < 67108864) {
                        carry = 0;
                    } else {
                        carry = w / 67108864 | 0;
                    }
                }
                return ws;
            };
            FFTM.prototype.convert13b = function convert13b(ws, len, rws, N) {
                var carry = 0;
                for (var i = 0; i < len; i++) {
                    carry = carry + (ws[i] | 0);
                    rws[2 * i] = carry & 8191;
                    carry = carry >>> 13;
                    rws[2 * i + 1] = carry & 8191;
                    carry = carry >>> 13;
                }
                for (i = 2 * len; i < N; ++i) {
                    rws[i] = 0;
                }
                assert(carry === 0);
                assert((carry & ~8191) === 0);
            };
            FFTM.prototype.stub = function stub(N) {
                var ph = new Array(N);
                for (var i = 0; i < N; i++) {
                    ph[i] = 0;
                }
                return ph;
            };
            FFTM.prototype.mulp = function mulp(x, y, out) {
                var N = 2 * this.guessLen13b(x.length, y.length);
                var rbt = this.makeRBT(N);
                var _ = this.stub(N);
                var rws = new Array(N);
                var rwst = new Array(N);
                var iwst = new Array(N);
                var nrws = new Array(N);
                var nrwst = new Array(N);
                var niwst = new Array(N);
                var rmws = out.words;
                rmws.length = N;
                this.convert13b(x.words, x.length, rws, N);
                this.convert13b(y.words, y.length, nrws, N);
                this.transform(rws, _, rwst, iwst, N, rbt);
                this.transform(nrws, _, nrwst, niwst, N, rbt);
                for (var i = 0; i < N; i++) {
                    var rx = rwst[i] * nrwst[i] - iwst[i] * niwst[i];
                    iwst[i] = rwst[i] * niwst[i] + iwst[i] * nrwst[i];
                    rwst[i] = rx;
                }
                this.conjugate(rwst, iwst, N);
                this.transform(rwst, iwst, rmws, _, N, rbt);
                this.conjugate(rmws, _, N);
                this.normalize13b(rmws, N);
                out.negative = x.negative ^ y.negative;
                out.length = x.length + y.length;
                return out.strip();
            };
            BN.prototype.mul = function mul(num) {
                var out = new BN(null);
                out.words = new Array(this.length + num.length);
                return this.mulTo(num, out);
            };
            BN.prototype.mulf = function mulf(num) {
                var out = new BN(null);
                out.words = new Array(this.length + num.length);
                return jumboMulTo(this, num, out);
            };
            BN.prototype.imul = function imul(num) {
                return this.clone().mulTo(num, this);
            };
            BN.prototype.imuln = function imuln(num) {
                assert(typeof num === "number");
                assert(num < 67108864);
                var carry = 0;
                for (var i = 0; i < this.length; i++) {
                    var w = (this.words[i] | 0) * num;
                    var lo = (w & 67108863) + (carry & 67108863);
                    carry >>= 26;
                    carry += w / 67108864 | 0;
                    carry += lo >>> 26;
                    this.words[i] = lo & 67108863;
                }
                if (carry !== 0) {
                    this.words[i] = carry;
                    this.length++;
                }
                return this;
            };
            BN.prototype.muln = function muln(num) {
                return this.clone().imuln(num);
            };
            BN.prototype.sqr = function sqr() {
                return this.mul(this);
            };
            BN.prototype.isqr = function isqr() {
                return this.imul(this.clone());
            };
            BN.prototype.pow = function pow(num) {
                var w = toBitArray(num);
                if (w.length === 0) return new BN(1);
                var res = this;
                for (var i = 0; i < w.length; i++, res = res.sqr()) {
                    if (w[i] !== 0) break;
                }
                if (++i < w.length) {
                    for (var q = res.sqr(); i < w.length; i++, q = q.sqr()) {
                        if (w[i] === 0) continue;
                        res = res.mul(q);
                    }
                }
                return res;
            };
            BN.prototype.iushln = function iushln(bits) {
                assert(typeof bits === "number" && bits >= 0);
                var r = bits % 26;
                var s = (bits - r) / 26;
                var carryMask = 67108863 >>> 26 - r << 26 - r;
                var i;
                if (r !== 0) {
                    var carry = 0;
                    for (i = 0; i < this.length; i++) {
                        var newCarry = this.words[i] & carryMask;
                        var c = (this.words[i] | 0) - newCarry << r;
                        this.words[i] = c | carry;
                        carry = newCarry >>> 26 - r;
                    }
                    if (carry) {
                        this.words[i] = carry;
                        this.length++;
                    }
                }
                if (s !== 0) {
                    for (i = this.length - 1; i >= 0; i--) {
                        this.words[i + s] = this.words[i];
                    }
                    for (i = 0; i < s; i++) {
                        this.words[i] = 0;
                    }
                    this.length += s;
                }
                return this.strip();
            };
            BN.prototype.ishln = function ishln(bits) {
                assert(this.negative === 0);
                return this.iushln(bits);
            };
            BN.prototype.iushrn = function iushrn(bits, hint, extended) {
                assert(typeof bits === "number" && bits >= 0);
                var h;
                if (hint) {
                    h = (hint - hint % 26) / 26;
                } else {
                    h = 0;
                }
                var r = bits % 26;
                var s = Math.min((bits - r) / 26, this.length);
                var mask = 67108863 ^ 67108863 >>> r << r;
                var maskedWords = extended;
                h -= s;
                h = Math.max(0, h);
                if (maskedWords) {
                    for (var i = 0; i < s; i++) {
                        maskedWords.words[i] = this.words[i];
                    }
                    maskedWords.length = s;
                }
                if (s === 0) {} else if (this.length > s) {
                    this.length -= s;
                    for (i = 0; i < this.length; i++) {
                        this.words[i] = this.words[i + s];
                    }
                } else {
                    this.words[0] = 0;
                    this.length = 1;
                }
                var carry = 0;
                for (i = this.length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
                    var word = this.words[i] | 0;
                    this.words[i] = carry << 26 - r | word >>> r;
                    carry = word & mask;
                }
                if (maskedWords && carry !== 0) {
                    maskedWords.words[maskedWords.length++] = carry;
                }
                if (this.length === 0) {
                    this.words[0] = 0;
                    this.length = 1;
                }
                return this.strip();
            };
            BN.prototype.ishrn = function ishrn(bits, hint, extended) {
                assert(this.negative === 0);
                return this.iushrn(bits, hint, extended);
            };
            BN.prototype.shln = function shln(bits) {
                return this.clone().ishln(bits);
            };
            BN.prototype.ushln = function ushln(bits) {
                return this.clone().iushln(bits);
            };
            BN.prototype.shrn = function shrn(bits) {
                return this.clone().ishrn(bits);
            };
            BN.prototype.ushrn = function ushrn(bits) {
                return this.clone().iushrn(bits);
            };
            BN.prototype.testn = function testn(bit) {
                assert(typeof bit === "number" && bit >= 0);
                var r = bit % 26;
                var s = (bit - r) / 26;
                var q = 1 << r;
                if (this.length <= s) return false;
                var w = this.words[s];
                return !!(w & q);
            };
            BN.prototype.imaskn = function imaskn(bits) {
                assert(typeof bits === "number" && bits >= 0);
                var r = bits % 26;
                var s = (bits - r) / 26;
                assert(this.negative === 0, "imaskn works only with positive numbers");
                if (this.length <= s) {
                    return this;
                }
                if (r !== 0) {
                    s++;
                }
                this.length = Math.min(s, this.length);
                if (r !== 0) {
                    var mask = 67108863 ^ 67108863 >>> r << r;
                    this.words[this.length - 1] &= mask;
                }
                return this.strip();
            };
            BN.prototype.maskn = function maskn(bits) {
                return this.clone().imaskn(bits);
            };
            BN.prototype.iaddn = function iaddn(num) {
                assert(typeof num === "number");
                assert(num < 67108864);
                if (num < 0) return this.isubn(-num);
                if (this.negative !== 0) {
                    if (this.length === 1 && (this.words[0] | 0) < num) {
                        this.words[0] = num - (this.words[0] | 0);
                        this.negative = 0;
                        return this;
                    }
                    this.negative = 0;
                    this.isubn(num);
                    this.negative = 1;
                    return this;
                }
                return this._iaddn(num);
            };
            BN.prototype._iaddn = function _iaddn(num) {
                this.words[0] += num;
                for (var i = 0; i < this.length && this.words[i] >= 67108864; i++) {
                    this.words[i] -= 67108864;
                    if (i === this.length - 1) {
                        this.words[i + 1] = 1;
                    } else {
                        this.words[i + 1]++;
                    }
                }
                this.length = Math.max(this.length, i + 1);
                return this;
            };
            BN.prototype.isubn = function isubn(num) {
                assert(typeof num === "number");
                assert(num < 67108864);
                if (num < 0) return this.iaddn(-num);
                if (this.negative !== 0) {
                    this.negative = 0;
                    this.iaddn(num);
                    this.negative = 1;
                    return this;
                }
                this.words[0] -= num;
                if (this.length === 1 && this.words[0] < 0) {
                    this.words[0] = -this.words[0];
                    this.negative = 1;
                } else {
                    for (var i = 0; i < this.length && this.words[i] < 0; i++) {
                        this.words[i] += 67108864;
                        this.words[i + 1] -= 1;
                    }
                }
                return this.strip();
            };
            BN.prototype.addn = function addn(num) {
                return this.clone().iaddn(num);
            };
            BN.prototype.subn = function subn(num) {
                return this.clone().isubn(num);
            };
            BN.prototype.iabs = function iabs() {
                this.negative = 0;
                return this;
            };
            BN.prototype.abs = function abs() {
                return this.clone().iabs();
            };
            BN.prototype._ishlnsubmul = function _ishlnsubmul(num, mul, shift) {
                var len = num.length + shift;
                var i;
                this._expand(len);
                var w;
                var carry = 0;
                for (i = 0; i < num.length; i++) {
                    w = (this.words[i + shift] | 0) + carry;
                    var right = (num.words[i] | 0) * mul;
                    w -= right & 67108863;
                    carry = (w >> 26) - (right / 67108864 | 0);
                    this.words[i + shift] = w & 67108863;
                }
                for (;i < this.length - shift; i++) {
                    w = (this.words[i + shift] | 0) + carry;
                    carry = w >> 26;
                    this.words[i + shift] = w & 67108863;
                }
                if (carry === 0) return this.strip();
                assert(carry === -1);
                carry = 0;
                for (i = 0; i < this.length; i++) {
                    w = -(this.words[i] | 0) + carry;
                    carry = w >> 26;
                    this.words[i] = w & 67108863;
                }
                this.negative = 1;
                return this.strip();
            };
            BN.prototype._wordDiv = function _wordDiv(num, mode) {
                var shift = this.length - num.length;
                var a = this.clone();
                var b = num;
                var bhi = b.words[b.length - 1] | 0;
                var bhiBits = this._countBits(bhi);
                shift = 26 - bhiBits;
                if (shift !== 0) {
                    b = b.ushln(shift);
                    a.iushln(shift);
                    bhi = b.words[b.length - 1] | 0;
                }
                var m = a.length - b.length;
                var q;
                if (mode !== "mod") {
                    q = new BN(null);
                    q.length = m + 1;
                    q.words = new Array(q.length);
                    for (var i = 0; i < q.length; i++) {
                        q.words[i] = 0;
                    }
                }
                var diff = a.clone()._ishlnsubmul(b, 1, m);
                if (diff.negative === 0) {
                    a = diff;
                    if (q) {
                        q.words[m] = 1;
                    }
                }
                for (var j = m - 1; j >= 0; j--) {
                    var qj = (a.words[b.length + j] | 0) * 67108864 + (a.words[b.length + j - 1] | 0);
                    qj = Math.min(qj / bhi | 0, 67108863);
                    a._ishlnsubmul(b, qj, j);
                    while (a.negative !== 0) {
                        qj--;
                        a.negative = 0;
                        a._ishlnsubmul(b, 1, j);
                        if (!a.isZero()) {
                            a.negative ^= 1;
                        }
                    }
                    if (q) {
                        q.words[j] = qj;
                    }
                }
                if (q) {
                    q.strip();
                }
                a.strip();
                if (mode !== "div" && shift !== 0) {
                    a.iushrn(shift);
                }
                return {
                    div: q || null,
                    mod: a
                };
            };
            BN.prototype.divmod = function divmod(num, mode, positive) {
                assert(!num.isZero());
                if (this.isZero()) {
                    return {
                        div: new BN(0),
                        mod: new BN(0)
                    };
                }
                var div, mod, res;
                if (this.negative !== 0 && num.negative === 0) {
                    res = this.neg().divmod(num, mode);
                    if (mode !== "mod") {
                        div = res.div.neg();
                    }
                    if (mode !== "div") {
                        mod = res.mod.neg();
                        if (positive && mod.negative !== 0) {
                            mod.iadd(num);
                        }
                    }
                    return {
                        div: div,
                        mod: mod
                    };
                }
                if (this.negative === 0 && num.negative !== 0) {
                    res = this.divmod(num.neg(), mode);
                    if (mode !== "mod") {
                        div = res.div.neg();
                    }
                    return {
                        div: div,
                        mod: res.mod
                    };
                }
                if ((this.negative & num.negative) !== 0) {
                    res = this.neg().divmod(num.neg(), mode);
                    if (mode !== "div") {
                        mod = res.mod.neg();
                        if (positive && mod.negative !== 0) {
                            mod.isub(num);
                        }
                    }
                    return {
                        div: res.div,
                        mod: mod
                    };
                }
                if (num.length > this.length || this.cmp(num) < 0) {
                    return {
                        div: new BN(0),
                        mod: this
                    };
                }
                if (num.length === 1) {
                    if (mode === "div") {
                        return {
                            div: this.divn(num.words[0]),
                            mod: null
                        };
                    }
                    if (mode === "mod") {
                        return {
                            div: null,
                            mod: new BN(this.modn(num.words[0]))
                        };
                    }
                    return {
                        div: this.divn(num.words[0]),
                        mod: new BN(this.modn(num.words[0]))
                    };
                }
                return this._wordDiv(num, mode);
            };
            BN.prototype.div = function div(num) {
                return this.divmod(num, "div", false).div;
            };
            BN.prototype.mod = function mod(num) {
                return this.divmod(num, "mod", false).mod;
            };
            BN.prototype.umod = function umod(num) {
                return this.divmod(num, "mod", true).mod;
            };
            BN.prototype.divRound = function divRound(num) {
                var dm = this.divmod(num);
                if (dm.mod.isZero()) return dm.div;
                var mod = dm.div.negative !== 0 ? dm.mod.isub(num) : dm.mod;
                var half = num.ushrn(1);
                var r2 = num.andln(1);
                var cmp = mod.cmp(half);
                if (cmp < 0 || r2 === 1 && cmp === 0) return dm.div;
                return dm.div.negative !== 0 ? dm.div.isubn(1) : dm.div.iaddn(1);
            };
            BN.prototype.modn = function modn(num) {
                assert(num <= 67108863);
                var p = (1 << 26) % num;
                var acc = 0;
                for (var i = this.length - 1; i >= 0; i--) {
                    acc = (p * acc + (this.words[i] | 0)) % num;
                }
                return acc;
            };
            BN.prototype.idivn = function idivn(num) {
                assert(num <= 67108863);
                var carry = 0;
                for (var i = this.length - 1; i >= 0; i--) {
                    var w = (this.words[i] | 0) + carry * 67108864;
                    this.words[i] = w / num | 0;
                    carry = w % num;
                }
                return this.strip();
            };
            BN.prototype.divn = function divn(num) {
                return this.clone().idivn(num);
            };
            BN.prototype.egcd = function egcd(p) {
                assert(p.negative === 0);
                assert(!p.isZero());
                var x = this;
                var y = p.clone();
                if (x.negative !== 0) {
                    x = x.umod(p);
                } else {
                    x = x.clone();
                }
                var A = new BN(1);
                var B = new BN(0);
                var C = new BN(0);
                var D = new BN(1);
                var g = 0;
                while (x.isEven() && y.isEven()) {
                    x.iushrn(1);
                    y.iushrn(1);
                    ++g;
                }
                var yp = y.clone();
                var xp = x.clone();
                while (!x.isZero()) {
                    for (var i = 0, im = 1; (x.words[0] & im) === 0 && i < 26; ++i, im <<= 1) ;
                    if (i > 0) {
                        x.iushrn(i);
                        while (i-- > 0) {
                            if (A.isOdd() || B.isOdd()) {
                                A.iadd(yp);
                                B.isub(xp);
                            }
                            A.iushrn(1);
                            B.iushrn(1);
                        }
                    }
                    for (var j = 0, jm = 1; (y.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1) ;
                    if (j > 0) {
                        y.iushrn(j);
                        while (j-- > 0) {
                            if (C.isOdd() || D.isOdd()) {
                                C.iadd(yp);
                                D.isub(xp);
                            }
                            C.iushrn(1);
                            D.iushrn(1);
                        }
                    }
                    if (x.cmp(y) >= 0) {
                        x.isub(y);
                        A.isub(C);
                        B.isub(D);
                    } else {
                        y.isub(x);
                        C.isub(A);
                        D.isub(B);
                    }
                }
                return {
                    a: C,
                    b: D,
                    gcd: y.iushln(g)
                };
            };
            BN.prototype._invmp = function _invmp(p) {
                assert(p.negative === 0);
                assert(!p.isZero());
                var a = this;
                var b = p.clone();
                if (a.negative !== 0) {
                    a = a.umod(p);
                } else {
                    a = a.clone();
                }
                var x1 = new BN(1);
                var x2 = new BN(0);
                var delta = b.clone();
                while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
                    for (var i = 0, im = 1; (a.words[0] & im) === 0 && i < 26; ++i, im <<= 1) ;
                    if (i > 0) {
                        a.iushrn(i);
                        while (i-- > 0) {
                            if (x1.isOdd()) {
                                x1.iadd(delta);
                            }
                            x1.iushrn(1);
                        }
                    }
                    for (var j = 0, jm = 1; (b.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1) ;
                    if (j > 0) {
                        b.iushrn(j);
                        while (j-- > 0) {
                            if (x2.isOdd()) {
                                x2.iadd(delta);
                            }
                            x2.iushrn(1);
                        }
                    }
                    if (a.cmp(b) >= 0) {
                        a.isub(b);
                        x1.isub(x2);
                    } else {
                        b.isub(a);
                        x2.isub(x1);
                    }
                }
                var res;
                if (a.cmpn(1) === 0) {
                    res = x1;
                } else {
                    res = x2;
                }
                if (res.cmpn(0) < 0) {
                    res.iadd(p);
                }
                return res;
            };
            BN.prototype.gcd = function gcd(num) {
                if (this.isZero()) return num.abs();
                if (num.isZero()) return this.abs();
                var a = this.clone();
                var b = num.clone();
                a.negative = 0;
                b.negative = 0;
                for (var shift = 0; a.isEven() && b.isEven(); shift++) {
                    a.iushrn(1);
                    b.iushrn(1);
                }
                do {
                    while (a.isEven()) {
                        a.iushrn(1);
                    }
                    while (b.isEven()) {
                        b.iushrn(1);
                    }
                    var r = a.cmp(b);
                    if (r < 0) {
                        var t = a;
                        a = b;
                        b = t;
                    } else if (r === 0 || b.cmpn(1) === 0) {
                        break;
                    }
                    a.isub(b);
                } while (true);
                return b.iushln(shift);
            };
            BN.prototype.invm = function invm(num) {
                return this.egcd(num).a.umod(num);
            };
            BN.prototype.isEven = function isEven() {
                return (this.words[0] & 1) === 0;
            };
            BN.prototype.isOdd = function isOdd() {
                return (this.words[0] & 1) === 1;
            };
            BN.prototype.andln = function andln(num) {
                return this.words[0] & num;
            };
            BN.prototype.bincn = function bincn(bit) {
                assert(typeof bit === "number");
                var r = bit % 26;
                var s = (bit - r) / 26;
                var q = 1 << r;
                if (this.length <= s) {
                    this._expand(s + 1);
                    this.words[s] |= q;
                    return this;
                }
                var carry = q;
                for (var i = s; carry !== 0 && i < this.length; i++) {
                    var w = this.words[i] | 0;
                    w += carry;
                    carry = w >>> 26;
                    w &= 67108863;
                    this.words[i] = w;
                }
                if (carry !== 0) {
                    this.words[i] = carry;
                    this.length++;
                }
                return this;
            };
            BN.prototype.isZero = function isZero() {
                return this.length === 1 && this.words[0] === 0;
            };
            BN.prototype.cmpn = function cmpn(num) {
                var negative = num < 0;
                if (this.negative !== 0 && !negative) return -1;
                if (this.negative === 0 && negative) return 1;
                this.strip();
                var res;
                if (this.length > 1) {
                    res = 1;
                } else {
                    if (negative) {
                        num = -num;
                    }
                    assert(num <= 67108863, "Number is too big");
                    var w = this.words[0] | 0;
                    res = w === num ? 0 : w < num ? -1 : 1;
                }
                if (this.negative !== 0) return -res | 0;
                return res;
            };
            BN.prototype.cmp = function cmp(num) {
                if (this.negative !== 0 && num.negative === 0) return -1;
                if (this.negative === 0 && num.negative !== 0) return 1;
                var res = this.ucmp(num);
                if (this.negative !== 0) return -res | 0;
                return res;
            };
            BN.prototype.ucmp = function ucmp(num) {
                if (this.length > num.length) return 1;
                if (this.length < num.length) return -1;
                var res = 0;
                for (var i = this.length - 1; i >= 0; i--) {
                    var a = this.words[i] | 0;
                    var b = num.words[i] | 0;
                    if (a === b) continue;
                    if (a < b) {
                        res = -1;
                    } else if (a > b) {
                        res = 1;
                    }
                    break;
                }
                return res;
            };
            BN.prototype.gtn = function gtn(num) {
                return this.cmpn(num) === 1;
            };
            BN.prototype.gt = function gt(num) {
                return this.cmp(num) === 1;
            };
            BN.prototype.gten = function gten(num) {
                return this.cmpn(num) >= 0;
            };
            BN.prototype.gte = function gte(num) {
                return this.cmp(num) >= 0;
            };
            BN.prototype.ltn = function ltn(num) {
                return this.cmpn(num) === -1;
            };
            BN.prototype.lt = function lt(num) {
                return this.cmp(num) === -1;
            };
            BN.prototype.lten = function lten(num) {
                return this.cmpn(num) <= 0;
            };
            BN.prototype.lte = function lte(num) {
                return this.cmp(num) <= 0;
            };
            BN.prototype.eqn = function eqn(num) {
                return this.cmpn(num) === 0;
            };
            BN.prototype.eq = function eq(num) {
                return this.cmp(num) === 0;
            };
            BN.red = function red(num) {
                return new Red(num);
            };
            BN.prototype.toRed = function toRed(ctx) {
                assert(!this.red, "Already a number in reduction context");
                assert(this.negative === 0, "red works only with positives");
                return ctx.convertTo(this)._forceRed(ctx);
            };
            BN.prototype.fromRed = function fromRed() {
                assert(this.red, "fromRed works only with numbers in reduction context");
                return this.red.convertFrom(this);
            };
            BN.prototype._forceRed = function _forceRed(ctx) {
                this.red = ctx;
                return this;
            };
            BN.prototype.forceRed = function forceRed(ctx) {
                assert(!this.red, "Already a number in reduction context");
                return this._forceRed(ctx);
            };
            BN.prototype.redAdd = function redAdd(num) {
                assert(this.red, "redAdd works only with red numbers");
                return this.red.add(this, num);
            };
            BN.prototype.redIAdd = function redIAdd(num) {
                assert(this.red, "redIAdd works only with red numbers");
                return this.red.iadd(this, num);
            };
            BN.prototype.redSub = function redSub(num) {
                assert(this.red, "redSub works only with red numbers");
                return this.red.sub(this, num);
            };
            BN.prototype.redISub = function redISub(num) {
                assert(this.red, "redISub works only with red numbers");
                return this.red.isub(this, num);
            };
            BN.prototype.redShl = function redShl(num) {
                assert(this.red, "redShl works only with red numbers");
                return this.red.shl(this, num);
            };
            BN.prototype.redMul = function redMul(num) {
                assert(this.red, "redMul works only with red numbers");
                this.red._verify2(this, num);
                return this.red.mul(this, num);
            };
            BN.prototype.redIMul = function redIMul(num) {
                assert(this.red, "redMul works only with red numbers");
                this.red._verify2(this, num);
                return this.red.imul(this, num);
            };
            BN.prototype.redSqr = function redSqr() {
                assert(this.red, "redSqr works only with red numbers");
                this.red._verify1(this);
                return this.red.sqr(this);
            };
            BN.prototype.redISqr = function redISqr() {
                assert(this.red, "redISqr works only with red numbers");
                this.red._verify1(this);
                return this.red.isqr(this);
            };
            BN.prototype.redSqrt = function redSqrt() {
                assert(this.red, "redSqrt works only with red numbers");
                this.red._verify1(this);
                return this.red.sqrt(this);
            };
            BN.prototype.redInvm = function redInvm() {
                assert(this.red, "redInvm works only with red numbers");
                this.red._verify1(this);
                return this.red.invm(this);
            };
            BN.prototype.redNeg = function redNeg() {
                assert(this.red, "redNeg works only with red numbers");
                this.red._verify1(this);
                return this.red.neg(this);
            };
            BN.prototype.redPow = function redPow(num) {
                assert(this.red && !num.red, "redPow(normalNum)");
                this.red._verify1(this);
                return this.red.pow(this, num);
            };
            var primes = {
                k256: null,
                p224: null,
                p192: null,
                p25519: null
            };
            function MPrime(name, p) {
                this.name = name;
                this.p = new BN(p, 16);
                this.n = this.p.bitLength();
                this.k = new BN(1).iushln(this.n).isub(this.p);
                this.tmp = this._tmp();
            }
            MPrime.prototype._tmp = function _tmp() {
                var tmp = new BN(null);
                tmp.words = new Array(Math.ceil(this.n / 13));
                return tmp;
            };
            MPrime.prototype.ireduce = function ireduce(num) {
                var r = num;
                var rlen;
                do {
                    this.split(r, this.tmp);
                    r = this.imulK(r);
                    r = r.iadd(this.tmp);
                    rlen = r.bitLength();
                } while (rlen > this.n);
                var cmp = rlen < this.n ? -1 : r.ucmp(this.p);
                if (cmp === 0) {
                    r.words[0] = 0;
                    r.length = 1;
                } else if (cmp > 0) {
                    r.isub(this.p);
                } else {
                    r.strip();
                }
                return r;
            };
            MPrime.prototype.split = function split(input, out) {
                input.iushrn(this.n, 0, out);
            };
            MPrime.prototype.imulK = function imulK(num) {
                return num.imul(this.k);
            };
            function K256() {
                MPrime.call(this, "k256", "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f");
            }
            inherits(K256, MPrime);
            K256.prototype.split = function split(input, output) {
                var mask = 4194303;
                var outLen = Math.min(input.length, 9);
                for (var i = 0; i < outLen; i++) {
                    output.words[i] = input.words[i];
                }
                output.length = outLen;
                if (input.length <= 9) {
                    input.words[0] = 0;
                    input.length = 1;
                    return;
                }
                var prev = input.words[9];
                output.words[output.length++] = prev & mask;
                for (i = 10; i < input.length; i++) {
                    var next = input.words[i] | 0;
                    input.words[i - 10] = (next & mask) << 4 | prev >>> 22;
                    prev = next;
                }
                prev >>>= 22;
                input.words[i - 10] = prev;
                if (prev === 0 && input.length > 10) {
                    input.length -= 10;
                } else {
                    input.length -= 9;
                }
            };
            K256.prototype.imulK = function imulK(num) {
                num.words[num.length] = 0;
                num.words[num.length + 1] = 0;
                num.length += 2;
                var lo = 0;
                for (var i = 0; i < num.length; i++) {
                    var w = num.words[i] | 0;
                    lo += w * 977;
                    num.words[i] = lo & 67108863;
                    lo = w * 64 + (lo / 67108864 | 0);
                }
                if (num.words[num.length - 1] === 0) {
                    num.length--;
                    if (num.words[num.length - 1] === 0) {
                        num.length--;
                    }
                }
                return num;
            };
            function P224() {
                MPrime.call(this, "p224", "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001");
            }
            inherits(P224, MPrime);
            function P192() {
                MPrime.call(this, "p192", "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff");
            }
            inherits(P192, MPrime);
            function P25519() {
                MPrime.call(this, "25519", "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed");
            }
            inherits(P25519, MPrime);
            P25519.prototype.imulK = function imulK(num) {
                var carry = 0;
                for (var i = 0; i < num.length; i++) {
                    var hi = (num.words[i] | 0) * 19 + carry;
                    var lo = hi & 67108863;
                    hi >>>= 26;
                    num.words[i] = lo;
                    carry = hi;
                }
                if (carry !== 0) {
                    num.words[num.length++] = carry;
                }
                return num;
            };
            BN._prime = function prime(name) {
                if (primes[name]) return primes[name];
                var prime;
                if (name === "k256") {
                    prime = new K256();
                } else if (name === "p224") {
                    prime = new P224();
                } else if (name === "p192") {
                    prime = new P192();
                } else if (name === "p25519") {
                    prime = new P25519();
                } else {
                    throw new Error("Unknown prime " + name);
                }
                primes[name] = prime;
                return prime;
            };
            function Red(m) {
                if (typeof m === "string") {
                    var prime = BN._prime(m);
                    this.m = prime.p;
                    this.prime = prime;
                } else {
                    assert(m.gtn(1), "modulus must be greater than 1");
                    this.m = m;
                    this.prime = null;
                }
            }
            Red.prototype._verify1 = function _verify1(a) {
                assert(a.negative === 0, "red works only with positives");
                assert(a.red, "red works only with red numbers");
            };
            Red.prototype._verify2 = function _verify2(a, b) {
                assert((a.negative | b.negative) === 0, "red works only with positives");
                assert(a.red && a.red === b.red, "red works only with red numbers");
            };
            Red.prototype.imod = function imod(a) {
                if (this.prime) return this.prime.ireduce(a)._forceRed(this);
                return a.umod(this.m)._forceRed(this);
            };
            Red.prototype.neg = function neg(a) {
                if (a.isZero()) {
                    return a.clone();
                }
                return this.m.sub(a)._forceRed(this);
            };
            Red.prototype.add = function add(a, b) {
                this._verify2(a, b);
                var res = a.add(b);
                if (res.cmp(this.m) >= 0) {
                    res.isub(this.m);
                }
                return res._forceRed(this);
            };
            Red.prototype.iadd = function iadd(a, b) {
                this._verify2(a, b);
                var res = a.iadd(b);
                if (res.cmp(this.m) >= 0) {
                    res.isub(this.m);
                }
                return res;
            };
            Red.prototype.sub = function sub(a, b) {
                this._verify2(a, b);
                var res = a.sub(b);
                if (res.cmpn(0) < 0) {
                    res.iadd(this.m);
                }
                return res._forceRed(this);
            };
            Red.prototype.isub = function isub(a, b) {
                this._verify2(a, b);
                var res = a.isub(b);
                if (res.cmpn(0) < 0) {
                    res.iadd(this.m);
                }
                return res;
            };
            Red.prototype.shl = function shl(a, num) {
                this._verify1(a);
                return this.imod(a.ushln(num));
            };
            Red.prototype.imul = function imul(a, b) {
                this._verify2(a, b);
                return this.imod(a.imul(b));
            };
            Red.prototype.mul = function mul(a, b) {
                this._verify2(a, b);
                return this.imod(a.mul(b));
            };
            Red.prototype.isqr = function isqr(a) {
                return this.imul(a, a.clone());
            };
            Red.prototype.sqr = function sqr(a) {
                return this.mul(a, a);
            };
            Red.prototype.sqrt = function sqrt(a) {
                if (a.isZero()) return a.clone();
                var mod3 = this.m.andln(3);
                assert(mod3 % 2 === 1);
                if (mod3 === 3) {
                    var pow = this.m.add(new BN(1)).iushrn(2);
                    return this.pow(a, pow);
                }
                var q = this.m.subn(1);
                var s = 0;
                while (!q.isZero() && q.andln(1) === 0) {
                    s++;
                    q.iushrn(1);
                }
                assert(!q.isZero());
                var one = new BN(1).toRed(this);
                var nOne = one.redNeg();
                var lpow = this.m.subn(1).iushrn(1);
                var z = this.m.bitLength();
                z = new BN(2 * z * z).toRed(this);
                while (this.pow(z, lpow).cmp(nOne) !== 0) {
                    z.redIAdd(nOne);
                }
                var c = this.pow(z, q);
                var r = this.pow(a, q.addn(1).iushrn(1));
                var t = this.pow(a, q);
                var m = s;
                while (t.cmp(one) !== 0) {
                    var tmp = t;
                    for (var i = 0; tmp.cmp(one) !== 0; i++) {
                        tmp = tmp.redSqr();
                    }
                    assert(i < m);
                    var b = this.pow(c, new BN(1).iushln(m - i - 1));
                    r = r.redMul(b);
                    c = b.redSqr();
                    t = t.redMul(c);
                    m = i;
                }
                return r;
            };
            Red.prototype.invm = function invm(a) {
                var inv = a._invmp(this.m);
                if (inv.negative !== 0) {
                    inv.negative = 0;
                    return this.imod(inv).redNeg();
                } else {
                    return this.imod(inv);
                }
            };
            Red.prototype.pow = function pow(a, num) {
                if (num.isZero()) return new BN(1).toRed(this);
                if (num.cmpn(1) === 0) return a.clone();
                var windowSize = 4;
                var wnd = new Array(1 << windowSize);
                wnd[0] = new BN(1).toRed(this);
                wnd[1] = a;
                for (var i = 2; i < wnd.length; i++) {
                    wnd[i] = this.mul(wnd[i - 1], a);
                }
                var res = wnd[0];
                var current = 0;
                var currentLen = 0;
                var start = num.bitLength() % 26;
                if (start === 0) {
                    start = 26;
                }
                for (i = num.length - 1; i >= 0; i--) {
                    var word = num.words[i];
                    for (var j = start - 1; j >= 0; j--) {
                        var bit = word >> j & 1;
                        if (res !== wnd[0]) {
                            res = this.sqr(res);
                        }
                        if (bit === 0 && current === 0) {
                            currentLen = 0;
                            continue;
                        }
                        current <<= 1;
                        current |= bit;
                        currentLen++;
                        if (currentLen !== windowSize && (i !== 0 || j !== 0)) continue;
                        res = this.mul(res, wnd[current]);
                        currentLen = 0;
                        current = 0;
                    }
                    start = 26;
                }
                return res;
            };
            Red.prototype.convertTo = function convertTo(num) {
                var r = num.umod(this.m);
                return r === num ? r.clone() : r;
            };
            Red.prototype.convertFrom = function convertFrom(num) {
                var res = num.clone();
                res.red = null;
                return res;
            };
            BN.mont = function mont(num) {
                return new Mont(num);
            };
            function Mont(m) {
                Red.call(this, m);
                this.shift = this.m.bitLength();
                if (this.shift % 26 !== 0) {
                    this.shift += 26 - this.shift % 26;
                }
                this.r = new BN(1).iushln(this.shift);
                this.r2 = this.imod(this.r.sqr());
                this.rinv = this.r._invmp(this.m);
                this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
                this.minv = this.minv.umod(this.r);
                this.minv = this.r.sub(this.minv);
            }
            inherits(Mont, Red);
            Mont.prototype.convertTo = function convertTo(num) {
                return this.imod(num.ushln(this.shift));
            };
            Mont.prototype.convertFrom = function convertFrom(num) {
                var r = this.imod(num.mul(this.rinv));
                r.red = null;
                return r;
            };
            Mont.prototype.imul = function imul(a, b) {
                if (a.isZero() || b.isZero()) {
                    a.words[0] = 0;
                    a.length = 1;
                    return a;
                }
                var t = a.imul(b);
                var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
                var u = t.isub(c).iushrn(this.shift);
                var res = u;
                if (u.cmp(this.m) >= 0) {
                    res = u.isub(this.m);
                } else if (u.cmpn(0) < 0) {
                    res = u.iadd(this.m);
                }
                return res._forceRed(this);
            };
            Mont.prototype.mul = function mul(a, b) {
                if (a.isZero() || b.isZero()) return new BN(0)._forceRed(this);
                var t = a.mul(b);
                var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
                var u = t.isub(c).iushrn(this.shift);
                var res = u;
                if (u.cmp(this.m) >= 0) {
                    res = u.isub(this.m);
                } else if (u.cmpn(0) < 0) {
                    res = u.iadd(this.m);
                }
                return res._forceRed(this);
            };
            Mont.prototype.invm = function invm(a) {
                var res = this.imod(a._invmp(this.m).mul(this.r2));
                return res._forceRed(this);
            };
        })(typeof module === "undefined" || module, this);
    }, {
        buffer: 25
    } ],
    24: [ function(require, module, exports) {
        var r;
        module.exports = function rand(len) {
            if (!r) r = new Rand(null);
            return r.generate(len);
        };
        function Rand(rand) {
            this.rand = rand;
        }
        module.exports.Rand = Rand;
        Rand.prototype.generate = function generate(len) {
            return this._rand(len);
        };
        Rand.prototype._rand = function _rand(n) {
            if (this.rand.getBytes) return this.rand.getBytes(n);
            var res = new Uint8Array(n);
            for (var i = 0; i < res.length; i++) res[i] = this.rand.getByte();
            return res;
        };
        if (typeof self === "object") {
            if (self.crypto && self.crypto.getRandomValues) {
                Rand.prototype._rand = function _rand(n) {
                    var arr = new Uint8Array(n);
                    self.crypto.getRandomValues(arr);
                    return arr;
                };
            } else if (self.msCrypto && self.msCrypto.getRandomValues) {
                Rand.prototype._rand = function _rand(n) {
                    var arr = new Uint8Array(n);
                    self.msCrypto.getRandomValues(arr);
                    return arr;
                };
            } else if (typeof window === "object") {
                Rand.prototype._rand = function() {
                    throw new Error("Not implemented yet");
                };
            }
        } else {
            try {
                var crypto = require("crypto");
                if (typeof crypto.randomBytes !== "function") throw new Error("Not supported");
                Rand.prototype._rand = function _rand(n) {
                    return crypto.randomBytes(n);
                };
            } catch (e) {}
        }
    }, {
        crypto: 25
    } ],
    25: [ function(require, module, exports) {}, {} ],
    26: [ function(require, module, exports) {
        (function(Buffer) {
            var uint_max = Math.pow(2, 32);
            function fixup_uint32(x) {
                var ret, x_pos;
                ret = x > uint_max || x < 0 ? (x_pos = Math.abs(x) % uint_max, x < 0 ? uint_max - x_pos : x_pos) : x;
                return ret;
            }
            function scrub_vec(v) {
                for (var i = 0; i < v.length; v++) {
                    v[i] = 0;
                }
                return false;
            }
            function Global() {
                this.SBOX = [];
                this.INV_SBOX = [];
                this.SUB_MIX = [ [], [], [], [] ];
                this.INV_SUB_MIX = [ [], [], [], [] ];
                this.init();
                this.RCON = [ 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 ];
            }
            Global.prototype.init = function() {
                var d, i, sx, t, x, x2, x4, x8, xi, _i;
                d = function() {
                    var _i, _results;
                    _results = [];
                    for (i = _i = 0; _i < 256; i = ++_i) {
                        if (i < 128) {
                            _results.push(i << 1);
                        } else {
                            _results.push(i << 1 ^ 283);
                        }
                    }
                    return _results;
                }();
                x = 0;
                xi = 0;
                for (i = _i = 0; _i < 256; i = ++_i) {
                    sx = xi ^ xi << 1 ^ xi << 2 ^ xi << 3 ^ xi << 4;
                    sx = sx >>> 8 ^ sx & 255 ^ 99;
                    this.SBOX[x] = sx;
                    this.INV_SBOX[sx] = x;
                    x2 = d[x];
                    x4 = d[x2];
                    x8 = d[x4];
                    t = d[sx] * 257 ^ sx * 16843008;
                    this.SUB_MIX[0][x] = t << 24 | t >>> 8;
                    this.SUB_MIX[1][x] = t << 16 | t >>> 16;
                    this.SUB_MIX[2][x] = t << 8 | t >>> 24;
                    this.SUB_MIX[3][x] = t;
                    t = x8 * 16843009 ^ x4 * 65537 ^ x2 * 257 ^ x * 16843008;
                    this.INV_SUB_MIX[0][sx] = t << 24 | t >>> 8;
                    this.INV_SUB_MIX[1][sx] = t << 16 | t >>> 16;
                    this.INV_SUB_MIX[2][sx] = t << 8 | t >>> 24;
                    this.INV_SUB_MIX[3][sx] = t;
                    if (x === 0) {
                        x = xi = 1;
                    } else {
                        x = x2 ^ d[d[d[x8 ^ x2]]];
                        xi ^= d[d[xi]];
                    }
                }
                return true;
            };
            var G = new Global();
            AES.blockSize = 4 * 4;
            AES.prototype.blockSize = AES.blockSize;
            AES.keySize = 256 / 8;
            AES.prototype.keySize = AES.keySize;
            function bufferToArray(buf) {
                var len = buf.length / 4;
                var out = new Array(len);
                var i = -1;
                while (++i < len) {
                    out[i] = buf.readUInt32BE(i * 4);
                }
                return out;
            }
            function AES(key) {
                this._key = bufferToArray(key);
                this._doReset();
            }
            AES.prototype._doReset = function() {
                var invKsRow, keySize, keyWords, ksRow, ksRows, t;
                keyWords = this._key;
                keySize = keyWords.length;
                this._nRounds = keySize + 6;
                ksRows = (this._nRounds + 1) * 4;
                this._keySchedule = [];
                for (ksRow = 0; ksRow < ksRows; ksRow++) {
                    this._keySchedule[ksRow] = ksRow < keySize ? keyWords[ksRow] : (t = this._keySchedule[ksRow - 1], 
                    ksRow % keySize === 0 ? (t = t << 8 | t >>> 24, t = G.SBOX[t >>> 24] << 24 | G.SBOX[t >>> 16 & 255] << 16 | G.SBOX[t >>> 8 & 255] << 8 | G.SBOX[t & 255], 
                    t ^= G.RCON[ksRow / keySize | 0] << 24) : keySize > 6 && ksRow % keySize === 4 ? t = G.SBOX[t >>> 24] << 24 | G.SBOX[t >>> 16 & 255] << 16 | G.SBOX[t >>> 8 & 255] << 8 | G.SBOX[t & 255] : void 0, 
                    this._keySchedule[ksRow - keySize] ^ t);
                }
                this._invKeySchedule = [];
                for (invKsRow = 0; invKsRow < ksRows; invKsRow++) {
                    ksRow = ksRows - invKsRow;
                    t = this._keySchedule[ksRow - (invKsRow % 4 ? 0 : 4)];
                    this._invKeySchedule[invKsRow] = invKsRow < 4 || ksRow <= 4 ? t : G.INV_SUB_MIX[0][G.SBOX[t >>> 24]] ^ G.INV_SUB_MIX[1][G.SBOX[t >>> 16 & 255]] ^ G.INV_SUB_MIX[2][G.SBOX[t >>> 8 & 255]] ^ G.INV_SUB_MIX[3][G.SBOX[t & 255]];
                }
                return true;
            };
            AES.prototype.encryptBlock = function(M) {
                M = bufferToArray(new Buffer(M));
                var out = this._doCryptBlock(M, this._keySchedule, G.SUB_MIX, G.SBOX);
                var buf = new Buffer(16);
                buf.writeUInt32BE(out[0], 0);
                buf.writeUInt32BE(out[1], 4);
                buf.writeUInt32BE(out[2], 8);
                buf.writeUInt32BE(out[3], 12);
                return buf;
            };
            AES.prototype.decryptBlock = function(M) {
                M = bufferToArray(new Buffer(M));
                var temp = [ M[3], M[1] ];
                M[1] = temp[0];
                M[3] = temp[1];
                var out = this._doCryptBlock(M, this._invKeySchedule, G.INV_SUB_MIX, G.INV_SBOX);
                var buf = new Buffer(16);
                buf.writeUInt32BE(out[0], 0);
                buf.writeUInt32BE(out[3], 4);
                buf.writeUInt32BE(out[2], 8);
                buf.writeUInt32BE(out[1], 12);
                return buf;
            };
            AES.prototype.scrub = function() {
                scrub_vec(this._keySchedule);
                scrub_vec(this._invKeySchedule);
                scrub_vec(this._key);
            };
            AES.prototype._doCryptBlock = function(M, keySchedule, SUB_MIX, SBOX) {
                var ksRow, s0, s1, s2, s3, t0, t1, t2, t3;
                s0 = M[0] ^ keySchedule[0];
                s1 = M[1] ^ keySchedule[1];
                s2 = M[2] ^ keySchedule[2];
                s3 = M[3] ^ keySchedule[3];
                ksRow = 4;
                for (var round = 1; round < this._nRounds; round++) {
                    t0 = SUB_MIX[0][s0 >>> 24] ^ SUB_MIX[1][s1 >>> 16 & 255] ^ SUB_MIX[2][s2 >>> 8 & 255] ^ SUB_MIX[3][s3 & 255] ^ keySchedule[ksRow++];
                    t1 = SUB_MIX[0][s1 >>> 24] ^ SUB_MIX[1][s2 >>> 16 & 255] ^ SUB_MIX[2][s3 >>> 8 & 255] ^ SUB_MIX[3][s0 & 255] ^ keySchedule[ksRow++];
                    t2 = SUB_MIX[0][s2 >>> 24] ^ SUB_MIX[1][s3 >>> 16 & 255] ^ SUB_MIX[2][s0 >>> 8 & 255] ^ SUB_MIX[3][s1 & 255] ^ keySchedule[ksRow++];
                    t3 = SUB_MIX[0][s3 >>> 24] ^ SUB_MIX[1][s0 >>> 16 & 255] ^ SUB_MIX[2][s1 >>> 8 & 255] ^ SUB_MIX[3][s2 & 255] ^ keySchedule[ksRow++];
                    s0 = t0;
                    s1 = t1;
                    s2 = t2;
                    s3 = t3;
                }
                t0 = (SBOX[s0 >>> 24] << 24 | SBOX[s1 >>> 16 & 255] << 16 | SBOX[s2 >>> 8 & 255] << 8 | SBOX[s3 & 255]) ^ keySchedule[ksRow++];
                t1 = (SBOX[s1 >>> 24] << 24 | SBOX[s2 >>> 16 & 255] << 16 | SBOX[s3 >>> 8 & 255] << 8 | SBOX[s0 & 255]) ^ keySchedule[ksRow++];
                t2 = (SBOX[s2 >>> 24] << 24 | SBOX[s3 >>> 16 & 255] << 16 | SBOX[s0 >>> 8 & 255] << 8 | SBOX[s1 & 255]) ^ keySchedule[ksRow++];
                t3 = (SBOX[s3 >>> 24] << 24 | SBOX[s0 >>> 16 & 255] << 16 | SBOX[s1 >>> 8 & 255] << 8 | SBOX[s2 & 255]) ^ keySchedule[ksRow++];
                return [ fixup_uint32(t0), fixup_uint32(t1), fixup_uint32(t2), fixup_uint32(t3) ];
            };
            exports.AES = AES;
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    27: [ function(require, module, exports) {
        (function(Buffer) {
            var aes = require("./aes");
            var Transform = require("cipher-base");
            var inherits = require("inherits");
            var GHASH = require("./ghash");
            var xor = require("buffer-xor");
            inherits(StreamCipher, Transform);
            module.exports = StreamCipher;
            function StreamCipher(mode, key, iv, decrypt) {
                if (!(this instanceof StreamCipher)) {
                    return new StreamCipher(mode, key, iv);
                }
                Transform.call(this);
                this._finID = Buffer.concat([ iv, new Buffer([ 0, 0, 0, 1 ]) ]);
                iv = Buffer.concat([ iv, new Buffer([ 0, 0, 0, 2 ]) ]);
                this._cipher = new aes.AES(key);
                this._prev = new Buffer(iv.length);
                this._cache = new Buffer("");
                this._secCache = new Buffer("");
                this._decrypt = decrypt;
                this._alen = 0;
                this._len = 0;
                iv.copy(this._prev);
                this._mode = mode;
                var h = new Buffer(4);
                h.fill(0);
                this._ghash = new GHASH(this._cipher.encryptBlock(h));
                this._authTag = null;
                this._called = false;
            }
            StreamCipher.prototype._update = function(chunk) {
                if (!this._called && this._alen) {
                    var rump = 16 - this._alen % 16;
                    if (rump < 16) {
                        rump = new Buffer(rump);
                        rump.fill(0);
                        this._ghash.update(rump);
                    }
                }
                this._called = true;
                var out = this._mode.encrypt(this, chunk);
                if (this._decrypt) {
                    this._ghash.update(chunk);
                } else {
                    this._ghash.update(out);
                }
                this._len += chunk.length;
                return out;
            };
            StreamCipher.prototype._final = function() {
                if (this._decrypt && !this._authTag) {
                    throw new Error("Unsupported state or unable to authenticate data");
                }
                var tag = xor(this._ghash.final(this._alen * 8, this._len * 8), this._cipher.encryptBlock(this._finID));
                if (this._decrypt) {
                    if (xorTest(tag, this._authTag)) {
                        throw new Error("Unsupported state or unable to authenticate data");
                    }
                } else {
                    this._authTag = tag;
                }
                this._cipher.scrub();
            };
            StreamCipher.prototype.getAuthTag = function getAuthTag() {
                if (!this._decrypt && Buffer.isBuffer(this._authTag)) {
                    return this._authTag;
                } else {
                    throw new Error("Attempting to get auth tag in unsupported state");
                }
            };
            StreamCipher.prototype.setAuthTag = function setAuthTag(tag) {
                if (this._decrypt) {
                    this._authTag = tag;
                } else {
                    throw new Error("Attempting to set auth tag in unsupported state");
                }
            };
            StreamCipher.prototype.setAAD = function setAAD(buf) {
                if (!this._called) {
                    this._ghash.update(buf);
                    this._alen += buf.length;
                } else {
                    throw new Error("Attempting to set AAD in unsupported state");
                }
            };
            function xorTest(a, b) {
                var out = 0;
                if (a.length !== b.length) {
                    out++;
                }
                var len = Math.min(a.length, b.length);
                var i = -1;
                while (++i < len) {
                    out += a[i] ^ b[i];
                }
                return out;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "./aes": 26,
        "./ghash": 31,
        buffer: 54,
        "buffer-xor": 53,
        "cipher-base": 55,
        inherits: 122
    } ],
    28: [ function(require, module, exports) {
        var ciphers = require("./encrypter");
        exports.createCipher = exports.Cipher = ciphers.createCipher;
        exports.createCipheriv = exports.Cipheriv = ciphers.createCipheriv;
        var deciphers = require("./decrypter");
        exports.createDecipher = exports.Decipher = deciphers.createDecipher;
        exports.createDecipheriv = exports.Decipheriv = deciphers.createDecipheriv;
        var modes = require("./modes");
        function getCiphers() {
            return Object.keys(modes);
        }
        exports.listCiphers = exports.getCiphers = getCiphers;
    }, {
        "./decrypter": 29,
        "./encrypter": 30,
        "./modes": 32
    } ],
    29: [ function(require, module, exports) {
        (function(Buffer) {
            var aes = require("./aes");
            var Transform = require("cipher-base");
            var inherits = require("inherits");
            var modes = require("./modes");
            var StreamCipher = require("./streamCipher");
            var AuthCipher = require("./authCipher");
            var ebtk = require("evp_bytestokey");
            inherits(Decipher, Transform);
            function Decipher(mode, key, iv) {
                if (!(this instanceof Decipher)) {
                    return new Decipher(mode, key, iv);
                }
                Transform.call(this);
                this._cache = new Splitter();
                this._last = void 0;
                this._cipher = new aes.AES(key);
                this._prev = new Buffer(iv.length);
                iv.copy(this._prev);
                this._mode = mode;
                this._autopadding = true;
            }
            Decipher.prototype._update = function(data) {
                this._cache.add(data);
                var chunk;
                var thing;
                var out = [];
                while (chunk = this._cache.get(this._autopadding)) {
                    thing = this._mode.decrypt(this, chunk);
                    out.push(thing);
                }
                return Buffer.concat(out);
            };
            Decipher.prototype._final = function() {
                var chunk = this._cache.flush();
                if (this._autopadding) {
                    return unpad(this._mode.decrypt(this, chunk));
                } else if (chunk) {
                    throw new Error("data not multiple of block length");
                }
            };
            Decipher.prototype.setAutoPadding = function(setTo) {
                this._autopadding = !!setTo;
                return this;
            };
            function Splitter() {
                if (!(this instanceof Splitter)) {
                    return new Splitter();
                }
                this.cache = new Buffer("");
            }
            Splitter.prototype.add = function(data) {
                this.cache = Buffer.concat([ this.cache, data ]);
            };
            Splitter.prototype.get = function(autoPadding) {
                var out;
                if (autoPadding) {
                    if (this.cache.length > 16) {
                        out = this.cache.slice(0, 16);
                        this.cache = this.cache.slice(16);
                        return out;
                    }
                } else {
                    if (this.cache.length >= 16) {
                        out = this.cache.slice(0, 16);
                        this.cache = this.cache.slice(16);
                        return out;
                    }
                }
                return null;
            };
            Splitter.prototype.flush = function() {
                if (this.cache.length) {
                    return this.cache;
                }
            };
            function unpad(last) {
                var padded = last[15];
                var i = -1;
                while (++i < padded) {
                    if (last[i + (16 - padded)] !== padded) {
                        throw new Error("unable to decrypt data");
                    }
                }
                if (padded === 16) {
                    return;
                }
                return last.slice(0, 16 - padded);
            }
            var modelist = {
                ECB: require("./modes/ecb"),
                CBC: require("./modes/cbc"),
                CFB: require("./modes/cfb"),
                CFB8: require("./modes/cfb8"),
                CFB1: require("./modes/cfb1"),
                OFB: require("./modes/ofb"),
                CTR: require("./modes/ctr"),
                GCM: require("./modes/ctr")
            };
            function createDecipheriv(suite, password, iv) {
                var config = modes[suite.toLowerCase()];
                if (!config) {
                    throw new TypeError("invalid suite type");
                }
                if (typeof iv === "string") {
                    iv = new Buffer(iv);
                }
                if (typeof password === "string") {
                    password = new Buffer(password);
                }
                if (password.length !== config.key / 8) {
                    throw new TypeError("invalid key length " + password.length);
                }
                if (iv.length !== config.iv) {
                    throw new TypeError("invalid iv length " + iv.length);
                }
                if (config.type === "stream") {
                    return new StreamCipher(modelist[config.mode], password, iv, true);
                } else if (config.type === "auth") {
                    return new AuthCipher(modelist[config.mode], password, iv, true);
                }
                return new Decipher(modelist[config.mode], password, iv);
            }
            function createDecipher(suite, password) {
                var config = modes[suite.toLowerCase()];
                if (!config) {
                    throw new TypeError("invalid suite type");
                }
                var keys = ebtk(password, false, config.key, config.iv);
                return createDecipheriv(suite, keys.key, keys.iv);
            }
            exports.createDecipher = createDecipher;
            exports.createDecipheriv = createDecipheriv;
        }).call(this, require("buffer").Buffer);
    }, {
        "./aes": 26,
        "./authCipher": 27,
        "./modes": 32,
        "./modes/cbc": 33,
        "./modes/cfb": 34,
        "./modes/cfb1": 35,
        "./modes/cfb8": 36,
        "./modes/ctr": 37,
        "./modes/ecb": 38,
        "./modes/ofb": 39,
        "./streamCipher": 40,
        buffer: 54,
        "cipher-base": 55,
        evp_bytestokey: 104,
        inherits: 122
    } ],
    30: [ function(require, module, exports) {
        (function(Buffer) {
            var aes = require("./aes");
            var Transform = require("cipher-base");
            var inherits = require("inherits");
            var modes = require("./modes");
            var ebtk = require("evp_bytestokey");
            var StreamCipher = require("./streamCipher");
            var AuthCipher = require("./authCipher");
            inherits(Cipher, Transform);
            function Cipher(mode, key, iv) {
                if (!(this instanceof Cipher)) {
                    return new Cipher(mode, key, iv);
                }
                Transform.call(this);
                this._cache = new Splitter();
                this._cipher = new aes.AES(key);
                this._prev = new Buffer(iv.length);
                iv.copy(this._prev);
                this._mode = mode;
                this._autopadding = true;
            }
            Cipher.prototype._update = function(data) {
                this._cache.add(data);
                var chunk;
                var thing;
                var out = [];
                while (chunk = this._cache.get()) {
                    thing = this._mode.encrypt(this, chunk);
                    out.push(thing);
                }
                return Buffer.concat(out);
            };
            Cipher.prototype._final = function() {
                var chunk = this._cache.flush();
                if (this._autopadding) {
                    chunk = this._mode.encrypt(this, chunk);
                    this._cipher.scrub();
                    return chunk;
                } else if (chunk.toString("hex") !== "10101010101010101010101010101010") {
                    this._cipher.scrub();
                    throw new Error("data not multiple of block length");
                }
            };
            Cipher.prototype.setAutoPadding = function(setTo) {
                this._autopadding = !!setTo;
                return this;
            };
            function Splitter() {
                if (!(this instanceof Splitter)) {
                    return new Splitter();
                }
                this.cache = new Buffer("");
            }
            Splitter.prototype.add = function(data) {
                this.cache = Buffer.concat([ this.cache, data ]);
            };
            Splitter.prototype.get = function() {
                if (this.cache.length > 15) {
                    var out = this.cache.slice(0, 16);
                    this.cache = this.cache.slice(16);
                    return out;
                }
                return null;
            };
            Splitter.prototype.flush = function() {
                var len = 16 - this.cache.length;
                var padBuff = new Buffer(len);
                var i = -1;
                while (++i < len) {
                    padBuff.writeUInt8(len, i);
                }
                var out = Buffer.concat([ this.cache, padBuff ]);
                return out;
            };
            var modelist = {
                ECB: require("./modes/ecb"),
                CBC: require("./modes/cbc"),
                CFB: require("./modes/cfb"),
                CFB8: require("./modes/cfb8"),
                CFB1: require("./modes/cfb1"),
                OFB: require("./modes/ofb"),
                CTR: require("./modes/ctr"),
                GCM: require("./modes/ctr")
            };
            function createCipheriv(suite, password, iv) {
                var config = modes[suite.toLowerCase()];
                if (!config) {
                    throw new TypeError("invalid suite type");
                }
                if (typeof iv === "string") {
                    iv = new Buffer(iv);
                }
                if (typeof password === "string") {
                    password = new Buffer(password);
                }
                if (password.length !== config.key / 8) {
                    throw new TypeError("invalid key length " + password.length);
                }
                if (iv.length !== config.iv) {
                    throw new TypeError("invalid iv length " + iv.length);
                }
                if (config.type === "stream") {
                    return new StreamCipher(modelist[config.mode], password, iv);
                } else if (config.type === "auth") {
                    return new AuthCipher(modelist[config.mode], password, iv);
                }
                return new Cipher(modelist[config.mode], password, iv);
            }
            function createCipher(suite, password) {
                var config = modes[suite.toLowerCase()];
                if (!config) {
                    throw new TypeError("invalid suite type");
                }
                var keys = ebtk(password, false, config.key, config.iv);
                return createCipheriv(suite, keys.key, keys.iv);
            }
            exports.createCipheriv = createCipheriv;
            exports.createCipher = createCipher;
        }).call(this, require("buffer").Buffer);
    }, {
        "./aes": 26,
        "./authCipher": 27,
        "./modes": 32,
        "./modes/cbc": 33,
        "./modes/cfb": 34,
        "./modes/cfb1": 35,
        "./modes/cfb8": 36,
        "./modes/ctr": 37,
        "./modes/ecb": 38,
        "./modes/ofb": 39,
        "./streamCipher": 40,
        buffer: 54,
        "cipher-base": 55,
        evp_bytestokey: 104,
        inherits: 122
    } ],
    31: [ function(require, module, exports) {
        (function(Buffer) {
            var zeros = new Buffer(16);
            zeros.fill(0);
            module.exports = GHASH;
            function GHASH(key) {
                this.h = key;
                this.state = new Buffer(16);
                this.state.fill(0);
                this.cache = new Buffer("");
            }
            GHASH.prototype.ghash = function(block) {
                var i = -1;
                while (++i < block.length) {
                    this.state[i] ^= block[i];
                }
                this._multiply();
            };
            GHASH.prototype._multiply = function() {
                var Vi = toArray(this.h);
                var Zi = [ 0, 0, 0, 0 ];
                var j, xi, lsb_Vi;
                var i = -1;
                while (++i < 128) {
                    xi = (this.state[~~(i / 8)] & 1 << 7 - i % 8) !== 0;
                    if (xi) {
                        Zi = xor(Zi, Vi);
                    }
                    lsb_Vi = (Vi[3] & 1) !== 0;
                    for (j = 3; j > 0; j--) {
                        Vi[j] = Vi[j] >>> 1 | (Vi[j - 1] & 1) << 31;
                    }
                    Vi[0] = Vi[0] >>> 1;
                    if (lsb_Vi) {
                        Vi[0] = Vi[0] ^ 225 << 24;
                    }
                }
                this.state = fromArray(Zi);
            };
            GHASH.prototype.update = function(buf) {
                this.cache = Buffer.concat([ this.cache, buf ]);
                var chunk;
                while (this.cache.length >= 16) {
                    chunk = this.cache.slice(0, 16);
                    this.cache = this.cache.slice(16);
                    this.ghash(chunk);
                }
            };
            GHASH.prototype.final = function(abl, bl) {
                if (this.cache.length) {
                    this.ghash(Buffer.concat([ this.cache, zeros ], 16));
                }
                this.ghash(fromArray([ 0, abl, 0, bl ]));
                return this.state;
            };
            function toArray(buf) {
                return [ buf.readUInt32BE(0), buf.readUInt32BE(4), buf.readUInt32BE(8), buf.readUInt32BE(12) ];
            }
            function fromArray(out) {
                out = out.map(fixup_uint32);
                var buf = new Buffer(16);
                buf.writeUInt32BE(out[0], 0);
                buf.writeUInt32BE(out[1], 4);
                buf.writeUInt32BE(out[2], 8);
                buf.writeUInt32BE(out[3], 12);
                return buf;
            }
            var uint_max = Math.pow(2, 32);
            function fixup_uint32(x) {
                var ret, x_pos;
                ret = x > uint_max || x < 0 ? (x_pos = Math.abs(x) % uint_max, x < 0 ? uint_max - x_pos : x_pos) : x;
                return ret;
            }
            function xor(a, b) {
                return [ a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3] ];
            }
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    32: [ function(require, module, exports) {
        exports["aes-128-ecb"] = {
            cipher: "AES",
            key: 128,
            iv: 0,
            mode: "ECB",
            type: "block"
        };
        exports["aes-192-ecb"] = {
            cipher: "AES",
            key: 192,
            iv: 0,
            mode: "ECB",
            type: "block"
        };
        exports["aes-256-ecb"] = {
            cipher: "AES",
            key: 256,
            iv: 0,
            mode: "ECB",
            type: "block"
        };
        exports["aes-128-cbc"] = {
            cipher: "AES",
            key: 128,
            iv: 16,
            mode: "CBC",
            type: "block"
        };
        exports["aes-192-cbc"] = {
            cipher: "AES",
            key: 192,
            iv: 16,
            mode: "CBC",
            type: "block"
        };
        exports["aes-256-cbc"] = {
            cipher: "AES",
            key: 256,
            iv: 16,
            mode: "CBC",
            type: "block"
        };
        exports["aes128"] = exports["aes-128-cbc"];
        exports["aes192"] = exports["aes-192-cbc"];
        exports["aes256"] = exports["aes-256-cbc"];
        exports["aes-128-cfb"] = {
            cipher: "AES",
            key: 128,
            iv: 16,
            mode: "CFB",
            type: "stream"
        };
        exports["aes-192-cfb"] = {
            cipher: "AES",
            key: 192,
            iv: 16,
            mode: "CFB",
            type: "stream"
        };
        exports["aes-256-cfb"] = {
            cipher: "AES",
            key: 256,
            iv: 16,
            mode: "CFB",
            type: "stream"
        };
        exports["aes-128-cfb8"] = {
            cipher: "AES",
            key: 128,
            iv: 16,
            mode: "CFB8",
            type: "stream"
        };
        exports["aes-192-cfb8"] = {
            cipher: "AES",
            key: 192,
            iv: 16,
            mode: "CFB8",
            type: "stream"
        };
        exports["aes-256-cfb8"] = {
            cipher: "AES",
            key: 256,
            iv: 16,
            mode: "CFB8",
            type: "stream"
        };
        exports["aes-128-cfb1"] = {
            cipher: "AES",
            key: 128,
            iv: 16,
            mode: "CFB1",
            type: "stream"
        };
        exports["aes-192-cfb1"] = {
            cipher: "AES",
            key: 192,
            iv: 16,
            mode: "CFB1",
            type: "stream"
        };
        exports["aes-256-cfb1"] = {
            cipher: "AES",
            key: 256,
            iv: 16,
            mode: "CFB1",
            type: "stream"
        };
        exports["aes-128-ofb"] = {
            cipher: "AES",
            key: 128,
            iv: 16,
            mode: "OFB",
            type: "stream"
        };
        exports["aes-192-ofb"] = {
            cipher: "AES",
            key: 192,
            iv: 16,
            mode: "OFB",
            type: "stream"
        };
        exports["aes-256-ofb"] = {
            cipher: "AES",
            key: 256,
            iv: 16,
            mode: "OFB",
            type: "stream"
        };
        exports["aes-128-ctr"] = {
            cipher: "AES",
            key: 128,
            iv: 16,
            mode: "CTR",
            type: "stream"
        };
        exports["aes-192-ctr"] = {
            cipher: "AES",
            key: 192,
            iv: 16,
            mode: "CTR",
            type: "stream"
        };
        exports["aes-256-ctr"] = {
            cipher: "AES",
            key: 256,
            iv: 16,
            mode: "CTR",
            type: "stream"
        };
        exports["aes-128-gcm"] = {
            cipher: "AES",
            key: 128,
            iv: 12,
            mode: "GCM",
            type: "auth"
        };
        exports["aes-192-gcm"] = {
            cipher: "AES",
            key: 192,
            iv: 12,
            mode: "GCM",
            type: "auth"
        };
        exports["aes-256-gcm"] = {
            cipher: "AES",
            key: 256,
            iv: 12,
            mode: "GCM",
            type: "auth"
        };
    }, {} ],
    33: [ function(require, module, exports) {
        var xor = require("buffer-xor");
        exports.encrypt = function(self, block) {
            var data = xor(block, self._prev);
            self._prev = self._cipher.encryptBlock(data);
            return self._prev;
        };
        exports.decrypt = function(self, block) {
            var pad = self._prev;
            self._prev = block;
            var out = self._cipher.decryptBlock(block);
            return xor(out, pad);
        };
    }, {
        "buffer-xor": 53
    } ],
    34: [ function(require, module, exports) {
        (function(Buffer) {
            var xor = require("buffer-xor");
            exports.encrypt = function(self, data, decrypt) {
                var out = new Buffer("");
                var len;
                while (data.length) {
                    if (self._cache.length === 0) {
                        self._cache = self._cipher.encryptBlock(self._prev);
                        self._prev = new Buffer("");
                    }
                    if (self._cache.length <= data.length) {
                        len = self._cache.length;
                        out = Buffer.concat([ out, encryptStart(self, data.slice(0, len), decrypt) ]);
                        data = data.slice(len);
                    } else {
                        out = Buffer.concat([ out, encryptStart(self, data, decrypt) ]);
                        break;
                    }
                }
                return out;
            };
            function encryptStart(self, data, decrypt) {
                var len = data.length;
                var out = xor(data, self._cache);
                self._cache = self._cache.slice(len);
                self._prev = Buffer.concat([ self._prev, decrypt ? data : out ]);
                return out;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "buffer-xor": 53
    } ],
    35: [ function(require, module, exports) {
        (function(Buffer) {
            function encryptByte(self, byteParam, decrypt) {
                var pad;
                var i = -1;
                var len = 8;
                var out = 0;
                var bit, value;
                while (++i < len) {
                    pad = self._cipher.encryptBlock(self._prev);
                    bit = byteParam & 1 << 7 - i ? 128 : 0;
                    value = pad[0] ^ bit;
                    out += (value & 128) >> i % 8;
                    self._prev = shiftIn(self._prev, decrypt ? bit : value);
                }
                return out;
            }
            exports.encrypt = function(self, chunk, decrypt) {
                var len = chunk.length;
                var out = new Buffer(len);
                var i = -1;
                while (++i < len) {
                    out[i] = encryptByte(self, chunk[i], decrypt);
                }
                return out;
            };
            function shiftIn(buffer, value) {
                var len = buffer.length;
                var i = -1;
                var out = new Buffer(buffer.length);
                buffer = Buffer.concat([ buffer, new Buffer([ value ]) ]);
                while (++i < len) {
                    out[i] = buffer[i] << 1 | buffer[i + 1] >> 7;
                }
                return out;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    36: [ function(require, module, exports) {
        (function(Buffer) {
            function encryptByte(self, byteParam, decrypt) {
                var pad = self._cipher.encryptBlock(self._prev);
                var out = pad[0] ^ byteParam;
                self._prev = Buffer.concat([ self._prev.slice(1), new Buffer([ decrypt ? byteParam : out ]) ]);
                return out;
            }
            exports.encrypt = function(self, chunk, decrypt) {
                var len = chunk.length;
                var out = new Buffer(len);
                var i = -1;
                while (++i < len) {
                    out[i] = encryptByte(self, chunk[i], decrypt);
                }
                return out;
            };
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    37: [ function(require, module, exports) {
        (function(Buffer) {
            var xor = require("buffer-xor");
            function incr32(iv) {
                var len = iv.length;
                var item;
                while (len--) {
                    item = iv.readUInt8(len);
                    if (item === 255) {
                        iv.writeUInt8(0, len);
                    } else {
                        item++;
                        iv.writeUInt8(item, len);
                        break;
                    }
                }
            }
            function getBlock(self) {
                var out = self._cipher.encryptBlock(self._prev);
                incr32(self._prev);
                return out;
            }
            exports.encrypt = function(self, chunk) {
                while (self._cache.length < chunk.length) {
                    self._cache = Buffer.concat([ self._cache, getBlock(self) ]);
                }
                var pad = self._cache.slice(0, chunk.length);
                self._cache = self._cache.slice(chunk.length);
                return xor(chunk, pad);
            };
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "buffer-xor": 53
    } ],
    38: [ function(require, module, exports) {
        exports.encrypt = function(self, block) {
            return self._cipher.encryptBlock(block);
        };
        exports.decrypt = function(self, block) {
            return self._cipher.decryptBlock(block);
        };
    }, {} ],
    39: [ function(require, module, exports) {
        (function(Buffer) {
            var xor = require("buffer-xor");
            function getBlock(self) {
                self._prev = self._cipher.encryptBlock(self._prev);
                return self._prev;
            }
            exports.encrypt = function(self, chunk) {
                while (self._cache.length < chunk.length) {
                    self._cache = Buffer.concat([ self._cache, getBlock(self) ]);
                }
                var pad = self._cache.slice(0, chunk.length);
                self._cache = self._cache.slice(chunk.length);
                return xor(chunk, pad);
            };
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "buffer-xor": 53
    } ],
    40: [ function(require, module, exports) {
        (function(Buffer) {
            var aes = require("./aes");
            var Transform = require("cipher-base");
            var inherits = require("inherits");
            inherits(StreamCipher, Transform);
            module.exports = StreamCipher;
            function StreamCipher(mode, key, iv, decrypt) {
                if (!(this instanceof StreamCipher)) {
                    return new StreamCipher(mode, key, iv);
                }
                Transform.call(this);
                this._cipher = new aes.AES(key);
                this._prev = new Buffer(iv.length);
                this._cache = new Buffer("");
                this._secCache = new Buffer("");
                this._decrypt = decrypt;
                iv.copy(this._prev);
                this._mode = mode;
            }
            StreamCipher.prototype._update = function(chunk) {
                return this._mode.encrypt(this, chunk, this._decrypt);
            };
            StreamCipher.prototype._final = function() {
                this._cipher.scrub();
            };
        }).call(this, require("buffer").Buffer);
    }, {
        "./aes": 26,
        buffer: 54,
        "cipher-base": 55,
        inherits: 122
    } ],
    41: [ function(require, module, exports) {
        var ebtk = require("evp_bytestokey");
        var aes = require("browserify-aes/browser");
        var DES = require("browserify-des");
        var desModes = require("browserify-des/modes");
        var aesModes = require("browserify-aes/modes");
        function createCipher(suite, password) {
            var keyLen, ivLen;
            suite = suite.toLowerCase();
            if (aesModes[suite]) {
                keyLen = aesModes[suite].key;
                ivLen = aesModes[suite].iv;
            } else if (desModes[suite]) {
                keyLen = desModes[suite].key * 8;
                ivLen = desModes[suite].iv;
            } else {
                throw new TypeError("invalid suite type");
            }
            var keys = ebtk(password, false, keyLen, ivLen);
            return createCipheriv(suite, keys.key, keys.iv);
        }
        function createDecipher(suite, password) {
            var keyLen, ivLen;
            suite = suite.toLowerCase();
            if (aesModes[suite]) {
                keyLen = aesModes[suite].key;
                ivLen = aesModes[suite].iv;
            } else if (desModes[suite]) {
                keyLen = desModes[suite].key * 8;
                ivLen = desModes[suite].iv;
            } else {
                throw new TypeError("invalid suite type");
            }
            var keys = ebtk(password, false, keyLen, ivLen);
            return createDecipheriv(suite, keys.key, keys.iv);
        }
        function createCipheriv(suite, key, iv) {
            suite = suite.toLowerCase();
            if (aesModes[suite]) {
                return aes.createCipheriv(suite, key, iv);
            } else if (desModes[suite]) {
                return new DES({
                    key: key,
                    iv: iv,
                    mode: suite
                });
            } else {
                throw new TypeError("invalid suite type");
            }
        }
        function createDecipheriv(suite, key, iv) {
            suite = suite.toLowerCase();
            if (aesModes[suite]) {
                return aes.createDecipheriv(suite, key, iv);
            } else if (desModes[suite]) {
                return new DES({
                    key: key,
                    iv: iv,
                    mode: suite,
                    decrypt: true
                });
            } else {
                throw new TypeError("invalid suite type");
            }
        }
        exports.createCipher = exports.Cipher = createCipher;
        exports.createCipheriv = exports.Cipheriv = createCipheriv;
        exports.createDecipher = exports.Decipher = createDecipher;
        exports.createDecipheriv = exports.Decipheriv = createDecipheriv;
        function getCiphers() {
            return Object.keys(desModes).concat(aes.getCiphers());
        }
        exports.listCiphers = exports.getCiphers = getCiphers;
    }, {
        "browserify-aes/browser": 28,
        "browserify-aes/modes": 32,
        "browserify-des": 42,
        "browserify-des/modes": 43,
        evp_bytestokey: 104
    } ],
    42: [ function(require, module, exports) {
        (function(Buffer) {
            var CipherBase = require("cipher-base");
            var des = require("des.js");
            var inherits = require("inherits");
            var modes = {
                "des-ede3-cbc": des.CBC.instantiate(des.EDE),
                "des-ede3": des.EDE,
                "des-ede-cbc": des.CBC.instantiate(des.EDE),
                "des-ede": des.EDE,
                "des-cbc": des.CBC.instantiate(des.DES),
                "des-ecb": des.DES
            };
            modes.des = modes["des-cbc"];
            modes.des3 = modes["des-ede3-cbc"];
            module.exports = DES;
            inherits(DES, CipherBase);
            function DES(opts) {
                CipherBase.call(this);
                var modeName = opts.mode.toLowerCase();
                var mode = modes[modeName];
                var type;
                if (opts.decrypt) {
                    type = "decrypt";
                } else {
                    type = "encrypt";
                }
                var key = opts.key;
                if (modeName === "des-ede" || modeName === "des-ede-cbc") {
                    key = Buffer.concat([ key, key.slice(0, 8) ]);
                }
                var iv = opts.iv;
                this._des = mode.create({
                    key: key,
                    iv: iv,
                    type: type
                });
            }
            DES.prototype._update = function(data) {
                return new Buffer(this._des.update(data));
            };
            DES.prototype._final = function() {
                return new Buffer(this._des.final());
            };
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "cipher-base": 55,
        "des.js": 67,
        inherits: 122
    } ],
    43: [ function(require, module, exports) {
        exports["des-ecb"] = {
            key: 8,
            iv: 0
        };
        exports["des-cbc"] = exports.des = {
            key: 8,
            iv: 8
        };
        exports["des-ede3-cbc"] = exports.des3 = {
            key: 24,
            iv: 8
        };
        exports["des-ede3"] = {
            key: 24,
            iv: 0
        };
        exports["des-ede-cbc"] = {
            key: 16,
            iv: 8
        };
        exports["des-ede"] = {
            key: 16,
            iv: 0
        };
    }, {} ],
    44: [ function(require, module, exports) {
        (function(Buffer) {
            var bn = require("bn.js");
            var randomBytes = require("randombytes");
            module.exports = crt;
            function blind(priv) {
                var r = getr(priv);
                var blinder = r.toRed(bn.mont(priv.modulus)).redPow(new bn(priv.publicExponent)).fromRed();
                return {
                    blinder: blinder,
                    unblinder: r.invm(priv.modulus)
                };
            }
            function crt(msg, priv) {
                var blinds = blind(priv);
                var len = priv.modulus.byteLength();
                var mod = bn.mont(priv.modulus);
                var blinded = new bn(msg).mul(blinds.blinder).umod(priv.modulus);
                var c1 = blinded.toRed(bn.mont(priv.prime1));
                var c2 = blinded.toRed(bn.mont(priv.prime2));
                var qinv = priv.coefficient;
                var p = priv.prime1;
                var q = priv.prime2;
                var m1 = c1.redPow(priv.exponent1);
                var m2 = c2.redPow(priv.exponent2);
                m1 = m1.fromRed();
                m2 = m2.fromRed();
                var h = m1.isub(m2).imul(qinv).umod(p);
                h.imul(q);
                m2.iadd(h);
                return new Buffer(m2.imul(blinds.unblinder).umod(priv.modulus).toArray(false, len));
            }
            crt.getr = getr;
            function getr(priv) {
                var len = priv.modulus.byteLength();
                var r = new bn(randomBytes(len));
                while (r.cmp(priv.modulus) >= 0 || !r.umod(priv.prime1) || !r.umod(priv.prime2)) {
                    r = new bn(randomBytes(len));
                }
                return r;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "bn.js": 23,
        buffer: 54,
        randombytes: 147
    } ],
    45: [ function(require, module, exports) {
        module.exports = require("./browser/algorithms.json");
    }, {
        "./browser/algorithms.json": 46
    } ],
    46: [ function(require, module, exports) {
        module.exports = {
            sha224WithRSAEncryption: {
                sign: "rsa",
                hash: "sha224",
                id: "302d300d06096086480165030402040500041c"
            },
            "RSA-SHA224": {
                sign: "ecdsa/rsa",
                hash: "sha224",
                id: "302d300d06096086480165030402040500041c"
            },
            sha256WithRSAEncryption: {
                sign: "rsa",
                hash: "sha256",
                id: "3031300d060960864801650304020105000420"
            },
            "RSA-SHA256": {
                sign: "ecdsa/rsa",
                hash: "sha256",
                id: "3031300d060960864801650304020105000420"
            },
            sha384WithRSAEncryption: {
                sign: "rsa",
                hash: "sha384",
                id: "3041300d060960864801650304020205000430"
            },
            "RSA-SHA384": {
                sign: "ecdsa/rsa",
                hash: "sha384",
                id: "3041300d060960864801650304020205000430"
            },
            sha512WithRSAEncryption: {
                sign: "rsa",
                hash: "sha512",
                id: "3051300d060960864801650304020305000440"
            },
            "RSA-SHA512": {
                sign: "ecdsa/rsa",
                hash: "sha512",
                id: "3051300d060960864801650304020305000440"
            },
            "RSA-SHA1": {
                sign: "rsa",
                hash: "sha1",
                id: "3021300906052b0e03021a05000414"
            },
            "ecdsa-with-SHA1": {
                sign: "ecdsa",
                hash: "sha1",
                id: ""
            },
            sha256: {
                sign: "ecdsa",
                hash: "sha256",
                id: ""
            },
            sha224: {
                sign: "ecdsa",
                hash: "sha224",
                id: ""
            },
            sha384: {
                sign: "ecdsa",
                hash: "sha384",
                id: ""
            },
            sha512: {
                sign: "ecdsa",
                hash: "sha512",
                id: ""
            },
            "DSA-SHA": {
                sign: "dsa",
                hash: "sha1",
                id: ""
            },
            "DSA-SHA1": {
                sign: "dsa",
                hash: "sha1",
                id: ""
            },
            DSA: {
                sign: "dsa",
                hash: "sha1",
                id: ""
            },
            "DSA-WITH-SHA224": {
                sign: "dsa",
                hash: "sha224",
                id: ""
            },
            "DSA-SHA224": {
                sign: "dsa",
                hash: "sha224",
                id: ""
            },
            "DSA-WITH-SHA256": {
                sign: "dsa",
                hash: "sha256",
                id: ""
            },
            "DSA-SHA256": {
                sign: "dsa",
                hash: "sha256",
                id: ""
            },
            "DSA-WITH-SHA384": {
                sign: "dsa",
                hash: "sha384",
                id: ""
            },
            "DSA-SHA384": {
                sign: "dsa",
                hash: "sha384",
                id: ""
            },
            "DSA-WITH-SHA512": {
                sign: "dsa",
                hash: "sha512",
                id: ""
            },
            "DSA-SHA512": {
                sign: "dsa",
                hash: "sha512",
                id: ""
            },
            "DSA-RIPEMD160": {
                sign: "dsa",
                hash: "rmd160",
                id: ""
            },
            ripemd160WithRSA: {
                sign: "rsa",
                hash: "rmd160",
                id: "3021300906052b2403020105000414"
            },
            "RSA-RIPEMD160": {
                sign: "rsa",
                hash: "rmd160",
                id: "3021300906052b2403020105000414"
            },
            md5WithRSAEncryption: {
                sign: "rsa",
                hash: "md5",
                id: "3020300c06082a864886f70d020505000410"
            },
            "RSA-MD5": {
                sign: "rsa",
                hash: "md5",
                id: "3020300c06082a864886f70d020505000410"
            }
        };
    }, {} ],
    47: [ function(require, module, exports) {
        module.exports = {
            "1.3.132.0.10": "secp256k1",
            "1.3.132.0.33": "p224",
            "1.2.840.10045.3.1.1": "p192",
            "1.2.840.10045.3.1.7": "p256",
            "1.3.132.0.34": "p384",
            "1.3.132.0.35": "p521"
        };
    }, {} ],
    48: [ function(require, module, exports) {
        (function(Buffer) {
            var createHash = require("create-hash");
            var stream = require("stream");
            var inherits = require("inherits");
            var sign = require("./sign");
            var verify = require("./verify");
            var algorithms = require("./algorithms.json");
            Object.keys(algorithms).forEach(function(key) {
                algorithms[key].id = new Buffer(algorithms[key].id, "hex");
                algorithms[key.toLowerCase()] = algorithms[key];
            });
            function Sign(algorithm) {
                stream.Writable.call(this);
                var data = algorithms[algorithm];
                if (!data) throw new Error("Unknown message digest");
                this._hashType = data.hash;
                this._hash = createHash(data.hash);
                this._tag = data.id;
                this._signType = data.sign;
            }
            inherits(Sign, stream.Writable);
            Sign.prototype._write = function _write(data, _, done) {
                this._hash.update(data);
                done();
            };
            Sign.prototype.update = function update(data, enc) {
                if (typeof data === "string") data = new Buffer(data, enc);
                this._hash.update(data);
                return this;
            };
            Sign.prototype.sign = function signMethod(key, enc) {
                this.end();
                var hash = this._hash.digest();
                var sig = sign(hash, key, this._hashType, this._signType, this._tag);
                return enc ? sig.toString(enc) : sig;
            };
            function Verify(algorithm) {
                stream.Writable.call(this);
                var data = algorithms[algorithm];
                if (!data) throw new Error("Unknown message digest");
                this._hash = createHash(data.hash);
                this._tag = data.id;
                this._signType = data.sign;
            }
            inherits(Verify, stream.Writable);
            Verify.prototype._write = function _write(data, _, done) {
                this._hash.update(data);
                done();
            };
            Verify.prototype.update = function update(data, enc) {
                if (typeof data === "string") data = new Buffer(data, enc);
                this._hash.update(data);
                return this;
            };
            Verify.prototype.verify = function verifyMethod(key, sig, enc) {
                if (typeof sig === "string") sig = new Buffer(sig, enc);
                this.end();
                var hash = this._hash.digest();
                return verify(sig, hash, key, this._signType, this._tag);
            };
            function createSign(algorithm) {
                return new Sign(algorithm);
            }
            function createVerify(algorithm) {
                return new Verify(algorithm);
            }
            module.exports = {
                Sign: createSign,
                Verify: createVerify,
                createSign: createSign,
                createVerify: createVerify
            };
        }).call(this, require("buffer").Buffer);
    }, {
        "./algorithms.json": 46,
        "./sign": 49,
        "./verify": 50,
        buffer: 54,
        "create-hash": 61,
        inherits: 122,
        stream: 179
    } ],
    49: [ function(require, module, exports) {
        (function(Buffer) {
            var createHmac = require("create-hmac");
            var crt = require("browserify-rsa");
            var EC = require("elliptic").ec;
            var BN = require("bn.js");
            var parseKeys = require("parse-asn1");
            var curves = require("./curves.json");
            function sign(hash, key, hashType, signType, tag) {
                var priv = parseKeys(key);
                if (priv.curve) {
                    if (signType !== "ecdsa" && signType !== "ecdsa/rsa") throw new Error("wrong private key type");
                    return ecSign(hash, priv);
                } else if (priv.type === "dsa") {
                    if (signType !== "dsa") throw new Error("wrong private key type");
                    return dsaSign(hash, priv, hashType);
                } else {
                    if (signType !== "rsa" && signType !== "ecdsa/rsa") throw new Error("wrong private key type");
                }
                hash = Buffer.concat([ tag, hash ]);
                var len = priv.modulus.byteLength();
                var pad = [ 0, 1 ];
                while (hash.length + pad.length + 1 < len) pad.push(255);
                pad.push(0);
                var i = -1;
                while (++i < hash.length) pad.push(hash[i]);
                var out = crt(pad, priv);
                return out;
            }
            function ecSign(hash, priv) {
                var curveId = curves[priv.curve.join(".")];
                if (!curveId) throw new Error("unknown curve " + priv.curve.join("."));
                var curve = new EC(curveId);
                var key = curve.keyFromPrivate(priv.privateKey);
                var out = key.sign(hash);
                return new Buffer(out.toDER());
            }
            function dsaSign(hash, priv, algo) {
                var x = priv.params.priv_key;
                var p = priv.params.p;
                var q = priv.params.q;
                var g = priv.params.g;
                var r = new BN(0);
                var k;
                var H = bits2int(hash, q).mod(q);
                var s = false;
                var kv = getKey(x, q, hash, algo);
                while (s === false) {
                    k = makeKey(q, kv, algo);
                    r = makeR(g, k, p, q);
                    s = k.invm(q).imul(H.add(x.mul(r))).mod(q);
                    if (s.cmpn(0) === 0) {
                        s = false;
                        r = new BN(0);
                    }
                }
                return toDER(r, s);
            }
            function toDER(r, s) {
                r = r.toArray();
                s = s.toArray();
                if (r[0] & 128) r = [ 0 ].concat(r);
                if (s[0] & 128) s = [ 0 ].concat(s);
                var total = r.length + s.length + 4;
                var res = [ 48, total, 2, r.length ];
                res = res.concat(r, [ 2, s.length ], s);
                return new Buffer(res);
            }
            function getKey(x, q, hash, algo) {
                x = new Buffer(x.toArray());
                if (x.length < q.byteLength()) {
                    var zeros = new Buffer(q.byteLength() - x.length);
                    zeros.fill(0);
                    x = Buffer.concat([ zeros, x ]);
                }
                var hlen = hash.length;
                var hbits = bits2octets(hash, q);
                var v = new Buffer(hlen);
                v.fill(1);
                var k = new Buffer(hlen);
                k.fill(0);
                k = createHmac(algo, k).update(v).update(new Buffer([ 0 ])).update(x).update(hbits).digest();
                v = createHmac(algo, k).update(v).digest();
                k = createHmac(algo, k).update(v).update(new Buffer([ 1 ])).update(x).update(hbits).digest();
                v = createHmac(algo, k).update(v).digest();
                return {
                    k: k,
                    v: v
                };
            }
            function bits2int(obits, q) {
                var bits = new BN(obits);
                var shift = (obits.length << 3) - q.bitLength();
                if (shift > 0) bits.ishrn(shift);
                return bits;
            }
            function bits2octets(bits, q) {
                bits = bits2int(bits, q);
                bits = bits.mod(q);
                var out = new Buffer(bits.toArray());
                if (out.length < q.byteLength()) {
                    var zeros = new Buffer(q.byteLength() - out.length);
                    zeros.fill(0);
                    out = Buffer.concat([ zeros, out ]);
                }
                return out;
            }
            function makeKey(q, kv, algo) {
                var t;
                var k;
                do {
                    t = new Buffer(0);
                    while (t.length * 8 < q.bitLength()) {
                        kv.v = createHmac(algo, kv.k).update(kv.v).digest();
                        t = Buffer.concat([ t, kv.v ]);
                    }
                    k = bits2int(t, q);
                    kv.k = createHmac(algo, kv.k).update(kv.v).update(new Buffer([ 0 ])).digest();
                    kv.v = createHmac(algo, kv.k).update(kv.v).digest();
                } while (k.cmp(q) !== -1);
                return k;
            }
            function makeR(g, k, p, q) {
                return g.toRed(BN.mont(p)).redPow(k).fromRed().mod(q);
            }
            module.exports = sign;
            module.exports.getKey = getKey;
            module.exports.makeKey = makeKey;
        }).call(this, require("buffer").Buffer);
    }, {
        "./curves.json": 47,
        "bn.js": 23,
        "browserify-rsa": 44,
        buffer: 54,
        "create-hmac": 64,
        elliptic: 87,
        "parse-asn1": 132
    } ],
    50: [ function(require, module, exports) {
        (function(Buffer) {
            var BN = require("bn.js");
            var EC = require("elliptic").ec;
            var parseKeys = require("parse-asn1");
            var curves = require("./curves.json");
            function verify(sig, hash, key, signType, tag) {
                var pub = parseKeys(key);
                if (pub.type === "ec") {
                    if (signType !== "ecdsa" && signType !== "ecdsa/rsa") throw new Error("wrong public key type");
                    return ecVerify(sig, hash, pub);
                } else if (pub.type === "dsa") {
                    if (signType !== "dsa") throw new Error("wrong public key type");
                    return dsaVerify(sig, hash, pub);
                } else {
                    if (signType !== "rsa" && signType !== "ecdsa/rsa") throw new Error("wrong public key type");
                }
                hash = Buffer.concat([ tag, hash ]);
                var len = pub.modulus.byteLength();
                var pad = [ 1 ];
                var padNum = 0;
                while (hash.length + pad.length + 2 < len) {
                    pad.push(255);
                    padNum++;
                }
                pad.push(0);
                var i = -1;
                while (++i < hash.length) {
                    pad.push(hash[i]);
                }
                pad = new Buffer(pad);
                var red = BN.mont(pub.modulus);
                sig = new BN(sig).toRed(red);
                sig = sig.redPow(new BN(pub.publicExponent));
                sig = new Buffer(sig.fromRed().toArray());
                var out = padNum < 8 ? 1 : 0;
                len = Math.min(sig.length, pad.length);
                if (sig.length !== pad.length) out = 1;
                i = -1;
                while (++i < len) out |= sig[i] ^ pad[i];
                return out === 0;
            }
            function ecVerify(sig, hash, pub) {
                var curveId = curves[pub.data.algorithm.curve.join(".")];
                if (!curveId) throw new Error("unknown curve " + pub.data.algorithm.curve.join("."));
                var curve = new EC(curveId);
                var pubkey = pub.data.subjectPrivateKey.data;
                return curve.verify(hash, sig, pubkey);
            }
            function dsaVerify(sig, hash, pub) {
                var p = pub.data.p;
                var q = pub.data.q;
                var g = pub.data.g;
                var y = pub.data.pub_key;
                var unpacked = parseKeys.signature.decode(sig, "der");
                var s = unpacked.s;
                var r = unpacked.r;
                checkValue(s, q);
                checkValue(r, q);
                var montp = BN.mont(p);
                var w = s.invm(q);
                var v = g.toRed(montp).redPow(new BN(hash).mul(w).mod(q)).fromRed().mul(y.toRed(montp).redPow(r.mul(w).mod(q)).fromRed()).mod(p).mod(q);
                return v.cmp(r) === 0;
            }
            function checkValue(b, q) {
                if (b.cmpn(0) <= 0) throw new Error("invalid sig");
                if (b.cmp(q) >= q) throw new Error("invalid sig");
            }
            module.exports = verify;
        }).call(this, require("buffer").Buffer);
    }, {
        "./curves.json": 47,
        "bn.js": 23,
        buffer: 54,
        elliptic: 87,
        "parse-asn1": 132
    } ],
    51: [ function(require, module, exports) {
        var Buffer = require("buffer").Buffer;
        var isBufferEncoding = Buffer.isEncoding || function(encoding) {
            switch (encoding && encoding.toLowerCase()) {
              case "hex":
              case "utf8":
              case "utf-8":
              case "ascii":
              case "binary":
              case "base64":
              case "ucs2":
              case "ucs-2":
              case "utf16le":
              case "utf-16le":
              case "raw":
                return true;

              default:
                return false;
            }
        };
        function assertEncoding(encoding) {
            if (encoding && !isBufferEncoding(encoding)) {
                throw new Error("Unknown encoding: " + encoding);
            }
        }
        var StringDecoder = exports.StringDecoder = function(encoding) {
            this.encoding = (encoding || "utf8").toLowerCase().replace(/[-_]/, "");
            assertEncoding(encoding);
            switch (this.encoding) {
              case "utf8":
                this.surrogateSize = 3;
                break;

              case "ucs2":
              case "utf16le":
                this.surrogateSize = 2;
                this.detectIncompleteChar = utf16DetectIncompleteChar;
                break;

              case "base64":
                this.surrogateSize = 3;
                this.detectIncompleteChar = base64DetectIncompleteChar;
                break;

              default:
                this.write = passThroughWrite;
                return;
            }
            this.charBuffer = new Buffer(6);
            this.charReceived = 0;
            this.charLength = 0;
        };
        StringDecoder.prototype.write = function(buffer) {
            var charStr = "";
            while (this.charLength) {
                var available = buffer.length >= this.charLength - this.charReceived ? this.charLength - this.charReceived : buffer.length;
                buffer.copy(this.charBuffer, this.charReceived, 0, available);
                this.charReceived += available;
                if (this.charReceived < this.charLength) {
                    return "";
                }
                buffer = buffer.slice(available, buffer.length);
                charStr = this.charBuffer.slice(0, this.charLength).toString(this.encoding);
                var charCode = charStr.charCodeAt(charStr.length - 1);
                if (charCode >= 55296 && charCode <= 56319) {
                    this.charLength += this.surrogateSize;
                    charStr = "";
                    continue;
                }
                this.charReceived = this.charLength = 0;
                if (buffer.length === 0) {
                    return charStr;
                }
                break;
            }
            this.detectIncompleteChar(buffer);
            var end = buffer.length;
            if (this.charLength) {
                buffer.copy(this.charBuffer, 0, buffer.length - this.charReceived, end);
                end -= this.charReceived;
            }
            charStr += buffer.toString(this.encoding, 0, end);
            var end = charStr.length - 1;
            var charCode = charStr.charCodeAt(end);
            if (charCode >= 55296 && charCode <= 56319) {
                var size = this.surrogateSize;
                this.charLength += size;
                this.charReceived += size;
                this.charBuffer.copy(this.charBuffer, size, 0, size);
                buffer.copy(this.charBuffer, 0, 0, size);
                return charStr.substring(0, end);
            }
            return charStr;
        };
        StringDecoder.prototype.detectIncompleteChar = function(buffer) {
            var i = buffer.length >= 3 ? 3 : buffer.length;
            for (;i > 0; i--) {
                var c = buffer[buffer.length - i];
                if (i == 1 && c >> 5 == 6) {
                    this.charLength = 2;
                    break;
                }
                if (i <= 2 && c >> 4 == 14) {
                    this.charLength = 3;
                    break;
                }
                if (i <= 3 && c >> 3 == 30) {
                    this.charLength = 4;
                    break;
                }
            }
            this.charReceived = i;
        };
        StringDecoder.prototype.end = function(buffer) {
            var res = "";
            if (buffer && buffer.length) res = this.write(buffer);
            if (this.charReceived) {
                var cr = this.charReceived;
                var buf = this.charBuffer;
                var enc = this.encoding;
                res += buf.slice(0, cr).toString(enc);
            }
            return res;
        };
        function passThroughWrite(buffer) {
            return buffer.toString(this.encoding);
        }
        function utf16DetectIncompleteChar(buffer) {
            this.charReceived = buffer.length % 2;
            this.charLength = this.charReceived ? 2 : 0;
        }
        function base64DetectIncompleteChar(buffer) {
            this.charReceived = buffer.length % 3;
            this.charLength = this.charReceived ? 3 : 0;
        }
    }, {
        buffer: 54
    } ],
    52: [ function(require, module, exports) {
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
            for (i = 0; buffer[i] === 0 && i < buffer.length - 1; i++) digits.push(0);
            var stringOutput = "";
            for (var i = digits.length - 1; i >= 0; i--) {
                stringOutput = stringOutput + ALPHABET[digits[i]];
            }
            return stringOutput;
        }
        function decode(string) {
            if (string.length === 0) return [];
            var i, j, bytes = [ 0 ];
            for (i = 0; i < string.length; i++) {
                var c = string[i];
                if (!(c in ALPHABET_MAP)) throw new Error("Non-base58 character");
                for (j = 0; j < bytes.length; j++) bytes[j] *= BASE;
                bytes[0] += ALPHABET_MAP[c];
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
            for (i = 0; string[i] === "1" && i < string.length - 1; i++) bytes.push(0);
            return bytes.reverse();
        }
        module.exports = {
            encode: encode,
            decode: decode
        };
    }, {} ],
    53: [ function(require, module, exports) {
        (function(Buffer) {
            module.exports = function xor(a, b) {
                var length = Math.min(a.length, b.length);
                var buffer = new Buffer(length);
                for (var i = 0; i < length; ++i) {
                    buffer[i] = a[i] ^ b[i];
                }
                return buffer;
            };
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    54: [ function(require, module, exports) {
        (function(global) {
            "use strict";
            var base64 = require("base64-js");
            var ieee754 = require("ieee754");
            var isArray = require("isarray");
            exports.Buffer = Buffer;
            exports.SlowBuffer = SlowBuffer;
            exports.INSPECT_MAX_BYTES = 50;
            Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined ? global.TYPED_ARRAY_SUPPORT : typedArraySupport();
            exports.kMaxLength = kMaxLength();
            function typedArraySupport() {
                try {
                    var arr = new Uint8Array(1);
                    arr.__proto__ = {
                        __proto__: Uint8Array.prototype,
                        foo: function() {
                            return 42;
                        }
                    };
                    return arr.foo() === 42 && typeof arr.subarray === "function" && arr.subarray(1, 1).byteLength === 0;
                } catch (e) {
                    return false;
                }
            }
            function kMaxLength() {
                return Buffer.TYPED_ARRAY_SUPPORT ? 2147483647 : 1073741823;
            }
            function createBuffer(that, length) {
                if (kMaxLength() < length) {
                    throw new RangeError("Invalid typed array length");
                }
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    that = new Uint8Array(length);
                    that.__proto__ = Buffer.prototype;
                } else {
                    if (that === null) {
                        that = new Buffer(length);
                    }
                    that.length = length;
                }
                return that;
            }
            function Buffer(arg, encodingOrOffset, length) {
                if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
                    return new Buffer(arg, encodingOrOffset, length);
                }
                if (typeof arg === "number") {
                    if (typeof encodingOrOffset === "string") {
                        throw new Error("If encoding is specified then the first argument must be a string");
                    }
                    return allocUnsafe(this, arg);
                }
                return from(this, arg, encodingOrOffset, length);
            }
            Buffer.poolSize = 8192;
            Buffer._augment = function(arr) {
                arr.__proto__ = Buffer.prototype;
                return arr;
            };
            function from(that, value, encodingOrOffset, length) {
                if (typeof value === "number") {
                    throw new TypeError('"value" argument must not be a number');
                }
                if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
                    return fromArrayBuffer(that, value, encodingOrOffset, length);
                }
                if (typeof value === "string") {
                    return fromString(that, value, encodingOrOffset);
                }
                return fromObject(that, value);
            }
            Buffer.from = function(value, encodingOrOffset, length) {
                return from(null, value, encodingOrOffset, length);
            };
            if (Buffer.TYPED_ARRAY_SUPPORT) {
                Buffer.prototype.__proto__ = Uint8Array.prototype;
                Buffer.__proto__ = Uint8Array;
                if (typeof Symbol !== "undefined" && Symbol.species && Buffer[Symbol.species] === Buffer) {
                    Object.defineProperty(Buffer, Symbol.species, {
                        value: null,
                        configurable: true
                    });
                }
            }
            function assertSize(size) {
                if (typeof size !== "number") {
                    throw new TypeError('"size" argument must be a number');
                } else if (size < 0) {
                    throw new RangeError('"size" argument must not be negative');
                }
            }
            function alloc(that, size, fill, encoding) {
                assertSize(size);
                if (size <= 0) {
                    return createBuffer(that, size);
                }
                if (fill !== undefined) {
                    return typeof encoding === "string" ? createBuffer(that, size).fill(fill, encoding) : createBuffer(that, size).fill(fill);
                }
                return createBuffer(that, size);
            }
            Buffer.alloc = function(size, fill, encoding) {
                return alloc(null, size, fill, encoding);
            };
            function allocUnsafe(that, size) {
                assertSize(size);
                that = createBuffer(that, size < 0 ? 0 : checked(size) | 0);
                if (!Buffer.TYPED_ARRAY_SUPPORT) {
                    for (var i = 0; i < size; ++i) {
                        that[i] = 0;
                    }
                }
                return that;
            }
            Buffer.allocUnsafe = function(size) {
                return allocUnsafe(null, size);
            };
            Buffer.allocUnsafeSlow = function(size) {
                return allocUnsafe(null, size);
            };
            function fromString(that, string, encoding) {
                if (typeof encoding !== "string" || encoding === "") {
                    encoding = "utf8";
                }
                if (!Buffer.isEncoding(encoding)) {
                    throw new TypeError('"encoding" must be a valid string encoding');
                }
                var length = byteLength(string, encoding) | 0;
                that = createBuffer(that, length);
                var actual = that.write(string, encoding);
                if (actual !== length) {
                    that = that.slice(0, actual);
                }
                return that;
            }
            function fromArrayLike(that, array) {
                var length = array.length < 0 ? 0 : checked(array.length) | 0;
                that = createBuffer(that, length);
                for (var i = 0; i < length; i += 1) {
                    that[i] = array[i] & 255;
                }
                return that;
            }
            function fromArrayBuffer(that, array, byteOffset, length) {
                array.byteLength;
                if (byteOffset < 0 || array.byteLength < byteOffset) {
                    throw new RangeError("'offset' is out of bounds");
                }
                if (array.byteLength < byteOffset + (length || 0)) {
                    throw new RangeError("'length' is out of bounds");
                }
                if (byteOffset === undefined && length === undefined) {
                    array = new Uint8Array(array);
                } else if (length === undefined) {
                    array = new Uint8Array(array, byteOffset);
                } else {
                    array = new Uint8Array(array, byteOffset, length);
                }
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    that = array;
                    that.__proto__ = Buffer.prototype;
                } else {
                    that = fromArrayLike(that, array);
                }
                return that;
            }
            function fromObject(that, obj) {
                if (Buffer.isBuffer(obj)) {
                    var len = checked(obj.length) | 0;
                    that = createBuffer(that, len);
                    if (that.length === 0) {
                        return that;
                    }
                    obj.copy(that, 0, 0, len);
                    return that;
                }
                if (obj) {
                    if (typeof ArrayBuffer !== "undefined" && obj.buffer instanceof ArrayBuffer || "length" in obj) {
                        if (typeof obj.length !== "number" || isnan(obj.length)) {
                            return createBuffer(that, 0);
                        }
                        return fromArrayLike(that, obj);
                    }
                    if (obj.type === "Buffer" && isArray(obj.data)) {
                        return fromArrayLike(that, obj.data);
                    }
                }
                throw new TypeError("First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.");
            }
            function checked(length) {
                if (length >= kMaxLength()) {
                    throw new RangeError("Attempt to allocate Buffer larger than maximum " + "size: 0x" + kMaxLength().toString(16) + " bytes");
                }
                return length | 0;
            }
            function SlowBuffer(length) {
                if (+length != length) {
                    length = 0;
                }
                return Buffer.alloc(+length);
            }
            Buffer.isBuffer = function isBuffer(b) {
                return !!(b != null && b._isBuffer);
            };
            Buffer.compare = function compare(a, b) {
                if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
                    throw new TypeError("Arguments must be Buffers");
                }
                if (a === b) return 0;
                var x = a.length;
                var y = b.length;
                for (var i = 0, len = Math.min(x, y); i < len; ++i) {
                    if (a[i] !== b[i]) {
                        x = a[i];
                        y = b[i];
                        break;
                    }
                }
                if (x < y) return -1;
                if (y < x) return 1;
                return 0;
            };
            Buffer.isEncoding = function isEncoding(encoding) {
                switch (String(encoding).toLowerCase()) {
                  case "hex":
                  case "utf8":
                  case "utf-8":
                  case "ascii":
                  case "latin1":
                  case "binary":
                  case "base64":
                  case "ucs2":
                  case "ucs-2":
                  case "utf16le":
                  case "utf-16le":
                    return true;

                  default:
                    return false;
                }
            };
            Buffer.concat = function concat(list, length) {
                if (!isArray(list)) {
                    throw new TypeError('"list" argument must be an Array of Buffers');
                }
                if (list.length === 0) {
                    return Buffer.alloc(0);
                }
                var i;
                if (length === undefined) {
                    length = 0;
                    for (i = 0; i < list.length; ++i) {
                        length += list[i].length;
                    }
                }
                var buffer = Buffer.allocUnsafe(length);
                var pos = 0;
                for (i = 0; i < list.length; ++i) {
                    var buf = list[i];
                    if (!Buffer.isBuffer(buf)) {
                        throw new TypeError('"list" argument must be an Array of Buffers');
                    }
                    buf.copy(buffer, pos);
                    pos += buf.length;
                }
                return buffer;
            };
            function byteLength(string, encoding) {
                if (Buffer.isBuffer(string)) {
                    return string.length;
                }
                if (typeof ArrayBuffer !== "undefined" && typeof ArrayBuffer.isView === "function" && (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
                    return string.byteLength;
                }
                if (typeof string !== "string") {
                    string = "" + string;
                }
                var len = string.length;
                if (len === 0) return 0;
                var loweredCase = false;
                for (;;) {
                    switch (encoding) {
                      case "ascii":
                      case "latin1":
                      case "binary":
                        return len;

                      case "utf8":
                      case "utf-8":
                      case undefined:
                        return utf8ToBytes(string).length;

                      case "ucs2":
                      case "ucs-2":
                      case "utf16le":
                      case "utf-16le":
                        return len * 2;

                      case "hex":
                        return len >>> 1;

                      case "base64":
                        return base64ToBytes(string).length;

                      default:
                        if (loweredCase) return utf8ToBytes(string).length;
                        encoding = ("" + encoding).toLowerCase();
                        loweredCase = true;
                    }
                }
            }
            Buffer.byteLength = byteLength;
            function slowToString(encoding, start, end) {
                var loweredCase = false;
                if (start === undefined || start < 0) {
                    start = 0;
                }
                if (start > this.length) {
                    return "";
                }
                if (end === undefined || end > this.length) {
                    end = this.length;
                }
                if (end <= 0) {
                    return "";
                }
                end >>>= 0;
                start >>>= 0;
                if (end <= start) {
                    return "";
                }
                if (!encoding) encoding = "utf8";
                while (true) {
                    switch (encoding) {
                      case "hex":
                        return hexSlice(this, start, end);

                      case "utf8":
                      case "utf-8":
                        return utf8Slice(this, start, end);

                      case "ascii":
                        return asciiSlice(this, start, end);

                      case "latin1":
                      case "binary":
                        return latin1Slice(this, start, end);

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
            }
            Buffer.prototype._isBuffer = true;
            function swap(b, n, m) {
                var i = b[n];
                b[n] = b[m];
                b[m] = i;
            }
            Buffer.prototype.swap16 = function swap16() {
                var len = this.length;
                if (len % 2 !== 0) {
                    throw new RangeError("Buffer size must be a multiple of 16-bits");
                }
                for (var i = 0; i < len; i += 2) {
                    swap(this, i, i + 1);
                }
                return this;
            };
            Buffer.prototype.swap32 = function swap32() {
                var len = this.length;
                if (len % 4 !== 0) {
                    throw new RangeError("Buffer size must be a multiple of 32-bits");
                }
                for (var i = 0; i < len; i += 4) {
                    swap(this, i, i + 3);
                    swap(this, i + 1, i + 2);
                }
                return this;
            };
            Buffer.prototype.swap64 = function swap64() {
                var len = this.length;
                if (len % 8 !== 0) {
                    throw new RangeError("Buffer size must be a multiple of 64-bits");
                }
                for (var i = 0; i < len; i += 8) {
                    swap(this, i, i + 7);
                    swap(this, i + 1, i + 6);
                    swap(this, i + 2, i + 5);
                    swap(this, i + 3, i + 4);
                }
                return this;
            };
            Buffer.prototype.toString = function toString() {
                var length = this.length | 0;
                if (length === 0) return "";
                if (arguments.length === 0) return utf8Slice(this, 0, length);
                return slowToString.apply(this, arguments);
            };
            Buffer.prototype.equals = function equals(b) {
                if (!Buffer.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
                if (this === b) return true;
                return Buffer.compare(this, b) === 0;
            };
            Buffer.prototype.inspect = function inspect() {
                var str = "";
                var max = exports.INSPECT_MAX_BYTES;
                if (this.length > 0) {
                    str = this.toString("hex", 0, max).match(/.{2}/g).join(" ");
                    if (this.length > max) str += " ... ";
                }
                return "<Buffer " + str + ">";
            };
            Buffer.prototype.compare = function compare(target, start, end, thisStart, thisEnd) {
                if (!Buffer.isBuffer(target)) {
                    throw new TypeError("Argument must be a Buffer");
                }
                if (start === undefined) {
                    start = 0;
                }
                if (end === undefined) {
                    end = target ? target.length : 0;
                }
                if (thisStart === undefined) {
                    thisStart = 0;
                }
                if (thisEnd === undefined) {
                    thisEnd = this.length;
                }
                if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
                    throw new RangeError("out of range index");
                }
                if (thisStart >= thisEnd && start >= end) {
                    return 0;
                }
                if (thisStart >= thisEnd) {
                    return -1;
                }
                if (start >= end) {
                    return 1;
                }
                start >>>= 0;
                end >>>= 0;
                thisStart >>>= 0;
                thisEnd >>>= 0;
                if (this === target) return 0;
                var x = thisEnd - thisStart;
                var y = end - start;
                var len = Math.min(x, y);
                var thisCopy = this.slice(thisStart, thisEnd);
                var targetCopy = target.slice(start, end);
                for (var i = 0; i < len; ++i) {
                    if (thisCopy[i] !== targetCopy[i]) {
                        x = thisCopy[i];
                        y = targetCopy[i];
                        break;
                    }
                }
                if (x < y) return -1;
                if (y < x) return 1;
                return 0;
            };
            function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
                if (buffer.length === 0) return -1;
                if (typeof byteOffset === "string") {
                    encoding = byteOffset;
                    byteOffset = 0;
                } else if (byteOffset > 2147483647) {
                    byteOffset = 2147483647;
                } else if (byteOffset < -2147483648) {
                    byteOffset = -2147483648;
                }
                byteOffset = +byteOffset;
                if (isNaN(byteOffset)) {
                    byteOffset = dir ? 0 : buffer.length - 1;
                }
                if (byteOffset < 0) byteOffset = buffer.length + byteOffset;
                if (byteOffset >= buffer.length) {
                    if (dir) return -1; else byteOffset = buffer.length - 1;
                } else if (byteOffset < 0) {
                    if (dir) byteOffset = 0; else return -1;
                }
                if (typeof val === "string") {
                    val = Buffer.from(val, encoding);
                }
                if (Buffer.isBuffer(val)) {
                    if (val.length === 0) {
                        return -1;
                    }
                    return arrayIndexOf(buffer, val, byteOffset, encoding, dir);
                } else if (typeof val === "number") {
                    val = val & 255;
                    if (Buffer.TYPED_ARRAY_SUPPORT && typeof Uint8Array.prototype.indexOf === "function") {
                        if (dir) {
                            return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset);
                        } else {
                            return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset);
                        }
                    }
                    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir);
                }
                throw new TypeError("val must be string, number or Buffer");
            }
            function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
                var indexSize = 1;
                var arrLength = arr.length;
                var valLength = val.length;
                if (encoding !== undefined) {
                    encoding = String(encoding).toLowerCase();
                    if (encoding === "ucs2" || encoding === "ucs-2" || encoding === "utf16le" || encoding === "utf-16le") {
                        if (arr.length < 2 || val.length < 2) {
                            return -1;
                        }
                        indexSize = 2;
                        arrLength /= 2;
                        valLength /= 2;
                        byteOffset /= 2;
                    }
                }
                function read(buf, i) {
                    if (indexSize === 1) {
                        return buf[i];
                    } else {
                        return buf.readUInt16BE(i * indexSize);
                    }
                }
                var i;
                if (dir) {
                    var foundIndex = -1;
                    for (i = byteOffset; i < arrLength; i++) {
                        if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
                            if (foundIndex === -1) foundIndex = i;
                            if (i - foundIndex + 1 === valLength) return foundIndex * indexSize;
                        } else {
                            if (foundIndex !== -1) i -= i - foundIndex;
                            foundIndex = -1;
                        }
                    }
                } else {
                    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength;
                    for (i = byteOffset; i >= 0; i--) {
                        var found = true;
                        for (var j = 0; j < valLength; j++) {
                            if (read(arr, i + j) !== read(val, j)) {
                                found = false;
                                break;
                            }
                        }
                        if (found) return i;
                    }
                }
                return -1;
            }
            Buffer.prototype.includes = function includes(val, byteOffset, encoding) {
                return this.indexOf(val, byteOffset, encoding) !== -1;
            };
            Buffer.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
                return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
            };
            Buffer.prototype.lastIndexOf = function lastIndexOf(val, byteOffset, encoding) {
                return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
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
                if (strLen % 2 !== 0) throw new TypeError("Invalid hex string");
                if (length > strLen / 2) {
                    length = strLen / 2;
                }
                for (var i = 0; i < length; ++i) {
                    var parsed = parseInt(string.substr(i * 2, 2), 16);
                    if (isNaN(parsed)) return i;
                    buf[offset + i] = parsed;
                }
                return i;
            }
            function utf8Write(buf, string, offset, length) {
                return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length);
            }
            function asciiWrite(buf, string, offset, length) {
                return blitBuffer(asciiToBytes(string), buf, offset, length);
            }
            function latin1Write(buf, string, offset, length) {
                return asciiWrite(buf, string, offset, length);
            }
            function base64Write(buf, string, offset, length) {
                return blitBuffer(base64ToBytes(string), buf, offset, length);
            }
            function ucs2Write(buf, string, offset, length) {
                return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length);
            }
            Buffer.prototype.write = function write(string, offset, length, encoding) {
                if (offset === undefined) {
                    encoding = "utf8";
                    length = this.length;
                    offset = 0;
                } else if (length === undefined && typeof offset === "string") {
                    encoding = offset;
                    length = this.length;
                    offset = 0;
                } else if (isFinite(offset)) {
                    offset = offset | 0;
                    if (isFinite(length)) {
                        length = length | 0;
                        if (encoding === undefined) encoding = "utf8";
                    } else {
                        encoding = length;
                        length = undefined;
                    }
                } else {
                    throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");
                }
                var remaining = this.length - offset;
                if (length === undefined || length > remaining) length = remaining;
                if (string.length > 0 && (length < 0 || offset < 0) || offset > this.length) {
                    throw new RangeError("Attempt to write outside buffer bounds");
                }
                if (!encoding) encoding = "utf8";
                var loweredCase = false;
                for (;;) {
                    switch (encoding) {
                      case "hex":
                        return hexWrite(this, string, offset, length);

                      case "utf8":
                      case "utf-8":
                        return utf8Write(this, string, offset, length);

                      case "ascii":
                        return asciiWrite(this, string, offset, length);

                      case "latin1":
                      case "binary":
                        return latin1Write(this, string, offset, length);

                      case "base64":
                        return base64Write(this, string, offset, length);

                      case "ucs2":
                      case "ucs-2":
                      case "utf16le":
                      case "utf-16le":
                        return ucs2Write(this, string, offset, length);

                      default:
                        if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
                        encoding = ("" + encoding).toLowerCase();
                        loweredCase = true;
                    }
                }
            };
            Buffer.prototype.toJSON = function toJSON() {
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
                end = Math.min(buf.length, end);
                var res = [];
                var i = start;
                while (i < end) {
                    var firstByte = buf[i];
                    var codePoint = null;
                    var bytesPerSequence = firstByte > 239 ? 4 : firstByte > 223 ? 3 : firstByte > 191 ? 2 : 1;
                    if (i + bytesPerSequence <= end) {
                        var secondByte, thirdByte, fourthByte, tempCodePoint;
                        switch (bytesPerSequence) {
                          case 1:
                            if (firstByte < 128) {
                                codePoint = firstByte;
                            }
                            break;

                          case 2:
                            secondByte = buf[i + 1];
                            if ((secondByte & 192) === 128) {
                                tempCodePoint = (firstByte & 31) << 6 | secondByte & 63;
                                if (tempCodePoint > 127) {
                                    codePoint = tempCodePoint;
                                }
                            }
                            break;

                          case 3:
                            secondByte = buf[i + 1];
                            thirdByte = buf[i + 2];
                            if ((secondByte & 192) === 128 && (thirdByte & 192) === 128) {
                                tempCodePoint = (firstByte & 15) << 12 | (secondByte & 63) << 6 | thirdByte & 63;
                                if (tempCodePoint > 2047 && (tempCodePoint < 55296 || tempCodePoint > 57343)) {
                                    codePoint = tempCodePoint;
                                }
                            }
                            break;

                          case 4:
                            secondByte = buf[i + 1];
                            thirdByte = buf[i + 2];
                            fourthByte = buf[i + 3];
                            if ((secondByte & 192) === 128 && (thirdByte & 192) === 128 && (fourthByte & 192) === 128) {
                                tempCodePoint = (firstByte & 15) << 18 | (secondByte & 63) << 12 | (thirdByte & 63) << 6 | fourthByte & 63;
                                if (tempCodePoint > 65535 && tempCodePoint < 1114112) {
                                    codePoint = tempCodePoint;
                                }
                            }
                        }
                    }
                    if (codePoint === null) {
                        codePoint = 65533;
                        bytesPerSequence = 1;
                    } else if (codePoint > 65535) {
                        codePoint -= 65536;
                        res.push(codePoint >>> 10 & 1023 | 55296);
                        codePoint = 56320 | codePoint & 1023;
                    }
                    res.push(codePoint);
                    i += bytesPerSequence;
                }
                return decodeCodePointsArray(res);
            }
            var MAX_ARGUMENTS_LENGTH = 4096;
            function decodeCodePointsArray(codePoints) {
                var len = codePoints.length;
                if (len <= MAX_ARGUMENTS_LENGTH) {
                    return String.fromCharCode.apply(String, codePoints);
                }
                var res = "";
                var i = 0;
                while (i < len) {
                    res += String.fromCharCode.apply(String, codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH));
                }
                return res;
            }
            function asciiSlice(buf, start, end) {
                var ret = "";
                end = Math.min(buf.length, end);
                for (var i = start; i < end; ++i) {
                    ret += String.fromCharCode(buf[i] & 127);
                }
                return ret;
            }
            function latin1Slice(buf, start, end) {
                var ret = "";
                end = Math.min(buf.length, end);
                for (var i = start; i < end; ++i) {
                    ret += String.fromCharCode(buf[i]);
                }
                return ret;
            }
            function hexSlice(buf, start, end) {
                var len = buf.length;
                if (!start || start < 0) start = 0;
                if (!end || end < 0 || end > len) end = len;
                var out = "";
                for (var i = start; i < end; ++i) {
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
            Buffer.prototype.slice = function slice(start, end) {
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
                var newBuf;
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    newBuf = this.subarray(start, end);
                    newBuf.__proto__ = Buffer.prototype;
                } else {
                    var sliceLen = end - start;
                    newBuf = new Buffer(sliceLen, undefined);
                    for (var i = 0; i < sliceLen; ++i) {
                        newBuf[i] = this[i + start];
                    }
                }
                return newBuf;
            };
            function checkOffset(offset, ext, length) {
                if (offset % 1 !== 0 || offset < 0) throw new RangeError("offset is not uint");
                if (offset + ext > length) throw new RangeError("Trying to access beyond buffer length");
            }
            Buffer.prototype.readUIntLE = function readUIntLE(offset, byteLength, noAssert) {
                offset = offset | 0;
                byteLength = byteLength | 0;
                if (!noAssert) checkOffset(offset, byteLength, this.length);
                var val = this[offset];
                var mul = 1;
                var i = 0;
                while (++i < byteLength && (mul *= 256)) {
                    val += this[offset + i] * mul;
                }
                return val;
            };
            Buffer.prototype.readUIntBE = function readUIntBE(offset, byteLength, noAssert) {
                offset = offset | 0;
                byteLength = byteLength | 0;
                if (!noAssert) {
                    checkOffset(offset, byteLength, this.length);
                }
                var val = this[offset + --byteLength];
                var mul = 1;
                while (byteLength > 0 && (mul *= 256)) {
                    val += this[offset + --byteLength] * mul;
                }
                return val;
            };
            Buffer.prototype.readUInt8 = function readUInt8(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 1, this.length);
                return this[offset];
            };
            Buffer.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                return this[offset] | this[offset + 1] << 8;
            };
            Buffer.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                return this[offset] << 8 | this[offset + 1];
            };
            Buffer.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 16777216;
            };
            Buffer.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return this[offset] * 16777216 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
            };
            Buffer.prototype.readIntLE = function readIntLE(offset, byteLength, noAssert) {
                offset = offset | 0;
                byteLength = byteLength | 0;
                if (!noAssert) checkOffset(offset, byteLength, this.length);
                var val = this[offset];
                var mul = 1;
                var i = 0;
                while (++i < byteLength && (mul *= 256)) {
                    val += this[offset + i] * mul;
                }
                mul *= 128;
                if (val >= mul) val -= Math.pow(2, 8 * byteLength);
                return val;
            };
            Buffer.prototype.readIntBE = function readIntBE(offset, byteLength, noAssert) {
                offset = offset | 0;
                byteLength = byteLength | 0;
                if (!noAssert) checkOffset(offset, byteLength, this.length);
                var i = byteLength;
                var mul = 1;
                var val = this[offset + --i];
                while (i > 0 && (mul *= 256)) {
                    val += this[offset + --i] * mul;
                }
                mul *= 128;
                if (val >= mul) val -= Math.pow(2, 8 * byteLength);
                return val;
            };
            Buffer.prototype.readInt8 = function readInt8(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 1, this.length);
                if (!(this[offset] & 128)) return this[offset];
                return (255 - this[offset] + 1) * -1;
            };
            Buffer.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                var val = this[offset] | this[offset + 1] << 8;
                return val & 32768 ? val | 4294901760 : val;
            };
            Buffer.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 2, this.length);
                var val = this[offset + 1] | this[offset] << 8;
                return val & 32768 ? val | 4294901760 : val;
            };
            Buffer.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
            };
            Buffer.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
            };
            Buffer.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return ieee754.read(this, offset, true, 23, 4);
            };
            Buffer.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 4, this.length);
                return ieee754.read(this, offset, false, 23, 4);
            };
            Buffer.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 8, this.length);
                return ieee754.read(this, offset, true, 52, 8);
            };
            Buffer.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
                if (!noAssert) checkOffset(offset, 8, this.length);
                return ieee754.read(this, offset, false, 52, 8);
            };
            function checkInt(buf, value, offset, ext, max, min) {
                if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance');
                if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
                if (offset + ext > buf.length) throw new RangeError("Index out of range");
            }
            Buffer.prototype.writeUIntLE = function writeUIntLE(value, offset, byteLength, noAssert) {
                value = +value;
                offset = offset | 0;
                byteLength = byteLength | 0;
                if (!noAssert) {
                    var maxBytes = Math.pow(2, 8 * byteLength) - 1;
                    checkInt(this, value, offset, byteLength, maxBytes, 0);
                }
                var mul = 1;
                var i = 0;
                this[offset] = value & 255;
                while (++i < byteLength && (mul *= 256)) {
                    this[offset + i] = value / mul & 255;
                }
                return offset + byteLength;
            };
            Buffer.prototype.writeUIntBE = function writeUIntBE(value, offset, byteLength, noAssert) {
                value = +value;
                offset = offset | 0;
                byteLength = byteLength | 0;
                if (!noAssert) {
                    var maxBytes = Math.pow(2, 8 * byteLength) - 1;
                    checkInt(this, value, offset, byteLength, maxBytes, 0);
                }
                var i = byteLength - 1;
                var mul = 1;
                this[offset + i] = value & 255;
                while (--i >= 0 && (mul *= 256)) {
                    this[offset + i] = value / mul & 255;
                }
                return offset + byteLength;
            };
            Buffer.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 1, 255, 0);
                if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
                this[offset] = value & 255;
                return offset + 1;
            };
            function objectWriteUInt16(buf, value, offset, littleEndian) {
                if (value < 0) value = 65535 + value + 1;
                for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; ++i) {
                    buf[offset + i] = (value & 255 << 8 * (littleEndian ? i : 1 - i)) >>> (littleEndian ? i : 1 - i) * 8;
                }
            }
            Buffer.prototype.writeUInt16LE = function writeUInt16LE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value & 255;
                    this[offset + 1] = value >>> 8;
                } else {
                    objectWriteUInt16(this, value, offset, true);
                }
                return offset + 2;
            };
            Buffer.prototype.writeUInt16BE = function writeUInt16BE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 8;
                    this[offset + 1] = value & 255;
                } else {
                    objectWriteUInt16(this, value, offset, false);
                }
                return offset + 2;
            };
            function objectWriteUInt32(buf, value, offset, littleEndian) {
                if (value < 0) value = 4294967295 + value + 1;
                for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; ++i) {
                    buf[offset + i] = value >>> (littleEndian ? i : 3 - i) * 8 & 255;
                }
            }
            Buffer.prototype.writeUInt32LE = function writeUInt32LE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset + 3] = value >>> 24;
                    this[offset + 2] = value >>> 16;
                    this[offset + 1] = value >>> 8;
                    this[offset] = value & 255;
                } else {
                    objectWriteUInt32(this, value, offset, true);
                }
                return offset + 4;
            };
            Buffer.prototype.writeUInt32BE = function writeUInt32BE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 24;
                    this[offset + 1] = value >>> 16;
                    this[offset + 2] = value >>> 8;
                    this[offset + 3] = value & 255;
                } else {
                    objectWriteUInt32(this, value, offset, false);
                }
                return offset + 4;
            };
            Buffer.prototype.writeIntLE = function writeIntLE(value, offset, byteLength, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) {
                    var limit = Math.pow(2, 8 * byteLength - 1);
                    checkInt(this, value, offset, byteLength, limit - 1, -limit);
                }
                var i = 0;
                var mul = 1;
                var sub = 0;
                this[offset] = value & 255;
                while (++i < byteLength && (mul *= 256)) {
                    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
                        sub = 1;
                    }
                    this[offset + i] = (value / mul >> 0) - sub & 255;
                }
                return offset + byteLength;
            };
            Buffer.prototype.writeIntBE = function writeIntBE(value, offset, byteLength, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) {
                    var limit = Math.pow(2, 8 * byteLength - 1);
                    checkInt(this, value, offset, byteLength, limit - 1, -limit);
                }
                var i = byteLength - 1;
                var mul = 1;
                var sub = 0;
                this[offset + i] = value & 255;
                while (--i >= 0 && (mul *= 256)) {
                    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
                        sub = 1;
                    }
                    this[offset + i] = (value / mul >> 0) - sub & 255;
                }
                return offset + byteLength;
            };
            Buffer.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 1, 127, -128);
                if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
                if (value < 0) value = 255 + value + 1;
                this[offset] = value & 255;
                return offset + 1;
            };
            Buffer.prototype.writeInt16LE = function writeInt16LE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value & 255;
                    this[offset + 1] = value >>> 8;
                } else {
                    objectWriteUInt16(this, value, offset, true);
                }
                return offset + 2;
            };
            Buffer.prototype.writeInt16BE = function writeInt16BE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 8;
                    this[offset + 1] = value & 255;
                } else {
                    objectWriteUInt16(this, value, offset, false);
                }
                return offset + 2;
            };
            Buffer.prototype.writeInt32LE = function writeInt32LE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value & 255;
                    this[offset + 1] = value >>> 8;
                    this[offset + 2] = value >>> 16;
                    this[offset + 3] = value >>> 24;
                } else {
                    objectWriteUInt32(this, value, offset, true);
                }
                return offset + 4;
            };
            Buffer.prototype.writeInt32BE = function writeInt32BE(value, offset, noAssert) {
                value = +value;
                offset = offset | 0;
                if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
                if (value < 0) value = 4294967295 + value + 1;
                if (Buffer.TYPED_ARRAY_SUPPORT) {
                    this[offset] = value >>> 24;
                    this[offset + 1] = value >>> 16;
                    this[offset + 2] = value >>> 8;
                    this[offset + 3] = value & 255;
                } else {
                    objectWriteUInt32(this, value, offset, false);
                }
                return offset + 4;
            };
            function checkIEEE754(buf, value, offset, ext, max, min) {
                if (offset + ext > buf.length) throw new RangeError("Index out of range");
                if (offset < 0) throw new RangeError("Index out of range");
            }
            function writeFloat(buf, value, offset, littleEndian, noAssert) {
                if (!noAssert) {
                    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e38, -3.4028234663852886e38);
                }
                ieee754.write(buf, value, offset, littleEndian, 23, 4);
                return offset + 4;
            }
            Buffer.prototype.writeFloatLE = function writeFloatLE(value, offset, noAssert) {
                return writeFloat(this, value, offset, true, noAssert);
            };
            Buffer.prototype.writeFloatBE = function writeFloatBE(value, offset, noAssert) {
                return writeFloat(this, value, offset, false, noAssert);
            };
            function writeDouble(buf, value, offset, littleEndian, noAssert) {
                if (!noAssert) {
                    checkIEEE754(buf, value, offset, 8, 1.7976931348623157e308, -1.7976931348623157e308);
                }
                ieee754.write(buf, value, offset, littleEndian, 52, 8);
                return offset + 8;
            }
            Buffer.prototype.writeDoubleLE = function writeDoubleLE(value, offset, noAssert) {
                return writeDouble(this, value, offset, true, noAssert);
            };
            Buffer.prototype.writeDoubleBE = function writeDoubleBE(value, offset, noAssert) {
                return writeDouble(this, value, offset, false, noAssert);
            };
            Buffer.prototype.copy = function copy(target, targetStart, start, end) {
                if (!start) start = 0;
                if (!end && end !== 0) end = this.length;
                if (targetStart >= target.length) targetStart = target.length;
                if (!targetStart) targetStart = 0;
                if (end > 0 && end < start) end = start;
                if (end === start) return 0;
                if (target.length === 0 || this.length === 0) return 0;
                if (targetStart < 0) {
                    throw new RangeError("targetStart out of bounds");
                }
                if (start < 0 || start >= this.length) throw new RangeError("sourceStart out of bounds");
                if (end < 0) throw new RangeError("sourceEnd out of bounds");
                if (end > this.length) end = this.length;
                if (target.length - targetStart < end - start) {
                    end = target.length - targetStart + start;
                }
                var len = end - start;
                var i;
                if (this === target && start < targetStart && targetStart < end) {
                    for (i = len - 1; i >= 0; --i) {
                        target[i + targetStart] = this[i + start];
                    }
                } else if (len < 1e3 || !Buffer.TYPED_ARRAY_SUPPORT) {
                    for (i = 0; i < len; ++i) {
                        target[i + targetStart] = this[i + start];
                    }
                } else {
                    Uint8Array.prototype.set.call(target, this.subarray(start, start + len), targetStart);
                }
                return len;
            };
            Buffer.prototype.fill = function fill(val, start, end, encoding) {
                if (typeof val === "string") {
                    if (typeof start === "string") {
                        encoding = start;
                        start = 0;
                        end = this.length;
                    } else if (typeof end === "string") {
                        encoding = end;
                        end = this.length;
                    }
                    if (val.length === 1) {
                        var code = val.charCodeAt(0);
                        if (code < 256) {
                            val = code;
                        }
                    }
                    if (encoding !== undefined && typeof encoding !== "string") {
                        throw new TypeError("encoding must be a string");
                    }
                    if (typeof encoding === "string" && !Buffer.isEncoding(encoding)) {
                        throw new TypeError("Unknown encoding: " + encoding);
                    }
                } else if (typeof val === "number") {
                    val = val & 255;
                }
                if (start < 0 || this.length < start || this.length < end) {
                    throw new RangeError("Out of range index");
                }
                if (end <= start) {
                    return this;
                }
                start = start >>> 0;
                end = end === undefined ? this.length : end >>> 0;
                if (!val) val = 0;
                var i;
                if (typeof val === "number") {
                    for (i = start; i < end; ++i) {
                        this[i] = val;
                    }
                } else {
                    var bytes = Buffer.isBuffer(val) ? val : utf8ToBytes(new Buffer(val, encoding).toString());
                    var len = bytes.length;
                    for (i = 0; i < end - start; ++i) {
                        this[i + start] = bytes[i % len];
                    }
                }
                return this;
            };
            var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g;
            function base64clean(str) {
                str = stringtrim(str).replace(INVALID_BASE64_RE, "");
                if (str.length < 2) return "";
                while (str.length % 4 !== 0) {
                    str = str + "=";
                }
                return str;
            }
            function stringtrim(str) {
                if (str.trim) return str.trim();
                return str.replace(/^\s+|\s+$/g, "");
            }
            function toHex(n) {
                if (n < 16) return "0" + n.toString(16);
                return n.toString(16);
            }
            function utf8ToBytes(string, units) {
                units = units || Infinity;
                var codePoint;
                var length = string.length;
                var leadSurrogate = null;
                var bytes = [];
                for (var i = 0; i < length; ++i) {
                    codePoint = string.charCodeAt(i);
                    if (codePoint > 55295 && codePoint < 57344) {
                        if (!leadSurrogate) {
                            if (codePoint > 56319) {
                                if ((units -= 3) > -1) bytes.push(239, 191, 189);
                                continue;
                            } else if (i + 1 === length) {
                                if ((units -= 3) > -1) bytes.push(239, 191, 189);
                                continue;
                            }
                            leadSurrogate = codePoint;
                            continue;
                        }
                        if (codePoint < 56320) {
                            if ((units -= 3) > -1) bytes.push(239, 191, 189);
                            leadSurrogate = codePoint;
                            continue;
                        }
                        codePoint = (leadSurrogate - 55296 << 10 | codePoint - 56320) + 65536;
                    } else if (leadSurrogate) {
                        if ((units -= 3) > -1) bytes.push(239, 191, 189);
                    }
                    leadSurrogate = null;
                    if (codePoint < 128) {
                        if ((units -= 1) < 0) break;
                        bytes.push(codePoint);
                    } else if (codePoint < 2048) {
                        if ((units -= 2) < 0) break;
                        bytes.push(codePoint >> 6 | 192, codePoint & 63 | 128);
                    } else if (codePoint < 65536) {
                        if ((units -= 3) < 0) break;
                        bytes.push(codePoint >> 12 | 224, codePoint >> 6 & 63 | 128, codePoint & 63 | 128);
                    } else if (codePoint < 1114112) {
                        if ((units -= 4) < 0) break;
                        bytes.push(codePoint >> 18 | 240, codePoint >> 12 & 63 | 128, codePoint >> 6 & 63 | 128, codePoint & 63 | 128);
                    } else {
                        throw new Error("Invalid code point");
                    }
                }
                return bytes;
            }
            function asciiToBytes(str) {
                var byteArray = [];
                for (var i = 0; i < str.length; ++i) {
                    byteArray.push(str.charCodeAt(i) & 255);
                }
                return byteArray;
            }
            function utf16leToBytes(str, units) {
                var c, hi, lo;
                var byteArray = [];
                for (var i = 0; i < str.length; ++i) {
                    if ((units -= 2) < 0) break;
                    c = str.charCodeAt(i);
                    hi = c >> 8;
                    lo = c % 256;
                    byteArray.push(lo);
                    byteArray.push(hi);
                }
                return byteArray;
            }
            function base64ToBytes(str) {
                return base64.toByteArray(base64clean(str));
            }
            function blitBuffer(src, dst, offset, length) {
                for (var i = 0; i < length; ++i) {
                    if (i + offset >= dst.length || i >= src.length) break;
                    dst[i + offset] = src[i];
                }
                return i;
            }
            function isnan(val) {
                return val !== val;
            }
        }).call(this, typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {
        "base64-js": 17,
        ieee754: 120,
        isarray: 124
    } ],
    55: [ function(require, module, exports) {
        var Buffer = require("safe-buffer").Buffer;
        var Transform = require("stream").Transform;
        var StringDecoder = require("string_decoder").StringDecoder;
        var inherits = require("inherits");
        function CipherBase(hashMode) {
            Transform.call(this);
            this.hashMode = typeof hashMode === "string";
            if (this.hashMode) {
                this[hashMode] = this._finalOrDigest;
            } else {
                this.final = this._finalOrDigest;
            }
            if (this._final) {
                this.__final = this._final;
                this._final = null;
            }
            this._decoder = null;
            this._encoding = null;
        }
        inherits(CipherBase, Transform);
        CipherBase.prototype.update = function(data, inputEnc, outputEnc) {
            if (typeof data === "string") {
                data = Buffer.from(data, inputEnc);
            }
            var outData = this._update(data);
            if (this.hashMode) return this;
            if (outputEnc) {
                outData = this._toString(outData, outputEnc);
            }
            return outData;
        };
        CipherBase.prototype.setAutoPadding = function() {};
        CipherBase.prototype.getAuthTag = function() {
            throw new Error("trying to get auth tag in unsupported state");
        };
        CipherBase.prototype.setAuthTag = function() {
            throw new Error("trying to set auth tag in unsupported state");
        };
        CipherBase.prototype.setAAD = function() {
            throw new Error("trying to set aad in unsupported state");
        };
        CipherBase.prototype._transform = function(data, _, next) {
            var err;
            try {
                if (this.hashMode) {
                    this._update(data);
                } else {
                    this.push(this._update(data));
                }
            } catch (e) {
                err = e;
            } finally {
                next(err);
            }
        };
        CipherBase.prototype._flush = function(done) {
            var err;
            try {
                this.push(this.__final());
            } catch (e) {
                err = e;
            }
            done(err);
        };
        CipherBase.prototype._finalOrDigest = function(outputEnc) {
            var outData = this.__final() || Buffer.alloc(0);
            if (outputEnc) {
                outData = this._toString(outData, outputEnc, true);
            }
            return outData;
        };
        CipherBase.prototype._toString = function(value, enc, fin) {
            if (!this._decoder) {
                this._decoder = new StringDecoder(enc);
                this._encoding = enc;
            }
            if (this._encoding !== enc) throw new Error("can't switch encodings");
            var out = this._decoder.write(value);
            if (fin) {
                out += this._decoder.end();
            }
            return out;
        };
        module.exports = CipherBase;
    }, {
        inherits: 122,
        "safe-buffer": 163,
        stream: 179,
        string_decoder: 51
    } ],
    56: [ function(require, module, exports) {
        var assert = require("assert");
        var cs = require("coinstring");
        var ECKey = require("eckey");
        var inherits = require("inherits");
        var secureRandom = require("secure-random");
        var util = require("./util");
        var DEFAULT_VERSIONS = {
            public: 0,
            private: 128
        };
        function CoinKey(privateKey, versions) {
            if (!(this instanceof CoinKey)) return new CoinKey(privateKey, versions);
            assert(util.isArrayish(privateKey), "privateKey must be arrayish");
            this._versions = util.normalizeVersions(versions) || util.clone(DEFAULT_VERSIONS);
            ECKey.call(this, privateKey, true);
        }
        inherits(CoinKey, ECKey);
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
            versions = util.normalizeVersions(versions);
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
        CoinKey.addressToHash = function(address) {
            return cs.decode(address).slice(1);
        };
        module.exports = CoinKey;
    }, {
        "./util": 57,
        assert: 16,
        coinstring: 58,
        eckey: 81,
        inherits: 122,
        "secure-random": 170
    } ],
    57: [ function(require, module, exports) {
        (function(Buffer) {
            function clone(obj) {
                return JSON.parse(JSON.stringify(obj));
            }
            function isArrayish(maybeArray) {
                return Array.isArray(maybeArray) || maybeArray instanceof Uint8Array || Buffer.isBuffer(maybeArray);
            }
            function normalizeVersions(versions) {
                if (!versions) return null;
                if (typeof versions !== "object") return null;
                versions = clone(versions);
                if (versions.version) versions.versions = versions.version;
                if (versions && "private" in versions) return versions; else versions = versions.versions;
                if (versions && "private" in versions) return versions; else return null;
            }
            module.exports = {
                clone: clone,
                isArrayish: isArrayish,
                normalizeVersions: normalizeVersions
            };
        }).call(this, {
            isBuffer: require("../../is-buffer/index.js")
        });
    }, {
        "../../is-buffer/index.js": 123
    } ],
    58: [ function(require, module, exports) {
        (function(Buffer) {
            var base58 = require("bs58");
            var createHash = require("create-hash");
            function encode(payload, version) {
                if (Array.isArray(payload) || payload instanceof Uint8Array) {
                    payload = new Buffer(payload);
                }
                var buf;
                if (version != null) {
                    if (typeof version === "number") {
                        version = new Buffer([ version ]);
                    }
                    buf = Buffer.concat([ version, payload ]);
                } else {
                    buf = payload;
                }
                var checksum = sha256x2(buf).slice(0, 4);
                var result = Buffer.concat([ buf, checksum ]);
                return base58.encode(result);
            }
            function decode(base58str, version) {
                var arr = base58.decode(base58str);
                var buf = new Buffer(arr);
                var versionLength;
                if (version == null) {
                    versionLength = 0;
                } else {
                    if (typeof version === "number") version = new Buffer([ version ]);
                    versionLength = version.length;
                    var versionCompare = buf.slice(0, versionLength);
                    if (versionCompare.toString("hex") !== version.toString("hex")) {
                        throw new Error("Invalid version");
                    }
                }
                var checksum = buf.slice(-4);
                var endPos = buf.length - 4;
                var bytes = buf.slice(0, endPos);
                var newChecksum = sha256x2(bytes).slice(0, 4);
                if (checksum.toString("hex") !== newChecksum.toString("hex")) {
                    throw new Error("Invalid checksum");
                }
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
                var sha = createHash("sha256").update(buffer).digest();
                return createHash("sha256").update(sha).digest();
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
        bs58: 52,
        buffer: 54,
        "create-hash": 61
    } ],
    59: [ function(require, module, exports) {
        (function(Buffer) {
            function isArray(arg) {
                if (Array.isArray) {
                    return Array.isArray(arg);
                }
                return objectToString(arg) === "[object Array]";
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
                return objectToString(re) === "[object RegExp]";
            }
            exports.isRegExp = isRegExp;
            function isObject(arg) {
                return typeof arg === "object" && arg !== null;
            }
            exports.isObject = isObject;
            function isDate(d) {
                return objectToString(d) === "[object Date]";
            }
            exports.isDate = isDate;
            function isError(e) {
                return objectToString(e) === "[object Error]" || e instanceof Error;
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
            exports.isBuffer = Buffer.isBuffer;
            function objectToString(o) {
                return Object.prototype.toString.call(o);
            }
        }).call(this, {
            isBuffer: require("../../is-buffer/index.js")
        });
    }, {
        "../../is-buffer/index.js": 123
    } ],
    60: [ function(require, module, exports) {
        (function(Buffer) {
            var elliptic = require("elliptic");
            var BN = require("bn.js");
            module.exports = function createECDH(curve) {
                return new ECDH(curve);
            };
            var aliases = {
                secp256k1: {
                    name: "secp256k1",
                    byteLength: 32
                },
                secp224r1: {
                    name: "p224",
                    byteLength: 28
                },
                prime256v1: {
                    name: "p256",
                    byteLength: 32
                },
                prime192v1: {
                    name: "p192",
                    byteLength: 24
                },
                ed25519: {
                    name: "ed25519",
                    byteLength: 32
                },
                secp384r1: {
                    name: "p384",
                    byteLength: 48
                },
                secp521r1: {
                    name: "p521",
                    byteLength: 66
                }
            };
            aliases.p224 = aliases.secp224r1;
            aliases.p256 = aliases.secp256r1 = aliases.prime256v1;
            aliases.p192 = aliases.secp192r1 = aliases.prime192v1;
            aliases.p384 = aliases.secp384r1;
            aliases.p521 = aliases.secp521r1;
            function ECDH(curve) {
                this.curveType = aliases[curve];
                if (!this.curveType) {
                    this.curveType = {
                        name: curve
                    };
                }
                this.curve = new elliptic.ec(this.curveType.name);
                this.keys = void 0;
            }
            ECDH.prototype.generateKeys = function(enc, format) {
                this.keys = this.curve.genKeyPair();
                return this.getPublicKey(enc, format);
            };
            ECDH.prototype.computeSecret = function(other, inenc, enc) {
                inenc = inenc || "utf8";
                if (!Buffer.isBuffer(other)) {
                    other = new Buffer(other, inenc);
                }
                var otherPub = this.curve.keyFromPublic(other).getPublic();
                var out = otherPub.mul(this.keys.getPrivate()).getX();
                return formatReturnValue(out, enc, this.curveType.byteLength);
            };
            ECDH.prototype.getPublicKey = function(enc, format) {
                var key = this.keys.getPublic(format === "compressed", true);
                if (format === "hybrid") {
                    if (key[key.length - 1] % 2) {
                        key[0] = 7;
                    } else {
                        key[0] = 6;
                    }
                }
                return formatReturnValue(key, enc);
            };
            ECDH.prototype.getPrivateKey = function(enc) {
                return formatReturnValue(this.keys.getPrivate(), enc);
            };
            ECDH.prototype.setPublicKey = function(pub, enc) {
                enc = enc || "utf8";
                if (!Buffer.isBuffer(pub)) {
                    pub = new Buffer(pub, enc);
                }
                this.keys._importPublic(pub);
                return this;
            };
            ECDH.prototype.setPrivateKey = function(priv, enc) {
                enc = enc || "utf8";
                if (!Buffer.isBuffer(priv)) {
                    priv = new Buffer(priv, enc);
                }
                var _priv = new BN(priv);
                _priv = _priv.toString(16);
                this.keys._importPrivate(_priv);
                return this;
            };
            function formatReturnValue(bn, enc, len) {
                if (!Array.isArray(bn)) {
                    bn = bn.toArray();
                }
                var buf = new Buffer(bn);
                if (len && buf.length < len) {
                    var zeros = new Buffer(len - buf.length);
                    zeros.fill(0);
                    buf = Buffer.concat([ zeros, buf ]);
                }
                if (!enc) {
                    return buf;
                } else {
                    return buf.toString(enc);
                }
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "bn.js": 23,
        buffer: 54,
        elliptic: 87
    } ],
    61: [ function(require, module, exports) {
        (function(Buffer) {
            "use strict";
            var inherits = require("inherits");
            var md5 = require("./md5");
            var RIPEMD160 = require("ripemd160");
            var sha = require("sha.js");
            var Base = require("cipher-base");
            function HashNoConstructor(hash) {
                Base.call(this, "digest");
                this._hash = hash;
                this.buffers = [];
            }
            inherits(HashNoConstructor, Base);
            HashNoConstructor.prototype._update = function(data) {
                this.buffers.push(data);
            };
            HashNoConstructor.prototype._final = function() {
                var buf = Buffer.concat(this.buffers);
                var r = this._hash(buf);
                this.buffers = null;
                return r;
            };
            function Hash(hash) {
                Base.call(this, "digest");
                this._hash = hash;
            }
            inherits(Hash, Base);
            Hash.prototype._update = function(data) {
                this._hash.update(data);
            };
            Hash.prototype._final = function() {
                return this._hash.digest();
            };
            module.exports = function createHash(alg) {
                alg = alg.toLowerCase();
                if (alg === "md5") return new HashNoConstructor(md5);
                if (alg === "rmd160" || alg === "ripemd160") return new Hash(new RIPEMD160());
                return new Hash(sha(alg));
            };
        }).call(this, require("buffer").Buffer);
    }, {
        "./md5": 63,
        buffer: 54,
        "cipher-base": 55,
        inherits: 122,
        ripemd160: 162,
        "sha.js": 172
    } ],
    62: [ function(require, module, exports) {
        (function(Buffer) {
            "use strict";
            var intSize = 4;
            var zeroBuffer = new Buffer(intSize);
            zeroBuffer.fill(0);
            var charSize = 8;
            var hashSize = 16;
            function toArray(buf) {
                if (buf.length % intSize !== 0) {
                    var len = buf.length + (intSize - buf.length % intSize);
                    buf = Buffer.concat([ buf, zeroBuffer ], len);
                }
                var arr = new Array(buf.length >>> 2);
                for (var i = 0, j = 0; i < buf.length; i += intSize, j++) {
                    arr[j] = buf.readInt32LE(i);
                }
                return arr;
            }
            module.exports = function hash(buf, fn) {
                var arr = fn(toArray(buf), buf.length * charSize);
                buf = new Buffer(hashSize);
                for (var i = 0; i < arr.length; i++) {
                    buf.writeInt32LE(arr[i], i << 2, true);
                }
                return buf;
            };
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    63: [ function(require, module, exports) {
        "use strict";
        var makeHash = require("./make-hash");
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
            return [ a, b, c, d ];
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
            return makeHash(buf, core_md5);
        };
    }, {
        "./make-hash": 62
    } ],
    64: [ function(require, module, exports) {
        "use strict";
        var inherits = require("inherits");
        var Legacy = require("./legacy");
        var Base = require("cipher-base");
        var Buffer = require("safe-buffer").Buffer;
        var md5 = require("create-hash/md5");
        var RIPEMD160 = require("ripemd160");
        var sha = require("sha.js");
        var ZEROS = Buffer.alloc(128);
        function Hmac(alg, key) {
            Base.call(this, "digest");
            if (typeof key === "string") {
                key = Buffer.from(key);
            }
            var blocksize = alg === "sha512" || alg === "sha384" ? 128 : 64;
            this._alg = alg;
            this._key = key;
            if (key.length > blocksize) {
                var hash = alg === "rmd160" ? new RIPEMD160() : sha(alg);
                key = hash.update(key).digest();
            } else if (key.length < blocksize) {
                key = Buffer.concat([ key, ZEROS ], blocksize);
            }
            var ipad = this._ipad = Buffer.allocUnsafe(blocksize);
            var opad = this._opad = Buffer.allocUnsafe(blocksize);
            for (var i = 0; i < blocksize; i++) {
                ipad[i] = key[i] ^ 54;
                opad[i] = key[i] ^ 92;
            }
            this._hash = alg === "rmd160" ? new RIPEMD160() : sha(alg);
            this._hash.update(ipad);
        }
        inherits(Hmac, Base);
        Hmac.prototype._update = function(data) {
            this._hash.update(data);
        };
        Hmac.prototype._final = function() {
            var h = this._hash.digest();
            var hash = this._alg === "rmd160" ? new RIPEMD160() : sha(this._alg);
            return hash.update(this._opad).update(h).digest();
        };
        module.exports = function createHmac(alg, key) {
            alg = alg.toLowerCase();
            if (alg === "rmd160" || alg === "ripemd160") {
                return new Hmac("rmd160", key);
            }
            if (alg === "md5") {
                return new Legacy(md5, key);
            }
            return new Hmac(alg, key);
        };
    }, {
        "./legacy": 65,
        "cipher-base": 55,
        "create-hash/md5": 63,
        inherits: 122,
        ripemd160: 162,
        "safe-buffer": 163,
        "sha.js": 172
    } ],
    65: [ function(require, module, exports) {
        "use strict";
        var inherits = require("inherits");
        var Buffer = require("safe-buffer").Buffer;
        var Base = require("cipher-base");
        var ZEROS = Buffer.alloc(128);
        var blocksize = 64;
        function Hmac(alg, key) {
            Base.call(this, "digest");
            if (typeof key === "string") {
                key = Buffer.from(key);
            }
            this._alg = alg;
            this._key = key;
            if (key.length > blocksize) {
                key = alg(key);
            } else if (key.length < blocksize) {
                key = Buffer.concat([ key, ZEROS ], blocksize);
            }
            var ipad = this._ipad = Buffer.allocUnsafe(blocksize);
            var opad = this._opad = Buffer.allocUnsafe(blocksize);
            for (var i = 0; i < blocksize; i++) {
                ipad[i] = key[i] ^ 54;
                opad[i] = key[i] ^ 92;
            }
            this._hash = [ ipad ];
        }
        inherits(Hmac, Base);
        Hmac.prototype._update = function(data) {
            this._hash.push(data);
        };
        Hmac.prototype._final = function() {
            var h = this._alg(Buffer.concat(this._hash));
            return this._alg(Buffer.concat([ this._opad, h ]));
        };
        module.exports = Hmac;
    }, {
        "cipher-base": 55,
        inherits: 122,
        "safe-buffer": 163
    } ],
    66: [ function(require, module, exports) {
        "use strict";
        exports.randomBytes = exports.rng = exports.pseudoRandomBytes = exports.prng = require("randombytes");
        exports.createHash = exports.Hash = require("create-hash");
        exports.createHmac = exports.Hmac = require("create-hmac");
        var algos = require("browserify-sign/algos");
        var algoKeys = Object.keys(algos);
        var hashes = [ "sha1", "sha224", "sha256", "sha384", "sha512", "md5", "rmd160" ].concat(algoKeys);
        exports.getHashes = function() {
            return hashes;
        };
        var p = require("pbkdf2");
        exports.pbkdf2 = p.pbkdf2;
        exports.pbkdf2Sync = p.pbkdf2Sync;
        var aes = require("browserify-cipher");
        exports.Cipher = aes.Cipher;
        exports.createCipher = aes.createCipher;
        exports.Cipheriv = aes.Cipheriv;
        exports.createCipheriv = aes.createCipheriv;
        exports.Decipher = aes.Decipher;
        exports.createDecipher = aes.createDecipher;
        exports.Decipheriv = aes.Decipheriv;
        exports.createDecipheriv = aes.createDecipheriv;
        exports.getCiphers = aes.getCiphers;
        exports.listCiphers = aes.listCiphers;
        var dh = require("diffie-hellman");
        exports.DiffieHellmanGroup = dh.DiffieHellmanGroup;
        exports.createDiffieHellmanGroup = dh.createDiffieHellmanGroup;
        exports.getDiffieHellman = dh.getDiffieHellman;
        exports.createDiffieHellman = dh.createDiffieHellman;
        exports.DiffieHellman = dh.DiffieHellman;
        var sign = require("browserify-sign");
        exports.createSign = sign.createSign;
        exports.Sign = sign.Sign;
        exports.createVerify = sign.createVerify;
        exports.Verify = sign.Verify;
        exports.createECDH = require("create-ecdh");
        var publicEncrypt = require("public-encrypt");
        exports.publicEncrypt = publicEncrypt.publicEncrypt;
        exports.privateEncrypt = publicEncrypt.privateEncrypt;
        exports.publicDecrypt = publicEncrypt.publicDecrypt;
        exports.privateDecrypt = publicEncrypt.privateDecrypt;
        exports.createCredentials = function() {
            throw new Error([ "sorry, createCredentials is not implemented yet", "we accept pull requests", "https://github.com/crypto-browserify/crypto-browserify" ].join("\n"));
        };
        exports.constants = {
            DH_CHECK_P_NOT_SAFE_PRIME: 2,
            DH_CHECK_P_NOT_PRIME: 1,
            DH_UNABLE_TO_CHECK_GENERATOR: 4,
            DH_NOT_SUITABLE_GENERATOR: 8,
            NPN_ENABLED: 1,
            ALPN_ENABLED: 1,
            RSA_PKCS1_PADDING: 1,
            RSA_SSLV23_PADDING: 2,
            RSA_NO_PADDING: 3,
            RSA_PKCS1_OAEP_PADDING: 4,
            RSA_X931_PADDING: 5,
            RSA_PKCS1_PSS_PADDING: 6,
            POINT_CONVERSION_COMPRESSED: 2,
            POINT_CONVERSION_UNCOMPRESSED: 4,
            POINT_CONVERSION_HYBRID: 6
        };
    }, {
        "browserify-cipher": 41,
        "browserify-sign": 48,
        "browserify-sign/algos": 45,
        "create-ecdh": 60,
        "create-hash": 61,
        "create-hmac": 64,
        "diffie-hellman": 73,
        pbkdf2: 134,
        "public-encrypt": 141,
        randombytes: 147
    } ],
    67: [ function(require, module, exports) {
        "use strict";
        exports.utils = require("./des/utils");
        exports.Cipher = require("./des/cipher");
        exports.DES = require("./des/des");
        exports.CBC = require("./des/cbc");
        exports.EDE = require("./des/ede");
    }, {
        "./des/cbc": 68,
        "./des/cipher": 69,
        "./des/des": 70,
        "./des/ede": 71,
        "./des/utils": 72
    } ],
    68: [ function(require, module, exports) {
        "use strict";
        var assert = require("minimalistic-assert");
        var inherits = require("inherits");
        var proto = {};
        function CBCState(iv) {
            assert.equal(iv.length, 8, "Invalid IV length");
            this.iv = new Array(8);
            for (var i = 0; i < this.iv.length; i++) this.iv[i] = iv[i];
        }
        function instantiate(Base) {
            function CBC(options) {
                Base.call(this, options);
                this._cbcInit();
            }
            inherits(CBC, Base);
            var keys = Object.keys(proto);
            for (var i = 0; i < keys.length; i++) {
                var key = keys[i];
                CBC.prototype[key] = proto[key];
            }
            CBC.create = function create(options) {
                return new CBC(options);
            };
            return CBC;
        }
        exports.instantiate = instantiate;
        proto._cbcInit = function _cbcInit() {
            var state = new CBCState(this.options.iv);
            this._cbcState = state;
        };
        proto._update = function _update(inp, inOff, out, outOff) {
            var state = this._cbcState;
            var superProto = this.constructor.super_.prototype;
            var iv = state.iv;
            if (this.type === "encrypt") {
                for (var i = 0; i < this.blockSize; i++) iv[i] ^= inp[inOff + i];
                superProto._update.call(this, iv, 0, out, outOff);
                for (var i = 0; i < this.blockSize; i++) iv[i] = out[outOff + i];
            } else {
                superProto._update.call(this, inp, inOff, out, outOff);
                for (var i = 0; i < this.blockSize; i++) out[outOff + i] ^= iv[i];
                for (var i = 0; i < this.blockSize; i++) iv[i] = inp[inOff + i];
            }
        };
    }, {
        inherits: 122,
        "minimalistic-assert": 126
    } ],
    69: [ function(require, module, exports) {
        "use strict";
        var assert = require("minimalistic-assert");
        function Cipher(options) {
            this.options = options;
            this.type = this.options.type;
            this.blockSize = 8;
            this._init();
            this.buffer = new Array(this.blockSize);
            this.bufferOff = 0;
        }
        module.exports = Cipher;
        Cipher.prototype._init = function _init() {};
        Cipher.prototype.update = function update(data) {
            if (data.length === 0) return [];
            if (this.type === "decrypt") return this._updateDecrypt(data); else return this._updateEncrypt(data);
        };
        Cipher.prototype._buffer = function _buffer(data, off) {
            var min = Math.min(this.buffer.length - this.bufferOff, data.length - off);
            for (var i = 0; i < min; i++) this.buffer[this.bufferOff + i] = data[off + i];
            this.bufferOff += min;
            return min;
        };
        Cipher.prototype._flushBuffer = function _flushBuffer(out, off) {
            this._update(this.buffer, 0, out, off);
            this.bufferOff = 0;
            return this.blockSize;
        };
        Cipher.prototype._updateEncrypt = function _updateEncrypt(data) {
            var inputOff = 0;
            var outputOff = 0;
            var count = (this.bufferOff + data.length) / this.blockSize | 0;
            var out = new Array(count * this.blockSize);
            if (this.bufferOff !== 0) {
                inputOff += this._buffer(data, inputOff);
                if (this.bufferOff === this.buffer.length) outputOff += this._flushBuffer(out, outputOff);
            }
            var max = data.length - (data.length - inputOff) % this.blockSize;
            for (;inputOff < max; inputOff += this.blockSize) {
                this._update(data, inputOff, out, outputOff);
                outputOff += this.blockSize;
            }
            for (;inputOff < data.length; inputOff++, this.bufferOff++) this.buffer[this.bufferOff] = data[inputOff];
            return out;
        };
        Cipher.prototype._updateDecrypt = function _updateDecrypt(data) {
            var inputOff = 0;
            var outputOff = 0;
            var count = Math.ceil((this.bufferOff + data.length) / this.blockSize) - 1;
            var out = new Array(count * this.blockSize);
            for (;count > 0; count--) {
                inputOff += this._buffer(data, inputOff);
                outputOff += this._flushBuffer(out, outputOff);
            }
            inputOff += this._buffer(data, inputOff);
            return out;
        };
        Cipher.prototype.final = function final(buffer) {
            var first;
            if (buffer) first = this.update(buffer);
            var last;
            if (this.type === "encrypt") last = this._finalEncrypt(); else last = this._finalDecrypt();
            if (first) return first.concat(last); else return last;
        };
        Cipher.prototype._pad = function _pad(buffer, off) {
            if (off === 0) return false;
            while (off < buffer.length) buffer[off++] = 0;
            return true;
        };
        Cipher.prototype._finalEncrypt = function _finalEncrypt() {
            if (!this._pad(this.buffer, this.bufferOff)) return [];
            var out = new Array(this.blockSize);
            this._update(this.buffer, 0, out, 0);
            return out;
        };
        Cipher.prototype._unpad = function _unpad(buffer) {
            return buffer;
        };
        Cipher.prototype._finalDecrypt = function _finalDecrypt() {
            assert.equal(this.bufferOff, this.blockSize, "Not enough data to decrypt");
            var out = new Array(this.blockSize);
            this._flushBuffer(out, 0);
            return this._unpad(out);
        };
    }, {
        "minimalistic-assert": 126
    } ],
    70: [ function(require, module, exports) {
        "use strict";
        var assert = require("minimalistic-assert");
        var inherits = require("inherits");
        var des = require("../des");
        var utils = des.utils;
        var Cipher = des.Cipher;
        function DESState() {
            this.tmp = new Array(2);
            this.keys = null;
        }
        function DES(options) {
            Cipher.call(this, options);
            var state = new DESState();
            this._desState = state;
            this.deriveKeys(state, options.key);
        }
        inherits(DES, Cipher);
        module.exports = DES;
        DES.create = function create(options) {
            return new DES(options);
        };
        var shiftTable = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 ];
        DES.prototype.deriveKeys = function deriveKeys(state, key) {
            state.keys = new Array(16 * 2);
            assert.equal(key.length, this.blockSize, "Invalid key length");
            var kL = utils.readUInt32BE(key, 0);
            var kR = utils.readUInt32BE(key, 4);
            utils.pc1(kL, kR, state.tmp, 0);
            kL = state.tmp[0];
            kR = state.tmp[1];
            for (var i = 0; i < state.keys.length; i += 2) {
                var shift = shiftTable[i >>> 1];
                kL = utils.r28shl(kL, shift);
                kR = utils.r28shl(kR, shift);
                utils.pc2(kL, kR, state.keys, i);
            }
        };
        DES.prototype._update = function _update(inp, inOff, out, outOff) {
            var state = this._desState;
            var l = utils.readUInt32BE(inp, inOff);
            var r = utils.readUInt32BE(inp, inOff + 4);
            utils.ip(l, r, state.tmp, 0);
            l = state.tmp[0];
            r = state.tmp[1];
            if (this.type === "encrypt") this._encrypt(state, l, r, state.tmp, 0); else this._decrypt(state, l, r, state.tmp, 0);
            l = state.tmp[0];
            r = state.tmp[1];
            utils.writeUInt32BE(out, l, outOff);
            utils.writeUInt32BE(out, r, outOff + 4);
        };
        DES.prototype._pad = function _pad(buffer, off) {
            var value = buffer.length - off;
            for (var i = off; i < buffer.length; i++) buffer[i] = value;
            return true;
        };
        DES.prototype._unpad = function _unpad(buffer) {
            var pad = buffer[buffer.length - 1];
            for (var i = buffer.length - pad; i < buffer.length; i++) assert.equal(buffer[i], pad);
            return buffer.slice(0, buffer.length - pad);
        };
        DES.prototype._encrypt = function _encrypt(state, lStart, rStart, out, off) {
            var l = lStart;
            var r = rStart;
            for (var i = 0; i < state.keys.length; i += 2) {
                var keyL = state.keys[i];
                var keyR = state.keys[i + 1];
                utils.expand(r, state.tmp, 0);
                keyL ^= state.tmp[0];
                keyR ^= state.tmp[1];
                var s = utils.substitute(keyL, keyR);
                var f = utils.permute(s);
                var t = r;
                r = (l ^ f) >>> 0;
                l = t;
            }
            utils.rip(r, l, out, off);
        };
        DES.prototype._decrypt = function _decrypt(state, lStart, rStart, out, off) {
            var l = rStart;
            var r = lStart;
            for (var i = state.keys.length - 2; i >= 0; i -= 2) {
                var keyL = state.keys[i];
                var keyR = state.keys[i + 1];
                utils.expand(l, state.tmp, 0);
                keyL ^= state.tmp[0];
                keyR ^= state.tmp[1];
                var s = utils.substitute(keyL, keyR);
                var f = utils.permute(s);
                var t = l;
                l = (r ^ f) >>> 0;
                r = t;
            }
            utils.rip(l, r, out, off);
        };
    }, {
        "../des": 67,
        inherits: 122,
        "minimalistic-assert": 126
    } ],
    71: [ function(require, module, exports) {
        "use strict";
        var assert = require("minimalistic-assert");
        var inherits = require("inherits");
        var des = require("../des");
        var Cipher = des.Cipher;
        var DES = des.DES;
        function EDEState(type, key) {
            assert.equal(key.length, 24, "Invalid key length");
            var k1 = key.slice(0, 8);
            var k2 = key.slice(8, 16);
            var k3 = key.slice(16, 24);
            if (type === "encrypt") {
                this.ciphers = [ DES.create({
                    type: "encrypt",
                    key: k1
                }), DES.create({
                    type: "decrypt",
                    key: k2
                }), DES.create({
                    type: "encrypt",
                    key: k3
                }) ];
            } else {
                this.ciphers = [ DES.create({
                    type: "decrypt",
                    key: k3
                }), DES.create({
                    type: "encrypt",
                    key: k2
                }), DES.create({
                    type: "decrypt",
                    key: k1
                }) ];
            }
        }
        function EDE(options) {
            Cipher.call(this, options);
            var state = new EDEState(this.type, this.options.key);
            this._edeState = state;
        }
        inherits(EDE, Cipher);
        module.exports = EDE;
        EDE.create = function create(options) {
            return new EDE(options);
        };
        EDE.prototype._update = function _update(inp, inOff, out, outOff) {
            var state = this._edeState;
            state.ciphers[0]._update(inp, inOff, out, outOff);
            state.ciphers[1]._update(out, outOff, out, outOff);
            state.ciphers[2]._update(out, outOff, out, outOff);
        };
        EDE.prototype._pad = DES.prototype._pad;
        EDE.prototype._unpad = DES.prototype._unpad;
    }, {
        "../des": 67,
        inherits: 122,
        "minimalistic-assert": 126
    } ],
    72: [ function(require, module, exports) {
        "use strict";
        exports.readUInt32BE = function readUInt32BE(bytes, off) {
            var res = bytes[0 + off] << 24 | bytes[1 + off] << 16 | bytes[2 + off] << 8 | bytes[3 + off];
            return res >>> 0;
        };
        exports.writeUInt32BE = function writeUInt32BE(bytes, value, off) {
            bytes[0 + off] = value >>> 24;
            bytes[1 + off] = value >>> 16 & 255;
            bytes[2 + off] = value >>> 8 & 255;
            bytes[3 + off] = value & 255;
        };
        exports.ip = function ip(inL, inR, out, off) {
            var outL = 0;
            var outR = 0;
            for (var i = 6; i >= 0; i -= 2) {
                for (var j = 0; j <= 24; j += 8) {
                    outL <<= 1;
                    outL |= inR >>> j + i & 1;
                }
                for (var j = 0; j <= 24; j += 8) {
                    outL <<= 1;
                    outL |= inL >>> j + i & 1;
                }
            }
            for (var i = 6; i >= 0; i -= 2) {
                for (var j = 1; j <= 25; j += 8) {
                    outR <<= 1;
                    outR |= inR >>> j + i & 1;
                }
                for (var j = 1; j <= 25; j += 8) {
                    outR <<= 1;
                    outR |= inL >>> j + i & 1;
                }
            }
            out[off + 0] = outL >>> 0;
            out[off + 1] = outR >>> 0;
        };
        exports.rip = function rip(inL, inR, out, off) {
            var outL = 0;
            var outR = 0;
            for (var i = 0; i < 4; i++) {
                for (var j = 24; j >= 0; j -= 8) {
                    outL <<= 1;
                    outL |= inR >>> j + i & 1;
                    outL <<= 1;
                    outL |= inL >>> j + i & 1;
                }
            }
            for (var i = 4; i < 8; i++) {
                for (var j = 24; j >= 0; j -= 8) {
                    outR <<= 1;
                    outR |= inR >>> j + i & 1;
                    outR <<= 1;
                    outR |= inL >>> j + i & 1;
                }
            }
            out[off + 0] = outL >>> 0;
            out[off + 1] = outR >>> 0;
        };
        exports.pc1 = function pc1(inL, inR, out, off) {
            var outL = 0;
            var outR = 0;
            for (var i = 7; i >= 5; i--) {
                for (var j = 0; j <= 24; j += 8) {
                    outL <<= 1;
                    outL |= inR >> j + i & 1;
                }
                for (var j = 0; j <= 24; j += 8) {
                    outL <<= 1;
                    outL |= inL >> j + i & 1;
                }
            }
            for (var j = 0; j <= 24; j += 8) {
                outL <<= 1;
                outL |= inR >> j + i & 1;
            }
            for (var i = 1; i <= 3; i++) {
                for (var j = 0; j <= 24; j += 8) {
                    outR <<= 1;
                    outR |= inR >> j + i & 1;
                }
                for (var j = 0; j <= 24; j += 8) {
                    outR <<= 1;
                    outR |= inL >> j + i & 1;
                }
            }
            for (var j = 0; j <= 24; j += 8) {
                outR <<= 1;
                outR |= inL >> j + i & 1;
            }
            out[off + 0] = outL >>> 0;
            out[off + 1] = outR >>> 0;
        };
        exports.r28shl = function r28shl(num, shift) {
            return num << shift & 268435455 | num >>> 28 - shift;
        };
        var pc2table = [ 14, 11, 17, 4, 27, 23, 25, 0, 13, 22, 7, 18, 5, 9, 16, 24, 2, 20, 12, 21, 1, 8, 15, 26, 15, 4, 25, 19, 9, 1, 26, 16, 5, 11, 23, 8, 12, 7, 17, 0, 22, 3, 10, 14, 6, 20, 27, 24 ];
        exports.pc2 = function pc2(inL, inR, out, off) {
            var outL = 0;
            var outR = 0;
            var len = pc2table.length >>> 1;
            for (var i = 0; i < len; i++) {
                outL <<= 1;
                outL |= inL >>> pc2table[i] & 1;
            }
            for (var i = len; i < pc2table.length; i++) {
                outR <<= 1;
                outR |= inR >>> pc2table[i] & 1;
            }
            out[off + 0] = outL >>> 0;
            out[off + 1] = outR >>> 0;
        };
        exports.expand = function expand(r, out, off) {
            var outL = 0;
            var outR = 0;
            outL = (r & 1) << 5 | r >>> 27;
            for (var i = 23; i >= 15; i -= 4) {
                outL <<= 6;
                outL |= r >>> i & 63;
            }
            for (var i = 11; i >= 3; i -= 4) {
                outR |= r >>> i & 63;
                outR <<= 6;
            }
            outR |= (r & 31) << 1 | r >>> 31;
            out[off + 0] = outL >>> 0;
            out[off + 1] = outR >>> 0;
        };
        var sTable = [ 14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13, 15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9, 10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12, 7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14, 2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3, 12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13, 4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12, 13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11 ];
        exports.substitute = function substitute(inL, inR) {
            var out = 0;
            for (var i = 0; i < 4; i++) {
                var b = inL >>> 18 - i * 6 & 63;
                var sb = sTable[i * 64 + b];
                out <<= 4;
                out |= sb;
            }
            for (var i = 0; i < 4; i++) {
                var b = inR >>> 18 - i * 6 & 63;
                var sb = sTable[4 * 64 + i * 64 + b];
                out <<= 4;
                out |= sb;
            }
            return out >>> 0;
        };
        var permuteTable = [ 16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22, 30, 24, 8, 18, 0, 5, 29, 23, 13, 19, 2, 26, 10, 21, 28, 7 ];
        exports.permute = function permute(num) {
            var out = 0;
            for (var i = 0; i < permuteTable.length; i++) {
                out <<= 1;
                out |= num >>> permuteTable[i] & 1;
            }
            return out >>> 0;
        };
        exports.padSplit = function padSplit(num, size, group) {
            var str = num.toString(2);
            while (str.length < size) str = "0" + str;
            var out = [];
            for (var i = 0; i < size; i += group) out.push(str.slice(i, i + group));
            return out.join(" ");
        };
    }, {} ],
    73: [ function(require, module, exports) {
        (function(Buffer) {
            var generatePrime = require("./lib/generatePrime");
            var primes = require("./lib/primes.json");
            var DH = require("./lib/dh");
            function getDiffieHellman(mod) {
                var prime = new Buffer(primes[mod].prime, "hex");
                var gen = new Buffer(primes[mod].gen, "hex");
                return new DH(prime, gen);
            }
            var ENCODINGS = {
                binary: true,
                hex: true,
                base64: true
            };
            function createDiffieHellman(prime, enc, generator, genc) {
                if (Buffer.isBuffer(enc) || ENCODINGS[enc] === undefined) {
                    return createDiffieHellman(prime, "binary", enc, generator);
                }
                enc = enc || "binary";
                genc = genc || "binary";
                generator = generator || new Buffer([ 2 ]);
                if (!Buffer.isBuffer(generator)) {
                    generator = new Buffer(generator, genc);
                }
                if (typeof prime === "number") {
                    return new DH(generatePrime(prime, generator), generator, true);
                }
                if (!Buffer.isBuffer(prime)) {
                    prime = new Buffer(prime, enc);
                }
                return new DH(prime, generator, true);
            }
            exports.DiffieHellmanGroup = exports.createDiffieHellmanGroup = exports.getDiffieHellman = getDiffieHellman;
            exports.createDiffieHellman = exports.DiffieHellman = createDiffieHellman;
        }).call(this, require("buffer").Buffer);
    }, {
        "./lib/dh": 74,
        "./lib/generatePrime": 75,
        "./lib/primes.json": 76,
        buffer: 54
    } ],
    74: [ function(require, module, exports) {
        (function(Buffer) {
            var BN = require("bn.js");
            var MillerRabin = require("miller-rabin");
            var millerRabin = new MillerRabin();
            var TWENTYFOUR = new BN(24);
            var ELEVEN = new BN(11);
            var TEN = new BN(10);
            var THREE = new BN(3);
            var SEVEN = new BN(7);
            var primes = require("./generatePrime");
            var randomBytes = require("randombytes");
            module.exports = DH;
            function setPublicKey(pub, enc) {
                enc = enc || "utf8";
                if (!Buffer.isBuffer(pub)) {
                    pub = new Buffer(pub, enc);
                }
                this._pub = new BN(pub);
                return this;
            }
            function setPrivateKey(priv, enc) {
                enc = enc || "utf8";
                if (!Buffer.isBuffer(priv)) {
                    priv = new Buffer(priv, enc);
                }
                this._priv = new BN(priv);
                return this;
            }
            var primeCache = {};
            function checkPrime(prime, generator) {
                var gen = generator.toString("hex");
                var hex = [ gen, prime.toString(16) ].join("_");
                if (hex in primeCache) {
                    return primeCache[hex];
                }
                var error = 0;
                if (prime.isEven() || !primes.simpleSieve || !primes.fermatTest(prime) || !millerRabin.test(prime)) {
                    error += 1;
                    if (gen === "02" || gen === "05") {
                        error += 8;
                    } else {
                        error += 4;
                    }
                    primeCache[hex] = error;
                    return error;
                }
                if (!millerRabin.test(prime.shrn(1))) {
                    error += 2;
                }
                var rem;
                switch (gen) {
                  case "02":
                    if (prime.mod(TWENTYFOUR).cmp(ELEVEN)) {
                        error += 8;
                    }
                    break;

                  case "05":
                    rem = prime.mod(TEN);
                    if (rem.cmp(THREE) && rem.cmp(SEVEN)) {
                        error += 8;
                    }
                    break;

                  default:
                    error += 4;
                }
                primeCache[hex] = error;
                return error;
            }
            function DH(prime, generator, malleable) {
                this.setGenerator(generator);
                this.__prime = new BN(prime);
                this._prime = BN.mont(this.__prime);
                this._primeLen = prime.length;
                this._pub = undefined;
                this._priv = undefined;
                this._primeCode = undefined;
                if (malleable) {
                    this.setPublicKey = setPublicKey;
                    this.setPrivateKey = setPrivateKey;
                } else {
                    this._primeCode = 8;
                }
            }
            Object.defineProperty(DH.prototype, "verifyError", {
                enumerable: true,
                get: function() {
                    if (typeof this._primeCode !== "number") {
                        this._primeCode = checkPrime(this.__prime, this.__gen);
                    }
                    return this._primeCode;
                }
            });
            DH.prototype.generateKeys = function() {
                if (!this._priv) {
                    this._priv = new BN(randomBytes(this._primeLen));
                }
                this._pub = this._gen.toRed(this._prime).redPow(this._priv).fromRed();
                return this.getPublicKey();
            };
            DH.prototype.computeSecret = function(other) {
                other = new BN(other);
                other = other.toRed(this._prime);
                var secret = other.redPow(this._priv).fromRed();
                var out = new Buffer(secret.toArray());
                var prime = this.getPrime();
                if (out.length < prime.length) {
                    var front = new Buffer(prime.length - out.length);
                    front.fill(0);
                    out = Buffer.concat([ front, out ]);
                }
                return out;
            };
            DH.prototype.getPublicKey = function getPublicKey(enc) {
                return formatReturnValue(this._pub, enc);
            };
            DH.prototype.getPrivateKey = function getPrivateKey(enc) {
                return formatReturnValue(this._priv, enc);
            };
            DH.prototype.getPrime = function(enc) {
                return formatReturnValue(this.__prime, enc);
            };
            DH.prototype.getGenerator = function(enc) {
                return formatReturnValue(this._gen, enc);
            };
            DH.prototype.setGenerator = function(gen, enc) {
                enc = enc || "utf8";
                if (!Buffer.isBuffer(gen)) {
                    gen = new Buffer(gen, enc);
                }
                this.__gen = gen;
                this._gen = new BN(gen);
                return this;
            };
            function formatReturnValue(bn, enc) {
                var buf = new Buffer(bn.toArray());
                if (!enc) {
                    return buf;
                } else {
                    return buf.toString(enc);
                }
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "./generatePrime": 75,
        "bn.js": 23,
        buffer: 54,
        "miller-rabin": 125,
        randombytes: 147
    } ],
    75: [ function(require, module, exports) {
        var randomBytes = require("randombytes");
        module.exports = findPrime;
        findPrime.simpleSieve = simpleSieve;
        findPrime.fermatTest = fermatTest;
        var BN = require("bn.js");
        var TWENTYFOUR = new BN(24);
        var MillerRabin = require("miller-rabin");
        var millerRabin = new MillerRabin();
        var ONE = new BN(1);
        var TWO = new BN(2);
        var FIVE = new BN(5);
        var SIXTEEN = new BN(16);
        var EIGHT = new BN(8);
        var TEN = new BN(10);
        var THREE = new BN(3);
        var SEVEN = new BN(7);
        var ELEVEN = new BN(11);
        var FOUR = new BN(4);
        var TWELVE = new BN(12);
        var primes = null;
        function _getPrimes() {
            if (primes !== null) return primes;
            var limit = 1048576;
            var res = [];
            res[0] = 2;
            for (var i = 1, k = 3; k < limit; k += 2) {
                var sqrt = Math.ceil(Math.sqrt(k));
                for (var j = 0; j < i && res[j] <= sqrt; j++) if (k % res[j] === 0) break;
                if (i !== j && res[j] <= sqrt) continue;
                res[i++] = k;
            }
            primes = res;
            return res;
        }
        function simpleSieve(p) {
            var primes = _getPrimes();
            for (var i = 0; i < primes.length; i++) if (p.modn(primes[i]) === 0) {
                if (p.cmpn(primes[i]) === 0) {
                    return true;
                } else {
                    return false;
                }
            }
            return true;
        }
        function fermatTest(p) {
            var red = BN.mont(p);
            return TWO.toRed(red).redPow(p.subn(1)).fromRed().cmpn(1) === 0;
        }
        function findPrime(bits, gen) {
            if (bits < 16) {
                if (gen === 2 || gen === 5) {
                    return new BN([ 140, 123 ]);
                } else {
                    return new BN([ 140, 39 ]);
                }
            }
            gen = new BN(gen);
            var num, n2;
            while (true) {
                num = new BN(randomBytes(Math.ceil(bits / 8)));
                while (num.bitLength() > bits) {
                    num.ishrn(1);
                }
                if (num.isEven()) {
                    num.iadd(ONE);
                }
                if (!num.testn(1)) {
                    num.iadd(TWO);
                }
                if (!gen.cmp(TWO)) {
                    while (num.mod(TWENTYFOUR).cmp(ELEVEN)) {
                        num.iadd(FOUR);
                    }
                } else if (!gen.cmp(FIVE)) {
                    while (num.mod(TEN).cmp(THREE)) {
                        num.iadd(FOUR);
                    }
                }
                n2 = num.shrn(1);
                if (simpleSieve(n2) && simpleSieve(num) && fermatTest(n2) && fermatTest(num) && millerRabin.test(n2) && millerRabin.test(num)) {
                    return num;
                }
            }
        }
    }, {
        "bn.js": 23,
        "miller-rabin": 125,
        randombytes: 147
    } ],
    76: [ function(require, module, exports) {
        module.exports = {
            modp1: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff"
            },
            modp2: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff"
            },
            modp5: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
            },
            modp14: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff"
            },
            modp15: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
            },
            modp16: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff"
            },
            modp17: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff"
            },
            modp18: {
                gen: "02",
                prime: "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff"
            }
        };
    }, {} ],
    77: [ function(require, module, exports) {
        (function(Buffer) {
            var createHmac = require("create-hmac");
            var typeforce = require("typeforce");
            var types = require("./types");
            var BigInteger = require("bigi");
            var ECSignature = require("./ecsignature");
            var ZERO = new Buffer([ 0 ]);
            var ONE = new Buffer([ 1 ]);
            var ecurve = require("ecurve");
            var secp256k1 = ecurve.getCurveByName("secp256k1");
            function deterministicGenerateK(hash, x, checkSig) {
                typeforce(types.tuple(types.Hash256bit, types.Buffer256bit, types.Function), arguments);
                var k = new Buffer(32);
                var v = new Buffer(32);
                v.fill(1);
                k.fill(0);
                k = createHmac("sha256", k).update(v).update(ZERO).update(x).update(hash).digest();
                v = createHmac("sha256", k).update(v).digest();
                k = createHmac("sha256", k).update(v).update(ONE).update(x).update(hash).digest();
                v = createHmac("sha256", k).update(v).digest();
                v = createHmac("sha256", k).update(v).digest();
                var T = BigInteger.fromBuffer(v);
                while (T.signum() <= 0 || T.compareTo(secp256k1.n) >= 0 || !checkSig(T)) {
                    k = createHmac("sha256", k).update(v).update(ZERO).digest();
                    v = createHmac("sha256", k).update(v).digest();
                    v = createHmac("sha256", k).update(v).digest();
                    T = BigInteger.fromBuffer(v);
                }
                return T;
            }
            var N_OVER_TWO = secp256k1.n.shiftRight(1);
            function sign(hash, d) {
                typeforce(types.tuple(types.Hash256bit, types.BigInt), arguments);
                var x = d.toBuffer(32);
                var e = BigInteger.fromBuffer(hash);
                var n = secp256k1.n;
                var G = secp256k1.G;
                var r, s;
                deterministicGenerateK(hash, x, function(k) {
                    var Q = G.multiply(k);
                    if (secp256k1.isInfinity(Q)) return false;
                    r = Q.affineX.mod(n);
                    if (r.signum() === 0) return false;
                    s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
                    if (s.signum() === 0) return false;
                    return true;
                });
                if (s.compareTo(N_OVER_TWO) > 0) {
                    s = n.subtract(s);
                }
                return new ECSignature(r, s);
            }
            function verify(hash, signature, Q) {
                typeforce(types.tuple(types.Hash256bit, types.ECSignature, types.ECPoint), arguments);
                var n = secp256k1.n;
                var G = secp256k1.G;
                var r = signature.r;
                var s = signature.s;
                if (r.signum() <= 0 || r.compareTo(n) >= 0) return false;
                if (s.signum() <= 0 || s.compareTo(n) >= 0) return false;
                var e = BigInteger.fromBuffer(hash);
                var sInv = s.modInverse(n);
                var u1 = e.multiply(sInv).mod(n);
                var u2 = r.multiply(sInv).mod(n);
                var R = G.multiplyTwo(u1, Q, u2);
                if (secp256k1.isInfinity(R)) return false;
                var xR = R.affineX;
                var v = xR.mod(n);
                return v.equals(r);
            }
            function recoverPubKey(e, signature, i) {
                typeforce(types.tuple(types.BigInt, types.ECSignature, types.UInt2), arguments);
                var n = secp256k1.n;
                var G = secp256k1.G;
                var r = signature.r;
                var s = signature.s;
                if (r.signum() <= 0 || r.compareTo(n) >= 0) throw new Error("Invalid r value");
                if (s.signum() <= 0 || s.compareTo(n) >= 0) throw new Error("Invalid s value");
                var isYOdd = i & 1;
                var isSecondKey = i >> 1;
                var x = isSecondKey ? r.add(n) : r;
                var R = secp256k1.pointFromX(isYOdd, x);
                var nR = R.multiply(n);
                if (!secp256k1.isInfinity(nR)) throw new Error("nR is not a valid curve point");
                var rInv = r.modInverse(n);
                var eNeg = e.negate().mod(n);
                var Q = R.multiplyTwo(s, G, eNeg).multiply(rInv);
                secp256k1.validate(Q);
                return Q;
            }
            function calcPubKeyRecoveryParam(e, signature, Q) {
                typeforce(types.tuple(types.BigInt, types.ECSignature, types.ECPoint), arguments);
                for (var i = 0; i < 4; i++) {
                    var Qprime = recoverPubKey(e, signature, i);
                    if (Qprime.equals(Q)) {
                        return i;
                    }
                }
                throw new Error("Unable to find valid recovery factor");
            }
            module.exports = {
                calcPubKeyRecoveryParam: calcPubKeyRecoveryParam,
                deterministicGenerateK: deterministicGenerateK,
                recoverPubKey: recoverPubKey,
                sign: sign,
                verify: verify,
                curve: secp256k1
            };
        }).call(this, require("buffer").Buffer);
    }, {
        "./ecsignature": 78,
        "./types": 80,
        bigi: 20,
        buffer: 54,
        "create-hmac": 64,
        ecurve: 84,
        typeforce: 183
    } ],
    78: [ function(require, module, exports) {
        (function(Buffer) {
            var bip66 = require("bip66");
            var typeforce = require("typeforce");
            var types = require("./types");
            var BigInteger = require("bigi");
            function ECSignature(r, s) {
                typeforce(types.tuple(types.BigInt, types.BigInt), arguments);
                this.r = r;
                this.s = s;
            }
            ECSignature.parseCompact = function(buffer) {
                if (buffer.length !== 65) throw new Error("Invalid signature length");
                var flagByte = buffer.readUInt8(0) - 27;
                if (flagByte !== (flagByte & 7)) throw new Error("Invalid signature parameter");
                var compressed = !!(flagByte & 4);
                var recoveryParam = flagByte & 3;
                var r = BigInteger.fromBuffer(buffer.slice(1, 33));
                var s = BigInteger.fromBuffer(buffer.slice(33));
                return {
                    compressed: compressed,
                    i: recoveryParam,
                    signature: new ECSignature(r, s)
                };
            };
            ECSignature.fromDER = function(buffer) {
                var decode = bip66.decode(buffer);
                var r = BigInteger.fromDERInteger(decode.r);
                var s = BigInteger.fromDERInteger(decode.s);
                return new ECSignature(r, s);
            };
            ECSignature.parseScriptSignature = function(buffer) {
                var hashType = buffer.readUInt8(buffer.length - 1);
                var hashTypeMod = hashType & ~128;
                if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error("Invalid hashType " + hashType);
                return {
                    signature: ECSignature.fromDER(buffer.slice(0, -1)),
                    hashType: hashType
                };
            };
            ECSignature.prototype.toCompact = function(i, compressed) {
                if (compressed) {
                    i += 4;
                }
                i += 27;
                var buffer = new Buffer(65);
                buffer.writeUInt8(i, 0);
                this.r.toBuffer(32).copy(buffer, 1);
                this.s.toBuffer(32).copy(buffer, 33);
                return buffer;
            };
            ECSignature.prototype.toDER = function() {
                var r = new Buffer(this.r.toDERInteger());
                var s = new Buffer(this.s.toDERInteger());
                return bip66.encode(r, s);
            };
            ECSignature.prototype.toScriptSignature = function(hashType) {
                var hashTypeMod = hashType & ~128;
                if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error("Invalid hashType " + hashType);
                var hashTypeBuffer = new Buffer(1);
                hashTypeBuffer.writeUInt8(hashType, 0);
                return Buffer.concat([ this.toDER(), hashTypeBuffer ]);
            };
            module.exports = ECSignature;
        }).call(this, require("buffer").Buffer);
    }, {
        "./types": 80,
        bigi: 20,
        bip66: 22,
        buffer: 54,
        typeforce: 183
    } ],
    79: [ function(require, module, exports) {
        var ecdsa = require("./ecdsa");
        var ecsignature = require("./ecsignature");
        var exp = {};
        Object.keys(ecdsa).forEach(function(fnName) {
            exp[fnName] = ecdsa[fnName];
        });
        exp.ECSignature = ecsignature;
        module.exports = exp;
    }, {
        "./ecdsa": 77,
        "./ecsignature": 78
    } ],
    80: [ function(require, module, exports) {
        var typeforce = require("typeforce");
        function nBuffer(value, n) {
            typeforce(types.Buffer, value);
            if (value.length !== n) throw new Error("Expected " + n * 8 + "-bit Buffer, got " + value.length * 8 + "-bit Buffer");
            return true;
        }
        function Hash160bit(value) {
            return nBuffer(value, 20);
        }
        function Hash256bit(value) {
            return nBuffer(value, 32);
        }
        function Buffer256bit(value) {
            return nBuffer(value, 32);
        }
        var UINT53_MAX = Math.pow(2, 53) - 1;
        function UInt2(value) {
            return (value & 3) === value;
        }
        function UInt8(value) {
            return (value & 255) === value;
        }
        function UInt32(value) {
            return value >>> 0 === value;
        }
        function UInt53(value) {
            return typeforce.Number(value) && value >= 0 && value <= UINT53_MAX && Math.floor(value) === value;
        }
        var BigInt = typeforce.quacksLike("BigInteger");
        var ECPoint = typeforce.quacksLike("Point");
        var ECSignature = typeforce.compile({
            r: BigInt,
            s: BigInt
        });
        var Network = typeforce.compile({
            messagePrefix: typeforce.oneOf(typeforce.Buffer, typeforce.String),
            bip32: {
                public: UInt32,
                private: UInt32
            },
            pubKeyHash: UInt8,
            scriptHash: UInt8,
            wif: UInt8,
            dustThreshold: UInt53
        });
        var types = {
            BigInt: BigInt,
            Buffer256bit: Buffer256bit,
            ECPoint: ECPoint,
            ECSignature: ECSignature,
            Hash160bit: Hash160bit,
            Hash256bit: Hash256bit,
            Network: Network,
            UInt2: UInt2,
            UInt8: UInt8,
            UInt32: UInt32,
            UInt53: UInt53
        };
        for (var typeName in typeforce) {
            types[typeName] = typeforce[typeName];
        }
        module.exports = types;
    }, {
        typeforce: 183
    } ],
    81: [ function(require, module, exports) {
        (function(Buffer) {
            var crypto = require("crypto");
            var secp256k1 = require("secp256k1");
            function ECKey(bytes, compressed) {
                if (!(this instanceof ECKey)) return new ECKey(bytes, compressed);
                this._compressed = typeof compressed === "boolean" ? compressed : true;
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
                    if (bytes.length !== 32) throw new Error("private key bytes must have a length of 32");
                    if (this._compressed) {
                        this._exportKey = Buffer.concat([ this.key, new Buffer([ 1 ]) ]);
                    } else {
                        this._exportKey = Buffer.concat([ this.key ]);
                    }
                    this._publicKey = null;
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
                    if (!this._publicKey) this._publicKey = secp256k1.publicKeyCreate(this.key, this.compressed);
                    return new Buffer(this._publicKey);
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
        buffer: 54,
        crypto: 66,
        secp256k1: 164
    } ],
    82: [ function(require, module, exports) {
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
            this.pLength = Math.floor((this.p.bitLength() + 7) / 8);
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
        "./point": 86,
        assert: 16,
        bigi: 20
    } ],
    83: [ function(require, module, exports) {
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
    84: [ function(require, module, exports) {
        var Point = require("./point");
        var Curve = require("./curve");
        var getCurveByName = require("./names");
        module.exports = {
            Curve: Curve,
            Point: Point,
            getCurveByName: getCurveByName
        };
    }, {
        "./curve": 82,
        "./names": 85,
        "./point": 86
    } ],
    85: [ function(require, module, exports) {
        var BigInteger = require("bigi");
        var curves = require("./curves.json");
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
        "./curve": 82,
        "./curves.json": 83,
        bigi: 20
    } ],
    86: [ function(require, module, exports) {
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
                var y1z1 = y1.multiply(this.z).mod(this.curve.p);
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
                    var hBit = h.testBit(i);
                    var eBit = e.testBit(i);
                    R = R.twice();
                    if (hBit !== eBit) {
                        R = R.add(hBit ? this : neg);
                    }
                }
                return R;
            };
            Point.prototype.multiplyTwo = function(j, x, k) {
                var i = Math.max(j.bitLength(), k.bitLength()) - 1;
                var R = this.curve.infinity;
                var both = this.add(x);
                while (i >= 0) {
                    var jBit = j.testBit(i);
                    var kBit = k.testBit(i);
                    R = R.twice();
                    if (jBit) {
                        if (kBit) {
                            R = R.add(both);
                        } else {
                            R = R.add(this);
                        }
                    } else if (kBit) {
                        R = R.add(x);
                    }
                    --i;
                }
                return R;
            };
            Point.prototype.getEncoded = function(compressed) {
                if (compressed == null) compressed = this.compressed;
                if (this.curve.isInfinity(this)) return new Buffer("00", "hex");
                var x = this.affineX;
                var y = this.affineY;
                var byteLength = this.curve.pLength;
                var buffer;
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
                var byteLength = Math.floor((curve.p.bitLength() + 7) / 8);
                var x = BigInteger.fromBuffer(buffer.slice(1, 1 + byteLength));
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
        assert: 16,
        bigi: 20,
        buffer: 54
    } ],
    87: [ function(require, module, exports) {
        "use strict";
        var elliptic = exports;
        elliptic.version = require("../package.json").version;
        elliptic.utils = require("./elliptic/utils");
        elliptic.rand = require("brorand");
        elliptic.curve = require("./elliptic/curve");
        elliptic.curves = require("./elliptic/curves");
        elliptic.ec = require("./elliptic/ec");
        elliptic.eddsa = require("./elliptic/eddsa");
    }, {
        "../package.json": 102,
        "./elliptic/curve": 90,
        "./elliptic/curves": 93,
        "./elliptic/ec": 94,
        "./elliptic/eddsa": 97,
        "./elliptic/utils": 101,
        brorand: 24
    } ],
    88: [ function(require, module, exports) {
        "use strict";
        var BN = require("bn.js");
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var getNAF = utils.getNAF;
        var getJSF = utils.getJSF;
        var assert = utils.assert;
        function BaseCurve(type, conf) {
            this.type = type;
            this.p = new BN(conf.p, 16);
            this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);
            this.zero = new BN(0).toRed(this.red);
            this.one = new BN(1).toRed(this.red);
            this.two = new BN(2).toRed(this.red);
            this.n = conf.n && new BN(conf.n, 16);
            this.g = conf.g && this.pointFromJSON(conf.g, conf.gRed);
            this._wnafT1 = new Array(4);
            this._wnafT2 = new Array(4);
            this._wnafT3 = new Array(4);
            this._wnafT4 = new Array(4);
            var adjustCount = this.n && this.p.div(this.n);
            if (!adjustCount || adjustCount.cmpn(100) > 0) {
                this.redN = null;
            } else {
                this._maxwellTrick = true;
                this.redN = this.n.toRed(this.red);
            }
        }
        module.exports = BaseCurve;
        BaseCurve.prototype.point = function point() {
            throw new Error("Not implemented");
        };
        BaseCurve.prototype.validate = function validate() {
            throw new Error("Not implemented");
        };
        BaseCurve.prototype._fixedNafMul = function _fixedNafMul(p, k) {
            assert(p.precomputed);
            var doubles = p._getDoubles();
            var naf = getNAF(k, 1);
            var I = (1 << doubles.step + 1) - (doubles.step % 2 === 0 ? 2 : 1);
            I /= 3;
            var repr = [];
            for (var j = 0; j < naf.length; j += doubles.step) {
                var nafW = 0;
                for (var k = j + doubles.step - 1; k >= j; k--) nafW = (nafW << 1) + naf[k];
                repr.push(nafW);
            }
            var a = this.jpoint(null, null, null);
            var b = this.jpoint(null, null, null);
            for (var i = I; i > 0; i--) {
                for (var j = 0; j < repr.length; j++) {
                    var nafW = repr[j];
                    if (nafW === i) b = b.mixedAdd(doubles.points[j]); else if (nafW === -i) b = b.mixedAdd(doubles.points[j].neg());
                }
                a = a.add(b);
            }
            return a.toP();
        };
        BaseCurve.prototype._wnafMul = function _wnafMul(p, k) {
            var w = 4;
            var nafPoints = p._getNAFPoints(w);
            w = nafPoints.wnd;
            var wnd = nafPoints.points;
            var naf = getNAF(k, w);
            var acc = this.jpoint(null, null, null);
            for (var i = naf.length - 1; i >= 0; i--) {
                for (var k = 0; i >= 0 && naf[i] === 0; i--) k++;
                if (i >= 0) k++;
                acc = acc.dblp(k);
                if (i < 0) break;
                var z = naf[i];
                assert(z !== 0);
                if (p.type === "affine") {
                    if (z > 0) acc = acc.mixedAdd(wnd[z - 1 >> 1]); else acc = acc.mixedAdd(wnd[-z - 1 >> 1].neg());
                } else {
                    if (z > 0) acc = acc.add(wnd[z - 1 >> 1]); else acc = acc.add(wnd[-z - 1 >> 1].neg());
                }
            }
            return p.type === "affine" ? acc.toP() : acc;
        };
        BaseCurve.prototype._wnafMulAdd = function _wnafMulAdd(defW, points, coeffs, len, jacobianResult) {
            var wndWidth = this._wnafT1;
            var wnd = this._wnafT2;
            var naf = this._wnafT3;
            var max = 0;
            for (var i = 0; i < len; i++) {
                var p = points[i];
                var nafPoints = p._getNAFPoints(defW);
                wndWidth[i] = nafPoints.wnd;
                wnd[i] = nafPoints.points;
            }
            for (var i = len - 1; i >= 1; i -= 2) {
                var a = i - 1;
                var b = i;
                if (wndWidth[a] !== 1 || wndWidth[b] !== 1) {
                    naf[a] = getNAF(coeffs[a], wndWidth[a]);
                    naf[b] = getNAF(coeffs[b], wndWidth[b]);
                    max = Math.max(naf[a].length, max);
                    max = Math.max(naf[b].length, max);
                    continue;
                }
                var comb = [ points[a], null, null, points[b] ];
                if (points[a].y.cmp(points[b].y) === 0) {
                    comb[1] = points[a].add(points[b]);
                    comb[2] = points[a].toJ().mixedAdd(points[b].neg());
                } else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
                    comb[1] = points[a].toJ().mixedAdd(points[b]);
                    comb[2] = points[a].add(points[b].neg());
                } else {
                    comb[1] = points[a].toJ().mixedAdd(points[b]);
                    comb[2] = points[a].toJ().mixedAdd(points[b].neg());
                }
                var index = [ -3, -1, -5, -7, 0, 7, 5, 1, 3 ];
                var jsf = getJSF(coeffs[a], coeffs[b]);
                max = Math.max(jsf[0].length, max);
                naf[a] = new Array(max);
                naf[b] = new Array(max);
                for (var j = 0; j < max; j++) {
                    var ja = jsf[0][j] | 0;
                    var jb = jsf[1][j] | 0;
                    naf[a][j] = index[(ja + 1) * 3 + (jb + 1)];
                    naf[b][j] = 0;
                    wnd[a] = comb;
                }
            }
            var acc = this.jpoint(null, null, null);
            var tmp = this._wnafT4;
            for (var i = max; i >= 0; i--) {
                var k = 0;
                while (i >= 0) {
                    var zero = true;
                    for (var j = 0; j < len; j++) {
                        tmp[j] = naf[j][i] | 0;
                        if (tmp[j] !== 0) zero = false;
                    }
                    if (!zero) break;
                    k++;
                    i--;
                }
                if (i >= 0) k++;
                acc = acc.dblp(k);
                if (i < 0) break;
                for (var j = 0; j < len; j++) {
                    var z = tmp[j];
                    var p;
                    if (z === 0) continue; else if (z > 0) p = wnd[j][z - 1 >> 1]; else if (z < 0) p = wnd[j][-z - 1 >> 1].neg();
                    if (p.type === "affine") acc = acc.mixedAdd(p); else acc = acc.add(p);
                }
            }
            for (var i = 0; i < len; i++) wnd[i] = null;
            if (jacobianResult) return acc; else return acc.toP();
        };
        function BasePoint(curve, type) {
            this.curve = curve;
            this.type = type;
            this.precomputed = null;
        }
        BaseCurve.BasePoint = BasePoint;
        BasePoint.prototype.eq = function eq() {
            throw new Error("Not implemented");
        };
        BasePoint.prototype.validate = function validate() {
            return this.curve.validate(this);
        };
        BaseCurve.prototype.decodePoint = function decodePoint(bytes, enc) {
            bytes = utils.toArray(bytes, enc);
            var len = this.p.byteLength();
            if ((bytes[0] === 4 || bytes[0] === 6 || bytes[0] === 7) && bytes.length - 1 === 2 * len) {
                if (bytes[0] === 6) assert(bytes[bytes.length - 1] % 2 === 0); else if (bytes[0] === 7) assert(bytes[bytes.length - 1] % 2 === 1);
                var res = this.point(bytes.slice(1, 1 + len), bytes.slice(1 + len, 1 + 2 * len));
                return res;
            } else if ((bytes[0] === 2 || bytes[0] === 3) && bytes.length - 1 === len) {
                return this.pointFromX(bytes.slice(1, 1 + len), bytes[0] === 3);
            }
            throw new Error("Unknown point format");
        };
        BasePoint.prototype.encodeCompressed = function encodeCompressed(enc) {
            return this.encode(enc, true);
        };
        BasePoint.prototype._encode = function _encode(compact) {
            var len = this.curve.p.byteLength();
            var x = this.getX().toArray("be", len);
            if (compact) return [ this.getY().isEven() ? 2 : 3 ].concat(x);
            return [ 4 ].concat(x, this.getY().toArray("be", len));
        };
        BasePoint.prototype.encode = function encode(enc, compact) {
            return utils.encode(this._encode(compact), enc);
        };
        BasePoint.prototype.precompute = function precompute(power) {
            if (this.precomputed) return this;
            var precomputed = {
                doubles: null,
                naf: null,
                beta: null
            };
            precomputed.naf = this._getNAFPoints(8);
            precomputed.doubles = this._getDoubles(4, power);
            precomputed.beta = this._getBeta();
            this.precomputed = precomputed;
            return this;
        };
        BasePoint.prototype._hasDoubles = function _hasDoubles(k) {
            if (!this.precomputed) return false;
            var doubles = this.precomputed.doubles;
            if (!doubles) return false;
            return doubles.points.length >= Math.ceil((k.bitLength() + 1) / doubles.step);
        };
        BasePoint.prototype._getDoubles = function _getDoubles(step, power) {
            if (this.precomputed && this.precomputed.doubles) return this.precomputed.doubles;
            var doubles = [ this ];
            var acc = this;
            for (var i = 0; i < power; i += step) {
                for (var j = 0; j < step; j++) acc = acc.dbl();
                doubles.push(acc);
            }
            return {
                step: step,
                points: doubles
            };
        };
        BasePoint.prototype._getNAFPoints = function _getNAFPoints(wnd) {
            if (this.precomputed && this.precomputed.naf) return this.precomputed.naf;
            var res = [ this ];
            var max = (1 << wnd) - 1;
            var dbl = max === 1 ? null : this.dbl();
            for (var i = 1; i < max; i++) res[i] = res[i - 1].add(dbl);
            return {
                wnd: wnd,
                points: res
            };
        };
        BasePoint.prototype._getBeta = function _getBeta() {
            return null;
        };
        BasePoint.prototype.dblp = function dblp(k) {
            var r = this;
            for (var i = 0; i < k; i++) r = r.dbl();
            return r;
        };
    }, {
        "../../elliptic": 87,
        "bn.js": 23
    } ],
    89: [ function(require, module, exports) {
        "use strict";
        var curve = require("../curve");
        var elliptic = require("../../elliptic");
        var BN = require("bn.js");
        var inherits = require("inherits");
        var Base = curve.base;
        var assert = elliptic.utils.assert;
        function EdwardsCurve(conf) {
            this.twisted = (conf.a | 0) !== 1;
            this.mOneA = this.twisted && (conf.a | 0) === -1;
            this.extended = this.mOneA;
            Base.call(this, "edwards", conf);
            this.a = new BN(conf.a, 16).umod(this.red.m);
            this.a = this.a.toRed(this.red);
            this.c = new BN(conf.c, 16).toRed(this.red);
            this.c2 = this.c.redSqr();
            this.d = new BN(conf.d, 16).toRed(this.red);
            this.dd = this.d.redAdd(this.d);
            assert(!this.twisted || this.c.fromRed().cmpn(1) === 0);
            this.oneC = (conf.c | 0) === 1;
        }
        inherits(EdwardsCurve, Base);
        module.exports = EdwardsCurve;
        EdwardsCurve.prototype._mulA = function _mulA(num) {
            if (this.mOneA) return num.redNeg(); else return this.a.redMul(num);
        };
        EdwardsCurve.prototype._mulC = function _mulC(num) {
            if (this.oneC) return num; else return this.c.redMul(num);
        };
        EdwardsCurve.prototype.jpoint = function jpoint(x, y, z, t) {
            return this.point(x, y, z, t);
        };
        EdwardsCurve.prototype.pointFromX = function pointFromX(x, odd) {
            x = new BN(x, 16);
            if (!x.red) x = x.toRed(this.red);
            var x2 = x.redSqr();
            var rhs = this.c2.redSub(this.a.redMul(x2));
            var lhs = this.one.redSub(this.c2.redMul(this.d).redMul(x2));
            var y2 = rhs.redMul(lhs.redInvm());
            var y = y2.redSqrt();
            if (y.redSqr().redSub(y2).cmp(this.zero) !== 0) throw new Error("invalid point");
            var isOdd = y.fromRed().isOdd();
            if (odd && !isOdd || !odd && isOdd) y = y.redNeg();
            return this.point(x, y);
        };
        EdwardsCurve.prototype.pointFromY = function pointFromY(y, odd) {
            y = new BN(y, 16);
            if (!y.red) y = y.toRed(this.red);
            var y2 = y.redSqr();
            var lhs = y2.redSub(this.one);
            var rhs = y2.redMul(this.d).redAdd(this.one);
            var x2 = lhs.redMul(rhs.redInvm());
            if (x2.cmp(this.zero) === 0) {
                if (odd) throw new Error("invalid point"); else return this.point(this.zero, y);
            }
            var x = x2.redSqrt();
            if (x.redSqr().redSub(x2).cmp(this.zero) !== 0) throw new Error("invalid point");
            if (x.isOdd() !== odd) x = x.redNeg();
            return this.point(x, y);
        };
        EdwardsCurve.prototype.validate = function validate(point) {
            if (point.isInfinity()) return true;
            point.normalize();
            var x2 = point.x.redSqr();
            var y2 = point.y.redSqr();
            var lhs = x2.redMul(this.a).redAdd(y2);
            var rhs = this.c2.redMul(this.one.redAdd(this.d.redMul(x2).redMul(y2)));
            return lhs.cmp(rhs) === 0;
        };
        function Point(curve, x, y, z, t) {
            Base.BasePoint.call(this, curve, "projective");
            if (x === null && y === null && z === null) {
                this.x = this.curve.zero;
                this.y = this.curve.one;
                this.z = this.curve.one;
                this.t = this.curve.zero;
                this.zOne = true;
            } else {
                this.x = new BN(x, 16);
                this.y = new BN(y, 16);
                this.z = z ? new BN(z, 16) : this.curve.one;
                this.t = t && new BN(t, 16);
                if (!this.x.red) this.x = this.x.toRed(this.curve.red);
                if (!this.y.red) this.y = this.y.toRed(this.curve.red);
                if (!this.z.red) this.z = this.z.toRed(this.curve.red);
                if (this.t && !this.t.red) this.t = this.t.toRed(this.curve.red);
                this.zOne = this.z === this.curve.one;
                if (this.curve.extended && !this.t) {
                    this.t = this.x.redMul(this.y);
                    if (!this.zOne) this.t = this.t.redMul(this.z.redInvm());
                }
            }
        }
        inherits(Point, Base.BasePoint);
        EdwardsCurve.prototype.pointFromJSON = function pointFromJSON(obj) {
            return Point.fromJSON(this, obj);
        };
        EdwardsCurve.prototype.point = function point(x, y, z, t) {
            return new Point(this, x, y, z, t);
        };
        Point.fromJSON = function fromJSON(curve, obj) {
            return new Point(curve, obj[0], obj[1], obj[2]);
        };
        Point.prototype.inspect = function inspect() {
            if (this.isInfinity()) return "<EC Point Infinity>";
            return "<EC Point x: " + this.x.fromRed().toString(16, 2) + " y: " + this.y.fromRed().toString(16, 2) + " z: " + this.z.fromRed().toString(16, 2) + ">";
        };
        Point.prototype.isInfinity = function isInfinity() {
            return this.x.cmpn(0) === 0 && this.y.cmp(this.z) === 0;
        };
        Point.prototype._extDbl = function _extDbl() {
            var a = this.x.redSqr();
            var b = this.y.redSqr();
            var c = this.z.redSqr();
            c = c.redIAdd(c);
            var d = this.curve._mulA(a);
            var e = this.x.redAdd(this.y).redSqr().redISub(a).redISub(b);
            var g = d.redAdd(b);
            var f = g.redSub(c);
            var h = d.redSub(b);
            var nx = e.redMul(f);
            var ny = g.redMul(h);
            var nt = e.redMul(h);
            var nz = f.redMul(g);
            return this.curve.point(nx, ny, nz, nt);
        };
        Point.prototype._projDbl = function _projDbl() {
            var b = this.x.redAdd(this.y).redSqr();
            var c = this.x.redSqr();
            var d = this.y.redSqr();
            var nx;
            var ny;
            var nz;
            if (this.curve.twisted) {
                var e = this.curve._mulA(c);
                var f = e.redAdd(d);
                if (this.zOne) {
                    nx = b.redSub(c).redSub(d).redMul(f.redSub(this.curve.two));
                    ny = f.redMul(e.redSub(d));
                    nz = f.redSqr().redSub(f).redSub(f);
                } else {
                    var h = this.z.redSqr();
                    var j = f.redSub(h).redISub(h);
                    nx = b.redSub(c).redISub(d).redMul(j);
                    ny = f.redMul(e.redSub(d));
                    nz = f.redMul(j);
                }
            } else {
                var e = c.redAdd(d);
                var h = this.curve._mulC(this.c.redMul(this.z)).redSqr();
                var j = e.redSub(h).redSub(h);
                nx = this.curve._mulC(b.redISub(e)).redMul(j);
                ny = this.curve._mulC(e).redMul(c.redISub(d));
                nz = e.redMul(j);
            }
            return this.curve.point(nx, ny, nz);
        };
        Point.prototype.dbl = function dbl() {
            if (this.isInfinity()) return this;
            if (this.curve.extended) return this._extDbl(); else return this._projDbl();
        };
        Point.prototype._extAdd = function _extAdd(p) {
            var a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));
            var b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));
            var c = this.t.redMul(this.curve.dd).redMul(p.t);
            var d = this.z.redMul(p.z.redAdd(p.z));
            var e = b.redSub(a);
            var f = d.redSub(c);
            var g = d.redAdd(c);
            var h = b.redAdd(a);
            var nx = e.redMul(f);
            var ny = g.redMul(h);
            var nt = e.redMul(h);
            var nz = f.redMul(g);
            return this.curve.point(nx, ny, nz, nt);
        };
        Point.prototype._projAdd = function _projAdd(p) {
            var a = this.z.redMul(p.z);
            var b = a.redSqr();
            var c = this.x.redMul(p.x);
            var d = this.y.redMul(p.y);
            var e = this.curve.d.redMul(c).redMul(d);
            var f = b.redSub(e);
            var g = b.redAdd(e);
            var tmp = this.x.redAdd(this.y).redMul(p.x.redAdd(p.y)).redISub(c).redISub(d);
            var nx = a.redMul(f).redMul(tmp);
            var ny;
            var nz;
            if (this.curve.twisted) {
                ny = a.redMul(g).redMul(d.redSub(this.curve._mulA(c)));
                nz = f.redMul(g);
            } else {
                ny = a.redMul(g).redMul(d.redSub(c));
                nz = this.curve._mulC(f).redMul(g);
            }
            return this.curve.point(nx, ny, nz);
        };
        Point.prototype.add = function add(p) {
            if (this.isInfinity()) return p;
            if (p.isInfinity()) return this;
            if (this.curve.extended) return this._extAdd(p); else return this._projAdd(p);
        };
        Point.prototype.mul = function mul(k) {
            if (this._hasDoubles(k)) return this.curve._fixedNafMul(this, k); else return this.curve._wnafMul(this, k);
        };
        Point.prototype.mulAdd = function mulAdd(k1, p, k2) {
            return this.curve._wnafMulAdd(1, [ this, p ], [ k1, k2 ], 2, false);
        };
        Point.prototype.jmulAdd = function jmulAdd(k1, p, k2) {
            return this.curve._wnafMulAdd(1, [ this, p ], [ k1, k2 ], 2, true);
        };
        Point.prototype.normalize = function normalize() {
            if (this.zOne) return this;
            var zi = this.z.redInvm();
            this.x = this.x.redMul(zi);
            this.y = this.y.redMul(zi);
            if (this.t) this.t = this.t.redMul(zi);
            this.z = this.curve.one;
            this.zOne = true;
            return this;
        };
        Point.prototype.neg = function neg() {
            return this.curve.point(this.x.redNeg(), this.y, this.z, this.t && this.t.redNeg());
        };
        Point.prototype.getX = function getX() {
            this.normalize();
            return this.x.fromRed();
        };
        Point.prototype.getY = function getY() {
            this.normalize();
            return this.y.fromRed();
        };
        Point.prototype.eq = function eq(other) {
            return this === other || this.getX().cmp(other.getX()) === 0 && this.getY().cmp(other.getY()) === 0;
        };
        Point.prototype.eqXToP = function eqXToP(x) {
            var rx = x.toRed(this.curve.red).redMul(this.z);
            if (this.x.cmp(rx) === 0) return true;
            var xc = x.clone();
            var t = this.curve.redN.redMul(this.z);
            for (;;) {
                xc.iadd(this.curve.n);
                if (xc.cmp(this.curve.p) >= 0) return false;
                rx.redIAdd(t);
                if (this.x.cmp(rx) === 0) return true;
            }
            return false;
        };
        Point.prototype.toP = Point.prototype.normalize;
        Point.prototype.mixedAdd = Point.prototype.add;
    }, {
        "../../elliptic": 87,
        "../curve": 90,
        "bn.js": 23,
        inherits: 122
    } ],
    90: [ function(require, module, exports) {
        "use strict";
        var curve = exports;
        curve.base = require("./base");
        curve.short = require("./short");
        curve.mont = require("./mont");
        curve.edwards = require("./edwards");
    }, {
        "./base": 88,
        "./edwards": 89,
        "./mont": 91,
        "./short": 92
    } ],
    91: [ function(require, module, exports) {
        "use strict";
        var curve = require("../curve");
        var BN = require("bn.js");
        var inherits = require("inherits");
        var Base = curve.base;
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        function MontCurve(conf) {
            Base.call(this, "mont", conf);
            this.a = new BN(conf.a, 16).toRed(this.red);
            this.b = new BN(conf.b, 16).toRed(this.red);
            this.i4 = new BN(4).toRed(this.red).redInvm();
            this.two = new BN(2).toRed(this.red);
            this.a24 = this.i4.redMul(this.a.redAdd(this.two));
        }
        inherits(MontCurve, Base);
        module.exports = MontCurve;
        MontCurve.prototype.validate = function validate(point) {
            var x = point.normalize().x;
            var x2 = x.redSqr();
            var rhs = x2.redMul(x).redAdd(x2.redMul(this.a)).redAdd(x);
            var y = rhs.redSqrt();
            return y.redSqr().cmp(rhs) === 0;
        };
        function Point(curve, x, z) {
            Base.BasePoint.call(this, curve, "projective");
            if (x === null && z === null) {
                this.x = this.curve.one;
                this.z = this.curve.zero;
            } else {
                this.x = new BN(x, 16);
                this.z = new BN(z, 16);
                if (!this.x.red) this.x = this.x.toRed(this.curve.red);
                if (!this.z.red) this.z = this.z.toRed(this.curve.red);
            }
        }
        inherits(Point, Base.BasePoint);
        MontCurve.prototype.decodePoint = function decodePoint(bytes, enc) {
            return this.point(utils.toArray(bytes, enc), 1);
        };
        MontCurve.prototype.point = function point(x, z) {
            return new Point(this, x, z);
        };
        MontCurve.prototype.pointFromJSON = function pointFromJSON(obj) {
            return Point.fromJSON(this, obj);
        };
        Point.prototype.precompute = function precompute() {};
        Point.prototype._encode = function _encode() {
            return this.getX().toArray("be", this.curve.p.byteLength());
        };
        Point.fromJSON = function fromJSON(curve, obj) {
            return new Point(curve, obj[0], obj[1] || curve.one);
        };
        Point.prototype.inspect = function inspect() {
            if (this.isInfinity()) return "<EC Point Infinity>";
            return "<EC Point x: " + this.x.fromRed().toString(16, 2) + " z: " + this.z.fromRed().toString(16, 2) + ">";
        };
        Point.prototype.isInfinity = function isInfinity() {
            return this.z.cmpn(0) === 0;
        };
        Point.prototype.dbl = function dbl() {
            var a = this.x.redAdd(this.z);
            var aa = a.redSqr();
            var b = this.x.redSub(this.z);
            var bb = b.redSqr();
            var c = aa.redSub(bb);
            var nx = aa.redMul(bb);
            var nz = c.redMul(bb.redAdd(this.curve.a24.redMul(c)));
            return this.curve.point(nx, nz);
        };
        Point.prototype.add = function add() {
            throw new Error("Not supported on Montgomery curve");
        };
        Point.prototype.diffAdd = function diffAdd(p, diff) {
            var a = this.x.redAdd(this.z);
            var b = this.x.redSub(this.z);
            var c = p.x.redAdd(p.z);
            var d = p.x.redSub(p.z);
            var da = d.redMul(a);
            var cb = c.redMul(b);
            var nx = diff.z.redMul(da.redAdd(cb).redSqr());
            var nz = diff.x.redMul(da.redISub(cb).redSqr());
            return this.curve.point(nx, nz);
        };
        Point.prototype.mul = function mul(k) {
            var t = k.clone();
            var a = this;
            var b = this.curve.point(null, null);
            var c = this;
            for (var bits = []; t.cmpn(0) !== 0; t.iushrn(1)) bits.push(t.andln(1));
            for (var i = bits.length - 1; i >= 0; i--) {
                if (bits[i] === 0) {
                    a = a.diffAdd(b, c);
                    b = b.dbl();
                } else {
                    b = a.diffAdd(b, c);
                    a = a.dbl();
                }
            }
            return b;
        };
        Point.prototype.mulAdd = function mulAdd() {
            throw new Error("Not supported on Montgomery curve");
        };
        Point.prototype.jumlAdd = function jumlAdd() {
            throw new Error("Not supported on Montgomery curve");
        };
        Point.prototype.eq = function eq(other) {
            return this.getX().cmp(other.getX()) === 0;
        };
        Point.prototype.normalize = function normalize() {
            this.x = this.x.redMul(this.z.redInvm());
            this.z = this.curve.one;
            return this;
        };
        Point.prototype.getX = function getX() {
            this.normalize();
            return this.x.fromRed();
        };
    }, {
        "../../elliptic": 87,
        "../curve": 90,
        "bn.js": 23,
        inherits: 122
    } ],
    92: [ function(require, module, exports) {
        "use strict";
        var curve = require("../curve");
        var elliptic = require("../../elliptic");
        var BN = require("bn.js");
        var inherits = require("inherits");
        var Base = curve.base;
        var assert = elliptic.utils.assert;
        function ShortCurve(conf) {
            Base.call(this, "short", conf);
            this.a = new BN(conf.a, 16).toRed(this.red);
            this.b = new BN(conf.b, 16).toRed(this.red);
            this.tinv = this.two.redInvm();
            this.zeroA = this.a.fromRed().cmpn(0) === 0;
            this.threeA = this.a.fromRed().sub(this.p).cmpn(-3) === 0;
            this.endo = this._getEndomorphism(conf);
            this._endoWnafT1 = new Array(4);
            this._endoWnafT2 = new Array(4);
        }
        inherits(ShortCurve, Base);
        module.exports = ShortCurve;
        ShortCurve.prototype._getEndomorphism = function _getEndomorphism(conf) {
            if (!this.zeroA || !this.g || !this.n || this.p.modn(3) !== 1) return;
            var beta;
            var lambda;
            if (conf.beta) {
                beta = new BN(conf.beta, 16).toRed(this.red);
            } else {
                var betas = this._getEndoRoots(this.p);
                beta = betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1];
                beta = beta.toRed(this.red);
            }
            if (conf.lambda) {
                lambda = new BN(conf.lambda, 16);
            } else {
                var lambdas = this._getEndoRoots(this.n);
                if (this.g.mul(lambdas[0]).x.cmp(this.g.x.redMul(beta)) === 0) {
                    lambda = lambdas[0];
                } else {
                    lambda = lambdas[1];
                    assert(this.g.mul(lambda).x.cmp(this.g.x.redMul(beta)) === 0);
                }
            }
            var basis;
            if (conf.basis) {
                basis = conf.basis.map(function(vec) {
                    return {
                        a: new BN(vec.a, 16),
                        b: new BN(vec.b, 16)
                    };
                });
            } else {
                basis = this._getEndoBasis(lambda);
            }
            return {
                beta: beta,
                lambda: lambda,
                basis: basis
            };
        };
        ShortCurve.prototype._getEndoRoots = function _getEndoRoots(num) {
            var red = num === this.p ? this.red : BN.mont(num);
            var tinv = new BN(2).toRed(red).redInvm();
            var ntinv = tinv.redNeg();
            var s = new BN(3).toRed(red).redNeg().redSqrt().redMul(tinv);
            var l1 = ntinv.redAdd(s).fromRed();
            var l2 = ntinv.redSub(s).fromRed();
            return [ l1, l2 ];
        };
        ShortCurve.prototype._getEndoBasis = function _getEndoBasis(lambda) {
            var aprxSqrt = this.n.ushrn(Math.floor(this.n.bitLength() / 2));
            var u = lambda;
            var v = this.n.clone();
            var x1 = new BN(1);
            var y1 = new BN(0);
            var x2 = new BN(0);
            var y2 = new BN(1);
            var a0;
            var b0;
            var a1;
            var b1;
            var a2;
            var b2;
            var prevR;
            var i = 0;
            var r;
            var x;
            while (u.cmpn(0) !== 0) {
                var q = v.div(u);
                r = v.sub(q.mul(u));
                x = x2.sub(q.mul(x1));
                var y = y2.sub(q.mul(y1));
                if (!a1 && r.cmp(aprxSqrt) < 0) {
                    a0 = prevR.neg();
                    b0 = x1;
                    a1 = r.neg();
                    b1 = x;
                } else if (a1 && ++i === 2) {
                    break;
                }
                prevR = r;
                v = u;
                u = r;
                x2 = x1;
                x1 = x;
                y2 = y1;
                y1 = y;
            }
            a2 = r.neg();
            b2 = x;
            var len1 = a1.sqr().add(b1.sqr());
            var len2 = a2.sqr().add(b2.sqr());
            if (len2.cmp(len1) >= 0) {
                a2 = a0;
                b2 = b0;
            }
            if (a1.negative) {
                a1 = a1.neg();
                b1 = b1.neg();
            }
            if (a2.negative) {
                a2 = a2.neg();
                b2 = b2.neg();
            }
            return [ {
                a: a1,
                b: b1
            }, {
                a: a2,
                b: b2
            } ];
        };
        ShortCurve.prototype._endoSplit = function _endoSplit(k) {
            var basis = this.endo.basis;
            var v1 = basis[0];
            var v2 = basis[1];
            var c1 = v2.b.mul(k).divRound(this.n);
            var c2 = v1.b.neg().mul(k).divRound(this.n);
            var p1 = c1.mul(v1.a);
            var p2 = c2.mul(v2.a);
            var q1 = c1.mul(v1.b);
            var q2 = c2.mul(v2.b);
            var k1 = k.sub(p1).sub(p2);
            var k2 = q1.add(q2).neg();
            return {
                k1: k1,
                k2: k2
            };
        };
        ShortCurve.prototype.pointFromX = function pointFromX(x, odd) {
            x = new BN(x, 16);
            if (!x.red) x = x.toRed(this.red);
            var y2 = x.redSqr().redMul(x).redIAdd(x.redMul(this.a)).redIAdd(this.b);
            var y = y2.redSqrt();
            if (y.redSqr().redSub(y2).cmp(this.zero) !== 0) throw new Error("invalid point");
            var isOdd = y.fromRed().isOdd();
            if (odd && !isOdd || !odd && isOdd) y = y.redNeg();
            return this.point(x, y);
        };
        ShortCurve.prototype.validate = function validate(point) {
            if (point.inf) return true;
            var x = point.x;
            var y = point.y;
            var ax = this.a.redMul(x);
            var rhs = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);
            return y.redSqr().redISub(rhs).cmpn(0) === 0;
        };
        ShortCurve.prototype._endoWnafMulAdd = function _endoWnafMulAdd(points, coeffs, jacobianResult) {
            var npoints = this._endoWnafT1;
            var ncoeffs = this._endoWnafT2;
            for (var i = 0; i < points.length; i++) {
                var split = this._endoSplit(coeffs[i]);
                var p = points[i];
                var beta = p._getBeta();
                if (split.k1.negative) {
                    split.k1.ineg();
                    p = p.neg(true);
                }
                if (split.k2.negative) {
                    split.k2.ineg();
                    beta = beta.neg(true);
                }
                npoints[i * 2] = p;
                npoints[i * 2 + 1] = beta;
                ncoeffs[i * 2] = split.k1;
                ncoeffs[i * 2 + 1] = split.k2;
            }
            var res = this._wnafMulAdd(1, npoints, ncoeffs, i * 2, jacobianResult);
            for (var j = 0; j < i * 2; j++) {
                npoints[j] = null;
                ncoeffs[j] = null;
            }
            return res;
        };
        function Point(curve, x, y, isRed) {
            Base.BasePoint.call(this, curve, "affine");
            if (x === null && y === null) {
                this.x = null;
                this.y = null;
                this.inf = true;
            } else {
                this.x = new BN(x, 16);
                this.y = new BN(y, 16);
                if (isRed) {
                    this.x.forceRed(this.curve.red);
                    this.y.forceRed(this.curve.red);
                }
                if (!this.x.red) this.x = this.x.toRed(this.curve.red);
                if (!this.y.red) this.y = this.y.toRed(this.curve.red);
                this.inf = false;
            }
        }
        inherits(Point, Base.BasePoint);
        ShortCurve.prototype.point = function point(x, y, isRed) {
            return new Point(this, x, y, isRed);
        };
        ShortCurve.prototype.pointFromJSON = function pointFromJSON(obj, red) {
            return Point.fromJSON(this, obj, red);
        };
        Point.prototype._getBeta = function _getBeta() {
            if (!this.curve.endo) return;
            var pre = this.precomputed;
            if (pre && pre.beta) return pre.beta;
            var beta = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);
            if (pre) {
                var curve = this.curve;
                var endoMul = function(p) {
                    return curve.point(p.x.redMul(curve.endo.beta), p.y);
                };
                pre.beta = beta;
                beta.precomputed = {
                    beta: null,
                    naf: pre.naf && {
                        wnd: pre.naf.wnd,
                        points: pre.naf.points.map(endoMul)
                    },
                    doubles: pre.doubles && {
                        step: pre.doubles.step,
                        points: pre.doubles.points.map(endoMul)
                    }
                };
            }
            return beta;
        };
        Point.prototype.toJSON = function toJSON() {
            if (!this.precomputed) return [ this.x, this.y ];
            return [ this.x, this.y, this.precomputed && {
                doubles: this.precomputed.doubles && {
                    step: this.precomputed.doubles.step,
                    points: this.precomputed.doubles.points.slice(1)
                },
                naf: this.precomputed.naf && {
                    wnd: this.precomputed.naf.wnd,
                    points: this.precomputed.naf.points.slice(1)
                }
            } ];
        };
        Point.fromJSON = function fromJSON(curve, obj, red) {
            if (typeof obj === "string") obj = JSON.parse(obj);
            var res = curve.point(obj[0], obj[1], red);
            if (!obj[2]) return res;
            function obj2point(obj) {
                return curve.point(obj[0], obj[1], red);
            }
            var pre = obj[2];
            res.precomputed = {
                beta: null,
                doubles: pre.doubles && {
                    step: pre.doubles.step,
                    points: [ res ].concat(pre.doubles.points.map(obj2point))
                },
                naf: pre.naf && {
                    wnd: pre.naf.wnd,
                    points: [ res ].concat(pre.naf.points.map(obj2point))
                }
            };
            return res;
        };
        Point.prototype.inspect = function inspect() {
            if (this.isInfinity()) return "<EC Point Infinity>";
            return "<EC Point x: " + this.x.fromRed().toString(16, 2) + " y: " + this.y.fromRed().toString(16, 2) + ">";
        };
        Point.prototype.isInfinity = function isInfinity() {
            return this.inf;
        };
        Point.prototype.add = function add(p) {
            if (this.inf) return p;
            if (p.inf) return this;
            if (this.eq(p)) return this.dbl();
            if (this.neg().eq(p)) return this.curve.point(null, null);
            if (this.x.cmp(p.x) === 0) return this.curve.point(null, null);
            var c = this.y.redSub(p.y);
            if (c.cmpn(0) !== 0) c = c.redMul(this.x.redSub(p.x).redInvm());
            var nx = c.redSqr().redISub(this.x).redISub(p.x);
            var ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
            return this.curve.point(nx, ny);
        };
        Point.prototype.dbl = function dbl() {
            if (this.inf) return this;
            var ys1 = this.y.redAdd(this.y);
            if (ys1.cmpn(0) === 0) return this.curve.point(null, null);
            var a = this.curve.a;
            var x2 = this.x.redSqr();
            var dyinv = ys1.redInvm();
            var c = x2.redAdd(x2).redIAdd(x2).redIAdd(a).redMul(dyinv);
            var nx = c.redSqr().redISub(this.x.redAdd(this.x));
            var ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
            return this.curve.point(nx, ny);
        };
        Point.prototype.getX = function getX() {
            return this.x.fromRed();
        };
        Point.prototype.getY = function getY() {
            return this.y.fromRed();
        };
        Point.prototype.mul = function mul(k) {
            k = new BN(k, 16);
            if (this._hasDoubles(k)) return this.curve._fixedNafMul(this, k); else if (this.curve.endo) return this.curve._endoWnafMulAdd([ this ], [ k ]); else return this.curve._wnafMul(this, k);
        };
        Point.prototype.mulAdd = function mulAdd(k1, p2, k2) {
            var points = [ this, p2 ];
            var coeffs = [ k1, k2 ];
            if (this.curve.endo) return this.curve._endoWnafMulAdd(points, coeffs); else return this.curve._wnafMulAdd(1, points, coeffs, 2);
        };
        Point.prototype.jmulAdd = function jmulAdd(k1, p2, k2) {
            var points = [ this, p2 ];
            var coeffs = [ k1, k2 ];
            if (this.curve.endo) return this.curve._endoWnafMulAdd(points, coeffs, true); else return this.curve._wnafMulAdd(1, points, coeffs, 2, true);
        };
        Point.prototype.eq = function eq(p) {
            return this === p || this.inf === p.inf && (this.inf || this.x.cmp(p.x) === 0 && this.y.cmp(p.y) === 0);
        };
        Point.prototype.neg = function neg(_precompute) {
            if (this.inf) return this;
            var res = this.curve.point(this.x, this.y.redNeg());
            if (_precompute && this.precomputed) {
                var pre = this.precomputed;
                var negate = function(p) {
                    return p.neg();
                };
                res.precomputed = {
                    naf: pre.naf && {
                        wnd: pre.naf.wnd,
                        points: pre.naf.points.map(negate)
                    },
                    doubles: pre.doubles && {
                        step: pre.doubles.step,
                        points: pre.doubles.points.map(negate)
                    }
                };
            }
            return res;
        };
        Point.prototype.toJ = function toJ() {
            if (this.inf) return this.curve.jpoint(null, null, null);
            var res = this.curve.jpoint(this.x, this.y, this.curve.one);
            return res;
        };
        function JPoint(curve, x, y, z) {
            Base.BasePoint.call(this, curve, "jacobian");
            if (x === null && y === null && z === null) {
                this.x = this.curve.one;
                this.y = this.curve.one;
                this.z = new BN(0);
            } else {
                this.x = new BN(x, 16);
                this.y = new BN(y, 16);
                this.z = new BN(z, 16);
            }
            if (!this.x.red) this.x = this.x.toRed(this.curve.red);
            if (!this.y.red) this.y = this.y.toRed(this.curve.red);
            if (!this.z.red) this.z = this.z.toRed(this.curve.red);
            this.zOne = this.z === this.curve.one;
        }
        inherits(JPoint, Base.BasePoint);
        ShortCurve.prototype.jpoint = function jpoint(x, y, z) {
            return new JPoint(this, x, y, z);
        };
        JPoint.prototype.toP = function toP() {
            if (this.isInfinity()) return this.curve.point(null, null);
            var zinv = this.z.redInvm();
            var zinv2 = zinv.redSqr();
            var ax = this.x.redMul(zinv2);
            var ay = this.y.redMul(zinv2).redMul(zinv);
            return this.curve.point(ax, ay);
        };
        JPoint.prototype.neg = function neg() {
            return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
        };
        JPoint.prototype.add = function add(p) {
            if (this.isInfinity()) return p;
            if (p.isInfinity()) return this;
            var pz2 = p.z.redSqr();
            var z2 = this.z.redSqr();
            var u1 = this.x.redMul(pz2);
            var u2 = p.x.redMul(z2);
            var s1 = this.y.redMul(pz2.redMul(p.z));
            var s2 = p.y.redMul(z2.redMul(this.z));
            var h = u1.redSub(u2);
            var r = s1.redSub(s2);
            if (h.cmpn(0) === 0) {
                if (r.cmpn(0) !== 0) return this.curve.jpoint(null, null, null); else return this.dbl();
            }
            var h2 = h.redSqr();
            var h3 = h2.redMul(h);
            var v = u1.redMul(h2);
            var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
            var ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
            var nz = this.z.redMul(p.z).redMul(h);
            return this.curve.jpoint(nx, ny, nz);
        };
        JPoint.prototype.mixedAdd = function mixedAdd(p) {
            if (this.isInfinity()) return p.toJ();
            if (p.isInfinity()) return this;
            var z2 = this.z.redSqr();
            var u1 = this.x;
            var u2 = p.x.redMul(z2);
            var s1 = this.y;
            var s2 = p.y.redMul(z2).redMul(this.z);
            var h = u1.redSub(u2);
            var r = s1.redSub(s2);
            if (h.cmpn(0) === 0) {
                if (r.cmpn(0) !== 0) return this.curve.jpoint(null, null, null); else return this.dbl();
            }
            var h2 = h.redSqr();
            var h3 = h2.redMul(h);
            var v = u1.redMul(h2);
            var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
            var ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
            var nz = this.z.redMul(h);
            return this.curve.jpoint(nx, ny, nz);
        };
        JPoint.prototype.dblp = function dblp(pow) {
            if (pow === 0) return this;
            if (this.isInfinity()) return this;
            if (!pow) return this.dbl();
            if (this.curve.zeroA || this.curve.threeA) {
                var r = this;
                for (var i = 0; i < pow; i++) r = r.dbl();
                return r;
            }
            var a = this.curve.a;
            var tinv = this.curve.tinv;
            var jx = this.x;
            var jy = this.y;
            var jz = this.z;
            var jz4 = jz.redSqr().redSqr();
            var jyd = jy.redAdd(jy);
            for (var i = 0; i < pow; i++) {
                var jx2 = jx.redSqr();
                var jyd2 = jyd.redSqr();
                var jyd4 = jyd2.redSqr();
                var c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));
                var t1 = jx.redMul(jyd2);
                var nx = c.redSqr().redISub(t1.redAdd(t1));
                var t2 = t1.redISub(nx);
                var dny = c.redMul(t2);
                dny = dny.redIAdd(dny).redISub(jyd4);
                var nz = jyd.redMul(jz);
                if (i + 1 < pow) jz4 = jz4.redMul(jyd4);
                jx = nx;
                jz = nz;
                jyd = dny;
            }
            return this.curve.jpoint(jx, jyd.redMul(tinv), jz);
        };
        JPoint.prototype.dbl = function dbl() {
            if (this.isInfinity()) return this;
            if (this.curve.zeroA) return this._zeroDbl(); else if (this.curve.threeA) return this._threeDbl(); else return this._dbl();
        };
        JPoint.prototype._zeroDbl = function _zeroDbl() {
            var nx;
            var ny;
            var nz;
            if (this.zOne) {
                var xx = this.x.redSqr();
                var yy = this.y.redSqr();
                var yyyy = yy.redSqr();
                var s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
                s = s.redIAdd(s);
                var m = xx.redAdd(xx).redIAdd(xx);
                var t = m.redSqr().redISub(s).redISub(s);
                var yyyy8 = yyyy.redIAdd(yyyy);
                yyyy8 = yyyy8.redIAdd(yyyy8);
                yyyy8 = yyyy8.redIAdd(yyyy8);
                nx = t;
                ny = m.redMul(s.redISub(t)).redISub(yyyy8);
                nz = this.y.redAdd(this.y);
            } else {
                var a = this.x.redSqr();
                var b = this.y.redSqr();
                var c = b.redSqr();
                var d = this.x.redAdd(b).redSqr().redISub(a).redISub(c);
                d = d.redIAdd(d);
                var e = a.redAdd(a).redIAdd(a);
                var f = e.redSqr();
                var c8 = c.redIAdd(c);
                c8 = c8.redIAdd(c8);
                c8 = c8.redIAdd(c8);
                nx = f.redISub(d).redISub(d);
                ny = e.redMul(d.redISub(nx)).redISub(c8);
                nz = this.y.redMul(this.z);
                nz = nz.redIAdd(nz);
            }
            return this.curve.jpoint(nx, ny, nz);
        };
        JPoint.prototype._threeDbl = function _threeDbl() {
            var nx;
            var ny;
            var nz;
            if (this.zOne) {
                var xx = this.x.redSqr();
                var yy = this.y.redSqr();
                var yyyy = yy.redSqr();
                var s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
                s = s.redIAdd(s);
                var m = xx.redAdd(xx).redIAdd(xx).redIAdd(this.curve.a);
                var t = m.redSqr().redISub(s).redISub(s);
                nx = t;
                var yyyy8 = yyyy.redIAdd(yyyy);
                yyyy8 = yyyy8.redIAdd(yyyy8);
                yyyy8 = yyyy8.redIAdd(yyyy8);
                ny = m.redMul(s.redISub(t)).redISub(yyyy8);
                nz = this.y.redAdd(this.y);
            } else {
                var delta = this.z.redSqr();
                var gamma = this.y.redSqr();
                var beta = this.x.redMul(gamma);
                var alpha = this.x.redSub(delta).redMul(this.x.redAdd(delta));
                alpha = alpha.redAdd(alpha).redIAdd(alpha);
                var beta4 = beta.redIAdd(beta);
                beta4 = beta4.redIAdd(beta4);
                var beta8 = beta4.redAdd(beta4);
                nx = alpha.redSqr().redISub(beta8);
                nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);
                var ggamma8 = gamma.redSqr();
                ggamma8 = ggamma8.redIAdd(ggamma8);
                ggamma8 = ggamma8.redIAdd(ggamma8);
                ggamma8 = ggamma8.redIAdd(ggamma8);
                ny = alpha.redMul(beta4.redISub(nx)).redISub(ggamma8);
            }
            return this.curve.jpoint(nx, ny, nz);
        };
        JPoint.prototype._dbl = function _dbl() {
            var a = this.curve.a;
            var jx = this.x;
            var jy = this.y;
            var jz = this.z;
            var jz4 = jz.redSqr().redSqr();
            var jx2 = jx.redSqr();
            var jy2 = jy.redSqr();
            var c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));
            var jxd4 = jx.redAdd(jx);
            jxd4 = jxd4.redIAdd(jxd4);
            var t1 = jxd4.redMul(jy2);
            var nx = c.redSqr().redISub(t1.redAdd(t1));
            var t2 = t1.redISub(nx);
            var jyd8 = jy2.redSqr();
            jyd8 = jyd8.redIAdd(jyd8);
            jyd8 = jyd8.redIAdd(jyd8);
            jyd8 = jyd8.redIAdd(jyd8);
            var ny = c.redMul(t2).redISub(jyd8);
            var nz = jy.redAdd(jy).redMul(jz);
            return this.curve.jpoint(nx, ny, nz);
        };
        JPoint.prototype.trpl = function trpl() {
            if (!this.curve.zeroA) return this.dbl().add(this);
            var xx = this.x.redSqr();
            var yy = this.y.redSqr();
            var zz = this.z.redSqr();
            var yyyy = yy.redSqr();
            var m = xx.redAdd(xx).redIAdd(xx);
            var mm = m.redSqr();
            var e = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
            e = e.redIAdd(e);
            e = e.redAdd(e).redIAdd(e);
            e = e.redISub(mm);
            var ee = e.redSqr();
            var t = yyyy.redIAdd(yyyy);
            t = t.redIAdd(t);
            t = t.redIAdd(t);
            t = t.redIAdd(t);
            var u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);
            var yyu4 = yy.redMul(u);
            yyu4 = yyu4.redIAdd(yyu4);
            yyu4 = yyu4.redIAdd(yyu4);
            var nx = this.x.redMul(ee).redISub(yyu4);
            nx = nx.redIAdd(nx);
            nx = nx.redIAdd(nx);
            var ny = this.y.redMul(u.redMul(t.redISub(u)).redISub(e.redMul(ee)));
            ny = ny.redIAdd(ny);
            ny = ny.redIAdd(ny);
            ny = ny.redIAdd(ny);
            var nz = this.z.redAdd(e).redSqr().redISub(zz).redISub(ee);
            return this.curve.jpoint(nx, ny, nz);
        };
        JPoint.prototype.mul = function mul(k, kbase) {
            k = new BN(k, kbase);
            return this.curve._wnafMul(this, k);
        };
        JPoint.prototype.eq = function eq(p) {
            if (p.type === "affine") return this.eq(p.toJ());
            if (this === p) return true;
            var z2 = this.z.redSqr();
            var pz2 = p.z.redSqr();
            if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).cmpn(0) !== 0) return false;
            var z3 = z2.redMul(this.z);
            var pz3 = pz2.redMul(p.z);
            return this.y.redMul(pz3).redISub(p.y.redMul(z3)).cmpn(0) === 0;
        };
        JPoint.prototype.eqXToP = function eqXToP(x) {
            var zs = this.z.redSqr();
            var rx = x.toRed(this.curve.red).redMul(zs);
            if (this.x.cmp(rx) === 0) return true;
            var xc = x.clone();
            var t = this.curve.redN.redMul(zs);
            for (;;) {
                xc.iadd(this.curve.n);
                if (xc.cmp(this.curve.p) >= 0) return false;
                rx.redIAdd(t);
                if (this.x.cmp(rx) === 0) return true;
            }
            return false;
        };
        JPoint.prototype.inspect = function inspect() {
            if (this.isInfinity()) return "<EC JPoint Infinity>";
            return "<EC JPoint x: " + this.x.toString(16, 2) + " y: " + this.y.toString(16, 2) + " z: " + this.z.toString(16, 2) + ">";
        };
        JPoint.prototype.isInfinity = function isInfinity() {
            return this.z.cmpn(0) === 0;
        };
    }, {
        "../../elliptic": 87,
        "../curve": 90,
        "bn.js": 23,
        inherits: 122
    } ],
    93: [ function(require, module, exports) {
        "use strict";
        var curves = exports;
        var hash = require("hash.js");
        var elliptic = require("../elliptic");
        var assert = elliptic.utils.assert;
        function PresetCurve(options) {
            if (options.type === "short") this.curve = new elliptic.curve.short(options); else if (options.type === "edwards") this.curve = new elliptic.curve.edwards(options); else this.curve = new elliptic.curve.mont(options);
            this.g = this.curve.g;
            this.n = this.curve.n;
            this.hash = options.hash;
            assert(this.g.validate(), "Invalid curve");
            assert(this.g.mul(this.n).isInfinity(), "Invalid curve, G*N != O");
        }
        curves.PresetCurve = PresetCurve;
        function defineCurve(name, options) {
            Object.defineProperty(curves, name, {
                configurable: true,
                enumerable: true,
                get: function() {
                    var curve = new PresetCurve(options);
                    Object.defineProperty(curves, name, {
                        configurable: true,
                        enumerable: true,
                        value: curve
                    });
                    return curve;
                }
            });
        }
        defineCurve("p192", {
            type: "short",
            prime: "p192",
            p: "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff",
            a: "ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc",
            b: "64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1",
            n: "ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831",
            hash: hash.sha256,
            gRed: false,
            g: [ "188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012", "07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811" ]
        });
        defineCurve("p224", {
            type: "short",
            prime: "p224",
            p: "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001",
            a: "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe",
            b: "b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4",
            n: "ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d",
            hash: hash.sha256,
            gRed: false,
            g: [ "b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21", "bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34" ]
        });
        defineCurve("p256", {
            type: "short",
            prime: null,
            p: "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff",
            a: "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc",
            b: "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b",
            n: "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551",
            hash: hash.sha256,
            gRed: false,
            g: [ "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296", "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5" ]
        });
        defineCurve("p384", {
            type: "short",
            prime: null,
            p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff " + "fffffffe ffffffff 00000000 00000000 ffffffff",
            a: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff " + "fffffffe ffffffff 00000000 00000000 fffffffc",
            b: "b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f " + "5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef",
            n: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 " + "f4372ddf 581a0db2 48b0a77a ecec196a ccc52973",
            hash: hash.sha384,
            gRed: false,
            g: [ "aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 " + "5502f25d bf55296c 3a545e38 72760ab7", "3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 " + "0a60b1ce 1d7e819d 7a431d7c 90ea0e5f" ]
        });
        defineCurve("p521", {
            type: "short",
            prime: null,
            p: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff " + "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff " + "ffffffff ffffffff ffffffff ffffffff ffffffff",
            a: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff " + "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff " + "ffffffff ffffffff ffffffff ffffffff fffffffc",
            b: "00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b " + "99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd " + "3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00",
            n: "000001ff ffffffff ffffffff ffffffff ffffffff ffffffff " + "ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 " + "f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409",
            hash: hash.sha512,
            gRed: false,
            g: [ "000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 " + "053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 " + "a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66", "00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 " + "579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 " + "3fad0761 353c7086 a272c240 88be9476 9fd16650" ]
        });
        defineCurve("curve25519", {
            type: "mont",
            prime: "p25519",
            p: "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed",
            a: "76d06",
            b: "1",
            n: "1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed",
            hash: hash.sha256,
            gRed: false,
            g: [ "9" ]
        });
        defineCurve("ed25519", {
            type: "edwards",
            prime: "p25519",
            p: "7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed",
            a: "-1",
            c: "1",
            d: "52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3",
            n: "1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed",
            hash: hash.sha256,
            gRed: false,
            g: [ "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", "6666666666666666666666666666666666666666666666666666666666666658" ]
        });
        var pre;
        try {
            pre = require("./precomputed/secp256k1");
        } catch (e) {
            pre = undefined;
        }
        defineCurve("secp256k1", {
            type: "short",
            prime: "k256",
            p: "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f",
            a: "0",
            b: "7",
            n: "ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141",
            h: "1",
            hash: hash.sha256,
            beta: "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
            lambda: "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",
            basis: [ {
                a: "3086d221a7d46bcde86c90e49284eb15",
                b: "-e4437ed6010e88286f547fa90abfe4c3"
            }, {
                a: "114ca50f7a8e2f3f657c1108d9d44cfd8",
                b: "3086d221a7d46bcde86c90e49284eb15"
            } ],
            gRed: false,
            g: [ "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", pre ]
        });
    }, {
        "../elliptic": 87,
        "./precomputed/secp256k1": 100,
        "hash.js": 106
    } ],
    94: [ function(require, module, exports) {
        "use strict";
        var BN = require("bn.js");
        var HmacDRBG = require("hmac-drbg");
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var assert = utils.assert;
        var KeyPair = require("./key");
        var Signature = require("./signature");
        function EC(options) {
            if (!(this instanceof EC)) return new EC(options);
            if (typeof options === "string") {
                assert(elliptic.curves.hasOwnProperty(options), "Unknown curve " + options);
                options = elliptic.curves[options];
            }
            if (options instanceof elliptic.curves.PresetCurve) options = {
                curve: options
            };
            this.curve = options.curve.curve;
            this.n = this.curve.n;
            this.nh = this.n.ushrn(1);
            this.g = this.curve.g;
            this.g = options.curve.g;
            this.g.precompute(options.curve.n.bitLength() + 1);
            this.hash = options.hash || options.curve.hash;
        }
        module.exports = EC;
        EC.prototype.keyPair = function keyPair(options) {
            return new KeyPair(this, options);
        };
        EC.prototype.keyFromPrivate = function keyFromPrivate(priv, enc) {
            return KeyPair.fromPrivate(this, priv, enc);
        };
        EC.prototype.keyFromPublic = function keyFromPublic(pub, enc) {
            return KeyPair.fromPublic(this, pub, enc);
        };
        EC.prototype.genKeyPair = function genKeyPair(options) {
            if (!options) options = {};
            var drbg = new HmacDRBG({
                hash: this.hash,
                pers: options.pers,
                persEnc: options.persEnc || "utf8",
                entropy: options.entropy || elliptic.rand(this.hash.hmacStrength),
                entropyEnc: options.entropy && options.entropyEnc || "utf8",
                nonce: this.n.toArray()
            });
            var bytes = this.n.byteLength();
            var ns2 = this.n.sub(new BN(2));
            do {
                var priv = new BN(drbg.generate(bytes));
                if (priv.cmp(ns2) > 0) continue;
                priv.iaddn(1);
                return this.keyFromPrivate(priv);
            } while (true);
        };
        EC.prototype._truncateToN = function truncateToN(msg, truncOnly) {
            var delta = msg.byteLength() * 8 - this.n.bitLength();
            if (delta > 0) msg = msg.ushrn(delta);
            if (!truncOnly && msg.cmp(this.n) >= 0) return msg.sub(this.n); else return msg;
        };
        EC.prototype.sign = function sign(msg, key, enc, options) {
            if (typeof enc === "object") {
                options = enc;
                enc = null;
            }
            if (!options) options = {};
            key = this.keyFromPrivate(key, enc);
            msg = this._truncateToN(new BN(msg, 16));
            var bytes = this.n.byteLength();
            var bkey = key.getPrivate().toArray("be", bytes);
            var nonce = msg.toArray("be", bytes);
            var drbg = new HmacDRBG({
                hash: this.hash,
                entropy: bkey,
                nonce: nonce,
                pers: options.pers,
                persEnc: options.persEnc || "utf8"
            });
            var ns1 = this.n.sub(new BN(1));
            for (var iter = 0; true; iter++) {
                var k = options.k ? options.k(iter) : new BN(drbg.generate(this.n.byteLength()));
                k = this._truncateToN(k, true);
                if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0) continue;
                var kp = this.g.mul(k);
                if (kp.isInfinity()) continue;
                var kpX = kp.getX();
                var r = kpX.umod(this.n);
                if (r.cmpn(0) === 0) continue;
                var s = k.invm(this.n).mul(r.mul(key.getPrivate()).iadd(msg));
                s = s.umod(this.n);
                if (s.cmpn(0) === 0) continue;
                var recoveryParam = (kp.getY().isOdd() ? 1 : 0) | (kpX.cmp(r) !== 0 ? 2 : 0);
                if (options.canonical && s.cmp(this.nh) > 0) {
                    s = this.n.sub(s);
                    recoveryParam ^= 1;
                }
                return new Signature({
                    r: r,
                    s: s,
                    recoveryParam: recoveryParam
                });
            }
        };
        EC.prototype.verify = function verify(msg, signature, key, enc) {
            msg = this._truncateToN(new BN(msg, 16));
            key = this.keyFromPublic(key, enc);
            signature = new Signature(signature, "hex");
            var r = signature.r;
            var s = signature.s;
            if (r.cmpn(1) < 0 || r.cmp(this.n) >= 0) return false;
            if (s.cmpn(1) < 0 || s.cmp(this.n) >= 0) return false;
            var sinv = s.invm(this.n);
            var u1 = sinv.mul(msg).umod(this.n);
            var u2 = sinv.mul(r).umod(this.n);
            if (!this.curve._maxwellTrick) {
                var p = this.g.mulAdd(u1, key.getPublic(), u2);
                if (p.isInfinity()) return false;
                return p.getX().umod(this.n).cmp(r) === 0;
            }
            var p = this.g.jmulAdd(u1, key.getPublic(), u2);
            if (p.isInfinity()) return false;
            return p.eqXToP(r);
        };
        EC.prototype.recoverPubKey = function(msg, signature, j, enc) {
            assert((3 & j) === j, "The recovery param is more than two bits");
            signature = new Signature(signature, enc);
            var n = this.n;
            var e = new BN(msg);
            var r = signature.r;
            var s = signature.s;
            var isYOdd = j & 1;
            var isSecondKey = j >> 1;
            if (r.cmp(this.curve.p.umod(this.curve.n)) >= 0 && isSecondKey) throw new Error("Unable to find sencond key candinate");
            if (isSecondKey) r = this.curve.pointFromX(r.add(this.curve.n), isYOdd); else r = this.curve.pointFromX(r, isYOdd);
            var rInv = signature.r.invm(n);
            var s1 = n.sub(e).mul(rInv).umod(n);
            var s2 = s.mul(rInv).umod(n);
            return this.g.mulAdd(s1, r, s2);
        };
        EC.prototype.getKeyRecoveryParam = function(e, signature, Q, enc) {
            signature = new Signature(signature, enc);
            if (signature.recoveryParam !== null) return signature.recoveryParam;
            for (var i = 0; i < 4; i++) {
                var Qprime;
                try {
                    Qprime = this.recoverPubKey(e, signature, i);
                } catch (e) {
                    continue;
                }
                if (Qprime.eq(Q)) return i;
            }
            throw new Error("Unable to find valid recovery factor");
        };
    }, {
        "../../elliptic": 87,
        "./key": 95,
        "./signature": 96,
        "bn.js": 23,
        "hmac-drbg": 119
    } ],
    95: [ function(require, module, exports) {
        "use strict";
        var BN = require("bn.js");
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var assert = utils.assert;
        function KeyPair(ec, options) {
            this.ec = ec;
            this.priv = null;
            this.pub = null;
            if (options.priv) this._importPrivate(options.priv, options.privEnc);
            if (options.pub) this._importPublic(options.pub, options.pubEnc);
        }
        module.exports = KeyPair;
        KeyPair.fromPublic = function fromPublic(ec, pub, enc) {
            if (pub instanceof KeyPair) return pub;
            return new KeyPair(ec, {
                pub: pub,
                pubEnc: enc
            });
        };
        KeyPair.fromPrivate = function fromPrivate(ec, priv, enc) {
            if (priv instanceof KeyPair) return priv;
            return new KeyPair(ec, {
                priv: priv,
                privEnc: enc
            });
        };
        KeyPair.prototype.validate = function validate() {
            var pub = this.getPublic();
            if (pub.isInfinity()) return {
                result: false,
                reason: "Invalid public key"
            };
            if (!pub.validate()) return {
                result: false,
                reason: "Public key is not a point"
            };
            if (!pub.mul(this.ec.curve.n).isInfinity()) return {
                result: false,
                reason: "Public key * N != O"
            };
            return {
                result: true,
                reason: null
            };
        };
        KeyPair.prototype.getPublic = function getPublic(compact, enc) {
            if (typeof compact === "string") {
                enc = compact;
                compact = null;
            }
            if (!this.pub) this.pub = this.ec.g.mul(this.priv);
            if (!enc) return this.pub;
            return this.pub.encode(enc, compact);
        };
        KeyPair.prototype.getPrivate = function getPrivate(enc) {
            if (enc === "hex") return this.priv.toString(16, 2); else return this.priv;
        };
        KeyPair.prototype._importPrivate = function _importPrivate(key, enc) {
            this.priv = new BN(key, enc || 16);
            this.priv = this.priv.umod(this.ec.curve.n);
        };
        KeyPair.prototype._importPublic = function _importPublic(key, enc) {
            if (key.x || key.y) {
                if (this.ec.curve.type === "mont") {
                    assert(key.x, "Need x coordinate");
                } else if (this.ec.curve.type === "short" || this.ec.curve.type === "edwards") {
                    assert(key.x && key.y, "Need both x and y coordinate");
                }
                this.pub = this.ec.curve.point(key.x, key.y);
                return;
            }
            this.pub = this.ec.curve.decodePoint(key, enc);
        };
        KeyPair.prototype.derive = function derive(pub) {
            return pub.mul(this.priv).getX();
        };
        KeyPair.prototype.sign = function sign(msg, enc, options) {
            return this.ec.sign(msg, this, enc, options);
        };
        KeyPair.prototype.verify = function verify(msg, signature) {
            return this.ec.verify(msg, signature, this);
        };
        KeyPair.prototype.inspect = function inspect() {
            return "<Key priv: " + (this.priv && this.priv.toString(16, 2)) + " pub: " + (this.pub && this.pub.inspect()) + " >";
        };
    }, {
        "../../elliptic": 87,
        "bn.js": 23
    } ],
    96: [ function(require, module, exports) {
        "use strict";
        var BN = require("bn.js");
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var assert = utils.assert;
        function Signature(options, enc) {
            if (options instanceof Signature) return options;
            if (this._importDER(options, enc)) return;
            assert(options.r && options.s, "Signature without r or s");
            this.r = new BN(options.r, 16);
            this.s = new BN(options.s, 16);
            if (options.recoveryParam === undefined) this.recoveryParam = null; else this.recoveryParam = options.recoveryParam;
        }
        module.exports = Signature;
        function Position() {
            this.place = 0;
        }
        function getLength(buf, p) {
            var initial = buf[p.place++];
            if (!(initial & 128)) {
                return initial;
            }
            var octetLen = initial & 15;
            var val = 0;
            for (var i = 0, off = p.place; i < octetLen; i++, off++) {
                val <<= 8;
                val |= buf[off];
            }
            p.place = off;
            return val;
        }
        function rmPadding(buf) {
            var i = 0;
            var len = buf.length - 1;
            while (!buf[i] && !(buf[i + 1] & 128) && i < len) {
                i++;
            }
            if (i === 0) {
                return buf;
            }
            return buf.slice(i);
        }
        Signature.prototype._importDER = function _importDER(data, enc) {
            data = utils.toArray(data, enc);
            var p = new Position();
            if (data[p.place++] !== 48) {
                return false;
            }
            var len = getLength(data, p);
            if (len + p.place !== data.length) {
                return false;
            }
            if (data[p.place++] !== 2) {
                return false;
            }
            var rlen = getLength(data, p);
            var r = data.slice(p.place, rlen + p.place);
            p.place += rlen;
            if (data[p.place++] !== 2) {
                return false;
            }
            var slen = getLength(data, p);
            if (data.length !== slen + p.place) {
                return false;
            }
            var s = data.slice(p.place, slen + p.place);
            if (r[0] === 0 && r[1] & 128) {
                r = r.slice(1);
            }
            if (s[0] === 0 && s[1] & 128) {
                s = s.slice(1);
            }
            this.r = new BN(r);
            this.s = new BN(s);
            this.recoveryParam = null;
            return true;
        };
        function constructLength(arr, len) {
            if (len < 128) {
                arr.push(len);
                return;
            }
            var octets = 1 + (Math.log(len) / Math.LN2 >>> 3);
            arr.push(octets | 128);
            while (--octets) {
                arr.push(len >>> (octets << 3) & 255);
            }
            arr.push(len);
        }
        Signature.prototype.toDER = function toDER(enc) {
            var r = this.r.toArray();
            var s = this.s.toArray();
            if (r[0] & 128) r = [ 0 ].concat(r);
            if (s[0] & 128) s = [ 0 ].concat(s);
            r = rmPadding(r);
            s = rmPadding(s);
            while (!s[0] && !(s[1] & 128)) {
                s = s.slice(1);
            }
            var arr = [ 2 ];
            constructLength(arr, r.length);
            arr = arr.concat(r);
            arr.push(2);
            constructLength(arr, s.length);
            var backHalf = arr.concat(s);
            var res = [ 48 ];
            constructLength(res, backHalf.length);
            res = res.concat(backHalf);
            return utils.encode(res, enc);
        };
    }, {
        "../../elliptic": 87,
        "bn.js": 23
    } ],
    97: [ function(require, module, exports) {
        "use strict";
        var hash = require("hash.js");
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var assert = utils.assert;
        var parseBytes = utils.parseBytes;
        var KeyPair = require("./key");
        var Signature = require("./signature");
        function EDDSA(curve) {
            assert(curve === "ed25519", "only tested with ed25519 so far");
            if (!(this instanceof EDDSA)) return new EDDSA(curve);
            var curve = elliptic.curves[curve].curve;
            this.curve = curve;
            this.g = curve.g;
            this.g.precompute(curve.n.bitLength() + 1);
            this.pointClass = curve.point().constructor;
            this.encodingLength = Math.ceil(curve.n.bitLength() / 8);
            this.hash = hash.sha512;
        }
        module.exports = EDDSA;
        EDDSA.prototype.sign = function sign(message, secret) {
            message = parseBytes(message);
            var key = this.keyFromSecret(secret);
            var r = this.hashInt(key.messagePrefix(), message);
            var R = this.g.mul(r);
            var Rencoded = this.encodePoint(R);
            var s_ = this.hashInt(Rencoded, key.pubBytes(), message).mul(key.priv());
            var S = r.add(s_).umod(this.curve.n);
            return this.makeSignature({
                R: R,
                S: S,
                Rencoded: Rencoded
            });
        };
        EDDSA.prototype.verify = function verify(message, sig, pub) {
            message = parseBytes(message);
            sig = this.makeSignature(sig);
            var key = this.keyFromPublic(pub);
            var h = this.hashInt(sig.Rencoded(), key.pubBytes(), message);
            var SG = this.g.mul(sig.S());
            var RplusAh = sig.R().add(key.pub().mul(h));
            return RplusAh.eq(SG);
        };
        EDDSA.prototype.hashInt = function hashInt() {
            var hash = this.hash();
            for (var i = 0; i < arguments.length; i++) hash.update(arguments[i]);
            return utils.intFromLE(hash.digest()).umod(this.curve.n);
        };
        EDDSA.prototype.keyFromPublic = function keyFromPublic(pub) {
            return KeyPair.fromPublic(this, pub);
        };
        EDDSA.prototype.keyFromSecret = function keyFromSecret(secret) {
            return KeyPair.fromSecret(this, secret);
        };
        EDDSA.prototype.makeSignature = function makeSignature(sig) {
            if (sig instanceof Signature) return sig;
            return new Signature(this, sig);
        };
        EDDSA.prototype.encodePoint = function encodePoint(point) {
            var enc = point.getY().toArray("le", this.encodingLength);
            enc[this.encodingLength - 1] |= point.getX().isOdd() ? 128 : 0;
            return enc;
        };
        EDDSA.prototype.decodePoint = function decodePoint(bytes) {
            bytes = utils.parseBytes(bytes);
            var lastIx = bytes.length - 1;
            var normed = bytes.slice(0, lastIx).concat(bytes[lastIx] & ~128);
            var xIsOdd = (bytes[lastIx] & 128) !== 0;
            var y = utils.intFromLE(normed);
            return this.curve.pointFromY(y, xIsOdd);
        };
        EDDSA.prototype.encodeInt = function encodeInt(num) {
            return num.toArray("le", this.encodingLength);
        };
        EDDSA.prototype.decodeInt = function decodeInt(bytes) {
            return utils.intFromLE(bytes);
        };
        EDDSA.prototype.isPoint = function isPoint(val) {
            return val instanceof this.pointClass;
        };
    }, {
        "../../elliptic": 87,
        "./key": 98,
        "./signature": 99,
        "hash.js": 106
    } ],
    98: [ function(require, module, exports) {
        "use strict";
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var assert = utils.assert;
        var parseBytes = utils.parseBytes;
        var cachedProperty = utils.cachedProperty;
        function KeyPair(eddsa, params) {
            this.eddsa = eddsa;
            this._secret = parseBytes(params.secret);
            if (eddsa.isPoint(params.pub)) this._pub = params.pub; else this._pubBytes = parseBytes(params.pub);
        }
        KeyPair.fromPublic = function fromPublic(eddsa, pub) {
            if (pub instanceof KeyPair) return pub;
            return new KeyPair(eddsa, {
                pub: pub
            });
        };
        KeyPair.fromSecret = function fromSecret(eddsa, secret) {
            if (secret instanceof KeyPair) return secret;
            return new KeyPair(eddsa, {
                secret: secret
            });
        };
        KeyPair.prototype.secret = function secret() {
            return this._secret;
        };
        cachedProperty(KeyPair, "pubBytes", function pubBytes() {
            return this.eddsa.encodePoint(this.pub());
        });
        cachedProperty(KeyPair, "pub", function pub() {
            if (this._pubBytes) return this.eddsa.decodePoint(this._pubBytes);
            return this.eddsa.g.mul(this.priv());
        });
        cachedProperty(KeyPair, "privBytes", function privBytes() {
            var eddsa = this.eddsa;
            var hash = this.hash();
            var lastIx = eddsa.encodingLength - 1;
            var a = hash.slice(0, eddsa.encodingLength);
            a[0] &= 248;
            a[lastIx] &= 127;
            a[lastIx] |= 64;
            return a;
        });
        cachedProperty(KeyPair, "priv", function priv() {
            return this.eddsa.decodeInt(this.privBytes());
        });
        cachedProperty(KeyPair, "hash", function hash() {
            return this.eddsa.hash().update(this.secret()).digest();
        });
        cachedProperty(KeyPair, "messagePrefix", function messagePrefix() {
            return this.hash().slice(this.eddsa.encodingLength);
        });
        KeyPair.prototype.sign = function sign(message) {
            assert(this._secret, "KeyPair can only verify");
            return this.eddsa.sign(message, this);
        };
        KeyPair.prototype.verify = function verify(message, sig) {
            return this.eddsa.verify(message, sig, this);
        };
        KeyPair.prototype.getSecret = function getSecret(enc) {
            assert(this._secret, "KeyPair is public only");
            return utils.encode(this.secret(), enc);
        };
        KeyPair.prototype.getPublic = function getPublic(enc) {
            return utils.encode(this.pubBytes(), enc);
        };
        module.exports = KeyPair;
    }, {
        "../../elliptic": 87
    } ],
    99: [ function(require, module, exports) {
        "use strict";
        var BN = require("bn.js");
        var elliptic = require("../../elliptic");
        var utils = elliptic.utils;
        var assert = utils.assert;
        var cachedProperty = utils.cachedProperty;
        var parseBytes = utils.parseBytes;
        function Signature(eddsa, sig) {
            this.eddsa = eddsa;
            if (typeof sig !== "object") sig = parseBytes(sig);
            if (Array.isArray(sig)) {
                sig = {
                    R: sig.slice(0, eddsa.encodingLength),
                    S: sig.slice(eddsa.encodingLength)
                };
            }
            assert(sig.R && sig.S, "Signature without R or S");
            if (eddsa.isPoint(sig.R)) this._R = sig.R;
            if (sig.S instanceof BN) this._S = sig.S;
            this._Rencoded = Array.isArray(sig.R) ? sig.R : sig.Rencoded;
            this._Sencoded = Array.isArray(sig.S) ? sig.S : sig.Sencoded;
        }
        cachedProperty(Signature, "S", function S() {
            return this.eddsa.decodeInt(this.Sencoded());
        });
        cachedProperty(Signature, "R", function R() {
            return this.eddsa.decodePoint(this.Rencoded());
        });
        cachedProperty(Signature, "Rencoded", function Rencoded() {
            return this.eddsa.encodePoint(this.R());
        });
        cachedProperty(Signature, "Sencoded", function Sencoded() {
            return this.eddsa.encodeInt(this.S());
        });
        Signature.prototype.toBytes = function toBytes() {
            return this.Rencoded().concat(this.Sencoded());
        };
        Signature.prototype.toHex = function toHex() {
            return utils.encode(this.toBytes(), "hex").toUpperCase();
        };
        module.exports = Signature;
    }, {
        "../../elliptic": 87,
        "bn.js": 23
    } ],
    100: [ function(require, module, exports) {
        module.exports = {
            doubles: {
                step: 4,
                points: [ [ "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a", "f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821" ], [ "8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508", "11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf" ], [ "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739", "d3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695" ], [ "363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640", "4e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9" ], [ "8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c", "4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36" ], [ "723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda", "96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f" ], [ "eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa", "5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999" ], [ "100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0", "cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09" ], [ "e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d", "9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d" ], [ "feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d", "e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088" ], [ "da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1", "9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d" ], [ "53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0", "5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8" ], [ "8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047", "10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a" ], [ "385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862", "283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453" ], [ "6f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7", "7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160" ], [ "3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd", "56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0" ], [ "85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83", "7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6" ], [ "948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a", "53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589" ], [ "6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8", "bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17" ], [ "e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d", "4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda" ], [ "e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725", "7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd" ], [ "213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754", "4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2" ], [ "4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c", "17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6" ], [ "fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6", "6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f" ], [ "76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39", "c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01" ], [ "c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891", "893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3" ], [ "d895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b", "febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f" ], [ "b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03", "2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7" ], [ "e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d", "eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78" ], [ "a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070", "7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1" ], [ "90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4", "e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150" ], [ "8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da", "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82" ], [ "e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11", "1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc" ], [ "8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e", "efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b" ], [ "e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41", "2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51" ], [ "b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef", "67c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45" ], [ "d68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8", "db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120" ], [ "324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d", "648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84" ], [ "4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96", "35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d" ], [ "9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd", "ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d" ], [ "6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5", "9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8" ], [ "a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266", "40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8" ], [ "7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71", "34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac" ], [ "928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac", "c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f" ], [ "85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751", "1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962" ], [ "ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e", "493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907" ], [ "827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241", "c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec" ], [ "eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3", "be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d" ], [ "e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f", "4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414" ], [ "1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19", "aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd" ], [ "146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be", "b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0" ], [ "fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9", "6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811" ], [ "da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2", "8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1" ], [ "a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13", "7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c" ], [ "174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c", "ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73" ], [ "959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba", "2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd" ], [ "d2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151", "e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405" ], [ "64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073", "d99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589" ], [ "8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458", "38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e" ], [ "13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b", "69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27" ], [ "bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366", "d3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1" ], [ "8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa", "40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482" ], [ "8ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0", "620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945" ], [ "dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787", "7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573" ], [ "f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e", "ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82" ] ]
            },
            naf: {
                wnd: 7,
                points: [ [ "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672" ], [ "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4", "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6" ], [ "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da" ], [ "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe", "cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37" ], [ "774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb", "d984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b" ], [ "f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8", "ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81" ], [ "d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e", "581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58" ], [ "defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34", "4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77" ], [ "2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c", "85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a" ], [ "352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5", "321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c" ], [ "2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f", "2de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67" ], [ "9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714", "73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402" ], [ "daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729", "a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55" ], [ "c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db", "2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482" ], [ "6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4", "e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82" ], [ "1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5", "b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396" ], [ "605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479", "2972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49" ], [ "62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d", "80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf" ], [ "80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f", "1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a" ], [ "7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb", "d0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7" ], [ "d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9", "eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933" ], [ "49370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963", "758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a" ], [ "77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74", "958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6" ], [ "f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530", "e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37" ], [ "463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b", "5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e" ], [ "f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247", "cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6" ], [ "caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1", "cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476" ], [ "2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120", "4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40" ], [ "7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435", "91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61" ], [ "754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18", "673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683" ], [ "e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8", "59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5" ], [ "186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb", "3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b" ], [ "df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f", "55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417" ], [ "5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143", "efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868" ], [ "290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba", "e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a" ], [ "af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45", "f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6" ], [ "766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a", "744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996" ], [ "59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e", "c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e" ], [ "f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8", "e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d" ], [ "7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c", "30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2" ], [ "948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519", "e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e" ], [ "7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab", "100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437" ], [ "3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca", "ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311" ], [ "d3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf", "8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4" ], [ "1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610", "68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575" ], [ "733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4", "f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d" ], [ "15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c", "d56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d" ], [ "a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940", "edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629" ], [ "e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980", "a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06" ], [ "311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3", "66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374" ], [ "34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf", "9414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee" ], [ "f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63", "4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1" ], [ "d7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448", "fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b" ], [ "32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf", "5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661" ], [ "7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5", "8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6" ], [ "ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6", "8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e" ], [ "16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5", "5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d" ], [ "eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99", "f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc" ], [ "78c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51", "f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4" ], [ "494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5", "42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c" ], [ "a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5", "204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b" ], [ "c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997", "4f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913" ], [ "841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881", "73867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154" ], [ "5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5", "39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865" ], [ "36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66", "d2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc" ], [ "336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726", "ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224" ], [ "8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede", "6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e" ], [ "1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94", "60660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6" ], [ "85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31", "3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511" ], [ "29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51", "b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b" ], [ "a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252", "ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2" ], [ "4e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5", "cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c" ], [ "d24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b", "6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3" ], [ "ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4", "322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d" ], [ "af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f", "6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700" ], [ "e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889", "2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4" ], [ "591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246", "b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196" ], [ "11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984", "998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4" ], [ "3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a", "b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257" ], [ "cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030", "bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13" ], [ "c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197", "6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096" ], [ "c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593", "c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38" ], [ "a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef", "21ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f" ], [ "347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38", "60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448" ], [ "da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a", "49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a" ], [ "c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111", "5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4" ], [ "4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502", "7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437" ], [ "3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea", "be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7" ], [ "cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26", "8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d" ], [ "b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986", "39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a" ], [ "d4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e", "62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54" ], [ "48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4", "25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77" ], [ "dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda", "ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517" ], [ "6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859", "cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10" ], [ "e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f", "f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125" ], [ "eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c", "6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e" ], [ "13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942", "fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1" ], [ "ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a", "1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2" ], [ "b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80", "5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423" ], [ "ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d", "438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8" ], [ "8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1", "cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758" ], [ "52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63", "c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375" ], [ "e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352", "6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d" ], [ "7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193", "ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec" ], [ "5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00", "9731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0" ], [ "32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58", "ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c" ], [ "e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7", "d3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4" ], [ "8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8", "c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f" ], [ "4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e", "67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649" ], [ "3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d", "cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826" ], [ "674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b", "299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5" ], [ "d32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f", "f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87" ], [ "30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6", "462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b" ], [ "be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297", "62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc" ], [ "93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a", "7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c" ], [ "b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c", "ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f" ], [ "d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52", "4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a" ], [ "d3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb", "bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46" ], [ "463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065", "bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f" ], [ "7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917", "603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03" ], [ "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9", "cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08" ], [ "30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3", "553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8" ], [ "9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57", "712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373" ], [ "176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66", "ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3" ], [ "75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8", "9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8" ], [ "809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721", "9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1" ], [ "1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180", "4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9" ] ]
            }
        };
    }, {} ],
    101: [ function(require, module, exports) {
        "use strict";
        var utils = exports;
        var BN = require("bn.js");
        var minAssert = require("minimalistic-assert");
        var minUtils = require("minimalistic-crypto-utils");
        utils.assert = minAssert;
        utils.toArray = minUtils.toArray;
        utils.zero2 = minUtils.zero2;
        utils.toHex = minUtils.toHex;
        utils.encode = minUtils.encode;
        function getNAF(num, w) {
            var naf = [];
            var ws = 1 << w + 1;
            var k = num.clone();
            while (k.cmpn(1) >= 0) {
                var z;
                if (k.isOdd()) {
                    var mod = k.andln(ws - 1);
                    if (mod > (ws >> 1) - 1) z = (ws >> 1) - mod; else z = mod;
                    k.isubn(z);
                } else {
                    z = 0;
                }
                naf.push(z);
                var shift = k.cmpn(0) !== 0 && k.andln(ws - 1) === 0 ? w + 1 : 1;
                for (var i = 1; i < shift; i++) naf.push(0);
                k.iushrn(shift);
            }
            return naf;
        }
        utils.getNAF = getNAF;
        function getJSF(k1, k2) {
            var jsf = [ [], [] ];
            k1 = k1.clone();
            k2 = k2.clone();
            var d1 = 0;
            var d2 = 0;
            while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {
                var m14 = k1.andln(3) + d1 & 3;
                var m24 = k2.andln(3) + d2 & 3;
                if (m14 === 3) m14 = -1;
                if (m24 === 3) m24 = -1;
                var u1;
                if ((m14 & 1) === 0) {
                    u1 = 0;
                } else {
                    var m8 = k1.andln(7) + d1 & 7;
                    if ((m8 === 3 || m8 === 5) && m24 === 2) u1 = -m14; else u1 = m14;
                }
                jsf[0].push(u1);
                var u2;
                if ((m24 & 1) === 0) {
                    u2 = 0;
                } else {
                    var m8 = k2.andln(7) + d2 & 7;
                    if ((m8 === 3 || m8 === 5) && m14 === 2) u2 = -m24; else u2 = m24;
                }
                jsf[1].push(u2);
                if (2 * d1 === u1 + 1) d1 = 1 - d1;
                if (2 * d2 === u2 + 1) d2 = 1 - d2;
                k1.iushrn(1);
                k2.iushrn(1);
            }
            return jsf;
        }
        utils.getJSF = getJSF;
        function cachedProperty(obj, name, computer) {
            var key = "_" + name;
            obj.prototype[name] = function cachedProperty() {
                return this[key] !== undefined ? this[key] : this[key] = computer.call(this);
            };
        }
        utils.cachedProperty = cachedProperty;
        function parseBytes(bytes) {
            return typeof bytes === "string" ? utils.toArray(bytes, "hex") : bytes;
        }
        utils.parseBytes = parseBytes;
        function intFromLE(bytes) {
            return new BN(bytes, "hex", "le");
        }
        utils.intFromLE = intFromLE;
    }, {
        "bn.js": 23,
        "minimalistic-assert": 126,
        "minimalistic-crypto-utils": 127
    } ],
    102: [ function(require, module, exports) {
        module.exports = {
            _args: [ [ {
                raw: "elliptic@^6.2.3",
                scope: null,
                escapedName: "elliptic",
                name: "elliptic",
                rawSpec: "^6.2.3",
                spec: ">=6.2.3 <7.0.0",
                type: "range"
            }, "/home/olitvin/share-home/htdocs/angular-ecdsa/node_modules/secp256k1" ] ],
            _from: "elliptic@>=6.2.3 <7.0.0",
            _id: "elliptic@6.4.0",
            _inCache: true,
            _location: "/elliptic",
            _nodeVersion: "7.0.0",
            _npmOperationalInternal: {
                host: "packages-18-east.internal.npmjs.com",
                tmp: "tmp/elliptic-6.4.0.tgz_1487798866428_0.30510620190761983"
            },
            _npmUser: {
                name: "indutny",
                email: "fedor@indutny.com"
            },
            _npmVersion: "3.10.8",
            _phantomChildren: {},
            _requested: {
                raw: "elliptic@^6.2.3",
                scope: null,
                escapedName: "elliptic",
                name: "elliptic",
                rawSpec: "^6.2.3",
                spec: ">=6.2.3 <7.0.0",
                type: "range"
            },
            _requiredBy: [ "/browserify-sign", "/create-ecdh", "/secp256k1" ],
            _resolved: "https://registry.npmjs.org/elliptic/-/elliptic-6.4.0.tgz",
            _shasum: "cac9af8762c85836187003c8dfe193e5e2eae5df",
            _shrinkwrap: null,
            _spec: "elliptic@^6.2.3",
            _where: "/home/olitvin/share-home/htdocs/angular-ecdsa/node_modules/secp256k1",
            author: {
                name: "Fedor Indutny",
                email: "fedor@indutny.com"
            },
            bugs: {
                url: "https://github.com/indutny/elliptic/issues"
            },
            dependencies: {
                "bn.js": "^4.4.0",
                brorand: "^1.0.1",
                "hash.js": "^1.0.0",
                "hmac-drbg": "^1.0.0",
                inherits: "^2.0.1",
                "minimalistic-assert": "^1.0.0",
                "minimalistic-crypto-utils": "^1.0.0"
            },
            description: "EC cryptography",
            devDependencies: {
                brfs: "^1.4.3",
                coveralls: "^2.11.3",
                grunt: "^0.4.5",
                "grunt-browserify": "^5.0.0",
                "grunt-cli": "^1.2.0",
                "grunt-contrib-connect": "^1.0.0",
                "grunt-contrib-copy": "^1.0.0",
                "grunt-contrib-uglify": "^1.0.1",
                "grunt-mocha-istanbul": "^3.0.1",
                "grunt-saucelabs": "^8.6.2",
                istanbul: "^0.4.2",
                jscs: "^2.9.0",
                jshint: "^2.6.0",
                mocha: "^2.1.0"
            },
            directories: {},
            dist: {
                shasum: "cac9af8762c85836187003c8dfe193e5e2eae5df",
                tarball: "https://registry.npmjs.org/elliptic/-/elliptic-6.4.0.tgz"
            },
            files: [ "lib" ],
            gitHead: "6b0d2b76caae91471649c8e21f0b1d3ba0f96090",
            homepage: "https://github.com/indutny/elliptic",
            keywords: [ "EC", "Elliptic", "curve", "Cryptography" ],
            license: "MIT",
            main: "lib/elliptic.js",
            maintainers: [ {
                name: "indutny",
                email: "fedor@indutny.com"
            } ],
            name: "elliptic",
            optionalDependencies: {},
            readme: "ERROR: No README data found!",
            repository: {
                type: "git",
                url: "git+ssh://git@github.com/indutny/elliptic.git"
            },
            scripts: {
                jscs: "jscs benchmarks/*.js lib/*.js lib/**/*.js lib/**/**/*.js test/index.js",
                jshint: "jscs benchmarks/*.js lib/*.js lib/**/*.js lib/**/**/*.js test/index.js",
                lint: "npm run jscs && npm run jshint",
                test: "npm run lint && npm run unit",
                unit: "istanbul test _mocha --reporter=spec test/index.js",
                version: "grunt dist && git add dist/"
            },
            version: "6.4.0"
        };
    }, {} ],
    103: [ function(require, module, exports) {
        function EventEmitter() {
            this._events = this._events || {};
            this._maxListeners = this._maxListeners || undefined;
        }
        module.exports = EventEmitter;
        EventEmitter.EventEmitter = EventEmitter;
        EventEmitter.prototype._events = undefined;
        EventEmitter.prototype._maxListeners = undefined;
        EventEmitter.defaultMaxListeners = 10;
        EventEmitter.prototype.setMaxListeners = function(n) {
            if (!isNumber(n) || n < 0 || isNaN(n)) throw TypeError("n must be a positive number");
            this._maxListeners = n;
            return this;
        };
        EventEmitter.prototype.emit = function(type) {
            var er, handler, len, args, i, listeners;
            if (!this._events) this._events = {};
            if (type === "error") {
                if (!this._events.error || isObject(this._events.error) && !this._events.error.length) {
                    er = arguments[1];
                    if (er instanceof Error) {
                        throw er;
                    } else {
                        var err = new Error('Uncaught, unspecified "error" event. (' + er + ")");
                        err.context = er;
                        throw err;
                    }
                }
            }
            handler = this._events[type];
            if (isUndefined(handler)) return false;
            if (isFunction(handler)) {
                switch (arguments.length) {
                  case 1:
                    handler.call(this);
                    break;

                  case 2:
                    handler.call(this, arguments[1]);
                    break;

                  case 3:
                    handler.call(this, arguments[1], arguments[2]);
                    break;

                  default:
                    args = Array.prototype.slice.call(arguments, 1);
                    handler.apply(this, args);
                }
            } else if (isObject(handler)) {
                args = Array.prototype.slice.call(arguments, 1);
                listeners = handler.slice();
                len = listeners.length;
                for (i = 0; i < len; i++) listeners[i].apply(this, args);
            }
            return true;
        };
        EventEmitter.prototype.addListener = function(type, listener) {
            var m;
            if (!isFunction(listener)) throw TypeError("listener must be a function");
            if (!this._events) this._events = {};
            if (this._events.newListener) this.emit("newListener", type, isFunction(listener.listener) ? listener.listener : listener);
            if (!this._events[type]) this._events[type] = listener; else if (isObject(this._events[type])) this._events[type].push(listener); else this._events[type] = [ this._events[type], listener ];
            if (isObject(this._events[type]) && !this._events[type].warned) {
                if (!isUndefined(this._maxListeners)) {
                    m = this._maxListeners;
                } else {
                    m = EventEmitter.defaultMaxListeners;
                }
                if (m && m > 0 && this._events[type].length > m) {
                    this._events[type].warned = true;
                    console.error("(node) warning: possible EventEmitter memory " + "leak detected. %d listeners added. " + "Use emitter.setMaxListeners() to increase limit.", this._events[type].length);
                    if (typeof console.trace === "function") {
                        console.trace();
                    }
                }
            }
            return this;
        };
        EventEmitter.prototype.on = EventEmitter.prototype.addListener;
        EventEmitter.prototype.once = function(type, listener) {
            if (!isFunction(listener)) throw TypeError("listener must be a function");
            var fired = false;
            function g() {
                this.removeListener(type, g);
                if (!fired) {
                    fired = true;
                    listener.apply(this, arguments);
                }
            }
            g.listener = listener;
            this.on(type, g);
            return this;
        };
        EventEmitter.prototype.removeListener = function(type, listener) {
            var list, position, length, i;
            if (!isFunction(listener)) throw TypeError("listener must be a function");
            if (!this._events || !this._events[type]) return this;
            list = this._events[type];
            length = list.length;
            position = -1;
            if (list === listener || isFunction(list.listener) && list.listener === listener) {
                delete this._events[type];
                if (this._events.removeListener) this.emit("removeListener", type, listener);
            } else if (isObject(list)) {
                for (i = length; i-- > 0; ) {
                    if (list[i] === listener || list[i].listener && list[i].listener === listener) {
                        position = i;
                        break;
                    }
                }
                if (position < 0) return this;
                if (list.length === 1) {
                    list.length = 0;
                    delete this._events[type];
                } else {
                    list.splice(position, 1);
                }
                if (this._events.removeListener) this.emit("removeListener", type, listener);
            }
            return this;
        };
        EventEmitter.prototype.removeAllListeners = function(type) {
            var key, listeners;
            if (!this._events) return this;
            if (!this._events.removeListener) {
                if (arguments.length === 0) this._events = {}; else if (this._events[type]) delete this._events[type];
                return this;
            }
            if (arguments.length === 0) {
                for (key in this._events) {
                    if (key === "removeListener") continue;
                    this.removeAllListeners(key);
                }
                this.removeAllListeners("removeListener");
                this._events = {};
                return this;
            }
            listeners = this._events[type];
            if (isFunction(listeners)) {
                this.removeListener(type, listeners);
            } else if (listeners) {
                while (listeners.length) this.removeListener(type, listeners[listeners.length - 1]);
            }
            delete this._events[type];
            return this;
        };
        EventEmitter.prototype.listeners = function(type) {
            var ret;
            if (!this._events || !this._events[type]) ret = []; else if (isFunction(this._events[type])) ret = [ this._events[type] ]; else ret = this._events[type].slice();
            return ret;
        };
        EventEmitter.prototype.listenerCount = function(type) {
            if (this._events) {
                var evlistener = this._events[type];
                if (isFunction(evlistener)) return 1; else if (evlistener) return evlistener.length;
            }
            return 0;
        };
        EventEmitter.listenerCount = function(emitter, type) {
            return emitter.listenerCount(type);
        };
        function isFunction(arg) {
            return typeof arg === "function";
        }
        function isNumber(arg) {
            return typeof arg === "number";
        }
        function isObject(arg) {
            return typeof arg === "object" && arg !== null;
        }
        function isUndefined(arg) {
            return arg === void 0;
        }
    }, {} ],
    104: [ function(require, module, exports) {
        (function(Buffer) {
            var md5 = require("create-hash/md5");
            module.exports = EVP_BytesToKey;
            function EVP_BytesToKey(password, salt, keyLen, ivLen) {
                if (!Buffer.isBuffer(password)) {
                    password = new Buffer(password, "binary");
                }
                if (salt && !Buffer.isBuffer(salt)) {
                    salt = new Buffer(salt, "binary");
                }
                keyLen = keyLen / 8;
                ivLen = ivLen || 0;
                var ki = 0;
                var ii = 0;
                var key = new Buffer(keyLen);
                var iv = new Buffer(ivLen);
                var addmd = 0;
                var md_buf;
                var i;
                var bufs = [];
                while (true) {
                    if (addmd++ > 0) {
                        bufs.push(md_buf);
                    }
                    bufs.push(password);
                    if (salt) {
                        bufs.push(salt);
                    }
                    md_buf = md5(Buffer.concat(bufs));
                    bufs = [];
                    i = 0;
                    if (keyLen > 0) {
                        while (true) {
                            if (keyLen === 0) {
                                break;
                            }
                            if (i === md_buf.length) {
                                break;
                            }
                            key[ki++] = md_buf[i];
                            keyLen--;
                            i++;
                        }
                    }
                    if (ivLen > 0 && i !== md_buf.length) {
                        while (true) {
                            if (ivLen === 0) {
                                break;
                            }
                            if (i === md_buf.length) {
                                break;
                            }
                            iv[ii++] = md_buf[i];
                            ivLen--;
                            i++;
                        }
                    }
                    if (keyLen === 0 && ivLen === 0) {
                        break;
                    }
                }
                for (i = 0; i < md_buf.length; i++) {
                    md_buf[i] = 0;
                }
                return {
                    key: key,
                    iv: iv
                };
            }
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "create-hash/md5": 63
    } ],
    105: [ function(require, module, exports) {
        (function(Buffer) {
            "use strict";
            var Transform = require("stream").Transform;
            var inherits = require("inherits");
            function HashBase(blockSize) {
                Transform.call(this);
                this._block = new Buffer(blockSize);
                this._blockSize = blockSize;
                this._blockOffset = 0;
                this._length = [ 0, 0, 0, 0 ];
                this._finalized = false;
            }
            inherits(HashBase, Transform);
            HashBase.prototype._transform = function(chunk, encoding, callback) {
                var error = null;
                try {
                    if (encoding !== "buffer") chunk = new Buffer(chunk, encoding);
                    this.update(chunk);
                } catch (err) {
                    error = err;
                }
                callback(error);
            };
            HashBase.prototype._flush = function(callback) {
                var error = null;
                try {
                    this.push(this._digest());
                } catch (err) {
                    error = err;
                }
                callback(error);
            };
            HashBase.prototype.update = function(data, encoding) {
                if (!Buffer.isBuffer(data) && typeof data !== "string") throw new TypeError("Data must be a string or a buffer");
                if (this._finalized) throw new Error("Digest already called");
                if (!Buffer.isBuffer(data)) data = new Buffer(data, encoding || "binary");
                var block = this._block;
                var offset = 0;
                while (this._blockOffset + data.length - offset >= this._blockSize) {
                    for (var i = this._blockOffset; i < this._blockSize; ) block[i++] = data[offset++];
                    this._update();
                    this._blockOffset = 0;
                }
                while (offset < data.length) block[this._blockOffset++] = data[offset++];
                for (var j = 0, carry = data.length * 8; carry > 0; ++j) {
                    this._length[j] += carry;
                    carry = this._length[j] / 4294967296 | 0;
                    if (carry > 0) this._length[j] -= 4294967296 * carry;
                }
                return this;
            };
            HashBase.prototype._update = function(data) {
                throw new Error("_update is not implemented");
            };
            HashBase.prototype.digest = function(encoding) {
                if (this._finalized) throw new Error("Digest already called");
                this._finalized = true;
                var digest = this._digest();
                if (encoding !== undefined) digest = digest.toString(encoding);
                return digest;
            };
            HashBase.prototype._digest = function() {
                throw new Error("_digest is not implemented");
            };
            module.exports = HashBase;
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        inherits: 122,
        stream: 179
    } ],
    106: [ function(require, module, exports) {
        var hash = exports;
        hash.utils = require("./hash/utils");
        hash.common = require("./hash/common");
        hash.sha = require("./hash/sha");
        hash.ripemd = require("./hash/ripemd");
        hash.hmac = require("./hash/hmac");
        hash.sha1 = hash.sha.sha1;
        hash.sha256 = hash.sha.sha256;
        hash.sha224 = hash.sha.sha224;
        hash.sha384 = hash.sha.sha384;
        hash.sha512 = hash.sha.sha512;
        hash.ripemd160 = hash.ripemd.ripemd160;
    }, {
        "./hash/common": 107,
        "./hash/hmac": 108,
        "./hash/ripemd": 109,
        "./hash/sha": 110,
        "./hash/utils": 117
    } ],
    107: [ function(require, module, exports) {
        "use strict";
        var utils = require("./utils");
        var assert = require("minimalistic-assert");
        function BlockHash() {
            this.pending = null;
            this.pendingTotal = 0;
            this.blockSize = this.constructor.blockSize;
            this.outSize = this.constructor.outSize;
            this.hmacStrength = this.constructor.hmacStrength;
            this.padLength = this.constructor.padLength / 8;
            this.endian = "big";
            this._delta8 = this.blockSize / 8;
            this._delta32 = this.blockSize / 32;
        }
        exports.BlockHash = BlockHash;
        BlockHash.prototype.update = function update(msg, enc) {
            msg = utils.toArray(msg, enc);
            if (!this.pending) this.pending = msg; else this.pending = this.pending.concat(msg);
            this.pendingTotal += msg.length;
            if (this.pending.length >= this._delta8) {
                msg = this.pending;
                var r = msg.length % this._delta8;
                this.pending = msg.slice(msg.length - r, msg.length);
                if (this.pending.length === 0) this.pending = null;
                msg = utils.join32(msg, 0, msg.length - r, this.endian);
                for (var i = 0; i < msg.length; i += this._delta32) this._update(msg, i, i + this._delta32);
            }
            return this;
        };
        BlockHash.prototype.digest = function digest(enc) {
            this.update(this._pad());
            assert(this.pending === null);
            return this._digest(enc);
        };
        BlockHash.prototype._pad = function pad() {
            var len = this.pendingTotal;
            var bytes = this._delta8;
            var k = bytes - (len + this.padLength) % bytes;
            var res = new Array(k + this.padLength);
            res[0] = 128;
            for (var i = 1; i < k; i++) res[i] = 0;
            len <<= 3;
            if (this.endian === "big") {
                for (var t = 8; t < this.padLength; t++) res[i++] = 0;
                res[i++] = 0;
                res[i++] = 0;
                res[i++] = 0;
                res[i++] = 0;
                res[i++] = len >>> 24 & 255;
                res[i++] = len >>> 16 & 255;
                res[i++] = len >>> 8 & 255;
                res[i++] = len & 255;
            } else {
                res[i++] = len & 255;
                res[i++] = len >>> 8 & 255;
                res[i++] = len >>> 16 & 255;
                res[i++] = len >>> 24 & 255;
                res[i++] = 0;
                res[i++] = 0;
                res[i++] = 0;
                res[i++] = 0;
                for (t = 8; t < this.padLength; t++) res[i++] = 0;
            }
            return res;
        };
    }, {
        "./utils": 117,
        "minimalistic-assert": 126
    } ],
    108: [ function(require, module, exports) {
        "use strict";
        var utils = require("./utils");
        var assert = require("minimalistic-assert");
        function Hmac(hash, key, enc) {
            if (!(this instanceof Hmac)) return new Hmac(hash, key, enc);
            this.Hash = hash;
            this.blockSize = hash.blockSize / 8;
            this.outSize = hash.outSize / 8;
            this.inner = null;
            this.outer = null;
            this._init(utils.toArray(key, enc));
        }
        module.exports = Hmac;
        Hmac.prototype._init = function init(key) {
            if (key.length > this.blockSize) key = new this.Hash().update(key).digest();
            assert(key.length <= this.blockSize);
            for (var i = key.length; i < this.blockSize; i++) key.push(0);
            for (i = 0; i < key.length; i++) key[i] ^= 54;
            this.inner = new this.Hash().update(key);
            for (i = 0; i < key.length; i++) key[i] ^= 106;
            this.outer = new this.Hash().update(key);
        };
        Hmac.prototype.update = function update(msg, enc) {
            this.inner.update(msg, enc);
            return this;
        };
        Hmac.prototype.digest = function digest(enc) {
            this.outer.update(this.inner.digest());
            return this.outer.digest(enc);
        };
    }, {
        "./utils": 117,
        "minimalistic-assert": 126
    } ],
    109: [ function(require, module, exports) {
        "use strict";
        var utils = require("./utils");
        var common = require("./common");
        var rotl32 = utils.rotl32;
        var sum32 = utils.sum32;
        var sum32_3 = utils.sum32_3;
        var sum32_4 = utils.sum32_4;
        var BlockHash = common.BlockHash;
        function RIPEMD160() {
            if (!(this instanceof RIPEMD160)) return new RIPEMD160();
            BlockHash.call(this);
            this.h = [ 1732584193, 4023233417, 2562383102, 271733878, 3285377520 ];
            this.endian = "little";
        }
        utils.inherits(RIPEMD160, BlockHash);
        exports.ripemd160 = RIPEMD160;
        RIPEMD160.blockSize = 512;
        RIPEMD160.outSize = 160;
        RIPEMD160.hmacStrength = 192;
        RIPEMD160.padLength = 64;
        RIPEMD160.prototype._update = function update(msg, start) {
            var A = this.h[0];
            var B = this.h[1];
            var C = this.h[2];
            var D = this.h[3];
            var E = this.h[4];
            var Ah = A;
            var Bh = B;
            var Ch = C;
            var Dh = D;
            var Eh = E;
            for (var j = 0; j < 80; j++) {
                var T = sum32(rotl32(sum32_4(A, f(j, B, C, D), msg[r[j] + start], K(j)), s[j]), E);
                A = E;
                E = D;
                D = rotl32(C, 10);
                C = B;
                B = T;
                T = sum32(rotl32(sum32_4(Ah, f(79 - j, Bh, Ch, Dh), msg[rh[j] + start], Kh(j)), sh[j]), Eh);
                Ah = Eh;
                Eh = Dh;
                Dh = rotl32(Ch, 10);
                Ch = Bh;
                Bh = T;
            }
            T = sum32_3(this.h[1], C, Dh);
            this.h[1] = sum32_3(this.h[2], D, Eh);
            this.h[2] = sum32_3(this.h[3], E, Ah);
            this.h[3] = sum32_3(this.h[4], A, Bh);
            this.h[4] = sum32_3(this.h[0], B, Ch);
            this.h[0] = T;
        };
        RIPEMD160.prototype._digest = function digest(enc) {
            if (enc === "hex") return utils.toHex32(this.h, "little"); else return utils.split32(this.h, "little");
        };
        function f(j, x, y, z) {
            if (j <= 15) return x ^ y ^ z; else if (j <= 31) return x & y | ~x & z; else if (j <= 47) return (x | ~y) ^ z; else if (j <= 63) return x & z | y & ~z; else return x ^ (y | ~z);
        }
        function K(j) {
            if (j <= 15) return 0; else if (j <= 31) return 1518500249; else if (j <= 47) return 1859775393; else if (j <= 63) return 2400959708; else return 2840853838;
        }
        function Kh(j) {
            if (j <= 15) return 1352829926; else if (j <= 31) return 1548603684; else if (j <= 47) return 1836072691; else if (j <= 63) return 2053994217; else return 0;
        }
        var r = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 ];
        var rh = [ 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 ];
        var s = [ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 ];
        var sh = [ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 ];
    }, {
        "./common": 107,
        "./utils": 117
    } ],
    110: [ function(require, module, exports) {
        "use strict";
        exports.sha1 = require("./sha/1");
        exports.sha224 = require("./sha/224");
        exports.sha256 = require("./sha/256");
        exports.sha384 = require("./sha/384");
        exports.sha512 = require("./sha/512");
    }, {
        "./sha/1": 111,
        "./sha/224": 112,
        "./sha/256": 113,
        "./sha/384": 114,
        "./sha/512": 115
    } ],
    111: [ function(require, module, exports) {
        "use strict";
        var utils = require("../utils");
        var common = require("../common");
        var shaCommon = require("./common");
        var rotl32 = utils.rotl32;
        var sum32 = utils.sum32;
        var sum32_5 = utils.sum32_5;
        var ft_1 = shaCommon.ft_1;
        var BlockHash = common.BlockHash;
        var sha1_K = [ 1518500249, 1859775393, 2400959708, 3395469782 ];
        function SHA1() {
            if (!(this instanceof SHA1)) return new SHA1();
            BlockHash.call(this);
            this.h = [ 1732584193, 4023233417, 2562383102, 271733878, 3285377520 ];
            this.W = new Array(80);
        }
        utils.inherits(SHA1, BlockHash);
        module.exports = SHA1;
        SHA1.blockSize = 512;
        SHA1.outSize = 160;
        SHA1.hmacStrength = 80;
        SHA1.padLength = 64;
        SHA1.prototype._update = function _update(msg, start) {
            var W = this.W;
            for (var i = 0; i < 16; i++) W[i] = msg[start + i];
            for (;i < W.length; i++) W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
            var a = this.h[0];
            var b = this.h[1];
            var c = this.h[2];
            var d = this.h[3];
            var e = this.h[4];
            for (i = 0; i < W.length; i++) {
                var s = ~~(i / 20);
                var t = sum32_5(rotl32(a, 5), ft_1(s, b, c, d), e, W[i], sha1_K[s]);
                e = d;
                d = c;
                c = rotl32(b, 30);
                b = a;
                a = t;
            }
            this.h[0] = sum32(this.h[0], a);
            this.h[1] = sum32(this.h[1], b);
            this.h[2] = sum32(this.h[2], c);
            this.h[3] = sum32(this.h[3], d);
            this.h[4] = sum32(this.h[4], e);
        };
        SHA1.prototype._digest = function digest(enc) {
            if (enc === "hex") return utils.toHex32(this.h, "big"); else return utils.split32(this.h, "big");
        };
    }, {
        "../common": 107,
        "../utils": 117,
        "./common": 116
    } ],
    112: [ function(require, module, exports) {
        "use strict";
        var utils = require("../utils");
        var SHA256 = require("./256");
        function SHA224() {
            if (!(this instanceof SHA224)) return new SHA224();
            SHA256.call(this);
            this.h = [ 3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428 ];
        }
        utils.inherits(SHA224, SHA256);
        module.exports = SHA224;
        SHA224.blockSize = 512;
        SHA224.outSize = 224;
        SHA224.hmacStrength = 192;
        SHA224.padLength = 64;
        SHA224.prototype._digest = function digest(enc) {
            if (enc === "hex") return utils.toHex32(this.h.slice(0, 7), "big"); else return utils.split32(this.h.slice(0, 7), "big");
        };
    }, {
        "../utils": 117,
        "./256": 113
    } ],
    113: [ function(require, module, exports) {
        "use strict";
        var utils = require("../utils");
        var common = require("../common");
        var shaCommon = require("./common");
        var assert = require("minimalistic-assert");
        var sum32 = utils.sum32;
        var sum32_4 = utils.sum32_4;
        var sum32_5 = utils.sum32_5;
        var ch32 = shaCommon.ch32;
        var maj32 = shaCommon.maj32;
        var s0_256 = shaCommon.s0_256;
        var s1_256 = shaCommon.s1_256;
        var g0_256 = shaCommon.g0_256;
        var g1_256 = shaCommon.g1_256;
        var BlockHash = common.BlockHash;
        var sha256_K = [ 1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298 ];
        function SHA256() {
            if (!(this instanceof SHA256)) return new SHA256();
            BlockHash.call(this);
            this.h = [ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 ];
            this.k = sha256_K;
            this.W = new Array(64);
        }
        utils.inherits(SHA256, BlockHash);
        module.exports = SHA256;
        SHA256.blockSize = 512;
        SHA256.outSize = 256;
        SHA256.hmacStrength = 192;
        SHA256.padLength = 64;
        SHA256.prototype._update = function _update(msg, start) {
            var W = this.W;
            for (var i = 0; i < 16; i++) W[i] = msg[start + i];
            for (;i < W.length; i++) W[i] = sum32_4(g1_256(W[i - 2]), W[i - 7], g0_256(W[i - 15]), W[i - 16]);
            var a = this.h[0];
            var b = this.h[1];
            var c = this.h[2];
            var d = this.h[3];
            var e = this.h[4];
            var f = this.h[5];
            var g = this.h[6];
            var h = this.h[7];
            assert(this.k.length === W.length);
            for (i = 0; i < W.length; i++) {
                var T1 = sum32_5(h, s1_256(e), ch32(e, f, g), this.k[i], W[i]);
                var T2 = sum32(s0_256(a), maj32(a, b, c));
                h = g;
                g = f;
                f = e;
                e = sum32(d, T1);
                d = c;
                c = b;
                b = a;
                a = sum32(T1, T2);
            }
            this.h[0] = sum32(this.h[0], a);
            this.h[1] = sum32(this.h[1], b);
            this.h[2] = sum32(this.h[2], c);
            this.h[3] = sum32(this.h[3], d);
            this.h[4] = sum32(this.h[4], e);
            this.h[5] = sum32(this.h[5], f);
            this.h[6] = sum32(this.h[6], g);
            this.h[7] = sum32(this.h[7], h);
        };
        SHA256.prototype._digest = function digest(enc) {
            if (enc === "hex") return utils.toHex32(this.h, "big"); else return utils.split32(this.h, "big");
        };
    }, {
        "../common": 107,
        "../utils": 117,
        "./common": 116,
        "minimalistic-assert": 126
    } ],
    114: [ function(require, module, exports) {
        "use strict";
        var utils = require("../utils");
        var SHA512 = require("./512");
        function SHA384() {
            if (!(this instanceof SHA384)) return new SHA384();
            SHA512.call(this);
            this.h = [ 3418070365, 3238371032, 1654270250, 914150663, 2438529370, 812702999, 355462360, 4144912697, 1731405415, 4290775857, 2394180231, 1750603025, 3675008525, 1694076839, 1203062813, 3204075428 ];
        }
        utils.inherits(SHA384, SHA512);
        module.exports = SHA384;
        SHA384.blockSize = 1024;
        SHA384.outSize = 384;
        SHA384.hmacStrength = 192;
        SHA384.padLength = 128;
        SHA384.prototype._digest = function digest(enc) {
            if (enc === "hex") return utils.toHex32(this.h.slice(0, 12), "big"); else return utils.split32(this.h.slice(0, 12), "big");
        };
    }, {
        "../utils": 117,
        "./512": 115
    } ],
    115: [ function(require, module, exports) {
        "use strict";
        var utils = require("../utils");
        var common = require("../common");
        var assert = require("minimalistic-assert");
        var rotr64_hi = utils.rotr64_hi;
        var rotr64_lo = utils.rotr64_lo;
        var shr64_hi = utils.shr64_hi;
        var shr64_lo = utils.shr64_lo;
        var sum64 = utils.sum64;
        var sum64_hi = utils.sum64_hi;
        var sum64_lo = utils.sum64_lo;
        var sum64_4_hi = utils.sum64_4_hi;
        var sum64_4_lo = utils.sum64_4_lo;
        var sum64_5_hi = utils.sum64_5_hi;
        var sum64_5_lo = utils.sum64_5_lo;
        var BlockHash = common.BlockHash;
        var sha512_K = [ 1116352408, 3609767458, 1899447441, 602891725, 3049323471, 3964484399, 3921009573, 2173295548, 961987163, 4081628472, 1508970993, 3053834265, 2453635748, 2937671579, 2870763221, 3664609560, 3624381080, 2734883394, 310598401, 1164996542, 607225278, 1323610764, 1426881987, 3590304994, 1925078388, 4068182383, 2162078206, 991336113, 2614888103, 633803317, 3248222580, 3479774868, 3835390401, 2666613458, 4022224774, 944711139, 264347078, 2341262773, 604807628, 2007800933, 770255983, 1495990901, 1249150122, 1856431235, 1555081692, 3175218132, 1996064986, 2198950837, 2554220882, 3999719339, 2821834349, 766784016, 2952996808, 2566594879, 3210313671, 3203337956, 3336571891, 1034457026, 3584528711, 2466948901, 113926993, 3758326383, 338241895, 168717936, 666307205, 1188179964, 773529912, 1546045734, 1294757372, 1522805485, 1396182291, 2643833823, 1695183700, 2343527390, 1986661051, 1014477480, 2177026350, 1206759142, 2456956037, 344077627, 2730485921, 1290863460, 2820302411, 3158454273, 3259730800, 3505952657, 3345764771, 106217008, 3516065817, 3606008344, 3600352804, 1432725776, 4094571909, 1467031594, 275423344, 851169720, 430227734, 3100823752, 506948616, 1363258195, 659060556, 3750685593, 883997877, 3785050280, 958139571, 3318307427, 1322822218, 3812723403, 1537002063, 2003034995, 1747873779, 3602036899, 1955562222, 1575990012, 2024104815, 1125592928, 2227730452, 2716904306, 2361852424, 442776044, 2428436474, 593698344, 2756734187, 3733110249, 3204031479, 2999351573, 3329325298, 3815920427, 3391569614, 3928383900, 3515267271, 566280711, 3940187606, 3454069534, 4118630271, 4000239992, 116418474, 1914138554, 174292421, 2731055270, 289380356, 3203993006, 460393269, 320620315, 685471733, 587496836, 852142971, 1086792851, 1017036298, 365543100, 1126000580, 2618297676, 1288033470, 3409855158, 1501505948, 4234509866, 1607167915, 987167468, 1816402316, 1246189591 ];
        function SHA512() {
            if (!(this instanceof SHA512)) return new SHA512();
            BlockHash.call(this);
            this.h = [ 1779033703, 4089235720, 3144134277, 2227873595, 1013904242, 4271175723, 2773480762, 1595750129, 1359893119, 2917565137, 2600822924, 725511199, 528734635, 4215389547, 1541459225, 327033209 ];
            this.k = sha512_K;
            this.W = new Array(160);
        }
        utils.inherits(SHA512, BlockHash);
        module.exports = SHA512;
        SHA512.blockSize = 1024;
        SHA512.outSize = 512;
        SHA512.hmacStrength = 192;
        SHA512.padLength = 128;
        SHA512.prototype._prepareBlock = function _prepareBlock(msg, start) {
            var W = this.W;
            for (var i = 0; i < 32; i++) W[i] = msg[start + i];
            for (;i < W.length; i += 2) {
                var c0_hi = g1_512_hi(W[i - 4], W[i - 3]);
                var c0_lo = g1_512_lo(W[i - 4], W[i - 3]);
                var c1_hi = W[i - 14];
                var c1_lo = W[i - 13];
                var c2_hi = g0_512_hi(W[i - 30], W[i - 29]);
                var c2_lo = g0_512_lo(W[i - 30], W[i - 29]);
                var c3_hi = W[i - 32];
                var c3_lo = W[i - 31];
                W[i] = sum64_4_hi(c0_hi, c0_lo, c1_hi, c1_lo, c2_hi, c2_lo, c3_hi, c3_lo);
                W[i + 1] = sum64_4_lo(c0_hi, c0_lo, c1_hi, c1_lo, c2_hi, c2_lo, c3_hi, c3_lo);
            }
        };
        SHA512.prototype._update = function _update(msg, start) {
            this._prepareBlock(msg, start);
            var W = this.W;
            var ah = this.h[0];
            var al = this.h[1];
            var bh = this.h[2];
            var bl = this.h[3];
            var ch = this.h[4];
            var cl = this.h[5];
            var dh = this.h[6];
            var dl = this.h[7];
            var eh = this.h[8];
            var el = this.h[9];
            var fh = this.h[10];
            var fl = this.h[11];
            var gh = this.h[12];
            var gl = this.h[13];
            var hh = this.h[14];
            var hl = this.h[15];
            assert(this.k.length === W.length);
            for (var i = 0; i < W.length; i += 2) {
                var c0_hi = hh;
                var c0_lo = hl;
                var c1_hi = s1_512_hi(eh, el);
                var c1_lo = s1_512_lo(eh, el);
                var c2_hi = ch64_hi(eh, el, fh, fl, gh, gl);
                var c2_lo = ch64_lo(eh, el, fh, fl, gh, gl);
                var c3_hi = this.k[i];
                var c3_lo = this.k[i + 1];
                var c4_hi = W[i];
                var c4_lo = W[i + 1];
                var T1_hi = sum64_5_hi(c0_hi, c0_lo, c1_hi, c1_lo, c2_hi, c2_lo, c3_hi, c3_lo, c4_hi, c4_lo);
                var T1_lo = sum64_5_lo(c0_hi, c0_lo, c1_hi, c1_lo, c2_hi, c2_lo, c3_hi, c3_lo, c4_hi, c4_lo);
                c0_hi = s0_512_hi(ah, al);
                c0_lo = s0_512_lo(ah, al);
                c1_hi = maj64_hi(ah, al, bh, bl, ch, cl);
                c1_lo = maj64_lo(ah, al, bh, bl, ch, cl);
                var T2_hi = sum64_hi(c0_hi, c0_lo, c1_hi, c1_lo);
                var T2_lo = sum64_lo(c0_hi, c0_lo, c1_hi, c1_lo);
                hh = gh;
                hl = gl;
                gh = fh;
                gl = fl;
                fh = eh;
                fl = el;
                eh = sum64_hi(dh, dl, T1_hi, T1_lo);
                el = sum64_lo(dl, dl, T1_hi, T1_lo);
                dh = ch;
                dl = cl;
                ch = bh;
                cl = bl;
                bh = ah;
                bl = al;
                ah = sum64_hi(T1_hi, T1_lo, T2_hi, T2_lo);
                al = sum64_lo(T1_hi, T1_lo, T2_hi, T2_lo);
            }
            sum64(this.h, 0, ah, al);
            sum64(this.h, 2, bh, bl);
            sum64(this.h, 4, ch, cl);
            sum64(this.h, 6, dh, dl);
            sum64(this.h, 8, eh, el);
            sum64(this.h, 10, fh, fl);
            sum64(this.h, 12, gh, gl);
            sum64(this.h, 14, hh, hl);
        };
        SHA512.prototype._digest = function digest(enc) {
            if (enc === "hex") return utils.toHex32(this.h, "big"); else return utils.split32(this.h, "big");
        };
        function ch64_hi(xh, xl, yh, yl, zh) {
            var r = xh & yh ^ ~xh & zh;
            if (r < 0) r += 4294967296;
            return r;
        }
        function ch64_lo(xh, xl, yh, yl, zh, zl) {
            var r = xl & yl ^ ~xl & zl;
            if (r < 0) r += 4294967296;
            return r;
        }
        function maj64_hi(xh, xl, yh, yl, zh) {
            var r = xh & yh ^ xh & zh ^ yh & zh;
            if (r < 0) r += 4294967296;
            return r;
        }
        function maj64_lo(xh, xl, yh, yl, zh, zl) {
            var r = xl & yl ^ xl & zl ^ yl & zl;
            if (r < 0) r += 4294967296;
            return r;
        }
        function s0_512_hi(xh, xl) {
            var c0_hi = rotr64_hi(xh, xl, 28);
            var c1_hi = rotr64_hi(xl, xh, 2);
            var c2_hi = rotr64_hi(xl, xh, 7);
            var r = c0_hi ^ c1_hi ^ c2_hi;
            if (r < 0) r += 4294967296;
            return r;
        }
        function s0_512_lo(xh, xl) {
            var c0_lo = rotr64_lo(xh, xl, 28);
            var c1_lo = rotr64_lo(xl, xh, 2);
            var c2_lo = rotr64_lo(xl, xh, 7);
            var r = c0_lo ^ c1_lo ^ c2_lo;
            if (r < 0) r += 4294967296;
            return r;
        }
        function s1_512_hi(xh, xl) {
            var c0_hi = rotr64_hi(xh, xl, 14);
            var c1_hi = rotr64_hi(xh, xl, 18);
            var c2_hi = rotr64_hi(xl, xh, 9);
            var r = c0_hi ^ c1_hi ^ c2_hi;
            if (r < 0) r += 4294967296;
            return r;
        }
        function s1_512_lo(xh, xl) {
            var c0_lo = rotr64_lo(xh, xl, 14);
            var c1_lo = rotr64_lo(xh, xl, 18);
            var c2_lo = rotr64_lo(xl, xh, 9);
            var r = c0_lo ^ c1_lo ^ c2_lo;
            if (r < 0) r += 4294967296;
            return r;
        }
        function g0_512_hi(xh, xl) {
            var c0_hi = rotr64_hi(xh, xl, 1);
            var c1_hi = rotr64_hi(xh, xl, 8);
            var c2_hi = shr64_hi(xh, xl, 7);
            var r = c0_hi ^ c1_hi ^ c2_hi;
            if (r < 0) r += 4294967296;
            return r;
        }
        function g0_512_lo(xh, xl) {
            var c0_lo = rotr64_lo(xh, xl, 1);
            var c1_lo = rotr64_lo(xh, xl, 8);
            var c2_lo = shr64_lo(xh, xl, 7);
            var r = c0_lo ^ c1_lo ^ c2_lo;
            if (r < 0) r += 4294967296;
            return r;
        }
        function g1_512_hi(xh, xl) {
            var c0_hi = rotr64_hi(xh, xl, 19);
            var c1_hi = rotr64_hi(xl, xh, 29);
            var c2_hi = shr64_hi(xh, xl, 6);
            var r = c0_hi ^ c1_hi ^ c2_hi;
            if (r < 0) r += 4294967296;
            return r;
        }
        function g1_512_lo(xh, xl) {
            var c0_lo = rotr64_lo(xh, xl, 19);
            var c1_lo = rotr64_lo(xl, xh, 29);
            var c2_lo = shr64_lo(xh, xl, 6);
            var r = c0_lo ^ c1_lo ^ c2_lo;
            if (r < 0) r += 4294967296;
            return r;
        }
    }, {
        "../common": 107,
        "../utils": 117,
        "minimalistic-assert": 126
    } ],
    116: [ function(require, module, exports) {
        "use strict";
        var utils = require("../utils");
        var rotr32 = utils.rotr32;
        function ft_1(s, x, y, z) {
            if (s === 0) return ch32(x, y, z);
            if (s === 1 || s === 3) return p32(x, y, z);
            if (s === 2) return maj32(x, y, z);
        }
        exports.ft_1 = ft_1;
        function ch32(x, y, z) {
            return x & y ^ ~x & z;
        }
        exports.ch32 = ch32;
        function maj32(x, y, z) {
            return x & y ^ x & z ^ y & z;
        }
        exports.maj32 = maj32;
        function p32(x, y, z) {
            return x ^ y ^ z;
        }
        exports.p32 = p32;
        function s0_256(x) {
            return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
        }
        exports.s0_256 = s0_256;
        function s1_256(x) {
            return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
        }
        exports.s1_256 = s1_256;
        function g0_256(x) {
            return rotr32(x, 7) ^ rotr32(x, 18) ^ x >>> 3;
        }
        exports.g0_256 = g0_256;
        function g1_256(x) {
            return rotr32(x, 17) ^ rotr32(x, 19) ^ x >>> 10;
        }
        exports.g1_256 = g1_256;
    }, {
        "../utils": 117
    } ],
    117: [ function(require, module, exports) {
        "use strict";
        var assert = require("minimalistic-assert");
        var inherits = require("inherits");
        exports.inherits = inherits;
        function toArray(msg, enc) {
            if (Array.isArray(msg)) return msg.slice();
            if (!msg) return [];
            var res = [];
            if (typeof msg === "string") {
                if (!enc) {
                    for (var i = 0; i < msg.length; i++) {
                        var c = msg.charCodeAt(i);
                        var hi = c >> 8;
                        var lo = c & 255;
                        if (hi) res.push(hi, lo); else res.push(lo);
                    }
                } else if (enc === "hex") {
                    msg = msg.replace(/[^a-z0-9]+/gi, "");
                    if (msg.length % 2 !== 0) msg = "0" + msg;
                    for (i = 0; i < msg.length; i += 2) res.push(parseInt(msg[i] + msg[i + 1], 16));
                }
            } else {
                for (i = 0; i < msg.length; i++) res[i] = msg[i] | 0;
            }
            return res;
        }
        exports.toArray = toArray;
        function toHex(msg) {
            var res = "";
            for (var i = 0; i < msg.length; i++) res += zero2(msg[i].toString(16));
            return res;
        }
        exports.toHex = toHex;
        function htonl(w) {
            var res = w >>> 24 | w >>> 8 & 65280 | w << 8 & 16711680 | (w & 255) << 24;
            return res >>> 0;
        }
        exports.htonl = htonl;
        function toHex32(msg, endian) {
            var res = "";
            for (var i = 0; i < msg.length; i++) {
                var w = msg[i];
                if (endian === "little") w = htonl(w);
                res += zero8(w.toString(16));
            }
            return res;
        }
        exports.toHex32 = toHex32;
        function zero2(word) {
            if (word.length === 1) return "0" + word; else return word;
        }
        exports.zero2 = zero2;
        function zero8(word) {
            if (word.length === 7) return "0" + word; else if (word.length === 6) return "00" + word; else if (word.length === 5) return "000" + word; else if (word.length === 4) return "0000" + word; else if (word.length === 3) return "00000" + word; else if (word.length === 2) return "000000" + word; else if (word.length === 1) return "0000000" + word; else return word;
        }
        exports.zero8 = zero8;
        function join32(msg, start, end, endian) {
            var len = end - start;
            assert(len % 4 === 0);
            var res = new Array(len / 4);
            for (var i = 0, k = start; i < res.length; i++, k += 4) {
                var w;
                if (endian === "big") w = msg[k] << 24 | msg[k + 1] << 16 | msg[k + 2] << 8 | msg[k + 3]; else w = msg[k + 3] << 24 | msg[k + 2] << 16 | msg[k + 1] << 8 | msg[k];
                res[i] = w >>> 0;
            }
            return res;
        }
        exports.join32 = join32;
        function split32(msg, endian) {
            var res = new Array(msg.length * 4);
            for (var i = 0, k = 0; i < msg.length; i++, k += 4) {
                var m = msg[i];
                if (endian === "big") {
                    res[k] = m >>> 24;
                    res[k + 1] = m >>> 16 & 255;
                    res[k + 2] = m >>> 8 & 255;
                    res[k + 3] = m & 255;
                } else {
                    res[k + 3] = m >>> 24;
                    res[k + 2] = m >>> 16 & 255;
                    res[k + 1] = m >>> 8 & 255;
                    res[k] = m & 255;
                }
            }
            return res;
        }
        exports.split32 = split32;
        function rotr32(w, b) {
            return w >>> b | w << 32 - b;
        }
        exports.rotr32 = rotr32;
        function rotl32(w, b) {
            return w << b | w >>> 32 - b;
        }
        exports.rotl32 = rotl32;
        function sum32(a, b) {
            return a + b >>> 0;
        }
        exports.sum32 = sum32;
        function sum32_3(a, b, c) {
            return a + b + c >>> 0;
        }
        exports.sum32_3 = sum32_3;
        function sum32_4(a, b, c, d) {
            return a + b + c + d >>> 0;
        }
        exports.sum32_4 = sum32_4;
        function sum32_5(a, b, c, d, e) {
            return a + b + c + d + e >>> 0;
        }
        exports.sum32_5 = sum32_5;
        function sum64(buf, pos, ah, al) {
            var bh = buf[pos];
            var bl = buf[pos + 1];
            var lo = al + bl >>> 0;
            var hi = (lo < al ? 1 : 0) + ah + bh;
            buf[pos] = hi >>> 0;
            buf[pos + 1] = lo;
        }
        exports.sum64 = sum64;
        function sum64_hi(ah, al, bh, bl) {
            var lo = al + bl >>> 0;
            var hi = (lo < al ? 1 : 0) + ah + bh;
            return hi >>> 0;
        }
        exports.sum64_hi = sum64_hi;
        function sum64_lo(ah, al, bh, bl) {
            var lo = al + bl;
            return lo >>> 0;
        }
        exports.sum64_lo = sum64_lo;
        function sum64_4_hi(ah, al, bh, bl, ch, cl, dh, dl) {
            var carry = 0;
            var lo = al;
            lo = lo + bl >>> 0;
            carry += lo < al ? 1 : 0;
            lo = lo + cl >>> 0;
            carry += lo < cl ? 1 : 0;
            lo = lo + dl >>> 0;
            carry += lo < dl ? 1 : 0;
            var hi = ah + bh + ch + dh + carry;
            return hi >>> 0;
        }
        exports.sum64_4_hi = sum64_4_hi;
        function sum64_4_lo(ah, al, bh, bl, ch, cl, dh, dl) {
            var lo = al + bl + cl + dl;
            return lo >>> 0;
        }
        exports.sum64_4_lo = sum64_4_lo;
        function sum64_5_hi(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
            var carry = 0;
            var lo = al;
            lo = lo + bl >>> 0;
            carry += lo < al ? 1 : 0;
            lo = lo + cl >>> 0;
            carry += lo < cl ? 1 : 0;
            lo = lo + dl >>> 0;
            carry += lo < dl ? 1 : 0;
            lo = lo + el >>> 0;
            carry += lo < el ? 1 : 0;
            var hi = ah + bh + ch + dh + eh + carry;
            return hi >>> 0;
        }
        exports.sum64_5_hi = sum64_5_hi;
        function sum64_5_lo(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
            var lo = al + bl + cl + dl + el;
            return lo >>> 0;
        }
        exports.sum64_5_lo = sum64_5_lo;
        function rotr64_hi(ah, al, num) {
            var r = al << 32 - num | ah >>> num;
            return r >>> 0;
        }
        exports.rotr64_hi = rotr64_hi;
        function rotr64_lo(ah, al, num) {
            var r = ah << 32 - num | al >>> num;
            return r >>> 0;
        }
        exports.rotr64_lo = rotr64_lo;
        function shr64_hi(ah, al, num) {
            return ah >>> num;
        }
        exports.shr64_hi = shr64_hi;
        function shr64_lo(ah, al, num) {
            var r = ah << 32 - num | al >>> num;
            return r >>> 0;
        }
        exports.shr64_lo = shr64_lo;
    }, {
        inherits: 118,
        "minimalistic-assert": 126
    } ],
    118: [ function(require, module, exports) {
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
    119: [ function(require, module, exports) {
        "use strict";
        var hash = require("hash.js");
        var utils = require("minimalistic-crypto-utils");
        var assert = require("minimalistic-assert");
        function HmacDRBG(options) {
            if (!(this instanceof HmacDRBG)) return new HmacDRBG(options);
            this.hash = options.hash;
            this.predResist = !!options.predResist;
            this.outLen = this.hash.outSize;
            this.minEntropy = options.minEntropy || this.hash.hmacStrength;
            this._reseed = null;
            this.reseedInterval = null;
            this.K = null;
            this.V = null;
            var entropy = utils.toArray(options.entropy, options.entropyEnc || "hex");
            var nonce = utils.toArray(options.nonce, options.nonceEnc || "hex");
            var pers = utils.toArray(options.pers, options.persEnc || "hex");
            assert(entropy.length >= this.minEntropy / 8, "Not enough entropy. Minimum is: " + this.minEntropy + " bits");
            this._init(entropy, nonce, pers);
        }
        module.exports = HmacDRBG;
        HmacDRBG.prototype._init = function init(entropy, nonce, pers) {
            var seed = entropy.concat(nonce).concat(pers);
            this.K = new Array(this.outLen / 8);
            this.V = new Array(this.outLen / 8);
            for (var i = 0; i < this.V.length; i++) {
                this.K[i] = 0;
                this.V[i] = 1;
            }
            this._update(seed);
            this._reseed = 1;
            this.reseedInterval = 281474976710656;
        };
        HmacDRBG.prototype._hmac = function hmac() {
            return new hash.hmac(this.hash, this.K);
        };
        HmacDRBG.prototype._update = function update(seed) {
            var kmac = this._hmac().update(this.V).update([ 0 ]);
            if (seed) kmac = kmac.update(seed);
            this.K = kmac.digest();
            this.V = this._hmac().update(this.V).digest();
            if (!seed) return;
            this.K = this._hmac().update(this.V).update([ 1 ]).update(seed).digest();
            this.V = this._hmac().update(this.V).digest();
        };
        HmacDRBG.prototype.reseed = function reseed(entropy, entropyEnc, add, addEnc) {
            if (typeof entropyEnc !== "string") {
                addEnc = add;
                add = entropyEnc;
                entropyEnc = null;
            }
            entropy = utils.toArray(entropy, entropyEnc);
            add = utils.toArray(add, addEnc);
            assert(entropy.length >= this.minEntropy / 8, "Not enough entropy. Minimum is: " + this.minEntropy + " bits");
            this._update(entropy.concat(add || []));
            this._reseed = 1;
        };
        HmacDRBG.prototype.generate = function generate(len, enc, add, addEnc) {
            if (this._reseed > this.reseedInterval) throw new Error("Reseed is required");
            if (typeof enc !== "string") {
                addEnc = add;
                add = enc;
                enc = null;
            }
            if (add) {
                add = utils.toArray(add, addEnc || "hex");
                this._update(add);
            }
            var temp = [];
            while (temp.length < len) {
                this.V = this._hmac().update(this.V).digest();
                temp = temp.concat(this.V);
            }
            var res = temp.slice(0, len);
            this._update(add);
            this._reseed++;
            return utils.encode(res, enc);
        };
    }, {
        "hash.js": 106,
        "minimalistic-assert": 126,
        "minimalistic-crypto-utils": 127
    } ],
    120: [ function(require, module, exports) {
        exports.read = function(buffer, offset, isLE, mLen, nBytes) {
            var e, m;
            var eLen = nBytes * 8 - mLen - 1;
            var eMax = (1 << eLen) - 1;
            var eBias = eMax >> 1;
            var nBits = -7;
            var i = isLE ? nBytes - 1 : 0;
            var d = isLE ? -1 : 1;
            var s = buffer[offset + i];
            i += d;
            e = s & (1 << -nBits) - 1;
            s >>= -nBits;
            nBits += eLen;
            for (;nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}
            m = e & (1 << -nBits) - 1;
            e >>= -nBits;
            nBits += mLen;
            for (;nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}
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
            var e, m, c;
            var eLen = nBytes * 8 - mLen - 1;
            var eMax = (1 << eLen) - 1;
            var eBias = eMax >> 1;
            var rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0;
            var i = isLE ? 0 : nBytes - 1;
            var d = isLE ? 1 : -1;
            var s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
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
            for (;mLen >= 8; buffer[offset + i] = m & 255, i += d, m /= 256, mLen -= 8) {}
            e = e << mLen | m;
            eLen += mLen;
            for (;eLen > 0; buffer[offset + i] = e & 255, i += d, e /= 256, eLen -= 8) {}
            buffer[offset + i - d] |= s * 128;
        };
    }, {} ],
    121: [ function(require, module, exports) {
        var indexOf = [].indexOf;
        module.exports = function(arr, obj) {
            if (indexOf) return arr.indexOf(obj);
            for (var i = 0; i < arr.length; ++i) {
                if (arr[i] === obj) return i;
            }
            return -1;
        };
    }, {} ],
    122: [ function(require, module, exports) {
        arguments[4][118][0].apply(exports, arguments);
    }, {
        dup: 118
    } ],
    123: [ function(require, module, exports) {
        module.exports = function(obj) {
            return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer);
        };
        function isBuffer(obj) {
            return !!obj.constructor && typeof obj.constructor.isBuffer === "function" && obj.constructor.isBuffer(obj);
        }
        function isSlowBuffer(obj) {
            return typeof obj.readFloatLE === "function" && typeof obj.slice === "function" && isBuffer(obj.slice(0, 0));
        }
    }, {} ],
    124: [ function(require, module, exports) {
        var toString = {}.toString;
        module.exports = Array.isArray || function(arr) {
            return toString.call(arr) == "[object Array]";
        };
    }, {} ],
    125: [ function(require, module, exports) {
        var bn = require("bn.js");
        var brorand = require("brorand");
        function MillerRabin(rand) {
            this.rand = rand || new brorand.Rand();
        }
        module.exports = MillerRabin;
        MillerRabin.create = function create(rand) {
            return new MillerRabin(rand);
        };
        MillerRabin.prototype._rand = function _rand(n) {
            var len = n.bitLength();
            var buf = this.rand.generate(Math.ceil(len / 8));
            buf[0] |= 3;
            var mask = len & 7;
            if (mask !== 0) buf[buf.length - 1] >>= 7 - mask;
            return new bn(buf);
        };
        MillerRabin.prototype.test = function test(n, k, cb) {
            var len = n.bitLength();
            var red = bn.mont(n);
            var rone = new bn(1).toRed(red);
            if (!k) k = Math.max(1, len / 48 | 0);
            var n1 = n.subn(1);
            var n2 = n1.subn(1);
            for (var s = 0; !n1.testn(s); s++) {}
            var d = n.shrn(s);
            var rn1 = n1.toRed(red);
            var prime = true;
            for (;k > 0; k--) {
                var a = this._rand(n2);
                if (cb) cb(a);
                var x = a.toRed(red).redPow(d);
                if (x.cmp(rone) === 0 || x.cmp(rn1) === 0) continue;
                for (var i = 1; i < s; i++) {
                    x = x.redSqr();
                    if (x.cmp(rone) === 0) return false;
                    if (x.cmp(rn1) === 0) break;
                }
                if (i === s) return false;
            }
            return prime;
        };
        MillerRabin.prototype.getDivisor = function getDivisor(n, k) {
            var len = n.bitLength();
            var red = bn.mont(n);
            var rone = new bn(1).toRed(red);
            if (!k) k = Math.max(1, len / 48 | 0);
            var n1 = n.subn(1);
            var n2 = n1.subn(1);
            for (var s = 0; !n1.testn(s); s++) {}
            var d = n.shrn(s);
            var rn1 = n1.toRed(red);
            for (;k > 0; k--) {
                var a = this._rand(n2);
                var g = n.gcd(a);
                if (g.cmpn(1) !== 0) return g;
                var x = a.toRed(red).redPow(d);
                if (x.cmp(rone) === 0 || x.cmp(rn1) === 0) continue;
                for (var i = 1; i < s; i++) {
                    x = x.redSqr();
                    if (x.cmp(rone) === 0) return x.fromRed().subn(1).gcd(n);
                    if (x.cmp(rn1) === 0) break;
                }
                if (i === s) {
                    x = x.redSqr();
                    return x.fromRed().subn(1).gcd(n);
                }
            }
            return false;
        };
    }, {
        "bn.js": 23,
        brorand: 24
    } ],
    126: [ function(require, module, exports) {
        module.exports = assert;
        function assert(val, msg) {
            if (!val) throw new Error(msg || "Assertion failed");
        }
        assert.equal = function assertEqual(l, r, msg) {
            if (l != r) throw new Error(msg || "Assertion failed: " + l + " != " + r);
        };
    }, {} ],
    127: [ function(require, module, exports) {
        "use strict";
        var utils = exports;
        function toArray(msg, enc) {
            if (Array.isArray(msg)) return msg.slice();
            if (!msg) return [];
            var res = [];
            if (typeof msg !== "string") {
                for (var i = 0; i < msg.length; i++) res[i] = msg[i] | 0;
                return res;
            }
            if (enc === "hex") {
                msg = msg.replace(/[^a-z0-9]+/gi, "");
                if (msg.length % 2 !== 0) msg = "0" + msg;
                for (var i = 0; i < msg.length; i += 2) res.push(parseInt(msg[i] + msg[i + 1], 16));
            } else {
                for (var i = 0; i < msg.length; i++) {
                    var c = msg.charCodeAt(i);
                    var hi = c >> 8;
                    var lo = c & 255;
                    if (hi) res.push(hi, lo); else res.push(lo);
                }
            }
            return res;
        }
        utils.toArray = toArray;
        function zero2(word) {
            if (word.length === 1) return "0" + word; else return word;
        }
        utils.zero2 = zero2;
        function toHex(msg) {
            var res = "";
            for (var i = 0; i < msg.length; i++) res += zero2(msg[i].toString(16));
            return res;
        }
        utils.toHex = toHex;
        utils.encode = function encode(arr, enc) {
            if (enc === "hex") return toHex(arr); else return arr;
        };
    }, {} ],
    128: [ function(require, module, exports) {
        module.exports = {
            "2.16.840.1.101.3.4.1.1": "aes-128-ecb",
            "2.16.840.1.101.3.4.1.2": "aes-128-cbc",
            "2.16.840.1.101.3.4.1.3": "aes-128-ofb",
            "2.16.840.1.101.3.4.1.4": "aes-128-cfb",
            "2.16.840.1.101.3.4.1.21": "aes-192-ecb",
            "2.16.840.1.101.3.4.1.22": "aes-192-cbc",
            "2.16.840.1.101.3.4.1.23": "aes-192-ofb",
            "2.16.840.1.101.3.4.1.24": "aes-192-cfb",
            "2.16.840.1.101.3.4.1.41": "aes-256-ecb",
            "2.16.840.1.101.3.4.1.42": "aes-256-cbc",
            "2.16.840.1.101.3.4.1.43": "aes-256-ofb",
            "2.16.840.1.101.3.4.1.44": "aes-256-cfb"
        };
    }, {} ],
    129: [ function(require, module, exports) {
        "use strict";
        var asn1 = require("asn1.js");
        exports.certificate = require("./certificate");
        var RSAPrivateKey = asn1.define("RSAPrivateKey", function() {
            this.seq().obj(this.key("version").int(), this.key("modulus").int(), this.key("publicExponent").int(), this.key("privateExponent").int(), this.key("prime1").int(), this.key("prime2").int(), this.key("exponent1").int(), this.key("exponent2").int(), this.key("coefficient").int());
        });
        exports.RSAPrivateKey = RSAPrivateKey;
        var RSAPublicKey = asn1.define("RSAPublicKey", function() {
            this.seq().obj(this.key("modulus").int(), this.key("publicExponent").int());
        });
        exports.RSAPublicKey = RSAPublicKey;
        var PublicKey = asn1.define("SubjectPublicKeyInfo", function() {
            this.seq().obj(this.key("algorithm").use(AlgorithmIdentifier), this.key("subjectPublicKey").bitstr());
        });
        exports.PublicKey = PublicKey;
        var AlgorithmIdentifier = asn1.define("AlgorithmIdentifier", function() {
            this.seq().obj(this.key("algorithm").objid(), this.key("none").null_().optional(), this.key("curve").objid().optional(), this.key("params").seq().obj(this.key("p").int(), this.key("q").int(), this.key("g").int()).optional());
        });
        var PrivateKeyInfo = asn1.define("PrivateKeyInfo", function() {
            this.seq().obj(this.key("version").int(), this.key("algorithm").use(AlgorithmIdentifier), this.key("subjectPrivateKey").octstr());
        });
        exports.PrivateKey = PrivateKeyInfo;
        var EncryptedPrivateKeyInfo = asn1.define("EncryptedPrivateKeyInfo", function() {
            this.seq().obj(this.key("algorithm").seq().obj(this.key("id").objid(), this.key("decrypt").seq().obj(this.key("kde").seq().obj(this.key("id").objid(), this.key("kdeparams").seq().obj(this.key("salt").octstr(), this.key("iters").int())), this.key("cipher").seq().obj(this.key("algo").objid(), this.key("iv").octstr()))), this.key("subjectPrivateKey").octstr());
        });
        exports.EncryptedPrivateKey = EncryptedPrivateKeyInfo;
        var DSAPrivateKey = asn1.define("DSAPrivateKey", function() {
            this.seq().obj(this.key("version").int(), this.key("p").int(), this.key("q").int(), this.key("g").int(), this.key("pub_key").int(), this.key("priv_key").int());
        });
        exports.DSAPrivateKey = DSAPrivateKey;
        exports.DSAparam = asn1.define("DSAparam", function() {
            this.int();
        });
        var ECPrivateKey = asn1.define("ECPrivateKey", function() {
            this.seq().obj(this.key("version").int(), this.key("privateKey").octstr(), this.key("parameters").optional().explicit(0).use(ECParameters), this.key("publicKey").optional().explicit(1).bitstr());
        });
        exports.ECPrivateKey = ECPrivateKey;
        var ECParameters = asn1.define("ECParameters", function() {
            this.choice({
                namedCurve: this.objid()
            });
        });
        exports.signature = asn1.define("signature", function() {
            this.seq().obj(this.key("r").int(), this.key("s").int());
        });
    }, {
        "./certificate": 130,
        "asn1.js": 2
    } ],
    130: [ function(require, module, exports) {
        "use strict";
        var asn = require("asn1.js");
        var Time = asn.define("Time", function() {
            this.choice({
                utcTime: this.utctime(),
                generalTime: this.gentime()
            });
        });
        var AttributeTypeValue = asn.define("AttributeTypeValue", function() {
            this.seq().obj(this.key("type").objid(), this.key("value").any());
        });
        var AlgorithmIdentifier = asn.define("AlgorithmIdentifier", function() {
            this.seq().obj(this.key("algorithm").objid(), this.key("parameters").optional());
        });
        var SubjectPublicKeyInfo = asn.define("SubjectPublicKeyInfo", function() {
            this.seq().obj(this.key("algorithm").use(AlgorithmIdentifier), this.key("subjectPublicKey").bitstr());
        });
        var RelativeDistinguishedName = asn.define("RelativeDistinguishedName", function() {
            this.setof(AttributeTypeValue);
        });
        var RDNSequence = asn.define("RDNSequence", function() {
            this.seqof(RelativeDistinguishedName);
        });
        var Name = asn.define("Name", function() {
            this.choice({
                rdnSequence: this.use(RDNSequence)
            });
        });
        var Validity = asn.define("Validity", function() {
            this.seq().obj(this.key("notBefore").use(Time), this.key("notAfter").use(Time));
        });
        var Extension = asn.define("Extension", function() {
            this.seq().obj(this.key("extnID").objid(), this.key("critical").bool().def(false), this.key("extnValue").octstr());
        });
        var TBSCertificate = asn.define("TBSCertificate", function() {
            this.seq().obj(this.key("version").explicit(0).int(), this.key("serialNumber").int(), this.key("signature").use(AlgorithmIdentifier), this.key("issuer").use(Name), this.key("validity").use(Validity), this.key("subject").use(Name), this.key("subjectPublicKeyInfo").use(SubjectPublicKeyInfo), this.key("issuerUniqueID").implicit(1).bitstr().optional(), this.key("subjectUniqueID").implicit(2).bitstr().optional(), this.key("extensions").explicit(3).seqof(Extension).optional());
        });
        var X509Certificate = asn.define("X509Certificate", function() {
            this.seq().obj(this.key("tbsCertificate").use(TBSCertificate), this.key("signatureAlgorithm").use(AlgorithmIdentifier), this.key("signatureValue").bitstr());
        });
        module.exports = X509Certificate;
    }, {
        "asn1.js": 2
    } ],
    131: [ function(require, module, exports) {
        (function(Buffer) {
            var findProc = /Proc-Type: 4,ENCRYPTED\n\r?DEK-Info: AES-((?:128)|(?:192)|(?:256))-CBC,([0-9A-H]+)\n\r?\n\r?([0-9A-z\n\r\+\/\=]+)\n\r?/m;
            var startRegex = /^-----BEGIN ((?:.* KEY)|CERTIFICATE)-----\n/m;
            var fullRegex = /^-----BEGIN ((?:.* KEY)|CERTIFICATE)-----\n\r?([0-9A-z\n\r\+\/\=]+)\n\r?-----END \1-----$/m;
            var evp = require("evp_bytestokey");
            var ciphers = require("browserify-aes");
            module.exports = function(okey, password) {
                var key = okey.toString();
                var match = key.match(findProc);
                var decrypted;
                if (!match) {
                    var match2 = key.match(fullRegex);
                    decrypted = new Buffer(match2[2].replace(/\r?\n/g, ""), "base64");
                } else {
                    var suite = "aes" + match[1];
                    var iv = new Buffer(match[2], "hex");
                    var cipherText = new Buffer(match[3].replace(/\r?\n/g, ""), "base64");
                    var cipherKey = evp(password, iv.slice(0, 8), parseInt(match[1], 10)).key;
                    var out = [];
                    var cipher = ciphers.createDecipheriv(suite, cipherKey, iv);
                    out.push(cipher.update(cipherText));
                    out.push(cipher.final());
                    decrypted = Buffer.concat(out);
                }
                var tag = key.match(startRegex)[1];
                return {
                    tag: tag,
                    data: decrypted
                };
            };
        }).call(this, require("buffer").Buffer);
    }, {
        "browserify-aes": 28,
        buffer: 54,
        evp_bytestokey: 104
    } ],
    132: [ function(require, module, exports) {
        (function(Buffer) {
            var asn1 = require("./asn1");
            var aesid = require("./aesid.json");
            var fixProc = require("./fixProc");
            var ciphers = require("browserify-aes");
            var compat = require("pbkdf2");
            module.exports = parseKeys;
            function parseKeys(buffer) {
                var password;
                if (typeof buffer === "object" && !Buffer.isBuffer(buffer)) {
                    password = buffer.passphrase;
                    buffer = buffer.key;
                }
                if (typeof buffer === "string") {
                    buffer = new Buffer(buffer);
                }
                var stripped = fixProc(buffer, password);
                var type = stripped.tag;
                var data = stripped.data;
                var subtype, ndata;
                switch (type) {
                  case "CERTIFICATE":
                    ndata = asn1.certificate.decode(data, "der").tbsCertificate.subjectPublicKeyInfo;

                  case "PUBLIC KEY":
                    if (!ndata) {
                        ndata = asn1.PublicKey.decode(data, "der");
                    }
                    subtype = ndata.algorithm.algorithm.join(".");
                    switch (subtype) {
                      case "1.2.840.113549.1.1.1":
                        return asn1.RSAPublicKey.decode(ndata.subjectPublicKey.data, "der");

                      case "1.2.840.10045.2.1":
                        ndata.subjectPrivateKey = ndata.subjectPublicKey;
                        return {
                            type: "ec",
                            data: ndata
                        };

                      case "1.2.840.10040.4.1":
                        ndata.algorithm.params.pub_key = asn1.DSAparam.decode(ndata.subjectPublicKey.data, "der");
                        return {
                            type: "dsa",
                            data: ndata.algorithm.params
                        };

                      default:
                        throw new Error("unknown key id " + subtype);
                    }
                    throw new Error("unknown key type " + type);

                  case "ENCRYPTED PRIVATE KEY":
                    data = asn1.EncryptedPrivateKey.decode(data, "der");
                    data = decrypt(data, password);

                  case "PRIVATE KEY":
                    ndata = asn1.PrivateKey.decode(data, "der");
                    subtype = ndata.algorithm.algorithm.join(".");
                    switch (subtype) {
                      case "1.2.840.113549.1.1.1":
                        return asn1.RSAPrivateKey.decode(ndata.subjectPrivateKey, "der");

                      case "1.2.840.10045.2.1":
                        return {
                            curve: ndata.algorithm.curve,
                            privateKey: asn1.ECPrivateKey.decode(ndata.subjectPrivateKey, "der").privateKey
                        };

                      case "1.2.840.10040.4.1":
                        ndata.algorithm.params.priv_key = asn1.DSAparam.decode(ndata.subjectPrivateKey, "der");
                        return {
                            type: "dsa",
                            params: ndata.algorithm.params
                        };

                      default:
                        throw new Error("unknown key id " + subtype);
                    }
                    throw new Error("unknown key type " + type);

                  case "RSA PUBLIC KEY":
                    return asn1.RSAPublicKey.decode(data, "der");

                  case "RSA PRIVATE KEY":
                    return asn1.RSAPrivateKey.decode(data, "der");

                  case "DSA PRIVATE KEY":
                    return {
                        type: "dsa",
                        params: asn1.DSAPrivateKey.decode(data, "der")
                    };

                  case "EC PRIVATE KEY":
                    data = asn1.ECPrivateKey.decode(data, "der");
                    return {
                        curve: data.parameters.value,
                        privateKey: data.privateKey
                    };

                  default:
                    throw new Error("unknown key type " + type);
                }
            }
            parseKeys.signature = asn1.signature;
            function decrypt(data, password) {
                var salt = data.algorithm.decrypt.kde.kdeparams.salt;
                var iters = parseInt(data.algorithm.decrypt.kde.kdeparams.iters.toString(), 10);
                var algo = aesid[data.algorithm.decrypt.cipher.algo.join(".")];
                var iv = data.algorithm.decrypt.cipher.iv;
                var cipherText = data.subjectPrivateKey;
                var keylen = parseInt(algo.split("-")[1], 10) / 8;
                var key = compat.pbkdf2Sync(password, salt, iters, keylen);
                var cipher = ciphers.createDecipheriv(algo, key, iv);
                var out = [];
                out.push(cipher.update(cipherText));
                out.push(cipher.final());
                return Buffer.concat(out);
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "./aesid.json": 128,
        "./asn1": 129,
        "./fixProc": 131,
        "browserify-aes": 28,
        buffer: 54,
        pbkdf2: 134
    } ],
    133: [ function(require, module, exports) {
        (function(Buffer) {
            var assert = require("assert");
            var crypto = require("crypto");
            function pbkdf2(key, salt, iterations, dkLen) {
                var hLen = 32;
                assert(dkLen <= (Math.pow(2, 32) - 1) * hLen, "requested key length too long");
                assert(typeof key == "string" || Buffer.isBuffer(key), "key must be a string or buffer");
                assert(typeof salt == "string" || Buffer.isBuffer(salt), "key must be a string or buffer");
                if (typeof key == "string") key = new Buffer(key);
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
        assert: 16,
        buffer: 54,
        crypto: 66
    } ],
    134: [ function(require, module, exports) {
        exports.pbkdf2 = require("./lib/async");
        exports.pbkdf2Sync = require("./lib/sync");
    }, {
        "./lib/async": 135,
        "./lib/sync": 138
    } ],
    135: [ function(require, module, exports) {
        (function(process, global) {
            var checkParameters = require("./precondition");
            var defaultEncoding = require("./default-encoding");
            var sync = require("./sync");
            var Buffer = require("safe-buffer").Buffer;
            var ZERO_BUF;
            var subtle = global.crypto && global.crypto.subtle;
            var toBrowser = {
                sha: "SHA-1",
                "sha-1": "SHA-1",
                sha1: "SHA-1",
                sha256: "SHA-256",
                "sha-256": "SHA-256",
                sha384: "SHA-384",
                "sha-384": "SHA-384",
                "sha-512": "SHA-512",
                sha512: "SHA-512"
            };
            var checks = [];
            function checkNative(algo) {
                if (global.process && !global.process.browser) {
                    return Promise.resolve(false);
                }
                if (!subtle || !subtle.importKey || !subtle.deriveBits) {
                    return Promise.resolve(false);
                }
                if (checks[algo] !== undefined) {
                    return checks[algo];
                }
                ZERO_BUF = ZERO_BUF || Buffer.alloc(8);
                var prom = browserPbkdf2(ZERO_BUF, ZERO_BUF, 10, 128, algo).then(function() {
                    return true;
                }).catch(function() {
                    return false;
                });
                checks[algo] = prom;
                return prom;
            }
            function browserPbkdf2(password, salt, iterations, length, algo) {
                return subtle.importKey("raw", password, {
                    name: "PBKDF2"
                }, false, [ "deriveBits" ]).then(function(key) {
                    return subtle.deriveBits({
                        name: "PBKDF2",
                        salt: salt,
                        iterations: iterations,
                        hash: {
                            name: algo
                        }
                    }, key, length << 3);
                }).then(function(res) {
                    return Buffer.from(res);
                });
            }
            function resolvePromise(promise, callback) {
                promise.then(function(out) {
                    process.nextTick(function() {
                        callback(null, out);
                    });
                }, function(e) {
                    process.nextTick(function() {
                        callback(e);
                    });
                });
            }
            module.exports = function(password, salt, iterations, keylen, digest, callback) {
                if (!Buffer.isBuffer(password)) password = Buffer.from(password, defaultEncoding);
                if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt, defaultEncoding);
                checkParameters(iterations, keylen);
                if (typeof digest === "function") {
                    callback = digest;
                    digest = undefined;
                }
                if (typeof callback !== "function") throw new Error("No callback provided to pbkdf2");
                digest = digest || "sha1";
                var algo = toBrowser[digest.toLowerCase()];
                if (!algo || typeof global.Promise !== "function") {
                    return process.nextTick(function() {
                        var out;
                        try {
                            out = sync(password, salt, iterations, keylen, digest);
                        } catch (e) {
                            return callback(e);
                        }
                        callback(null, out);
                    });
                }
                resolvePromise(checkNative(algo).then(function(resp) {
                    if (resp) {
                        return browserPbkdf2(password, salt, iterations, keylen, algo);
                    } else {
                        return sync(password, salt, iterations, keylen, digest);
                    }
                }), callback);
            };
        }).call(this, require("_process"), typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {
        "./default-encoding": 136,
        "./precondition": 137,
        "./sync": 138,
        _process: 140,
        "safe-buffer": 163
    } ],
    136: [ function(require, module, exports) {
        (function(process) {
            var defaultEncoding;
            if (process.browser) {
                defaultEncoding = "utf-8";
            } else {
                var pVersionMajor = parseInt(process.version.split(".")[0].slice(1), 10);
                defaultEncoding = pVersionMajor >= 6 ? "utf-8" : "binary";
            }
            module.exports = defaultEncoding;
        }).call(this, require("_process"));
    }, {
        _process: 140
    } ],
    137: [ function(require, module, exports) {
        var MAX_ALLOC = Math.pow(2, 30) - 1;
        module.exports = function(iterations, keylen) {
            if (typeof iterations !== "number") {
                throw new TypeError("Iterations not a number");
            }
            if (iterations < 0) {
                throw new TypeError("Bad iterations");
            }
            if (typeof keylen !== "number") {
                throw new TypeError("Key length not a number");
            }
            if (keylen < 0 || keylen > MAX_ALLOC || keylen !== keylen) {
                throw new TypeError("Bad key length");
            }
        };
    }, {} ],
    138: [ function(require, module, exports) {
        var md5 = require("create-hash/md5");
        var rmd160 = require("ripemd160");
        var sha = require("sha.js");
        var checkParameters = require("./precondition");
        var defaultEncoding = require("./default-encoding");
        var Buffer = require("safe-buffer").Buffer;
        var ZEROS = Buffer.alloc(128);
        var sizes = {
            md5: 16,
            sha1: 20,
            sha224: 28,
            sha256: 32,
            sha384: 48,
            sha512: 64,
            rmd160: 20,
            ripemd160: 20
        };
        function Hmac(alg, key, saltLen) {
            var hash = getDigest(alg);
            var blocksize = alg === "sha512" || alg === "sha384" ? 128 : 64;
            if (key.length > blocksize) {
                key = hash(key);
            } else if (key.length < blocksize) {
                key = Buffer.concat([ key, ZEROS ], blocksize);
            }
            var ipad = Buffer.allocUnsafe(blocksize + sizes[alg]);
            var opad = Buffer.allocUnsafe(blocksize + sizes[alg]);
            for (var i = 0; i < blocksize; i++) {
                ipad[i] = key[i] ^ 54;
                opad[i] = key[i] ^ 92;
            }
            var ipad1 = Buffer.allocUnsafe(blocksize + saltLen + 4);
            ipad.copy(ipad1, 0, 0, blocksize);
            this.ipad1 = ipad1;
            this.ipad2 = ipad;
            this.opad = opad;
            this.alg = alg;
            this.blocksize = blocksize;
            this.hash = hash;
            this.size = sizes[alg];
        }
        Hmac.prototype.run = function(data, ipad) {
            data.copy(ipad, this.blocksize);
            var h = this.hash(ipad);
            h.copy(this.opad, this.blocksize);
            return this.hash(this.opad);
        };
        function getDigest(alg) {
            function shaFunc(data) {
                return sha(alg).update(data).digest();
            }
            if (alg === "rmd160" || alg === "ripemd160") return rmd160;
            if (alg === "md5") return md5;
            return shaFunc;
        }
        function pbkdf2(password, salt, iterations, keylen, digest) {
            if (!Buffer.isBuffer(password)) password = Buffer.from(password, defaultEncoding);
            if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt, defaultEncoding);
            checkParameters(iterations, keylen);
            digest = digest || "sha1";
            var hmac = new Hmac(digest, password, salt.length);
            var DK = Buffer.allocUnsafe(keylen);
            var block1 = Buffer.allocUnsafe(salt.length + 4);
            salt.copy(block1, 0, 0, salt.length);
            var destPos = 0;
            var hLen = sizes[digest];
            var l = Math.ceil(keylen / hLen);
            for (var i = 1; i <= l; i++) {
                block1.writeUInt32BE(i, salt.length);
                var T = hmac.run(block1, hmac.ipad1);
                var U = T;
                for (var j = 1; j < iterations; j++) {
                    U = hmac.run(U, hmac.ipad2);
                    for (var k = 0; k < hLen; k++) T[k] ^= U[k];
                }
                T.copy(DK, destPos);
                destPos += hLen;
            }
            return DK;
        }
        module.exports = pbkdf2;
    }, {
        "./default-encoding": 136,
        "./precondition": 137,
        "create-hash/md5": 63,
        ripemd160: 162,
        "safe-buffer": 163,
        "sha.js": 172
    } ],
    139: [ function(require, module, exports) {
        (function(process) {
            "use strict";
            if (!process.version || process.version.indexOf("v0.") === 0 || process.version.indexOf("v1.") === 0 && process.version.indexOf("v1.8.") !== 0) {
                module.exports = nextTick;
            } else {
                module.exports = process.nextTick;
            }
            function nextTick(fn, arg1, arg2, arg3) {
                if (typeof fn !== "function") {
                    throw new TypeError('"callback" argument must be a function');
                }
                var len = arguments.length;
                var args, i;
                switch (len) {
                  case 0:
                  case 1:
                    return process.nextTick(fn);

                  case 2:
                    return process.nextTick(function afterTickOne() {
                        fn.call(null, arg1);
                    });

                  case 3:
                    return process.nextTick(function afterTickTwo() {
                        fn.call(null, arg1, arg2);
                    });

                  case 4:
                    return process.nextTick(function afterTickThree() {
                        fn.call(null, arg1, arg2, arg3);
                    });

                  default:
                    args = new Array(len - 1);
                    i = 0;
                    while (i < args.length) {
                        args[i++] = arguments[i];
                    }
                    return process.nextTick(function afterTick() {
                        fn.apply(null, args);
                    });
                }
            }
        }).call(this, require("_process"));
    }, {
        _process: 140
    } ],
    140: [ function(require, module, exports) {
        var process = module.exports = {};
        var cachedSetTimeout;
        var cachedClearTimeout;
        function defaultSetTimout() {
            throw new Error("setTimeout has not been defined");
        }
        function defaultClearTimeout() {
            throw new Error("clearTimeout has not been defined");
        }
        (function() {
            try {
                if (typeof setTimeout === "function") {
                    cachedSetTimeout = setTimeout;
                } else {
                    cachedSetTimeout = defaultSetTimout;
                }
            } catch (e) {
                cachedSetTimeout = defaultSetTimout;
            }
            try {
                if (typeof clearTimeout === "function") {
                    cachedClearTimeout = clearTimeout;
                } else {
                    cachedClearTimeout = defaultClearTimeout;
                }
            } catch (e) {
                cachedClearTimeout = defaultClearTimeout;
            }
        })();
        function runTimeout(fun) {
            if (cachedSetTimeout === setTimeout) {
                return setTimeout(fun, 0);
            }
            if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
                cachedSetTimeout = setTimeout;
                return setTimeout(fun, 0);
            }
            try {
                return cachedSetTimeout(fun, 0);
            } catch (e) {
                try {
                    return cachedSetTimeout.call(null, fun, 0);
                } catch (e) {
                    return cachedSetTimeout.call(this, fun, 0);
                }
            }
        }
        function runClearTimeout(marker) {
            if (cachedClearTimeout === clearTimeout) {
                return clearTimeout(marker);
            }
            if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
                cachedClearTimeout = clearTimeout;
                return clearTimeout(marker);
            }
            try {
                return cachedClearTimeout(marker);
            } catch (e) {
                try {
                    return cachedClearTimeout.call(null, marker);
                } catch (e) {
                    return cachedClearTimeout.call(this, marker);
                }
            }
        }
        var queue = [];
        var draining = false;
        var currentQueue;
        var queueIndex = -1;
        function cleanUpNextTick() {
            if (!draining || !currentQueue) {
                return;
            }
            draining = false;
            if (currentQueue.length) {
                queue = currentQueue.concat(queue);
            } else {
                queueIndex = -1;
            }
            if (queue.length) {
                drainQueue();
            }
        }
        function drainQueue() {
            if (draining) {
                return;
            }
            var timeout = runTimeout(cleanUpNextTick);
            draining = true;
            var len = queue.length;
            while (len) {
                currentQueue = queue;
                queue = [];
                while (++queueIndex < len) {
                    if (currentQueue) {
                        currentQueue[queueIndex].run();
                    }
                }
                queueIndex = -1;
                len = queue.length;
            }
            currentQueue = null;
            draining = false;
            runClearTimeout(timeout);
        }
        process.nextTick = function(fun) {
            var args = new Array(arguments.length - 1);
            if (arguments.length > 1) {
                for (var i = 1; i < arguments.length; i++) {
                    args[i - 1] = arguments[i];
                }
            }
            queue.push(new Item(fun, args));
            if (queue.length === 1 && !draining) {
                runTimeout(drainQueue);
            }
        };
        function Item(fun, array) {
            this.fun = fun;
            this.array = array;
        }
        Item.prototype.run = function() {
            this.fun.apply(null, this.array);
        };
        process.title = "browser";
        process.browser = true;
        process.env = {};
        process.argv = [];
        process.version = "";
        process.versions = {};
        function noop() {}
        process.on = noop;
        process.addListener = noop;
        process.once = noop;
        process.off = noop;
        process.removeListener = noop;
        process.removeAllListeners = noop;
        process.emit = noop;
        process.prependListener = noop;
        process.prependOnceListener = noop;
        process.listeners = function(name) {
            return [];
        };
        process.binding = function(name) {
            throw new Error("process.binding is not supported");
        };
        process.cwd = function() {
            return "/";
        };
        process.chdir = function(dir) {
            throw new Error("process.chdir is not supported");
        };
        process.umask = function() {
            return 0;
        };
    }, {} ],
    141: [ function(require, module, exports) {
        exports.publicEncrypt = require("./publicEncrypt");
        exports.privateDecrypt = require("./privateDecrypt");
        exports.privateEncrypt = function privateEncrypt(key, buf) {
            return exports.publicEncrypt(key, buf, true);
        };
        exports.publicDecrypt = function publicDecrypt(key, buf) {
            return exports.privateDecrypt(key, buf, true);
        };
    }, {
        "./privateDecrypt": 143,
        "./publicEncrypt": 144
    } ],
    142: [ function(require, module, exports) {
        (function(Buffer) {
            var createHash = require("create-hash");
            module.exports = function(seed, len) {
                var t = new Buffer("");
                var i = 0, c;
                while (t.length < len) {
                    c = i2ops(i++);
                    t = Buffer.concat([ t, createHash("sha1").update(seed).update(c).digest() ]);
                }
                return t.slice(0, len);
            };
            function i2ops(c) {
                var out = new Buffer(4);
                out.writeUInt32BE(c, 0);
                return out;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "create-hash": 61
    } ],
    143: [ function(require, module, exports) {
        (function(Buffer) {
            var parseKeys = require("parse-asn1");
            var mgf = require("./mgf");
            var xor = require("./xor");
            var bn = require("bn.js");
            var crt = require("browserify-rsa");
            var createHash = require("create-hash");
            var withPublic = require("./withPublic");
            module.exports = function privateDecrypt(private_key, enc, reverse) {
                var padding;
                if (private_key.padding) {
                    padding = private_key.padding;
                } else if (reverse) {
                    padding = 1;
                } else {
                    padding = 4;
                }
                var key = parseKeys(private_key);
                var k = key.modulus.byteLength();
                if (enc.length > k || new bn(enc).cmp(key.modulus) >= 0) {
                    throw new Error("decryption error");
                }
                var msg;
                if (reverse) {
                    msg = withPublic(new bn(enc), key);
                } else {
                    msg = crt(enc, key);
                }
                var zBuffer = new Buffer(k - msg.length);
                zBuffer.fill(0);
                msg = Buffer.concat([ zBuffer, msg ], k);
                if (padding === 4) {
                    return oaep(key, msg);
                } else if (padding === 1) {
                    return pkcs1(key, msg, reverse);
                } else if (padding === 3) {
                    return msg;
                } else {
                    throw new Error("unknown padding");
                }
            };
            function oaep(key, msg) {
                var n = key.modulus;
                var k = key.modulus.byteLength();
                var mLen = msg.length;
                var iHash = createHash("sha1").update(new Buffer("")).digest();
                var hLen = iHash.length;
                var hLen2 = 2 * hLen;
                if (msg[0] !== 0) {
                    throw new Error("decryption error");
                }
                var maskedSeed = msg.slice(1, hLen + 1);
                var maskedDb = msg.slice(hLen + 1);
                var seed = xor(maskedSeed, mgf(maskedDb, hLen));
                var db = xor(maskedDb, mgf(seed, k - hLen - 1));
                if (compare(iHash, db.slice(0, hLen))) {
                    throw new Error("decryption error");
                }
                var i = hLen;
                while (db[i] === 0) {
                    i++;
                }
                if (db[i++] !== 1) {
                    throw new Error("decryption error");
                }
                return db.slice(i);
            }
            function pkcs1(key, msg, reverse) {
                var p1 = msg.slice(0, 2);
                var i = 2;
                var status = 0;
                while (msg[i++] !== 0) {
                    if (i >= msg.length) {
                        status++;
                        break;
                    }
                }
                var ps = msg.slice(2, i - 1);
                var p2 = msg.slice(i - 1, i);
                if (p1.toString("hex") !== "0002" && !reverse || p1.toString("hex") !== "0001" && reverse) {
                    status++;
                }
                if (ps.length < 8) {
                    status++;
                }
                if (status) {
                    throw new Error("decryption error");
                }
                return msg.slice(i);
            }
            function compare(a, b) {
                a = new Buffer(a);
                b = new Buffer(b);
                var dif = 0;
                var len = a.length;
                if (a.length !== b.length) {
                    dif++;
                    len = Math.min(a.length, b.length);
                }
                var i = -1;
                while (++i < len) {
                    dif += a[i] ^ b[i];
                }
                return dif;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "./mgf": 142,
        "./withPublic": 145,
        "./xor": 146,
        "bn.js": 23,
        "browserify-rsa": 44,
        buffer: 54,
        "create-hash": 61,
        "parse-asn1": 132
    } ],
    144: [ function(require, module, exports) {
        (function(Buffer) {
            var parseKeys = require("parse-asn1");
            var randomBytes = require("randombytes");
            var createHash = require("create-hash");
            var mgf = require("./mgf");
            var xor = require("./xor");
            var bn = require("bn.js");
            var withPublic = require("./withPublic");
            var crt = require("browserify-rsa");
            var constants = {
                RSA_PKCS1_OAEP_PADDING: 4,
                RSA_PKCS1_PADDIN: 1,
                RSA_NO_PADDING: 3
            };
            module.exports = function publicEncrypt(public_key, msg, reverse) {
                var padding;
                if (public_key.padding) {
                    padding = public_key.padding;
                } else if (reverse) {
                    padding = 1;
                } else {
                    padding = 4;
                }
                var key = parseKeys(public_key);
                var paddedMsg;
                if (padding === 4) {
                    paddedMsg = oaep(key, msg);
                } else if (padding === 1) {
                    paddedMsg = pkcs1(key, msg, reverse);
                } else if (padding === 3) {
                    paddedMsg = new bn(msg);
                    if (paddedMsg.cmp(key.modulus) >= 0) {
                        throw new Error("data too long for modulus");
                    }
                } else {
                    throw new Error("unknown padding");
                }
                if (reverse) {
                    return crt(paddedMsg, key);
                } else {
                    return withPublic(paddedMsg, key);
                }
            };
            function oaep(key, msg) {
                var k = key.modulus.byteLength();
                var mLen = msg.length;
                var iHash = createHash("sha1").update(new Buffer("")).digest();
                var hLen = iHash.length;
                var hLen2 = 2 * hLen;
                if (mLen > k - hLen2 - 2) {
                    throw new Error("message too long");
                }
                var ps = new Buffer(k - mLen - hLen2 - 2);
                ps.fill(0);
                var dblen = k - hLen - 1;
                var seed = randomBytes(hLen);
                var maskedDb = xor(Buffer.concat([ iHash, ps, new Buffer([ 1 ]), msg ], dblen), mgf(seed, dblen));
                var maskedSeed = xor(seed, mgf(maskedDb, hLen));
                return new bn(Buffer.concat([ new Buffer([ 0 ]), maskedSeed, maskedDb ], k));
            }
            function pkcs1(key, msg, reverse) {
                var mLen = msg.length;
                var k = key.modulus.byteLength();
                if (mLen > k - 11) {
                    throw new Error("message too long");
                }
                var ps;
                if (reverse) {
                    ps = new Buffer(k - mLen - 3);
                    ps.fill(255);
                } else {
                    ps = nonZero(k - mLen - 3);
                }
                return new bn(Buffer.concat([ new Buffer([ 0, reverse ? 1 : 2 ]), ps, new Buffer([ 0 ]), msg ], k));
            }
            function nonZero(len, crypto) {
                var out = new Buffer(len);
                var i = 0;
                var cache = randomBytes(len * 2);
                var cur = 0;
                var num;
                while (i < len) {
                    if (cur === cache.length) {
                        cache = randomBytes(len * 2);
                        cur = 0;
                    }
                    num = cache[cur++];
                    if (num) {
                        out[i++] = num;
                    }
                }
                return out;
            }
        }).call(this, require("buffer").Buffer);
    }, {
        "./mgf": 142,
        "./withPublic": 145,
        "./xor": 146,
        "bn.js": 23,
        "browserify-rsa": 44,
        buffer: 54,
        "create-hash": 61,
        "parse-asn1": 132,
        randombytes: 147
    } ],
    145: [ function(require, module, exports) {
        (function(Buffer) {
            var bn = require("bn.js");
            function withPublic(paddedMsg, key) {
                return new Buffer(paddedMsg.toRed(bn.mont(key.modulus)).redPow(new bn(key.publicExponent)).fromRed().toArray());
            }
            module.exports = withPublic;
        }).call(this, require("buffer").Buffer);
    }, {
        "bn.js": 23,
        buffer: 54
    } ],
    146: [ function(require, module, exports) {
        module.exports = function xor(a, b) {
            var len = a.length;
            var i = -1;
            while (++i < len) {
                a[i] ^= b[i];
            }
            return a;
        };
    }, {} ],
    147: [ function(require, module, exports) {
        (function(process, global) {
            "use strict";
            function oldBrowser() {
                throw new Error("secure random number generation not supported by this browser\nuse chrome, FireFox or Internet Explorer 11");
            }
            var Buffer = require("safe-buffer").Buffer;
            var crypto = global.crypto || global.msCrypto;
            if (crypto && crypto.getRandomValues) {
                module.exports = randomBytes;
            } else {
                module.exports = oldBrowser;
            }
            function randomBytes(size, cb) {
                if (size > 65536) throw new Error("requested too many random bytes");
                var rawBytes = new global.Uint8Array(size);
                if (size > 0) {
                    crypto.getRandomValues(rawBytes);
                }
                var bytes = Buffer.from(rawBytes.buffer);
                if (typeof cb === "function") {
                    return process.nextTick(function() {
                        cb(null, bytes);
                    });
                }
                return bytes;
            }
        }).call(this, require("_process"), typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {
        _process: 140,
        "safe-buffer": 163
    } ],
    148: [ function(require, module, exports) {
        module.exports = require("./lib/_stream_duplex.js");
    }, {
        "./lib/_stream_duplex.js": 149
    } ],
    149: [ function(require, module, exports) {
        "use strict";
        var processNextTick = require("process-nextick-args");
        var objectKeys = Object.keys || function(obj) {
            var keys = [];
            for (var key in obj) {
                keys.push(key);
            }
            return keys;
        };
        module.exports = Duplex;
        var util = require("core-util-is");
        util.inherits = require("inherits");
        var Readable = require("./_stream_readable");
        var Writable = require("./_stream_writable");
        util.inherits(Duplex, Readable);
        var keys = objectKeys(Writable.prototype);
        for (var v = 0; v < keys.length; v++) {
            var method = keys[v];
            if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
        }
        function Duplex(options) {
            if (!(this instanceof Duplex)) return new Duplex(options);
            Readable.call(this, options);
            Writable.call(this, options);
            if (options && options.readable === false) this.readable = false;
            if (options && options.writable === false) this.writable = false;
            this.allowHalfOpen = true;
            if (options && options.allowHalfOpen === false) this.allowHalfOpen = false;
            this.once("end", onend);
        }
        function onend() {
            if (this.allowHalfOpen || this._writableState.ended) return;
            processNextTick(onEndNT, this);
        }
        function onEndNT(self) {
            self.end();
        }
        Object.defineProperty(Duplex.prototype, "destroyed", {
            get: function() {
                if (this._readableState === undefined || this._writableState === undefined) {
                    return false;
                }
                return this._readableState.destroyed && this._writableState.destroyed;
            },
            set: function(value) {
                if (this._readableState === undefined || this._writableState === undefined) {
                    return;
                }
                this._readableState.destroyed = value;
                this._writableState.destroyed = value;
            }
        });
        Duplex.prototype._destroy = function(err, cb) {
            this.push(null);
            this.end();
            processNextTick(cb, err);
        };
        function forEach(xs, f) {
            for (var i = 0, l = xs.length; i < l; i++) {
                f(xs[i], i);
            }
        }
    }, {
        "./_stream_readable": 151,
        "./_stream_writable": 153,
        "core-util-is": 59,
        inherits: 157,
        "process-nextick-args": 139
    } ],
    150: [ function(require, module, exports) {
        "use strict";
        module.exports = PassThrough;
        var Transform = require("./_stream_transform");
        var util = require("core-util-is");
        util.inherits = require("inherits");
        util.inherits(PassThrough, Transform);
        function PassThrough(options) {
            if (!(this instanceof PassThrough)) return new PassThrough(options);
            Transform.call(this, options);
        }
        PassThrough.prototype._transform = function(chunk, encoding, cb) {
            cb(null, chunk);
        };
    }, {
        "./_stream_transform": 152,
        "core-util-is": 59,
        inherits: 157
    } ],
    151: [ function(require, module, exports) {
        (function(process, global) {
            "use strict";
            var processNextTick = require("process-nextick-args");
            module.exports = Readable;
            var isArray = require("isarray");
            var Duplex;
            Readable.ReadableState = ReadableState;
            var EE = require("events").EventEmitter;
            var EElistenerCount = function(emitter, type) {
                return emitter.listeners(type).length;
            };
            var Stream = require("./internal/streams/stream");
            var Buffer = require("safe-buffer").Buffer;
            var OurUint8Array = global.Uint8Array || function() {};
            function _uint8ArrayToBuffer(chunk) {
                return Buffer.from(chunk);
            }
            function _isUint8Array(obj) {
                return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
            }
            var util = require("core-util-is");
            util.inherits = require("inherits");
            var debugUtil = require("util");
            var debug = void 0;
            if (debugUtil && debugUtil.debuglog) {
                debug = debugUtil.debuglog("stream");
            } else {
                debug = function() {};
            }
            var BufferList = require("./internal/streams/BufferList");
            var destroyImpl = require("./internal/streams/destroy");
            var StringDecoder;
            util.inherits(Readable, Stream);
            var kProxyEvents = [ "error", "close", "destroy", "pause", "resume" ];
            function prependListener(emitter, event, fn) {
                if (typeof emitter.prependListener === "function") {
                    return emitter.prependListener(event, fn);
                } else {
                    if (!emitter._events || !emitter._events[event]) emitter.on(event, fn); else if (isArray(emitter._events[event])) emitter._events[event].unshift(fn); else emitter._events[event] = [ fn, emitter._events[event] ];
                }
            }
            function ReadableState(options, stream) {
                Duplex = Duplex || require("./_stream_duplex");
                options = options || {};
                this.objectMode = !!options.objectMode;
                if (stream instanceof Duplex) this.objectMode = this.objectMode || !!options.readableObjectMode;
                var hwm = options.highWaterMark;
                var defaultHwm = this.objectMode ? 16 : 16 * 1024;
                this.highWaterMark = hwm || hwm === 0 ? hwm : defaultHwm;
                this.highWaterMark = Math.floor(this.highWaterMark);
                this.buffer = new BufferList();
                this.length = 0;
                this.pipes = null;
                this.pipesCount = 0;
                this.flowing = null;
                this.ended = false;
                this.endEmitted = false;
                this.reading = false;
                this.sync = true;
                this.needReadable = false;
                this.emittedReadable = false;
                this.readableListening = false;
                this.resumeScheduled = false;
                this.destroyed = false;
                this.defaultEncoding = options.defaultEncoding || "utf8";
                this.awaitDrain = 0;
                this.readingMore = false;
                this.decoder = null;
                this.encoding = null;
                if (options.encoding) {
                    if (!StringDecoder) StringDecoder = require("string_decoder/").StringDecoder;
                    this.decoder = new StringDecoder(options.encoding);
                    this.encoding = options.encoding;
                }
            }
            function Readable(options) {
                Duplex = Duplex || require("./_stream_duplex");
                if (!(this instanceof Readable)) return new Readable(options);
                this._readableState = new ReadableState(options, this);
                this.readable = true;
                if (options) {
                    if (typeof options.read === "function") this._read = options.read;
                    if (typeof options.destroy === "function") this._destroy = options.destroy;
                }
                Stream.call(this);
            }
            Object.defineProperty(Readable.prototype, "destroyed", {
                get: function() {
                    if (this._readableState === undefined) {
                        return false;
                    }
                    return this._readableState.destroyed;
                },
                set: function(value) {
                    if (!this._readableState) {
                        return;
                    }
                    this._readableState.destroyed = value;
                }
            });
            Readable.prototype.destroy = destroyImpl.destroy;
            Readable.prototype._undestroy = destroyImpl.undestroy;
            Readable.prototype._destroy = function(err, cb) {
                this.push(null);
                cb(err);
            };
            Readable.prototype.push = function(chunk, encoding) {
                var state = this._readableState;
                var skipChunkCheck;
                if (!state.objectMode) {
                    if (typeof chunk === "string") {
                        encoding = encoding || state.defaultEncoding;
                        if (encoding !== state.encoding) {
                            chunk = Buffer.from(chunk, encoding);
                            encoding = "";
                        }
                        skipChunkCheck = true;
                    }
                } else {
                    skipChunkCheck = true;
                }
                return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
            };
            Readable.prototype.unshift = function(chunk) {
                return readableAddChunk(this, chunk, null, true, false);
            };
            function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
                var state = stream._readableState;
                if (chunk === null) {
                    state.reading = false;
                    onEofChunk(stream, state);
                } else {
                    var er;
                    if (!skipChunkCheck) er = chunkInvalid(state, chunk);
                    if (er) {
                        stream.emit("error", er);
                    } else if (state.objectMode || chunk && chunk.length > 0) {
                        if (typeof chunk !== "string" && !state.objectMode && Object.getPrototypeOf(chunk) !== Buffer.prototype) {
                            chunk = _uint8ArrayToBuffer(chunk);
                        }
                        if (addToFront) {
                            if (state.endEmitted) stream.emit("error", new Error("stream.unshift() after end event")); else addChunk(stream, state, chunk, true);
                        } else if (state.ended) {
                            stream.emit("error", new Error("stream.push() after EOF"));
                        } else {
                            state.reading = false;
                            if (state.decoder && !encoding) {
                                chunk = state.decoder.write(chunk);
                                if (state.objectMode || chunk.length !== 0) addChunk(stream, state, chunk, false); else maybeReadMore(stream, state);
                            } else {
                                addChunk(stream, state, chunk, false);
                            }
                        }
                    } else if (!addToFront) {
                        state.reading = false;
                    }
                }
                return needMoreData(state);
            }
            function addChunk(stream, state, chunk, addToFront) {
                if (state.flowing && state.length === 0 && !state.sync) {
                    stream.emit("data", chunk);
                    stream.read(0);
                } else {
                    state.length += state.objectMode ? 1 : chunk.length;
                    if (addToFront) state.buffer.unshift(chunk); else state.buffer.push(chunk);
                    if (state.needReadable) emitReadable(stream);
                }
                maybeReadMore(stream, state);
            }
            function chunkInvalid(state, chunk) {
                var er;
                if (!_isUint8Array(chunk) && typeof chunk !== "string" && chunk !== undefined && !state.objectMode) {
                    er = new TypeError("Invalid non-string/buffer chunk");
                }
                return er;
            }
            function needMoreData(state) {
                return !state.ended && (state.needReadable || state.length < state.highWaterMark || state.length === 0);
            }
            Readable.prototype.isPaused = function() {
                return this._readableState.flowing === false;
            };
            Readable.prototype.setEncoding = function(enc) {
                if (!StringDecoder) StringDecoder = require("string_decoder/").StringDecoder;
                this._readableState.decoder = new StringDecoder(enc);
                this._readableState.encoding = enc;
                return this;
            };
            var MAX_HWM = 8388608;
            function computeNewHighWaterMark(n) {
                if (n >= MAX_HWM) {
                    n = MAX_HWM;
                } else {
                    n--;
                    n |= n >>> 1;
                    n |= n >>> 2;
                    n |= n >>> 4;
                    n |= n >>> 8;
                    n |= n >>> 16;
                    n++;
                }
                return n;
            }
            function howMuchToRead(n, state) {
                if (n <= 0 || state.length === 0 && state.ended) return 0;
                if (state.objectMode) return 1;
                if (n !== n) {
                    if (state.flowing && state.length) return state.buffer.head.data.length; else return state.length;
                }
                if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
                if (n <= state.length) return n;
                if (!state.ended) {
                    state.needReadable = true;
                    return 0;
                }
                return state.length;
            }
            Readable.prototype.read = function(n) {
                debug("read", n);
                n = parseInt(n, 10);
                var state = this._readableState;
                var nOrig = n;
                if (n !== 0) state.emittedReadable = false;
                if (n === 0 && state.needReadable && (state.length >= state.highWaterMark || state.ended)) {
                    debug("read: emitReadable", state.length, state.ended);
                    if (state.length === 0 && state.ended) endReadable(this); else emitReadable(this);
                    return null;
                }
                n = howMuchToRead(n, state);
                if (n === 0 && state.ended) {
                    if (state.length === 0) endReadable(this);
                    return null;
                }
                var doRead = state.needReadable;
                debug("need readable", doRead);
                if (state.length === 0 || state.length - n < state.highWaterMark) {
                    doRead = true;
                    debug("length less than watermark", doRead);
                }
                if (state.ended || state.reading) {
                    doRead = false;
                    debug("reading or ended", doRead);
                } else if (doRead) {
                    debug("do read");
                    state.reading = true;
                    state.sync = true;
                    if (state.length === 0) state.needReadable = true;
                    this._read(state.highWaterMark);
                    state.sync = false;
                    if (!state.reading) n = howMuchToRead(nOrig, state);
                }
                var ret;
                if (n > 0) ret = fromList(n, state); else ret = null;
                if (ret === null) {
                    state.needReadable = true;
                    n = 0;
                } else {
                    state.length -= n;
                }
                if (state.length === 0) {
                    if (!state.ended) state.needReadable = true;
                    if (nOrig !== n && state.ended) endReadable(this);
                }
                if (ret !== null) this.emit("data", ret);
                return ret;
            };
            function onEofChunk(stream, state) {
                if (state.ended) return;
                if (state.decoder) {
                    var chunk = state.decoder.end();
                    if (chunk && chunk.length) {
                        state.buffer.push(chunk);
                        state.length += state.objectMode ? 1 : chunk.length;
                    }
                }
                state.ended = true;
                emitReadable(stream);
            }
            function emitReadable(stream) {
                var state = stream._readableState;
                state.needReadable = false;
                if (!state.emittedReadable) {
                    debug("emitReadable", state.flowing);
                    state.emittedReadable = true;
                    if (state.sync) processNextTick(emitReadable_, stream); else emitReadable_(stream);
                }
            }
            function emitReadable_(stream) {
                debug("emit readable");
                stream.emit("readable");
                flow(stream);
            }
            function maybeReadMore(stream, state) {
                if (!state.readingMore) {
                    state.readingMore = true;
                    processNextTick(maybeReadMore_, stream, state);
                }
            }
            function maybeReadMore_(stream, state) {
                var len = state.length;
                while (!state.reading && !state.flowing && !state.ended && state.length < state.highWaterMark) {
                    debug("maybeReadMore read 0");
                    stream.read(0);
                    if (len === state.length) break; else len = state.length;
                }
                state.readingMore = false;
            }
            Readable.prototype._read = function(n) {
                this.emit("error", new Error("_read() is not implemented"));
            };
            Readable.prototype.pipe = function(dest, pipeOpts) {
                var src = this;
                var state = this._readableState;
                switch (state.pipesCount) {
                  case 0:
                    state.pipes = dest;
                    break;

                  case 1:
                    state.pipes = [ state.pipes, dest ];
                    break;

                  default:
                    state.pipes.push(dest);
                    break;
                }
                state.pipesCount += 1;
                debug("pipe count=%d opts=%j", state.pipesCount, pipeOpts);
                var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;
                var endFn = doEnd ? onend : unpipe;
                if (state.endEmitted) processNextTick(endFn); else src.once("end", endFn);
                dest.on("unpipe", onunpipe);
                function onunpipe(readable, unpipeInfo) {
                    debug("onunpipe");
                    if (readable === src) {
                        if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
                            unpipeInfo.hasUnpiped = true;
                            cleanup();
                        }
                    }
                }
                function onend() {
                    debug("onend");
                    dest.end();
                }
                var ondrain = pipeOnDrain(src);
                dest.on("drain", ondrain);
                var cleanedUp = false;
                function cleanup() {
                    debug("cleanup");
                    dest.removeListener("close", onclose);
                    dest.removeListener("finish", onfinish);
                    dest.removeListener("drain", ondrain);
                    dest.removeListener("error", onerror);
                    dest.removeListener("unpipe", onunpipe);
                    src.removeListener("end", onend);
                    src.removeListener("end", unpipe);
                    src.removeListener("data", ondata);
                    cleanedUp = true;
                    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
                }
                var increasedAwaitDrain = false;
                src.on("data", ondata);
                function ondata(chunk) {
                    debug("ondata");
                    increasedAwaitDrain = false;
                    var ret = dest.write(chunk);
                    if (false === ret && !increasedAwaitDrain) {
                        if ((state.pipesCount === 1 && state.pipes === dest || state.pipesCount > 1 && indexOf(state.pipes, dest) !== -1) && !cleanedUp) {
                            debug("false write response, pause", src._readableState.awaitDrain);
                            src._readableState.awaitDrain++;
                            increasedAwaitDrain = true;
                        }
                        src.pause();
                    }
                }
                function onerror(er) {
                    debug("onerror", er);
                    unpipe();
                    dest.removeListener("error", onerror);
                    if (EElistenerCount(dest, "error") === 0) dest.emit("error", er);
                }
                prependListener(dest, "error", onerror);
                function onclose() {
                    dest.removeListener("finish", onfinish);
                    unpipe();
                }
                dest.once("close", onclose);
                function onfinish() {
                    debug("onfinish");
                    dest.removeListener("close", onclose);
                    unpipe();
                }
                dest.once("finish", onfinish);
                function unpipe() {
                    debug("unpipe");
                    src.unpipe(dest);
                }
                dest.emit("pipe", src);
                if (!state.flowing) {
                    debug("pipe resume");
                    src.resume();
                }
                return dest;
            };
            function pipeOnDrain(src) {
                return function() {
                    var state = src._readableState;
                    debug("pipeOnDrain", state.awaitDrain);
                    if (state.awaitDrain) state.awaitDrain--;
                    if (state.awaitDrain === 0 && EElistenerCount(src, "data")) {
                        state.flowing = true;
                        flow(src);
                    }
                };
            }
            Readable.prototype.unpipe = function(dest) {
                var state = this._readableState;
                var unpipeInfo = {
                    hasUnpiped: false
                };
                if (state.pipesCount === 0) return this;
                if (state.pipesCount === 1) {
                    if (dest && dest !== state.pipes) return this;
                    if (!dest) dest = state.pipes;
                    state.pipes = null;
                    state.pipesCount = 0;
                    state.flowing = false;
                    if (dest) dest.emit("unpipe", this, unpipeInfo);
                    return this;
                }
                if (!dest) {
                    var dests = state.pipes;
                    var len = state.pipesCount;
                    state.pipes = null;
                    state.pipesCount = 0;
                    state.flowing = false;
                    for (var i = 0; i < len; i++) {
                        dests[i].emit("unpipe", this, unpipeInfo);
                    }
                    return this;
                }
                var index = indexOf(state.pipes, dest);
                if (index === -1) return this;
                state.pipes.splice(index, 1);
                state.pipesCount -= 1;
                if (state.pipesCount === 1) state.pipes = state.pipes[0];
                dest.emit("unpipe", this, unpipeInfo);
                return this;
            };
            Readable.prototype.on = function(ev, fn) {
                var res = Stream.prototype.on.call(this, ev, fn);
                if (ev === "data") {
                    if (this._readableState.flowing !== false) this.resume();
                } else if (ev === "readable") {
                    var state = this._readableState;
                    if (!state.endEmitted && !state.readableListening) {
                        state.readableListening = state.needReadable = true;
                        state.emittedReadable = false;
                        if (!state.reading) {
                            processNextTick(nReadingNextTick, this);
                        } else if (state.length) {
                            emitReadable(this);
                        }
                    }
                }
                return res;
            };
            Readable.prototype.addListener = Readable.prototype.on;
            function nReadingNextTick(self) {
                debug("readable nexttick read 0");
                self.read(0);
            }
            Readable.prototype.resume = function() {
                var state = this._readableState;
                if (!state.flowing) {
                    debug("resume");
                    state.flowing = true;
                    resume(this, state);
                }
                return this;
            };
            function resume(stream, state) {
                if (!state.resumeScheduled) {
                    state.resumeScheduled = true;
                    processNextTick(resume_, stream, state);
                }
            }
            function resume_(stream, state) {
                if (!state.reading) {
                    debug("resume read 0");
                    stream.read(0);
                }
                state.resumeScheduled = false;
                state.awaitDrain = 0;
                stream.emit("resume");
                flow(stream);
                if (state.flowing && !state.reading) stream.read(0);
            }
            Readable.prototype.pause = function() {
                debug("call pause flowing=%j", this._readableState.flowing);
                if (false !== this._readableState.flowing) {
                    debug("pause");
                    this._readableState.flowing = false;
                    this.emit("pause");
                }
                return this;
            };
            function flow(stream) {
                var state = stream._readableState;
                debug("flow", state.flowing);
                while (state.flowing && stream.read() !== null) {}
            }
            Readable.prototype.wrap = function(stream) {
                var state = this._readableState;
                var paused = false;
                var self = this;
                stream.on("end", function() {
                    debug("wrapped end");
                    if (state.decoder && !state.ended) {
                        var chunk = state.decoder.end();
                        if (chunk && chunk.length) self.push(chunk);
                    }
                    self.push(null);
                });
                stream.on("data", function(chunk) {
                    debug("wrapped data");
                    if (state.decoder) chunk = state.decoder.write(chunk);
                    if (state.objectMode && (chunk === null || chunk === undefined)) return; else if (!state.objectMode && (!chunk || !chunk.length)) return;
                    var ret = self.push(chunk);
                    if (!ret) {
                        paused = true;
                        stream.pause();
                    }
                });
                for (var i in stream) {
                    if (this[i] === undefined && typeof stream[i] === "function") {
                        this[i] = function(method) {
                            return function() {
                                return stream[method].apply(stream, arguments);
                            };
                        }(i);
                    }
                }
                for (var n = 0; n < kProxyEvents.length; n++) {
                    stream.on(kProxyEvents[n], self.emit.bind(self, kProxyEvents[n]));
                }
                self._read = function(n) {
                    debug("wrapped _read", n);
                    if (paused) {
                        paused = false;
                        stream.resume();
                    }
                };
                return self;
            };
            Readable._fromList = fromList;
            function fromList(n, state) {
                if (state.length === 0) return null;
                var ret;
                if (state.objectMode) ret = state.buffer.shift(); else if (!n || n >= state.length) {
                    if (state.decoder) ret = state.buffer.join(""); else if (state.buffer.length === 1) ret = state.buffer.head.data; else ret = state.buffer.concat(state.length);
                    state.buffer.clear();
                } else {
                    ret = fromListPartial(n, state.buffer, state.decoder);
                }
                return ret;
            }
            function fromListPartial(n, list, hasStrings) {
                var ret;
                if (n < list.head.data.length) {
                    ret = list.head.data.slice(0, n);
                    list.head.data = list.head.data.slice(n);
                } else if (n === list.head.data.length) {
                    ret = list.shift();
                } else {
                    ret = hasStrings ? copyFromBufferString(n, list) : copyFromBuffer(n, list);
                }
                return ret;
            }
            function copyFromBufferString(n, list) {
                var p = list.head;
                var c = 1;
                var ret = p.data;
                n -= ret.length;
                while (p = p.next) {
                    var str = p.data;
                    var nb = n > str.length ? str.length : n;
                    if (nb === str.length) ret += str; else ret += str.slice(0, n);
                    n -= nb;
                    if (n === 0) {
                        if (nb === str.length) {
                            ++c;
                            if (p.next) list.head = p.next; else list.head = list.tail = null;
                        } else {
                            list.head = p;
                            p.data = str.slice(nb);
                        }
                        break;
                    }
                    ++c;
                }
                list.length -= c;
                return ret;
            }
            function copyFromBuffer(n, list) {
                var ret = Buffer.allocUnsafe(n);
                var p = list.head;
                var c = 1;
                p.data.copy(ret);
                n -= p.data.length;
                while (p = p.next) {
                    var buf = p.data;
                    var nb = n > buf.length ? buf.length : n;
                    buf.copy(ret, ret.length - n, 0, nb);
                    n -= nb;
                    if (n === 0) {
                        if (nb === buf.length) {
                            ++c;
                            if (p.next) list.head = p.next; else list.head = list.tail = null;
                        } else {
                            list.head = p;
                            p.data = buf.slice(nb);
                        }
                        break;
                    }
                    ++c;
                }
                list.length -= c;
                return ret;
            }
            function endReadable(stream) {
                var state = stream._readableState;
                if (state.length > 0) throw new Error('"endReadable()" called on non-empty stream');
                if (!state.endEmitted) {
                    state.ended = true;
                    processNextTick(endReadableNT, state, stream);
                }
            }
            function endReadableNT(state, stream) {
                if (!state.endEmitted && state.length === 0) {
                    state.endEmitted = true;
                    stream.readable = false;
                    stream.emit("end");
                }
            }
            function forEach(xs, f) {
                for (var i = 0, l = xs.length; i < l; i++) {
                    f(xs[i], i);
                }
            }
            function indexOf(xs, x) {
                for (var i = 0, l = xs.length; i < l; i++) {
                    if (xs[i] === x) return i;
                }
                return -1;
            }
        }).call(this, require("_process"), typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {
        "./_stream_duplex": 149,
        "./internal/streams/BufferList": 154,
        "./internal/streams/destroy": 155,
        "./internal/streams/stream": 156,
        _process: 140,
        "core-util-is": 59,
        events: 103,
        inherits: 157,
        isarray: 124,
        "process-nextick-args": 139,
        "safe-buffer": 163,
        "string_decoder/": 180,
        util: 25
    } ],
    152: [ function(require, module, exports) {
        "use strict";
        module.exports = Transform;
        var Duplex = require("./_stream_duplex");
        var util = require("core-util-is");
        util.inherits = require("inherits");
        util.inherits(Transform, Duplex);
        function TransformState(stream) {
            this.afterTransform = function(er, data) {
                return afterTransform(stream, er, data);
            };
            this.needTransform = false;
            this.transforming = false;
            this.writecb = null;
            this.writechunk = null;
            this.writeencoding = null;
        }
        function afterTransform(stream, er, data) {
            var ts = stream._transformState;
            ts.transforming = false;
            var cb = ts.writecb;
            if (!cb) {
                return stream.emit("error", new Error("write callback called multiple times"));
            }
            ts.writechunk = null;
            ts.writecb = null;
            if (data !== null && data !== undefined) stream.push(data);
            cb(er);
            var rs = stream._readableState;
            rs.reading = false;
            if (rs.needReadable || rs.length < rs.highWaterMark) {
                stream._read(rs.highWaterMark);
            }
        }
        function Transform(options) {
            if (!(this instanceof Transform)) return new Transform(options);
            Duplex.call(this, options);
            this._transformState = new TransformState(this);
            var stream = this;
            this._readableState.needReadable = true;
            this._readableState.sync = false;
            if (options) {
                if (typeof options.transform === "function") this._transform = options.transform;
                if (typeof options.flush === "function") this._flush = options.flush;
            }
            this.once("prefinish", function() {
                if (typeof this._flush === "function") this._flush(function(er, data) {
                    done(stream, er, data);
                }); else done(stream);
            });
        }
        Transform.prototype.push = function(chunk, encoding) {
            this._transformState.needTransform = false;
            return Duplex.prototype.push.call(this, chunk, encoding);
        };
        Transform.prototype._transform = function(chunk, encoding, cb) {
            throw new Error("_transform() is not implemented");
        };
        Transform.prototype._write = function(chunk, encoding, cb) {
            var ts = this._transformState;
            ts.writecb = cb;
            ts.writechunk = chunk;
            ts.writeencoding = encoding;
            if (!ts.transforming) {
                var rs = this._readableState;
                if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
            }
        };
        Transform.prototype._read = function(n) {
            var ts = this._transformState;
            if (ts.writechunk !== null && ts.writecb && !ts.transforming) {
                ts.transforming = true;
                this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
            } else {
                ts.needTransform = true;
            }
        };
        Transform.prototype._destroy = function(err, cb) {
            var _this = this;
            Duplex.prototype._destroy.call(this, err, function(err2) {
                cb(err2);
                _this.emit("close");
            });
        };
        function done(stream, er, data) {
            if (er) return stream.emit("error", er);
            if (data !== null && data !== undefined) stream.push(data);
            var ws = stream._writableState;
            var ts = stream._transformState;
            if (ws.length) throw new Error("Calling transform done when ws.length != 0");
            if (ts.transforming) throw new Error("Calling transform done when still transforming");
            return stream.push(null);
        }
    }, {
        "./_stream_duplex": 149,
        "core-util-is": 59,
        inherits: 157
    } ],
    153: [ function(require, module, exports) {
        (function(process, global) {
            "use strict";
            var processNextTick = require("process-nextick-args");
            module.exports = Writable;
            function WriteReq(chunk, encoding, cb) {
                this.chunk = chunk;
                this.encoding = encoding;
                this.callback = cb;
                this.next = null;
            }
            function CorkedRequest(state) {
                var _this = this;
                this.next = null;
                this.entry = null;
                this.finish = function() {
                    onCorkedFinish(_this, state);
                };
            }
            var asyncWrite = !process.browser && [ "v0.10", "v0.9." ].indexOf(process.version.slice(0, 5)) > -1 ? setImmediate : processNextTick;
            var Duplex;
            Writable.WritableState = WritableState;
            var util = require("core-util-is");
            util.inherits = require("inherits");
            var internalUtil = {
                deprecate: require("util-deprecate")
            };
            var Stream = require("./internal/streams/stream");
            var Buffer = require("safe-buffer").Buffer;
            var OurUint8Array = global.Uint8Array || function() {};
            function _uint8ArrayToBuffer(chunk) {
                return Buffer.from(chunk);
            }
            function _isUint8Array(obj) {
                return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
            }
            var destroyImpl = require("./internal/streams/destroy");
            util.inherits(Writable, Stream);
            function nop() {}
            function WritableState(options, stream) {
                Duplex = Duplex || require("./_stream_duplex");
                options = options || {};
                this.objectMode = !!options.objectMode;
                if (stream instanceof Duplex) this.objectMode = this.objectMode || !!options.writableObjectMode;
                var hwm = options.highWaterMark;
                var defaultHwm = this.objectMode ? 16 : 16 * 1024;
                this.highWaterMark = hwm || hwm === 0 ? hwm : defaultHwm;
                this.highWaterMark = Math.floor(this.highWaterMark);
                this.finalCalled = false;
                this.needDrain = false;
                this.ending = false;
                this.ended = false;
                this.finished = false;
                this.destroyed = false;
                var noDecode = options.decodeStrings === false;
                this.decodeStrings = !noDecode;
                this.defaultEncoding = options.defaultEncoding || "utf8";
                this.length = 0;
                this.writing = false;
                this.corked = 0;
                this.sync = true;
                this.bufferProcessing = false;
                this.onwrite = function(er) {
                    onwrite(stream, er);
                };
                this.writecb = null;
                this.writelen = 0;
                this.bufferedRequest = null;
                this.lastBufferedRequest = null;
                this.pendingcb = 0;
                this.prefinished = false;
                this.errorEmitted = false;
                this.bufferedRequestCount = 0;
                this.corkedRequestsFree = new CorkedRequest(this);
            }
            WritableState.prototype.getBuffer = function getBuffer() {
                var current = this.bufferedRequest;
                var out = [];
                while (current) {
                    out.push(current);
                    current = current.next;
                }
                return out;
            };
            (function() {
                try {
                    Object.defineProperty(WritableState.prototype, "buffer", {
                        get: internalUtil.deprecate(function() {
                            return this.getBuffer();
                        }, "_writableState.buffer is deprecated. Use _writableState.getBuffer " + "instead.", "DEP0003")
                    });
                } catch (_) {}
            })();
            var realHasInstance;
            if (typeof Symbol === "function" && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === "function") {
                realHasInstance = Function.prototype[Symbol.hasInstance];
                Object.defineProperty(Writable, Symbol.hasInstance, {
                    value: function(object) {
                        if (realHasInstance.call(this, object)) return true;
                        return object && object._writableState instanceof WritableState;
                    }
                });
            } else {
                realHasInstance = function(object) {
                    return object instanceof this;
                };
            }
            function Writable(options) {
                Duplex = Duplex || require("./_stream_duplex");
                if (!realHasInstance.call(Writable, this) && !(this instanceof Duplex)) {
                    return new Writable(options);
                }
                this._writableState = new WritableState(options, this);
                this.writable = true;
                if (options) {
                    if (typeof options.write === "function") this._write = options.write;
                    if (typeof options.writev === "function") this._writev = options.writev;
                    if (typeof options.destroy === "function") this._destroy = options.destroy;
                    if (typeof options.final === "function") this._final = options.final;
                }
                Stream.call(this);
            }
            Writable.prototype.pipe = function() {
                this.emit("error", new Error("Cannot pipe, not readable"));
            };
            function writeAfterEnd(stream, cb) {
                var er = new Error("write after end");
                stream.emit("error", er);
                processNextTick(cb, er);
            }
            function validChunk(stream, state, chunk, cb) {
                var valid = true;
                var er = false;
                if (chunk === null) {
                    er = new TypeError("May not write null values to stream");
                } else if (typeof chunk !== "string" && chunk !== undefined && !state.objectMode) {
                    er = new TypeError("Invalid non-string/buffer chunk");
                }
                if (er) {
                    stream.emit("error", er);
                    processNextTick(cb, er);
                    valid = false;
                }
                return valid;
            }
            Writable.prototype.write = function(chunk, encoding, cb) {
                var state = this._writableState;
                var ret = false;
                var isBuf = _isUint8Array(chunk) && !state.objectMode;
                if (isBuf && !Buffer.isBuffer(chunk)) {
                    chunk = _uint8ArrayToBuffer(chunk);
                }
                if (typeof encoding === "function") {
                    cb = encoding;
                    encoding = null;
                }
                if (isBuf) encoding = "buffer"; else if (!encoding) encoding = state.defaultEncoding;
                if (typeof cb !== "function") cb = nop;
                if (state.ended) writeAfterEnd(this, cb); else if (isBuf || validChunk(this, state, chunk, cb)) {
                    state.pendingcb++;
                    ret = writeOrBuffer(this, state, isBuf, chunk, encoding, cb);
                }
                return ret;
            };
            Writable.prototype.cork = function() {
                var state = this._writableState;
                state.corked++;
            };
            Writable.prototype.uncork = function() {
                var state = this._writableState;
                if (state.corked) {
                    state.corked--;
                    if (!state.writing && !state.corked && !state.finished && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
                }
            };
            Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
                if (typeof encoding === "string") encoding = encoding.toLowerCase();
                if (!([ "hex", "utf8", "utf-8", "ascii", "binary", "base64", "ucs2", "ucs-2", "utf16le", "utf-16le", "raw" ].indexOf((encoding + "").toLowerCase()) > -1)) throw new TypeError("Unknown encoding: " + encoding);
                this._writableState.defaultEncoding = encoding;
                return this;
            };
            function decodeChunk(state, chunk, encoding) {
                if (!state.objectMode && state.decodeStrings !== false && typeof chunk === "string") {
                    chunk = Buffer.from(chunk, encoding);
                }
                return chunk;
            }
            function writeOrBuffer(stream, state, isBuf, chunk, encoding, cb) {
                if (!isBuf) {
                    var newChunk = decodeChunk(state, chunk, encoding);
                    if (chunk !== newChunk) {
                        isBuf = true;
                        encoding = "buffer";
                        chunk = newChunk;
                    }
                }
                var len = state.objectMode ? 1 : chunk.length;
                state.length += len;
                var ret = state.length < state.highWaterMark;
                if (!ret) state.needDrain = true;
                if (state.writing || state.corked) {
                    var last = state.lastBufferedRequest;
                    state.lastBufferedRequest = {
                        chunk: chunk,
                        encoding: encoding,
                        isBuf: isBuf,
                        callback: cb,
                        next: null
                    };
                    if (last) {
                        last.next = state.lastBufferedRequest;
                    } else {
                        state.bufferedRequest = state.lastBufferedRequest;
                    }
                    state.bufferedRequestCount += 1;
                } else {
                    doWrite(stream, state, false, len, chunk, encoding, cb);
                }
                return ret;
            }
            function doWrite(stream, state, writev, len, chunk, encoding, cb) {
                state.writelen = len;
                state.writecb = cb;
                state.writing = true;
                state.sync = true;
                if (writev) stream._writev(chunk, state.onwrite); else stream._write(chunk, encoding, state.onwrite);
                state.sync = false;
            }
            function onwriteError(stream, state, sync, er, cb) {
                --state.pendingcb;
                if (sync) {
                    processNextTick(cb, er);
                    processNextTick(finishMaybe, stream, state);
                    stream._writableState.errorEmitted = true;
                    stream.emit("error", er);
                } else {
                    cb(er);
                    stream._writableState.errorEmitted = true;
                    stream.emit("error", er);
                    finishMaybe(stream, state);
                }
            }
            function onwriteStateUpdate(state) {
                state.writing = false;
                state.writecb = null;
                state.length -= state.writelen;
                state.writelen = 0;
            }
            function onwrite(stream, er) {
                var state = stream._writableState;
                var sync = state.sync;
                var cb = state.writecb;
                onwriteStateUpdate(state);
                if (er) onwriteError(stream, state, sync, er, cb); else {
                    var finished = needFinish(state);
                    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
                        clearBuffer(stream, state);
                    }
                    if (sync) {
                        asyncWrite(afterWrite, stream, state, finished, cb);
                    } else {
                        afterWrite(stream, state, finished, cb);
                    }
                }
            }
            function afterWrite(stream, state, finished, cb) {
                if (!finished) onwriteDrain(stream, state);
                state.pendingcb--;
                cb();
                finishMaybe(stream, state);
            }
            function onwriteDrain(stream, state) {
                if (state.length === 0 && state.needDrain) {
                    state.needDrain = false;
                    stream.emit("drain");
                }
            }
            function clearBuffer(stream, state) {
                state.bufferProcessing = true;
                var entry = state.bufferedRequest;
                if (stream._writev && entry && entry.next) {
                    var l = state.bufferedRequestCount;
                    var buffer = new Array(l);
                    var holder = state.corkedRequestsFree;
                    holder.entry = entry;
                    var count = 0;
                    var allBuffers = true;
                    while (entry) {
                        buffer[count] = entry;
                        if (!entry.isBuf) allBuffers = false;
                        entry = entry.next;
                        count += 1;
                    }
                    buffer.allBuffers = allBuffers;
                    doWrite(stream, state, true, state.length, buffer, "", holder.finish);
                    state.pendingcb++;
                    state.lastBufferedRequest = null;
                    if (holder.next) {
                        state.corkedRequestsFree = holder.next;
                        holder.next = null;
                    } else {
                        state.corkedRequestsFree = new CorkedRequest(state);
                    }
                } else {
                    while (entry) {
                        var chunk = entry.chunk;
                        var encoding = entry.encoding;
                        var cb = entry.callback;
                        var len = state.objectMode ? 1 : chunk.length;
                        doWrite(stream, state, false, len, chunk, encoding, cb);
                        entry = entry.next;
                        if (state.writing) {
                            break;
                        }
                    }
                    if (entry === null) state.lastBufferedRequest = null;
                }
                state.bufferedRequestCount = 0;
                state.bufferedRequest = entry;
                state.bufferProcessing = false;
            }
            Writable.prototype._write = function(chunk, encoding, cb) {
                cb(new Error("_write() is not implemented"));
            };
            Writable.prototype._writev = null;
            Writable.prototype.end = function(chunk, encoding, cb) {
                var state = this._writableState;
                if (typeof chunk === "function") {
                    cb = chunk;
                    chunk = null;
                    encoding = null;
                } else if (typeof encoding === "function") {
                    cb = encoding;
                    encoding = null;
                }
                if (chunk !== null && chunk !== undefined) this.write(chunk, encoding);
                if (state.corked) {
                    state.corked = 1;
                    this.uncork();
                }
                if (!state.ending && !state.finished) endWritable(this, state, cb);
            };
            function needFinish(state) {
                return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
            }
            function callFinal(stream, state) {
                stream._final(function(err) {
                    state.pendingcb--;
                    if (err) {
                        stream.emit("error", err);
                    }
                    state.prefinished = true;
                    stream.emit("prefinish");
                    finishMaybe(stream, state);
                });
            }
            function prefinish(stream, state) {
                if (!state.prefinished && !state.finalCalled) {
                    if (typeof stream._final === "function") {
                        state.pendingcb++;
                        state.finalCalled = true;
                        processNextTick(callFinal, stream, state);
                    } else {
                        state.prefinished = true;
                        stream.emit("prefinish");
                    }
                }
            }
            function finishMaybe(stream, state) {
                var need = needFinish(state);
                if (need) {
                    prefinish(stream, state);
                    if (state.pendingcb === 0) {
                        state.finished = true;
                        stream.emit("finish");
                    }
                }
                return need;
            }
            function endWritable(stream, state, cb) {
                state.ending = true;
                finishMaybe(stream, state);
                if (cb) {
                    if (state.finished) processNextTick(cb); else stream.once("finish", cb);
                }
                state.ended = true;
                stream.writable = false;
            }
            function onCorkedFinish(corkReq, state, err) {
                var entry = corkReq.entry;
                corkReq.entry = null;
                while (entry) {
                    var cb = entry.callback;
                    state.pendingcb--;
                    cb(err);
                    entry = entry.next;
                }
                if (state.corkedRequestsFree) {
                    state.corkedRequestsFree.next = corkReq;
                } else {
                    state.corkedRequestsFree = corkReq;
                }
            }
            Object.defineProperty(Writable.prototype, "destroyed", {
                get: function() {
                    if (this._writableState === undefined) {
                        return false;
                    }
                    return this._writableState.destroyed;
                },
                set: function(value) {
                    if (!this._writableState) {
                        return;
                    }
                    this._writableState.destroyed = value;
                }
            });
            Writable.prototype.destroy = destroyImpl.destroy;
            Writable.prototype._undestroy = destroyImpl.undestroy;
            Writable.prototype._destroy = function(err, cb) {
                this.end();
                cb(err);
            };
        }).call(this, require("_process"), typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {
        "./_stream_duplex": 149,
        "./internal/streams/destroy": 155,
        "./internal/streams/stream": 156,
        _process: 140,
        "core-util-is": 59,
        inherits: 157,
        "process-nextick-args": 139,
        "safe-buffer": 163,
        "util-deprecate": 185
    } ],
    154: [ function(require, module, exports) {
        "use strict";
        function _classCallCheck(instance, Constructor) {
            if (!(instance instanceof Constructor)) {
                throw new TypeError("Cannot call a class as a function");
            }
        }
        var Buffer = require("safe-buffer").Buffer;
        function copyBuffer(src, target, offset) {
            src.copy(target, offset);
        }
        module.exports = function() {
            function BufferList() {
                _classCallCheck(this, BufferList);
                this.head = null;
                this.tail = null;
                this.length = 0;
            }
            BufferList.prototype.push = function push(v) {
                var entry = {
                    data: v,
                    next: null
                };
                if (this.length > 0) this.tail.next = entry; else this.head = entry;
                this.tail = entry;
                ++this.length;
            };
            BufferList.prototype.unshift = function unshift(v) {
                var entry = {
                    data: v,
                    next: this.head
                };
                if (this.length === 0) this.tail = entry;
                this.head = entry;
                ++this.length;
            };
            BufferList.prototype.shift = function shift() {
                if (this.length === 0) return;
                var ret = this.head.data;
                if (this.length === 1) this.head = this.tail = null; else this.head = this.head.next;
                --this.length;
                return ret;
            };
            BufferList.prototype.clear = function clear() {
                this.head = this.tail = null;
                this.length = 0;
            };
            BufferList.prototype.join = function join(s) {
                if (this.length === 0) return "";
                var p = this.head;
                var ret = "" + p.data;
                while (p = p.next) {
                    ret += s + p.data;
                }
                return ret;
            };
            BufferList.prototype.concat = function concat(n) {
                if (this.length === 0) return Buffer.alloc(0);
                if (this.length === 1) return this.head.data;
                var ret = Buffer.allocUnsafe(n >>> 0);
                var p = this.head;
                var i = 0;
                while (p) {
                    copyBuffer(p.data, ret, i);
                    i += p.data.length;
                    p = p.next;
                }
                return ret;
            };
            return BufferList;
        }();
    }, {
        "safe-buffer": 163
    } ],
    155: [ function(require, module, exports) {
        "use strict";
        var processNextTick = require("process-nextick-args");
        function destroy(err, cb) {
            var _this = this;
            var readableDestroyed = this._readableState && this._readableState.destroyed;
            var writableDestroyed = this._writableState && this._writableState.destroyed;
            if (readableDestroyed || writableDestroyed) {
                if (cb) {
                    cb(err);
                } else if (err && (!this._writableState || !this._writableState.errorEmitted)) {
                    processNextTick(emitErrorNT, this, err);
                }
                return;
            }
            if (this._readableState) {
                this._readableState.destroyed = true;
            }
            if (this._writableState) {
                this._writableState.destroyed = true;
            }
            this._destroy(err || null, function(err) {
                if (!cb && err) {
                    processNextTick(emitErrorNT, _this, err);
                    if (_this._writableState) {
                        _this._writableState.errorEmitted = true;
                    }
                } else if (cb) {
                    cb(err);
                }
            });
        }
        function undestroy() {
            if (this._readableState) {
                this._readableState.destroyed = false;
                this._readableState.reading = false;
                this._readableState.ended = false;
                this._readableState.endEmitted = false;
            }
            if (this._writableState) {
                this._writableState.destroyed = false;
                this._writableState.ended = false;
                this._writableState.ending = false;
                this._writableState.finished = false;
                this._writableState.errorEmitted = false;
            }
        }
        function emitErrorNT(self, err) {
            self.emit("error", err);
        }
        module.exports = {
            destroy: destroy,
            undestroy: undestroy
        };
    }, {
        "process-nextick-args": 139
    } ],
    156: [ function(require, module, exports) {
        module.exports = require("events").EventEmitter;
    }, {
        events: 103
    } ],
    157: [ function(require, module, exports) {
        arguments[4][118][0].apply(exports, arguments);
    }, {
        dup: 118
    } ],
    158: [ function(require, module, exports) {
        module.exports = require("./readable").PassThrough;
    }, {
        "./readable": 159
    } ],
    159: [ function(require, module, exports) {
        exports = module.exports = require("./lib/_stream_readable.js");
        exports.Stream = exports;
        exports.Readable = exports;
        exports.Writable = require("./lib/_stream_writable.js");
        exports.Duplex = require("./lib/_stream_duplex.js");
        exports.Transform = require("./lib/_stream_transform.js");
        exports.PassThrough = require("./lib/_stream_passthrough.js");
    }, {
        "./lib/_stream_duplex.js": 149,
        "./lib/_stream_passthrough.js": 150,
        "./lib/_stream_readable.js": 151,
        "./lib/_stream_transform.js": 152,
        "./lib/_stream_writable.js": 153
    } ],
    160: [ function(require, module, exports) {
        module.exports = require("./readable").Transform;
    }, {
        "./readable": 159
    } ],
    161: [ function(require, module, exports) {
        module.exports = require("./lib/_stream_writable.js");
    }, {
        "./lib/_stream_writable.js": 153
    } ],
    162: [ function(require, module, exports) {
        (function(Buffer) {
            "use strict";
            var inherits = require("inherits");
            var HashBase = require("hash-base");
            function RIPEMD160() {
                HashBase.call(this, 64);
                this._a = 1732584193;
                this._b = 4023233417;
                this._c = 2562383102;
                this._d = 271733878;
                this._e = 3285377520;
            }
            inherits(RIPEMD160, HashBase);
            RIPEMD160.prototype._update = function() {
                var m = new Array(16);
                for (var i = 0; i < 16; ++i) m[i] = this._block.readInt32LE(i * 4);
                var al = this._a;
                var bl = this._b;
                var cl = this._c;
                var dl = this._d;
                var el = this._e;
                al = fn1(al, bl, cl, dl, el, m[0], 0, 11);
                cl = rotl(cl, 10);
                el = fn1(el, al, bl, cl, dl, m[1], 0, 14);
                bl = rotl(bl, 10);
                dl = fn1(dl, el, al, bl, cl, m[2], 0, 15);
                al = rotl(al, 10);
                cl = fn1(cl, dl, el, al, bl, m[3], 0, 12);
                el = rotl(el, 10);
                bl = fn1(bl, cl, dl, el, al, m[4], 0, 5);
                dl = rotl(dl, 10);
                al = fn1(al, bl, cl, dl, el, m[5], 0, 8);
                cl = rotl(cl, 10);
                el = fn1(el, al, bl, cl, dl, m[6], 0, 7);
                bl = rotl(bl, 10);
                dl = fn1(dl, el, al, bl, cl, m[7], 0, 9);
                al = rotl(al, 10);
                cl = fn1(cl, dl, el, al, bl, m[8], 0, 11);
                el = rotl(el, 10);
                bl = fn1(bl, cl, dl, el, al, m[9], 0, 13);
                dl = rotl(dl, 10);
                al = fn1(al, bl, cl, dl, el, m[10], 0, 14);
                cl = rotl(cl, 10);
                el = fn1(el, al, bl, cl, dl, m[11], 0, 15);
                bl = rotl(bl, 10);
                dl = fn1(dl, el, al, bl, cl, m[12], 0, 6);
                al = rotl(al, 10);
                cl = fn1(cl, dl, el, al, bl, m[13], 0, 7);
                el = rotl(el, 10);
                bl = fn1(bl, cl, dl, el, al, m[14], 0, 9);
                dl = rotl(dl, 10);
                al = fn1(al, bl, cl, dl, el, m[15], 0, 8);
                cl = rotl(cl, 10);
                el = fn2(el, al, bl, cl, dl, m[7], 1518500249, 7);
                bl = rotl(bl, 10);
                dl = fn2(dl, el, al, bl, cl, m[4], 1518500249, 6);
                al = rotl(al, 10);
                cl = fn2(cl, dl, el, al, bl, m[13], 1518500249, 8);
                el = rotl(el, 10);
                bl = fn2(bl, cl, dl, el, al, m[1], 1518500249, 13);
                dl = rotl(dl, 10);
                al = fn2(al, bl, cl, dl, el, m[10], 1518500249, 11);
                cl = rotl(cl, 10);
                el = fn2(el, al, bl, cl, dl, m[6], 1518500249, 9);
                bl = rotl(bl, 10);
                dl = fn2(dl, el, al, bl, cl, m[15], 1518500249, 7);
                al = rotl(al, 10);
                cl = fn2(cl, dl, el, al, bl, m[3], 1518500249, 15);
                el = rotl(el, 10);
                bl = fn2(bl, cl, dl, el, al, m[12], 1518500249, 7);
                dl = rotl(dl, 10);
                al = fn2(al, bl, cl, dl, el, m[0], 1518500249, 12);
                cl = rotl(cl, 10);
                el = fn2(el, al, bl, cl, dl, m[9], 1518500249, 15);
                bl = rotl(bl, 10);
                dl = fn2(dl, el, al, bl, cl, m[5], 1518500249, 9);
                al = rotl(al, 10);
                cl = fn2(cl, dl, el, al, bl, m[2], 1518500249, 11);
                el = rotl(el, 10);
                bl = fn2(bl, cl, dl, el, al, m[14], 1518500249, 7);
                dl = rotl(dl, 10);
                al = fn2(al, bl, cl, dl, el, m[11], 1518500249, 13);
                cl = rotl(cl, 10);
                el = fn2(el, al, bl, cl, dl, m[8], 1518500249, 12);
                bl = rotl(bl, 10);
                dl = fn3(dl, el, al, bl, cl, m[3], 1859775393, 11);
                al = rotl(al, 10);
                cl = fn3(cl, dl, el, al, bl, m[10], 1859775393, 13);
                el = rotl(el, 10);
                bl = fn3(bl, cl, dl, el, al, m[14], 1859775393, 6);
                dl = rotl(dl, 10);
                al = fn3(al, bl, cl, dl, el, m[4], 1859775393, 7);
                cl = rotl(cl, 10);
                el = fn3(el, al, bl, cl, dl, m[9], 1859775393, 14);
                bl = rotl(bl, 10);
                dl = fn3(dl, el, al, bl, cl, m[15], 1859775393, 9);
                al = rotl(al, 10);
                cl = fn3(cl, dl, el, al, bl, m[8], 1859775393, 13);
                el = rotl(el, 10);
                bl = fn3(bl, cl, dl, el, al, m[1], 1859775393, 15);
                dl = rotl(dl, 10);
                al = fn3(al, bl, cl, dl, el, m[2], 1859775393, 14);
                cl = rotl(cl, 10);
                el = fn3(el, al, bl, cl, dl, m[7], 1859775393, 8);
                bl = rotl(bl, 10);
                dl = fn3(dl, el, al, bl, cl, m[0], 1859775393, 13);
                al = rotl(al, 10);
                cl = fn3(cl, dl, el, al, bl, m[6], 1859775393, 6);
                el = rotl(el, 10);
                bl = fn3(bl, cl, dl, el, al, m[13], 1859775393, 5);
                dl = rotl(dl, 10);
                al = fn3(al, bl, cl, dl, el, m[11], 1859775393, 12);
                cl = rotl(cl, 10);
                el = fn3(el, al, bl, cl, dl, m[5], 1859775393, 7);
                bl = rotl(bl, 10);
                dl = fn3(dl, el, al, bl, cl, m[12], 1859775393, 5);
                al = rotl(al, 10);
                cl = fn4(cl, dl, el, al, bl, m[1], 2400959708, 11);
                el = rotl(el, 10);
                bl = fn4(bl, cl, dl, el, al, m[9], 2400959708, 12);
                dl = rotl(dl, 10);
                al = fn4(al, bl, cl, dl, el, m[11], 2400959708, 14);
                cl = rotl(cl, 10);
                el = fn4(el, al, bl, cl, dl, m[10], 2400959708, 15);
                bl = rotl(bl, 10);
                dl = fn4(dl, el, al, bl, cl, m[0], 2400959708, 14);
                al = rotl(al, 10);
                cl = fn4(cl, dl, el, al, bl, m[8], 2400959708, 15);
                el = rotl(el, 10);
                bl = fn4(bl, cl, dl, el, al, m[12], 2400959708, 9);
                dl = rotl(dl, 10);
                al = fn4(al, bl, cl, dl, el, m[4], 2400959708, 8);
                cl = rotl(cl, 10);
                el = fn4(el, al, bl, cl, dl, m[13], 2400959708, 9);
                bl = rotl(bl, 10);
                dl = fn4(dl, el, al, bl, cl, m[3], 2400959708, 14);
                al = rotl(al, 10);
                cl = fn4(cl, dl, el, al, bl, m[7], 2400959708, 5);
                el = rotl(el, 10);
                bl = fn4(bl, cl, dl, el, al, m[15], 2400959708, 6);
                dl = rotl(dl, 10);
                al = fn4(al, bl, cl, dl, el, m[14], 2400959708, 8);
                cl = rotl(cl, 10);
                el = fn4(el, al, bl, cl, dl, m[5], 2400959708, 6);
                bl = rotl(bl, 10);
                dl = fn4(dl, el, al, bl, cl, m[6], 2400959708, 5);
                al = rotl(al, 10);
                cl = fn4(cl, dl, el, al, bl, m[2], 2400959708, 12);
                el = rotl(el, 10);
                bl = fn5(bl, cl, dl, el, al, m[4], 2840853838, 9);
                dl = rotl(dl, 10);
                al = fn5(al, bl, cl, dl, el, m[0], 2840853838, 15);
                cl = rotl(cl, 10);
                el = fn5(el, al, bl, cl, dl, m[5], 2840853838, 5);
                bl = rotl(bl, 10);
                dl = fn5(dl, el, al, bl, cl, m[9], 2840853838, 11);
                al = rotl(al, 10);
                cl = fn5(cl, dl, el, al, bl, m[7], 2840853838, 6);
                el = rotl(el, 10);
                bl = fn5(bl, cl, dl, el, al, m[12], 2840853838, 8);
                dl = rotl(dl, 10);
                al = fn5(al, bl, cl, dl, el, m[2], 2840853838, 13);
                cl = rotl(cl, 10);
                el = fn5(el, al, bl, cl, dl, m[10], 2840853838, 12);
                bl = rotl(bl, 10);
                dl = fn5(dl, el, al, bl, cl, m[14], 2840853838, 5);
                al = rotl(al, 10);
                cl = fn5(cl, dl, el, al, bl, m[1], 2840853838, 12);
                el = rotl(el, 10);
                bl = fn5(bl, cl, dl, el, al, m[3], 2840853838, 13);
                dl = rotl(dl, 10);
                al = fn5(al, bl, cl, dl, el, m[8], 2840853838, 14);
                cl = rotl(cl, 10);
                el = fn5(el, al, bl, cl, dl, m[11], 2840853838, 11);
                bl = rotl(bl, 10);
                dl = fn5(dl, el, al, bl, cl, m[6], 2840853838, 8);
                al = rotl(al, 10);
                cl = fn5(cl, dl, el, al, bl, m[15], 2840853838, 5);
                el = rotl(el, 10);
                bl = fn5(bl, cl, dl, el, al, m[13], 2840853838, 6);
                dl = rotl(dl, 10);
                var ar = this._a;
                var br = this._b;
                var cr = this._c;
                var dr = this._d;
                var er = this._e;
                ar = fn5(ar, br, cr, dr, er, m[5], 1352829926, 8);
                cr = rotl(cr, 10);
                er = fn5(er, ar, br, cr, dr, m[14], 1352829926, 9);
                br = rotl(br, 10);
                dr = fn5(dr, er, ar, br, cr, m[7], 1352829926, 9);
                ar = rotl(ar, 10);
                cr = fn5(cr, dr, er, ar, br, m[0], 1352829926, 11);
                er = rotl(er, 10);
                br = fn5(br, cr, dr, er, ar, m[9], 1352829926, 13);
                dr = rotl(dr, 10);
                ar = fn5(ar, br, cr, dr, er, m[2], 1352829926, 15);
                cr = rotl(cr, 10);
                er = fn5(er, ar, br, cr, dr, m[11], 1352829926, 15);
                br = rotl(br, 10);
                dr = fn5(dr, er, ar, br, cr, m[4], 1352829926, 5);
                ar = rotl(ar, 10);
                cr = fn5(cr, dr, er, ar, br, m[13], 1352829926, 7);
                er = rotl(er, 10);
                br = fn5(br, cr, dr, er, ar, m[6], 1352829926, 7);
                dr = rotl(dr, 10);
                ar = fn5(ar, br, cr, dr, er, m[15], 1352829926, 8);
                cr = rotl(cr, 10);
                er = fn5(er, ar, br, cr, dr, m[8], 1352829926, 11);
                br = rotl(br, 10);
                dr = fn5(dr, er, ar, br, cr, m[1], 1352829926, 14);
                ar = rotl(ar, 10);
                cr = fn5(cr, dr, er, ar, br, m[10], 1352829926, 14);
                er = rotl(er, 10);
                br = fn5(br, cr, dr, er, ar, m[3], 1352829926, 12);
                dr = rotl(dr, 10);
                ar = fn5(ar, br, cr, dr, er, m[12], 1352829926, 6);
                cr = rotl(cr, 10);
                er = fn4(er, ar, br, cr, dr, m[6], 1548603684, 9);
                br = rotl(br, 10);
                dr = fn4(dr, er, ar, br, cr, m[11], 1548603684, 13);
                ar = rotl(ar, 10);
                cr = fn4(cr, dr, er, ar, br, m[3], 1548603684, 15);
                er = rotl(er, 10);
                br = fn4(br, cr, dr, er, ar, m[7], 1548603684, 7);
                dr = rotl(dr, 10);
                ar = fn4(ar, br, cr, dr, er, m[0], 1548603684, 12);
                cr = rotl(cr, 10);
                er = fn4(er, ar, br, cr, dr, m[13], 1548603684, 8);
                br = rotl(br, 10);
                dr = fn4(dr, er, ar, br, cr, m[5], 1548603684, 9);
                ar = rotl(ar, 10);
                cr = fn4(cr, dr, er, ar, br, m[10], 1548603684, 11);
                er = rotl(er, 10);
                br = fn4(br, cr, dr, er, ar, m[14], 1548603684, 7);
                dr = rotl(dr, 10);
                ar = fn4(ar, br, cr, dr, er, m[15], 1548603684, 7);
                cr = rotl(cr, 10);
                er = fn4(er, ar, br, cr, dr, m[8], 1548603684, 12);
                br = rotl(br, 10);
                dr = fn4(dr, er, ar, br, cr, m[12], 1548603684, 7);
                ar = rotl(ar, 10);
                cr = fn4(cr, dr, er, ar, br, m[4], 1548603684, 6);
                er = rotl(er, 10);
                br = fn4(br, cr, dr, er, ar, m[9], 1548603684, 15);
                dr = rotl(dr, 10);
                ar = fn4(ar, br, cr, dr, er, m[1], 1548603684, 13);
                cr = rotl(cr, 10);
                er = fn4(er, ar, br, cr, dr, m[2], 1548603684, 11);
                br = rotl(br, 10);
                dr = fn3(dr, er, ar, br, cr, m[15], 1836072691, 9);
                ar = rotl(ar, 10);
                cr = fn3(cr, dr, er, ar, br, m[5], 1836072691, 7);
                er = rotl(er, 10);
                br = fn3(br, cr, dr, er, ar, m[1], 1836072691, 15);
                dr = rotl(dr, 10);
                ar = fn3(ar, br, cr, dr, er, m[3], 1836072691, 11);
                cr = rotl(cr, 10);
                er = fn3(er, ar, br, cr, dr, m[7], 1836072691, 8);
                br = rotl(br, 10);
                dr = fn3(dr, er, ar, br, cr, m[14], 1836072691, 6);
                ar = rotl(ar, 10);
                cr = fn3(cr, dr, er, ar, br, m[6], 1836072691, 6);
                er = rotl(er, 10);
                br = fn3(br, cr, dr, er, ar, m[9], 1836072691, 14);
                dr = rotl(dr, 10);
                ar = fn3(ar, br, cr, dr, er, m[11], 1836072691, 12);
                cr = rotl(cr, 10);
                er = fn3(er, ar, br, cr, dr, m[8], 1836072691, 13);
                br = rotl(br, 10);
                dr = fn3(dr, er, ar, br, cr, m[12], 1836072691, 5);
                ar = rotl(ar, 10);
                cr = fn3(cr, dr, er, ar, br, m[2], 1836072691, 14);
                er = rotl(er, 10);
                br = fn3(br, cr, dr, er, ar, m[10], 1836072691, 13);
                dr = rotl(dr, 10);
                ar = fn3(ar, br, cr, dr, er, m[0], 1836072691, 13);
                cr = rotl(cr, 10);
                er = fn3(er, ar, br, cr, dr, m[4], 1836072691, 7);
                br = rotl(br, 10);
                dr = fn3(dr, er, ar, br, cr, m[13], 1836072691, 5);
                ar = rotl(ar, 10);
                cr = fn2(cr, dr, er, ar, br, m[8], 2053994217, 15);
                er = rotl(er, 10);
                br = fn2(br, cr, dr, er, ar, m[6], 2053994217, 5);
                dr = rotl(dr, 10);
                ar = fn2(ar, br, cr, dr, er, m[4], 2053994217, 8);
                cr = rotl(cr, 10);
                er = fn2(er, ar, br, cr, dr, m[1], 2053994217, 11);
                br = rotl(br, 10);
                dr = fn2(dr, er, ar, br, cr, m[3], 2053994217, 14);
                ar = rotl(ar, 10);
                cr = fn2(cr, dr, er, ar, br, m[11], 2053994217, 14);
                er = rotl(er, 10);
                br = fn2(br, cr, dr, er, ar, m[15], 2053994217, 6);
                dr = rotl(dr, 10);
                ar = fn2(ar, br, cr, dr, er, m[0], 2053994217, 14);
                cr = rotl(cr, 10);
                er = fn2(er, ar, br, cr, dr, m[5], 2053994217, 6);
                br = rotl(br, 10);
                dr = fn2(dr, er, ar, br, cr, m[12], 2053994217, 9);
                ar = rotl(ar, 10);
                cr = fn2(cr, dr, er, ar, br, m[2], 2053994217, 12);
                er = rotl(er, 10);
                br = fn2(br, cr, dr, er, ar, m[13], 2053994217, 9);
                dr = rotl(dr, 10);
                ar = fn2(ar, br, cr, dr, er, m[9], 2053994217, 12);
                cr = rotl(cr, 10);
                er = fn2(er, ar, br, cr, dr, m[7], 2053994217, 5);
                br = rotl(br, 10);
                dr = fn2(dr, er, ar, br, cr, m[10], 2053994217, 15);
                ar = rotl(ar, 10);
                cr = fn2(cr, dr, er, ar, br, m[14], 2053994217, 8);
                er = rotl(er, 10);
                br = fn1(br, cr, dr, er, ar, m[12], 0, 8);
                dr = rotl(dr, 10);
                ar = fn1(ar, br, cr, dr, er, m[15], 0, 5);
                cr = rotl(cr, 10);
                er = fn1(er, ar, br, cr, dr, m[10], 0, 12);
                br = rotl(br, 10);
                dr = fn1(dr, er, ar, br, cr, m[4], 0, 9);
                ar = rotl(ar, 10);
                cr = fn1(cr, dr, er, ar, br, m[1], 0, 12);
                er = rotl(er, 10);
                br = fn1(br, cr, dr, er, ar, m[5], 0, 5);
                dr = rotl(dr, 10);
                ar = fn1(ar, br, cr, dr, er, m[8], 0, 14);
                cr = rotl(cr, 10);
                er = fn1(er, ar, br, cr, dr, m[7], 0, 6);
                br = rotl(br, 10);
                dr = fn1(dr, er, ar, br, cr, m[6], 0, 8);
                ar = rotl(ar, 10);
                cr = fn1(cr, dr, er, ar, br, m[2], 0, 13);
                er = rotl(er, 10);
                br = fn1(br, cr, dr, er, ar, m[13], 0, 6);
                dr = rotl(dr, 10);
                ar = fn1(ar, br, cr, dr, er, m[14], 0, 5);
                cr = rotl(cr, 10);
                er = fn1(er, ar, br, cr, dr, m[0], 0, 15);
                br = rotl(br, 10);
                dr = fn1(dr, er, ar, br, cr, m[3], 0, 13);
                ar = rotl(ar, 10);
                cr = fn1(cr, dr, er, ar, br, m[9], 0, 11);
                er = rotl(er, 10);
                br = fn1(br, cr, dr, er, ar, m[11], 0, 11);
                dr = rotl(dr, 10);
                var t = this._b + cl + dr | 0;
                this._b = this._c + dl + er | 0;
                this._c = this._d + el + ar | 0;
                this._d = this._e + al + br | 0;
                this._e = this._a + bl + cr | 0;
                this._a = t;
            };
            RIPEMD160.prototype._digest = function() {
                this._block[this._blockOffset++] = 128;
                if (this._blockOffset > 56) {
                    this._block.fill(0, this._blockOffset, 64);
                    this._update();
                    this._blockOffset = 0;
                }
                this._block.fill(0, this._blockOffset, 56);
                this._block.writeUInt32LE(this._length[0], 56);
                this._block.writeUInt32LE(this._length[1], 60);
                this._update();
                var buffer = new Buffer(20);
                buffer.writeInt32LE(this._a, 0);
                buffer.writeInt32LE(this._b, 4);
                buffer.writeInt32LE(this._c, 8);
                buffer.writeInt32LE(this._d, 12);
                buffer.writeInt32LE(this._e, 16);
                return buffer;
            };
            function rotl(x, n) {
                return x << n | x >>> 32 - n;
            }
            function fn1(a, b, c, d, e, m, k, s) {
                return rotl(a + (b ^ c ^ d) + m + k | 0, s) + e | 0;
            }
            function fn2(a, b, c, d, e, m, k, s) {
                return rotl(a + (b & c | ~b & d) + m + k | 0, s) + e | 0;
            }
            function fn3(a, b, c, d, e, m, k, s) {
                return rotl(a + ((b | ~c) ^ d) + m + k | 0, s) + e | 0;
            }
            function fn4(a, b, c, d, e, m, k, s) {
                return rotl(a + (b & d | c & ~d) + m + k | 0, s) + e | 0;
            }
            function fn5(a, b, c, d, e, m, k, s) {
                return rotl(a + (b ^ (c | ~d)) + m + k | 0, s) + e | 0;
            }
            module.exports = RIPEMD160;
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54,
        "hash-base": 105,
        inherits: 122
    } ],
    163: [ function(require, module, exports) {
        var buffer = require("buffer");
        var Buffer = buffer.Buffer;
        function copyProps(src, dst) {
            for (var key in src) {
                dst[key] = src[key];
            }
        }
        if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
            module.exports = buffer;
        } else {
            copyProps(buffer, exports);
            exports.Buffer = SafeBuffer;
        }
        function SafeBuffer(arg, encodingOrOffset, length) {
            return Buffer(arg, encodingOrOffset, length);
        }
        copyProps(Buffer, SafeBuffer);
        SafeBuffer.from = function(arg, encodingOrOffset, length) {
            if (typeof arg === "number") {
                throw new TypeError("Argument must not be a number");
            }
            return Buffer(arg, encodingOrOffset, length);
        };
        SafeBuffer.alloc = function(size, fill, encoding) {
            if (typeof size !== "number") {
                throw new TypeError("Argument must be a number");
            }
            var buf = Buffer(size);
            if (fill !== undefined) {
                if (typeof encoding === "string") {
                    buf.fill(fill, encoding);
                } else {
                    buf.fill(fill);
                }
            } else {
                buf.fill(0);
            }
            return buf;
        };
        SafeBuffer.allocUnsafe = function(size) {
            if (typeof size !== "number") {
                throw new TypeError("Argument must be a number");
            }
            return Buffer(size);
        };
        SafeBuffer.allocUnsafeSlow = function(size) {
            if (typeof size !== "number") {
                throw new TypeError("Argument must be a number");
            }
            return buffer.SlowBuffer(size);
        };
    }, {
        buffer: 54
    } ],
    164: [ function(require, module, exports) {
        "use strict";
        module.exports = require("./lib")(require("./lib/elliptic"));
    }, {
        "./lib": 168,
        "./lib/elliptic": 167
    } ],
    165: [ function(require, module, exports) {
        (function(Buffer) {
            "use strict";
            var toString = Object.prototype.toString;
            exports.isArray = function(value, message) {
                if (!Array.isArray(value)) throw TypeError(message);
            };
            exports.isBoolean = function(value, message) {
                if (toString.call(value) !== "[object Boolean]") throw TypeError(message);
            };
            exports.isBuffer = function(value, message) {
                if (!Buffer.isBuffer(value)) throw TypeError(message);
            };
            exports.isFunction = function(value, message) {
                if (toString.call(value) !== "[object Function]") throw TypeError(message);
            };
            exports.isNumber = function(value, message) {
                if (toString.call(value) !== "[object Number]") throw TypeError(message);
            };
            exports.isObject = function(value, message) {
                if (toString.call(value) !== "[object Object]") throw TypeError(message);
            };
            exports.isBufferLength = function(buffer, length, message) {
                if (buffer.length !== length) throw RangeError(message);
            };
            exports.isBufferLength2 = function(buffer, length1, length2, message) {
                if (buffer.length !== length1 && buffer.length !== length2) throw RangeError(message);
            };
            exports.isLengthGTZero = function(value, message) {
                if (value.length === 0) throw RangeError(message);
            };
            exports.isNumberInInterval = function(number, x, y, message) {
                if (number <= x || number >= y) throw RangeError(message);
            };
        }).call(this, {
            isBuffer: require("../../is-buffer/index.js")
        });
    }, {
        "../../is-buffer/index.js": 123
    } ],
    166: [ function(require, module, exports) {
        "use strict";
        var Buffer = require("safe-buffer").Buffer;
        var bip66 = require("bip66");
        var EC_PRIVKEY_EXPORT_DER_COMPRESSED = Buffer.from([ 48, 129, 211, 2, 1, 1, 4, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 129, 133, 48, 129, 130, 2, 1, 1, 48, 44, 6, 7, 42, 134, 72, 206, 61, 1, 1, 2, 33, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47, 48, 6, 4, 1, 0, 4, 1, 7, 4, 33, 2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152, 2, 33, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65, 2, 1, 1, 161, 36, 3, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]);
        var EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED = Buffer.from([ 48, 130, 1, 19, 2, 1, 1, 4, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 129, 165, 48, 129, 162, 2, 1, 1, 48, 44, 6, 7, 42, 134, 72, 206, 61, 1, 1, 2, 33, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47, 48, 6, 4, 1, 0, 4, 1, 7, 4, 65, 4, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152, 72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184, 2, 33, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65, 2, 1, 1, 161, 68, 3, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]);
        var ZERO_BUFFER_32 = Buffer.from([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]);
        exports.privateKeyExport = function(privateKey, publicKey, compressed) {
            var result = Buffer.from(compressed ? EC_PRIVKEY_EXPORT_DER_COMPRESSED : EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED);
            privateKey.copy(result, compressed ? 8 : 9);
            publicKey.copy(result, compressed ? 181 : 214);
            return result;
        };
        exports.privateKeyImport = function(privateKey) {
            var length = privateKey.length;
            var index = 0;
            if (length < index + 1 || privateKey[index] !== 48) return;
            index += 1;
            if (length < index + 1 || !(privateKey[index] & 128)) return;
            var lenb = privateKey[index] & 127;
            index += 1;
            if (lenb < 1 || lenb > 2) return;
            if (length < index + lenb) return;
            var len = privateKey[index + lenb - 1] | (lenb > 1 ? privateKey[index + lenb - 2] << 8 : 0);
            index += lenb;
            if (length < index + len) return;
            if (length < index + 3 || privateKey[index] !== 2 || privateKey[index + 1] !== 1 || privateKey[index + 2] !== 1) {
                return;
            }
            index += 3;
            if (length < index + 2 || privateKey[index] !== 4 || privateKey[index + 1] > 32 || length < index + 2 + privateKey[index + 1]) {
                return;
            }
            return privateKey.slice(index + 2, index + 2 + privateKey[index + 1]);
        };
        exports.signatureExport = function(sigObj) {
            var r = Buffer.concat([ Buffer.from([ 0 ]), sigObj.r ]);
            for (var lenR = 33, posR = 0; lenR > 1 && r[posR] === 0 && !(r[posR + 1] & 128); --lenR, 
            ++posR) ;
            var s = Buffer.concat([ Buffer.from([ 0 ]), sigObj.s ]);
            for (var lenS = 33, posS = 0; lenS > 1 && s[posS] === 0 && !(s[posS + 1] & 128); --lenS, 
            ++posS) ;
            return bip66.encode(r.slice(posR), s.slice(posS));
        };
        exports.signatureImport = function(sig) {
            var r = Buffer.from(ZERO_BUFFER_32);
            var s = Buffer.from(ZERO_BUFFER_32);
            try {
                var sigObj = bip66.decode(sig);
                if (sigObj.r.length === 33 && sigObj.r[0] === 0) sigObj.r = sigObj.r.slice(1);
                if (sigObj.r.length > 32) throw new Error("R length is too long");
                if (sigObj.s.length === 33 && sigObj.s[0] === 0) sigObj.s = sigObj.s.slice(1);
                if (sigObj.s.length > 32) throw new Error("S length is too long");
            } catch (err) {
                return;
            }
            sigObj.r.copy(r, 32 - sigObj.r.length);
            sigObj.s.copy(s, 32 - sigObj.s.length);
            return {
                r: r,
                s: s
            };
        };
        exports.signatureImportLax = function(sig) {
            var r = Buffer.from(ZERO_BUFFER_32);
            var s = Buffer.from(ZERO_BUFFER_32);
            var length = sig.length;
            var index = 0;
            if (sig[index++] !== 48) return;
            var lenbyte = sig[index++];
            if (lenbyte & 128) {
                index += lenbyte - 128;
                if (index > length) return;
            }
            if (sig[index++] !== 2) return;
            var rlen = sig[index++];
            if (rlen & 128) {
                lenbyte = rlen - 128;
                if (index + lenbyte > length) return;
                for (;lenbyte > 0 && sig[index] === 0; index += 1, lenbyte -= 1) ;
                for (rlen = 0; lenbyte > 0; index += 1, lenbyte -= 1) rlen = (rlen << 8) + sig[index];
            }
            if (rlen > length - index) return;
            var rindex = index;
            index += rlen;
            if (sig[index++] !== 2) return;
            var slen = sig[index++];
            if (slen & 128) {
                lenbyte = slen - 128;
                if (index + lenbyte > length) return;
                for (;lenbyte > 0 && sig[index] === 0; index += 1, lenbyte -= 1) ;
                for (slen = 0; lenbyte > 0; index += 1, lenbyte -= 1) slen = (slen << 8) + sig[index];
            }
            if (slen > length - index) return;
            var sindex = index;
            index += slen;
            for (;rlen > 0 && sig[rindex] === 0; rlen -= 1, rindex += 1) ;
            if (rlen > 32) return;
            var rvalue = sig.slice(rindex, rindex + rlen);
            rvalue.copy(r, 32 - rvalue.length);
            for (;slen > 0 && sig[sindex] === 0; slen -= 1, sindex += 1) ;
            if (slen > 32) return;
            var svalue = sig.slice(sindex, sindex + slen);
            svalue.copy(s, 32 - svalue.length);
            return {
                r: r,
                s: s
            };
        };
    }, {
        bip66: 22,
        "safe-buffer": 163
    } ],
    167: [ function(require, module, exports) {
        "use strict";
        var Buffer = require("safe-buffer").Buffer;
        var createHash = require("create-hash");
        var BN = require("bn.js");
        var EC = require("elliptic").ec;
        var messages = require("../messages.json");
        var ec = new EC("secp256k1");
        var ecparams = ec.curve;
        function loadCompressedPublicKey(first, xBuffer) {
            var x = new BN(xBuffer);
            if (x.cmp(ecparams.p) >= 0) return null;
            x = x.toRed(ecparams.red);
            var y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt();
            if (first === 3 !== y.isOdd()) y = y.redNeg();
            return ec.keyPair({
                pub: {
                    x: x,
                    y: y
                }
            });
        }
        function loadUncompressedPublicKey(first, xBuffer, yBuffer) {
            var x = new BN(xBuffer);
            var y = new BN(yBuffer);
            if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) return null;
            x = x.toRed(ecparams.red);
            y = y.toRed(ecparams.red);
            if ((first === 6 || first === 7) && y.isOdd() !== (first === 7)) return null;
            var x3 = x.redSqr().redIMul(x);
            if (!y.redSqr().redISub(x3.redIAdd(ecparams.b)).isZero()) return null;
            return ec.keyPair({
                pub: {
                    x: x,
                    y: y
                }
            });
        }
        function loadPublicKey(publicKey) {
            var first = publicKey[0];
            switch (first) {
              case 2:
              case 3:
                if (publicKey.length !== 33) return null;
                return loadCompressedPublicKey(first, publicKey.slice(1, 33));

              case 4:
              case 6:
              case 7:
                if (publicKey.length !== 65) return null;
                return loadUncompressedPublicKey(first, publicKey.slice(1, 33), publicKey.slice(33, 65));

              default:
                return null;
            }
        }
        exports.privateKeyVerify = function(privateKey) {
            var bn = new BN(privateKey);
            return bn.cmp(ecparams.n) < 0 && !bn.isZero();
        };
        exports.privateKeyExport = function(privateKey, compressed) {
            var d = new BN(privateKey);
            if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL);
            return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true));
        };
        exports.privateKeyTweakAdd = function(privateKey, tweak) {
            var bn = new BN(tweak);
            if (bn.cmp(ecparams.n) >= 0) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL);
            bn.iadd(new BN(privateKey));
            if (bn.cmp(ecparams.n) >= 0) bn.isub(ecparams.n);
            if (bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL);
            return bn.toArrayLike(Buffer, "be", 32);
        };
        exports.privateKeyTweakMul = function(privateKey, tweak) {
            var bn = new BN(tweak);
            if (bn.cmp(ecparams.n) >= 0 || bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL);
            bn.imul(new BN(privateKey));
            if (bn.cmp(ecparams.n)) bn = bn.umod(ecparams.n);
            return bn.toArrayLike(Buffer, "be", 32);
        };
        exports.publicKeyCreate = function(privateKey, compressed) {
            var d = new BN(privateKey);
            if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL);
            return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true));
        };
        exports.publicKeyConvert = function(publicKey, compressed) {
            var pair = loadPublicKey(publicKey);
            if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL);
            return Buffer.from(pair.getPublic(compressed, true));
        };
        exports.publicKeyVerify = function(publicKey) {
            return loadPublicKey(publicKey) !== null;
        };
        exports.publicKeyTweakAdd = function(publicKey, tweak, compressed) {
            var pair = loadPublicKey(publicKey);
            if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL);
            tweak = new BN(tweak);
            if (tweak.cmp(ecparams.n) >= 0) throw new Error(messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL);
            return Buffer.from(ecparams.g.mul(tweak).add(pair.pub).encode(true, compressed));
        };
        exports.publicKeyTweakMul = function(publicKey, tweak, compressed) {
            var pair = loadPublicKey(publicKey);
            if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL);
            tweak = new BN(tweak);
            if (tweak.cmp(ecparams.n) >= 0 || tweak.isZero()) throw new Error(messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL);
            return Buffer.from(pair.pub.mul(tweak).encode(true, compressed));
        };
        exports.publicKeyCombine = function(publicKeys, compressed) {
            var pairs = new Array(publicKeys.length);
            for (var i = 0; i < publicKeys.length; ++i) {
                pairs[i] = loadPublicKey(publicKeys[i]);
                if (pairs[i] === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL);
            }
            var point = pairs[0].pub;
            for (var j = 1; j < pairs.length; ++j) point = point.add(pairs[j].pub);
            if (point.isInfinity()) throw new Error(messages.EC_PUBLIC_KEY_COMBINE_FAIL);
            return Buffer.from(point.encode(true, compressed));
        };
        exports.signatureNormalize = function(signature) {
            var r = new BN(signature.slice(0, 32));
            var s = new BN(signature.slice(32, 64));
            if (r.cmp(ecparams.n) >= 0 || s.cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL);
            var result = Buffer.from(signature);
            if (s.cmp(ec.nh) === 1) ecparams.n.sub(s).toArrayLike(Buffer, "be", 32).copy(result, 32);
            return result;
        };
        exports.signatureExport = function(signature) {
            var r = signature.slice(0, 32);
            var s = signature.slice(32, 64);
            if (new BN(r).cmp(ecparams.n) >= 0 || new BN(s).cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL);
            return {
                r: r,
                s: s
            };
        };
        exports.signatureImport = function(sigObj) {
            var r = new BN(sigObj.r);
            if (r.cmp(ecparams.n) >= 0) r = new BN(0);
            var s = new BN(sigObj.s);
            if (s.cmp(ecparams.n) >= 0) s = new BN(0);
            return Buffer.concat([ r.toArrayLike(Buffer, "be", 32), s.toArrayLike(Buffer, "be", 32) ]);
        };
        exports.sign = function(message, privateKey, noncefn, data) {
            if (typeof noncefn === "function") {
                var getNonce = noncefn;
                noncefn = function(counter) {
                    var nonce = getNonce(message, privateKey, null, data, counter);
                    if (!Buffer.isBuffer(nonce) || nonce.length !== 32) throw new Error(messages.ECDSA_SIGN_FAIL);
                    return new BN(nonce);
                };
            }
            var d = new BN(privateKey);
            if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.ECDSA_SIGN_FAIL);
            var result = ec.sign(message, privateKey, {
                canonical: true,
                k: noncefn,
                pers: data
            });
            return {
                signature: Buffer.concat([ result.r.toArrayLike(Buffer, "be", 32), result.s.toArrayLike(Buffer, "be", 32) ]),
                recovery: result.recoveryParam
            };
        };
        exports.verify = function(message, signature, publicKey) {
            var sigObj = {
                r: signature.slice(0, 32),
                s: signature.slice(32, 64)
            };
            var sigr = new BN(sigObj.r);
            var sigs = new BN(sigObj.s);
            if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL);
            if (sigs.cmp(ec.nh) === 1 || sigr.isZero() || sigs.isZero()) return false;
            var pair = loadPublicKey(publicKey);
            if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL);
            return ec.verify(message, sigObj, {
                x: pair.pub.x,
                y: pair.pub.y
            });
        };
        exports.recover = function(message, signature, recovery, compressed) {
            var sigObj = {
                r: signature.slice(0, 32),
                s: signature.slice(32, 64)
            };
            var sigr = new BN(sigObj.r);
            var sigs = new BN(sigObj.s);
            if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL);
            try {
                if (sigr.isZero() || sigs.isZero()) throw new Error();
                var point = ec.recoverPubKey(message, sigObj, recovery);
                return Buffer.from(point.encode(true, compressed));
            } catch (err) {
                throw new Error(messages.ECDSA_RECOVER_FAIL);
            }
        };
        exports.ecdh = function(publicKey, privateKey) {
            var shared = exports.ecdhUnsafe(publicKey, privateKey, true);
            return createHash("sha256").update(shared).digest();
        };
        exports.ecdhUnsafe = function(publicKey, privateKey, compressed) {
            var pair = loadPublicKey(publicKey);
            if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL);
            var scalar = new BN(privateKey);
            if (scalar.cmp(ecparams.n) >= 0 || scalar.isZero()) throw new Error(messages.ECDH_FAIL);
            return Buffer.from(pair.pub.mul(scalar).encode(true, compressed));
        };
    }, {
        "../messages.json": 169,
        "bn.js": 23,
        "create-hash": 61,
        elliptic: 87,
        "safe-buffer": 163
    } ],
    168: [ function(require, module, exports) {
        "use strict";
        var assert = require("./assert");
        var der = require("./der");
        var messages = require("./messages.json");
        function initCompressedValue(value, defaultValue) {
            if (value === undefined) return defaultValue;
            assert.isBoolean(value, messages.COMPRESSED_TYPE_INVALID);
            return value;
        }
        module.exports = function(secp256k1) {
            return {
                privateKeyVerify: function(privateKey) {
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    return privateKey.length === 32 && secp256k1.privateKeyVerify(privateKey);
                },
                privateKeyExport: function(privateKey, compressed) {
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    var publicKey = secp256k1.privateKeyExport(privateKey, compressed);
                    return der.privateKeyExport(privateKey, publicKey, compressed);
                },
                privateKeyImport: function(privateKey) {
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    privateKey = der.privateKeyImport(privateKey);
                    if (privateKey && privateKey.length === 32 && secp256k1.privateKeyVerify(privateKey)) return privateKey;
                    throw new Error(messages.EC_PRIVATE_KEY_IMPORT_DER_FAIL);
                },
                privateKeyTweakAdd: function(privateKey, tweak) {
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID);
                    assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID);
                    return secp256k1.privateKeyTweakAdd(privateKey, tweak);
                },
                privateKeyTweakMul: function(privateKey, tweak) {
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID);
                    assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID);
                    return secp256k1.privateKeyTweakMul(privateKey, tweak);
                },
                publicKeyCreate: function(privateKey, compressed) {
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.publicKeyCreate(privateKey, compressed);
                },
                publicKeyConvert: function(publicKey, compressed) {
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.publicKeyConvert(publicKey, compressed);
                },
                publicKeyVerify: function(publicKey) {
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    return secp256k1.publicKeyVerify(publicKey);
                },
                publicKeyTweakAdd: function(publicKey, tweak, compressed) {
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID);
                    assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.publicKeyTweakAdd(publicKey, tweak, compressed);
                },
                publicKeyTweakMul: function(publicKey, tweak, compressed) {
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID);
                    assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.publicKeyTweakMul(publicKey, tweak, compressed);
                },
                publicKeyCombine: function(publicKeys, compressed) {
                    assert.isArray(publicKeys, messages.EC_PUBLIC_KEYS_TYPE_INVALID);
                    assert.isLengthGTZero(publicKeys, messages.EC_PUBLIC_KEYS_LENGTH_INVALID);
                    for (var i = 0; i < publicKeys.length; ++i) {
                        assert.isBuffer(publicKeys[i], messages.EC_PUBLIC_KEY_TYPE_INVALID);
                        assert.isBufferLength2(publicKeys[i], 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    }
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.publicKeyCombine(publicKeys, compressed);
                },
                signatureNormalize: function(signature) {
                    assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID);
                    assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID);
                    return secp256k1.signatureNormalize(signature);
                },
                signatureExport: function(signature) {
                    assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID);
                    assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID);
                    var sigObj = secp256k1.signatureExport(signature);
                    return der.signatureExport(sigObj);
                },
                signatureImport: function(sig) {
                    assert.isBuffer(sig, messages.ECDSA_SIGNATURE_TYPE_INVALID);
                    assert.isLengthGTZero(sig, messages.ECDSA_SIGNATURE_LENGTH_INVALID);
                    var sigObj = der.signatureImport(sig);
                    if (sigObj) return secp256k1.signatureImport(sigObj);
                    throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL);
                },
                signatureImportLax: function(sig) {
                    assert.isBuffer(sig, messages.ECDSA_SIGNATURE_TYPE_INVALID);
                    assert.isLengthGTZero(sig, messages.ECDSA_SIGNATURE_LENGTH_INVALID);
                    var sigObj = der.signatureImportLax(sig);
                    if (sigObj) return secp256k1.signatureImport(sigObj);
                    throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL);
                },
                sign: function(message, privateKey, options) {
                    assert.isBuffer(message, messages.MSG32_TYPE_INVALID);
                    assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID);
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    var data = null;
                    var noncefn = null;
                    if (options !== undefined) {
                        assert.isObject(options, messages.OPTIONS_TYPE_INVALID);
                        if (options.data !== undefined) {
                            assert.isBuffer(options.data, messages.OPTIONS_DATA_TYPE_INVALID);
                            assert.isBufferLength(options.data, 32, messages.OPTIONS_DATA_LENGTH_INVALID);
                            data = options.data;
                        }
                        if (options.noncefn !== undefined) {
                            assert.isFunction(options.noncefn, messages.OPTIONS_NONCEFN_TYPE_INVALID);
                            noncefn = options.noncefn;
                        }
                    }
                    return secp256k1.sign(message, privateKey, noncefn, data);
                },
                verify: function(message, signature, publicKey) {
                    assert.isBuffer(message, messages.MSG32_TYPE_INVALID);
                    assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID);
                    assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID);
                    assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID);
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    return secp256k1.verify(message, signature, publicKey);
                },
                recover: function(message, signature, recovery, compressed) {
                    assert.isBuffer(message, messages.MSG32_TYPE_INVALID);
                    assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID);
                    assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID);
                    assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID);
                    assert.isNumber(recovery, messages.RECOVERY_ID_TYPE_INVALID);
                    assert.isNumberInInterval(recovery, -1, 4, messages.RECOVERY_ID_VALUE_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.recover(message, signature, recovery, compressed);
                },
                ecdh: function(publicKey, privateKey) {
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    return secp256k1.ecdh(publicKey, privateKey);
                },
                ecdhUnsafe: function(publicKey, privateKey, compressed) {
                    assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID);
                    assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID);
                    assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID);
                    assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID);
                    compressed = initCompressedValue(compressed, true);
                    return secp256k1.ecdhUnsafe(publicKey, privateKey, compressed);
                }
            };
        };
    }, {
        "./assert": 165,
        "./der": 166,
        "./messages.json": 169
    } ],
    169: [ function(require, module, exports) {
        module.exports = {
            COMPRESSED_TYPE_INVALID: "compressed should be a boolean",
            EC_PRIVATE_KEY_TYPE_INVALID: "private key should be a Buffer",
            EC_PRIVATE_KEY_LENGTH_INVALID: "private key length is invalid",
            EC_PRIVATE_KEY_TWEAK_ADD_FAIL: "tweak out of range or resulting private key is invalid",
            EC_PRIVATE_KEY_TWEAK_MUL_FAIL: "tweak out of range",
            EC_PRIVATE_KEY_EXPORT_DER_FAIL: "couldn't export to DER format",
            EC_PRIVATE_KEY_IMPORT_DER_FAIL: "couldn't import from DER format",
            EC_PUBLIC_KEYS_TYPE_INVALID: "public keys should be an Array",
            EC_PUBLIC_KEYS_LENGTH_INVALID: "public keys Array should have at least 1 element",
            EC_PUBLIC_KEY_TYPE_INVALID: "public key should be a Buffer",
            EC_PUBLIC_KEY_LENGTH_INVALID: "public key length is invalid",
            EC_PUBLIC_KEY_PARSE_FAIL: "the public key could not be parsed or is invalid",
            EC_PUBLIC_KEY_CREATE_FAIL: "private was invalid, try again",
            EC_PUBLIC_KEY_TWEAK_ADD_FAIL: "tweak out of range or resulting public key is invalid",
            EC_PUBLIC_KEY_TWEAK_MUL_FAIL: "tweak out of range",
            EC_PUBLIC_KEY_COMBINE_FAIL: "the sum of the public keys is not valid",
            ECDH_FAIL: "scalar was invalid (zero or overflow)",
            ECDSA_SIGNATURE_TYPE_INVALID: "signature should be a Buffer",
            ECDSA_SIGNATURE_LENGTH_INVALID: "signature length is invalid",
            ECDSA_SIGNATURE_PARSE_FAIL: "couldn't parse signature",
            ECDSA_SIGNATURE_PARSE_DER_FAIL: "couldn't parse DER signature",
            ECDSA_SIGNATURE_SERIALIZE_DER_FAIL: "couldn't serialize signature to DER format",
            ECDSA_SIGN_FAIL: "nonce generation function failed or private key is invalid",
            ECDSA_RECOVER_FAIL: "couldn't recover public key from signature",
            MSG32_TYPE_INVALID: "message should be a Buffer",
            MSG32_LENGTH_INVALID: "message length is invalid",
            OPTIONS_TYPE_INVALID: "options should be an Object",
            OPTIONS_DATA_TYPE_INVALID: "options.data should be a Buffer",
            OPTIONS_DATA_LENGTH_INVALID: "options.data length is invalid",
            OPTIONS_NONCEFN_TYPE_INVALID: "options.noncefn should be a Function",
            RECOVERY_ID_TYPE_INVALID: "recovery should be a Number",
            RECOVERY_ID_VALUE_INVALID: "recovery should have value between -1 and 4",
            TWEAK_TYPE_INVALID: "tweak should be a Buffer",
            TWEAK_LENGTH_INVALID: "tweak length is invalid"
        };
    }, {} ],
    170: [ function(require, module, exports) {
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
        _process: 140,
        buffer: 54,
        crypto: 25
    } ],
    171: [ function(require, module, exports) {
        (function(Buffer) {
            function Hash(blockSize, finalSize) {
                this._block = new Buffer(blockSize);
                this._finalSize = finalSize;
                this._blockSize = blockSize;
                this._len = 0;
                this._s = 0;
            }
            Hash.prototype.update = function(data, enc) {
                if (typeof data === "string") {
                    enc = enc || "utf8";
                    data = new Buffer(data, enc);
                }
                var l = this._len += data.length;
                var s = this._s || 0;
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
            module.exports = Hash;
        }).call(this, require("buffer").Buffer);
    }, {
        buffer: 54
    } ],
    172: [ function(require, module, exports) {
        var exports = module.exports = function SHA(algorithm) {
            algorithm = algorithm.toLowerCase();
            var Algorithm = exports[algorithm];
            if (!Algorithm) throw new Error(algorithm + " is not supported (we accept pull requests)");
            return new Algorithm();
        };
        exports.sha = require("./sha");
        exports.sha1 = require("./sha1");
        exports.sha224 = require("./sha224");
        exports.sha256 = require("./sha256");
        exports.sha384 = require("./sha384");
        exports.sha512 = require("./sha512");
    }, {
        "./sha": 173,
        "./sha1": 174,
        "./sha224": 175,
        "./sha256": 176,
        "./sha384": 177,
        "./sha512": 178
    } ],
    173: [ function(require, module, exports) {
        (function(Buffer) {
            var inherits = require("inherits");
            var Hash = require("./hash");
            var K = [ 1518500249, 1859775393, 2400959708 | 0, 3395469782 | 0 ];
            var W = new Array(80);
            function Sha() {
                this.init();
                this._w = W;
                Hash.call(this, 64, 56);
            }
            inherits(Sha, Hash);
            Sha.prototype.init = function() {
                this._a = 1732584193;
                this._b = 4023233417;
                this._c = 2562383102;
                this._d = 271733878;
                this._e = 3285377520;
                return this;
            };
            function rotl5(num) {
                return num << 5 | num >>> 27;
            }
            function rotl30(num) {
                return num << 30 | num >>> 2;
            }
            function ft(s, b, c, d) {
                if (s === 0) return b & c | ~b & d;
                if (s === 2) return b & c | b & d | c & d;
                return b ^ c ^ d;
            }
            Sha.prototype._update = function(M) {
                var W = this._w;
                var a = this._a | 0;
                var b = this._b | 0;
                var c = this._c | 0;
                var d = this._d | 0;
                var e = this._e | 0;
                for (var i = 0; i < 16; ++i) W[i] = M.readInt32BE(i * 4);
                for (;i < 80; ++i) W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
                for (var j = 0; j < 80; ++j) {
                    var s = ~~(j / 20);
                    var t = rotl5(a) + ft(s, b, c, d) + e + W[j] + K[s] | 0;
                    e = d;
                    d = c;
                    c = rotl30(b);
                    b = a;
                    a = t;
                }
                this._a = a + this._a | 0;
                this._b = b + this._b | 0;
                this._c = c + this._c | 0;
                this._d = d + this._d | 0;
                this._e = e + this._e | 0;
            };
            Sha.prototype._hash = function() {
                var H = new Buffer(20);
                H.writeInt32BE(this._a | 0, 0);
                H.writeInt32BE(this._b | 0, 4);
                H.writeInt32BE(this._c | 0, 8);
                H.writeInt32BE(this._d | 0, 12);
                H.writeInt32BE(this._e | 0, 16);
                return H;
            };
            module.exports = Sha;
        }).call(this, require("buffer").Buffer);
    }, {
        "./hash": 171,
        buffer: 54,
        inherits: 122
    } ],
    174: [ function(require, module, exports) {
        (function(Buffer) {
            var inherits = require("inherits");
            var Hash = require("./hash");
            var K = [ 1518500249, 1859775393, 2400959708 | 0, 3395469782 | 0 ];
            var W = new Array(80);
            function Sha1() {
                this.init();
                this._w = W;
                Hash.call(this, 64, 56);
            }
            inherits(Sha1, Hash);
            Sha1.prototype.init = function() {
                this._a = 1732584193;
                this._b = 4023233417;
                this._c = 2562383102;
                this._d = 271733878;
                this._e = 3285377520;
                return this;
            };
            function rotl1(num) {
                return num << 1 | num >>> 31;
            }
            function rotl5(num) {
                return num << 5 | num >>> 27;
            }
            function rotl30(num) {
                return num << 30 | num >>> 2;
            }
            function ft(s, b, c, d) {
                if (s === 0) return b & c | ~b & d;
                if (s === 2) return b & c | b & d | c & d;
                return b ^ c ^ d;
            }
            Sha1.prototype._update = function(M) {
                var W = this._w;
                var a = this._a | 0;
                var b = this._b | 0;
                var c = this._c | 0;
                var d = this._d | 0;
                var e = this._e | 0;
                for (var i = 0; i < 16; ++i) W[i] = M.readInt32BE(i * 4);
                for (;i < 80; ++i) W[i] = rotl1(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]);
                for (var j = 0; j < 80; ++j) {
                    var s = ~~(j / 20);
                    var t = rotl5(a) + ft(s, b, c, d) + e + W[j] + K[s] | 0;
                    e = d;
                    d = c;
                    c = rotl30(b);
                    b = a;
                    a = t;
                }
                this._a = a + this._a | 0;
                this._b = b + this._b | 0;
                this._c = c + this._c | 0;
                this._d = d + this._d | 0;
                this._e = e + this._e | 0;
            };
            Sha1.prototype._hash = function() {
                var H = new Buffer(20);
                H.writeInt32BE(this._a | 0, 0);
                H.writeInt32BE(this._b | 0, 4);
                H.writeInt32BE(this._c | 0, 8);
                H.writeInt32BE(this._d | 0, 12);
                H.writeInt32BE(this._e | 0, 16);
                return H;
            };
            module.exports = Sha1;
        }).call(this, require("buffer").Buffer);
    }, {
        "./hash": 171,
        buffer: 54,
        inherits: 122
    } ],
    175: [ function(require, module, exports) {
        (function(Buffer) {
            var inherits = require("inherits");
            var Sha256 = require("./sha256");
            var Hash = require("./hash");
            var W = new Array(64);
            function Sha224() {
                this.init();
                this._w = W;
                Hash.call(this, 64, 56);
            }
            inherits(Sha224, Sha256);
            Sha224.prototype.init = function() {
                this._a = 3238371032;
                this._b = 914150663;
                this._c = 812702999;
                this._d = 4144912697;
                this._e = 4290775857;
                this._f = 1750603025;
                this._g = 1694076839;
                this._h = 3204075428;
                return this;
            };
            Sha224.prototype._hash = function() {
                var H = new Buffer(28);
                H.writeInt32BE(this._a, 0);
                H.writeInt32BE(this._b, 4);
                H.writeInt32BE(this._c, 8);
                H.writeInt32BE(this._d, 12);
                H.writeInt32BE(this._e, 16);
                H.writeInt32BE(this._f, 20);
                H.writeInt32BE(this._g, 24);
                return H;
            };
            module.exports = Sha224;
        }).call(this, require("buffer").Buffer);
    }, {
        "./hash": 171,
        "./sha256": 176,
        buffer: 54,
        inherits: 122
    } ],
    176: [ function(require, module, exports) {
        (function(Buffer) {
            var inherits = require("inherits");
            var Hash = require("./hash");
            var K = [ 1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298 ];
            var W = new Array(64);
            function Sha256() {
                this.init();
                this._w = W;
                Hash.call(this, 64, 56);
            }
            inherits(Sha256, Hash);
            Sha256.prototype.init = function() {
                this._a = 1779033703;
                this._b = 3144134277;
                this._c = 1013904242;
                this._d = 2773480762;
                this._e = 1359893119;
                this._f = 2600822924;
                this._g = 528734635;
                this._h = 1541459225;
                return this;
            };
            function ch(x, y, z) {
                return z ^ x & (y ^ z);
            }
            function maj(x, y, z) {
                return x & y | z & (x | y);
            }
            function sigma0(x) {
                return (x >>> 2 | x << 30) ^ (x >>> 13 | x << 19) ^ (x >>> 22 | x << 10);
            }
            function sigma1(x) {
                return (x >>> 6 | x << 26) ^ (x >>> 11 | x << 21) ^ (x >>> 25 | x << 7);
            }
            function gamma0(x) {
                return (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ x >>> 3;
            }
            function gamma1(x) {
                return (x >>> 17 | x << 15) ^ (x >>> 19 | x << 13) ^ x >>> 10;
            }
            Sha256.prototype._update = function(M) {
                var W = this._w;
                var a = this._a | 0;
                var b = this._b | 0;
                var c = this._c | 0;
                var d = this._d | 0;
                var e = this._e | 0;
                var f = this._f | 0;
                var g = this._g | 0;
                var h = this._h | 0;
                for (var i = 0; i < 16; ++i) W[i] = M.readInt32BE(i * 4);
                for (;i < 64; ++i) W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16] | 0;
                for (var j = 0; j < 64; ++j) {
                    var T1 = h + sigma1(e) + ch(e, f, g) + K[j] + W[j] | 0;
                    var T2 = sigma0(a) + maj(a, b, c) | 0;
                    h = g;
                    g = f;
                    f = e;
                    e = d + T1 | 0;
                    d = c;
                    c = b;
                    b = a;
                    a = T1 + T2 | 0;
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
            module.exports = Sha256;
        }).call(this, require("buffer").Buffer);
    }, {
        "./hash": 171,
        buffer: 54,
        inherits: 122
    } ],
    177: [ function(require, module, exports) {
        (function(Buffer) {
            var inherits = require("inherits");
            var SHA512 = require("./sha512");
            var Hash = require("./hash");
            var W = new Array(160);
            function Sha384() {
                this.init();
                this._w = W;
                Hash.call(this, 128, 112);
            }
            inherits(Sha384, SHA512);
            Sha384.prototype.init = function() {
                this._ah = 3418070365;
                this._bh = 1654270250;
                this._ch = 2438529370;
                this._dh = 355462360;
                this._eh = 1731405415;
                this._fh = 2394180231;
                this._gh = 3675008525;
                this._hh = 1203062813;
                this._al = 3238371032;
                this._bl = 914150663;
                this._cl = 812702999;
                this._dl = 4144912697;
                this._el = 4290775857;
                this._fl = 1750603025;
                this._gl = 1694076839;
                this._hl = 3204075428;
                return this;
            };
            Sha384.prototype._hash = function() {
                var H = new Buffer(48);
                function writeInt64BE(h, l, offset) {
                    H.writeInt32BE(h, offset);
                    H.writeInt32BE(l, offset + 4);
                }
                writeInt64BE(this._ah, this._al, 0);
                writeInt64BE(this._bh, this._bl, 8);
                writeInt64BE(this._ch, this._cl, 16);
                writeInt64BE(this._dh, this._dl, 24);
                writeInt64BE(this._eh, this._el, 32);
                writeInt64BE(this._fh, this._fl, 40);
                return H;
            };
            module.exports = Sha384;
        }).call(this, require("buffer").Buffer);
    }, {
        "./hash": 171,
        "./sha512": 178,
        buffer: 54,
        inherits: 122
    } ],
    178: [ function(require, module, exports) {
        (function(Buffer) {
            var inherits = require("inherits");
            var Hash = require("./hash");
            var K = [ 1116352408, 3609767458, 1899447441, 602891725, 3049323471, 3964484399, 3921009573, 2173295548, 961987163, 4081628472, 1508970993, 3053834265, 2453635748, 2937671579, 2870763221, 3664609560, 3624381080, 2734883394, 310598401, 1164996542, 607225278, 1323610764, 1426881987, 3590304994, 1925078388, 4068182383, 2162078206, 991336113, 2614888103, 633803317, 3248222580, 3479774868, 3835390401, 2666613458, 4022224774, 944711139, 264347078, 2341262773, 604807628, 2007800933, 770255983, 1495990901, 1249150122, 1856431235, 1555081692, 3175218132, 1996064986, 2198950837, 2554220882, 3999719339, 2821834349, 766784016, 2952996808, 2566594879, 3210313671, 3203337956, 3336571891, 1034457026, 3584528711, 2466948901, 113926993, 3758326383, 338241895, 168717936, 666307205, 1188179964, 773529912, 1546045734, 1294757372, 1522805485, 1396182291, 2643833823, 1695183700, 2343527390, 1986661051, 1014477480, 2177026350, 1206759142, 2456956037, 344077627, 2730485921, 1290863460, 2820302411, 3158454273, 3259730800, 3505952657, 3345764771, 106217008, 3516065817, 3606008344, 3600352804, 1432725776, 4094571909, 1467031594, 275423344, 851169720, 430227734, 3100823752, 506948616, 1363258195, 659060556, 3750685593, 883997877, 3785050280, 958139571, 3318307427, 1322822218, 3812723403, 1537002063, 2003034995, 1747873779, 3602036899, 1955562222, 1575990012, 2024104815, 1125592928, 2227730452, 2716904306, 2361852424, 442776044, 2428436474, 593698344, 2756734187, 3733110249, 3204031479, 2999351573, 3329325298, 3815920427, 3391569614, 3928383900, 3515267271, 566280711, 3940187606, 3454069534, 4118630271, 4000239992, 116418474, 1914138554, 174292421, 2731055270, 289380356, 3203993006, 460393269, 320620315, 685471733, 587496836, 852142971, 1086792851, 1017036298, 365543100, 1126000580, 2618297676, 1288033470, 3409855158, 1501505948, 4234509866, 1607167915, 987167468, 1816402316, 1246189591 ];
            var W = new Array(160);
            function Sha512() {
                this.init();
                this._w = W;
                Hash.call(this, 128, 112);
            }
            inherits(Sha512, Hash);
            Sha512.prototype.init = function() {
                this._ah = 1779033703;
                this._bh = 3144134277;
                this._ch = 1013904242;
                this._dh = 2773480762;
                this._eh = 1359893119;
                this._fh = 2600822924;
                this._gh = 528734635;
                this._hh = 1541459225;
                this._al = 4089235720;
                this._bl = 2227873595;
                this._cl = 4271175723;
                this._dl = 1595750129;
                this._el = 2917565137;
                this._fl = 725511199;
                this._gl = 4215389547;
                this._hl = 327033209;
                return this;
            };
            function Ch(x, y, z) {
                return z ^ x & (y ^ z);
            }
            function maj(x, y, z) {
                return x & y | z & (x | y);
            }
            function sigma0(x, xl) {
                return (x >>> 28 | xl << 4) ^ (xl >>> 2 | x << 30) ^ (xl >>> 7 | x << 25);
            }
            function sigma1(x, xl) {
                return (x >>> 14 | xl << 18) ^ (x >>> 18 | xl << 14) ^ (xl >>> 9 | x << 23);
            }
            function Gamma0(x, xl) {
                return (x >>> 1 | xl << 31) ^ (x >>> 8 | xl << 24) ^ x >>> 7;
            }
            function Gamma0l(x, xl) {
                return (x >>> 1 | xl << 31) ^ (x >>> 8 | xl << 24) ^ (x >>> 7 | xl << 25);
            }
            function Gamma1(x, xl) {
                return (x >>> 19 | xl << 13) ^ (xl >>> 29 | x << 3) ^ x >>> 6;
            }
            function Gamma1l(x, xl) {
                return (x >>> 19 | xl << 13) ^ (xl >>> 29 | x << 3) ^ (x >>> 6 | xl << 26);
            }
            function getCarry(a, b) {
                return a >>> 0 < b >>> 0 ? 1 : 0;
            }
            Sha512.prototype._update = function(M) {
                var W = this._w;
                var ah = this._ah | 0;
                var bh = this._bh | 0;
                var ch = this._ch | 0;
                var dh = this._dh | 0;
                var eh = this._eh | 0;
                var fh = this._fh | 0;
                var gh = this._gh | 0;
                var hh = this._hh | 0;
                var al = this._al | 0;
                var bl = this._bl | 0;
                var cl = this._cl | 0;
                var dl = this._dl | 0;
                var el = this._el | 0;
                var fl = this._fl | 0;
                var gl = this._gl | 0;
                var hl = this._hl | 0;
                for (var i = 0; i < 32; i += 2) {
                    W[i] = M.readInt32BE(i * 4);
                    W[i + 1] = M.readInt32BE(i * 4 + 4);
                }
                for (;i < 160; i += 2) {
                    var xh = W[i - 15 * 2];
                    var xl = W[i - 15 * 2 + 1];
                    var gamma0 = Gamma0(xh, xl);
                    var gamma0l = Gamma0l(xl, xh);
                    xh = W[i - 2 * 2];
                    xl = W[i - 2 * 2 + 1];
                    var gamma1 = Gamma1(xh, xl);
                    var gamma1l = Gamma1l(xl, xh);
                    var Wi7h = W[i - 7 * 2];
                    var Wi7l = W[i - 7 * 2 + 1];
                    var Wi16h = W[i - 16 * 2];
                    var Wi16l = W[i - 16 * 2 + 1];
                    var Wil = gamma0l + Wi7l | 0;
                    var Wih = gamma0 + Wi7h + getCarry(Wil, gamma0l) | 0;
                    Wil = Wil + gamma1l | 0;
                    Wih = Wih + gamma1 + getCarry(Wil, gamma1l) | 0;
                    Wil = Wil + Wi16l | 0;
                    Wih = Wih + Wi16h + getCarry(Wil, Wi16l) | 0;
                    W[i] = Wih;
                    W[i + 1] = Wil;
                }
                for (var j = 0; j < 160; j += 2) {
                    Wih = W[j];
                    Wil = W[j + 1];
                    var majh = maj(ah, bh, ch);
                    var majl = maj(al, bl, cl);
                    var sigma0h = sigma0(ah, al);
                    var sigma0l = sigma0(al, ah);
                    var sigma1h = sigma1(eh, el);
                    var sigma1l = sigma1(el, eh);
                    var Kih = K[j];
                    var Kil = K[j + 1];
                    var chh = Ch(eh, fh, gh);
                    var chl = Ch(el, fl, gl);
                    var t1l = hl + sigma1l | 0;
                    var t1h = hh + sigma1h + getCarry(t1l, hl) | 0;
                    t1l = t1l + chl | 0;
                    t1h = t1h + chh + getCarry(t1l, chl) | 0;
                    t1l = t1l + Kil | 0;
                    t1h = t1h + Kih + getCarry(t1l, Kil) | 0;
                    t1l = t1l + Wil | 0;
                    t1h = t1h + Wih + getCarry(t1l, Wil) | 0;
                    var t2l = sigma0l + majl | 0;
                    var t2h = sigma0h + majh + getCarry(t2l, sigma0l) | 0;
                    hh = gh;
                    hl = gl;
                    gh = fh;
                    gl = fl;
                    fh = eh;
                    fl = el;
                    el = dl + t1l | 0;
                    eh = dh + t1h + getCarry(el, dl) | 0;
                    dh = ch;
                    dl = cl;
                    ch = bh;
                    cl = bl;
                    bh = ah;
                    bl = al;
                    al = t1l + t2l | 0;
                    ah = t1h + t2h + getCarry(al, t1l) | 0;
                }
                this._al = this._al + al | 0;
                this._bl = this._bl + bl | 0;
                this._cl = this._cl + cl | 0;
                this._dl = this._dl + dl | 0;
                this._el = this._el + el | 0;
                this._fl = this._fl + fl | 0;
                this._gl = this._gl + gl | 0;
                this._hl = this._hl + hl | 0;
                this._ah = this._ah + ah + getCarry(this._al, al) | 0;
                this._bh = this._bh + bh + getCarry(this._bl, bl) | 0;
                this._ch = this._ch + ch + getCarry(this._cl, cl) | 0;
                this._dh = this._dh + dh + getCarry(this._dl, dl) | 0;
                this._eh = this._eh + eh + getCarry(this._el, el) | 0;
                this._fh = this._fh + fh + getCarry(this._fl, fl) | 0;
                this._gh = this._gh + gh + getCarry(this._gl, gl) | 0;
                this._hh = this._hh + hh + getCarry(this._hl, hl) | 0;
            };
            Sha512.prototype._hash = function() {
                var H = new Buffer(64);
                function writeInt64BE(h, l, offset) {
                    H.writeInt32BE(h, offset);
                    H.writeInt32BE(l, offset + 4);
                }
                writeInt64BE(this._ah, this._al, 0);
                writeInt64BE(this._bh, this._bl, 8);
                writeInt64BE(this._ch, this._cl, 16);
                writeInt64BE(this._dh, this._dl, 24);
                writeInt64BE(this._eh, this._el, 32);
                writeInt64BE(this._fh, this._fl, 40);
                writeInt64BE(this._gh, this._gl, 48);
                writeInt64BE(this._hh, this._hl, 56);
                return H;
            };
            module.exports = Sha512;
        }).call(this, require("buffer").Buffer);
    }, {
        "./hash": 171,
        buffer: 54,
        inherits: 122
    } ],
    179: [ function(require, module, exports) {
        module.exports = Stream;
        var EE = require("events").EventEmitter;
        var inherits = require("inherits");
        inherits(Stream, EE);
        Stream.Readable = require("readable-stream/readable.js");
        Stream.Writable = require("readable-stream/writable.js");
        Stream.Duplex = require("readable-stream/duplex.js");
        Stream.Transform = require("readable-stream/transform.js");
        Stream.PassThrough = require("readable-stream/passthrough.js");
        Stream.Stream = Stream;
        function Stream() {
            EE.call(this);
        }
        Stream.prototype.pipe = function(dest, options) {
            var source = this;
            function ondata(chunk) {
                if (dest.writable) {
                    if (false === dest.write(chunk) && source.pause) {
                        source.pause();
                    }
                }
            }
            source.on("data", ondata);
            function ondrain() {
                if (source.readable && source.resume) {
                    source.resume();
                }
            }
            dest.on("drain", ondrain);
            if (!dest._isStdio && (!options || options.end !== false)) {
                source.on("end", onend);
                source.on("close", onclose);
            }
            var didOnEnd = false;
            function onend() {
                if (didOnEnd) return;
                didOnEnd = true;
                dest.end();
            }
            function onclose() {
                if (didOnEnd) return;
                didOnEnd = true;
                if (typeof dest.destroy === "function") dest.destroy();
            }
            function onerror(er) {
                cleanup();
                if (EE.listenerCount(this, "error") === 0) {
                    throw er;
                }
            }
            source.on("error", onerror);
            dest.on("error", onerror);
            function cleanup() {
                source.removeListener("data", ondata);
                dest.removeListener("drain", ondrain);
                source.removeListener("end", onend);
                source.removeListener("close", onclose);
                source.removeListener("error", onerror);
                dest.removeListener("error", onerror);
                source.removeListener("end", cleanup);
                source.removeListener("close", cleanup);
                dest.removeListener("close", cleanup);
            }
            source.on("end", cleanup);
            source.on("close", cleanup);
            dest.on("close", cleanup);
            dest.emit("pipe", source);
            return dest;
        };
    }, {
        events: 103,
        inherits: 122,
        "readable-stream/duplex.js": 148,
        "readable-stream/passthrough.js": 158,
        "readable-stream/readable.js": 159,
        "readable-stream/transform.js": 160,
        "readable-stream/writable.js": 161
    } ],
    180: [ function(require, module, exports) {
        "use strict";
        var Buffer = require("safe-buffer").Buffer;
        var isEncoding = Buffer.isEncoding || function(encoding) {
            encoding = "" + encoding;
            switch (encoding && encoding.toLowerCase()) {
              case "hex":
              case "utf8":
              case "utf-8":
              case "ascii":
              case "binary":
              case "base64":
              case "ucs2":
              case "ucs-2":
              case "utf16le":
              case "utf-16le":
              case "raw":
                return true;

              default:
                return false;
            }
        };
        function _normalizeEncoding(enc) {
            if (!enc) return "utf8";
            var retried;
            while (true) {
                switch (enc) {
                  case "utf8":
                  case "utf-8":
                    return "utf8";

                  case "ucs2":
                  case "ucs-2":
                  case "utf16le":
                  case "utf-16le":
                    return "utf16le";

                  case "latin1":
                  case "binary":
                    return "latin1";

                  case "base64":
                  case "ascii":
                  case "hex":
                    return enc;

                  default:
                    if (retried) return;
                    enc = ("" + enc).toLowerCase();
                    retried = true;
                }
            }
        }
        function normalizeEncoding(enc) {
            var nenc = _normalizeEncoding(enc);
            if (typeof nenc !== "string" && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error("Unknown encoding: " + enc);
            return nenc || enc;
        }
        exports.StringDecoder = StringDecoder;
        function StringDecoder(encoding) {
            this.encoding = normalizeEncoding(encoding);
            var nb;
            switch (this.encoding) {
              case "utf16le":
                this.text = utf16Text;
                this.end = utf16End;
                nb = 4;
                break;

              case "utf8":
                this.fillLast = utf8FillLast;
                nb = 4;
                break;

              case "base64":
                this.text = base64Text;
                this.end = base64End;
                nb = 3;
                break;

              default:
                this.write = simpleWrite;
                this.end = simpleEnd;
                return;
            }
            this.lastNeed = 0;
            this.lastTotal = 0;
            this.lastChar = Buffer.allocUnsafe(nb);
        }
        StringDecoder.prototype.write = function(buf) {
            if (buf.length === 0) return "";
            var r;
            var i;
            if (this.lastNeed) {
                r = this.fillLast(buf);
                if (r === undefined) return "";
                i = this.lastNeed;
                this.lastNeed = 0;
            } else {
                i = 0;
            }
            if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
            return r || "";
        };
        StringDecoder.prototype.end = utf8End;
        StringDecoder.prototype.text = utf8Text;
        StringDecoder.prototype.fillLast = function(buf) {
            if (this.lastNeed <= buf.length) {
                buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
                return this.lastChar.toString(this.encoding, 0, this.lastTotal);
            }
            buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
            this.lastNeed -= buf.length;
        };
        function utf8CheckByte(byte) {
            if (byte <= 127) return 0; else if (byte >> 5 === 6) return 2; else if (byte >> 4 === 14) return 3; else if (byte >> 3 === 30) return 4;
            return -1;
        }
        function utf8CheckIncomplete(self, buf, i) {
            var j = buf.length - 1;
            if (j < i) return 0;
            var nb = utf8CheckByte(buf[j]);
            if (nb >= 0) {
                if (nb > 0) self.lastNeed = nb - 1;
                return nb;
            }
            if (--j < i) return 0;
            nb = utf8CheckByte(buf[j]);
            if (nb >= 0) {
                if (nb > 0) self.lastNeed = nb - 2;
                return nb;
            }
            if (--j < i) return 0;
            nb = utf8CheckByte(buf[j]);
            if (nb >= 0) {
                if (nb > 0) {
                    if (nb === 2) nb = 0; else self.lastNeed = nb - 3;
                }
                return nb;
            }
            return 0;
        }
        function utf8CheckExtraBytes(self, buf, p) {
            if ((buf[0] & 192) !== 128) {
                self.lastNeed = 0;
                return "�".repeat(p);
            }
            if (self.lastNeed > 1 && buf.length > 1) {
                if ((buf[1] & 192) !== 128) {
                    self.lastNeed = 1;
                    return "�".repeat(p + 1);
                }
                if (self.lastNeed > 2 && buf.length > 2) {
                    if ((buf[2] & 192) !== 128) {
                        self.lastNeed = 2;
                        return "�".repeat(p + 2);
                    }
                }
            }
        }
        function utf8FillLast(buf) {
            var p = this.lastTotal - this.lastNeed;
            var r = utf8CheckExtraBytes(this, buf, p);
            if (r !== undefined) return r;
            if (this.lastNeed <= buf.length) {
                buf.copy(this.lastChar, p, 0, this.lastNeed);
                return this.lastChar.toString(this.encoding, 0, this.lastTotal);
            }
            buf.copy(this.lastChar, p, 0, buf.length);
            this.lastNeed -= buf.length;
        }
        function utf8Text(buf, i) {
            var total = utf8CheckIncomplete(this, buf, i);
            if (!this.lastNeed) return buf.toString("utf8", i);
            this.lastTotal = total;
            var end = buf.length - (total - this.lastNeed);
            buf.copy(this.lastChar, 0, end);
            return buf.toString("utf8", i, end);
        }
        function utf8End(buf) {
            var r = buf && buf.length ? this.write(buf) : "";
            if (this.lastNeed) return r + "�".repeat(this.lastTotal - this.lastNeed);
            return r;
        }
        function utf16Text(buf, i) {
            if ((buf.length - i) % 2 === 0) {
                var r = buf.toString("utf16le", i);
                if (r) {
                    var c = r.charCodeAt(r.length - 1);
                    if (c >= 55296 && c <= 56319) {
                        this.lastNeed = 2;
                        this.lastTotal = 4;
                        this.lastChar[0] = buf[buf.length - 2];
                        this.lastChar[1] = buf[buf.length - 1];
                        return r.slice(0, -1);
                    }
                }
                return r;
            }
            this.lastNeed = 1;
            this.lastTotal = 2;
            this.lastChar[0] = buf[buf.length - 1];
            return buf.toString("utf16le", i, buf.length - 1);
        }
        function utf16End(buf) {
            var r = buf && buf.length ? this.write(buf) : "";
            if (this.lastNeed) {
                var end = this.lastTotal - this.lastNeed;
                return r + this.lastChar.toString("utf16le", 0, end);
            }
            return r;
        }
        function base64Text(buf, i) {
            var n = (buf.length - i) % 3;
            if (n === 0) return buf.toString("base64", i);
            this.lastNeed = 3 - n;
            this.lastTotal = 3;
            if (n === 1) {
                this.lastChar[0] = buf[buf.length - 1];
            } else {
                this.lastChar[0] = buf[buf.length - 2];
                this.lastChar[1] = buf[buf.length - 1];
            }
            return buf.toString("base64", i, buf.length - n);
        }
        function base64End(buf) {
            var r = buf && buf.length ? this.write(buf) : "";
            if (this.lastNeed) return r + this.lastChar.toString("base64", 0, 3 - this.lastNeed);
            return r;
        }
        function simpleWrite(buf) {
            return buf.toString(this.encoding);
        }
        function simpleEnd(buf) {
            return buf && buf.length ? this.write(buf) : "";
        }
    }, {
        "safe-buffer": 163
    } ],
    181: [ function(require, module, exports) {
        var inherits = require("inherits");
        var native = require("./native");
        function TfTypeError(type, value, valueTypeName) {
            this.__error = Error.call(this);
            this.__type = type;
            this.__value = value;
            this.__valueTypeName = valueTypeName;
            var message;
            Object.defineProperty(this, "message", {
                enumerable: true,
                get: function() {
                    if (message) return message;
                    valueTypeName = valueTypeName || getValueTypeName(value);
                    message = tfErrorString(type, value, valueTypeName);
                    return message;
                }
            });
        }
        function TfPropertyTypeError(type, property, label, value, error, valueTypeName) {
            this.__error = error || Error.call(this);
            this.__label = label;
            this.__property = property;
            this.__type = type;
            this.__value = value;
            this.__valueTypeName = valueTypeName;
            var message;
            Object.defineProperty(this, "message", {
                enumerable: true,
                get: function() {
                    if (message) return message;
                    if (type) {
                        valueTypeName = valueTypeName || getValueTypeName(value);
                        message = tfPropertyErrorString(type, label, property, value, valueTypeName);
                    } else {
                        message = 'Unexpected property "' + property + '"';
                    }
                    return message;
                }
            });
            Object.defineProperty(this, "stack", {
                get: function() {
                    return this.__error.stack;
                }
            });
        }
        [ TfTypeError, TfPropertyTypeError ].forEach(function(tfErrorType) {
            inherits(tfErrorType, Error);
        });
        function tfCustomError(expected, actual) {
            return new TfTypeError(expected, {}, actual);
        }
        function tfSubError(e, property, label) {
            if (e instanceof TfPropertyTypeError) {
                property = property + "." + e.__property;
                label = e.__label;
                return new TfPropertyTypeError(e.__type, property, label, e.__value, e.__error, e.__valueTypeName);
            }
            if (e instanceof TfTypeError) {
                return new TfPropertyTypeError(e.__type, property, label, e.__value, e.__error, e.__valueTypeName);
            }
            return e;
        }
        function getTypeName(fn) {
            return fn.name || fn.toString().match(/function (.*?)\s*\(/)[1];
        }
        function getValueTypeName(value) {
            return native.Nil(value) ? "" : getTypeName(value.constructor);
        }
        function getValue(value) {
            if (native.Function(value)) return "";
            if (native.String(value)) return JSON.stringify(value);
            if (value && native.Object(value)) return "";
            return value;
        }
        function tfJSON(type) {
            if (native.Function(type)) return type.toJSON ? type.toJSON() : getTypeName(type);
            if (native.Array(type)) return "Array";
            if (type && native.Object(type)) return "Object";
            return type !== undefined ? type : "";
        }
        function tfErrorString(type, value, valueTypeName) {
            var valueJson = getValue(value);
            return "Expected " + tfJSON(type) + ", got" + (valueTypeName !== "" ? " " + valueTypeName : "") + (valueJson !== "" ? " " + valueJson : "");
        }
        function tfPropertyErrorString(type, label, name, value, valueTypeName) {
            var description = '" of type ';
            if (label === "key") description = '" with key type ';
            return tfErrorString('property "' + tfJSON(name) + description + tfJSON(type), value, valueTypeName);
        }
        module.exports = {
            TfTypeError: TfTypeError,
            TfPropertyTypeError: TfPropertyTypeError,
            tfCustomError: tfCustomError,
            tfSubError: tfSubError,
            tfJSON: tfJSON,
            getValueTypeName: getValueTypeName
        };
    }, {
        "./native": 184,
        inherits: 122
    } ],
    182: [ function(require, module, exports) {
        (function(Buffer) {
            var NATIVE = require("./native");
            var ERRORS = require("./errors");
            function _Buffer(value) {
                return Buffer.isBuffer(value);
            }
            function Hex(value) {
                return typeof value === "string" && /^([0-9a-f]{2})+$/i.test(value);
            }
            function _LengthN(type, length) {
                var name = type.toJSON();
                function Length(value) {
                    if (!type(value)) return false;
                    if (value.length === length) return true;
                    throw ERRORS.tfCustomError(name + "(Length: " + length + ")", name + "(Length: " + value.length + ")");
                }
                Length.toJSON = function() {
                    return name;
                };
                return Length;
            }
            var _ArrayN = _LengthN.bind(null, NATIVE.Array);
            var _BufferN = _LengthN.bind(null, _Buffer);
            var _HexN = _LengthN.bind(null, Hex);
            var UINT53_MAX = Math.pow(2, 53) - 1;
            function Finite(value) {
                return typeof value === "number" && isFinite(value);
            }
            function Int8(value) {
                return value << 24 >> 24 === value;
            }
            function Int16(value) {
                return value << 16 >> 16 === value;
            }
            function Int32(value) {
                return (value | 0) === value;
            }
            function UInt8(value) {
                return (value & 255) === value;
            }
            function UInt16(value) {
                return (value & 65535) === value;
            }
            function UInt32(value) {
                return value >>> 0 === value;
            }
            function UInt53(value) {
                return typeof value === "number" && value >= 0 && value <= UINT53_MAX && Math.floor(value) === value;
            }
            var types = {
                ArrayN: _ArrayN,
                Buffer: _Buffer,
                BufferN: _BufferN,
                Finite: Finite,
                Hex: Hex,
                HexN: _HexN,
                Int8: Int8,
                Int16: Int16,
                Int32: Int32,
                UInt8: UInt8,
                UInt16: UInt16,
                UInt32: UInt32,
                UInt53: UInt53
            };
            for (var typeName in types) {
                types[typeName].toJSON = function(t) {
                    return t;
                }.bind(null, typeName);
            }
            module.exports = types;
        }).call(this, {
            isBuffer: require("../is-buffer/index.js")
        });
    }, {
        "../is-buffer/index.js": 123,
        "./errors": 181,
        "./native": 184
    } ],
    183: [ function(require, module, exports) {
        var ERRORS = require("./errors");
        var NATIVE = require("./native");
        var tfJSON = ERRORS.tfJSON;
        var TfTypeError = ERRORS.TfTypeError;
        var TfPropertyTypeError = ERRORS.TfPropertyTypeError;
        var tfSubError = ERRORS.tfSubError;
        var getValueTypeName = ERRORS.getValueTypeName;
        var TYPES = {
            arrayOf: function arrayOf(type) {
                type = compile(type);
                function _arrayOf(array, strict) {
                    if (!NATIVE.Array(array)) return false;
                    return array.every(function(value, i) {
                        try {
                            return typeforce(type, value, strict);
                        } catch (e) {
                            throw tfSubError(e, i);
                        }
                    });
                }
                _arrayOf.toJSON = function() {
                    return "[" + tfJSON(type) + "]";
                };
                return _arrayOf;
            },
            maybe: function maybe(type) {
                type = compile(type);
                function _maybe(value, strict) {
                    return NATIVE.Nil(value) || type(value, strict, maybe);
                }
                _maybe.toJSON = function() {
                    return "?" + tfJSON(type);
                };
                return _maybe;
            },
            map: function map(propertyType, propertyKeyType) {
                propertyType = compile(propertyType);
                if (propertyKeyType) propertyKeyType = compile(propertyKeyType);
                function _map(value, strict) {
                    if (!NATIVE.Object(value, strict)) return false;
                    if (NATIVE.Nil(value, strict)) return false;
                    for (var propertyName in value) {
                        try {
                            if (propertyKeyType) {
                                typeforce(propertyKeyType, propertyName, strict);
                            }
                        } catch (e) {
                            throw tfSubError(e, propertyName, "key");
                        }
                        try {
                            var propertyValue = value[propertyName];
                            typeforce(propertyType, propertyValue, strict);
                        } catch (e) {
                            throw tfSubError(e, propertyName);
                        }
                    }
                    return true;
                }
                if (propertyKeyType) {
                    _map.toJSON = function() {
                        return "{" + tfJSON(propertyKeyType) + ": " + tfJSON(propertyType) + "}";
                    };
                } else {
                    _map.toJSON = function() {
                        return "{" + tfJSON(propertyType) + "}";
                    };
                }
                return _map;
            },
            object: function object(uncompiled) {
                var type = {};
                for (var typePropertyName in uncompiled) {
                    type[typePropertyName] = compile(uncompiled[typePropertyName]);
                }
                function _object(value, strict) {
                    if (!NATIVE.Object(value)) return false;
                    if (NATIVE.Nil(value)) return false;
                    var propertyName;
                    try {
                        for (propertyName in type) {
                            var propertyType = type[propertyName];
                            var propertyValue = value[propertyName];
                            typeforce(propertyType, propertyValue, strict);
                        }
                    } catch (e) {
                        throw tfSubError(e, propertyName);
                    }
                    if (strict) {
                        for (propertyName in value) {
                            if (type[propertyName]) continue;
                            throw new TfPropertyTypeError(undefined, propertyName);
                        }
                    }
                    return true;
                }
                _object.toJSON = function() {
                    return tfJSON(type);
                };
                return _object;
            },
            oneOf: function oneOf() {
                var types = [].slice.call(arguments).map(compile);
                function _oneOf(value, strict) {
                    return types.some(function(type) {
                        try {
                            return typeforce(type, value, strict);
                        } catch (e) {
                            return false;
                        }
                    });
                }
                _oneOf.toJSON = function() {
                    return types.map(tfJSON).join("|");
                };
                return _oneOf;
            },
            quacksLike: function quacksLike(type) {
                function _quacksLike(value) {
                    return type === getValueTypeName(value);
                }
                _quacksLike.toJSON = function() {
                    return type;
                };
                return _quacksLike;
            },
            tuple: function tuple() {
                var types = [].slice.call(arguments).map(compile);
                function _tuple(values, strict) {
                    return types.every(function(type, i) {
                        try {
                            return typeforce(type, values[i], strict);
                        } catch (e) {
                            throw tfSubError(e, i);
                        }
                    }) && (!strict || values.length === arguments.length);
                }
                _tuple.toJSON = function() {
                    return "(" + types.map(tfJSON).join(", ") + ")";
                };
                return _tuple;
            },
            value: function value(expected) {
                function _value(actual) {
                    return actual === expected;
                }
                _value.toJSON = function() {
                    return expected;
                };
                return _value;
            }
        };
        function compile(type) {
            if (NATIVE.String(type)) {
                if (type[0] === "?") return TYPES.maybe(compile(type.slice(1)));
                return NATIVE[type] || TYPES.quacksLike(type);
            } else if (type && NATIVE.Object(type)) {
                if (NATIVE.Array(type)) return TYPES.arrayOf(compile(type[0]));
                return TYPES.object(type);
            } else if (NATIVE.Function(type)) {
                return type;
            }
            return TYPES.value(type);
        }
        function typeforce(type, value, strict, surrogate) {
            if (NATIVE.Function(type)) {
                if (type(value, strict)) return true;
                throw new TfTypeError(surrogate || type, value);
            }
            return typeforce(compile(type), value, strict);
        }
        for (var typeName in NATIVE) {
            typeforce[typeName] = NATIVE[typeName];
        }
        for (typeName in TYPES) {
            typeforce[typeName] = TYPES[typeName];
        }
        var EXTRA = require("./extra");
        for (typeName in EXTRA) {
            typeforce[typeName] = EXTRA[typeName];
        }
        function __async(type, value, strict, callback) {
            if (typeof strict === "function") return __async(type, value, false, strict);
            try {
                typeforce(type, value, strict);
            } catch (e) {
                return callback(e);
            }
            callback();
        }
        typeforce.async = __async;
        typeforce.compile = compile;
        typeforce.TfTypeError = TfTypeError;
        typeforce.TfPropertyTypeError = TfPropertyTypeError;
        module.exports = typeforce;
    }, {
        "./errors": 181,
        "./extra": 182,
        "./native": 184
    } ],
    184: [ function(require, module, exports) {
        var types = {
            Array: function(value) {
                return value !== null && value !== undefined && value.constructor === Array;
            },
            Boolean: function(value) {
                return typeof value === "boolean";
            },
            Function: function(value) {
                return typeof value === "function";
            },
            Nil: function(value) {
                return value === undefined || value === null;
            },
            Number: function(value) {
                return typeof value === "number";
            },
            Object: function(value) {
                return typeof value === "object";
            },
            String: function(value) {
                return typeof value === "string";
            },
            "": function() {
                return true;
            }
        };
        types.Null = types.Nil;
        for (var typeName in types) {
            types[typeName].toJSON = function(t) {
                return t;
            }.bind(null, typeName);
        }
        module.exports = types;
    }, {} ],
    185: [ function(require, module, exports) {
        (function(global) {
            module.exports = deprecate;
            function deprecate(fn, msg) {
                if (config("noDeprecation")) {
                    return fn;
                }
                var warned = false;
                function deprecated() {
                    if (!warned) {
                        if (config("throwDeprecation")) {
                            throw new Error(msg);
                        } else if (config("traceDeprecation")) {
                            console.trace(msg);
                        } else {
                            console.warn(msg);
                        }
                        warned = true;
                    }
                    return fn.apply(this, arguments);
                }
                return deprecated;
            }
            function config(name) {
                try {
                    if (!global.localStorage) return false;
                } catch (_) {
                    return false;
                }
                var val = global.localStorage[name];
                if (null == val) return false;
                return String(val).toLowerCase() === "true";
            }
        }).call(this, typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {});
    }, {} ],
    186: [ function(require, module, exports) {
        module.exports = function isBuffer(arg) {
            return arg && typeof arg === "object" && typeof arg.copy === "function" && typeof arg.fill === "function" && typeof arg.readUInt8 === "function";
        };
    }, {} ],
    187: [ function(require, module, exports) {
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
                boolean: "yellow",
                undefined: "grey",
                null: "bold",
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
        "./support/isBuffer": 186,
        _process: 140,
        inherits: 122
    } ],
    188: [ function(require, module, exports) {
        var indexOf = require("indexof");
        var Object_keys = function(obj) {
            if (Object.keys) return Object.keys(obj); else {
                var res = [];
                for (var key in obj) res.push(key);
                return res;
            }
        };
        var forEach = function(xs, fn) {
            if (xs.forEach) return xs.forEach(fn); else for (var i = 0; i < xs.length; i++) {
                fn(xs[i], i, xs);
            }
        };
        var defineProp = function() {
            try {
                Object.defineProperty({}, "_", {});
                return function(obj, name, value) {
                    Object.defineProperty(obj, name, {
                        writable: true,
                        enumerable: false,
                        configurable: true,
                        value: value
                    });
                };
            } catch (e) {
                return function(obj, name, value) {
                    obj[name] = value;
                };
            }
        }();
        var globals = [ "Array", "Boolean", "Date", "Error", "EvalError", "Function", "Infinity", "JSON", "Math", "NaN", "Number", "Object", "RangeError", "ReferenceError", "RegExp", "String", "SyntaxError", "TypeError", "URIError", "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "escape", "eval", "isFinite", "isNaN", "parseFloat", "parseInt", "undefined", "unescape" ];
        function Context() {}
        Context.prototype = {};
        var Script = exports.Script = function NodeScript(code) {
            if (!(this instanceof Script)) return new Script(code);
            this.code = code;
        };
        Script.prototype.runInContext = function(context) {
            if (!(context instanceof Context)) {
                throw new TypeError("needs a 'context' argument.");
            }
            var iframe = document.createElement("iframe");
            if (!iframe.style) iframe.style = {};
            iframe.style.display = "none";
            document.body.appendChild(iframe);
            var win = iframe.contentWindow;
            var wEval = win.eval, wExecScript = win.execScript;
            if (!wEval && wExecScript) {
                wExecScript.call(win, "null");
                wEval = win.eval;
            }
            forEach(Object_keys(context), function(key) {
                win[key] = context[key];
            });
            forEach(globals, function(key) {
                if (context[key]) {
                    win[key] = context[key];
                }
            });
            var winKeys = Object_keys(win);
            var res = wEval.call(win, this.code);
            forEach(Object_keys(win), function(key) {
                if (key in context || indexOf(winKeys, key) === -1) {
                    context[key] = win[key];
                }
            });
            forEach(globals, function(key) {
                if (!(key in context)) {
                    defineProp(context, key, win[key]);
                }
            });
            document.body.removeChild(iframe);
            return res;
        };
        Script.prototype.runInThisContext = function() {
            return eval(this.code);
        };
        Script.prototype.runInNewContext = function(context) {
            var ctx = Script.createContext(context);
            var res = this.runInContext(ctx);
            forEach(Object_keys(ctx), function(key) {
                context[key] = ctx[key];
            });
            return res;
        };
        forEach(Object_keys(Script.prototype), function(name) {
            exports[name] = Script[name] = function(code) {
                var s = Script(code);
                return s[name].apply(s, [].slice.call(arguments, 1));
            };
        });
        exports.createScript = function(code) {
            return exports.Script(code);
        };
        exports.createContext = Script.createContext = function(context) {
            var copy = new Context();
            if (typeof context === "object") {
                forEach(Object_keys(context), function(key) {
                    copy[key] = context[key];
                });
            }
            return copy;
        };
    }, {
        indexof: 121
    } ],
    189: [ function(require, module, exports) {
        angular.module("ng-ecdsa", [ "sacketty.ecdsa", "sacketty.crypto", "sacketty.coinkey", "sacketty.buffer" ]);
        angular.module("ng-crypto", [ "sacketty.crypto" ]);
        angular.module("ng-coinkey", [ "sacketty.coinkey" ]);
        angular.module("ng-aes", [ "sacketty.aes" ]);
        angular.module("ng-buffer", [ "sacketty.buffer" ]);
        angular.module("ng-pbkdf2", [ "sacketty.pbkdf2" ]);
    }, {} ],
    190: [ function(require, module, exports) {
        "use strict";
        var AES = require("aes");
        angular.module("sacketty.aes", []).factory("AES", function() {
            return AES;
        });
    }, {
        aes: 1
    } ],
    191: [ function(require, module, exports) {
        "use strict";
        var buffer = require("buffer");
        angular.module("sacketty.buffer", []).factory("buffer", function() {
            return buffer;
        });
    }, {
        buffer: 54
    } ],
    192: [ function(require, module, exports) {
        "use strict";
        var CoinKey = require("coinkey");
        angular.module("sacketty.coinkey", []).factory("CoinKey", function() {
            return CoinKey;
        });
    }, {
        coinkey: 56
    } ],
    193: [ function(require, module, exports) {
        "use strict";
        var crypto = require("crypto");
        angular.module("sacketty.crypto", []).factory("crypto", function() {
            return crypto;
        });
    }, {
        crypto: 66
    } ],
    194: [ function(require, module, exports) {
        "use strict";
        var ecdsa = require("ecdsa");
        angular.module("sacketty.ecdsa", []).factory("ecdsa", function() {
            return ecdsa;
        });
    }, {
        ecdsa: 79
    } ],
    195: [ function(require, module, exports) {
        "use strict";
        var pbkdf2 = require("pbkdf2-sha256");
        angular.module("sacketty.pbkdf2", []).factory("pbkdf2", function() {
            return pbkdf2;
        });
    }, {
        "pbkdf2-sha256": 133
    } ]
}, {}, [ 189, 190, 191, 192, 193, 194, 195 ]);