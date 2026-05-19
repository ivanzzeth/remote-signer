(() => {
  var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
    get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
  }) : x)(function(x) {
    if (typeof require !== "undefined") return require.apply(this, arguments);
    throw Error('Dynamic require of "' + x + '" is not supported');
  });

  // ../pkg/js-client/node_modules/@noble/ed25519/index.js
  var ed25519_CURVE = {
    p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
    n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
    h: 8n,
    a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
    d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
    Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
    Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n
  };
  var { p: P, n: N, Gx, Gy, a: _a, d: _d } = ed25519_CURVE;
  var h = 8n;
  var L = 32;
  var L2 = 64;
  var err = (m = "") => {
    throw new Error(m);
  };
  var isBig = (n) => typeof n === "bigint";
  var isStr = (s) => typeof s === "string";
  var isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  var abytes = (a, l) => !isBytes(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
  var u8n = (len) => new Uint8Array(len);
  var u8fr = (buf) => Uint8Array.from(buf);
  var padh = (n, pad) => n.toString(16).padStart(pad, "0");
  var bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
  var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
  var _ch = (ch) => {
    if (ch >= C._0 && ch <= C._9)
      return ch - C._0;
    if (ch >= C.A && ch <= C.F)
      return ch - (C.A - 10);
    if (ch >= C.a && ch <= C.f)
      return ch - (C.a - 10);
    return;
  };
  var hexToBytes = (hex) => {
    const e = "hex invalid";
    if (!isStr(hex))
      return err(e);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
      return err(e);
    const array = u8n(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
      const n1 = _ch(hex.charCodeAt(hi));
      const n2 = _ch(hex.charCodeAt(hi + 1));
      if (n1 === void 0 || n2 === void 0)
        return err(e);
      array[ai] = n1 * 16 + n2;
    }
    return array;
  };
  var toU8 = (a, len) => abytes(isStr(a) ? hexToBytes(a) : u8fr(abytes(a)), len);
  var cr = () => globalThis?.crypto;
  var subtle = () => cr()?.subtle ?? err("crypto.subtle must be defined");
  var concatBytes = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
    let pad = 0;
    arrs.forEach((a) => {
      r.set(a, pad);
      pad += a.length;
    });
    return r;
  };
  var randomBytes = (len = L) => {
    const c = cr();
    return c.getRandomValues(u8n(len));
  };
  var big = BigInt;
  var arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
  var M = (a, b = P) => {
    const r = a % b;
    return r >= 0n ? r : b + r;
  };
  var modN = (a) => M(a, N);
  var invert = (num, md) => {
    if (num === 0n || md <= 0n)
      err("no inverse n=" + num + " mod=" + md);
    let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) {
      const q = b / a, r = b % a;
      const m = x - u * q, n = y - v * q;
      b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? M(x, md) : err("no inverse");
  };
  var apoint = (p) => p instanceof Point ? p : err("Point expected");
  var B256 = 2n ** 256n;
  var Point = class _Point {
    static BASE;
    static ZERO;
    ex;
    ey;
    ez;
    et;
    constructor(ex, ey, ez, et) {
      const max = B256;
      this.ex = arange(ex, 0n, max);
      this.ey = arange(ey, 0n, max);
      this.ez = arange(ez, 1n, max);
      this.et = arange(et, 0n, max);
      Object.freeze(this);
    }
    static fromAffine(p) {
      return new _Point(p.x, p.y, 1n, M(p.x * p.y));
    }
    /** RFC8032 5.1.3: Uint8Array to Point. */
    static fromBytes(hex, zip215 = false) {
      const d = _d;
      const normed = u8fr(abytes(hex, L));
      const lastByte = hex[31];
      normed[31] = lastByte & ~128;
      const y = bytesToNumLE(normed);
      const max = zip215 ? B256 : P;
      arange(y, 0n, max);
      const y2 = M(y * y);
      const u = M(y2 - 1n);
      const v = M(d * y2 + 1n);
      let { isValid, value: x } = uvRatio(u, v);
      if (!isValid)
        err("bad point: y not sqrt");
      const isXOdd = (x & 1n) === 1n;
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && x === 0n && isLastByteOdd)
        err("bad point: x==0, isLastByteOdd");
      if (isLastByteOdd !== isXOdd)
        x = M(-x);
      return new _Point(x, y, 1n, M(x * y));
    }
    /** Checks if the point is valid and on-curve. */
    assertValidity() {
      const a = _a;
      const d = _d;
      const p = this;
      if (p.is0())
        throw new Error("bad point: ZERO");
      const { ex: X, ey: Y, ez: Z, et: T } = p;
      const X2 = M(X * X);
      const Y2 = M(Y * Y);
      const Z2 = M(Z * Z);
      const Z4 = M(Z2 * Z2);
      const aX2 = M(X2 * a);
      const left = M(Z2 * M(aX2 + Y2));
      const right = M(Z4 + M(d * M(X2 * Y2)));
      if (left !== right)
        throw new Error("bad point: equation left != right (1)");
      const XY = M(X * Y);
      const ZT = M(Z * T);
      if (XY !== ZT)
        throw new Error("bad point: equation left != right (2)");
      return this;
    }
    /** Equality check: compare points P&Q. */
    equals(other) {
      const { ex: X1, ey: Y1, ez: Z1 } = this;
      const { ex: X2, ey: Y2, ez: Z2 } = apoint(other);
      const X1Z2 = M(X1 * Z2);
      const X2Z1 = M(X2 * Z1);
      const Y1Z2 = M(Y1 * Z2);
      const Y2Z1 = M(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(I);
    }
    /** Flip point over y coordinate. */
    negate() {
      return new _Point(M(-this.ex), this.ey, this.ez, M(-this.et));
    }
    /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
    double() {
      const { ex: X1, ey: Y1, ez: Z1 } = this;
      const a = _a;
      const A = M(X1 * X1);
      const B = M(Y1 * Y1);
      const C2 = M(2n * M(Z1 * Z1));
      const D = M(a * A);
      const x1y1 = X1 + Y1;
      const E = M(M(x1y1 * x1y1) - A - B);
      const G2 = D + B;
      const F = G2 - C2;
      const H = D - B;
      const X3 = M(E * F);
      const Y3 = M(G2 * H);
      const T3 = M(E * H);
      const Z3 = M(F * G2);
      return new _Point(X3, Y3, Z3, T3);
    }
    /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
    add(other) {
      const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
      const { ex: X2, ey: Y2, ez: Z2, et: T2 } = apoint(other);
      const a = _a;
      const d = _d;
      const A = M(X1 * X2);
      const B = M(Y1 * Y2);
      const C2 = M(T1 * d * T2);
      const D = M(Z1 * Z2);
      const E = M((X1 + Y1) * (X2 + Y2) - A - B);
      const F = M(D - C2);
      const G2 = M(D + C2);
      const H = M(B - a * A);
      const X3 = M(E * F);
      const Y3 = M(G2 * H);
      const T3 = M(E * H);
      const Z3 = M(F * G2);
      return new _Point(X3, Y3, Z3, T3);
    }
    /**
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n, safe = true) {
      if (!safe && (n === 0n || this.is0()))
        return I;
      arange(n, 1n, N);
      if (n === 1n)
        return this;
      if (this.equals(G))
        return wNAF(n).p;
      let p = I;
      let f = G;
      for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
        if (n & 1n)
          p = p.add(d);
        else if (safe)
          f = f.add(d);
      }
      return p;
    }
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine() {
      const { ex: x, ey: y, ez: z } = this;
      if (this.equals(I))
        return { x: 0n, y: 1n };
      const iz = invert(z, P);
      if (M(z * iz) !== 1n)
        err("invalid inverse");
      return { x: M(x * iz), y: M(y * iz) };
    }
    toBytes() {
      const { x, y } = this.assertValidity().toAffine();
      const b = numTo32bLE(y);
      b[31] |= x & 1n ? 128 : 0;
      return b;
    }
    toHex() {
      return bytesToHex(this.toBytes());
    }
    // encode to hex string
    clearCofactor() {
      return this.multiply(big(h), false);
    }
    isSmallOrder() {
      return this.clearCofactor().is0();
    }
    isTorsionFree() {
      let p = this.multiply(N / 2n, false).double();
      if (N % 2n)
        p = p.add(this);
      return p.is0();
    }
    static fromHex(hex, zip215) {
      return _Point.fromBytes(toU8(hex), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    toRawBytes() {
      return this.toBytes();
    }
  };
  var G = new Point(Gx, Gy, 1n, M(Gx * Gy));
  var I = new Point(0n, 1n, 1n, 0n);
  Point.BASE = G;
  Point.ZERO = I;
  var numTo32bLE = (num) => hexToBytes(padh(arange(num, 0n, B256), L2)).reverse();
  var bytesToNumLE = (b) => big("0x" + bytesToHex(u8fr(abytes(b)).reverse()));
  var pow2 = (x, power) => {
    let r = x;
    while (power-- > 0n) {
      r *= r;
      r %= P;
    }
    return r;
  };
  var pow_2_252_3 = (x) => {
    const x2 = x * x % P;
    const b2 = x2 * x % P;
    const b4 = pow2(b2, 2n) * b2 % P;
    const b5 = pow2(b4, 1n) * x % P;
    const b10 = pow2(b5, 5n) * b5 % P;
    const b20 = pow2(b10, 10n) * b10 % P;
    const b40 = pow2(b20, 20n) * b20 % P;
    const b80 = pow2(b40, 40n) * b40 % P;
    const b160 = pow2(b80, 80n) * b80 % P;
    const b240 = pow2(b160, 80n) * b80 % P;
    const b250 = pow2(b240, 10n) * b10 % P;
    const pow_p_5_8 = pow2(b250, 2n) * x % P;
    return { pow_p_5_8, b2 };
  };
  var RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
  var uvRatio = (u, v) => {
    const v3 = M(v * v * v);
    const v7 = M(v3 * v3 * v);
    const pow = pow_2_252_3(u * v7).pow_p_5_8;
    let x = M(u * v3 * pow);
    const vx2 = M(v * x * x);
    const root1 = x;
    const root2 = M(x * RM1);
    const useRoot1 = vx2 === u;
    const useRoot2 = vx2 === M(-u);
    const noRoot = vx2 === M(-u * RM1);
    if (useRoot1)
      x = root1;
    if (useRoot2 || noRoot)
      x = root2;
    if ((M(x) & 1n) === 1n)
      x = M(-x);
    return { isValid: useRoot1 || useRoot2, value: x };
  };
  var modL_LE = (hash) => modN(bytesToNumLE(hash));
  var sha512a = (...m) => etc.sha512Async(...m);
  var hash2extK = (hashed) => {
    const head = hashed.slice(0, L);
    head[0] &= 248;
    head[31] &= 127;
    head[31] |= 64;
    const prefix = hashed.slice(L, L2);
    const scalar = modL_LE(head);
    const point = G.multiply(scalar);
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  };
  var getExtendedPublicKeyAsync = (priv) => sha512a(toU8(priv, L)).then(hash2extK);
  var hashFinishA = (res) => sha512a(res.hashable).then(res.finish);
  var _sign = (e, rBytes, msg) => {
    const { pointBytes: P2, scalar: s } = e;
    const r = modL_LE(rBytes);
    const R = G.multiply(r).toBytes();
    const hashable = concatBytes(R, P2, msg);
    const finish = (hashed) => {
      const S = modN(r + modL_LE(hashed) * s);
      return abytes(concatBytes(R, numTo32bLE(S)), L2);
    };
    return { hashable, finish };
  };
  var signAsync = async (msg, privKey) => {
    const m = toU8(msg);
    const e = await getExtendedPublicKeyAsync(privKey);
    const rBytes = await sha512a(e.prefix, m);
    return hashFinishA(_sign(e, rBytes, m));
  };
  var etc = {
    sha512Async: async (...messages) => {
      const s = subtle();
      const m = concatBytes(...messages);
      return u8n(await s.digest("SHA-512", m.buffer));
    },
    sha512Sync: void 0,
    bytesToHex,
    hexToBytes,
    concatBytes,
    mod: M,
    invert,
    randomBytes
  };
  var W = 8;
  var scalarBits = 256;
  var pwindows = Math.ceil(scalarBits / W) + 1;
  var pwindowSize = 2 ** (W - 1);
  var precompute = () => {
    const points = [];
    let p = G;
    let b = p;
    for (let w = 0; w < pwindows; w++) {
      b = p;
      points.push(b);
      for (let i = 1; i < pwindowSize; i++) {
        b = b.add(p);
        points.push(b);
      }
      p = b.double();
    }
    return points;
  };
  var Gpows = void 0;
  var ctneg = (cnd, p) => {
    const n = p.negate();
    return cnd ? n : p;
  };
  var wNAF = (n) => {
    const comp = Gpows || (Gpows = precompute());
    let p = I;
    let f = G;
    const pow_2_w = 2 ** W;
    const maxNum = pow_2_w;
    const mask = big(pow_2_w - 1);
    const shiftBy = big(W);
    for (let w = 0; w < pwindows; w++) {
      let wbits = Number(n & mask);
      n >>= shiftBy;
      if (wbits > pwindowSize) {
        wbits -= maxNum;
        n += 1n;
      }
      const off = w * pwindowSize;
      const offF = off;
      const offP = off + Math.abs(wbits) - 1;
      const isEven = w % 2 !== 0;
      const isNeg = wbits < 0;
      if (wbits === 0) {
        f = f.add(ctneg(isEven, comp[offF]));
      } else {
        p = p.add(ctneg(isNeg, comp[offP]));
      }
    }
    return { p, f };
  };

  // ../pkg/js-client/node_modules/@noble/hashes/esm/utils.js
  function isBytes2(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  }
  function abytes2(b, ...lengths) {
    if (!isBytes2(b))
      throw new Error("Uint8Array expected");
    if (lengths.length > 0 && !lengths.includes(b.length))
      throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function aoutput(out, instance) {
    abytes2(out);
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error("digestInto() expects output buffer of length at least " + min);
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function utf8ToBytes(str) {
    if (typeof str !== "string")
      throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str));
  }
  function toBytes(data) {
    if (typeof data === "string")
      data = utf8ToBytes(data);
    abytes2(data);
    return data;
  }
  var Hash = class {
  };
  function createHasher(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
  }

  // ../pkg/js-client/node_modules/@noble/hashes/esm/_md.js
  function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === "function")
      return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(4294967295);
    const wh = Number(value >> _32n & _u32_max);
    const wl = Number(value & _u32_max);
    const h2 = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h2, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
  }
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD = class extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
      super();
      this.finished = false;
      this.length = 0;
      this.pos = 0;
      this.destroyed = false;
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
    }
    update(data) {
      aexists(this);
      data = toBytes(data);
      abytes2(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView(data);
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
        }
      }
      this.length += data.length;
      this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      clean(this.buffer.subarray(pos));
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        pos = 0;
      }
      for (let i = pos; i < blockLen; i++)
        buffer[i] = 0;
      setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
      this.process(view, 0);
      const oview = createView(out);
      const len = this.outputLen;
      if (len % 4)
        throw new Error("_sha2: outputLen should be aligned to 32bit");
      const outLen = len / 4;
      const state = this.get();
      if (outLen > state.length)
        throw new Error("_sha2: outputLen bigger than state");
      for (let i = 0; i < outLen; i++)
        oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneInto(to) {
      to || (to = new this.constructor());
      to.set(...this.get());
      const { blockLen, buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (length % blockLen)
        to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
  ]);

  // ../pkg/js-client/node_modules/@noble/hashes/esm/sha2.js
  var SHA256_K = /* @__PURE__ */ Uint32Array.from([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
  var SHA256 = class extends HashMD {
    constructor(outputLen = 32) {
      super(64, outputLen, 8, false);
      this.A = SHA256_IV[0] | 0;
      this.B = SHA256_IV[1] | 0;
      this.C = SHA256_IV[2] | 0;
      this.D = SHA256_IV[3] | 0;
      this.E = SHA256_IV[4] | 0;
      this.F = SHA256_IV[5] | 0;
      this.G = SHA256_IV[6] | 0;
      this.H = SHA256_IV[7] | 0;
    }
    get() {
      const { A, B, C: C2, D, E, F, G: G2, H } = this;
      return [A, B, C2, D, E, F, G2, H];
    }
    // prettier-ignore
    set(A, B, C2, D, E, F, G2, H) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C2 | 0;
      this.D = D | 0;
      this.E = E | 0;
      this.F = F | 0;
      this.G = G2 | 0;
      this.H = H | 0;
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4)
        SHA256_W[i] = view.getUint32(offset, false);
      for (let i = 16; i < 64; i++) {
        const W15 = SHA256_W[i - 15];
        const W2 = SHA256_W[i - 2];
        const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
        const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
        SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
      }
      let { A, B, C: C2, D, E, F, G: G2, H } = this;
      for (let i = 0; i < 64; i++) {
        const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
        const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        const T2 = sigma0 + Maj(A, B, C2) | 0;
        H = G2;
        G2 = F;
        F = E;
        E = D + T1 | 0;
        D = C2;
        C2 = B;
        B = A;
        A = T1 + T2 | 0;
      }
      A = A + this.A | 0;
      B = B + this.B | 0;
      C2 = C2 + this.C | 0;
      D = D + this.D | 0;
      E = E + this.E | 0;
      F = F + this.F | 0;
      G2 = G2 + this.G | 0;
      H = H + this.H | 0;
      this.set(A, B, C2, D, E, F, G2, H);
    }
    roundClean() {
      clean(SHA256_W);
    }
    destroy() {
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
      clean(this.buffer);
    }
  };
  var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());

  // ../pkg/js-client/node_modules/@noble/hashes/esm/sha256.js
  var sha2562 = sha256;

  // ../pkg/js-client/dist/index.mjs
  var __require2 = /* @__PURE__ */ ((x) => typeof __require !== "undefined" ? __require : typeof Proxy !== "undefined" ? new Proxy(x, {
    get: (a, b) => (typeof __require !== "undefined" ? __require : a)[b]
  }) : x)(function(x) {
    if (typeof __require !== "undefined") return __require.apply(this, arguments);
    throw Error('Dynamic require of "' + x + '" is not supported');
  });
  function parsePrivateKey(key) {
    if (key instanceof Uint8Array) {
      if (key.length === 32) {
        return key;
      } else if (key.length === 64) {
        return key.slice(0, 32);
      } else {
        throw new Error(
          `Invalid private key length: expected 32 or 64 bytes, got ${key.length}`
        );
      }
    }
    const trimmed = key.trim();
    if (trimmed.includes("BEGIN PRIVATE KEY")) {
      const match = trimmed.match(
        /-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/
      );
      if (!match) {
        throw new Error("malformed PKCS#8 PEM block");
      }
      const b64 = match[1].replace(/\s+/g, "");
      const bin = atob(b64);
      const der = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        der[i] = bin.charCodeAt(i);
      }
      if (der.length < 32) {
        throw new Error(`PKCS#8 DER too short: ${der.length} bytes`);
      }
      return der.slice(-32);
    }
    const hex = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error("expected hex or PKCS#8 PEM input");
    }
    const bytes = new Uint8Array(
      hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
    if (bytes.length === 32) {
      return bytes;
    } else if (bytes.length === 64) {
      return bytes.slice(0, 32);
    } else {
      throw new Error(
        `Invalid private key length: expected 32 or 64 bytes (hex), got ${bytes.length}`
      );
    }
  }
  function generateNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function signRequestWithNonce(privateKey, timestamp, nonce, method, path, body) {
    const bodyHash = sha2562(body);
    const message = `${timestamp}|${nonce}|${method}|${path}|${bytesToHex2(bodyHash)}`;
    const messageBytes = new TextEncoder().encode(message);
    const signature = await signAsync(messageBytes, privateKey);
    return btoa(String.fromCharCode(...Array.from(signature)));
  }
  function bytesToHex2(b) {
    let out = "";
    for (const v of b) {
      out += v.toString(16).padStart(2, "0");
    }
    return out;
  }
  var RemoteSignerError = class extends Error {
    constructor(message, code) {
      super(message);
      this.code = code;
      this.name = "RemoteSignerError";
    }
  };
  var APIError = class extends RemoteSignerError {
    constructor(message, statusCode, code) {
      super(message, code);
      this.statusCode = statusCode;
      this.name = "APIError";
    }
  };
  var SignError = class extends RemoteSignerError {
    constructor(message, requestID, status) {
      super(message);
      this.requestID = requestID;
      this.status = status;
      this.name = "SignError";
    }
  };
  var TimeoutError = class extends RemoteSignerError {
    constructor(message = "Timeout waiting for approval") {
      super(message);
      this.name = "TimeoutError";
    }
  };
  var HttpTransport = class _HttpTransport {
    constructor(config) {
      if (!config.baseURL) {
        throw new Error("baseURL is required");
      }
      if (!config.apiKeyID) {
        throw new Error("apiKeyID is required");
      }
      if (!config.privateKey) {
        throw new Error("privateKey is required");
      }
      this.baseURL = config.baseURL.replace(/\/$/, "");
      this.apiKeyID = config.apiKeyID;
      this.privateKey = parsePrivateKey(config.privateKey);
      const timeout = config.httpClient?.timeout ?? 3e4;
      const base = config.baseURL.replace(/\/$/, "");
      const isHttps = base.toLowerCase().startsWith("https://");
      if (config.httpClient?.fetch) {
        this.httpClient = { fetch: config.httpClient.fetch, timeout };
      } else if (_HttpTransport.isNodeJS() && (isHttps || config.httpClient?.tls)) {
        this.httpClient = {
          fetch: _HttpTransport.createNodeTLSFetch(config.httpClient?.tls ?? {}),
          timeout
        };
      } else {
        this.httpClient = {
          fetch: globalThis.fetch.bind(globalThis),
          timeout
        };
      }
    }
    /**
     * Detect if running in Node.js environment.
     */
    static isNodeJS() {
      return typeof process !== "undefined" && process.versions != null && process.versions.node != null;
    }
    /**
     * Create a fetch function with TLS/mTLS support for Node.js.
     * Uses Node.js built-in https.Agent for certificate configuration.
     *
     * @param tlsConfig - TLS configuration with CA, client cert, and key
     * @returns A fetch-compatible function with TLS configured
     */
    static createNodeTLSFetch(tlsConfig) {
      const https = __require2("https");
      const agent = new https.Agent({
        ca: tlsConfig.ca,
        cert: tlsConfig.cert,
        key: tlsConfig.key,
        rejectUnauthorized: tlsConfig.rejectUnauthorized ?? true
      });
      const fetchWithTLS = (input, init) => {
        const url = typeof input === "string" ? input : input.toString();
        const method = init?.method ?? "GET";
        const headers = init?.headers;
        const body = init?.body;
        const signal = init?.signal;
        return new Promise((resolve, reject) => {
          if (signal?.aborted) {
            const err2 = new Error("The operation was aborted.");
            err2.name = "AbortError";
            reject(err2);
            return;
          }
          const parsed = new URL(url);
          const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method,
            headers: headers || {},
            agent: parsed.protocol === "https:" ? agent : void 0
          };
          const proto = parsed.protocol === "https:" ? https : __require2("http");
          const req = proto.request(options, (res) => {
            const chunks = [];
            res.on("data", (chunk) => chunks.push(chunk));
            res.on("end", () => {
              const buffer = Buffer.concat(chunks);
              const bodyText = buffer.toString("utf-8");
              resolve({
                ok: res.statusCode >= 200 && res.statusCode < 300,
                status: res.statusCode,
                statusText: res.statusMessage || "",
                headers: {
                  get: (name) => res.headers[name.toLowerCase()] || null
                },
                text: () => Promise.resolve(bodyText),
                json: () => Promise.resolve(JSON.parse(bodyText))
              });
            });
            res.on("error", reject);
          });
          req.on("error", reject);
          if (signal) {
            const onAbort = () => {
              req.destroy();
              const err2 = new Error("The operation was aborted.");
              err2.name = "AbortError";
              reject(err2);
            };
            signal.addEventListener("abort", onAbort, { once: true });
            req.on("close", () => signal.removeEventListener("abort", onAbort));
          }
          if (body) {
            req.write(body);
          }
          req.end();
        });
      };
      return fetchWithTLS;
    }
    /**
     * Make an authenticated HTTP request.
     */
    async request(method, path, body) {
      const url = this.baseURL + path;
      const bodyBytes = body ? new TextEncoder().encode(JSON.stringify(body)) : new Uint8Array(0);
      const timestamp = Date.now();
      const nonce = generateNonce();
      const signature = await signRequestWithNonce(
        this.privateKey,
        timestamp,
        nonce,
        method,
        path,
        bodyBytes
      );
      const headers = {
        "X-API-Key-ID": this.apiKeyID,
        "X-Timestamp": timestamp.toString(),
        "X-Nonce": nonce,
        "X-Signature": signature
      };
      if (body) {
        headers["Content-Type"] = "application/json";
      }
      return this.doFetch(url, method, headers, body);
    }
    /**
     * Make an unauthenticated HTTP request (for /health, /metrics).
     */
    async requestNoAuth(method, path) {
      const url = this.baseURL + path;
      return this.doFetch(url, method, {}, null);
    }
    /**
     * Execute the actual HTTP fetch with timeout and error handling.
     */
    async doFetch(url, method, headers, body) {
      const controller = new AbortController();
      const timeoutId = this.httpClient.timeout ? setTimeout(() => controller.abort(), this.httpClient.timeout) : null;
      try {
        const response = await this.httpClient.fetch(url, {
          method,
          headers,
          body: body ? JSON.stringify(body) : void 0,
          signal: controller.signal
        });
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
        const responseBody = await response.text();
        let data;
        try {
          data = responseBody ? JSON.parse(responseBody) : {};
        } catch {
          data = { message: responseBody };
        }
        if (!response.ok) {
          const env = data;
          const description = env.error || env.message || (typeof data === "string" ? data : "") || `HTTP ${response.status}`;
          throw new APIError(description, response.status, env.error);
        }
        return data;
      } catch (error) {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
        if (error instanceof APIError) {
          throw error;
        }
        if (error instanceof Error && error.name === "AbortError") {
          throw new TimeoutError("Request timeout");
        }
        throw new RemoteSignerError(
          error instanceof Error ? error.message : "Unknown error"
        );
      }
    }
  };
  var EvmSignService = class {
    constructor(transport, pollInterval, pollTimeout) {
      this.transport = transport;
      this.pollInterval = pollInterval;
      this.pollTimeout = pollTimeout;
    }
    /**
     * Submit a signing request and poll until completion or timeout.
     */
    async execute(request) {
      return this.doSign(request, true);
    }
    /**
     * Submit a signing request without waiting for completion.
     */
    async executeAsync(request) {
      return this.doSign(request, false);
    }
    /**
     * Submit a batch of signing requests atomically.
     * If any transaction fails rules/budget/simulation, the entire batch is rejected.
     */
    async executeBatch(request) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/sign/batch",
        request
      );
    }
    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------
    async doSign(request, waitForApproval) {
      const response = await this.transport.request(
        "POST",
        "/api/v1/evm/sign",
        request
      );
      if (response.status === "completed") {
        return response;
      }
      if (response.status === "rejected" || response.status === "failed") {
        throw new SignError(
          response.message || "Request rejected or failed",
          response.request_id,
          response.status
        );
      }
      if (waitForApproval && (response.status === "pending" || response.status === "authorizing")) {
        return this.pollForResult(response.request_id);
      }
      throw new SignError(
        response.message || "Pending manual approval",
        response.request_id,
        response.status
      );
    }
    /**
     * Poll for the result of a pending request.
     */
    async pollForResult(requestID) {
      const deadline = Date.now() + this.pollTimeout;
      const poll = async () => {
        if (Date.now() > deadline) {
          throw new TimeoutError();
        }
        const status = await this.transport.request(
          "GET",
          `/api/v1/evm/requests/${requestID}`,
          null
        );
        switch (status.status) {
          case "completed":
            return {
              request_id: status.id,
              status: status.status,
              signature: status.signature,
              signed_data: status.signed_data,
              rule_matched_id: status.rule_matched_id || void 0
            };
          case "rejected":
          case "failed":
            throw new SignError(
              status.error_message || "Request rejected or failed",
              status.id,
              status.status
            );
          default:
            await new Promise((resolve) => setTimeout(resolve, this.pollInterval));
            return poll();
        }
      };
      return poll();
    }
  };
  var EvmRequestService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * Get the status of a signing request.
     */
    async get(requestID) {
      return this.transport.request(
        "GET",
        `/api/v1/evm/requests/${requestID}`,
        null
      );
    }
    /**
     * List signing requests with optional filters.
     */
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.status) {
        params.append("status", filter.status);
      }
      if (filter?.signer_address) {
        params.append("signer_address", filter.signer_address);
      }
      if (filter?.chain_id) {
        params.append("chain_id", filter.chain_id);
      }
      if (filter?.limit) {
        params.append("limit", filter.limit.toString());
      }
      if (filter?.cursor) {
        params.append("cursor", filter.cursor);
      }
      if (filter?.cursor_id) {
        params.append("cursor_id", filter.cursor_id);
      }
      const queryString = params.toString();
      const path = `/api/v1/evm/requests${queryString ? `?${queryString}` : ""}`;
      return this.transport.request("GET", path, null);
    }
    /**
     * Approve or reject a pending request.
     */
    async approve(requestID, approveRequest) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/requests/${requestID}/approve`,
        approveRequest
      );
    }
    /**
     * Preview what rule would be generated for a pending request.
     */
    async previewRule(requestID, previewRequest) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/requests/${requestID}/preview-rule`,
        previewRequest
      );
    }
  };
  var EvmRuleService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List rules with optional filters.
     */
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.chain_type) params.append("chain_type", filter.chain_type);
      if (filter?.signer_address) params.append("signer_address", filter.signer_address);
      if (filter?.api_key_id) params.append("api_key_id", filter.api_key_id);
      if (filter?.type) params.append("type", filter.type);
      if (filter?.mode) params.append("mode", filter.mode);
      if (filter?.enabled !== void 0) params.append("enabled", String(filter.enabled));
      if (filter?.limit) params.append("limit", filter.limit.toString());
      if (filter?.offset) params.append("offset", filter.offset.toString());
      const qs = params.toString();
      return this.transport.request(
        "GET",
        `/api/v1/evm/rules${qs ? `?${qs}` : ""}`,
        null
      );
    }
    /**
     * Get a rule by ID.
     */
    async get(ruleID) {
      return this.transport.request(
        "GET",
        `/api/v1/evm/rules/${ruleID}`,
        null
      );
    }
    /**
     * Create a new rule.
     */
    async create(rule) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/rules",
        rule
      );
    }
    /**
     * Update an existing rule.
     */
    async update(ruleID, update) {
      return this.transport.request(
        "PATCH",
        `/api/v1/evm/rules/${ruleID}`,
        update
      );
    }
    /**
     * Delete a rule.
     */
    async delete(ruleID) {
      await this.transport.request(
        "DELETE",
        `/api/v1/evm/rules/${ruleID}`,
        null
      );
    }
    /**
     * Toggle a rule's enabled state.
     */
    async toggle(ruleID, enabled) {
      return this.update(ruleID, { enabled });
    }
    /**
     * List budgets for a rule (GET /api/v1/evm/rules/{ruleID}/budgets).
     */
    async listBudgets(ruleID) {
      const list = await this.transport.request(
        "GET",
        `/api/v1/evm/rules/${encodeURIComponent(ruleID)}/budgets`,
        null
      );
      return list ?? [];
    }
    /**
     * Approve a pending rule (POST /api/v1/evm/rules/{ruleID}/approve).
     */
    async approve(ruleID) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/rules/${encodeURIComponent(ruleID)}/approve`,
        null
      );
    }
    /**
     * Reject a pending rule (POST /api/v1/evm/rules/{ruleID}/reject).
     */
    async reject(ruleID, reason) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/rules/${encodeURIComponent(ruleID)}/reject`,
        { reason }
      );
    }
  };
  var EvmSignerService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List signers with optional filters.
     */
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.type) params.append("type", filter.type);
      if (filter?.offset) params.append("offset", filter.offset.toString());
      if (filter?.limit) params.append("limit", filter.limit.toString());
      const qs = params.toString();
      return this.transport.request(
        "GET",
        `/api/v1/evm/signers${qs ? `?${qs}` : ""}`,
        null
      );
    }
    /**
     * Create a new keystore signer.
     */
    async create(req) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/signers",
        req
      );
    }
    /**
     * Unlock a locked signer (admin only).
     */
    async unlock(address, req) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/signers/${address}/unlock`,
        req
      );
    }
    /**
     * Lock an unlocked signer (admin only).
     */
    async lock(address) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/signers/${address}/lock`,
        null
      );
    }
    /**
     * Approve a pending signer (admin only).
     */
    async approveSigner(address) {
      await this.transport.request(
        "POST",
        `/api/v1/evm/signers/${address}/approve`,
        null
      );
    }
    /**
     * Grant access to a signer for another API key (owner only).
     */
    async grantAccess(address, req) {
      await this.transport.request(
        "POST",
        `/api/v1/evm/signers/${address}/access`,
        req
      );
    }
    /**
     * Revoke access from a signer for an API key (owner only).
     */
    async revokeAccess(address, apiKeyId) {
      await this.transport.request(
        "DELETE",
        `/api/v1/evm/signers/${address}/access/${apiKeyId}`,
        null
      );
    }
    /**
     * List access grants for a signer (owner only).
     */
    async listAccess(address) {
      const list = await this.transport.request(
        "GET",
        `/api/v1/evm/signers/${address}/access`,
        null
      );
      return list ?? [];
    }
    /**
     * Transfer signer ownership to a new API key (owner only).
     * Clears the entire access list; old owner loses ALL access.
     */
    async transferOwnership(address, req) {
      await this.transport.request(
        "POST",
        `/api/v1/evm/signers/${address}/transfer`,
        req
      );
    }
    /**
     * Delete a signer's ownership and access records (owner only).
     */
    async deleteSigner(address) {
      await this.transport.request(
        "DELETE",
        `/api/v1/evm/signers/${address}`,
        null
      );
    }
  };
  var RemoteSigner = class {
    constructor(signService, address, chainID) {
      this.signService = signService;
      this.address = address;
      this._chainID = chainID;
    }
    get chainID() {
      return this._chainID;
    }
    /** Update the chain ID for subsequent signing requests. */
    setChainID(chainID) {
      this._chainID = chainID;
    }
    getAddress() {
      return this.address;
    }
    /** Sign a pre-computed 32-byte hash (0x-prefixed hex). */
    async signHash(hash) {
      const resp = await this.signService.execute({
        chain_id: this._chainID,
        signer_address: this.address,
        sign_type: "hash",
        payload: { hash }
      });
      return resp.signature;
    }
    /** Sign raw message bytes (base64-encoded string or Uint8Array). */
    async signRawMessage(rawMessage) {
      const resp = await this.signService.execute({
        chain_id: this._chainID,
        signer_address: this.address,
        sign_type: "raw_message",
        payload: { raw_message: rawMessage }
      });
      return resp.signature;
    }
    /** Sign an EIP-191 formatted message. */
    async signEIP191Message(message) {
      const resp = await this.signService.execute({
        chain_id: this._chainID,
        signer_address: this.address,
        sign_type: "eip191",
        payload: { message }
      });
      return resp.signature;
    }
    /** Sign using personal_sign (EIP-191 version 0x45). */
    async personalSign(message) {
      console.log("[RemoteSigner] personalSign called:", {
        address: this.address,
        chainId: this._chainID,
        message
      });
      const resp = await this.signService.execute({
        chain_id: this._chainID,
        signer_address: this.address,
        sign_type: "personal",
        payload: { message }
      });
      console.log("[RemoteSigner] personalSign response:", resp);
      return resp.signature;
    }
    /** Sign EIP-712 typed data. */
    async signTypedData(typedData) {
      const resp = await this.signService.execute({
        chain_id: this._chainID,
        signer_address: this.address,
        sign_type: "typed_data",
        payload: { typed_data: typedData }
      });
      return resp.signature;
    }
    /** Sign an EVM transaction. Returns signed transaction hex. */
    async signTransaction(transaction) {
      const resp = await this.signService.execute({
        chain_id: this._chainID,
        signer_address: this.address,
        sign_type: "transaction",
        payload: { transaction }
      });
      return resp.signed_data;
    }
  };
  var EvmHDWalletService = class {
    constructor(transport, signService) {
      this.transport = transport;
      this.signService = signService;
    }
    /**
     * Create a new HD wallet.
     */
    async create(req) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/hd-wallets",
        { action: "create", ...req }
      );
    }
    /**
     * Import an HD wallet from a mnemonic.
     */
    async import(req) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/hd-wallets",
        { action: "import", ...req }
      );
    }
    /**
     * List all HD wallets.
     */
    async list() {
      return this.transport.request(
        "GET",
        "/api/v1/evm/hd-wallets",
        null
      );
    }
    /**
     * Derive address(es) from an HD wallet.
     */
    async deriveAddress(primaryAddr, req) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/hd-wallets/${primaryAddr}/derive`,
        req
      );
    }
    /**
     * List derived addresses for an HD wallet.
     */
    async listDerived(primaryAddr) {
      return this.transport.request(
        "GET",
        `/api/v1/evm/hd-wallets/${primaryAddr}/derived`,
        null
      );
    }
    /**
     * Derive (if needed) the address at the given index and return a RemoteSigner.
     * The RemoteSigner provides convenience methods (signHash, personalSign, etc.)
     * mirroring the Go client's RemoteSigner.
     */
    async getSigner(primaryAddr, chainId, index) {
      const resp = await this.deriveAddress(primaryAddr, { index });
      if (!resp.derived.length) {
        throw new Error(`no address derived at index ${index}`);
      }
      return new RemoteSigner(this.signService, resp.derived[0].address, chainId);
    }
    /**
     * Derive a batch of addresses and return RemoteSigner instances.
     */
    async getSigners(primaryAddr, chainId, start, count) {
      const resp = await this.deriveAddress(primaryAddr, { start, count });
      return resp.derived.map(
        (d) => new RemoteSigner(this.signService, d.address, chainId)
      );
    }
  };
  var EvmGuardService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * Resume the guard (e.g. after a pause or restart).
     */
    async resume() {
      await this.transport.request(
        "POST",
        "/api/v1/evm/guard/resume",
        null
      );
    }
  };
  var EvmSimulateService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * Simulate a single transaction.
     */
    async simulate(req) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/simulate",
        req
      );
    }
    /**
     * Simulate multiple transactions in sequence.
     */
    async simulateBatch(req) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/simulate/batch",
        req
      );
    }
    /**
     * Get simulation engine status (enabled flag, engine id string, optional per-chain details).
     */
    async status() {
      return this.transport.request(
        "GET",
        "/api/v1/evm/simulate/status",
        null
      );
    }
  };
  var EvmBudgetService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List every budget row visible to the caller.
     *
     * Admin/dev see all rows including synthetic simulation budgets;
     * agents see only budgets attached to rules they own and never see
     * simulation budgets (signer-level spend across peers is operator
     * information).
     */
    async list() {
      return this.transport.request(
        "GET",
        "/api/v1/evm/budgets",
        null
      );
    }
    /** Fetch a single budget by its primary key. */
    async get(id) {
      return this.transport.request(
        "GET",
        `/api/v1/evm/budgets/${encodeURIComponent(id)}`,
        null
      );
    }
    /** Create a budget for an existing rule. Admin only. */
    async create(req) {
      return this.transport.request(
        "POST",
        "/api/v1/evm/budgets",
        req
      );
    }
    /** Patch mutable fields on an existing budget. Admin only. */
    async update(id, req) {
      return this.transport.request(
        "PATCH",
        `/api/v1/evm/budgets/${encodeURIComponent(id)}`,
        req
      );
    }
    /** Zero spent/tx_count/alert_sent in one shot. Admin only. */
    async reset(id) {
      return this.transport.request(
        "POST",
        `/api/v1/evm/budgets/${encodeURIComponent(id)}/reset`,
        null
      );
    }
    /** Delete a budget row. Admin only. */
    async delete(id) {
      await this.transport.request(
        "DELETE",
        `/api/v1/evm/budgets/${encodeURIComponent(id)}`,
        null
      );
    }
  };
  var ProviderRpcError = class _ProviderRpcError extends Error {
    constructor(code, message, data) {
      super(message);
      this.name = "ProviderRpcError";
      this.code = code;
      this.data = data;
      if (Error.captureStackTrace) {
        Error.captureStackTrace(this, _ProviderRpcError);
      }
    }
    /**
     * Convert error to JSON-RPC error format
     */
    toJSON() {
      return {
        code: this.code,
        message: this.message,
        ...this.data !== void 0 && { data: this.data }
      };
    }
  };
  var providerErrors = {
    userRejectedRequest: (message = "User rejected the request") => new ProviderRpcError(4001, message),
    unauthorized: (message = "Unauthorized to perform this action") => new ProviderRpcError(4100, message),
    unsupportedMethod: (method) => new ProviderRpcError(
      4200,
      `The method "${method}" is not supported`
    ),
    disconnected: (message = "Provider is disconnected from all chains") => new ProviderRpcError(4900, message),
    chainDisconnected: (chainId) => new ProviderRpcError(
      4901,
      `Provider is not connected to chain ${chainId}`
    ),
    /**
     * Create a custom RPC error
     */
    rpc: (code, message, data) => new ProviderRpcError(code, message, data)
  };
  function normalizeEip1193Tx(tx) {
    const hexToDec = (v) => {
      if (v == null) return void 0;
      if (typeof v === "string") {
        if (v.startsWith("0x") || v.startsWith("0X")) return BigInt(v).toString(10);
        return v;
      }
      if (typeof v === "number" || typeof v === "bigint") return BigInt(v).toString(10);
      return String(v);
    };
    const hexToNum = (v) => {
      if (v == null) return void 0;
      if (typeof v === "number") return v;
      if (typeof v === "string") {
        return v.startsWith("0x") || v.startsWith("0X") ? Number(BigInt(v)) : Number(v);
      }
      return Number(v);
    };
    const hasMaxFee = tx.maxFeePerGas != null || tx.maxPriorityFeePerGas != null;
    const out = {
      to: tx.to,
      value: hexToDec(tx.value) ?? "0",
      data: tx.data ?? tx.input,
      nonce: hexToNum(tx.nonce),
      // EIP-1193 uses "gas"; our struct names it the same.
      gas: hexToNum(tx.gas ?? tx.gasLimit) ?? 0,
      txType: tx.txType ?? (hasMaxFee ? "eip1559" : "legacy")
    };
    if (tx.gasPrice != null) out.gasPrice = hexToDec(tx.gasPrice);
    if (tx.maxFeePerGas != null) out.gasFeeCap = hexToDec(tx.maxFeePerGas);
    if (tx.maxPriorityFeePerGas != null) out.gasTipCap = hexToDec(tx.maxPriorityFeePerGas);
    return out;
  }
  var EIP1193Provider = class _EIP1193Provider {
    /**
     * Private constructor - use EIP1193Provider.create() instead
     */
    constructor(config) {
      this._signers = [];
      this._activeIndex = 0;
      this._connected = false;
      this._eventHandlers = /* @__PURE__ */ new Map();
      this.isMetaMask = true;
      this._chainId = config.defaultChainId ?? 1;
      this._activeIndex = config.defaultAccountIndex ?? 0;
      this._rpcOverrides = config.rpcOverrides ?? {};
      this._rpcResolver = config.rpcResolver;
    }
    /**
     * Create and initialize a new EIP-1193 Provider
     *
     * This async factory method replaces the constructor to support async initialization
     *
     * @param config Provider configuration with signersSource
     * @returns Initialized provider instance
     * @throws {ProviderRpcError} If initialization fails
     */
    static async create(config) {
      const provider2 = new _EIP1193Provider(config);
      await provider2._initializeSigners(config.signersSource);
      if (provider2._signers.length > 0) {
        if (provider2._activeIndex >= provider2._signers.length) {
          provider2._activeIndex = 0;
        }
        provider2._connected = true;
        provider2._emit("connect", {
          chainId: `0x${provider2._chainId.toString(16)}`
        });
      }
      return provider2;
    }
    /**
     * Initialize signers from the configured source
     *
     * Supports three modes:
     * 1. client: Auto-fetch from remote-signer backend (filters enabled & unlocked)
     * 2. hdwallet: Batch derive from HD wallet
     * 3. manual: Use pre-created RemoteSigner array
     */
    async _initializeSigners(source) {
      switch (source.type) {
        case "client": {
          const { signers: signerInfos } = await source.client.evm.signers.list();
          const validSigners = signerInfos.filter((s) => s.enabled && !s.locked);
          this._signers = validSigners.map(
            (info) => new RemoteSigner(
              source.client.evm.sign,
              info.address,
              source.chainId?.toString() ?? this._chainId.toString()
            )
          );
          break;
        }
        case "hdwallet": {
          const start = source.start ?? 0;
          const count = source.count ?? 10;
          this._signers = await source.client.evm.hdWallets.getSigners(
            source.primaryAddress,
            source.chainId,
            start,
            count
          );
          break;
        }
        case "manual": {
          this._signers = [...source.signers];
          break;
        }
        default:
          throw new Error("Invalid signers source type");
      }
    }
    /**
     * Get current active account address
     * Returns null if not connected or no accounts
     */
    get selectedAddress() {
      return this._connected && this._signers.length > 0 ? this._signers[this._activeIndex].address : null;
    }
    /**
     * Get current chain ID as hex string
     */
    get chainId() {
      return `0x${this._chainId.toString(16)}`;
    }
    /**
     * Check if provider is connected
     * Returns true only if connected AND has at least one account
     */
    isConnected() {
      return this._connected && this._signers.length > 0;
    }
    /**
     * Get all account addresses (active account first)
     */
    _getAccounts() {
      if (!this._connected || this._signers.length === 0) {
        return [];
      }
      const active = this._signers[this._activeIndex].address;
      const others = this._signers.filter((_, i) => i !== this._activeIndex).map((s) => s.address);
      return [active, ...others];
    }
    /**
     * Get current active signer
     */
    _getActiveSigner() {
      if (!this._connected || this._signers.length === 0) {
        throw providerErrors.disconnected();
      }
      return this._signers[this._activeIndex];
    }
    /**
     * Switch active account by address or index
     *
     * @param addressOrIndex Account address (string) or index (number)
     * @throws {ProviderRpcError} If account not found or provider disconnected
     */
    async switchAccount(addressOrIndex) {
      if (!this._connected || this._signers.length === 0) {
        throw providerErrors.disconnected();
      }
      let newIndex;
      if (typeof addressOrIndex === "number") {
        if (addressOrIndex < 0 || addressOrIndex >= this._signers.length) {
          throw new Error(`Invalid account index: ${addressOrIndex}`);
        }
        newIndex = addressOrIndex;
      } else {
        const address = addressOrIndex.toLowerCase();
        newIndex = this._signers.findIndex((s) => s.address.toLowerCase() === address);
        if (newIndex === -1) {
          throw new Error(`Account not found: ${addressOrIndex}`);
        }
      }
      if (newIndex === this._activeIndex) {
        return;
      }
      this._activeIndex = newIndex;
      this._emit("accountsChanged", this._getAccounts());
    }
    /**
     * Add a new account to the provider
     *
     * @param signer RemoteSigner instance to add
     */
    async addAccount(signer) {
      const exists = this._signers.some(
        (s) => s.address.toLowerCase() === signer.address.toLowerCase()
      );
      if (exists) {
        throw new Error(`Account already exists: ${signer.address}`);
      }
      this._signers.push(signer);
      if (this._signers.length === 1) {
        this._activeIndex = 0;
        this._connected = true;
        this._emit("connect", {
          chainId: this.chainId
        });
      }
      this._emit("accountsChanged", this._getAccounts());
    }
    /**
     * Remove an account from the provider
     *
     * @param addressOrIndex Account address (string) or index (number)
     * @throws {Error} If account not found
     */
    async removeAccount(addressOrIndex) {
      if (this._signers.length === 0) {
        throw new Error("No accounts to remove");
      }
      let indexToRemove;
      if (typeof addressOrIndex === "number") {
        if (addressOrIndex < 0 || addressOrIndex >= this._signers.length) {
          throw new Error(`Invalid account index: ${addressOrIndex}`);
        }
        indexToRemove = addressOrIndex;
      } else {
        const address = addressOrIndex.toLowerCase();
        indexToRemove = this._signers.findIndex(
          (s) => s.address.toLowerCase() === address
        );
        if (indexToRemove === -1) {
          throw new Error(`Account not found: ${addressOrIndex}`);
        }
      }
      this._signers.splice(indexToRemove, 1);
      if (indexToRemove === this._activeIndex) {
        this._activeIndex = 0;
      } else if (indexToRemove < this._activeIndex) {
        this._activeIndex--;
      }
      if (this._signers.length === 0) {
        this._connected = false;
        this._emit("disconnect", providerErrors.disconnected("All accounts removed"));
      } else {
        this._emit("accountsChanged", this._getAccounts());
      }
    }
    /**
     * Disconnect provider and clear all accounts
     */
    async disconnect() {
      this._signers = [];
      this._activeIndex = 0;
      this._connected = false;
      this._emit("disconnect", {
        code: 1e3,
        message: "User disconnected"
      });
    }
    /**
     * Handle EIP-1193 JSON-RPC requests
     *
     * @param args Request arguments
     * @returns Promise resolving to the result
     */
    async request(args) {
      const { method, params } = args;
      switch (method) {
        // Account methods
        case "eth_accounts":
        case "eth_requestAccounts":
          return this._getAccounts();
        case "eth_coinbase":
          return this.selectedAddress;
        // Chain methods
        case "eth_chainId":
        case "net_version":
          return this.chainId;
        // Signing methods
        case "personal_sign": {
          const [message, address] = params;
          const signer = this._getActiveSigner();
          console.log("[EIP1193] personal_sign called:", {
            message,
            address,
            signerAddress: signer.address,
            signerChainId: signer.chainId || signer._chainID,
            providerChainId: this._chainId
          });
          if (address.toLowerCase() !== signer.address.toLowerCase()) {
            throw providerErrors.unauthorized(
              `Address mismatch: expected ${signer.address}, got ${address}`
            );
          }
          return await signer.personalSign(message);
        }
        case "eth_sign": {
          const [address, hash] = params;
          const signer = this._getActiveSigner();
          if (address.toLowerCase() !== signer.address.toLowerCase()) {
            throw providerErrors.unauthorized(
              `Address mismatch: expected ${signer.address}, got ${address}`
            );
          }
          return await signer.signHash(hash);
        }
        case "eth_signTypedData":
        case "eth_signTypedData_v3":
        case "eth_signTypedData_v4": {
          const [address, typedData] = params;
          const signer = this._getActiveSigner();
          if (address.toLowerCase() !== signer.address.toLowerCase()) {
            throw providerErrors.unauthorized(
              `Address mismatch: expected ${signer.address}, got ${address}`
            );
          }
          const typedDataObj = typeof typedData === "string" ? JSON.parse(typedData) : typedData;
          return await signer.signTypedData(typedDataObj);
        }
        case "eth_sendTransaction": {
          const [tx] = params;
          const signer = this._getActiveSigner();
          if (tx.from && tx.from.toLowerCase() !== signer.address.toLowerCase()) {
            throw providerErrors.unauthorized(
              `Address mismatch: expected ${signer.address}, got ${tx.from}`
            );
          }
          const rpcUrl = await this._getRpcUrl();
          const filled = await this._fillTxDefaults(tx, signer.address, rpcUrl);
          const signedTx = await signer.signTransaction(normalizeEip1193Tx(filled));
          const response = await fetch(rpcUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: Date.now(),
              method: "eth_sendRawTransaction",
              params: [signedTx]
            })
          });
          const result = await response.json();
          if (result.error) {
            throw new Error(result.error.message);
          }
          return result.result;
        }
        case "eth_signTransaction": {
          const [tx] = params;
          const signer = this._getActiveSigner();
          if (tx.from && tx.from.toLowerCase() !== signer.address.toLowerCase()) {
            throw providerErrors.unauthorized(
              `Address mismatch: expected ${signer.address}, got ${tx.from}`
            );
          }
          return await signer.signTransaction(normalizeEip1193Tx(tx));
        }
        // Read methods - delegate to RPC provider
        case "eth_blockNumber":
        case "eth_call":
        case "eth_estimateGas":
        case "eth_gasPrice":
        case "eth_getBalance":
        case "eth_getBlockByHash":
        case "eth_getBlockByNumber":
        case "eth_getCode":
        case "eth_getLogs":
        case "eth_getStorageAt":
        case "eth_getTransactionByHash":
        case "eth_getTransactionCount":
        case "eth_getTransactionReceipt": {
          const rpcUrl = await this._getRpcUrl();
          const response = await fetch(rpcUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: Date.now(),
              method,
              params: params ?? []
            })
          });
          const result = await response.json();
          if (result.error) {
            throw new Error(result.error.message);
          }
          return result.result;
        }
        // Wallet methods
        case "wallet_requestPermissions": {
          return [{ parentCapability: "eth_accounts" }];
        }
        case "wallet_switchEthereumChain": {
          console.log("[EIP1193] wallet_switchEthereumChain called:", params);
          const chainIdParam = params?.[0]?.chainId;
          if (!chainIdParam) {
            console.error("[EIP1193] wallet_switchEthereumChain: Missing chainId parameter");
            throw providerErrors.rpc(-32602, "Missing chainId parameter");
          }
          const newChainId = parseInt(chainIdParam, 16);
          if (isNaN(newChainId)) {
            console.error("[EIP1193] wallet_switchEthereumChain: Invalid chainId format:", chainIdParam);
            throw providerErrors.rpc(-32602, "Invalid chainId format");
          }
          console.log("[EIP1193] Switching from chain", this._chainId, "to chain", newChainId);
          this._chainId = newChainId;
          const newChainIdStr = newChainId.toString();
          console.log("[EIP1193] Updating signers to chainId:", newChainIdStr);
          for (const signer of this._signers) {
            signer.setChainID(newChainIdStr);
          }
          console.log("[EIP1193] Emitting chainChanged:", `0x${newChainId.toString(16)}`);
          this._emit("chainChanged", `0x${newChainId.toString(16)}`);
          console.log("[EIP1193] Emitting accountsChanged:", this._getAccounts());
          this._emit("accountsChanged", this._getAccounts());
          console.log("[EIP1193] wallet_switchEthereumChain completed successfully");
          return null;
        }
        // Unsupported methods
        default:
          throw providerErrors.unsupportedMethod(method);
      }
    }
    /**
     * Get RPC URL for the current chain
     */
    async _getRpcUrl() {
      let rpcUrl = this._rpcOverrides[this._chainId];
      if (!rpcUrl && this._rpcResolver) {
        rpcUrl = await this._rpcResolver(this._chainId);
      }
      if (!rpcUrl) {
        throw new Error(`No RPC URL configured for chain ${this._chainId}`);
      }
      return rpcUrl;
    }
    /**
     * Fill in transaction defaults that dApps routinely omit — gas, gasPrice
     * (or EIP-1559 caps), and nonce. The remote-signer backend signs whatever
     * we hand it, so we have to mimic the same auto-fill MetaMask performs
     * client-side before signing. Missing fields are fetched from the chain
     * RPC; values the caller supplied are preserved as-is.
     */
    async _fillTxDefaults(tx, fromAddr, rpcUrl) {
      const filled = { ...tx, from: tx.from ?? fromAddr };
      const rpc = async (method, params) => {
        const res = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params })
        });
        const json = await res.json();
        if (json.error) throw new Error(`${method}: ${json.error.message}`);
        return json.result;
      };
      if (filled.nonce == null) {
        filled.nonce = await rpc("eth_getTransactionCount", [fromAddr, "pending"]);
      }
      if (filled.gas == null && filled.gasLimit == null) {
        filled.gas = await rpc("eth_estimateGas", [{ ...filled, from: fromAddr }]);
      }
      const hasFeeCap = filled.maxFeePerGas != null || filled.maxPriorityFeePerGas != null;
      if (filled.gasPrice == null && !hasFeeCap) {
        filled.gasPrice = await rpc("eth_gasPrice", []);
      }
      return filled;
    }
    /**
     * Switch to a different chain
     *
     * @param chainId New chain ID (number or hex string)
     */
    async switchChain(chainId) {
      const newChainId = typeof chainId === "string" ? parseInt(chainId.replace("0x", ""), 16) : chainId;
      if (newChainId === this._chainId) {
        return;
      }
      const oldChainId = this._chainId;
      this._chainId = newChainId;
      const chainIdStr = newChainId.toString();
      this._signers.forEach((signer) => {
        signer.setChainID(chainIdStr);
      });
      this._emit("chainChanged", `0x${newChainId.toString(16)}`);
      this._emit("accountsChanged", this._getAccounts());
    }
    /**
     * Register an event listener
     *
     * @param event Event name
     * @param handler Event handler function
     */
    on(event, handler) {
      if (!this._eventHandlers.has(event)) {
        this._eventHandlers.set(event, /* @__PURE__ */ new Set());
      }
      this._eventHandlers.get(event).add(handler);
    }
    /**
     * Unregister an event listener
     *
     * @param event Event name
     * @param handler Event handler function
     */
    removeListener(event, handler) {
      const handlers = this._eventHandlers.get(event);
      if (handlers) {
        handlers.delete(handler);
      }
    }
    /**
     * Emit an event to all registered listeners
     *
     * @param event Event name
     * @param args Event arguments
     */
    _emit(event, ...args) {
      const handlers = this._eventHandlers.get(event);
      if (handlers) {
        handlers.forEach((handler) => {
          try {
            handler(...args);
          } catch (error) {
            console.error(`Error in ${event} handler:`, error);
          }
        });
      }
    }
  };
  var EvmService = class {
    constructor(transport, pollInterval, pollTimeout) {
      this.sign = new EvmSignService(transport, pollInterval, pollTimeout);
      this.requests = new EvmRequestService(transport);
      this.rules = new EvmRuleService(transport);
      this.signers = new EvmSignerService(transport);
      this.hdWallets = new EvmHDWalletService(transport, this.sign);
      this.guard = new EvmGuardService(transport);
      this.simulate = new EvmSimulateService(transport);
      this.budgets = new EvmBudgetService(transport);
    }
  };
  var AuditService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List audit log records with optional filters.
     */
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.event_type) {
        params.append("event_type", filter.event_type);
      }
      if (filter?.severity) {
        params.append("severity", filter.severity);
      }
      if (filter?.api_key_id) {
        params.append("api_key_id", filter.api_key_id);
      }
      if (filter?.signer_address) {
        params.append("signer_address", filter.signer_address);
      }
      if (filter?.chain_type) {
        params.append("chain_type", filter.chain_type);
      }
      if (filter?.chain_id) {
        params.append("chain_id", filter.chain_id);
      }
      if (filter?.start_time) {
        params.append("start_time", filter.start_time);
      }
      if (filter?.end_time) {
        params.append("end_time", filter.end_time);
      }
      if (filter?.limit) {
        params.append("limit", filter.limit.toString());
      }
      if (filter?.cursor) {
        params.append("cursor", filter.cursor);
      }
      if (filter?.cursor_id) {
        params.append("cursor_id", filter.cursor_id);
      }
      const queryString = params.toString();
      const path = `/api/v1/audit${queryString ? `?${queryString}` : ""}`;
      return this.transport.request("GET", path, null);
    }
  };
  var TemplateService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List templates with optional filters.
     */
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.type) params.append("type", filter.type);
      if (filter?.source) params.append("source", filter.source);
      if (filter?.enabled !== void 0) params.append("enabled", String(filter.enabled));
      if (filter?.limit) params.append("limit", filter.limit.toString());
      if (filter?.offset) params.append("offset", filter.offset.toString());
      const qs = params.toString();
      return this.transport.request(
        "GET",
        `/api/v1/templates${qs ? `?${qs}` : ""}`,
        null
      );
    }
    /**
     * Get a template by ID.
     */
    async get(templateID) {
      return this.transport.request(
        "GET",
        `/api/v1/templates/${templateID}`,
        null
      );
    }
    /**
     * Create a new template.
     */
    async create(req) {
      return this.transport.request(
        "POST",
        "/api/v1/templates",
        req
      );
    }
    /**
     * Update an existing template.
     */
    async update(templateID, req) {
      return this.transport.request(
        "PATCH",
        `/api/v1/templates/${templateID}`,
        req
      );
    }
    /**
     * Delete a template.
     */
    async delete(templateID) {
      await this.transport.request(
        "DELETE",
        `/api/v1/templates/${templateID}`,
        null
      );
    }
    /**
     * Instantiate a template into a concrete rule.
     */
    async instantiate(templateID, req) {
      return this.transport.request(
        "POST",
        `/api/v1/templates/${templateID}/instantiate`,
        req
      );
    }
    /**
     * Revoke (delete) a rule instance created from a template.
     */
    async revokeInstance(ruleID) {
      return this.transport.request(
        "DELETE",
        `/api/v1/templates/instances/${ruleID}`,
        null
      );
    }
  };
  var APIKeyService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List API keys with optional filters.
     */
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.source) params.append("source", filter.source);
      if (filter?.enabled !== void 0)
        params.append("enabled", String(filter.enabled));
      if (filter?.limit) params.append("limit", filter.limit.toString());
      if (filter?.offset) params.append("offset", filter.offset.toString());
      const qs = params.toString();
      return this.transport.request(
        "GET",
        `/api/v1/api-keys${qs ? `?${qs}` : ""}`,
        null
      );
    }
    /**
     * Get an API key by ID.
     */
    async get(id) {
      return this.transport.request(
        "GET",
        `/api/v1/api-keys/${encodeURIComponent(id)}`,
        null
      );
    }
    /**
     * Create a new API key (admin only).
     */
    async create(req) {
      return this.transport.request("POST", "/api/v1/api-keys", req);
    }
    /**
     * Update an API key (admin only).
     */
    async update(id, req) {
      return this.transport.request(
        "PUT",
        `/api/v1/api-keys/${encodeURIComponent(id)}`,
        req
      );
    }
    /**
     * Delete an API key (admin only).
     */
    async delete(id) {
      await this.transport.request(
        "DELETE",
        `/api/v1/api-keys/${encodeURIComponent(id)}`,
        null
      );
    }
  };
  var ACLService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * Get IP whitelist configuration (admin only).
     */
    async getIPWhitelist() {
      return this.transport.request(
        "GET",
        "/api/v1/acls/ip-whitelist",
        null
      );
    }
  };
  var PresetService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * List all available presets (admin only).
     */
    async list() {
      return this.transport.request(
        "GET",
        "/api/v1/presets",
        null
      );
    }
    /**
     * Get the full detail for a preset: identity, chain, template ids, and
     * each operator-overridable variable joined against the referenced
     * template's variable definition (type/description/default).
     */
    async get(id) {
      return this.transport.request(
        "GET",
        `/api/v1/presets/${encodeURIComponent(id)}`,
        null
      );
    }
    /**
     * Apply a preset to create rule instances (admin only). Returns one
     * result entry per materialised rule.
     */
    async apply(id, req) {
      return this.transport.request(
        "POST",
        `/api/v1/presets/${encodeURIComponent(id)}/apply`,
        req
      );
    }
    /**
     * Convenience: apply a preset with just variables (no applied_to).
     */
    async applyWithVariables(id, variables) {
      return this.apply(id, { variables });
    }
  };
  var RegistryService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /**
     * Re-run Template + Preset Registry sync against disk. Returns one
     * report per kind. Per-file errors come back as entries on
     * `templates.errors` / `presets.errors` — the rest of the sync still
     * went through, so the operator can fix one file at a time.
     */
    async refresh() {
      return this.transport.request(
        "POST",
        "/api/v1/registry/refresh",
        null
      );
    }
  };
  var SettingsService = class {
    constructor(transport) {
      this.transport = transport;
    }
    /** Fetches the current snapshot for one group. */
    async get(group) {
      return this.transport.request(
        "GET",
        `/api/v1/admin/settings/${group}`,
        null
      );
    }
    /**
     * Replaces the snapshot for one group. The daemon validates the shape per
     * group; bad input returns 400 with the validation error in the body.
     */
    async put(group, snapshot) {
      return this.transport.request(
        "PUT",
        `/api/v1/admin/settings/${group}`,
        snapshot
      );
    }
  };
  var WalletService = class {
    constructor(transport) {
      this.transport = transport;
    }
    async list(filter) {
      const params = new URLSearchParams();
      if (filter?.offset !== void 0)
        params.append("offset", String(filter.offset));
      if (filter?.limit !== void 0)
        params.append("limit", String(filter.limit));
      const qs = params.toString();
      return this.transport.request(
        "GET",
        `/api/v1/wallets${qs ? `?${qs}` : ""}`,
        null
      );
    }
    async get(id) {
      return this.transport.request(
        "GET",
        `/api/v1/wallets/${encodeURIComponent(id)}`,
        null
      );
    }
    async create(req) {
      return this.transport.request("POST", "/api/v1/wallets", req);
    }
    async delete(id) {
      await this.transport.request(
        "DELETE",
        `/api/v1/wallets/${encodeURIComponent(id)}`,
        null
      );
    }
    async listMembers(walletID) {
      return this.transport.request(
        "GET",
        `/api/v1/wallets/${encodeURIComponent(walletID)}/members`,
        null
      );
    }
    async addMember(walletID, req) {
      return this.transport.request(
        "POST",
        `/api/v1/wallets/${encodeURIComponent(walletID)}/members`,
        req
      );
    }
    async removeMember(walletID, signerAddress) {
      await this.transport.request(
        "DELETE",
        `/api/v1/wallets/${encodeURIComponent(walletID)}/members/${encodeURIComponent(signerAddress)}`,
        null
      );
    }
  };
  var RemoteSignerClient = class {
    constructor(config) {
      this.transport = new HttpTransport(config);
      const pollInterval = config.pollInterval ?? 2e3;
      const pollTimeout = config.pollTimeout ?? 3e5;
      this.evm = new EvmService(this.transport, pollInterval, pollTimeout);
      this.audit = new AuditService(this.transport);
      this.templates = new TemplateService(this.transport);
      this.apiKeys = new APIKeyService(this.transport);
      this.acls = new ACLService(this.transport);
      this.presets = new PresetService(this.transport);
      this.registry = new RegistryService(this.transport);
      this.settings = new SettingsService(this.transport);
      this.wallets = new WalletService(this.transport);
    }
    /**
     * Health check.
     */
    async health() {
      return this.transport.request("GET", "/health", null);
    }
    /**
     * Prometheus metrics endpoint.
     */
    async metrics() {
      return this.transport.requestNoAuth("GET", "/metrics");
    }
    // =========================================================================
    // Backward-compatible convenience methods (delegate to sub-services)
    // =========================================================================
    /** @deprecated Use client.evm.sign.execute(request) */
    async sign(request, waitForApproval = true) {
      return waitForApproval ? this.evm.sign.execute(request) : this.evm.sign.executeAsync(request);
    }
    /** @deprecated Use client.evm.requests.get(requestID) */
    async getRequest(requestID) {
      return this.evm.requests.get(requestID);
    }
    /** @deprecated Use client.evm.requests.list(filter) */
    async listRequests(filter) {
      return this.evm.requests.list(filter);
    }
    /** @deprecated Use client.evm.requests.approve(requestID, req) */
    async approveRequest(requestID, approveRequest) {
      return this.evm.requests.approve(requestID, approveRequest);
    }
    /** @deprecated Use client.evm.signers.list() */
    async listSigners() {
      return this.evm.signers.list();
    }
    /** @deprecated Use client.evm.signers.create(req) */
    async createSigner(req) {
      return this.evm.signers.create(req);
    }
    /** @deprecated Use client.evm.rules.list() */
    async listRules() {
      return this.evm.rules.list();
    }
    /** @deprecated Use client.evm.rules.get(ruleID) */
    async getRule(ruleID) {
      return this.evm.rules.get(ruleID);
    }
    /** @deprecated Use client.evm.rules.create(rule) */
    async createRule(rule) {
      return this.evm.rules.create(rule);
    }
    /** @deprecated Use client.evm.rules.update(ruleID, update) */
    async updateRule(ruleID, update) {
      return this.evm.rules.update(ruleID, update);
    }
    /** @deprecated Use client.evm.rules.delete(ruleID) */
    async deleteRule(ruleID) {
      return this.evm.rules.delete(ruleID);
    }
    /** @deprecated Use client.audit.list(filter) */
    async listAuditLogs(filter) {
      return this.audit.list(filter);
    }
    /** @deprecated Use client.evm.requests.previewRule(requestID, req) */
    async previewRule(requestID, previewRequest) {
      return this.evm.requests.previewRule(requestID, previewRequest);
    }
    /** @deprecated Use client.evm.hdWallets.create(req) */
    async createHDWallet(req) {
      return this.evm.hdWallets.create(req);
    }
    /** @deprecated Use client.evm.hdWallets.import(req) */
    async importHDWallet(req) {
      return this.evm.hdWallets.import(req);
    }
    /** @deprecated Use client.evm.hdWallets.list() */
    async listHDWallets() {
      return this.evm.hdWallets.list();
    }
    /** @deprecated Use client.evm.hdWallets.deriveAddress(primaryAddr, req) */
    async deriveAddress(primaryAddr, req) {
      return this.evm.hdWallets.deriveAddress(primaryAddr, req);
    }
    /** @deprecated Use client.evm.hdWallets.listDerived(primaryAddr) */
    async listDerivedAddresses(primaryAddr) {
      return this.evm.hdWallets.listDerived(primaryAddr);
    }
  };

  // src/background.ts
  var DEFAULT_CONFIG = {
    remoteSignerUrl: "http://127.0.0.1:8548",
    // "agent" is the standard role name used by `remote-signer` when it
    // bootstraps a local instance (see `~/.remote-signer/apikeys/agent.key.priv`).
    // Defaulting the field saves the user a step on first run.
    apiKeyId: "agent",
    apiKeyPrivateKey: "",
    selectedChain: 1
  };
  var EXTENSION_VERSION = typeof chrome !== "undefined" && chrome.runtime?.getManifest?.()?.version || "dev";
  var CLIENT_VERSION_STRING = `RemoteSigner/v${EXTENSION_VERSION}/javascript`;
  var DEFAULT_CHAINS = [
    { chainId: 1, chainName: "Ethereum", rpcUrls: ["https://eth.llamarpc.com"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
    { chainId: 10, chainName: "Optimism", rpcUrls: ["https://mainnet.optimism.io"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
    { chainId: 56, chainName: "BNB Smart Chain", rpcUrls: ["https://bsc-dataseed.binance.org"], nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 } },
    { chainId: 137, chainName: "Polygon", rpcUrls: ["https://polygon-rpc.com"], nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 } },
    { chainId: 8453, chainName: "Base", rpcUrls: ["https://mainnet.base.org"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
    { chainId: 42161, chainName: "Arbitrum One", rpcUrls: ["https://arb1.arbitrum.io/rpc"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
    { chainId: 11155111, chainName: "Sepolia", rpcUrls: ["https://ethereum-sepolia-rpc.publicnode.com"], nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 } }
  ];
  var chainRegistry = new Map(
    DEFAULT_CHAINS.map((c) => [c.chainId, c])
  );
  function getRpcUrl(chainId) {
    return chainRegistry.get(chainId)?.rpcUrls?.[0];
  }
  function rpcOverridesFromRegistry() {
    const out = {};
    for (const [chainId, cfg] of chainRegistry) {
      const url = cfg.rpcUrls?.[0];
      if (url) out[chainId] = url;
    }
    return out;
  }
  var provider = null;
  var client = null;
  var initPromise = null;
  var initError = null;
  var cachedConfig = { ...DEFAULT_CONFIG };
  function configKey() {
    return `remoteSignerConfig`;
  }
  async function loadConfig() {
    const result = await chrome.storage.local.get(configKey());
    if (result[configKey()]) {
      cachedConfig = result[configKey()];
    }
    return cachedConfig;
  }
  async function saveConfig(cfg) {
    cachedConfig = {
      ...cfg,
      apiKeyPrivateKey: normalizePrivateKey(cfg.apiKeyPrivateKey)
    };
    await chrome.storage.local.set({ [configKey()]: cachedConfig });
  }
  function normalizePrivateKey(input) {
    if (!input) return input;
    const trimmed = input.trim();
    if (!trimmed.includes("-----BEGIN")) return trimmed;
    const m = trimmed.match(/-----BEGIN[^-]+-----([\s\S]+?)-----END[^-]+-----/);
    if (!m) {
      throw new Error("Malformed PEM: missing BEGIN/END markers");
    }
    const b64 = m[1].replace(/\s+/g, "");
    let bin;
    try {
      bin = atob(b64);
    } catch {
      throw new Error("Malformed PEM: body is not valid base64");
    }
    if (bin.length < 48) {
      throw new Error(`Malformed PEM: decoded ${bin.length} bytes, expected at least 48`);
    }
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = bin.charCodeAt(16 + i);
    return Array.from(seed).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function registerContentScript() {
    try {
      await chrome.scripting.unregisterContentScripts({ ids: ["remote-signer-cs"] }).catch(() => {
      });
      await chrome.scripting.registerContentScripts([
        {
          id: "remote-signer-cs",
          matches: ["http://*/*", "https://*/*"],
          js: ["content-script.js"],
          runAt: "document_start",
          allFrames: false,
          world: "ISOLATED"
        }
      ]);
    } catch (e) {
      console.error("[background] Failed to register content script:", e);
    }
  }
  chrome.runtime.onInstalled.addListener(() => registerContentScript());
  chrome.runtime.onStartup.addListener(() => registerContentScript());
  registerContentScript();
  chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    try {
      await chrome.scripting.executeScript({
        target: { tabId: details.tabId },
        world: "MAIN",
        injectImmediately: true,
        func: () => {
          const removeCSP = () => {
            document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]').forEach((el) => {
              console.log(
                "[CSP bypass] Removing meta CSP:",
                el.getAttribute("content")?.substring(0, 80)
              );
              el.remove();
            });
            document.querySelectorAll(
              'meta[http-equiv="Content-Security-Policy-Report-Only"]'
            ).forEach((el) => el.remove());
          };
          removeCSP();
          const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
              for (const node of mutation.addedNodes) {
                if (node.nodeName === "META") {
                  const httpEquiv = node.getAttribute("http-equiv");
                  if (httpEquiv && httpEquiv.toLowerCase().includes("content-security-policy")) {
                    console.log(
                      "[CSP bypass] Intercepted meta CSP:",
                      node.getAttribute("content")?.substring(0, 80)
                    );
                    node.remove();
                  }
                }
              }
            }
          });
          observer.observe(document.documentElement, {
            childList: true,
            subtree: true
          });
          setTimeout(() => observer.disconnect(), 3e4);
        }
      });
    } catch (e) {
      if (!e.message?.includes("Cannot access")) {
        console.error("[background] CSP bypass injection failed:", e);
      }
    }
  });
  async function initProvider() {
    const cfg = await loadConfig();
    if (!cfg.apiKeyPrivateKey) {
      initError = "API key not configured. Open extension popup to configure.";
      console.warn("[background]", initError);
      return;
    }
    if (!cfg.apiKeyId) {
      initError = "API key ID not configured. Open extension popup to configure.";
      console.warn("[background]", initError);
      return;
    }
    console.log("[background] Initializing provider...", {
      remoteSignerUrl: cfg.remoteSignerUrl,
      apiKeyId: cfg.apiKeyId,
      chainId: cfg.selectedChain
    });
    client = new RemoteSignerClient({
      baseURL: cfg.remoteSignerUrl,
      apiKeyID: cfg.apiKeyId,
      privateKey: cfg.apiKeyPrivateKey,
      httpClient: {
        fetch: fetch.bind(self)
      }
    });
    provider = await EIP1193Provider.create({
      signersSource: { type: "client", client, chainId: cfg.selectedChain },
      defaultChainId: cfg.selectedChain,
      rpcOverrides: rpcOverridesFromRegistry(),
      rpcResolver: async (chainId) => {
        const url = getRpcUrl(chainId);
        if (!url) throw new Error(`No RPC URL configured for chain ${chainId}`);
        return url;
      }
    });
    if (cfg.activeSignerAddress && provider.isConnected()) {
      try {
        await provider.switchAccount(cfg.activeSignerAddress);
      } catch (err2) {
        console.warn("[background] stored active signer no longer usable:", err2);
        cfg.activeSignerAddress = void 0;
        await saveConfig(cfg);
      }
    }
    console.log("[background] Provider created successfully");
    console.log("  - Connected:", provider.isConnected());
    console.log("  - Active account:", provider.selectedAddress);
    console.log("  - Chain ID:", provider.chainId);
    const events = ["accountsChanged", "chainChanged", "connect", "disconnect"];
    for (const event of events) {
      provider.on(event, (data) => {
        broadcastEvent(event, data);
      });
    }
    provider.on("chainChanged", async (chainIdHex) => {
      if (typeof chainIdHex !== "string") return;
      const newChainId = parseInt(chainIdHex, 16);
      if (!Number.isFinite(newChainId) || newChainId <= 0) return;
      if (cachedConfig.selectedChain === newChainId) return;
      cachedConfig.selectedChain = newChainId;
      try {
        await chrome.storage.local.set({ [configKey()]: cachedConfig });
      } catch (err2) {
        console.error("[background] Failed to persist chainChanged:", err2);
      }
    });
    provider.on("accountsChanged", async (accounts) => {
      if (!Array.isArray(accounts) || accounts.length === 0) return;
      const active = typeof accounts[0] === "string" ? accounts[0].toLowerCase() : void 0;
      if (!active) return;
      if (cachedConfig.activeSignerAddress?.toLowerCase() === active) return;
      cachedConfig.activeSignerAddress = active;
      try {
        await chrome.storage.local.set({ [configKey()]: cachedConfig });
      } catch (err2) {
        console.error("[background] Failed to persist accountsChanged:", err2);
      }
    });
  }
  function ensureInit() {
    if (!initPromise) {
      initPromise = initProvider().catch((err2) => {
        initError = err2.message || String(err2);
        console.error("[background] Provider init failed:", err2);
      });
    }
    return initPromise;
  }
  async function broadcastEvent(event, data) {
    try {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        if (tab.id != null) {
          chrome.tabs.sendMessage(tab.id, {
            type: "web3-eip1193-event",
            event,
            data
          }).catch(() => {
          });
        }
      }
    } catch {
    }
  }
  async function forwardToRpc(method, params) {
    const chainId = provider ? parseInt(provider.chainId, 16) : 1;
    const rpcUrl = getRpcUrl(chainId);
    if (!rpcUrl) {
      return {
        error: { code: -32603, message: `No RPC URL configured for chain ${chainId}` }
      };
    }
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: Date.now(),
          method,
          params: Array.isArray(params) ? params : []
        })
      });
      const json = await res.json();
      if (json.error) {
        return { error: { code: json.error.code ?? -32603, message: json.error.message ?? "RPC error", data: json.error.data } };
      }
      return { result: json.result };
    } catch (err2) {
      return { error: { code: -32603, message: err2?.message || String(err2) } };
    }
  }
  function handleAddEthereumChain(params) {
    const first = Array.isArray(params) ? params[0] : void 0;
    const chainIdHex = first?.chainId;
    if (typeof chainIdHex !== "string" || !chainIdHex.startsWith("0x")) {
      return { error: { code: -32602, message: "Invalid chainId parameter" } };
    }
    const chainId = parseInt(chainIdHex, 16);
    if (!Number.isFinite(chainId) || chainId <= 0) {
      return { error: { code: -32602, message: "Invalid chainId parameter" } };
    }
    const rpcUrls = Array.isArray(first?.rpcUrls) ? first.rpcUrls : [];
    if (chainRegistry.has(chainId)) return { result: null };
    if (rpcUrls.length === 0) {
      return { error: { code: -32602, message: "wallet_addEthereumChain requires rpcUrls" } };
    }
    chainRegistry.set(chainId, {
      chainId,
      rpcUrls,
      chainName: typeof first?.chainName === "string" ? first.chainName : void 0,
      nativeCurrency: first?.nativeCurrency,
      blockExplorerUrls: Array.isArray(first?.blockExplorerUrls) ? first.blockExplorerUrls : void 0
    });
    return { result: null };
  }
  async function tryHandleExtraMethod(msg) {
    const { method, params } = msg;
    switch (method) {
      // ── Legacy / informational ─────────────────────────────────────────────
      case "web3_clientVersion":
        return { handled: true, result: CLIENT_VERSION_STRING };
      case "net_listening":
        return { handled: true, result: true };
      case "net_peerCount":
        return { handled: true, result: "0x0" };
      // ── Permissions (EIP-2255) ─────────────────────────────────────────────
      case "wallet_getPermissions":
        return { handled: true, result: [{ parentCapability: "eth_accounts" }] };
      case "wallet_revokePermissions":
        broadcastEvent("accountsChanged", []);
        return { handled: true, result: null };
      // ── Watch asset (EIP-747) ─────────────────────────────────────────────
      case "wallet_watchAsset":
        return { handled: true, result: true };
      // ── Capabilities (EIP-5792) ───────────────────────────────────────────
      case "wallet_getCapabilities":
        return { handled: true, result: {} };
      // ── Chain management (EIP-3085 / 3326) ────────────────────────────────
      case "wallet_addEthereumChain":
        return { handled: true, ...handleAddEthereumChain(params) };
      case "wallet_switchEthereumChain": {
        const first = Array.isArray(params) ? params[0] : void 0;
        const chainIdHex = first?.chainId;
        if (typeof chainIdHex !== "string" || !chainIdHex.startsWith("0x")) {
          return { handled: true, error: { code: -32602, message: "Missing or invalid chainId parameter" } };
        }
        const chainId = parseInt(chainIdHex, 16);
        if (!chainRegistry.has(chainId)) {
          return {
            handled: true,
            error: { code: 4902, message: `Unrecognized chain ID "${chainIdHex}". Try adding the chain with wallet_addEthereumChain.` }
          };
        }
        return { handled: false };
      }
      // ── Forwarded read / send methods ─────────────────────────────────────
      // The SDK enumerates most read methods but misses these. Forward to the
      // active chain's RPC endpoint.
      case "eth_sendRawTransaction":
      case "eth_maxPriorityFeePerGas":
      case "eth_feeHistory":
      case "eth_getProof":
      case "eth_blobBaseFee":
      case "eth_syncing":
        return { handled: true, ...await forwardToRpc(method, params) };
      default:
        return { handled: false };
    }
  }
  async function handleEIP1193Request(msg) {
    await ensureInit();
    if (initError) {
      return {
        type: "web3-eip1193-response",
        id: msg.id,
        error: { code: -32603, message: `Provider init failed: ${initError}` }
      };
    }
    if (!provider) {
      return {
        type: "web3-eip1193-response",
        id: msg.id,
        error: { code: -32603, message: "Provider not initialized" }
      };
    }
    const extra = await tryHandleExtraMethod(msg);
    if (extra.handled) {
      if (extra.error) {
        return { type: "web3-eip1193-response", id: msg.id, error: extra.error };
      }
      return { type: "web3-eip1193-response", id: msg.id, result: extra.result };
    }
    try {
      const result = await provider.request({
        method: msg.method,
        params: msg.params
      });
      return {
        type: "web3-eip1193-response",
        id: msg.id,
        result
      };
    } catch (err2) {
      return {
        type: "web3-eip1193-response",
        id: msg.id,
        error: {
          code: err2.code || -32603,
          message: err2.message || String(err2),
          data: err2.data
        }
      };
    }
  }
  async function handleGetState(id) {
    await ensureInit();
    if (!provider) {
      return {
        type: "web3-state-response",
        id,
        accounts: [],
        chainId: "0x1",
        isConnected: false
      };
    }
    let accounts = [];
    try {
      accounts = await provider.request({
        method: "eth_accounts"
      });
    } catch {
    }
    return {
      type: "web3-state-response",
      id,
      accounts,
      chainId: provider.chainId,
      isConnected: provider.isConnected()
    };
  }
  async function handlePopupGetConfig() {
    const cfg = await loadConfig();
    return {
      type: "popup:config",
      config: cfg
    };
  }
  async function handlePopupSaveConfig(msg) {
    try {
      await saveConfig(msg.config);
    } catch (err2) {
      return {
        type: "popup:configSaved",
        ok: false,
        error: err2?.message || String(err2)
      };
    }
    initPromise = null;
    initError = null;
    provider = null;
    client = null;
    return {
      type: "popup:configSaved",
      ok: true
    };
  }
  function buildPopupClient(cfg) {
    return new RemoteSignerClient({
      baseURL: cfg.remoteSignerUrl,
      apiKeyID: cfg.apiKeyId,
      privateKey: cfg.apiKeyPrivateKey,
      httpClient: { fetch: fetch.bind(self) }
    });
  }
  async function handlePopupTestConnection() {
    const cfg = cachedConfig;
    if (!cfg.remoteSignerUrl) {
      return {
        type: "popup:connectionResult",
        ok: false,
        error: "Remote Signer URL not configured"
      };
    }
    if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
      return {
        type: "popup:connectionResult",
        ok: false,
        error: "API key not configured"
      };
    }
    let popupClient;
    try {
      popupClient = buildPopupClient(cfg);
    } catch (err2) {
      return {
        type: "popup:connectionResult",
        ok: false,
        error: `Invalid configuration: ${err2.message || String(err2)}`
      };
    }
    let serverVersion = "unknown";
    try {
      const health = await popupClient.health();
      serverVersion = health?.version || "unknown";
    } catch (err2) {
      return {
        type: "popup:connectionResult",
        ok: false,
        error: `Cannot reach server: ${err2.message || String(err2)}`
      };
    }
    let signerCount = 0;
    try {
      const list = await popupClient.evm.signers.list();
      signerCount = list?.signers?.length ?? 0;
    } catch (err2) {
      const status = err2?.statusCode;
      const msg = err2?.message || String(err2);
      return {
        type: "popup:connectionResult",
        ok: false,
        error: status ? `Auth failed (HTTP ${status}): ${msg}` : `Auth failed: ${msg}`
      };
    }
    return {
      type: "popup:connectionResult",
      ok: true,
      version: serverVersion,
      url: cfg.remoteSignerUrl,
      signerCount
    };
  }
  async function handlePopupGetState() {
    const cfg = cachedConfig;
    if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey || !cfg.remoteSignerUrl) {
      return {
        type: "popup:state",
        connected: false,
        configured: false,
        accounts: [],
        chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
        error: null,
        signerStatus: null
      };
    }
    let popupClient;
    try {
      popupClient = buildPopupClient(cfg);
    } catch (err2) {
      return {
        type: "popup:state",
        connected: false,
        configured: true,
        accounts: [],
        chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
        error: `Invalid configuration: ${err2?.message || String(err2)}`,
        signerStatus: null
      };
    }
    try {
      await popupClient.health();
    } catch (err2) {
      return {
        type: "popup:state",
        connected: false,
        configured: true,
        accounts: [],
        chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
        error: `Cannot reach server: ${err2?.message || String(err2)}`,
        signerStatus: null
      };
    }
    let signers = [];
    try {
      const list = await popupClient.evm.signers.list();
      signers = list?.signers ?? [];
    } catch (err2) {
      const status = err2?.statusCode;
      const msg = err2?.message || String(err2);
      return {
        type: "popup:state",
        connected: false,
        configured: true,
        accounts: [],
        chainId: `0x${(cfg.selectedChain || 1).toString(16)}`,
        error: status ? `Auth failed (HTTP ${status}): ${msg}` : `Auth failed: ${msg}`,
        signerStatus: null
      };
    }
    const usable = signers.filter((s) => s.enabled && !s.locked);
    const locked = signers.filter((s) => s.locked);
    const disabled = signers.filter((s) => !s.enabled);
    const accounts = usable.map((s) => s.address).filter(Boolean);
    const chainId = `0x${(cfg.selectedChain || 1).toString(16)}`;
    let activeAddress = null;
    if (provider && provider.isConnected()) {
      activeAddress = provider.selectedAddress;
    }
    if (!activeAddress && cfg.activeSignerAddress) {
      const match = usable.find(
        (s) => s.address?.toLowerCase() === cfg.activeSignerAddress.toLowerCase()
      );
      if (match) activeAddress = match.address;
    }
    if (!activeAddress && accounts.length > 0) {
      activeAddress = accounts[0];
    }
    return {
      type: "popup:state",
      connected: true,
      configured: true,
      accounts,
      activeAddress,
      // Full signer list with status flags so the popup can render the
      // locked/disabled rows greyed out alongside usable ones.
      signers: signers.map((s) => ({
        address: s.address,
        type: s.type,
        enabled: !!s.enabled,
        locked: !!s.locked
      })),
      chainId,
      error: null,
      signerStatus: {
        total: signers.length,
        usable: usable.length,
        locked: locked.length,
        disabled: disabled.length
      }
    };
  }
  async function safeSdkCall(fn) {
    try {
      const data = await fn();
      return { ok: true, data };
    } catch (err2) {
      return { ok: false, error: err2?.message || String(err2) };
    }
  }
  async function handlePopupGetDashboard() {
    const cfg = cachedConfig;
    if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
      return {
        type: "popup:dashboard",
        signers: [],
        signerCount: 0,
        ruleCount: 0,
        requestCount: 0,
        apiKeyRole: "unknown"
      };
    }
    let popupClient;
    try {
      popupClient = buildPopupClient(cfg);
    } catch {
      return {
        type: "popup:dashboard",
        signers: [],
        signerCount: 0,
        ruleCount: 0,
        requestCount: 0,
        apiKeyRole: "unknown"
      };
    }
    const [signersResult, rulesResult, requestsResult, apikeysResult] = await Promise.all([
      safeSdkCall(() => popupClient.evm.signers.list()),
      safeSdkCall(() => popupClient.evm.rules.list({ limit: 1 })),
      safeSdkCall(() => popupClient.evm.requests.list({ limit: 100 })),
      safeSdkCall(() => popupClient.apiKeys.list())
    ]);
    let apiKeyRole = "unknown";
    if (apikeysResult.ok) {
      apiKeyRole = "admin";
    } else if (signersResult.ok) {
      apiKeyRole = "agent";
    }
    const signersData = signersResult.data ?? {};
    const signerList = Array.isArray(signersData) ? signersData : signersData.signers ?? [];
    const rulesData = rulesResult.data ?? {};
    const requestsData = requestsResult.data ?? {};
    return {
      type: "popup:dashboard",
      signers: signerList.map((s) => typeof s === "string" ? s : s?.address).filter(Boolean),
      signerCount: signerList.length,
      ruleCount: rulesData.total ?? (Array.isArray(rulesData.rules) ? rulesData.rules.length : 0),
      requestCount: requestsData.total ?? (Array.isArray(requestsData.requests) ? requestsData.requests.length : 0),
      apiKeyRole
    };
  }
  async function handlePopupOpenManagement() {
    const cfg = await loadConfig();
    const url = cfg.remoteSignerUrl.replace(/\/$/, "");
    await chrome.tabs.create({ url });
    return { type: "popup:managementOpened" };
  }
  async function handlePopupGetActivity(msg) {
    const cfg = cachedConfig;
    if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
      return { type: "popup:activity", ok: false, error: "Not configured", requests: [] };
    }
    let popupClient;
    try {
      popupClient = buildPopupClient(cfg);
    } catch (err2) {
      return { type: "popup:activity", ok: false, error: err2?.message || String(err2), requests: [] };
    }
    try {
      const filter = { limit: msg.limit ?? 20 };
      if (msg.status) filter.status = msg.status;
      const list = await popupClient.evm.requests.list(filter);
      return {
        type: "popup:activity",
        ok: true,
        requests: list?.requests ?? [],
        total: list?.total ?? 0,
        hasMore: !!list?.has_more
      };
    } catch (err2) {
      return { type: "popup:activity", ok: false, error: err2?.message || String(err2), requests: [] };
    }
  }
  async function handlePopupGetRequest(msg) {
    const cfg = cachedConfig;
    if (!cfg.apiKeyId || !cfg.apiKeyPrivateKey) {
      return { type: "popup:request", ok: false, error: "Not configured" };
    }
    let popupClient;
    try {
      popupClient = buildPopupClient(cfg);
    } catch (err2) {
      return { type: "popup:request", ok: false, error: err2?.message || String(err2) };
    }
    try {
      const req = await popupClient.evm.requests.get(msg.requestId);
      return { type: "popup:request", ok: true, request: req };
    } catch (err2) {
      return { type: "popup:request", ok: false, error: err2?.message || String(err2) };
    }
  }
  async function handlePopupSwitchAccount(msg) {
    await ensureInit();
    if (!provider) {
      return { type: "popup:accountSwitched", ok: false, error: initError || "Provider not initialized" };
    }
    try {
      await provider.switchAccount(msg.address);
    } catch (err2) {
      return { type: "popup:accountSwitched", ok: false, error: err2?.message || String(err2) };
    }
    cachedConfig.activeSignerAddress = msg.address;
    await chrome.storage.local.set({ [configKey()]: cachedConfig });
    return { type: "popup:accountSwitched", ok: true, address: provider.selectedAddress };
  }
  chrome.runtime.onMessage.addListener(
    (message, _sender, sendResponse) => {
      if (message.type === "web3-eip1193-request") {
        handleEIP1193Request(message).then(sendResponse).catch((err2) => {
          sendResponse({
            type: "web3-eip1193-response",
            id: message.id,
            error: {
              code: -32603,
              message: err2.message || String(err2)
            }
          });
        });
        return true;
      }
      if (message.type === "web3-get-state") {
        handleGetState(message.id).then(sendResponse).catch((err2) => {
          sendResponse({
            type: "web3-state-response",
            id: message.id,
            error: err2.message || String(err2)
          });
        });
        return true;
      }
      if (message.type === "popup:getConfig") {
        handlePopupGetConfig().then(sendResponse);
        return true;
      }
      if (message.type === "popup:saveConfig") {
        handlePopupSaveConfig(message).then(sendResponse);
        return true;
      }
      if (message.type === "popup:testConnection") {
        handlePopupTestConnection().then(sendResponse);
        return true;
      }
      if (message.type === "popup:getState") {
        handlePopupGetState().then(sendResponse);
        return true;
      }
      if (message.type === "popup:getDashboard") {
        handlePopupGetDashboard().then(sendResponse);
        return true;
      }
      if (message.type === "popup:openManagement") {
        handlePopupOpenManagement().then(sendResponse);
        return true;
      }
      if (message.type === "popup:switchAccount") {
        handlePopupSwitchAccount(message).then(sendResponse);
        return true;
      }
      if (message.type === "popup:getActivity") {
        handlePopupGetActivity(message).then(sendResponse);
        return true;
      }
      if (message.type === "popup:getRequest") {
        handlePopupGetRequest(message).then(sendResponse);
        return true;
      }
      return false;
    }
  );
})();
/*! Bundled license information:

@noble/ed25519/index.js:
  (*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
