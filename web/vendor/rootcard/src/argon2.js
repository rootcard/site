// Argon2id, version 0x13 (RFC 9106), the one primitive this package implements itself ([CRY-1]). It supports the
// general parameters of the RFC (lanes, secret, associated data) so that it can be checked against the RFC vectors;
// rootcard uses p = 1, no secret and no associated data ([CRY-6]).

import { blake2b } from "./blake2b.js";

function le32(n) {
  return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]);
}

/** H' (RFC 9106 §3.3): variable-length hash of `parts` to `T` bytes. */
function hPrime(T, ...parts) {
  if (T <= 64) return blake2b(T, le32(T), ...parts);
  const out = new Uint8Array(T);
  const r = Math.ceil(T / 32) - 2;
  let v = blake2b(64, le32(T), ...parts);
  out.set(v.subarray(0, 32), 0);
  for (let i = 1; i < r; i++) {
    v = blake2b(64, v);
    out.set(v.subarray(0, 32), i * 32);
  }
  out.set(blake2b(T - 32 * r, v), r * 32);
  return out;
}

// Scratch space for the compression function: R (256 words) and Q (256 words).
const R = new Uint32Array(256);
const Q = new Uint32Array(256);

// a = a + b + 2 * lo(a) * lo(b) on 64-bit words at word offsets a and b of Q (in u32 units: 2a, 2a+1).
function fBlaMka(a, b) {
  const al = Q[a];
  const bl = Q[b];
  // 64-bit product of the two low halves.
  const a1 = al >>> 16;
  const a0 = al & 0xffff;
  const b1 = bl >>> 16;
  const b0 = bl & 0xffff;
  const p00 = a0 * b0;
  const mid = a1 * b0 + a0 * b1 + (p00 >>> 16);
  let ph = a1 * b1 + Math.floor(mid / 65536);
  let pl = (Math.imul(al, bl) >>> 0);
  // times two
  ph = ((ph << 1) | (pl >>> 31)) >>> 0;
  pl = (pl << 1) >>> 0;
  // a + b
  let lo = Q[a] + Q[b];
  let hi = Q[a + 1] + Q[b + 1] + (lo >= 0x100000000 ? 1 : 0);
  lo >>>= 0;
  // + product
  const lo2 = lo + pl;
  hi = hi + ph + (lo2 >= 0x100000000 ? 1 : 0);
  Q[a] = lo2;
  Q[a + 1] = hi;
}

function rotr(d, n) {
  const l = Q[d];
  const h = Q[d + 1];
  if (n === 32) {
    Q[d] = h;
    Q[d + 1] = l;
  } else if (n < 32) {
    Q[d] = (l >>> n) | (h << (32 - n));
    Q[d + 1] = (h >>> n) | (l << (32 - n));
  } else {
    const k = n - 32;
    Q[d] = (h >>> k) | (l << (32 - k));
    Q[d + 1] = (l >>> k) | (h << (32 - k));
  }
}

function xor(d, a) {
  Q[d] ^= Q[a];
  Q[d + 1] ^= Q[a + 1];
}

// GB on 64-bit words with u32 offsets a, b, c, d into Q.
function gb(a, b, c, d) {
  fBlaMka(a, b);
  xor(d, a);
  rotr(d, 32);
  fBlaMka(c, d);
  xor(b, c);
  rotr(b, 24);
  fBlaMka(a, b);
  xor(d, a);
  rotr(d, 16);
  fBlaMka(c, d);
  xor(b, c);
  rotr(b, 63);
}

// P on 16 64-bit words whose u32 offsets are in `w`.
function p(w) {
  gb(w[0], w[4], w[8], w[12]);
  gb(w[1], w[5], w[9], w[13]);
  gb(w[2], w[6], w[10], w[14]);
  gb(w[3], w[7], w[11], w[15]);
  gb(w[0], w[5], w[10], w[15]);
  gb(w[1], w[6], w[11], w[12]);
  gb(w[2], w[7], w[8], w[13]);
  gb(w[3], w[4], w[9], w[14]);
}

const ROWS = [];
const COLS = [];
for (let i = 0; i < 8; i++) {
  ROWS.push(Array.from({ length: 16 }, (_, k) => 2 * (16 * i + k)));
  COLS.push(Array.from({ length: 16 }, (_, k) => 2 * (2 * i + 16 * (k >> 1) + (k & 1))));
}

/**
 * G(X, Y) of RFC 9106 §3.5 into `out` (all Uint32Array views of 256 words). With `xorOut`, the result is XORed into
 * the existing contents of `out` (passes after the first, version 0x13).
 */
function compress(out, outOff, x, xOff, y, yOff, xorOut) {
  for (let i = 0; i < 256; i++) R[i] = x[xOff + i] ^ y[yOff + i];
  Q.set(R);
  for (let i = 0; i < 8; i++) p(ROWS[i]);
  for (let i = 0; i < 8; i++) p(COLS[i]);
  if (xorOut) for (let i = 0; i < 256; i++) out[outOff + i] ^= Q[i] ^ R[i];
  else for (let i = 0; i < 256; i++) out[outOff + i] = Q[i] ^ R[i];
}

function blockToWords(bytes, mem, off) {
  for (let i = 0; i < 256; i++) {
    mem[off + i] = bytes[4 * i] | (bytes[4 * i + 1] << 8) | (bytes[4 * i + 2] << 16) | (bytes[4 * i + 3] << 24);
  }
}

/**
 * Argon2id (RFC 9106) with a `tagLength`-byte tag. `m` is in KiB.
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {{ m: number, t: number, p: number, tagLength?: number, secret?: Uint8Array, ad?: Uint8Array }} params
 */
export function argon2id(password, salt, params) {
  const { m, t, p: lanes } = params;
  const T = params.tagLength ?? 32;
  const K = params.secret ?? new Uint8Array(0);
  const X = params.ad ?? new Uint8Array(0);
  if (!(lanes >= 1 && t >= 1 && m >= 8 * lanes && T >= 4)) throw new RangeError("argon2id parameters");
  const h0 = blake2b(
    64,
    le32(lanes), le32(T), le32(m), le32(t), le32(0x13), le32(2),
    le32(password.length), password, le32(salt.length), salt, le32(K.length), K, le32(X.length), X,
  );
  const mPrime = 4 * lanes * Math.floor(m / (4 * lanes));
  const q = mPrime / lanes;
  const segment = q / 4;
  const mem = new Uint32Array(mPrime * 256);
  const at = (lane, col) => (lane * q + col) * 256;
  for (let l = 0; l < lanes; l++) {
    blockToWords(hPrime(1024, h0, le32(0), le32(l)), mem, at(l, 0));
    blockToWords(hPrime(1024, h0, le32(1), le32(l)), mem, at(l, 1));
  }
  const zero = new Uint32Array(256);
  const input = new Uint32Array(256);
  const address = new Uint32Array(256);
  for (let pass = 0; pass < t; pass++) {
    for (let slice = 0; slice < 4; slice++) {
      for (let lane = 0; lane < lanes; lane++) {
        const independent = pass === 0 && slice < 2;
        if (independent) {
          input.fill(0);
          input[0] = pass;
          input[2] = lane;
          input[4] = slice;
          input[6] = mPrime;
          input[8] = t;
          input[10] = 2;
          input[12] = 0; // counter
        }
        const nextAddresses = () => {
          input[12]++;
          address.fill(0);
          compress(address, 0, zero, 0, input, 0, false);
          compress(address, 0, zero, 0, address.slice(), 0, false);
        };
        let start = 0;
        if (pass === 0 && slice === 0) {
          start = 2;
          if (independent) nextAddresses();
        }
        for (let index = start; index < segment; index++) {
          const col = slice * segment + index;
          const prevCol = col === 0 ? q - 1 : col - 1;
          let j1;
          let j2;
          if (independent) {
            if (index % 128 === 0) nextAddresses();
            const k = 2 * (index % 128);
            j1 = address[k];
            j2 = address[k + 1];
          } else {
            const o = at(lane, prevCol);
            j1 = mem[o];
            j2 = mem[o + 1];
          }
          let refLane = j2 % lanes;
          if (pass === 0 && slice === 0) refLane = lane;
          const same = refLane === lane;
          let area;
          if (pass === 0) {
            if (slice === 0) area = index - 1;
            else if (same) area = slice * segment + index - 1;
            else area = slice * segment + (index === 0 ? -1 : 0);
          } else if (same) area = q - segment + index - 1;
          else area = q - segment + (index === 0 ? -1 : 0);
          // x = j1^2 >> 32; y = area * x >> 32; z = area - 1 - y
          const x = Number((BigInt(j1) * BigInt(j1)) >> 32n);
          const y = Number((BigInt(area) * BigInt(x)) >> 32n);
          const z = area - 1 - y;
          const startPos = pass === 0 ? 0 : slice === 3 ? 0 : (slice + 1) * segment;
          const refCol = (startPos + z) % q;
          compress(mem, at(lane, col), mem, at(lane, prevCol), mem, at(refLane, refCol), pass > 0);
        }
      }
    }
  }
  const c = new Uint32Array(256);
  for (let l = 0; l < lanes; l++) {
    const o = at(l, q - 1);
    for (let i = 0; i < 256; i++) c[i] ^= mem[o + i];
  }
  const cb = new Uint8Array(1024);
  for (let i = 0; i < 256; i++) {
    cb[4 * i] = c[i];
    cb[4 * i + 1] = c[i] >>> 8;
    cb[4 * i + 2] = c[i] >>> 16;
    cb[4 * i + 3] = c[i] >>> 24;
  }
  const tag = hPrime(T, cb);
  mem.fill(0);
  cb.fill(0);
  c.fill(0);
  return tag;
}
