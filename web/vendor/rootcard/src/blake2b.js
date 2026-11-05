// BLAKE2b (RFC 7693), needed only inside Argon2id ([CRY-1]): WebCrypto has neither. 64-bit words are pairs of 32-bit
// integers (low, high) in a Uint32Array.

const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a, 0xade682d1,
  0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
].map((r) => r.map((x) => x * 2));

const v = new Uint32Array(32);
const m = new Uint32Array(32);

function add64(a, b) {
  const lo = v[a] + v[b];
  let hi = v[a + 1] + v[b + 1];
  if (lo >= 0x100000000) hi++;
  v[a] = lo;
  v[a + 1] = hi;
}

function add64m(a, i) {
  const lo = v[a] + m[i];
  let hi = v[a + 1] + m[i + 1];
  if (lo >= 0x100000000) hi++;
  v[a] = lo;
  v[a + 1] = hi;
}

function g(a, b, c, d, x, y) {
  add64(a, b);
  add64m(a, x);
  let xl = v[d] ^ v[a];
  let xh = v[d + 1] ^ v[a + 1];
  v[d] = xh;
  v[d + 1] = xl;
  add64(c, d);
  xl = v[b] ^ v[c];
  xh = v[b + 1] ^ v[c + 1];
  v[b] = (xl >>> 24) ^ (xh << 8);
  v[b + 1] = (xh >>> 24) ^ (xl << 8);
  add64(a, b);
  add64m(a, y);
  xl = v[d] ^ v[a];
  xh = v[d + 1] ^ v[a + 1];
  v[d] = (xl >>> 16) ^ (xh << 16);
  v[d + 1] = (xh >>> 16) ^ (xl << 16);
  add64(c, d);
  xl = v[b] ^ v[c];
  xh = v[b + 1] ^ v[c + 1];
  v[b] = (xh >>> 31) ^ (xl << 1);
  v[b + 1] = (xl >>> 31) ^ (xh << 1);
}

function compress(h, block, t, last) {
  for (let i = 0; i < 16; i++) {
    v[i] = h[i];
    v[i + 16] = IV[i];
  }
  v[24] ^= t;
  v[25] ^= t / 0x100000000;
  if (last) {
    v[28] = ~v[28];
    v[29] = ~v[29];
  }
  for (let i = 0; i < 32; i++) {
    m[i] = block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
  }
  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r % 10];
    g(0, 8, 16, 24, s[0], s[1]);
    g(2, 10, 18, 26, s[2], s[3]);
    g(4, 12, 20, 28, s[4], s[5]);
    g(6, 14, 22, 30, s[6], s[7]);
    g(0, 10, 20, 30, s[8], s[9]);
    g(2, 12, 22, 24, s[10], s[11]);
    g(4, 14, 16, 26, s[12], s[13]);
    g(6, 8, 18, 28, s[14], s[15]);
  }
  for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i + 16];
}

/** BLAKE2b without a key, with an output of `outlen` bytes (1 to 64), over the concatenation of `parts`. */
export function blake2b(outlen, ...parts) {
  const h = new Uint32Array(16);
  h.set(IV);
  h[0] ^= 0x01010000 ^ outlen;
  const block = new Uint8Array(128);
  let fill = 0;
  let t = 0;
  for (const p of parts) {
    for (let i = 0; i < p.length; i++) {
      if (fill === 128) {
        t += 128;
        compress(h, block, t, false);
        fill = 0;
      }
      block[fill++] = p[i];
    }
  }
  t += fill;
  block.fill(0, fill);
  compress(h, block, t, true);
  const out = new Uint8Array(outlen);
  for (let i = 0; i < outlen; i++) out[i] = h[i >> 2] >>> (8 * (i & 3));
  block.fill(0);
  h.fill(0);
  return out;
}
