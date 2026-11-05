// Byte encodings (SPEC §3): unpadded base64url, Crockford base32, hex and UTF-8.

import { fail } from "./errors.js";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64_VALUE = new Map([...B64].map((c, i) => [c, i]));

/** Unpadded base64url ([B64-1]). @param {Uint8Array} bytes */
export function base64urlEncode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = Math.min(3, bytes.length - i) + 1;
    for (let j = 0; j < chars; j++) out += B64[(n >>> (18 - 6 * j)) & 63];
  }
  return out;
}

/** Strict unpadded base64url decoding ([B64-2]). → bad_base64 */
export function base64urlDecode(text) {
  if (typeof text !== "string" || text.length % 4 === 1) fail("bad_base64");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    const chunk = text.slice(i, i + 4);
    let n = 0;
    for (let j = 0; j < chunk.length; j++) {
      const v = B64_VALUE.get(chunk[j]);
      if (v === undefined) fail("bad_base64");
      n |= v << (18 - 6 * j);
    }
    const len = chunk.length - 1;
    const unused = len === 1 ? n & 0xffff : len === 2 ? n & 0xff : 0;
    if (unused !== 0) fail("bad_base64");
    const b = [(n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    for (let j = 0; j < len; j++) out[o++] = b[j];
  }
  return out;
}

/** The Crockford base32 alphabet ([B32-1]). */
export const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Crockford base32 ([B32-2]). */
export function base32Encode(bytes) {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = ((acc << 8) | b) >>> 0;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

/** Strict Crockford base32 decoding of exactly `len` bytes ([B32-3]). → bad_base32 */
export function base32Decode(text, len) {
  if (typeof text !== "string" || text.length !== Math.ceil((len * 8) / 5)) fail("bad_base32");
  const out = new Uint8Array(len);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (const c of text) {
    const v = B32.indexOf(c);
    if (v < 0 || c.length !== 1) fail("bad_base32");
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 255;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) fail("bad_base32");
  return out;
}

/** Lenient normalization of typed base32 ([B32-4]). */
export function base32Normalize(text) {
  let out = "";
  for (const c of text) {
    if (c === "-" || c === " ") continue;
    const u = c.length === 1 && c >= "a" && c <= "z" ? c.toUpperCase() : c;
    out += u === "I" || u === "L" ? "1" : u === "O" ? "0" : u;
  }
  return out;
}

/** Lenient decoding for human input ([B32-4]). → bad_base32 */
export function base32DecodeLenient(text, len) {
  return base32Decode(base32Normalize(text), len);
}

/** Lower-case hexadecimal. */
export function hexEncode(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Hexadecimal to bytes. → bad_field */
export function hexDecode(text) {
  if (text.length % 2 || !/^[0-9a-fA-F]*$/.test(text)) fail("bad_field");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const te = new TextEncoder();
/** UTF-8 bytes of a string. */
export function utf8(s) {
  return te.encode(s);
}

/** Concatenate byte arrays. */
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Byte equality (not constant time; use ctEqual for secrets). */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Constant-time equality of two byte arrays ([IMP-4]). */
export function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
