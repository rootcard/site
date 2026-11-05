// Cryptographic primitives (SPEC §4) over WebCrypto, and domain separation (SPEC §5).
// Private keys are imported non-extractable for signing and agreement; raw secret buffers are overwritten by the
// callers that own them ([IMP-2]).

import { fail } from "./errors.js";
import { canonical } from "./json.js";
import { concat, utf8 } from "./encoding.js";

const subtle = globalThis.crypto?.subtle;

let support;
/** Check that WebCrypto has Ed25519 and X25519 ([IMP-3]). → unsupported_browser */
export async function checkSupport() {
  if (support === undefined) {
    support = (async () => {
      if (!subtle) return false;
      try {
        await subtle.importKey("raw", new Uint8Array(32).fill(9), { name: "X25519" }, true, []);
        const k = await subtle.importKey("raw", ED_TEST_KEY, { name: "Ed25519" }, true, ["verify"]);
        return !!k;
      } catch {
        return false;
      }
    })();
  }
  if (!(await support)) fail("unsupported_browser");
}

// The Ed25519 public key of RFC 8032 test 1, used only to probe for support.
const ED_TEST_KEY = new Uint8Array([
  0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72,
  0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
]);

/** `frame(label, m) = utf8(label) ‖ 0x00 ‖ m` ([DS-1]). */
export function frame(label, m) {
  return concat(utf8(label), new Uint8Array([0]), m);
}

/** `frame(label, canonical(x))`. */
export function frameObject(label, x) {
  return frame(label, canonical(x));
}

/** SHA-256. */
export async function sha256(m) {
  return new Uint8Array(await subtle.digest("SHA-256", m));
}

/** HKDF-SHA256 with a 32-byte output ([CRY-5]). */
export async function hkdf(ikm, salt, info) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, 256));
}

const ED_PKCS8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
const X_PKCS8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

function b64uToBytes(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

async function importPrivate(prefix, alg, secret, extractable, usages) {
  const der = concat(prefix, secret);
  try {
    return await subtle.importKey("pkcs8", der, { name: alg }, extractable, usages);
  } finally {
    der.fill(0);
  }
}

async function publicOf(prefix, alg, secret, usages) {
  const k = await importPrivate(prefix, alg, secret, true, usages);
  const jwk = await subtle.exportKey("jwk", k);
  const x = b64uToBytes(jwk.x);
  jwk.d = "";
  return x;
}

/** The Ed25519 public key of a 32-byte seed ([CRY-2]). */
export async function ed25519Public(seed) {
  return publicOf(ED_PKCS8, "Ed25519", seed, ["sign"]);
}

/** Import an Ed25519 seed as a non-extractable signing key ([IMP-2]). */
export async function ed25519SigningKey(seed) {
  return importPrivate(ED_PKCS8, "Ed25519", seed, false, ["sign"]);
}

/** A deterministic Ed25519 signature ([CRY-8]). `key` is a seed or a key from ed25519SigningKey. */
export async function ed25519Sign(key, m) {
  const k = key instanceof Uint8Array ? await ed25519SigningKey(key) : key;
  return new Uint8Array(await subtle.sign("Ed25519", k, m));
}

// L, p and the small-order encodings of [CRY-3].
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const P = 2n ** 255n - 19n;
const SMALL_ORDER = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];
const NEG_ZERO = [
  "0100000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

function le(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function hex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** [CRY-3] steps 3 and 4 for an encoded point: canonical and not of small order (also [KEY-3]). */
export function ed25519PointOk(e) {
  if (e.length !== 32) return false;
  const y = e.slice();
  y[31] &= 0x7f;
  if (le(y) >= P) return false;
  const h = hex(e);
  return !NEG_ZERO.includes(h) && !SMALL_ORDER.includes(h);
}

/** Strict Ed25519 verification ([CRY-3]). → bad_signature */
export async function ed25519Verify(publicKey, m, sig) {
  if (publicKey.length !== 32 || sig.length !== 64) fail("bad_signature");
  const r = sig.subarray(0, 32);
  const s = sig.subarray(32);
  if (le(s) >= L || !ed25519PointOk(publicKey) || !ed25519PointOk(r)) fail("bad_signature");
  let ok = false;
  try {
    const k = await subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    ok = await subtle.verify("Ed25519", k, sig, m);
  } catch {
    ok = false;
  }
  if (!ok) fail("bad_signature");
}

/** The X25519 public key of a 32-byte secret ([CRY-2]). */
export async function x25519Public(secret) {
  return publicOf(X_PKCS8, "X25519", secret, ["deriveBits"]);
}

/** X25519 key agreement; an all-zero result fails ([CRY-4]). → bad_key */
export async function x25519(secret, publicKey) {
  let bits;
  try {
    const priv = await importPrivate(X_PKCS8, "X25519", secret, false, ["deriveBits"]);
    const pub = await subtle.importKey("raw", publicKey, { name: "X25519" }, false, []);
    bits = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  } catch {
    fail("bad_key");
  }
  if (bits.every((b) => b === 0)) fail("bad_key");
  return bits;
}

/** AES-256-GCM encryption: ciphertext ‖ tag ([CRY-7]). */
export async function aesGcmEncrypt(key, nonce, plaintext, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, k, plaintext));
}

/** AES-256-GCM decryption. → unlock_failed */
export async function aesGcmDecrypt(key, nonce, ct, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, k, ct));
  } catch {
    fail("unlock_failed");
  }
}
