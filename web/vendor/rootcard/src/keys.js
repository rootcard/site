// Keys in JSON (SPEC §3.3) and the schema helpers every structure uses ([CJ-11]–[CJ-13]).

import { fail } from "./errors.js";
import { isObject } from "./json.js";
import { base64urlDecode, base64urlEncode, base32Decode } from "./encoding.js";
import { ed25519PointOk } from "./crypto.js";

/** `"<type>:" + b64u(raw)` ([KEY-1]). */
export function formatKey(type, raw) {
  return `${type}:${base64urlEncode(raw)}`;
}

/** Parse a key string of the required type ([KEY-1]–[KEY-3]). → bad_key */
export function parseKey(s, type) {
  if (typeof s !== "string") fail("bad_key");
  const i = s.indexOf(":");
  if (i < 0 || s.slice(0, i) !== type) fail("bad_key");
  let raw;
  try {
    raw = base64urlDecode(s.slice(i + 1));
  } catch {
    fail("bad_key");
  }
  if (raw.length !== 32) fail("bad_key");
  if (type === "ed25519" && !ed25519PointOk(raw)) fail("bad_key");
  return raw;
}

// --- schema helpers (each failure is bad_field unless stated otherwise) ---

export function object(v) {
  if (!isObject(v)) fail("bad_field");
  return v;
}

/** [CJ-12] */
export function version(m) {
  const v = m.v;
  if (!Object.hasOwn(m, "v") || typeof v !== "number") fail("bad_field");
  if (v !== 1) fail("unsupported_version");
}

/** [CJ-11] */
export function members(m, required, optional = []) {
  for (const k of required) if (!Object.hasOwn(m, k)) fail("bad_field");
  for (const k of Object.keys(m)) if (!required.includes(k) && !optional.includes(k)) fail("bad_field");
}

export function get(m, k) {
  if (!Object.hasOwn(m, k)) fail("bad_field");
  return m[k];
}

export function string(m, k) {
  const v = get(m, k);
  if (typeof v !== "string") fail("bad_field");
  return v;
}

export function int(m, k) {
  const v = get(m, k);
  if (typeof v !== "number") fail("bad_field");
  return v;
}

export function intIn(m, k, lo, hi) {
  const v = int(m, k);
  if (v < lo || v > hi) fail("bad_field");
  return v;
}

export function bool(m, k) {
  const v = get(m, k);
  if (typeof v !== "boolean") fail("bad_field");
  return v;
}

export function member(m, k) {
  return object(get(m, k));
}

export function array(m, k) {
  const v = get(m, k);
  if (!Array.isArray(v)) fail("bad_field");
  return v;
}

/** A base64url string of exactly `n` bytes. */
export function bytes(m, k, n) {
  const s = string(m, k);
  let b;
  try {
    b = base64urlDecode(s);
  } catch {
    fail("bad_field");
  }
  if (b.length !== n) fail("bad_field");
  return b;
}

/** A key string: not a string → bad_field, a bad key → bad_key ([CJ-13]). */
export function key(m, k, type) {
  return parseKey(string(m, k), type);
}

/** A 64-byte signature ([KEY-4]). */
export function sig(m, k) {
  return bytes(m, k, 64);
}

/** An account id in strict form ([ID-3]). */
export function account(m, k) {
  const s = string(m, k);
  checkAccountId(s);
  return s;
}

/** [ID-3] → bad_field */
export function checkAccountId(s) {
  try {
    base32Decode(s, 32);
  } catch {
    fail("bad_field");
  }
}

/** A version `{ seq, hash }` ([VER-1]). */
export function versionRef(v) {
  const m = object(v);
  members(m, ["seq", "hash"]);
  intIn(m, "seq", 0, 999);
  bytes(m, "hash", 32);
  return { seq: m.seq, hash: m.hash };
}
