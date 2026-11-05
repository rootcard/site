// The vault's structure and signatures (SPEC §11), without any decryption: what hosts need ([VLT-3], [VLT-4]).

import { fail } from "./errors.js";
import { base64urlDecode, bytesEqual } from "./encoding.js";
import { ed25519Verify, frameObject, sha256 } from "./crypto.js";
import { canonical, isObject, without } from "./json.js";
import * as s from "./keys.js";
import { label } from "./labels.js";

export const VAULT_LIMIT = 96 * 1024;
export const CONTENTS_LIMIT = 64 * 1024;
export const DATA_LIMIT = 48 * 1024;
export const MAX_SLOTS = 15;
export const MAX_REV = 2 ** 32;

/** Argon2id defaults and bounds ([LCK-6]). */
export const KDF_DEFAULT = Object.freeze({ m: 65536, t: 3, p: 1 });
export const KDF_MIN = Object.freeze({ m: 47104, t: 2, p: 1 });

/** [LCK-6] → kdf_params */
export function checkKdf(k) {
  if (!(k.p === 1 && k.m >= 47104 && k.m <= 1048576 && k.t >= 2 && k.t <= 16)) fail("kdf_params");
}

/** [LCK-2] → bad_field */
export function checkLabel(l) {
  const chars = [...l];
  if (chars.length < 1 || chars.length > 64 || chars.some((c) => c < " " || c === "\x7f")) fail("bad_field");
}

/** The grant message signed by the recovery key ([LCK-3]). */
export function grantMessage(grant, account, instance) {
  return frameObject(label("locks"), { ...without(grant, "sig"), account, instance });
}

/** The message the account key signs on a vault ([VLT-2]). */
export function vaultMessage(vault) {
  return frameObject(label("vault"), without(vault, "sig"));
}

/** The authenticated data of the contents encryption ([VLT-6]). */
export function contentsAad(vault) {
  return frameObject(label("contents"), without(vault, "nonce", "ct", "sig"));
}

function parseWrap(m) {
  s.members(m, ["epk", "nonce", "ct"]);
  return { epk: s.key(m, "epk", "x25519"), nonce: s.bytes(m, "nonce", 12), ct: s.bytes(m, "ct", 48) };
}

function parseLock(v) {
  const m = s.object(v);
  const kind = s.string(m, "kind");
  if (kind === "password") {
    s.members(m, ["id", "kind", "kdf", "auth", "box", "wrap"]);
    const id = s.string(m, "id");
    s.bytes(m, "id", 8);
    const k = s.member(m, "kdf");
    s.members(k, ["alg", "m", "t", "p", "salt"]);
    const kdf = { alg: s.string(k, "alg"), m: s.int(k, "m"), t: s.int(k, "t"), p: s.int(k, "p"), salt: s.bytes(k, "salt", 16) };
    const auth = s.key(m, "auth", "ed25519");
    const box = s.key(m, "box", "x25519");
    const wrap = parseWrap(s.member(m, "wrap"));
    return { kind, id, kdf, auth, box, wrap, value: m };
  }
  if (kind === "recovery") {
    s.members(m, ["id", "kind", "box", "wrap"]);
    const id = s.string(m, "id");
    const box = s.key(m, "box", "x25519");
    return { kind, id, box, boxString: m.box, wrap: parseWrap(s.member(m, "wrap")), value: m };
  }
  fail("bad_field");
}

function parseVault(v) {
  if (isObject(v) && canonical(v).length > VAULT_LIMIT) fail("too_large");
  const m = s.object(v);
  s.version(m);
  s.members(m, ["v", "account", "instance", "rev", "locks", "nonce", "ct", "sig"]);
  s.account(m, "account");
  s.bytes(m, "instance", 32);
  const rev = s.intIn(m, "rev", 1, MAX_REV);
  const locks = s.member(m, "locks");
  s.members(locks, ["grant", "list"]);
  const grant = s.member(locks, "grant");
  s.members(grant, ["gen", "slots", "recovery", "sig"]);
  const gen = s.intIn(grant, "gen", 1, MAX_REV);
  const slots = [];
  for (const x of s.array(grant, "slots")) {
    const o = s.object(x);
    s.members(o, ["id", "label"]);
    s.bytes(o, "id", 8);
    slots.push({ id: s.string(o, "id"), label: s.string(o, "label") });
  }
  s.key(grant, "recovery", "x25519");
  const grantSig = s.sig(grant, "sig");
  const list = s.array(locks, "list").map(parseLock);
  s.bytes(m, "nonce", 12);
  let ct;
  try {
    ct = base64urlDecode(s.string(m, "ct"));
  } catch {
    fail("bad_field");
  }
  if (ct.length < 16) fail("bad_field");
  const sig = s.sig(m, "sig");
  return { map: m, grant, rev, gen, slots, list, grantSig, sig };
}

function checkLockSet(p) {
  const { slots, list } = p;
  const unique = new Set(slots.map((x) => x.id)).size === slots.length;
  const rec = list.filter((l) => l.kind === "recovery");
  const recoveryOk = rec.length === 1 && rec[0].id === "recovery" && rec[0].boxString === p.grant.recovery;
  const pw = list.filter((l) => l.kind === "password");
  const perSlot = pw.length === slots.length && slots.every((x) => pw.filter((l) => l.id === x.id).length === 1);
  if (slots.length > MAX_SLOTS || !unique || !recoveryOk || !perSlot) fail("bad_locks");
  for (const x of slots) checkLabel(x.label);
  for (const l of pw) {
    const ok32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
    if (l.kdf.alg !== "argon2id" || ![l.kdf.m, l.kdf.t, l.kdf.p].every(ok32)) fail("kdf_params");
    checkKdf(l.kdf);
  }
}

/**
 * Verify a vault against a log state ([VLT-3]), without decrypting it. Returns `{ rev, gen, slots, locks, hints }`.
 */
export async function verifyVault(vault, state) {
  const p = parseVault(vault);
  if (p.map.account !== state.account) fail("account_mismatch");
  if (state.retired) fail("account_retired");
  if (!state.instance) fail("no_instance");
  if (p.map.instance !== state.instance.hash) fail("wrong_instance");
  checkLockSet(p);
  await ed25519Verify(s.parseKey(state.recovery, "ed25519"), grantMessage(p.grant, state.account, p.map.instance), p.grantSig);
  await ed25519Verify(s.parseKey(state.instance.account_key, "ed25519"), vaultMessage(p.map), p.sig);
  return info(p);
}

function info(p) {
  const hints = [];
  for (const x of p.slots) {
    const l = p.list.find((y) => y.kind === "password" && y.id === x.id);
    if (l) hints.push({ id: x.id, label: x.label, kdf: l.value.kdf });
  }
  return { rev: p.rev, gen: p.gen, slots: p.slots, locks: p.list, hints };
}

/** Classify a replacement of `old` by `new` ([VLT-4], [HST-12]). → stale_rev, stale_locks */
export async function vaultChange(oldVault, newVault) {
  const o = s.object(oldVault);
  const n = s.object(newVault);
  if (s.int(n, "rev") <= s.int(o, "rev")) fail("stale_rev");
  const ol = s.member(o, "locks");
  const nl = s.member(n, "locks");
  const og = s.int(s.member(ol, "grant"), "gen");
  const ng = s.int(s.member(nl, "grant"), "gen");
  if (ng < og) fail("stale_locks");
  if (ng > og) return { change: "grant" };
  const same = (a, b) => {
    try {
      return bytesEqual(canonical(a), canonical(b));
    } catch {
      return false;
    }
  };
  if (!same(ol.grant, nl.grant)) fail("stale_locks");
  const olist = s.array(ol, "list");
  const nlist = s.array(nl, "list");
  if (olist.length !== nlist.length) fail("stale_locks");
  const changed = [];
  for (let i = 0; i < olist.length; i++) if (!same(olist[i], nlist[i])) changed.push(i);
  if (changed.length === 0) return { change: "data" };
  if (changed.length > 1) fail("stale_locks");
  const a = s.object(olist[changed[0]]);
  const b = s.object(nlist[changed[0]]);
  if (a.kind !== "password" || b.kind !== "password" || a.id !== b.id) fail("stale_locks");
  return { change: "password", slot: s.string(b, "id"), new: await sha256(canonical(b)) };
}
