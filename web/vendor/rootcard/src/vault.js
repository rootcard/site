// The vault cryptography (SPEC §11): password locks, wrapping, contents, unlocking and changes. This module is separate
// from the verification core so that a server bundle never loads it (ARCHITECTURE.md §4).
//
// Functions that need random bytes take `random(n) → Uint8Array` ([IMP-1]). The order of the draws is part of the
// contract and identical to the Rust crate, so both produce the same bytes from the same stream.

import { fail } from "./errors.js";
import { base64urlDecode, base64urlEncode, concat, utf8 } from "./encoding.js";
import {
  aesGcmDecrypt, aesGcmEncrypt, DRAW_ATTEMPTS, ed25519Public, ed25519PublicIs, ed25519Sign, frameObject, hkdf, sha256, usableSeed, x25519, x25519Public,
} from "./crypto.js";
import { argon2id } from "./argon2.js";
import { canonical, parseLimited } from "./json.js";
import * as s from "./keys.js";
import { formatKey } from "./keys.js";
import { label } from "./labels.js";
import { checkData } from "./profile.js";
import {
  CONTENTS_LIMIT, DATA_LIMIT, MAX_SLOTS, VAULT_LIMIT, checkKdf, checkLabel, contentsAad, grantMessage, vaultMessage,
  verifyVault,
} from "./vaultcheck.js";

const EMPTY = new Uint8Array(0);

/** The password rules ([LCK-8]). → weak_password */
export function checkPassword(password, username) {
  const n = password.normalize("NFC");
  if ([...n].length < 12 || utf8(n).length > 1024 || (n.toLowerCase() === username.toLowerCase() && /^[\x00-\x7f]*$/.test(n))) {
    fail("weak_password");
  }
}

/** Derive a password lock's secrets ([LCK-7]): `{ authSeed, boxSecret }`. → kdf_params */
export async function deriveLockSecrets(account, lock, password, kdf, salt) {
  checkKdf(kdf);
  const pw = utf8(password.normalize("NFC"));
  const a = argon2id(pw, salt, { m: kdf.m, t: kdf.t, p: kdf.p });
  pw.fill(0);
  const ctx = { account, lock };
  try {
    return {
      authSeed: await hkdf(a, EMPTY, frameObject(label("password/auth"), ctx)),
      boxSecret: await hkdf(a, EMPTY, frameObject(label("password/box"), ctx)),
    };
  } finally {
    a.fill(0);
  }
}

async function wrapKey(shared, epk, box, account, instance, lock) {
  return hkdf(shared, concat(epk, box), frameObject(label("wrap"), { account, instance, lock }));
}

/** Wrap the vault key to a lock's `box` ([LCK-9]). Draws: e (32), nonce (12). → bad_key */
export async function wrapVaultKey(vk, box, account, instance, lock, random) {
  const e = random(32);
  const nonce = random(12);
  const epk = await x25519Public(e);
  const shared = await x25519(e, box);
  const wk = await wrapKey(shared, epk, box, account, instance, lock);
  const ct = await aesGcmEncrypt(wk, nonce, vk, EMPTY);
  e.fill(0);
  shared.fill(0);
  wk.fill(0);
  return { epk: formatKey("x25519", epk), nonce: base64urlEncode(nonce), ct: base64urlEncode(ct) };
}

/** Unwrap the vault key with a lock secret ([LCK-9]). → unlock_failed, bad_key */
export async function unwrapVaultKey(wrap, secret, box, account, instance, lock) {
  const pub = await x25519Public(secret);
  if (formatKey("x25519", pub) !== formatKey("x25519", box)) fail("unlock_failed");
  const epk = s.parseKey(wrap.epk, "x25519");
  const shared = await x25519(secret, epk);
  const wk = await wrapKey(shared, epk, box, account, instance, lock);
  const vk = await aesGcmDecrypt(wk, base64urlDecode(wrap.nonce), base64urlDecode(wrap.ct), EMPTY);
  shared.fill(0);
  wk.fill(0);
  if (vk.length !== 32) fail("unlock_failed");
  return vk;
}

/** Check vault contents ([VLT-7]). → too_large, bad_field, unsupported_version, bad_data_key */
export function checkContents(v) {
  if (canonical(v).length > CONTENTS_LIMIT) fail("too_large");
  const m = s.object(v);
  s.version(m);
  s.members(m, ["v", "account_seed", "data"], ["known"]);
  const seed = s.bytes(m, "account_seed", 32);
  const data = s.member(m, "data");
  checkData(data, DATA_LIMIT);
  if (Object.hasOwn(m, "known")) {
    const k = s.object(m.known);
    for (const id of Object.keys(k)) {
      s.checkAccountId(id);
      const e = s.object(k[id]);
      s.members(e, ["handle", "version"]);
      s.string(e, "handle");
      s.versionRef(s.get(e, "version"));
    }
  }
  return { accountSeed: seed, data, known: m.known };
}

function contentsValue(c) {
  const v = { v: 1, account_seed: base64urlEncode(c.accountSeed), data: c.data };
  if (c.known !== undefined) v.known = c.known;
  return v;
}

/**
 * Unlock a vault ([VLT-8]). `secret` is `{ lock, password }` or `{ recovery: { signSeed, boxSecret } }`.
 * Returns `{ vaultKey, contents: { accountSeed, data, known }, lock, lockSeed, info }`.
 */
export async function unlockVault(vault, state, secret) {
  const info = await verifyVault(vault, state);
  let lockId;
  let lockSecret;
  let lockSeed;
  if (secret.recovery) {
    if (!info.locks.find((l) => l.id === "recovery")) fail("bad_locks");
    lockId = "recovery";
    lockSecret = secret.recovery.boxSecret;
    lockSeed = secret.recovery.signSeed;
  } else {
    const p = info.locks.find((l) => l.kind === "password" && l.id === secret.lock);
    if (!p) fail("bad_locks");
    const ls = await deriveLockSecrets(state.account, secret.lock, secret.password, p.kdf, p.kdf.salt);
    lockId = secret.lock;
    lockSecret = ls.boxSecret;
    lockSeed = ls.authSeed;
  }
  const lock = info.locks.find((l) => l.id === lockId);
  if (!lock) fail("bad_locks");
  const vk = await unwrapVaultKey(lock.value.wrap, lockSecret, lock.box, state.account, vault.instance, lockId);
  const pt = await aesGcmDecrypt(vk, base64urlDecode(vault.nonce), base64urlDecode(vault.ct), contentsAad(vault));
  const contents = checkContents(parseLimited(pt, CONTENTS_LIMIT));
  pt.fill(0);
  if (!state.instance) fail("no_instance");
  if (!(await ed25519PublicIs(contents.accountSeed, s.parseKey(state.instance.account_key, "ed25519")))) {
    fail("wrong_account_key");
  }
  // Check the signing seed of the lock against its key on record, so that a platform that cannot import it signs
  // with it anyway ([IMP-6]); a mismatch is not this function's to judge (a login with it fails at the host).
  const signKey = lockId === "recovery" ? state.recovery : lock.value.auth;
  await ed25519PublicIs(lockSeed, s.parseKey(signKey, "ed25519"));
  return { vaultKey: vk, contents, lock: lockId, lockSeed, info };
}

/** Sign a grant with the recovery key ([LCK-3]). `recoveryBox` is the raw X25519 public key. */
export async function signGrant(account, instance, gen, slots, recoveryBox, recoverySeed) {
  const g = { gen, slots: slots.map((x) => ({ id: x.id, label: x.label })), recovery: formatKey("x25519", recoveryBox) };
  g.sig = base64urlEncode(await ed25519Sign(recoverySeed, grantMessage(g, account, instance)));
  return g;
}

/** Encrypt the contents and sign a vault ([VLT-2], [VLT-6]). Draws: the contents nonce (12). */
export async function sealVault(account, instance, rev, grant, list, contents, vaultKey, random) {
  const cv = contentsValue(contents);
  checkContents(cv);
  const plain = canonical(cv);
  const nonce = random(12);
  const v = { v: 1, account, instance, rev, locks: { grant, list }, nonce: base64urlEncode(nonce) };
  v.ct = base64urlEncode(await aesGcmEncrypt(vaultKey, nonce, plain, contentsAad(v)));
  plain.fill(0);
  v.sig = base64urlEncode(await ed25519Sign(contents.accountSeed, vaultMessage(v)));
  if (canonical(v).length > VAULT_LIMIT) fail("too_large");
  return v;
}

function kdfValue(kdf, salt) {
  return { alg: "argon2id", m: kdf.m, t: kdf.t, p: kdf.p, salt: base64urlEncode(salt) };
}

/** A new salt and its lock secrets, drawn again while the auth seed is unusable ([CRY-9]). → bad_key (broken generator) */
async function newLockSecrets(account, lock, password, kdf, random) {
  for (let i = 0; i < DRAW_ATTEMPTS; i++) {
    const salt = random(16);
    const ls = await deriveLockSecrets(account, lock, password, kdf, salt);
    if (usableSeed(ls.authSeed)) return [salt, ls];
    ls.authSeed.fill(0);
    ls.boxSecret.fill(0);
  }
  fail("bad_key");
}

/**
 * Create a new password lock's public part. `slot` is `{ label, password, username, kdf }`; the password must satisfy
 * [LCK-8] for `username` (`weak_password`), as in every function that creates a password lock. Draws: slot id (8),
 * salt (16, again while the auth seed is unusable, [CRY-9]). Returns `[slot, lockPublic]`.
 */
export async function newPasswordLock(account, slot, random) {
  checkPassword(slot.password, slot.username);
  checkLabel(slot.label);
  const id = base64urlEncode(random(8));
  const kdf = { m: slot.kdf.m, t: slot.kdf.t, p: slot.kdf.p ?? 1 };
  const [salt, ls] = await newLockSecrets(account, id, slot.password, kdf, random);
  const pub = {
    id,
    kdf: kdfValue(kdf, salt),
    auth: formatKey("ed25519", await ed25519Public(ls.authSeed)),
    box: formatKey("x25519", await x25519Public(ls.boxSecret)),
  };
  ls.authSeed.fill(0);
  ls.boxSecret.fill(0);
  return [{ id, label: slot.label }, pub];
}

function passwordLock(pub, wrap) {
  return { id: pub.id, kind: "password", kdf: pub.kdf, auth: pub.auth, box: pub.box, wrap };
}

async function buildLocksAndSeal(account, instance, rev, grant, rbox, pairs, contents, vk, random) {
  const list = [
    { id: "recovery", kind: "recovery", box: formatKey("x25519", rbox), wrap: await wrapVaultKey(vk, rbox, account, instance, "recovery", random) },
  ];
  for (const [, pub] of pairs) {
    const w = await wrapVaultKey(vk, s.parseKey(pub.box, "x25519"), account, instance, pub.id, random);
    list.push(passwordLock(pub, w));
  }
  return sealVault(account, instance, rev, grant, list, contents, vk, random);
}

/**
 * Build the vault of a new instance (`rev` 1, `gen` 1). Draws: vault key (32); for a new slot, id (8) and salt (16);
 * the recovery wrap (32 + 12); each password wrap (32 + 12) in slot order; the contents nonce (12).
 * `p`: `{ account, instance, recovery: { signSeed, boxSecret }, contents, keep: [[slot, lockPublic]], add?: slot }`.
 */
export async function instanceVault(p, random) {
  const vk = random(32);
  const pairs = [...p.keep];
  if (p.add) pairs.push(await newPasswordLock(p.account, p.add, random));
  const rbox = await x25519Public(p.recovery.boxSecret);
  const grant = await signGrant(p.account, p.instance, 1, pairs.map(([x]) => x), rbox, p.recovery.signSeed);
  try {
    return await buildLocksAndSeal(p.account, p.instance, 1, grant, rbox, pairs, p.contents, vk, random);
  } finally {
    vk.fill(0);
  }
}

/** The password locks of an unlocked vault to carry over ([KT-3]); `drop` names slots to leave out. */
export function carriedLocks(u, drop = []) {
  const out = [];
  for (const x of u.info.slots) {
    if (drop.includes(x.id)) continue;
    const l = u.info.locks.find((y) => y.kind === "password" && y.id === x.id);
    if (l) out.push([{ id: x.id, label: x.label }, { id: l.id, kdf: l.value.kdf, auth: l.value.auth, box: l.value.box }]);
  }
  return out;
}

function idsOf(u, vault) {
  const m = s.object(vault);
  const grant = s.member(s.member(m, "locks"), "grant");
  if (s.int(m, "rev") !== u.info.rev || s.int(grant, "gen") !== u.info.gen) fail("stale_rev");
  return { account: s.string(m, "account"), instance: s.string(m, "instance"), grant };
}

/** A data update ([HST-12] case 1): `rev + 1`. Draws: the contents nonce (12). */
export async function updateContents(u, vault, contents, random) {
  const { account, instance, grant } = idsOf(u, vault);
  const list = u.info.locks.map((l) => l.value);
  return sealVault(account, instance, u.info.rev + 1, grant, list, contents, u.vaultKey, random);
}

/**
 * A password change ([CHG-1] step 1); the new password must satisfy [LCK-8] for `username` (`weak_password`).
 * Draws: salt (16), wrap (32 + 12), contents nonce (12).
 * Returns `{ vault, new }` where `new` is `SHA-256(canonical(new lock))`.
 */
export async function changePassword(u, vault, slot, password, username, kdf, random) {
  checkPassword(password, username);
  const { account, instance, grant } = idsOf(u, vault);
  const index = u.info.locks.findIndex((l) => l.kind === "password" && l.id === slot);
  if (index < 0) fail("bad_locks");
  const k = { m: kdf.m, t: kdf.t, p: kdf.p ?? 1 };
  const [salt, ls] = await newLockSecrets(account, slot, password, k, random);
  const box = await x25519Public(ls.boxSecret);
  const pub = { id: slot, kdf: kdfValue(k, salt), auth: formatKey("ed25519", await ed25519Public(ls.authSeed)), box: formatKey("x25519", box) };
  ls.authSeed.fill(0);
  ls.boxSecret.fill(0);
  const lock = passwordLock(pub, await wrapVaultKey(u.vaultKey, box, account, instance, slot, random));
  const hash = await sha256(canonical(lock));
  const list = u.info.locks.map((l) => l.value);
  list[index] = lock;
  return { vault: await sealVault(account, instance, u.info.rev + 1, grant, list, u.contents, u.vaultKey, random), new: hash };
}

/** Add a password slot ([KT-4]). Draws: id (8), salt (16), wrap (32 + 12), contents nonce (12). */
export async function addSlot(u, vault, recovery, slot, random) {
  const { account, instance } = idsOf(u, vault);
  if (u.info.slots.length >= MAX_SLOTS) fail("bad_locks");
  const [x, pub] = await newPasswordLock(account, slot, random);
  const w = await wrapVaultKey(u.vaultKey, s.parseKey(pub.box, "x25519"), account, instance, x.id, random);
  const slots = [...u.info.slots, x];
  const list = [...u.info.locks.map((l) => l.value), passwordLock(pub, w)];
  const grant = await signGrant(account, instance, u.info.gen + 1, slots, await x25519Public(recovery.boxSecret), recovery.signSeed);
  return sealVault(account, instance, u.info.rev + 1, grant, list, u.contents, u.vaultKey, random);
}

/** The vault after a recovery-key rotation ([KT-5]). Draws: wrap (32 + 12), contents nonce (12). */
export async function regrant(u, vault, newRecovery, random) {
  const { account, instance } = idsOf(u, vault);
  const rbox = await x25519Public(newRecovery.boxSecret);
  const grant = await signGrant(account, instance, u.info.gen + 1, u.info.slots, rbox, newRecovery.signSeed);
  const list = [];
  for (const l of u.info.locks) {
    if (l.kind === "recovery") {
      list.push({ id: "recovery", kind: "recovery", box: formatKey("x25519", rbox), wrap: await wrapVaultKey(u.vaultKey, rbox, account, instance, "recovery", random) });
    } else list.push(l.value);
  }
  return sealVault(account, instance, u.info.rev + 1, grant, list, u.contents, u.vaultKey, random);
}

export { verifyVault };
