// The recovery key (SPEC §6).

import { fail } from "./errors.js";
import { B32, base32Decode, base32Encode, base32Normalize, bytesEqual } from "./encoding.js";
import { DRAW_ATTEMPTS, ed25519Public, frame, frameObject, hkdf, sha256, usableSeed } from "./crypto.js";
import { label } from "./labels.js";

async function checksum(key) {
  return base32Encode(await sha256(frame(label("recovery/check"), key))).slice(0, 4);
}

/** The written form `RCR-XXXX-…-CCCC` ([RK-1]). */
export async function formatRecoveryKey(key) {
  const body = base32Encode(key) + (await checksum(key));
  const groups = [];
  for (let i = 0; i < 14; i++) groups.push(body.slice(4 * i, 4 * i + 4));
  return "RCR-" + groups.join("-");
}

/** Parse a typed recovery key ([RK-2]). → bad_base32, bad_checksum */
export async function parseRecoveryKey(text) {
  let s = [...text].filter((c) => c !== "-" && c !== " ").join("");
  if ([...s].length === 59 && s.slice(0, 3).toUpperCase() === "RCR") s = s.slice(3);
  if (s.length !== 56 || !/^[\x00-\x7f]*$/.test(s)) fail("bad_base32");
  const n = base32Normalize(s);
  for (const c of n) if (!B32.includes(c)) fail("bad_base32");
  const key = base32Decode(n.slice(0, 52), 32);
  if (n.slice(52) !== (await checksum(key))) fail("bad_checksum");
  return key;
}

/**
 * Derive an identity's recovery keys ([RK-4]): `signSeed` (Ed25519) and `boxSecret` (X25519).
 * @returns {Promise<{ signSeed: Uint8Array, boxSecret: Uint8Array }>}
 */
export async function deriveRecoveryKeys(rk, realm, username) {
  const ctx = { realm, username };
  return {
    signSeed: await hkdf(rk, new Uint8Array(0), frameObject(label("recovery/sign"), ctx)),
    boxSecret: await hkdf(rk, new Uint8Array(0), frameObject(label("recovery/box"), ctx)),
  };
}

/**
 * Generate a recovery key for an identity ([RK-3]): 32 random bytes, drawn again while the derived signing seed is
 * unusable ([CRY-9]). Draws: 32 bytes per attempt. → bad_key only for a broken generator.
 */
export async function newRecoveryKey(realm, username, random) {
  for (let i = 0; i < DRAW_ATTEMPTS; i++) {
    const rk = random(32);
    const keys = await deriveRecoveryKeys(rk, realm, username);
    const ok = usableSeed(keys.signSeed);
    keys.signSeed.fill(0);
    keys.boxSecret.fill(0);
    if (ok) return rk;
    rk.fill(0);
  }
  fail("bad_key");
}

/** A new recovery key must give a usable signing seed ([CRY-9]). → bad_key */
export function checkNewRecoveryKey(keys) {
  if (!usableSeed(keys.signSeed)) fail("bad_key");
}

/** The public recovery signing key. */
export async function recoverySignPublic(keys) {
  return ed25519Public(keys.signSeed);
}

export { bytesEqual };
