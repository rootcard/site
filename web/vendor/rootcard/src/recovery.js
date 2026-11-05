// The recovery key (SPEC §6).

import { fail } from "./errors.js";
import { B32, base32Decode, base32Encode, base32Normalize, bytesEqual } from "./encoding.js";
import { ed25519Public, frame, frameObject, hkdf, sha256 } from "./crypto.js";
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

/** The public recovery signing key. */
export async function recoverySignPublic(keys) {
  return ed25519Public(keys.signSeed);
}

export { bytesEqual };
