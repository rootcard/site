// Challenges and the signed messages of vault fetch, login and password change (SPEC §13).

import { fail } from "./errors.js";
import { base64urlEncode } from "./encoding.js";
import { ed25519Sign, ed25519Verify, frameObject } from "./crypto.js";
import * as s from "./keys.js";
import { label } from "./labels.js";
import { checkUrl } from "./log.js";

export const CHALLENGE_LIFETIME = 60;

/** Parse a challenge ([CHL-1]). → bad_field, bad_key */
export function parseChallenge(v) {
  const m = s.object(v);
  s.members(m, ["nonce", "host", "realm", "version", "expires"]);
  s.bytes(m, "nonce", 32);
  s.key(m, "host", "ed25519");
  s.string(m, "realm");
  s.versionRef(s.get(m, "version"));
  s.int(m, "expires");
  return m;
}

/** The login message ([LGN-1] step 5). `host` is a key string, `nonce` b64u. */
export function loginMessage(account, host, lock, nonce, realm, url, version) {
  return frameObject(label("login"), { account, host, lock, nonce, realm, url, version: { seq: version.seq, hash: version.hash } });
}

/** The vault fetch message ([FET-1]). */
export function fetchMessage(account, host, lock, nonce, url) {
  return frameObject(label("fetch"), { account, host, lock, nonce, url });
}

/** The password change proof message ([CHG-1] step 2). `newLockHash` is b64u. */
export function changeMessage(account, host, lock, newLockHash, nonce, url) {
  return frameObject(label("change"), { account, host, lock, new: newLockHash, nonce, url });
}

/**
 * Sign a login for `challenge` with the account key and the lock's key ([LGN-1] steps 4, 5). → wrong_host, stale_version
 * @returns {Promise<{account, nonce, version, url, lock, sig, lock_sig}>}
 */
export async function signLogin(state, challenge, url, lock, accountSeed, lockSeed) {
  const ch = parseChallenge(challenge);
  if (!state.instance) fail("no_instance");
  if (ch.host !== state.instance.home.key || ch.realm !== state.realm) fail("wrong_host");
  if (ch.version.seq !== state.version.seq || ch.version.hash !== state.version.hash) fail("stale_version");
  checkUrl(url);
  const msg = loginMessage(state.account, ch.host, lock, ch.nonce, state.realm, url, state.version);
  return {
    account: state.account,
    nonce: ch.nonce,
    version: { seq: state.version.seq, hash: state.version.hash },
    url,
    lock,
    sig: base64urlEncode(await ed25519Sign(accountSeed, msg)),
    lock_sig: base64urlEncode(await ed25519Sign(lockSeed, msg)),
  };
}

/** Parse a login request. → bad_field */
export function parseLoginRequest(v) {
  const m = s.object(v);
  s.members(m, ["account", "nonce", "version", "url", "lock", "sig", "lock_sig"]);
  checkUrl(s.string(m, "url"));
  const lock = s.string(m, "lock");
  if (lock.length < 1 || lock.length > 16) fail("bad_field");
  s.account(m, "account");
  s.bytes(m, "nonce", 32);
  s.versionRef(s.get(m, "version"));
  s.sig(m, "sig");
  s.sig(m, "lock_sig");
  return m;
}

/** Verify both signatures of a login request ([LGN-1] step 6). Keys are key strings. → bad_signature */
export async function verifyLogin(request, realm, homeKey, accountKey, lockKey) {
  const r = parseLoginRequest(request);
  const msg = loginMessage(r.account, homeKey, r.lock, r.nonce, realm, r.url, r.version);
  await ed25519Verify(s.parseKey(accountKey, "ed25519"), msg, s.sig(r, "sig"));
  await ed25519Verify(s.parseKey(lockKey, "ed25519"), msg, s.sig(r, "lock_sig"));
}
