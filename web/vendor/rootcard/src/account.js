// High-level flows (SPEC §18): registration ([CLT-1]), new instances ([KT-3], [KT-4], [KT-8]) and recovery-key
// rotation ([KT-5]). The random draws are in the same order as the Rust crate's `account` module.

import { fail } from "./errors.js";
import { base64urlEncode } from "./encoding.js";
import { inception } from "./id.js";
import { checkRecoveryKey, eventHash, pendingInstance, rotateRecoveryEvent, verifyLog } from "./log.js";
import { signPublic } from "./profile.js";
import { checkNewRecoveryKey, deriveRecoveryKeys } from "./recovery.js";
import { DRAW_ATTEMPTS, usableSeed } from "./crypto.js";
import { recoveryCard } from "./file.js";
import { carriedLocks, checkPassword, instanceVault, regrant } from "./vault.js";

/** The account seed of a new instance: 32 random bytes, drawn again while unusable ([CRY-9]). → bad_key (broken generator) */
function drawAccountSeed(random) {
  for (let i = 0; i < DRAW_ATTEMPTS; i++) {
    const seed = random(32);
    if (usableSeed(seed)) return seed;
  }
  fail("bad_key");
}

/**
 * Build a registration ([CLT-1]) from a recovery key the caller generated ([RK-3]; usable by [CRY-9], see
 * newRecoveryKey → bad_key). `home` is `{ key, url }` with a key string. Draws: the account seed (32, again while
 * unusable, [CRY-9]), then instanceVault with one new slot.
 * @returns {Promise<{ log, vault, public, card, account }>}
 */
export async function register(recoveryKey, realm, username, password, slotLabel, home, time, kdf, random) {
  checkPassword(password, username);
  const keys = await deriveRecoveryKeys(recoveryKey, realm, username);
  checkNewRecoveryKey(keys);
  const inc = await inception(keys, realm, username);
  const state = await verifyLog([inc], { realms: [realm] });
  const seed = drawAccountSeed(random);
  const pending = await pendingInstance(state, keys.signSeed, seed, home, "register", time);
  const instance = base64urlEncode(await eventHash(pending));
  const vault = await instanceVault(
    {
      account: state.account,
      instance,
      recovery: keys,
      contents: { accountSeed: seed, data: {} },
      keep: [],
      add: { label: slotLabel, password, username, kdf },
    },
    random,
  );
  const pub = await signPublic(state.account, instance, 1, {}, seed);
  const card = await recoveryCard(realm, username, state.account, recoveryKey);
  seed.fill(0);
  keys.signSeed.fill(0);
  keys.boxSecret.fill(0);
  return { log: [inc, pending], vault, public: pub, card, account: state.account };
}

/**
 * Build a new instance on top of `state` ([KT-3]). `mode` is `{ restore: true }`, `{ revoke: [slot ids] }`,
 * `{ reset: slot }` or `{ fresh: slot }`, where a slot is `{ label, password, kdf }`. `old` is the current vault
 * unlocked with the recovery lock (not needed for fresh). Draws: the account seed (32, again while unusable,
 * [CRY-9]), then instanceVault.
 * @returns {Promise<{ event, vault, public }>}
 */
export async function newInstance(state, recovery, old, oldPublicData, mode, home, time, random) {
  await checkRecoveryKey(state, recovery.signSeed);
  const slot = mode.reset ?? mode.fresh;
  if (slot) {
    // The new password is checked before anything is drawn ([LCK-8]); its username must be this identity's.
    if (slot.username !== state.username) fail("bad_field");
    checkPassword(slot.password, state.username);
  }
  const seed = drawAccountSeed(random);
  const reason = mode.restore ? "restore" : mode.fresh ? "fresh" : "revoke";
  const event = await pendingInstance(state, recovery.signSeed, seed, home, reason, time);
  const instance = base64urlEncode(await eventHash(event));
  let data = {};
  let known;
  let keep = [];
  let add;
  let publicData = {};
  if (!mode.fresh) {
    if (!old) fail("bad_locks");
    data = old.contents.data;
    known = old.contents.known;
    publicData = oldPublicData ?? {};
    if (mode.restore) keep = carriedLocks(old, []);
    else if (mode.revoke) keep = carriedLocks(old, mode.revoke);
    else add = mode.reset;
  } else add = mode.fresh;
  const contents = { accountSeed: seed, data };
  if (known !== undefined) contents.known = known;
  const vault = await instanceVault({ account: state.account, instance, recovery, contents, keep, add }, random);
  const pub = await signPublic(state.account, instance, 1, publicData, seed);
  seed.fill(0);
  return { event, vault, public: pub };
}

/**
 * Rotate the recovery key ([KT-5]) to `newKey` (usable by [CRY-9] → bad_key; see newRecoveryKey). `unlocked` is the current vault unlocked. Draws: regrant.
 * @returns {Promise<{ event, vault, card }>}
 */
export async function rotateRecovery(state, log, oldKeys, newKey, oldVault, unlocked, time, random) {
  const next = await deriveRecoveryKeys(newKey, state.realm, state.username);
  checkNewRecoveryKey(next);
  const event = await rotateRecoveryEvent(state, oldKeys.signSeed, next.signSeed, time);
  const vault = await regrant(unlocked, oldVault, next, random);
  const card = await recoveryCard(state.realm, state.username, state.account, newKey, [...log, event]);
  return { event, vault, card };
}
