// Argon2id runs here, off the main thread, so the page stays responsive during the one or two seconds it takes.
// Everything that derives a password lock goes through this worker: registration, unlocking and password changes.

import { register, changePassword, deriveLockSecrets } from "/vendor/rootcard/src/vault-index.js";
import { accountId, deriveRecoveryKeys, inception, newRecoveryKey, recoveryCard } from "/vendor/rootcard/src/index.js";

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

// [CLT-1]: the recovery key is generated here and never leaves this worker except inside the card, which the page makes
// the user save before anything is sent. The registration is built only when the user activates it, so the instance
// time is fresh for the host's receipt window; the key is erased once the host has the identity, or on "forget".
let pending = null; // { rk, realm, username }

function forget() {
  pending?.rk.fill(0);
  pending = null;
}

const ops = {
  async prepare(realm, username) {
    forget();
    const rk = await newRecoveryKey(realm, username, random);
    const keys = await deriveRecoveryKeys(rk, realm, username);
    const account = await accountId(await inception(keys, realm, username));
    keys.signSeed.fill(0);
    keys.boxSecret.fill(0);
    pending = { rk, realm, username };
    return { account, card: await recoveryCard(realm, username, account, rk) };
  },
  async register(password, home, time, kdf) {
    if (!pending) throw new Error("Start over: the recovery key is gone.");
    return register(pending.rk, pending.realm, pending.username, password, "Password", home, time, kdf, random);
  },
  async forget() {
    forget();
    return true;
  },
  async derive(account, lock, password, kdf, salt) {
    return deriveLockSecrets(account, lock, password, kdf, salt);
  },
  // changePassword checks the password rules ([LCK-8]) against the username; the page checks them first too.
  async changePassword(u, vault, slot, password, username, kdf) {
    return changePassword(u, vault, slot, password, username, kdf, random);
  },
};

self.onmessage = async ({ data }) => {
  const { id, op, args } = data;
  try {
    self.postMessage({ id, result: await ops[op](...args) });
  } catch (e) {
    self.postMessage({ id, error: { code: e?.code, message: String(e?.message ?? e) } });
  }
};
