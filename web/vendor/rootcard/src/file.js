// The account file and the recovery card (SPEC §15).

import { fail } from "./errors.js";
import { canonical } from "./json.js";
import * as s from "./keys.js";
import { verifyLog } from "./log.js";
import { verifyPublic } from "./profile.js";
import { verifyVault } from "./vaultcheck.js";
import { accountId, inception, tag } from "./id.js";
import { deriveRecoveryKeys, formatRecoveryKey, parseRecoveryKey, recoverySignPublic } from "./recovery.js";
import { formatKey } from "./keys.js";

export const FILE_LIMIT = 5 * 1024 * 1024;
export const HOST_DATA_LIMIT = 16 * 1024;

/** Build an account file ([FIL-2]). */
export function exportAccount(state, log, publicProfile, vault, hostData) {
  const f = {
    format: "rootcard-account",
    v: 1,
    realm: state.realm,
    account: state.account,
    handle: state.handle,
    version: { seq: state.version.seq, hash: state.version.hash },
    log: [...log],
  };
  if (publicProfile !== undefined && publicProfile !== null) f.public = publicProfile;
  if (vault !== undefined && vault !== null) f.vault = vault;
  if (hostData !== undefined && hostData !== null) f.host_data = hostData;
  return f;
}

/** The suggested file name ([FIL-1]). */
export function accountFileName(state) {
  return `${state.username}-${tag(state.account)}.rootcard.json`;
}

/** Import an account file ([FIL-3]). Returns `{ state, log, public?, vault?, hostData? }`. */
export async function importAccount(file, options) {
  if (canonical(file).length > FILE_LIMIT) fail("too_large");
  const m = s.object(file);
  if (m.format !== "rootcard-account") fail("bad_field");
  s.version(m);
  s.members(m, ["format", "v", "realm", "account", "handle", "version", "log"], ["public", "vault", "host_data"]);
  const realm = s.string(m, "realm");
  const account = s.account(m, "account");
  const handle = s.string(m, "handle");
  const version = s.versionRef(s.get(m, "version"));
  const log = s.array(m, "log");
  let hostData;
  if (Object.hasOwn(m, "host_data")) {
    hostData = s.object(m.host_data);
    if (canonical(hostData).length > HOST_DATA_LIMIT) fail("too_large");
  }
  const state = await verifyLog(log, options);
  if (state.account !== account || state.realm !== realm || state.handle !== handle ||
      state.version.seq !== version.seq || state.version.hash !== version.hash) {
    fail("account_mismatch");
  }
  const out = { state, log };
  if (Object.hasOwn(m, "public")) out.public = { value: m.public, info: await verifyPublic(m.public, state) };
  if (Object.hasOwn(m, "vault")) out.vault = { value: m.vault, info: await verifyVault(m.vault, state) };
  if (hostData !== undefined) out.hostData = hostData;
  return out;
}

/** Build a recovery card ([CRD-1], [CRD-2]). */
export async function recoveryCard(realm, username, account, key, log) {
  const c = { format: "rootcard-card", v: 1, realm, username, account, key: await formatRecoveryKey(key) };
  if (log) c.log = [...log];
  return c;
}

/** Read a recovery card ([CRD-3]). Returns `{ realm, username, account, key, keys, log, state }`. */
export async function readCard(card) {
  const m = s.object(card);
  if (m.format !== "rootcard-card") fail("bad_field");
  s.version(m);
  s.members(m, ["format", "v", "realm", "username", "account", "key"], ["log"]);
  const realm = s.string(m, "realm");
  const username = s.string(m, "username");
  const account = s.account(m, "account");
  const keyText = s.string(m, "key");
  const logValue = Object.hasOwn(m, "log") ? s.array(m, "log") : undefined;
  const key = await parseRecoveryKey(keyText);
  const keys = await deriveRecoveryKeys(key, realm, username);
  const options = { realms: [realm] };
  let log;
  let state;
  if (logValue === undefined) {
    const inc = await inception(keys, realm, username);
    if ((await accountId(inc)) !== account) fail("account_mismatch");
    log = [inc];
    state = await verifyLog(log, options);
  } else {
    log = logValue;
    state = await verifyLog(log, options);
    if (state.account !== account || state.realm !== realm || state.username !== username) fail("account_mismatch");
    if (formatKey("ed25519", await recoverySignPublic(keys)) !== state.recovery) fail("wrong_recovery_key");
  }
  return { realm, username, account, key, keys, log, state };
}

/** The printable text form of a recovery card ([CRD-4]). */
export async function cardText(card) {
  const c = await readCard(card);
  const groups = (str) => str.match(/.{1,4}/g).join(" ");
  const key = (await formatRecoveryKey(c.key)).slice(4).replace(/-/g, " ");
  return (
    "rootcard recovery card\n\n" +
    `Handle:     ${c.state.handle}\n` +
    `Realm:      ${c.realm}\n` +
    `Account id: ${groups(c.account)}\n\n` +
    `Recovery key:\n  RCR ${key}\n\n` +
    "Anyone who has this card controls the identity. Keep it offline and private.\n" +
    "Only enter the recovery key in the rootcard key tool.\n"
  );
}
