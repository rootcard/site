// Proofs of identity (SPEC §14).

import { fail } from "./errors.js";
import { base64urlEncode } from "./encoding.js";
import { ed25519PublicIs, ed25519Sign, ed25519Verify, frameObject, sha256 } from "./crypto.js";
import { utf8 } from "./encoding.js";
import { validate, without } from "./json.js";
import * as s from "./keys.js";
import { formatKey } from "./keys.js";
import { label } from "./labels.js";
import { checkRecoveryKey, verifyLog } from "./log.js";

/** `SHA-256(frame("rootcard/statement/v1", { statement }))` ([PRF-5]). → bad_json */
export async function statementChallenge(statement) {
  validate(statement);
  return sha256(frameObject(label("statement"), { statement }));
}

function checkRecipient(r) {
  const n = utf8(r).length;
  if (n < 1 || n > 256) fail("bad_field");
}

/** Make a proof ([PRF-1], [PRF-2]). `by` is "account" or "recovery"; `challenge` is 32 bytes. */
export async function prove(state, by, seed, challenge, recipient) {
  checkRecipient(recipient);
  const p = { v: 1, by, account: state.account, challenge: base64urlEncode(challenge), recipient };
  if (by === "account") {
    if (!state.instance) fail("no_instance");
    if (!(await ed25519PublicIs(seed, s.parseKey(state.instance.account_key, "ed25519")))) fail("wrong_account_key");
    p.instance = state.instance.hash;
  } else {
    await checkRecoveryKey(state, seed);
  }
  p.sig = base64urlEncode(await ed25519Sign(seed, frameObject(label("proof"), p)));
  return p;
}

/** Verify a proof against the newest log the verifier knows ([PRF-4]). Returns the log state. */
export async function verifyProof(proof, log, challenge, recipient, options) {
  const m = s.object(proof);
  s.version(m);
  const by = s.string(m, "by");
  if (by !== "account" && by !== "recovery") fail("bad_field");
  if (by === "account") s.members(m, ["v", "by", "account", "instance", "challenge", "recipient", "sig"]);
  else s.members(m, ["v", "by", "account", "challenge", "recipient", "sig"]);
  const account = s.account(m, "account");
  if (by === "account") s.bytes(m, "instance", 32);
  s.bytes(m, "challenge", 32);
  checkRecipient(s.string(m, "recipient"));
  const sig = s.sig(m, "sig");
  const state = await verifyLog(log, options);
  if (account !== state.account) fail("account_mismatch");
  if (state.retired) fail("account_retired");
  if (m.challenge !== base64urlEncode(challenge)) fail("wrong_challenge");
  if (m.recipient !== recipient) fail("wrong_recipient");
  let key;
  if (by === "account") {
    if (!state.instance) fail("no_instance");
    if (m.instance !== state.instance.hash) fail("stale_version");
    key = state.instance.account_key;
  } else key = state.recovery;
  await ed25519Verify(s.parseKey(key, "ed25519"), frameObject(label("proof"), without(m, "sig")), sig);
  return state;
}
