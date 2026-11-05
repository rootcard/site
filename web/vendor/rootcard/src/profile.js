// Arbitrary data: the public profile and data keys (SPEC §12).

import { fail } from "./errors.js";
import { base64urlEncode } from "./encoding.js";
import { ed25519Sign, ed25519Verify, frameObject } from "./crypto.js";
import { canonical, validate, without } from "./json.js";
import * as s from "./keys.js";
import { label } from "./labels.js";

export const PROFILE_LIMIT = 16 * 1024;
const MAX_REV = 2 ** 32;

/** [DAT-4] → bad_data_key */
export function checkDataKey(key) {
  if (typeof key !== "string" || key.length < 1 || key.length > 64 || !/^[a-z0-9._-]+$/.test(key)) fail("bad_data_key");
  let rest;
  if (key.startsWith("user.")) rest = key.slice(5);
  else if (key.startsWith("app.")) {
    const r = key.slice(4);
    const dot = r.indexOf(".");
    if (dot < 0) fail("bad_data_key");
    checkAppName(r.slice(0, dot));
    rest = r.slice(dot + 1);
  } else fail("bad_data_key");
  if (rest.length === 0) fail("bad_data_key");
}

/** An application namespace name ([DAT-4]). → bad_data_key */
export function checkAppName(name) {
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(name)) fail("bad_data_key");
}

/** Every key of `data` is valid and its canonical form is at most `limit` bytes. → bad_data_key, too_large */
export function checkData(data, limit) {
  for (const k of Object.keys(data)) checkDataKey(k);
  if (canonical(data).length > limit) fail("too_large");
}

/** Set `key` on behalf of application `app` ([DAT-7]). Returns a new object. → bad_data_key, bad_json */
export function setData(data, app, key, value) {
  checkDataKey(key);
  checkAppName(app);
  if (!key.startsWith("user.") && !key.startsWith(`app.${app}.`)) fail("bad_data_key");
  validate(value);
  return { ...data, [key]: value };
}

/** Remove `key` on behalf of application `app` ([DAT-7]). Returns a new object. → bad_data_key */
export function removeData(data, app, key) {
  checkDataKey(key);
  if (!key.startsWith("user.") && !key.startsWith(`app.${app}.`)) fail("bad_data_key");
  const d = { ...data };
  delete d[key];
  return d;
}

/** The message the account key signs on a profile ([DAT-2]). */
export function publicMessage(profile) {
  return frameObject(label("public"), without(profile, "sig"));
}

/** Sign a public profile with the account key. → bad_data_key, too_large */
export async function signPublic(account, instance, rev, data, accountSeed) {
  checkData(data, PROFILE_LIMIT);
  const p = { v: 1, account, instance, rev, data };
  p.sig = base64urlEncode(await ed25519Sign(accountSeed, publicMessage(p)));
  if (canonical(p).length > PROFILE_LIMIT) fail("too_large");
  return p;
}

/** Verify a public profile ([DAT-2]). Returns `{ rev, data }`. */
export async function verifyPublic(profile, state) {
  if (canonical(profile).length > PROFILE_LIMIT) fail("too_large");
  const m = s.object(profile);
  s.version(m);
  s.members(m, ["v", "account", "instance", "rev", "data", "sig"]);
  const account = s.account(m, "account");
  s.bytes(m, "instance", 32);
  const rev = s.intIn(m, "rev", 1, MAX_REV);
  const data = s.member(m, "data");
  const sig = s.sig(m, "sig");
  if (account !== state.account) fail("account_mismatch");
  if (state.retired) fail("account_retired");
  if (!state.instance) fail("no_instance");
  if (m.instance !== state.instance.hash) fail("wrong_instance");
  for (const k of Object.keys(data)) checkDataKey(k);
  await ed25519Verify(s.parseKey(state.instance.account_key, "ed25519"), publicMessage(m), sig);
  return { rev, data };
}
