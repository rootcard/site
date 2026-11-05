// The identity log (SPEC §9) and versions (SPEC §10). A log state is plain JSON, identical to the Rust crate's
// `LogState::to_value`, so that hosts can store it ([LOG-16]).

import { fail } from "./errors.js";
import { base64urlEncode, base64urlDecode, bytesEqual } from "./encoding.js";
import { ed25519Public, ed25519PublicIs, ed25519Sign, ed25519Verify, frameObject, sha256 } from "./crypto.js";
import { canonical, without, isObject, MAX_SAFE } from "./json.js";
import * as s from "./keys.js";
import { formatKey } from "./keys.js";
import { accountId, checkRealm, checkUsername, handle } from "./id.js";
import { label } from "./labels.js";

export const MAX_EVENTS = 1000;
export const EVENT_LIMIT = 4096;
export const FUTURE_WINDOW = 600;
const REASONS = ["register", "revoke", "restore", "fresh"];

/** The message owners sign on an event ([LOG-6]). */
export function eventMessage(e) {
  return frameObject(label("event"), without(e, "sigs"));
}

/** The message the primary host signs as its receipt ([LOG-8]). */
export function receiptMessage(e) {
  return frameObject(label("receipt"), without(e, "sigs"));
}

/** The event hash ([LOG-5]). */
export async function eventHash(e) {
  return sha256(eventMessage(e));
}

/** `home.url` ([LOG-4]). → bad_field */
export function checkUrl(url) {
  if (typeof url !== "string" || url.length < 1 || url.length > 256 || !/^[\x21-\x7e]+$/.test(url)) fail("bad_field");
}

function parseHome(m) {
  s.members(m, ["key", "url"]);
  const key = s.key(m, "key", "ed25519");
  checkUrl(s.string(m, "url"));
  return { key: m.key, keyRaw: key, url: m.url };
}

/** [LOG-12] step 2 for one event. */
function parseEvent(v, index) {
  if (isObject(v) && canonical(v).length > EVENT_LIMIT) fail("too_large");
  const m = s.object(v);
  s.version(m);
  const kind = s.string(m, "kind");
  if (!["incept", "instance", "rotate_recovery", "retire"].includes(kind)) fail("bad_kind");
  if ((index === 0) !== (kind === "incept")) fail("bad_kind");
  if (kind === "incept") s.members(m, ["v", "kind", "seq", "body", "sigs"]);
  else s.members(m, ["v", "account", "seq", "prev", "kind", "time", "body", "sigs"]);
  const e = { map: m, kind, seq: s.intIn(m, "seq", 0, MAX_SAFE) };
  if (kind !== "incept") {
    e.account = s.account(m, "account");
    e.prev = s.bytes(m, "prev", 32);
    e.time = s.intIn(m, "time", 0, MAX_SAFE);
  } else {
    e.time = 0;
  }
  e.sigs = [];
  for (const x of s.array(m, "sigs")) {
    const o = s.object(x);
    s.members(o, ["key", "sig"]);
    s.key(o, "key", "ed25519");
    e.sigs.push({ key: o.key, sig: s.sig(o, "sig") });
  }
  const body = s.member(m, "body");
  if (kind === "incept") {
    s.members(body, ["realm", "username", "recovery"]);
    e.realm = s.string(body, "realm");
    e.username = s.string(body, "username");
    s.key(body, "recovery", "ed25519");
    e.recovery = body.recovery;
  } else if (kind === "instance") {
    s.members(body, ["account_key", "home", "reason"]);
    s.key(body, "account_key", "ed25519");
    e.accountKey = body.account_key;
    e.home = parseHome(s.member(body, "home"));
    const reason = s.string(body, "reason");
    if (!REASONS.includes(reason)) fail("bad_reason");
    e.reason = reason;
  } else if (kind === "rotate_recovery") {
    s.members(body, ["recovery"]);
    s.key(body, "recovery", "ed25519");
    e.recovery = body.recovery;
  } else {
    s.members(body, []);
  }
  return e;
}

function checkLength(n) {
  if (n === 0) fail("bad_field");
  if (n > MAX_EVENTS) fail("too_many_events");
}

function rawKey(k) {
  return s.parseKey(k, "ed25519");
}

/** [LOG-12] step 4 for one event, updating the state `st` (a copy) in place. */
async function apply(st, e, index, now, receipt) {
  if (st.retired) fail("account_retired");
  if (e.account !== st.account) fail("account_mismatch");
  if (e.seq !== index) fail("bad_seq");
  if (base64urlEncode(e.prev) !== st.version.hash) fail("bad_prev");
  if (e.time < st.time) fail("time_backwards");
  if (now !== undefined && now !== null && e.time > now + FUTURE_WINDOW) fail("future_time");
  let expected;
  if (e.kind === "instance") {
    expected = [st.recovery, e.accountKey];
    if (receipt) expected.push(e.home.key);
  } else if (e.kind === "rotate_recovery") expected = [st.recovery, e.recovery];
  else expected = [st.recovery];
  if (e.sigs.length !== expected.length || e.sigs.some((x, i) => x.key !== expected[i])) fail("wrong_signer");
  if (e.kind === "instance") {
    const ak = e.accountKey;
    const hk = e.home.key;
    if (ak === hk || st.keys.includes(ak) || st.homes.includes(ak) || st.keys.includes(hk)) fail("key_reuse");
  } else if (e.kind === "rotate_recovery") {
    if (st.keys.includes(e.recovery) || st.homes.includes(e.recovery)) fail("key_reuse");
  }
  if (e.reason !== undefined) {
    const has = st.instance !== undefined;
    const ok = e.reason === "register" ? !has : e.reason === "fresh" ? true : has;
    if (!ok) fail("bad_reason");
  }
  const msg = eventMessage(e.map);
  const owners = e.kind === "instance" ? 2 : e.sigs.length;
  for (let i = 0; i < owners; i++) await ed25519Verify(rawKey(e.sigs[i].key), msg, e.sigs[i].sig);
  if (e.kind === "instance" && receipt) {
    try {
      await ed25519Verify(rawKey(e.sigs[2].key), receiptMessage(e.map), e.sigs[2].sig);
    } catch {
      fail("bad_receipt");
    }
  }
  const hash = base64urlEncode(await sha256(msg));
  if (e.kind === "instance") {
    st.keys.push(e.accountKey);
    if (!st.homes.includes(e.home.key)) st.homes.push(e.home.key);
    st.instance = {
      hash,
      seq: index,
      account_key: e.accountKey,
      home: { key: e.home.key, url: e.home.url },
      reason: e.reason,
    };
  } else if (e.kind === "rotate_recovery") {
    st.recovery = e.recovery;
    st.keys.push(e.recovery);
  } else if (e.kind === "retire") {
    st.retired = true;
    delete st.instance;
  }
  st.time = e.time;
  st.version = { seq: index, hash };
}

function copyState(st) {
  const c = {
    account: st.account,
    realm: st.realm,
    username: st.username,
    handle: st.handle,
    recovery: st.recovery,
    retired: st.retired,
    version: { ...st.version },
    time: st.time,
    keys: [...st.keys],
    homes: [...st.homes],
  };
  if (st.instance) c.instance = { ...st.instance, home: { ...st.instance.home } };
  return c;
}

/**
 * Verify a whole log ([LOG-12]) and return its state.
 * @param {any[]} events
 * @param {{ realms: string[], now?: number }} options
 */
export async function verifyLog(events, options) {
  if (!Array.isArray(events)) fail("bad_field");
  checkLength(events.length);
  const parsed = events.map((v, i) => parseEvent(v, i));
  const inc = parsed[0];
  if (inc.seq !== 0) fail("bad_seq");
  checkRealm(inc.realm);
  if (!options.realms.includes(inc.realm)) fail("realm_not_accepted");
  checkUsername(inc.username);
  if (inc.sigs.length !== 1 || inc.sigs[0].key !== inc.recovery) fail("wrong_signer");
  const msg = eventMessage(inc.map);
  await ed25519Verify(rawKey(inc.recovery), msg, inc.sigs[0].sig);
  const account = await accountId(inc.map);
  const st = {
    account,
    realm: inc.realm,
    username: inc.username,
    handle: handle(inc.username, account),
    recovery: inc.recovery,
    retired: false,
    version: { seq: 0, hash: base64urlEncode(await sha256(msg)) },
    time: 0,
    keys: [inc.recovery],
    homes: [],
  };
  for (let i = 1; i < parsed.length; i++) await apply(st, parsed[i], i, options.now, true);
  return st;
}

/** Verify events that extend a verified log state ([LOG-15]). */
export async function extendLog(state, events, options) {
  const start = state.version.seq + 1;
  if (start + events.length > MAX_EVENTS) fail("too_many_events");
  const parsed = events.map((v, i) => parseEvent(v, start + i));
  const st = copyState(state);
  for (let i = 0; i < parsed.length; i++) await apply(st, parsed[i], start + i, options.now, true);
  return st;
}

/** Check a pending instance ([LOG-9]). */
export async function verifyPending(state, event, now) {
  const index = state.version.seq + 1;
  if (index >= MAX_EVENTS) fail("too_many_events");
  const e = parseEvent(event, index);
  if (e.kind !== "instance") fail("bad_kind");
  await apply(copyState(state), e, index, now, false);
}

/** Compare two valid logs of one account ([VER-2]): `b` relative to `a`. → account_mismatch */
export async function compareLogs(a, b) {
  if (!a.length || !b.length || !isObject(a[0]) || !isObject(b[0])) fail("bad_field");
  if ((await accountId(a[0])) !== (await accountId(b[0]))) fail("account_mismatch");
  const h = async (v) => {
    if (!isObject(v)) fail("bad_field");
    return eventHash(v);
  };
  if (a.length === b.length) {
    return bytesEqual(await h(a[a.length - 1]), await h(b[b.length - 1])) ? "same" : "fork";
  }
  const [short, long, order] = a.length < b.length ? [a, b, "newer"] : [b, a, "older"];
  return bytesEqual(await h(short[short.length - 1]), await h(long[short.length - 1])) ? order : "fork";
}

/** An unsigned event after `state` (`sigs` empty). */
export function unsignedEvent(state, kind, body, time) {
  return {
    v: 1,
    account: state.account,
    seq: state.version.seq + 1,
    prev: state.version.hash,
    kind,
    time,
    body,
    sigs: [],
  };
}

/** Append an owner signature ([LOG-6]). */
export async function signEvent(e, seed) {
  const sig = await ed25519Sign(seed, eventMessage(e));
  e.sigs = [...e.sigs, { key: formatKey("ed25519", await ed25519Public(seed)), sig: base64urlEncode(sig) }];
  return e;
}

/** Append the primary host's receipt ([LOG-8]). */
export async function addReceipt(e, hostSeed) {
  const sig = await ed25519Sign(hostSeed, receiptMessage(e));
  e.sigs = [...e.sigs, { key: formatKey("ed25519", await ed25519Public(hostSeed)), sig: base64urlEncode(sig) }];
  return e;
}

/** [RK-5] → wrong_recovery_key */
export async function checkRecoveryKey(state, seed) {
  if (!(await ed25519PublicIs(seed, s.parseKey(state.recovery, "ed25519")))) fail("wrong_recovery_key");
}

/** A pending instance ([LOG-9]). `home` is `{ key: "ed25519:…", url }`. */
export async function pendingInstance(state, recoverySeed, accountSeed, home, reason, time) {
  await checkRecoveryKey(state, recoverySeed);
  checkUrl(home.url);
  const body = {
    account_key: formatKey("ed25519", await ed25519Public(accountSeed)),
    home: { key: home.key, url: home.url },
    reason,
  };
  const e = unsignedEvent(state, "instance", body, time);
  await signEvent(e, recoverySeed);
  await signEvent(e, accountSeed);
  return e;
}

/** A `rotate_recovery` event ([KT-5]). */
export async function rotateRecoveryEvent(state, oldSeed, newSeed, time) {
  await checkRecoveryKey(state, oldSeed);
  const e = unsignedEvent(state, "rotate_recovery", { recovery: formatKey("ed25519", await ed25519Public(newSeed)) }, time);
  await signEvent(e, oldSeed);
  await signEvent(e, newSeed);
  return e;
}

/** A `retire` event ([KT-6]). */
export async function retireEvent(state, recoverySeed, time) {
  await checkRecoveryKey(state, recoverySeed);
  const e = unsignedEvent(state, "retire", {}, time);
  await signEvent(e, recoverySeed);
  return e;
}

/** The raw bytes of a b64u hash string. */
export function hashBytes(h) {
  return base64urlDecode(h);
}
