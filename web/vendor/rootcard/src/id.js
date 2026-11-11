// Realm, username, inception, account id (SPEC §7), handles and tags (SPEC §8).

import { fail } from "./errors.js";
import { B32, base32Encode, base64urlEncode } from "./encoding.js";
import { ed25519Public, ed25519Sign, frameObject, sha256 } from "./crypto.js";
import { without } from "./json.js";
import { formatKey } from "./keys.js";
import { label } from "./labels.js";

/** [RLM-1] → bad_realm */
export function checkRealm(realm) {
  if (typeof realm !== "string" || !/^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$/.test(realm)) fail("bad_realm");
}

/** [USR-1] → bad_username */
export function checkUsername(username) {
  if (typeof username !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/.test(username)) fail("bad_username");
}

/** The default username policy ([USR-3]): [USR-1], 3 to 20 characters, beginning with A–Z a–z. */
export function defaultUsernamePolicy(username) {
  return /^[A-Za-z][A-Za-z0-9_-]{2,19}$/.test(username);
}

/** [USR-2] */
export function similarUsernames(a, b) {
  return a.toLowerCase() === b.toLowerCase() && /^[\x00-\x7f]*$/.test(a + b);
}

/** The account id of an inception ([ID-3]). */
export async function accountId(inception) {
  return base32Encode(await sha256(frameObject(label("id"), without(inception, "sigs"))));
}

/** The deterministic inception of an identity ([ID-1], [ID-2]). → bad_realm, bad_username */
export async function inception(keys, realm, username) {
  checkRealm(realm);
  checkUsername(username);
  const recovery = formatKey("ed25519", await ed25519Public(keys.signSeed));
  const unsigned = { v: 1, kind: "incept", seq: 0, body: { realm, username, recovery } };
  const sig = await ed25519Sign(keys.signSeed, frameObject(label("event"), unsigned));
  return { ...unsigned, sigs: [{ key: recovery, sig: base64urlEncode(sig) }] };
}

/** The tag of an account id ([HDL-1]). */
export function tag(account) {
  return Array.from(account).slice(0, 4).join("");
}

/** `username + "#" + tag` ([HDL-1]). */
export function handle(username, account) {
  return `${username}#${tag(account)}`;
}

function lenientChars(s) {
  let out = "";
  for (const c of s) {
    const u = c.length === 1 && c >= "a" && c <= "z" ? c.toUpperCase() : c;
    const m = u === "I" || u === "L" ? "1" : u === "O" ? "0" : u;
    if (m.length !== 1 || !B32.includes(m)) return null;
    out += m;
  }
  return out;
}

/** Parse a typed handle ([HDL-3]). → bad_handle */
export function parseHandle(text) {
  const at = text.lastIndexOf("#");
  if (at < 0) fail("bad_handle");
  const username = text.slice(0, at);
  try {
    checkUsername(username);
  } catch {
    fail("bad_handle");
  }
  const t = text.slice(at + 1);
  const dash = t.indexOf("-");
  const t4 = lenientChars(dash < 0 ? t : t.slice(0, dash));
  if (t4 === null || t4.length !== 4) fail("bad_handle");
  const result = { username, tag: t4 };
  if (dash >= 0) {
    const e = lenientChars(t.slice(dash + 1));
    if (e === null || e.length < 1 || e.length > 48) fail("bad_handle");
    result.extension = e;
  }
  return result;
}

/** Whether an identity matches a parsed handle (similar username, [USR-2]). */
export function handleMatches(parsed, username, account) {
  return similarUsernames(parsed.username, username) && account.startsWith(parsed.tag + (parsed.extension ?? ""));
}

/** The extended tags of colliding account ids ([HDL-6]), in the order given. */
export function extendedTags(ids) {
  const distinct = [...new Set(ids)];
  if (distinct.length < 2) return ids.map(tag);
  // Characters (code points), not UTF-16 units ([HDL-6]), as in the Rust core.
  const chars = distinct.map((s) => Array.from(s));
  const max = Math.min(...chars.map((c) => c.length));
  let n = 5;
  while (n < max) {
    const prefixes = chars.map((c) => c.slice(0, n).join(""));
    if (new Set(prefixes).size === prefixes.length) break;
    n++;
  }
  n = Math.min(n, max);
  return ids.map((id) => {
    const c = Array.from(id);
    return `${c.slice(0, 4).join("")}-${c.slice(4, n).join("")}`;
  });
}
