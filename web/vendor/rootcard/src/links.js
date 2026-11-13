// Linked accounts (SPEC §12.3): the `user.links` profile key, link tokens and the interpreter of service descriptors.
//
// No I/O here ([IMP-1]): linkRequests says what to fetch, the caller fetches it under [LNK-9] (HTTPS, no redirects, no
// credentials, at most RESPONSE_LIMIT bytes, FETCH_TIMEOUT_SECS), and checkLink decides from the answers. The
// descriptors of the registry in spec/links/ are bundled (links-registry.js, generated) and returned by registry().

import { fail, RootcardError } from "./errors.js";
import { checkAccountId } from "./keys.js";
import { isObject, parseJson, parseResponseJson } from "./json.js";
import { REGISTRY } from "./links-registry.js";

export const LINKS_KEY = "user.links";
export const MAX_LINKS = 16;
export const TOKEN_PREFIX = "rootcard:";
export const TOKEN_SEARCH_LIMIT = 64 * 1024;
export const RESPONSE_LIMIT = 64 * 1024;
export const FETCH_TIMEOUT_SECS = 10;

const MAX_STEPS = 4;
const MAX_ENTRIES = 8;
const MAX_FORMS = 16;
const MAX_POINTER_SEGMENTS = 8;
const MAX_TEMPLATE = 256;
const MAX_CHARS = 64;
const MAX_REV = 2 ** 32;

const enc = new TextEncoder();
const utf8Length = (s) => enc.encode(s).length;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
/** Member names in the order of the Rust core's maps (UTF-16 code units, RFC 8785). */
const sorted = (o) => Object.keys(o).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const isInt = (v) => typeof v === "number" && Number.isSafeInteger(v);
const isLower = (c) => c >= 0x61 && c <= 0x7a;
const isDigitCode = (c) => c >= 0x30 && c <= 0x39;
const isAlnum = (c) => isLower(c) || isDigitCode(c) || (c >= 0x41 && c <= 0x5a);

function statusOf(f) {
  try {
    f();
    return "ok";
  } catch (e) {
    if (e instanceof RootcardError) return e.code;
    throw e;
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Links

/** A service name ([LNK-1]): 1 to 32 characters of `a–z 0–9 -`, beginning with `a–z`. */
function isServiceName(s) {
  return typeof s === "string" && /^[a-z][a-z0-9-]{0,31}$/.test(s);
}

const isFormName = isServiceName;

function isUidChar(c) {
  return isAlnum(c) || c === 0x2e || c === 0x5f || c === 0x3a || c === 0x2d;
}

/** A link with the schema of [LNK-1], as `{ service, name, uid?, ref? }`. → bad_link */
function linkSchema(v) {
  if (!isObject(v)) fail("bad_link");
  for (const k of Object.keys(v)) if (!["service", "name", "uid", "ref"].includes(k)) fail("bad_link");
  for (const k of Object.keys(v)) if (typeof v[k] !== "string") fail("bad_link");
  if (!own(v, "service") || !own(v, "name")) fail("bad_link");
  const link = { service: v.service, name: v.name };
  if (own(v, "uid")) link.uid = v.uid;
  if (own(v, "ref")) link.ref = v.ref;
  const nl = utf8Length(link.name);
  const ok =
    isServiceName(link.service) &&
    nl >= 1 &&
    nl <= 256 &&
    (link.uid === undefined ||
      (link.uid.length >= 1 && link.uid.length <= 64 && [...link.uid].every((c) => isUidChar(c.codePointAt(0))))) &&
    (link.ref === undefined || (utf8Length(link.ref) >= 1 && utf8Length(link.ref) <= 256));
  if (!ok) fail("bad_link");
  return link;
}

/** A link from its JSON form, checked against the schema of [LNK-1]: `{ service, name, uid?, ref? }`. → bad_link */
export function parseLink(v) {
  return linkSchema(v);
}

/** The descriptor for `service` in `registry`: the first one with that name ([LNK-19]). */
export function findDescriptor(registry, service) {
  return registry.find((d) => d.service === service);
}

/**
 * The links of a verified profile's `data` ([LNK-1], [LNK-2], [LNK-13]): one `{ link?, status }` per link, in order,
 * where `status` is "ok", "bad_link" or "unsupported". No `user.links` key means no links. → bad_link or unsupported
 * for the value as a whole
 */
export function parseLinks(data, registry) {
  if (!own(data, LINKS_KEY)) return [];
  const m = data[LINKS_KEY];
  if (!isObject(m)) fail("bad_link");
  if (!isInt(m.v) || !own(m, "v")) fail("bad_link");
  if (m.v !== 1) fail("unsupported");
  if (Object.keys(m).length !== 2 || !own(m, "links") || !Array.isArray(m.links)) fail("bad_link");
  if (m.links.length > MAX_LINKS) fail("bad_link");
  const out = [];
  for (const v of m.links) {
    let link;
    try {
      link = linkSchema(v);
    } catch (e) {
      if (!(e instanceof RootcardError)) throw e;
      out.push({ status: e.code });
      continue;
    }
    const d = findDescriptor(registry, link.service);
    const status = !d
      ? "unsupported"
      : statusOf(() => {
          checkFields(d, link);
          const dup = out.some(
            (e) => e.status === "ok" && e.link.service === link.service && sameName(d, e.link, link),
          );
          if (dup) fail("bad_link");
        });
    out.push({ link, status });
  }
  return out;
}

/** The `user.links` value for `links` ([LNK-1], [LNK-4]). → bad_link, unsupported */
export function linksValue(links, registry) {
  if (links.length > MAX_LINKS) fail("bad_link");
  const list = [];
  links.forEach((link, i) => {
    const l = linkSchema(link);
    const d = findDescriptor(registry, l.service);
    if (!d) fail("unsupported");
    checkFields(d, l);
    if (links.slice(0, i).some((o) => o.service === l.service && sameName(d, o, l))) fail("bad_link");
    list.push(l);
  });
  return { v: 1, links: list };
}

// ---------------------------------------------------------------------------------------------------------------------
// Tokens

/** The link token of an identity ([LNK-5]): `rootcard:` and the account id. → bad_field */
export function linkToken(account) {
  checkAccountId(account);
  return TOKEN_PREFIX + account;
}

/**
 * Whether the link token of `account` occurs in the first TOKEN_SEARCH_LIMIT bytes of `text` (a string, as UTF-8, or
 * bytes), with no ASCII letter or digit directly before or after it ([LNK-6]). → bad_field
 */
export function findLinkToken(text, account) {
  const t = enc.encode(linkToken(account));
  let b = typeof text === "string" ? enc.encode(text) : text;
  if (b.length > TOKEN_SEARCH_LIMIT) b = b.subarray(0, TOKEN_SEARCH_LIMIT);
  outer: for (let i = 0; i + t.length <= b.length; i++) {
    for (let j = 0; j < t.length; j++) if (b[i + j] !== t[j]) continue outer;
    if (i > 0 && isAlnum(b[i - 1])) continue;
    if (i + t.length < b.length && isAlnum(b[i + t.length])) continue;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------------------------------
// Descriptors

/** A domain name ([LNK-21]). */
export function isDomain(s) {
  if (typeof s !== "string" || s.length === 0 || s.length > 253) return false;
  const labels = s.split(".");
  return (
    labels.length >= 2 &&
    labels.every((l) => /^[a-z0-9-]{1,63}$/.test(l) && l[0] !== "-" && l[l.length - 1] !== "-") &&
    !/^[0-9]+$/.test(labels[labels.length - 1])
  );
}

function fieldCheck(f, s) {
  if (f.kind === "token") {
    // `.` and `..` are never values: in a URL path they are dot segments, even percent-encoded ([LNK-8]).
    if (s.length < f.min || s.length > f.max || s === "." || s === "..") return false;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 128 || !f.chars[c]) return false;
    }
    return true;
  }
  if (f.kind === "domain") return isDomain(s);
  return false;
}

function fieldEqual(f, a, b) {
  const lower = (x) => x.replace(/[A-Z]/g, (c) => c.toLowerCase()); // ASCII only, as Rust's eq_ignore_ascii_case
  if (f.compare === "ascii-ci") return lower(a) === lower(b);
  return a === b;
}

function fieldOf(v, allow) {
  if (!isObject(v)) fail("bad_field");
  const kind = v.type;
  if (typeof kind !== "string") fail("bad_field");
  if (!["token", "domain", "none"].includes(kind)) fail("unsupported");
  if (!allow.includes(kind)) fail("bad_field");
  if (kind !== "token") {
    if (Object.keys(v).length !== 1) fail("bad_field");
    return { kind, compare: "exact" };
  }
  for (const k of Object.keys(v)) if (!["type", "chars", "min", "max", "compare"].includes(k)) fail("bad_field");
  if (typeof v.chars !== "string") fail("bad_field");
  const chars = charSet(v.chars);
  const int = (k) => {
    if (!isInt(v[k]) || v[k] < 1 || v[k] > 256) fail("bad_field");
    return v[k];
  };
  const min = int("min");
  const max = int("max");
  if (min > max) fail("bad_field");
  let compare = "exact";
  if (own(v, "compare")) {
    if (v.compare === "exact" || v.compare === "ascii-ci") compare = v.compare;
    else fail("bad_field");
  }
  return { kind, chars, min, max, compare };
}

/** A character set ([LNK-22]): printable ASCII, where `x-y` is a range. */
function charSet(s) {
  const b = enc.encode(s);
  if (b.length === 0 || b.length > MAX_CHARS || !b.every((c) => c >= 0x21 && c <= 0x7e)) fail("bad_field");
  const set = new Array(128).fill(false);
  let i = 0;
  while (i < b.length) {
    if (i + 2 < b.length && b[i + 1] === 0x2d) {
      if (b[i] > b[i + 2]) fail("bad_field");
      for (let c = b[i]; c <= b[i + 2]; c++) set[c] = true;
      i += 3;
    } else {
      set[b[i]] = true;
      i += 1;
    }
  }
  return set;
}

function templateOf(s) {
  if (typeof s !== "string" || s.length === 0 || utf8Length(s) > MAX_TEMPLATE) fail("bad_field");
  const parts = [];
  let lit = "";
  let rest = s;
  while (rest.length > 0) {
    const c = rest[0];
    if (c === "{") {
      const end = rest.indexOf("}");
      if (end < 0) fail("bad_field");
      const slot = rest.slice(1, end);
      if (!["name", "uid", "ref"].includes(slot)) fail("bad_field");
      if (lit) parts.push({ lit });
      lit = "";
      parts.push({ slot });
      rest = rest.slice(end + 1);
    } else if (c === "}") {
      fail("bad_field");
    } else {
      lit += c;
      rest = rest.slice(1);
    }
  }
  if (lit) parts.push({ lit });
  return parts;
}

const isPathText = (s) => /^[A-Za-z0-9\-._~/]*$/.test(s);
const allows = (slots, s) => s === "name" || (s === "uid" && slots.uid) || (s === "ref" && slots.ref);

/** A URL template ([LNK-8], [LNK-22]). */
function urlTemplate(s, slots) {
  const t = templateOf(s);
  let i = 0;
  const first = t[i++];
  if (!first || first.lit === undefined || !first.lit.startsWith("https://")) fail("bad_field");
  const after = first.lit.slice(8);
  let pathStart;
  if (after.length === 0) {
    const n = t[i++];
    if (!slots.nameIsDomain || !n || n.slot !== "name") fail("bad_field");
    const l = t[i++];
    if (!l || l.lit === undefined || !l.lit.startsWith("/")) fail("bad_field");
    pathStart = l.lit;
  } else {
    const slash = after.indexOf("/");
    if (slash < 0 || !isDomain(after.slice(0, slash))) fail("bad_field");
    pathStart = after.slice(slash);
  }
  if (!isPathText(pathStart)) fail("bad_field");
  // Every placeholder in the path is a whole segment: after a `/`, before a `/` or the end ([LNK-8]).
  let prevEndsSlash = pathStart.endsWith("/");
  for (; i < t.length; i++) {
    const p = t[i];
    if (p.lit !== undefined) {
      if (!isPathText(p.lit)) fail("bad_field");
      prevEndsSlash = p.lit.endsWith("/");
    } else {
      if (!allows(slots, p.slot)) fail("bad_field");
      const next = t[i + 1];
      const nextOk = next === undefined || (next.lit !== undefined && next.lit.startsWith("/"));
      if (!prevEndsSlash || !nextOk) fail("bad_field");
      prevEndsSlash = false;
    }
  }
  return t;
}

/** A DNS name template ([LNK-22]). */
function dnsTemplate(s, slots) {
  const t = templateOf(s);
  let ok = false;
  if (slots.nameIsDomain) {
    if (t.length === 1 && t[0].slot === "name") ok = true;
    else if (t.length === 2 && t[0].lit !== undefined && t[1].slot === "name" && t[0].lit.endsWith(".")) {
      ok = t[0].lit
        .slice(0, -1)
        .split(".")
        .every((l) => /^[a-z0-9\-_]{1,63}$/.test(l));
    }
  }
  if (!ok) fail("bad_field");
  return t;
}

function valueTemplate(s, slots) {
  const t = templateOf(s);
  if (!t.every((p) => p.lit !== undefined || allows(slots, p.slot))) fail("bad_field");
  return t;
}

/** A JSON pointer (RFC 6901) of at most 8 segments; a segment `*` stands for every member or element. */
function pointerOf(s, wildcard) {
  if (typeof s !== "string") fail("bad_field");
  if (s === "") return [];
  if (s[0] !== "/") fail("bad_field");
  const segs = [];
  for (const raw of s.slice(1).split("/")) {
    if (raw === "*") {
      if (!wildcard) fail("bad_field");
      segs.push({ any: true });
      continue;
    }
    let out = "";
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === "~") {
        const n = raw[++i];
        if (n === "0") out += "~";
        else if (n === "1") out += "/";
        else fail("bad_field");
      } else out += raw[i];
    }
    segs.push({ name: out });
  }
  if (segs.length > MAX_POINTER_SEGMENTS) fail("bad_field");
  return segs;
}

function stepOf(v, slots) {
  if (!isObject(v)) fail("bad_field");
  if (typeof v.kind !== "string") fail("bad_field");
  const kind = v.kind;
  if (!["http-json", "http-text", "dns-txt"].includes(kind)) fail("unsupported");
  const allowed = {
    "http-json": ["kind", "url", "equal", "token_in"],
    "http-text": ["kind", "url"],
    "dns-txt": ["kind", "name"],
  }[kind];
  for (const k of Object.keys(v)) if (!allowed.includes(k)) fail("bad_field");
  let target;
  if (kind === "dns-txt") {
    if (typeof v.name !== "string") fail("bad_field");
    target = dnsTemplate(v.name, slots);
  } else {
    if (typeof v.url !== "string") fail("bad_field");
    target = urlTemplate(v.url, slots);
  }
  const equal = [];
  if (own(v, "equal")) {
    if (!isObject(v.equal)) fail("bad_field");
    const keys = sorted(v.equal);
    if (keys.length < 1 || keys.length > MAX_ENTRIES) fail("bad_field");
    for (const p of keys) {
      const ptr = pointerOf(p, false);
      if (typeof v.equal[p] !== "string") fail("bad_field");
      equal.push([ptr, valueTemplate(v.equal[p], slots)]);
    }
  }
  const tokenIn = [];
  if (own(v, "token_in")) {
    if (!Array.isArray(v.token_in)) fail("bad_field");
    if (v.token_in.length < 1 || v.token_in.length > MAX_ENTRIES) fail("bad_field");
    for (const p of v.token_in) tokenIn.push(pointerOf(p, true));
  }
  if (kind === "http-json" && equal.length === 0 && tokenIn.length === 0) fail("bad_field");
  return { kind, target, equal, tokenIn };
}

const findsToken = (s) => s.kind !== "http-json" || s.tokenIn.length > 0;
const compares = (s, slot) => s.equal.some(([, t]) => t.length === 1 && t[0].slot === slot);

/**
 * Check a service descriptor against the format of [LNK-22] and the rules of [LNK-7], [LNK-8], [LNK-18]. Returns the
 * parsed descriptor. → bad_field; unsupported for a `v`, field type or step kind this interpreter does not know
 */
export function parseDescriptor(v) {
  if (!isObject(v)) fail("bad_field");
  if (!own(v, "v") || !isInt(v.v)) fail("bad_field");
  if (v.v !== 1) fail("unsupported");
  for (const k of Object.keys(v)) {
    if (!["v", "service", "rev", "status", "fields", "display", "checks"].includes(k)) fail("bad_field");
  }
  if (!isServiceName(v.service)) fail("bad_field");
  if (!isInt(v.rev) || v.rev < 1 || v.rev > MAX_REV) fail("bad_field");
  let retired;
  if (v.status === "active") retired = false;
  else if (v.status === "retired") retired = true;
  else fail("bad_field");
  const fields = v.fields;
  if (!isObject(fields)) fail("bad_field");
  for (const k of Object.keys(fields)) if (!["name", "uid", "ref"].includes(k)) fail("bad_field");
  if (!own(fields, "name")) fail("bad_field");
  const name = fieldOf(fields.name, ["token", "domain"]);
  const uid = own(fields, "uid") ? fieldOf(fields.uid, ["token"]) : undefined;
  if (uid && (uid.max > 64 || uid.chars.some((on, c) => on && !isUidChar(c)))) fail("bad_field");
  const nameIsDomain = name.kind === "domain";
  if (!nameIsDomain && !uid) fail("bad_field");
  const forms = [];
  if (own(fields, "ref")) {
    if (!isObject(fields.ref)) fail("bad_field");
    const keys = sorted(fields.ref);
    if (keys.length < 1 || keys.length > MAX_FORMS) fail("bad_field");
    for (const form of keys) {
      if (!isFormName(form)) fail("bad_field");
      forms.push([form, fieldOf(fields.ref[form], ["token", "none"])]);
    }
  }
  if (typeof v.display !== "string") fail("bad_field");
  const display = urlTemplate(v.display, { uid: !!uid, ref: false, nameIsDomain });
  if (!isObject(v.checks)) fail("bad_field");
  const keys = sorted(v.checks);
  if (keys.length === 0) fail("bad_field");
  const checks = [];
  for (const key of keys) {
    const form = forms.find(([f]) => f === key);
    if (key !== "*" && !form) fail("bad_field");
    const slots = { uid: !!uid, ref: !!form && form[1].kind !== "none", nameIsDomain };
    const list = v.checks[key];
    if (!Array.isArray(list) || list.length < 1 || list.length > MAX_STEPS) fail("bad_field");
    const steps = list.map((s) => stepOf(s, slots));
    if (!steps.some(findsToken)) fail("bad_field");
    if (uid && !(steps.some((s) => compares(s, "uid")) && steps.some((s) => compares(s, "name")))) fail("bad_field");
    checks.push([key, steps]);
  }
  if (forms.some(([f]) => !checks.some(([k]) => k === f))) fail("bad_field");
  return Object.freeze({ service: v.service, rev: v.rev, retired, name, uid, forms, display, checks });
}

/** The descriptors bundled with this package ([LNK-19]); one this interpreter cannot read is left out. */
export function registry() {
  const list = parseJson(REGISTRY);
  const out = [];
  for (const d of list) {
    try {
      out.push(parseDescriptor(d));
    } catch (e) {
      if (!(e instanceof RootcardError)) throw e;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------------
// Checking

function formOf(d, ref) {
  const colon = ref.indexOf(":");
  const form = colon < 0 ? ref : ref.slice(0, colon);
  const value = colon < 0 ? undefined : ref.slice(colon + 1);
  if (!isFormName(form)) fail("bad_link");
  const f = d.forms.find(([n]) => n === form);
  if (!f) fail("unsupported");
  return { form, field: f[1], value };
}

/** The service's rules for a link's fields ([LNK-2], [LNK-13]): name, uid, ref. → bad_link, unsupported */
function checkFields(d, link) {
  if (d.retired) fail("unsupported");
  if (!fieldCheck(d.name, link.name)) fail("bad_link");
  if (d.uid) {
    if (link.uid === undefined || !fieldCheck(d.uid, link.uid)) fail("bad_link");
  } else if (link.uid !== undefined) fail("bad_link");
  if (link.ref === undefined) {
    if (!d.checks.some(([k]) => k === "*")) fail("bad_link");
    return;
  }
  const { field, value } = formOf(d, link.ref);
  if (field.kind === "none") {
    if (value !== undefined) fail("bad_link");
  } else if (value === undefined || !fieldCheck(field, value)) fail("bad_link");
}

function sameName(d, a, b) {
  return fieldEqual(d.name, a.name, b.name);
}

function stepsOf(d, link) {
  checkFields(d, link);
  const key = link.ref === undefined ? "*" : formOf(d, link.ref).form;
  const c = d.checks.find(([k]) => k === key);
  if (!c) fail("bad_link");
  return c[1];
}

function slotValue(link, s) {
  if (s === "name") return link.name;
  if (s === "uid") return link.uid ?? "";
  const r = link.ref ?? "";
  const colon = r.indexOf(":");
  return colon < 0 ? "" : r.slice(colon + 1);
}

function slotField(d, s) {
  if (s === "name") return d.name;
  if (s === "uid") return d.uid;
  return undefined;
}

function percentEncode(s) {
  let out = "";
  for (const c of enc.encode(s)) {
    if (isAlnum(c) || c === 0x2d || c === 0x2e || c === 0x5f || c === 0x7e) out += String.fromCharCode(c);
    else out += "%" + c.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

function fill(t, link, encode) {
  let out = "";
  for (const p of t) {
    if (p.lit !== undefined) out += p.lit;
    else out += encode ? percentEncode(slotValue(link, p.slot)) : slotValue(link, p.slot);
  }
  return out;
}

function asLink(link) {
  return linkSchema(link);
}

/**
 * The requests that check `link` with descriptor `d`, in order ([LNK-10]): `{ kind, url }` or `{ kind, name }` for
 * `dns-txt` ([LNK-8]). → bad_link, unsupported
 */
export function linkRequests(link, d) {
  const l = asLink(link);
  if (l.service !== d.service) fail("bad_link");
  return stepsOf(d, l).map((s) =>
    s.kind === "dns-txt"
      ? { kind: s.kind, name: fill(s.target, l, false) }
      : { kind: s.kind, url: fill(s.target, l, true) },
  );
}

/** The URL that shows the linked account ([LNK-12]): shown, never fetched. → bad_link, unsupported */
export function linkDisplay(link, d) {
  const l = asLink(link);
  if (l.service !== d.service) fail("bad_link");
  checkFields(d, l);
  return fill(d.display, l, true);
}

function resolve(v, segs, out) {
  if (v === undefined) return;
  if (segs.length === 0) {
    out.push(v);
    return;
  }
  const [first, ...rest] = segs;
  if (first.any) {
    if (Array.isArray(v)) for (const x of v) resolve(x, rest, out);
    else if (isObject(v)) for (const k of sorted(v)) resolve(v[k], rest, out);
  } else if (isObject(v) && own(v, first.name)) resolve(v[first.name], rest, out);
}

const bytesOf = (b) => (typeof b === "string" ? enc.encode(b) : b);

/**
 * Check a link with the answers to its linkRequests ([LNK-10]). An answer is `null` (the request failed under
 * [LNK-9]), `{ body }` (the body of a 200 answer, a string or bytes) or `{ txt: [[string or bytes, ...], ...] }` (the
 * TXT records of a DNS answer). Returns normally if the link is verified, by this check, now ([LNK-11]).
 * → fetch_failed, wrong_owner, token_missing, bad_link, unsupported, bad_field
 */
export function checkLink(link, account, d, responses) {
  checkAccountId(account);
  const l = asLink(link);
  if (l.service !== d.service) fail("bad_link");
  const steps = stepsOf(d, l);
  if (!Array.isArray(responses) || responses.length !== steps.length) fail("bad_field");
  steps.forEach((step, i) => {
    const r = responses[i];
    if (r === null || r === undefined) fail("fetch_failed");
    if (step.kind === "dns-txt") {
      if (!Array.isArray(r.txt)) fail("bad_field");
      const records = r.txt.map((rec) => {
        if (!Array.isArray(rec)) fail("bad_field");
        return rec.map(bytesOf);
      });
      if (records.flat().reduce((n, b) => n + b.length, 0) > RESPONSE_LIMIT) fail("fetch_failed");
      let found = false;
      for (const rec of records) {
        const all = new Uint8Array(rec.reduce((n, b) => n + b.length, 0));
        let o = 0;
        for (const b of rec) {
          all.set(b, o);
          o += b.length;
        }
        if (findLinkToken(all, account)) found = true;
      }
      if (!found) fail("token_missing");
      return;
    }
    if (r.body === undefined) fail("bad_field");
    const body = bytesOf(r.body);
    if (body.length > RESPONSE_LIMIT) fail("fetch_failed");
    if (step.kind === "http-text") {
      if (!findLinkToken(body, account)) fail("token_missing");
      return;
    }
    let root;
    try {
      root = parseResponseJson(body);
    } catch (e) {
      if (e instanceof RootcardError) fail("fetch_failed");
      throw e;
    }
    for (const [p, t] of step.equal) {
      const want = fill(t, l, false);
      const field = t.length === 1 && t[0].slot !== undefined ? slotField(d, t[0].slot) : undefined;
      const got = [];
      resolve(root, p, got);
      const g = got[0];
      let ok = false;
      if (typeof g === "string") ok = field ? fieldEqual(field, g, want) : g === want;
      else if (isInt(g)) ok = String(g) === want;
      if (!ok) fail("wrong_owner");
    }
    if (step.tokenIn.length > 0) {
      let found = false;
      for (const p of step.tokenIn) {
        const got = [];
        resolve(root, p, got);
        for (const g of got) if (typeof g === "string" && findLinkToken(g, account)) found = true;
      }
      if (!found) fail("token_missing");
    }
  });
}
