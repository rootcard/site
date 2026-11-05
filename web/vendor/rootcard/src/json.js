// Canonical JSON (SPEC §2): a strict parser and the RFC 8785 serialization of the rootcard subset of JSON.
// Values are plain objects, arrays, strings, safe integers and booleans. Parsed objects have no prototype.

import { fail } from "./errors.js";

export const MAX_SAFE = Number.MAX_SAFE_INTEGER;
export const MAX_DEPTH = 32;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Whether `v` is a plain object (not an array). */
export function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}

/** A new empty object without prototype. */
export function obj(entries) {
  const o = Object.create(null);
  if (entries) for (const [k, v] of Object.entries(entries)) o[k] = v;
  return o;
}

/** Whether `name` sorts before `other` by UTF-16 code units (RFC 8785 §3.2.3). JS string order is exactly that. */
function sortedKeys(o) {
  return Object.keys(o).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Check that a value built in code is a rootcard JSON value ([CJ-1]–[CJ-5]). → bad_json */
export function validate(v, depth = 0) {
  if (typeof v === "string") {
    if (!v.isWellFormed()) fail("bad_json");
  } else if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) fail("bad_json");
  } else if (typeof v === "boolean") {
    // ok
  } else if (Array.isArray(v)) {
    if (depth >= MAX_DEPTH) fail("bad_json");
    for (const x of v) validate(x, depth + 1);
  } else if (isObject(v)) {
    if (depth >= MAX_DEPTH) fail("bad_json");
    for (const k of Object.keys(v)) {
      if (!k.isWellFormed()) fail("bad_json");
      if (v[k] === undefined) fail("bad_json");
      validate(v[k], depth + 1);
    }
  } else {
    fail("bad_json");
  }
}

function writeString(s, out) {
  out.push('"');
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out.push('\\"');
    else if (ch === "\\") out.push("\\\\");
    else if (c === 0x08) out.push("\\b");
    else if (c === 0x09) out.push("\\t");
    else if (c === 0x0a) out.push("\\n");
    else if (c === 0x0c) out.push("\\f");
    else if (c === 0x0d) out.push("\\r");
    else if (c < 0x20) out.push("\\u00" + c.toString(16).padStart(2, "0"));
    else out.push(ch);
  }
  out.push('"');
}

function write(v, out) {
  if (typeof v === "string") writeString(v, out);
  else if (typeof v === "number") out.push(String(v));
  else if (typeof v === "boolean") out.push(v ? "true" : "false");
  else if (Array.isArray(v)) {
    out.push("[");
    v.forEach((x, i) => {
      if (i) out.push(",");
      write(x, out);
    });
    out.push("]");
  } else {
    out.push("{");
    sortedKeys(v).forEach((k, i) => {
      if (i) out.push(",");
      writeString(k, out);
      out.push(":");
      write(v[k], out);
    });
    out.push("}");
  }
}

/** `canonical(x)` as a string ([CJ-9]). The value must be valid ([CJ-1]–[CJ-5]). */
export function canonicalString(v) {
  validate(v);
  const out = [];
  write(v, out);
  return out.join("");
}

/** `canonical(x)` as UTF-8 bytes ([CJ-9]). */
export function canonical(v) {
  return enc.encode(canonicalString(v));
}

/** The object `o` without the member `name` (SPEC §0.1). */
export function without(o, ...names) {
  const r = obj();
  for (const k of Object.keys(o)) if (!names.includes(k)) r[k] = o[k];
  return r;
}

/** Parse a JSON text strictly ([CJ-6]). → bad_json */
export function parseJson(bytes) {
  if (typeof bytes === "string") bytes = enc.encode(bytes);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail("bad_json");
  let text;
  try {
    text = dec.decode(bytes);
  } catch {
    fail("bad_json");
  }
  const p = { s: text, i: 0 };
  ws(p);
  const v = value(p, 1);
  ws(p);
  if (p.i !== p.s.length) fail("bad_json");
  return v;
}

/** Parse with a size limit ([CJ-8]). → too_large, bad_json */
export function parseLimited(bytes, limit) {
  if (typeof bytes === "string") bytes = enc.encode(bytes);
  if (bytes.length > limit + Math.floor(limit / 4)) fail("too_large");
  const v = parseJson(bytes);
  if (canonical(v).length > limit) fail("too_large");
  return v;
}

function ws(p) {
  while (p.i < p.s.length) {
    const c = p.s.charCodeAt(p.i);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) p.i++;
    else break;
  }
}

function eat(p, lit) {
  if (p.s.startsWith(lit, p.i)) p.i += lit.length;
  else fail("bad_json");
}

function value(p, depth) {
  const c = p.s[p.i];
  if (c === "{") {
    if (depth > MAX_DEPTH) fail("bad_json");
    p.i++;
    const o = obj();
    ws(p);
    if (p.s[p.i] === "}") {
      p.i++;
      return o;
    }
    for (;;) {
      ws(p);
      if (p.s[p.i] !== '"') fail("bad_json");
      const k = string(p);
      ws(p);
      eat(p, ":");
      ws(p);
      const v = value(p, depth + 1);
      if (Object.prototype.hasOwnProperty.call(o, k)) fail("bad_json");
      o[k] = v;
      ws(p);
      if (p.s[p.i] === ",") p.i++;
      else if (p.s[p.i] === "}") {
        p.i++;
        return o;
      } else fail("bad_json");
    }
  }
  if (c === "[") {
    if (depth > MAX_DEPTH) fail("bad_json");
    p.i++;
    const a = [];
    ws(p);
    if (p.s[p.i] === "]") {
      p.i++;
      return a;
    }
    for (;;) {
      ws(p);
      a.push(value(p, depth + 1));
      ws(p);
      if (p.s[p.i] === ",") p.i++;
      else if (p.s[p.i] === "]") {
        p.i++;
        return a;
      } else fail("bad_json");
    }
  }
  if (c === '"') return string(p);
  if (c === "t") {
    eat(p, "true");
    return true;
  }
  if (c === "f") {
    eat(p, "false");
    return false;
  }
  if (c === "-" || (c >= "0" && c <= "9")) return number(p);
  fail("bad_json");
}

function number(p) {
  const m = /^-?(0|[1-9][0-9]*)/.exec(p.s.slice(p.i, p.i + 20));
  if (!m) fail("bad_json");
  const text = m[0];
  p.i += text.length;
  const next = p.s[p.i];
  if (next === "." || next === "e" || next === "E" || (next >= "0" && next <= "9")) fail("bad_json");
  if (text === "-0" || text.length > 17) fail("bad_json");
  const n = Number(text);
  if (!Number.isSafeInteger(n)) fail("bad_json");
  return n;
}

function hex4(p) {
  const h = p.s.slice(p.i, p.i + 4);
  if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad_json");
  p.i += 4;
  return parseInt(h, 16);
}

function string(p) {
  p.i++;
  let out = "";
  for (;;) {
    if (p.i >= p.s.length) fail("bad_json");
    const c = p.s.charCodeAt(p.i);
    if (c === 0x22) {
      p.i++;
      return out;
    }
    if (c === 0x5c) {
      p.i++;
      const e = p.s[p.i++];
      if (e === '"') out += '"';
      else if (e === "\\") out += "\\";
      else if (e === "/") out += "/";
      else if (e === "b") out += "\b";
      else if (e === "f") out += "\f";
      else if (e === "n") out += "\n";
      else if (e === "r") out += "\r";
      else if (e === "t") out += "\t";
      else if (e === "u") {
        const u = hex4(p);
        if (u >= 0xd800 && u < 0xdc00) {
          eat(p, "\\u");
          const lo = hex4(p);
          if (!(lo >= 0xdc00 && lo < 0xe000)) fail("bad_json");
          out += String.fromCharCode(u, lo);
        } else if (u >= 0xdc00 && u < 0xe000) {
          fail("bad_json");
        } else {
          out += String.fromCharCode(u);
        }
      } else fail("bad_json");
      continue;
    }
    if (c < 0x20) fail("bad_json");
    // A surrogate pair in the decoded text is one scalar value; copy both halves.
    if (c >= 0xd800 && c < 0xdc00) {
      out += p.s.slice(p.i, p.i + 2);
      p.i += 2;
    } else {
      out += p.s[p.i];
      p.i++;
    }
  }
}
